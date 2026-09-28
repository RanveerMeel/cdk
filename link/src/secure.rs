//! Post-quantum secure channel over the CDK link (roadmap 3.2).
//!
//! ## Handshake (`CDK-LINK-v1`)
//!
//! ```text
//! client (CDK)                                   server (gateway)
//!   CH = 1 ‖ nonce_c ‖ X25519_c ‖ ML-KEM-768 ek   ──►
//!                                                ◄──  SH = nonce_s ‖ X25519_s ‖ ML-KEM ct
//!                                                        ‖ server identity ‖ Sig_s
//!   CF = client identity ‖ Sig_c                  ──►
//! ```
//!
//! * Key exchange is **hybrid**: X25519 and ML-KEM-768 (FIPS 203); the
//!   session keys depend on both shared secrets, so breaking the channel
//!   requires breaking both.
//! * Both sides authenticate with **hybrid signatures** (Ed25519 + ML-DSA-65,
//!   FIPS 204 context `CDK-LINK-v1`, both must verify) over the transcript:
//!   `Sig_s` covers `CH ‖ SH-without-signature`, `Sig_c` covers
//!   `CH ‖ SH ‖ CF-without-signature`. The client additionally decides
//!   whether it trusts the server identity (CDK pins the gateway's key).
//! * Keys: `HKDF-SHA256(salt = SHA-256("CDK-LINK-v1 keys" ‖ CH ‖ SH ‖ CF),
//!   ikm = X25519_ss ‖ ML-KEM_ss)`, expanded into one ChaCha20-Poly1305 key
//!   per direction.
//!
//! ## Sealed data
//!
//! `seq (u64 LE) ‖ ciphertext ‖ tag`, nonce = `0⁴ ‖ seq`, AAD = the
//! domain string and `seq`. Each direction's `seq` must arrive strictly in
//! order, so replayed, dropped, or reordered frames are rejected.
//!
//! Randomness is injected by the caller (the kernel has its own RNG), which
//! also makes the handshake deterministic under test.

use alloc::boxed::Box;
use alloc::vec::Vec;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use ml_kem::{Decapsulate, DecapsulationKey, KeyExport, MlKem768, Seed as KemSeed, B32 as KemB32};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const PROTOCOL: &[u8] = b"CDK-LINK-v1";
pub const VERSION: u8 = 1;

pub const NONCE_LEN: usize = 32;
pub const X25519_LEN: usize = 32;
pub const KEM_EK_LEN: usize = 1184;
pub const KEM_CT_LEN: usize = 1088;
pub const ED_PUB_LEN: usize = 32;
pub const ML_PUB_LEN: usize = 1952;
pub const ED_SIG_LEN: usize = 64;
pub const ML_SIG_LEN: usize = 3309;
/// Serialized identity: Ed25519 public key ‖ ML-DSA-65 public key.
pub const IDENTITY_LEN: usize = ED_PUB_LEN + ML_PUB_LEN;
pub const SIG_LEN: usize = ED_SIG_LEN + ML_SIG_LEN;

pub const CH_LEN: usize = 1 + NONCE_LEN + X25519_LEN + KEM_EK_LEN;
const SH_UNSIGNED: usize = NONCE_LEN + X25519_LEN + KEM_CT_LEN + IDENTITY_LEN;
pub const SH_LEN: usize = SH_UNSIGNED + SIG_LEN;
pub const CF_LEN: usize = IDENTITY_LEN + SIG_LEN;

/// Sealed-frame overhead (sequence number + tag) and plaintext limit.
pub const SEAL_OVERHEAD: usize = 8 + 16;
pub const MAX_PLAINTEXT: usize = crate::MAX_PAYLOAD - SEAL_OVERHEAD;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HsError {
    BadLength,
    BadVersion,
    BadKey,
    /// The server's signature did not verify, or its identity is not trusted.
    ServerAuth,
    /// The client's signature did not verify (or the server rejects it).
    ClientAuth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    TooLarge,
    BufferTooSmall,
    /// Wrong sequence number: replayed, dropped, or reordered.
    Sequence,
    /// Authentication tag mismatch: tampered or wrong key.
    Auth,
    Exhausted,
}

/// A long-term hybrid public identity.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    pub ed: [u8; ED_PUB_LEN],
    pub ml: Box<[u8; ML_PUB_LEN]>,
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity(")?;
        for b in self.id() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl Identity {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != IDENTITY_LEN {
            return None;
        }
        let mut ed = [0u8; ED_PUB_LEN];
        ed.copy_from_slice(&b[..ED_PUB_LEN]);
        let mut ml = Box::new([0u8; ML_PUB_LEN]);
        ml.copy_from_slice(&b[ED_PUB_LEN..]);
        Some(Self { ed, ml })
    }

    pub fn write_to(&self, out: &mut [u8]) {
        out[..ED_PUB_LEN].copy_from_slice(&self.ed);
        out[ED_PUB_LEN..IDENTITY_LEN].copy_from_slice(&self.ml[..]);
    }

    /// 16-byte fingerprint, the same construction as the kernel issuer id:
    /// `SHA-256("CDK-ISSUER-v1" ‖ ed ‖ ml)[..16]`.
    pub fn id(&self) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(b"CDK-ISSUER-v1");
        h.update(self.ed);
        h.update(&self.ml[..]);
        let d = h.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&d[..16]);
        id
    }
}

/// A hybrid signature: Ed25519 ‖ ML-DSA-65.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    pub ed: [u8; ED_SIG_LEN],
    pub ml: Box<[u8; ML_SIG_LEN]>,
}

impl Signature {
    fn from_bytes(b: &[u8]) -> Self {
        let mut ed = [0u8; ED_SIG_LEN];
        ed.copy_from_slice(&b[..ED_SIG_LEN]);
        let mut ml = Box::new([0u8; ML_SIG_LEN]);
        ml.copy_from_slice(&b[ED_SIG_LEN..SIG_LEN]);
        Self { ed, ml }
    }

    fn write_to(&self, out: &mut [u8]) {
        out[..ED_SIG_LEN].copy_from_slice(&self.ed);
        out[ED_SIG_LEN..SIG_LEN].copy_from_slice(&self.ml[..]);
    }
}

/// Hybrid Ed25519 + ML-DSA-65 keys for the link (the gateway's identity;
/// the kernel signs with its issuer, which uses the same format).
pub mod hybrid {
    use super::*;
    use ml_dsa::{signature::Keypair as _, EncodedSignature, EncodedVerifyingKey, MlDsa65};

    /// FIPS 204 context string for link signatures.
    pub const CONTEXT: &[u8] = b"CDK-LINK-v1";

    pub struct Keypair {
        ed: ed25519_dalek::SigningKey,
        ml: Box<ml_dsa::SigningKey<MlDsa65>>,
        public: Identity,
    }

    impl Keypair {
        pub fn from_seeds(ed_seed: &[u8; 32], ml_seed: &[u8; 32]) -> Self {
            let ed = ed25519_dalek::SigningKey::from_bytes(ed_seed);
            let mut seed = ml_dsa::B32::from(*ml_seed);
            let ml = Box::new(ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed));
            seed.zeroize();
            let mut mlp = Box::new([0u8; ML_PUB_LEN]);
            mlp.copy_from_slice(&ml.verifying_key().encode());
            let public = Identity {
                ed: ed.verifying_key().to_bytes(),
                ml: mlp,
            };
            Self { ed, ml, public }
        }

        pub fn public(&self) -> &Identity {
            &self.public
        }

        pub fn sign(&self, digest: &[u8; 32]) -> Signature {
            use ed25519_dalek::Signer;
            let ed = self.ed.sign(digest).to_bytes();
            let sig = self
                .ml
                .expanded_key()
                .sign_deterministic(digest, CONTEXT)
                .expect("context under 255 bytes");
            let mut ml = Box::new([0u8; ML_SIG_LEN]);
            ml.copy_from_slice(&sig.encode());
            Signature { ed, ml }
        }
    }

    /// Both halves must verify (Ed25519 strictly).
    pub fn verify(id: &Identity, digest: &[u8; 32], sig: &Signature) -> bool {
        let Ok(ed) = ed25519_dalek::VerifyingKey::from_bytes(&id.ed) else {
            return false;
        };
        if ed
            .verify_strict(digest, &ed25519_dalek::Signature::from_bytes(&sig.ed))
            .is_err()
        {
            return false;
        }
        let Ok(vk) = EncodedVerifyingKey::<MlDsa65>::try_from(&id.ml[..]) else {
            return false;
        };
        let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&vk);
        let Ok(enc) = EncodedSignature::<MlDsa65>::try_from(&sig.ml[..]) else {
            return false;
        };
        match ml_dsa::Signature::<MlDsa65>::decode(&enc) {
            Some(s) => vk.verify_with_context(digest, CONTEXT, &s),
            None => false,
        }
    }
}

fn digest(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PROTOCOL);
    h.update(b" ");
    h.update(label);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn derive(ch: &[u8], sh: &[u8], cf: &[u8], x_ss: &[u8; 32], kem_ss: &[u8]) -> ([u8; 32], [u8; 32]) {
    let salt = digest(b"keys", &[ch, sh, cf]);
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(x_ss);
    ikm[32..].copy_from_slice(kem_ss);
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm);
    ikm.zeroize();
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"CDK-LINK-v1 c2s", &mut c2s).expect("32 bytes");
    hk.expand(b"CDK-LINK-v1 s2c", &mut s2c).expect("32 bytes");
    (c2s, s2c)
}

/// Randomness for the client: X25519 secret, ML-KEM seed (64 B), nonce.
pub struct ClientRandom {
    pub x25519: [u8; 32],
    pub kem_seed: [u8; 64],
    pub nonce: [u8; 32],
}

/// Randomness for the server: X25519 secret, ML-KEM message, nonce.
pub struct ServerRandom {
    pub x25519: [u8; 32],
    pub kem_m: [u8; 32],
    pub nonce: [u8; 32],
}

pub struct ClientState {
    x_secret: x25519_dalek::StaticSecret,
    dk: Box<DecapsulationKey<MlKem768>>,
    ch: Vec<u8>,
}

/// Start the handshake: returns the state and `CH` (length [`CH_LEN`]).
pub fn client_hello(mut rnd: ClientRandom) -> (ClientState, Vec<u8>) {
    let x_secret = x25519_dalek::StaticSecret::from(rnd.x25519);
    let x_pub = x25519_dalek::PublicKey::from(&x_secret);
    let dk = Box::new(DecapsulationKey::<MlKem768>::from_seed(KemSeed::from(
        rnd.kem_seed,
    )));
    let mut ch = Vec::with_capacity(CH_LEN);
    ch.push(VERSION);
    ch.extend_from_slice(&rnd.nonce);
    ch.extend_from_slice(x_pub.as_bytes());
    ch.extend_from_slice(&dk.encapsulation_key().to_bytes());
    rnd.x25519.zeroize();
    rnd.kem_seed.zeroize();
    (
        ClientState {
            x_secret,
            dk,
            ch: ch.clone(),
        },
        ch,
    )
}

/// Finish as the client: check `SH`, authenticate the server (`trust`
/// verifies the signature *and* decides whether the identity is trusted),
/// sign the transcript with `sign`, and return the session, `CF`, and the
/// server's identity.
pub fn client_finish(
    state: ClientState,
    sh: &[u8],
    trust: impl FnOnce(&Identity, &[u8; 32], &Signature) -> bool,
    my_identity: &Identity,
    sign: impl FnOnce(&[u8; 32]) -> Signature,
) -> Result<(Session, Vec<u8>, Identity), HsError> {
    if sh.len() != SH_LEN {
        return Err(HsError::BadLength);
    }
    let mut off = NONCE_LEN;
    let mut x_pub = [0u8; 32];
    x_pub.copy_from_slice(&sh[off..off + X25519_LEN]);
    off += X25519_LEN;
    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(&sh[off..off + KEM_CT_LEN])
        .map_err(|_| HsError::BadKey)?;
    off += KEM_CT_LEN;
    let server = Identity::from_bytes(&sh[off..off + IDENTITY_LEN]).ok_or(HsError::BadLength)?;
    let server_sig = Signature::from_bytes(&sh[SH_UNSIGNED..]);
    let d = digest(b"server", &[&state.ch, &sh[..SH_UNSIGNED]]);
    if !trust(&server, &d, &server_sig) {
        return Err(HsError::ServerAuth);
    }

    let mut cf = alloc::vec![0u8; CF_LEN];
    my_identity.write_to(&mut cf[..IDENTITY_LEN]);
    let d = digest(b"client", &[&state.ch, sh, &cf[..IDENTITY_LEN]]);
    sign(&d).write_to(&mut cf[IDENTITY_LEN..]);

    let x_ss = state
        .x_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(x_pub));
    let kem_ss = state.dk.decapsulate(&ct);
    let (c2s, s2c) = derive(&state.ch, sh, &cf, x_ss.as_bytes(), &kem_ss);
    Ok((Session::new(&c2s, &s2c), cf, server))
}

pub struct ServerState {
    ch: Vec<u8>,
    sh: Vec<u8>,
    x_ss: [u8; 32],
    kem_ss: [u8; 32],
}

impl Drop for ServerState {
    fn drop(&mut self) {
        self.x_ss.zeroize();
        self.kem_ss.zeroize();
    }
}

/// Respond as the server: parse `CH`, encapsulate, sign; returns `SH`.
pub fn server_respond(
    ch: &[u8],
    mut rnd: ServerRandom,
    my_identity: &Identity,
    sign: impl FnOnce(&[u8; 32]) -> Signature,
) -> Result<(ServerState, Vec<u8>), HsError> {
    if ch.len() != CH_LEN {
        return Err(HsError::BadLength);
    }
    if ch[0] != VERSION {
        return Err(HsError::BadVersion);
    }
    let mut peer_x = [0u8; 32];
    peer_x.copy_from_slice(&ch[1 + NONCE_LEN..1 + NONCE_LEN + X25519_LEN]);
    let ek_bytes = &ch[1 + NONCE_LEN + X25519_LEN..];
    let ek_arr = ml_kem::Key::<ml_kem::EncapsulationKey<MlKem768>>::try_from(ek_bytes)
        .map_err(|_| HsError::BadKey)?;
    let ek = ml_kem::EncapsulationKey::<MlKem768>::new(&ek_arr).map_err(|_| HsError::BadKey)?;
    let (ct, kem_ss) = ek.encapsulate_deterministic(&KemB32::from(rnd.kem_m));

    let x_secret = x25519_dalek::StaticSecret::from(rnd.x25519);
    let x_pub = x25519_dalek::PublicKey::from(&x_secret);
    let x_ss = x_secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer_x));

    let mut sh = alloc::vec![0u8; SH_LEN];
    let mut off = 0;
    sh[off..off + NONCE_LEN].copy_from_slice(&rnd.nonce);
    off += NONCE_LEN;
    sh[off..off + X25519_LEN].copy_from_slice(x_pub.as_bytes());
    off += X25519_LEN;
    sh[off..off + KEM_CT_LEN].copy_from_slice(&ct);
    off += KEM_CT_LEN;
    my_identity.write_to(&mut sh[off..off + IDENTITY_LEN]);
    let d = digest(b"server", &[ch, &sh[..SH_UNSIGNED]]);
    sign(&d).write_to(&mut sh[SH_UNSIGNED..]);

    rnd.x25519.zeroize();
    rnd.kem_m.zeroize();
    let mut kem = [0u8; 32];
    kem.copy_from_slice(&kem_ss);
    Ok((
        ServerState {
            ch: ch.to_vec(),
            sh: sh.clone(),
            x_ss: *x_ss.as_bytes(),
            kem_ss: kem,
        },
        sh,
    ))
}

/// Finish as the server: authenticate the client (`trust` verifies its
/// signature and may apply a policy) and return the session and its
/// identity.
pub fn server_finish(
    state: ServerState,
    cf: &[u8],
    trust: impl FnOnce(&Identity, &[u8; 32], &Signature) -> bool,
) -> Result<(Session, Identity), HsError> {
    if cf.len() != CF_LEN {
        return Err(HsError::BadLength);
    }
    let client = Identity::from_bytes(&cf[..IDENTITY_LEN]).ok_or(HsError::BadLength)?;
    let sig = Signature::from_bytes(&cf[IDENTITY_LEN..]);
    let d = digest(b"client", &[&state.ch, &state.sh, &cf[..IDENTITY_LEN]]);
    if !trust(&client, &d, &sig) {
        return Err(HsError::ClientAuth);
    }
    let (c2s, s2c) = derive(&state.ch, &state.sh, cf, &state.x_ss, &state.kem_ss);
    // The server sends on s2c and receives on c2s.
    Ok((Session::new(&s2c, &c2s), client))
}

/// An established session: one AEAD key and sequence counter per direction.
pub struct Session {
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    tx_seq: u64,
    rx_seq: u64,
}

impl Session {
    fn new(tx_key: &[u8; 32], rx_key: &[u8; 32]) -> Self {
        Self {
            tx: ChaCha20Poly1305::new(tx_key.into()),
            rx: ChaCha20Poly1305::new(rx_key.into()),
            tx_seq: 0,
            rx_seq: 0,
        }
    }

    fn nonce(seq: u64) -> chacha20poly1305::Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&seq.to_le_bytes());
        n.into()
    }

    fn aad(seq: u64) -> [u8; 19] {
        let mut a = [0u8; 19];
        a[..11].copy_from_slice(PROTOCOL);
        a[11..].copy_from_slice(&seq.to_le_bytes());
        a
    }

    /// Seal `plaintext` into `out` (`seq ‖ ciphertext ‖ tag`); returns length.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, SealError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(SealError::TooLarge);
        }
        let total = 8 + plaintext.len() + 16;
        if out.len() < total {
            return Err(SealError::BufferTooSmall);
        }
        if self.tx_seq == u64::MAX {
            return Err(SealError::Exhausted);
        }
        let seq = self.tx_seq;
        out[..8].copy_from_slice(&seq.to_le_bytes());
        let body = &mut out[8..8 + plaintext.len()];
        body.copy_from_slice(plaintext);
        let tag = self
            .tx
            .encrypt_in_place_detached(&Self::nonce(seq), &Self::aad(seq), body)
            .map_err(|_| SealError::Auth)?;
        out[8 + plaintext.len()..total].copy_from_slice(&tag);
        self.tx_seq += 1;
        Ok(total)
    }

    /// Open a sealed message into `out`; returns the plaintext length. The
    /// sequence number must be exactly the next one expected.
    pub fn open(&mut self, sealed: &[u8], out: &mut [u8]) -> Result<usize, SealError> {
        if sealed.len() < SEAL_OVERHEAD {
            return Err(SealError::Auth);
        }
        let n = sealed.len() - SEAL_OVERHEAD;
        if out.len() < n {
            return Err(SealError::BufferTooSmall);
        }
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&sealed[..8]);
        let seq = u64::from_le_bytes(seq);
        if seq != self.rx_seq {
            return Err(SealError::Sequence);
        }
        let plain = &mut out[..n];
        plain.copy_from_slice(&sealed[8..8 + n]);
        let tag = chacha20poly1305::Tag::from_slice(&sealed[8 + n..]);
        if self
            .rx
            .decrypt_in_place_detached(&Self::nonce(seq), &Self::aad(seq), plain, tag)
            .is_err()
        {
            plain.zeroize();
            return Err(SealError::Auth);
        }
        self.rx_seq += 1;
        Ok(n)
    }
}

/// Split a handshake message into `(flags, chunk)` frames.
pub fn for_each_fragment(msg: &[u8], mut f: impl FnMut(u8, &[u8])) {
    let chunks = msg.chunks(crate::MAX_PAYLOAD);
    let last = msg.len().div_ceil(crate::MAX_PAYLOAD).max(1) - 1;
    if msg.is_empty() {
        f(0, &[]);
        return;
    }
    for (i, c) in chunks.enumerate() {
        f(if i < last { crate::FLAG_MORE } else { 0 }, c);
    }
}

/// A handshake message grew past [`Reassembler::MAX`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Oversized;

/// Reassembles fragmented handshake messages (up to 8 KiB).
pub struct Reassembler {
    buf: Vec<u8>,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub const MAX: usize = 8192;

    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Add a fragment; returns the whole message once the last fragment
    /// arrives, or `Err` (and resets) if it grows past [`Self::MAX`].
    pub fn push(&mut self, flags: u8, chunk: &[u8]) -> Result<Option<Vec<u8>>, Oversized> {
        if self.buf.len() + chunk.len() > Self::MAX {
            self.buf.clear();
            return Err(Oversized);
        }
        self.buf.extend_from_slice(chunk);
        if flags & crate::FLAG_MORE != 0 {
            return Ok(None);
        }
        Ok(Some(core::mem::take(&mut self.buf)))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    fn client_rnd(k: u8) -> ClientRandom {
        ClientRandom {
            x25519: [k; 32],
            kem_seed: [k.wrapping_add(1); 64],
            nonce: [k.wrapping_add(2); 32],
        }
    }

    fn server_rnd(k: u8) -> ServerRandom {
        ServerRandom {
            x25519: [k; 32],
            kem_m: [k.wrapping_add(1); 32],
            nonce: [k.wrapping_add(2); 32],
        }
    }

    struct Pair {
        client: Session,
        server: Session,
    }

    fn handshake(
        cli: &hybrid::Keypair,
        srv: &hybrid::Keypair,
        pinned: &Identity,
    ) -> Result<Pair, HsError> {
        let (cs, ch) = client_hello(client_rnd(1));
        assert_eq!(ch.len(), CH_LEN);
        let (ss, sh) = server_respond(&ch, server_rnd(9), srv.public(), |d| srv.sign(d))?;
        assert_eq!(sh.len(), SH_LEN);
        let (client, cf, server_id) = client_finish(
            cs,
            &sh,
            |id, d, s| id == pinned && hybrid::verify(id, d, s),
            cli.public(),
            |d| cli.sign(d),
        )?;
        assert_eq!(&server_id, srv.public());
        let (server, client_id) = server_finish(ss, &cf, hybrid::verify)?;
        assert_eq!(&client_id, cli.public());
        Ok(Pair { client, server })
    }

    fn keys() -> (hybrid::Keypair, hybrid::Keypair) {
        (
            hybrid::Keypair::from_seeds(&[1; 32], &[2; 32]),
            hybrid::Keypair::from_seeds(&[3; 32], &[4; 32]),
        )
    }

    #[test]
    fn handshake_establishes_matching_sessions() {
        let (cli, srv) = keys();
        let mut p = handshake(&cli, &srv, srv.public()).unwrap();
        let mut sealed = [0u8; 1024];
        let mut plain = [0u8; 1024];
        for msg in [&b"hello gateway"[..], b"", &[7u8; MAX_PLAINTEXT]] {
            let n = p.client.seal(msg, &mut sealed).unwrap();
            if !msg.is_empty() {
                assert_ne!(
                    &sealed[8..8 + msg.len()],
                    msg,
                    "ciphertext differs from plaintext"
                );
            }
            let m = p.server.open(&sealed[..n], &mut plain).unwrap();
            assert_eq!(&plain[..m], msg);
        }
        let n = p.server.seal(b"ack", &mut sealed).unwrap();
        let m = p.client.open(&sealed[..n], &mut plain).unwrap();
        assert_eq!(&plain[..m], b"ack");
    }

    #[test]
    fn unpinned_server_is_rejected() {
        let (cli, srv) = keys();
        let impostor = hybrid::Keypair::from_seeds(&[5; 32], &[6; 32]);
        // A validly signing server that isn't the pinned one (MITM).
        assert_eq!(
            handshake(&cli, &impostor, srv.public()).err(),
            Some(HsError::ServerAuth)
        );
    }

    #[test]
    fn tampered_server_hello_is_rejected() {
        let (cli, srv) = keys();
        let (cs, ch) = client_hello(client_rnd(1));
        let (_, mut sh) =
            server_respond(&ch, server_rnd(9), srv.public(), |d| srv.sign(d)).unwrap();
        sh[40] ^= 1; // flip a bit in the server's X25519 key
        let r = client_finish(
            cs,
            &sh,
            |id, d, s| id == srv.public() && hybrid::verify(id, d, s),
            cli.public(),
            |d| cli.sign(d),
        );
        assert_eq!(r.err(), Some(HsError::ServerAuth));
    }

    #[test]
    fn forged_client_signature_is_rejected() {
        let (cli, srv) = keys();
        let other = hybrid::Keypair::from_seeds(&[7; 32], &[8; 32]);
        let (cs, ch) = client_hello(client_rnd(1));
        let (ss, sh) = server_respond(&ch, server_rnd(9), srv.public(), |d| srv.sign(d)).unwrap();
        // Claims cli's identity but signs with another key.
        let (_, cf, _) =
            client_finish(cs, &sh, hybrid::verify, cli.public(), |d| other.sign(d)).unwrap();
        assert_eq!(
            server_finish(ss, &cf, hybrid::verify).err(),
            Some(HsError::ClientAuth)
        );
    }

    #[test]
    fn replay_reorder_and_tamper_are_rejected() {
        let (cli, srv) = keys();
        let mut p = handshake(&cli, &srv, srv.public()).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 64];
        let na = p.client.seal(b"first", &mut a).unwrap();
        let nb = p.client.seal(b"second", &mut b).unwrap();
        assert_eq!(
            p.server.open(&b[..nb], &mut out),
            Err(SealError::Sequence),
            "reorder"
        );
        p.server.open(&a[..na], &mut out).unwrap();
        assert_eq!(
            p.server.open(&a[..na], &mut out),
            Err(SealError::Sequence),
            "replay"
        );
        let mut t = b;
        t[9] ^= 1;
        assert_eq!(
            p.server.open(&t[..nb], &mut out),
            Err(SealError::Auth),
            "tamper"
        );
        p.server.open(&b[..nb], &mut out).unwrap();
        // Direction keys differ: a client frame can't be reflected back.
        let nc = p.client.seal(b"x", &mut a).unwrap();
        assert_eq!(p.client.open(&a[..nc], &mut out), Err(SealError::Sequence));
    }

    #[test]
    fn fragments_round_trip() {
        let msg: Vec<u8> = (0..SH_LEN).map(|i| i as u8).collect();
        let mut r = Reassembler::new();
        let mut got = None;
        let mut frames = 0;
        for_each_fragment(&msg, |flags, chunk| {
            frames += 1;
            assert!(chunk.len() <= crate::MAX_PAYLOAD);
            if let Some(m) = r.push(flags, chunk).unwrap() {
                got = Some(m);
            }
        });
        assert_eq!(frames, SH_LEN.div_ceil(crate::MAX_PAYLOAD));
        assert_eq!(got.unwrap(), msg);
        let mut r = Reassembler::new();
        let big = vec![0u8; crate::MAX_PAYLOAD];
        for _ in 0..8 {
            r.push(crate::FLAG_MORE, &big).unwrap();
        }
        assert!(r.push(0, &big).is_err());
    }

    /// Known answer: ML-KEM-768 key generation from seed 00..3f reproduces
    /// the IETF LAMPS example public key (ml-kem crate tests/examples).
    #[test]
    fn mlkem768_keygen_matches_ietf_example() {
        let mut seed = [0u8; 64];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        let dk = DecapsulationKey::<MlKem768>::from_seed(KemSeed::from(seed));
        let ek = dk.encapsulation_key().to_bytes();
        assert_eq!(ek.len(), KEM_EK_LEN);
        let h: [u8; 32] = Sha256::digest(&ek[..]).into();
        let hex: std::string::String = h.iter().map(|b| std::format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"
        );
    }

    #[test]
    fn identity_id_matches_kernel_issuer_construction() {
        let kp = hybrid::Keypair::from_seeds(&[1; 32], &[2; 32]);
        let mut h = Sha256::new();
        h.update(b"CDK-ISSUER-v1");
        h.update(kp.public().ed);
        h.update(&kp.public().ml[..]);
        assert_eq!(&kp.public().id()[..], &h.finalize()[..16]);
    }
}
