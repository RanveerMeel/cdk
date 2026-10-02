//! Framed link to the host gateway (roadmap 3.1), over [`virtio_console`].
//!
//! Frames use the shared `cdk-link` crate, so the kernel and the host
//! gateway speak byte-identical framing and handshake.
//!
//! [`secure_connect`] runs the post-quantum handshake (roadmap 3.2): hybrid
//! X25519 + ML-KEM-768 key exchange, the kernel authenticates with its
//! issuer (Ed25519 + ML-DSA-65, domain `CDK-LINK-v1`), and the gateway must
//! present the identity pinned in the boot ramdisk (`gateway.pub`). After
//! that, [`send_data`] seals and [`recv`] opens every message
//! (ChaCha20-Poly1305, strictly ordered sequence numbers).
//!
//! [`virtio_console`]: crate::virtio_console

extern crate alloc;

use alloc::vec::Vec;

use cdk_link::secure::{self, Identity, Reassembler, Session, Signature};
use cdk_link::{kind, Decoder, MAX_FRAME};
use rand_core::RngCore;
use spin::Mutex;

use crate::issuer::{self, HybridSignature, IssuerPublic, SigDomain};
use crate::virtio_console;

static DECODER: Mutex<Decoder> = Mutex::new(Decoder::new());
static SESSION: Mutex<Option<Established>> = Mutex::new(None);

/// Ramdisk file holding the pinned gateway identity (Ed25519 ‖ ML-DSA-65).
pub const PINNED_GATEWAY_FILE: &str = "gateway.pub";

struct Established {
    session: Session,
    gateway: Identity,
}

/// Send one frame.
pub fn send(kind: u8, payload: &[u8]) -> Result<(), &'static str> {
    send_flags(kind, 0, payload)
}

fn send_flags(kind: u8, flags: u8, payload: &[u8]) -> Result<(), &'static str> {
    let mut buf = [0u8; MAX_FRAME];
    let n = cdk_link::encode_with_flags(kind, flags, payload, &mut buf)
        .map_err(|_| "frame too large")?;
    virtio_console::write_all(&buf[..n])
}

/// Whether a secure session is established.
pub fn is_secure() -> bool {
    SESSION.lock().is_some()
}

/// Fingerprint of the gateway of the current session.
pub fn gateway_id() -> Option<[u8; 16]> {
    SESSION.lock().as_ref().map(|e| e.gateway.id())
}

/// The gateway identity pinned in the boot ramdisk, if any.
pub fn pinned_gateway() -> Option<Identity> {
    crate::initrd::find(PINNED_GATEWAY_FILE).and_then(|f| Identity::from_bytes(f.data))
}

/// Why a secure handshake failed (also the audit `detail` code).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureError {
    NoLink = 1,
    NoPinnedGateway = 2,
    Timeout = 3,
    /// The gateway's signature failed or it is not the pinned gateway.
    GatewayRejected = 4,
    Protocol = 5,
}

/// Run the post-quantum handshake with the gateway and keep the session.
pub fn secure_connect(timeout_ms: u64) -> Result<[u8; 16], SecureError> {
    let result = secure_connect_inner(timeout_ms);
    match &result {
        Ok(id) => crate::audit::record_fmt(
            crate::audit::EventKind::LinkEstablished,
            format_args!(
                "gateway:{:02x}{:02x}{:02x}{:02x}",
                id[0], id[1], id[2], id[3]
            ),
            1,
        ),
        Err(e) => crate::audit::record(crate::audit::EventKind::LinkRejected, "gateway", *e as u64),
    }
    result
}

fn secure_connect_inner(timeout_ms: u64) -> Result<[u8; 16], SecureError> {
    if !virtio_console::is_ready() {
        return Err(SecureError::NoLink);
    }
    let pinned = pinned_gateway().ok_or(SecureError::NoPinnedGateway)?;
    let issuer = issuer::kernel();
    let me = Identity {
        ed: issuer.public().ed25519,
        ml: issuer.public().mldsa65.clone(),
    };

    let mut rnd = secure::ClientRandom {
        x25519: [0; 32],
        kem_seed: [0; 64],
        nonce: [0; 32],
    };
    let mut rng = crate::rng::KernelRng;
    rng.fill_bytes(&mut rnd.x25519);
    rng.fill_bytes(&mut rnd.kem_seed);
    rng.fill_bytes(&mut rnd.nonce);
    // ML-KEM key generation needs more stack than kernel stacks provide.
    let (state, ch) = issuer::crypto_stack::run(|| secure::client_hello(rnd));
    *SESSION.lock() = None;
    send_message(&ch).map_err(|_| SecureError::NoLink)?;

    let sh = wait_handshake(timeout_ms).ok_or(SecureError::Timeout)?;
    let result = issuer::crypto_stack::run(|| {
        secure::client_finish(
            state,
            &sh,
            |id, digest, sig| *id == pinned && verify_hybrid(id, digest, sig),
            &me,
            |digest| {
                let s = issuer.sign(SigDomain::Link, digest);
                Signature {
                    ed: s.ed25519,
                    ml: s.mldsa65,
                }
            },
        )
    });
    let (session, cf, gateway) = match result {
        Ok(v) => v,
        Err(secure::HsError::ServerAuth) => return Err(SecureError::GatewayRejected),
        Err(_) => return Err(SecureError::Protocol),
    };
    send_message(&cf).map_err(|_| SecureError::NoLink)?;
    let id = gateway.id();
    *SESSION.lock() = Some(Established { session, gateway });
    Ok(id)
}

fn verify_hybrid(id: &Identity, digest: &[u8; 32], sig: &Signature) -> bool {
    let public = IssuerPublic {
        id: id.id(),
        ed25519: id.ed,
        mldsa65: id.ml.clone(),
    };
    let sig = HybridSignature {
        ed25519: sig.ed,
        mldsa65: sig.ml.clone(),
    };
    public.verify(SigDomain::Link, digest, &sig)
}

/// Send a handshake message as fragments.
fn send_message(msg: &[u8]) -> Result<(), &'static str> {
    let mut result = Ok(());
    secure::for_each_fragment(msg, |flags, chunk| {
        if result.is_ok() {
            result = send_flags(kind::HANDSHAKE, flags, chunk);
        }
    });
    result
}

/// Wait for one complete handshake message.
fn wait_handshake(timeout_ms: u64) -> Option<Vec<u8>> {
    let start = crate::cpu::rdtsc();
    let limit = timeout_ms.saturating_mul(2_000_000);
    let mut re = Reassembler::new();
    let mut done = None;
    while done.is_none() && crate::cpu::rdtsc().wrapping_sub(start) < limit {
        let mut dec = DECODER.lock();
        virtio_console::poll(|mut bytes| {
            while !bytes.is_empty() {
                let n = dec.push(bytes);
                bytes = &bytes[n..];
                while let Some(f) = dec.next_frame() {
                    if f.kind == kind::HANDSHAKE && done.is_none() {
                        if let Ok(Some(m)) = re.push(f.flags, f.payload) {
                            done = Some(m);
                        }
                    }
                }
            }
        });
        drop(dec);
        core::hint::spin_loop();
    }
    done
}

/// Send application data: sealed if a secure session exists, otherwise a
/// plaintext `DATA` frame. Returns whether it was sealed.
pub fn send_data(data: &[u8]) -> Result<bool, &'static str> {
    let mut guard = SESSION.lock();
    match guard.as_mut() {
        Some(est) => {
            let mut sealed = [0u8; cdk_link::MAX_PAYLOAD];
            let n = est
                .session
                .seal(data, &mut sealed)
                .map_err(|_| "message too large to seal")?;
            drop(guard);
            send(kind::SEALED, &sealed[..n]).map(|_| true)
        }
        None => {
            drop(guard);
            send(kind::DATA, data).map(|_| false)
        }
    }
}

/// A received message, after decryption.
pub enum Incoming<'a> {
    /// A plaintext frame.
    Plain(u8, &'a [u8]),
    /// Data that arrived sealed and authenticated.
    Sealed(&'a [u8]),
    /// A sealed frame that failed to open (tampered, replayed, reordered,
    /// or no session); the session is kept.
    Rejected(secure::SealError),
}

/// Like [`poll`], but opens sealed frames with the current session.
pub fn recv(mut f: impl FnMut(Incoming<'_>)) -> usize {
    poll(|k, p| {
        if k != kind::SEALED {
            f(Incoming::Plain(k, p));
            return;
        }
        let mut guard = SESSION.lock();
        let Some(est) = guard.as_mut() else {
            drop(guard);
            f(Incoming::Rejected(secure::SealError::Auth));
            return;
        };
        let mut plain = [0u8; cdk_link::MAX_PAYLOAD];
        let opened = est.session.open(p, &mut plain);
        drop(guard);
        match opened {
            Ok(n) => f(Incoming::Sealed(&plain[..n])),
            Err(e) => f(Incoming::Rejected(e)),
        }
    })
}

/// Drain the device and hand each complete frame to `f(kind, payload)`.
/// Returns the number of frames delivered.
pub fn poll(mut f: impl FnMut(u8, &[u8])) -> usize {
    let mut dec = DECODER.lock();
    let mut frames = 0;
    virtio_console::poll(|mut bytes| {
        while !bytes.is_empty() {
            let n = dec.push(bytes);
            bytes = &bytes[n..];
            while let Some(frame) = dec.next_frame() {
                frames += 1;
                f(frame.kind, frame.payload);
            }
        }
    });
    frames
}

/// Decoder counters (frames, CRC errors, skipped bytes).
pub fn decoder_stats() -> cdk_link::DecoderStats {
    DECODER.lock().stats
}

/// Send a `PING` with `nonce` and wait up to ~`timeout_ms` for the matching
/// `PONG`. Other frames that arrive meanwhile go to `other`. Returns the
/// round trip in TSC cycles.
pub fn ping(
    nonce: u64,
    timeout_ms: u64,
    mut other: impl FnMut(u8, &[u8]),
) -> Result<u64, &'static str> {
    let start = crate::cpu::rdtsc();
    send(kind::PING, &nonce.to_le_bytes())?;
    // ~2 GHz TSC assumed; coarse on purpose.
    let limit = timeout_ms.saturating_mul(2_000_000);
    loop {
        let mut rtt = None;
        poll(|k, p| {
            if k == kind::PONG && p == nonce.to_le_bytes() {
                rtt = Some(crate::cpu::rdtsc().wrapping_sub(start));
            } else {
                other(k, p);
            }
        });
        if let Some(r) = rtt {
            return Ok(r);
        }
        if crate::cpu::rdtsc().wrapping_sub(start) > limit {
            return Err("no PONG (is the gateway connected?)");
        }
        core::hint::spin_loop();
    }
}
