//! TPM 2.0 quotes (roadmap 4.2, hardware root): the message CDK sends with
//! its attestation, and parsing of the TPM-signed `TPMS_ATTEST` structure.
//! Shared by the kernel (which builds TPM commands) and the gateway (which
//! verifies quotes). Signature verification itself (ECDSA P-256) is done by
//! the gateway.
//!
//! CDK replays its three boot measurements into PCRs [`CDK_PCRS`] (8, 9,
//! 10), so they equal the software registers of [`crate::attest`]; the
//! firmware measures early boot into PCRs 0–7 (under UEFI, PCR 4 includes
//! CDK's measuring loader), and that loader measures the kernel file and
//! the ramdisk into [`LOADER_PCRS`] (11, 12) before the kernel runs. A
//! quote covers PCRs 0–12.
//!
//! ```text
//! Quote : 0x32 | nonce [32] | AK x [32] | AK y [32] | PCR 0..=10 [11 × 32]
//!              | attest_len u16 | TPMS_ATTEST | r_len u8 | r | s_len u8 | s
//!   (PCRs are 0..=12: 13 × 32 bytes)
//! ```
//!
//! **Endorsement** (`cdk-gateway --tpm-ca`): proof that the attestation key
//! lives in a TPM certified by its manufacturer. When the attestation request
//! asks for it ([`PROVE_ENDORSEMENT`]), CDK also creates the TPM's standard
//! endorsement key (EK, TCG EK Credential Profile template L-2: ECC P-256)
//! and sends it with the manufacturer's EK certificate from NV index
//! [`EK_CERT_NV_INDEX`]. The gateway checks the certificate chain, then
//! `TPM2_MakeCredential`: a secret encrypted to the EK and bound to the AK's
//! name, which only `TPM2_ActivateCredential` in the TPM holding both keys
//! can recover.
//!
//! ```text
//! EkChunk   : 0x33 | total u16 | offset u16 | bytes   ┐ reassembled:
//!                                                     ┘ EK x [32] | EK y [32] | cert DER
//! Challenge : 0x34 | id_len u16 | TPM2B_ID_OBJECT body | secret_len u16 | TPM2B_ENCRYPTED_SECRET body
//! Proof     : 0x35 | len u8 | recovered secret
//! ```

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub const QUOTE: u8 = 0x32;
pub const EK_CHUNK: u8 = 0x33;
pub const CHALLENGE: u8 = 0x34;
pub const PROOF: u8 = 0x35;
/// Attestation-request flag: prove the AK with the endorsement key.
pub const PROVE_ENDORSEMENT: u8 = 0x01;
/// NV index of the ECC NIST P-256 EK certificate (TCG EK Credential Profile).
pub const EK_CERT_NV_INDEX: u32 = 0x01c0_000a;
/// Largest EK blob (EK point + certificate) accepted.
pub const MAX_EK_BLOB: usize = 4096;
/// Bytes of EK blob per chunk message.
pub const EK_CHUNK_DATA: usize = 512;
/// PCRs a quote covers: 0..=12.
pub const QUOTED_PCRS: usize = 13;
/// PCRs CDK extends with its measurement registers.
pub const CDK_PCRS: [u32; 3] = [8, 9, 10];
/// PCRs CDK's measuring UEFI loader extends before the kernel runs: the
/// kernel ELF file and the ramdisk.
pub const LOADER_PCRS: [u32; 2] = [11, 12];
/// `TPMS_PCR_SELECT` bitmap for PCRs 0..=12.
pub const PCR_SELECT: [u8; 3] = [0xFF, 0x1F, 0x00];

/// What the measuring loader puts in PCRs 11 and 12 for these files.
pub fn expected_loader_pcrs(kernel_file: &[u8], ramdisk: &[u8]) -> [[u8; 32]; 2] {
    let mut out = [[0u8; 32]; 2];
    crate::attest::extend(&mut out[0], &Sha256::digest(kernel_file).into());
    crate::attest::extend(&mut out[1], &Sha256::digest(ramdisk).into());
    out
}

pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
pub const TPM_ALG_SHA256: u16 = 0x000B;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quote<'a> {
    pub nonce: [u8; 32],
    /// Attestation key public point (P-256, uncompressed x, y).
    pub ak_x: [u8; 32],
    pub ak_y: [u8; 32],
    pub pcrs: [[u8; 32]; QUOTED_PCRS],
    /// The TPM-generated `TPMS_ATTEST` the signature covers.
    pub attest: &'a [u8],
    pub sig_r: &'a [u8],
    pub sig_s: &'a [u8],
}

pub fn encode_quote(q: &Quote<'_>) -> Option<Vec<u8>> {
    if q.attest.len() > 512 || q.sig_r.len() > 66 || q.sig_s.len() > 66 {
        return None;
    }
    let mut m = Vec::new();
    m.push(QUOTE);
    m.extend_from_slice(&q.nonce);
    m.extend_from_slice(&q.ak_x);
    m.extend_from_slice(&q.ak_y);
    for p in &q.pcrs {
        m.extend_from_slice(p);
    }
    m.extend_from_slice(&(q.attest.len() as u16).to_le_bytes());
    m.extend_from_slice(q.attest);
    m.push(q.sig_r.len() as u8);
    m.extend_from_slice(q.sig_r);
    m.push(q.sig_s.len() as u8);
    m.extend_from_slice(q.sig_s);
    (m.len() <= crate::secure::MAX_PLAINTEXT).then_some(m)
}

pub fn is_quote(msg: &[u8]) -> bool {
    msg.first() == Some(&QUOTE)
}

pub fn decode_quote(b: &[u8]) -> Option<Quote<'_>> {
    let r = b.strip_prefix(&[QUOTE])?;
    let arr = |o: usize| -> Option<[u8; 32]> { r.get(o..o + 32)?.try_into().ok() };
    let nonce = arr(0)?;
    let ak_x = arr(32)?;
    let ak_y = arr(64)?;
    let mut pcrs = [[0u8; 32]; QUOTED_PCRS];
    for (i, p) in pcrs.iter_mut().enumerate() {
        *p = arr(96 + 32 * i)?;
    }
    let mut o = 96 + 32 * QUOTED_PCRS;
    let alen = u16::from_le_bytes(r.get(o..o + 2)?.try_into().ok()?) as usize;
    o += 2;
    let attest = r.get(o..o + alen)?;
    o += alen;
    let rlen = *r.get(o)? as usize;
    let sig_r = r.get(o + 1..o + 1 + rlen)?;
    o += 1 + rlen;
    let slen = *r.get(o)? as usize;
    let sig_s = r.get(o + 1..o + 1 + slen)?;
    if r.len() != o + 1 + slen || alen > 512 || rlen > 66 || slen > 66 {
        return None;
    }
    Some(Quote {
        nonce,
        ak_x,
        ak_y,
        pcrs,
        attest,
        sig_r,
        sig_s,
    })
}

/// What a `TPMS_QUOTE_INFO` reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteInfo<'a> {
    pub extra_data: &'a [u8],
    /// `(hash algorithm, select bitmap)` per selection.
    pub selection: Vec<(u16, &'a [u8])>,
    pub pcr_digest: &'a [u8],
}

/// Parse a TPM-generated `TPMS_ATTEST` of type quote (big-endian, TPM 2.0
/// Part 2 §10.12). Every length is bounds-checked.
pub fn parse_attest(b: &[u8]) -> Option<QuoteInfo<'_>> {
    let mut o = 0usize;
    let u16_at = |o: usize| Some(u16::from_be_bytes(b.get(o..o + 2)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_be_bytes(b.get(o..o + 4)?.try_into().ok()?));
    if u32_at(o)? != TPM_GENERATED_VALUE {
        return None;
    }
    o += 4;
    if u16_at(o)? != TPM_ST_ATTEST_QUOTE {
        return None;
    }
    o += 2;
    let signer = u16_at(o)? as usize; // qualifiedSigner TPM2B_NAME
    o += 2 + signer;
    let extra_len = u16_at(o)? as usize; // extraData TPM2B_DATA
    let extra_data = b.get(o + 2..o + 2 + extra_len)?;
    o += 2 + extra_len;
    o += 8 + 4 + 4 + 1; // clockInfo: clock, resetCount, restartCount, safe
    o += 8; // firmwareVersion
    let count = u32_at(o)? as usize; // TPML_PCR_SELECTION
    o += 4;
    if count > 4 {
        return None;
    }
    let mut selection = Vec::new();
    for _ in 0..count {
        let alg = u16_at(o)?;
        let size = *b.get(o + 2)? as usize;
        selection.push((alg, b.get(o + 3..o + 3 + size)?));
        o += 3 + size;
    }
    let dlen = u16_at(o)? as usize; // pcrDigest TPM2B_DIGEST
    let pcr_digest = b.get(o + 2..o + 2 + dlen)?;
    if o + 2 + dlen != b.len() {
        return None;
    }
    Some(QuoteInfo {
        extra_data,
        selection,
        pcr_digest,
    })
}

/// The `pcrDigest` a quote of `pcrs` (in selection order) carries.
pub fn pcr_digest(pcrs: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in pcrs {
        h.update(p);
    }
    h.finalize().into()
}

/// Everything about a quote except its signature: the attest structure is
/// a quote over PCRs 0..=10 (SHA-256), for `nonce`, whose digest matches
/// the reported PCR values. The caller must still verify the signature.
pub fn check_quote_contents(q: &Quote<'_>) -> Result<(), &'static str> {
    let info = parse_attest(q.attest).ok_or("not a TPM-generated quote structure")?;
    if info.extra_data != q.nonce {
        return Err("quote is not for this nonce");
    }
    if info.selection.len() != 1 || info.selection[0] != (TPM_ALG_SHA256, &PCR_SELECT[..]) {
        return Err("quote covers other PCRs (expected 0-12)");
    }
    if info.pcr_digest != pcr_digest(&q.pcrs) {
        return Err("reported PCR values do not match the quoted digest");
    }
    Ok(())
}

pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_AES: u16 = 0x0006;
pub const TPM_ALG_CFB: u16 = 0x0043;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ECC_NIST_P256: u16 = 0x0003;

/// AK: fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA |
/// restricted | sign. `noDA`: the key has an empty authorization value, so
/// there is nothing to guess; without it the TPM's dictionary-attack
/// protection, which counts every unclean power-off, eventually refuses
/// quotes (TPM_RC_LOCKOUT).
pub const AK_ATTRIBUTES: u32 =
    0x0000_0002 | 0x0000_0010 | 0x0000_0020 | 0x0000_0040 | 0x0000_0400 | 0x0001_0000 | 0x0004_0000;
/// EK (template L-2): fixedTPM | fixedParent | sensitiveDataOrigin |
/// adminWithPolicy | restricted | decrypt.
pub const EK_ATTRIBUTES: u32 =
    0x0000_0002 | 0x0000_0010 | 0x0000_0020 | 0x0000_0080 | 0x0001_0000 | 0x0002_0000;
/// EK authPolicy: `PolicySecret(TPM_RH_ENDORSEMENT)` (TCG EK Credential Profile).
pub const EK_POLICY: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
];

fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn put2b(v: &mut Vec<u8>, b: &[u8]) {
    put16(v, b.len() as u16);
    v.extend_from_slice(b);
}

/// The AK's `TPMT_PUBLIC`: with `unique = None` the template CDK passes to
/// `TPM2_CreatePrimary`, with the point the public area the TPM returns.
pub fn ak_public(unique: Option<(&[u8; 32], &[u8; 32])>) -> Vec<u8> {
    let mut v = Vec::with_capacity(90);
    put16(&mut v, TPM_ALG_ECC);
    put16(&mut v, TPM_ALG_SHA256);
    v.extend_from_slice(&AK_ATTRIBUTES.to_be_bytes());
    put2b(&mut v, &[]); // authPolicy
    put16(&mut v, TPM_ALG_NULL); // symmetric
    put16(&mut v, TPM_ALG_ECDSA);
    put16(&mut v, TPM_ALG_SHA256); // scheme
    put16(&mut v, TPM_ECC_NIST_P256);
    put16(&mut v, TPM_ALG_NULL); // kdf
    match unique {
        Some((x, y)) => {
            put2b(&mut v, x);
            put2b(&mut v, y);
        }
        None => {
            put2b(&mut v, &[]);
            put2b(&mut v, &[]);
        }
    }
    v
}

/// The EK's `TPMT_PUBLIC` (template L-2). The template's unique field is
/// two 32-byte zero buffers; the TPM returns the point there.
pub fn ek_public(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(124);
    put16(&mut v, TPM_ALG_ECC);
    put16(&mut v, TPM_ALG_SHA256);
    v.extend_from_slice(&EK_ATTRIBUTES.to_be_bytes());
    put2b(&mut v, &EK_POLICY);
    put16(&mut v, TPM_ALG_AES);
    put16(&mut v, 128);
    put16(&mut v, TPM_ALG_CFB);
    put16(&mut v, TPM_ALG_NULL); // scheme
    put16(&mut v, TPM_ECC_NIST_P256);
    put16(&mut v, TPM_ALG_NULL); // kdf
    put2b(&mut v, x);
    put2b(&mut v, y);
    v
}

/// A TPM object's name: `nameAlg ‖ SHA-256(TPMT_PUBLIC)`.
pub fn name(public: &[u8]) -> [u8; 34] {
    let mut n = [0u8; 34];
    n[..2].copy_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    n[2..].copy_from_slice(&Sha256::digest(public));
    n
}

/// Split the EK blob (`EK x ‖ EK y ‖ certificate`) into chunk messages.
pub fn encode_ek_chunks(x: &[u8; 32], y: &[u8; 32], cert: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut blob = Vec::with_capacity(64 + cert.len());
    blob.extend_from_slice(x);
    blob.extend_from_slice(y);
    blob.extend_from_slice(cert);
    if blob.len() > MAX_EK_BLOB {
        return None;
    }
    let total = blob.len() as u16;
    Some(
        blob.chunks(EK_CHUNK_DATA)
            .enumerate()
            .map(|(i, c)| {
                let mut m = Vec::with_capacity(5 + c.len());
                m.push(EK_CHUNK);
                m.extend_from_slice(&total.to_le_bytes());
                m.extend_from_slice(&((i * EK_CHUNK_DATA) as u16).to_le_bytes());
                m.extend_from_slice(c);
                m
            })
            .collect(),
    )
}

/// Reassembles EK chunks, which must arrive in order.
#[derive(Default)]
pub struct EkAssembler {
    blob: Vec<u8>,
    total: usize,
}

/// A complete EK blob.
pub struct EkBlob<'a> {
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub cert: &'a [u8],
}

impl EkAssembler {
    /// Add one chunk; `Err` for a malformed or out-of-order chunk.
    pub fn push(&mut self, msg: &[u8]) -> Result<(), &'static str> {
        let r = msg.strip_prefix(&[EK_CHUNK]).ok_or("not an EK chunk")?;
        let total = u16::from_le_bytes(
            r.get(0..2)
                .ok_or("short EK chunk")?
                .try_into()
                .unwrap_or([0; 2]),
        ) as usize;
        let offset = u16::from_le_bytes(
            r.get(2..4)
                .ok_or("short EK chunk")?
                .try_into()
                .unwrap_or([0; 2]),
        ) as usize;
        let data = &r[4..];
        if !(64..=MAX_EK_BLOB).contains(&total) || data.is_empty() || data.len() > EK_CHUNK_DATA {
            return Err("EK chunk with a bad size");
        }
        if offset == 0 {
            self.blob.clear();
            self.total = total;
        }
        if total != self.total || offset != self.blob.len() || offset + data.len() > total {
            return Err("EK chunk out of order");
        }
        self.blob.extend_from_slice(data);
        Ok(())
    }

    pub fn complete(&self) -> Option<EkBlob<'_>> {
        if self.total == 0 || self.blob.len() != self.total {
            return None;
        }
        Some(EkBlob {
            x: self.blob[..32].try_into().ok()?,
            y: self.blob[32..64].try_into().ok()?,
            cert: &self.blob[64..],
        })
    }
}

/// `TPM2_MakeCredential` output: the bodies of `TPM2B_ID_OBJECT` and
/// `TPM2B_ENCRYPTED_SECRET`.
pub fn encode_challenge(id_object: &[u8], secret: &[u8]) -> Option<Vec<u8>> {
    if id_object.len() > 256 || secret.len() > 256 {
        return None;
    }
    let mut m = Vec::with_capacity(5 + id_object.len() + secret.len());
    m.push(CHALLENGE);
    m.extend_from_slice(&(id_object.len() as u16).to_le_bytes());
    m.extend_from_slice(id_object);
    m.extend_from_slice(&(secret.len() as u16).to_le_bytes());
    m.extend_from_slice(secret);
    Some(m)
}

/// `(id_object, secret)` of a challenge.
pub fn decode_challenge(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let r = b.strip_prefix(&[CHALLENGE])?;
    let ilen = u16::from_le_bytes(r.get(0..2)?.try_into().ok()?) as usize;
    let id_object = r.get(2..2 + ilen)?;
    let o = 2 + ilen;
    let slen = u16::from_le_bytes(r.get(o..o + 2)?.try_into().ok()?) as usize;
    let secret = r.get(o + 2..o + 2 + slen)?;
    if r.len() != o + 2 + slen || ilen > 256 || slen > 256 {
        return None;
    }
    Some((id_object, secret))
}

pub fn encode_proof(recovered: &[u8]) -> Option<Vec<u8>> {
    if recovered.len() > 64 {
        return None;
    }
    let mut m = alloc::vec![PROOF, recovered.len() as u8];
    m.extend_from_slice(recovered);
    Some(m)
}

pub fn decode_proof(b: &[u8]) -> Option<&[u8]> {
    let r = b.strip_prefix(&[PROOF])?;
    let (&len, rest) = r.split_first()?;
    (rest.len() == len as usize && len <= 64).then_some(rest)
}

/// Messages of the endorsement exchange (chunk, challenge, proof).
pub fn is_endorsement(msg: &[u8]) -> bool {
    matches!(msg.first(), Some(&(EK_CHUNK | CHALLENGE | PROOF)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ek_blob_chunks_reassemble() {
        let cert: Vec<u8> = (0..1500u32).map(|i| i as u8).collect();
        let msgs = encode_ek_chunks(&[1; 32], &[2; 32], &cert).unwrap();
        assert_eq!(msgs.len(), 4);
        assert!(msgs.iter().all(|m| m.len() <= crate::secure::MAX_PLAINTEXT));
        let mut a = EkAssembler::default();
        for m in &msgs {
            assert!(a.complete().is_none());
            a.push(m).unwrap();
        }
        let b = a.complete().unwrap();
        assert_eq!((b.x, b.y, b.cert), ([1; 32], [2; 32], &cert[..]));
        // Out of order, or a chunk past the end: refused.
        let mut a = EkAssembler::default();
        a.push(&msgs[0]).unwrap();
        assert!(a.push(&msgs[2]).is_err());
        let mut long = msgs[3].clone();
        long.extend_from_slice(&[0; 200]);
        let mut a = EkAssembler::default();
        for m in &msgs[..3] {
            a.push(m).unwrap();
        }
        assert!(a.push(&long).is_err());
        assert!(encode_ek_chunks(&[0; 32], &[0; 32], &[0; MAX_EK_BLOB]).is_none());
    }

    #[test]
    fn challenge_and_proof_round_trip() {
        let m = encode_challenge(&[7; 68], &[8; 68]).unwrap();
        assert_eq!(decode_challenge(&m), Some((&[7u8; 68][..], &[8u8; 68][..])));
        assert_eq!(decode_challenge(&m[..m.len() - 1]), None);
        let p = encode_proof(&[9; 32]).unwrap();
        assert_eq!(decode_proof(&p), Some(&[9u8; 32][..]));
        assert_eq!(decode_proof(&p[..10]), None);
    }

    #[test]
    fn templates_and_names() {
        // The AK template as CDK has always sent it (TPMT_PUBLIC, 24 bytes).
        assert_eq!(ak_public(None).len(), 24);
        assert_eq!(ak_public(Some((&[1; 32], &[2; 32]))).len(), 24 + 64);
        // EK template L-2 is 122 bytes with its 32-byte zero unique fields.
        assert_eq!(ek_public(&[0; 32], &[0; 32]).len(), 122);
        assert_eq!(&name(b"x")[..2], &[0x00, 0x0B]);
    }

    /// A TPMS_ATTEST as a TPM would produce it.
    pub(crate) fn attest(nonce: &[u8], pcrs: &[[u8; 32]]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        a.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        a.extend_from_slice(&34u16.to_be_bytes());
        a.extend_from_slice(&[0x00, 0x0B]);
        a.extend_from_slice(&[0x11; 32]); // signer name
        a.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        a.extend_from_slice(nonce);
        a.extend_from_slice(&[0; 17]); // clockInfo
        a.extend_from_slice(&[0; 8]); // firmwareVersion
        a.extend_from_slice(&1u32.to_be_bytes());
        a.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        a.push(3);
        a.extend_from_slice(&PCR_SELECT);
        a.extend_from_slice(&32u16.to_be_bytes());
        a.extend_from_slice(&pcr_digest(pcrs));
        a
    }

    #[test]
    fn quote_round_trip_and_checks() {
        let pcrs = [[3u8; 32]; QUOTED_PCRS];
        let att = attest(&[9; 32], &pcrs);
        let q = Quote {
            nonce: [9; 32],
            ak_x: [1; 32],
            ak_y: [2; 32],
            pcrs,
            attest: &att,
            sig_r: &[5; 32],
            sig_s: &[6; 32],
        };
        let m = encode_quote(&q).unwrap();
        assert!(m.len() <= crate::secure::MAX_PLAINTEXT);
        assert_eq!(decode_quote(&m), Some(q.clone()));
        assert_eq!(check_quote_contents(&q), Ok(()));

        let mut other = q.clone();
        other.nonce = [8; 32];
        assert_eq!(
            check_quote_contents(&other),
            Err("quote is not for this nonce")
        );
        let mut lied = q.clone();
        lied.pcrs[9] = [0; 32];
        assert_eq!(
            check_quote_contents(&lied),
            Err("reported PCR values do not match the quoted digest")
        );
        let mut bad = att.clone();
        bad[0] ^= 1;
        assert_eq!(parse_attest(&bad), None);
        let mut trailing = att.clone();
        trailing.push(0);
        assert_eq!(parse_attest(&trailing), None);
        assert_eq!(decode_quote(&m[..m.len() - 1]), None);
    }
}
