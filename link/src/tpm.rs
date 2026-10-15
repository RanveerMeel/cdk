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

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub const QUOTE: u8 = 0x32;
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

#[cfg(test)]
mod tests {
    use super::*;

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
