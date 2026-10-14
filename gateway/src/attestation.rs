//! Attestation of CDK's measured boot (roadmap 4.2).
//!
//! Right after each handshake the gateway sends a fresh nonce; CDK answers
//! with its boot verdict, release key id and measurement registers, and —
//! when it has a TPM — a TPM quote of PCRs 0..=10 over the same nonce.
//!
//! * `--expect FILE` (from `cdk-sign measure`): the registers must match.
//! * `--tpm FILE`: a TPM quote is required. Its ECDSA P-256 signature must
//!   verify, its PCR 8–10 values must equal the reported registers, and the
//!   attestation key and firmware PCRs 0–7 must equal the enrolled ones. If
//!   FILE does not exist yet, the first valid quote enrolls this machine
//!   (trust on first use, logged loudly).
//!
//! Until both pass, tools, models and approvals are refused.

use std::path::{Path, PathBuf};

use cdk_link::attest::{self, Message, REGISTERS};
use cdk_link::tpm::{self, QUOTED_PCRS};
use rand_core::{OsRng, RngCore};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// No (complete) answer yet for this session.
    Pending,
    /// Everything required matched.
    Trusted,
    Rejected,
}

/// An enrolled machine: its TPM attestation key and firmware PCRs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrollment {
    pub ak: [u8; 64],
    pub firmware: [[u8; 32]; 8],
}

impl Enrollment {
    fn parse(text: &str) -> Option<Self> {
        let mut ak = None;
        let mut firmware = [None; 8];
        for line in text
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter(|l| !l.is_empty())
        {
            let w: Vec<&str> = line.split_whitespace().collect();
            match w.as_slice() {
                ["ak", h] => ak = Some(unhex::<64>(h)?),
                ["pcr", i, h] => {
                    *firmware.get_mut(i.parse::<usize>().ok()?)? = Some(unhex::<32>(h)?)
                }
                _ => return None,
            }
        }
        let mut fw = [[0u8; 32]; 8];
        for (i, v) in firmware.iter().enumerate() {
            fw[i] = (*v)?;
        }
        Some(Enrollment {
            ak: ak?,
            firmware: fw,
        })
    }

    fn render(&self) -> String {
        let mut s = String::from(
            "# CDK TPM enrollment (cdk-gateway --tpm): attestation key and firmware PCRs 0-7\n",
        );
        s.push_str(&format!("ak {}\n", attest::hex(&self.ak)));
        for (i, p) in self.firmware.iter().enumerate() {
            s.push_str(&format!("pcr {i} {}\n", attest::hex(p)));
        }
        s
    }
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A verified quote from this session.
#[derive(Clone, Debug)]
struct Quoted {
    ak: [u8; 64],
    pcrs: [[u8; 32]; QUOTED_PCRS],
}

/// Verify the quote's ECDSA P-256 signature over its `TPMS_ATTEST`.
pub fn verify_quote_signature(q: &tpm::Quote<'_>) -> bool {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let point =
        p256::EncodedPoint::from_affine_coordinates((&q.ak_x).into(), (&q.ak_y).into(), false);
    let Ok(vk) = VerifyingKey::from_encoded_point(&point) else {
        return false;
    };
    let pad = |b: &[u8]| -> Option<[u8; 32]> {
        if b.len() > 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out[32 - b.len()..].copy_from_slice(b);
        Some(out)
    };
    let (Some(r), Some(s)) = (pad(q.sig_r), pad(q.sig_s)) else {
        return false;
    };
    let Ok(sig) = Signature::from_scalars(r, s) else {
        return false;
    };
    vk.verify(q.attest, &sig).is_ok()
}

pub struct Attestor {
    expect: Option<[[u8; 32]; REGISTERS]>,
    tpm_file: Option<PathBuf>,
    enrolled: Option<Enrollment>,
    nonce: [u8; 32],
    quote: Option<Result<Quoted, String>>,
    pub status: Status,
}

impl Attestor {
    pub fn new(expect: Option<[[u8; 32]; REGISTERS]>, tpm_file: Option<&Path>) -> Self {
        let enrolled = tpm_file
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| {
                Enrollment::parse(&t).unwrap_or_else(|| {
                    eprintln!("gateway: --tpm file is not a TPM enrollment");
                    std::process::exit(2)
                })
            });
        Attestor {
            expect,
            tpm_file: tpm_file.map(Path::to_path_buf),
            enrolled,
            nonce: [0; 32],
            quote: None,
            status: Status::Pending,
        }
    }

    /// Start attesting a new session; returns the request to send.
    pub fn request(&mut self) -> Vec<u8> {
        OsRng.fill_bytes(&mut self.nonce);
        self.status = Status::Pending;
        self.quote = None;
        attest::encode_request(&self.nonce)
    }

    /// Whether tool, model and approval traffic may be served.
    pub fn serving(&self) -> bool {
        if self.expect.is_some() || self.tpm_file.is_some() {
            self.status == Status::Trusted
        } else {
            self.status != Status::Rejected
        }
    }

    /// A TPM quote (CDK sends it just before its attestation).
    pub fn on_quote(&mut self, msg: &[u8]) {
        let result = (|| {
            let q = tpm::decode_quote(msg).ok_or("malformed TPM quote")?;
            if q.nonce != self.nonce {
                return Err("TPM quote for a stale or wrong nonce");
            }
            tpm::check_quote_contents(&q)?;
            if !verify_quote_signature(&q) {
                return Err("TPM quote signature does not verify");
            }
            let mut ak = [0u8; 64];
            ak[..32].copy_from_slice(&q.ak_x);
            ak[32..].copy_from_slice(&q.ak_y);
            Ok(Quoted { ak, pcrs: q.pcrs })
        })();
        match &result {
            Ok(q) => eprintln!(
                "gateway: <- TPM quote: signature verified (attestation key {}…), PCRs 0-10 match the quoted digest",
                attest::hex(&q.ak[..6])
            ),
            Err(e) => eprintln!("gateway: <- TPM quote REJECTED: {e}"),
        }
        self.quote = Some(result.map_err(str::to_string));
    }

    pub fn on_message(&mut self, msg: &[u8]) {
        let Some(Message::Attestation(a)) = attest::decode(msg) else {
            eprintln!("gateway: malformed attestation ignored");
            return;
        };
        if a.nonce != self.nonce {
            eprintln!("gateway: attestation with a stale or wrong nonce — REJECTED");
            self.status = Status::Rejected;
            return;
        }
        eprintln!(
            "gateway: <- attestation: boot {}, release key {}",
            a.verdict.name(),
            attest::hex(&a.release_id[..4])
        );
        for (i, r) in a.registers.iter().enumerate() {
            eprintln!("gateway:    register {i} {}", attest::hex(r));
        }
        let mut ok = true;
        match &self.expect {
            None => eprintln!("gateway: registers not checked (no --expect)"),
            Some(exp) if *exp == a.registers => {
                eprintln!("gateway: registers MATCH the expected measurements")
            }
            Some(exp) => {
                for (i, (got, want)) in a.registers.iter().zip(exp).enumerate() {
                    if got != want {
                        eprintln!(
                            "gateway:    register {i} differs: expected {}",
                            attest::hex(want)
                        );
                    }
                }
                eprintln!("gateway: registers do NOT match the expected measurements");
                ok = false;
            }
        }
        ok &= self.check_tpm(&a.registers);
        self.status = if ok {
            Status::Trusted
        } else {
            Status::Rejected
        };
        eprintln!(
            "gateway: attestation {}",
            if ok {
                "ACCEPTED — serving"
            } else {
                "REJECTED — refusing tools, models and approvals for this session"
            }
        );
    }

    fn check_tpm(&mut self, registers: &[[u8; 32]; REGISTERS]) -> bool {
        let quote = match (&self.quote, &self.tpm_file) {
            (None, None) => return true,
            (Some(Ok(_)), None) => {
                eprintln!("gateway: TPM quote verified (not required: no --tpm)");
                return true;
            }
            (Some(Err(_)), None) => return true, // already logged; not required
            (None, Some(_)) => {
                eprintln!("gateway: --tpm requires a TPM quote and CDK sent none");
                return false;
            }
            (Some(Err(_)), Some(_)) => return false,
            (Some(Ok(q)), Some(_)) => q.clone(),
        };
        for (i, reg) in registers.iter().enumerate() {
            if quote.pcrs[tpm::CDK_PCRS[i] as usize] != *reg {
                eprintln!("gateway: TPM PCR {} differs from reported register {i} — the kernel's report is not what the TPM holds", tpm::CDK_PCRS[i]);
                return false;
            }
        }
        let mut firmware = [[0u8; 32]; 8];
        firmware.copy_from_slice(&quote.pcrs[..8]);
        let seen = Enrollment {
            ak: quote.ak,
            firmware,
        };
        match &self.enrolled {
            Some(e) if *e == seen => {
                eprintln!("gateway: TPM matches the enrolled machine (attestation key and firmware PCRs 0-7)");
                true
            }
            Some(e) => {
                if e.ak != seen.ak {
                    eprintln!("gateway: TPM attestation key differs from the enrolled one — another machine or a reset TPM");
                }
                for i in 0..8 {
                    if e.firmware[i] != seen.firmware[i] {
                        eprintln!(
                            "gateway: firmware PCR {i} differs from enrollment: {} (enrolled {})",
                            attest::hex(&seen.firmware[i][..8]),
                            attest::hex(&e.firmware[i][..8])
                        );
                    }
                }
                false
            }
            None => {
                let path = self.tpm_file.clone().expect("checked above");
                match std::fs::write(&path, seen.render()) {
                    Ok(()) => {
                        eprintln!(
                            "gateway: ENROLLED this machine's TPM (trust on first use) -> {}",
                            path.display()
                        );
                        self.enrolled = Some(seen);
                        true
                    }
                    Err(e) => {
                        eprintln!(
                            "gateway: could not write enrollment {}: {e}",
                            path.display()
                        );
                        false
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk_link::attest::{encode_attestation, expected_registers, Attestation, Verdict};
    use p256::ecdsa::signature::Signer;

    fn answer(at: &Attestor, regs: [[u8; 32]; REGISTERS]) -> Vec<u8> {
        encode_attestation(&Attestation {
            nonce: at.nonce,
            verdict: Verdict::Verified,
            release_id: [1; 16],
            registers: regs,
            log: "",
        })
    }

    fn tpms_attest(nonce: &[u8], pcrs: &[[u8; 32]]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&tpm::TPM_GENERATED_VALUE.to_be_bytes());
        a.extend_from_slice(&tpm::TPM_ST_ATTEST_QUOTE.to_be_bytes());
        a.extend_from_slice(&[0, 0]);
        a.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        a.extend_from_slice(nonce);
        a.extend_from_slice(&[0; 25]);
        a.extend_from_slice(&1u32.to_be_bytes());
        a.extend_from_slice(&tpm::TPM_ALG_SHA256.to_be_bytes());
        a.push(3);
        a.extend_from_slice(&tpm::PCR_SELECT);
        a.extend_from_slice(&32u16.to_be_bytes());
        a.extend_from_slice(&tpm::pcr_digest(pcrs));
        a
    }

    /// A quote as the TPM would sign it, with AK seed `k`.
    fn quote(at: &Attestor, k: u8, pcrs: [[u8; 32]; QUOTED_PCRS]) -> Vec<u8> {
        let sk = p256::ecdsa::SigningKey::from_bytes(&[k; 32].into()).unwrap();
        let pt = sk.verifying_key().to_encoded_point(false);
        let att = tpms_attest(&at.nonce, &pcrs);
        let sig: p256::ecdsa::Signature = sk.sign(&att);
        let (r, s) = sig.split_bytes();
        tpm::encode_quote(&tpm::Quote {
            nonce: at.nonce,
            ak_x: pt.x().unwrap().as_slice().try_into().unwrap(),
            ak_y: pt.y().unwrap().as_slice().try_into().unwrap(),
            pcrs,
            attest: &att,
            sig_r: &r,
            sig_s: &s,
        })
        .unwrap()
    }

    fn pcrs_for(regs: &[[u8; 32]; REGISTERS], fw: u8) -> [[u8; 32]; QUOTED_PCRS] {
        let mut p = [[fw; 32]; QUOTED_PCRS];
        for (i, r) in regs.iter().enumerate() {
            p[tpm::CDK_PCRS[i] as usize] = *r;
        }
        p
    }

    #[test]
    fn serves_only_matching_fresh_attestations() {
        let good = expected_registers(b"k", b"r", Verdict::Verified, &[1; 16]);
        let bad = expected_registers(b"k", b"r2", Verdict::Verified, &[1; 16]);
        let mut a = Attestor::new(Some(good), None);
        a.request();
        assert!(!a.serving(), "nothing before the answer");
        a.on_message(&answer(&a, good));
        assert!(a.serving());
        a.request();
        a.on_message(&answer(&a, bad));
        assert!(!a.serving());
        let old = answer(&a, good);
        a.request();
        a.on_message(&old);
        assert_eq!(a.status, Status::Rejected, "replayed answer");
        let mut b = Attestor::new(None, None);
        b.request();
        assert!(b.serving());
        b.on_message(&old);
        assert!(!b.serving());
    }

    #[test]
    fn tpm_enrollment_then_matching() {
        let regs = expected_registers(b"k", b"r", Verdict::Verified, &[1; 16]);
        let file = std::env::temp_dir().join(format!("cdk-tpm-enroll-{}", std::process::id()));
        let _ = std::fs::remove_file(&file);

        // First contact enrolls.
        let mut a = Attestor::new(Some(regs), Some(&file));
        a.request();
        a.on_quote(&quote(&a, 7, pcrs_for(&regs, 0x33)));
        a.on_message(&answer(&a, regs));
        assert!(a.serving());
        assert!(file.exists());

        // Same machine, next boot: accepted.
        let mut b = Attestor::new(Some(regs), Some(&file));
        b.request();
        b.on_quote(&quote(&b, 7, pcrs_for(&regs, 0x33)));
        b.on_message(&answer(&b, regs));
        assert!(b.serving());

        // Another TPM (clone of the disk on other hardware): rejected.
        b.request();
        b.on_quote(&quote(&b, 8, pcrs_for(&regs, 0x33)));
        b.on_message(&answer(&b, regs));
        assert!(!b.serving());

        // Different firmware: rejected.
        b.request();
        b.on_quote(&quote(&b, 7, pcrs_for(&regs, 0x44)));
        b.on_message(&answer(&b, regs));
        assert!(!b.serving());

        // A kernel reporting registers the TPM does not hold: rejected.
        let other = expected_registers(b"k", b"r2", Verdict::Verified, &[1; 16]);
        let mut c = Attestor::new(None, Some(&file));
        c.request();
        c.on_quote(&quote(&c, 7, pcrs_for(&other, 0x33)));
        c.on_message(&answer(&c, regs));
        assert!(!c.serving());

        // No quote at all: rejected when --tpm is set.
        c.request();
        c.on_message(&answer(&c, regs));
        assert!(!c.serving());

        // Tampered quote (signature no longer verifies): rejected.
        c.request();
        let mut q = quote(&c, 7, pcrs_for(&regs, 0x33));
        let n = q.len();
        q[n - 1] ^= 1;
        c.on_quote(&q);
        c.on_message(&answer(&c, regs));
        assert!(!c.serving());
        std::fs::remove_file(&file).unwrap();
    }
}
