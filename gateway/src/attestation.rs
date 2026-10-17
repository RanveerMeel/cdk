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
//!   (trust on first use, logged loudly — unless `--tpm-ca` is also set).
//! * `--tpm-ca DIR`: the TPM must prove it is genuine. CDK sends the TPM's
//!   endorsement key (EK) and the manufacturer's EK certificate; the
//!   certificate must chain to a root CA in DIR ([`crate::ekcert`]) and
//!   certify that EK; then a `TPM2_MakeCredential` challenge
//!   ([`crate::credential`]) bound to the attestation key's name must come
//!   back decrypted, which only the TPM holding both keys can do. With
//!   `--tpm` too, a machine is enrolled only after this proof.
//!
//! Until all of these pass, tools, models and approvals are refused.

use std::path::{Path, PathBuf};

use cdk_link::attest::{self, Message, REGISTERS};
use cdk_link::tpm::{self, QUOTED_PCRS};
use rand_core::{OsRng, RngCore};

use crate::ekcert::{Certificate, PublicKey, TrustStore};

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

/// Constant-time equality of two byte strings of public length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub struct Attestor {
    expect: Option<[[u8; 32]; REGISTERS]>,
    /// Expected PCRs 11-12 from the measuring loader (UEFI boots).
    expect_loader: Option<[[u8; 32]; 2]>,
    tpm_file: Option<PathBuf>,
    enrolled: Option<Enrollment>,
    /// TPM manufacturer CAs (`--tpm-ca`): endorsement proof required.
    trust: Option<TrustStore>,
    nonce: [u8; 32],
    quote: Option<Result<Quoted, String>>,
    ek_chunks: tpm::EkAssembler,
    /// The certified endorsement key `(x, y)`, or why it is not.
    ek: Option<Result<([u8; 32], [u8; 32]), String>>,
    /// The secret of the challenge sent this session.
    credential: Option<[u8; 32]>,
    ek_proven: Option<Result<(), String>>,
    /// Outcome of everything but the endorsement proof.
    attest_ok: Option<bool>,
    /// A first enrollment waiting for the endorsement proof.
    pending_enrollment: Option<Enrollment>,
    pub status: Status,
}

impl Attestor {
    pub fn new(
        expect: Option<[[u8; 32]; REGISTERS]>,
        expect_loader: Option<[[u8; 32]; 2]>,
        tpm_file: Option<&Path>,
        trust: Option<TrustStore>,
    ) -> Self {
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
            expect_loader,
            tpm_file: tpm_file.map(Path::to_path_buf),
            enrolled,
            trust,
            nonce: [0; 32],
            quote: None,
            ek_chunks: tpm::EkAssembler::default(),
            ek: None,
            credential: None,
            ek_proven: None,
            attest_ok: None,
            pending_enrollment: None,
            status: Status::Pending,
        }
    }

    /// Start attesting a new session; returns the request to send.
    pub fn request(&mut self) -> Vec<u8> {
        OsRng.fill_bytes(&mut self.nonce);
        self.status = Status::Pending;
        self.quote = None;
        self.ek_chunks = tpm::EkAssembler::default();
        self.ek = None;
        self.credential = None;
        self.ek_proven = None;
        self.attest_ok = None;
        self.pending_enrollment = None;
        let flags = if self.trust.is_some() {
            tpm::PROVE_ENDORSEMENT
        } else {
            0
        };
        attest::encode_request(&self.nonce, flags)
    }

    /// Whether a TPM quote is required.
    fn tpm_required(&self) -> bool {
        self.tpm_file.is_some() || self.trust.is_some()
    }

    /// Whether tool, model and approval traffic may be served.
    pub fn serving(&self) -> bool {
        if self.expect.is_some() || self.tpm_required() {
            self.status == Status::Trusted
        } else {
            self.status != Status::Rejected
        }
    }

    /// Endorsement messages: EK chunks (CDK sends them before its quote)
    /// and the answer to the credential challenge.
    pub fn on_endorsement(&mut self, msg: &[u8]) {
        if self.trust.is_none() {
            eprintln!("gateway: endorsement message ignored (no --tpm-ca)");
            return;
        }
        match msg.first() {
            Some(&tpm::EK_CHUNK) => {
                if self.ek.is_some() {
                    eprintln!("gateway: endorsement key already received; chunk ignored");
                    return;
                }
                if let Err(e) = self.ek_chunks.push(msg) {
                    self.ek = Some(Err(e.to_string()));
                    return;
                }
                if self.ek_chunks.complete().is_some() {
                    let r = self.check_ek();
                    match &r {
                        Ok(_) => {}
                        Err(e) => eprintln!("gateway: <- endorsement key REJECTED: {e}"),
                    }
                    self.ek = Some(r);
                }
            }
            Some(&tpm::PROOF) => {
                if self.ek_proven.is_some() {
                    // One answer per challenge: a second one cannot overturn
                    // the first (no guessing the secret over retries).
                    eprintln!("gateway: second endorsement proof ignored");
                    return;
                }
                let r = match (tpm::decode_proof(msg), &self.credential) {
                    (Some(got), Some(want)) if ct_eq(got, want) => Ok(()),
                    (Some(_), Some(_)) => {
                        Err("the TPM did not recover the challenge secret".to_string())
                    }
                    _ => Err("unexpected or malformed endorsement proof".to_string()),
                };
                match &r {
                    Ok(()) => eprintln!("gateway: <- endorsement proof: the attestation key is in the certified TPM (credential activated)"),
                    Err(e) => eprintln!("gateway: <- endorsement proof REJECTED: {e}"),
                }
                self.ek_proven = Some(r);
                self.finish();
            }
            _ => eprintln!("gateway: unexpected endorsement message ignored"),
        }
    }

    /// The EK certificate chains to a trusted manufacturer and certifies
    /// the EK that CDK's TPM created.
    fn check_ek(&self) -> Result<([u8; 32], [u8; 32]), String> {
        let blob = self.ek_chunks.complete().ok_or("incomplete")?;
        let trust = self.trust.as_ref().ok_or("no trust store")?;
        let cert = Certificate::parse(blob.cert).ok_or("EK certificate is not valid X.509 DER")?;
        let mut point = vec![4u8];
        point.extend_from_slice(&blob.x);
        point.extend_from_slice(&blob.y);
        if cert.key != PublicKey::P256(point) {
            return Err("the EK certificate does not certify the TPM's endorsement key".into());
        }
        // Only an EK certificate vouches for a TPM-resident decryption key:
        // a CA's or another kind of certificate from the same vendor CA
        // could name a key whose private half exists outside any TPM.
        if cert.is_ca || !cert.ek_usage {
            return Err("not an EK certificate (needs the TCG EK extended key usage 2.23.133.8.1, and must not be a CA)".into());
        }
        let path = trust.verify(&cert)?;
        eprintln!(
            "gateway: <- endorsement key {}… certified: {}",
            attest::hex(&blob.x[..6]),
            path.join(" <- ")
        );
        Ok((blob.x, blob.y))
    }

    /// A TPM quote (CDK sends it just before its attestation). With
    /// `--tpm-ca`, returns the credential challenge to send CDK.
    pub fn on_quote(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        if self.quote.is_some() {
            eprintln!("gateway: second TPM quote in this session ignored");
            return None;
        }
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
                "gateway: <- TPM quote: signature verified (attestation key {}…), PCRs 0-12 match the quoted digest",
                attest::hex(&q.ak[..6])
            ),
            Err(e) => eprintln!("gateway: <- TPM quote REJECTED: {e}"),
        }
        self.quote = Some(result.map_err(str::to_string));
        self.trust.as_ref()?;
        let ak = match &self.quote {
            Some(Ok(q)) => q.ak,
            _ => return None,
        };
        let (x, y) = match &self.ek {
            Some(Ok(ek)) => *ek,
            Some(Err(_)) => return None, // already logged
            None => {
                self.ek_proven = Some(Err(
                    "CDK sent no endorsement key and certificate (no EK certificate in its TPM?)"
                        .into(),
                ));
                eprintln!("gateway: CDK sent no endorsement key and certificate");
                return None;
            }
        };
        let (ak_x, ak_y) = (ak[..32].try_into().ok()?, ak[32..].try_into().ok()?);
        let name = tpm::name(&tpm::ak_public(Some((ak_x, ak_y))));
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        match crate::credential::make_credential(&x, &y, &name, &secret)
            .ok()
            .and_then(|(id, enc)| tpm::encode_challenge(&id, &enc))
        {
            Some(m) => {
                self.credential = Some(secret);
                eprintln!("gateway: -> credential challenge (bound to the attestation key, encrypted to the endorsement key)");
                Some(m)
            }
            None => {
                self.ek_proven = Some(Err("could not build the credential challenge".into()));
                None
            }
        }
    }

    pub fn on_message(&mut self, msg: &[u8]) {
        if self.attest_ok.is_some() || self.status != Status::Pending {
            eprintln!("gateway: second attestation in this session ignored");
            return;
        }
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
        self.attest_ok = Some(ok);
        self.finish();
    }

    /// Decide once the attestation (and, with `--tpm-ca`, the endorsement
    /// proof) are in.
    fn finish(&mut self) {
        if self.status != Status::Pending {
            return; // decided: only a new request (new session) starts over
        }
        let Some(mut ok) = self.attest_ok else {
            return;
        };
        if self.trust.is_some() && ok {
            match &self.ek_proven {
                Some(Ok(())) => {}
                Some(Err(e)) => {
                    eprintln!("gateway: TPM endorsement not proven: {e}");
                    ok = false;
                }
                None if self.credential.is_some() => {
                    eprintln!("gateway: waiting for the endorsement proof");
                    return;
                }
                None => {
                    eprintln!("gateway: TPM endorsement not proven (no valid endorsement key)");
                    ok = false;
                }
            }
        }
        if let Some(seen) = self.pending_enrollment.take() {
            ok = ok && self.enroll(seen, "certified TPM: endorsement proven");
        }
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

    fn enroll(&mut self, seen: Enrollment, how: &str) -> bool {
        let path = self.tpm_file.clone().expect("enrollment needs --tpm");
        match std::fs::write(&path, seen.render()) {
            Ok(()) => {
                eprintln!(
                    "gateway: ENROLLED this machine's TPM ({how}) -> {}",
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

    fn check_tpm(&mut self, registers: &[[u8; 32]; REGISTERS]) -> bool {
        let quote = match (&self.quote, self.tpm_required()) {
            (None, false) => return true,
            (Some(Ok(_)), false) => {
                eprintln!("gateway: TPM quote verified (not required: no --tpm)");
                return true;
            }
            (Some(Err(_)), false) => return true, // already logged; not required
            (None, true) => {
                eprintln!("gateway: --tpm/--tpm-ca require a TPM quote and CDK sent none");
                return false;
            }
            (Some(Err(_)), true) => return false,
            (Some(Ok(q)), true) => q.clone(),
        };
        for (i, reg) in registers.iter().enumerate() {
            if quote.pcrs[tpm::CDK_PCRS[i] as usize] != *reg {
                eprintln!("gateway: TPM PCR {} differs from reported register {i} — the kernel's report is not what the TPM holds", tpm::CDK_PCRS[i]);
                return false;
            }
        }
        if let Some(exp) = &self.expect_loader {
            for (i, pcr) in tpm::LOADER_PCRS.iter().enumerate() {
                let got = quote.pcrs[*pcr as usize];
                if got == [0; 32] {
                    eprintln!("gateway: PCR {pcr} is empty — CDK was not started by the measuring loader (BIOS boot?)");
                    return false;
                }
                if got != exp[i] {
                    eprintln!(
                        "gateway: PCR {pcr} (measured by the loader before the kernel ran) differs from the build: {} (expected {})",
                        attest::hex(&got[..8]),
                        attest::hex(&exp[i][..8])
                    );
                    return false;
                }
            }
            eprintln!(
                "gateway: PCRs 11-12 (kernel and ramdisk, measured by the loader) MATCH the build"
            );
        }
        if self.tpm_file.is_none() {
            return true; // --tpm-ca without enrollment: any certified TPM
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
            None if self.trust.is_some() => {
                self.pending_enrollment = Some(seen); // after the endorsement proof
                true
            }
            None => self.enroll(seen, "trust on first use"),
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
        let mut a = Attestor::new(Some(good), None, None, None);
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
        let mut b = Attestor::new(None, None, None, None);
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
        let mut a = Attestor::new(Some(regs), None, Some(&file), None);
        a.request();
        a.on_quote(&quote(&a, 7, pcrs_for(&regs, 0x33)));
        a.on_message(&answer(&a, regs));
        assert!(a.serving());
        assert!(file.exists());

        // Same machine, next boot: accepted.
        let mut b = Attestor::new(Some(regs), None, Some(&file), None);
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
        let mut c = Attestor::new(None, None, Some(&file), None);
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

    #[test]
    fn loader_pcrs_must_match_the_build() {
        let regs = expected_registers(b"k", b"r", Verdict::Verified, &[1; 16]);
        let loader = tpm::expected_loader_pcrs(b"kernel elf", b"r");
        let file = std::env::temp_dir().join(format!("cdk-tpm-loader-{}", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let with_loader = |l: Option<[[u8; 32]; 2]>| {
            let mut p = pcrs_for(&regs, 0x33);
            if let Some(l) = l {
                p[11] = l[0];
                p[12] = l[1];
            }
            p
        };
        let mut a = Attestor::new(Some(regs), Some(loader), Some(&file), None);
        a.request();
        a.on_quote(&quote(&a, 7, with_loader(Some(loader))));
        a.on_message(&answer(&a, regs));
        assert!(a.serving(), "measured by the loader, matching the build");

        // Another kernel file measured by the loader: refused.
        let other = tpm::expected_loader_pcrs(b"other kernel", b"r");
        a.request();
        a.on_quote(&quote(&a, 7, with_loader(Some(other))));
        a.on_message(&answer(&a, regs));
        assert!(!a.serving());

        // Not started by the measuring loader (BIOS boot): refused.
        a.request();
        a.on_quote(&quote(&a, 7, with_loader(None)));
        a.on_message(&answer(&a, regs));
        assert!(!a.serving());
        std::fs::remove_file(&file).unwrap();
    }

    fn trust() -> TrustStore {
        let pem = |b: &[u8]| Certificate::parse(&crate::ekcert::decode_certs(b)[0]).unwrap();
        TrustStore::from_certs(vec![
            pem(include_bytes!("../tests/data/tpm-ca-root.pem")),
            pem(include_bytes!("../tests/data/tpm-ca-issuer.pem")),
        ])
    }

    /// The fixture EK certificate's key.
    fn ek_point() -> ([u8; 32], [u8; 32]) {
        let c = Certificate::parse(include_bytes!("../tests/data/ek-p256.der")).unwrap();
        let PublicKey::P256(k) = c.key else { panic!() };
        (k[1..33].try_into().unwrap(), k[33..65].try_into().unwrap())
    }

    #[test]
    fn endorsement_is_required_with_tpm_ca() {
        let regs = expected_registers(b"k", b"r", Verdict::Verified, &[1; 16]);
        let cert: &[u8] = include_bytes!("../tests/data/ek-p256.der");
        let (x, y) = ek_point();
        let mut a = Attestor::new(Some(regs), None, None, Some(trust()));
        let req = a.request();
        assert_eq!(req.last(), Some(&tpm::PROVE_ENDORSEMENT), "asks for the EK");

        // Certified EK: the quote is answered with a challenge, and nothing
        // is served until the proof comes back.
        for m in tpm::encode_ek_chunks(&x, &y, cert).unwrap() {
            a.on_endorsement(&m);
        }
        assert!(matches!(a.ek, Some(Ok(_))));
        let challenge = a.on_quote(&quote(&a, 7, pcrs_for(&regs, 0x33)));
        assert!(challenge
            .as_deref()
            .and_then(tpm::decode_challenge)
            .is_some());
        a.on_message(&answer(&a, regs));
        assert_eq!(a.status, Status::Pending);
        assert!(!a.serving());
        // A wrong answer (not the TPM that holds the EK): rejected.
        a.on_endorsement(&tpm::encode_proof(&[0; 32]).unwrap());
        assert!(!a.serving());

        // The right answer: served.
        a.request();
        for m in tpm::encode_ek_chunks(&x, &y, cert).unwrap() {
            a.on_endorsement(&m);
        }
        a.on_quote(&quote(&a, 7, pcrs_for(&regs, 0x33)));
        a.on_message(&answer(&a, regs));
        let secret = a.credential.unwrap();
        a.on_endorsement(&tpm::encode_proof(&secret).unwrap());
        assert!(a.serving());

        // A certificate for another key than the TPM's EK: rejected.
        a.request();
        for m in tpm::encode_ek_chunks(&y, &x, cert).unwrap() {
            a.on_endorsement(&m);
        }
        assert!(a.on_quote(&quote(&a, 7, pcrs_for(&regs, 0x33))).is_none());
        a.on_message(&answer(&a, regs));
        assert_eq!(a.status, Status::Rejected);

        // No EK at all (TPM without a certificate): rejected.
        a.request();
        assert!(a.on_quote(&quote(&a, 7, pcrs_for(&regs, 0x33))).is_none());
        a.on_message(&answer(&a, regs));
        assert_eq!(a.status, Status::Rejected);

        // No TPM at all: rejected.
        a.request();
        a.on_message(&answer(&a, regs));
        assert_eq!(a.status, Status::Rejected);
    }

    #[test]
    fn first_enrollment_waits_for_the_endorsement_proof() {
        let regs = expected_registers(b"k", b"r", Verdict::Verified, &[1; 16]);
        let cert: &[u8] = include_bytes!("../tests/data/ek-p256.der");
        let (x, y) = ek_point();
        let file = std::env::temp_dir().join(format!("cdk-tpm-ek-enroll-{}", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let mut a = Attestor::new(Some(regs), None, Some(&file), Some(trust()));
        a.request();
        for m in tpm::encode_ek_chunks(&x, &y, cert).unwrap() {
            a.on_endorsement(&m);
        }
        a.on_quote(&quote(&a, 7, pcrs_for(&regs, 0x33)));
        a.on_message(&answer(&a, regs));
        assert!(!file.exists(), "not enrolled before the proof");
        a.on_endorsement(&tpm::encode_proof(&[1; 32]).unwrap());
        assert!(!file.exists(), "not enrolled after a failed proof");
        a.request();
        for m in tpm::encode_ek_chunks(&x, &y, cert).unwrap() {
            a.on_endorsement(&m);
        }
        a.on_quote(&quote(&a, 7, pcrs_for(&regs, 0x33)));
        a.on_message(&answer(&a, regs));
        let secret = a.credential.unwrap();
        a.on_endorsement(&tpm::encode_proof(&secret).unwrap());
        assert!(a.serving() && file.exists());
        std::fs::remove_file(&file).unwrap();
    }

    /// Security review 2026-10-16: one proof per challenge, and a decided
    /// session stays decided.
    #[test]
    fn a_rejected_session_cannot_be_overturned() {
        let regs = expected_registers(b"k", b"r", Verdict::Verified, &[1; 16]);
        let cert: &[u8] = include_bytes!("../tests/data/ek-p256.der");
        let (x, y) = ek_point();
        let mut a = Attestor::new(Some(regs), None, None, Some(trust()));
        a.request();
        for m in tpm::encode_ek_chunks(&x, &y, cert).unwrap() {
            a.on_endorsement(&m);
        }
        a.on_quote(&quote(&a, 7, pcrs_for(&regs, 0x33)));
        a.on_message(&answer(&a, regs));
        let secret = a.credential.unwrap();
        a.on_endorsement(&tpm::encode_proof(&[0; 32]).unwrap());
        assert_eq!(a.status, Status::Rejected);
        // The right answer afterwards: still rejected (no retries).
        a.on_endorsement(&tpm::encode_proof(&secret).unwrap());
        assert_eq!(a.status, Status::Rejected);
        // Nor does a second attestation, quote or EK change anything.
        a.on_message(&answer(&a, regs));
        assert!(a.on_quote(&quote(&a, 7, pcrs_for(&regs, 0x33))).is_none());
        assert_eq!(a.status, Status::Rejected);

        // Without --tpm-ca: a rejected attestation stays rejected too.
        let other = expected_registers(b"k", b"r2", Verdict::Verified, &[1; 16]);
        let mut b = Attestor::new(Some(regs), None, None, None);
        b.request();
        b.on_message(&answer(&b, other));
        b.on_message(&answer(&b, regs));
        assert!(!b.serving());
    }

    /// Security review 2026-10-16: only an EK certificate vouches for an
    /// endorsement key, even from a trusted manufacturer CA.
    #[test]
    fn only_ek_certificates_are_accepted() {
        let regs = expected_registers(b"k", b"r", Verdict::Verified, &[1; 16]);
        let (x, y) = ek_point();
        for (what, cert) in [
            (
                "no TCG EK usage",
                &include_bytes!("../tests/data/ek-p256-no-eku.der")[..],
            ),
            (
                "a CA certificate",
                &include_bytes!("../tests/data/ek-p256-as-ca.der")[..],
            ),
        ] {
            let c = Certificate::parse(cert).unwrap();
            assert!(
                trust().verify(&c).is_ok(),
                "{what}: chains to the trusted root"
            );
            let mut a = Attestor::new(Some(regs), None, None, Some(trust()));
            a.request();
            for m in tpm::encode_ek_chunks(&x, &y, cert).unwrap() {
                a.on_endorsement(&m);
            }
            assert!(matches!(a.ek, Some(Err(_))), "{what}: refused");
            assert!(a.on_quote(&quote(&a, 7, pcrs_for(&regs, 0x33))).is_none());
            a.on_message(&answer(&a, regs));
            assert_eq!(a.status, Status::Rejected, "{what}");
        }
    }
}
