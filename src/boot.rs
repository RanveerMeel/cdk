//! Verified and measured boot (roadmap 4.2).
//!
//! **Verified boot.** The release public key is compiled into the kernel
//! (`build.rs`, from `cdk-sign init`). At boot, before any pinned key is
//! trusted, [`measure_and_verify`] checks the ramdisk's `boot.manifest`
//! against its release-key signature (hybrid Ed25519 + ML-DSA-65, context
//! `CDK-BOOT-v1`) and every ramdisk file against the manifest. If anything
//! fails the kernel **locks down**: the ramdisk is hidden (no programs, no
//! pinned gateway or operator keys, no boot policy), no process may be
//! spawned, and every policy change is refused. A kernel built without a
//! release key boots unverified and says so.
//!
//! **Measured boot.** Register 0 measures the kernel ELF image as loaded
//! (its read-only segments: code, read-only data, headers),
//! register 1 the ramdisk archive, register 2 the verdict and release key
//! ([`cdk_link::attest`]). Measurements are audit-logged.
//!
//! **Attestation.** After the post-quantum handshake the gateway asks for
//! the registers with a fresh nonce ([`attestation`]); with `--expect` it
//! serves nothing to a CDK whose registers differ from the build's.
//!
//! **Limits.** The registers live in kernel memory, not a TPM: a modified
//! kernel could report false values. They become hardware-rooted when they
//! are also extended into a TPM (or measured by firmware Secure Boot) —
//! future work. Verification already protects the ramdisk: changing a
//! program, `gateway.pub`, an operator key or `policy.rules` without the
//! release key locks the kernel down.

extern crate alloc;

use alloc::string::String;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};

use cdk_link::attest::{self, ManifestError, Verdict, REGISTERS};
use cdk_link::secure::{hybrid, Identity, Signature};
use sha2::{Digest, Sha256};
use spin::Mutex;

use crate::audit::{self, EventKind};

/// The release public key compiled into this kernel (empty: none).
static RELEASE_PUB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/release.pub"));

static LOCKDOWN: AtomicBool = AtomicBool::new(false);

struct State {
    /// `(register, digest)` in the order they were extended, so they can be
    /// replayed into the TPM once its registers are mapped.
    events: alloc::vec::Vec<(usize, [u8; 32])>,
    /// The TPM attestation key, once the TPM holds the measurements.
    ak: Option<crate::tpm::Ak>,
    tpm_note: &'static str,
    loader_note: &'static str,
    verdict: Verdict,
    release_id: [u8; 16],
    registers: [[u8; 32]; REGISTERS],
    log: String,
    reason: &'static str,
}

static STATE: Mutex<State> = Mutex::new(State {
    events: alloc::vec::Vec::new(),
    ak: None,
    tpm_note: "not probed",
    loader_note: "",
    verdict: Verdict::Unverified,
    release_id: [0; 16],
    registers: [[0; 32]; REGISTERS],
    log: String::new(),
    reason: "",
});

/// Whether the kernel is in lockdown (boot verification failed).
pub fn lockdown() -> bool {
    LOCKDOWN.load(Ordering::SeqCst)
}

pub fn verdict() -> Verdict {
    STATE.lock().verdict
}

fn prefix(d: &[u8; 32]) -> u64 {
    u64::from_be_bytes(d[..8].try_into().unwrap_or([0; 8]))
}

fn measure(st: &mut State, reg: usize, name: &str, digest: &[u8; 32]) {
    attest::extend(&mut st.registers[reg], digest);
    st.events.push((reg, *digest));
    let _ = writeln!(st.log, "{} {} {}", reg, name, attest::hex(&digest[..8]));
    let mut subj: heapless::String<48> = heapless::String::new();
    let _ = write!(subj, "reg-{}:{}", reg, name);
    audit::record(EventKind::BootMeasured, &subj, prefix(digest));
}

/// Verify the ramdisk against the release key; returns the number of files
/// it covers.
fn verify(key: &Identity) -> Result<usize, &'static str> {
    let files = || crate::initrd::parse(crate::initrd::archive()).filter_map(Result::ok);
    let manifest = files()
        .find(|f| f.name == attest::MANIFEST_FILE)
        .ok_or("no boot.manifest in the ramdisk")?;
    let sig = files()
        .find(|f| f.name == attest::SIGNATURE_FILE)
        .and_then(|f| Signature::from_slice(f.data))
        .ok_or("no valid boot.manifest.sig in the ramdisk")?;
    let digest = attest::manifest_digest(manifest.data);
    let ok = crate::issuer::crypto_stack::run(|| {
        hybrid::verify_with(key, &digest, &sig, attest::MANIFEST_CONTEXT)
    });
    if !ok {
        return Err("manifest signature does not verify against the release key");
    }
    let text = core::str::from_utf8(manifest.data).map_err(|_| "manifest is not UTF-8")?;
    attest::check_manifest(text, files().map(|f| (f.name, f.data))).map_err(|e| match e {
        ManifestError::Malformed => "manifest malformed",
        ManifestError::Mismatch => "a ramdisk file does not match the manifest",
        ManifestError::Missing => "a file listed in the manifest is missing",
        ManifestError::Unlisted => "the ramdisk holds a file the manifest does not list",
    })
}

/// Measure the kernel image and the ramdisk, then verify the ramdisk.
/// Call once at boot, after the audit log and before anything reads keys
/// or programs from the ramdisk.
pub fn measure_and_verify(kernel_image: &[u8]) {
    let ramdisk = crate::initrd::archive();
    let mut st = STATE.lock();
    // Read-only segments only: the bootloader relocates the writable ones.
    let kernel = attest::kernel_measurement(kernel_image).unwrap_or([0; 32]);
    measure(&mut st, attest::REG_KERNEL, "kernel", &kernel);
    measure(
        &mut st,
        attest::REG_RAMDISK,
        "ramdisk",
        &Sha256::digest(ramdisk).into(),
    );

    let (verdict, release_id, reason) = match Identity::from_bytes(RELEASE_PUB) {
        None if RELEASE_PUB.is_empty() => {
            (Verdict::Unverified, [0; 16], "no release key compiled in")
        }
        None => (
            Verdict::Failed,
            [0; 16],
            "the compiled-in release key is malformed",
        ),
        Some(key) => {
            let id = key.id();
            drop(st);
            let r = verify(&key);
            st = STATE.lock();
            match r {
                Ok(n) => {
                    let mut subj: heapless::String<48> = heapless::String::new();
                    let _ = write!(subj, "release:{}", attest::hex(&id[..4]));
                    audit::record(EventKind::BootVerified, &subj, n as u64);
                    (Verdict::Verified, id, "")
                }
                Err(why) => (Verdict::Failed, id, why),
            }
        }
    };
    st.verdict = verdict;
    st.release_id = release_id;
    st.reason = reason;
    measure(
        &mut st,
        attest::REG_VERDICT,
        verdict.name(),
        &attest::verdict_digest(verdict, &release_id),
    );
    drop(st);

    match verdict {
        Verdict::Verified => crate::println!(
            "Boot: VERIFIED — ramdisk matches the manifest signed by release key {}",
            attest::hex(&release_id[..4])
        ),
        Verdict::Unverified => crate::println!("Boot: unverified ({}) — development build", reason),
        Verdict::Failed => {
            LOCKDOWN.store(true, Ordering::SeqCst);
            crate::initrd::lock();
            crate::println!("Boot: VERIFICATION FAILED — {}", reason);
            crate::println!("Boot: LOCKDOWN — ramdisk hidden, no programs, no link keys, policy changes refused");
            audit::record(EventKind::BootRejected, "boot", 1);
        }
    }
}

/// Replay the boot measurements into TPM PCRs 8–10 and create the
/// attestation key. Call once, after the TIS page is mapped and before any
/// program runs. Without a TPM, attestation stays software-only.
pub fn tpm_commit() {
    if !crate::tpm::probe() {
        STATE.lock().tpm_note = "no TPM found";
        crate::println!("TPM: none — measurements are software-only");
        return;
    }
    let r = (|| -> Result<crate::tpm::Ak, crate::tpm::TpmError> {
        crate::tpm::startup()?;
        let events = STATE.lock().events.clone();
        for (reg, digest) in &events {
            crate::tpm::pcr_extend(cdk_link::tpm::CDK_PCRS[*reg], digest)?;
        }
        let pcrs = crate::tpm::pcr_read_quoted()?;
        let regs = STATE.lock().registers;
        for (i, reg) in regs.iter().enumerate() {
            if pcrs[cdk_link::tpm::CDK_PCRS[i] as usize] != *reg {
                // PCRs 8-10 were not at zero: something extended them first.
                return Err(crate::tpm::TpmError::BadResponse);
            }
        }
        // A measuring loader (UEFI boot) put the ramdisk into PCR 12; it
        // hashed the same bytes the kernel measured into register 1.
        let loader = pcrs[cdk_link::tpm::LOADER_PCRS[1] as usize];
        let note = if loader == [0; 32] {
            "no measuring loader (PCRs 11-12 empty: BIOS boot or no TPM in the loader)"
        } else if loader == regs[attest::REG_RAMDISK] {
            "loader measured kernel and ramdisk into PCRs 11-12 (ramdisk matches)"
        } else {
            "LOADER PCR 12 DIFFERS from the ramdisk the kernel received"
        };
        STATE.lock().loader_note = note;
        crate::tpm::create_ak()
    })();
    match r {
        Ok(ak) => {
            crate::println!(
                "TPM: {:08x} — measurements extended into PCRs 8-10 (match the registers); attestation key {}…",
                crate::tpm::did_vid(),
                attest::hex(&ak.x[..6])
            );
            crate::println!("TPM: {}", STATE.lock().loader_note);
            let mut subj: heapless::String<48> = heapless::String::new();
            let _ = write!(subj, "ak:{}", attest::hex(&ak.x[..8]));
            audit::record(EventKind::TpmReady, &subj, crate::tpm::did_vid() as u64);
            let mut st = STATE.lock();
            st.ak = Some(ak);
            st.tpm_note = "PCRs 8-10 hold the measurements";
        }
        Err(e) => {
            crate::println!(
                "TPM: present but unusable ({:?}) — measurements are software-only",
                e
            );
            STATE.lock().tpm_note = "TPM present but unusable";
            audit::record(EventKind::TpmReady, "tpm-failed", 0);
        }
    }
}

/// A TPM quote of PCRs 0..=10 over the gateway's `nonce`, if the TPM holds
/// the measurements.
pub fn tpm_quote(nonce: &[u8; 32]) -> Option<alloc::vec::Vec<u8>> {
    let ak = STATE.lock().ak?;
    let r =
        crate::tpm::pcr_read_quoted().and_then(|p| crate::tpm::quote(&ak, nonce).map(|q| (p, q)));
    let (pcrs, (attest_bytes, r, s)) = match r {
        Ok(v) => v,
        Err(e) => {
            crate::println!("TPM: quote failed: {:?}", e);
            return None;
        }
    };
    cdk_link::tpm::encode_quote(&cdk_link::tpm::Quote {
        nonce: *nonce,
        ak_x: ak.x,
        ak_y: ak.y,
        pcrs,
        attest: &attest_bytes,
        sig_r: &r,
        sig_s: &s,
    })
}

/// The TPM's endorsement key and the messages carrying it with the
/// manufacturer's EK certificate, for a gateway that asked for proof
/// (`--tpm-ca`). The caller flushes the EK when the exchange is over.
pub fn tpm_endorsement() -> Option<(crate::tpm::Ek, alloc::vec::Vec<alloc::vec::Vec<u8>>)> {
    STATE.lock().ak?;
    let cert = match crate::tpm::nv_read(
        cdk_link::tpm::EK_CERT_NV_INDEX,
        cdk_link::tpm::MAX_EK_BLOB - 64,
    ) {
        Ok(c) => c,
        Err(e) => {
            crate::println!("TPM: no EK certificate in NV (index 0x01c0000a): {:x?}", e);
            return None;
        }
    };
    let ek = match crate::tpm::create_ek() {
        Ok(ek) => ek,
        Err(e) => {
            crate::println!("TPM: endorsement key not created: {:x?}", e);
            return None;
        }
    };
    match cdk_link::tpm::encode_ek_chunks(&ek.x, &ek.y, &cert) {
        Some(msgs) => Some((ek, msgs)),
        None => {
            let _ = crate::tpm::flush(ek.handle);
            None
        }
    }
}

/// Answer the gateway's credential challenge with `TPM2_ActivateCredential`.
pub fn tpm_activate(ek: &crate::tpm::Ek, challenge: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let ak = STATE.lock().ak?;
    let (id_object, secret) = cdk_link::tpm::decode_challenge(challenge)?;
    match crate::tpm::activate_credential(&ak, ek, id_object, secret) {
        Ok(recovered) => cdk_link::tpm::encode_proof(&recovered),
        Err(e) => {
            crate::println!("TPM: credential activation failed: {:x?}", e);
            None
        }
    }
}

/// The attestation answer to a gateway's `nonce`.
pub fn attestation(nonce: &[u8; 32]) -> alloc::vec::Vec<u8> {
    let st = STATE.lock();
    attest::encode_attestation(&attest::Attestation {
        nonce: *nonce,
        verdict: st.verdict,
        release_id: st.release_id,
        registers: st.registers,
        log: &st.log,
    })
}

/// For the console: verdict, reason, release key id, registers, log.
pub fn report(mut f: impl FnMut(&str)) {
    let st = STATE.lock();
    let mut s = String::new();
    let _ = writeln!(
        s,
        "boot: {}{}{}",
        st.verdict.name(),
        if st.reason.is_empty() { "" } else { " — " },
        st.reason
    );
    if st.verdict != Verdict::Unverified {
        let _ = writeln!(s, "release key: {}", attest::hex(&st.release_id));
    }
    for (i, r) in st.registers.iter().enumerate() {
        let _ = writeln!(s, "register {} {}", i, attest::hex(r));
    }
    let _ = writeln!(s, "tpm: {}", st.tpm_note);
    if !st.loader_note.is_empty() {
        let _ = writeln!(s, "loader: {}", st.loader_note);
    }
    if let Some(ak) = &st.ak {
        let _ = writeln!(
            s,
            "tpm attestation key: {}{}",
            attest::hex(&ak.x),
            attest::hex(&ak.y)
        );
    }
    s.push_str("measurement log:\n");
    for line in st.log.lines() {
        let _ = writeln!(s, "  {}", line);
    }
    if lockdown() {
        s.push_str("LOCKDOWN: ramdisk hidden, spawning and policy changes refused\n");
    }
    f(&s);
}
