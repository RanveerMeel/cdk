//! Verified and measured boot (roadmap 4.2): the boot manifest format, the
//! measurement registers, and the attestation messages. Shared by the
//! kernel, the gateway and the build tool (`cdk-sign`) so all three compute
//! identical values.
//!
//! **Verified boot.** `boot.manifest` in the ramdisk lists the SHA-256 of
//! every other ramdisk file; `boot.manifest.sig` is a hybrid Ed25519 +
//! ML-DSA-65 signature (FIPS 204 context [`MANIFEST_CONTEXT`]) over
//! [`manifest_digest`] by the release key, whose public half is compiled
//! into the kernel.
//!
//! ```text
//! CDK-BOOT-MANIFEST-v1
//! <sha256 hex> <name>        one line per file, sorted by name
//! ```
//!
//! **Measured boot.** Software measurement registers, extended like TPM
//! PCRs (`r = SHA-256(r ‖ digest)`, starting from zeros):
//!
//! | register | measures |
//! |---|---|
//! | 0 | the kernel ELF image |
//! | 1 | the ramdisk archive |
//! | 2 | the verification outcome and release key ([`verdict_digest`]) |
//!
//! **Attestation.** Inside the sealed session the gateway sends
//! `AttestRequest { nonce }`; CDK answers `Attest { nonce, verdict, release
//! key id, registers, event log }`. The session is authenticated by the
//! hybrid-signed handshake, so the answer is bound to the kernel issuer the
//! gateway verified.
//!
//! ```text
//! AttestRequest : 0x30 | nonce [32]
//! Attest        : 0x31 | nonce [32] | verdict u8 | release id [16]
//!                      | registers [3 × 32] | log_len u16 | log (UTF-8)
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use sha2::{Digest, Sha256};

pub const MANIFEST_FILE: &str = "boot.manifest";
pub const SIGNATURE_FILE: &str = "boot.manifest.sig";
pub const MANIFEST_HEADER: &str = "CDK-BOOT-MANIFEST-v1";
/// FIPS 204 context of release-key signatures.
pub const MANIFEST_CONTEXT: &[u8] = b"CDK-BOOT-v1";

pub const REGISTERS: usize = 3;
pub const REG_KERNEL: usize = 0;
pub const REG_RAMDISK: usize = 1;
pub const REG_VERDICT: usize = 2;

pub const ATTEST_REQUEST: u8 = 0x30;
pub const ATTEST: u8 = 0x31;

/// Boot verification outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Verdict {
    /// No release key compiled in (development build).
    Unverified = 0,
    /// The manifest verified and every ramdisk file matched it.
    Verified = 1,
    /// Verification failed; the kernel is in lockdown.
    Failed = 2,
}

impl Verdict {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Verdict::Unverified),
            1 => Some(Verdict::Verified),
            2 => Some(Verdict::Failed),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Verdict::Unverified => "unverified",
            Verdict::Verified => "verified",
            Verdict::Failed => "FAILED",
        }
    }
}

/// `r ← SHA-256(r ‖ digest)`.
pub fn extend(register: &mut [u8; 32], digest: &[u8; 32]) {
    let mut h = Sha256::new();
    h.update(*register);
    h.update(digest);
    *register = h.finalize().into();
}

/// The kernel measurement: SHA-256 over every read-only `PT_LOAD` segment
/// of the kernel ELF (code, read-only data, and the headers, which sit in
/// the first one), each prefixed with its file offset and size. Writable
/// segments are left out: the bootloader relocates them and the kernel
/// changes them, so their bytes differ from the file once running.
/// Returns `None` if `elf` is not a well-formed ELF64 image.
pub fn kernel_measurement(elf: &[u8]) -> Option<[u8; 32]> {
    let u16_at = |o: usize| Some(u16::from_le_bytes(elf.get(o..o + 2)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_le_bytes(elf.get(o..o + 4)?.try_into().ok()?));
    let u64_at = |o: usize| Some(u64::from_le_bytes(elf.get(o..o + 8)?.try_into().ok()?));
    if elf.get(..4)? != b"\x7fELF" || *elf.get(4)? != 2 {
        return None;
    }
    let phoff = u64_at(32)? as usize;
    let (phentsize, phnum) = (u16_at(54)? as usize, u16_at(56)? as usize);
    if phentsize != 56 || phnum == 0 || phnum > 64 {
        return None;
    }
    let mut h = Sha256::new();
    h.update(b"CDK-KERNEL-MEASUREMENT-v1");
    let mut segments = 0;
    for i in 0..phnum {
        let ph = phoff.checked_add(i * phentsize)?;
        const PT_LOAD: u32 = 1;
        const PF_W: u32 = 2;
        if u32_at(ph)? != PT_LOAD || u32_at(ph + 4)? & PF_W != 0 {
            continue;
        }
        let (off, size) = (u64_at(ph + 8)?, u64_at(ph + 32)?);
        let bytes = elf.get(off as usize..(off as usize).checked_add(size as usize)?)?;
        h.update(off.to_le_bytes());
        h.update(size.to_le_bytes());
        h.update(bytes);
        segments += 1;
    }
    (segments > 0).then(|| h.finalize().into())
}

/// What register 2 is extended with.
pub fn verdict_digest(verdict: Verdict, release_id: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"CDK-BOOT-VERDICT-v1");
    h.update([verdict as u8]);
    h.update(release_id);
    h.finalize().into()
}

/// The registers a boot of `kernel` with `ramdisk` produces.
pub fn expected_registers(
    kernel: &[u8],
    ramdisk: &[u8],
    verdict: Verdict,
    release_id: &[u8; 16],
) -> [[u8; 32]; REGISTERS] {
    let mut r = [[0u8; 32]; REGISTERS];
    extend(
        &mut r[REG_KERNEL],
        &kernel_measurement(kernel).unwrap_or([0; 32]),
    );
    extend(&mut r[REG_RAMDISK], &Sha256::digest(ramdisk).into());
    extend(&mut r[REG_VERDICT], &verdict_digest(verdict, release_id));
    r
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Build a manifest from `(name, contents)` pairs.
pub fn build_manifest<'a>(files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> String {
    let mut entries: Vec<(&str, [u8; 32])> = files
        .into_iter()
        .filter(|(n, _)| *n != MANIFEST_FILE && *n != SIGNATURE_FILE)
        .map(|(n, d)| (n, Sha256::digest(d).into()))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut m = String::from(MANIFEST_HEADER);
    m.push('\n');
    for (n, d) in entries {
        let _ = writeln!(m, "{} {}", hex(&d), n);
    }
    m
}

/// What the release key signs.
pub fn manifest_digest(manifest: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MANIFEST_CONTEXT);
    h.update([0]);
    h.update(manifest);
    h.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestError {
    Malformed,
    /// A file's digest does not match.
    Mismatch,
    /// A listed file is missing from the ramdisk.
    Missing,
    /// The ramdisk holds a file the manifest does not list.
    Unlisted,
}

/// Check that `files` are exactly what `manifest` lists.
pub fn check_manifest<'a>(
    manifest: &str,
    files: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Result<usize, ManifestError> {
    let mut lines = manifest.lines();
    if lines.next() != Some(MANIFEST_HEADER) {
        return Err(ManifestError::Malformed);
    }
    let mut listed: Vec<(&str, [u8; 32], bool)> = Vec::new();
    let mut prev: Option<&str> = None;
    for line in lines {
        let (d, n) = line.split_once(' ').ok_or(ManifestError::Malformed)?;
        let d = unhex32(d).ok_or(ManifestError::Malformed)?;
        if n.is_empty() || prev.is_some_and(|p| p >= n) {
            return Err(ManifestError::Malformed); // sorted and unique
        }
        prev = Some(n);
        listed.push((n, d, false));
    }
    // Exactly the canonical text (lowercase hex, `\n` line ends, final
    // newline), so one set of files has exactly one valid manifest.
    let mut canonical = String::from(MANIFEST_HEADER);
    canonical.push('\n');
    for (n, d, _) in &listed {
        let _ = writeln!(canonical, "{} {}", hex(d), n);
    }
    if canonical != manifest {
        return Err(ManifestError::Malformed);
    }
    for (name, data) in files {
        if name == MANIFEST_FILE || name == SIGNATURE_FILE {
            continue;
        }
        let entry = listed
            .iter_mut()
            .find(|e| e.0 == name)
            .ok_or(ManifestError::Unlisted)?;
        if entry.2 {
            return Err(ManifestError::Unlisted); // duplicate archive entry
        }
        let d: [u8; 32] = Sha256::digest(data).into();
        if d != entry.1 {
            return Err(ManifestError::Mismatch);
        }
        entry.2 = true;
    }
    if listed.iter().any(|e| !e.2) {
        return Err(ManifestError::Missing);
    }
    Ok(listed.len())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation<'a> {
    pub nonce: [u8; 32],
    pub verdict: Verdict,
    pub release_id: [u8; 16],
    pub registers: [[u8; 32]; REGISTERS],
    pub log: &'a str,
}

const ATTEST_HEADER: usize = 1 + 32 + 1 + 16 + 32 * REGISTERS + 2;
pub const MAX_LOG: usize = crate::secure::MAX_PLAINTEXT - ATTEST_HEADER;

pub fn encode_request(nonce: &[u8; 32]) -> Vec<u8> {
    let mut m = alloc::vec![ATTEST_REQUEST];
    m.extend_from_slice(nonce);
    m
}

/// Encode an attestation; the log is cut to [`MAX_LOG`] at a character
/// boundary.
pub fn encode_attestation(a: &Attestation<'_>) -> Vec<u8> {
    let mut end = a.log.len().min(MAX_LOG);
    while !a.log.is_char_boundary(end) {
        end -= 1;
    }
    let log = &a.log[..end];
    let mut m = Vec::with_capacity(ATTEST_HEADER + log.len());
    m.push(ATTEST);
    m.extend_from_slice(&a.nonce);
    m.push(a.verdict as u8);
    m.extend_from_slice(&a.release_id);
    for r in &a.registers {
        m.extend_from_slice(r);
    }
    m.extend_from_slice(&(log.len() as u16).to_le_bytes());
    m.extend_from_slice(log.as_bytes());
    m
}

pub enum Message<'a> {
    Request([u8; 32]),
    Attestation(Attestation<'a>),
}

pub fn is_attest(msg: &[u8]) -> bool {
    matches!(msg.first(), Some(&(ATTEST_REQUEST | ATTEST)))
}

pub fn decode(b: &[u8]) -> Option<Message<'_>> {
    let (&tag, r) = b.split_first()?;
    match tag {
        ATTEST_REQUEST if r.len() == 32 => Some(Message::Request(r.try_into().ok()?)),
        ATTEST => {
            let nonce: [u8; 32] = r.get(..32)?.try_into().ok()?;
            let verdict = Verdict::from_u8(*r.get(32)?)?;
            let release_id: [u8; 16] = r.get(33..49)?.try_into().ok()?;
            let mut registers = [[0u8; 32]; REGISTERS];
            for (i, reg) in registers.iter_mut().enumerate() {
                *reg = r.get(49 + 32 * i..81 + 32 * i)?.try_into().ok()?;
            }
            let at = 49 + 32 * REGISTERS;
            let len = u16::from_le_bytes(r.get(at..at + 2)?.try_into().ok()?) as usize;
            let log = r.get(at + 2..at + 2 + len)?;
            if r.len() != at + 2 + len || len > MAX_LOG {
                return None;
            }
            Some(Message::Attestation(Attestation {
                nonce,
                verdict,
                release_id,
                registers,
                log: core::str::from_utf8(log).ok()?,
            }))
        }
        _ => None,
    }
}

/// Expected loader PCRs from an expected-measurements file: `loader 11
/// <hex>` and `loader 12 <hex>` lines (written by `cdk-sign measure
/// --loader`); `None` if the file has none (BIOS boots are not measured by
/// a loader).
pub fn parse_expected_loader(text: &str) -> Option<[[u8; 32]; 2]> {
    let mut out = [None; 2];
    for line in text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
    {
        let mut w = line.split_whitespace();
        if w.next() != Some("loader") {
            continue;
        }
        let i = match w.next()? {
            "11" => 0,
            "12" => 1,
            _ => return None,
        };
        out[i] = Some(unhex32(w.next()?)?);
    }
    Some([out[0]?, out[1]?])
}

/// Parse an expected-measurements file (written by `cdk-sign measure`):
/// `register <n> <hex>` lines (and `loader` lines, see
/// [`parse_expected_loader`]); `#` comments.
pub fn parse_expected(text: &str) -> Option<[[u8; 32]; REGISTERS]> {
    let mut out = [None; REGISTERS];
    for line in text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
    {
        let mut w = line.split_whitespace();
        let first = w.next();
        if first == Some("loader") {
            continue;
        }
        let (Some("register"), Some(i), Some(h), None) = (first, w.next(), w.next(), w.next())
        else {
            return None;
        };
        let i: usize = i.parse().ok().filter(|i| *i < REGISTERS)?;
        out[i] = Some(unhex32(h)?);
    }
    let mut r = [[0u8; 32]; REGISTERS];
    for (i, v) in out.iter().enumerate() {
        r[i] = (*v)?;
    }
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trip_and_tampering() {
        let files = [
            ("hello", &b"elf"[..]),
            ("gateway.pub", &b"key"[..]),
            ("policy.rules", &b"approval credential\n"[..]),
        ];
        let m = build_manifest(files);
        assert!(m.starts_with("CDK-BOOT-MANIFEST-v1\n"));
        assert_eq!(check_manifest(&m, files), Ok(3));
        // The manifest and its signature may be in the archive.
        let with_meta = [
            files[0],
            files[1],
            files[2],
            (MANIFEST_FILE, m.as_bytes()),
            (SIGNATURE_FILE, &b"sig"[..]),
        ];
        assert_eq!(check_manifest(&m, with_meta), Ok(3));
        assert_eq!(
            check_manifest(&m, [files[0], ("gateway.pub", &b"KEY"[..]), files[2]]),
            Err(ManifestError::Mismatch)
        );
        assert_eq!(
            check_manifest(&m, [files[0], files[1]]),
            Err(ManifestError::Missing)
        );
        assert_eq!(
            check_manifest(&m, [files[0], files[1], files[2], ("extra", &b""[..])]),
            Err(ManifestError::Unlisted)
        );
        assert_eq!(
            check_manifest(&m, [files[0], files[0], files[1], files[2]]),
            Err(ManifestError::Unlisted)
        );
        let unsorted = m.replace("gateway.pub", "zzz");
        assert_eq!(
            check_manifest(&unsorted, files),
            Err(ManifestError::Malformed)
        );
        assert_eq!(
            check_manifest("CDK-BOOT-MANIFEST-v2\n", files),
            Err(ManifestError::Malformed)
        );
        // Found by fuzzing: non-canonical spellings of a valid manifest.
        for variant in [
            m.to_uppercase()
                .replacen("CDK-BOOT-MANIFEST-V1", MANIFEST_HEADER, 1),
            m.replace('\n', "\r\n"),
            m.trim_end().into(),
        ] {
            assert_eq!(
                check_manifest(&variant, files),
                Err(ManifestError::Malformed),
                "{variant:?}"
            );
        }
        assert_ne!(
            manifest_digest(m.as_bytes()),
            manifest_digest(unsorted.as_bytes())
        );
    }

    /// A minimal ELF64 with one read-only and one writable PT_LOAD.
    fn elf(ro: &[u8], rw: &[u8]) -> alloc::vec::Vec<u8> {
        let mut e = alloc::vec![0u8; 64 + 2 * 56];
        e[..4].copy_from_slice(b"\x7fELF");
        e[4] = 2;
        e[32..40].copy_from_slice(&64u64.to_le_bytes());
        e[54..56].copy_from_slice(&56u16.to_le_bytes());
        e[56..58].copy_from_slice(&2u16.to_le_bytes());
        let base = e.len() as u64;
        let segs = [
            (5u32, base, ro.len()),
            (6u32, base + ro.len() as u64, rw.len()),
        ];
        for (i, (flags, off, len)) in segs.into_iter().enumerate() {
            let p = 64 + i * 56;
            e[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
            e[p + 4..p + 8].copy_from_slice(&flags.to_le_bytes());
            e[p + 8..p + 16].copy_from_slice(&off.to_le_bytes());
            e[p + 32..p + 40].copy_from_slice(&(len as u64).to_le_bytes());
        }
        e.extend_from_slice(ro);
        e.extend_from_slice(rw);
        e
    }

    #[test]
    fn kernel_measurement_covers_only_read_only_segments() {
        let m = kernel_measurement(&elf(b"code", b"data")).unwrap();
        assert_eq!(
            m,
            kernel_measurement(&elf(b"code", b"DATA")).unwrap(),
            "writable data ignored"
        );
        assert_ne!(
            m,
            kernel_measurement(&elf(b"c0de", b"data")).unwrap(),
            "code measured"
        );
        assert_eq!(kernel_measurement(b"not an elf"), None);
        let mut short = elf(b"code", b"data");
        short.truncate(64 + 2 * 56 + 2);
        assert_eq!(kernel_measurement(&short), None);
    }

    #[test]
    fn registers_and_attestation() {
        let r = expected_registers(b"kernel", b"ramdisk", Verdict::Verified, &[7; 16]);
        assert_ne!(
            r,
            expected_registers(b"kernel", b"ramdisk!", Verdict::Verified, &[7; 16])
        );
        assert_ne!(
            r,
            expected_registers(b"kernel", b"ramdisk", Verdict::Unverified, &[7; 16])
        );
        assert_ne!(
            r,
            expected_registers(b"kernel", b"ramdisk", Verdict::Verified, &[8; 16])
        );
        let a = Attestation {
            nonce: [1; 32],
            verdict: Verdict::Verified,
            release_id: [7; 16],
            registers: r,
            log: "0 kernel …",
        };
        let m = encode_attestation(&a);
        assert!(m.len() <= crate::secure::MAX_PLAINTEXT);
        match decode(&m) {
            Some(Message::Attestation(b)) => assert_eq!(a, b),
            _ => panic!(),
        }
        let long = "é".repeat(MAX_LOG);
        assert!(
            encode_attestation(&Attestation {
                log: &long,
                ..a.clone()
            })
            .len()
                <= crate::secure::MAX_PLAINTEXT
        );
        assert!(
            matches!(decode(&encode_request(&[9; 32])), Some(Message::Request(n)) if n == [9; 32])
        );
        let text = (0..REGISTERS)
            .map(|i| alloc::format!("register {i} {}\n", hex(&r[i])))
            .collect::<String>();
        assert_eq!(parse_expected(&text), Some(r));
        assert_eq!(parse_expected("register 0 00\n"), None);
        assert_eq!(parse_expected_loader(&text), None, "no loader lines");
        let with_loader = alloc::format!(
            "{text}loader 11 {}\nloader 12 {}\n",
            hex(&[1; 32]),
            hex(&[2; 32])
        );
        assert_eq!(
            parse_expected(&with_loader),
            Some(r),
            "loader lines are ignored here"
        );
        assert_eq!(
            parse_expected_loader(&with_loader),
            Some([[1; 32], [2; 32]])
        );
    }
}
