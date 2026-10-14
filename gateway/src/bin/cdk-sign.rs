//! `cdk-sign`: release signing for verified and measured boot (roadmap 4.2).
//!
//! ```text
//! cdk-sign init [--key FILE] [--pub-out FILE]      create the release key (0600) once
//! cdk-sign manifest <ramdisk-stage-dir> [--key FILE]
//!                                                  write boot.manifest + boot.manifest.sig
//! cdk-sign measure <kernel-elf> <ramdisk.tar> [--pub FILE] [--out FILE] [--loader]
//!                                                  expected measurement registers
//!                                                  (--loader: also PCRs 11-12 from
//!                                                  the measuring UEFI loader)
//! cdk-sign verify <ramdisk-stage-dir> [--pub FILE] check a staged ramdisk
//! ```
//!
//! Defaults: `target/release-signing.key`, `target/release.pub` (compiled
//! into the kernel by `build.rs`), `target/boot.measurements` (given to the
//! gateway with `--expect`). Keep the release key off build machines that
//! should not be able to ship CDK images; in production it belongs in an HSM.

use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use cdk_link::attest::{self, Verdict};
use cdk_link::secure::{hybrid, Identity, Signature, IDENTITY_LEN, SIG_LEN};
use rand_core::{OsRng, RngCore};

fn die(msg: &str) -> ! {
    eprintln!("cdk-sign: {msg}");
    std::process::exit(1)
}

fn usage() -> ! {
    die("usage: cdk-sign init | manifest <stage-dir> | measure <kernel-elf> <ramdisk.tar> | verify <stage-dir>")
}

fn load_key(path: &Path) -> hybrid::Keypair {
    let meta = std::fs::metadata(path)
        .unwrap_or_else(|e| die(&format!("{}: {e} (run cdk-sign init)", path.display())));
    if meta.mode() & 0o077 != 0 {
        die(&format!(
            "{} must not be readable by group or others (chmod 600)",
            path.display()
        ));
    }
    let seeds = std::fs::read(path).unwrap_or_else(|e| die(&e.to_string()));
    if seeds.len() != 64 {
        die(&format!("{} is not a 64-byte release key", path.display()));
    }
    let (mut ed, mut ml) = ([0u8; 32], [0u8; 32]);
    ed.copy_from_slice(&seeds[..32]);
    ml.copy_from_slice(&seeds[32..]);
    hybrid::Keypair::from_seeds(&ed, &ml)
}

fn load_pub(path: &Path) -> Option<Identity> {
    std::fs::read(path)
        .ok()
        .and_then(|b| Identity::from_bytes(&b))
}

fn init(key: &Path, pub_out: &Path) {
    if key.exists() {
        let kp = load_key(key);
        write_pub(&kp, pub_out);
        println!(
            "release key {} exists: id {}",
            key.display(),
            attest::hex(&kp.public().id())
        );
        return;
    }
    if let Some(dir) = key.parent() {
        std::fs::create_dir_all(dir).unwrap_or_else(|e| die(&e.to_string()));
    }
    let mut seeds = [0u8; 64];
    OsRng.fill_bytes(&mut seeds);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(key)
        .and_then(|mut f| f.write_all(&seeds))
        .unwrap_or_else(|e| die(&format!("{}: {e}", key.display())));
    seeds.fill(0);
    let kp = load_key(key);
    write_pub(&kp, pub_out);
    println!(
        "release key {} created: id {}",
        key.display(),
        attest::hex(&kp.public().id())
    );
    println!(
        "public key {} (compiled into the kernel; rebuild it)",
        pub_out.display()
    );
}

fn write_pub(kp: &hybrid::Keypair, out: &Path) {
    let mut b = vec![0u8; IDENTITY_LEN];
    kp.public().write_to(&mut b);
    if std::fs::read(out).ok().as_deref() != Some(&b[..]) {
        std::fs::write(out, &b).unwrap_or_else(|e| die(&e.to_string()));
    }
}

/// `(name, contents)` of every file in a staged ramdisk directory.
fn stage_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| die(&format!("{}: {e}", dir.display())))
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap_or_default(),
            )
        })
        .collect();
    v.sort();
    v
}

fn manifest(dir: &Path, key: &Path) {
    let kp = load_key(key);
    let files = stage_files(dir);
    let m = attest::build_manifest(files.iter().map(|(n, d)| (n.as_str(), d.as_slice())));
    let sig = kp.sign_with(
        &attest::manifest_digest(m.as_bytes()),
        attest::MANIFEST_CONTEXT,
    );
    let mut sb = vec![0u8; SIG_LEN];
    sig.write_to(&mut sb);
    std::fs::write(dir.join(attest::MANIFEST_FILE), &m).unwrap_or_else(|e| die(&e.to_string()));
    std::fs::write(dir.join(attest::SIGNATURE_FILE), &sb).unwrap_or_else(|e| die(&e.to_string()));
    println!(
        "signed boot manifest: {} file(s), release key {}",
        m.lines().count() - 1,
        attest::hex(&kp.public().id()[..4])
    );
}

fn verify(dir: &Path, pubf: &Path) {
    let id = load_pub(pubf)
        .unwrap_or_else(|| die(&format!("{}: not a release public key", pubf.display())));
    let files = stage_files(dir);
    let get = |n: &str| files.iter().find(|(f, _)| f == n).map(|(_, d)| d.clone());
    let m = get(attest::MANIFEST_FILE).unwrap_or_else(|| die("no boot.manifest"));
    let sig = get(attest::SIGNATURE_FILE)
        .and_then(|s| Signature::from_slice(&s))
        .unwrap_or_else(|| die("no valid boot.manifest.sig"));
    if !hybrid::verify_with(
        &id,
        &attest::manifest_digest(&m),
        &sig,
        attest::MANIFEST_CONTEXT,
    ) {
        die("signature does not verify");
    }
    let text = String::from_utf8(m).unwrap_or_else(|_| die("manifest is not UTF-8"));
    match attest::check_manifest(&text, files.iter().map(|(n, d)| (n.as_str(), d.as_slice()))) {
        Ok(n) => println!(
            "ok: {n} file(s) match the manifest signed by {}",
            attest::hex(&id.id()[..4])
        ),
        Err(e) => die(&format!("{e:?}")),
    }
}

fn measure(kernel: &Path, ramdisk: &Path, pubf: &Path, out: &Path, loader: bool) {
    let k = std::fs::read(kernel).unwrap_or_else(|e| die(&format!("{}: {e}", kernel.display())));
    let r = std::fs::read(ramdisk).unwrap_or_else(|e| die(&format!("{}: {e}", ramdisk.display())));
    let (verdict, release_id) = match load_pub(pubf) {
        Some(id) => (Verdict::Verified, id.id()),
        None => (Verdict::Unverified, [0u8; 16]),
    };
    let regs = attest::expected_registers(&k, &r, verdict, &release_id);
    let mut text = format!(
        "# Expected CDK boot measurements (cdk-sign measure): boot {}, release key {}\n# kernel {}\n# ramdisk {}\n",
        verdict.name(),
        attest::hex(&release_id),
        kernel.display(),
        ramdisk.display()
    );
    for (i, reg) in regs.iter().enumerate() {
        text.push_str(&format!("register {i} {}\n", attest::hex(reg)));
    }
    if loader {
        // UEFI boot: CDK's measuring loader extends PCRs 11 and 12 with the
        // kernel file and the ramdisk before the kernel runs.
        let pcrs = cdk_link::tpm::expected_loader_pcrs(&k, &r);
        for (pcr, v) in cdk_link::tpm::LOADER_PCRS.iter().zip(pcrs) {
            text.push_str(&format!("loader {pcr} {}\n", attest::hex(&v)));
        }
    }
    std::fs::write(out, text).unwrap_or_else(|e| die(&e.to_string()));
    println!(
        "expected measurements ({}) -> {}",
        verdict.name(),
        out.display()
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opt = |flag: &str, default: &str| -> PathBuf {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .map_or_else(|| PathBuf::from(default), PathBuf::from)
    };
    let key = opt("--key", "target/release-signing.key");
    let pubf = opt("--pub", "target/release.pub");
    let arg = |i: usize| args.get(i).map(PathBuf::from).unwrap_or_else(|| usage());
    match args.first().map(String::as_str) {
        Some("init") => init(&key, &opt("--pub-out", "target/release.pub")),
        Some("manifest") => manifest(&arg(1), &key),
        Some("verify") => verify(&arg(1), &pubf),
        Some("measure") => measure(
            &arg(1),
            &arg(2),
            &pubf,
            &opt("--out", "target/boot.measurements"),
            args.iter().any(|a| a == "--loader"),
        ),
        _ => usage(),
    }
}
