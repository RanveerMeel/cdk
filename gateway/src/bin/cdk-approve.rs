//! `cdk-approve`: the operator's tool for CDK signed approvals (roadmap 2.8).
//!
//! ```text
//! cdk-approve init <name> [--dir DIR]          create DIR/<name>.key (0600) and DIR/<name>.pub
//! cdk-approve list [--spool DIR]               show open requests and what they ask for
//! cdk-approve approve <id> --key FILE [--spool DIR]
//! cdk-approve deny <id> --key FILE [--spool DIR]
//! ```
//!
//! Defaults: keys in `target/operators/` (packed into the CDK ramdisk as
//! `operator-<name>.pub`, public half only), spool `target/approvals/`.
//!
//! The tool decodes each request itself, shows its text, and signs the
//! statement it computes from those same bytes (`cdk_link::approval::statement`)
//! — what you see is what you sign. The private key never leaves this
//! machine: in production, run this on a separate device with the spool
//! synced to it (the gateway and the spool are untrusted couriers; CDK
//! verifies every signature against its pinned keys).

use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use cdk_link::approval::{self, Message};
use cdk_link::secure::{hybrid, IDENTITY_LEN, SIG_LEN};
use rand_core::{OsRng, RngCore};

#[path = "../spool.rs"]
mod spool;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn die(msg: &str) -> ! {
    eprintln!("cdk-approve: {msg}");
    std::process::exit(1)
}

fn usage() -> ! {
    die("usage: cdk-approve init <name> [--dir DIR] | list [--spool DIR] | approve|deny <id> --key FILE [--spool DIR]")
}

fn load_key(path: &Path) -> hybrid::Keypair {
    let meta = std::fs::metadata(path).unwrap_or_else(|e| die(&format!("{}: {e}", path.display())));
    if meta.mode() & 0o077 != 0 {
        die(&format!(
            "{} must not be readable by group or others (chmod 600)",
            path.display()
        ));
    }
    let seeds = std::fs::read(path).unwrap_or_else(|e| die(&format!("{}: {e}", path.display())));
    if seeds.len() != 64 {
        die(&format!("{} is not a 64-byte operator key", path.display()));
    }
    let (mut ed, mut ml) = ([0u8; 32], [0u8; 32]);
    ed.copy_from_slice(&seeds[..32]);
    ml.copy_from_slice(&seeds[32..]);
    hybrid::Keypair::from_seeds(&ed, &ml)
}

fn init(name: &str, dir: &Path) {
    if name.is_empty()
        || name.len() > 24
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        die("operator names use letters, digits, - and _ (at most 24)");
    }
    std::fs::create_dir_all(dir).unwrap_or_else(|e| die(&e.to_string()));
    let key = dir.join(format!("{name}.key"));
    let mut seeds = [0u8; 64];
    OsRng.fill_bytes(&mut seeds);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key)
        .and_then(|mut f| f.write_all(&seeds))
        .unwrap_or_else(|e| die(&format!("{}: {e}", key.display())));
    seeds.fill(0);
    let kp = load_key(&key);
    let mut public = vec![0u8; IDENTITY_LEN];
    kp.public().write_to(&mut public);
    let pubf = dir.join(format!("{name}.pub"));
    std::fs::write(&pubf, &public).unwrap_or_else(|e| die(&e.to_string()));
    println!("operator {name}: id {}", hex(&kp.public().id()));
    println!(
        "  private key {} (0600 — keep it on the operator's device)",
        key.display()
    );
    println!(
        "  public key  {} (pack into the CDK ramdisk: tools/build_user_programs.sh)",
        pubf.display()
    );
}

fn read_request(spool: &Path, id: u32) -> Vec<u8> {
    let p = spool.join("pending").join(format!("{id}.req"));
    std::fs::read(&p)
        .unwrap_or_else(|_| die(&format!("no open request #{id} in {}", spool.display())))
}

fn show(bytes: &[u8]) -> Option<u32> {
    let Ok(Message::Request(r)) = approval::decode(bytes) else {
        println!("  (malformed request — ignored)");
        return None;
    };
    println!(
        "request #{} — {} — needs {} operator(s), expires {} s after it was opened",
        r.id,
        if r.kind == approval::KIND_POLICY {
            "POLICY CHANGE"
        } else {
            "AGENT ACTION"
        },
        r.quorum,
        r.ttl_s
    );
    println!("  kernel issuer  {}", hex(&r.issuer));
    println!("  payload sha256 {}", hex(&r.payload_digest));
    for line in r.text.lines() {
        // The text is already sanitized by CDK; escape anything else anyway.
        let safe: String = line
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect();
        println!("  | {safe}");
    }
    println!(
        "  approve statement sha256 {}",
        hex(&approval::statement(&r, true))
    );
    Some(r.id)
}

fn list(spool: &Path) {
    let mut ids: Vec<(u32, PathBuf)> = std::fs::read_dir(spool.join("pending"))
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let p = e.path();
                    let id = p.file_stem()?.to_str()?.parse().ok()?;
                    Some((id, p))
                })
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    if ids.is_empty() {
        println!("no open requests in {}", spool.display());
    }
    for (_, p) in ids {
        if let Ok(b) = std::fs::read(&p) {
            show(&b);
            println!();
        }
    }
}

fn decide(spool: &Path, id: u32, key: &Path, approve: bool) {
    let kp = load_key(key);
    let bytes = read_request(spool, id);
    show(&bytes).unwrap_or_else(|| die("malformed request"));
    let Ok(Message::Request(r)) = approval::decode(&bytes) else {
        die("malformed request")
    };
    let statement = approval::statement(&r, approve);
    let sig = kp.sign_with(&statement, approval::CONTEXT);
    let mut signature = vec![0u8; SIG_LEN];
    sig.write_to(&mut signature);
    let operator = kp.public().id();
    let d = spool::Decision {
        id,
        operator,
        approve,
        signature,
    };
    let dir = spool.join("decisions");
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| die(&e.to_string()));
    let name = format!("{id}-{}", hex(&operator[..4]));
    let tmp = dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp, d.to_bytes()).unwrap_or_else(|e| die(&e.to_string()));
    std::fs::rename(&tmp, dir.join(format!("{name}.dec"))).unwrap_or_else(|e| die(&e.to_string()));
    println!(
        "signed: {} request #{id} as operator {} (Ed25519 + ML-DSA-65, context {})",
        if approve { "APPROVE" } else { "DENY" },
        hex(&operator[..4]),
        String::from_utf8_lossy(approval::CONTEXT)
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
    let spool = opt("--spool", "target/approvals");
    match args.first().map(String::as_str) {
        Some("init") => init(
            args.get(1).map_or_else(|| usage(), |s| s.as_str()),
            &opt("--dir", "target/operators"),
        ),
        Some("list") => list(&spool),
        Some(cmd @ ("approve" | "deny")) => {
            let id: u32 = args
                .get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            if !args.iter().any(|a| a == "--key") {
                usage();
            }
            decide(&spool, id, &opt("--key", ""), cmd == "approve");
        }
        _ => usage(),
    }
}
