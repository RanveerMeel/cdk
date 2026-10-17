//! Host-side gateway for the CDK link (roadmap Phase 3).
//!
//! Connects to the Unix socket QEMU exposes for CDK's virtio-console and
//! speaks the shared `cdk-link` protocol:
//!
//! * plaintext: logs `HELLO`, answers `PING`, acknowledges `DATA`, serves
//!   test bursts (`burst N`);
//! * secure channel (3.2): answers CDK's post-quantum handshake with its own
//!   long-term hybrid identity (Ed25519 + ML-DSA-65), verifies CDK's issuer
//!   signature, then opens and answers sealed messages. Once a session
//!   exists, plaintext `DATA` is refused.
//!
//! * MCP gateway (3.3): sealed tool messages (`cdk_link::tool`) are
//!   translated to MCP `tools/list` / `tools/call` on the configured stdio
//!   MCP servers; an optional allowlist limits which tools CDK may reach.
//! * model backends (3.4): OpenAI-compatible model servers appear to CDK as
//!   tools `model:<name>`; the gateway injects each backend's credential,
//!   which CDK never sees (`models`). Long results are chunked.
//! * signed approvals (2.8): CDK's approval requests are written to a spool
//!   directory for operators (`cdk-approve`), and their signed decisions are
//!   forwarded back; CDK verifies every signature (`spool`).
//! * attestation (4.2): after each handshake the gateway asks CDK for its
//!   measured-boot registers; with `--expect FILE` it serves nothing unless
//!   they match the build; with `--tpm FILE` it also requires a TPM quote
//!   from the enrolled machine; with `--tpm-ca DIR`, proof that the quoting
//!   key is in a TPM certified by a manufacturer CA in DIR (`attestation`,
//!   `ekcert`, `credential`).
//!
//! ```text
//! cdk-gateway --init [--identity FILE] [--pub-out FILE]   create identity, export public key
//! cdk-gateway [--identity FILE] [--mcp NAME=COMMAND]... [--model SPEC]... [--allow t1,t2]
//!             [--spool DIR] [--expect FILE] [--tpm FILE] [--tpm-ca DIR]
//!             [--registry-key FILE --node NAME [--cert-validity S]] [--cap-dir DIR] [SOCKET]
//! ```
//! The public key file (1984 bytes) is packed into CDK's ramdisk as
//! `gateway.pub`; CDK refuses any other gateway.

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cdk_link::secure::{self, hybrid, Reassembler, ServerState, Session};
use cdk_link::tool::{self, Status};
use cdk_link::{kind, Decoder, MAX_FRAME};
use rand_core::{OsRng, RngCore};

mod attestation;
mod credential;
mod ekcert;
mod mcp;
mod models;
mod registry;
mod spool;

fn send(stream: &mut UnixStream, k: u8, flags: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut buf = [0u8; MAX_FRAME];
    let n = cdk_link::encode_with_flags(k, flags, payload, &mut buf).expect("fits a frame");
    stream.write_all(&buf[..n])
}

fn printable(p: &[u8]) -> String {
    p.iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                (b as char).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Load the identity seeds (ed25519 ‖ ml-dsa, 64 bytes), creating them
/// (mode 0600) if the file does not exist.
fn load_identity(path: &Path) -> std::io::Result<hybrid::Keypair> {
    let seeds = match std::fs::read(path) {
        Ok(s) if s.len() == 64 => s,
        Ok(_) => {
            return Err(std::io::Error::other(format!(
                "{} is not a 64-byte identity file",
                path.display()
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut s = vec![0u8; 64];
            OsRng.fill_bytes(&mut s);
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?
                .write_all(&s)?;
            eprintln!("gateway: created identity {}", path.display());
            s
        }
        Err(e) => return Err(e),
    };
    let mut ed = [0u8; 32];
    let mut ml = [0u8; 32];
    ed.copy_from_slice(&seeds[..32]);
    ml.copy_from_slice(&seeds[32..]);
    Ok(hybrid::Keypair::from_seeds(&ed, &ml))
}

/// Answer a sealed tool message from CDK; returns the reply messages
/// (several when a long result is chunked).
fn handle_tool(
    msg: &[u8],
    registry: &mut mcp::Registry,
    models: &[models::Backend],
    allowed: &dyn Fn(&str) -> bool,
) -> Vec<Vec<u8>> {
    match tool::decode(msg) {
        Ok(tool::Message::ListRequest) => {
            // (name, flags, endpoint); MCP tools are reported by server, with
            // no flags: the gateway cannot know what an MCP server reaches.
            let listed: Vec<(String, u8, String)> = registry
                .tool_names()
                .into_iter()
                .map(|n| {
                    let server = format!("mcp:{}", registry.server_of(&n).unwrap_or("?"));
                    (n, 0, server)
                })
                .chain(models.iter().map(models::Backend::entry))
                .filter(|(n, _, _)| allowed(n))
                .take(tool::MAX_TOOLS)
                .collect();
            let entries: Vec<tool::Entry> = listed
                .iter()
                .map(|(name, flags, endpoint)| tool::Entry {
                    name,
                    flags: *flags,
                    endpoint,
                })
                .collect();
            let names: Vec<&str> = entries.iter().map(|e| e.name).collect();
            eprintln!("gateway: <- tools/list, -> {names:?}");
            vec![tool::encode_list_response(&entries)
                .unwrap_or_else(|_| tool::encode_list_response(&[]).unwrap())]
        }
        Ok(tool::Message::CallRequest {
            call_id,
            name,
            args,
        }) => {
            eprintln!(
                "gateway: <- tools/call #{call_id} {name} {}",
                printable(args)
            );
            let outcome = if !allowed(name) {
                Err((
                    Status::Refused,
                    format!("{name} is not allowed by the gateway"),
                ))
            } else if let Some(model) = name.strip_prefix(tool::MODEL_PREFIX) {
                models
                    .iter()
                    .find(|m| m.name == model)
                    .map(|b| b.call(args))
                    .ok_or((Status::UnknownTool, format!("no model backend {model}")))
            } else {
                registry.call(name, args).ok_or((
                    Status::UnknownTool,
                    format!("no MCP server provides {name}"),
                ))
            };
            let (status, body) = match outcome {
                Err(e) => e,
                Ok(mcp::CallOutcome::Ok(t)) => (Status::Ok, t),
                Ok(mcp::CallOutcome::ToolError(t)) => (Status::ToolError, t),
                Ok(mcp::CallOutcome::Failed(t)) => (Status::Unavailable, t),
            };
            let shown: String = body.chars().take(160).collect();
            eprintln!(
                "gateway: -> #{call_id} {status:?} ({} B) {}",
                body.len(),
                printable(shown.as_bytes())
            );
            tool::encode_call_result(call_id, status, body.as_bytes())
        }
        _ => vec![tool::encode_call_response(
            0,
            Status::ToolError,
            b"malformed tool message",
        )],
    }
}

/// Answer a tool message from an unattested CDK: an empty listing, or
/// `Refused` for a call.
fn refuse_unattested(msg: &[u8]) -> Vec<Vec<u8>> {
    match tool::decode(msg) {
        Ok(tool::Message::ListRequest) => vec![tool::encode_list_response(&[]).unwrap()],
        Ok(tool::Message::CallRequest { call_id, .. }) => vec![tool::encode_call_response(
            call_id,
            Status::Refused,
            b"the gateway refuses service: CDK's measured boot did not attest",
        )],
        _ => Vec::new(),
    }
}

fn connect(path: &str) -> std::io::Result<UnixStream> {
    let deadline = Instant::now() + Duration::from_secs(60); // CDK may still be booting
    loop {
        match UnixStream::connect(path) {
            Ok(s) => return Ok(s),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => return Err(e),
        }
    }
}

struct Args {
    init: bool,
    identity: PathBuf,
    pub_out: PathBuf,
    socket: String,
    mcp: Vec<(String, String)>,
    models: Vec<String>,
    allow: Option<Vec<String>>,
    spool: PathBuf,
    expect: Option<PathBuf>,
    tpm: Option<PathBuf>,
    tpm_ca: Option<PathBuf>,
    registry_key: Option<PathBuf>,
    node: Option<String>,
    cert_validity: Option<u64>,
    cap_dir: PathBuf,
}

/// Once the attestation is accepted: the node certificate for the key CDK
/// proved in this session's handshake, as blob chunks (roadmap 3.5).
fn certify(
    reg: &Option<registry::Registry>,
    attestor: &attestation::Attestor,
    client: &Option<cdk_link::secure::Identity>,
    certified: &mut bool,
) -> Vec<Vec<u8>> {
    let (Some(reg), Some(client)) = (reg, client) else {
        return Vec::new();
    };
    if *certified || attestor.status != attestation::Status::Trusted {
        return Vec::new();
    }
    *certified = true;
    let cert = reg.certify(client, attestor.attested_digest());
    eprintln!(
        "gateway: -> node certificate: '{}' = CDK issuer {}… (serial {:#x})",
        cert.name,
        hex(&client.id()[..8]),
        cert.serial
    );
    cdk_link::peer::encode_blob(cdk_link::peer::kind::NODE_CERT, &cert.encode()).unwrap_or_default()
}

/// Capability exports and imports: the gateway carries them between its
/// outbox/inbox and CDK, which verifies everything (roadmap 3.5).
fn handle_peer(
    msg: &[u8],
    serving: bool,
    caps: &registry::CapDir,
    blobs: &mut cdk_link::peer::BlobAssembler,
) -> Vec<Vec<u8>> {
    use cdk_link::peer;
    if !serving {
        eprintln!("gateway: capability transfer refused — CDK not attested");
        return vec![peer::encode_status(
            false,
            "the gateway refuses: CDK not attested",
        )];
    }
    match msg.first() {
        Some(&peer::BLOB) => match blobs.push(msg) {
            Ok(Some((peer::kind::EXPORT, data))) => match caps.write_export(&data) {
                Ok(path) => vec![peer::encode_status(
                    true,
                    &format!("written to {}", path.display()),
                )],
                Err(e) => vec![peer::encode_status(false, &e)],
            },
            Ok(_) => Vec::new(),
            Err(e) => vec![peer::encode_status(false, e)],
        },
        Some(&peer::IMPORT_REQUEST) => {
            let Some(name) = peer::decode_import_request(msg) else {
                return vec![peer::encode_status(false, "bad import request")];
            };
            match caps.read_import(name) {
                Ok(data) => {
                    eprintln!("gateway: -> capability {name}.pcap from the inbox to CDK");
                    peer::encode_blob(peer::kind::IMPORT, &data).unwrap_or_default()
                }
                Err(e) => vec![peer::encode_status(false, &e)],
            }
        }
        _ => Vec::new(),
    }
}

fn args() -> Args {
    let mut a = Args {
        init: false,
        identity: PathBuf::from("target/gateway-identity.key"),
        pub_out: PathBuf::from("target/gateway.pub"),
        socket: "target/cdk-link.sock".to_string(),
        mcp: Vec::new(),
        models: Vec::new(),
        spool: PathBuf::from("target/approvals"),
        expect: None,
        tpm: None,
        tpm_ca: None,
        registry_key: None,
        node: None,
        cert_validity: None,
        cap_dir: PathBuf::from("target/caps"),
        allow: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--init" => a.init = true,
            "--identity" => a.identity = it.next().expect("--identity FILE").into(),
            "--pub-out" => a.pub_out = it.next().expect("--pub-out FILE").into(),
            "--mcp" => {
                let spec = it.next().expect("--mcp NAME=COMMAND");
                let (name, cmd) = spec.split_once('=').expect("--mcp NAME=COMMAND");
                a.mcp.push((name.to_string(), cmd.to_string()));
            }
            "--model" => a
                .models
                .push(it.next().expect("--model NAME=URL[,options]")),
            "--spool" => a.spool = it.next().expect("--spool DIR").into(),
            "--expect" => a.expect = Some(it.next().expect("--expect FILE").into()),
            "--tpm" => a.tpm = Some(it.next().expect("--tpm ENROLLMENT-FILE").into()),
            "--tpm-ca" => a.tpm_ca = Some(it.next().expect("--tpm-ca DIR").into()),
            "--registry-key" => {
                a.registry_key = Some(it.next().expect("--registry-key FILE").into())
            }
            "--node" => a.node = Some(it.next().expect("--node NAME")),
            "--cert-validity" => {
                a.cert_validity = Some(
                    it.next()
                        .and_then(|s| s.parse().ok())
                        .filter(|s| (60..=30 * 86400).contains(s))
                        .expect("--cert-validity SECONDS (60..=2592000)"),
                )
            }
            "--cap-dir" => a.cap_dir = it.next().expect("--cap-dir DIR").into(),
            "--allow" => {
                let list = it.next().expect("--allow tool1,tool2");
                a.allow = Some(list.split(',').map(str::to_string).collect());
            }
            s => a.socket = s.to_string(),
        }
    }
    a
}

enum Handshake {
    Idle,
    AwaitingFinish(ServerState),
}

fn main() -> std::io::Result<()> {
    let a = args();
    let me = load_identity(&a.identity)?;
    let mut pubkey = vec![0u8; secure::IDENTITY_LEN];
    me.public().write_to(&mut pubkey);
    if a.init {
        std::fs::write(&a.pub_out, &pubkey)?;
        eprintln!(
            "gateway: identity {} -> public key {} (pack into the CDK ramdisk as gateway.pub)",
            hex(&me.public().id()),
            a.pub_out.display()
        );
        return Ok(());
    }

    eprintln!("gateway: identity {}", hex(&me.public().id()));
    // Models first: `key-env` removes keys from the environment before any
    // MCP server is started.
    let mut backends = Vec::new();
    for spec in &a.models {
        match models::Backend::from_spec(spec) {
            Ok(b) => {
                eprintln!("gateway: model {}", b.describe());
                backends.push(b);
            }
            Err(e) => {
                let name = spec.split(',').next().unwrap_or("");
                eprintln!("gateway: --model {name}: {e}");
                std::process::exit(2);
            }
        }
    }
    let mut registry = mcp::Registry::default();
    for (name, cmd) in &a.mcp {
        match mcp::Server::start(name, cmd) {
            Ok(s) => {
                eprintln!("gateway: MCP server {name}: tools {:?}", s.tools);
                registry.add(s);
            }
            Err(e) => eprintln!("gateway: MCP server {name} failed: {e}"),
        }
    }
    let allowed = |t: &str| a.allow.as_ref().is_none_or(|l| l.iter().any(|x| x == t));
    eprintln!(
        "gateway: connecting to {} (waiting up to 60 s for CDK)",
        a.socket
    );
    let mut stream = match connect(&a.socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "gateway: cannot connect to the CDK link socket {} ({e})\n\
                 gateway: start CDK first (./run_qemu.sh), then the gateway",
                a.socket
            );
            std::process::exit(1);
        }
    };
    eprintln!("gateway: connected");
    send(&mut stream, kind::HELLO, 0, b"cdk-gateway 0.2")?;

    let mut decoder = Decoder::new();
    let mut reassembler = Reassembler::new();
    let mut handshake = Handshake::Idle;
    let mut session: Option<Session> = None;
    let mut announced: Option<String> = None;
    let spool = spool::Spool::open(&a.spool)?;
    let expect_text = a.expect.as_ref().map(|p| {
        std::fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("gateway: --expect {}: {e}", p.display());
            std::process::exit(2)
        })
    });
    let expect = expect_text.as_deref().map(|text| {
        cdk_link::attest::parse_expected(text).unwrap_or_else(|| {
            eprintln!("gateway: --expect: not a measurements file");
            std::process::exit(2)
        })
    });
    let expect_loader = expect_text
        .as_deref()
        .and_then(cdk_link::attest::parse_expected_loader);
    if expect_loader.is_some() {
        eprintln!("gateway: expecting a UEFI boot measured by CDK's loader (PCRs 11-12)");
    }
    if let Some(p) = &a.expect {
        eprintln!(
            "gateway: attestation required: expected measurements {}",
            p.display()
        );
    }
    if let Some(p) = &a.tpm {
        eprintln!(
            "gateway: TPM quote required: enrollment {} ({})",
            p.display(),
            if p.exists() {
                "enrolled"
            } else {
                "first valid quote enrolls"
            }
        );
    }
    let trust = a.tpm_ca.as_deref().map(|dir| {
        let store = ekcert::TrustStore::load(dir).unwrap_or_else(|e| {
            eprintln!("gateway: --tpm-ca: {e}");
            std::process::exit(2)
        });
        let (roots, intermediates) = store.len();
        eprintln!(
            "gateway: TPM endorsement required: {roots} manufacturer root CA(s), {intermediates} intermediate(s) from {}",
            dir.display()
        );
        store
    });
    let mut attestor = attestation::Attestor::new(expect, expect_loader, a.tpm.as_deref(), trust);
    // Distributed capabilities (roadmap 3.5): certify the attested CDK.
    let node_registry = a.registry_key.as_deref().map(|path| {
        let node = a.node.as_deref().unwrap_or_else(|| {
            eprintln!("gateway: --registry-key needs --node NAME");
            std::process::exit(2)
        });
        if a.expect.is_none() && a.tpm.is_none() && a.tpm_ca.is_none() {
            eprintln!("gateway: refusing to certify an unattested node: --registry-key needs --expect, --tpm or --tpm-ca");
            std::process::exit(2)
        }
        let mut reg = registry::Registry::load(path, node).unwrap_or_else(|e| {
            eprintln!("gateway: --registry-key: {e}");
            std::process::exit(2)
        });
        if let Some(v) = a.cert_validity {
            reg.validity_s = v;
        }
        eprintln!(
            "gateway: registry {}… will certify this CDK as node '{}' after its attestation is accepted",
            hex(&reg.public().id()[..8]),
            reg.node
        );
        reg
    });
    attestor.certify = node_registry.is_some();
    let caps = registry::CapDir(a.cap_dir.clone());
    let mut blobs = cdk_link::peer::BlobAssembler::default();
    let mut peer_identity: Option<cdk_link::secure::Identity> = None;
    let mut certified = false;
    eprintln!("gateway: approval spool {}", spool.dir().display());
    // Wake up regularly to forward operators' decisions.
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    let mut buf = [0u8; 8192];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if let Some(s) = session.as_mut() {
                    for d in spool.take_decisions() {
                        eprintln!(
                            "gateway: -> decision on request #{} ({}) from operator {}",
                            d.id,
                            if d.approve { "approve" } else { "deny" },
                            hex(&d.operator[..4])
                        );
                        for part in cdk_link::approval::encode_decision(
                            d.id,
                            d.operator,
                            d.approve,
                            &d.signature,
                        ) {
                            let mut out = [0u8; cdk_link::MAX_PAYLOAD];
                            let len = s.seal(&part, &mut out).expect("decision part fits");
                            send(&mut stream, kind::SEALED, 0, &out[..len])?;
                        }
                    }
                }
                continue;
            }
            Err(e) => return Err(e),
        };
        if n == 0 {
            eprintln!("gateway: CDK closed the link");
            return Ok(());
        }
        let mut rest = &buf[..n];
        while !rest.is_empty() {
            let used = decoder.push(rest);
            rest = &rest[used..];
            while let Some(frame) = decoder.next_frame() {
                let (k, flags, payload) = (frame.kind, frame.flags, frame.payload.to_vec());
                match k {
                    kind::HELLO => {
                        eprintln!("gateway: <- HELLO \"{}\"", printable(&payload));
                        announced = std::str::from_utf8(&payload)
                            .ok()
                            .and_then(|s| s.strip_prefix("cdk issuer="))
                            .map(str::to_string);
                    }
                    kind::PING => send(&mut stream, kind::PONG, 0, &payload)?,
                    kind::HANDSHAKE => {
                        let Ok(Some(msg)) = reassembler.push(flags, &payload) else {
                            continue;
                        };
                        handshake = match std::mem::replace(&mut handshake, Handshake::Idle) {
                            Handshake::AwaitingFinish(state) if msg.len() == secure::CF_LEN => {
                                let expected = announced.clone();
                                let result = secure::server_finish(state, &msg, |id, d, s| {
                                    // The client must sign correctly, and be the
                                    // issuer CDK announced in HELLO.
                                    let prefix = hex(&id.id()[..8]);
                                    hybrid::verify(id, d, s)
                                        && expected.as_deref().is_none_or(|a| a == prefix)
                                });
                                match result {
                                    Ok((s, client)) => {
                                        eprintln!(
                                            "gateway: SECURE session with CDK issuer {} (X25519+ML-KEM-768, ChaCha20-Poly1305)",
                                            hex(&client.id())
                                        );
                                        peer_identity = Some(client.clone());
                                        certified = false;
                                        session = Some(s);
                                        // Ask CDK to attest its measured boot.
                                        if let Some(s) = session.as_mut() {
                                            let req = attestor.request();
                                            let mut out = [0u8; cdk_link::MAX_PAYLOAD];
                                            let len = s.seal(&req, &mut out).expect("fits");
                                            send(&mut stream, kind::SEALED, 0, &out[..len])?;
                                        }
                                    }
                                    Err(e) => eprintln!("gateway: handshake rejected: {e:?}"),
                                }
                                Handshake::Idle
                            }
                            _ => {
                                // A (new) ClientHello: any old session ends.
                                session = None;
                                let mut rnd = secure::ServerRandom {
                                    x25519: [0; 32],
                                    kem_m: [0; 32],
                                    nonce: [0; 32],
                                };
                                OsRng.fill_bytes(&mut rnd.x25519);
                                OsRng.fill_bytes(&mut rnd.kem_m);
                                OsRng.fill_bytes(&mut rnd.nonce);
                                match secure::server_respond(&msg, rnd, me.public(), |d| me.sign(d))
                                {
                                    Ok((state, sh)) => {
                                        eprintln!(
                                            "gateway: <- ClientHello, -> ServerHello ({} B)",
                                            sh.len()
                                        );
                                        let mut err = None;
                                        secure::for_each_fragment(&sh, |f, chunk| {
                                            if err.is_none() {
                                                err = send(&mut stream, kind::HANDSHAKE, f, chunk)
                                                    .err();
                                            }
                                        });
                                        if let Some(e) = err {
                                            return Err(e);
                                        }
                                        Handshake::AwaitingFinish(state)
                                    }
                                    Err(e) => {
                                        eprintln!("gateway: bad ClientHello: {e:?}");
                                        Handshake::Idle
                                    }
                                }
                            }
                        };
                    }
                    kind::SEALED => {
                        let Some(s) = session.as_mut() else {
                            eprintln!("gateway: sealed frame without a session — dropped");
                            continue;
                        };
                        let mut plain = [0u8; cdk_link::MAX_PAYLOAD];
                        match s.open(&payload, &mut plain) {
                            Ok(m) if m > 0 && cdk_link::tpm::is_quote(&plain[..m]) => {
                                if let Some(challenge) = attestor.on_quote(&plain[..m]) {
                                    let mut out = [0u8; cdk_link::MAX_PAYLOAD];
                                    let len = s.seal(&challenge, &mut out).expect("challenge fits");
                                    send(&mut stream, kind::SEALED, 0, &out[..len])?;
                                }
                            }
                            Ok(m) if m > 0 && cdk_link::tpm::is_endorsement(&plain[..m]) => {
                                attestor.on_endorsement(&plain[..m]);
                                for msg in certify(
                                    &node_registry,
                                    &attestor,
                                    &peer_identity,
                                    &mut certified,
                                ) {
                                    let mut out = [0u8; cdk_link::MAX_PAYLOAD];
                                    let len = s.seal(&msg, &mut out).expect("chunk fits");
                                    send(&mut stream, kind::SEALED, 0, &out[..len])?;
                                }
                            }
                            Ok(m) if m > 0 && cdk_link::attest::is_attest(&plain[..m]) => {
                                attestor.on_message(&plain[..m]);
                                for msg in certify(
                                    &node_registry,
                                    &attestor,
                                    &peer_identity,
                                    &mut certified,
                                ) {
                                    let mut out = [0u8; cdk_link::MAX_PAYLOAD];
                                    let len = s.seal(&msg, &mut out).expect("chunk fits");
                                    send(&mut stream, kind::SEALED, 0, &out[..len])?;
                                }
                            }
                            Ok(m) if m > 0 && cdk_link::peer::is_peer(&plain[..m]) => {
                                for msg in
                                    handle_peer(&plain[..m], attestor.serving(), &caps, &mut blobs)
                                {
                                    let mut out = [0u8; cdk_link::MAX_PAYLOAD];
                                    let len = s.seal(&msg, &mut out).expect("message fits");
                                    send(&mut stream, kind::SEALED, 0, &out[..len])?;
                                }
                            }
                            Ok(m) if m > 0 && cdk_link::approval::is_approval(&plain[..m]) => {
                                if attestor.serving() {
                                    spool.on_message(&plain[..m]);
                                } else {
                                    eprintln!(
                                        "gateway: approval message refused — CDK not attested"
                                    );
                                }
                            }
                            Ok(m) if plain[0] <= tool::LIST_RESPONSE && m > 0 => {
                                let replies = if attestor.serving() {
                                    handle_tool(&plain[..m], &mut registry, &backends, &allowed)
                                } else {
                                    eprintln!("gateway: tool message refused — CDK not attested");
                                    refuse_unattested(&plain[..m])
                                };
                                for reply in replies {
                                    let mut out = [0u8; cdk_link::MAX_PAYLOAD];
                                    let len = s.seal(&reply, &mut out).expect("tool reply fits");
                                    send(&mut stream, kind::SEALED, 0, &out[..len])?;
                                }
                            }
                            Ok(m) => {
                                let text = &plain[..m];
                                eprintln!("gateway: <- SEALED \"{}\"", printable(text));
                                let mut reply = b"sealed ack: ".to_vec();
                                reply.extend_from_slice(text);
                                reply.truncate(secure::MAX_PLAINTEXT);
                                let mut out = [0u8; cdk_link::MAX_PAYLOAD];
                                let len = s.seal(&reply, &mut out).expect("fits");
                                send(&mut stream, kind::SEALED, 0, &out[..len])?;
                            }
                            Err(e) => eprintln!("gateway: sealed frame REJECTED: {e:?}"),
                        }
                    }
                    kind::DATA if session.is_some() => {
                        eprintln!("gateway: plaintext DATA refused (secure session active)");
                    }
                    kind::DATA if payload.starts_with(b"burst ") => {
                        let n: usize = std::str::from_utf8(&payload[6..])
                            .ok()
                            .and_then(|s| s.trim().parse().ok())
                            .unwrap_or(1)
                            .min(1000);
                        eprintln!("gateway: <- burst request, -> {n} frames");
                        for i in 0..n {
                            let mut f = format!("burst {i:04} ").into_bytes();
                            while f.len() < 1000 {
                                f.push(b'a' + (f.len() % 26) as u8);
                            }
                            send(&mut stream, kind::DATA, 0, &f)?;
                        }
                    }
                    kind::DATA => {
                        eprintln!("gateway: <- DATA \"{}\"", printable(&payload));
                        let mut reply = b"ack: ".to_vec();
                        reply.extend_from_slice(&payload);
                        reply.truncate(cdk_link::MAX_PAYLOAD);
                        send(&mut stream, kind::DATA, 0, &reply)?;
                    }
                    other => eprintln!("gateway: <- unknown frame type {other}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_registry() -> mcp::Registry {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/demo_mcp_server.py");
        let mut r = mcp::Registry::default();
        r.add(
            mcp::Server::start("demo", &format!("python3 {script}"))
                .expect("start demo MCP server"),
        );
        r
    }

    fn call(
        r: &mut mcp::Registry,
        allowed: &dyn Fn(&str) -> bool,
        name: &str,
        args: &[u8],
    ) -> (Status, String) {
        let req = tool::encode_call_request(7, name, args).unwrap();
        match tool::decode(&handle_tool(&req, r, &[], allowed)[0]).unwrap() {
            tool::Message::CallResponse {
                call_id,
                status,
                body,
            } => {
                assert_eq!(call_id, 7);
                (status, String::from_utf8(body.to_vec()).unwrap())
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn allowlist_filters_listing_and_refuses_calls() {
        let mut r = demo_registry();
        let allowed = |t: &str| t == "echo";
        let list = handle_tool(&tool::encode_list_request(), &mut r, &[], &allowed);
        match tool::decode(&list[0]).unwrap() {
            tool::Message::ListResponse(names) => {
                assert_eq!(
                    names,
                    [tool::Entry {
                        name: "echo",
                        flags: 0,
                        endpoint: "mcp:demo"
                    }]
                )
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            call(&mut r, &allowed, "echo", br#"{"text":"hi"}"#),
            (Status::Ok, "hi".into())
        );
        let (status, _) = call(&mut r, &allowed, "word_count", br#"{"text":"a b"}"#);
        assert_eq!(status, Status::Refused);
    }

    #[test]
    fn call_outcomes_map_to_statuses() {
        let mut r = demo_registry();
        let all = |_: &str| true;
        assert_eq!(
            call(&mut r, &all, "word_count", br#"{"text":"a b c"}"#),
            (Status::Ok, "3".into())
        );
        assert_eq!(call(&mut r, &all, "nope", b"{}").0, Status::UnknownTool);
        assert_eq!(
            call(&mut r, &all, "sleep", br#"{"seconds":"x"}"#).0,
            Status::ToolError
        );
        // Arguments that are not a JSON object are rejected before the server.
        assert_eq!(call(&mut r, &all, "echo", b"not json").0, Status::ToolError);
        // The server survives all of the above.
        assert_eq!(
            call(&mut r, &all, "echo", br#"{"text":"ok"}"#),
            (Status::Ok, "ok".into())
        );
    }
}
