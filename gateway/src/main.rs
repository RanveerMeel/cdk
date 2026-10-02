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
//!
//! ```text
//! cdk-gateway --init [--identity FILE] [--pub-out FILE]   create identity, export public key
//! cdk-gateway [--identity FILE] [--mcp NAME=COMMAND]... [--model SPEC]... [--allow t1,t2] [SOCKET]
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

mod mcp;
mod models;

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
            let names: Vec<String> = registry
                .tool_names()
                .into_iter()
                .chain(models.iter().map(models::Backend::tool_name))
                .filter(|n| allowed(n))
                .take(tool::MAX_TOOLS)
                .collect();
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            eprintln!("gateway: <- tools/list, -> {refs:?}");
            vec![tool::encode_list_response(&refs)
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

fn connect(path: &str) -> std::io::Result<UnixStream> {
    let deadline = Instant::now() + Duration::from_secs(60);
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
}

fn args() -> Args {
    let mut a = Args {
        init: false,
        identity: PathBuf::from("target/gateway-identity.key"),
        pub_out: PathBuf::from("target/gateway.pub"),
        socket: "target/cdk-link.sock".to_string(),
        mcp: Vec::new(),
        models: Vec::new(),
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
    eprintln!("gateway: connecting to {}", a.socket);
    let mut stream = connect(&a.socket)?;
    eprintln!("gateway: connected");
    send(&mut stream, kind::HELLO, 0, b"cdk-gateway 0.2")?;

    let mut decoder = Decoder::new();
    let mut reassembler = Reassembler::new();
    let mut handshake = Handshake::Idle;
    let mut session: Option<Session> = None;
    let mut announced: Option<String> = None;
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf)?;
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
                                        session = Some(s);
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
                            Ok(m) if plain[0] <= tool::LIST_RESPONSE && m > 0 => {
                                for reply in
                                    handle_tool(&plain[..m], &mut registry, &backends, &allowed)
                                {
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
                assert_eq!(names.into_iter().collect::<Vec<&str>>(), ["echo"])
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
