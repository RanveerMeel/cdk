//! Host-side gateway for the CDK link (roadmap Phase 3).
//!
//! Connects to the Unix socket QEMU exposes for CDK's virtio-console and
//! speaks the shared `cdk-link` framing. Today it is an echo peer: it logs
//! `HELLO`, answers `PING` with `PONG`, and acknowledges `DATA`. The
//! post-quantum secure channel (3.2) and the MCP tool gateway (3.3) build
//! on this loop.
//!
//!   tools/run_gateway.sh [socket]       (default target/cdk-link.sock)

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use cdk_link::{kind, Decoder, MAX_FRAME};

fn send(stream: &mut UnixStream, k: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut buf = [0u8; MAX_FRAME];
    let n = cdk_link::encode(k, payload, &mut buf).expect("payload fits a frame");
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

fn connect(path: &str) -> std::io::Result<UnixStream> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match UnixStream::connect(path) {
            Ok(s) => return Ok(s),
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(e),
        }
    }
}

fn main() -> std::io::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target/cdk-link.sock".to_string());
    eprintln!("gateway: connecting to {path}");
    let mut stream = connect(&path)?;
    eprintln!("gateway: connected");
    send(&mut stream, kind::HELLO, b"cdk-gateway 0.1")?;

    let mut decoder = Decoder::new();
    let mut buf = [0u8; 4096];
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
                let (k, payload) = (frame.kind, frame.payload.to_vec());
                match k {
                    kind::HELLO => eprintln!("gateway: <- HELLO \"{}\"", printable(&payload)),
                    kind::PING => {
                        eprintln!("gateway: <- PING, -> PONG");
                        send(&mut stream, kind::PONG, &payload)?;
                    }
                    kind::DATA if payload.starts_with(b"burst ") => {
                        // Link test: N near-maximum frames, each tagged and
                        // filled with a checkable pattern.
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
                            send(&mut stream, kind::DATA, &f)?;
                        }
                    }
                    kind::DATA => {
                        eprintln!("gateway: <- DATA \"{}\"", printable(&payload));
                        let mut reply = b"ack: ".to_vec();
                        reply.extend_from_slice(&payload);
                        reply.truncate(cdk_link::MAX_PAYLOAD);
                        send(&mut stream, kind::DATA, &reply)?;
                    }
                    other => eprintln!("gateway: <- unknown frame type {other}"),
                }
            }
        }
    }
}
