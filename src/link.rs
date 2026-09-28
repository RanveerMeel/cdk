//! Framed link to the host gateway (roadmap 3.1), over [`virtio_console`].
//!
//! Frames use the shared `cdk-link` crate, so the kernel and the host
//! gateway speak byte-identical framing. Everything here is plaintext and
//! only integrity-checked (CRC); the post-quantum secure channel (roadmap
//! 3.2) will run inside `DATA` frames.
//!
//! [`virtio_console`]: crate::virtio_console

use cdk_link::{kind, Decoder, MAX_FRAME};
use spin::Mutex;

use crate::virtio_console;

static DECODER: Mutex<Decoder> = Mutex::new(Decoder::new());

/// Send one frame.
pub fn send(kind: u8, payload: &[u8]) -> Result<(), &'static str> {
    let mut buf = [0u8; MAX_FRAME];
    let n = cdk_link::encode(kind, payload, &mut buf).map_err(|_| "frame too large")?;
    virtio_console::write_all(&buf[..n])
}

/// Drain the device and hand each complete frame to `f(kind, payload)`.
/// Returns the number of frames delivered.
pub fn poll(mut f: impl FnMut(u8, &[u8])) -> usize {
    let mut dec = DECODER.lock();
    let mut frames = 0;
    virtio_console::poll(|mut bytes| {
        while !bytes.is_empty() {
            let n = dec.push(bytes);
            bytes = &bytes[n..];
            while let Some(frame) = dec.next_frame() {
                frames += 1;
                f(frame.kind, frame.payload);
            }
        }
    });
    frames
}

/// Decoder counters (frames, CRC errors, skipped bytes).
pub fn decoder_stats() -> cdk_link::DecoderStats {
    DECODER.lock().stats
}

/// Send a `PING` with `nonce` and wait up to ~`timeout_ms` for the matching
/// `PONG`. Other frames that arrive meanwhile go to `other`. Returns the
/// round trip in TSC cycles.
pub fn ping(
    nonce: u64,
    timeout_ms: u64,
    mut other: impl FnMut(u8, &[u8]),
) -> Result<u64, &'static str> {
    let start = crate::cpu::rdtsc();
    send(kind::PING, &nonce.to_le_bytes())?;
    // ~2 GHz TSC assumed; coarse on purpose.
    let limit = timeout_ms.saturating_mul(2_000_000);
    loop {
        let mut rtt = None;
        poll(|k, p| {
            if k == kind::PONG && p == nonce.to_le_bytes() {
                rtt = Some(crate::cpu::rdtsc().wrapping_sub(start));
            } else {
                other(k, p);
            }
        });
        if let Some(r) = rtt {
            return Ok(r);
        }
        if crate::cpu::rdtsc().wrapping_sub(start) > limit {
            return Err("no PONG (is the gateway connected?)");
        }
        core::hint::spin_loop();
    }
}
