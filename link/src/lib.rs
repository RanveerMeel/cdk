//! The CDK ↔ host link protocol (roadmap Phase 3), shared by the kernel and
//! the host gateway so both sides are byte-identical. `no_std`.
//!
//! The transport is a reliable byte stream (virtio-console today). This
//! crate provides framing over it; the post-quantum secure channel
//! (roadmap 3.2) will run inside `DATA` frames.
//!
//! ## Frame format v1
//!
//! ```text
//! magic "CDK1" | type u8 | flags u8 | len u16 LE | payload[len] | crc32 LE
//! ```
//!
//! `len` ≤ [`MAX_PAYLOAD`]. The CRC-32 (IEEE) covers `type ‖ flags ‖ len ‖
//! payload` and only detects corruption — authenticity and secrecy come from
//! the secure channel, not from the frame layer. The [`Decoder`] resyncs on
//! the next magic after garbage or a bad CRC.

#![no_std]

extern crate alloc;

pub mod secure;
pub mod tool;

pub const MAGIC: [u8; 4] = *b"CDK1";
pub const MAX_PAYLOAD: usize = 1024;
const HEADER: usize = 8;
const TRAILER: usize = 4;
pub const MAX_FRAME: usize = HEADER + MAX_PAYLOAD + TRAILER;

/// Frame types.
pub mod kind {
    /// Peer announces itself; payload = UTF-8 name.
    pub const HELLO: u8 = 1;
    /// Liveness probe; payload echoed in the `PONG`.
    pub const PING: u8 = 2;
    pub const PONG: u8 = 3;
    /// Application data (plaintext; only before a secure session exists).
    pub const DATA: u8 = 4;
    /// Handshake message fragment; `flags` bit 0 = more fragments follow.
    pub const HANDSHAKE: u8 = 5;
    /// AEAD-sealed application data (see [`crate::secure::Session`]).
    pub const SEALED: u8 = 6;
}

/// `flags` bit: more fragments of this message follow.
pub const FLAG_MORE: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    PayloadTooLarge,
    BufferTooSmall,
}

/// CRC-32 (IEEE 802.3, reflected, init/xorout 0xFFFFFFFF).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Encode one frame into `out`; returns its length.
pub fn encode(kind: u8, payload: &[u8], out: &mut [u8]) -> Result<usize, FrameError> {
    encode_with_flags(kind, 0, payload, out)
}

/// [`encode`] with explicit flags.
pub fn encode_with_flags(
    kind: u8,
    flags: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, FrameError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(FrameError::PayloadTooLarge);
    }
    let total = HEADER + payload.len() + TRAILER;
    if out.len() < total {
        return Err(FrameError::BufferTooSmall);
    }
    out[..4].copy_from_slice(&MAGIC);
    out[4] = kind;
    out[5] = flags;
    out[6..8].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    out[8..8 + payload.len()].copy_from_slice(payload);
    let crc = crc32(&out[4..8 + payload.len()]);
    out[8 + payload.len()..total].copy_from_slice(&crc.to_le_bytes());
    Ok(total)
}

/// A decoded frame borrowing the decoder's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: u8,
    pub flags: u8,
    pub payload: &'a [u8],
}

/// Counters for diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DecoderStats {
    pub frames: u64,
    pub crc_errors: u64,
    /// Bytes skipped while searching for a magic.
    pub skipped: u64,
    pub oversized: u64,
}

/// Streaming frame decoder: push bytes, pop frames.
pub struct Decoder {
    buf: [u8; MAX_FRAME],
    len: usize,
    /// Bytes of the frame last returned, dropped on the next call.
    pending: usize,
    pub stats: DecoderStats,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_FRAME],
            len: 0,
            pending: 0,
            stats: DecoderStats {
                frames: 0,
                crc_errors: 0,
                skipped: 0,
                oversized: 0,
            },
        }
    }

    /// Append bytes; returns how many were accepted (stop and call
    /// [`next_frame`](Self::next_frame) when the buffer is full).
    pub fn push(&mut self, bytes: &[u8]) -> usize {
        self.settle();
        let n = bytes.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        n
    }

    fn settle(&mut self) {
        if self.pending > 0 {
            let n = self.pending;
            self.pending = 0;
            self.drop_front(n);
        }
    }

    fn drop_front(&mut self, n: usize) {
        self.buf.copy_within(n..self.len, 0);
        self.len -= n;
    }

    /// Next complete, valid frame, or `None` if more bytes are needed.
    /// Garbage and corrupt frames are skipped (and counted).
    pub fn next_frame(&mut self) -> Option<Frame<'_>> {
        self.settle();
        loop {
            // Align on a magic.
            let start = (0..self.len).find(|&i| {
                let tail = &self.buf[i..self.len];
                let k = tail.len().min(4);
                tail[..k] == MAGIC[..k]
            });
            match start {
                Some(0) => {}
                Some(i) => {
                    self.stats.skipped += i as u64;
                    self.drop_front(i);
                }
                None => {
                    self.stats.skipped += self.len as u64;
                    self.len = 0;
                    return None;
                }
            }
            if self.len < HEADER {
                return None;
            }
            let plen = u16::from_le_bytes([self.buf[6], self.buf[7]]) as usize;
            if plen > MAX_PAYLOAD {
                // Not a real frame: skip this magic and resync.
                self.stats.oversized += 1;
                self.drop_front(1);
                continue;
            }
            let total = HEADER + plen + TRAILER;
            if self.len < total {
                return None;
            }
            let crc = u32::from_le_bytes([
                self.buf[8 + plen],
                self.buf[9 + plen],
                self.buf[10 + plen],
                self.buf[11 + plen],
            ]);
            if crc != crc32(&self.buf[4..8 + plen]) {
                self.stats.crc_errors += 1;
                self.drop_front(1);
                continue;
            }
            // The frame stays in place until the next call drops it.
            self.stats.frames += 1;
            self.pending = total;
            return Some(Frame {
                kind: self.buf[4],
                flags: self.buf[5],
                payload: &self.buf[HEADER..HEADER + plen],
            });
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = [0u8; MAX_FRAME];
        let n = encode(kind, payload, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn decode_all(bytes: &[u8]) -> (Vec<(u8, Vec<u8>)>, DecoderStats) {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        let mut rest = bytes;
        loop {
            let n = d.push(rest);
            rest = &rest[n..];
            while let Some(f) = d.next_frame() {
                out.push((f.kind, f.payload.to_vec()));
            }
            if rest.is_empty() {
                break;
            }
        }
        (out, d.stats)
    }

    #[test]
    fn crc32_matches_reference() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn round_trip_including_byte_by_byte_delivery() {
        let mut stream = frame(kind::HELLO, b"cdk");
        stream.extend(frame(kind::DATA, &[7u8; MAX_PAYLOAD]));
        stream.extend(frame(kind::PING, b""));
        let (frames, stats) = decode_all(&stream);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], (kind::HELLO, b"cdk".to_vec()));
        assert_eq!(frames[1].1.len(), MAX_PAYLOAD);
        assert_eq!(frames[2], (kind::PING, Vec::new()));
        assert_eq!(stats.frames, 3);

        let mut d = Decoder::new();
        let mut got = 0;
        for b in &stream {
            assert_eq!(d.push(core::slice::from_ref(b)), 1);
            while d.next_frame().is_some() {
                got += 1;
            }
        }
        assert_eq!(got, 3);
    }

    #[test]
    fn resyncs_after_garbage_and_corruption() {
        let mut stream = b"noise CDK garbage".to_vec();
        stream.extend(frame(kind::DATA, b"one"));
        let mut bad = frame(kind::DATA, b"two");
        bad[9] ^= 0xFF; // corrupt payload -> CRC mismatch
        stream.extend(bad);
        stream.extend(b"CDK1\x04\x00\xff\xff"); // oversized length
        stream.extend(frame(kind::DATA, b"three"));
        let (frames, stats) = decode_all(&stream);
        let payloads: Vec<_> = frames.iter().map(|f| f.1.clone()).collect();
        assert_eq!(payloads, std::vec![b"one".to_vec(), b"three".to_vec()]);
        assert_eq!(stats.crc_errors, 1);
        assert_eq!(stats.oversized, 1);
        assert!(stats.skipped > 0);
    }

    #[test]
    fn encode_rejects_bad_sizes() {
        let mut out = [0u8; MAX_FRAME];
        assert_eq!(
            encode(kind::DATA, &[0; MAX_PAYLOAD + 1], &mut out),
            Err(FrameError::PayloadTooLarge)
        );
        assert_eq!(
            encode(kind::DATA, b"x", &mut out[..8]),
            Err(FrameError::BufferTooSmall)
        );
    }
}
