//! Persistent sealed store: the state a CDK node must keep across reboots
//! (revocations it issued, peer messages and capabilities it already
//! accepted), shared by the kernel and the gateway.
//!
//! The kernel has no disk; its gateway keeps the store as an opaque file.
//! The gateway is not trusted with it:
//!
//! * **Confidentiality and integrity.** The records are encrypted with a
//!   random 256-bit key (ChaCha20-Poly1305). The key itself is *sealed* by
//!   the node's TPM to the boot chain measured before the kernel ran
//!   (firmware, loader, kernel), and travels in the envelope as the TPM's
//!   `TPM2B_PUBLIC`/`TPM2B_PRIVATE` pair: only that TPM, after that boot
//!   chain, will unseal it.
//! * **Freshness.** Every envelope carries a counter value, authenticated
//!   with the records. The TPM holds a monotonic NV counter: the kernel
//!   writes the envelope for `counter + 1`, waits for the gateway to
//!   confirm it is stored, then increments the TPM counter. At boot an
//!   envelope must carry the TPM's value ([`Freshness::Current`]) or the
//!   next one (a write whose increment did not happen:
//!   [`Freshness::Uncommitted`], committed then); anything older is a
//!   rollback.
//!
//! ```text
//! Envelope : "CDK-STORE-v1" | counter u64 | public_len u16 | sealed public
//!            | private_len u16 | sealed private | nonce [12]     (authenticated)
//!            | ct_len u32 | ciphertext (records) | tag [16]
//! Records  : n u16 | revoked serial u64 × n
//!            | n u16 | delivered (sender id [16], seq u64, not_after u64) × n
//!            | n u16 | imported (issuer id [16], serial u64, not_after u64) × n
//! StoreGet : 0x4A                       (kernel → gateway; answered with a
//!                                        `kind::STORE` blob, or a status)
//! ```
//!
//! Integers are little-endian. Decoding is strict: an encoding decodes only
//! if re-encoding gives the same bytes.

use alloc::vec::Vec;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

pub const MAGIC: &[u8; 12] = b"CDK-STORE-v1";
/// Link message: the kernel asks the gateway for the stored envelope.
pub const STORE_GET: u8 = 0x4A;
/// Store key length (ChaCha20-Poly1305).
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Largest sealed TPM object part the envelope carries.
pub const MAX_SEALED: usize = 512;
/// Record limits (each list is pruned of expired entries before it fills).
pub const MAX_REVOKED: usize = 128;
pub const MAX_DELIVERED: usize = 256;
pub const MAX_IMPORTED: usize = 64;
/// Largest envelope (fits one peer blob).
pub const MAX_ENVELOPE: usize = MAGIC.len()
    + 8
    + 2 * (2 + MAX_SEALED)
    + NONCE_LEN
    + 4
    + 6
    + 8 * MAX_REVOKED
    + 32 * (MAX_DELIVERED + MAX_IMPORTED)
    + TAG_LEN;

/// An accepted message or import: who (a sender's or issuer's per-boot key
/// id), which (sequence number or serial), and until when it matters (after
/// `not_after` the peer's certificate or delegation has expired, so the
/// same bytes would be refused anyway and the entry can be dropped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen {
    pub id: [u8; 16],
    pub n: u64,
    pub not_after: u64,
}

/// What the store holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Records {
    /// Serials of delegations this node revoked.
    pub revoked: Vec<u64>,
    /// Peer messages delivered here.
    pub delivered: Vec<Seen>,
    /// Portable capabilities imported here.
    pub imported: Vec<Seen>,
}

/// A bounds-checked reader over a byte slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// The next `n` bytes, or `None` if fewer remain.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    /// A little-endian `u16`.
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    /// A little-endian `u32`.
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    /// A little-endian `u64`.
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    /// One [`Seen`] entry.
    fn seen(&mut self) -> Option<Seen> {
        Some(Seen {
            id: self.take(16)?.try_into().ok()?,
            n: self.u64()?,
            not_after: self.u64()?,
        })
    }
}

impl Records {
    /// Whether every list is within its limit.
    pub fn fits(&self) -> bool {
        self.revoked.len() <= MAX_REVOKED
            && self.delivered.len() <= MAX_DELIVERED
            && self.imported.len() <= MAX_IMPORTED
    }

    /// Drop entries whose certificate or delegation expired before `now`
    /// (the gateway's clock). Revocations are kept: their delegations'
    /// lifetimes are not recorded.
    pub fn prune(&mut self, now: u64) {
        self.delivered.retain(|s| s.not_after >= now);
        self.imported.retain(|s| s.not_after >= now);
    }

    /// The plaintext encoding; `None` if a list is over its limit.
    pub fn encode(&self) -> Option<Vec<u8>> {
        if !self.fits() {
            return None;
        }
        let mut v = Vec::with_capacity(
            6 + 8 * self.revoked.len() + 32 * (self.delivered.len() + self.imported.len()),
        );
        v.extend_from_slice(&(self.revoked.len() as u16).to_le_bytes());
        for s in &self.revoked {
            v.extend_from_slice(&s.to_le_bytes());
        }
        for list in [&self.delivered, &self.imported] {
            v.extend_from_slice(&(list.len() as u16).to_le_bytes());
            for s in list {
                v.extend_from_slice(&s.id);
                v.extend_from_slice(&s.n.to_le_bytes());
                v.extend_from_slice(&s.not_after.to_le_bytes());
            }
        }
        Some(v)
    }

    /// Strict decoding.
    pub fn decode(b: &[u8]) -> Option<Records> {
        let mut r = Reader(b);
        let n = r.u16()? as usize;
        if n > MAX_REVOKED {
            return None;
        }
        let mut revoked = Vec::with_capacity(n);
        for _ in 0..n {
            revoked.push(r.u64()?);
        }
        let mut lists = [Vec::new(), Vec::new()];
        for (list, max) in lists.iter_mut().zip([MAX_DELIVERED, MAX_IMPORTED]) {
            let n = r.u16()? as usize;
            if n > max {
                return None;
            }
            for _ in 0..n {
                list.push(r.seen()?);
            }
        }
        let [delivered, imported] = lists;
        r.0.is_empty().then_some(Records {
            revoked,
            delivered,
            imported,
        })
    }
}

/// The stored file: the sealed key and the encrypted records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// The TPM counter value this envelope is for.
    pub counter: u64,
    /// The sealed key object (`TPM2B_PUBLIC` contents).
    pub sealed_public: Vec<u8>,
    /// The sealed key object (`TPM2B_PRIVATE` contents).
    pub sealed_private: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    /// Encrypted records followed by the tag.
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    /// The authenticated header (everything before the ciphertext length).
    fn header(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            MAGIC.len() + 8 + 4 + self.sealed_public.len() + self.sealed_private.len() + NONCE_LEN,
        );
        v.extend_from_slice(MAGIC);
        v.extend_from_slice(&self.counter.to_le_bytes());
        for part in [&self.sealed_public, &self.sealed_private] {
            v.extend_from_slice(&(part.len() as u16).to_le_bytes());
            v.extend_from_slice(part);
        }
        v.extend_from_slice(&self.nonce);
        v
    }

    /// Encrypt `records` under `key` for `counter`. `nonce` must never repeat
    /// for one key (the kernel draws it at random). `None` if the records or
    /// the sealed parts are over their limits.
    pub fn seal(
        key: &[u8; KEY_LEN],
        counter: u64,
        sealed_public: &[u8],
        sealed_private: &[u8],
        nonce: [u8; NONCE_LEN],
        records: &Records,
    ) -> Option<Envelope> {
        if sealed_public.len() > MAX_SEALED || sealed_private.len() > MAX_SEALED {
            return None;
        }
        let mut env = Envelope {
            counter,
            sealed_public: sealed_public.to_vec(),
            sealed_private: sealed_private.to_vec(),
            nonce,
            ciphertext: Vec::new(),
        };
        let mut body = records.encode()?;
        let tag = ChaCha20Poly1305::new(key.into())
            .encrypt_in_place_detached(&nonce.into(), &env.header(), &mut body)
            .ok()?;
        body.extend_from_slice(&tag);
        env.ciphertext = body;
        Some(env)
    }

    /// Decrypt with `key`; `None` if anything was changed or the key is
    /// wrong.
    pub fn open(&self, key: &[u8; KEY_LEN]) -> Option<Records> {
        let split = self.ciphertext.len().checked_sub(TAG_LEN)?;
        let mut body = self.ciphertext[..split].to_vec();
        let tag = chacha20poly1305::Tag::from_slice(&self.ciphertext[split..]);
        ChaCha20Poly1305::new(key.into())
            .decrypt_in_place_detached(&self.nonce.into(), &self.header(), &mut body, tag)
            .ok()?;
        let records = Records::decode(&body);
        zeroize::Zeroize::zeroize(body.as_mut_slice());
        records
    }

    /// The wire form (see the module documentation).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.header();
        v.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.ciphertext);
        v
    }

    /// Strict decoding (the ciphertext is checked only by [`Envelope::open`]).
    pub fn decode(b: &[u8]) -> Option<Envelope> {
        if b.len() > MAX_ENVELOPE {
            return None;
        }
        let mut r = Reader(b);
        if r.take(MAGIC.len())? != MAGIC {
            return None;
        }
        let counter = r.u64()?;
        let mut parts = [Vec::new(), Vec::new()];
        for part in parts.iter_mut() {
            let n = r.u16()? as usize;
            if n > MAX_SEALED {
                return None;
            }
            *part = r.take(n)?.to_vec();
        }
        let nonce = r.take(NONCE_LEN)?.try_into().ok()?;
        let n = r.u32()? as usize;
        if n < TAG_LEN {
            return None;
        }
        let ciphertext = r.take(n)?.to_vec();
        let [sealed_public, sealed_private] = parts;
        r.0.is_empty().then_some(Envelope {
            counter,
            sealed_public,
            sealed_private,
            nonce,
            ciphertext,
        })
    }
}

/// How an envelope's counter relates to the TPM's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// The latest committed state.
    Current,
    /// Written, but the TPM counter was not incremented after it (the node
    /// stopped in between): commit it now.
    Uncommitted,
    /// Older than the TPM counter: a rollback (or lost writes).
    RolledBack,
    /// Newer than any write the kernel can have made.
    Invalid,
}

/// Compare an envelope's `counter` with the TPM counter `tpm`.
pub fn freshness(counter: u64, tpm: u64) -> Freshness {
    if counter == tpm {
        Freshness::Current
    } else if Some(counter) == tpm.checked_add(1) {
        Freshness::Uncommitted
    } else if counter < tpm {
        Freshness::RolledBack
    } else {
        Freshness::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sample records with every list in use.
    fn records() -> Records {
        Records {
            revoked: alloc::vec![7, u64::MAX],
            delivered: alloc::vec![Seen {
                id: [1; 16],
                n: 3,
                not_after: 100
            }],
            imported: alloc::vec![
                Seen {
                    id: [2; 16],
                    n: 9,
                    not_after: 50
                },
                Seen {
                    id: [3; 16],
                    n: 1,
                    not_after: 500
                },
            ],
        }
    }

    /// Records and envelopes round-trip; strict decoding refuses extra or
    /// missing bytes and lists over their limits.
    #[test]
    fn records_and_envelopes_round_trip() {
        let r = records();
        let enc = r.encode().unwrap();
        assert_eq!(Records::decode(&enc), Some(r.clone()));
        assert!(Records::decode(&enc[..enc.len() - 1]).is_none());
        let mut long = enc.clone();
        long.push(0);
        assert!(Records::decode(&long).is_none());
        let mut over = Records::default();
        over.imported = alloc::vec![Seen { id: [0; 16], n: 0, not_after: 0 }; MAX_IMPORTED + 1];
        assert!(over.encode().is_none());
        assert!(Records::decode(&[0, 0, 0, 0, 0xFF, 0xFF]).is_none());

        let key = [9u8; KEY_LEN];
        let env = Envelope::seal(&key, 42, b"pub", b"priv", [5; NONCE_LEN], &r).unwrap();
        let bytes = env.encode();
        let back = Envelope::decode(&bytes).unwrap();
        assert_eq!(back, env);
        assert_eq!(back.encode(), bytes);
        assert_eq!(back.open(&key), Some(r));
        assert!(Envelope::decode(&bytes[..bytes.len() - 1]).is_none());
        assert!(bytes.len() <= MAX_ENVELOPE);
    }

    /// Any change to the envelope — counter, sealed key, nonce, records —
    /// or the wrong key fails authentication.
    #[test]
    fn tampering_is_detected() {
        let key = [9u8; KEY_LEN];
        let env = Envelope::seal(&key, 42, b"pub", b"priv", [5; NONCE_LEN], &records()).unwrap();
        assert!(env.open(&[8; KEY_LEN]).is_none(), "wrong key");
        let mut e = env.clone();
        e.counter = 43;
        assert!(e.open(&key).is_none(), "counter is authenticated");
        let mut e = env.clone();
        e.sealed_private[0] ^= 1;
        assert!(e.open(&key).is_none(), "sealed key is authenticated");
        let mut e = env.clone();
        e.nonce[0] ^= 1;
        assert!(e.open(&key).is_none());
        let mut e = env.clone();
        e.ciphertext[0] ^= 1;
        assert!(e.open(&key).is_none());
        let mut e = env.clone();
        e.ciphertext.truncate(TAG_LEN - 1);
        assert!(e.open(&key).is_none());
    }

    /// The counter rule: the TPM's value or the next; older is a rollback.
    #[test]
    fn freshness_against_the_tpm_counter() {
        assert_eq!(freshness(10, 10), Freshness::Current);
        assert_eq!(freshness(11, 10), Freshness::Uncommitted);
        assert_eq!(freshness(9, 10), Freshness::RolledBack);
        assert_eq!(freshness(0, 10), Freshness::RolledBack);
        assert_eq!(freshness(12, 10), Freshness::Invalid);
        assert_eq!(freshness(u64::MAX, u64::MAX), Freshness::Current);
        assert_eq!(freshness(0, u64::MAX), Freshness::RolledBack);
    }

    /// Pruning drops expired acceptances and keeps revocations.
    #[test]
    fn prune_keeps_revocations() {
        let mut r = records();
        r.prune(100);
        assert_eq!(r.revoked, alloc::vec![7, u64::MAX]);
        assert_eq!(r.delivered.len(), 1, "not_after == now is kept");
        assert_eq!(
            r.imported,
            alloc::vec![Seen {
                id: [3; 16],
                n: 1,
                not_after: 500
            }]
        );
    }
}
