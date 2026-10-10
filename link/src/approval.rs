//! Signed operator approvals (roadmap 2.8): the messages between CDK, the
//! gateway and the operator tool, and the statement operators sign.
//!
//! CDK opens a [`Request`] for an approval-gated action or a policy change
//! and sends it (sealed) to the gateway, which spools it for operators. An
//! operator's tool (`cdk-approve`) decodes the request, shows its text,
//! computes the [`statement`] itself and signs it with the operator's
//! hybrid key (Ed25519 + ML-DSA-65, FIPS 204 context [`CONTEXT`]). The
//! signature travels back as [`DecisionPart`](Message::DecisionPart)s; CDK
//! verifies it against the operator keys pinned in its ramdisk. The gateway
//! only carries bytes: it cannot forge, alter, or replay a decision, because
//! the statement binds the kernel's issuer for this boot, the request id, the
//! exact payload digest, the text the operator saw, the quorum, and the
//! decision itself.
//!
//! ```text
//! Request      : 0x20 | id u32 | issuer [16] | kind u8 | quorum u8 | ttl_s u16
//!                     | payload_digest [32] | text_len u16 | text (UTF-8)
//! DecisionPart : 0x21 | id u32 | operator [16] | approve u8 | total u16
//!                     | offset u16 | len u16 | bytes      (signature, in order)
//! Resolved     : 0x22 | id u32 | outcome u8
//! ```

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// FIPS 204 context (and statement prefix) of approval signatures.
pub const CONTEXT: &[u8] = b"CDK-APPROVAL-v1";

pub const REQUEST: u8 = 0x20;
pub const DECISION_PART: u8 = 0x21;
pub const RESOLVED: u8 = 0x22;

/// An agent's approval-gated action (send, tool call, model prompt).
pub const KIND_ACTION: u8 = 1;
/// A policy change (grant, rule or label edit, gateway listing).
pub const KIND_POLICY: u8 = 2;

pub const OUTCOME_APPROVED: u8 = 1;
pub const OUTCOME_DENIED: u8 = 2;
pub const OUTCOME_TIMEOUT: u8 = 3;

const REQUEST_HEADER: usize = 1 + 4 + 16 + 1 + 1 + 2 + 32 + 2;
const PART_HEADER: usize = 1 + 4 + 16 + 1 + 2 + 2 + 2;
/// Longest request text (the request fits one sealed frame).
pub const MAX_TEXT: usize = crate::secure::MAX_PLAINTEXT - REQUEST_HEADER;
/// Signature bytes per decision part.
pub const PART_BYTES: usize = crate::secure::MAX_PLAINTEXT - PART_HEADER;

/// Whether a sealed payload is an approval message.
pub fn is_approval(msg: &[u8]) -> bool {
    matches!(msg.first(), Some(&(REQUEST | DECISION_PART | RESOLVED)))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub id: u32,
    /// Kernel issuer id: binds the request to one boot.
    pub issuer: [u8; 16],
    pub kind: u8,
    /// Distinct operators that must approve.
    pub quorum: u8,
    /// Seconds before CDK denies the request.
    pub ttl_s: u16,
    /// SHA-256 of the exact payload (action) or reviewed diff (policy).
    pub payload_digest: [u8; 32],
    /// What the operator is shown.
    pub text: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message<'a> {
    Request(Request<'a>),
    DecisionPart {
        id: u32,
        operator: [u8; 16],
        approve: bool,
        total: u16,
        offset: u16,
        bytes: &'a [u8],
    },
    Resolved {
        id: u32,
        outcome: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalMsgError {
    Malformed,
    TooLarge,
}

/// The 32-byte statement an operator signs to `approve` (or deny) `req`.
pub fn statement(req: &Request<'_>, approve: bool) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONTEXT);
    h.update([0]);
    h.update(req.id.to_le_bytes());
    h.update(req.issuer);
    h.update([req.kind, req.quorum]);
    h.update(req.ttl_s.to_le_bytes());
    h.update(req.payload_digest);
    h.update((req.text.len() as u16).to_le_bytes());
    h.update(req.text.as_bytes());
    h.update([if approve { 1 } else { 0 }]);
    h.finalize().into()
}

pub fn encode_request(req: &Request<'_>) -> Result<Vec<u8>, ApprovalMsgError> {
    if req.text.len() > MAX_TEXT {
        return Err(ApprovalMsgError::TooLarge);
    }
    let mut out = Vec::with_capacity(REQUEST_HEADER + req.text.len());
    out.push(REQUEST);
    out.extend_from_slice(&req.id.to_le_bytes());
    out.extend_from_slice(&req.issuer);
    out.push(req.kind);
    out.push(req.quorum);
    out.extend_from_slice(&req.ttl_s.to_le_bytes());
    out.extend_from_slice(&req.payload_digest);
    out.extend_from_slice(&(req.text.len() as u16).to_le_bytes());
    out.extend_from_slice(req.text.as_bytes());
    Ok(out)
}

/// A signed decision as [`Message::DecisionPart`]s, in order.
pub fn encode_decision(
    id: u32,
    operator: [u8; 16],
    approve: bool,
    signature: &[u8],
) -> Vec<Vec<u8>> {
    let total = signature.len() as u16;
    signature
        .chunks(PART_BYTES)
        .enumerate()
        .map(|(i, part)| {
            let mut m = Vec::with_capacity(PART_HEADER + part.len());
            m.push(DECISION_PART);
            m.extend_from_slice(&id.to_le_bytes());
            m.extend_from_slice(&operator);
            m.push(approve as u8);
            m.extend_from_slice(&total.to_le_bytes());
            m.extend_from_slice(&((i * PART_BYTES) as u16).to_le_bytes());
            m.extend_from_slice(&(part.len() as u16).to_le_bytes());
            m.extend_from_slice(part);
            m
        })
        .collect()
}

pub fn encode_resolved(id: u32, outcome: u8) -> Vec<u8> {
    let mut m = alloc::vec![RESOLVED];
    m.extend_from_slice(&id.to_le_bytes());
    m.push(outcome);
    m
}

/// Parse any approval message; every length is bounds-checked.
pub fn decode(b: &[u8]) -> Result<Message<'_>, ApprovalMsgError> {
    let bad = ApprovalMsgError::Malformed;
    let (&tag, r) = b.split_first().ok_or(bad)?;
    let u16_at = |s: &[u8], i: usize| -> Result<u16, ApprovalMsgError> {
        Ok(u16::from_le_bytes(
            s.get(i..i + 2).ok_or(bad)?.try_into().map_err(|_| bad)?,
        ))
    };
    let u32_at = |s: &[u8], i: usize| -> Result<u32, ApprovalMsgError> {
        Ok(u32::from_le_bytes(
            s.get(i..i + 4).ok_or(bad)?.try_into().map_err(|_| bad)?,
        ))
    };
    let arr16 = |s: &[u8], i: usize| -> Result<[u8; 16], ApprovalMsgError> {
        s.get(i..i + 16).ok_or(bad)?.try_into().map_err(|_| bad)
    };
    match tag {
        REQUEST => {
            let id = u32_at(r, 0)?;
            let issuer = arr16(r, 4)?;
            let kind = *r.get(20).ok_or(bad)?;
            let quorum = *r.get(21).ok_or(bad)?;
            let ttl_s = u16_at(r, 22)?;
            let payload_digest: [u8; 32] = r.get(24..56).ok_or(bad)?.try_into().map_err(|_| bad)?;
            let len = u16_at(r, 56)? as usize;
            let text = r.get(58..58 + len).ok_or(bad)?;
            if r.len() != 58 + len
                || len > MAX_TEXT
                || !(KIND_ACTION..=KIND_POLICY).contains(&kind)
                || quorum == 0
            {
                return Err(bad);
            }
            let text = core::str::from_utf8(text).map_err(|_| bad)?;
            Ok(Message::Request(Request {
                id,
                issuer,
                kind,
                quorum,
                ttl_s,
                payload_digest,
                text,
            }))
        }
        DECISION_PART => {
            let id = u32_at(r, 0)?;
            let operator = arr16(r, 4)?;
            let approve = match r.get(20) {
                Some(0) => false,
                Some(1) => true,
                _ => return Err(bad),
            };
            let total = u16_at(r, 21)?;
            let offset = u16_at(r, 23)?;
            let len = u16_at(r, 25)? as usize;
            let bytes = r.get(27..27 + len).ok_or(bad)?;
            if r.len() != 27 + len || offset as usize + len > total as usize {
                return Err(bad);
            }
            Ok(Message::DecisionPart {
                id,
                operator,
                approve,
                total,
                offset,
                bytes,
            })
        }
        RESOLVED if r.len() == 5 => Ok(Message::Resolved {
            id: u32_at(r, 0)?,
            outcome: r[4],
        }),
        _ => Err(bad),
    }
}

/// Reassembles decision parts. Parts arrive in order on the sealed channel;
/// a gap or a change of decision restarts the signature.
#[derive(Default)]
pub struct Assembler {
    key: Option<(u32, [u8; 16], bool)>,
    buf: Vec<u8>,
}

impl Assembler {
    pub const fn new() -> Self {
        Assembler {
            key: None,
            buf: Vec::new(),
        }
    }

    /// Feed one part; returns `(id, operator, approve, signature)` when the
    /// signature is complete.
    pub fn push(
        &mut self,
        id: u32,
        operator: [u8; 16],
        approve: bool,
        total: u16,
        offset: u16,
        bytes: &[u8],
    ) -> Option<(u32, [u8; 16], bool, Vec<u8>)> {
        if offset == 0
            || self.key != Some((id, operator, approve))
            || self.buf.len() != offset as usize
        {
            self.key = Some((id, operator, approve));
            self.buf.clear();
            if offset != 0 {
                return None;
            }
        }
        self.buf.extend_from_slice(bytes);
        if self.buf.len() == total as usize {
            self.key = None;
            return Some((id, operator, approve, core::mem::take(&mut self.buf)));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::{hybrid, Signature, SIG_LEN};

    fn req(text: &str) -> Request<'_> {
        Request {
            id: 7,
            issuer: [9; 16],
            kind: KIND_ACTION,
            quorum: 2,
            ttl_s: 300,
            payload_digest: [3; 32],
            text,
        }
    }

    #[test]
    fn request_round_trip_and_limits() {
        let r = req("pid 1 'analyst' wants to prompt model 'demo'");
        let m = encode_request(&r).unwrap();
        assert!(m.len() <= crate::secure::MAX_PLAINTEXT);
        assert_eq!(decode(&m), Ok(Message::Request(r)));
        let long = "x".repeat(MAX_TEXT + 1);
        assert_eq!(encode_request(&req(&long)), Err(ApprovalMsgError::TooLarge));
        assert!(
            encode_request(&req(&"x".repeat(MAX_TEXT))).unwrap().len()
                <= crate::secure::MAX_PLAINTEXT
        );
        assert_eq!(
            decode(&encode_resolved(7, OUTCOME_DENIED)),
            Ok(Message::Resolved { id: 7, outcome: 2 })
        );
        for b in [
            &[0x20, 1][..],
            &[0x21][..],
            &[0x22, 0, 0, 0][..],
            &[0x23, 0][..],
        ] {
            assert_eq!(decode(b), Err(ApprovalMsgError::Malformed));
        }
    }

    #[test]
    fn statement_binds_every_field() {
        let base = req("send 5 bytes to obj-2");
        let s = statement(&base, true);
        assert_ne!(s, statement(&base, false), "decision");
        let variants = [
            Request {
                id: 8,
                ..base.clone()
            },
            Request {
                issuer: [1; 16],
                ..base.clone()
            },
            Request {
                kind: KIND_POLICY,
                ..base.clone()
            },
            Request {
                quorum: 1,
                ..base.clone()
            },
            Request {
                ttl_s: 30,
                ..base.clone()
            },
            Request {
                payload_digest: [4; 32],
                ..base.clone()
            },
            Request {
                text: "send 5 bytes to obj-3",
                ..base.clone()
            },
        ];
        for v in &variants {
            assert_ne!(statement(v, true), s, "{v:?}");
        }
    }

    #[test]
    fn signed_decision_survives_the_wire() {
        let op = hybrid::Keypair::from_seeds(&[1; 32], &[2; 32]);
        let r = req("call tool 'echo'");
        let sig = op.sign_with(&statement(&r, true), CONTEXT);
        let mut bytes = alloc::vec![0u8; SIG_LEN];
        sig.write_to(&mut bytes);
        let parts = encode_decision(r.id, op.public().id(), true, &bytes);
        assert!(parts.len() > 1);
        let mut a = Assembler::new();
        let mut done = None;
        for p in &parts {
            assert!(p.len() <= crate::secure::MAX_PLAINTEXT);
            let Message::DecisionPart {
                id,
                operator,
                approve,
                total,
                offset,
                bytes,
            } = decode(p).unwrap()
            else {
                panic!()
            };
            done = a.push(id, operator, approve, total, offset, bytes).or(done);
        }
        let (id, operator, approve, got) = done.expect("complete");
        assert_eq!((id, operator, approve), (7, op.public().id(), true));
        let sig = Signature::from_slice(&got).unwrap();
        assert!(hybrid::verify_with(
            op.public(),
            &statement(&r, true),
            &sig,
            CONTEXT
        ));
        // Not valid as a denial, for another request, or as a link signature.
        assert!(!hybrid::verify_with(
            op.public(),
            &statement(&r, false),
            &sig,
            CONTEXT
        ));
        assert!(!hybrid::verify_with(
            op.public(),
            &statement(&Request { id: 8, ..r.clone() }, true),
            &sig,
            CONTEXT
        ));
        assert!(!hybrid::verify(op.public(), &statement(&r, true), &sig));
    }

    #[test]
    fn assembler_restarts_on_gaps() {
        let mut a = Assembler::new();
        assert!(a.push(1, [0; 16], true, 4, 2, b"cd").is_none(), "no start");
        assert!(a.push(1, [0; 16], true, 4, 0, b"ab").is_none());
        assert!(
            a.push(1, [0; 16], false, 4, 2, b"cd").is_none(),
            "decision changed"
        );
        assert!(a.push(1, [0; 16], true, 4, 0, b"ab").is_none());
        assert_eq!(a.push(1, [0; 16], true, 4, 2, b"cd").unwrap().3, b"abcd");
    }
}
