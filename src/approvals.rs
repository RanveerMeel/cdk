//! Signed operator approvals (roadmap 2.8).
//!
//! When operator keys are pinned in the ramdisk (`operator-<name>.pub`,
//! hybrid Ed25519 + ML-DSA-65 identities made by `cdk-approve init`), a
//! typed `y` no longer approves anything. Each approval-gated agent action
//! and each policy change becomes a signed request
//! ([`cdk_link::approval`]): CDK sends it sealed to the gateway, operators
//! approve or deny it with `cdk-approve` (on another machine if they like),
//! and CDK verifies every signature against the pinned keys before it
//! counts. `quorum` rules require several distinct operators; any valid
//! denial vetoes; unanswered requests are denied after `approval-timeout`.
//!
//! The statement an operator signs binds this boot's kernel issuer, the
//! request id, the payload digest, the text shown, the quorum and the
//! decision, so the gateway (which only carries messages) cannot forge,
//! redirect, or replay one. Votes are audit-logged (`approval-signed`, with
//! the first 8 bytes of SHA-256 of the signature); bad signatures, unknown
//! operators, duplicates and time-outs are logged too.
//!
//! Without pinned operator keys CDK stays in console mode (lab use): the
//! console operator answers `y`/`N` as before.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use cdk_link::approval::{self as ap, Message, Request};
use cdk_link::secure::{hybrid, Identity, Signature};
use heapless::String;
use sha2::{Digest, Sha256};
use spin::Mutex;

use crate::audit::{self, EventKind};

/// Ramdisk file names of pinned operator keys: `operator-<name>.pub`.
pub const KEY_PREFIX: &str = "operator-";
pub const KEY_SUFFIX: &str = ".pub";

/// `detail` codes for [`EventKind::ApprovalRejected`].
pub mod reject {
    /// Signed by a key that is not pinned.
    pub const UNKNOWN_OPERATOR: u64 = 1;
    /// The signature does not verify for this request and decision.
    pub const BAD_SIGNATURE: u64 = 2;
    /// This operator already voted on the request.
    pub const DUPLICATE: u64 = 3;
    /// No open request with that id (already decided, or never opened).
    pub const UNKNOWN_REQUEST: u64 = 4;
}

pub struct Operator {
    pub name: String<24>,
    pub id: [u8; 16],
    key: Identity,
}

static OPERATORS: Mutex<Vec<Operator>> = Mutex::new(Vec::new());
static LOADED: AtomicBool = AtomicBool::new(false);

/// Load the pinned operator keys from the ramdisk (once, at boot).
pub fn load_operators() {
    if LOADED.swap(true, Ordering::SeqCst) {
        return;
    }
    let mut ops = OPERATORS.lock();
    let mut h = Sha256::new();
    for f in crate::initrd::files().filter_map(Result::ok) {
        let Some(name) = f
            .name
            .strip_prefix(KEY_PREFIX)
            .and_then(|n| n.strip_suffix(KEY_SUFFIX))
        else {
            continue;
        };
        let (Some(key), Ok(name)) = (Identity::from_bytes(f.data), String::try_from(name)) else {
            crate::println!("approvals: ignoring malformed operator key {}", f.name);
            continue;
        };
        let id = key.id();
        if ops.iter().any(|o| o.id == id) {
            continue;
        }
        h.update(id);
        ops.push(Operator { name, id, key });
    }
    if ops.is_empty() {
        return;
    }
    crate::print!("approvals: {} operator key(s) pinned:", ops.len());
    for o in ops.iter() {
        crate::print!(
            " {} ({:02x}{:02x}{:02x}{:02x})",
            o.name,
            o.id[0],
            o.id[1],
            o.id[2],
            o.id[3]
        );
    }
    crate::println!(" — signed approvals required");
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    drop(ops);
    let mut subj: String<48> = String::new();
    let _ = write!(subj, "operators:{}", operator_count());
    audit::record(EventKind::PolicyApplied, &subj, u64::from_be_bytes(b));
}

/// Whether approvals must be signed (operator keys are pinned).
pub fn signed_mode() -> bool {
    !OPERATORS.lock().is_empty()
}

pub fn operator_count() -> usize {
    OPERATORS.lock().len()
}

/// `(name, id)` of each pinned operator.
pub fn for_each_operator(mut f: impl FnMut(&str, &[u8; 16])) {
    for o in OPERATORS.lock().iter() {
        f(&o.name, &o.id);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    Denied,
    TimedOut,
}

struct Open {
    id: u32,
    kind: u8,
    quorum: u8,
    ttl_s: u16,
    deadline: u64,
    yes: [u8; 32],
    no: [u8; 32],
    /// Operators who approved.
    approvals: Vec<[u8; 16]>,
    outcome: Option<Outcome>,
}

static OPEN: Mutex<Vec<Open>> = Mutex::new(Vec::new());
static ASSEMBLER: Mutex<ap::Assembler> = Mutex::new(ap::Assembler::new());
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

pub fn has_open() -> bool {
    !OPEN.lock().is_empty()
}

/// Cut `text` to fit a request (at a character boundary).
pub fn fit_text(text: &str) -> &str {
    if text.len() <= ap::MAX_TEXT {
        return text;
    }
    let mut end = ap::MAX_TEXT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Open a signed request and send it to the gateway. `payload` is digested
/// exactly; `text` (≤ [`ap::MAX_TEXT`]) is what operators are shown.
pub fn open(
    kind: u8,
    quorum: u8,
    ttl_s: u16,
    payload: &[u8],
    text: &str,
) -> Result<u32, &'static str> {
    if !crate::link::is_secure() {
        return Err("no secure link to the gateway (signed approvals travel through it)");
    }
    if text.len() > ap::MAX_TEXT {
        return Err("too much to review in one signed request; split it");
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let req = Request {
        id,
        issuer: crate::issuer::kernel().public().id,
        kind,
        quorum: quorum.max(1),
        ttl_s,
        payload_digest: Sha256::digest(payload).into(),
        text,
    };
    let msg = ap::encode_request(&req).map_err(|_| "request too large")?;
    match crate::link::send_data(&msg) {
        Ok(true) => {}
        _ => return Err("could not send the request to the gateway"),
    }
    let (yes, no) = (ap::statement(&req, true), ap::statement(&req, false));
    OPEN.lock().push(Open {
        id,
        kind,
        quorum: req.quorum,
        ttl_s,
        deadline: crate::cpu::rdtsc().wrapping_add(ttl_s as u64 * 2_000_000_000),
        yes,
        no,
        approvals: Vec::new(),
        outcome: None,
    });
    crate::println!(
        "  signed approval: request #{} needs {} operator signature(s) within {} s",
        id,
        req.quorum,
        ttl_s
    );
    crate::print!("  statement sha256 (approve): ");
    for b in &yes[..8] {
        crate::print!("{:02x}", b);
    }
    crate::println!(
        "…  — on an operator device: cdk-approve list / approve {} / deny {}",
        id,
        id
    );
    Ok(id)
}

fn hex8(id: &[u8; 16]) -> String<8> {
    let mut s = String::new();
    let _ = write!(s, "{:02x}{:02x}{:02x}{:02x}", id[0], id[1], id[2], id[3]);
    s
}

/// Handle an approval message from the gateway.
pub fn on_message(p: &[u8]) {
    let Ok(Message::DecisionPart {
        id,
        operator,
        approve,
        total,
        offset,
        bytes,
    }) = ap::decode(p)
    else {
        return;
    };
    let Some((id, operator, approve, sig)) = ASSEMBLER
        .lock()
        .push(id, operator, approve, total, offset, bytes)
    else {
        return;
    };
    let rejected = |what: &str, reason| {
        let mut subj: String<48> = String::new();
        let _ = write!(subj, "req-{}:op-{}", id, hex8(&operator));
        audit::record(EventKind::ApprovalRejected, &subj, reason);
        crate::println!(
            "approvals: request #{}: {} (operator {}) — ignored",
            id,
            what,
            hex8(&operator)
        );
    };
    let ops = OPERATORS.lock();
    let Some(op) = ops.iter().find(|o| o.id == operator) else {
        drop(ops);
        return rejected(
            "decision signed by an unknown key",
            reject::UNKNOWN_OPERATOR,
        );
    };
    let mut open = OPEN.lock();
    let Some(req) = open.iter_mut().find(|r| r.id == id && r.outcome.is_none()) else {
        drop((open, ops));
        return rejected("no open request with this id", reject::UNKNOWN_REQUEST);
    };
    let statement = if approve { req.yes } else { req.no };
    let valid = Signature::from_slice(&sig).is_some_and(|s| {
        crate::issuer::crypto_stack::run(|| {
            hybrid::verify_with(&op.key, &statement, &s, ap::CONTEXT)
        })
    });
    if !valid {
        drop((open, ops));
        return rejected("signature does not verify", reject::BAD_SIGNATURE);
    }
    if req.approvals.contains(&operator) {
        drop((open, ops));
        return rejected("duplicate vote", reject::DUPLICATE);
    }
    let name = op.name.clone();
    drop(ops);
    let d = Sha256::digest(&sig);
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    let mut subj: String<48> = String::new();
    let _ = write!(
        subj,
        "req-{}:{}:{}",
        id,
        name,
        if approve { "yes" } else { "no" }
    );
    if approve {
        req.approvals.push(operator);
        crate::println!(
            "approvals: request #{}: {} APPROVED (signature verified, {} of {})",
            id,
            name,
            req.approvals.len(),
            req.quorum
        );
        if req.approvals.len() >= req.quorum as usize {
            req.outcome = Some(Outcome::Approved);
        }
    } else {
        crate::println!(
            "approvals: request #{}: {} DENIED (signature verified)",
            id,
            name
        );
        req.outcome = Some(Outcome::Denied);
    }
    drop(open);
    audit::record(EventKind::ApprovalSigned, &subj, u64::from_be_bytes(b));
}

/// Deny requests whose time is up.
pub fn check_timeouts() {
    let now = crate::cpu::rdtsc();
    let mut expired: Vec<(u32, u16)> = Vec::new();
    for r in OPEN.lock().iter_mut() {
        if r.outcome.is_none() && now.wrapping_sub(r.deadline) < u64::MAX / 2 {
            r.outcome = Some(Outcome::TimedOut);
            expired.push((r.id, r.ttl_s));
        }
    }
    for (id, ttl) in expired {
        crate::println!(
            "approvals: request #{} timed out after {} s — denied",
            id,
            ttl
        );
        let mut subj: String<48> = String::new();
        let _ = write!(subj, "req-{}", id);
        audit::record(EventKind::ApprovalTimeout, &subj, ttl as u64);
    }
}

/// The decision on `id`, once there is one.
pub fn outcome(id: u32) -> Option<Outcome> {
    OPEN.lock()
        .iter()
        .find(|r| r.id == id)
        .and_then(|r| r.outcome)
}

/// Forget a decided request and tell the gateway.
pub fn close(id: u32) {
    let removed = {
        let mut open = OPEN.lock();
        open.iter().position(|r| r.id == id).map(|i| open.remove(i))
    };
    if let Some(r) = removed {
        let code = match r.outcome {
            Some(Outcome::Approved) => ap::OUTCOME_APPROVED,
            Some(Outcome::Denied) => ap::OUTCOME_DENIED,
            _ => ap::OUTCOME_TIMEOUT,
        };
        let _ = crate::link::send_data(&ap::encode_resolved(id, code));
    }
}

/// Receive from the link (tool results and decisions) and expire requests.
pub fn pump() {
    crate::tools::pump();
    check_timeouts();
}

/// Block until `id` is decided; returns the outcome and closes it.
pub fn wait(id: u32) -> Outcome {
    loop {
        pump();
        if let Some(o) = outcome(id) {
            close(id);
            return o;
        }
        core::hint::spin_loop();
    }
}

/// Block until any open request is decided (the scheduler's idle wait).
pub fn wait_any() {
    loop {
        pump();
        if OPEN.lock().iter().any(|r| r.outcome.is_some()) || !has_open() {
            return;
        }
        core::hint::spin_loop();
    }
}

/// `(id, kind, approvals so far, quorum)` of each open request.
pub fn for_each_open(mut f: impl FnMut(u32, u8, usize, u8)) {
    for r in OPEN.lock().iter() {
        f(r.id, r.kind, r.approvals.len(), r.quorum);
    }
}
