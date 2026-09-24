//! Tamper-evident audit log (roadmap milestone 1.2).
//!
//! Security-relevant events — capability issuance, capability checks
//! (accepted and rejected), and process lifecycle — are appended to a
//! hash-chained log. Every [`CHECKPOINT_INTERVAL`] records the kernel issuer
//! signs the chain head with a hybrid Ed25519 + ML-DSA-65 signature.
//!
//! ```text
//! genesis   = SHA-256("CDK-AUDIT-GENESIS-v1" ‖ issuer_id)
//! hash[n]   = SHA-256("CDK-AUDIT-REC-v1" ‖ hash[n-1] ‖ seq ‖ tsc ‖ kind
//!                     ‖ u8(len(subject)) ‖ subject ‖ detail)
//! ckpt      = Sign(SHA-256("CDK-AUDIT-CKPT-v1" ‖ issuer_id ‖ seq ‖ hash[seq]))
//! ```
//!
//! [`AuditLog::verify`] recomputes the chain and checks every checkpoint.
//! Editing, deleting, inserting, or reordering a record breaks the chain;
//! rewriting the whole chain (possible for code that can write kernel
//! memory) cannot reproduce the signed checkpoints without the issuer's
//! secret keys. Records after the latest checkpoint are only hash-chained,
//! so [`VerifyReport::unsigned_tail`] reports how many are not yet covered by
//! a signature. Exporting checkpoints off the machine (roadmap phase 3) makes
//! the log verifiable even if the whole kernel is later compromised.
//!
//! The log is a ring: when full, the oldest record is evicted and its hash
//! becomes the verification anchor for the records that remain.

use core::fmt::Write;

use heapless::{Deque, String};
use sha2::{Digest, Sha256};
use spin::Mutex;

use crate::issuer::{self, HybridSignature, Issuer, IssuerId, SigDomain};

/// Records kept in memory (oldest evicted first).
pub const LOG_CAPACITY: usize = 1024;
/// A signed checkpoint is taken after every this many records.
pub const CHECKPOINT_INTERVAL: u64 = 64;
/// Signed checkpoints kept in memory.
pub const MAX_CHECKPOINTS: usize = 8;
/// Longest subject stored per record (longer subjects are truncated).
pub const MAX_SUBJECT: usize = 48;

const GENESIS_DOMAIN: &[u8] = b"CDK-AUDIT-GENESIS-v1";
const RECORD_DOMAIN: &[u8] = b"CDK-AUDIT-REC-v1";
const CHECKPOINT_DOMAIN: &[u8] = b"CDK-AUDIT-CKPT-v1";

pub type Hash = [u8; 32];

/// What happened. Values are part of the hashed record format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    /// Log started. `detail` = 1 if the issuer's entropy was secure.
    Boot = 1,
    /// Kernel issued a capability. `detail` = permission bitmask.
    CapIssued = 2,
    /// A capability passed verification. `detail` = permission bitmask.
    CapAccepted = 3,
    /// A capability failed verification. `detail` = [`reject_reason`] code.
    CapRejected = 4,
    /// Process loaded. `detail` = entry point.
    ProcessSpawned = 5,
    /// Process entered ring 3.
    ProcessStarted = 6,
    /// Process called `SYS_exit`. `detail` = exit code.
    ProcessExited = 7,
    /// Process reaped. `detail` = frames freed.
    ProcessReaped = 8,
    /// Process killed by a CPU exception. `detail` = exception vector.
    ProcessCrashed = 9,
}

impl EventKind {
    pub fn name(self) -> &'static str {
        match self {
            EventKind::Boot => "boot",
            EventKind::CapIssued => "cap-issued",
            EventKind::CapAccepted => "cap-accepted",
            EventKind::CapRejected => "cap-rejected",
            EventKind::ProcessSpawned => "proc-spawned",
            EventKind::ProcessStarted => "proc-started",
            EventKind::ProcessExited => "proc-exited",
            EventKind::ProcessReaped => "proc-reaped",
            EventKind::ProcessCrashed => "proc-crashed",
        }
    }
}

/// `detail` codes for [`EventKind::CapRejected`].
pub mod reject_reason {
    /// No proof, or the signature did not verify.
    pub const INVALID_SIGNATURE: u64 = 1;
    /// Signed by an issuer the kernel does not trust.
    pub const UNKNOWN_ISSUER: u64 = 2;
    /// Unsupported token format.
    pub const UNSUPPORTED_FORMAT: u64 = 3;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    /// CPU timestamp counter when recorded: monotonic, not wall-clock.
    pub tsc: u64,
    pub kind: EventKind,
    pub subject: String<MAX_SUBJECT>,
    pub detail: u64,
    /// Chain hash of this record (covers every earlier record).
    pub hash: Hash,
}

#[derive(Clone, Debug)]
pub struct Checkpoint {
    /// Sequence number of the last record covered.
    pub seq: u64,
    /// Chain hash of record `seq`.
    pub head: Hash,
    pub issuer_id: IssuerId,
    pub signature: HybridSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditError {
    /// The record with this sequence number does not match the chain.
    BrokenAt(u64),
    /// Sequence numbers are not contiguous before this record.
    GapBefore(u64),
    /// The stored head does not match the last record.
    HeadMismatch,
    /// No records were evicted, but the chain does not start at genesis.
    BadGenesis,
    /// A checkpoint signature is invalid (or from another issuer).
    BadCheckpoint(u64),
    /// A validly signed checkpoint disagrees with the retained record.
    CheckpointMismatch(u64),
}

/// Result of a successful verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyReport {
    pub records: usize,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub evicted: u64,
    pub checkpoints: usize,
    pub latest_checkpoint: Option<u64>,
    /// Records after the latest checkpoint (hash-chained but not yet signed).
    pub unsigned_tail: u64,
}

/// A hash-chained, checkpointed ring of audit records.
pub struct AuditLog<const N: usize> {
    records: Deque<Record, N>,
    checkpoints: Deque<Checkpoint, MAX_CHECKPOINTS>,
    genesis: Hash,
    /// Hash preceding the oldest retained record.
    anchor: Hash,
    head: Hash,
    next_seq: u64,
    evicted: u64,
    started: bool,
}

impl<const N: usize> AuditLog<N> {
    pub const fn new() -> Self {
        Self {
            records: Deque::new(),
            checkpoints: Deque::new(),
            genesis: [0; 32],
            anchor: [0; 32],
            head: [0; 32],
            next_seq: 0,
            evicted: 0,
            started: false,
        }
    }

    /// Bind the log to `issuer_id` and start the chain at its genesis hash.
    /// Does nothing if the log already started.
    pub fn start(&mut self, issuer_id: &IssuerId) {
        if self.started {
            return;
        }
        let mut h = Sha256::new();
        h.update(GENESIS_DOMAIN);
        h.update(issuer_id);
        self.genesis = h.finalize().into();
        self.anchor = self.genesis;
        self.head = self.genesis;
        self.started = true;
    }

    pub fn is_started(&self) -> bool {
        self.started
    }

    /// Append a record; returns its sequence number.
    pub fn append(&mut self, tsc: u64, kind: EventKind, subject: &str, detail: u64) -> u64 {
        if self.records.is_full() {
            if let Some(old) = self.records.pop_front() {
                self.anchor = old.hash;
                self.evicted += 1;
            }
        }
        let seq = self.next_seq;
        let subject = truncate(subject);
        let hash = record_hash(&self.head, seq, tsc, kind, &subject, detail);
        let _ = self.records.push_back(Record {
            seq,
            tsc,
            kind,
            subject,
            detail,
            hash,
        });
        self.head = hash;
        self.next_seq += 1;
        seq
    }

    /// Sign the current head with `issuer`. Returns the covered sequence
    /// number, or `None` if the log is empty.
    pub fn checkpoint(&mut self, issuer: &Issuer) -> Option<u64> {
        let last = self.records.back()?;
        let seq = last.seq;
        if self.checkpoints.back().is_some_and(|c| c.seq == seq) {
            return Some(seq);
        }
        let digest = checkpoint_digest(issuer.id(), seq, &self.head);
        let signature = issuer.sign(SigDomain::AuditCheckpoint, &digest);
        if self.checkpoints.is_full() {
            let _ = self.checkpoints.pop_front();
        }
        let _ = self.checkpoints.push_back(Checkpoint {
            seq,
            head: self.head,
            issuer_id: *issuer.id(),
            signature,
        });
        Some(seq)
    }

    /// Recompute the chain and verify every checkpoint with `verify_sig`.
    pub fn verify(
        &self,
        trusted: &IssuerId,
        verify_sig: impl Fn(&Hash, &HybridSignature) -> bool,
    ) -> Result<VerifyReport, AuditError> {
        if self.evicted == 0 && self.anchor != self.genesis {
            return Err(AuditError::BadGenesis);
        }
        let mut prev = self.anchor;
        for (expected_seq, r) in (self.evicted..).zip(self.records.iter()) {
            if r.seq != expected_seq {
                return Err(AuditError::GapBefore(r.seq));
            }
            let h = record_hash(&prev, r.seq, r.tsc, r.kind, &r.subject, r.detail);
            if h != r.hash {
                return Err(AuditError::BrokenAt(r.seq));
            }
            prev = h;
        }
        if prev != self.head {
            return Err(AuditError::HeadMismatch);
        }

        for c in self.checkpoints.iter() {
            let digest = checkpoint_digest(&c.issuer_id, c.seq, &c.head);
            if c.issuer_id != *trusted || !verify_sig(&digest, &c.signature) {
                return Err(AuditError::BadCheckpoint(c.seq));
            }
            if let Some(r) = self.records.iter().find(|r| r.seq == c.seq) {
                if r.hash != c.head {
                    return Err(AuditError::CheckpointMismatch(c.seq));
                }
            }
        }

        let last_seq = self.records.back().map(|r| r.seq);
        let latest_checkpoint = self.checkpoints.back().map(|c| c.seq);
        let unsigned_tail = match (last_seq, latest_checkpoint) {
            (Some(last), Some(ck)) => last.saturating_sub(ck),
            (Some(_), None) => self.records.len() as u64,
            _ => 0,
        };
        Ok(VerifyReport {
            records: self.records.len(),
            first_seq: self.records.front().map(|r| r.seq),
            last_seq,
            evicted: self.evicted,
            checkpoints: self.checkpoints.len(),
            latest_checkpoint,
            unsigned_tail,
        })
    }

    pub fn records(&self) -> impl DoubleEndedIterator<Item = &Record> + ExactSizeIterator {
        self.records.iter()
    }

    pub fn checkpoints(&self) -> impl Iterator<Item = &Checkpoint> {
        self.checkpoints.iter()
    }

    pub fn head(&self) -> &Hash {
        &self.head
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Mutable access to a retained record, for tests and the tamper demo.
    fn record_mut(&mut self, seq: u64) -> Option<&mut Record> {
        self.records.iter_mut().find(|r| r.seq == seq)
    }
}

impl<const N: usize> Default for AuditLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn truncate(subject: &str) -> String<MAX_SUBJECT> {
    let mut out = String::new();
    for ch in subject.chars() {
        if out.push(ch).is_err() {
            break;
        }
    }
    out
}

fn record_hash(
    prev: &Hash,
    seq: u64,
    tsc: u64,
    kind: EventKind,
    subject: &str,
    detail: u64,
) -> Hash {
    let mut h = Sha256::new();
    h.update(RECORD_DOMAIN);
    h.update(prev);
    h.update(seq.to_le_bytes());
    h.update(tsc.to_le_bytes());
    h.update([kind as u8, subject.len() as u8]);
    h.update(subject.as_bytes());
    h.update(detail.to_le_bytes());
    h.finalize().into()
}

fn checkpoint_digest(issuer_id: &IssuerId, seq: u64, head: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(CHECKPOINT_DOMAIN);
    h.update(issuer_id);
    h.update(seq.to_le_bytes());
    h.update(head);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Kernel-wide log
// ---------------------------------------------------------------------------

static LOG: Mutex<AuditLog<LOG_CAPACITY>> = Mutex::new(AuditLog::new());

/// CPU timestamp counter. Lock-free, so safe from any context; the PIT tick
/// counter stops once the BSP switches to its local APIC timer.
fn now() -> u64 {
    crate::cpu::rdtsc()
}

/// Start the kernel log (bound to the kernel issuer) and record `Boot`.
/// Idempotent; [`record`] calls it implicitly.
pub fn init() {
    let mut log = LOG.lock();
    start_locked(&mut log);
}

fn start_locked(log: &mut AuditLog<LOG_CAPACITY>) {
    if log.is_started() {
        return;
    }
    let issuer = issuer::kernel();
    log.start(issuer.id());
    let secure = issuer.entropy().is_secure() as u64;
    log.append(now(), EventKind::Boot, "kernel", secure);
}

/// Append an event to the kernel log, signing a checkpoint every
/// [`CHECKPOINT_INTERVAL`] records. Not for use in interrupt handlers.
pub fn record(kind: EventKind, subject: &str, detail: u64) {
    let mut log = LOG.lock();
    start_locked(&mut log);
    let seq = log.append(now(), kind, subject, detail);
    if (seq + 1).is_multiple_of(CHECKPOINT_INTERVAL) {
        log.checkpoint(issuer::kernel());
    }
}

/// [`record`] with a subject formatted from arguments (e.g. `pid-3`).
pub fn record_fmt(kind: EventKind, subject: core::fmt::Arguments<'_>, detail: u64) {
    let mut s: String<MAX_SUBJECT> = String::new();
    let _ = s.write_fmt(subject);
    record(kind, &s, detail);
}

/// Sign a checkpoint over everything recorded so far.
pub fn checkpoint_now() -> Option<u64> {
    let mut log = LOG.lock();
    start_locked(&mut log);
    log.checkpoint(issuer::kernel())
}

/// Verify the kernel log against the kernel issuer.
pub fn verify() -> Result<VerifyReport, AuditError> {
    let log = LOG.lock();
    let issuer = issuer::kernel();
    log.verify(issuer.id(), |digest, sig| {
        issuer.verify(SigDomain::AuditCheckpoint, digest, sig)
    })
}

/// Call `f` with the log locked (for console display).
pub fn with_log<R>(f: impl FnOnce(&AuditLog<LOG_CAPACITY>) -> R) -> R {
    f(&LOG.lock())
}

/// **Demo only:** flip one bit in a retained record's `detail` field without
/// updating hashes, to show that verification detects it. Returns `false` if
/// the record is no longer retained.
pub fn demo_tamper(seq: u64) -> bool {
    match LOG.lock().record_mut(seq) {
        Some(r) => {
            r.detail ^= 1;
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::EntropySource;

    fn issuer() -> Issuer {
        Issuer::from_seeds(&[11; 32], &[22; 32], EntropySource::Os)
    }

    fn verify<const N: usize>(log: &AuditLog<N>, i: &Issuer) -> Result<VerifyReport, AuditError> {
        log.verify(i.id(), |d, s| i.verify(SigDomain::AuditCheckpoint, d, s))
    }

    fn filled<const N: usize>(i: &Issuer, n: u64) -> AuditLog<N> {
        let mut log = AuditLog::<N>::new();
        log.start(i.id());
        for k in 0..n {
            log.append(k * 10, EventKind::CapAccepted, "obj-1", k);
        }
        log
    }

    #[test]
    fn empty_and_intact_logs_verify() {
        let i = issuer();
        let mut log = AuditLog::<16>::new();
        log.start(i.id());
        assert_eq!(verify(&log, &i).unwrap().records, 0);

        let log = filled::<16>(&i, 5);
        let r = verify(&log, &i).unwrap();
        assert_eq!((r.records, r.first_seq, r.last_seq), (5, Some(0), Some(4)));
        assert_eq!(r.unsigned_tail, 5);
    }

    #[test]
    fn edited_record_breaks_chain() {
        let i = issuer();
        let mut log = filled::<16>(&i, 6);
        log.record_mut(3).unwrap().detail = 999;
        assert_eq!(verify(&log, &i), Err(AuditError::BrokenAt(3)));

        let mut log = filled::<16>(&i, 6);
        log.record_mut(2).unwrap().subject = truncate("obj-2");
        assert_eq!(verify(&log, &i), Err(AuditError::BrokenAt(2)));
    }

    #[test]
    fn edited_record_with_recomputed_hash_breaks_next_link() {
        let i = issuer();
        let mut log = filled::<16>(&i, 6);
        let prev = log.record_mut(1).unwrap().hash;
        let r = log.record_mut(2).unwrap();
        r.detail = 999;
        r.hash = record_hash(&prev, r.seq, r.tsc, r.kind, &r.subject, r.detail);
        assert_eq!(verify(&log, &i), Err(AuditError::BrokenAt(3)));
    }

    #[test]
    fn deleted_or_reordered_records_are_detected() {
        let i = issuer();
        let mut log = filled::<16>(&i, 6);
        let mut kept: Deque<Record, 16> = Deque::new();
        for r in log.records.iter().filter(|r| r.seq != 2) {
            let _ = kept.push_back(r.clone());
        }
        log.records = kept;
        assert_eq!(verify(&log, &i), Err(AuditError::GapBefore(3)));

        // Swap records at positions 1 and 2.
        let mut log = filled::<16>(&i, 6);
        let a = log.records.iter().nth(1).unwrap().clone();
        let b = log.records.iter().nth(2).unwrap().clone();
        *log.records.iter_mut().nth(1).unwrap() = b;
        *log.records.iter_mut().nth(2).unwrap() = a;
        assert_eq!(verify(&log, &i), Err(AuditError::GapBefore(2)));
    }

    #[test]
    fn truncated_tail_is_detected() {
        let i = issuer();
        let mut log = filled::<16>(&i, 6);
        let _ = log.records.pop_back();
        assert_eq!(verify(&log, &i), Err(AuditError::HeadMismatch));
    }

    #[test]
    fn rewritten_chain_fails_signed_checkpoint() {
        let i = issuer();
        let mut log = filled::<16>(&i, 6);
        log.checkpoint(&i).unwrap();
        assert_eq!(verify(&log, &i).unwrap().unsigned_tail, 0);

        // Attacker rewrites record 4 and recomputes every later hash and the
        // head, but cannot re-sign the checkpoint.
        let mut prev = log.record_mut(3).unwrap().hash;
        for seq in 4..6 {
            let r = log.record_mut(seq).unwrap();
            if seq == 4 {
                r.detail = 999;
            }
            r.hash = record_hash(&prev, r.seq, r.tsc, r.kind, &r.subject, r.detail);
            prev = r.hash;
        }
        log.head = prev;
        assert_eq!(verify(&log, &i), Err(AuditError::CheckpointMismatch(5)));
    }

    #[test]
    fn forged_or_foreign_checkpoints_are_rejected() {
        let i = issuer();
        let attacker = Issuer::from_seeds(&[1; 32], &[2; 32], EntropySource::Os);

        let mut log = filled::<16>(&i, 4);
        log.checkpoint(&attacker).unwrap();
        assert_eq!(verify(&log, &i), Err(AuditError::BadCheckpoint(3)));

        let mut log = filled::<16>(&i, 4);
        log.checkpoint(&i).unwrap();
        log.checkpoints.back_mut().unwrap().signature.mldsa65[0] ^= 1;
        assert_eq!(verify(&log, &i), Err(AuditError::BadCheckpoint(3)));
    }

    #[test]
    fn capability_signature_is_not_a_checkpoint_signature() {
        let i = issuer();
        let mut log = filled::<16>(&i, 3);
        log.checkpoint(&i).unwrap();
        let c = log.checkpoints.back_mut().unwrap();
        let digest = checkpoint_digest(&c.issuer_id, c.seq, &c.head);
        c.signature = i.sign(SigDomain::Capability, &digest);
        assert_eq!(verify(&log, &i), Err(AuditError::BadCheckpoint(2)));
    }

    #[test]
    fn ring_eviction_keeps_log_verifiable() {
        let i = issuer();
        let mut log = filled::<8>(&i, 5);
        log.checkpoint(&i).unwrap();
        for k in 5..20 {
            log.append(k, EventKind::ProcessExited, "pid-1", k);
        }
        let r = verify(&log, &i).unwrap();
        assert_eq!((r.records, r.evicted, r.first_seq), (8, 12, Some(12)));
        // The checkpoint at seq 4 covers evicted records; still signature-checked.
        assert_eq!(r.checkpoints, 1);

        // Tampering with the oldest retained record is still caught.
        log.record_mut(12).unwrap().detail ^= 1;
        assert_eq!(verify(&log, &i), Err(AuditError::BrokenAt(12)));
    }

    #[test]
    fn chain_is_bound_to_issuer_genesis() {
        let i = issuer();
        let other = Issuer::from_seeds(&[3; 32], &[4; 32], EntropySource::Os);
        let log = filled::<16>(&other, 3);
        // Records are internally consistent but checkpoints/genesis differ.
        let mut a = filled::<16>(&i, 3);
        assert_ne!(a.head(), log.head());
        a.anchor = [9; 32];
        assert_eq!(verify(&a, &i), Err(AuditError::BadGenesis));
    }

    #[test]
    fn long_subjects_are_truncated() {
        let i = issuer();
        let mut log = AuditLog::<4>::new();
        log.start(i.id());
        let long = "x".repeat(200);
        log.append(0, EventKind::CapIssued, &long, 0);
        assert_eq!(log.records().next().unwrap().subject.len(), MAX_SUBJECT);
        verify(&log, &i).unwrap();
    }
}
