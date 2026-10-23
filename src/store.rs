//! Persistent sealed store (roadmap 4.5), kernel side. Format and the
//! trust model: [`cdk_link::store`].
//!
//! What it keeps across reboots: the serials of delegations this node
//! revoked, and the peer messages and portable capabilities it accepted (so
//! they cannot be replayed after a reboot, until they expire). The records
//! live in [`crate::peer`]; this module seals, stores and checks them.
//!
//! * **Key.** A random 256-bit key, sealed by the TPM under its storage
//!   primary key to [`SEAL_PCRS`]: the firmware, the loader, the Secure Boot
//!   state, and the kernel as CDK's loader measured it *before it ran*.
//!   PCRs 8–10 are not used — the kernel extends those itself, so any
//!   kernel could reproduce them. Without a loader measurement (BIOS boot)
//!   or without a TPM the store is off and state lasts one boot.
//! * **Writes** ([`commit`]): the envelope for the next counter value goes
//!   to the gateway; only once the gateway confirms it is stored is the TPM
//!   counter ([`NV_COUNTER`]) incremented. A change is persistent once
//!   `commit` returns `Ok(true)`.
//! * **Boot** ([`load`], after the gateway accepted the attestation): the
//!   envelope must unseal, authenticate and match the TPM counter. If it is
//!   missing, rolled back, tampered with, or sealed to another boot chain,
//!   the store **fails closed**: peer messages and imports are refused
//!   ([`acceptance_blocked`]) until the operator starts a new store
//!   (`store-reset`, a reviewed policy change), because the replay and
//!   revocation state they depend on is gone. A *new* store is also only
//!   created by `store-reset`: a TPM with neither counter nor store may be
//!   a new machine, or one whose counter and store were both deleted
//!   (the TPM owner hierarchy usually has no password), and only the
//!   operator can tell.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use cdk_link::store::{self, Envelope, Freshness, Records, KEY_LEN, NONCE_LEN};
use spin::Mutex;
use zeroize::Zeroizing;

use crate::audit::{self, EventKind};
use crate::tpm::{self, TpmError};

/// NV index of the store's monotonic counter (owner range, "CD").
pub const NV_COUNTER: u32 = 0x0100_4344;
/// PCR selection the key is sealed to: 0 (firmware), 2 (option ROMs),
/// 4 (boot loader), 7 (Secure Boot policy) and 11 (the kernel, measured by
/// CDK's loader).
pub const SEAL_PCRS: [u8; 3] = [0x95, 0x08, 0x00];

/// `store-failed` reasons.
pub mod failure {
    pub const MISSING: u64 = 1;
    pub const OTHER_BOOT_CHAIN: u64 = 2;
    pub const TAMPERED: u64 = 3;
    pub const ROLLED_BACK: u64 = 4;
    pub const TPM: u64 = 5;
    pub const INCONSISTENT: u64 = 6;
    /// No store yet: only the operator creates one (`store-reset`).
    pub const NONE_YET: u64 = 7;
}

/// An open store.
struct Ready {
    key: Zeroizing<[u8; KEY_LEN]>,
    public: Vec<u8>,
    private: Vec<u8>,
    /// The TPM counter value of the last committed write.
    counter: u64,
}

enum State {
    /// Before the first secure link.
    NotLoaded,
    /// No TPM-backed store on this boot (state lasts one boot).
    Off(String),
    Ready(Ready),
    /// Fail closed: acceptance is refused until `store-reset`.
    Failed(String),
}

static STATE: Mutex<State> = Mutex::new(State::NotLoaded);

/// What to do at boot, given the TPM counter (`None`: not defined) and the
/// gateway's answer (`Ok(true)`: it holds an envelope, `Ok(false)`: none,
/// `Err`: it keeps no store or did not answer).
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// Neither a counter nor a store: a new machine — or one whose TPM
    /// counter and store were both deleted. Only the operator can tell, so
    /// creating one is theirs to decide (`store-reset`).
    NoneYet,
    Open,
    Off(&'static str),
    Fail(u64, &'static str),
}

/// The boot decision for a TPM counter and the gateway's answer.
fn plan(counter: Option<u64>, stored: Result<bool, ()>) -> Plan {
    match (counter, stored) {
        (None, Ok(false)) => Plan::NoneYet,
        (None, Err(())) => Plan::Off("the gateway keeps no store (cdk-gateway --store FILE)"),
        (None, Ok(true)) => Plan::Fail(
            failure::INCONSISTENT,
            "the gateway holds a store but the TPM has no store counter (deleted, or another machine's store)",
        ),
        (Some(_), Ok(true)) => Plan::Open,
        (Some(_), _) => Plan::Fail(
            failure::MISSING,
            "the TPM store counter exists but the gateway has no store (lost or withheld)",
        ),
    }
}

/// Why this boot cannot have a TPM-backed store, if it cannot.
fn ineligible() -> Option<&'static str> {
    if crate::boot::lockdown() {
        return Some("boot verification failed (lockdown)");
    }
    if !crate::boot::tpm_ready() {
        return Some("no usable TPM");
    }
    match tpm::pcr_read_quoted() {
        Err(_) => Some("TPM PCRs unreadable"),
        Ok(p) if p[cdk_link::tpm::LOADER_PCRS[0] as usize] == [0; 32] => {
            Some("no loader measurement of the kernel (BIOS boot): the TPM cannot tell this kernel from another")
        }
        Ok(_) => None,
    }
}

/// Fail closed: report, audit `store-failed` with `code`, refuse acceptance.
fn failed(code: u64, why: String) {
    crate::println!("store: FAILED — {} (peer messages and imports refused until store-reset)", why);
    audit::record_fmt(EventKind::StoreFailed, format_args!("store"), code);
    *STATE.lock() = State::Failed(why);
}

/// The TPM counter, `None` if it was never defined. A counter defined but
/// never incremented is incremented now.
fn read_counter() -> Result<Option<u64>, TpmError> {
    match tpm::nv_counter_read(NV_COUNTER) {
        Ok(c) => Ok(Some(c)),
        Err(TpmError::Rc(tpm::RC_NV_ABSENT)) => Ok(None),
        Err(TpmError::Rc(tpm::RC_NV_UNINITIALIZED)) => {
            tpm::nv_increment(NV_COUNTER)?;
            tpm::nv_counter_read(NV_COUNTER).map(Some)
        }
        Err(e) => Err(e),
    }
}

/// Open the store after a secure link with an accepting gateway. Called on
/// every `link-secure`; an open store is kept.
pub fn load() {
    if matches!(*STATE.lock(), State::Ready(_)) {
        return;
    }
    if let Some(why) = ineligible() {
        // A TPM that already holds a store counter belongs to a machine
        // that keeps one: booting without it (say, BIOS instead of UEFI)
        // must not reopen replay.
        if crate::boot::tpm_ready() && tpm::nv_counter_read(NV_COUNTER).is_ok() {
            return failed(failure::OTHER_BOOT_CHAIN, format!("this TPM holds a sealed store, but {}", why));
        }
        crate::println!("store: off — {} (revocations and replay state last one boot)", why);
        *STATE.lock() = State::Off(why.to_string());
        return;
    }
    let counter = match read_counter() {
        Ok(c) => c,
        Err(e) => return failed(failure::TPM, format!("TPM counter unreadable ({:?})", e)),
    };
    let stored = crate::peer::store_get();
    match plan(counter, stored.as_ref().map(|s| s.is_some()).map_err(|_| ())) {
        Plan::Off(why) => {
            crate::println!("store: off — {}", why);
            *STATE.lock() = State::Off(why.to_string());
        }
        Plan::Fail(code, why) => failed(code, why.to_string()),
        Plan::NoneYet => {
            crate::println!(
                "store: none yet on this TPM — store-reset creates one (reviewed); until then peer messages and imports are refused"
            );
            audit::record_fmt(EventKind::StoreFailed, format_args!("store"), failure::NONE_YET);
            *STATE.lock() = State::Failed("no sealed store yet".into());
        }
        Plan::Open => {
            let bytes = stored.ok().flatten().unwrap_or_default();
            match open(counter.unwrap_or(0), &bytes) {
                Ok((ready, records)) => {
                    let c = ready.counter;
                    crate::peer::restore(&records);
                    *STATE.lock() = State::Ready(ready);
                    crate::println!(
                        "store: sealed store loaded (TPM counter {}): {} revocation(s), {} delivered, {} imported",
                        c,
                        records.revoked.len(),
                        records.delivered.len(),
                        records.imported.len()
                    );
                    audit::record_fmt(EventKind::StoreLoaded, format_args!("store:loaded"), c);
                }
                Err((code, why)) => failed(code, why),
            }
        }
    }
}

/// Recover the store key from its sealed object.
fn unseal_key(public: &[u8], private: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, (u64, String)> {
    let srk = tpm::create_storage_key().map_err(|e| (failure::TPM, format!("TPM storage key ({:?})", e)))?;
    let out = tpm::unseal(srk, public, private, &SEAL_PCRS);
    let _ = tpm::flush(srk);
    let mut data = out.map_err(|e| match e {
        TpmError::Rc(tpm::RC_POLICY_FAIL) => (
            failure::OTHER_BOOT_CHAIN,
            "the store is sealed to another boot chain (firmware, loader or kernel changed)".to_string(),
        ),
        e => (failure::TAMPERED, format!("the store key does not unseal ({:?})", e)),
    })?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    if data.len() != KEY_LEN {
        zeroize::Zeroize::zeroize(data.as_mut_slice());
        return Err((failure::TAMPERED, "the sealed key has the wrong length".into()));
    }
    key.copy_from_slice(&data);
    zeroize::Zeroize::zeroize(data.as_mut_slice());
    Ok(key)
}

/// Unseal, authenticate and check freshness against TPM counter `tpm_counter`.
fn open(tpm_counter: u64, bytes: &[u8]) -> Result<(Ready, Records), (u64, String)> {
    let env = Envelope::decode(bytes).ok_or((failure::TAMPERED, "not a store envelope".to_string()))?;
    let key = unseal_key(&env.sealed_public, &env.sealed_private)?;
    let records = env
        .open(&key)
        .ok_or((failure::TAMPERED, "the store does not authenticate (changed)".to_string()))?;
    let counter = match store::freshness(env.counter, tpm_counter) {
        Freshness::Current => env.counter,
        Freshness::Uncommitted => {
            tpm::nv_increment(NV_COUNTER).map_err(|e| (failure::TPM, format!("TPM counter ({:?})", e)))?;
            env.counter
        }
        Freshness::RolledBack => {
            return Err((
                failure::ROLLED_BACK,
                format!("the store was ROLLED BACK (envelope {}, TPM counter {})", env.counter, tpm_counter),
            ))
        }
        Freshness::Invalid => {
            return Err((
                failure::TAMPERED,
                format!("the envelope is ahead of the TPM counter ({} > {})", env.counter, tpm_counter),
            ))
        }
    };
    Ok((
        Ready {
            key,
            public: env.sealed_public,
            private: env.sealed_private,
            counter,
        },
        records,
    ))
}

/// A new key sealed to this boot chain, and a first write of the current
/// records. Defines the TPM counter if needed. Returns the counter value.
fn create(now: Option<u64>) -> Result<u64, (u64, String)> {
    let tpm_err = |what: &str, e: TpmError| (failure::TPM, format!("{} ({:?})", what, e));
    if !crate::rng::entropy_source().is_secure() {
        return Err((failure::TPM, "no secure randomness for a store key".into()));
    }
    let counter = match read_counter().map_err(|e| tpm_err("TPM counter", e))? {
        Some(c) => c,
        None => {
            tpm::nv_counter_define(NV_COUNTER).map_err(|e| tpm_err("defining the TPM counter", e))?;
            tpm::nv_counter_read(NV_COUNTER).map_err(|e| tpm_err("TPM counter", e))?
        }
    };
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand_core::RngCore::fill_bytes(&mut crate::rng::KernelRng, &mut key[..]);
    let policy = tpm::pcr_policy_digest(&SEAL_PCRS).map_err(|e| tpm_err("PCR policy", e))?;
    let srk = tpm::create_storage_key().map_err(|e| tpm_err("TPM storage key", e))?;
    let sealed = tpm::seal(srk, &key[..], &policy);
    let _ = tpm::flush(srk);
    let (public, private) = sealed.map_err(|e| tpm_err("sealing the store key", e))?;
    let mut ready = Ready {
        key,
        public,
        private,
        counter,
    };
    write(&mut ready, now).map_err(|e| (failure::MISSING, e))?;
    let c = ready.counter;
    *STATE.lock() = State::Ready(ready);
    Ok(c)
}

/// Write the current records for the next counter value, then commit it.
fn write(r: &mut Ready, now: Option<u64>) -> Result<(), String> {
    let tpm_counter = tpm::nv_counter_read(NV_COUNTER).map_err(|e| format!("TPM counter ({:?})", e))?;
    if tpm_counter != r.counter {
        return Err(format!(
            "the TPM counter moved outside CDK (expected {}, found {})",
            r.counter, tpm_counter
        ));
    }
    let mut records = crate::peer::snapshot();
    if let Some(now) = now {
        records.prune(now);
    }
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::RngCore::fill_bytes(&mut crate::rng::KernelRng, &mut nonce);
    let next = tpm_counter.checked_add(1).ok_or("TPM counter exhausted")?;
    let env = Envelope::seal(&r.key, next, &r.public, &r.private, nonce, &records).ok_or("the store is full")?;
    crate::peer::store_put(&env.encode())?;
    tpm::nv_increment(NV_COUNTER).map_err(|e| format!("TPM counter increment ({:?})", e))?;
    r.counter = next;
    Ok(())
}

/// Persist the current records. `Ok(true)`: committed; `Ok(false)`: the
/// store is off on this boot (nothing persists); `Err`: not persisted. `now`
/// (the gateway's clock) prunes expired entries.
pub fn commit(now: Option<u64>) -> Result<bool, String> {
    let mut st = STATE.lock();
    match &mut *st {
        State::Off(_) => Ok(false),
        State::NotLoaded => Err("the sealed store is not loaded (link-secure)".into()),
        State::Failed(why) => Err(why.clone()),
        State::Ready(r) => write(r, now).map(|_| true),
    }
}

/// Why peer messages and imports must be refused now, if they must: the
/// store failed, this boot should have one and has not loaded it, or the
/// policy requires one (`require sealed-store`) and it is not open.
pub fn acceptance_blocked() -> Option<String> {
    let required = crate::policy::policy().require_sealed_store;
    match &*STATE.lock() {
        State::Ready(_) => None,
        State::Failed(why) => Some(alloc::format!("sealed store unusable: {} (store-reset)", why)),
        State::NotLoaded if required || crate::boot::tpm_ready() => {
            Some("the sealed store is not loaded yet (link-secure)".into())
        }
        State::Off(why) if required => Some(alloc::format!(
            "the policy requires the sealed store (require sealed-store), but it is off: {}",
            why
        )),
        _ => None,
    }
}

/// Start a new store from this boot's state (console `store-reset`, after
/// review): a new key sealed to the current boot chain. Records in the old
/// store that this boot does not hold are lost.
pub fn reset() -> Result<u64, String> {
    if let Some(why) = ineligible() {
        return Err(why.into());
    }
    if !crate::link::is_secure() {
        return Err("no secure link (run link-secure)".into());
    }
    let c = create(None).map_err(|(_, e)| e)?;
    audit::record_fmt(EventKind::StoreReset, format_args!("store"), c);
    Ok(c)
}

/// One line for the console.
pub fn status() -> String {
    match &*STATE.lock() {
        State::NotLoaded => "not loaded (link-secure loads it)".into(),
        State::Off(why) => format!("off — {}", why),
        State::Ready(r) => format!(
            "sealed to PCRs 0,2,4,7,11; TPM counter {} (NV {:#010x})",
            r.counter, NV_COUNTER
        ),
        State::Failed(why) => format!("FAILED — {}; acceptance refused until store-reset", why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Boot decisions: nothing is created at boot; anything missing or
    /// inconsistent fails closed.
    #[test]
    fn boot_plan() {
        assert_eq!(plan(None, Ok(false)), Plan::NoneYet, "never created silently");
        assert!(matches!(plan(None, Err(())), Plan::Off(_)));
        assert!(matches!(plan(None, Ok(true)), Plan::Fail(failure::INCONSISTENT, _)));
        assert_eq!(plan(Some(5), Ok(true)), Plan::Open);
        assert!(matches!(plan(Some(5), Ok(false)), Plan::Fail(failure::MISSING, _)));
        assert!(matches!(plan(Some(5), Err(())), Plan::Fail(failure::MISSING, _)));
    }

    /// PCRs 0, 2, 4, 7 and 11 — never the kernel's own 8-10.
    #[test]
    fn sealed_to_measurements_made_before_the_kernel() {
        let pcrs: Vec<u32> = (0..24u32).filter(|i| SEAL_PCRS[*i as usize / 8] & (1 << (i % 8)) != 0).collect();
        assert_eq!(pcrs, alloc::vec![0, 2, 4, 7, 11]);
        for own in cdk_link::tpm::CDK_PCRS {
            assert!(!pcrs.contains(&own));
        }
    }
}
