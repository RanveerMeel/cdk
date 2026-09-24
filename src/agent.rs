//! Agent capability handles and the syscalls that use them (roadmap 2.2).
//!
//! Each process has a table of up to [`MAX_HANDLES`] capabilities. The
//! tokens never leave kernel memory: a program refers to them by index, so it
//! cannot forge, copy, or leak one. The console grants handles
//! (`grant <pid> <object> [perms]`); a program can list them, drop them, and
//! **derive** weaker ones (permissions may only be removed), and uses them to
//! `send` messages to — and `recv` messages from — the handle's object.
//!
//! Every use re-verifies the token through [`Kernel`] (hybrid post-quantum
//! proof, served from the verified-proof cache) and checks its permissions;
//! grants, derivations, and denials are written to the audit log.
//!
//! ## Syscall ABI
//!
//! | nr | name        | args                         | returns                  |
//! |----|-------------|------------------------------|--------------------------|
//! | 3  | `cap_list`  | `buf: *mut CapInfo, max`     | number of handles        |
//! | 4  | `cap_drop`  | `handle`                     | 0                        |
//! | 5  | `cap_derive`| `handle, perm_mask`          | new handle               |
//! | 6  | `send`      | `handle, ptr, len (≤ 64)`    | 0                        |
//! | 7  | `recv`      | `handle, ptr, len`           | bytes copied             |
//!
//! Errors are returned as `-(code)` (see [`errno`]). `CapInfo` is two
//! little-endian `u32`s: handle index and permission mask (bit = permission
//! tag, as in [`Capability::permission_mask`]).

use spin::Mutex;

use crate::audit::{self, reject_reason, EventKind};
use crate::capability::{Capability, Permission};
use crate::kernel::{Kernel, KernelError};
use crate::message::{Message, MessagePayload};
use crate::process::MAX_PROCESSES;

/// Handles per process.
pub const MAX_HANDLES: usize = 16;
/// Largest message payload (`send`) in bytes.
pub const MAX_MESSAGE: usize = 64;

pub const SYS_CAP_LIST: u64 = 3;
pub const SYS_CAP_DROP: u64 = 4;
pub const SYS_CAP_DERIVE: u64 = 5;
pub const SYS_SEND: u64 = 6;
pub const SYS_RECV: u64 = 7;

/// Error codes, returned to user space as `-(code)`.
pub mod errno {
    /// No such handle.
    pub const EBADH: u64 = 1;
    /// The handle lacks the permission (or a derive would add one).
    pub const EPERM: u64 = 2;
    /// Bad pointer, length, or argument.
    pub const EINVAL: u64 = 3;
    /// The object's message queue is full.
    pub const EFULL: u64 = 4;
    /// No message waiting.
    pub const EEMPTY: u64 = 5;
    /// The handle table is full.
    pub const ENOSPC: u64 = 6;
    /// The token failed verification.
    pub const ESIG: u64 = 7;
    /// A human denied the action (approval-gated handle).
    pub const EDENIED: u64 = 8;
}

/// Encode an error code as a syscall return value.
pub const fn err(code: u64) -> u64 {
    code.wrapping_neg()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleError {
    BadHandle,
    /// Derivation would add permissions the parent lacks.
    Escalation,
    TableFull,
    /// No table for this pid (process not registered).
    NoProcess,
}

/// One process's capability handles.
pub struct HandleTable {
    pid: u32,
    caps: [Option<Capability>; MAX_HANDLES],
}

impl HandleTable {
    const EMPTY: Option<Capability> = None;

    pub const fn new() -> Self {
        Self {
            pid: 0,
            caps: [Self::EMPTY; MAX_HANDLES],
        }
    }

    fn reset(&mut self, pid: u32) {
        self.pid = pid;
        for c in self.caps.iter_mut() {
            *c = None;
        }
    }

    /// Store `cap` in the lowest free slot; returns its handle.
    pub fn insert(&mut self, cap: Capability) -> Result<u32, HandleError> {
        let slot = self
            .caps
            .iter()
            .position(Option::is_none)
            .ok_or(HandleError::TableFull)?;
        self.caps[slot] = Some(cap);
        Ok(slot as u32)
    }

    pub fn get(&self, handle: u64) -> Result<&Capability, HandleError> {
        self.caps
            .get(handle as usize)
            .and_then(Option::as_ref)
            .ok_or(HandleError::BadHandle)
    }

    pub fn remove(&mut self, handle: u64) -> Result<Capability, HandleError> {
        self.caps
            .get_mut(handle as usize)
            .and_then(Option::take)
            .ok_or(HandleError::BadHandle)
    }

    /// Unsigned child of `handle` holding only `mask`'s permissions; errors
    /// if `mask` asks for anything the parent does not hold. The approval
    /// constraint is never dropped (a child may add it, not remove it).
    pub fn attenuate(&self, handle: u64, mask: u64) -> Result<Capability, HandleError> {
        let parent = self.get(handle)?;
        let parent_mask = parent.permission_mask();
        if mask & !parent_mask & !APPROVAL_BIT != 0 {
            return Err(HandleError::Escalation);
        }
        let mask = mask | (parent_mask & APPROVAL_BIT);
        let mut child = parent.clone();
        for p in ALL_PERMISSIONS {
            if mask & perm_bit(&p) == 0 {
                child.remove_permission(&p);
            }
        }
        if mask & APPROVAL_BIT != 0 {
            let _ = child.add_permission(Permission::RequiresApproval);
        }
        Ok(child)
    }

    /// `(handle, permission mask)` for each live handle.
    pub fn list(&self) -> impl Iterator<Item = (u32, u64)> + '_ {
        self.caps
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.as_ref().map(|c| (i as u32, c.permission_mask())))
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

const ALL_PERMISSIONS: [Permission; 7] = [
    Permission::Read,
    Permission::Write,
    Permission::Execute,
    Permission::SendMessage,
    Permission::ReceiveMessage,
    Permission::Delete,
    Permission::RequiresApproval,
];

/// Mask bit of the human-approval constraint.
pub const APPROVAL_BIT: u64 = 1 << 7;

/// Mask bit for `p` (same encoding as [`Capability::permission_mask`]).
fn perm_bit(p: &Permission) -> u64 {
    1u64 << p.tag()
}

/// Parse `send,recv,...` (or `all`) into permissions.
pub fn parse_permissions(spec: &str) -> Option<heapless::Vec<Permission, 7>> {
    let mut out = heapless::Vec::new();
    for word in spec.split(',').filter(|w| !w.is_empty()) {
        let p = match word {
            "read" => Permission::Read,
            "write" => Permission::Write,
            "exec" => Permission::Execute,
            "send" => Permission::SendMessage,
            "recv" => Permission::ReceiveMessage,
            "delete" => Permission::Delete,
            "approval" => Permission::RequiresApproval,
            "all" => {
                out.clear();
                for p in ALL_PERMISSIONS
                    .iter()
                    .filter(|p| **p != Permission::RequiresApproval)
                {
                    let _ = out.push(p.clone());
                }
                return Some(out);
            }
            _ => return None,
        };
        if !out.contains(&p) {
            let _ = out.push(p);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Short names for a permission mask, e.g. `send,recv`.
pub fn permission_names(mask: u64) -> heapless::String<48> {
    let mut s = heapless::String::new();
    for (p, name) in ALL_PERMISSIONS.iter().zip([
        "read", "write", "exec", "send", "recv", "delete", "approval",
    ]) {
        if mask & perm_bit(p) != 0 {
            if !s.is_empty() {
                let _ = s.push(',');
            }
            let _ = s.push_str(name);
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Per-process tables
// ---------------------------------------------------------------------------

static TABLES: Mutex<[HandleTable; MAX_PROCESSES]> =
    Mutex::new([const { HandleTable::new() }; MAX_PROCESSES]);

/// Give `pid` a fresh, empty handle table (called at spawn).
pub fn create_table(pid: u32) -> Result<(), HandleError> {
    let mut tables = TABLES.lock();
    let slot = tables
        .iter()
        .position(|t| t.pid == pid)
        .or_else(|| tables.iter().position(|t| t.pid == 0))
        .ok_or(HandleError::TableFull)?;
    tables[slot].reset(pid);
    Ok(())
}

/// Drop every handle `pid` holds and free its table (called at reap).
pub fn destroy_table(pid: u32) {
    let mut tables = TABLES.lock();
    if let Some(t) = tables.iter_mut().find(|t| t.pid == pid) {
        t.reset(0);
    }
}

fn with_table<R>(pid: u32, f: impl FnOnce(&mut HandleTable) -> R) -> Result<R, HandleError> {
    let mut tables = TABLES.lock();
    let t = tables
        .iter_mut()
        .find(|t| t.pid == pid && pid != 0)
        .ok_or(HandleError::NoProcess)?;
    Ok(f(t))
}

/// Kernel-issue a capability for `object` with `perms` and give it to `pid`.
/// Returns the new handle.
pub fn grant(
    pid: u32,
    object: &crate::object::KernelObject,
    perms: &[Permission],
) -> Result<u32, HandleError> {
    let mut cap = Capability::with_permissions(object, perms);
    cap.issue().map_err(|_| HandleError::NoProcess)?;
    let mask = cap.permission_mask();
    let handle = with_table(pid, |t| t.insert(cap))??;
    audit::record_fmt(
        EventKind::CapGranted,
        format_args!("pid-{}:h{}:{}", pid, handle, object.id),
        mask,
    );
    Ok(handle)
}

/// `(handle, mask, object id)` for each handle `pid` holds.
pub fn describe(pid: u32, mut f: impl FnMut(u32, u64, &str)) -> Result<(), HandleError> {
    with_table(pid, |t| {
        for (h, mask) in t.list() {
            if let Ok(cap) = t.get(h as u64) {
                f(h, mask, &cap.object_id);
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Human approval
// ---------------------------------------------------------------------------

/// A blocked `send` waiting for a human decision.
pub struct Pending {
    pub id: u32,
    pub pid: u32,
    pub handle: u64,
    cap: Capability,
    payload: heapless::Vec<u8, MAX_MESSAGE>,
}

impl Pending {
    pub fn object(&self) -> &str {
        &self.cap.object_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Requests queued at most (one per blocked process is the norm).
pub const MAX_PENDING: usize = 8;

static PENDING: Mutex<heapless::Deque<Pending, MAX_PENDING>> = Mutex::new(heapless::Deque::new());
static NEXT_REQUEST: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

/// Whether any request is waiting for a human decision.
pub fn has_pending() -> bool {
    !PENDING.lock().is_empty()
}

/// Ask the human at the console about every pending request, apply each
/// decision, and resume the waiting processes. Returns how many were decided.
pub fn resolve_approvals() -> usize {
    resolve_with(prompt_console)
}

/// Decide every pending request with `decide` (tests use a scripted one).
pub fn resolve_with(mut decide: impl FnMut(&Pending) -> bool) -> usize {
    let mut n = 0;
    loop {
        // Never hold the queue lock while a human thinks.
        let Some(req) = PENDING.lock().pop_front() else {
            break;
        };
        let approved = decide(&req);
        let kind = if approved {
            EventKind::ApprovalGranted
        } else {
            EventKind::ApprovalDenied
        };
        audit::record_fmt(
            kind,
            format_args!("pid-{}:req-{}:{}", req.pid, req.id, req.object()),
            req.id as u64,
        );
        let result = if approved {
            match perform_send(req.pid, req.handle, &req.cap, &req.payload) {
                Ok(v) => v,
                Err(code) => err(code),
            }
        } else {
            err(errno::EDENIED)
        };
        crate::process::unblock(req.pid, result);
        n += 1;
    }
    n
}

/// Write `bytes` so that nothing an agent sends can move the cursor, clear
/// the screen, or fake console output: printable ASCII passes through,
/// everything else (and `"`/`\`) is shown as a `\xNN` escape.
pub fn write_sanitized(bytes: &[u8], mut out: impl FnMut(&str)) {
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\' {
            let s = [b];
            out(core::str::from_utf8(&s).unwrap_or("?"));
        } else {
            let mut hex: heapless::String<4> = heapless::String::new();
            let _ = core::fmt::write(&mut hex, format_args!("\\x{:02x}", b));
            out(&hex);
        }
    }
}

fn prompt_console(req: &Pending) -> bool {
    let name = crate::process::name_of(req.pid);
    crate::println!();
    crate::println!("=== HUMAN APPROVAL REQUIRED (request #{}) ===", req.id);
    crate::println!(
        "  agent  : pid {} '{}'",
        req.pid,
        name.as_ref().map_or("?", |n| n.as_str())
    );
    crate::println!(
        "  action : send {} bytes to {} (handle h{})",
        req.payload.len(),
        req.object(),
        req.handle
    );
    crate::print!("  data   : \"");
    write_sanitized(&req.payload, |s| crate::print!("{}", s));
    crate::println!("\"");
    crate::print!("Approve? [y/N] ");
    let approved = read_decision();
    crate::println!("  -> {}", if approved { "APPROVED" } else { "DENIED" });
    approved
}

/// Read one line from the console; `y`/`yes` (any case) approves.
fn read_decision() -> bool {
    #[cfg(target_os = "none")]
    {
        let mut line = [0u8; 8];
        let mut len = 0;
        loop {
            let b = crate::serial::read_byte();
            match b {
                b'\r' | b'\n' => break,
                0x08 | 0x7f if len > 0 => len -= 1,
                0x20..=0x7e if len < line.len() => {
                    line[len] = b;
                    len += 1;
                    crate::serial::write_byte(b);
                }
                _ => {}
            }
        }
        crate::println!();
        let answer = &line[..len];
        answer.eq_ignore_ascii_case(b"y") || answer.eq_ignore_ascii_case(b"yes")
    }
    #[cfg(not(target_os = "none"))]
    false
}

// ---------------------------------------------------------------------------
// Syscalls
// ---------------------------------------------------------------------------

/// Kernel state the syscalls act on, lent by the caller of [`with_kernel`].
static KERNEL_CTX: core::sync::atomic::AtomicPtr<Kernel> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Run `f` (which enters ring 3) with `kernel` lent to the syscall layer.
///
/// The caller already holds exclusive access to `kernel` (e.g. the console,
/// holding the kernel lock). A ring-3 program runs synchronously on the same
/// CPU until it exits, so its syscalls are the only code that can touch
/// `kernel` meanwhile. This must be revisited when user processes are
/// scheduled preemptively (roadmap 2.3).
pub fn with_kernel<R>(kernel: &mut Kernel, f: impl FnOnce() -> R) -> R {
    use core::sync::atomic::Ordering;
    KERNEL_CTX.store(kernel as *mut Kernel, Ordering::Release);
    let r = f();
    KERNEL_CTX.store(core::ptr::null_mut(), Ordering::Release);
    r
}

fn kernel() -> Option<&'static mut Kernel> {
    let p = KERNEL_CTX.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: see `with_kernel`; non-null only while the lender is blocked
    // in ring-3 execution on this CPU.
    unsafe { p.as_mut() }
}

/// Dispatch an agent syscall for the current process.
pub fn syscall(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let Some(pid) = crate::process::current_pid() else {
        return err(errno::EINVAL);
    };
    let result = match nr {
        SYS_CAP_LIST => sys_cap_list(pid, a0, a1),
        SYS_CAP_DROP => sys_cap_drop(pid, a0),
        SYS_CAP_DERIVE => sys_cap_derive(pid, a0, a1),
        // `send` may block for approval; it is dispatched by `sys_send_outcome`.
        SYS_SEND => match sys_send_outcome(a0, a1, a2) {
            crate::syscall::Outcome::Return(v) => return v,
            crate::syscall::Outcome::Block => Err(errno::EINVAL),
        },
        SYS_RECV => sys_recv(pid, a0, a1, a2),
        _ => Err(errno::EINVAL),
    };
    match result {
        Ok(v) => v,
        Err(code) => err(code),
    }
}

fn handle_errno(e: HandleError) -> u64 {
    match e {
        HandleError::BadHandle | HandleError::NoProcess => errno::EBADH,
        HandleError::Escalation => errno::EPERM,
        HandleError::TableFull => errno::ENOSPC,
    }
}

fn user_tables() -> crate::paging::PageTableManager {
    crate::paging::PageTableManager::from_pml4_phys(crate::syscall::current_cr3())
}

fn sys_cap_list(pid: u32, buf: u64, max: u64) -> Result<u64, u64> {
    let mut entries = [[0u8; 8]; MAX_HANDLES];
    let mut n = 0usize;
    with_table(pid, |t| {
        for (h, mask) in t.list() {
            entries[n][..4].copy_from_slice(&h.to_le_bytes());
            entries[n][4..].copy_from_slice(&(mask as u32).to_le_bytes());
            n += 1;
        }
    })
    .map_err(handle_errno)?;
    let count = n.min(max as usize);
    if count > 0 {
        let bytes = entries[..count].as_flattened();
        user_tables()
            .copy_to_user(buf, bytes)
            .map_err(|_| errno::EINVAL)?;
    }
    Ok(n as u64)
}

fn sys_cap_drop(pid: u32, handle: u64) -> Result<u64, u64> {
    with_table(pid, |t| t.remove(handle))
        .map_err(handle_errno)?
        .map_err(handle_errno)?;
    Ok(0)
}

fn sys_cap_derive(pid: u32, handle: u64, mask: u64) -> Result<u64, u64> {
    let child = with_table(pid, |t| {
        let parent = t.get(handle)?;
        // The parent must still verify before anything is derived from it.
        if parent.verify() != Ok(true) {
            return Err(HandleError::BadHandle);
        }
        t.attenuate(handle, mask)
    })
    .map_err(handle_errno)?;
    let mut child = match child {
        Ok(c) => c,
        Err(HandleError::Escalation) => {
            audit_denied(pid, handle, "derive-escalation");
            return Err(errno::EPERM);
        }
        Err(e) => return Err(handle_errno(e)),
    };
    child.issue().map_err(|_| errno::ESIG)?;
    let object = child.object_id.clone();
    let mask = child.permission_mask();
    let new = with_table(pid, |t| t.insert(child))
        .map_err(handle_errno)?
        .map_err(handle_errno)?;
    audit::record_fmt(
        EventKind::CapDerived,
        format_args!("pid-{}:h{}->h{}:{}", pid, handle, new, object),
        mask,
    );
    Ok(new as u64)
}

fn audit_denied(pid: u32, handle: u64, what: &str) {
    audit::record_fmt(
        EventKind::CapRejected,
        format_args!("pid-{}:h{}:{}", pid, handle, what),
        reject_reason::PERMISSION_DENIED,
    );
}

fn map_kernel_error(pid: u32, handle: u64, what: &str, e: KernelError) -> u64 {
    match e {
        KernelError::PermissionDenied => {
            audit_denied(pid, handle, what);
            errno::EPERM
        }
        KernelError::InvalidSignature => errno::ESIG,
        KernelError::MessageQueueFull => errno::EFULL,
        _ => errno::EINVAL,
    }
}

/// `send`, which blocks for a human decision when the handle carries the
/// approval constraint.
pub fn sys_send_outcome(handle: u64, ptr: u64, len: u64) -> crate::syscall::Outcome {
    use crate::syscall::Outcome;
    let Some(pid) = crate::process::current_pid() else {
        return Outcome::Return(err(errno::EINVAL));
    };
    let (cap, payload) = match prepare_send(pid, handle, ptr, len) {
        Ok(v) => v,
        Err(code) => return Outcome::Return(err(code)),
    };
    if !cap.has_permission(&Permission::RequiresApproval) {
        return Outcome::Return(match perform_send(pid, handle, &cap, &payload) {
            Ok(v) => v,
            Err(code) => err(code),
        });
    }
    // Only a handle that could send at all may ask; otherwise it is a
    // plain permission failure, not a request for a human.
    if !cap.has_permission(&Permission::SendMessage) {
        audit_denied(pid, handle, "send");
        return Outcome::Return(err(errno::EPERM));
    }
    let id = NEXT_REQUEST.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let object = cap.object_id.clone();
    let queued = PENDING.lock().push_back(Pending {
        id,
        pid,
        handle,
        cap,
        payload,
    });
    if queued.is_err() {
        return Outcome::Return(err(errno::EFULL));
    }
    audit::record_fmt(
        EventKind::ApprovalRequested,
        format_args!("pid-{}:req-{}:{}", pid, id, object),
        id as u64,
    );
    Outcome::Block
}

/// Copy the message from user memory and look up the handle.
fn prepare_send(
    pid: u32,
    handle: u64,
    ptr: u64,
    len: u64,
) -> Result<(Capability, heapless::Vec<u8, MAX_MESSAGE>), u64> {
    if len as usize > MAX_MESSAGE {
        return Err(errno::EINVAL);
    }
    let mut buf = [0u8; MAX_MESSAGE];
    let buf = &mut buf[..len as usize];
    user_tables()
        .copy_from_user(ptr, buf)
        .map_err(|_| errno::EINVAL)?;
    let cap = with_table(pid, |t| t.get(handle).cloned())
        .map_err(handle_errno)?
        .map_err(handle_errno)?;
    let payload = heapless::Vec::from_slice(buf).map_err(|_| errno::EINVAL)?;
    Ok((cap, payload))
}

/// Deliver the message through the kernel (re-verifies and permission-checks).
fn perform_send(pid: u32, handle: u64, cap: &Capability, buf: &[u8]) -> Result<u64, u64> {
    let kernel = kernel().ok_or(errno::EINVAL)?;
    let mut from: heapless::String<16> = heapless::String::new();
    let _ = core::fmt::write(&mut from, format_args!("pid-{}", pid));
    let payload = MessagePayload::Data(heapless::Vec::from_slice(buf).map_err(|_| errno::EINVAL)?);
    let msg = Message::new(&from, &cap.object_id, payload).map_err(|_| errno::EINVAL)?;
    kernel
        .send_message(cap, &cap.object_id, msg)
        .map_err(|e| map_kernel_error(pid, handle, "send", e))?;
    Ok(0)
}

fn sys_recv(pid: u32, handle: u64, ptr: u64, len: u64) -> Result<u64, u64> {
    let cap = with_table(pid, |t| t.get(handle).cloned())
        .map_err(handle_errno)?
        .map_err(handle_errno)?;
    let kernel = kernel().ok_or(errno::EINVAL)?;
    let msg = kernel
        .receive_message(&cap)
        .map_err(|e| map_kernel_error(pid, handle, "recv", e))?
        .ok_or(errno::EEMPTY)?;
    let bytes: &[u8] = match &msg.payload {
        MessagePayload::Data(d) => d,
        MessagePayload::Text(t) | MessagePayload::Command(t) => t.as_bytes(),
        MessagePayload::Response { result } => result.as_bytes(),
        MessagePayload::Request { method, .. } => method.as_bytes(),
    };
    let n = bytes.len().min(len as usize);
    user_tables()
        .copy_to_user(ptr, &bytes[..n])
        .map_err(|_| errno::EINVAL)?;
    Ok(n as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::KernelObject;
    extern crate std;

    fn cap(perms: &[Permission]) -> Capability {
        let obj = KernelObject::new_compute("agent-test", "normal");
        let mut c = Capability::with_permissions(&obj, perms);
        c.issue().unwrap();
        c
    }

    const SEND: u64 = 1 << 4;
    const RECV: u64 = 1 << 5;
    const DELETE: u64 = 1 << 6;

    #[test]
    fn permission_bits_match_capability_mask() {
        let c = cap(&[Permission::SendMessage, Permission::ReceiveMessage]);
        assert_eq!(c.permission_mask(), SEND | RECV);
        for p in ALL_PERMISSIONS {
            let one = cap(&[p.clone()]);
            assert_eq!(one.permission_mask(), perm_bit(&p));
        }
    }

    #[test]
    fn insert_get_remove_and_list() {
        let mut t = HandleTable::new();
        let h0 = t.insert(cap(&[Permission::SendMessage])).unwrap();
        let h1 = t.insert(cap(&[Permission::ReceiveMessage])).unwrap();
        assert_eq!((h0, h1), (0, 1));
        assert!(t.get(1).is_ok());
        assert_eq!(t.get(2).err(), Some(HandleError::BadHandle));
        assert_eq!(t.get(u64::MAX).err(), Some(HandleError::BadHandle));
        t.remove(0).unwrap();
        assert_eq!(t.remove(0).err(), Some(HandleError::BadHandle));
        let listed: heapless::Vec<(u32, u64), 4> = t.list().collect();
        assert_eq!(&listed[..], &[(1, RECV)]);
        // Freed slot is reused.
        assert_eq!(t.insert(cap(&[Permission::Read])).unwrap(), 0);
    }

    #[test]
    fn table_full_is_reported() {
        let mut t = HandleTable::new();
        for _ in 0..MAX_HANDLES {
            t.insert(cap(&[Permission::Read])).unwrap();
        }
        assert_eq!(
            t.insert(cap(&[Permission::Read])),
            Err(HandleError::TableFull)
        );
    }

    #[test]
    fn attenuation_only_removes_permissions() {
        let mut t = HandleTable::new();
        let h = t
            .insert(cap(&[Permission::SendMessage, Permission::ReceiveMessage]))
            .unwrap() as u64;
        let child = t.attenuate(h, RECV).unwrap();
        assert_eq!(child.permission_mask(), RECV);
        assert!(!child.is_signed(), "derived child must be re-issued");
        assert_eq!(
            t.attenuate(h, RECV | DELETE).err(),
            Some(HandleError::Escalation)
        );
        assert_eq!(t.attenuate(h, 0).unwrap().permission_mask(), 0);
        assert_eq!(t.attenuate(9, RECV).err(), Some(HandleError::BadHandle));
    }

    #[test]
    fn approval_constraint_is_inherited_never_dropped() {
        let mut t = HandleTable::new();
        let gated = t
            .insert(cap(&[
                Permission::SendMessage,
                Permission::RequiresApproval,
            ]))
            .unwrap() as u64;
        // Asking for "send" only still yields a gated child.
        let child = t.attenuate(gated, SEND).unwrap();
        assert_eq!(child.permission_mask(), SEND | APPROVAL_BIT);
        // An ungated handle may add the constraint (that only restricts it).
        let open = t.insert(cap(&[Permission::SendMessage])).unwrap() as u64;
        assert_eq!(
            t.attenuate(open, SEND | APPROVAL_BIT)
                .unwrap()
                .permission_mask(),
            SEND | APPROVAL_BIT
        );
        // Rights still can't be added.
        assert_eq!(
            t.attenuate(gated, SEND | RECV).err(),
            Some(HandleError::Escalation)
        );
    }

    #[test]
    fn sanitizer_neutralizes_control_and_quote_bytes() {
        let mut out = std::string::String::new();
        write_sanitized(b"pay \x1b[2J\"ok\"\n\\", |s| out.push_str(s));
        assert_eq!(out, "pay \\x1b[2J\\x22ok\\x22\\x0a\\x5c");
    }

    #[test]
    fn denied_requests_resume_with_edenied() {
        // Queue a request for a pid that is not in the process table; the
        // decision is still audited and consumed.
        let obj = KernelObject::new_compute("approval-test", "normal");
        let c = cap(&[Permission::SendMessage, Permission::RequiresApproval]);
        let _ = obj;
        let _ = PENDING.lock().push_back(Pending {
            id: 77,
            pid: 4242,
            handle: 0,
            cap: c,
            payload: heapless::Vec::from_slice(b"transfer 5").unwrap(),
        });
        let mut seen = std::vec::Vec::new();
        let n = resolve_with(|req| {
            seen.push((req.id, req.payload().to_vec()));
            false
        });
        assert_eq!(n, 1);
        assert_eq!(seen, std::vec![(77, b"transfer 5".to_vec())]);
        assert!(PENDING.lock().is_empty());
    }

    #[test]
    fn permission_parsing_and_names() {
        let p = parse_permissions("send,recv").unwrap();
        assert_eq!(
            &p[..],
            &[Permission::SendMessage, Permission::ReceiveMessage]
        );
        assert_eq!(
            parse_permissions("all").unwrap().len(),
            6,
            "all = every right, no constraint"
        );
        assert_eq!(
            &parse_permissions("send,approval").unwrap()[..],
            &[Permission::SendMessage, Permission::RequiresApproval]
        );
        assert_eq!(
            permission_names(SEND | APPROVAL_BIT).as_str(),
            "send,approval"
        );
        assert_eq!(parse_permissions("send,bogus"), None);
        assert_eq!(parse_permissions(""), None);
        assert_eq!(permission_names(SEND | RECV).as_str(), "send,recv");
    }

    #[test]
    fn error_encoding_is_negative() {
        assert_eq!(err(errno::EPERM) as i64, -2);
        assert_eq!(err(errno::EBADH) as i64, -1);
    }

    #[test]
    fn tables_are_per_pid_and_reset_on_create() {
        create_table(900).unwrap();
        let obj = KernelObject::new_compute("t", "normal");
        let h = grant(900, &obj, &[Permission::SendMessage]).unwrap();
        assert_eq!(h, 0);
        // Another pid cannot see it.
        create_table(901).unwrap();
        let mut seen = 0;
        describe(901, |_, _, _| seen += 1).unwrap();
        assert_eq!(seen, 0);
        // Re-creating the table for the same pid clears it.
        create_table(900).unwrap();
        describe(900, |_, _, _| seen += 1).unwrap();
        assert_eq!(seen, 0);
        destroy_table(900);
        destroy_table(901);
        assert_eq!(describe(900, |_, _, _| {}), Err(HandleError::NoProcess));
    }
}
