//! Agent tool calls through the host MCP gateway (roadmap 3.3), and model
//! inference through Linux-hosted model servers (3.4).
//!
//! Model backends (`model:<name>`) are called exactly like tools; the
//! gateway turns the call into an OpenAI-compatible chat completion and
//! adds the backend's credential, which never enters CDK.
//!
//! Tools offered by the gateway's MCP servers become kernel objects of kind
//! `tool:<name>` ([`sync`]). An agent can call a tool only through a
//! capability handle to that object carrying `Execute`
//! (`grant <pid> tool:echo exec`); the call:
//!
//! 1. re-verifies the token and checks `Execute` (audited like any use),
//! 2. requires the post-quantum secure link to the pinned gateway,
//! 3. waits for a human first if the handle carries the approval
//!    constraint,
//! 4. is sent sealed to the gateway (`cdk_link::tool::CallRequest`), which
//!    runs MCP `tools/call`, and
//! 5. blocks the agent until the result arrives (copied into its buffer) or
//!    [`CALL_TIMEOUT_MS`] passes.
//!
//! Calls and results are audit-logged (`tool-call`, `tool-result`). The
//! agent supplies the arguments as JSON bytes, which the kernel passes
//! through without parsing. Results longer than one frame arrive as chunks
//! and are copied into the agent's buffer as they come.

extern crate alloc;

use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

use cdk_link::tool::{self, Message, Status};
use heapless::String;
use sha2::{Digest, Sha256};
use spin::Mutex;

use crate::agent::{err, errno};
use crate::audit::{self, EventKind};
use crate::capability::Permission;
use crate::kernel::Kernel;
use crate::syscall::Outcome;

pub const SYS_TOOL_CALL: u64 = 9;
/// A call with no result after this long fails with `ETIMEDOUT`. Longer
/// than the gateway's own MCP timeout (10 s), so a slow tool is normally
/// reported by the gateway (`Unavailable`) and this only fires if the
/// gateway itself goes silent.
pub const CALL_TIMEOUT_MS: u64 = 15_000;
/// Time-out for model calls: longer than the gateway's model time-out (90 s).
pub const MODEL_CALL_TIMEOUT_MS: u64 = 120_000;
/// Largest result buffer an agent may pass.
pub const MAX_RESULT: u64 = tool::MAX_RESULT as u64;
/// Kind prefix of tool objects.
pub const KIND_PREFIX: &str = "tool:";

/// The name the gateway knows an object by: `tool:echo` → `echo`,
/// `model:qwen` → `model:qwen`; `None` if the object is neither.
pub fn wire_name(kind: &str) -> Option<&str> {
    kind.strip_prefix(KIND_PREFIX)
        .or_else(|| kind.starts_with(tool::MODEL_PREFIX).then_some(kind))
}

struct InFlight {
    call_id: u32,
    pid: u32,
    tool: String<{ tool::MAX_NAME }>,
    out_ptr: u64,
    out_len: u64,
    pml4: u64,
    started: u64,
    timeout_ms: u64,
    /// Result bytes received so far (chunks).
    received: usize,
    /// A chunk could not be copied to the agent.
    failed: bool,
}

static INFLIGHT: Mutex<heapless::Vec<InFlight, 8>> = Mutex::new(heapless::Vec::new());
static NEXT_CALL: AtomicU32 = AtomicU32::new(1);

/// A tool or model as last approved by the operator (roadmap 2.9).
struct Pinned {
    kind: String<32>,
    flags: u8,
    endpoint: String<{ tool::MAX_ENDPOINT }>,
    /// Session in which this listing was last confirmed; calls are allowed
    /// only when it is the current one.
    epoch: u32,
}

static MANIFEST: Mutex<heapless::Vec<Pinned, 32>> = Mutex::new(heapless::Vec::new());

/// Approved gateway flags of a tool object (0 if not pinned).
pub fn pinned_flags(kind: &str) -> u8 {
    MANIFEST
        .lock()
        .iter()
        .find(|p| p.kind == kind)
        .map_or(0, |p| p.flags)
}

/// Approved endpoint of a tool object.
pub fn pinned_endpoint(kind: &str) -> Option<String<{ tool::MAX_ENDPOINT }>> {
    MANIFEST
        .lock()
        .iter()
        .find(|p| p.kind == kind && !p.endpoint.is_empty())
        .map(|p| p.endpoint.clone())
}

/// `(kind, flags, endpoint, callable now)` for each pinned tool or model.
pub fn for_each_pinned(mut f: impl FnMut(&str, u8, &str, bool)) {
    let epoch = crate::link::session_epoch();
    for p in MANIFEST.lock().iter() {
        f(
            &p.kind,
            p.flags,
            &p.endpoint,
            p.epoch == epoch && epoch != 0,
        );
    }
}

/// Whether calls to `kind` are allowed: its listing is approved and was
/// confirmed in the current secure session.
pub fn verified(kind: &str) -> bool {
    let epoch = crate::link::session_epoch();
    MANIFEST
        .lock()
        .iter()
        .any(|p| p.kind == kind && p.epoch == epoch && epoch != 0)
}

/// One entry of the gateway's listing, owned.
pub struct Listed {
    pub kind: String<32>,
    pub flags: u8,
    pub endpoint: String<{ tool::MAX_ENDPOINT }>,
}

fn object_kind(name: &str) -> Option<String<32>> {
    let mut kind: String<32> = String::new();
    let written = if name.starts_with(tool::MODEL_PREFIX) {
        kind.push_str(name).map_err(|_| core::fmt::Error)
    } else {
        write!(kind, "{KIND_PREFIX}{name}")
    };
    written.ok().map(|_| kind)
}

pub fn flag_names(flags: u8) -> &'static str {
    match flags & (tool::FLAG_CREDENTIAL | tool::FLAG_REMOTE) {
        0 => "-",
        tool::FLAG_CREDENTIAL => "credential",
        tool::FLAG_REMOTE => "remote",
        _ => "credential,remote",
    }
}

/// Ask the gateway for its tools and models and review the listing against
/// the pinned manifest: unchanged entries are confirmed for this session; new
/// or changed ones (other flags or endpoint) are shown with the agents they
/// affect, checked against the policy rules, and pinned only if the operator
/// approves. Until then calls to them fail with `EPOLICY`. Returns the
/// listing.
pub fn sync(kernel: &mut Kernel) -> Result<heapless::Vec<Listed, 16>, &'static str> {
    if !crate::link::is_secure() {
        return Err("no secure link (run link-secure)");
    }
    if !crate::link::send_data(&tool::encode_list_request()).map_err(|_| "send failed")? {
        return Err("link not sealed");
    }
    let start = crate::cpu::rdtsc();
    let mut listed: Option<heapless::Vec<Listed, 16>> = None;
    while listed.is_none() && crate::cpu::rdtsc().wrapping_sub(start) < 5_000 * 2_000_000 {
        crate::link::recv(|m| {
            let crate::link::Incoming::Sealed(p) = m else {
                return;
            };
            match tool::decode(p) {
                Ok(Message::ListResponse(list)) => {
                    let mut v = heapless::Vec::new();
                    for e in list {
                        let (Some(kind), Ok(endpoint)) =
                            (object_kind(e.name), String::try_from(e.endpoint))
                        else {
                            continue; // name too long for an object kind
                        };
                        let _ = v.push(Listed {
                            kind,
                            flags: e.flags,
                            endpoint,
                        });
                    }
                    listed = Some(v);
                }
                Ok(Message::CallResponse { .. } | Message::CallChunk { .. }) => deliver(p),
                _ => {}
            }
        });
    }
    let listed = listed.ok_or("gateway did not answer tools/list")?;
    review_listing(kernel, &listed);
    Ok(listed)
}

fn review_listing(kernel: &mut Kernel, listed: &[Listed]) {
    let epoch = crate::link::session_epoch();
    // Confirm unchanged entries; collect new and changed ones.
    let mut pending: heapless::Vec<usize, 16> = heapless::Vec::new();
    {
        let mut m = MANIFEST.lock();
        for (i, l) in listed.iter().enumerate() {
            match m.iter_mut().find(|p| p.kind == l.kind) {
                Some(p) if p.flags == l.flags && p.endpoint == l.endpoint => p.epoch = epoch,
                _ => {
                    let _ = pending.push(i);
                }
            }
        }
        for p in m
            .iter()
            .filter(|p| !listed.iter().any(|l| l.kind == p.kind))
        {
            crate::println!("  - {} no longer offered by the gateway", p.kind);
        }
    }
    if pending.is_empty() {
        return;
    }

    let policy = crate::policy::policy();
    let before = crate::policy::current_grants(kernel);
    // The same handles, seen with the listing's new attributes.
    let mut after = before.clone();
    for g in after.iter_mut() {
        if let Some(&i) = pending.iter().find(|&&i| listed[i].kind == g.kind) {
            g.flags = listed[i].flags;
        }
    }
    let mut text = alloc::string::String::new();
    crate::println!("=== POLICY CHANGE REVIEW: gateway listing ===");
    for &i in &pending {
        let l = &listed[i];
        let old = MANIFEST
            .lock()
            .iter()
            .find(|p| p.kind == l.kind)
            .map(|p| (p.flags, p.endpoint.clone()));
        let labels = policy.labels_of("", &l.kind, l.flags);
        let mut line: String<256> = String::new();
        match &old {
            None => {
                let _ = write!(line, "+ new {} via {} [", l.kind, l.endpoint);
            }
            Some((f, ep)) => {
                let _ = write!(
                    line,
                    "~ CHANGED {}: endpoint {} -> {}, flags {} -> {} [",
                    l.kind,
                    ep,
                    l.endpoint,
                    flag_names(*f),
                    flag_names(l.flags)
                );
            }
        }
        for (n, lab) in labels.iter().enumerate() {
            let _ = write!(line, "{}{}", if n > 0 { "," } else { "" }, lab);
        }
        let _ = line.push(']');
        crate::println!("  {}", line);
        let _ = writeln!(text, "{line}");
        for g in after.iter().filter(|g| g.kind == l.kind) {
            crate::println!(
                "      held by pid {} ({}){}",
                g.pid,
                crate::agent::permission_names(g.mask),
                if old.is_some() {
                    ": its reach changes"
                } else {
                    ""
                }
            );
        }
    }
    let mut subj: String<48> = String::new();
    let _ = write!(subj, "tools:{}-change(s)", pending.len());
    if crate::policy::is_broken() {
        crate::println!("policy: refused — the boot policy is malformed; these stay blocked");
        audit::record(
            EventKind::PolicyRefused,
            &subj,
            crate::policy::refuse_reason::POLICY_BROKEN,
        );
        return;
    }
    let old_v = policy.violations(&before);
    let fresh: alloc::vec::Vec<_> = policy
        .violations(&after)
        .into_iter()
        .filter(|v| !old_v.contains(v))
        .collect();
    if !fresh.is_empty() {
        for v in &fresh {
            crate::println!("  ! VIOLATION: {}", v);
        }
        crate::println!("policy: refused — calls to these stay blocked (EPOLICY)");
        audit::record(
            EventKind::PolicyRefused,
            &subj,
            crate::policy::refuse_reason::VIOLATION,
        );
        return;
    }
    if !crate::policy::confirm("Pin this gateway listing?") {
        crate::println!("policy: declined — calls to these stay blocked (EPOLICY)");
        audit::record(
            EventKind::PolicyRefused,
            &subj,
            crate::policy::refuse_reason::DECLINED,
        );
        return;
    }
    {
        let mut m = MANIFEST.lock();
        for &i in &pending {
            let l = &listed[i];
            match m.iter_mut().find(|p| p.kind == l.kind) {
                Some(p) => {
                    p.flags = l.flags;
                    p.endpoint = l.endpoint.clone();
                    p.epoch = epoch;
                }
                None => {
                    let _ = m.push(Pinned {
                        kind: l.kind.clone(),
                        flags: l.flags,
                        endpoint: l.endpoint.clone(),
                        epoch,
                    });
                }
            }
        }
    }
    for &i in &pending {
        let kind = &listed[i].kind;
        if kernel.resolve_object_ref(kind).is_err() {
            let _ = kernel.register_object(crate::object::KernelObject::new_compute(kind, "tool"));
        }
    }
    audit::record(
        EventKind::PolicyApplied,
        &subj,
        crate::policy::digest(&text),
    );
}

/// Whether any tool call is waiting for its result.
pub fn has_inflight() -> bool {
    !INFLIGHT.lock().is_empty()
}

/// `tool_call(handle, args_ptr, args_len, out_ptr, out_len)`.
///
/// Returns (via the blocked process's `rax`) `status << 32 | length` on
/// completion, or `-errno`.
pub fn sys_tool_call(
    handle: u64,
    args_ptr: u64,
    args_len: u64,
    out_ptr: u64,
    out_len: u64,
) -> Outcome {
    match prepare(handle, args_ptr, args_len, out_ptr, out_len) {
        Ok(p) => p,
        Err(code) => Outcome::Return(err(code)),
    }
}

fn prepare(
    handle: u64,
    args_ptr: u64,
    args_len: u64,
    out_ptr: u64,
    out_len: u64,
) -> Result<Outcome, u64> {
    let pid = crate::process::current_pid().ok_or(errno::EINVAL)?;
    if args_len as usize > tool::MAX_BODY || out_len > MAX_RESULT {
        return Err(errno::EINVAL);
    }
    let tables = crate::paging::PageTableManager::from_pml4_phys(crate::syscall::current_cr3());
    let mut args = [0u8; tool::MAX_BODY];
    let args = &mut args[..args_len as usize];
    tables
        .copy_from_user(args_ptr, args)
        .map_err(|_| errno::EINVAL)?;
    // Fail now, not when the result arrives, if the buffer is unusable.
    if out_len > 0 {
        tables
            .check_user_writable(out_ptr, out_len)
            .map_err(|_| errno::EINVAL)?;
    }

    let cap = crate::agent::handle_cap(pid, handle).map_err(|_| errno::EBADH)?;
    let kernel = crate::agent::kernel_ref().ok_or(errno::EINVAL)?;
    if Kernel::verify_capability(&cap) != Ok(true) {
        return Err(errno::ESIG);
    }
    let tool_name = kernel
        .for_each_object_find(&cap.object_id)
        .and_then(|o| {
            wire_name(&o.kind).map(|n| {
                let mut s: String<{ tool::MAX_NAME }> = String::new();
                let _ = s.push_str(n);
                s
            })
        })
        .ok_or(errno::EINVAL)?;
    let kind: String<32> = kernel
        .for_each_object_find(&cap.object_id)
        .and_then(|o| String::try_from(o.kind.as_str()).ok())
        .unwrap_or_default();
    if !cap.has_permission(&Permission::Execute) {
        crate::agent::audit_denied(pid, handle, "tool");
        return Err(errno::EPERM);
    }
    if !crate::link::is_secure() {
        return Err(errno::ENOLINK);
    }
    if !verified(&kind) {
        audit::record_fmt(
            EventKind::PolicyRefused,
            format_args!("call:pid-{}:{}", pid, kind),
            crate::policy::refuse_reason::UNREVIEWED_TOOL,
        );
        return Err(errno::EPOLICY);
    }
    let pml4 = crate::process::pml4_of(pid).ok_or(errno::EINVAL)?;
    let call = Call {
        pid,
        tool: tool_name,
        args: heapless::Vec::from_slice(args).map_err(|_| errno::EINVAL)?,
        out_ptr,
        out_len,
        pml4,
    };
    if cap.has_permission(&Permission::RequiresApproval) {
        crate::agent::request_tool_approval(handle, cap, call).map_err(|_| errno::EFULL)?;
        return Ok(Outcome::Block);
    }
    dispatch(call)?;
    Ok(Outcome::Block)
}

/// A tool call ready to go to the gateway.
pub struct Call {
    pub pid: u32,
    pub tool: String<{ tool::MAX_NAME }>,
    pub args: heapless::Vec<u8, { tool::MAX_BODY }>,
    pub out_ptr: u64,
    pub out_len: u64,
    pub pml4: u64,
}

/// Send `call` sealed to the gateway and record it as in flight. On error
/// the caller must unblock the process.
pub fn dispatch(call: Call) -> Result<(), u64> {
    let call_id = NEXT_CALL.fetch_add(1, Ordering::Relaxed);
    let msg =
        tool::encode_call_request(call_id, &call.tool, &call.args).map_err(|_| errno::EINVAL)?;
    if INFLIGHT.lock().is_full() {
        return Err(errno::EFULL);
    }
    match crate::link::send_data(&msg) {
        Ok(true) => {}
        _ => return Err(errno::ENOLINK),
    }
    let digest = Sha256::digest(&call.args);
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    audit::record_fmt(
        EventKind::ToolCall,
        format_args!("pid-{}:call-{}:{}", call.pid, call_id, call.tool),
        u64::from_be_bytes(prefix),
    );
    let timeout_ms = if call.tool.starts_with(tool::MODEL_PREFIX) {
        MODEL_CALL_TIMEOUT_MS
    } else {
        CALL_TIMEOUT_MS
    };
    let _ = INFLIGHT.lock().push(InFlight {
        call_id,
        pid: call.pid,
        tool: call.tool,
        out_ptr: call.out_ptr,
        out_len: call.out_len,
        pml4: call.pml4,
        started: crate::cpu::rdtsc(),
        timeout_ms,
        received: 0,
        failed: false,
    });
    Ok(())
}

/// Deliver results that have arrived and fail calls that timed out.
/// Returns how many calls finished.
pub fn poll() -> usize {
    let mut done = 0;
    crate::link::recv(|m| {
        if let crate::link::Incoming::Sealed(p) = m {
            match tool::decode(p) {
                Ok(Message::CallResponse { .. }) => {
                    deliver(p);
                    done += 1;
                }
                Ok(Message::CallChunk { .. }) => deliver(p),
                _ => {}
            }
        }
    });
    let now = crate::cpu::rdtsc();
    loop {
        let expired = {
            let mut inflight = INFLIGHT.lock();
            let pos = inflight
                .iter()
                .position(|c| now.wrapping_sub(c.started) > c.timeout_ms * 2_000_000);
            pos.map(|i| inflight.swap_remove(i))
        };
        let Some(c) = expired else {
            break;
        };
        audit::record_fmt(
            EventKind::ToolResult,
            format_args!("pid-{}:call-{}:{}", c.pid, c.call_id, c.tool),
            u64::MAX,
        );
        crate::process::unblock(c.pid, err(errno::ETIMEDOUT));
        done += 1;
    }
    done
}

/// Poll until at least one call finishes (or they all time out).
pub fn wait_progress() {
    while has_inflight() && poll() == 0 {
        core::hint::spin_loop();
    }
}

/// Handle a `CallChunk` (copy it at the current offset) or the final
/// `CallResponse` (copy the rest, audit, and wake the agent).
fn deliver(msg: &[u8]) {
    let (call_id, status, body) = match tool::decode(msg) {
        Ok(Message::CallChunk { call_id, body }) => (call_id, None, body),
        Ok(Message::CallResponse {
            call_id,
            status,
            body,
        }) => (call_id, Some(status), body),
        _ => return,
    };
    let mut inflight = INFLIGHT.lock();
    let Some(i) = inflight.iter().position(|c| c.call_id == call_id) else {
        return; // unknown or already timed out
    };
    let c = &mut inflight[i];
    let room = (c.out_len as usize).saturating_sub(c.received);
    let n = body.len().min(room);
    if n > 0 && !c.failed {
        let tables = crate::paging::PageTableManager::from_pml4_phys(c.pml4);
        c.failed = tables
            .copy_to_user(c.out_ptr + c.received as u64, &body[..n])
            .is_err();
    }
    c.received += body.len();
    let Some(status) = status else {
        return; // more to come
    };
    let call = inflight.swap_remove(i);
    drop(inflight);

    let copied = call.received.min(call.out_len as usize);
    let result = if call.failed {
        err(errno::EINVAL)
    } else {
        let status = if copied < call.received && status == Status::Ok {
            Status::Truncated
        } else {
            status
        };
        ((status as u64) << 32) | copied as u64
    };
    audit::record_fmt(
        EventKind::ToolResult,
        format_args!("pid-{}:call-{}:{}", call.pid, call_id, call.tool),
        ((status as u64) << 32) | call.received as u64,
    );
    crate::process::unblock(call.pid, result);
}
