//! Agent tool calls through the host MCP gateway (roadmap 3.3).
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
//! through without parsing.

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
/// Largest result buffer an agent may pass.
pub const MAX_RESULT: u64 = 4096;
/// Kind prefix of tool objects.
pub const KIND_PREFIX: &str = "tool:";

struct InFlight {
    call_id: u32,
    pid: u32,
    tool: String<{ tool::MAX_NAME }>,
    out_ptr: u64,
    out_len: u64,
    pml4: u64,
    started: u64,
}

static INFLIGHT: Mutex<heapless::Vec<InFlight, 8>> = Mutex::new(heapless::Vec::new());
static NEXT_CALL: AtomicU32 = AtomicU32::new(1);

/// Ask the gateway for its tools and register a `tool:<name>` object for
/// each new one. Returns the tool names now available.
pub fn sync(
    kernel: &mut Kernel,
) -> Result<heapless::Vec<String<{ tool::MAX_NAME }>, 16>, &'static str> {
    if !crate::link::is_secure() {
        return Err("no secure link (run link-secure)");
    }
    if !crate::link::send_data(&tool::encode_list_request()).map_err(|_| "send failed")? {
        return Err("link not sealed");
    }
    let start = crate::cpu::rdtsc();
    let mut names: Option<heapless::Vec<String<{ tool::MAX_NAME }>, 16>> = None;
    while names.is_none() && crate::cpu::rdtsc().wrapping_sub(start) < 5_000 * 2_000_000 {
        crate::link::recv(|m| {
            let crate::link::Incoming::Sealed(p) = m else {
                return;
            };
            match tool::decode(p) {
                Ok(Message::ListResponse(list)) => {
                    let mut v = heapless::Vec::new();
                    for n in list {
                        let mut s = String::new();
                        if s.push_str(n).is_ok() {
                            let _ = v.push(s);
                        }
                    }
                    names = Some(v);
                }
                Ok(Message::CallResponse { .. }) => deliver(p),
                _ => {}
            }
        });
    }
    let names = names.ok_or("gateway did not answer tools/list")?;
    for n in names.iter() {
        let mut kind: String<32> = String::new();
        if write!(kind, "{KIND_PREFIX}{n}").is_err() {
            continue; // name too long for an object kind
        }
        if kernel.resolve_object_ref(&kind).is_err() {
            let _ = kernel.register_object(crate::object::KernelObject::new_compute(&kind, "tool"));
        }
    }
    Ok(names)
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
            o.kind.strip_prefix(KIND_PREFIX).map(|n| {
                let mut s: String<{ tool::MAX_NAME }> = String::new();
                let _ = s.push_str(n);
                s
            })
        })
        .ok_or(errno::EINVAL)?;
    if !cap.has_permission(&Permission::Execute) {
        crate::agent::audit_denied(pid, handle, "tool");
        return Err(errno::EPERM);
    }
    if !crate::link::is_secure() {
        return Err(errno::ENOLINK);
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
    let _ = INFLIGHT.lock().push(InFlight {
        call_id,
        pid: call.pid,
        tool: call.tool,
        out_ptr: call.out_ptr,
        out_len: call.out_len,
        pml4: call.pml4,
        started: crate::cpu::rdtsc(),
    });
    Ok(())
}

/// Deliver results that have arrived and fail calls that timed out.
/// Returns how many calls finished.
pub fn poll() -> usize {
    let mut done = 0;
    crate::link::recv(|m| {
        if let crate::link::Incoming::Sealed(p) = m {
            if matches!(tool::decode(p), Ok(Message::CallResponse { .. })) {
                deliver(p);
                done += 1;
            }
        }
    });
    let now = crate::cpu::rdtsc();
    let limit = CALL_TIMEOUT_MS * 2_000_000;
    loop {
        let expired = {
            let mut inflight = INFLIGHT.lock();
            let pos = inflight
                .iter()
                .position(|c| now.wrapping_sub(c.started) > limit);
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

fn deliver(msg: &[u8]) {
    let Ok(Message::CallResponse {
        call_id,
        status,
        body,
    }) = tool::decode(msg)
    else {
        return;
    };
    let call = {
        let mut inflight = INFLIGHT.lock();
        let Some(i) = inflight.iter().position(|c| c.call_id == call_id) else {
            return; // unknown or already timed out
        };
        inflight.swap_remove(i)
    };
    let n = body.len().min(call.out_len as usize);
    let tables = crate::paging::PageTableManager::from_pml4_phys(call.pml4);
    let result = if n == 0 || tables.copy_to_user(call.out_ptr, &body[..n]).is_ok() {
        let status = if n < body.len() && status == Status::Ok {
            Status::Truncated
        } else {
            status
        };
        ((status as u64) << 32) | n as u64
    } else {
        err(errno::EINVAL)
    };
    audit::record_fmt(
        EventKind::ToolResult,
        format_args!("pid-{}:call-{}:{}", call.pid, call_id, call.tool),
        ((status as u64) << 32) | body.len() as u64,
    );
    crate::process::unblock(call.pid, result);
}
