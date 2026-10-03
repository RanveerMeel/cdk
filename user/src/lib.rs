//! Minimal runtime for CDK user programs.
//!
//! Provides the `_start` entry point, syscall wrappers, `print!`/`println!`,
//! and a panic handler. A program defines
//!
//! ```ignore
//! #[no_mangle]
//! pub extern "C" fn cdk_main() -> u64 { /* ... */ 0 }
//! ```
//!
//! and its return value becomes the process exit code.
//!
//! Syscall ABI (matches the kernel's `syscall_dispatch`): number in `rax`,
//! arguments in `rdi`, `rsi`, `rdx`; result in `rax` (errors as `-(code)`).
//! The kernel may clobber every caller-saved register.
//!
//! Capability handles ([`cap_list`], [`cap_derive`], [`send`], [`recv`]) are
//! indices into the kernel's per-process handle table; the tokens themselves
//! never enter user memory.

#![no_std]

use core::fmt::{self, Write};

/// Integer-only model inference (`CDKLM1`), re-exported from `cdk-ml`.
pub use cdk_ml as ml;

pub const SYS_EXIT: u64 = 1;
pub const SYS_WRITE: u64 = 2;
pub const SYS_CAP_LIST: u64 = 3;
pub const SYS_CAP_DROP: u64 = 4;
pub const SYS_CAP_DERIVE: u64 = 5;
pub const SYS_SEND: u64 = 6;
pub const SYS_RECV: u64 = 7;
pub const SYS_GETPID: u64 = 8;
pub const SYS_TOOL_CALL: u64 = 9;

/// Permission bits in a capability mask (bit = kernel permission tag).
pub mod perm {
    pub const READ: u32 = 1 << 1;
    pub const WRITE: u32 = 1 << 2;
    pub const EXEC: u32 = 1 << 3;
    pub const SEND: u32 = 1 << 4;
    pub const RECV: u32 = 1 << 5;
    pub const DELETE: u32 = 1 << 6;
    /// Constraint: every send through this handle waits for a human.
    pub const APPROVAL: u32 = 1 << 7;
}

/// Errors from capability syscalls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No such handle.
    BadHandle,
    /// The handle lacks the permission (or a derive would add one).
    Denied,
    /// Bad pointer, length, or argument.
    Invalid,
    /// The object's queue is full.
    Full,
    /// No message waiting.
    Empty,
    /// The handle table is full.
    NoSpace,
    /// The capability failed verification.
    BadSignature,
    /// A human denied the action (approval-gated handle).
    HumanDenied,
    /// No secure link to the gateway.
    NoLink,
    /// The tool call got no result in time.
    TimedOut,
    /// The tool's gateway listing changed and the operator has not approved
    /// it (policy review); calls are blocked until they do.
    PolicyBlocked,
    /// Unrecognized error code.
    Other(u64),
}

impl Error {
    fn from_code(code: u64) -> Self {
        match code {
            1 => Error::BadHandle,
            2 => Error::Denied,
            3 => Error::Invalid,
            4 => Error::Full,
            5 => Error::Empty,
            6 => Error::NoSpace,
            7 => Error::BadSignature,
            8 => Error::HumanDenied,
            9 => Error::NoLink,
            10 => Error::TimedOut,
            11 => Error::PolicyBlocked,
            c => Error::Other(c),
        }
    }
}

fn check(ret: u64) -> Result<u64, Error> {
    if (ret as i64) < 0 {
        Err(Error::from_code(ret.wrapping_neg()))
    } else {
        Ok(ret)
    }
}

/// A capability handle as reported by [`cap_list`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct CapInfo {
    pub handle: u32,
    /// Permission mask (see [`perm`]).
    pub perms: u32,
}

/// Largest write the kernel accepts in one call.
pub const MAX_WRITE: usize = 1024;

core::arch::global_asm!(
    r#"
    .section .text._start, "ax"
    .global _start
    _start:
        // The kernel enters with RSP at the 16-byte-aligned stack top and no
        // return address. Align, call into Rust, then exit with its result.
        and rsp, -16
        call {entry}
        mov rdi, rax
        mov eax, {exit}
        syscall
        ud2
    "#,
    entry = sym runtime_entry,
    exit = const SYS_EXIT,
);

unsafe extern "C" {
    fn cdk_main() -> u64;
}

extern "C" fn runtime_entry() -> u64 {
    unsafe { cdk_main() }
}

#[inline]
unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a0,
        in("rsi") a1,
        lateout("rcx") _,
        lateout("r11") _,
        clobber_abi("C"),
        options(nostack),
    );
    ret
}

#[inline]
unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        lateout("rcx") _,
        lateout("r11") _,
        clobber_abi("C"),
        options(nostack),
    );
    ret
}

/// Fill `out` with this process's handles; returns how many it holds
/// (which may exceed `out.len()`).
pub fn cap_list(out: &mut [CapInfo]) -> Result<usize, Error> {
    let r = unsafe { syscall3(SYS_CAP_LIST, out.as_mut_ptr() as u64, out.len() as u64, 0) };
    check(r).map(|n| n as usize)
}

/// Give up a handle.
pub fn cap_drop(handle: u32) -> Result<(), Error> {
    check(unsafe { syscall3(SYS_CAP_DROP, handle as u64, 0, 0) }).map(|_| ())
}

/// Derive a new handle to the same object holding only `perms` (a subset of
/// the parent's; asking for more fails with [`Error::Denied`]).
pub fn cap_derive(handle: u32, perms: u32) -> Result<u32, Error> {
    check(unsafe { syscall3(SYS_CAP_DERIVE, handle as u64, perms as u64, 0) }).map(|h| h as u32)
}

/// Send up to 64 bytes to the handle's object (needs [`perm::SEND`]). If the
/// handle carries [`perm::APPROVAL`], this blocks until a human decides.
pub fn send(handle: u32, msg: &[u8]) -> Result<(), Error> {
    let r = unsafe {
        syscall3(
            SYS_SEND,
            handle as u64,
            msg.as_ptr() as u64,
            msg.len() as u64,
        )
    };
    check(r).map(|_| ())
}

/// Receive the next message from the handle's object (needs [`perm::RECV`]).
pub fn recv(handle: u32, buf: &mut [u8]) -> Result<usize, Error> {
    let r = unsafe {
        syscall3(
            SYS_RECV,
            handle as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    };
    check(r).map(|n| n as usize)
}

#[inline]
unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        in("r10") a3,
        in("r8") a4,
        lateout("rcx") _,
        lateout("r11") _,
        clobber_abi("C"),
        options(nostack),
    );
    ret
}

/// How a tool call ended (from the gateway / MCP server).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolStatus {
    Ok,
    /// The tool reported an error; the result text explains it.
    ToolError,
    UnknownTool,
    /// The gateway's policy refused the call.
    Refused,
    /// The tool server failed or timed out.
    Unavailable,
    /// The result did not fit and was cut.
    Truncated,
    Other(u32),
}

/// Call the MCP tool behind `handle` (needs [`perm::EXEC`]) with JSON
/// `args`; the result text is written to `out`. Blocks until the gateway
/// answers (or a human decides, for approval-gated handles). Returns the
/// status and the number of result bytes written.
pub fn tool_call(handle: u32, args: &[u8], out: &mut [u8]) -> Result<(ToolStatus, usize), Error> {
    let r = unsafe {
        syscall5(
            SYS_TOOL_CALL,
            handle as u64,
            args.as_ptr() as u64,
            args.len() as u64,
            out.as_mut_ptr() as u64,
            out.len() as u64,
        )
    };
    let v = check(r)?;
    let status = match (v >> 32) as u32 {
        0 => ToolStatus::Ok,
        1 => ToolStatus::ToolError,
        2 => ToolStatus::UnknownTool,
        3 => ToolStatus::Refused,
        4 => ToolStatus::Unavailable,
        5 => ToolStatus::Truncated,
        s => ToolStatus::Other(s),
    };
    Ok((status, (v & 0xffff_ffff) as usize))
}

/// Largest JSON argument block the kernel accepts for one call.
pub const MAX_ARGS: usize = 900;

/// Ask the model behind `handle` (a `model:<name>` object; needs
/// [`perm::EXEC`]). Builds `{"prompt":…,"system":…,"max_tokens":…}` and calls
/// it like a tool; the gateway runs the model and adds any credential, which
/// the agent never sees. Returns [`Error::Invalid`] if the escaped request
/// exceeds [`MAX_ARGS`].
pub fn ask_model(
    handle: u32,
    system: Option<&str>,
    prompt: &str,
    max_tokens: u32,
    out: &mut [u8],
) -> Result<(ToolStatus, usize), Error> {
    let mut buf = [0u8; MAX_ARGS];
    let mut w = JsonWriter {
        buf: &mut buf,
        len: 0,
        overflow: false,
    };
    w.raw("{\"prompt\":");
    w.string(prompt);
    if let Some(s) = system {
        w.raw(",\"system\":");
        w.string(s);
    }
    let _ = core::fmt::Write::write_fmt(&mut w, format_args!(",\"max_tokens\":{}}}", max_tokens));
    if w.overflow {
        return Err(Error::Invalid);
    }
    let len = w.len;
    tool_call(handle, &buf[..len], out)
}

struct JsonWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
    overflow: bool,
}

impl JsonWriter<'_> {
    fn raw(&mut self, s: &str) {
        for &b in s.as_bytes() {
            self.byte(b);
        }
    }

    fn byte(&mut self, b: u8) {
        match self.buf.get_mut(self.len) {
            Some(slot) => {
                *slot = b;
                self.len += 1;
            }
            None => self.overflow = true,
        }
    }

    /// A JSON string literal; control characters, `"` and `\\` escaped.
    fn string(&mut self, s: &str) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.byte(b'"');
        for &b in s.as_bytes() {
            match b {
                b'"' | b'\\' => {
                    self.byte(b'\\');
                    self.byte(b);
                }
                0..=0x1f => {
                    self.raw("\\u00");
                    self.byte(HEX[(b >> 4) as usize]);
                    self.byte(HEX[(b & 15) as usize]);
                }
                _ => self.byte(b),
            }
        }
        self.byte(b'"');
    }
}

impl core::fmt::Write for JsonWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.raw(s);
        Ok(())
    }
}

/// This process's id.
pub fn getpid() -> u32 {
    unsafe { syscall3(SYS_GETPID, 0, 0, 0) as u32 }
}

/// Write bytes to the kernel console. Returns the number written, or `None`
/// if the kernel rejected the buffer.
pub fn write(buf: &[u8]) -> Option<usize> {
    let mut done = 0;
    for chunk in buf.chunks(MAX_WRITE) {
        let r = unsafe { syscall2(SYS_WRITE, chunk.as_ptr() as u64, chunk.len() as u64) };
        if r == u64::MAX {
            return None;
        }
        done += r as usize;
    }
    Some(done)
}

/// Terminate the process with `code`.
pub fn exit(code: u64) -> ! {
    unsafe {
        syscall2(SYS_EXIT, code, 0);
        core::hint::unreachable_unchecked()
    }
}

/// Console writer that buffers a line before issuing `SYS_write`.
pub struct Console {
    buf: [u8; 256],
    len: usize,
}

impl Console {
    pub const fn new() -> Self {
        Self {
            buf: [0; 256],
            len: 0,
        }
    }

    pub fn flush(&mut self) {
        if self.len > 0 {
            let _ = write(&self.buf[..self.len]);
            self.len = 0;
        }
    }
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len == self.buf.len() {
                self.flush();
            }
            self.buf[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        self.flush();
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    let mut c = Console::new();
    let _ = c.write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::_print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::_print(format_args!("{}\n", format_args!($($arg)*))) };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut c = Console::new();
    let _ = writeln!(c, "user panic: {}", info.message());
    c.flush();
    exit(101)
}
