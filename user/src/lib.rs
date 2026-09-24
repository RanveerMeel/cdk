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
//! arguments in `rdi`, `rsi`; result in `rax`. The kernel may clobber every
//! caller-saved register.

#![no_std]

use core::fmt::{self, Write};

pub const SYS_EXIT: u64 = 1;
pub const SYS_WRITE: u64 = 2;

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
