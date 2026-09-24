//! Minimal process table for ring-3 ELF tasks.
//!
//! Lifecycle: [`spawn_smoke_elf`] loads a program and records it `Ready`;
//! [`enter`] runs it in ring 3 (`Running`) until `SYS_exit` marks it
//! `Zombie` — or a CPU exception marks it `Crashed` — and control returns to
//! the caller; [`reap`] frees its address space and slot. Console
//! `elf-spawn` / `elf-run` / `ps` / `reap` drive this.

use core::sync::atomic::{AtomicU32, Ordering};
use heapless::Vec;
use spin::Mutex;

use crate::allocator::FrameAllocator;
use crate::audit::{self, EventKind};
use crate::elf::{self, ElfError};
use crate::paging::{AddressSpace, PageTableManager};

pub const MAX_PROCESSES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Free,
    /// Loaded, not yet entered.
    Ready,
    /// Executing in ring 3.
    Running,
    /// Exited; address space still allocated until reaped.
    Zombie,
    /// Killed by a CPU exception; address space kept until reaped.
    Crashed,
}

/// Offset added to the exception vector to form a crashed process's exit
/// code (Unix shells use 128 + signal the same way).
pub const CRASH_EXIT_BASE: u64 = 128;

/// A CPU exception raised by user code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserFault {
    pub vector: u8,
    /// Hardware error code (0 for exceptions without one).
    pub error_code: u64,
    /// Faulting instruction.
    pub rip: u64,
    /// Faulting address (`CR2`) for page faults, otherwise 0.
    pub addr: u64,
}

impl UserFault {
    /// Mnemonic and description of the exception vector.
    pub fn name(&self) -> &'static str {
        match self.vector {
            0 => "#DE divide error",
            1 => "#DB debug",
            3 => "#BP breakpoint",
            4 => "#OF overflow",
            5 => "#BR bound range exceeded",
            6 => "#UD invalid opcode",
            7 => "#NM device not available",
            11 => "#NP segment not present",
            12 => "#SS stack-segment fault",
            13 => "#GP general protection",
            14 => "#PF page fault",
            16 => "#MF x87 floating-point",
            17 => "#AC alignment check",
            19 => "#XM SIMD floating-point",
            _ => "CPU exception",
        }
    }

    pub fn exit_code(&self) -> u64 {
        CRASH_EXIT_BASE + self.vector as u64
    }
}

/// How a process left ring 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// Called `SYS_exit(code)`.
    Exited(u64),
    /// Killed by a CPU exception.
    Crashed(UserFault),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub state: ProcessState,
    pub exit_code: u64,
    pub entry: u64,
    pub stack_top: u64,
    pub pml4_phys: u64,
    /// Set when the process is `Crashed`.
    pub fault: Option<UserFault>,
    /// Program name (ramdisk file or built-in program).
    pub name: ProcName,
}

/// Fixed-size, `Copy` process name (truncated to [`ProcName::CAPACITY`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcName {
    bytes: [u8; ProcName::CAPACITY],
    len: u8,
}

impl ProcName {
    pub const CAPACITY: usize = 24;

    pub const fn empty() -> Self {
        Self {
            bytes: [0; Self::CAPACITY],
            len: 0,
        }
    }

    pub fn new(name: &str) -> Self {
        let mut out = Self::empty();
        for ch in name.chars() {
            let mut buf = [0u8; 4];
            let enc = ch.encode_utf8(&mut buf).as_bytes();
            let at = out.len as usize;
            if at + enc.len() > Self::CAPACITY {
                break;
            }
            out.bytes[at..at + enc.len()].copy_from_slice(enc);
            out.len += enc.len() as u8;
        }
        out
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("?")
    }
}

impl Process {
    const fn free_slot() -> Self {
        Self {
            pid: 0,
            state: ProcessState::Free,
            exit_code: 0,
            entry: 0,
            stack_top: 0,
            pml4_phys: 0,
            fault: None,
            name: ProcName::empty(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessError {
    Full,
    NotFound,
    /// The process is not in a state that allows the operation.
    BadState(ProcessState),
    /// Another process is already running on this CPU.
    Busy,
    Elf(ElfError),
    Enter(&'static str),
}

struct ProcessTable {
    slots: [Process; MAX_PROCESSES],
    current: Option<u32>,
}

impl ProcessTable {
    const fn new() -> Self {
        Self {
            slots: [Process::free_slot(); MAX_PROCESSES],
            current: None,
        }
    }

    fn find(&self, pid: u32) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.state != ProcessState::Free && s.pid == pid)
    }

    fn insert(
        &mut self,
        pid: u32,
        entry: u64,
        stack_top: u64,
        pml4_phys: u64,
    ) -> Result<Process, ProcessError> {
        let idx = self
            .slots
            .iter()
            .position(|s| s.state == ProcessState::Free)
            .ok_or(ProcessError::Full)?;
        self.slots[idx] = Process {
            pid,
            state: ProcessState::Ready,
            exit_code: 0,
            entry,
            stack_top,
            pml4_phys,
            fault: None,
            name: ProcName::empty(),
        };
        Ok(self.slots[idx])
    }

    /// `Ready` → `Running` and make it current.
    fn start(&mut self, pid: u32) -> Result<Process, ProcessError> {
        if self.current.is_some() {
            return Err(ProcessError::Busy);
        }
        let idx = self.find(pid).ok_or(ProcessError::NotFound)?;
        let p = &mut self.slots[idx];
        if p.state != ProcessState::Ready {
            return Err(ProcessError::BadState(p.state));
        }
        p.state = ProcessState::Running;
        self.current = Some(pid);
        Ok(*p)
    }

    /// Current process → `Zombie` with `code`; clears `current`.
    /// Returns the pid that exited.
    fn exit_current(&mut self, code: u64) -> Option<u32> {
        let pid = self.current.take()?;
        if let Some(idx) = self.find(pid) {
            self.slots[idx].state = ProcessState::Zombie;
            self.slots[idx].exit_code = code;
        }
        Some(pid)
    }

    fn set_name(&mut self, pid: u32, name: ProcName) {
        if let Some(idx) = self.find(pid) {
            self.slots[idx].name = name;
        }
    }

    /// Current process → `Crashed` with `fault`; clears `current`.
    /// Returns the pid that crashed.
    fn crash_current(&mut self, fault: UserFault) -> Option<u32> {
        let pid = self.current.take()?;
        if let Some(idx) = self.find(pid) {
            let p = &mut self.slots[idx];
            p.state = ProcessState::Crashed;
            p.exit_code = fault.exit_code();
            p.fault = Some(fault);
        }
        Some(pid)
    }

    fn status(&self, pid: u32) -> Option<ExitStatus> {
        let p = &self.slots[self.find(pid)?];
        match (p.state, p.fault) {
            (ProcessState::Crashed, Some(f)) => Some(ExitStatus::Crashed(f)),
            (ProcessState::Zombie, _) => Some(ExitStatus::Exited(p.exit_code)),
            _ => None,
        }
    }

    /// Remove a `Ready`, `Zombie`, or `Crashed` process, returning it so the caller can
    /// free its address space.
    fn take_for_reap(&mut self, pid: u32) -> Result<Process, ProcessError> {
        let idx = self.find(pid).ok_or(ProcessError::NotFound)?;
        let p = self.slots[idx];
        match p.state {
            ProcessState::Ready | ProcessState::Zombie | ProcessState::Crashed => {
                self.slots[idx] = Process::free_slot();
                Ok(p)
            }
            other => Err(ProcessError::BadState(other)),
        }
    }
}

static TABLE: Mutex<ProcessTable> = Mutex::new(ProcessTable::new());
static NEXT_PID: AtomicU32 = AtomicU32::new(1);

/// Load a built-in test program into a new address space and record it `Ready`.
pub fn spawn_smoke_elf(
    kernel_pt: &PageTableManager,
    fa: &mut FrameAllocator,
    program: elf::SmokeProgram,
) -> Result<Process, ProcessError> {
    let loaded = elf::load_smoke(kernel_pt, fa, program).map_err(ProcessError::Elf)?;
    register(loaded, program.name(), fa)
}

/// Load an ELF `image` (e.g. from the boot ramdisk) as process `name` and
/// record it `Ready`. Returns the process and the image's SHA-256, which is
/// also written to the audit log (`program-loaded`) for provenance.
pub fn spawn_image(
    kernel_pt: &PageTableManager,
    fa: &mut FrameAllocator,
    name: &str,
    image: &[u8],
) -> Result<(Process, [u8; 32]), ProcessError> {
    use sha2::{Digest, Sha256};
    let hash: [u8; 32] = Sha256::digest(image).into();
    let loaded = elf::load_image(kernel_pt, fa, image).map_err(ProcessError::Elf)?;
    let proc = register(loaded, name, fa)?;
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&hash[..8]);
    audit::record_fmt(
        EventKind::ProgramLoaded,
        format_args!("pid-{}:{}", proc.pid, name),
        u64::from_be_bytes(prefix),
    );
    Ok((proc, hash))
}

/// Record a loaded address space as a new `Ready` process.
fn register(
    (aspace, entry, stack_top): (AddressSpace, u64, u64),
    name: &str,
    fa: &mut FrameAllocator,
) -> Result<Process, ProcessError> {
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let inserted = {
        let mut table = TABLE.lock();
        table
            .insert(pid, entry, stack_top, aspace.pml4_phys())
            .map(|mut proc| {
                let name = ProcName::new(name);
                table.set_name(pid, name);
                proc.name = name;
                proc
            })
    };
    match inserted {
        Ok(proc) => {
            audit::record_fmt(
                EventKind::ProcessSpawned,
                format_args!("pid-{}", pid),
                entry,
            );
            Ok(proc)
        }
        Err(e) => {
            aspace.destroy(fa);
            Err(e)
        }
    }
}

/// Run a `Ready` process in ring 3 until it exits or crashes.
///
/// The process stays in the table (`Zombie` or `Crashed`) until [`reap`]ed.
pub fn enter(pid: u32) -> Result<ExitStatus, ProcessError> {
    let proc = TABLE.lock().start(pid)?;
    audit::record_fmt(EventKind::ProcessStarted, format_args!("pid-{}", pid), 0);
    // TABLE must not be held here: SYS_exit takes it from the syscall path.
    match crate::syscall::run_user(proc.entry, proc.stack_top, proc.pml4_phys) {
        Ok(code) => Ok(TABLE.lock().status(pid).unwrap_or(ExitStatus::Exited(code))),
        Err(e) => {
            // Never reached ring 3: put it back so it can be retried or reaped.
            let mut t = TABLE.lock();
            t.current = None;
            if let Some(idx) = t.find(pid) {
                t.slots[idx].state = ProcessState::Ready;
            }
            Err(ProcessError::Enter(e))
        }
    }
}

pub fn current_pid() -> Option<u32> {
    TABLE.lock().current
}

/// Called from `SYS_exit`: mark the current process `Zombie`.
pub fn mark_exit(code: u64) {
    let exited = TABLE.lock().exit_current(code);
    if let Some(pid) = exited {
        audit::record_fmt(EventKind::ProcessExited, format_args!("pid-{}", pid), code);
    }
}

/// Called from a CPU exception handler for a fault raised in ring 3: mark the
/// current process `Crashed` and record it in the audit log.
pub fn mark_crashed(fault: UserFault) {
    let crashed = TABLE.lock().crash_current(fault);
    if let Some(pid) = crashed {
        audit::record_fmt(
            EventKind::ProcessCrashed,
            format_args!("pid-{}", pid),
            fault.vector as u64,
        );
    }
}

/// Free a `Ready`, `Zombie`, or `Crashed` process's address space and slot.
///
/// Returns `(exit_code, frames_freed)`.
pub fn reap(pid: u32, fa: &mut FrameAllocator) -> Result<(u64, usize), ProcessError> {
    let p = TABLE.lock().take_for_reap(pid)?;
    let freed = AddressSpace::from_pml4_phys(p.pml4_phys).destroy(fa);
    audit::record_fmt(
        EventKind::ProcessReaped,
        format_args!("pid-{}", pid),
        freed as u64,
    );
    Ok((p.exit_code, freed))
}

pub fn for_each(mut f: impl FnMut(&Process)) {
    let t = TABLE.lock();
    for p in t.slots.iter() {
        if p.state != ProcessState::Free {
            f(p);
        }
    }
}

pub fn list() -> Vec<Process, MAX_PROCESSES> {
    let mut out = Vec::new();
    for_each(|p| {
        let _ = out.push(*p);
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_ready_running_zombie_reaped() {
        let mut t = ProcessTable::new();
        t.insert(7, 0x1000, 0x2000, 0x3000).unwrap();
        assert_eq!(t.slots[0].state, ProcessState::Ready);
        assert_eq!(t.current, None);

        t.start(7).unwrap();
        assert_eq!(t.slots[0].state, ProcessState::Running);
        assert_eq!(t.current, Some(7));

        t.exit_current(19);
        assert_eq!(t.slots[0].state, ProcessState::Zombie);
        assert_eq!(t.slots[0].exit_code, 19);
        assert_eq!(t.current, None);

        let p = t.take_for_reap(7).unwrap();
        assert_eq!((p.exit_code, p.pml4_phys), (19, 0x3000));
        assert_eq!(t.find(7), None);
    }

    #[test]
    fn cannot_start_twice_or_while_busy() {
        let mut t = ProcessTable::new();
        t.insert(1, 0, 0, 0).unwrap();
        t.insert(2, 0, 0, 0).unwrap();
        t.start(1).unwrap();
        assert_eq!(t.start(2), Err(ProcessError::Busy));
        t.exit_current(0);
        assert_eq!(
            t.start(1),
            Err(ProcessError::BadState(ProcessState::Zombie))
        );
        t.start(2).unwrap();
    }

    #[test]
    fn running_process_cannot_be_reaped() {
        let mut t = ProcessTable::new();
        t.insert(3, 0, 0, 0).unwrap();
        t.start(3).unwrap();
        assert_eq!(
            t.take_for_reap(3),
            Err(ProcessError::BadState(ProcessState::Running))
        );
    }

    #[test]
    fn ready_process_can_be_reaped_and_slot_reused() {
        let mut t = ProcessTable::new();
        for pid in 0..MAX_PROCESSES as u32 {
            t.insert(pid + 1, 0, 0, 0).unwrap();
        }
        assert_eq!(t.insert(99, 0, 0, 0), Err(ProcessError::Full));
        t.take_for_reap(1).unwrap();
        t.insert(99, 0, 0, 0).unwrap();
    }

    #[test]
    fn crash_marks_process_and_is_reapable() {
        let mut t = ProcessTable::new();
        t.insert(5, 0, 0, 0x5000).unwrap();
        t.start(5).unwrap();
        let fault = UserFault {
            vector: 14,
            error_code: 4,
            rip: 0x8000400000,
            addr: 0,
        };
        assert_eq!(t.crash_current(fault), Some(5));
        assert_eq!(t.current, None);
        assert_eq!(t.slots[0].state, ProcessState::Crashed);
        assert_eq!(t.slots[0].exit_code, 142);
        assert_eq!(t.status(5), Some(ExitStatus::Crashed(fault)));
        assert_eq!(
            t.start(5),
            Err(ProcessError::BadState(ProcessState::Crashed))
        );
        let p = t.take_for_reap(5).unwrap();
        assert_eq!(p.fault, Some(fault));
    }

    #[test]
    fn exit_status_reports_normal_exit() {
        let mut t = ProcessTable::new();
        t.insert(6, 0, 0, 0).unwrap();
        t.start(6).unwrap();
        t.exit_current(19);
        assert_eq!(t.status(6), Some(ExitStatus::Exited(19)));
    }

    #[test]
    fn fault_names_cover_common_vectors() {
        let f = |vector| UserFault {
            vector,
            error_code: 0,
            rip: 0,
            addr: 0,
        };
        assert_eq!(f(0).name(), "#DE divide error");
        assert_eq!(f(6).name(), "#UD invalid opcode");
        assert_eq!(f(13).name(), "#GP general protection");
        assert_eq!(f(14).name(), "#PF page fault");
        assert_eq!(f(0).exit_code(), 128);
    }

    #[test]
    fn names_are_kept_and_truncated() {
        let mut t = ProcessTable::new();
        t.insert(9, 0, 0, 0).unwrap();
        t.set_name(9, ProcName::new("hello"));
        assert_eq!(t.slots[0].name.as_str(), "hello");
        let long = ProcName::new("a-very-long-program-name-over-24");
        assert_eq!(long.as_str().len(), ProcName::CAPACITY);
        assert_eq!(ProcName::new("héllo").as_str(), "héllo");
    }

    #[test]
    fn exit_without_current_is_noop() {
        let mut t = ProcessTable::new();
        t.insert(4, 0, 0, 0).unwrap();
        t.exit_current(42);
        assert_eq!(t.slots[0].state, ProcessState::Ready);
    }

    #[test]
    fn reap_missing_pid_fails() {
        let mut t = ProcessTable::new();
        assert_eq!(t.take_for_reap(0xFFFF_FFFE), Err(ProcessError::NotFound));
    }
}
