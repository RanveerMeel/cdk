//! Minimal process table for ring-3 ELF tasks.
//!
//! Lifecycle: [`spawn_smoke_elf`] loads a program and records it `Ready`;
//! [`enter`] runs it in ring 3 (`Running`) until `SYS_exit` marks it
//! `Zombie` and control returns to the caller; [`reap`] frees its address
//! space and slot. Console `elf-spawn` / `elf-run` / `ps` / `reap` drive this.

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub state: ProcessState,
    pub exit_code: u64,
    pub entry: u64,
    pub stack_top: u64,
    pub pml4_phys: u64,
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

    /// Remove a `Ready` or `Zombie` process, returning it so the caller can
    /// free its address space.
    fn take_for_reap(&mut self, pid: u32) -> Result<Process, ProcessError> {
        let idx = self.find(pid).ok_or(ProcessError::NotFound)?;
        let p = self.slots[idx];
        match p.state {
            ProcessState::Ready | ProcessState::Zombie => {
                self.slots[idx] = Process::free_slot();
                Ok(p)
            }
            other => Err(ProcessError::BadState(other)),
        }
    }
}

static TABLE: Mutex<ProcessTable> = Mutex::new(ProcessTable::new());
static NEXT_PID: AtomicU32 = AtomicU32::new(1);

/// Load the built-in smoke ELF into a new address space and record it `Ready`.
pub fn spawn_smoke_elf(
    kernel_pt: &PageTableManager,
    fa: &mut FrameAllocator,
) -> Result<Process, ProcessError> {
    let (aspace, entry, stack_top) = elf::load_smoke(kernel_pt, fa).map_err(ProcessError::Elf)?;
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let inserted = TABLE
        .lock()
        .insert(pid, entry, stack_top, aspace.pml4_phys());
    match inserted {
        Ok(_) => audit::record_fmt(EventKind::ProcessSpawned, format_args!("pid-{}", pid), entry),
        Err(_) => {
            aspace.destroy(fa);
        }
    }
    inserted
}

/// Run a `Ready` process in ring 3 until it exits; returns its exit code.
///
/// The process stays in the table as a `Zombie` until [`reap`]ed.
pub fn enter(pid: u32) -> Result<u64, ProcessError> {
    let proc = TABLE.lock().start(pid)?;
    audit::record_fmt(EventKind::ProcessStarted, format_args!("pid-{}", pid), 0);
    // TABLE must not be held here: SYS_exit takes it from the syscall path.
    match crate::syscall::run_user(proc.entry, proc.stack_top, proc.pml4_phys) {
        Ok(code) => Ok(code),
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

/// Free a `Ready` or `Zombie` process's address space and slot.
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
