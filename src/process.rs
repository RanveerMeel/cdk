//! Minimal process table for ring-3 ELF tasks.
//!
//! Tracks pid, address-space root, entry/stack, and Running/Zombie state.
//! `SYS_exit` marks the current process Zombie; console `ps` / `reap` inspect it.

use core::sync::atomic::{AtomicU32, Ordering};
use heapless::Vec;
use spin::Mutex;

use crate::allocator::FrameAllocator;
use crate::elf::{self, ElfError};
use crate::paging::PageTableManager;

pub const MAX_PROCESSES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Free,
    Running,
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
}

static TABLE: Mutex<ProcessTable> = Mutex::new(ProcessTable::new());
static NEXT_PID: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessError {
    Full,
    NotFound,
    Elf(ElfError),
    NoSelectors,
    NoKernelStack,
}

/// Spawn the built-in smoke ELF into a new address space and record a Running process.
pub fn spawn_smoke_elf(
    kernel_pt: &PageTableManager,
    fa: &mut FrameAllocator,
) -> Result<Process, ProcessError> {
    let (aspace, entry, stack_top) =
        elf::load_smoke(kernel_pt, fa).map_err(ProcessError::Elf)?;
    let pml4 = aspace.pml4_phys();
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);

    let mut t = TABLE.lock();
    let idx = t
        .slots
        .iter()
        .position(|s| s.state == ProcessState::Free)
        .ok_or(ProcessError::Full)?;
    t.slots[idx] = Process {
        pid,
        state: ProcessState::Running,
        exit_code: 0,
        entry,
        stack_top,
        pml4_phys: pml4,
    };
    t.current = Some(pid);
    let proc = t.slots[idx];
    drop(t);

    // Activate user address space before returning so caller can enter_user.
    aspace.activate();
    Ok(proc)
}

pub fn current_pid() -> Option<u32> {
    TABLE.lock().current
}

pub fn mark_exit(code: u64) {
    let mut t = TABLE.lock();
    let Some(pid) = t.current else {
        return;
    };
    if let Some(p) = t.slots.iter_mut().find(|s| s.pid == pid) {
        p.state = ProcessState::Zombie;
        p.exit_code = code;
    }
}

pub fn reap(pid: u32) -> Result<u64, ProcessError> {
    let mut t = TABLE.lock();
    let idx = t
        .slots
        .iter()
        .position(|s| s.pid == pid && s.state == ProcessState::Zombie)
        .ok_or(ProcessError::NotFound)?;
    let code = t.slots[idx].exit_code;
    if t.current == Some(pid) {
        t.current = None;
    }
    t.slots[idx] = Process::free_slot();
    Ok(code)
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

/// Enter ring-3 for `proc` (does not return on success).
pub fn enter(proc: &Process) -> Result<(), ProcessError> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = proc;
        crate::println!(
            "process: host stub enter pid={} entry={:#x}",
            proc.pid,
            proc.entry
        );
        mark_exit(0);
        return Ok(());
    }
    #[cfg(target_os = "none")]
    {
        let Some((_, ucode, udata)) = crate::gdt::star_selectors() else {
            return Err(ProcessError::NoSelectors);
        };
        let kstack = crate::gdt::kernel_stack_top(0).ok_or(ProcessError::NoKernelStack)?;
        crate::gdt::set_rsp0(0, kstack);
        crate::percpu::set_kernel_rsp(0, kstack);
        crate::percpu::prepare_user_gs(0);
        // Ensure CR3 is the process PML4.
        unsafe {
            core::arch::asm!(
                "mov cr3, {}",
                in(reg) proc.pml4_phys,
                options(nostack, preserves_flags)
            );
        }
        crate::println!(
            "process: enter pid={} rip={:#x} rsp={:#x} cr3={:#x}",
            proc.pid,
            proc.entry,
            proc.stack_top,
            proc.pml4_phys
        );
        unsafe {
            crate::syscall::enter_user_public(
                proc.entry,
                proc.stack_top,
                ucode.0 as u64,
                udata.0 as u64,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reap_missing_pid_fails() {
        assert_eq!(reap(0xFFFF_FFFE), Err(ProcessError::NotFound));
    }

    #[test]
    fn mark_exit_without_current_is_noop() {
        let before = list().len();
        mark_exit(42);
        assert_eq!(list().len(), before);
    }
}
