//! Minimal process table for ring-3 ELF tasks.
//!
//! Lifecycle: [`spawn_smoke_elf`] / [`spawn_image`] load a program and record
//! it `Ready`; [`run_scheduled`] runs the selected processes in ring 3 until
//! each exits (`Zombie`), faults (`Crashed`), or exhausts its CPU budget
//! (`Killed`); [`reap`] frees its address space and slot.
//!
//! ## Preemptive scheduling (roadmap 2.3)
//!
//! Every process carries a saved [`TrapFrame`]. When a timer interrupt
//! arrives while a process is in ring 3, [`on_user_tick`] charges it one
//! tick; after [`slice_ticks`] it saves the interrupted frame, loads the next
//! runnable process's frame and page tables, and the interrupt returns into
//! that process (round-robin). Switching happens only at ring-3 interrupt
//! boundaries — syscalls run with interrupts disabled — so one kernel stack
//! per CPU suffices. A process that exceeds [`budget_ticks`] is killed.
//!
//! ## Agents on every CPU (roadmap 2.7)
//!
//! Each CPU (topology slot) has its own current process, time slice and
//! round-robin cursor. [`run_scheduled`] gives every selected process a home
//! CPU, spreading them over the agent CPUs (the application processors);
//! each AP runs its own queue first and takes queued work from other CPUs
//! when it has none ([`run_on_this_cpu`]). A process runs on one CPU at a
//! time. The console's CPU supervises — human approvals, tool results — and
//! runs agents itself only when there are no APs. Syscalls lock the kernel
//! themselves ([`crate::kernel::lock_global`]).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use heapless::Vec;
use spin::Mutex;

use crate::allocator::FrameAllocator;
use crate::percpu::MAX_CPUS;
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
    /// Killed by the kernel for exceeding its CPU budget.
    Killed,
    /// Waiting in a syscall (e.g. for human approval); resumes when
    /// [`unblock`] delivers the result.
    Blocked,
}

/// Saved ring-3 register state. The layout matches the timer entry stubs:
/// general-purpose registers in reverse push order, then the CPU's interrupt
/// frame (`rip, cs, rflags, rsp, ss`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrame {
    /// Size in bytes (15 GPRs + 5-word interrupt frame).
    pub const SIZE: usize = 20 * 8;

    /// Initial frame for a new process: all registers zero, interrupts on.
    /// `cs`/`ss` are filled in with the user selectors at dispatch.
    pub const fn user_entry(rip: u64, rsp: u64) -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rbp: 0,
            rdi: 0,
            rsi: 0,
            rdx: 0,
            rcx: 0,
            rbx: 0,
            rax: 0,
            rip,
            cs: 0,
            rflags: 0x202,
            rsp,
            ss: 0,
        }
    }

    /// Whether the interrupted code ran in ring 3.
    pub fn from_user(&self) -> bool {
        self.cs & 3 == 3
    }
}

/// Which `Ready` processes [`run_scheduled`] should run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Select {
    One(u32),
    AllReady,
}

/// What the timer path should do after charging a tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TickAction {
    /// Keep running the current process.
    Continue,
    /// The frame now holds another process; load this page-table root.
    Switch { pml4_phys: u64 },
    /// The current process exceeded its budget and has been marked `Killed`.
    Kill { pid: u32, ticks: u64 },
}

// Ticks are timer interrupts landing while a process is in ring 3. On the
// BSP that is the local APIC timer, calibrated to 20 Hz (50 ms per tick).
static SLICE_TICKS: AtomicU64 = AtomicU64::new(2); // ~100 ms
static BUDGET_TICKS: AtomicU64 = AtomicU64::new(200); // ~10 s

/// Timer ticks a process runs before another runnable one gets the CPU.
pub fn slice_ticks() -> u64 {
    SLICE_TICKS.load(Ordering::Relaxed)
}

/// Total timer ticks a process may run before it is killed.
pub fn budget_ticks() -> u64 {
    BUDGET_TICKS.load(Ordering::Relaxed)
}

pub fn set_budget_ticks(ticks: u64) {
    BUDGET_TICKS.store(ticks.max(1), Ordering::Relaxed);
}

pub fn set_slice_ticks(ticks: u64) {
    SLICE_TICKS.store(ticks.max(1), Ordering::Relaxed);
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
    /// User stack pointer at the fault.
    pub rsp: u64,
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
    /// Killed for exceeding its CPU budget after this many ticks.
    Killed { ticks: u64 },
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
    /// Saved user registers (valid while not `Running`).
    pub frame: TrapFrame,
    /// Timer ticks spent in ring 3.
    pub ticks_used: u64,
    /// Times the process was preempted.
    pub switches: u32,
    /// Selected by the current [`run_scheduled`] call.
    pub scheduled: bool,
    /// Has entered ring 3 at least once.
    pub started: bool,
    /// CPU (topology slot) whose queue the process is on.
    pub home: u8,
    /// CPUs it has run on (bit = topology slot).
    pub cpus: u64,
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
            frame: TrapFrame::user_entry(0, 0),
            ticks_used: 0,
            switches: 0,
            scheduled: false,
            started: false,
            home: 0,
            cpus: 0,
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
    /// Boot verification failed (roadmap 4.2): nothing may run.
    Lockdown,
}

struct ProcessTable {
    slots: [Process; MAX_PROCESSES],
    /// Process running on each CPU (topology slot).
    current: [Option<u32>; MAX_CPUS],
    /// Ticks each CPU's current process has run since it was dispatched.
    slice_used: [u64; MAX_CPUS],
    /// Slot index each CPU dispatched most recently (round-robin cursor).
    cursor: [usize; MAX_CPUS],
}

impl ProcessTable {
    const fn new() -> Self {
        Self {
            slots: [Process::free_slot(); MAX_PROCESSES],
            current: [None; MAX_CPUS],
            slice_used: [0; MAX_CPUS],
            cursor: [MAX_PROCESSES - 1; MAX_CPUS],
        }
    }

    fn busy(&self) -> bool {
        self.current.iter().any(Option::is_some)
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
            frame: TrapFrame::user_entry(entry, stack_top),
            ticks_used: 0,
            switches: 0,
            scheduled: false,
            started: false,
            home: 0,
            cpus: 0,
        };
        Ok(self.slots[idx])
    }

    /// Mark which `Ready` processes the next run may schedule, spreading
    /// them over `homes` (the agent CPUs) round-robin. Returns the selected
    /// pids.
    fn select(
        &mut self,
        which: Select,
        homes: &[usize],
    ) -> Result<Vec<u32, MAX_PROCESSES>, ProcessError> {
        if self.busy() {
            return Err(ProcessError::Busy);
        }
        if let Select::One(pid) = which {
            let idx = self.find(pid).ok_or(ProcessError::NotFound)?;
            if self.slots[idx].state != ProcessState::Ready {
                return Err(ProcessError::BadState(self.slots[idx].state));
            }
        }
        let mut picked = Vec::new();
        for p in self.slots.iter_mut() {
            p.scheduled = p.state == ProcessState::Ready
                && match which {
                    Select::One(pid) => p.pid == pid,
                    Select::AllReady => true,
                };
            if p.scheduled {
                if !homes.is_empty() {
                    p.home = homes[picked.len() % homes.len()] as u8;
                }
                let _ = picked.push(p.pid);
            }
        }
        Ok(picked)
    }

    /// Next scheduled `Ready` slot for `cpu`: its own queue first
    /// (round-robin after its cursor), else any other CPU's.
    fn next_runnable(&self, cpu: usize) -> Option<usize> {
        let runnable = |i: &usize| {
            self.slots[*i].scheduled && self.slots[*i].state == ProcessState::Ready
        };
        let order = || (1..=MAX_PROCESSES).map(|k| (self.cursor[cpu] + k) % MAX_PROCESSES);
        order()
            .filter(runnable)
            .find(|&i| self.slots[i].home as usize == cpu)
            .or_else(|| order().find(runnable))
    }

    /// Make the next runnable process current and `Running` on `cpu`.
    fn dispatch_next(&mut self, cpu: usize) -> Option<Process> {
        if self.current[cpu].is_some() {
            return None;
        }
        let idx = self.next_runnable(cpu)?;
        self.run_slot(cpu, idx);
        Some(self.slots[idx])
    }

    fn run_slot(&mut self, cpu: usize, idx: usize) {
        let p = &mut self.slots[idx];
        p.state = ProcessState::Running;
        p.home = cpu as u8; // a process taken from another queue moves here
        p.cpus |= 1 << cpu;
        self.current[cpu] = Some(p.pid);
        self.cursor[cpu] = idx;
        self.slice_used[cpu] = 0;
    }

    /// Scheduled processes still to run (`Ready` or `Running`) and those
    /// `Blocked`.
    fn outstanding(&self) -> (usize, Vec<u32, MAX_PROCESSES>) {
        let active = self
            .slots
            .iter()
            .filter(|p| {
                p.scheduled && matches!(p.state, ProcessState::Ready | ProcessState::Running)
            })
            .count();
        (active, self.blocked_scheduled())
    }

    /// Charge the current process one tick of ring-3 time; preempt or kill
    /// it as the policy requires. On `Switch`, `frame` has been saved into
    /// the old process and replaced with the new one's.
    fn tick(&mut self, cpu: usize, frame: &mut TrapFrame, slice: u64, budget: u64) -> TickAction {
        let Some(pid) = self.current[cpu] else {
            return TickAction::Continue;
        };
        let Some(idx) = self.find(pid) else {
            return TickAction::Continue;
        };
        self.slots[idx].ticks_used += 1;
        self.slice_used[cpu] += 1;
        let used = self.slots[idx].ticks_used;
        if used > budget {
            return TickAction::Kill { pid, ticks: used };
        }
        if self.slice_used[cpu] < slice {
            return TickAction::Continue;
        }
        self.slice_used[cpu] = 0;
        // Round-robin from the current slot; staying put if nobody else is runnable.
        let Some(next) = self.next_runnable(cpu) else {
            return TickAction::Continue;
        };
        let old = &mut self.slots[idx];
        old.frame = *frame;
        old.state = ProcessState::Ready;
        old.switches += 1;
        let (user_cs, user_ss) = (frame.cs, frame.ss);
        self.current[cpu] = None;
        self.run_slot(cpu, next);
        let new = &self.slots[next];
        *frame = new.frame;
        // A process that has never run has no selectors yet (they are
        // filled in at first dispatch); `iretq` with a null CS faults. All
        // processes share the ring-3 selectors, so take the interrupted
        // process's.
        if frame.cs == 0 {
            frame.cs = user_cs;
            frame.ss = user_ss;
        }
        frame.rflags |= 0x200;
        TickAction::Switch {
            pml4_phys: new.pml4_phys,
        }
    }

    /// Current process → `Blocked` with its registers saved; clears `current`.
    fn block_current(&mut self, cpu: usize, frame: &TrapFrame) -> Option<u32> {
        let pid = self.current[cpu].take()?;
        if let Some(idx) = self.find(pid) {
            let p = &mut self.slots[idx];
            p.frame = *frame;
            p.state = ProcessState::Blocked;
        }
        Some(pid)
    }

    /// `Blocked` → `Ready`, with `result` returned from its syscall.
    fn unblock(&mut self, pid: u32, result: u64) -> bool {
        match self.find(pid) {
            Some(idx) if self.slots[idx].state == ProcessState::Blocked => {
                let p = &mut self.slots[idx];
                p.frame.rax = result;
                p.state = ProcessState::Ready;
                true
            }
            _ => false,
        }
    }

    fn blocked_scheduled(&self) -> Vec<u32, MAX_PROCESSES> {
        let mut out = Vec::new();
        for p in self.slots.iter() {
            if p.scheduled && p.state == ProcessState::Blocked {
                let _ = out.push(p.pid);
            }
        }
        out
    }

    /// Current process → `Killed`; clears `current`.
    fn kill_current(&mut self, cpu: usize) -> Option<u32> {
        let pid = self.current[cpu].take()?;
        if let Some(idx) = self.find(pid) {
            let p = &mut self.slots[idx];
            p.state = ProcessState::Killed;
            p.scheduled = false;
        }
        Some(pid)
    }

    /// Test helper: select and dispatch exactly `pid`.
    #[cfg(test)]
    fn start(&mut self, pid: u32) -> Result<Process, ProcessError> {
        self.select(Select::One(pid), &[0])?;
        self.dispatch_next(0).ok_or(ProcessError::NotFound)
    }

    /// Current process → `Zombie` with `code`; clears `current`.
    /// Returns the pid that exited.
    fn exit_current(&mut self, cpu: usize, code: u64) -> Option<u32> {
        let pid = self.current[cpu].take()?;
        if let Some(idx) = self.find(pid) {
            self.slots[idx].state = ProcessState::Zombie;
            self.slots[idx].exit_code = code;
            self.slots[idx].scheduled = false;
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
    fn crash_current(&mut self, cpu: usize, fault: UserFault) -> Option<u32> {
        let pid = self.current[cpu].take()?;
        if let Some(idx) = self.find(pid) {
            let p = &mut self.slots[idx];
            p.state = ProcessState::Crashed;
            p.exit_code = fault.exit_code();
            p.fault = Some(fault);
            p.scheduled = false;
        }
        Some(pid)
    }

    fn status(&self, pid: u32) -> Option<ExitStatus> {
        let p = &self.slots[self.find(pid)?];
        match (p.state, p.fault) {
            (ProcessState::Crashed, Some(f)) => Some(ExitStatus::Crashed(f)),
            (ProcessState::Zombie, _) => Some(ExitStatus::Exited(p.exit_code)),
            (ProcessState::Killed, _) => Some(ExitStatus::Killed {
                ticks: p.ticks_used,
            }),
            _ => None,
        }
    }

    /// Remove a `Ready`, `Zombie`, or `Crashed` process, returning it so the caller can
    /// free its address space.
    fn take_for_reap(&mut self, pid: u32) -> Result<Process, ProcessError> {
        let idx = self.find(pid).ok_or(ProcessError::NotFound)?;
        let p = self.slots[idx];
        match p.state {
            ProcessState::Ready
            | ProcessState::Zombie
            | ProcessState::Crashed
            | ProcessState::Killed => {
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
    if crate::boot::lockdown() {
        aspace.destroy(fa);
        return Err(ProcessError::Lockdown);
    }
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
            let _ = crate::agent::create_table(pid);
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

/// Run one `Ready` process until it exits, crashes, or is killed.
///
/// The process stays in the table until [`reap`]ed.
pub fn enter(pid: u32) -> Result<ExitStatus, ProcessError> {
    let results = run_scheduled(Select::One(pid))?;
    results
        .iter()
        .find(|(p, _)| *p == pid)
        .map(|(_, s)| *s)
        .ok_or(ProcessError::NotFound)
}

/// Topology slot of the executing CPU (0 on the host).
pub fn this_cpu() -> usize {
    crate::percpu::slot_for_apic(crate::percpu::current_apic_id())
        .unwrap_or(0)
        .min(MAX_CPUS - 1)
}

/// APs ready to run agents (bit = topology slot): they have their own
/// stacks, TSS, IDT and SYSCALL MSRs.
static AGENT_CPUS: AtomicU64 = AtomicU64::new(0);

/// Called by an AP once it can run agents.
pub fn enable_agent_cpu(slot: usize) {
    if slot > 0 && slot < MAX_CPUS {
        AGENT_CPUS.fetch_or(1 << slot, Ordering::AcqRel);
    }
}

/// CPUs agents run on: the APs, or just this CPU if there are none.
fn agent_cpus() -> Vec<usize, MAX_CPUS> {
    let mask = AGENT_CPUS.load(Ordering::Acquire);
    let mut out = Vec::new();
    for slot in 0..MAX_CPUS {
        if mask & (1 << slot) != 0 {
            let _ = out.push(slot);
        }
    }
    if out.is_empty() {
        let _ = out.push(this_cpu());
    }
    out
}

pub fn agent_cpu_count() -> usize {
    agent_cpus().len()
}

/// CPUs process `pid` has run on (bit = topology slot).
pub fn cpus_used(pid: u32) -> Option<u64> {
    let t = TABLE.lock();
    t.find(pid).map(|i| t.slots[i].cpus)
}

/// Run the selected `Ready` processes, preemptively, until every one of
/// them has exited, crashed, or been killed. Returns each selected pid's
/// outcome.
///
/// With APs, they run the agents and this CPU supervises (approvals, tool
/// results); without, this CPU runs them itself. Returns only when the run
/// is over.
pub fn run_scheduled(which: Select) -> Result<Vec<(u32, ExitStatus), MAX_PROCESSES>, ProcessError> {
    let cpus = agent_cpus();
    let selected = TABLE.lock().select(which, &cpus)?;
    let supervise = AGENT_CPUS.load(Ordering::Acquire) != 0;
    if supervise {
        for &slot in cpus.iter() {
            if let Some(apic) = crate::percpu::apic_for_slot(slot) {
                crate::local_apic::send_reschedule_ipi(apic);
            }
        }
    }
    loop {
        // An agent that just blocked for approval returns control here;
        // ask the human right away rather than after the others finish.
        if crate::agent::has_pending() {
            crate::agent::resolve_approvals();
        }
        // Deliver any tool results that have arrived.
        if crate::tools::has_inflight() {
            crate::tools::poll();
        }
        if !supervise {
            // Bind first: the table guard must be gone before run_one.
            let next = TABLE.lock().dispatch_next(this_cpu());
            if let Some(proc) = next {
                run_one(proc)?;
                continue;
            }
        }
        let (active, blocked) = TABLE.lock().outstanding();
        if active > 0 {
            // Agents are running on the APs: wait for the next tick.
            wait_tick();
            continue;
        }
        if blocked.is_empty() {
            break;
        }
        // Nothing runnable. Processes waiting on a human get their
        // decisions now; anything still blocked afterwards has no
        // pending request and is released with an error.
        crate::agent::resolve_approvals();
        if crate::approvals::signed_mode() && crate::agent::has_pending() {
            // Agents waiting on operator signatures (roadmap 2.8).
            crate::approvals::wait_any();
            continue;
        }
        if crate::tools::has_inflight() {
            // Agents waiting on tool results: wait for one to finish.
            crate::tools::wait_progress();
            continue;
        }
        for pid in TABLE.lock().blocked_scheduled() {
            unblock(pid, crate::agent::err(crate::agent::errno::EDENIED));
        }
    }
    let t = TABLE.lock();
    let mut out = Vec::new();
    for pid in selected {
        if let Some(status) = t.status(pid) {
            let _ = out.push((pid, status));
        }
    }
    Ok(out)
}

/// Run `proc` (just dispatched on this CPU) in ring 3 until the process
/// running on this CPU — whichever that is after preemption — exits,
/// crashes, blocks, or is killed.
fn run_one(proc: Process) -> Result<(), ProcessError> {
    if !proc.started {
        {
            let mut t = TABLE.lock();
            if let Some(idx) = t.find(proc.pid) {
                t.slots[idx].started = true;
            }
        }
        audit::record_fmt(
            EventKind::ProcessStarted,
            format_args!("pid-{}", proc.pid),
            0,
        );
    }
    // TABLE must not be held here: SYS_exit, faults, and the timer path
    // all take it while the process runs.
    if let Err(e) = crate::syscall::run_frame(&proc.frame, proc.pml4_phys) {
        // Never reached ring 3: put it back so it can be retried or reaped.
        let cpu = this_cpu();
        let mut t = TABLE.lock();
        if let Some(pid) = t.current[cpu].take() {
            if let Some(idx) = t.find(pid) {
                t.slots[idx].state = ProcessState::Ready;
                t.slots[idx].scheduled = false;
            }
        }
        return Err(ProcessError::Enter(e));
    }
    Ok(())
}

/// AP side (roadmap 2.7): run this CPU's agents, then any others queued,
/// until none is runnable. Called from the AP idle loop on every wake.
pub fn run_on_this_cpu() {
    let cpu = this_cpu();
    if AGENT_CPUS.load(Ordering::Acquire) & (1 << cpu) == 0 {
        return;
    }
    loop {
        let Some(proc) = TABLE.lock().dispatch_next(cpu) else {
            return;
        };
        if let Err(e) = run_one(proc) {
            crate::println!("SMP: cpu {} could not enter pid {}: {:?}", cpu, proc.pid, e);
            return;
        }
    }
}

/// Sleep until the next interrupt (a timer tick at most ~50 ms away).
fn wait_tick() {
    #[cfg(target_os = "none")]
    unsafe {
        core::arch::asm!("sti; hlt", options(nomem, nostack, preserves_flags));
    }
    #[cfg(not(target_os = "none"))]
    core::hint::spin_loop();
}

/// Timer interrupt from ring 3: charge the current process and decide
/// whether to keep it, switch to another, or kill it. On `Switch` the new
/// process's page tables are already loaded.
pub fn on_user_tick(frame: &mut TrapFrame) -> TickAction {
    // The interrupted code was in ring 3, so no kernel lock is held on this
    // CPU; `try_lock` only guards against another CPU holding the table.
    let Some(mut t) = TABLE.try_lock() else {
        return TickAction::Continue;
    };
    let cpu = this_cpu();
    let action = t.tick(cpu, frame, slice_ticks(), budget_ticks());
    match action {
        TickAction::Switch { pml4_phys } => {
            drop(t);
            load_page_tables(pml4_phys);
        }
        TickAction::Kill { pid, ticks } => {
            t.kill_current(cpu);
            drop(t);
            audit::record_fmt(EventKind::ProcessKilled, format_args!("pid-{}", pid), ticks);
        }
        TickAction::Continue => {}
    }
    action
}

fn load_page_tables(pml4_phys: u64) {
    #[cfg(target_os = "none")]
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) pml4_phys, options(nostack, preserves_flags));
    }
    #[cfg(not(target_os = "none"))]
    let _ = pml4_phys;
}

/// Park the current process (called from the syscall path with its frame).
pub fn block_current(frame: &TrapFrame) {
    TABLE.lock().block_current(this_cpu(), frame);
}

/// Resume a `Blocked` process with `result` as its syscall return value.
pub fn unblock(pid: u32, result: u64) -> bool {
    TABLE.lock().unblock(pid, result)
}

/// Page-table root of process `pid`, if it exists.
pub fn pml4_of(pid: u32) -> Option<u64> {
    let t = TABLE.lock();
    t.find(pid).map(|i| t.slots[i].pml4_phys)
}

/// Name of process `pid`, if it exists.
pub fn name_of(pid: u32) -> Option<ProcName> {
    let t = TABLE.lock();
    t.find(pid).map(|i| t.slots[i].name)
}

/// The process running on this CPU.
pub fn current_pid() -> Option<u32> {
    TABLE.lock().current[this_cpu()]
}

/// Called from `SYS_exit`: mark the current process `Zombie`.
pub fn mark_exit(code: u64) {
    let exited = TABLE.lock().exit_current(this_cpu(), code);
    if let Some(pid) = exited {
        audit::record_fmt(EventKind::ProcessExited, format_args!("pid-{}", pid), code);
    }
}

/// Called from a CPU exception handler for a fault raised in ring 3: mark the
/// current process `Crashed` and record it in the audit log.
pub fn mark_crashed(fault: UserFault) {
    let crashed = TABLE.lock().crash_current(this_cpu(), fault);
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
    crate::agent::destroy_table(pid);
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
        assert_eq!(t.current[0], None);

        t.start(7).unwrap();
        assert_eq!(t.slots[0].state, ProcessState::Running);
        assert_eq!(t.current[0], Some(7));

        t.exit_current(0, 19);
        assert_eq!(t.slots[0].state, ProcessState::Zombie);
        assert_eq!(t.slots[0].exit_code, 19);
        assert_eq!(t.current[0], None);

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
        t.exit_current(0, 0);
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
            rsp: 0,
        };
        assert_eq!(t.crash_current(0, fault), Some(5));
        assert_eq!(t.current[0], None);
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
        t.exit_current(0, 19);
        assert_eq!(t.status(6), Some(ExitStatus::Exited(19)));
    }

    #[test]
    fn fault_names_cover_common_vectors() {
        let f = |vector| UserFault {
            vector,
            error_code: 0,
            rip: 0,
            addr: 0,
            rsp: 0,
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

    fn frame(tag: u64) -> TrapFrame {
        let mut f = TrapFrame::user_entry(0x1000 * tag, 0x2000 * tag);
        f.rax = tag;
        f.cs = 0x23;
        f.ss = 0x1b;
        f
    }

    fn table_with(n: u32) -> ProcessTable {
        let mut t = ProcessTable::new();
        for pid in 1..=n {
            t.insert(
                pid,
                0x1000 * pid as u64,
                0x2000 * pid as u64,
                0x100 * pid as u64,
            )
            .unwrap();
        }
        t
    }

    #[test]
    fn trap_frame_layout_matches_entry_stub() {
        assert_eq!(core::mem::size_of::<TrapFrame>(), TrapFrame::SIZE);
        assert_eq!(core::mem::offset_of!(TrapFrame, rax), 14 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, rip), 15 * 8);
        assert_eq!(core::mem::offset_of!(TrapFrame, ss), 19 * 8);
        assert!(frame(1).from_user());
    }

    #[test]
    fn round_robin_switches_after_a_slice() {
        let mut t = table_with(3);
        assert_eq!(t.select(Select::AllReady, &[0]).unwrap().len(), 3);
        let first = t.dispatch_next(0).unwrap();
        assert_eq!(first.pid, 1);
        assert_eq!(first.frame.rip, 0x1000);

        let mut f = frame(1);
        assert_eq!(t.tick(0, &mut f, 2, 100), TickAction::Continue);
        f.rax = 111; // process 1 made progress
        assert_eq!(
            t.tick(0, &mut f, 2, 100),
            TickAction::Switch { pml4_phys: 0x200 }
        );
        assert_eq!(t.current[0], Some(2));
        assert_eq!(f.rip, 0x2000, "frame now belongs to pid 2");
        // Regression: pid 2 never ran, so its selectors come from pid 1.
        assert_eq!((f.cs, f.ss), (0x23, frame(1).ss));
        assert_ne!(f.rflags & 0x200, 0, "interrupts stay enabled in ring 3");
        assert_eq!(t.slots[0].frame.rax, 111, "pid 1's registers were saved");
        assert_eq!(t.slots[0].state, ProcessState::Ready);
        assert_eq!(t.slots[0].switches, 1);

        t.tick(0, &mut f, 2, 100);
        assert_eq!(
            t.tick(0, &mut f, 2, 100),
            TickAction::Switch { pml4_phys: 0x300 }
        );
        t.tick(0, &mut f, 2, 100);
        // Wraps around to pid 1 with its saved registers.
        assert_eq!(
            t.tick(0, &mut f, 2, 100),
            TickAction::Switch { pml4_phys: 0x100 }
        );
        assert_eq!(f.rax, 111);
    }

    #[test]
    fn lone_process_keeps_running_and_budget_kills() {
        let mut t = table_with(1);
        t.select(Select::One(1), &[0]).unwrap();
        t.dispatch_next(0).unwrap();
        let mut f = frame(1);
        for _ in 0..5 {
            assert_eq!(t.tick(0, &mut f, 1, 5), TickAction::Continue);
        }
        assert_eq!(t.tick(0, &mut f, 1, 5), TickAction::Kill { pid: 1, ticks: 6 });
        assert_eq!(t.kill_current(0), Some(1));
        assert_eq!(t.slots[0].state, ProcessState::Killed);
        assert_eq!(t.status(1), Some(ExitStatus::Killed { ticks: 6 }));
        assert!(t.take_for_reap(1).is_ok());
    }

    #[test]
    fn select_one_leaves_others_unscheduled() {
        let mut t = table_with(2);
        t.select(Select::One(2), &[0]).unwrap();
        assert_eq!(t.dispatch_next(0).unwrap().pid, 2);
        let mut f = frame(2);
        // Slice expires but pid 1 was not selected: pid 2 keeps the CPU.
        assert_eq!(t.tick(0, &mut f, 1, 100), TickAction::Continue);
        t.exit_current(0, 0);
        assert_eq!(t.dispatch_next(0), None);
        assert_eq!(t.slots[0].state, ProcessState::Ready);
    }

    #[test]
    fn exited_process_is_not_dispatched_again() {
        let mut t = table_with(2);
        t.select(Select::AllReady, &[0]).unwrap();
        t.dispatch_next(0).unwrap();
        t.exit_current(0, 7);
        assert_eq!(t.dispatch_next(0).unwrap().pid, 2);
        t.exit_current(0, 8);
        assert_eq!(t.dispatch_next(0), None);
    }

    #[test]
    fn blocked_process_resumes_with_result() {
        let mut t = table_with(2);
        t.select(Select::AllReady, &[0]).unwrap();
        t.dispatch_next(0).unwrap();
        let mut f = frame(1);
        f.rip = 0x1234;
        assert_eq!(t.block_current(0, &f), Some(1));
        assert_eq!(t.slots[0].state, ProcessState::Blocked);
        assert_eq!(t.current[0], None);
        // A blocked process is not dispatched; the other one is.
        assert_eq!(t.dispatch_next(0).unwrap().pid, 2);
        t.exit_current(0, 0);
        assert_eq!(t.dispatch_next(0), None);
        assert_eq!(&t.blocked_scheduled()[..], &[1]);
        assert!(t.unblock(1, 42));
        assert!(!t.unblock(1, 42), "only blocked processes can be unblocked");
        let p = t.dispatch_next(0).unwrap();
        assert_eq!((p.pid, p.frame.rax, p.frame.rip), (1, 42, 0x1234));
        // Blocked processes are not reapable.
        let mut t2 = table_with(1);
        t2.start(1).unwrap();
        t2.block_current(0, &frame(1));
        assert_eq!(
            t2.take_for_reap(1).err(),
            Some(ProcessError::BadState(ProcessState::Blocked))
        );
    }

    #[test]
    fn exit_without_current_is_noop() {
        let mut t = ProcessTable::new();
        t.insert(4, 0, 0, 0).unwrap();
        t.exit_current(0, 42);
        assert_eq!(t.slots[0].state, ProcessState::Ready);
    }

    #[test]
    fn reap_missing_pid_fails() {
        let mut t = ProcessTable::new();
        assert_eq!(t.take_for_reap(0xFFFF_FFFE), Err(ProcessError::NotFound));
    }

    /// Roadmap 2.7: processes spread over the agent CPUs, each runs on one
    /// CPU at a time, and an idle CPU takes queued work from another.
    #[test]
    fn agents_spread_over_cpus_and_idle_cpus_take_work() {
        let mut t = table_with(4);
        let picked = t.select(Select::AllReady, &[1, 2]).unwrap();
        assert_eq!(picked.len(), 4);
        // Homes alternate between the agent CPUs.
        let homes: heapless::Vec<u8, 4> = t.slots[..4].iter().map(|p| p.home).collect();
        assert_eq!(&homes[..], &[1, 2, 1, 2]);
        let a = t.dispatch_next(1).unwrap();
        let b = t.dispatch_next(2).unwrap();
        assert_ne!(a.pid, b.pid);
        assert_eq!((a.home, b.home), (1, 2));
        assert_eq!((t.current[1], t.current[2]), (Some(a.pid), Some(b.pid)));
        // One process per CPU: a busy CPU gets nothing more.
        assert_eq!(t.dispatch_next(1), None);
        // An idle CPU outside the homes takes the remaining work.
        let c = t.dispatch_next(3).unwrap();
        assert!(c.pid != a.pid && c.pid != b.pid);
        assert_eq!(c.home, 3, "moves to the CPU that took it");
        let d = t.dispatch_next(4).unwrap();
        assert_eq!(t.dispatch_next(5), None, "nothing left");
        let mut seen = [a.pid, b.pid, c.pid, d.pid];
        seen.sort();
        assert_eq!(seen, [1, 2, 3, 4]);
        // Exits are per CPU.
        assert_eq!(t.exit_current(2, 0), Some(b.pid));
        assert_eq!(t.current[1], Some(a.pid));
        assert_eq!(t.outstanding().0, 3);
    }

    #[test]
    fn ticks_and_switches_stay_on_their_cpu() {
        let mut t = table_with(3);
        t.select(Select::AllReady, &[1, 2]).unwrap();
        let a = t.dispatch_next(1).unwrap();
        let b = t.dispatch_next(2).unwrap();
        // CPU 1's slice ends: it switches to the third process (CPU 1's
        // queue), never to the one running on CPU 2.
        let mut f = frame(a.pid as u64);
        assert_eq!(t.tick(1, &mut f, 1, 100), TickAction::Switch { pml4_phys: 0x300 });
        let now1 = t.current[1].unwrap();
        assert!(now1 != a.pid && now1 != b.pid);
        assert_eq!(t.current[2], Some(b.pid));
        // CPU 2's slice ends with nothing else Ready: it keeps its process.
        let mut g = frame(b.pid as u64);
        t.slots.iter_mut().filter(|p| p.pid == a.pid).for_each(|p| p.scheduled = false);
        assert_eq!(t.tick(2, &mut g, 1, 100), TickAction::Continue);
        assert_eq!(t.current[2], Some(b.pid));
        // CPUs a process ran on are recorded.
        let ran = t.slots.iter().find(|p| p.pid == now1).unwrap().cpus;
        assert_eq!(ran, 1 << 1);
    }

    #[test]
    fn blocked_process_resumes_on_any_cpu() {
        let mut t = table_with(1);
        t.select(Select::AllReady, &[1]).unwrap();
        let a = t.dispatch_next(1).unwrap();
        assert_eq!(t.block_current(1, &frame(9)), Some(a.pid));
        assert_eq!(t.outstanding(), (0, heapless::Vec::from_slice(&[a.pid]).unwrap()));
        assert!(t.unblock(a.pid, 42));
        let again = t.dispatch_next(2).unwrap();
        assert_eq!((again.pid, again.frame.rax), (a.pid, 42));
        assert_eq!(t.slots[0].cpus, (1 << 1) | (1 << 2));
    }
}
