//! Per-CPU runtime state and lock-free AP online mailbox (roadmap reset M1/M3).
//!
//! Topology slots are dense indices `0..MAX_CPUS`. APIC ids may be sparse;
//! use [`slot_for_apic`] / [`apic_for_slot`] rather than `apic_id - 1`.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use heapless::Vec;
use spin::Mutex;

use crate::acpi::{CpuTopology, MadtCpu, MAX_MADT_CPUS};
use crate::local_apic::DEFAULT_TIMER_INITIAL_COUNT;

pub const MAX_CPUS: usize = MAX_MADT_CPUS;

#[derive(Clone, Copy, Debug, Default)]
pub struct PerCpu {
    pub slot: u8,
    pub apic_id: u32,
    pub online: bool,
    pub irq_depth: u32,
    pub ticks: u64,
    /// Active kernel thread id (0 = none).
    pub current_thread: u16,
}

/// GS-base local block (unlocked, one per topology slot).
///
/// Layout is ABI for the syscall trampoline (`gs:[offset]`):
/// - `kernel_rsp` at offset 16
/// - `user_rsp` at offset 24
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CpuLocal {
    pub slot: u32,
    pub apic_id: u32,
    pub current_thread: u32,
    pub _pad: u32,
    pub kernel_rsp: u64,
    pub user_rsp: u64,
}

/// Byte offsets into [`CpuLocal`] used by `syscall_entry_shim`.
pub const CPULOCAL_KERNEL_RSP: usize = 16;
pub const CPULOCAL_USER_RSP: usize = 24;

/// Wrapper so a static array of `UnsafeCell<CpuLocal>` is `Sync`.
struct CpuLocalCell(core::cell::UnsafeCell<CpuLocal>);
// SAFETY: each slot is only mutated by its owning CPU after topology init.
unsafe impl Sync for CpuLocalCell {}

static CPU_LOCAL: [CpuLocalCell; MAX_CPUS] = [const {
    CpuLocalCell(core::cell::UnsafeCell::new(CpuLocal {
        slot: 0,
        apic_id: 0,
        current_thread: 0,
        _pad: 0,
        kernel_rsp: 0,
        user_rsp: 0,
    }))
}; MAX_CPUS];

static TOPOLOGY: Mutex<CpuTopology> = Mutex::new(CpuTopology {
    cpus: Vec::new(),
    lapic_address: 0xFEE0_0000,
});
static SLOT_TO_APIC: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(u32::MAX) }; MAX_CPUS];
static APIC_TO_SLOT: [AtomicU32; 256] = [const { AtomicU32::new(u32::MAX) }; 256];
static PERCPU: [Mutex<PerCpu>; MAX_CPUS] = [const { Mutex::new(PerCpu {
    slot: 0,
    apic_id: 0,
    online: false,
    irq_depth: 0,
    ticks: 0,
    current_thread: 0,
}) }; MAX_CPUS];
static CPU_COUNT: AtomicU32 = AtomicU32::new(0);
static TOPOLOGY_READY: AtomicBool = AtomicBool::new(false);

/// Bitmask of APs that reached long-mode entry without needing `KERNEL` lock.
static AP_READY_MASK: AtomicU64 = AtomicU64::new(0);
/// Startup sequence published by each AP when signalling ready (indexed by slot).
static AP_READY_SEQ: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// BSP-published LAPIC timer initial count for AP inheritance without Kernel lock.
static BSP_TIMER_COUNT: AtomicU32 = AtomicU32::new(DEFAULT_TIMER_INITIAL_COUNT);

/// Install topology from MADT (or fallback) and build slot ↔ APIC maps.
pub fn init_topology(topo: CpuTopology) {
    let mut guard = TOPOLOGY.lock();
    *guard = topo;
    for slot in 0..MAX_CPUS {
        SLOT_TO_APIC[slot].store(u32::MAX, Ordering::Relaxed);
    }
    for e in APIC_TO_SLOT.iter() {
        e.store(u32::MAX, Ordering::Relaxed);
    }
    let mut n = 0u32;
    for (slot, cpu) in guard.cpus.iter().enumerate() {
        if slot >= MAX_CPUS {
            break;
        }
        SLOT_TO_APIC[slot].store(cpu.apic_id, Ordering::Release);
        if (cpu.apic_id as usize) < APIC_TO_SLOT.len() {
            APIC_TO_SLOT[cpu.apic_id as usize].store(slot as u32, Ordering::Release);
        }
        let mut pc = PERCPU[slot].lock();
        *pc = PerCpu {
            slot: slot as u8,
            apic_id: cpu.apic_id,
            online: cpu.is_bsp,
            irq_depth: 0,
            ticks: 0,
            current_thread: 0,
        };
        // SAFETY: exclusive init before CPUs go online.
        unsafe {
            *CPU_LOCAL[slot].0.get() = CpuLocal {
                slot: slot as u32,
                apic_id: cpu.apic_id,
                current_thread: 0,
                _pad: 0,
                kernel_rsp: 0,
                user_rsp: 0,
            };
        }
        n = n.saturating_add(1);
    }
    CPU_COUNT.store(n, Ordering::Release);
    TOPOLOGY_READY.store(true, Ordering::Release);
}

/// Point GS at this topology slot's [`CpuLocal`] (call on the target CPU).
pub fn load_gs_for_slot(slot: usize) {
    if slot >= MAX_CPUS {
        return;
    }
    let ptr = CPU_LOCAL[slot].0.get() as u64;
    crate::cpu::set_gs_base(ptr);
    // Seed syscall kernel stack from TSS RSP0 when available.
    #[cfg(target_os = "none")]
    if let Some(apic) = apic_for_slot(slot) {
        if let Some(top) = crate::gdt::kernel_stack_top(apic) {
            set_kernel_rsp(slot, top);
        }
    }
}

/// Current CPU's [`CpuLocal`] via GS base (None on host / before load).
pub fn current_local() -> Option<&'static CpuLocal> {
    let base = crate::cpu::gs_base();
    if base == 0 {
        return None;
    }
    Some(unsafe { &*(base as *const CpuLocal) })
}

pub fn set_current_thread(slot: usize, thread_id: Option<u16>) {
    if slot >= MAX_CPUS {
        return;
    }
    let tid = thread_id.unwrap_or(0) as u32;
    unsafe {
        (*CPU_LOCAL[slot].0.get()).current_thread = tid;
    }
    if let Some(mut pc) = PERCPU.get(slot).map(|m| m.lock()) {
        pc.current_thread = thread_id.unwrap_or(0);
    }
}

/// Publish the kernel stack top used by the SYSCALL trampoline on this slot.
pub fn set_kernel_rsp(slot: usize, rsp: u64) {
    if slot >= MAX_CPUS {
        return;
    }
    unsafe {
        (*CPU_LOCAL[slot].0.get()).kernel_rsp = rsp;
    }
}

/// Prepare GS for ring-3: `KERNEL_GS_BASE` → CpuLocal, `GS_BASE` → 0.
///
/// Call on the current CPU immediately before `iretq`/`sysret` into user mode so
/// the syscall stub's `swapgs` restores the kernel CpuLocal pointer.
pub fn prepare_user_gs(slot: usize) {
    if slot >= MAX_CPUS {
        return;
    }
    let ptr = CPU_LOCAL[slot].0.get() as u64;
    crate::cpu::wrmsr(crate::cpu::IA32_KERNEL_GS_BASE, ptr);
    crate::cpu::set_gs_base(0);
}

pub fn topology_ready() -> bool {
    TOPOLOGY_READY.load(Ordering::Acquire)
}

pub fn cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Acquire)
}

pub fn slot_for_apic(apic_id: u32) -> Option<usize> {
    if (apic_id as usize) >= APIC_TO_SLOT.len() {
        return None;
    }
    let slot = APIC_TO_SLOT[apic_id as usize].load(Ordering::Acquire);
    if slot == u32::MAX {
        None
    } else {
        Some(slot as usize)
    }
}

pub fn apic_for_slot(slot: usize) -> Option<u32> {
    if slot >= MAX_CPUS {
        return None;
    }
    let id = SLOT_TO_APIC[slot].load(Ordering::Acquire);
    if id == u32::MAX {
        None
    } else {
        Some(id)
    }
}

pub fn for_each_cpu(mut f: impl FnMut(MadtCpu)) {
    // Copy under the lock, then invoke callbacks unlocked so ISR/boot code
    // that also touches TOPOLOGY cannot deadlock the BSP.
    let snapshot: Vec<MadtCpu, MAX_CPUS> = {
        let topo = TOPOLOGY.lock();
        let mut out = Vec::new();
        for cpu in topo.cpus.iter() {
            let _ = out.push(*cpu);
        }
        out
    };
    for cpu in snapshot.iter().copied() {
        f(cpu);
    }
}

pub fn first_application_apic() -> Option<u32> {
    let topo = TOPOLOGY.lock();
    topo.cpus
        .iter()
        .find(|c| c.enabled && !c.is_bsp)
        .map(|c| c.apic_id)
}

/// AP signals online via atomics (no Kernel lock required).
pub fn signal_ap_ready(apic_id: u32, startup_seq: u32) {
    let Some(slot) = slot_for_apic(apic_id) else {
        return;
    };
    AP_READY_SEQ[slot].store(startup_seq, Ordering::Release);
    AP_READY_MASK.fetch_or(1u64 << slot, Ordering::Release);
    let mut pc = PERCPU[slot].lock();
    pc.online = true;
}

pub fn ap_ready(apic_id: u32) -> bool {
    let Some(slot) = slot_for_apic(apic_id) else {
        return false;
    };
    AP_READY_MASK.load(Ordering::Acquire) & (1u64 << slot) != 0
}

pub fn ap_ready_seq(apic_id: u32) -> Option<u32> {
    let slot = slot_for_apic(apic_id)?;
    if AP_READY_MASK.load(Ordering::Acquire) & (1u64 << slot) == 0 {
        return None;
    }
    Some(AP_READY_SEQ[slot].load(Ordering::Acquire))
}

pub fn ap_ready_mask() -> u64 {
    AP_READY_MASK.load(Ordering::Acquire)
}

pub fn publish_bsp_timer_count(count: u32) {
    if count != 0 {
        BSP_TIMER_COUNT.store(count, Ordering::Release);
    }
}

pub fn bsp_timer_count() -> u32 {
    BSP_TIMER_COUNT.load(Ordering::Acquire)
}

pub fn note_tick(apic_id: u32) {
    if let Some(slot) = slot_for_apic(apic_id) {
        let mut pc = PERCPU[slot].lock();
        pc.ticks = pc.ticks.saturating_add(1);
    }
}

pub fn percpu_snapshot(apic_id: u32) -> Option<PerCpu> {
    let slot = slot_for_apic(apic_id)?;
    Some(*PERCPU[slot].lock())
}

/// Read current CPU APIC id from local APIC (0 on host).
pub fn current_apic_id() -> u32 {
    crate::local_apic::XApicController::new().local_apic_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acpi::fallback_topology;

    #[test]
    fn topology_maps_sparse_ready_bits_by_slot() {
        let _ = AP_READY_MASK.swap(0, Ordering::SeqCst);
        init_topology(fallback_topology());
        assert_eq!(cpu_count(), 2);
        assert_eq!(slot_for_apic(0), Some(0));
        assert_eq!(slot_for_apic(1), Some(1));
        assert!(!ap_ready(1));
        signal_ap_ready(1, 42);
        assert!(ap_ready(1));
        assert_eq!(ap_ready_seq(1), Some(42));
    }
}
