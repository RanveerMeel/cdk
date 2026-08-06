//! Global Descriptor Table and Task State Segment.
//!
//! Sets up a minimal GDT with a kernel code segment and a TSS that provides:
//! - IST slot 0 for the double-fault handler
//! - RSP0 (`privilege_stack_table[0]`) as the per-core kernel stack (Phase 17)
//!
//! Phase 16/17 give each AP its own TSS, IST stack, and RSP0 kernel stack.

use spin::Once;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// IST slot used for the double-fault handler stack (0-indexed).
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Size of the dedicated double-fault stack (8 KiB).
const DOUBLE_FAULT_STACK_SIZE: usize = 8 * 1024;

/// Size of the per-core privilege-0 kernel stack used as TSS RSP0 (16 KiB).
pub const KERNEL_STACK_SIZE: usize = 16 * 1024;

/// Maximum number of application processors with private TSS/IST/RSP0 state.
/// Indexed by topology **slot** (not raw APIC id): slots `1..MAX_AP_TSS+1`.
pub const MAX_AP_TSS: usize = 7;

static mut DOUBLE_FAULT_STACK: [u8; DOUBLE_FAULT_STACK_SIZE] = [0u8; DOUBLE_FAULT_STACK_SIZE];
static mut BSP_KERNEL_STACK: [u8; KERNEL_STACK_SIZE] = [0u8; KERNEL_STACK_SIZE];

static mut AP_DOUBLE_FAULT_STACKS: [[u8; DOUBLE_FAULT_STACK_SIZE]; MAX_AP_TSS] =
    [[0u8; DOUBLE_FAULT_STACK_SIZE]; MAX_AP_TSS];
static mut AP_KERNEL_STACKS: [[u8; KERNEL_STACK_SIZE]; MAX_AP_TSS] =
    [[0u8; KERNEL_STACK_SIZE]; MAX_AP_TSS];

static TSS: Once<TaskStateSegment> = Once::new();
static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();

static AP_TSS: [Once<TaskStateSegment>; MAX_AP_TSS] = [const { Once::new() }; MAX_AP_TSS];
static AP_GDT: [Once<(GlobalDescriptorTable, Selectors)>; MAX_AP_TSS] =
    [const { Once::new() }; MAX_AP_TSS];

pub struct Selectors {
    pub code_selector: SegmentSelector,
    pub data_selector: SegmentSelector,
    pub user_data_selector: SegmentSelector,
    pub user_code_selector: SegmentSelector,
    pub tss_selector: SegmentSelector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApGdtError {
    /// `apic_id` 0 is the BSP — use [`init`] instead.
    BootstrapCore,
    /// No TSS slot for this APIC id (supports `1..=MAX_AP_TSS`).
    NoSlot,
}

/// Map an application APIC id onto a TSS array index via topology slot.
///
/// Uses [`crate::percpu::slot_for_apic`] when topology is ready; falls back to
/// `apic_id - 1` for early boot / host tests.
pub fn ap_tss_slot(apic_id: u32) -> Option<usize> {
    if let Some(topo_slot) = crate::percpu::slot_for_apic(apic_id) {
        if topo_slot == 0 {
            return None; // BSP
        }
        let idx = topo_slot.checked_sub(1)?;
        return (idx < MAX_AP_TSS).then_some(idx);
    }
    if apic_id == 0 {
        return None;
    }
    let idx = (apic_id as usize).checked_sub(1)?;
    (idx < MAX_AP_TSS).then_some(idx)
}

/// Whether this APIC id has (or can have) a private TSS slot.
pub fn ap_tss_supported(apic_id: u32) -> bool {
    ap_tss_slot(apic_id).is_some()
}

/// Whether the private TSS/GDT for `apic_id` has already been initialised.
pub fn ap_tss_ready(apic_id: u32) -> bool {
    ap_tss_slot(apic_id).is_some_and(|idx| AP_GDT[idx].get().is_some())
}

/// Virtual address of the top of the per-core kernel stack (RSP0).
pub fn kernel_stack_top(apic_id: u32) -> Option<u64> {
    if apic_id == 0 {
        let start = VirtAddr::from_ptr(&raw const BSP_KERNEL_STACK as *const u8);
        return Some(start.as_u64() + KERNEL_STACK_SIZE as u64);
    }
    let idx = ap_tss_slot(apic_id)?;
    // SAFETY: indexing a `static mut` array requires unsafe; each AP owns one slot.
    let start = unsafe { VirtAddr::from_ptr(&raw const AP_KERNEL_STACKS[idx] as *const u8) };
    Some(start.as_u64() + KERNEL_STACK_SIZE as u64)
}

/// Update TSS RSP0 for privilege transitions into ring 0 (per-thread stacks).
pub fn set_rsp0(apic_id: u32, stack_top: u64) {
    let virt = VirtAddr::new(stack_top);
    unsafe {
        if apic_id == 0 {
            if let Some(tss) = TSS.get() {
                let tss_mut = tss as *const TaskStateSegment as *mut TaskStateSegment;
                (*tss_mut).privilege_stack_table[0] = virt;
            }
        } else if let Some(idx) = ap_tss_slot(apic_id) {
            if let Some(tss) = AP_TSS[idx].get() {
                let tss_mut = tss as *const TaskStateSegment as *mut TaskStateSegment;
                (*tss_mut).privilege_stack_table[0] = virt;
            }
        }
    }
}

/// Kernel / user selectors for STAR programming (syscall).
pub fn star_selectors() -> Option<(SegmentSelector, SegmentSelector, SegmentSelector)> {
    let (_, sel) = GDT.get()?;
    Some((sel.code_selector, sel.user_code_selector, sel.user_data_selector))
}

/// Initialises the TSS and GDT and loads them into the CPU.
///
/// Must be called once, early in `kernel_main`, before the IDT is loaded.
pub fn init() {
    let tss = TSS.call_once(|| {
        build_tss(
            &raw const DOUBLE_FAULT_STACK as *const u8,
            &raw const BSP_KERNEL_STACK as *const u8,
        )
    });

    let (gdt, selectors) = GDT.call_once(|| build_gdt(tss));
    load_gdt_selectors(gdt, selectors, true);
}

/// Initialise and load a private GDT + TSS (IST + RSP0) for an AP.
pub fn init_for_ap(apic_id: u32) -> Result<(), ApGdtError> {
    let idx = ap_tss_slot(apic_id).ok_or(if apic_id == 0 {
        ApGdtError::BootstrapCore
    } else {
        ApGdtError::NoSlot
    })?;

    let tss = AP_TSS[idx].call_once(|| {
        // SAFETY: each AP owns unique DF + kernel stack slots.
        unsafe {
            build_tss(
                &raw const AP_DOUBLE_FAULT_STACKS[idx] as *const u8,
                &raw const AP_KERNEL_STACKS[idx] as *const u8,
            )
        }
    });

    let (gdt, selectors) = AP_GDT[idx].call_once(|| build_gdt(tss));
    load_gdt_selectors(gdt, selectors, true);
    Ok(())
}

/// Reload the already-initialised shared GDT/segments on an AP (fallback).
pub fn reload_for_ap() {
    let Some((gdt, selectors)) = GDT.get() else {
        return;
    };
    load_gdt_selectors(gdt, selectors, false);
}

fn build_tss(df_stack: *const u8, kernel_stack: *const u8) -> TaskStateSegment {
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
        let stack_start = VirtAddr::from_ptr(df_stack);
        stack_start + DOUBLE_FAULT_STACK_SIZE as u64
    };
    // RSP0: stack used on privilege transitions into ring 0.
    tss.privilege_stack_table[0] = {
        let stack_start = VirtAddr::from_ptr(kernel_stack);
        stack_start + KERNEL_STACK_SIZE as u64
    };
    tss
}

fn build_gdt(tss: &'static TaskStateSegment) -> (GlobalDescriptorTable, Selectors) {
    let mut gdt = GlobalDescriptorTable::new();
    let code_selector = gdt.append(Descriptor::kernel_code_segment());
    let data_selector = gdt.append(Descriptor::kernel_data_segment());
    // User segments (DPL3) for ring-3 / STAR.
    let user_data_selector = gdt.append(Descriptor::user_data_segment());
    let user_code_selector = gdt.append(Descriptor::user_code_segment());
    let tss_selector = gdt.append(Descriptor::tss_segment(tss));
    (
        gdt,
        Selectors {
            code_selector,
            data_selector,
            user_data_selector,
            user_code_selector,
            tss_selector,
        },
    )
}

fn load_gdt_selectors(
    gdt: &'static GlobalDescriptorTable,
    selectors: &Selectors,
    with_tss: bool,
) {
    // Safety: loading a correctly-formed GDT / optional TSS.
    unsafe {
        use x86_64::instructions::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
        use x86_64::instructions::tables::load_tss;

        gdt.load();
        CS::set_reg(selectors.code_selector);
        DS::set_reg(selectors.data_selector);
        ES::set_reg(selectors.data_selector);
        FS::set_reg(selectors.data_selector);
        GS::set_reg(selectors.data_selector);
        SS::set_reg(selectors.data_selector);
        if with_tss {
            load_tss(selectors.tss_selector);
        }
    }
}
