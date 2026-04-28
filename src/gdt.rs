//! Global Descriptor Table and Task State Segment.
//!
//! Sets up a minimal GDT with a kernel code segment and a TSS that provides
//! an Independent Stack Table (IST) entry for the double-fault handler.  The
//! double-fault handler runs on IST slot 0 so it has a clean stack even when
//! the kernel stack overflows or is otherwise corrupted.

use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;
use spin::Once;

/// IST slot used for the double-fault handler stack (0-indexed, so slot 1 in
/// the TSS which is 1-indexed).
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Size of the dedicated double-fault stack (8 KiB).
const DOUBLE_FAULT_STACK_SIZE: usize = 8 * 1024;

/// Static storage for the double-fault stack.
static mut DOUBLE_FAULT_STACK: [u8; DOUBLE_FAULT_STACK_SIZE] =
    [0u8; DOUBLE_FAULT_STACK_SIZE];

static TSS: Once<TaskStateSegment> = Once::new();
static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();

pub struct Selectors {
    pub code_selector: SegmentSelector,
    pub data_selector: SegmentSelector,
    pub tss_selector: SegmentSelector,
}

/// Initialises the TSS and GDT and loads them into the CPU.
///
/// Must be called once, early in `kernel_main`, before the IDT is loaded.
pub fn init() {
    let tss = TSS.call_once(|| {
        let mut tss = TaskStateSegment::new();
        // Point IST slot 0 at the top of our dedicated stack (stacks grow down).
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(unsafe { &raw const DOUBLE_FAULT_STACK } as *const u8);
            stack_start + DOUBLE_FAULT_STACK_SIZE as u64
        };
        tss
    });

    let (gdt, selectors) = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let code_selector = gdt.append(Descriptor::kernel_code_segment());
        let data_selector = gdt.append(Descriptor::kernel_data_segment());
        let tss_selector = gdt.append(Descriptor::tss_segment(tss));
        (gdt, Selectors { code_selector, data_selector, tss_selector })
    });

    // Safety: loading a correctly-formed GDT / TSS.
    unsafe {
        use x86_64::instructions::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
        use x86_64::instructions::tables::load_tss;

        gdt.load();
        CS::set_reg(selectors.code_selector);
        // Set all data segment registers to the kernel data segment.
        DS::set_reg(selectors.data_selector);
        ES::set_reg(selectors.data_selector);
        FS::set_reg(selectors.data_selector);
        GS::set_reg(selectors.data_selector);
        SS::set_reg(selectors.data_selector);
        load_tss(selectors.tss_selector);
    }
}
