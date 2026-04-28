//! Interrupt Descriptor Table (IDT) setup.
//!
//! Handlers implemented here:
//!   - Double-fault  (runs on IST slot 0 — guaranteed clean stack)
//!   - PIT timer     (IRQ 0, mapped to vector 0x20 after PIC remapping)
//!   - PS/2 keyboard (IRQ 1, mapped to vector 0x21 after PIC remapping)
//!
//! The 8259 PIC is remapped so its IRQ vectors start at 0x20, keeping them
//! clear of the CPU exception vectors 0x00–0x1F.

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use spin::{Mutex, Once};

// ---------------------------------------------------------------------------
// PIC constants
// ---------------------------------------------------------------------------

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// Offset where PIC1 IRQs start (must be ≥ 0x20 to avoid CPU exceptions).
const PIC1_OFFSET: u8 = 0x20;
/// Offset where PIC2 IRQs start.
const PIC2_OFFSET: u8 = PIC1_OFFSET + 8;

/// Vector for IRQ 0 (PIT timer).
pub const TIMER_INTERRUPT_ID: u8 = PIC1_OFFSET;
/// Vector for IRQ 1 (PS/2 keyboard).
pub const KEYBOARD_INTERRUPT_ID: u8 = PIC1_OFFSET + 1;

// ---------------------------------------------------------------------------
// Global tick counter
// ---------------------------------------------------------------------------

/// Incremented on every PIT timer interrupt.  Read with [`ticks()`].
static TICKS: Mutex<u64> = Mutex::new(0);

/// Returns the number of timer ticks since the IDT was loaded.
pub fn ticks() -> u64 {
    *TICKS.lock()
}

// ---------------------------------------------------------------------------
// IDT
// ---------------------------------------------------------------------------

static IDT: Once<InterruptDescriptorTable> = Once::new();

/// Initialise the GDT, remap the PIC, build and load the IDT.
///
/// Call once at the very start of `kernel_main`.
pub fn init() {
    crate::gdt::init();
    remap_pic();

    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();

        // CPU exceptions
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);

        // Double-fault on its own IST stack so a stack overflow doesn't
        // cause a triple-fault before we can print the error.
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(crate::gdt::DOUBLE_FAULT_IST_INDEX);
        }

        // Hardware interrupts
        idt[usize::from(TIMER_INTERRUPT_ID)].set_handler_fn(timer_handler);
        idt[usize::from(KEYBOARD_INTERRUPT_ID)].set_handler_fn(keyboard_handler);

        idt
    });

    idt.load();

    // Enable hardware interrupts.
    x86_64::instructions::interrupts::enable();

    crate::println!("IDT loaded — double-fault, timer, keyboard handlers active");
}

// ---------------------------------------------------------------------------
// PIC helpers (raw port I/O via inline asm)
// ---------------------------------------------------------------------------

#[inline]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nomem, nostack, preserves_flags),
    );
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!(
        "in al, dx",
        in("dx") port,
        out("al") v,
        options(nomem, nostack, preserves_flags),
    );
    v
}

/// A short I/O delay using a harmless write to port 0x80 (POST code port).
#[inline]
unsafe fn io_wait() {
    outb(0x80, 0);
}

/// Remap both 8259 PICs so their IRQ vectors start at `PIC1_OFFSET` / `PIC2_OFFSET`.
fn remap_pic() {
    unsafe {
        // Save existing masks.
        let mask1 = inb(PIC1_DATA);
        let mask2 = inb(PIC2_DATA);

        // Start initialisation sequence (ICW1).
        outb(PIC1_CMD, 0x11); io_wait();
        outb(PIC2_CMD, 0x11); io_wait();

        // ICW2 — vector offsets.
        outb(PIC1_DATA, PIC1_OFFSET); io_wait();
        outb(PIC2_DATA, PIC2_OFFSET); io_wait();

        // ICW3 — cascade wiring.
        outb(PIC1_DATA, 0x04); io_wait(); // PIC1: slave on IRQ2
        outb(PIC2_DATA, 0x02); io_wait(); // PIC2: cascade identity = 2

        // ICW4 — 8086 mode.
        outb(PIC1_DATA, 0x01); io_wait();
        outb(PIC2_DATA, 0x01); io_wait();

        // Restore masks.
        outb(PIC1_DATA, mask1);
        outb(PIC2_DATA, mask2);

        // Unmask IRQ 0 (timer) and IRQ 1 (keyboard) on PIC1;
        // mask everything else on both PICs.
        outb(PIC1_DATA, 0b1111_1100); // keep IRQ0 + IRQ1 unmasked
        outb(PIC2_DATA, 0xFF);        // all PIC2 IRQs masked
    }
}

/// Send End-of-Interrupt to the appropriate PIC(s).
unsafe fn send_eoi(irq: u8) {
    if irq >= 8 {
        outb(PIC2_CMD, 0x20);
    }
    outb(PIC1_CMD, 0x20);
}

// ---------------------------------------------------------------------------
// Exception handlers
// ---------------------------------------------------------------------------

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    crate::println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    let cr2: u64;
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack));
    }
    crate::println!("EXCEPTION: PAGE FAULT");
    crate::println!("  Accessed address: {:#x}", cr2);
    crate::println!("  Error code: {:?}", error_code);
    crate::println!("{:#?}", stack_frame);
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    crate::println!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
    loop {
        x86_64::instructions::hlt();
    }
}

// ---------------------------------------------------------------------------
// Hardware interrupt handlers
// ---------------------------------------------------------------------------

extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
    let mut t = TICKS.lock();
    *t = t.wrapping_add(1);
    // EOI must be sent while NOT holding a lock that a non-interrupt path
    // might also hold, to avoid deadlock.
    drop(t);
    unsafe { send_eoi(0) };
}

extern "x86-interrupt" fn keyboard_handler(_stack_frame: InterruptStackFrame) {
    // Read and discard the scancode for now — prevents the keyboard
    // controller from locking up (it won't send further interrupts until
    // its output buffer is drained).
    let _scancode: u8 = unsafe { inb(0x60) };
    unsafe { send_eoi(1) };
}
