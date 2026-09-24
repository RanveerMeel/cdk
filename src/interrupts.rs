//! Interrupt Descriptor Table (IDT) setup.
//!
//! Handlers implemented here:
//!   - CPU exceptions (#DE #OF #BR #UD #NM #NP #SS #GP #PF #MF #AC #XM #BP):
//!     a fault raised in ring 3 terminates the offending process and returns
//!     to the kernel (see [`crate::syscall::abort_user`]); a fault in kernel
//!     mode prints diagnostics and halts the CPU
//!   - Double-fault  (runs on IST slot 0 — guaranteed clean stack)
//!   - PIT timer     (IRQ 0, mapped to vector 0x20 after PIC remapping)
//!   - PS/2 keyboard (IRQ 1, mapped to vector 0x21 after PIC remapping)
//!
//! The 8259 PIC is remapped so its IRQ vectors start at 0x20, keeping them
//! clear of the CPU exception vectors 0x00–0x1F.
//!
//! ## Preemptive scheduling hook
//!
//! `main.rs` calls [`set_preempt_hook`] once at boot to register a function
//! that the timer ISR invokes on every tick.  The hook receives the current
//! tick count so it can decide whether the running task's time slice has
//! expired without the ISR needing to know about `KERNEL` directly.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering as AtomicOrdering};
use spin::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

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
/// Vector reserved for local APIC timer interrupts.
pub const LOCAL_APIC_TIMER_INTERRUPT_ID: u8 = crate::local_apic::LOCAL_APIC_TIMER_VECTOR;
/// Vector reserved for cross-core reschedule IPIs.
pub const RESCHEDULE_INTERRUPT_ID: u8 = crate::local_apic::RESCHEDULE_IPI_VECTOR;
/// Vector reserved for TLB shootdown IPIs.
pub const TLB_SHOOTDOWN_INTERRUPT_ID: u8 = crate::local_apic::TLB_SHOOTDOWN_IPI_VECTOR;

// ---------------------------------------------------------------------------
// Global tick counter
// ---------------------------------------------------------------------------

/// Incremented on every PIT timer interrupt.  Read with [`ticks()`].
///
/// `AtomicU64` is used instead of `spin::Mutex` so the ISR never spins —
/// a spinlock here would deadlock if the same core interrupted itself while
/// holding the lock (relevant on multi-core where lock-holder migration is
/// possible).
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Returns the number of timer ticks since the IDT was loaded.
pub fn ticks() -> u64 {
    TICKS.load(AtomicOrdering::Relaxed)
}

// ---------------------------------------------------------------------------
// Preemption hook
// ---------------------------------------------------------------------------

/// Signature for the preemption callback installed by `main.rs`.
///
/// The argument is the current tick count.  The function should attempt a
/// non-blocking lock on `KERNEL` and call `Kernel::preempt_tick`; if the
/// lock is busy (console command in progress) the tick is silently skipped —
/// the scheduler will catch up on the next tick.
pub type PreemptFn = fn(u64);
pub type LocalApicTickFn = fn(u32);
pub type RescheduleIpiFn = fn(u32);
pub type TlbShootdownIpiFn = fn(u32);

/// Null sentinel: no hook installed yet.
fn noop_preempt(_tick: u64) {}
fn noop_local_apic_tick(_apic_id: u32) {}
fn noop_reschedule_ipi(_apic_id: u32) {}
fn noop_tlb_shootdown_ipi(_apic_id: u32) {}

/// Atomic pointer holding the current preemption callback.
///
/// We store a raw function pointer cast to `*mut u8` so we can use
/// `AtomicPtr` (the only atomic pointer type stable in `no_std`).
static PREEMPT_HOOK: AtomicPtr<u8> = AtomicPtr::new(noop_preempt as *mut u8);
static LOCAL_APIC_TICK_HOOK: AtomicPtr<u8> = AtomicPtr::new(noop_local_apic_tick as *mut u8);
static RESCHEDULE_IPI_HOOK: AtomicPtr<u8> = AtomicPtr::new(noop_reschedule_ipi as *mut u8);
static TLB_SHOOTDOWN_IPI_HOOK: AtomicPtr<u8> = AtomicPtr::new(noop_tlb_shootdown_ipi as *mut u8);

/// Register the preemption callback.  Call once from `kernel_main` before
/// enabling interrupts (or immediately after — the hook is set atomically).
pub fn set_preempt_hook(f: PreemptFn) {
    PREEMPT_HOOK.store(f as *mut u8, AtomicOrdering::Release);
}

pub fn set_local_apic_tick_hook(f: LocalApicTickFn) {
    LOCAL_APIC_TICK_HOOK.store(f as *mut u8, AtomicOrdering::Release);
}

pub fn set_reschedule_ipi_hook(f: RescheduleIpiFn) {
    RESCHEDULE_IPI_HOOK.store(f as *mut u8, AtomicOrdering::Release);
}

pub fn set_tlb_shootdown_ipi_hook(f: TlbShootdownIpiFn) {
    TLB_SHOOTDOWN_IPI_HOOK.store(f as *mut u8, AtomicOrdering::Release);
}

#[inline]
fn call_preempt_hook(tick: u64) {
    let raw = PREEMPT_HOOK.load(AtomicOrdering::Acquire);
    // SAFETY: we only ever store valid `PreemptFn` function pointers here.
    let f: PreemptFn = unsafe { core::mem::transmute(raw) };
    f(tick);
}

#[inline]
fn call_local_apic_tick_hook(apic_id: u32) {
    let raw = LOCAL_APIC_TICK_HOOK.load(AtomicOrdering::Acquire);
    // SAFETY: we only ever store valid `LocalApicTickFn` function pointers here.
    let f: LocalApicTickFn = unsafe { core::mem::transmute(raw) };
    f(apic_id);
}

#[inline]
fn call_reschedule_ipi_hook(apic_id: u32) {
    let raw = RESCHEDULE_IPI_HOOK.load(AtomicOrdering::Acquire);
    // SAFETY: we only ever store valid `RescheduleIpiFn` function pointers here.
    let f: RescheduleIpiFn = unsafe { core::mem::transmute(raw) };
    f(apic_id);
}

#[inline]
fn call_tlb_shootdown_ipi_hook(apic_id: u32) {
    let raw = TLB_SHOOTDOWN_IPI_HOOK.load(AtomicOrdering::Acquire);
    // SAFETY: we only ever store valid `TlbShootdownIpiFn` function pointers here.
    let f: TlbShootdownIpiFn = unsafe { core::mem::transmute(raw) };
    f(apic_id);
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
        idt.divide_error.set_handler_fn(divide_error_handler);
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.overflow.set_handler_fn(overflow_handler);
        idt.bound_range_exceeded.set_handler_fn(bound_range_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.device_not_available.set_handler_fn(device_not_available_handler);
        idt.segment_not_present.set_handler_fn(segment_not_present_handler);
        idt.stack_segment_fault.set_handler_fn(stack_segment_handler);
        idt.general_protection_fault.set_handler_fn(general_protection_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.x87_floating_point.set_handler_fn(x87_floating_point_handler);
        idt.alignment_check.set_handler_fn(alignment_check_handler);
        idt.simd_floating_point.set_handler_fn(simd_floating_point_handler);

        // Double-fault on its own IST stack so a stack overflow doesn't
        // cause a triple-fault before we can print the error.
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(crate::gdt::DOUBLE_FAULT_IST_INDEX);
        }

        // Hardware interrupts — IDT indexed by u8 in x86_64 0.15
        // Timer vectors use full-register entry stubs so the user scheduler
        // can switch processes by rewriting the saved frame.
        unsafe {
            idt[TIMER_INTERRUPT_ID]
                .set_handler_addr(x86_64::VirtAddr::new(cdk_timer_entry as *const () as u64));
            idt[LOCAL_APIC_TIMER_INTERRUPT_ID]
                .set_handler_addr(x86_64::VirtAddr::new(cdk_lapic_timer_entry as *const () as u64));
        }
        idt[KEYBOARD_INTERRUPT_ID].set_handler_fn(keyboard_handler);
        idt[RESCHEDULE_INTERRUPT_ID].set_handler_fn(reschedule_ipi_handler);
        idt[TLB_SHOOTDOWN_INTERRUPT_ID].set_handler_fn(tlb_shootdown_ipi_handler);

        idt
    });

    idt.load();

    // Enable hardware interrupts.
    x86_64::instructions::interrupts::enable();

    crate::println!("IDT loaded — CPU exceptions (ring-3 faults contained), double-fault, timer, keyboard, LAPIC, reschedule, TLB handlers active");
}

/// Reload the IDT on an application processor (same table as the BSP).
pub fn load_idt() {
    if let Some(idt) = IDT.get() {
        idt.load();
    }
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
        outb(PIC1_CMD, 0x11);
        io_wait();
        outb(PIC2_CMD, 0x11);
        io_wait();

        // ICW2 — vector offsets.
        outb(PIC1_DATA, PIC1_OFFSET);
        io_wait();
        outb(PIC2_DATA, PIC2_OFFSET);
        io_wait();

        // ICW3 — cascade wiring.
        outb(PIC1_DATA, 0x04);
        io_wait(); // PIC1: slave on IRQ2
        outb(PIC2_DATA, 0x02);
        io_wait(); // PIC2: cascade identity = 2

        // ICW4 — 8086 mode.
        outb(PIC1_DATA, 0x01);
        io_wait();
        outb(PIC2_DATA, 0x01);
        io_wait();

        // Restore masks.
        outb(PIC1_DATA, mask1);
        outb(PIC2_DATA, mask2);

        // Unmask IRQ 0 (timer) and IRQ 1 (keyboard) on PIC1;
        // mask everything else on both PICs.
        outb(PIC1_DATA, 0b1111_1100); // keep IRQ0 + IRQ1 unmasked
        outb(PIC2_DATA, 0xFF); // all PIC2 IRQs masked
    }
}

/// Mask all 8259 lines (used after IOAPIC takes ownership of ISA IRQs).
pub fn mask_all_pic() {
    unsafe {
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
    }
    crate::println!("PIC: all IRQs masked (IOAPIC active)");
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

/// Route a CPU exception. Faults raised in ring 3 terminate the offending
/// process and resume the kernel; faults in kernel mode are fatal.
fn handle_exception(vector: u8, frame: &InterruptStackFrame, error_code: u64, addr: u64) -> ! {
    let fault = crate::process::UserFault {
        vector,
        error_code,
        rip: frame.instruction_pointer.as_u64(),
        addr,
        rsp: frame.stack_pointer.as_u64(),
    };
    if frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        crate::syscall::abort_user(fault);
    }
    crate::println!("EXCEPTION: {} in kernel mode", fault.name());
    crate::println!("  rip={:#x} addr={:#x} error_code={:#x}", fault.rip, addr, error_code);
    crate::println!("{:#?}", frame);
    loop {
        x86_64::instructions::interrupts::disable();
        x86_64::instructions::hlt();
    }
}

macro_rules! exception_handler {
    ($name:ident, $vector:expr) => {
        extern "x86-interrupt" fn $name(frame: InterruptStackFrame) {
            handle_exception($vector, &frame, 0, 0);
        }
    };
    ($name:ident, $vector:expr, error_code) => {
        extern "x86-interrupt" fn $name(frame: InterruptStackFrame, error_code: u64) {
            handle_exception($vector, &frame, error_code, 0);
        }
    };
}

exception_handler!(divide_error_handler, 0);
exception_handler!(overflow_handler, 4);
exception_handler!(bound_range_handler, 5);
exception_handler!(invalid_opcode_handler, 6);
exception_handler!(device_not_available_handler, 7);
exception_handler!(segment_not_present_handler, 11, error_code);
exception_handler!(stack_segment_handler, 12, error_code);
exception_handler!(general_protection_handler, 13, error_code);
exception_handler!(x87_floating_point_handler, 16);
exception_handler!(alignment_check_handler, 17, error_code);
exception_handler!(simd_floating_point_handler, 19);

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    if stack_frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        handle_exception(3, &stack_frame, 0, 0);
    }
    // Kernel `int3`: report and continue.
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
    handle_exception(14, &stack_frame, error_code.bits(), cr2);
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

// Full-register entry stubs for the timer vectors. They save every GPR so
// the stack holds a `process::TrapFrame` (GPRs + CPU interrupt frame), call
// `timer_dispatch`, and restore whatever the frame then contains — which, if
// the user scheduler switched processes, is another process.
//
// Stack alignment: the CPU aligns RSP to 16 before pushing its 5-word frame
// (40 bytes); 15 pushes (120 bytes) make 160, so RSP is 16-aligned at `call`.
core::arch::global_asm!(
    r#"
    .macro CDK_TIMER_ENTRY name, vector
    .global \name
    .type \name, @function
    \name:
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push rbp
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
        mov rdi, rsp
        mov esi, \vector
        cld
        call {dispatch}
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rbp
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        iretq
    .endm

    CDK_TIMER_ENTRY cdk_timer_entry, {pit}
    CDK_TIMER_ENTRY cdk_lapic_timer_entry, {lapic}
    "#,
    dispatch = sym timer_dispatch,
    pit = const TIMER_INTERRUPT_ID as u32,
    lapic = const LOCAL_APIC_TIMER_INTERRUPT_ID as u32,
);

unsafe extern "C" {
    fn cdk_timer_entry();
    fn cdk_lapic_timer_entry();
}

/// Rust side of the timer entry stubs: run the tick bookkeeping, then, if
/// the interrupt arrived from ring 3, let the user scheduler charge the
/// process and possibly switch or kill it.
extern "C" fn timer_dispatch(frame: &mut crate::process::TrapFrame, vector: u32) {
    if vector == TIMER_INTERRUPT_ID as u32 {
        // fetch_add is atomic and lock-free — safe to call inside an ISR.
        let tick = TICKS.fetch_add(1, AtomicOrdering::Relaxed) + 1;
        // EOI before the hook so the PIC can accept the next interrupt
        // while the preemption callback runs.
        unsafe { send_eoi(0) };
        call_preempt_hook(tick);
    } else {
        // Local APIC timer is per-core, so we read the APIC ID to route
        // runtime service to the currently interrupted CPU.
        let apic_id = current_local_apic_id();
        unsafe { local_apic_eoi() };
        call_local_apic_tick_hook(apic_id);
    }
    if frame.from_user() {
        if let crate::process::TickAction::Kill { pid, ticks } =
            crate::process::on_user_tick(frame)
        {
            crate::syscall::abort_user_killed(pid, ticks);
        }
    }
}

extern "x86-interrupt" fn keyboard_handler(_stack_frame: InterruptStackFrame) {
    // Read and discard the scancode for now — prevents the keyboard
    // controller from locking up (it won't send further interrupts until
    // its output buffer is drained).
    let _scancode: u8 = unsafe { inb(0x60) };
    unsafe { send_eoi(1) };
}

extern "x86-interrupt" fn reschedule_ipi_handler(_stack_frame: InterruptStackFrame) {
    let apic_id = current_local_apic_id();
    unsafe { local_apic_eoi() };
    call_reschedule_ipi_hook(apic_id);
}

extern "x86-interrupt" fn tlb_shootdown_ipi_handler(_stack_frame: InterruptStackFrame) {
    let apic_id = current_local_apic_id();
    unsafe { local_apic_eoi() };
    call_tlb_shootdown_ipi_hook(apic_id);
}

/// Software injection path used by debug scaffolding (`cpu-step-ap`) when an
/// AP's local APIC timer is not yet delivering hardware IRQs.
///
/// Prefer [`crate::local_apic::arm_current_core_runtime_timer`] on the AP so
/// the local APIC timer entry stub drives runtime instead.
pub fn inject_local_apic_timer_tick(apic_id: u32) {
    call_local_apic_tick_hook(apic_id);
}

/// Software injection of a reschedule IPI (console / tests).
pub fn inject_reschedule_ipi(apic_id: u32) {
    call_reschedule_ipi_hook(apic_id);
}

/// Software injection of a TLB shootdown IPI (console / tests).
pub fn inject_tlb_shootdown_ipi(apic_id: u32) {
    call_tlb_shootdown_ipi_hook(apic_id);
}

#[inline]
fn current_local_apic_id() -> u32 {
    #[cfg(target_os = "none")]
    unsafe {
        let reg = (0xFEE0_0000u64 + 0x20) as *const u32;
        (core::ptr::read_volatile(reg) >> 24) & 0xff
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

#[inline]
unsafe fn local_apic_eoi() {
    #[cfg(target_os = "none")]
    {
        let eoi = (0xFEE0_0000u64 + 0xB0) as *mut u32;
        core::ptr::write_volatile(eoi, 0);
    }
}
