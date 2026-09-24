//! SYSCALL / SYSRET path, ring-3 entry/return, and ring-3 smoke (M14).
//!
//! [`run_user`] saves the calling kernel context, switches `CR3` to the user
//! address space and `iretq`s into ring 3. `SYS_exit` restores that context,
//! so `run_user` returns the exit code to its caller (e.g. the console).

#[cfg(target_os = "none")]
use crate::cpu::{self, EFER_SCE, IA32_EFER, IA32_FMASK, IA32_LSTAR, IA32_STAR};
#[cfg(target_os = "none")]
use crate::percpu::{CPULOCAL_KERNEL_RSP, CPULOCAL_USER_RSP};

pub const SYS_EXIT: u64 = 1;
pub const SYS_WRITE: u64 = 2;

/// Largest buffer a single `SYS_write` will copy from user space.
pub const MAX_WRITE_LEN: usize = 1024;
/// Returned in `rax` for a failed syscall (`-1` as `i64`).
pub const SYSCALL_ERR: u64 = u64::MAX;

/// Install EFER.SCE + STAR/LSTAR/FMASK for 64-bit SYSCALL.
pub fn init() {
    #[cfg(target_os = "none")]
    {
        let Some((kcode, ucode, _udata)) = crate::gdt::star_selectors() else {
            crate::println!("Syscall: WARNING — GDT selectors missing");
            return;
        };
        // STAR[47:32] = kernel CS (SYSCALL). STAR[63:48] = SYSRET base such that
        // CS = base+16 and SS = base+8 (Intel SDM). With user_data then user_code
        // in the GDT, base = user_code - 16.
        let star_user = (ucode.0 as u64).wrapping_sub(16);
        let star = (star_user << 48) | ((kcode.0 as u64) << 32);
        cpu::wrmsr(IA32_STAR, star);
        cpu::wrmsr(IA32_LSTAR, syscall_entry_shim as *const () as usize as u64);
        // Clear IF and DF on entry.
        cpu::wrmsr(IA32_FMASK, 0x200 | 0x400);
        let efer = cpu::rdmsr(IA32_EFER) | EFER_SCE;
        cpu::wrmsr(IA32_EFER, efer);
        crate::println!(
            "Syscall: SCE enabled LSTAR={:#x}",
            syscall_entry_shim as *const () as usize
        );
    }
}

/// Rust dispatcher: `nr` in rax, `arg0` in rdi, `arg1` in rsi.
#[no_mangle]
pub extern "C" fn syscall_dispatch(nr: u64, arg0: u64, arg1: u64) -> u64 {
    match nr {
        SYS_EXIT => {
            crate::process::mark_exit(arg0);
            crate::println!("Syscall: SYS_exit code={}", arg0);
            #[cfg(target_os = "none")]
            {
                // Return to the kernel context that entered ring 3.
                if let Some(slot) = resume::take_armed(current_slot()) {
                    unsafe { resume::resume(slot, arg0) }
                }
                // No saved context (should not happen): park this CPU.
                loop {
                    unsafe {
                        core::arch::asm!("sti; hlt", options(nomem, nostack, preserves_flags));
                    }
                }
            }
            #[cfg(not(target_os = "none"))]
            0
        }
        SYS_WRITE => sys_write(arg0, arg1),
        _ => {
            crate::println!("Syscall: unknown nr={}", nr);
            SYSCALL_ERR
        }
    }
}

/// Terminate the ring-3 program that raised `fault` and resume the kernel
/// context that entered it (as `SYS_exit` does). Called from CPU exception
/// handlers only when the fault came from ring 3.
#[cfg(target_os = "none")]
pub fn abort_user(fault: crate::process::UserFault) -> ! {
    // The exception arrived through an interrupt gate, which (unlike the
    // SYSCALL stub) does not swap GS: GS_BASE still holds the user value and
    // KERNEL_GS_BASE the CpuLocal pointer. Swap back before anything else.
    unsafe { core::arch::asm!("swapgs", options(nomem, nostack, preserves_flags)) };
    crate::process::mark_crashed(fault);
    crate::println!(
        "Fault: {} in ring 3 at rip={:#x} addr={:#x} err={:#x} — process terminated",
        fault.name(),
        fault.rip,
        fault.addr,
        fault.error_code
    );
    if let Some(slot) = resume::take_armed(current_slot()) {
        unsafe { resume::resume(slot, fault.exit_code()) }
    }
    // No saved context (should not happen): park this CPU.
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

/// `SYS_write(ptr, len)`: print `len` bytes of user memory at `ptr` to the
/// console. Returns the byte count, or [`SYSCALL_ERR`] if the buffer is too
/// long or any byte of it is not mapped user memory.
fn sys_write(ptr: u64, len: u64) -> u64 {
    if len as usize > MAX_WRITE_LEN {
        return SYSCALL_ERR;
    }
    let mut buf = [0u8; MAX_WRITE_LEN];
    let buf = &mut buf[..len as usize];
    let pt = crate::paging::PageTableManager::from_pml4_phys(current_cr3());
    if pt.copy_from_user(ptr, buf).is_err() {
        return SYSCALL_ERR;
    }
    for chunk in buf.utf8_chunks() {
        crate::print!("{}", chunk.valid());
        if !chunk.invalid().is_empty() {
            crate::print!("\u{FFFD}");
        }
    }
    len
}

fn current_cr3() -> u64 {
    #[cfg(target_os = "none")]
    {
        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }
        cr3 & !0xfff
    }
    #[cfg(not(target_os = "none"))]
    0
}

/// Topology slot of the executing CPU (0 before topology is known).
fn current_slot() -> usize {
    crate::percpu::slot_for_apic(crate::percpu::current_apic_id()).unwrap_or(0)
}

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .global syscall_entry_shim
    .type syscall_entry_shim, @function
    syscall_entry_shim:
        // SYSCALL leaves RSP = user RSP. Switch to kernel stack before any
        // push/call (SMAP / USER pages are not a safe ring-0 stack).
        swapgs
        mov gs:[{user_rsp}], rsp
        mov rsp, gs:[{kernel_rsp}]
        push rcx
        push r11
        mov rdx, rsi
        mov rsi, rdi
        mov rdi, rax
        call syscall_dispatch
        pop r11
        pop rcx
        mov rsp, gs:[{user_rsp}]
        swapgs
        sysretq
    "#,
    kernel_rsp = const CPULOCAL_KERNEL_RSP,
    user_rsp = const CPULOCAL_USER_RSP,
);

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn syscall_entry_shim();
}

#[cfg(not(target_os = "none"))]
fn syscall_entry_shim() {}

#[cfg(target_os = "none")]
mod resume {
    //! Saved kernel context for returning from ring 3 (one per CPU slot).

    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicBool, Ordering};

    use crate::percpu::MAX_CPUS;

    /// Callee-saved registers, stack, flags and `CR3` at the `run_user` call.
    /// Field offsets are hard-coded in the assembly below.
    #[repr(C)]
    pub struct KernelResume {
        r15: u64,
        r14: u64,
        r13: u64,
        r12: u64,
        rbx: u64,
        rbp: u64,
        rsp: u64,
        rflags: u64,
        cr3: u64,
    }

    struct Slot(UnsafeCell<KernelResume>);
    // SAFETY: each slot is only touched by its own CPU, gated by `ARMED`.
    unsafe impl Sync for Slot {}

    static SLOTS: [Slot; MAX_CPUS] = [const {
        Slot(UnsafeCell::new(KernelResume {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            rbp: 0,
            rsp: 0,
            rflags: 0,
            cr3: 0,
        }))
    }; MAX_CPUS];
    static ARMED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

    core::arch::global_asm!(
        r#"
        // u64 cdk_user_enter(ctx, rip, rsp, cs, ss, cr3)
        //   rdi=ctx rsi=rip rdx=rsp rcx=cs r8=ss r9=cr3
        // Saves the kernel context, then iretq's into ring 3. Returns only
        // via cdk_user_resume, with the exit code in rax.
        .global cdk_user_enter
        .type cdk_user_enter, @function
        cdk_user_enter:
            mov [rdi + 0x00], r15
            mov [rdi + 0x08], r14
            mov [rdi + 0x10], r13
            mov [rdi + 0x18], r12
            mov [rdi + 0x20], rbx
            mov [rdi + 0x28], rbp
            mov [rdi + 0x30], rsp
            pushfq
            pop rax
            mov [rdi + 0x38], rax
            mov rax, cr3
            mov [rdi + 0x40], rax
            mov cr3, r9
            mov ax, r8w
            mov ds, ax
            mov es, ax
            push r8
            push rdx
            push 0x202
            push rcx
            push rsi
            iretq

        // ! cdk_user_resume(ctx, code)  —  rdi=ctx rsi=code
        // Restores the context saved by cdk_user_enter and returns `code`
        // from it. Called on the syscall kernel stack after swapgs.
        .global cdk_user_resume
        .type cdk_user_resume, @function
        cdk_user_resume:
            mov rax, [rdi + 0x40]
            mov cr3, rax
            xor eax, eax
            mov ds, ax
            mov es, ax
            mov r15, [rdi + 0x00]
            mov r14, [rdi + 0x08]
            mov r13, [rdi + 0x10]
            mov r12, [rdi + 0x18]
            mov rbx, [rdi + 0x20]
            mov rbp, [rdi + 0x28]
            mov rsp, [rdi + 0x30]
            push qword ptr [rdi + 0x38]
            popfq
            mov rax, rsi
            ret
        "#
    );

    unsafe extern "C" {
        fn cdk_user_enter(
            ctx: *mut KernelResume,
            rip: u64,
            rsp: u64,
            cs: u64,
            ss: u64,
            cr3: u64,
        ) -> u64;
        fn cdk_user_resume(ctx: *const KernelResume, code: u64) -> !;
    }

    /// Enter ring 3 on `slot` and block until the program calls `SYS_exit`.
    ///
    /// # Safety
    /// `cr3` must map `rip`/`rsp` as user pages and share the kernel mappings;
    /// selectors must be ring-3; per-CPU syscall state must be prepared.
    pub unsafe fn enter(slot: usize, rip: u64, rsp: u64, cs: u64, ss: u64, cr3: u64) -> u64 {
        ARMED[slot].store(true, Ordering::Release);
        let code = cdk_user_enter(SLOTS[slot].0.get(), rip, rsp, cs, ss, cr3);
        ARMED[slot].store(false, Ordering::Release);
        code
    }

    /// Claim the saved context for `slot` if one is armed.
    pub fn take_armed(slot: usize) -> Option<usize> {
        (slot < MAX_CPUS && ARMED[slot].swap(false, Ordering::AcqRel)).then_some(slot)
    }

    /// # Safety
    /// `slot` must have been returned by [`take_armed`] on this CPU.
    pub unsafe fn resume(slot: usize, code: u64) -> ! {
        cdk_user_resume(SLOTS[slot].0.get(), code)
    }
}

/// Run user code at `rip`/`rsp` in address space `pml4_phys` until it calls
/// `SYS_exit`, then return its exit code. Kernel `CR3` is restored on return.
pub fn run_user(rip: u64, rsp: u64, pml4_phys: u64) -> Result<u64, &'static str> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (rip, rsp, pml4_phys);
        // Host stub: behave as if the program exited immediately with 0.
        crate::process::mark_exit(0);
        Ok(0)
    }
    #[cfg(target_os = "none")]
    {
        let Some((_, ucode, udata)) = crate::gdt::star_selectors() else {
            return Err("no user selectors");
        };
        let apic = crate::percpu::current_apic_id();
        let slot = crate::percpu::slot_for_apic(apic).unwrap_or(0);
        let kstack = crate::gdt::kernel_stack_top(apic).ok_or("no kernel stack")?;
        crate::gdt::set_rsp0(apic, kstack);
        crate::percpu::set_kernel_rsp(slot, kstack);
        crate::percpu::prepare_user_gs(slot);
        // SAFETY: caller provides a user address space built by `AddressSpace`.
        let code =
            unsafe { resume::enter(slot, rip, rsp, ucode.0 as u64, udata.0 as u64, pml4_phys) };
        Ok(code)
    }
}

/// Map a tiny user program that issues `SYS_exit(0)`, run it, and tear the
/// address space down again.
pub fn run_user_smoke(
    page_table: &mut crate::paging::PageTableManager,
    frame_alloc: &mut crate::allocator::FrameAllocator,
) -> Result<(), &'static str> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (page_table, frame_alloc);
        crate::println!("user-smoke: host stub OK");
        Ok(())
    }
    #[cfg(target_os = "none")]
    {
        use crate::paging::{AddressSpace, MapFlags, USER_BASE};

        // mov eax,1; xor edi,edi; syscall; ud2
        let code: &[u8] = &[
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x31, 0xFF, // xor edi, edi
            0x0F, 0x05, // syscall
            0x0F, 0x0B, // ud2
        ];
        let code_virt = USER_BASE;
        let stack_virt = USER_BASE + 0x1000;

        let mut aspace =
            AddressSpace::from_kernel(page_table, frame_alloc).map_err(|_| "address space")?;
        let mapped = (|| {
            let mut map_page = |virt: u64, flags: MapFlags| -> Result<u64, &'static str> {
                let phys = frame_alloc.alloc().map_err(|_| "no frame for user page")?;
                if aspace
                    .map_user(virt, phys.base_addr(), flags, frame_alloc)
                    .is_err()
                {
                    let _ = frame_alloc.free(phys);
                    return Err("map user page");
                }
                Ok(phys.base_addr())
            };
            let code_phys = map_page(code_virt, MapFlags::user_rx())?;
            map_page(stack_virt, MapFlags::user_rw())?;
            unsafe {
                let dst = crate::phys_mem::phys_to_mut_ptr::<u8>(code_phys);
                core::ptr::copy_nonoverlapping(code.as_ptr(), dst, code.len());
            }
            Ok(())
        })();
        let result = mapped.and_then(|()| {
            crate::println!("user-smoke: entering ring3 rip={:#x}", code_virt);
            run_user(code_virt, stack_virt + 0x1000, aspace.pml4_phys())
        });
        let freed = aspace.destroy(frame_alloc);
        let code = result?;
        crate::println!("user-smoke: returned exit={} freed_frames={}", code, freed);
        Ok(())
    }
}
