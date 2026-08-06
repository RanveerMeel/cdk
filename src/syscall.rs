//! SYSCALL / SYSRET path and ring-3 smoke (M14).

#[cfg(target_os = "none")]
use crate::cpu::{self, EFER_SCE, IA32_EFER, IA32_FMASK, IA32_LSTAR, IA32_STAR};
#[cfg(target_os = "none")]
use crate::percpu::{CPULOCAL_KERNEL_RSP, CPULOCAL_USER_RSP};

pub const SYS_EXIT: u64 = 1;
pub const SYS_WRITE: u64 = 2;

static mut USER_SMOKE_STACK: [u8; 4096] = [0u8; 4096];
static mut USER_SMOKE_CODE: [u8; 64] = [0u8; 64];

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

/// Rust dispatcher. `nr` in rax, arg0 in rdi (SYS_WRITE buffer ignored — prints fixed).
#[no_mangle]
pub extern "C" fn syscall_dispatch(nr: u64, arg0: u64, _arg1: u64) -> u64 {
    match nr {
        SYS_EXIT => {
            crate::println!("Syscall: SYS_exit code={} (user-smoke complete)", arg0);
            // Do not SYSRET — park in kernel.
            #[cfg(target_os = "none")]
            loop {
                unsafe {
                    core::arch::asm!("sti; hlt", options(nomem, nostack, preserves_flags));
                }
            }
            #[cfg(not(target_os = "none"))]
            {
                let _ = arg0;
                0
            }
        }
        SYS_WRITE => {
            crate::println!("Syscall: SYS_write (smoke ok)");
            0
        }
        _ => {
            crate::println!("Syscall: unknown nr={}", nr);
            u64::MAX
        }
    }
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

/// Map a tiny user page that issues `syscall` (SYS_EXIT) and enter ring 3.
pub fn run_user_smoke(
    page_table: &mut crate::paging::PageTableManager,
    frame_alloc: &mut crate::allocator::FrameAllocator,
) -> Result<(), &'static str> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (page_table, frame_alloc);
        crate::println!("user-smoke: host stub OK");
        return Ok(());
    }
    #[cfg(target_os = "none")]
    {
        // User code at 0x40000000: mov eax,1; xor edi,edi; syscall; ud2
        let code: &[u8] = &[
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x31, 0xFF, // xor edi, edi
            0x0F, 0x05, // syscall
            0x0F, 0x0B, // ud2
        ];
        let code_phys = frame_alloc
            .alloc()
            .map_err(|_| "no frame for user code")?
            .base_addr();
        let stack_phys = frame_alloc
            .alloc()
            .map_err(|_| "no frame for user stack")?
            .base_addr();

        let code_virt = 0x4000_0000u64;
        let stack_virt = 0x4000_1000u64;

        let mut aspace = crate::paging::AddressSpace::from_kernel(page_table, frame_alloc)
            .map_err(|_| "address space")?;
        aspace
            .tables()
            .map(
                code_virt,
                code_phys,
                crate::paging::MapFlags::user_rx(),
                frame_alloc,
            )
            .map_err(|_| "map user code")?;
        aspace
            .tables()
            .map(
                stack_virt,
                stack_phys,
                crate::paging::MapFlags::user_rw(),
                frame_alloc,
            )
            .map_err(|_| "map user stack")?;

        unsafe {
            let dst = crate::phys_mem::phys_to_mut_ptr::<u8>(code_phys);
            core::ptr::copy_nonoverlapping(code.as_ptr(), dst, code.len());
            let _ = (&raw mut USER_SMOKE_CODE, &raw mut USER_SMOKE_STACK);
        }

        aspace.activate();

        let user_rsp = stack_virt + 0x1000;
        let user_rip = code_virt;
        let Some((_, ucode, udata)) = crate::gdt::star_selectors() else {
            return Err("no user selectors");
        };

        let kstack = crate::gdt::kernel_stack_top(0).ok_or("no kernel stack")?;
        crate::gdt::set_rsp0(0, kstack);
        crate::percpu::set_kernel_rsp(0, kstack);
        crate::percpu::prepare_user_gs(0);

        crate::println!(
            "user-smoke: entering ring3 rip={:#x} rsp={:#x}",
            user_rip,
            user_rsp
        );

        unsafe {
            enter_user(user_rip, user_rsp, ucode.0 as u64, udata.0 as u64);
        }
    }
}

#[cfg(target_os = "none")]
unsafe fn enter_user(rip: u64, rsp: u64, user_cs: u64, user_ss: u64) -> ! {
    // iretq frame: SS, RSP, RFLAGS, CS, RIP
    core::arch::asm!(
        "mov ax, {uss:x}",
        "mov ds, ax",
        "mov es, ax",
        "push {uss}",
        "push {ursp}",
        "push {rflags}",
        "push {ucs}",
        "push {urip}",
        "iretq",
        uss = in(reg) user_ss,
        ursp = in(reg) rsp,
        rflags = in(reg) 0x202u64,
        ucs = in(reg) user_cs,
        urip = in(reg) rip,
        options(noreturn),
    );
}
