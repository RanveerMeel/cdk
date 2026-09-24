//! Low-level CPU helpers: MSRs, GS-base, and APIC-mode probes.

/// IA32_APIC_BASE MSR.
pub const IA32_APIC_BASE: u32 = 0x1B;
/// Enable x2APIC mode in IA32_APIC_BASE.
pub const APIC_BASE_X2APIC_ENABLE: u64 = 1 << 10;
/// APIC global enable in IA32_APIC_BASE.
pub const APIC_BASE_GLOBAL_ENABLE: u64 = 1 << 11;

/// IA32_EFER MSR.
pub const IA32_EFER: u32 = 0xC000_0080;
/// System Call Extensions (SCE) bit in EFER.
pub const EFER_SCE: u64 = 1 << 0;
/// Long Mode Enable / Active bits (informational).
pub const EFER_LME: u64 = 1 << 8;
pub const EFER_LMA: u64 = 1 << 10;
pub const EFER_NXE: u64 = 1 << 11;

/// IA32_STAR — SYSRET/SYSCALL segment selectors.
pub const IA32_STAR: u32 = 0xC000_0081;
/// IA32_LSTAR — SYSCALL 64-bit entry RIP.
pub const IA32_LSTAR: u32 = 0xC000_0082;
/// IA32_FMASK / SFMASK — RFLAGS mask on SYSCALL.
pub const IA32_FMASK: u32 = 0xC000_0084;

/// IA32_GS_BASE — kernel percpu pointer while in ring 0.
pub const IA32_GS_BASE: u32 = 0xC000_0101;
/// IA32_KERNEL_GS_BASE — swapped via SWAPGS on syscall entry.
pub const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// x2APIC MSR base (register = 0x800 + mmio_offset/0x10).
pub const X2APIC_MSR_BASE: u32 = 0x800;

#[inline]
pub fn rdmsr(msr: u32) -> u64 {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    unsafe {
        let low: u32;
        let high: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags),
        );
        ((high as u64) << 32) | low as u64
    }
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    {
        let _ = msr;
        0
    }
}

#[inline]
pub fn wrmsr(msr: u32, value: u64) {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    unsafe {
        let low = value as u32;
        let high = (value >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    {
        let _ = (msr, value);
    }
}

/// CPUID leaf 1: EBX bits 31:24 = initial local APIC id of the executing CPU.
///
/// Safe to call before any LAPIC MMIO mapping exists (unlike reading
/// `0xFEE0_0020`), so boot topology code can identify the BSP early.
pub fn cpuid_apic_id() -> u32 {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    unsafe {
        let ebx_out: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "mov {out:e}, ebx",
            "pop rbx",
            out = out(reg) ebx_out,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags),
        );
        ebx_out >> 24
    }
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    {
        0
    }
}

/// CPUID leaf 1: ECX bit 30 = RDRAND.
/// Read the CPU timestamp counter (0 on the host).
pub fn rdtsc() -> u64 {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        let lo: u32;
        let hi: u32;
        // SAFETY: RDTSC only reads the timestamp counter.
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags)
            );
        }
        ((hi as u64) << 32) | lo as u64
    }
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    0
}

pub fn cpuid_has_rdrand() -> bool {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    unsafe {
        let mut ecx: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("eax") _,
            out("ecx") ecx,
            out("edx") _,
            options(nostack, preserves_flags),
        );
        (ecx & (1 << 30)) != 0
    }
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    {
        false
    }
}

/// CPUID leaf 1: ECX bit 21 = x2APIC.
pub fn cpuid_has_x2apic() -> bool {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    unsafe {
        let mut ecx: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("eax") _,
            out("ecx") ecx,
            out("edx") _,
            options(nostack, preserves_flags),
        );
        (ecx & (1 << 21)) != 0
    }
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    {
        false
    }
}

/// Write `IA32_GS_BASE` so `gs:` relative addressing hits `ptr`.
pub fn set_gs_base(ptr: u64) {
    wrmsr(IA32_GS_BASE, ptr);
}

pub fn gs_base() -> u64 {
    rdmsr(IA32_GS_BASE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_msr_helpers_are_noops() {
        assert_eq!(rdmsr(IA32_GS_BASE), 0);
        wrmsr(IA32_GS_BASE, 0x1234);
        assert!(!cpuid_has_x2apic());
    }
}
