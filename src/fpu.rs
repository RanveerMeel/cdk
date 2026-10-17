//! Per-agent FPU / SSE / AVX state (roadmap 2.6).
//!
//! Agents may use the x87 FPU and the vector registers; the kernel never
//! does (its target disables MMX/SSE, and `tools/check_kernel_no_simd.sh`
//! checks the built kernel in CI). So the registers always belong to the
//! agent that ran last on a CPU, and the kernel switches them only when it
//! switches agents:
//!
//! * every process slot has a save area, reset to the initial state
//!   ([`reset`]) when a process is created — no agent sees another's values;
//! * entering an agent ([`restore`]) loads its area; preemption, blocking or
//!   migration saves the outgoing agent's registers ([`save`]) first.
//!
//! [`init_cpu`] enables the state on each CPU (CR0.MP|NE, CR4.OSFXSR,
//! OSXMMEXCPT, OSXSAVE) with XCR0 = x87 | SSE | AVX, plus AVX-512 when the
//! CPU has it and its state fits in [`AREA_SIZE`]. Without XSAVE it falls
//! back to FXSAVE (x87 + SSE). Floating-point exceptions stay masked by
//! default; an agent that unmasks and raises one (#MF, #XM) is terminated
//! like any other ring-3 fault.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use spin::Mutex;

use crate::process::MAX_PROCESSES;

/// Bytes per save area (XSAVE needs ~2.7 KiB with AVX-512).
pub const AREA_SIZE: usize = 4096;

/// x87 | SSE | AVX | AVX-512 (opmask, ZMM_Hi256, Hi16_ZMM).
const XCR0_X87_SSE_AVX: u64 = 0b111;
const XCR0_AVX512: u64 = 0b1110_0000;

#[repr(C, align(64))]
pub struct Area([u8; AREA_SIZE]);

impl Area {
    /// Initial state: FCW 0x037F and MXCSR 0x1F80 (all exceptions masked),
    /// everything else zero; an XSAVE header of zeros (XSTATE_BV = 0) makes
    /// XRSTOR put every component in its initial state.
    const fn initial() -> Self {
        let mut a = [0u8; AREA_SIZE];
        a[0] = 0x7F;
        a[1] = 0x03;
        a[24] = 0x80;
        a[25] = 0x1F;
        Area(a)
    }
}

static AREAS: [Mutex<Area>; MAX_PROCESSES] =
    [const { Mutex::new(Area::initial()) }; MAX_PROCESSES];

static READY: AtomicBool = AtomicBool::new(false);
static USE_XSAVE: AtomicBool = AtomicBool::new(false);
/// Components enabled in XCR0 (same on every CPU).
static XCR0: AtomicU64 = AtomicU64::new(0);
/// Bytes of the save area in use (CPUID.0xD.0:EBX for XCR0).
static SIZE: AtomicUsize = AtomicUsize::new(512);

/// Whether agents have their own FPU/vector state (false: no FXSR).
pub fn enabled() -> bool {
    READY.load(Ordering::Acquire)
}

/// `(xsave?, XCR0, bytes)` for reports.
pub fn summary() -> (bool, u64, usize) {
    (
        USE_XSAVE.load(Ordering::Acquire),
        XCR0.load(Ordering::Acquire),
        SIZE.load(Ordering::Acquire),
    )
}

/// Enable FPU/SSE/AVX state on this CPU. The bootstrap CPU decides the
/// feature set (`bsp = true`); APs apply the same one.
pub fn init_cpu(bsp: bool) {
    #[cfg(target_os = "none")]
    unsafe {
        use core::arch::x86_64::__cpuid_count;
        let leaf1 = __cpuid_count(1, 0);
        let fxsr = leaf1.edx & (1 << 24) != 0;
        let xsave = leaf1.ecx & (1 << 26) != 0;
        if !fxsr {
            return; // agents stay soft-float
        }
        let mut cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 &= !((1 << 2) | (1 << 3)); // EM, TS off: no emulation, no lazy traps
        cr0 |= (1 << 1) | (1 << 5); // MP, NE: native FPU error reporting
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= (1 << 9) | (1 << 10); // OSFXSR, OSXMMEXCPT
        if xsave {
            cr4 |= 1 << 18; // OSXSAVE
        }
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
        if xsave {
            let xcr0 = if bsp {
                let leaf_d = __cpuid_count(0xD, 0);
                let supported = leaf_d.eax as u64 | (leaf_d.edx as u64) << 32;
                let mut want = supported & XCR0_X87_SSE_AVX;
                if supported & XCR0_AVX512 == XCR0_AVX512 && want & 0b100 != 0 {
                    want |= XCR0_AVX512;
                }
                xsetbv(want);
                if __cpuid_count(0xD, 0).ebx as usize > AREA_SIZE {
                    want &= !XCR0_AVX512;
                    xsetbv(want);
                }
                XCR0.store(want, Ordering::Release);
                SIZE.store(__cpuid_count(0xD, 0).ebx as usize, Ordering::Release);
                USE_XSAVE.store(true, Ordering::Release);
                want
            } else {
                XCR0.load(Ordering::Acquire)
            };
            if !bsp {
                xsetbv(xcr0);
            }
        }
        if bsp {
            READY.store(true, Ordering::Release);
        }
    }
    #[cfg(not(target_os = "none"))]
    let _ = bsp;
}

#[cfg(target_os = "none")]
#[target_feature(enable = "xsave")]
unsafe fn xsetbv(value: u64) {
    core::arch::asm!(
        "xsetbv",
        in("ecx") 0u32,
        in("eax") value as u32,
        in("edx") (value >> 32) as u32,
        options(nomem, nostack, preserves_flags)
    );
}

/// Give process slot `slot` the initial state (a new process).
pub fn reset(slot: usize) {
    if let Some(a) = AREAS.get(slot) {
        *a.lock() = Area::initial();
    }
}

/// Save this CPU's registers into slot `slot` (its agent is leaving the CPU).
pub fn save(slot: usize) {
    if !enabled() {
        return;
    }
    let Some(a) = AREAS.get(slot) else {
        return;
    };
    let mut area = a.lock();
    #[cfg(target_os = "none")]
    unsafe {
        if USE_XSAVE.load(Ordering::Relaxed) {
            xsave(area.0.as_mut_ptr());
        } else {
            fxsave(area.0.as_mut_ptr());
        }
    }
    #[cfg(not(target_os = "none"))]
    let _ = &mut area;
}

/// Load slot `slot` into this CPU's registers (its agent is about to run).
pub fn restore(slot: usize) {
    if !enabled() {
        return;
    }
    let Some(a) = AREAS.get(slot) else {
        return;
    };
    let area = a.lock();
    #[cfg(target_os = "none")]
    unsafe {
        if USE_XSAVE.load(Ordering::Relaxed) {
            xrstor(area.0.as_ptr());
        } else {
            fxrstor(area.0.as_ptr());
        }
    }
    #[cfg(not(target_os = "none"))]
    let _ = &area;
}

#[cfg(target_os = "none")]
#[target_feature(enable = "xsave")]
unsafe fn xsave(p: *mut u8) {
    core::arch::asm!("xsave64 [{}]", in(reg) p, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack, preserves_flags));
}

#[cfg(target_os = "none")]
#[target_feature(enable = "xsave")]
unsafe fn xrstor(p: *const u8) {
    core::arch::asm!("xrstor64 [{}]", in(reg) p, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack, preserves_flags));
}

#[cfg(target_os = "none")]
#[target_feature(enable = "fxsr")]
unsafe fn fxsave(p: *mut u8) {
    core::arch::asm!("fxsave64 [{}]", in(reg) p, options(nostack, preserves_flags));
}

#[cfg(target_os = "none")]
#[target_feature(enable = "fxsr")]
unsafe fn fxrstor(p: *const u8) {
    core::arch::asm!("fxrstor64 [{}]", in(reg) p, options(nostack, preserves_flags));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_area_is_a_valid_clean_state() {
        let a = Area::initial();
        assert_eq!(u16::from_le_bytes([a.0[0], a.0[1]]), 0x037F, "FCW: exceptions masked");
        assert_eq!(u32::from_le_bytes(a.0[24..28].try_into().unwrap()), 0x1F80, "MXCSR default");
        assert!(a.0[512..576].iter().all(|&b| b == 0), "XSAVE header: initial state");
        assert_eq!(core::mem::align_of::<Area>(), 64);
    }

    #[test]
    fn reset_clears_a_slot() {
        AREAS[3].lock().0[100] = 0xAA;
        reset(3);
        assert_eq!(AREAS[3].lock().0[100], 0);
        reset(MAX_PROCESSES); // out of range: ignored
    }
}
