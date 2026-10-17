//! FPU/vector isolation check (roadmap 2.6). Run several with `run-all`:
//! each fills all 16 vector registers with a pattern unique to its pid
//! (full 256-bit YMM registers when the CPU and kernel enable AVX), spins
//! long enough to be preempted many times — and moved between CPUs —
//! then checks every register still holds exactly its own pattern. It also
//! computes a floating-point sum with a known result. Exit code: number of
//! failed checks (0 = isolated and correct).

#![no_std]
#![no_main]

use cdk_user::{getpid, println};

const ROUNDS: u32 = 12;
const SPIN: u64 = 4_000_000;

#[repr(C, align(32))]
struct Pattern([u8; 16 * 32]);

fn pattern(pid: u32, round: u32) -> Pattern {
    let mut p = Pattern([0; 16 * 32]);
    for (i, b) in p.0.iter_mut().enumerate() {
        *b = (pid as u8)
            .wrapping_mul(31)
            .wrapping_add(round as u8 * 7)
            .wrapping_add(i as u8);
    }
    p
}

/// Whether AVX is usable (CPUID.1:ECX.AVX and OSXSAVE, and XCR0 enables YMM).
fn avx() -> bool {
    let ecx = core::arch::x86_64::__cpuid(1).ecx;
    if ecx & (1 << 28) == 0 || ecx & (1 << 27) == 0 {
        return false;
    }
    let xcr0: u32;
    unsafe { core::arch::asm!("xgetbv", in("ecx") 0, out("eax") xcr0, out("edx") _) };
    xcr0 & 0b110 == 0b110
}

/// Load XMM0-15 from `p`, spin, and return a bitmask of the registers that
/// no longer match.
fn check_sse(p: &Pattern) -> u32 {
    let bad: u32;
    unsafe {
        core::arch::asm!(
            "movdqa xmm0, [{p}]", "movdqa xmm1, [{p} + 16]", "movdqa xmm2, [{p} + 32]",
            "movdqa xmm3, [{p} + 48]", "movdqa xmm4, [{p} + 64]", "movdqa xmm5, [{p} + 80]",
            "movdqa xmm6, [{p} + 96]", "movdqa xmm7, [{p} + 112]", "movdqa xmm8, [{p} + 128]",
            "movdqa xmm9, [{p} + 144]", "movdqa xmm10, [{p} + 160]", "movdqa xmm11, [{p} + 176]",
            "movdqa xmm12, [{p} + 192]", "movdqa xmm13, [{p} + 208]", "movdqa xmm14, [{p} + 224]",
            "movdqa xmm15, [{p} + 240]",
            "mov {n}, {spin}",
            "2:", "pause", "dec {n}", "jnz 2b",
            "xor {bad:e}, {bad:e}",
            ".irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
            "pcmpeqb xmm\\i, [{p} + 16*\\i]",
            "pmovmskb {t:e}, xmm\\i",
            "cmp {t:e}, 0xFFFF",
            "je 3f",
            "bts {bad:e}, \\i",
            "3:",
            ".endr",
            p = in(reg) p.0.as_ptr(),
            spin = in(reg) SPIN,
            n = out(reg) _,
            bad = out(reg) bad,
            t = out(reg) _,
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
        );
    }
    bad
}

/// The same with full YMM registers (upper 128 bits are AVX state, saved
/// only by XSAVE).
#[target_feature(enable = "avx2")]
unsafe fn check_avx(p: &Pattern) -> u32 {
    let bad: u32;
    core::arch::asm!(
        ".irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
        "vmovdqa ymm\\i, [{p} + 32*\\i]",
        ".endr",
        "mov {n}, {spin}",
        "2:", "pause", "dec {n}", "jnz 2b",
        "xor {bad:e}, {bad:e}",
        ".irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
        "vpcmpeqb ymm\\i, ymm\\i, [{p} + 32*\\i]",
        "vpmovmskb {t:e}, ymm\\i",
        "cmp {t:e}, -1",
        "je 3f",
        "bts {bad:e}, \\i",
        "3:",
        ".endr",
        "vzeroupper",
        p = in(reg) p.0.as_ptr(),
        spin = in(reg) SPIN,
        n = out(reg) _,
        bad = out(reg) bad,
        t = out(reg) _,
        out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
        out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
        out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
        out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
    );
    bad
}

/// `sqrtsd`: hardware square root (`core` has no `f64::sqrt` without std).
#[target_feature(enable = "sse2")]
fn sqrt(x: f64) -> f64 {
    use core::arch::x86_64::{_mm_cvtsd_f64, _mm_set_sd, _mm_sqrt_sd};
    let v = _mm_set_sd(x);
    _mm_cvtsd_f64(_mm_sqrt_sd(v, v))
}

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let pid = getpid();
    let wide = avx();
    let mut failures = 0u64;
    for round in 0..ROUNDS {
        let p = pattern(pid, round);
        let bad = if wide {
            unsafe { check_avx(&p) }
        } else {
            check_sse(&p)
        };
        if bad != 0 {
            failures += 1;
            println!("fpu pid={} round {}: registers changed under us: {:#06x}", pid, round, bad);
        }
    }
    // Hardware floating point: sum of square roots 1..=100000 (sqrtsd).
    let mut sum = 0.0f64;
    for i in 1..=100_000u32 {
        // SAFETY: SSE2 is the target's baseline.
        sum += unsafe { sqrt(core::hint::black_box(i as f64)) };
    }
    let expected = 21_082_008.973_917_74_f64;
    if !(sum - expected < 1e-3 && expected - sum < 1e-3) {
        failures += 1;
        println!("fpu pid={} float sum {} != {}", pid, sum, expected);
    }
    println!(
        "fpu pid={} {}: {} rounds of {} registers, float sum {:.3} — {}",
        pid,
        if wide { "AVX (YMM 256-bit)" } else { "SSE (XMM 128-bit)" },
        ROUNDS,
        16,
        sum,
        if failures == 0 { "isolated" } else { "FAILED" }
    );
    failures
}
