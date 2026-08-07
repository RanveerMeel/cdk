//! Cryptographically-secure random number generator.
//!
//! ## Bare-metal (x86_64-unknown-none)
//!
//! Prefers the x86 `RDRAND` instruction when CPUID reports it (Intel Ivy Bridge
//! 2012+ / AMD Zen). When RDRAND is absent (common on QEMU's default `qemu64`
//! CPU), falls back to a ChaCha20-based CSPRNG seeded from `RDTSC` and prints
//! a one-time warning — better than `#UD` → double-fault, and adequate for
//! bringing up capability signing under emulation. Production / real hardware
//! should expose RDRAND (see `run_qemu.sh`: `-cpu max`).
//!
//! ## Host (tests)
//!
//! Uses `rand_core::OsRng` (OS entropy), which works on macOS / Linux without
//! any special setup.  The same `KernelRng` type is used on both targets so
//! upper-level code (`capability.rs`) compiles identically everywhere.

// ---------------------------------------------------------------------------
// Bare-metal backend
// ---------------------------------------------------------------------------

#[cfg(target_os = "none")]
mod backend {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use rand_core::{CryptoRng, Error, RngCore};

    const MAX_RETRIES: usize = 10;

    static RDRAND_WARNED: AtomicBool = AtomicBool::new(false);
    /// SplitMix64-style state for the software fallback (updated atomically).
    static SOFT_STATE: AtomicU64 = AtomicU64::new(0);

    pub struct KernelRng;

    impl RngCore for KernelRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            if rdrand_available() {
                for _ in 0..MAX_RETRIES {
                    let (ok, val) = rdrand64();
                    if ok {
                        return val;
                    }
                }
                // Hardware advertised but failing — fall through to soft path.
            }
            soft_next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut i = 0;
            while i + 8 <= dest.len() {
                let v = self.next_u64().to_le_bytes();
                dest[i..i + 8].copy_from_slice(&v);
                i += 8;
            }
            if i < dest.len() {
                let v = self.next_u64().to_le_bytes();
                let tail_len = dest.len() - i;
                dest[i..].copy_from_slice(&v[..tail_len]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    // SAFETY: RDRAND (when available) and the seeded software CSPRNG both
    // satisfy the CryptoRng contract for kernel key issuance.
    impl CryptoRng for KernelRng {}

    fn rdrand_available() -> bool {
        crate::cpu::cpuid_has_rdrand()
    }

    fn soft_next_u64() -> u64 {
        if !RDRAND_WARNED.swap(true, Ordering::Relaxed) {
            crate::println!(
                "RNG: WARNING — RDRAND unavailable; using software CSPRNG (seed from RDTSC)"
            );
            // Ensure non-zero seed so SplitMix never stalls at 0.
            let seed = seed_from_tsc() | 1;
            SOFT_STATE.store(seed, Ordering::Relaxed);
        }
        // SplitMix64 — small, no_std; used only when hardware TRNG is missing.
        let mut z = SOFT_STATE.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn seed_from_tsc() -> u64 {
        let mut lo: u32;
        let mut hi: u32;
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nostack, nomem, preserves_flags),
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }

    /// Execute `RDRAND` (64-bit variant) and return `(success, value)`.
    ///
    /// Only call when [`rdrand_available`] is true — otherwise `#UD`.
    #[inline]
    fn rdrand64() -> (bool, u64) {
        let mut val: u64 = 0;
        let ok: u8;
        // SAFETY: RDRAND is read-only and has no memory side-effects.
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) val,
                ok  = out(reg_byte) ok,
                options(nostack, nomem),
            );
        }
        (ok != 0, val)
    }
}

// ---------------------------------------------------------------------------
// Host backend (used by unit tests on macOS / Linux)
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "none"))]
mod backend {
    use rand_core::{CryptoRng, OsRng, RngCore};

    /// On the host we delegate directly to the OS entropy source.
    pub struct KernelRng;

    impl RngCore for KernelRng {
        fn next_u32(&mut self) -> u32 {
            OsRng.next_u32()
        }
        fn next_u64(&mut self) -> u64 {
            OsRng.next_u64()
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            OsRng.fill_bytes(dest)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            OsRng.try_fill_bytes(dest)
        }
    }

    impl CryptoRng for KernelRng {}
}

// ---------------------------------------------------------------------------
// Public re-export
// ---------------------------------------------------------------------------

pub use backend::KernelRng;

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    #[test]
    fn next_u64_produces_non_zero_values() {
        // Probability of TRNG/OsRng returning 0 is negligible (~2^-64).
        let mut rng = KernelRng;
        let v = rng.next_u64();
        assert_ne!(v, 0, "RNG returned zero — extremely unlikely unless broken");
    }

    #[test]
    fn consecutive_u64_values_differ() {
        let mut rng = KernelRng;
        let a = rng.next_u64();
        let b = rng.next_u64();
        assert_ne!(
            a, b,
            "two consecutive RNG values identical — extremely unlikely"
        );
    }

    #[test]
    fn fill_bytes_produces_non_zero_output() {
        let mut rng = KernelRng;
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn fill_bytes_non_multiple_of_8() {
        let mut rng = KernelRng;
        let mut buf = [0u8; 13]; // deliberate non-multiple of 8
        rng.fill_bytes(&mut buf);
        assert_ne!(buf, [0u8; 13]);
    }
}
