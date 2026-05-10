//! Cryptographically-secure random number generator.
//!
//! ## Bare-metal (x86_64-unknown-none)
//!
//! Uses the x86 `RDRAND` instruction, which is a hardware TRNG present on
//! Intel Ivy Bridge (2012+) and all AMD Zen processors.  The instruction is
//! retried up to `MAX_RETRIES` times; if it never yields a valid sample the
//! kernel panics — absence of a working RNG means capability signing is
//! impossible and it is safer to halt than to silently produce weak keys.
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
    use rand_core::{CryptoRng, Error, RngCore};

    const MAX_RETRIES: usize = 10;

    pub struct KernelRng;

    impl RngCore for KernelRng {
        fn next_u32(&mut self) -> u32 {
            for _ in 0..MAX_RETRIES {
                let (ok, val) = rdrand32();
                if ok { return val; }
            }
            panic!("RDRAND failed after {} retries — hardware RNG unavailable", MAX_RETRIES);
        }

        fn next_u64(&mut self) -> u64 {
            for _ in 0..MAX_RETRIES {
                let (ok, val) = rdrand64();
                if ok { return val; }
            }
            panic!("RDRAND failed after {} retries — hardware RNG unavailable", MAX_RETRIES);
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
                dest[i..].copy_from_slice(&v[..dest.len() - i]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    // SAFETY: RDRAND produces independent, cryptographically-secure values;
    // it satisfies the CryptoRng contract.
    impl CryptoRng for KernelRng {}

    /// Execute `RDRAND` (32-bit variant) and return `(success, value)`.
    #[inline]
    fn rdrand32() -> (bool, u32) {
        let mut val: u32 = 0;
        let ok: u8;
        // SAFETY: RDRAND is read-only and has no memory side-effects.
        unsafe {
            core::arch::asm!(
                "rdrand {val:e}",
                "setc {ok}",
                val = out(reg) val,
                ok  = out(reg_byte) ok,
                options(nostack, nomem),
            );
        }
        (ok != 0, val)
    }

    /// Execute `RDRAND` (64-bit variant) and return `(success, value)`.
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
        fn next_u32(&mut self) -> u32 { OsRng.next_u32() }
        fn next_u64(&mut self) -> u64 { OsRng.next_u64() }
        fn fill_bytes(&mut self, dest: &mut [u8]) { OsRng.fill_bytes(dest) }
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
        assert_ne!(a, b, "two consecutive RNG values identical — extremely unlikely");
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
