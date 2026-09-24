//! First program loaded from the boot ramdisk: exercises .text, .rodata,
//! .data, .bss, formatting, and a multi-page stack.

#![no_std]
#![no_main]

use cdk_user::println;

static GREETING: &str = "Hello from a Rust program loaded from the CDK ramdisk!";
static mut COUNTER: u64 = 0; // .bss
static mut PRIMES: [u64; 4] = [2, 3, 5, 7]; // .data

#[inline(never)]
fn deep(n: u64, pad: &mut [u8; 512]) -> u64 {
    // Each frame holds 512 bytes: 32 levels need ~16 KiB of stack.
    pad[(n % 512) as usize] = n as u8;
    if n == 0 {
        pad.iter().map(|&b| b as u64).sum()
    } else {
        let mut next = [0u8; 512];
        deep(n - 1, &mut next) + pad[(n % 512) as usize] as u64
    }
}

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    println!("{}", GREETING);
    let sum: u64 = unsafe {
        COUNTER += 1;
        PRIMES[3] = 11;
        let primes = &*core::ptr::addr_of!(PRIMES);
        primes.iter().sum::<u64>() + COUNTER
    };
    println!("  .data/.bss ok: sum={} (expect 22)", sum);
    let mut pad = [0u8; 512];
    let depth = deep(32, &mut pad);
    println!("  stack ok: 32 frames x 512 B, checksum={}", depth);
    0
}
