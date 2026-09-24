//! Recurses until it runs off the bottom of its 64 KiB stack. The page below
//! the stack is unmapped, so the kernel sees a #PF in ring 3, terminates this
//! program, and keeps running.

#![no_std]
#![no_main]

use cdk_user::println;

// Unbounded on purpose: the point is to hit the stack guard page.
#[allow(unconditional_recursion)]
#[inline(never)]
fn recurse(depth: u64) -> u64 {
    let frame = core::hint::black_box([depth as u8; 1024]);
    if depth.is_multiple_of(16) {
        println!("overflow: depth {} (~{} KiB of stack)", depth, depth);
    }
    recurse(depth + 1) + frame[0] as u64
}

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    recurse(1)
}
