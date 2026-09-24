//! CPU-bound worker that never yields. Run two or more with `run-all`: their
//! progress lines interleave only because the kernel preempts them.

#![no_std]
#![no_main]

use cdk_user::{getpid, println};

const STEPS: u64 = 5;
const WORK_PER_STEP: u64 = 60_000_000;

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let pid = getpid();
    let mut acc: u64 = pid as u64;
    for step in 1..=STEPS {
        for i in 0..WORK_PER_STEP {
            acc = core::hint::black_box(acc.wrapping_mul(6364136223846793005).wrapping_add(i));
        }
        println!("spin pid={} step {}/{}", pid, step, STEPS);
    }
    println!("spin pid={} done (acc={:#x})", pid, acc & 0xffff);
    pid as u64
}
