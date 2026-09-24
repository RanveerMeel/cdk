//! A runaway agent: spins forever without a syscall. The kernel's CPU-budget
//! watchdog must kill it; without preemption it would freeze the machine.

#![no_std]
#![no_main]

use cdk_user::{getpid, println};

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    println!("hog pid={}: spinning forever", getpid());
    let mut x: u64 = 0;
    loop {
        x = core::hint::black_box(x.wrapping_add(1));
    }
}
