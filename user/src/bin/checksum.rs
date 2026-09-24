//! Computes FNV-1a over a buffer and reports it — a small, deterministic
//! "agent" workload whose exit code is verifiable from the kernel console.

#![no_std]
#![no_main]

use cdk_user::println;

const DATA: &[u8] =
    b"CDK agents run in ring 3 under kernel-issued, post-quantum-signed capabilities.";

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let h = fnv1a(DATA);
    println!("checksum: fnv1a({} bytes) = {:#018x}", DATA.len(), h);
    // Exit with the low byte so the kernel console shows a checkable value.
    h & 0xff
}
