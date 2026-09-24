//! An agent with no grants. Everything it tries must fail: it has no
//! handles, cannot guess one, and cannot mint one.

#![no_std]
#![no_main]

use cdk_user::{cap_derive, cap_list, perm, println, recv, send, CapInfo, Error};

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let mut blocked = 0u64;
    let mut caps = [CapInfo::default(); 4];
    let n = cap_list(&mut caps).unwrap_or(99);
    println!("intruder: holds {} handle(s)", n);
    if n == 0 {
        blocked += 1;
    }
    for h in 0..16 {
        if send(h, b"exfiltrate") == Err(Error::BadHandle) {
            blocked += 1;
        }
    }
    let mut buf = [0u8; 64];
    if recv(0, &mut buf) == Err(Error::BadHandle) {
        blocked += 1;
    }
    if cap_derive(0, perm::SEND | perm::RECV | perm::DELETE) == Err(Error::BadHandle) {
        blocked += 1;
    }
    println!("intruder: {}/19 attempts blocked", blocked);
    // Exit 0 only if everything was blocked.
    19 - blocked
}
