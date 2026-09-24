//! An agent whose handle is approval-gated: each `send` blocks until a
//! human approves or denies it at the kernel console.
//!
//!   cdk> exec requester obj-2 send,approval
//!
//! The kernel shows exactly what will be sent and performs the send only
//! if the human approves; a derived handle cannot shed the constraint.

#![no_std]
#![no_main]

use cdk_user::{cap_derive, cap_drop, cap_list, perm, println, send, CapInfo};

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let mut caps = [CapInfo::default(); 8];
    let n = cap_list(&mut caps).unwrap_or(0);
    let Some(c) = caps[..n.min(caps.len())]
        .iter()
        .find(|c| c.perms & perm::SEND != 0)
    else {
        println!("requester: no send handle (try: exec requester obj-2 send,approval)");
        return 2;
    };
    let h = c.handle;
    println!(
        "requester: handle h{} is {}",
        h,
        if c.perms & perm::APPROVAL != 0 {
            "approval-gated"
        } else {
            "NOT gated"
        }
    );

    // Try to shed the constraint by deriving a "send only" handle.
    if let Ok(d) = cap_derive(h, perm::SEND) {
        let mut again = [CapInfo::default(); 8];
        let m = cap_list(&mut again).unwrap_or(0);
        let gated = again[..m]
            .iter()
            .any(|x| x.handle == d && x.perms & perm::APPROVAL != 0);
        println!("requester: derived h{} still gated: {}", d, gated);
        let _ = cap_drop(d);
    }

    for msg in [
        &b"transfer 5000 to account 1234"[..],
        &b"transfer 99999 to account 6666"[..],
    ] {
        println!(
            "requester: asking to send \"{}\"",
            core::str::from_utf8(msg).unwrap_or("?")
        );
        match send(h, msg) {
            Ok(()) => println!("requester: -> sent (approved)"),
            Err(e) => println!("requester: -> not sent: {:?}", e),
        }
    }
    0
}
