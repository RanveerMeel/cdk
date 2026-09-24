//! A well-behaved agent: uses the handle it was granted, and shows that the
//! kernel enforces capability rules. Run it with a handle, e.g.
//! `exec agent obj-2 send,recv`. Exits 0 only if every rule held.

#![no_std]
#![no_main]

use cdk_user::{cap_derive, cap_drop, cap_list, perm, println, recv, send, CapInfo, Error};

fn check(ok: bool, what: &str, failures: &mut u64) {
    println!("  [{}] {}", if ok { "ok" } else { "FAIL" }, what);
    if !ok {
        *failures += 1;
    }
}

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let mut failures = 0;
    let mut caps = [CapInfo::default(); 8];
    let n = cap_list(&mut caps).unwrap_or(0);
    println!("agent: holds {} handle(s)", n);
    for c in &caps[..n.min(caps.len())] {
        println!("  h{} perms={:#x}", c.handle, c.perms);
    }
    let Some(h) = caps[..n]
        .iter()
        .find(|c| c.perms & perm::SEND != 0)
        .map(|c| c.handle)
    else {
        println!("agent: no send handle granted (try: exec agent obj-2 send,recv)");
        return 2;
    };

    let task = b"task: triage fraud case 42";
    check(
        send(h, task).is_ok(),
        "send through granted handle",
        &mut failures,
    );

    let mut buf = [0u8; 64];
    match recv(h, &mut buf) {
        Ok(len) => {
            let text = core::str::from_utf8(&buf[..len]).unwrap_or("?");
            check(
                &buf[..len] == task,
                "recv returns the message",
                &mut failures,
            );
            println!("       got \"{}\"", text);
        }
        Err(e) => {
            println!("       recv error {:?}", e);
            check(false, "recv returns the message", &mut failures);
        }
    }
    check(
        recv(h, &mut buf) == Err(Error::Empty),
        "queue is now empty",
        &mut failures,
    );

    // Attenuation: a receive-only child can't send.
    match cap_derive(h, perm::RECV) {
        Ok(ro) => {
            check(true, "derive a receive-only handle", &mut failures);
            check(
                send(ro, b"x") == Err(Error::Denied),
                "receive-only handle cannot send",
                &mut failures,
            );
            check(
                cap_drop(ro).is_ok(),
                "drop the derived handle",
                &mut failures,
            );
            check(
                send(ro, b"x") == Err(Error::BadHandle),
                "dropped handle is gone",
                &mut failures,
            );
        }
        Err(e) => {
            println!("       derive error {:?}", e);
            check(false, "derive a receive-only handle", &mut failures);
        }
    }

    // Escalation: asking for a permission the parent lacks is refused.
    check(
        cap_derive(h, perm::SEND | perm::DELETE) == Err(Error::Denied),
        "derive cannot add DELETE",
        &mut failures,
    );
    check(
        send(15, b"x") == Err(Error::BadHandle),
        "unknown handle is rejected",
        &mut failures,
    );
    check(
        send(h, &[0u8; 65]) == Err(Error::Invalid),
        "oversized message is rejected",
        &mut failures,
    );

    println!("agent: {} rule(s) violated", failures);
    failures
}
