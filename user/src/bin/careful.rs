//! Calls each tool it holds once with fixed arguments and reports the
//! outcome — used to exercise approval-gated tools, gateway allowlists, and
//! the no-link and time-out paths.

#![no_std]
#![no_main]

use cdk_user::{cap_list, perm, println, tool_call, CapInfo};

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let mut caps = [CapInfo::default(); 8];
    let n = cap_list(&mut caps).unwrap_or(0).min(caps.len());
    let mut out = [0u8; 128];
    for c in caps[..n].iter().filter(|c| c.perms & perm::EXEC != 0) {
        let args: &[u8] = br#"{"text":"wire 5000 INR to account 1234","seconds":12}"#;
        let gated = c.perms & perm::APPROVAL != 0;
        match tool_call(c.handle, args, &mut out) {
            Ok((st, len)) => println!(
                "careful: h{}{} -> {:?} \"{}\"",
                c.handle,
                if gated { " (gated)" } else { "" },
                st,
                core::str::from_utf8(&out[..len]).unwrap_or("?")
            ),
            Err(e) => println!(
                "careful: h{}{} -> error {:?}",
                c.handle,
                if gated { " (gated)" } else { "" },
                e
            ),
        }
    }
    0
}
