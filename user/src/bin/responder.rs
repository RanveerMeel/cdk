//! Fraud-response agent (fraud-prevention demo, `tools/demo_fraud.sh`).
//!
//! For each alert from triage: freeze the payee account, then request a
//! refund to the victim from the bank's suspense account. Both tools are
//! approval-gated: the policy asks one operator signature for a freeze
//! (`quorum account-action 1`) and two for any money movement (`quorum
//! money-movement 2`); a single signed denial vetoes. Handles, in order:
//!   h0 recv on alerts
//!   h1 exec,approval on tool:freeze_account
//!   h2 exec,approval on tool:wire_transfer

#![no_std]
#![no_main]

use core::fmt::Write as _;

use cdk_user::{cap_list, perm, println, recv, tool_call, CapInfo, Error, StrBuf, ToolStatus};

static mut OUT: [u8; 512] = [0; 512];

fn act(what: &str, handle: u32, args: &str, out: &mut [u8]) -> bool {
    println!("responder: requesting {} {}", what, args);
    match tool_call(handle, args.as_bytes(), out) {
        Ok((ToolStatus::Ok, n)) => {
            println!(
                "responder:   -> {}",
                core::str::from_utf8(&out[..n]).unwrap_or("?")
            );
            true
        }
        Ok((st, n)) => {
            println!(
                "responder:   -> {:?}: {}",
                st,
                core::str::from_utf8(&out[..n]).unwrap_or("?")
            );
            false
        }
        Err(Error::HumanDenied) => {
            println!("responder:   -> DENIED by operator signature (or timed out)");
            false
        }
        Err(e) => {
            println!("responder:   -> error {:?}", e);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let mut caps = [CapInfo::default(); 8];
    let n = cap_list(&mut caps).unwrap_or(0).min(caps.len());
    let caps = &caps[..n];
    let alerts = caps
        .iter()
        .find(|c| c.perms & perm::RECV != 0)
        .map(|c| c.handle);
    let mut exec = caps
        .iter()
        .filter(|c| c.perms & perm::EXEC != 0)
        .map(|c| c.handle);
    let (Some(alerts), Some(freeze), Some(wire)) = (alerts, exec.next(), exec.next()) else {
        println!("responder: needs recv on alerts and exec on freeze_account and wire_transfer");
        return 2;
    };
    // SAFETY: single-threaded; the only reference.
    let out = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let mut buf = [0u8; 64];
    loop {
        let len = match recv(alerts, &mut buf) {
            Ok(n) => n,
            Err(Error::Empty) => break,
            Err(e) => {
                println!("responder: recv failed: {:?}", e);
                return 1;
            }
        };
        let Ok(alert) = core::str::from_utf8(&buf[..len]) else {
            continue;
        };
        let mut w = alert.split_whitespace();
        let (Some("ALERT"), Some(id), Some(payee), Some(victim), Some(amount)) =
            (w.next(), w.next(), w.next(), w.next(), w.next())
        else {
            continue;
        };
        let ok = |s: &str| s.bytes().all(|b| b.is_ascii_alphanumeric());
        if !(ok(id) && ok(payee) && ok(victim) && amount.bytes().all(|b| b.is_ascii_digit())) {
            continue;
        }
        println!(
            "responder: alert for TXN {} (payee {}, victim {}, INR {})",
            id, payee, victim, amount
        );
        let mut args: StrBuf<160> = StrBuf::new();
        let _ = write!(
            args,
            "{{\"account\":\"{payee}\",\"reason\":\"fraud triage alert TXN {id}\"}}"
        );
        if !act("freeze", freeze, args.as_str(), out) {
            continue;
        }
        args.clear();
        let _ = write!(
            args,
            "{{\"from\":\"suspense\",\"to\":\"{victim}\",\"amount\":{amount},\"reason\":\"refund TXN {id}\"}}"
        );
        act("refund", wire, args.as_str(), out);
    }
    println!("responder: done");
    0
}
