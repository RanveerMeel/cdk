//! An agent that uses MCP tools through CDK. Every tool call goes through a
//! kernel capability handle, the post-quantum link, and the host gateway.
//!
//!   cdk> link-secure
//!   cdk> tools-sync
//!   cdk> spawn researcher
//!   cdk> grant <pid> tool:word_count exec
//!   cdk> grant <pid> tool:echo exec
//!   cdk> elf-run <pid>

#![no_std]
#![no_main]

use cdk_user::{cap_list, perm, println, tool_call, CapInfo, Error};

const ARGS: &[u8] = br#"{"text":"CDK agents call MCP tools through kernel capabilities"}"#;

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let mut caps = [CapInfo::default(); 8];
    let n = cap_list(&mut caps).unwrap_or(0).min(caps.len());
    println!("researcher: {} handle(s)", n);
    let mut out = [0u8; 256];
    let mut calls = 0;
    for c in &caps[..n] {
        if c.perms & perm::EXEC == 0 {
            // A handle without EXEC must not be able to call its tool.
            let r = tool_call(c.handle, ARGS, &mut out);
            println!("  h{} (no exec): {:?}", c.handle, r.map(|x| x.0));
            continue;
        }
        match tool_call(c.handle, ARGS, &mut out) {
            Ok((status, len)) => {
                calls += 1;
                println!(
                    "  h{} -> {:?}: \"{}\"",
                    c.handle,
                    status,
                    core::str::from_utf8(&out[..len]).unwrap_or("?")
                );
            }
            Err(e) => println!("  h{} -> error {:?}", c.handle, e),
        }
    }
    // A handle it does not hold.
    let forged = tool_call(15, ARGS, &mut out);
    println!("  h15 (not granted): {:?}", forged.map(|x| x.0));
    if forged != Err(Error::BadHandle) {
        return 1;
    }
    println!("researcher: {} tool call(s) completed", calls);
    0
}
