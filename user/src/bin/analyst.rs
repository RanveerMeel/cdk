//! An agent that uses a large language model through CDK (roadmap 3.4).
//! The model runs on the Linux host (Ollama, vLLM, llama.cpp, …) behind the
//! gateway; the agent reaches it only through a capability handle to a
//! `model:<name>` object, and never sees the backend's credential.
//!
//!   cdk> link-secure
//!   cdk> tools-sync
//!   cdk> spawn analyst
//!   cdk> grant <pid> model:qwen exec          (add ,approval to gate it)
//!   cdk> elf-run <pid>

#![no_std]
#![no_main]

use cdk_user::{ask_model, cap_list, perm, println, write, CapInfo};

const SYSTEM: &str = "You are a concise security operations assistant.";
const PROMPTS: [(&str, u32); 2] = [
    (
        "Classify this alert as ROUTINE or URGENT and give a one-line reason: \"payment system failing right now\"",
        60,
    ),
    (
        "List eight checks an operator should make before approving an unusual outgoing wire transfer. One short paragraph each.",
        400,
    ),
];

static mut OUT: [u8; 8192] = [0; 8192];

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let mut caps = [CapInfo::default(); 8];
    let n = cap_list(&mut caps).unwrap_or(0).min(caps.len());
    let Some(model) = caps[..n].iter().find(|c| c.perms & perm::EXEC != 0) else {
        println!("analyst: no model handle (grant <pid> model:<name> exec)");
        return 1;
    };
    // SAFETY: single-threaded program; the only reference to OUT.
    let out = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    for (i, (prompt, max_tokens)) in PROMPTS.iter().enumerate() {
        println!("analyst: [{}] asking h{} ...", i + 1, model.handle);
        match ask_model(model.handle, Some(SYSTEM), prompt, *max_tokens, out) {
            Ok((status, len)) => {
                println!("analyst: [{}] {:?}, {} bytes:", i + 1, status, len);
                // A cut result may end inside a UTF-8 sequence; print the valid part.
                let text = &out[..len];
                let valid =
                    core::str::from_utf8(text).map_or_else(|e| e.valid_up_to(), |s| s.len());
                write(&text[..valid]);
                println!();
            }
            Err(e) => println!("analyst: [{}] error {:?}", i + 1, e),
        }
    }
    0
}
