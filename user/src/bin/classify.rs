//! Inference agent: classifies every message queued on the object it was
//! granted, using the public demo model (message priority, ROUTINE/URGENT)
//! embedded at build time. Integer-only inference, no FPU.
//!
//!   cdk> send obj-2 server down, production outage
//!   cdk> send obj-2 lunch menu for friday
//!   cdk> exec classify obj-2 recv
//!
//! The model is part of this binary, so the `program-loaded` SHA-256 in the
//! audit log identifies code and model together.

#![no_std]
#![no_main]

use cdk_user::ml::{text, Model};
use cdk_user::{cap_list, perm, println, recv, CapInfo, Error};

static MODEL: &[u8] = include_bytes!("../../models/priority-demo.cdklm");

#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let model = match Model::parse(MODEL) {
        Ok(m) => m,
        Err(e) => {
            println!("classify: bad model: {:?}", e);
            return 3;
        }
    };
    let mut caps = [CapInfo::default(); 8];
    let n = cap_list(&mut caps).unwrap_or(0);
    let Some(h) = caps[..n.min(caps.len())]
        .iter()
        .find(|c| c.perms & perm::RECV != 0)
        .map(|c| c.handle)
    else {
        println!("classify: no recv handle (try: exec classify obj-2 recv)");
        return 2;
    };
    println!(
        "classify: model {} features x {} classes, reading handle h{}",
        model.n_features(),
        model.n_classes(),
        h
    );
    let mut features = [0u8; 128];
    let features = &mut features[..model.n_features().min(128)];
    let mut buf = [0u8; 64];
    let mut count = 0u64;
    loop {
        let len = match recv(h, &mut buf) {
            Ok(len) => len,
            Err(Error::Empty) => break,
            Err(e) => {
                println!("classify: recv error {:?}", e);
                return 4;
            }
        };
        let msg = &buf[..len];
        text::hashed_trigrams(msg, features);
        match model.classify(features) {
            Ok(p) => println!(
                "  {:<7} margin={:<7} \"{}\"",
                model.label(p.class),
                p.margin,
                core::str::from_utf8(msg).unwrap_or("?")
            ),
            Err(e) => println!("  error {:?}", e),
        }
        count += 1;
    }
    println!("classify: {} message(s) classified", count);
    0
}
