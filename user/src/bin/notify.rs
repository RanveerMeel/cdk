//! Sends one alert on the first handle it holds with `send` and exits —
//! e.g. on a peer proxy (roadmap 3.5): `cap-import to-branch 1`, then
//! `elf-run 1` and `peer-sync`; the owning node delivers it to its object.

#![no_std]
#![no_main]

use cdk_user::{cap_list, getpid, perm, println, send, CapInfo};

/// Send the alert; exit 0 on success, 1 without a send handle, 2 if the
/// send fails.
#[no_mangle]
pub extern "C" fn cdk_main() -> u64 {
    let mut caps = [CapInfo::default(); 16];
    let n = cap_list(&mut caps).unwrap_or(0);
    let Some(h) = caps[..n].iter().find(|c| c.perms & perm::SEND != 0) else {
        println!("notify: no send handle");
        return 1;
    };
    let mut msg = *b"ALERT from pid-0: TXN 1002 HIGH";
    msg[15] = b'0' + (getpid() % 10) as u8;
    match send(h.handle, &msg) {
        Ok(()) => {
            println!("notify: sent \"{}\" on h{}", core::str::from_utf8(&msg).unwrap_or("?"), h.handle);
            0
        }
        Err(e) => {
            println!("notify: send failed: {:?}", e);
            2
        }
    }
}
