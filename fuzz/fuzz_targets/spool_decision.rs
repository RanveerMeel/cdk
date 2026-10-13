//! Gateway spool decision files (written by anyone with spool access).
#![no_main]
use libfuzzer_sys::fuzz_target;

#[allow(dead_code)]
#[path = "../../gateway/src/spool.rs"]
mod spool;

fuzz_target!(|data: &[u8]| {
    if let Some(d) = spool::Decision::from_bytes(data) {
        assert_eq!(d.to_bytes(), data);
    }
});
