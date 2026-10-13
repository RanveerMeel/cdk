//! Link framing: arbitrary bytes from the host, in arbitrary chunks.
#![no_main]
use cdk_link::{Decoder, MAX_PAYLOAD};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut d = Decoder::new();
    // The first byte picks a chunk size, to exercise frames split across reads.
    let (step, data) = match data.split_first() {
        Some((&s, rest)) => (1 + s as usize % 64, rest),
        None => return,
    };
    for chunk in data.chunks(step) {
        let mut rest = chunk;
        while !rest.is_empty() {
            let n = d.push(rest);
            assert!(n > 0 && n <= rest.len(), "decoder must make progress");
            rest = &rest[n..];
            while let Some(f) = d.next_frame() {
                assert!(f.payload.len() <= MAX_PAYLOAD);
            }
        }
    }
});
