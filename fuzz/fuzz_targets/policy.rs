//! Policy files (boot policy, runtime edits) and the rule checker.
#![no_main]
use cdk::policy::{Grant, Policy, Rule};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let _ = Rule::parse(text);
    if let Ok(p) = Policy::parse(text) {
        assert!((10..=3600).contains(&p.approval_timeout_s));
        assert!(p.quorums.iter().all(|(_, n)| (1..=8).contains(n)));
        // Every rule renders and parses back to itself.
        for r in &p.rules {
            assert_eq!(Rule::parse(&r.to_string()).as_ref(), Ok(r));
        }
        let grants = [
            Grant::new(1, "obj-2", "agent-inbox", 0, 1 << 5),
            Grant::new(1, "obj-8", "model:paid", 3, (1 << 3) | (1 << 7)),
            Grant::new(2, "obj-4", "tool:echo", 0, 1 << 3),
        ];
        let _ = p.violations(&grants);
        let _ = p.quorum_for(&p.labels_of("obj-8", "model:paid", 3));
    }
});
