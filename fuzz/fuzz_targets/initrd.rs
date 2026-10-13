//! The boot ramdisk (ustar): every entry must lie inside the archive.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let range = data.as_ptr_range();
    for f in cdk::initrd::parse(data).flatten() {
        let r = f.data.as_ptr_range();
        assert!(f.data.is_empty() || (r.start >= range.start && r.end <= range.end));
        assert!(!f.name.is_empty());
    }
});
