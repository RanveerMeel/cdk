//! Verified and measured boot inputs: the ramdisk manifest (checked
//! against the ramdisk), kernel ELF measurement, attestation messages, and
//! the gateway's expected-measurements file.
#![no_main]
use cdk_link::attest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = attest::kernel_measurement(data);
    if let Some(attest::Message::Attestation(a)) = attest::decode(data) {
        // Decoding is canonical.
        assert_eq!(attest::encode_attestation(&a), data);
    }
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let _ = attest::parse_expected(text);
    // The text as a manifest, checked against a fixed ramdisk; a manifest
    // that accepts it must list exactly these files with these digests.
    let files = [
        ("hello", &b"elf"[..]),
        ("policy.rules", &b"approval credential\n"[..]),
    ];
    if attest::check_manifest(text, files).is_ok() {
        assert_eq!(text, attest::build_manifest(files));
    }
});
