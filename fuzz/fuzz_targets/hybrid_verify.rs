//! Hybrid Ed25519 + ML-DSA-65 verification of arbitrary signatures and
//! identities (capability proofs, link transcripts, operator approvals use
//! the same code). Must never panic and never accept.
#![no_main]
use std::sync::OnceLock;

use cdk_link::approval::CONTEXT;
use cdk_link::secure::{hybrid, Identity, Signature, IDENTITY_LEN, SIG_LEN};
use libfuzzer_sys::fuzz_target;

fn key() -> &'static hybrid::Keypair {
    static K: OnceLock<hybrid::Keypair> = OnceLock::new();
    K.get_or_init(|| hybrid::Keypair::from_seeds(&[1; 32], &[2; 32]))
}

fuzz_target!(|data: &[u8]| {
    let digest = [0x5a; 32];
    // Arbitrary signature bytes against a real key.
    let mut sig = vec![0u8; SIG_LEN];
    let n = data.len().min(SIG_LEN);
    sig[..n].copy_from_slice(&data[..n]);
    if let Some(s) = Signature::from_slice(&sig) {
        assert!(!hybrid::verify(key().public(), &digest, &s));
        assert!(!hybrid::verify_with(key().public(), &digest, &s, CONTEXT));
    }
    // Arbitrary identity bytes with a real signature.
    if data.len() >= IDENTITY_LEN {
        if let Some(id) = Identity::from_bytes(&data[..IDENTITY_LEN]) {
            let real = key().sign(&digest);
            if id != *key().public() {
                assert!(
                    !hybrid::verify(&id, &digest, &real),
                    "signature verified under a different key"
                );
            }
        }
    }
});
