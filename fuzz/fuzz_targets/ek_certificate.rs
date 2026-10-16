//! TPM endorsement-key certificates (gateway --tpm-ca): the X.509/DER
//! parser and chain check run on the certificate CDK's TPM sends.
#![no_main]
use libfuzzer_sys::fuzz_target;

#[allow(dead_code)]
#[path = "../../gateway/src/ekcert.rs"]
mod ekcert;

fuzz_target!(|data: &[u8]| {
    let _ = ekcert::decode_certs(data);
    let Some(cert) = ekcert::Certificate::parse(data) else {
        return;
    };
    let _ = cert.common_name();
    let _ = cert.signed_by(&cert);
    let store = ekcert::TrustStore::from_certs(vec![cert.clone()]);
    let _ = store.verify(&cert);
});
