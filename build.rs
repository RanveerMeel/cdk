//! Embed the release public key (roadmap 4.2, verified boot).
//!
//! `CDK_RELEASE_PUB` names the key file (default `target/release.pub`,
//! created by `cdk-sign init`). With a key the kernel verifies the ramdisk
//! manifest at boot and locks down if it does not verify; without one it
//! boots unverified (development) and says so.
use std::path::PathBuf;

fn main() {
    let path = std::env::var_os("CDK_RELEASE_PUB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/release.pub"));
    println!("cargo:rerun-if-env-changed=CDK_RELEASE_PUB");
    println!("cargo:rerun-if-changed={}", path.display());
    let key = std::fs::read(&path).unwrap_or_default();
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("release.pub");
    std::fs::write(out, key).unwrap();
}
