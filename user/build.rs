// Link every user program with `link.ld` (fixed load address in CDK's user region).
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bins=-T{dir}/link.ld");
    println!("cargo:rerun-if-changed=link.ld");
}
