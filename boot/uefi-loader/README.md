> **CDK fork.** This is `bootloader-x86_64-uefi` 0.11.17 from
> [rust-osdev/bootloader](https://github.com/rust-osdev/bootloader)
> (MIT OR Apache-2.0), with one addition: before the kernel runs it measures
> the kernel file into TPM PCR 11 and the ramdisk into PCR 12 through
> `EFI_TCG2_PROTOCOL` (see `measure()` in `src/main.rs`; roadmap 4.2 in
> CDK's ROADMAP.md). `run_qemu.sh` builds it and places it at
> `efi/boot/bootx64.efi` in CDK's boot image. Upstream README follows.

# UEFI Bootloader for `x86_64`

## Build

```
cargo b --target x86_64-unknown-uefi --release -Zbuild-std=core -Zbuild-std-features=compiler-builtins-mem 
```
