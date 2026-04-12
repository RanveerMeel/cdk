//! Host tool: wrap a built kernel ELF in a BIOS bootable raw disk image (bootloader 0.11).
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let kernel: PathBuf = args
        .next()
        .map(Into::into)
        .ok_or_else(|| anyhow::anyhow!("usage: create_disk_image <kernel-elf> <output.img>"))?;
    let out: PathBuf = args
        .next()
        .map(Into::into)
        .ok_or_else(|| anyhow::anyhow!("usage: create_disk_image <kernel-elf> <output.img>"))?;

    bootloader::BiosBoot::new(&kernel).create_disk_image(&out)?;
    Ok(())
}
