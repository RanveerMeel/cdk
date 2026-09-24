//! Host tool: wrap a built kernel ELF (and an optional ramdisk) in a BIOS
//! bootable raw disk image (bootloader 0.11).
use std::path::PathBuf;

const USAGE: &str = "usage: create_disk_image <kernel-elf> <output.img> [ramdisk]";

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let kernel: PathBuf = args
        .next()
        .map(Into::into)
        .ok_or_else(|| anyhow::anyhow!(USAGE))?;
    let out: PathBuf = args
        .next()
        .map(Into::into)
        .ok_or_else(|| anyhow::anyhow!(USAGE))?;
    let ramdisk: Option<PathBuf> = args.next().map(Into::into);

    let mut boot = bootloader::BiosBoot::new(&kernel);
    if let Some(ramdisk) = ramdisk {
        boot.set_ramdisk(&ramdisk);
    }
    boot.create_disk_image(&out)?;
    Ok(())
}
