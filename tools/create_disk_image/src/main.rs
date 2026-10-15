//! Host tool: wrap a built kernel ELF (and an optional ramdisk) in a raw
//! disk image (bootloader 0.11). The image always boots with BIOS; with a
//! UEFI loader (CDK's measuring loader, `boot/uefi-loader`) it also boots
//! with UEFI firmware, which starts `efi/boot/bootx64.efi` from the same
//! FAT partition.
use std::path::PathBuf;

const USAGE: &str = "usage: create_disk_image <kernel-elf> <output.img> [ramdisk] [uefi-loader.efi]";

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
    let uefi_loader: Option<PathBuf> = args.next().map(Into::into);

    let mut image = bootloader::DiskImageBuilder::new(kernel);
    if let Some(ramdisk) = ramdisk {
        image.set_ramdisk(ramdisk);
    }
    if let Some(loader) = uefi_loader {
        image.set_file("efi/boot/bootx64.efi".into(), loader);
    }
    image.create_bios_image(&out)?;
    Ok(())
}
