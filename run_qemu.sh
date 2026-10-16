#!/bin/bash

# QEMU run script for CDK (Cognitive Distributed Kernel)
#
# Default (serial console): kernel output appears in this terminal via serial.
# GUI window:  CDK_QEMU_GUI=1 ./run_qemu.sh
#
# QEMU locks the disk image path. We copy the built .bin to a fresh temp file per run so
# another VM (or a stuck process) locking the image does not block this run.

set -e

echo "Building CDK for bare metal..."

# Force all cargo invocations to share the workspace target dir so the disk
# image tool always packages the kernel binary built in this run.
export CARGO_TARGET_DIR="$PWD/target"

# Check if QEMU is installed
if ! command -v qemu-system-x86_64 &> /dev/null; then
    echo "Error: qemu-system-x86_64 not found. Please install QEMU:"
    echo "  sudo apt install qemu-system-x86"
    exit 1
fi

# Release signing key (created once). Its public half is compiled into the
# kernel (build.rs), which then verifies the ramdisk at boot (roadmap 4.2).
# CDK_RELEASE_PUB=/dev/null builds an unverified development kernel.
tools/sign.sh init >/dev/null

# Build the kernel
echo "Building kernel..."
# Work around an LLVM backend crash observed with curve25519-dalek SIMD codegen
# on some host toolchains by forcing the serial backend.
# Optional: CDK_VIRTIO_HW=1 enables virtio-net/gpu MMIO+PCI probe paths.
FEATURES=()
if [[ "${CDK_VIRTIO_HW:-}" == "1" ]]; then
    FEATURES=(--features virtio-hw)
fi

RUSTFLAGS="${RUSTFLAGS:-} --cfg curve25519_dalek_backend=\"serial\" --cfg poly1305_force_soft --cfg chacha20_force_soft" \
    cargo build --release --bin cdk "${FEATURES[@]}"

# BIOS bootable raw image (bootloader 0.11)
echo "Creating bootable image..."
KERNEL_ELF="target/x86_64-unknown-none/release/cdk"
DISK_IMG="target/x86_64-unknown-none/release/bootimage-cdk.bin"
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
if ! rustup toolchain list | grep -q '^nightly'; then
    echo "Error: nightly Rust is required to build the BIOS disk image (bootloader 0.11)."
    echo "  rustup toolchain install nightly"
    echo "  rustup component add rust-src llvm-tools-preview --toolchain nightly"
    exit 1
fi
# Gateway identity (created once) whose public key CDK pins for the link.
tools/run_gateway.sh --init

# User programs (user/) packed into the boot ramdisk (ustar).
echo "Building user programs..."
RAMDISK="target/initrd.tar"
tools/build_user_programs.sh "$PWD/$RAMDISK"
# Boot path (roadmap 4.2): UEFI when OVMF is installed — the firmware
# measures CDK's measuring loader (boot/uefi-loader), which measures the
# kernel and ramdisk into TPM PCRs 11-12 before the kernel runs. The same
# image also boots with BIOS (CDK_BOOT=bios), without that loader stage.
OVMF_CODE="${CDK_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS="${CDK_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
BOOT_MODE="${CDK_BOOT:-}"
if [[ -z "$BOOT_MODE" ]]; then
    if [[ -f "$OVMF_CODE" && -f "$OVMF_VARS" ]]; then BOOT_MODE=uefi; else BOOT_MODE=bios; fi
fi
# UEFI Secure Boot (CDK_SECURE_BOOT=1): the firmware runs only a loader signed
# with CDK's Secure Boot key (tools/secureboot.sh), and that loader runs only
# the kernel whose SHA-256 is built into it. Uses OVMF's SMM build (q35).
SECURE_BOOT="${CDK_SECURE_BOOT:-0}"
if [[ "$SECURE_BOOT" == "1" && "$BOOT_MODE" != "uefi" ]]; then
    echo "Error: CDK_SECURE_BOOT=1 needs UEFI (OVMF)"
    exit 1
fi
if [[ "$SECURE_BOOT" == "1" && "${CDK_RELEASE_PUB:-}" == "/dev/null" ]]; then
    echo "Warning: Secure Boot with an unverified kernel (CDK_RELEASE_PUB=/dev/null): the chain ends at the kernel; the ramdisk is not checked"
fi
UEFI_LOADER=()
if [[ "$BOOT_MODE" == "uefi" ]]; then
    echo "Building the measuring UEFI loader..."
    PIN=()
    if [[ "$SECURE_BOOT" == "1" ]]; then
        PIN=(env CDK_KERNEL_SHA256="$(sha256sum "$KERNEL_ELF" | cut -d' ' -f1)")
    fi
    (cd boot/uefi-loader && "${PIN[@]}" rustup run nightly cargo build --release --quiet --target x86_64-unknown-uefi \
        -Zbuild-std=core -Zbuild-std-features=compiler-builtins-mem)
    UEFI_LOADER=("$CARGO_TARGET_DIR/x86_64-unknown-uefi/release/cdk-uefi-loader.efi")
    if [[ "$SECURE_BOOT" == "1" ]]; then
        tools/secureboot.sh init
        tools/secureboot.sh sign "${UEFI_LOADER[0]}" "$PWD/target/cdk-uefi-loader.signed.efi"
        UEFI_LOADER=("$PWD/target/cdk-uefi-loader.signed.efi")
    fi
fi
rustup run nightly cargo run --manifest-path tools/create_disk_image/Cargo.toml --release --target "$HOST_TARGET" -- \
    "$KERNEL_ELF" "$DISK_IMG" "$RAMDISK" "${UEFI_LOADER[@]}"
# Expected boot measurements, for the gateway's attestation check (--expect).
if [[ "$BOOT_MODE" == "uefi" ]]; then
    tools/sign.sh measure "$KERNEL_ELF" "$RAMDISK" --loader
else
    tools/sign.sh measure "$KERNEL_ELF" "$RAMDISK"
fi

RUN_IMG="$(mktemp /tmp/cdk_boot.XXXXXX)"
trap 'rm -f "$RUN_IMG"' EXIT
cp -- "$DISK_IMG" "$RUN_IMG"

# Run in QEMU
if [[ "${CDK_QEMU_GUI:-}" == "1" ]]; then
    echo "Starting QEMU (graphical window)..."
    DISPLAY_ARGS=()
else
    echo "Starting QEMU (serial console — type 'help' at the cdk> prompt)..."
    DISPLAY_ARGS=(-display none)
fi

# -smp 2: exercise AP trampoline / LAPIC path (roadmap reset M1).
SMP_ARGS=(-smp "${CDK_QEMU_SMP:-2}")

# Virtio-gpu on the PCI bus (soft backend always works without it).
GPU_ARGS=(-device virtio-gpu-pci)

# Host link: virtio-console backed by a Unix socket. Run the gateway with
# tools/run_gateway.sh in another terminal (it connects to this socket).
LINK_SOCK="${CDK_LINK_SOCK:-$PWD/target/cdk-link.sock}"
rm -f "$LINK_SOCK"
LINK_ARGS=(-device virtio-serial-pci
    -chardev "socket,id=cdklink,path=$LINK_SOCK,server=on,wait=off"
    -device virtconsole,chardev=cdklink)

# TPM 2.0 (roadmap 4.2): a software TPM (swtpm) when installed, with state in
# target/tpm/ so the attestation key persists like a real chip's. A new one is
# "manufactured" with EK certificates from a test CA (tools/tpm_manufacture.sh,
# needs swtpm-tools and tpm2-tools) so the gateway can check it is genuine.
# CDK_TPM_DIR overrides the state directory; CDK_TPM=0 disables the TPM.
TPM_ARGS=()
if [[ "${CDK_TPM:-1}" != "0" ]] && command -v swtpm &> /dev/null; then
    TPM_DIR="${CDK_TPM_DIR:-$PWD/target/tpm}"
    if [[ ! -e "$TPM_DIR/tpm2-00.permall" ]] && command -v swtpm_setup &> /dev/null \
        && command -v tpm2_createek &> /dev/null; then
        tools/tpm_manufacture.sh "$TPM_DIR" || echo "TPM: manufacturing failed; using an uncertified swtpm"
    elif [[ ! -e "$TPM_DIR/.ek-certified" ]]; then
        echo "TPM: this software TPM has no EK certificate (remove $TPM_DIR and the TPM enrollment files to manufacture a certified one)"
    fi
    mkdir -p "$TPM_DIR"
    rm -f "$TPM_DIR/swtpm-sock"
    swtpm socket --tpm2 --tpmstate dir="$TPM_DIR" --ctrl type=unixio,path="$TPM_DIR/swtpm-sock" \
        --terminate --log file="$TPM_DIR/swtpm.log",level=1 &
    for _ in $(seq 1 50); do [ -S "$TPM_DIR/swtpm-sock" ] && break; sleep 0.1; done
    TPM_ARGS=(-chardev "socket,id=chrtpm,path=$TPM_DIR/swtpm-sock"
        -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0)
    echo "TPM: swtpm (state in $TPM_DIR)"
fi

FIRMWARE_ARGS=()
if [[ "$BOOT_MODE" == "uefi" && "$SECURE_BOOT" == "1" ]]; then
    # Variables with CDK's key enrolled (PK, KEK, db), fresh each run.
    tools/secureboot.sh vars "$PWD/target/ovmf-vars.fd" > /dev/null
    FIRMWARE_ARGS=(-machine q35,smm=on -global driver=cfi.pflash01,property=secure,value=on
        -drive "if=pflash,format=raw,unit=0,readonly=on,file=${CDK_OVMF_SECBOOT_CODE:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}"
        -drive "if=pflash,format=raw,unit=1,file=$PWD/target/ovmf-vars.fd")
    echo "Boot: UEFI Secure Boot (OVMF, SMM) — signed loader, pinned kernel"
elif [[ "$BOOT_MODE" == "uefi" ]]; then
    # A fresh copy of the variable store each run keeps firmware PCRs stable.
    cp "$OVMF_VARS" "$PWD/target/ovmf-vars.fd"
    FIRMWARE_ARGS=(-drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE"
        -drive "if=pflash,format=raw,file=$PWD/target/ovmf-vars.fd")
    echo "Boot: UEFI (OVMF) with CDK's measuring loader"
else
    echo "Boot: BIOS"
fi

QEMU_ARGS=(
    "${FIRMWARE_ARGS[@]}"
    -cpu max
    -drive format=raw,file="$RUN_IMG",snapshot=on
    -serial stdio
    "${SMP_ARGS[@]}"
    "${GPU_ARGS[@]}"
    "${LINK_ARGS[@]}"
    "${TPM_ARGS[@]}"
    "${DISPLAY_ARGS[@]}"
    -no-reboot
    -no-shutdown
)
if [[ -n "${CDK_QEMU_PIDFILE:-}" ]]; then
    # Scripted runs (tools/demo_fraud.sh --auto): console input comes from a
    # pipe; run QEMU in the background so the driver can stop it.
    qemu-system-x86_64 "${QEMU_ARGS[@]}" <&0 &
    echo $! > "$CDK_QEMU_PIDFILE"
    wait $!
else
    qemu-system-x86_64 "${QEMU_ARGS[@]}"
fi
