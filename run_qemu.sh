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

# Check if QEMU is installed
if ! command -v qemu-system-x86_64 &> /dev/null; then
    echo "Error: qemu-system-x86_64 not found. Please install QEMU:"
    echo "  sudo apt install qemu-system-x86"
    exit 1
fi

# Build the kernel
echo "Building kernel..."
cargo build --release --bin cdk

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
rustup run nightly cargo run --manifest-path tools/create_disk_image/Cargo.toml --release --target "$HOST_TARGET" -- \
    "$KERNEL_ELF" "$DISK_IMG"

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

qemu-system-x86_64 \
    -drive format=raw,file="$RUN_IMG",snapshot=on \
    -serial stdio \
    "${DISPLAY_ARGS[@]}" \
    -no-reboot \
    -no-shutdown
