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
rustup run nightly cargo run --manifest-path tools/create_disk_image/Cargo.toml --release --target "$HOST_TARGET" -- \
    "$KERNEL_ELF" "$DISK_IMG" "$RAMDISK"
# Expected boot measurements, for the gateway's attestation check (--expect).
tools/sign.sh measure "$KERNEL_ELF" "$RAMDISK"

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
# target/tpm/ so the attestation key persists like a real chip's.
# CDK_TPM=0 disables it.
TPM_ARGS=()
if [[ "${CDK_TPM:-1}" != "0" ]] && command -v swtpm &> /dev/null; then
    TPM_DIR="$PWD/target/tpm"
    mkdir -p "$TPM_DIR"
    rm -f "$TPM_DIR/swtpm-sock"
    swtpm socket --tpm2 --tpmstate dir="$TPM_DIR" --ctrl type=unixio,path="$TPM_DIR/swtpm-sock" \
        --terminate --log file="$TPM_DIR/swtpm.log",level=1 &
    for _ in $(seq 1 50); do [ -S "$TPM_DIR/swtpm-sock" ] && break; sleep 0.1; done
    TPM_ARGS=(-chardev "socket,id=chrtpm,path=$TPM_DIR/swtpm-sock"
        -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0)
    echo "TPM: swtpm (state in $TPM_DIR)"
fi

QEMU_ARGS=(
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
