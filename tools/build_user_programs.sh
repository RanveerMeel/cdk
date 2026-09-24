#!/bin/bash
# Build the user programs in user/ and pack them into a reproducible ustar
# ramdisk that the bootloader loads next to the kernel.
#
#   tools/build_user_programs.sh [output.tar]   (default: target/initrd.tar)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/target/initrd.tar}"
STAGE="$ROOT/target/initrd"

# user/.cargo/config.toml (target, static relocation model, large code
# model) applies only when cargo runs from inside user/.
(cd "$ROOT/user" && cargo build --release --bins --quiet)

BIN_DIR="$ROOT/user/target/x86_64-unknown-none/release"
rm -rf "$STAGE"
mkdir -p "$STAGE" "$(dirname "$OUT")"
for src in "$ROOT"/user/src/bin/*.rs; do
    name="$(basename "$src" .rs)"
    cp "$BIN_DIR/$name" "$STAGE/$name"
done

# Reproducible archive: fixed order, owner, and timestamps.
(cd "$STAGE" && tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime=@0 -cf "$OUT" -- *)
echo "Ramdisk: $OUT ($(stat -c %s "$OUT") bytes): $(cd "$STAGE" && echo *)"
