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
# model) applies only when cargo runs from inside user/. Pin the target dir:
# run_qemu.sh exports CARGO_TARGET_DIR for the kernel, and inheriting it would
# build the programs elsewhere and pack stale binaries from user/target.
USER_TARGET="$ROOT/user/target"
(cd "$ROOT/user" && CARGO_TARGET_DIR="$USER_TARGET" cargo build --release --bins --quiet)

BIN_DIR="$USER_TARGET/x86_64-unknown-none/release"
rm -rf "$STAGE"
mkdir -p "$STAGE" "$(dirname "$OUT")"
for src in "$ROOT"/user/src/bin/*.rs; do
    name="$(basename "$src" .rs)"
    cp "$BIN_DIR/$name" "$STAGE/$name"
done

# Optional private programs: prebuilt ELF files from a directory OUTSIDE this
# repository (e.g. proprietary agents with embedded models). They are packed
# into this build's ramdisk only; nothing from that directory is committed.
if [ -n "${CDK_PRIVATE_PROGRAMS_DIR:-}" ]; then
    case "$(realpath "$CDK_PRIVATE_PROGRAMS_DIR")/" in
        "$ROOT"/*) echo "CDK_PRIVATE_PROGRAMS_DIR must be outside the repository" >&2; exit 1 ;;
    esac
    for f in "$CDK_PRIVATE_PROGRAMS_DIR"/*; do
        [ -f "$f" ] || continue
        name="$(basename "$f")"
        if [ -e "$STAGE/$name" ]; then
            echo "private program '$name' clashes with a public one" >&2
            exit 1
        fi
        cp "$f" "$STAGE/$name"
    done
fi

# Reproducible archive: fixed order, owner, and timestamps.
(cd "$STAGE" && tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime=@0 -cf "$OUT" -- *)
echo "Ramdisk: $OUT ($(stat -c %s "$OUT") bytes): $(cd "$STAGE" && echo *)"
