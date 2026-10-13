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

# The gateway identity CDK pins for its secure link (see tools/run_gateway.sh
# --init). Public key only; override with CDK_GATEWAY_PUB.
GATEWAY_PUB="${CDK_GATEWAY_PUB:-$ROOT/target/gateway.pub}"
if [ -f "$GATEWAY_PUB" ]; then
    cp "$GATEWAY_PUB" "$STAGE/gateway.pub"
else
    echo "note: no $GATEWAY_PUB — the secure link will refuse to connect (run tools/run_gateway.sh --init)" >&2
fi

# Boot policy (roadmap 2.9): rules every grant and gateway change is checked
# against. Override with CDK_POLICY_FILE (e.g. a deployment's policy kept
# outside the repository).
POLICY_FILE="${CDK_POLICY_FILE:-$ROOT/policy/default.rules}"
if [ -f "$POLICY_FILE" ]; then
    cp "$POLICY_FILE" "$STAGE/policy.rules"
fi

# Operator public keys for signed approvals (roadmap 2.8), made with
# tools/approve.sh init <name>. Public halves only; none = console mode.
OPERATORS_DIR="${CDK_OPERATORS_DIR:-$ROOT/target/operators}"
if [ -d "$OPERATORS_DIR" ]; then
    for f in "$OPERATORS_DIR"/*.pub; do
        [ -f "$f" ] || continue
        cp "$f" "$STAGE/operator-$(basename "$f")"
    done
fi

# Verified boot (roadmap 4.2): sign a manifest of every file above with the
# release key (tools/sign.sh init). The kernel checks it before trusting any
# pinned key or program; without a key the ramdisk is unsigned (development).
RELEASE_KEY="${CDK_RELEASE_KEY:-$ROOT/target/release-signing.key}"
if [ -f "$RELEASE_KEY" ]; then
    "$ROOT/tools/sign.sh" manifest "$STAGE" --key "$RELEASE_KEY"
else
    echo "note: no release key ($RELEASE_KEY) — ramdisk unsigned; boot will be unverified" >&2
fi

# Reproducible archive: fixed order, owner, and timestamps.
(cd "$STAGE" && tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime=@0 -cf "$OUT" -- *)
echo "Ramdisk: $OUT ($(stat -c %s "$OUT") bytes): $(cd "$STAGE" && echo *)"
