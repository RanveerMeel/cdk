#!/bin/bash
# Build and run cdk-sign (release signing for verified and measured boot,
# roadmap 4.2) from the repository root:
#   tools/sign.sh init                         create target/release-signing.key + release.pub
#   tools/sign.sh manifest target/initrd       sign a staged ramdisk (build_user_programs.sh does this)
#   tools/sign.sh measure KERNEL RAMDISK       write target/boot.measurements (run_qemu.sh does this)
#   tools/sign.sh verify target/initrd         check a staged ramdisk
#   tools/sign.sh node-authority NODE --root target/registry.key
#                                              let one gateway certify node NODE
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
(cd "$ROOT/gateway" && CARGO_TARGET_DIR="$ROOT/gateway/target" cargo build --release --quiet --target "$HOST" --bin cdk-sign)
cd "$ROOT"
exec "$ROOT/gateway/target/$HOST/release/cdk-sign" "$@"
