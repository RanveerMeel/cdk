#!/bin/bash
# Build and run cdk-approve, the operator tool for signed approvals
# (roadmap 2.8), from the repository root:
#   tools/approve.sh init alice           create target/operators/alice.{key,pub}
#   tools/approve.sh list                 open requests in target/approvals
#   tools/approve.sh approve 3 --key target/operators/alice.key
#   tools/approve.sh deny 3 --key target/operators/alice.key
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
(cd "$ROOT/gateway" && CARGO_TARGET_DIR="$ROOT/gateway/target" cargo build --release --quiet --target "$HOST" --bin cdk-approve)
cd "$ROOT"
exec "$ROOT/gateway/target/$HOST/release/cdk-approve" "$@"
