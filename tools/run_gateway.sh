#!/bin/bash
# Build and run the host gateway (gateway/) for the host platform, connecting
# to the CDK link socket that run_qemu.sh creates.
#   tools/run_gateway.sh [socket]   (default target/cdk-link.sock)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
cd "$ROOT/gateway"
# The repository's .cargo/config.toml targets bare metal; build for the host.
CARGO_TARGET_DIR="$ROOT/gateway/target" cargo build --release --quiet --target "$HOST"
exec "$ROOT/gateway/target/$HOST/release/cdk-gateway" "${1:-$ROOT/target/cdk-link.sock}"
