#!/bin/bash
# Build and run the host gateway (gateway/) for the host platform.
#   tools/run_gateway.sh [socket]   run, connecting to the CDK link socket
#                                   (default target/cdk-link.sock)
#   tools/run_gateway.sh --init     create target/gateway-identity.key (0600)
#                                   and export target/gateway.pub for CDK
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
cd "$ROOT/gateway"
# The repository's .cargo/config.toml targets bare metal; build for the host.
CARGO_TARGET_DIR="$ROOT/gateway/target" cargo build --release --quiet --target "$HOST"
BIN="$ROOT/gateway/target/$HOST/release/cdk-gateway"
ID=(--identity "$ROOT/target/gateway-identity.key")
if [ "${1:-}" = "--init" ]; then
    exec "$BIN" --init "${ID[@]}" --pub-out "$ROOT/target/gateway.pub"
fi
exec "$BIN" "${ID[@]}" "${1:-$ROOT/target/cdk-link.sock}"
