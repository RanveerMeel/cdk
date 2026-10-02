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
# MCP servers the gateway exposes to CDK agents. Default: the demo server.
# Override with CDK_MCP="name=command args" (one server).
MCP=(--mcp "${CDK_MCP:-demo=python3 $ROOT/gateway/examples/demo_mcp_server.py}")
# Model backends (OpenAI-compatible), seen by CDK as tools model:<name>.
# CDK_MODEL holds one or more specs separated by spaces, e.g. a local Ollama:
#   CDK_MODEL="qwen=http://127.0.0.1:11434/v1,model=qwen2.5:3b-instruct"
# A key for a remote API is injected by the gateway, never seen by CDK:
#   CDK_MODEL="remote=https://api.example.com/v1,model=m,key-file=$HOME/.cdk/remote.key"
MODELS=()
for spec in ${CDK_MODEL:-}; do MODELS+=(--model "$spec"); done
# CDK_MCP_ALLOW limits what CDK may reach (tool names and model:<name>).
exec "$BIN" "${ID[@]}" "${MCP[@]}" "${MODELS[@]}" ${CDK_MCP_ALLOW:+--allow "$CDK_MCP_ALLOW"} "${1:-$ROOT/target/cdk-link.sock}"
