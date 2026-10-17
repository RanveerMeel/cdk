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
# Signed approvals (roadmap 2.8): requests for operators and their decisions
# (tools/approve.sh list / approve / deny). Override with CDK_APPROVAL_SPOOL.
SPOOL=(--spool "${CDK_APPROVAL_SPOOL:-$ROOT/target/approvals}")
# Attestation (roadmap 4.2): serve only a CDK whose measured boot matches the
# build (run_qemu.sh writes target/boot.measurements). CDK_EXPECT=none: log only.
EXPECT=()
EXPECT_FILE="${CDK_EXPECT:-$ROOT/target/boot.measurements}"
if [ "$EXPECT_FILE" != "none" ] && [ -f "$EXPECT_FILE" ]; then EXPECT=(--expect "$EXPECT_FILE"); fi
# TPM quote (roadmap 4.2): when CDK runs with a TPM (run_qemu.sh starts swtpm),
# require a quote from the enrolled machine; the first valid quote enrolls it
# into target/tpm-enrollment. CDK_TPM=0: don't require one.
if [ "${CDK_TPM:-1}" != "0" ] && command -v swtpm &> /dev/null; then
    EXPECT+=(--tpm "${CDK_TPM_ENROLLMENT:-$ROOT/target/tpm-enrollment}")
    # Endorsement: the TPM must prove it was certified by its manufacturer
    # (for the software TPM, the test CA of tools/tpm_manufacture.sh).
    # CDK_TPM_CA=DIR names other manufacturer CAs; CDK_TPM_CA=none skips it.
    TPM_CA="${CDK_TPM_CA:-}"
    if [ -z "$TPM_CA" ] && [ -e "${CDK_TPM_DIR:-$ROOT/target/tpm}/.ek-certified" ]; then
        TPM_CA="$ROOT/target/tpm-manufacturer/trust"
    fi
    if [ -n "$TPM_CA" ] && [ "$TPM_CA" != "none" ]; then EXPECT+=(--tpm-ca "$TPM_CA"); fi
fi
# Distributed capabilities (roadmap 3.5): CDK_NODE=<name> makes this gateway
# the registry authority for the CDK it serves — once the attestation is
# accepted it certifies CDK as node <name> with the registry key
# (CDK_REGISTRY_KEY, default target/registry.key: tools/sign.sh init --key
# target/registry.key --pub-out target/registry.pub). Exports and imports go
# through CDK_CAP_DIR (default target/caps/{outbox,inbox}); CDK_CERT_VALIDITY
# sets the certificate lifetime in seconds (default 24 h).
if [ -n "${CDK_NODE:-}" ]; then
    EXPECT+=(--registry-key "${CDK_REGISTRY_KEY:-$ROOT/target/registry.key}" --node "$CDK_NODE" \
        --cap-dir "${CDK_CAP_DIR:-$ROOT/target/caps}" ${CDK_CERT_VALIDITY:+--cert-validity "$CDK_CERT_VALIDITY"})
fi
exec "$BIN" "${ID[@]}" "${MCP[@]}" "${MODELS[@]}" "${SPOOL[@]}" "${EXPECT[@]}" ${CDK_MCP_ALLOW:+--allow "$CDK_MCP_ALLOW"} "${1:-$ROOT/target/cdk-link.sock}"
