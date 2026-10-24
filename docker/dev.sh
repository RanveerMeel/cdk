#!/bin/bash
# Full CDK stack in one container: build and boot the kernel (./run_qemu.sh,
# serial console in this terminal) and start the gateway once CDK's link
# socket exists. Keys, the TPM and build output persist in /cdk/target.
#   cdk-dev            kernel + gateway (then type link-secure at cdk>); Ctrl-C quits
#   cdk-dev --shell    a shell in the repository instead
set -euo pipefail
cd /cdk
if [[ "${1:-}" == "--shell" ]]; then exec bash; fi
mkdir -p target
rm -f target/cdk-link.sock
(
    for _ in $(seq 1 1800); do [[ -S target/cdk-link.sock ]] && break; sleep 1; done
    exec tools/run_gateway.sh > target/gateway.log 2>&1
) &
echo "cdk-dev: the gateway starts once CDK is up (log: target/gateway.log); then type link-secure"
exec ./run_qemu.sh
