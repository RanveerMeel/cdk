#!/bin/bash
# Full CDK stack in one container: build and boot the kernel (./run_qemu.sh,
# serial console in this terminal) and start the gateway once CDK's link
# socket exists. Keys, the TPM and every build (kernel, agents, gateway)
# persist in the /cdk/target volume.
#   cdk-dev            kernel + gateway (then type link-secure at cdk>); Ctrl-C quits
#   cdk-dev --shell    a shell in the repository instead
set -uo pipefail
cd /cdk
mkdir -p target/gateway-build target/user-build
# The gateway and the agents build in their own target directories; keep
# them in the volume too.
for d in gateway user; do
    [[ -L "$d/target" ]] || { rm -rf "$d/target"; ln -s "../target/$d-build" "$d/target"; }
done
if [[ "${1:-}" == "--shell" ]]; then exec bash; fi
rm -f target/cdk-link.sock

# The gateway: started once CDK is up; if it stops, say so on the console
# (it is not restarted: fix the cause, see target/gateway.log).
(
    for _ in $(seq 1 1800); do [[ -S target/cdk-link.sock ]] && break; sleep 1; done
    tools/run_gateway.sh > target/gateway.log 2>&1
    status=$?
    if [[ $status -ne 0 && $status -ne 143 ]]; then
        printf '\r\n*** cdk-dev: the gateway STOPPED (status %s) — link-secure will fail; see target/gateway.log ***\r\n' \
            "$status" > /dev/tty 2>/dev/null || true
        tail -n 5 target/gateway.log > /dev/tty 2>/dev/null || true
    fi
) &
gateway=$!
echo "cdk-dev: the gateway starts once CDK is up (log: target/gateway.log); then type link-secure"

# QEMU in the foreground (it owns the terminal); when it ends, so does the
# gateway, and the container exits with QEMU's status.
./run_qemu.sh
status=$?
pkill -TERM -P "$gateway" 2>/dev/null
kill "$gateway" 2>/dev/null
wait "$gateway" 2>/dev/null
exit "$status"
