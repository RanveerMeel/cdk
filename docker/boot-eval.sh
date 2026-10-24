#!/bin/sh
# Boot the CDK evaluation image in QEMU with a software TPM (UEFI by default,
# so the firmware → CDK loader → kernel chain is measured into the TPM).
#   CDK_BOOT=bios  CDK_SMP=N  CDK_QEMU_ACCEL=kvm|tcg  CDK_CPU=model  CDK_EXTRA="qemu args"
# State (the TPM, so its attestation key persists) lives in /var/lib/cdk.
set -eu
STATE=/var/lib/cdk
mkdir -p "$STATE/tpm"
rm -f "$STATE/tpm/sock"
swtpm socket --tpm2 --tpmstate dir="$STATE/tpm" --ctrl type=unixio,path="$STATE/tpm/sock" \
    --terminate --log file="$STATE/tpm/swtpm.log",level=1 &
i=0; while [ ! -S "$STATE/tpm/sock" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done

ACCEL="${CDK_QEMU_ACCEL:-}"
if [ -z "$ACCEL" ]; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ACCEL=kvm; else ACCEL=tcg; fi
fi
FIRMWARE=""
if [ "${CDK_BOOT:-uefi}" = "uefi" ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd "$STATE/ovmf-vars.fd"
    FIRMWARE="-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd -drive if=pflash,format=raw,file=$STATE/ovmf-vars.fd"
fi
echo "CDK v${CDK_VERSION} evaluation image — ${CDK_BOOT:-uefi} boot, accel $ACCEL, TPM: swtpm"
echo "Type 'help' at the cdk> prompt; Ctrl-A X quits QEMU."
# shellcheck disable=SC2086
exec qemu-system-x86_64 $FIRMWARE -accel "$ACCEL" -cpu "${CDK_CPU:-max}" -smp "${CDK_SMP:-4}" \
    -drive format=raw,file=/opt/cdk/cdk-eval.img,snapshot=on \
    -chardev "socket,id=chrtpm,path=$STATE/tpm/sock" -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -serial mon:stdio -display none -no-reboot ${CDK_EXTRA:-}
