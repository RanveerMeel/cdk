#!/bin/bash
# UEFI Secure Boot for CDK (roadmap 4.2): keys, enrolled firmware variables,
# and signing the loader.
#
#   tools/secureboot.sh init               create the Secure Boot key (once)
#   tools/secureboot.sh vars OUT.fd        OVMF variable store with that key
#                                          enrolled as PK, KEK and db, Secure
#                                          Boot on, no Microsoft keys
#   tools/secureboot.sh sign IN.efi OUT.efi   sign a loader (sbsign)
#
# Keys live in CDK_SB_DIR (default target/secureboot): sb.key (0600), sb.crt.
# UEFI only verifies RSA (classical) signatures, so this layer is not
# post-quantum; it stops the machine from *running* an unsigned loader,
# while the post-quantum release signature (kernel -> ramdisk) and the TPM
# attestation (measured boot) do not depend on it.
#
# One key serves as PK, KEK and db here. A production platform keeps the PK
# and KEK offline and signs db updates with them; the db key signs loaders.
# Needs openssl, sbsigntool (sbsign) and python3-virt-firmware (virt-fw-vars).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${CDK_SB_DIR:-$ROOT/target/secureboot}"
OVMF_VARS="${CDK_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
# Owner GUID of CDK's signature-list entries.
OWNER=4b14a0c8-6b2c-4a7e-9d41-cd6b00000001

need() { command -v "$1" > /dev/null || { echo "secureboot: $1 not found ($2)" >&2; exit 1; }; }
have_key() { [ -f "$DIR/sb.key" ] && [ -f "$DIR/sb.crt" ]; }

case "${1:-}" in
init)
    need openssl openssl
    if have_key; then
        echo "secureboot: key already exists in $DIR"
        exit 0
    fi
    mkdir -p "$DIR"
    (umask 077 && openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 36500 \
        -keyout "$DIR/sb.key" -out "$DIR/sb.crt" \
        -subj "/O=CDK/CN=CDK Secure Boot key ($(hostname -s))" 2> /dev/null)
    chmod 644 "$DIR/sb.crt"
    echo "secureboot: created $DIR/sb.key and sb.crt ($(openssl x509 -in "$DIR/sb.crt" -noout -fingerprint -sha256 | cut -d= -f2))"
    ;;
vars)
    OUT="${2:?usage: secureboot.sh vars OUT.fd}"
    need virt-fw-vars python3-virt-firmware
    have_key || { echo "secureboot: no key (tools/secureboot.sh init)" >&2; exit 1; }
    virt-fw-vars --input "$OVMF_VARS" --output "$OUT" \
        --set-pk "$OWNER" "$DIR/sb.crt" --add-kek "$OWNER" "$DIR/sb.crt" --add-db "$OWNER" "$DIR/sb.crt" \
        --no-microsoft --secure-boot > /dev/null 2>&1
    echo "secureboot: $OUT enrolls $DIR/sb.crt (PK, KEK, db), Secure Boot enabled"
    ;;
sign)
    IN="${2:?usage: secureboot.sh sign IN.efi OUT.efi}"
    OUT="${3:?usage: secureboot.sh sign IN.efi OUT.efi}"
    need sbsign sbsigntool
    have_key || { echo "secureboot: no key (tools/secureboot.sh init)" >&2; exit 1; }
    sbsign --key "$DIR/sb.key" --cert "$DIR/sb.crt" --output "$OUT" "$IN" 2> /dev/null
    sbverify --cert "$DIR/sb.crt" "$OUT" > /dev/null 2>&1
    echo "secureboot: signed $OUT"
    ;;
*)
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
