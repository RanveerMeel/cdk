#!/bin/bash
# "Manufacture" a software TPM (swtpm) the way a TPM vendor does a real one:
# endorsement keys plus EK certificates signed by a manufacturer CA, so that
# cdk-gateway --tpm-ca can check the TPM is genuine (roadmap 4.2).
#
#   tools/tpm_manufacture.sh [STATE_DIR] [CA_DIR]
#       STATE_DIR  swtpm state to create (default target/tpm; must not exist
#                  yet, since the endorsement seed is fixed at manufacture)
#       CA_DIR     test manufacturer CA (default target/tpm-manufacturer;
#                  created on first use). CA_DIR/trust/ holds only its
#                  certificates: pass that to cdk-gateway --tpm-ca.
#
# swtpm_setup certifies an RSA-2048 and an ECC P-384 EK; real TPMs also ship
# the ECC P-256 EK certificate (TCG template L-2, NV index 0x01c0000a),
# which is the one CDK uses, so this adds it with tpm2-tools.
#
# THIS IS A TEST CA, not a TPM vendor: anyone holding CA_DIR's keys can
# certify any (software) TPM. Real deployments use the vendors' CA
# certificates (Infineon, Nuvoton, STMicroelectronics, ...).
#
# Needs swtpm, swtpm-tools (swtpm_setup, swtpm_localca), tpm2-tools, openssl.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$(realpath -m "${1:-$ROOT/target/tpm}")"
CA="$(realpath -m "${2:-$ROOT/target/tpm-manufacturer}")"
for t in swtpm swtpm_setup swtpm_localca swtpm_ioctl tpm2_createek tpm2_nvdefine openssl; do
    command -v "$t" > /dev/null || { echo "tpm_manufacture: $t not found" >&2; exit 1; }
done
if [ -e "$STATE/tpm2-00.permall" ]; then
    echo "tpm_manufacture: $STATE already holds a TPM (remove it to manufacture a new one)" >&2
    exit 1
fi

# The manufacturer CA: a root and an EK-issuing intermediate (RSA, like most
# TPM vendors' CAs).
if [ ! -f "$CA/signkey.pem" ]; then
    mkdir -p "$CA/trust"
    chmod 700 "$CA"
    (
        cd "$CA"
        openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out trust/root.pem -days 36500 \
            -subj "/O=CDK TEST (not a TPM vendor)/CN=CDK test TPM manufacturer root CA" \
            -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2> /dev/null
        openssl req -newkey rsa:2048 -nodes -keyout signkey.pem -out issuer.csr \
            -subj "/O=CDK TEST (not a TPM vendor)/CN=CDK test TPM EK CA" 2> /dev/null
        printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" > issuer.ext
        openssl x509 -req -in issuer.csr -CA trust/root.pem -CAkey root.key -set_serial 2 \
            -out trust/issuer.pem -days 36500 -extfile issuer.ext 2> /dev/null
        cp trust/issuer.pem issuercert.pem
        echo 1 > certserial
        rm -f issuer.csr issuer.ext
    )
    cat > "$CA/localca.conf" << EOF
statedir = $CA
signingkey = $CA/signkey.pem
issuercert = $CA/issuercert.pem
certserial = $CA/certserial
EOF
    printf -- "--platform-manufacturer CDK\n--platform-version 2.1\n--platform-model QEMU\n" > "$CA/localca.options"
    cat > "$CA/swtpm_setup.conf" << EOF
create_certs_tool = $(command -v swtpm_localca)
create_certs_tool_config = $CA/localca.conf
create_certs_tool_options = $CA/localca.options
active_pcr_banks = sha256
EOF
    echo "tpm_manufacture: created test manufacturer CA in $CA (trust anchors: $CA/trust)"
fi

mkdir -p "$STATE"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
swtpm_setup --tpm2 --tpmstate "$STATE" --create-ek-cert --config "$CA/swtpm_setup.conf" \
    --logfile "$WORK/setup.log" > /dev/null || { cat "$WORK/setup.log" >&2; exit 1; }

# The P-256 EK certificate, as TPM vendors provision it.
PORT=$((20000 + RANDOM % 20000))
swtpm socket --tpm2 --tpmstate dir="$STATE" --server type=tcp,port=$PORT \
    --ctrl type=tcp,port=$((PORT + 1)) --flags not-need-init,startup-clear \
    --daemon --log file="$WORK/swtpm.log"
stop() { swtpm_ioctl --tcp 127.0.0.1:$((PORT + 1)) -s 2> /dev/null || true; }
trap 'stop; rm -rf "$WORK"' EXIT
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$PORT"
for _ in $(seq 1 50); do tpm2_getrandom 1 > /dev/null 2>&1 && break; sleep 0.1; done
tpm2_createek -c "$WORK/ek.ctx" -G ecc -u "$WORK/ek.pem" -f pem > /dev/null
XY="$(openssl ec -pubin -in "$WORK/ek.pem" -text -noout 2> /dev/null | sed -n '/^pub:/,/^ASN1/p' \
    | grep -v '^pub:\|^ASN1' | tr -d ' :\n')"
mkdir -p "$WORK/cert"
swtpm_localca --type ek --ek "x=${XY:2:64},y=${XY:66:64},id=secp256r1" --dir "$WORK/cert" \
    --tpm-spec-family 2.0 --tpm-spec-level 0 --tpm-spec-revision 164 \
    --tpm-manufacturer id:00001014 --tpm-model swtpm --tpm-version id:20191023 --tpm2 \
    --configfile "$CA/localca.conf" --optsfile "$CA/localca.options" --logfile "$WORK/localca.log" \
    || { cat "$WORK/localca.log" >&2; exit 1; }
tpm2_nvdefine 0x01c0000a -C p -s "$(stat -c %s "$WORK/cert/ek.cert")" \
    -a "ppwrite|writedefine|ppread|ownerread|authread|no_da|platformcreate" > /dev/null
tpm2_nvwrite 0x01c0000a -C p -i "$WORK/cert/ek.cert"
tpm2_flushcontext -t > /dev/null
tpm2_shutdown
cp "$WORK/cert/ek.cert" "$STATE/ek-p256.der"
touch "$STATE/.ek-certified"
echo "tpm_manufacture: TPM in $STATE with EK certificates (P-256 at NV 0x01c0000a) from the test CA $CA"
