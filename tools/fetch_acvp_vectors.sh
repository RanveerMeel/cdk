#!/bin/bash
# Download the NIST ACVP test vectors CDK's crypto is checked against
# (roadmap 1.5) into target/acvp/. Pinned to one ACVP-Server commit and
# verified by SHA-256; the files are not committed (about 17.5 MB).
#
#   tools/fetch_acvp_vectors.sh            download (skips files already present and valid)
#   tools/fetch_acvp_vectors.sh --print    print the SHA-256 lines (to update the pins)
#
# Source: https://github.com/usnistgov/ACVP-Server (gen-val/json-files),
# NIST test data, a U.S. government work (public domain in the U.S.).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMMIT=975de31eb83d87039ec88934fdc47d8c312b892d
BASE="https://raw.githubusercontent.com/usnistgov/ACVP-Server/$COMMIT/gen-val/json-files"
OUT="${CDK_ACVP_DIR:-$ROOT/target/acvp}"
SETS=(
    ML-DSA-keyGen-FIPS204
    ML-DSA-sigGen-FIPS204
    ML-DSA-sigVer-FIPS204
    ML-KEM-keyGen-FIPS203
    ML-KEM-encapDecap-FIPS203
    EDDSA-KeyGen-1.0
    EDDSA-SigGen-1.0
    EDDSA-SigVer-1.0
    SHA2-256-1.0
)
# sha256  set (of internalProjection.json at $COMMIT)
PINS="$(cat <<'PINS'
e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf ML-DSA-keyGen-FIPS204
72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22 ML-DSA-sigGen-FIPS204
47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437 ML-DSA-sigVer-FIPS204
d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b ML-KEM-keyGen-FIPS203
a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f ML-KEM-encapDecap-FIPS203
8847fbe4a18c980dab179c5dce182ebd0f9f990f409fa359665a8e67bee33fea EDDSA-KeyGen-1.0
794d58fb39f08de4f852d63cb98b95c39bcc38ea42c7d42d09e92c15dadd5d81 EDDSA-SigGen-1.0
8556b9c48ef7ff209a9f866ed83e3c3881cfdd3c4c1ee1abe2602da69c1e97b0 EDDSA-SigVer-1.0
a7e0bf4f5c661f1787b343bf3ae1a809b1e62f8fb2c8a627791510d03a570a6c SHA2-256-1.0
PINS
)"
mkdir -p "$OUT"
for s in "${SETS[@]}"; do
    f="$OUT/$s.json"
    want="$(printf '%s\n' "$PINS" | awk -v s="$s" '$2 == s { print $1 }')"
    if [ -f "$f" ] && [ -n "$want" ] && [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$want" ]; then
        continue
    fi
    curl -fsSL --retry 3 -o "$f.part" "$BASE/$s/internalProjection.json"
    got="$(sha256sum "$f.part" | cut -d' ' -f1)"
    if [ "${1:-}" != "--print" ] && [ "$got" != "$want" ]; then
        rm -f "$f.part"
        echo "$s: SHA-256 mismatch (got $got, pinned ${want:-none})" >&2
        exit 1
    fi
    mv "$f.part" "$f"
done
if [ "${1:-}" = "--print" ]; then
    for s in "${SETS[@]}"; do echo "$(sha256sum "$OUT/$s.json" | cut -d' ' -f1) $s"; done
else
    echo "ACVP vectors (ACVP-Server $COMMIT) in $OUT"
fi
