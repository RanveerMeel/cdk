#!/bin/bash
# The NIST ACVP tests (link/tests/acvp.rs) exercise the crypto crates as
# resolved for link/; this checks the kernel links exactly the same
# versions, so the tested code is the shipped code (roadmap 1.5).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATES=(ml-dsa ml-kem ed25519-dalek curve25519-dalek sha2 sha3 keccak module-lattice)
versions() { # lockfile crate -> sorted versions
    awk -v c="$2" '$1 == "name" && $3 == "\"" c "\"" { getline; gsub(/"/, "", $3); print $3 }' "$1" | sort -u | tr '\n' ' '
}
fail=0
for c in "${CRATES[@]}"; do
    k="$(versions "$ROOT/Cargo.lock" "$c")"
    l="$(versions "$ROOT/link/Cargo.lock" "$c")"
    if [ -z "$k" ]; then continue; fi
    if [ "$k" != "$l" ]; then
        echo "MISMATCH $c: kernel $k / link $l"
        fail=1
    else
        echo "ok $c $k"
    fi
done
exit $fail
