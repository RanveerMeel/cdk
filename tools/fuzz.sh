#!/bin/bash
# Fuzz CDK's parsers of untrusted bytes (roadmap 4.3); needs cargo-fuzz.
#
#   tools/fuzz.sh [SECONDS] [TARGET...]   fuzz each target (default: all, 60 s), in parallel
#   tools/fuzz.sh --replay                run every seed and regression input once (CI)
#   tools/fuzz.sh --list                  list targets
#
# Corpora grow in fuzz/corpus/<target>/ (not committed). A crash is written to
# fuzz/artifacts/<target>/; once fixed, copy it to fuzz/regressions/<target>/
# with a descriptive name so it is replayed forever.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TARGETS=(frame_decoder link_messages sealed_channel handshake hybrid_verify elf initrd policy spool_decision boot_attest ek_certificate vsock)
python3 tools/gen_fuzz_seeds.py >/dev/null

dirs() { # target -> corpus dirs (first one writable)
    mkdir -p "fuzz/corpus/$1"
    local d=("fuzz/corpus/$1")
    [ -d "fuzz/seeds/$1" ] && d+=("fuzz/seeds/$1")
    [ -d "fuzz/regressions/$1" ] && d+=("fuzz/regressions/$1")
    echo "${d[@]}"
}

case "${1:-}" in
    --list) printf '%s\n' "${TARGETS[@]}"; exit 0 ;;
    --replay)
        cargo fuzz build -O >/dev/null
        mkdir -p target/fuzz-logs
        for t in "${TARGETS[@]}"; do
            log="target/fuzz-logs/replay-$t.log"
            # shellcheck disable=SC2046
            if cargo fuzz run -O "$t" $(dirs "$t") -- -runs=0 > "$log" 2>&1; then
                echo "$t: ok"
            else
                echo "$t: FAILED"; grep -a -E "panicked|SUMMARY|ERROR" "$log" | head -5; exit 1
            fi
        done
        exit 0 ;;
esac

SECS="${1:-60}"; shift || true
[ $# -gt 0 ] && TARGETS=("$@")
cargo fuzz build -O >/dev/null
mkdir -p target/fuzz-logs
fail=0
for t in "${TARGETS[@]}"; do
    # shellcheck disable=SC2046
    (cargo fuzz run -O "$t" $(dirs "$t") -- -max_total_time="$SECS" -rss_limit_mb=2048 \
        > "target/fuzz-logs/$t.log" 2>&1) &
done
for job in $(jobs -p); do wait "$job" || fail=1; done
for t in "${TARGETS[@]}"; do
    printf '%-16s %s\n' "$t" "$(grep -a -E 'Done [0-9]+ runs|panicked at|SUMMARY' "target/fuzz-logs/$t.log" | head -1)"
done
[ $fail -eq 0 ] || { echo "a target failed — see target/fuzz-logs/ and fuzz/artifacts/"; exit 1; }
