#!/bin/bash
# The kernel must never use the x87/MMX/SSE/AVX registers (roadmap 2.6): they
# hold the interrupted agent's state, which the kernel switches only between
# agents (src/fpu.rs). Its target disables those features; this checks the
# built kernel anyway. Allowed: the save/restore instructions themselves.
#
#   tools/check_kernel_no_simd.sh [kernel ELF]
set -euo pipefail
KERNEL="${1:-target/x86_64-unknown-none/release/cdk}"
[ -f "$KERNEL" ] || { echo "check_kernel_no_simd: $KERNEL not found (build the kernel first)" >&2; exit 1; }
# Instruction lines are "addr:<TAB>mnemonic operands  # comment"; look at the
# mnemonic and operands only (AT&T syntax).
BAD="$(objdump -d --no-show-raw-insn "$KERNEL" | awk -F'\t' 'NF >= 2 && $1 ~ /:$/ {
        insn = $2; sub(/#.*/, "", insn); split(insn, w, " "); m = w[1]
        if (m ~ /^(xsave64|xrstor64|fxsave64|fxrstor64|xsetbv|xgetbv)$/) next
        if (insn ~ /%([xyz]mm[0-9]|st|mm[0-7])/ || m ~ /^(f[a-z0-9]+|emms|ldmxcsr|stmxcsr|vzero(upper|all))$/) print
    }' || true)"
if [ -n "$BAD" ]; then
    echo "check_kernel_no_simd: the kernel uses FPU/vector registers:" >&2
    echo "$BAD" | head -20 >&2
    exit 1
fi
echo "check_kernel_no_simd: OK — no x87/MMX/SSE/AVX use in $KERNEL (only state save/restore)"
