#!/bin/bash
# Build a CDK release reproducibly, sign it, and write its SBOM.
#
#   tools/release.sh 0.2.0 [--allow-dirty]
#
# 1. Archives the committed source (git archive HEAD).
# 2. Unpacks it into two different directories and builds each from scratch,
#    offline (CARGO_NET_OFFLINE), with the same release key: kernel, agent
#    programs, evaluation ramdisk (programs + default policy, signed manifest;
#    no deployment keys), measuring UEFI loader (pinned to that kernel's
#    SHA-256; unsigned — deployments sign it for Secure Boot), boot image, and the expected
#    boot measurements.
# 3. Requires every artifact to be byte-identical between the two builds.
# 4. Writes SHA256SUMS, signs it with the release key (cdk-sign sign-file:
#    Ed25519 + ML-DSA-65), adds the release public key, the SBOM (CycloneDX)
#    and the release notes, into target/release/v<version>/.
#
# Keys: CDK_RELEASE_KEY / CDK_RELEASE_PUB (default target/release-signing.key
# and target/release.pub). Keep the release key offline (an HSM in production).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="${1:?usage: tools/release.sh VERSION [--allow-dirty]}"
VERSION="${VERSION#v}"
if [ "${2:-}" != "--allow-dirty" ] && [ -n "$(git status --porcelain)" ]; then
    echo "release: the working tree has uncommitted changes (commit, or pass --allow-dirty for a dry run)" >&2
    exit 1
fi
KEY="$(realpath "${CDK_RELEASE_KEY:-$ROOT/target/release-signing.key}")"
PUB="$(realpath "${CDK_RELEASE_PUB:-$ROOT/target/release.pub}")"
[ -f "$KEY" ] && [ -f "$PUB" ] || { echo "release: no release key (tools/sign.sh init)" >&2; exit 1; }

OUT="$ROOT/target/release/v$VERSION"
WORK="$ROOT/target/release/work"
rm -rf "$OUT" "$WORK"
mkdir -p "$OUT" "$WORK"
COMMIT="$(git rev-parse HEAD)"
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
SRC="cdk-$VERSION-src.tar.gz"
git archive --format=tar --prefix="cdk-$VERSION/" HEAD | gzip -n > "$OUT/$SRC"
echo "release: v$VERSION from $COMMIT"

build_tree() { # $1 = directory to unpack and build in
    local dir="$1"
    mkdir -p "$dir"
    tar -xzf "$OUT/$SRC" -C "$dir"
    local tree="$dir/cdk-$VERSION"
    (
        cd "$tree"
        export CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$tree/target"
        export CDK_RELEASE_PUB="$PUB" CDK_RELEASE_KEY="$KEY"
        export CDK_GATEWAY_PUB=/nonexistent CDK_OPERATORS_DIR=/nonexistent CDK_REGISTRY_PUB=/nonexistent
        unset CDK_POLICY_FILE CDK_PRIVATE_PROGRAMS_DIR
        HOST="$(rustc -vV | sed -n 's/^host: //p')"
        cargo build --release --locked --quiet --bin cdk
        tools/build_user_programs.sh "$tree/target/initrd.tar" > "$dir/ramdisk.log" 2>&1
        # The release loader boots only the release kernel (Secure Boot
        # deployments sign it with their own key: tools/secureboot.sh sign).
        (cd boot/uefi-loader && CDK_KERNEL_SHA256="$(sha256sum < ../../target/x86_64-unknown-none/release/cdk | cut -d' ' -f1)" \
            cargo build --release --locked --quiet --target x86_64-unknown-uefi \
            -Zbuild-std=core -Zbuild-std-features=compiler-builtins-mem)
        cargo run --quiet --locked --manifest-path tools/create_disk_image/Cargo.toml --release --target "$HOST" -- \
            target/x86_64-unknown-none/release/cdk target/boot.img target/initrd.tar \
            target/x86_64-unknown-uefi/release/cdk-uefi-loader.efi
        tools/sign.sh measure target/x86_64-unknown-none/release/cdk target/initrd.tar --loader \
            --pub "$PUB" --out target/boot.measurements > /dev/null
        mkdir -p "$dir/artifacts"
        cp target/x86_64-unknown-none/release/cdk "$dir/artifacts/cdk-kernel-x86_64.elf"
        cp target/x86_64-unknown-uefi/release/cdk-uefi-loader.efi "$dir/artifacts/cdk-uefi-loader.efi"
        cp target/initrd.tar "$dir/artifacts/cdk-ramdisk-eval.tar"
        cp target/boot.img "$dir/artifacts/cdk-$VERSION-eval.img"
        cp target/boot.measurements "$dir/artifacts/cdk-$VERSION-eval.measurements"
    )
}

echo "release: build A ..."
build_tree "$WORK/a"
echo "release: build B (another directory) ..."
build_tree "$WORK/b/second/path"

# Reproducibility: every artifact identical.
REPORT="$OUT/REPRODUCIBILITY.txt"
{
    echo "CDK v$VERSION — reproducibility check"
    echo "commit $COMMIT, SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH, $(rustc +nightly -V 2>/dev/null || rustc -V)"
    echo "two clean builds from $SRC in different directories, offline:"
    echo
} > "$REPORT"
same=1
for f in "$WORK/a/artifacts/"*; do
    n="$(basename "$f")"
    a="$(sha256sum < "$f" | cut -d' ' -f1)"
    b="$(sha256sum < "$WORK/b/second/path/artifacts/$n" | cut -d' ' -f1)"
    if [ "$a" = "$b" ]; then
        echo "identical  $a  $n" >> "$REPORT"
    else
        echo "DIFFERENT  $a / $b  $n" >> "$REPORT"
        same=0
    fi
done
cat "$REPORT"
if [ "$same" != 1 ]; then
    echo "release: builds are NOT reproducible — not signing" >&2
    exit 1
fi

cp "$WORK/a/artifacts/"* "$OUT/"
cp "$PUB" "$OUT/cdk-release.pub"
python3 tools/sbom.py "$VERSION" "$OUT/cdk-$VERSION.cdx.json" > "$WORK/sbom.log"
cat "$WORK/sbom.log"
[ -f "docs/releases/v$VERSION.md" ] && cp "docs/releases/v$VERSION.md" "$OUT/RELEASE-NOTES.md"
(cd "$OUT" && sha256sum -- $(ls | grep -v '^SHA256SUMS' | sort) > SHA256SUMS)
tools/sign.sh sign-file "$OUT/SHA256SUMS" --key "$KEY"
tools/sign.sh verify-file "$OUT/SHA256SUMS" --pub "$OUT/cdk-release.pub"
echo
echo "release: v$VERSION ready in $OUT"
ls -la "$OUT"
