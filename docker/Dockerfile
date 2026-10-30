# CDK in Docker (roadmap 5.1). CDK is a kernel, so the container runs QEMU,
# which boots CDK; add `--device /dev/kvm` for hardware acceleration.
#
#   docker build -f docker/Dockerfile --target eval -t cdk:0.2.0 .
#   docker run -it --rm cdk:0.2.0                    # the signed v0.2.0 release
#
#   docker build -f docker/Dockerfile --target dev -t cdk:dev .
#   docker run -it --rm --init -v cdk-target:/cdk/target cdk:dev   # full stack from source
#
# See docker/README.md.

# Debian 13 (trixie), pinned by digest.
ARG BASE=debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

# QEMU, UEFI firmware (OVMF) and a software TPM.
FROM ${BASE} AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends qemu-system-x86 ovmf swtpm ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# eval: the published release image, checked against its signed checksums.
# ---------------------------------------------------------------------------
FROM runtime AS eval
ARG VERSION=0.2.0
# SHA-256 of that release's SHA256SUMS (itself signed with the release key
# 0b57f6795dcdf315f2512079b8e16ba8; see docs/releases/v0.2.0.md).
ARG SUMS_SHA256=0a7c19424beea49065d3bed6cbc91569dc95ee9b376f842298bb1357ac8bca3d
ARG RELEASE_URL=https://github.com/RanveerMeel/cdk/releases/download/v${VERSION}
WORKDIR /opt/cdk
ADD ${RELEASE_URL}/SHA256SUMS ${RELEASE_URL}/SHA256SUMS.sig ${RELEASE_URL}/cdk-release.pub \
    ${RELEASE_URL}/cdk-${VERSION}-eval.img ${RELEASE_URL}/cdk-${VERSION}-eval.measurements \
    ${RELEASE_URL}/RELEASE-NOTES.md ./
RUN echo "${SUMS_SHA256}  SHA256SUMS" | sha256sum -c - \
    && sha256sum -c --ignore-missing SHA256SUMS \
    && ln -s cdk-${VERSION}-eval.img cdk-eval.img
COPY docker/boot-eval.sh /usr/local/bin/cdk-boot
# v0.2.0 starts its other CPUs through the xAPIC registers even when it
# has switched to x2APIC (fixed after 0.2.0), so this image hides x2APIC.
ARG CPU=max,-x2apic
ENV CDK_VERSION=${VERSION} CDK_CPU=${CPU}
VOLUME /var/lib/cdk
ENTRYPOINT ["/usr/local/bin/cdk-boot"]

# ---------------------------------------------------------------------------
# dev: the repository with its toolchain; builds and runs kernel + gateway.
# ---------------------------------------------------------------------------
FROM runtime AS dev
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl git python3 openssl \
        swtpm-tools tpm2-tools \
    && rm -rf /var/lib/apt/lists/*
# The nightly CDK is built and released with, installed as "nightly" (the
# scripts call `rustup run nightly`).
ARG NIGHTLY=nightly-2026-08-05
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && rustup toolchain install ${NIGHTLY} --profile minimal \
        --component rust-src,llvm-tools-preview,rustfmt,clippy \
        --target x86_64-unknown-none,x86_64-unknown-uefi \
    && host="$(rustc +stable -vV | sed -n 's/^host: //p')" \
    && mv "$RUSTUP_HOME/toolchains/${NIGHTLY}-$host" "$RUSTUP_HOME/toolchains/nightly-$host" \
    && rustc +nightly -V
WORKDIR /cdk
COPY . .
# Dependencies only (offline later). Keys are made at first run, in the
# target/ volume — never baked into the image.
RUN for d in . link gateway user user/ml tools/create_disk_image boot/uefi-loader; do \
        (cd "$d" && cargo +nightly fetch --quiet) || exit 1; done
COPY docker/dev.sh /usr/local/bin/cdk-dev
VOLUME /cdk/target
ENTRYPOINT ["/usr/local/bin/cdk-dev"]
