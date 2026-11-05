# CDK in Docker (roadmap 5.1). CDK is a kernel, so the container runs QEMU,
# which boots CDK; add `--device /dev/kvm` for hardware acceleration.
#
#   docker build -f docker/Dockerfile --target eval -t cdk:0.3.0 .
#   docker run -it --rm cdk:0.3.0                    # the signed v0.3.0 release
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
# verifier: cdk-sign, built from this source, to check a release's signature.
# (Stable Rust suffices for it; the repository's pinned nightly is not used.)
# ---------------------------------------------------------------------------
FROM ${BASE} AS verifier
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.93.0
COPY link /src/link
COPY gateway /src/gateway
RUN cd /src/gateway && cargo build --release --locked --quiet --bin cdk-sign \
    && cp target/release/cdk-sign /usr/local/bin/

# ---------------------------------------------------------------------------
# eval: a published release image. The build stops unless SHA256SUMS is
# signed (Ed25519 + ML-DSA-65) by the CDK release key with the pinned id —
# the same key for every release — and every file matches it.
# ---------------------------------------------------------------------------
FROM runtime AS eval
ARG VERSION=0.3.0
ARG RELEASE_KEY_ID=0b57f6795dcdf315f2512079b8e16ba8
ARG RELEASE_URL=https://github.com/RanveerMeel/cdk/releases/download/v${VERSION}
WORKDIR /opt/cdk
COPY --from=verifier /usr/local/bin/cdk-sign /usr/local/bin/cdk-sign
ADD ${RELEASE_URL}/SHA256SUMS ${RELEASE_URL}/SHA256SUMS.sig ${RELEASE_URL}/cdk-release.pub \
    ${RELEASE_URL}/cdk-${VERSION}-eval.img ${RELEASE_URL}/cdk-${VERSION}-eval.measurements \
    ${RELEASE_URL}/RELEASE-NOTES.md ./
RUN cdk-sign verify-file SHA256SUMS --pub cdk-release.pub | tee /tmp/verify \
    && grep -qx "ok: SHA256SUMS is signed by release key ${RELEASE_KEY_ID}" /tmp/verify \
    && sha256sum -c --ignore-missing SHA256SUMS \
    && ln -s cdk-${VERSION}-eval.img cdk-eval.img \
    && rm /tmp/verify
COPY docker/boot-eval.sh /usr/local/bin/cdk-boot
# v0.2.0 starts its other CPUs through the xAPIC registers after switching
# to x2APIC (fixed in 0.3.0): build it with --build-arg CPU=max,-x2apic.
ARG CPU=max
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
# The nightly CDK is built and released with, as pinned in
# rust-toolchain.toml (installed from that file).
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
WORKDIR /cdk
COPY rust-toolchain.toml .
RUN rustup toolchain install --profile minimal && rustc -V
COPY . .
# Dependencies only (offline later). Keys are made at first run, in the
# target/ volume — never baked into the image.
RUN for d in . link gateway user user/ml tools/create_disk_image boot/uefi-loader; do \
        (cd "$d" && cargo fetch --quiet) || exit 1; done
COPY docker/dev.sh /usr/local/bin/cdk-dev
VOLUME /cdk/target
ENTRYPOINT ["/usr/local/bin/cdk-dev"]
