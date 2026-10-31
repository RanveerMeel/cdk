# CDK in Docker

CDK is a kernel, so it cannot run *as* a container. These images run QEMU,
which boots CDK, with a software TPM — the same way `./run_qemu.sh` does,
on any machine with Docker. Roadmap 5.1; the deployment model is in
[docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md).

## Try the release: `cdk:<version>`

```bash
docker build -f docker/Dockerfile --target eval -t cdk:0.2.0 .
docker run -it --rm cdk:0.2.0
```

The build downloads the release files from GitHub and refuses to finish
unless they match the release's `SHA256SUMS` (whose own hash is pinned in
the Dockerfile; that file is signed with the release key
`0b57f6795dcdf315f2512079b8e16ba8`). At the `cdk>` prompt try `boot`,
`spawn hello`, `run-all`, `policy`, `audit-verify`; **Ctrl-A X** quits.

| Option | Effect |
|---|---|
| `--device /dev/kvm` | Hardware acceleration (KVM), about ten times faster |
| `-e CDK_BOOT=bios` | BIOS instead of UEFI (no loader measurements) |
| `-e CDK_SMP=1` | One CPU instead of four |
| `-v cdk-tpm:/var/lib/cdk` | Keep the software TPM (its attestation key) between runs |

The evaluation image has no deployment keys, so there is no gateway: no
tools, models, signed approvals or distributed capabilities. For those, use
`cdk:dev`.

## The full stack from source: `cdk:dev`

```bash
docker build -f docker/Dockerfile --target dev -t cdk:dev .
docker run -it --rm --init --device /dev/kvm -v cdk-target:/cdk/target cdk:dev
```

The container builds the kernel, agents, loader and gateway (the first run
takes several minutes; the `cdk-target` volume keeps every build — kernel,
agents and gateway — plus the keys and the TPM for the next), boots CDK with the serial console in your terminal, and
starts the gateway as soon as CDK is up. Then:

```
cdk> link-secure        # post-quantum link + attestation + sealed store
cdk> store-reset        # first run only: create the TPM-sealed store
cdk> tools-sync         # the demo MCP tools appear as objects
```

**Ctrl-C** quits (QEMU and the gateway); `--init` lets `docker stop` end
it cleanly too. If the gateway stops, a notice appears on the console and
its log is in the volume (`target/gateway.log`). A first run takes about four minutes with KVM (mostly
compiling), later ones about a minute. `docker run … cdk:dev --shell` opens a shell in the repository instead
(`./run_qemu.sh`, `tools/run_gateway.sh`, `cargo test-host`, …). Keys —
release, gateway identity, registry root — are created on first run inside
the volume, never in the image. The toolchain is the nightly CDK is built
and released with, so builds match the repository's.

## The link over vsock

`CDK_LINK=vsock` connects kernel and gateway over virtio-vsock (roadmap
5.2), as on micro-VM hypervisors. QEMU needs the host's vhost-vsock device:

```bash
docker run -it --rm --init --device /dev/kvm --device /dev/vhost-vsock \
    -e CDK_LINK=vsock -v cdk-target:/cdk/target cdk:dev
```

Docker's default security profiles (seccomp and AppArmor) forbid vsock
sockets inside containers, so the gateway in this container cannot connect;
run it on the host instead, as it would run beside a real micro-VM — with
this volume's gateway key (it is pinned in CDK's ramdisk):

```bash
docker run --rm -v cdk-target:/t --entrypoint cat cdk:dev /t/gateway-identity.key > gw.key && chmod 600 gw.key
gateway/target/x86_64-unknown-linux-gnu/release/cdk-gateway --identity gw.key \
    --mcp "demo=python3 gateway/examples/demo_mcp_server.py" vsock:3
```

## Notes

* Without `--device /dev/kvm` both images use QEMU's emulation (slow, but
  needs no privileges). The firmware measures the virtual CPU, so a volume's
  TPM enrollment made under one mode is refused under the other: keep using
  the same mode, or enroll again. With it, the container can use KVM even if your
  user cannot open `/dev/kvm` directly — the Docker daemon runs as root
  (and membership of the `docker` group is equivalent to root).
* Docker installed as a snap can only bind-mount files under your home
  directory.
* v0.2.0 starts its other CPUs through the xAPIC registers even after
  switching to x2APIC, which QEMU 10 and KVM offer; the `cdk:0.2.0` image
  therefore hides x2APIC (`CDK_CPU=max,-x2apic`). Fixed after 0.2.0.
