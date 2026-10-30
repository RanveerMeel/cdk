# Deploying CDK

CDK is a kernel. It cannot run *as* a container — containers share the
host's Linux kernel — and its guarantees (isolation of agents, measured
boot, sealed keys) depend on owning the machine it boots on. So CDK always
runs as a **virtual machine** (or on bare metal), and everything around it
uses tools people already have.

This page describes the target model and what works today. The plan and its
order are roadmap Phase 5 ([ROADMAP.md](../ROADMAP.md)): each step is meant
to be put in front of users before the next one gets more complex.

## The building block: one CDK node

```
┌──────────── CDK VM (own kernel, own TPM) ──────────────┐       ┌──── Gateway (Linux container) ─────┐
│ agents (ring 3, from the release-signed ramdisk)       │       │ MCP tools, model endpoints (vLLM…) │
│ capabilities · policy review · audit log · sealed store│◄─────►│ API keys and other credentials     │
│ verified + measured boot                               │ link  │ approval spool, node authority     │
└────────────────────────────────────────────────────────┘       └────────────────────────────────────┘
```

* The **CDK VM** holds the trust: what each agent may do, human approvals,
  the audit log, and keys that never leave it.
* The **gateway** is an ordinary Linux process (a container in practice):
  it reaches the network, model servers and GPUs, and holds credentials so
  agents never see them. CDK does not trust it: the link is post-quantum
  encrypted and authenticated, the gateway must accept CDK's attestation
  before serving it, and everything it carries is verified by the kernel.

What changes between environments is only *how the VM is started* and *how
the two halves are connected* (the link: virtio-console today, virtio-vsock
next — roadmap 5.2).

## Environments

| Environment | How CDK runs | Status |
|---|---|---|
| **Docker** (development, demos, CI, evaluation) | QEMU inside a container boots CDK; `--device /dev/kvm` makes it fast | Works (roadmap 5.1) |
| **Kubernetes** (production) | A pod whose runtime is a micro-VM (Kata Containers or KubeVirt) boots CDK with a persistent vTPM; the gateway is a sidecar container in the same pod, connected over vsock; CDK images ship as OCI images (containerDisk) | Roadmap 5.2–5.4 |
| **Cloud VM** | A custom image on a KVM-based cloud; on **confidential VMs** (AMD SEV-SNP, Intel TDX) even the cloud operator cannot read agent memory or keys | Roadmap 5.3, 5.5 |
| **Bare metal / appliance** (edge, branches, air-gapped) | CDK boots directly with Secure Boot and a discrete TPM; later, with Linux in a driver VM for GPUs (roadmap 4.4) | Works in QEMU today; hardware profile is roadmap 5.8 |

## From agents to a running node

1. **Write agents** — programs against CDK's syscall interface (`user/`;
   Rust today).
2. **Build the image** — agents, `policy.rules`, pinned keys (gateway,
   operators, registry root) go into a ramdisk whose manifest is signed with
   *your* release key; the build is reproducible and produces the expected
   boot measurements (`tools/release.sh`; a one-command builder is roadmap
   5.6).
3. **Deploy** — boot the image (Docker, Kubernetes, cloud, bare metal) with
   its gateway. The gateway checks the node's attestation (`--expect`, TPM
   quote, endorsement), certifies it under its node authority, and serves
   it; the node opens its sealed store. On a new machine — a TPM that has
   never held a store — the operator creates it once with `store-reset`
   after the first `link-secure` (a reviewed decision; until then the node
   refuses peers' messages and imports).
4. **Operate** — operators approve actions with their own keys, using
   `cdk-approve` (`tools/approve.sh init <name>`, `list`, `approve <id>
   --key …` builds and runs it from the repository; on an operator's machine,
   `cargo install --path gateway --bin cdk-approve --target "$(rustc -vV |
   sed -n 's/^host: //p')"` puts it on `PATH`);
   audit checkpoints are exported; updates are signed with the release key
   and prepared with `store-migrate`.

## What works today

* **Docker** ([docker/README.md](../docker/README.md)): `cdk:0.2.0` boots the
  signed release (checked at build) at the `cdk>` prompt; `cdk:dev` runs the
  whole stack from source in one container. Both use KVM with
  `--device /dev/kvm`.
* `./run_qemu.sh` + `tools/run_gateway.sh` on a Linux machine: everything —
  verified and measured boot with a software TPM, the gateway, tools and
  models, signed approvals, distributed capabilities, the sealed store.
* The [v0.2.0 release](https://github.com/RanveerMeel/cdk/releases/tag/v0.2.0)
  evaluation image boots in QEMU (BIOS or UEFI) without building anything.
* Not yet: running directly on a cloud hypervisor or physical server. CDK
  has only been tested on QEMU's virtual hardware; its link needs QEMU's
  virtio-console, and its TPM driver the TIS interface (cloud vTPMs and
  firmware TPMs use CRB). Those are roadmap 5.2 and 5.3.
