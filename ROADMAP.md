# CDK Roadmap — Quantum-Safe Agent Trust Kernel

CDK is an open-source, capability-secured Rust kernel for running AI agents
under **kernel-enforced, cryptographically provable permissions**, built on
**post-quantum cryptography** from the start.

This document is the plan of record. Status markers: ✅ done · 🚧 in progress · ⬜ planned.

---

## 1. Vision

Operating-system vendors are adding agents on top of general-purpose kernels,
where every permission check is ultimately bypassable by anything that
compromises the kernel underneath. CDK takes the opposite approach:

- **Agents are isolated processes.** An agent can only touch an object, tool,
  model, or network endpoint if it holds a capability for it.
- **Capabilities are issued and verified by the kernel**, signed with a hybrid
  classical + post-quantum signature, so they cannot be forged — today or by a
  future quantum computer.
- **Every consequential action is recorded** in a tamper-evident, signed audit
  log that a third party can verify.
- **Humans stay in control.** Actions marked consequential require a human
  approval capability; the kernel enforces it, not the agent.

### What CDK is not

- Not a general-purpose desktop or mobile OS, and not a Linux replacement.
- Not a GPU driver project. Heavy inference runs on Linux (with CUDA or other
  vendor stacks); CDK is the control plane that decides which agent may use
  which model, with what data, and records that it happened.

## 2. Design principles

1. **Least privilege, no ambient authority** — no root user, no global
   namespace an agent can reach without a capability.
2. **Quantum-safe by default** — hybrid signatures (Ed25519 + ML-DSA-65,
   FIPS 204) and hybrid key exchange (X25519 + ML-KEM-768, FIPS 203). Both
   halves must verify.
3. **Crypto agility** — every token, log record, and channel carries an
   algorithm identifier so algorithms can be replaced without a redesign.
4. **No secret cryptography** — all cryptography lives in the open core and is
   publicly reviewable. Security rests on keys, never on hidden algorithms.
5. **Interoperate** — speak MCP (Model Context Protocol) and standard virtio
   transports instead of inventing closed protocols.
6. **Human-in-the-loop for consequential actions**, enforced by the kernel.
7. **Precise claims** — "quantum-safe" means NIST post-quantum algorithms in
   hybrid mode; never "unbreakable".

## 3. Architecture target

```
┌────────────────────────── one machine / node ──────────────────────────┐
│                                                                        │
│  CDK (trust kernel)                          Linux (host or VM)        │
│  ├─ agents = ring-3 processes                ├─ GPU driver + CUDA/...  │
│  ├─ capability tokens (hybrid PQ-signed)     ├─ inference servers      │
│  ├─ policy + human-approval gates            └─ MCP tool servers       │
│  ├─ tamper-evident signed audit log                  ▲                 │
│  └─ PQ-secure channel (X25519+ML-KEM) ◄── virtio-vsock ┘               │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

Longer term, CDK can move underneath Linux as a small hypervisor with Linux
demoted to a sandboxed driver VM (see Phase 4).

---

## 4. Phases and milestones

### Phase 0 — Kernel foundation ✅

Boot, IDT, paging, heap, preemptive scheduler, SMP bring-up (M1–M20), ring-3
entry, ELF64 loader, process table, user address spaces isolated in their own
PML4 slot, `SYS_exit` returning to the kernel, `SYS_write` with checked user
copies, address-space teardown. See `README.md` for the full list.

### Phase 1 — Quantum-safe trust core

| # | Milestone | Status |
|---|---|---|
| 1.1 | **Issuer-bound, hybrid post-quantum capability tokens.** A kernel issuer identity (Ed25519 + ML-DSA-65) is generated at boot. Tokens carry a format version, algorithm ID, issuer key ID, and a canonical, domain-separated digest. Verification checks the signature against the **pinned issuer key**, not a key embedded in the token (fixes a forgery hole in the original design, where any self-signed token verified). | ✅ |
| 1.2 | **Tamper-evident audit log.** Append-only, hash-chained records (SHA-256) of capability issuance, use, denial, and process lifecycle; hybrid-signed checkpoints every 64 records; console `audit` / `audit-verify`. Exporting checkpoints off the machine follows in Phase 3. | ✅ |
| 1.3 | **User-fault containment.** CPU exceptions raised in ring 3 (`#DE #OF #BR #UD #NM #NP #SS #GP #PF #MF #AC #XM #BP`) terminate the offending process (`Crashed`, exit code 128 + vector, audit-logged) and return to the kernel; kernel-mode faults print diagnostics and halt instead of escalating to a double fault. | ✅ |
| 1.4 | **Key hygiene.** Secret keys zeroized on drop (dependency `zeroize` features) and seeds wiped after use; issuer secrets live only in the non-`Clone`, non-`Debug` `Issuer`; the crypto stack is scrubbed after every operation and kernel heap blocks are zeroed on free; no secret-dependent comparisons in CDK code (signature checks are inside the audited crates); known-answer tests for Ed25519 (RFC 8032) and ML-DSA-65 key generation (IETF LAMPS example); a verified-proof cache makes repeated capability checks ~30x cheaper. | ✅ |
| 1.5 | **NIST test vectors.** All NIST ACVP vectors for the parameter sets CDK uses, except HashML-DSA pre-hash — ML-DSA-65 keyGen/sigGen/sigVer (FIPS 204: external pure with contexts, deterministic and hedged, internal, external-μ), ML-KEM-768 keyGen/encapsulation/decapsulation incl. implicit rejection and key checks (FIPS 203), Ed25519 keyGen/sigGen/sigVer (pure and ph), SHA-256 AFT, Monte Carlo and 1–8 GiB large-data (FIPS 180-4) — 854 NIST test cases, all passing (the large-data SHA-256 cases run on demand); HashML-DSA pre-hash (45, unused by CDK) is reported as skipped. Vectors are fetched from a pinned ACVP-Server commit and SHA-256-checked (`tools/fetch_acvp_vectors.sh`), run in CI with the kernel's backends, and `tools/check_crypto_versions.sh` checks that the kernel links the tested crate versions. RFC vectors cover HKDF-SHA256, X25519 and ChaCha20-Poly1305. This is self-testing against NIST's published vectors, not a CAVP certificate or FIPS 140 validation. | ✅ |

### Phase 2 — Agent runtime

| # | Milestone | Status |
|---|---|---|
| 2.1 | **Programs from the boot ramdisk.** User programs written in Rust (`user/`, static ET_EXEC at the user base, large code model) are packed into a reproducible `ustar` ramdisk; the kernel parses it strictly (checksums, bounds), loads programs with a 64 KiB stack plus guard page, and records each image's SHA-256 in the audit log. Console `ls`, `spawn`, `exec`. | ✅ |
| 2.2 | **Agents hold capability handles.** Per-process table of kernel-held tokens referenced by index; syscalls `cap_list`, `cap_drop`, `cap_derive` (attenuation only, re-issued with hybrid PQ signatures), `send`/`recv` to the handle's object; every use re-verified and permission-checked; grants, derivations, and denials audit-logged. Console `grant`, `handles`, `exec <prog> <obj> <perms>`. | ✅ |
| 2.3 | **Preemptive scheduling of agents (one CPU).** Timer entry stubs save full register frames; round-robin switching at ring-3 interrupt boundaries (100 ms slice); per-process CPU budget watchdog (10 s default) kills runaway agents; `run-all`, `budget`, `slice`, `getpid`. | ✅ |
| 2.4 | **Native CPU inference.** `cdk-ml`: integer-only (`no_std`, no FPU) `CDKLM1` int8 linear-model format and runtime with a hashed-trigram text featurizer; public demo model trained reproducibly by `tools/train_demo_model.py` and cross-checked bit-for-bit against an independent Python implementation; `classify` agent reads messages through a capability handle. Proprietary agents and models are packed into the ramdisk from outside the repository (`CDK_PRIVATE_PROGRAMS_DIR`), never committed. | ✅ |
| 2.5 | **Human-approval gates.** `RequiresApproval` is a signed capability constraint that derived handles can never drop. A `send` through a gated handle blocks the agent (syscalls now save a full register frame, so any syscall can park a process); the console immediately shows the exact, sanitized payload; the kernel performs the send only on approval, otherwise the agent gets `HumanDenied`. Requests and decisions are audit-logged. | ✅ |
| 2.8 | **Signed operator approvals.** With operator keys pinned in the ramdisk (`operator-<name>.pub`, hybrid Ed25519 + ML-DSA-65, made by `cdk-approve init`), a typed `y` no longer approves: every approval-gated agent action and every policy change (2.9) becomes a signed request sent through the gateway; operators approve or deny it with `cdk-approve` on their own device, and CDK verifies each signature (FIPS 204 context `CDK-APPROVAL-v1`) over a statement binding this boot's kernel issuer, the request id, the exact payload digest, the text shown, the quorum and the decision — so the gateway cannot forge, alter or replay one. Policy rules `quorum <label\|policy> <n>` require M distinct operators; any valid denial vetoes; `approval-timeout` denies unanswered requests. Every vote is audit-logged with a digest of its signature; unknown keys, bad signatures and duplicates are logged and ignored. Review cannot be switched off while operator keys are pinned. Without keys CDK stays in console mode (lab). Hardware-token operator keys and an approval UI on a second device are follow-ups. | ✅ |
| 2.6 | **Per-agent FPU/SSE/AVX state** ✅: every CPU enables x87/SSE/AVX (AVX-512 when present) with `XSAVE` (`FXSAVE` fallback); each process slot has its own save area, reset to a clean state for every new agent, restored on entry and saved on preemption, blocking or migration — no agent sees another's registers. The kernel never touches those registers (its target disables them; `tools/check_kernel_no_simd.sh` checks every build in CI). Agents build for `user/x86_64-cdk-user.json` (hardware floating point, SSE2 baseline, AVX via runtime detection). Tested with the `fpu` agent: six agents holding all sixteen 256-bit YMM registers while preempted every tick and moved across three CPUs stay intact, and a run with switching disabled shows every register corrupted. | ✅ |
| 2.7 | **Agents on every CPU** ✅: every AP boots onto a private stack with its own TSS, IDT and SYSCALL MSRs and runs agents; the process table tracks the running process, slice and cursor per CPU; agents get a home CPU and idle CPUs take queued work; the console's CPU supervises (human approvals, tool results). Syscalls lock the kernel themselves instead of using a reference lent by the console, and console output is serialized per line. Tested in QEMU with 4 CPUs: parallel CPU-bound agents, three `chaos` fuzzers at once (60,000 hostile syscalls) with the audit log verifying, simultaneous watchdog kills and faults on different CPUs, and the full fraud demo with agents moving between CPUs. | ✅ |
| 2.9 | **Policy change review.** Every grant (`grant`, `exec … <obj> <perms>`, or a staged batch: `policy begin` … `commit`), policy edit, and gateway listing change is shown as a *reach diff* — which agent gains which permission on which object, with its labels (`tool`, `model`, `credential`, `remote`, operator labels) and endpoint, and whether it is human-gated — checked against invariant rules (`deny <l>`, `separate <a> <b>`, `approval <l>`), and applied only after the operator approves; rule violations are refused outright. The gateway now reports each tool's credential/remote flags and endpoint; CDK pins the approved listing, re-confirms it every session, and blocks calls (`EPOLICY`) to any tool or model whose listing changed (e.g. gained a key or moved host) until the change is reviewed. Boot policy from the ramdisk (`policy.rules`; default requires approval for `credential` and `remote`), fail-closed if malformed. `cap_derive` needs no review: attenuation provably preserves every rule. Decisions are audit-logged with a digest of the reviewed diff. Signed approvals of the diff follow in 2.8. | ✅ |

### Phase 3 — Connected agents

| # | Milestone | Status |
|---|---|---|
| 3.1 | **Host link.** virtio-console transport (port 0, polled split virtqueues; no host privileges, unlike vhost-vsock) with shared `cdk-link` framing (magic, length, CRC-32, resync) and a host gateway (`gateway/`); `link`, `link-ping`, `link-send`, `link-recv`. A vhost-vsock backend can follow where the host allows it. | ✅ |
| 3.2 | **PQ-secure channel.** Hybrid X25519 + ML-KEM-768 key exchange (HKDF-SHA256 over the transcript); both sides sign the transcript with Ed25519 + ML-DSA-65 (`CDK-LINK-v1`); CDK pins the gateway identity from the ramdisk (`gateway.pub`); ChaCha20-Poly1305 with strictly ordered per-direction sequence numbers; `link-secure`, audit `link-secure` / `link-rejected`. | ✅ |
| 3.3 | **MCP gateway.** Gateway tools become kernel objects `tool:<name>` (`tools-sync`); agents call them with `tool_call` (syscall 9) through a handle carrying `exec`, optionally approval-gated; calls go sealed over the 3.2 channel, the gateway runs MCP `tools/call` on its configured servers (stdio JSON-RPC, optional allowlist), and every call and result is audit-logged (`tool-call` with the arguments' SHA-256, `tool-result`). The agent blocks until the result or a 15 s timeout. | ✅ |
| 3.4 | **Model inference through Linux-hosted model servers, with credential injection.** Gateway model backends (`--model NAME=URL,...`, any OpenAI-compatible server: vLLM, llama.cpp, Ollama, TensorRT-LLM, or a remote API) appear as kernel objects `model:<name>`, granted per model with `exec` and optionally approval-gated; agents call them with `tool_call` (`ask_model` in the user library). The gateway holds each backend's key (0600 file or env var, removed from the environment, wiped on drop) and adds it only to that backend's own URL: no redirects, no proxy, no key over plaintext http to non-loopback hosts, keys scrubbed from anything returned. Agents and the kernel never see credentials. Long results arrive as chunks (≤ 16 KiB); model calls time out after 90 s (gateway) / 120 s (kernel). GPUs stay with the Linux host's drivers. | ✅ |
| 3.5 | Distributed capabilities: tokens verifiable across CDK nodes via an issuer key registry. | ⬜ |

### Phase 4 — Hardening and platforms

| # | Milestone | Status |
|---|---|---|
| 4.1 | ARM64 port (edge / appliance hardware). | ⬜ |
| 4.2 | **Verified and measured boot** ✅: a release key (hybrid Ed25519 + ML-DSA-65, `cdk-sign init`) signs a manifest of every ramdisk file; its public half is compiled into the kernel, which verifies the manifest at boot before trusting any pinned key, program or policy, and **locks down** (ramdisk hidden, no processes, no link, policy refused) if anything fails — tested against a weakened policy, a smuggled operator key, and a manifest re-signed with another key. Measurement registers (kernel read-only segments, ramdisk, verdict + release key) are audit-logged and **attested** to the gateway with a fresh nonce after every handshake; with `--expect` (from `cdk-sign measure`) the gateway serves no tools, models or approvals to a CDK that boots anything else. **TPM root** ✅: a TPM 2.0 driver (TIS) replays the measurements into PCRs 8–10, creates a restricted, `noDA` ECDSA P-256 attestation key under the endorsement hierarchy, and answers each attestation with a TPM quote of PCRs 0–10 over the gateway's nonce; with `--tpm` the gateway verifies the quote signature, requires PCRs 8–10 to equal the reported registers, and pins the machine's attestation key and firmware PCRs 0–7 at enrollment (a different TPM, changed firmware, or no TPM is refused). Tested with swtpm, cross-checked against tpm2-tools. **Measuring loader** ✅: under UEFI (OVMF), the firmware measures CDK's loader (`boot/uefi-loader`, a fork of the rust-osdev UEFI stage) into PCR 4, and the loader measures the kernel file and the ramdisk into PCRs 11–12 through `EFI_TCG2_PROTOCOL` before the kernel runs — no stage measures itself; the gateway compares PCRs 11–12 with the build (`cdk-sign measure --loader`) and refuses BIOS boots or other kernels; the kernel cross-checks PCR 12 against the ramdisk it received. **Endorsement** ✅: with `--tpm-ca`, the TPM proves it is genuine — CDK sends the TPM's standard ECC endorsement key and the manufacturer's EK certificate (NV `0x01c0000a`); the gateway checks the certificate chains to a trusted manufacturer root and certifies that key, then challenges the AK with `TPM2_MakeCredential`, which only `TPM2_ActivateCredential` in the TPM holding both keys answers; enrollment happens only after that proof (`tools/tpm_manufacture.sh` gives swtpm a test manufacturer CA). **Secure Boot** ✅: `CDK_SECURE_BOOT=1 ./run_qemu.sh` boots OVMF's SMM build with CDK's own Secure Boot key enrolled as PK, KEK and db (`tools/secureboot.sh`, no Microsoft keys); the firmware runs only a loader signed with it, and that loader runs only the kernel whose SHA-256 is built into it (release builds pin the release kernel), which in turn accepts only a ramdisk signed by the release key. Tested: unsigned loader and a loader signed by another key refused by the firmware, a changed kernel refused by the loader, the full demo runs on the signed chain. (UEFI signatures are RSA, so this layer is classical; the release signature and attestation stay post-quantum.) | ✅ |
| 4.3 | **Fuzzing and sanitizers** ✅: eleven libFuzzer targets cover every parser of untrusted bytes — link framing, handshake, sealed channel, tool/model/approval messages, hybrid signature verification, ELF loader, ramdisk, policy files, approval spool, and (with 4.2) the boot manifest, attestation and TPM endorsement certificates — with seeds (`tools/gen_fuzz_seeds.py`), replayed regressions and a CI smoke run (`tools/fuzz.sh`); the `chaos` ring-3 program fires 20,000 hostile syscalls in QEMU; host suites run under AddressSanitizer. Found and fixed: the ELF loader could copy a segment into kernel-shared memory (now `elf::validate` checks the whole image first), and a decoder/encoder length mismatch. **Independent security review** ⬜: brief in [SECURITY-REVIEW.md](SECURITY-REVIEW.md). | 🟡 |
| 4.4 | Research: CDK as a minimal hypervisor with a Linux driver VM (VT-x/EPT, IOMMU passthrough). | ⬜ |

---

## 5. Editions

CDK follows an **open-core** model.

| Open-source core (Apache-2.0, this repository) | Commercial editions (separate, proprietary) |
|---|---|
| Kernel, capability model, agent runtime | Integration with quantum key distribution (QKD) hardware, combined with ML-KEM (never QKD alone) |
| All cryptography, including post-quantum algorithms | Hardware security module / secure-element key custody, hardware-locked secure boot |
| MCP gateway, audit log format and verifier | Certified builds and evaluation evidence for regulated sectors |
| Standard drivers and transports | Sector policy packs (e.g. finance compliance rules, defense human-in-the-loop profiles) |
| Documentation and reference tooling | Deployment support, SLAs, on-premises assistance |

Rules that keep this honest:

- Cryptographic algorithms and protocol formats are always public, in the core.
- Security fixes land in the open core first or at the same time.
- Contributions are accepted under the [Contributor License Agreement](CLA.md),
  which lets the project steward also ship contributed code in commercial
  editions while guaranteeing it stays available here under Apache-2.0.

## 6. Responsible use

CDK is intended for **defensive and protective computing**: securing systems,
keys, data, and AI agents, with human oversight of consequential actions.
Commercial work for defense customers is scoped to defensive, human-supervised
use and is developed outside this public repository.
