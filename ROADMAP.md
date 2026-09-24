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
| 1.5 | **Full NIST test vectors.** Vendor the NIST ACVP ML-DSA sigGen/sigVer (and later ML-KEM) vector files and run them in CI; today only key generation has an independent ML-DSA known-answer test. | ⬜ |

### Phase 2 — Agent runtime

| # | Milestone | Status |
|---|---|---|
| 2.1 | **Programs from the boot ramdisk.** User programs written in Rust (`user/`, static ET_EXEC at the user base, large code model) are packed into a reproducible `ustar` ramdisk; the kernel parses it strictly (checksums, bounds), loads programs with a 64 KiB stack plus guard page, and records each image's SHA-256 in the audit log. Console `ls`, `spawn`, `exec`. | ✅ |
| 2.2 | **Agents hold capability handles.** Per-process handle table; syscalls take handles and the kernel checks rights (`SYS_cap_list`, `SYS_cap_derive` with attenuation only, `SYS_cap_drop`). | ⬜ |
| 2.3 | Preemptive scheduling of user processes; per-process FPU/SSE/AVX state (XSAVE) so user code can run vectorized inference. | ⬜ |
| 2.4 | **Native CPU inference demo:** run the SecureGuard int8 scam classifier inside a CDK process. | ⬜ |
| 2.5 | Human-approval capabilities: an action tagged consequential blocks until an approval token is presented on the console / approval channel. | ⬜ |

### Phase 3 — Connected agents

| # | Milestone | Status |
|---|---|---|
| 3.1 | virtio-vsock transport to a Linux host / VM. | ⬜ |
| 3.2 | **PQ-secure channel:** hybrid X25519 + ML-KEM-768 handshake, authenticated with hybrid issuer signatures, then AEAD (ChaCha20-Poly1305 / AES-256-GCM). | ⬜ |
| 3.3 | **MCP gateway:** agent tool calls leave CDK only through a policy check against the agent's capabilities, and every call is audit-logged. | ⬜ |
| 3.4 | GPU inference through Linux-hosted model servers (vLLM, llama.cpp, TensorRT), gated by per-model capabilities. | ⬜ |
| 3.5 | Distributed capabilities: tokens verifiable across CDK nodes via an issuer key registry. | ⬜ |

### Phase 4 — Hardening and platforms

| # | Milestone | Status |
|---|---|---|
| 4.1 | ARM64 port (edge / appliance hardware). | ⬜ |
| 4.2 | Measured and verified boot chain (signed kernel images, hybrid signatures). | ⬜ |
| 4.3 | Fuzzing (syscalls, ELF loader, token parsing), sanitizers on host tests, independent security review. | ⬜ |
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
