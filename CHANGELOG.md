# Changelog

## Unreleased

- Agents on every CPU (roadmap 2.7): every AP starts at boot on its own
  stack and runs agents; per-CPU scheduling with work stealing; syscalls
  lock the kernel themselves; `run-all` shows each agent's CPUs and the wall
  clock. `run_qemu.sh` now starts 4 vCPUs (`CDK_QEMU_SMP`). The CPU count is
  part of the measured firmware configuration, so re-enroll TPM machines.
- TPM endorsement (roadmap 4.2): `cdk-gateway --tpm-ca DIR` requires the
  TPM's endorsement-key certificate to chain to a manufacturer CA in DIR and
  proves the attestation key is in that TPM (`TPM2_MakeCredential` /
  `TPM2_ActivateCredential`) before serving or enrolling; enrollment is no
  longer trust-on-first-use. `tools/tpm_manufacture.sh` gives swtpm EK
  certificates from a test manufacturer CA; new fuzz target `ek_certificate`.
- UEFI Secure Boot (roadmap 4.2, now complete): `CDK_SECURE_BOOT=1
  ./run_qemu.sh` enrolls CDK's own key in OVMF (SMM build) and boots a
  signed loader that runs only the kernel whose SHA-256 is built into it
  (`tools/secureboot.sh`). Release loaders are pinned to the release kernel.
- Security review fixes (2026-10-16): one endorsement proof per challenge,
  compared in constant time, and attestation decisions are final per
  session; EK certificates must carry the TCG EK usage and not be CAs; the
  TPM EK object is always flushed. See SECURITY-REVIEW.md §4.
- The UEFI loader changed, so PCR 4 changes: machines enrolled under UEFI
  (`target/tpm-enrollment*`) must be re-enrolled once — delete the
  enrollment file and the next attestation enrolls again.

## v0.1.0 — preview (2026-10)

First public preview. See [docs/releases/v0.1.0.md](docs/releases/v0.1.0.md)
for the full notes and how to verify the release.

Roadmap milestones in this release: 1.1–1.5 (quantum-safe trust core, NIST
vectors), 2.1–2.5, 2.8, 2.9 (agent runtime, signed approvals, policy review),
3.1–3.4 (post-quantum link, MCP gateway, models with credential injection),
4.2 (verified and measured boot with TPM and a measuring loader), 4.3
(fuzzing and sanitizers; independent review pending), and the
fraud-prevention demo.
