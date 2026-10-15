# Changelog

## Unreleased

- TPM endorsement (roadmap 4.2): `cdk-gateway --tpm-ca DIR` requires the
  TPM's endorsement-key certificate to chain to a manufacturer CA in DIR and
  proves the attestation key is in that TPM (`TPM2_MakeCredential` /
  `TPM2_ActivateCredential`) before serving or enrolling; enrollment is no
  longer trust-on-first-use. `tools/tpm_manufacture.sh` gives swtpm EK
  certificates from a test manufacturer CA; new fuzz target `ek_certificate`.

## v0.1.0 — preview (2026-10)

First public preview. See [docs/releases/v0.1.0.md](docs/releases/v0.1.0.md)
for the full notes and how to verify the release.

Roadmap milestones in this release: 1.1–1.5 (quantum-safe trust core, NIST
vectors), 2.1–2.5, 2.8, 2.9 (agent runtime, signed approvals, policy review),
3.1–3.4 (post-quantum link, MCP gateway, models with credential injection),
4.2 (verified and measured boot with TPM and a measuring loader), 4.3
(fuzzing and sanitizers; independent review pending), and the
fraud-prevention demo.
