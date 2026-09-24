# Security Policy

CDK is a security kernel, so vulnerability reports are welcome and taken
seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub:
**Security → Report a vulnerability** on
[github.com/RanveerMeel/cdk](https://github.com/RanveerMeel/cdk/security/advisories/new).

Include:

- affected commit or version, and the component (e.g. capability tokens,
  syscall path, ELF loader, paging);
- reproduction steps or a proof of concept (QEMU console transcript is ideal);
- impact as you understand it.

## What to expect

| Step | Target |
|---|---|
| Acknowledge the report | 5 working days |
| Initial assessment | 15 working days |
| Fix or mitigation plan | depends on severity; critical issues first |

Reporters are credited in the advisory unless they prefer otherwise. Fixes
land in the open-source core at the same time as, or before, any commercial
edition.

## Scope

In scope: everything in this repository, especially

- capability issuance and verification, post-quantum cryptography usage,
  key handling;
- ring-3 isolation: syscalls, user-copy checks, address spaces, paging;
- the ELF loader and any parser of untrusted input.

CDK is an **early development preview** and is not yet suitable for
production. Known limitations are tracked in [ROADMAP.md](ROADMAP.md).

## Cryptography

All algorithms and formats are public. CDK uses NIST-standardized
post-quantum algorithms (ML-DSA, FIPS 204; ML-KEM, FIPS 203) in **hybrid**
mode with classical Ed25519 / X25519, so a break in either family alone does
not break CDK. Reports about implementation weaknesses (timing side
channels, misuse, weak randomness) are especially valuable.
