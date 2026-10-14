# CDK Security Review Brief

A starting point for an independent security review (roadmap 4.3). It
describes what CDK protects, where untrusted input enters, how each entry
point is tested, and what is known to be missing. Report findings privately
as described in [SECURITY.md](SECURITY.md).

CDK is an **early development preview**. Nothing here is a certification
claim: the crypto is tested against NIST's published vectors, but CDK has no
CAVP certificate or FIPS 140 validation.

## 1. What CDK protects

| Asset | Protection |
|---|---|
| What an agent may reach (objects, tools, models) | Kernel-held capability handles; tokens signed by the boot-time kernel issuer (Ed25519 + ML-DSA-65); attenuation-only derivation |
| The kernel and other agents | Ring-3 processes in their own address space (dedicated PML4 slot); every user pointer checked before use; fault containment |
| Consequential actions | Approval-gated handles; with pinned operator keys, signed M-of-N operator decisions verified by the kernel |
| Policy | Every widening change shown as a reach diff, checked against invariant rules, approved; fail-closed boot policy |
| Credentials for tools and models | Held only by the gateway; never sent to CDK or agents |
| Evidence | Hash-chained audit log with hybrid-signed checkpoints |

## 2. Trust boundaries and attackers

| Attacker | Controls | Must not be able to |
|---|---|---|
| A malicious agent (ring 3) | Its code, every syscall argument, timing | Reach objects without a capability, escalate a handle, read or write kernel or other agents' memory, crash the kernel, forge console output or approvals |
| A malicious or compromised gateway / host | Every byte on the link before and after the handshake; tool, model and approval traffic; the spool | Impersonate the pinned gateway; read or alter sealed traffic; forge, alter or replay an operator decision; widen an agent's reach without review |
| A malicious MCP server or model backend | Its responses | Affect anything beyond the response text the agent asked for; obtain other backends' keys |
| A spool writer (anyone who can write the approval directory) | Decision files | Produce a decision that verifies |
| A malicious program image (ramdisk, `CDK_PRIVATE_PROGRAMS_DIR`) | ELF headers and contents | Map memory outside the user region or over the stack |

**Out of scope today:** physical attacks, DMA from malicious devices (no
IOMMU yet), side channels between agents on one CPU (no constant-time
review of the kernel paths yet), a compromised boot image (measured boot is
the kernel measures itself; see §6), and denial of service by the host (it can always drop the link).

## 3. Entry points for untrusted bytes, and how each is tested

| Entry point | Code | Fuzz target / test |
|---|---|---|
| Link framing (magic, length, CRC, resync) | `link/src/lib.rs` `Decoder` | `frame_decoder` |
| Handshake (ClientHello / ServerHello / ClientFinish) | `link/src/secure.rs` | `handshake`; host tests for impostor gateway, forged signatures, tampering |
| Sealed frames (ChaCha20-Poly1305, strict sequence) | `link/src/secure.rs` `Session` | `sealed_channel` (forgeries never open, genuine frames round-trip, replays rejected) |
| Tool, model and approval messages | `link/src/tool.rs`, `link/src/approval.rs` | `link_messages` (decode ⇒ canonical re-encode; reassembly bounds) |
| Hybrid signature verification (capability proofs, link, approvals) | `link/src/secure.rs` `hybrid`, `src/issuer.rs` | `hybrid_verify`; NIST ACVP vectors (`link/tests/acvp.rs`) |
| Program images | `src/elf.rs` `parse`, `validate`, `load_into` | `elf` (accepted ⇒ inside the user region, clear of the stack); regression tests |
| Boot ramdisk (ustar) | `src/initrd.rs` | `initrd` (every entry inside the archive) |
| Boot policy and runtime policy edits | `src/policy.rs` | `policy` (bounds, rules round-trip) |
| Approval spool decision files | `gateway/src/spool.rs` | `spool_decision` |
| TPM quotes at the gateway (`TPMS_ATTEST`, ECDSA signature, enrollment) | `link/src/tpm.rs`, `gateway/src/attestation.rs` | `boot_attest` (quote decode/re-encode, attest parsing); gateway tests: other TPM, changed firmware, kernel report ≠ TPM, missing or tampered quote; QEMU + swtpm: enroll, same machine, other TPM, no TPM; AK template cross-checked with tpm2-tools |
| Boot manifest, kernel ELF measurement, attestation messages, expected-measurements file | `link/src/attest.rs`, `src/boot.rs` | `boot_attest` (accepted manifest ⇒ canonical; attestations re-encode exactly); QEMU tests: weakened policy, smuggled operator key, manifest re-signed with another key all lock down; unverified kernel refused by the gateway |
| Syscalls (every argument) | `src/syscall.rs`, `src/agent.rs`, `src/tools.rs`, `src/paging.rs` | `chaos` ring-3 program in QEMU: 20,000 syscalls with kernel, unmapped, read-only and boundary-straddling pointers, huge lengths, unknown numbers and handles |
| MCP and model server responses | `gateway/src/mcp.rs`, `gateway/src/models.rs` | Gateway tests (status mapping, wrong-key redaction, redirects); not yet fuzzed |

Run the fuzzers with `tools/fuzz.sh [seconds]` (needs `cargo-fuzz`; seeds
come from `tools/gen_fuzz_seeds.py`, past crashes live in
`fuzz/regressions/` and are replayed by `tools/fuzz.sh --replay` in CI). The
host test suites also run under AddressSanitizer
(`RUSTFLAGS=-Zsanitizer=address`).

## 4. Findings so far

| Found by | Issue | Status |
|---|---|---|
| Code review during 4.3 | The ELF loader checked only the entry point against the user region. A `PT_LOAD` segment at an address the user page tables already translate (the kernel-shared slots) would have had file bytes **copied into kernel memory**. | Fixed: `elf::validate` checks every segment (user region, stack, file range, sizes, executable entry, at most 64 headers) before anything is mapped; regression tests |
| `link_messages` fuzzer (seconds) | `tool::decode` accepted call arguments and response bodies longer than `MAX_BODY`, which the encoder can never produce. Bounded by the frame size, so not exploitable, but a parser/encoder mismatch. | Fixed; regression test and `fuzz/regressions/link_messages/` |
| `boot_attest` fuzzer (4.2, under a minute) | The manifest checker accepted non-canonical spellings (uppercase hex, CRLF). Not exploitable — the release signature covers the exact bytes — but one set of files should have exactly one valid manifest. | Fixed: canonical form required; regression test and replayed input |
| The nine 4.3 fuzz targets, 10 minutes each after the fixes (about 296 million executions: `spool_decision` 139 M, `initrd` 82 M, `policy` 36 M, `link_messages` 21 M, `frame_decoder` 7.9 M, `sealed_channel` 6.4 M, `elf` 1.9 M, `hybrid_verify` 1.5 M, `handshake` 0.7 M) | No crashes, sanitizer reports, or property violations | — |
| `chaos` in QEMU (20,000 syscalls; with h0 granted and two messages queued) | Every hostile call rejected: bad buffers `-3`, escalating derives `-2`, unknown handles and syscalls `-1`, empty queue `-5`; valid calls succeeded; read-only canary intact; the kernel kept running programs; 940 audit records with 8 signed checkpoints verified | — |
| AddressSanitizer: kernel host tests (279), link (21 + 3 RFC), gateway (8) | No reports | — |

## 5. Areas that most need an expert

1. **Paging and user copies** (`src/paging.rs`: `copy_from_user`,
   `copy_to_user`, `check_user_writable`, `translate_user`) and every
   `unsafe` block in `src/syscall.rs`, `src/process.rs`, `src/elf.rs`. These
   run only on bare metal, so the host fuzzers and sanitizers do not cover
   them; `chaos` exercises them in QEMU.
2. **Kernel locking** while agents run: the console lends its kernel
   reference to syscalls (`agent::with_kernel`); sound only because agents run
   on one CPU (roadmap 2.7 replaces it).
3. **Approval and policy flows** (`src/approvals.rs`, `src/policy.rs`,
   `src/tools.rs`): the statement binding, quorum counting, veto, timeouts,
   and the pinned gateway listing.
4. **Key handling**: issuer key generation from RDRAND/RDSEED, zeroization,
   the crypto stack, operator key files.
5. **Constant time**: the kernel's own comparisons (capability digests,
   verified-proof cache) have not been reviewed for timing leaks.

## 6. Known limitations

- Operator keys are 0600 files; hardware tokens are future work (editions).
- The audit log stores a digest of each operator signature, not the
  signature itself (the spool's `sent/` directory has the full decisions).
- Rules and labels edited at runtime are lost at reboot unless added to
  `policy.rules`.
- MCP tools are listed without `credential`/`remote` flags; the operator must
  label them.
- The kernel measures itself (into TPM PCRs 8–10 when a TPM is present);
  a kernel modified from the start could extend the expected digests. A
  measuring bootloader is future work. TPM enrollment is trust-on-first-use
  (no endorsement-certificate check yet).
