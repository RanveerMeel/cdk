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
the measurement chain and its limits are in §6), and denial of service by the host (it can always drop the link).

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
| TPM endorsement: EK certificate (X.509/DER), EK chunks, credential challenge and proof | `gateway/src/ekcert.rs`, `gateway/src/credential.rs`, `link/src/tpm.rs`, `src/tpm.rs` (`nv_read`, `activate_credential`) | `ek_certificate` (DER parser, chain walk); `boot_attest` (EK chunk reassembly, challenge/proof re-encode); gateway tests on a real swtpm-issued EK certificate: chain to the root, missing intermediate, other vendor, intermediate alone, forged key; MakeCredential round trip bound to AK name and EK; attestor: EK ≠ certificate key, no EK, wrong proof, enrollment only after proof; QEMU + swtpm: certified TPM proven and enrolled, untrusted manufacturer and uncertified TPM refused |
| Measuring UEFI loader (kernel and ramdisk files from the boot medium) | `boot/uefi-loader/src/main.rs` (`measure`, `PINNED_KERNEL`) | QEMU + OVMF + swtpm: PCRs 11–12 match `cdk-sign measure --loader`; the kernel's PCR 12 cross-check; gateway test: other kernel, BIOS boot (empty PCRs) refused; Secure Boot (OVMF SMM): unsigned loader and loader signed by another key refused by the firmware, changed kernel refused by the loader before parsing |
| Boot manifest, kernel ELF measurement, attestation messages, expected-measurements file | `link/src/attest.rs`, `src/boot.rs` | `boot_attest` (accepted manifest ⇒ canonical; attestations re-encode exactly); QEMU tests: weakened policy, smuggled operator key, manifest re-signed with another key all lock down; unverified kernel refused by the gateway |
| FPU/vector register isolation between agents | `src/fpu.rs`, `src/process.rs` (reset, restore, save on switch/block) | `fpu` agent in QEMU: 16 × 256-bit registers checked across preemptions and CPU migrations; negative control with switching disabled; `tools/check_kernel_no_simd.sh` keeps vector code out of the kernel (CI) |
| Peer messages and revocation lists (roadmap 3.5 stage 2): from an untrusted courier | `link/src/peer.rs` (`PeerMessage`), `src/peer.rs` (`deliver`, `message_policy`), `gateway/src/registry.rs` | `link_messages` (strict decode, verify never panics, revocation and inbox codecs); unit tests: wrong audience, another node replaying a delegation, forged sender signature, tampered payload, foreign registry, expiry, payload bounds, `send` permission, revocation; QEMU, three boots: delivered after the owner rebooted, replayed copy and revoked delegation refused |
| Peer capabilities and node certificates (roadmap 3.5): from an untrusted courier | `link/src/peer.rs`, `src/peer.rs`, `gateway/src/registry.rs` | `link_messages` (strict decode ⇒ canonical re-encode, verify never panics, blob reassembly bounds); unit tests: other registry, renamed certificate, widened permissions, another object, forged issuer, wrong audience, own node, expiry, outliving the certificate; QEMU with two nodes: replay, wrong audience, untrusted object, tampered file, expired after reboot refused |
| Sealed store envelope (roadmap 4.5): from the untrusted gateway | `link/src/store.rs` (`Envelope`, `Records`, `freshness`), `src/store.rs`, `src/tpm.rs` (`seal`, `unseal`, NV counter), `gateway/src/store.rs` | `link_messages` (strict decode ⇒ canonical re-encode, opening never panics); unit tests: tampered counter, sealed key, nonce or records, wrong key, counter rules; QEMU with swtpm: rollback to an older envelope, a changed byte, a missing store, a changed kernel (key does not unseal), a BIOS boot on a TPM with a store, a TPM-less boot under `require sealed-store` — all refused and audit-logged; a replayed peer message refused after the receiver rebooted; policy digests checked against swtpm (known answers) and against the TPM before each `store-migrate`; QEMU: a migrated store opens under the updated kernel with its records, the old kernel loses it after a re-seal, a third kernel is refused |
| vsock packets (roadmap 5.2): from the hypervisor, when the link runs over virtio-vsock | `src/virtio_vsock.rs` (`Header`, `Endpoint`) | `vsock` (any packet sequence: at most two replies, resets never answered, data only from the connected peer, sends never beyond the peer's credit); host tests: connect/exchange/shutdown, strangers reset, reconnect, credit accounting; QEMU vhost-vsock: handshake, attestation, tools, gateway restart |
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
| Diff security review (2026-10-14; verified boot, gateway attestation with `--expect`, ELF `validate()`, tool decoder bounds — the 4.3 and 4.2 changes) | No medium, high or critical findings. Gaps it noted were already documented: TPM-less measurements, `--expect` being optional, a software-only root at the time (since then the TPM root and the measuring loader address the last). Not the independent review below; the TPM-root and fraud-demo changes were not in its scope. | — |
| `boot_attest` fuzzer (4.2, under a minute) | The manifest checker accepted non-canonical spellings (uppercase hex, CRLF). Not exploitable — the release signature covers the exact bytes — but one set of files should have exactly one valid manifest. | Fixed: canonical form required; regression test and replayed input |
| Diff security review (2026-10-16; TPM endorsement and UEFI Secure Boot — `gateway/src/ekcert.rs`, `credential.rs`, `attestation.rs`, `link/src/tpm.rs`, the kernel's TPM commands, the loader's kernel pin, the TPM and Secure Boot scripts) | **Medium:** within one session the gateway accepted any number of endorsement proofs and compared the secret with `==`, so a rejected session could later become trusted (and the secret could in principle be guessed byte by byte from timing). **Medium:** the EK certificate's purpose was not enforced — a CA certificate, or a non-EK certificate from a trusted vendor CA, naming a key whose private half lives outside a TPM, would have been accepted as an EK certificate. **Low:** a failed send leaked the TPM transient EK object (later `CreatePrimary` could fail). **Low:** Secure Boot with an unverified development kernel ended the chain at the kernel without saying so. **Info:** the loader still reads the unsigned `boot.json` (display and logging settings only; the kernel's own boot config is in the pinned kernel). | Fixed: one proof per challenge, constant-time comparison, and every attestation decision is final for its session (a second attestation, quote or EK is ignored); EK certificates must carry the TCG EK usage (2.23.133.8.1) and not be CAs; the EK is flushed on every path; `run_qemu.sh` warns. Regression tests with certificates that chain correctly but are not EK certificates; the tests fail with the old code. `boot.json`: documented |
| The nine 4.3 fuzz targets, 10 minutes each after the fixes (about 296 million executions: `spool_decision` 139 M, `initrd` 82 M, `policy` 36 M, `link_messages` 21 M, `frame_decoder` 7.9 M, `sealed_channel` 6.4 M, `elf` 1.9 M, `hybrid_verify` 1.5 M, `handshake` 0.7 M) | No crashes, sanitizer reports, or property violations | — |
| `chaos` in QEMU (20,000 syscalls; with h0 granted and two messages queued) | Every hostile call rejected: bad buffers `-3`, escalating derives `-2`, unknown handles and syscalls `-1`, empty queue `-5`; valid calls succeeded; read-only canary intact; the kernel kept running programs; 940 audit records with 8 signed checkpoints verified | — |
| Diff security review (2026-10-21; distributed capabilities stages 1–2 — `link/src/peer.rs`, `src/peer.rs`, the `cap-*`/`peer-sync` console commands, `gateway/src/registry.rs`) | **High:** every certifying gateway held the registry root key, so one compromised gateway could certify itself as *any* node name and receive or send under other nodes' delegations. **Medium:** inbound delivery resolved the delegation's object name by id, then kind, then intent, so a sender could aim a message at a different object whose id or intent matched the name. **Medium:** `cap-export` signed a delegation without the policy review or the operator approval (two-person control in signed mode) that local grants get. **Low:** the docs said a courier "can only add revocations", but across reboots the kernel relies on the gateway's file. **Info:** per-boot replay protection and the gateway as time source (already documented). | Fixed: the root signs a per-gateway `NodeAuthority` scoped to one node name (`cdk-sign node-authority`), carried and checked in every certificate, which cannot outlive it; delivery matches object names only, and only when exactly one object has that name; `cap-export` shows a delegation review and requires confirmation or a signed approval before signing. Regression tests: a certificate for another node from a valid authority, a certificate outliving its authority, a foreign root, name/id/intent confusion. Revocation persistence: documented as a limitation |
| Security review (2026-10-22; signed approvals and the kernel RNG) | **High:** signed *action* approvals (gated `send`, tool calls, model prompts) cut the operator-visible text to one request's limit with `fit_text`, while the signed statement still digested the full payload — a tool call with a benign prefix and a long escaped tail could be approved by an operator who never saw the tail (policy changes already refused text that did not fit). **Medium:** when RDRAND was advertised but failed 10 times in a row, the RNG fell back to SplitMix64 while `entropy_source()` still reported `Hardware`, so the issuer could mint keys from the fallback without the "tokens are forgeable" warning or the audit flag. | Fixed: `approvals::whole_text` replaces `fit_text` and refuses (never cuts) text that does not fit; a gated action whose description does not fit is denied. The fallback sets a sticky flag and `entropy_source()` reports `InsecureFallback` once it has been used; the issuer checks after drawing its seeds. Regression tests for both |
| AddressSanitizer: kernel host tests (279), link (21 + 3 RFC), gateway (8) | No reports | — |

## 5. Areas that most need an expert

1. **Paging and user copies** (`src/paging.rs`: `copy_from_user`,
   `copy_to_user`, `check_user_writable`, `translate_user`) and every
   `unsafe` block in `src/syscall.rs`, `src/process.rs`, `src/elf.rs`. These
   run only on bare metal, so the host fuzzers and sanitizers do not cover
   them; `chaos` exercises them in QEMU.
2. **Kernel locking with agents on every CPU** (roadmap 2.7): syscalls lock
   the kernel per operation (`kernel::lock_global`), the per-CPU process
   table (`src/process.rs`), AP stacks and bring-up (`gdt::run_on_ap_stack`),
   and the per-CPU print lock. Tested with concurrent `chaos` runs in QEMU;
   a review for lock ordering, interrupt masking and TLB handling across
   CPUs is wanted.
3. **Approval and policy flows** (`src/approvals.rs`, `src/policy.rs`,
   `src/tools.rs`): the statement binding, quorum counting, veto, timeouts,
   and the pinned gateway listing.
4. **Key handling**: issuer key generation from RDRAND/RDSEED, zeroization,
   the crypto stack, operator key files.
5. **Constant time**: the kernel's own comparisons (capability digests,
   verified-proof cache) have not been reviewed for timing leaks.
6. **Sealed store** (roadmap 4.5, `src/store.rs`, `src/tpm.rs`): the PCR
   selection (0, 2, 4, 7, 11) as the boundary between "this kernel on this
   machine" and anything else, the write/commit order against crashes and
   a hostile gateway, and the TPM command encodings (hand-built).

## 6. Known limitations

- Operator keys are 0600 files; hardware tokens are future work (editions).
- The audit log stores a digest of each operator signature, not the
  signature itself (the spool's `sent/` directory has the full decisions).
- Rules and labels edited at runtime are lost at reboot unless added to
  `policy.rules`.
- MCP tools are listed without `credential`/`remote` flags; the operator must
  label them.
- Under UEFI the kernel and ramdisk are measured by CDK's loader, which
  the firmware measures; under BIOS the kernel only measures itself (the
  gateway refuses BIOS boots when it expects loader measurements). UEFI
  Secure Boot is opt-in (`CDK_SECURE_BOOT=1`); without it a changed loader
  is detected (PCR 4) but not prevented. Secure Boot signatures are RSA
  (classical, a UEFI constraint); one key serves as PK, KEK and db in the
  QEMU setup.
- Distributed capabilities (3.5): each certifying gateway holds a key the
  registry root authorized for one node name (no authority revocation list
  yet; authorities expire); time comes from the gateway's clock;
  revocation is enforced by the issuing node for messages, not by
  importers. Revocations and replay protection survive reboots through the
  sealed store (4.5) on machines with a TPM and CDK's measuring loader;
  elsewhere they last one boot (`require sealed-store` refuses peers'
  messages and imports then).
- Sealed store (4.5): updates need `store-migrate` beforehand (to target
  PCR values the operator supplies — predicted for the kernel, read from a
  trial boot of a new loader or firmware); without it the store is
  unopenable until `store-reset`. A migrated store keeps opening under the
  previous chain until the next `store-migrate`. The key crosses the TPM bus unencrypted when unsealed; anyone with
  the TPM owner hierarchy (usually no password) can increment or delete the
  counter — a detected, fail-closed denial of service.
- Under Secure Boot the loader still reads `boot.json` from the boot
  partition unsigned; it sets display and logging options only (the
  kernel's boot configuration is compiled into the pinned kernel).
- With `--tpm-ca`, the TPM must prove its attestation key is in a TPM
  certified by a trusted manufacturer CA (EK certificate chain +
  `MakeCredential`/`ActivateCredential`). Only ECC P-256 endorsement keys
  (template L-2, certificate at NV `0x01c0000a`) are supported, as provisioned
  on discrete TPMs; firmware TPMs (Intel PTT, AMD fTPM) whose EK certificate
  is fetched from the vendor online, and RSA-only EKs, are not yet. EK
  certificate dates and revocation are not checked (the certificate must carry
  the TCG EK usage and not be a CA), and the EK template is
  assumed standard (no NV template override). Without `--tpm-ca`, TPM
  enrollment is trust-on-first-use.
