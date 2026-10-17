# CDK — Quantum-Safe Agent Trust Kernel

**Website:** [https://ranveermeel.github.io/cdk/](https://ranveermeel.github.io/cdk/) _(GitHub Pages)_ · **Release:** [v0.1.0 preview](https://github.com/RanveerMeel/cdk/releases/tag/v0.1.0) · **Demo:** [DEMO.md](DEMO.md) · **Plan:** [ROADMAP.md](ROADMAP.md) · **Security:** [SECURITY.md](SECURITY.md) · **Review brief:** [SECURITY-REVIEW.md](SECURITY-REVIEW.md)

CDK (Cognitive Distributed Kernel) is an open-source, bare-metal Rust kernel for running **AI agents under kernel-enforced, cryptographically provable permissions**, built on **post-quantum cryptography** from the start.

- **Agents are isolated processes.** An agent can only reach an object, tool, model, or network endpoint if it holds a capability for it.
- **Capabilities are issued and verified by the kernel**, signed with hybrid **Ed25519 + ML-DSA-65 (FIPS 204)**, so they can't be forged by classical or future quantum attackers.
- **Every consequential action is provable** through a tamper-evident, hash-chained audit log with signed checkpoints.
- **Humans stay in control, provably:** a capability can require human approval for every action. With operator keys pinned, the approval is a post-quantum **signature** from named operators — two-person (M-of-N) rules, vetoes, time-outs — verified by the kernel and kept in the audit trail. Every grant and policy change is shown as a reach diff and checked against invariant rules first.

Heavy AI inference (GPUs, CUDA) runs on Linux next to CDK; CDK is the control plane that decides which agent may use which model and records it. See [ROADMAP.md](ROADMAP.md) for the architecture and milestones.

## See It Work

`tools/demo_fraud.sh --auto` runs a fraud-prevention scenario end to end on synthetic data: a triage agent scores transactions (native model, rules, local LLM), a responder freezes accounts and requests refunds, operators alice and bob sign the decisions (two signatures to move money, any denial vetoes), a prompt-injected transaction can't make any agent move money because policy never lets the agent that read it hold a money tool — all on a verified, TPM-attested boot, with a verified audit trail and a case file at the end. See [DEMO.md](DEMO.md).

## Status

**Early development preview — not for production use.** CDK boots on bare metal (QEMU) with SMP, preemptive scheduling, ring-3 processes in isolated address spaces, and an interactive serial console. The quantum-safe trust core (Phase 1 of the [roadmap](ROADMAP.md)) is being built now: Phase 1 is done. In Phase 2 (agent runtime), Rust agent programs load from the boot ramdisk, act only through kernel-held capability handles, run concurrently under a preemptive scheduler with a CPU-budget watchdog, can run integer-only ML models natively, and can be forced to wait for a signed human decision before acting. In Phase 3 they reach tools and models on Linux through a post-quantum-secured gateway that holds the credentials. Interfaces can still change quickly.

### Editions

CDK is **open core**. This repository — the kernel, the capability model, the agent runtime, and *all* cryptography — is Apache-2.0. Commercial editions for regulated sectors (finance, defense) add hardware integrations (QKD, HSMs), certified builds, sector policy packs, and support; see [ROADMAP.md § Editions](ROADMAP.md#5-editions).

## Features

**Bare-Metal Execution** — Boots on x86_64 hardware (or QEMU) with no OS underneath. Built with `#![no_std]` and `bootloader_api` 0.11.

**Capability-Based Security** — Every operation requires a capability token issued by the kernel. No global root, no ambient authority.

**Quantum-Safe Capability Tokens** — Tokens are signed by a boot-time kernel issuer with hybrid Ed25519 + ML-DSA-65 (FIPS 204); both must verify, and only the pinned issuer is trusted, so self-signed or tampered tokens are rejected. Post-quantum operations run on a dedicated 512 KiB crypto stack. Console: `issuer`, `capsign`, `capverify`.

**User Programs from a Boot Ramdisk** — Programs in `user/` are ordinary `no_std` Rust (`cdk_user` provides `_start`, syscalls, `println!`). `run_qemu.sh` builds them, packs a reproducible `ustar` ramdisk, and the bootloader loads it next to the kernel. The kernel parses the archive strictly, maps each program at its linked address with a 64 KiB stack and an unmapped guard page, and logs the image's SHA-256 (`program-loaded`) so every process can be traced to the exact binary that ran.

**Agent Capability Handles** — Each process holds up to 16 capabilities in a kernel-side table and refers to them only by index, so tokens can't be forged, copied, or leaked. Syscalls `cap_list`, `cap_drop`, `cap_derive` (a new handle may only *drop* permissions, and is re-issued with hybrid post-quantum signatures), `send` and `recv` (to the handle's object). Every use is re-verified and permission-checked; grants, derivations, and denials land in the audit log. Demo agents: `agent` checks every rule, `intruder` (no grants) is blocked on all 19 attempts.

**Host Link and Gateway** — `run_qemu.sh` attaches a virtio-console device backed by `target/cdk-link.sock`; in another terminal `tools/run_gateway.sh` starts the host gateway, which connects to it. Kernel and gateway share the `link/` crate (framing with CRC-32 and resync), so both sides are byte-identical. Try `link-ping`, `link-send hello`, `link-recv`. Then `link-secure` runs the post-quantum handshake: hybrid X25519 + ML-KEM-768 key exchange, both sides sign the transcript with Ed25519 + ML-DSA-65, and CDK only accepts the gateway whose public key is pinned in the ramdisk (`run_qemu.sh` creates `target/gateway-identity.key` once and packs `target/gateway.pub`). After that every `link-send` is sealed with ChaCha20-Poly1305; replayed, reordered, or tampered frames are rejected, and the gateway refuses plaintext.

**Agent Tools over MCP** — The gateway fronts MCP (Model Context Protocol) servers: `tools/run_gateway.sh` starts the stdlib demo server (`gateway/examples/demo_mcp_server.py`: `echo`, `word_count`, `utc_time`, `sleep`) unless `CDK_MCP="name=command"` names another, and `CDK_MCP_ALLOW=echo,word_count` limits what CDK may reach. After `link-secure`, `tools-sync` turns each offered tool into a kernel object `tool:<name>`. An agent can call a tool only through a handle with `exec`: `spawn researcher`, `grant 1 tool:word_count exec`, `elf-run 1`. Add `approval` (`grant 1 tool:echo exec,approval`) and a human must approve the exact arguments first (`spawn careful` shows approve, deny, and a slow tool). Calls travel sealed; the kernel records `tool-call` (SHA-256 of the arguments) and `tool-result` (status and length) in the audit log.

**Models on the Host, Credentials in the Gateway** — Large models run on Linux, next to its GPU drivers (vLLM, llama.cpp, Ollama, TensorRT-LLM, or a remote API — anything OpenAI-compatible). `CDK_MODEL="qwen=http://127.0.0.1:11434/v1,model=qwen2.5:3b-instruct" tools/run_gateway.sh` offers a local Ollama model; after `tools-sync` it is the kernel object `model:qwen`. `spawn analyst`, `grant 1 model:qwen exec` (add `,approval` to gate every prompt), `elf-run 1`. For a paid or remote API, add `key-file=PATH` (mode 0600) or `key-env=VAR`: the gateway attaches the key only to that backend's URL, never follows redirects, refuses keys over plaintext http to remote hosts, and scrubs the key from anything it returns. Agents and the kernel never see it.

**Policy Change Review** — Nothing widens an agent's reach silently. `grant 1 model:demo exec` first prints a reach diff (`+ pid 1 'analyst' gains exec on obj-9 (model:demo) [model,credential] via 127.0.0.1:18080, NOT gated`), checks it against the policy rules, and asks before applying; with the default boot policy (`policy/default.rules`: `approval credential`, `approval remote`) that grant is refused until you add `,approval`. Rules are invariants over every agent's handles — `deny <label>`, `separate <a> <b>` (e.g. keep agents that read customer data away from tools), `approval <label>` — and labels come from the gateway (`credential`, `remote`) or the operator (`policy label obj-2 customer-data`). `tools-sync` pins the gateway's listing; if a model later gains a key or moves to another host, CDK shows which agents' reach changes, and calls to it fail with `PolicyBlocked` until the change is approved. `policy begin` … `policy commit` reviews several grants as one change. Use `CDK_POLICY_FILE` to pack your own rules; a malformed policy makes CDK refuse every change.

**Human-Approval Gates** — Grant a handle with the `approval` constraint (`exec requester obj-2 send,approval`). Every `send` through it blocks the agent; the console shows who is asking, the target, and the exact payload (control characters escaped, so an agent can't forge console output), and the kernel performs the send only if the human answers `y`. Otherwise the agent gets `HumanDenied`. The constraint is part of the signed token and survives derivation; requests and decisions are audit-logged (`approval-asked`, `approval-yes`, `approval-no`).

**Signed Operator Approvals** — For real oversight, pin operator keys: `tools/approve.sh init alice` (and `bob`) creates hybrid Ed25519 + ML-DSA-65 keys in `target/operators/`; the public halves are packed into the ramdisk. From then on a typed `y` approves nothing. An approval-gated action or a policy change opens a signed request, which the gateway spools (`target/approvals/`). On the operator's device, `tools/approve.sh list` shows exactly what is asked, and `tools/approve.sh approve 3 --key target/operators/alice.key` (or `deny`) signs it. CDK verifies the signature against the pinned keys. The signed statement binds this boot, the request, the payload digest, the text shown, the quorum and the decision, so a gateway or spool in the middle can't forge or replay one. Add `quorum credential 2` to the policy for two-person control, `quorum policy 2` for policy changes, `approval-timeout 120` to deny unanswered requests. Any valid denial vetoes. Votes, bad signatures, unknown keys and time-outs are all audit-logged. `operators` shows the pinned keys and open requests.

**Verified and Measured Boot** — `run_qemu.sh` creates a release key once (`tools/sign.sh init`, kept in `target/release-signing.key`); its public half is compiled into the kernel, and every ramdisk is signed (`boot.manifest` + `boot.manifest.sig`, covering programs, `gateway.pub`, operator keys and `policy.rules`). At boot the kernel checks the manifest before trusting anything in the ramdisk; any change made without the release key puts it in **lockdown**: ramdisk hidden, no processes, no link, every policy change refused. The kernel also measures itself (code and read-only data), the ramdisk and the verdict into three registers (`boot` shows them). After each handshake the gateway asks for them with a fresh nonce, and with `--expect target/boot.measurements` (written by `run_qemu.sh`) it serves nothing to a CDK that booted anything else. `CDK_RELEASE_PUB=/dev/null` builds an unverified development kernel. With a TPM (`run_qemu.sh` starts `swtpm` when it is installed), the kernel also extends the registers into TPM PCRs 8–10 and answers with a **TPM quote** signed by a key that never leaves the TPM; the gateway (`--tpm target/tpm-enrollment`) enrolls the machine on first contact and afterwards refuses a different TPM, changed firmware, a kernel whose report disagrees with the TPM, or no TPM at all. With `--tpm-ca DIR` the TPM must also prove it is **genuine**: its endorsement-key certificate must chain to a manufacturer CA in DIR, and a `MakeCredential` challenge proves the quoting key lives in that same TPM — before anything is served or enrolled (`run_qemu.sh` gives its software TPM a test manufacturer CA via `tools/tpm_manufacture.sh`). With **UEFI Secure Boot** (`CDK_SECURE_BOOT=1 ./run_qemu.sh`, keys from `tools/secureboot.sh`) the firmware runs only a loader signed with CDK's key, and that loader runs only the kernel it was built for — so a changed boot chain is not just detected but refused. Under UEFI (`run_qemu.sh` uses OVMF when installed) CDK's **measuring loader** — started and measured by the firmware — measures the kernel and ramdisk into PCRs 11–12 *before* the kernel runs, and the gateway checks them against the build: no stage vouches for itself.

**Distributed Capabilities (stage 1)** — CDK nodes can delegate to each other. A registry authority (here the gateway: `CDK_NODE=hq tools/run_gateway.sh` with `target/registry.key` from `tools/sign.sh init --key target/registry.key --pub-out target/registry.pub`) certifies each node's per-boot key right after accepting its attestation, and every node pins the registry key in its signed ramdisk. On `hq`, `cap-export 1 h0 branch to-branch send` writes a portable capability, signed by hq and addressed only to `branch`, to the gateway's outbox; on `branch`, `cap-import to-branch 1` verifies the certificate chain, signature, audience, expiry and replay, checks `trust hq alerts send` in branch's policy, and grants pid 1 a handle on the proxy `peer:hq/alerts` through the normal policy review. `peer` shows a node's certificate and trust rules. Forwarding messages to the remote object is stage 2.

**Fuzzed and Sanitized** — Every place CDK reads bytes it didn't create has a fuzz target: link frames, the handshake, sealed frames, tool/model/approval messages, signature verification, ELF images, the ramdisk, policy files, the approval spool (`tools/fuzz.sh 300` runs them all for five minutes; CI replays past crashes and fuzzes each for 30 s). Inside the kernel, `spawn chaos` / `elf-run` fires 20,000 syscalls with kernel, unmapped, read-only and boundary-straddling pointers. Host test suites also pass under AddressSanitizer. See [SECURITY-REVIEW.md](SECURITY-REVIEW.md) for the threat model and findings.

**Native Inference in Agents** — `user/ml` (`cdk-ml`) evaluates int8 linear models (`CDKLM1`) with integer arithmetic only, so agents need no FPU state. An agent embeds its model at build time, so the audit log's `program-loaded` SHA-256 identifies code *and* model. Demo: `send obj-2 server down, production outage`, `send obj-2 lunch menu for friday`, then `exec classify obj-2 recv`. The demo model (`user/models/priority-demo.cdklm`, message priority ROUTINE/URGENT) is synthetic and regenerated reproducibly by `tools/train_demo_model.py`.

**Private programs** — Proprietary agents or models never go into this repository. Build them elsewhere and pack them into a local image with `CDK_PRIVATE_PROGRAMS_DIR=/path/outside/repo ./run_qemu.sh`; the build refuses a directory inside the repo and name clashes with public programs.

**Preemptive Agent Scheduling** — Agents that never yield still share the CPU: the timer entry stubs save every register, and after each 100 ms slice the kernel switches to the next runnable agent (round-robin). A per-agent CPU budget watchdog kills runaway agents (`proc-killed` in the audit log). Try `spawn spin`, `spawn spin`, `spawn hog`, `run-all`. Agents run in parallel on every CPU (roadmap 2.7) and use hardware floating point and SSE/AVX with their own register state (roadmap 2.6); `spawn fpu` ×4 then `run-all` checks that no agent sees another's registers.

**Tamper-Evident Audit Log** — Capability issuance, every capability check (accepted or rejected, with reason), and process spawn/start/exit/reap are appended to a SHA-256 hash chain bound to the kernel issuer. Every 64 records the issuer signs the chain head (Ed25519 + ML-DSA-65). Editing, deleting, reordering, or truncating records is detected, and rewriting the whole chain cannot reproduce the signed checkpoints. Console: `audit`, `audit-verify`, `audit-checkpoint`.

**Message-Passing IPC** — Objects communicate via typed messages (Data, Text, Command, Request/Response) through per-object queues.

**Intent-Driven Scheduling** — Tasks carry intent labels (`low_latency`, `batch`, `interactive`, etc.) that the scheduler maps to priorities.

**Memory Object Graph** — Tracks memory allocations per object with reference counting and usage statistics.

**Distributed Node Awareness** — Cloud, Edge, and Local node types with discovery, routing, and latency-aware selection built in from the start.

**Network Stack Integration** — Loopback + external interface scaffolding, capability-gated send/recv, and bridge routing with telemetry.

**Virtio-Net Hardware Path** — Optional `virtio-hw` feature enables MMIO virtio-net bring-up (device probe + status/queue setup) through the same descriptor-oriented adapter boundary.

**Multi-Core Foundation (Phase 1)** — Kernel tracks per-core topology and telemetry (BSP/AP roles, online state, tick/dispatch/completion counters) and exposes it via console status.

**Multi-Core Startup Scaffold (Phase 2)** — AP lifecycle state machine (registered → booting → online/halted), boot-time AP provisioning scaffold, and console controls for AP management.

**Multi-Core Bring-Up Orchestration (Phase 3)** — AP startup mailbox + trampoline vector planning, local APIC INIT/SIPI orchestration hooks, and startup handshake tracking.

**Multi-Core Dispatch Split (Phase 4)** — Initial per-core run-queue depth split with core-targeted dispatch assignment plus AP-entry handshake path wired through startup plans.

**Multi-Core Trampoline Handoff (Phase 5)** — AP startup now carries a concrete trampoline machine-code blob with checksum metadata and an explicit AP entry handoff context (signature, target APIC, stack top, kernel entry).

**Multi-Core Async AP Online (Phase 6)** — AP launch now stages the trampoline slot image into low memory during startup planning and uses sequence-based AP entry acknowledgment before transitioning from booting to online.

**Multi-Core AP Entry Hook (Phase 7)** — Startup handoff now carries a real kernel entry hook pointer + page-table root metadata, and AP bring-up paths invoke the trampoline entry hook for automatic sequence-checked online transition.

**Multi-Core AP Runtime Loop (Phase 8)** — AP trampoline entry path now drives a per-core runtime probe loop that only dispatches work assigned to that AP, establishing the first true core-targeted execution path.

**Multi-Core Runtime Service (Phase 9)** — AP cores are now registered into a persistent runtime set and serviced on each timer tick via per-core runtime steps, replacing one-shot probe behavior with continuous AP scheduling service.

**Multi-Core Local Tick Sources (Phase 10)** — Kernel now tracks per-core local runtime tick cursors and can advance AP runtime independently of BSP tick time, including manual AP tick stepping for local timer simulation.

**Multi-Core LAPIC Drive Modes (Phase 11)** — Per-core runtime drive mode now distinguishes BSP-proxied vs local-APIC execution; AP startup transitions into local-APIC mode and BSP tick service skips those cores while local timer pulses drive runtime.

**Multi-Core LAPIC Timer IRQ Hook (Phase 12)** — Interrupt layer now exposes a dedicated local APIC timer callback path carrying APIC ID, and kernel integrates AP-local timer tick handling for mode-gated runtime servicing.

**Multi-Core LAPIC Timer Delivery (Phase 13)** — AP entry arms the current core's local APIC periodic timer (vector `0xF0`, SVR enable + LVT/DCR/init-count programming) so hardware IRQs drive AP runtime; `cpu-step-ap` remains a debug software inject fallback.

**Multi-Core Trampoline Execution + Timer Calibration (Phase 14)** — SIPI trampoline now loads handoff stack, verifies the `"CDKA"` signature, and publishes AP status for BSP polling (no immediate BSP soft-ack); INIT/SIPI includes ICR idle waits + settle delays; `cpu-calibrate` measures LAPIC countdown against PIT ticks and stores per-core timer rates.

**Multi-Core Long-Mode Handoff (Phase 15)** — Trampoline performs real→protected→long mode with an embedded GDT, identity-maps `0x8000`, and calls `ap_kernel_entry`; boot re-enables the heap, adopts bootloader CR3, and issues live INIT/SIPI for AP online.

**Multi-Core Per-AP TSS + Calibrated Timer (Phase 16)** — Each AP loads a private GDT/TSS with its own double-fault IST stack; BSP calibrates the LAPIC rate against PIT ticks at boot and APs inherit that calibration when arming vector `0xF0` after handoff.

**Multi-Core RSP0 + Reschedule IPI (Phase 17)** — Per-core TSS RSP0 kernel stacks (16 KiB) plus Fixed IPI vector `0xF1` to nudge LocalApic cores when work is queued (`cpu-ipi-resched`).

**Multi-Core Idle Wake + TLB Shootdown (Phase 18)** — AP idle loop tracks `sti; hlt` park/wake; Fixed IPI `0xF2` invalidates remote TLBs (`cpu-ipi-tlb`); `vmmap`/`vmunmap` broadcast shootdowns to online APs.

**Multi-Core Run Queues + Work Stealing (Phase 19)** — Per-core object-id run queues with fair lightest-core dispatch (tie-break by fewest dispatches); idle cores steal from the busiest victim; `cpus` reports `steals=`.

**Multi-Core Parallel Running Slots (Phase 20)** — Scheduler keeps a fine-grained ready-queue lock plus private per-core running slots so multiple APIC ids can hold dispatched tasks at once (`running` / `cpus` show `run=`).

**SMP Roadmap Reset (M1–M6)** — Unblocked 2-vCPU bring-up (`-smp 2`, Kernel lock released before INIT/SIPI, lock-free AP ready mailbox); ACPI MADT CPU discovery with fallback topology; slot-based `percpu` maps; contexts stay running until completed; global scheduler usable without Kernel lock; TLB shootdown ACK wait.

**CPU Hardening + Ring-3 Foundation (M7–M14)** — Quiet LAPIC/IPI logging with cooperative `yield`/`complete`; contiguous-frame heap; GS-base `PerCpu`; kernel `CpuContext` switch; BSP `lapic-local`; x2APIC (xAPIC fallback); MADT IOAPIC + `irq-route`; user GDT + SCE/`user-smoke`; ELF64 loader and minimal process table.

**User Processes** — Each process gets its own PML4 that shares kernel mappings; user pages live only in a dedicated PML4 slot (`0x80_0000_0000`, 512 GiB) so they never touch kernel page tables. `SYS_exit` restores the kernel context that entered ring 3, so `elf-run` returns to the console; a CPU exception in ring 3 does the same, marking the process `Crashed` instead of taking the kernel down; `SYS_write(ptr, len)` copies from user memory after checking every page is user-mapped; `reap` frees the address space.

**GPU Foundation** — Virtio-gpu 2D command packing, soft scanout/resource/flush into the boot framebuffer, modern virtio-pci capability parse + control virtqueue under `virtio-hw`, console `gpuinfo` / `gpusmoke`.

**Unified Memory Foundation** — Contiguous shared CPU/GPU regions (`umalloc` / `umfree` / `um-smoke`), coherency fence before device attach, IOMMU identity stub; page migration not yet implemented.

**Interactive Serial Console** — A `cdk>` prompt over COM1 for creating objects, sending messages, inspecting state, and controlling the scheduler at runtime.

## Quick Start

### Try a release

The [v0.1.0 preview](https://github.com/RanveerMeel/cdk/releases/tag/v0.1.0) ships a ready-to-boot evaluation image, built reproducibly (two independent builds are byte-identical) and with an SBOM. Check its signed checksums before running it; the release key ID `0b57f6795dcdf315f2512079b8e16ba8` is stated in the [release notes](docs/releases/v0.1.0.md):

```bash
sha256sum -c SHA256SUMS
tools/sign.sh verify-file SHA256SUMS --pub cdk-release.pub   # from a source checkout
qemu-system-x86_64 -cpu max -drive format=raw,file=cdk-0.1.0-eval.img -serial stdio -display none
```

To cut a release yourself: `tools/release.sh VERSION` (see [CHANGELOG.md](CHANGELOG.md)).

### Prerequisites

```bash
rustup target add x86_64-unknown-none
rustup toolchain install nightly
rustup component add rust-src llvm-tools-preview --toolchain nightly
sudo apt install qemu-system-x86
```

### Build and Run

```bash
./run_qemu.sh
```

This builds the kernel, creates a disk image that boots under both BIOS and UEFI (UEFI via OVMF when it is installed; `CDK_BOOT=bios` forces BIOS), and launches QEMU with **4 vCPUs** (`-smp 4`: the console's CPU supervises, the other three run agents in parallel) and the serial console connected to your terminal. Override with `CDK_QEMU_SMP=1 ./run_qemu.sh` to run everything on one CPU. Type `help` at the `cdk>` prompt.

For a graphical QEMU window instead:

```bash
CDK_QEMU_GUI=1 ./run_qemu.sh
```

To compile virtio-net / virtio-gpu hardware probe paths:

```bash
cargo check --features virtio-hw
# or: CDK_VIRTIO_HW=1 ./run_qemu.sh
```

`./run_qemu.sh` attaches `-device virtio-gpu-pci`. Soft GPU (`gpuinfo` / `gpusmoke`) works without `virtio-hw`. With `CDK_VIRTIO_HW=1`, modern virtio-pci caps are parsed and `gpusmoke` submits create/attach/scanout/transfer/flush on the device.

## Architecture

```
 src/
  main.rs          Kernel entry point, static state, boot config
  lib.rs           Crate root (re-exports all modules)
  kernel.rs        Core kernel — object registry, capability enforcement
  capability.rs    Capability tokens with permission sets
  object.rs        Kernel objects (id, kind, intent, message queue)
  scheduler.rs     Priority queue mapped from intent labels
  message.rs       Typed IPC messages and payloads
  memory_graph.rs  Per-object memory tracking
  node.rs          Distributed node types and discovery
  network.rs       Network interfaces, packet queues, and loopback service
  allocator.rs     Bitmap physical frame allocator
  heap.rs          Kernel heap (#[global_allocator], linked-list, 2 MiB)
  rng.rs           RDRAND RNG (bare-metal) / OsRng (host tests)
  framebuffer.rs   Pixel framebuffer renderer (8×16 font, scroll, RGB/BGR)
  gpu.rs           Soft/virtio-gpu 2D command pipeline, scanout flush
  um.rs            Unified memory regions (CPU/GPU shared phys + fence)
  pci.rs           Minimal PCI config access (virtio-gpu discovery)
  serial.rs        COM1 UART driver (init, read, write)
  vga_buffer.rs    print!/println! macros → serial + framebuffer
  console.rs       Interactive serial console and command dispatch
 tools/
  create_disk_image/   Host-side tool to wrap the kernel ELF in a BIOS boot image
```

### Design Principles

- **No global state on the stack** — `Kernel`, `MemoryGraph`, and `KernelNode` live in `static` storage behind `spin::Mutex`, keeping the kernel stack small.
- **Everything is an object** — Compute units, data stores, services — all represented as `KernelObject` instances managed through capabilities.
- **Security by default** — Operations go through capability verification before touching any object.
- **Distributed from day one** — The node subsystem models multi-machine topologies so scheduling and routing decisions can factor in location and latency.

## Console Commands

| Command | Description |
|---|---|
| `help` | List available commands |
| `status` | Kernel overview (objects, scheduler queue, memory) |
| `create <name> <intent>` | Create a compute object |
| `list` | List all registered objects |
| `schedule <id>` | Queue an object for execution |
| `run` | Manually dispatch next task from the scheduler queue |
| `running` | Show the currently running (preempted) task |
| `timeslice` | Show the preemptive time-slice length in ticks |
| `ls` | List programs in the boot ramdisk with size and SHA-256 prefix |
| `spawn <name>` | Load a ramdisk program as a `Ready` process |
| `exec <name> [obj perms]` | Load and run a ramdisk program, optionally granting one handle first (`exec agent obj-2 send,recv`, `exec classify obj-2 recv`) |
| `grant <pid> <obj> [perms]` | Give a process a kernel-issued capability handle (`send,recv` by default; `read,write,exec,send,recv,delete` or `all`; add `approval` to require a human decision for every send) |
| `handles <pid>` | List a process's handles |
| `run-all` | Run every `Ready` process concurrently under the preemptive scheduler |
| `budget [ticks]` | Show/set the per-process CPU budget; the watchdog kills a process that exceeds it (default 200 ticks ≈ 10 s) |
| `slice [ticks]` | Show/set the time slice before preemption (default 2 ticks ≈ 100 ms) |
| `elf-spawn [prog]` | Load a built-in program as a `Ready` process: `hello` (default), or crash tests `ud`, `pf`, `gp`, `de` |
| `elf-run <pid>` | Run a `Ready` process in ring 3 until it calls `SYS_exit` |
| `elf-smoke [prog]` | `elf-spawn` + `elf-run` in one step (`elf-smoke pf` shows a contained page fault) |
| `ps` | List processes (Ready / Running / Blocked / Zombie / Crashed / Killed) with ticks used and preemptions |
| `reap <pid>` | Free a `Ready`/`Zombie`/`Crashed` process and its address space |
| `user-smoke` | Minimal ring-3 round trip (enter, `SYS_exit`, return) |
| `issuer` | Kernel capability issuer: id, algorithms, entropy source, crypto-stack peak |
| `link` | Host link status (bytes, frames, CRC errors) |
| `link-ping` | Round-trip a `PING` through the host gateway |
| `link-send <text>` | Send a `DATA` frame to the gateway (`link-send burst 50` asks it for a 50-frame test burst) |
| `link-recv` | Show frames received from the gateway (sealed ones are shown decrypted and marked authenticated) |
| `link-secure` | Post-quantum handshake with the pinned gateway; afterwards all `link-send` traffic is sealed |
| `tools-sync` | Ask the gateway for its MCP tools and register a `tool:<name>` object for each |
| `tools` | List registered tool objects (and whether each is callable or blocked pending review) |
| `policy` | Rules, labels, review mode, and the pinned gateway listing |
| `policy check` / `policy reach` | Check all handles against the rules / show what each agent can reach |
| `policy rule add <deny L \| separate A B \| approval L>`, `policy rule del <n>` | Edit rules (reviewed) |
| `policy label <obj-or-kind> <l>`, `policy unlabel …` | Attach or remove a label (reviewed) |
| `policy begin` / `diff` / `commit` / `abort` | Stage several grants and review them as one change |
| `policy review on\|off` | Ask before applying (off = lab mode; rules stay enforced; refused while operator keys are pinned) |
| `operators` | Pinned operator keys (signed approvals) and open signed requests |
| `boot` | Verified-boot verdict, release key, measurement registers and log |
| `capsign <id>` | Issue a hybrid post-quantum capability for an object and verify it |
| `capverify <id>` | Show unsigned, forged, and escalated tokens being rejected |
| `capbench <id> [n]` | Time *n* capability checks without and with the verified-proof cache |
| `audit [n]` | Last *n* audit records (default 12) |
| `audit-verify` | Verify the audit hash chain and every signed checkpoint |
| `audit-checkpoint` | Sign a checkpoint over the log now |
| `audit-demo-tamper <seq>` | Demo only: corrupt one record so `audit-verify` can show detection |
| `send <id> <text>` | Send a text message to an object |
| `recv <id>` | Pop next message from an object |
| `delete <id>` | Remove an object |
| `mem` | Memory graph summary |
| `node` | Show local node info |
| `discover <id> <ms>` | Simulate discovering a remote node |
| `net` / `net-status` | Show network interface count and packet stats |
| `netsend <if> <text>` | Queue packet payload bytes on an interface |
| `netrecv <if>` | Read one packet from an interface RX queue |
| `nettick` | Service network + run one automated bridge routing cycle |
| `netcaps` | Show capability-attributed network send/receive telemetry |
| `net2obj <if> <obj>` | Bridge one packet from interface into object message queue |
| `obj2net <obj> <if>` | Bridge one object message out as packet bytes |
| `cpus` | Show registered CPU cores, runtime drive mode, and per-core telemetry |
| `cpu-add-ap <id>` | Register an application core by APIC id |
| `cpu-start-ap <id> [force]` | Launch AP via INIT/SIPI and wait for trampoline status (`force` = BSP soft-ack debug path) |
| `cpu-ack-ap <id> <seq>` | Acknowledge AP entry for startup sequence and mark AP online |
| `cpu-arm-timer` | Arm this CPU's local APIC periodic timer (vector `0xF0`) and switch it to `lapic-local` drive mode |
| `cpu-calibrate [hz]` | Calibrate this CPU's LAPIC timer against PIT ticks and arm it (default target 20 Hz) |
| `cpu-ipi-resched <id>` | Send a Fixed reschedule IPI (vector `0xF1`) to wake/service a LocalApic core |
| `cpu-ipi-tlb <id\|all> [page\|#]` | Send Fixed TLB shootdown IPI (vector `0xF2`); `#`/omit = full flush |
| `cpu-step-ap <id> <n>` | Debug: software-inject `n` local timer ticks (prefer hardware after `cpu-arm-timer` / AP entry) |
| `cpu-halt <id>` | Mark a core as halted |
| `netbind-in <if> <obj>` | Bind interface ingress for automated bridge pumping |
| `netbind-out <obj> <if>` | Bind object egress for automated bridge pumping |
| `netbind-list` | Show configured automated bridge bindings |
| `netbind-clear` | Clear automated bridge bindings |
| `netadd-ext <if> <backend>` | Register an external interface backend (`virtio-net` or `stub-tap`) |
| `netpump <n>` | Run `n` automated bridge routing cycles (default 1) |
| `capsign <id>` | Sign a fresh capability for object `<id>` and verify the signature |
| `capverify <id>` | Check whether a capability for `<id>` is signed |
| `heapinfo` | Kernel heap usage (total / used / free) |
| `fbinfo` | Pixel framebuffer resolution and text grid size |
| `frames` | Physical frame allocator summary |
| `palloc` | Allocate one physical frame, print address |
| `pfree <addr>` | Free a physical frame by hex base address |
| `vminfo` | Virtual memory summary (PML4 address, mapped pages) |
| `vmmap <virt> <phys> [flags]` | Map virtual page → physical frame (`flags`: `krx`, `krw`, `urw`) |
| `vmunmap <virt>` | Remove a virtual page mapping |
| `vmtranslate <virt>` | Resolve virtual address to physical |
| `clear` | Clear serial console screen |

Console input shortcuts:

- `↑` recalls the previous command
- `Tab` autocompletes command names

## Website (GitHub Pages)

This repository includes a static website in `docs/` and a GitHub Actions workflow to publish it with GitHub Pages.

Local preview:

```bash
python3 -m http.server 8080 --directory docs
```

Then open [http://localhost:8080](http://localhost:8080).

Deployment:

- Workflow file: `.github/workflows/pages.yml`
- Source: `docs/`
- Published URL (after enabling Pages): `https://<your-github-username>.github.io/cdk/`

## Dependencies

| Crate | Purpose |
|---|---|
| `bootloader_api` 0.11 | Kernel entry point and boot info |
| `heapless` 0.8 | Fixed-capacity `no_std` collections |
| `spin` 0.9 | Spinlock-based `Mutex` for `no_std` |
| `panic-halt` 0.2 | Halt-on-panic handler |
| `volatile` 0.4 | Volatile memory access |

## Roadmap

The full plan — phases, milestones, and editions — is in [ROADMAP.md](ROADMAP.md). Phase 0 (kernel foundation) is complete:

- [x] Wire up `BootInfo` and a physical frame allocator
- [x] Set up IDT with double-fault, timer, and keyboard handlers
- [x] Timer-driven preemptive scheduling (50 ms time slice, round-robin re-queue)
- [x] 4-level x86_64 page-table manager (map / unmap / translate, lazy interior allocation)
- [x] Kernel heap allocator (`#[global_allocator]`, linked-list, 2 MiB reserved at boot)
- [x] Ed25519 capability signing (RDRAND on bare-metal, OsRng on host; SHA-256 message digest)
- [x] Issuer-bound hybrid post-quantum capability tokens (Ed25519 + ML-DSA-65, format v1) — roadmap milestone 1.1
- [x] Tamper-evident audit log with hybrid-signed checkpoints — roadmap milestone 1.2
- [x] User-fault containment: a crashing ring-3 program is terminated, audit-logged, and the kernel keeps running — roadmap milestone 1.3
- [x] NIST ACVP test vectors for ML-DSA-65, ML-KEM-768, Ed25519 and SHA-256 (854 test cases) plus RFC vectors for HKDF, X25519 and ChaCha20-Poly1305, run in CI — roadmap milestone 1.5
- [x] Key hygiene: zeroized keys and seeds, scrubbed crypto stack, zero-on-free heap, RFC 8032 / IETF ML-DSA known-answer tests, verified-proof cache — roadmap milestone 1.4
- [x] Rust user programs loaded from a boot ramdisk, with SHA-256 provenance in the audit log — roadmap milestone 2.1
- [x] Per-agent capability handles: grant, list, derive (attenuate only), drop, send/recv — every use verified and audited — roadmap milestone 2.2
- [x] Preemptive round-robin scheduling of agents, with a CPU-budget watchdog — roadmap milestone 2.3
- [x] Agents on every CPU: per-CPU scheduling with work stealing, kernel locking for syscalls, the console's CPU supervising approvals and tool results — roadmap milestone 2.7
- [x] Native integer-only inference for agents (`cdk-ml`, `CDKLM1` models) with a public demo classifier — roadmap milestone 2.4
- [x] Human-approval gates: approval-constrained capabilities block the agent until a person approves the exact payload — roadmap milestone 2.5
- [x] Host link: virtio-console transport, shared framing crate, and a host gateway — roadmap milestone 3.1
- [x] Post-quantum secure channel to the gateway: hybrid X25519 + ML-KEM-768, hybrid-signed transcript, pinned gateway identity, ChaCha20-Poly1305 — roadmap milestone 3.2
- [x] MCP gateway: agent tool calls gated by `exec` capabilities (optionally human-approved), sent sealed to MCP servers, and audit-logged — roadmap milestone 3.3
- [x] Model inference through Linux-hosted model servers (OpenAI-compatible), per-model capabilities, gateway-side credential injection — roadmap milestone 3.4
- [x] Fraud-prevention demo: two agents, signed two-person approvals, a prompt-injection that can't move money, case file — `tools/demo_fraud.sh --auto` ([DEMO.md](DEMO.md))
- [x] Verified and measured boot: release-signed ramdisk manifest checked by the kernel (lockdown on failure), firmware → measuring loader → kernel chain in TPM PCRs, attested with TPM quotes from an enrolled machine whose TPM proves it is genuine (endorsement certificate chain + credential activation) and UEFI Secure Boot (signed loader, pinned kernel) — roadmap milestone 4.2
- [x] Fuzzing of every parser of untrusted bytes (11 libFuzzer targets in CI), an in-kernel syscall fuzzer (`chaos`), AddressSanitizer on host tests — roadmap milestone 4.3 (independent review pending; see [SECURITY-REVIEW.md](SECURITY-REVIEW.md))
- [x] Signed operator approvals: post-quantum operator signatures, M-of-N quorum, vetoes, time-outs, every vote audit-logged — roadmap milestone 2.8
- [x] Policy change review: reach diffs, invariant rules, pinned gateway listings that block changed tools until approved, fail-closed boot policy — roadmap milestone 2.9
- [x] Framebuffer text rendering (8×16 bitmap font, RGB/BGR/U8 pixel formats, auto-scroll)
- [x] Network stack integration (loopback interfaces, capability-gated send/recv, object bridge routing, bindings, pump telemetry)
- [x] External network transport (virtio-net MMIO bring-up path + non-loopback external interfaces via `eth0` default external backend and adapter-based transports)
- [x] Multi-core foundation (trampoline, LAPIC, TSS, IPIs, MADT discovery, AP ready mailbox, percpu slots, TLB ACK)
- [x] Multi-core hardening (quiet SMP lifecycle, contiguous heap, GS-base PerCpu, kernel context switch, BSP lapic-local, x2APIC with xAPIC fallback, IOAPIC IRQ0/1 + optional `irq-route`)
- [x] User-mode / ring-3 foundation (user GDT segments, SCE/LSTAR syscall + `user-smoke`)
- [x] ELF64 loader and minimal process table
- [x] Run a loaded ELF as a ring-3 process (spawn → user entry → `SYS_write` → `SYS_exit` returns to the kernel → reap frees the address space)
- [ ] Load ELF programs from the boot image instead of the built-in smoke binary
- [ ] Schedule user processes preemptively alongside kernel tasks
- [x] GPU support (soft 2D command pipeline + FB flush; PCI/MMIO virtio-gpu probe under `virtio-hw`; `gpuinfo` / `gpusmoke`)
- [x] Unified memory foundation (contiguous shared regions, CPU fill + fence, virtio-gpu attach; IOMMU identity stub — no migration yet)

## Open Source Guidelines

This project welcomes external contributions. Please follow these baseline rules:

- Sign the [Contributor License Agreement](CLA.md) in your first pull request and sign off commits (`git commit -s`).
- Report security issues privately ([SECURITY.md](SECURITY.md)), never in public issues.
- Open an issue first for large changes so design direction can be aligned early.
- Keep pull requests focused. One concern per PR is preferred.
- Include tests or a clear validation procedure for behavioral changes.
- Update docs (`README.md`, `ARCHITECTURE.md`, and code comments) when behavior changes.
- Keep `no_std` and bare-metal constraints in mind; avoid adding host-only assumptions in kernel paths.

Detailed contributor workflow and review checklist lives in `CONTRIBUTING.md`.

## Hard Commit Standards

This repository uses strict commit message validation for local development and CI.

Accepted format:

```text
type(scope): short imperative summary
```

Required rules:

- `type` must be one of: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`
- `scope` is required and must be lowercase kebab-case (for example: `scheduler`, `console-shell`)
- subject must be 15-72 characters, start lowercase, and must not end with `.`
- `WIP`, `tmp`, `fixup!`, and `squash!` commit messages are rejected
- `feat`, `fix`, and `refactor` commits must include a body with implementation context

Examples:

- `feat(scheduler): add intent-aware queue aging`
- `fix(console): prevent message queue underflow on recv`
- `docs(readme): document qemu gui launch mode`

### Enable local enforcement

Run once after cloning:

```bash
./tools/install_git_hooks.sh
```

The installer sets both hooks:

- `.githooks/commit-msg` -> enforces commit message standard
- `.githooks/pre-push` -> blocks any push that updates `main` (tags and branches can be pushed from any checkout) and requires branch + PR workflow

### Branch Protection Workflow

- Do not push directly to `main`
- Create a topic branch for every change
- Push that branch and open a Pull Request into `main`

Example:

```bash
git switch -c feat/my-change
git push -u origin HEAD
```

## License

The open-source edition of CDK is licensed under the **Apache License 2.0**.

- Full license text: [`LICENSE`](LICENSE)
- Attribution and trademark notes: [`NOTICE`](NOTICE)
- Contributions are accepted under the [Contributor License Agreement](CLA.md) — you keep your copyright, and your code stays available here under Apache-2.0
- Vulnerability reporting: [`SECURITY.md`](SECURITY.md)
- Intended use: defensive and protective computing with human oversight — see [ROADMAP.md § Responsible use](ROADMAP.md#6-responsible-use)
