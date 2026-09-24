# CDK — Quantum-Safe Agent Trust Kernel

**Website:** [https://ranveermeel.github.io/cdk/](https://ranveermeel.github.io/cdk/) _(GitHub Pages)_ · **Plan:** [ROADMAP.md](ROADMAP.md) · **Security:** [SECURITY.md](SECURITY.md)

CDK (Cognitive Distributed Kernel) is an open-source, bare-metal Rust kernel for running **AI agents under kernel-enforced, cryptographically provable permissions**, built on **post-quantum cryptography** from the start.

- **Agents are isolated processes.** An agent can only reach an object, tool, model, or network endpoint if it holds a capability for it.
- **Capabilities are issued and verified by the kernel**, signed with hybrid **Ed25519 + ML-DSA-65 (FIPS 204)**, so they can't be forged by classical or future quantum attackers.
- **Every consequential action is provable** through a tamper-evident, hash-chained audit log with signed checkpoints.
- **Humans stay in control:** consequential actions require a human-approval capability, enforced by the kernel *(planned)*.

Heavy AI inference (GPUs, CUDA) runs on Linux next to CDK; CDK is the control plane that decides which agent may use which model and records it. See [ROADMAP.md](ROADMAP.md) for the architecture and milestones.

## Status

**Early development preview — not for production use.** CDK boots on bare metal (QEMU) with SMP, preemptive scheduling, ring-3 processes in isolated address spaces, and an interactive serial console. The quantum-safe trust core (Phase 1 of the [roadmap](ROADMAP.md)) is being built now: Phase 1 is done, and Phase 2 (agent runtime) has started: user programs written in Rust now load from the boot ramdisk. Per-agent capability handles are next. Interfaces can still change quickly.

### Editions

CDK is **open core**. This repository — the kernel, the capability model, the agent runtime, and *all* cryptography — is Apache-2.0. Commercial editions for regulated sectors (finance, defense) add hardware integrations (QKD, HSMs), certified builds, sector policy packs, and support; see [ROADMAP.md § Editions](ROADMAP.md#5-editions).

## Features

**Bare-Metal Execution** — Boots on x86_64 hardware (or QEMU) with no OS underneath. Built with `#![no_std]` and `bootloader_api` 0.11.

**Capability-Based Security** — Every operation requires a capability token issued by the kernel. No global root, no ambient authority.

**Quantum-Safe Capability Tokens** — Tokens are signed by a boot-time kernel issuer with hybrid Ed25519 + ML-DSA-65 (FIPS 204); both must verify, and only the pinned issuer is trusted, so self-signed or tampered tokens are rejected. Post-quantum operations run on a dedicated 512 KiB crypto stack. Console: `issuer`, `capsign`, `capverify`.

**User Programs from a Boot Ramdisk** — Programs in `user/` are ordinary `no_std` Rust (`cdk_user` provides `_start`, syscalls, `println!`). `run_qemu.sh` builds them, packs a reproducible `ustar` ramdisk, and the bootloader loads it next to the kernel. The kernel parses the archive strictly, maps each program at its linked address with a 64 KiB stack and an unmapped guard page, and logs the image's SHA-256 (`program-loaded`) so every process can be traced to the exact binary that ran.

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

This builds the kernel, creates a BIOS-bootable disk image, and launches QEMU with **2 vCPUs** (`-smp 2`) and the serial console connected to your terminal. Override with `CDK_QEMU_SMP=4 ./run_qemu.sh`. Type `help` at the `cdk>` prompt.

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
| `exec <name>` | Load and run a ramdisk program (`exec hello`, `exec checksum`, `exec overflow`) |
| `elf-spawn [prog]` | Load a built-in program as a `Ready` process: `hello` (default), or crash tests `ud`, `pf`, `gp`, `de` |
| `elf-run <pid>` | Run a `Ready` process in ring 3 until it calls `SYS_exit` |
| `elf-smoke [prog]` | `elf-spawn` + `elf-run` in one step (`elf-smoke pf` shows a contained page fault) |
| `ps` | List processes (Ready / Running / Zombie / Crashed) |
| `reap <pid>` | Free a `Ready`/`Zombie`/`Crashed` process and its address space |
| `user-smoke` | Minimal ring-3 round trip (enter, `SYS_exit`, return) |
| `issuer` | Kernel capability issuer: id, algorithms, entropy source, crypto-stack peak |
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
- [x] Key hygiene: zeroized keys and seeds, scrubbed crypto stack, zero-on-free heap, RFC 8032 / IETF ML-DSA known-answer tests, verified-proof cache — roadmap milestone 1.4
- [x] Rust user programs loaded from a boot ramdisk, with SHA-256 provenance in the audit log — roadmap milestone 2.1
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
- `.githooks/pre-push` -> blocks direct pushes to `main` and requires branch + PR workflow

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
