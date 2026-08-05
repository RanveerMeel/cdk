# CDK — Cognitive Distributed Kernel

**Website:** [https://ranveermeel.github.io/cdk/](https://ranveermeel.github.io/cdk/) _(GitHub Pages)_

A **bare-metal operating system kernel** written in Rust, designed around capability-based security, intent-driven scheduling, and distributed-first architecture.

## Status

**Early development preview.** CDK boots on bare metal (QEMU), exposes an interactive serial console, and includes foundational scheduling, capability, networking, and multicore scaffolding. Interfaces can still change quickly while core subsystems stabilize.

## Features

**Bare-Metal Execution** — Boots on x86_64 hardware (or QEMU) with no OS underneath. Built with `#![no_std]` and `bootloader_api` 0.11.

**Capability-Based Security** — Every operation requires a cryptographic capability token. No global root, no ambient authority.

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

This builds the kernel, creates a BIOS-bootable disk image, and launches QEMU with the serial console connected to your terminal. Type `help` at the `cdk>` prompt.

For a graphical QEMU window instead:

```bash
CDK_QEMU_GUI=1 ./run_qemu.sh
```

To compile the virtio-net hardware backend path:

```bash
cargo check --features virtio-hw
```

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
| `cpu-start-ap <id>` | Launch AP startup and complete online transition via trampoline entry hook |
| `cpu-ack-ap <id> <seq>` | Acknowledge AP entry for startup sequence and mark AP online |
| `cpu-step-ap <id> <n>` | Simulate `n` local APIC timer ticks and service AP-assigned work |
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

- [x] Wire up `BootInfo` and a physical frame allocator
- [x] Set up IDT with double-fault, timer, and keyboard handlers
- [x] Timer-driven preemptive scheduling (50 ms time slice, round-robin re-queue)
- [x] 4-level x86_64 page-table manager (map / unmap / translate, lazy interior allocation)
- [x] Kernel heap allocator (`#[global_allocator]`, linked-list, 2 MiB reserved at boot)
- [x] Ed25519 capability signing (RDRAND on bare-metal, OsRng on host; SHA-256 message digest)
- [x] Framebuffer text rendering (8×16 bitmap font, RGB/BGR/U8 pixel formats, auto-scroll)
- [x] Network stack integration (loopback interfaces, capability-gated send/recv, object bridge routing, bindings, pump telemetry)
- [x] External network transport (virtio-net MMIO bring-up path + non-loopback external interfaces via `eth0` default external backend and adapter-based transports)
- [ ] Multi-core support (Phase 12 complete: local APIC timer IRQ hook path integrated to AP runtime service API; next: route real AP local timer vector delivery on AP cores and replace console stepping with hardware interrupts)
- [ ] GPU support (PCI/virtio-gpu discovery, mode setting, command submission pipeline)
- [ ] Unified memory support (shared CPU/GPU VA model, page migration/coherency, IOMMU integration)

## Open Source Guidelines

This project welcomes external contributions. Please follow these baseline rules:

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

CDK is licensed under the **Apache License 2.0**.

- Full license text: `LICENSE`
- Third-party attribution notes: `NOTICE`
