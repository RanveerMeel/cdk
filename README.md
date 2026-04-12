# CDK — Cognitive Distributed Kernel

A **bare-metal operating system kernel** written in Rust, designed around capability-based security, intent-driven scheduling, and distributed-first architecture.

## Features

**Bare-Metal Execution** — Boots on x86_64 hardware (or QEMU) with no OS underneath. Built with `#![no_std]` and `bootloader_api` 0.11.

**Capability-Based Security** — Every operation requires a cryptographic capability token. No global root, no ambient authority.

**Message-Passing IPC** — Objects communicate via typed messages (Data, Text, Command, Request/Response) through per-object queues.

**Intent-Driven Scheduling** — Tasks carry intent labels (`low_latency`, `batch`, `interactive`, etc.) that the scheduler maps to priorities.

**Memory Object Graph** — Tracks memory allocations per object with reference counting and usage statistics.

**Distributed Node Awareness** — Cloud, Edge, and Local node types with discovery, routing, and latency-aware selection built in from the start.

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
  serial.rs        COM1 UART driver (init, read, write)
  vga_buffer.rs    Serial-backed print!/println! macros
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
| `run` | Execute next task from the scheduler |
| `send <id> <text>` | Send a text message to an object |
| `recv <id>` | Pop next message from an object |
| `delete <id>` | Remove an object |
| `mem` | Memory graph summary |
| `node` | Show local node info |
| `discover <id> <ms>` | Simulate discovering a remote node |

## Dependencies

| Crate | Purpose |
|---|---|
| `bootloader_api` 0.11 | Kernel entry point and boot info |
| `heapless` 0.8 | Fixed-capacity `no_std` collections |
| `spin` 0.9 | Spinlock-based `Mutex` for `no_std` |
| `panic-halt` 0.2 | Halt-on-panic handler |
| `volatile` 0.4 | Volatile memory access |

## Roadmap

- [ ] Wire up `BootInfo` and a physical frame allocator
- [ ] Set up IDT with double-fault, timer, and keyboard handlers
- [ ] Timer-driven preemptive scheduling
- [ ] Restore Ed25519 capability signing (needs bare-metal RNG)
- [ ] Framebuffer text rendering (replace serial-only output)
- [ ] Network stack integration
- [ ] Multi-core support

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

The hook installs `.githooks/commit-msg`, which runs `tools/validate_commit_msg.sh`.

## License

This project is in early development.
