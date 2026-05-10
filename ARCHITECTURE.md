# CDK Architecture

## Overview

The Cognitive Distributed Kernel (CDK) is a bare-metal kernel targeting x86_64 with:

- `#![no_std]` — no OS, no allocator, no standard library
- Capability-based security for all object access
- Message-passing IPC between kernel objects
- Intent-driven scheduling (not thread-based)
- Distributed node awareness (cloud/edge/local)

## Core Components

### Kernel (`src/kernel.rs`)

Central registry of kernel objects. All access goes through capability tokens. Owns the scheduler and dispatches execution.

### Capabilities (`src/capability.rs`)

Permission tokens bound to a specific object. Supports: Read, Write, Execute, SendMessage, ReceiveMessage, Delete. Designed for Ed25519 signing (currently simplified for bare-metal — no RNG yet).

### Objects (`src/object.rs`)

Every schedulable unit is a `KernelObject` with a unique ID, a kind, an intent label, and a message queue (`heapless::Deque`).

### Scheduler (`src/scheduler.rs`)

Priority queue (`heapless::Vec` sorted by priority). Intent labels map to numeric priorities:

| Intent | Priority |
|---|---|
| `low_latency` | 10 (highest) |
| `interactive` | 7 |
| `normal` | 5 |
| `batch` | 3 |
| `energy_saving` | 2 (lowest) |

#### Preemptive time-slicing

`Scheduler` tracks a `running: Option<RunningTask>` slot alongside the ready queue.
Each dispatched task records the tick at which it started (`started_at_tick`).

On every PIT timer interrupt the ISR calls `Kernel::preempt_tick(current_tick)` via
a statically-registered function pointer hook (`interrupts::set_preempt_hook`).
If the running task has consumed `TICKS_PER_SLICE` (50) ticks it is evicted, re-queued
at its original priority (round-robin within a priority band), and the next queued task
is dispatched immediately.

The hook uses `Mutex::try_lock` so the ISR never spins — if the lock is held by the
console or boot path the tick is silently skipped and scheduling catches up on the next
IRQ.

### Messages (`src/message.rs`)

Typed payloads: `Data(Vec<u8>)`, `Text(String)`, `Command(String)`, `Request { method, params }`, `Response { result }`. All backed by `heapless` fixed-capacity types.

### Memory Graph (`src/memory_graph.rs`)

Tracks per-object memory allocations with reference counting. Provides total memory usage and per-object queries.

### Distributed Nodes (`src/node.rs`)

Models a multi-machine topology with Local, Edge, and Cloud node types. Supports discovery, latency tracking, and type-preferred routing.

### Virtual Memory (`src/paging.rs`)

Manages a single 4-level x86_64 page-table hierarchy (PML4 → PDPT → PD → PT).

| Concept | Detail |
|---|---|
| Root frame | PML4 allocated from `FrameAllocator` at boot; physical address stored in `PageTableManager` |
| Interior nodes | Allocated lazily on first use via `FrameSource::alloc_zeroed` |
| Identity mapping | All physical addresses are assumed identity-mapped (phys == virt for kernel space) — the bootloader guarantees this |
| Page flags | `MapFlags` wraps `PRESENT`, `WRITABLE`, `USER`, `NO_EXECUTE` into three presets: `kernel_rx`, `kernel_rw`, `user_rw` |
| API | `map(virt, phys, flags)`, `unmap(virt)`, `translate(virt) → phys` |

The `FrameSource` trait decouples the walker from the concrete allocator, enabling lightweight mock allocators in host unit tests.

### Serial Console (`src/console.rs`)

Interactive command loop over COM1. Locks the global `Kernel`, `MemoryGraph`, and `KernelNode` mutexes per command, then releases them.

## Memory Layout

Large data structures (`Kernel`, `MemoryGraph`, `KernelNode`) are `static` globals in BSS behind `spin::Mutex`, keeping the kernel stack small (~8 KB). The bootloader allocates a 100 KiB stack.

## Build Pipeline

1. `cargo build --release --bin cdk` — compiles the kernel ELF for `x86_64-unknown-none`
2. `tools/create_disk_image` — wraps the ELF in a BIOS-bootable raw disk image using `bootloader` 0.11's `BiosBoot` API (requires nightly for `-Z build-std`)
3. QEMU boots the image; the bootloader sets up paging, a graphical framebuffer, and a GDT, then jumps to `_start` which calls `kernel_main`

## Dependencies

All dependencies are `no_std` compatible:

- `bootloader_api` — entry point macro and `BootInfo`
- `heapless` — `FnvIndexMap`, `Vec`, `Deque`, `String` with fixed capacities
- `spin` — spinlock `Mutex` (no OS primitives needed)
- `panic-halt` — halts on panic
- `volatile` — volatile memory operations
