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
| `interactive` | 8 |
| `normal` | 5 |
| `batch` | 3 |
| `energy_saving` | 1 (lowest) |

### Messages (`src/message.rs`)

Typed payloads: `Data(Vec<u8>)`, `Text(String)`, `Command(String)`, `Request { method, params }`, `Response { result }`. All backed by `heapless` fixed-capacity types.

### Memory Graph (`src/memory_graph.rs`)

Tracks per-object memory allocations with reference counting. Provides total memory usage and per-object queries.

### Distributed Nodes (`src/node.rs`)

Models a multi-machine topology with Local, Edge, and Cloud node types. Supports discovery, latency tracking, and type-preferred routing.

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
