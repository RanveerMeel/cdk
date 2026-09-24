# CDK Architecture

## Overview

The Cognitive Distributed Kernel (CDK) is a bare-metal kernel targeting x86_64 with:

- `#![no_std]` + `extern crate alloc` — no OS, no standard library; a custom heap provides `alloc` types
- Capability-based security for all object access
- Message-passing IPC between kernel objects
- Intent-driven scheduling (not thread-based)
- Distributed node awareness (cloud/edge/local)

## Core Components

### Kernel (`src/kernel.rs`)

Central registry of kernel objects. All access goes through capability tokens. Owns the scheduler and dispatches execution.

### Capabilities (`src/capability.rs`, `src/issuer.rs`, `src/rng.rs`)

Permission tokens bound to a specific object. Supports: Read, Write, Execute, SendMessage, ReceiveMessage, Delete.

#### Issuer-bound hybrid post-quantum proofs (token format v1)

At boot the kernel generates one **issuer** identity: an Ed25519 key pair and an ML-DSA-65 (FIPS 204) key pair, from independent RDRAND seeds. Every kernel-issued capability carries a proof signed by that issuer:

```
digest = SHA-256( "CDK-CAP" ‖ format ‖ algorithm ‖ issuer_id[16]
                  ‖ u16_le(len(object_id)) ‖ object_id ‖ u8(count) ‖ sorted_permission_tags )
proof  = { format=1, algorithm=HybridEd25519MlDsa65, issuer_id,
           Ed25519(digest), ML-DSA-65(digest, context="CDK-CAP-v1") }
```

| Detail | Value |
|---|---|
| Signatures | Ed25519 (64 B) **and** ML-DSA-65 (3,309 B); both must verify |
| Issuer public keys | 32 B + 1,952 B; `issuer_id = SHA-256("CDK-ISSUER-v1" ‖ keys)[..16]` |
| Trust anchor | The pinned kernel issuer; tokens naming another issuer fail with `UnknownIssuer` |
| Downgrade protection | `format` and `algorithm` are inside the signed digest |
| Foreign issuers | `Capability::verify_with(&IssuerPublic)` (for future multi-node trust) |

Format v0 stored the signer's public key inside the token and accepted any self-signed token, so anyone could mint a capability; v1 verifies only against the pinned issuer. `Kernel::check_signature` enforces a valid proof on every capability-gated operation (`KernelError::InvalidSignature` otherwise). Console: `issuer`, `capsign <id>`, `capverify <id>`.

#### Crypto stack

ML-DSA-65 needs more stack than any kernel stack provides (host measurements: ~280 KiB keygen, ~100 KiB sign, ~66 KiB verify; QEMU peak 323 KiB). All issuer operations switch to a dedicated, pattern-painted 512 KiB stack (`issuer::crypto_stack`) under a lock, so capability checks are safe from any context, including 16 KiB syscall/interrupt stacks. `issuer` reports the peak usage.

#### RNG (`src/rng.rs`)

`KernelRng` implements `rand_core::CryptoRng + RngCore`:
- **Bare-metal**: RDRAND (retried up to 10 times). Without RDRAND it falls back to SplitMix64 seeded from RDTSC, which is **not secure**; `rng::entropy_source()` reports this and the issuer prints a warning that tokens are forgeable.
- **Host tests**: `rand_core::OsRng` backed by OS entropy

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

#### User address spaces

`AddressSpace::from_kernel` allocates a private PML4 and copies every present kernel PML4 entry by reference. Because those lower-level tables are shared, writing a user mapping into any of them would leak it into the kernel and every other process. User pages therefore live only in `USER_PML4_SLOT` (slot 1, `USER_BASE = 0x80_0000_0000` .. `USER_TOP`, 512 GiB), which the address space owns outright:

- `map_user` rejects addresses outside the user region or non-user flags.
- `from_kernel` fails with `UserSlotInUse` if the kernel ever occupies slot 1.
- `translate_user` / `copy_from_user` require the USER bit at every level and read through the physical-memory map, so syscalls can validate and copy user buffers without faulting.
- `destroy` frees the user pages, the slot-1 tables, and the PML4.

### User Processes (`src/process.rs`, `src/syscall.rs`, `src/elf.rs`)

Lifecycle: `elf-spawn` loads an ELF into a new address space → `Ready`; `elf-run` → `Running`; `SYS_exit` → `Zombie`; `reap` frees the address space and slot.

`syscall::run_user` saves the caller's callee-saved registers, `RSP`, `RFLAGS` and `CR3` in a per-CPU slot, loads the process `CR3`, and `iretq`s into ring 3. On `SYS_exit` the syscall path restores that context, so `run_user` simply returns the exit code — the console keeps running. Syscalls: `SYS_exit(code)` (1) and `SYS_write(ptr, len)` (2, up to 1024 bytes, returns the byte count or `-1`).

### Kernel Heap (`src/heap.rs`)

A `linked_list_allocator::Heap` wrapped in a `spin::Mutex`, registered as `#[global_allocator]` on bare-metal.

| Concept | Detail |
|---|---|
| Backing memory | 512 physical frames (2 MiB) allocated from `FrameAllocator` at boot |
| Address model | Identity-mapped — frame physical addresses == virtual addresses |
| Thread safety | All access goes through `spin::Mutex`; safe for single-core use |
| Host tests | `#[global_allocator]` is `#[cfg(target_os = "none")]`-gated; tests call `init_from_slice` with a stack-allocated buffer |

Once the heap is live, `alloc` types (`Box`, `Vec`, `String`, `Arc`) become available throughout the kernel. Current consumers: none yet — the heap is the foundation for the next features (capability signing, smoltcp network stack).

Boot sequence: serial init → framebuffer init → interrupts → frame allocator → **heap init** → page-table setup → console.

### Framebuffer (`src/framebuffer.rs`)

Pixel-level text renderer that displays kernel output directly on the QEMU graphical window.

| Concept | Detail |
|---|---|
| Font | Built-in 8×16 monospaced bitmap covering printable ASCII (0x20–0x7E) |
| Pixel formats | `Rgb`, `Bgr`, `U8` (greyscale); format detected at runtime from bootloader `FrameBuffer::info()` |
| Scroll | Entire buffer shifted up one character row (`core::ptr::copy`); last row cleared |
| Cursor | Software (col, row) — no hardware cursor, no blink |
| Init | `framebuffer::init(fb: &'static mut BootInfo::framebuffer)` — called once during boot before first `println!` |
| Multiplexing | `vga_buffer::_print` writes to both COM1 serial and the framebuffer so output is always visible |
| Thread safety | Global `FRAMEBUFFER: spin::Mutex<Option<Framebuffer>>`; `try_lock` used in the print path to avoid deadlocks |

Boot sequence: serial init → **framebuffer init** → interrupts → frame allocator → heap → page tables → console.

### Serial Console (`src/console.rs`)

Interactive command loop over COM1. Locks the global `Kernel`, `MemoryGraph`, and `KernelNode` mutexes per command, then releases them.

## Memory Layout

Large data structures (`Kernel`, `MemoryGraph`, `KernelNode`) are `static` globals in BSS behind `spin::Mutex`, keeping the kernel stack small (~8 KB). The bootloader allocates a 100 KiB stack.

The kernel heap occupies a contiguous 2 MiB region within the physical address space that the bootloader marks as `Usable`.

## Build Pipeline

1. `cargo build --release --bin cdk` — compiles the kernel ELF for `x86_64-unknown-none`
2. `tools/create_disk_image` — wraps the ELF in a BIOS-bootable raw disk image using `bootloader` 0.11's `BiosBoot` API (requires nightly for `-Z build-std`)
3. QEMU boots the image; the bootloader sets up paging, a graphical framebuffer, and a GDT, then jumps to `_start` which calls `kernel_main`

## Dependencies

All dependencies are `no_std` compatible:

- `bootloader_api` — entry point macro and `BootInfo`
- `heapless` — `FnvIndexMap`, `Vec`, `Deque`, `String` with fixed capacities
- `spin` — spinlock `Mutex` (no OS primitives needed)
- `linked_list_allocator` — `no_std`-compatible heap for `#[global_allocator]`
- `ed25519-dalek` — Ed25519 signing and verification
- `sha2` — SHA-256 message digest
- `rand_core` — `CryptoRng` / `RngCore` traits
- (no extra crate needed for framebuffer — the bootloader provides the pixel buffer and format info directly via `bootloader_api`)
- `panic-halt` — halts on panic
- `volatile` — volatile memory operations
