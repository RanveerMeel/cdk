#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", feature(abi_x86_interrupt))]

pub mod allocator;
pub mod capability;
pub mod console;
pub mod framebuffer;
#[cfg(target_os = "none")]
pub mod gdt;
pub mod heap;
#[cfg(target_os = "none")]
pub mod interrupts;
pub mod kernel;
pub mod local_apic;
pub mod memory_graph;
pub mod message;
pub mod multicore;
pub mod network;
pub mod node;
pub mod object;
pub mod paging;
pub mod phys_mem;
pub mod rng;
pub mod scheduler;
pub mod serial;
pub mod vga_buffer;
