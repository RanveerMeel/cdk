#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", feature(abi_x86_interrupt))]

pub mod serial;
pub mod vga_buffer;
#[cfg(target_os = "none")]
pub mod gdt;
#[cfg(target_os = "none")]
pub mod interrupts;
pub mod console;
pub mod kernel;
pub mod object;
pub mod capability;
pub mod scheduler;
pub mod message;
pub mod memory_graph;
pub mod node;
