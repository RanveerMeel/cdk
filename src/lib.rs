#![cfg_attr(target_os = "none", no_std)]

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
