#![cfg_attr(not(test), no_std)]

pub mod serial;
pub mod vga_buffer;
#[cfg(not(test))]
pub mod gdt;
#[cfg(not(test))]
pub mod interrupts;
pub mod console;
pub mod kernel;
pub mod object;
pub mod capability;
pub mod scheduler;
pub mod message;
pub mod memory_graph;
pub mod node;
