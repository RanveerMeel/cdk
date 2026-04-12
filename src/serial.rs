//! COM1 (0x3F8) — same device QEMU maps with `-serial stdio`, so kernel logs show in the terminal.

use core::fmt;

const COM1: u16 = 0x3F8;

#[inline]
unsafe fn outb(port: u16, v: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") v,
        options(nomem, nostack, preserves_flags),
    );
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!(
        "in al, dx",
        in("dx") port,
        out("al") v,
        options(nomem, nostack, preserves_flags),
    );
    v
}

/// Minimal 8N1 @ 38400 — sufficient for QEMU and matches common bootloader expectations.
pub fn init() {
    unsafe {
        outb(COM1 + 1, 0x00); // Disable interrupts
        outb(COM1 + 3, 0x80); // DLAB on
        outb(COM1 + 0, 0x03); // Divisor low byte (38400)
        outb(COM1 + 1, 0x00); // Divisor high byte
        outb(COM1 + 3, 0x03); // 8N1, DLAB off
        outb(COM1 + 2, 0xc7); // FIFO enable, clear, 14-byte threshold
        outb(COM1 + 4, 0x0b); // RTS/DSR set, IRQs off
    }
}

pub fn write_byte(byte: u8) {
    unsafe {
        while (inb(COM1 + 5) & 0x20) == 0 {}
        outb(COM1, byte);
    }
}

/// Returns true if a byte is waiting in the receive buffer.
pub fn data_available() -> bool {
    unsafe { (inb(COM1 + 5) & 0x01) != 0 }
}

/// Blocking read — spins until a byte arrives on COM1.
pub fn read_byte() -> u8 {
    unsafe {
        while !data_available() {
            core::arch::asm!("pause", options(nomem, nostack));
        }
        inb(COM1)
    }
}

fn write_str(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}

pub struct SerialPort;

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str(s);
        Ok(())
    }
}
