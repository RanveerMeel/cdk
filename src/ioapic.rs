//! I/O APIC routing (M13).
//!
//! Discovers the first IOAPIC from MADT, maps its MMIO window, and programs
//! redirection entries for ISA IRQs (PIT / keyboard by default).

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use heapless::Vec;

const MAX_OVERRIDES: usize = 16;
const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;

const IOAPICID: u32 = 0;
const IOAPICVER: u32 = 1;
const IOREDTBL: u32 = 0x10;

static READY: AtomicBool = AtomicBool::new(false);
static IOAPIC_BASE: AtomicU64 = AtomicU64::new(0);
static IOAPIC_ID: AtomicU32 = AtomicU32::new(0);
static GSI_BASE: AtomicU32 = AtomicU32::new(0);
static MAX_REDIR: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, Default)]
pub struct IsoOverride {
    pub irq: u8,
    pub gsi: u32,
    pub flags: u16,
}

static OVERRIDES: spin::Mutex<Vec<IsoOverride, MAX_OVERRIDES>> = spin::Mutex::new(Vec::new());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoApicError {
    NotReady,
    NoIoApic,
    MapFailed,
    BadIrq,
}

/// Record MADT IOAPIC (type 1) and ISO (type 2) entries during ACPI parse.
pub fn note_ioapic(id: u8, address: u64, gsi_base: u32) {
    if IOAPIC_BASE.load(Ordering::Relaxed) == 0 {
        IOAPIC_ID.store(id as u32, Ordering::Relaxed);
        IOAPIC_BASE.store(address, Ordering::Relaxed);
        GSI_BASE.store(gsi_base, Ordering::Relaxed);
    }
}

pub fn note_iso(irq: u8, gsi: u32, flags: u16) {
    let mut o = OVERRIDES.lock();
    let _ = o.push(IsoOverride { irq, gsi, flags });
}

pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

pub fn mmio_base() -> u64 {
    IOAPIC_BASE.load(Ordering::Acquire)
}

fn reg_write(base: u64, index: u32, value: u32) {
    #[cfg(target_os = "none")]
    unsafe {
        core::ptr::write_volatile((base + IOREGSEL) as *mut u32, index);
        core::ptr::write_volatile((base + IOWIN) as *mut u32, value);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (base, index, value);
    }
}

fn reg_read(base: u64, index: u32) -> u32 {
    #[cfg(target_os = "none")]
    unsafe {
        core::ptr::write_volatile((base + IOREGSEL) as *mut u32, index);
        core::ptr::read_volatile((base + IOWIN) as *const u32)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (base, index);
        0
    }
}

fn write_rte(base: u64, index: u32, low: u32, high: u32) {
    reg_write(base, IOREDTBL + index * 2, low);
    reg_write(base, IOREDTBL + index * 2 + 1, high);
}

/// Map IOAPIC MMIO and program IRQ0/IRQ1 to PIC-compatible vectors 0x20/0x21.
pub fn init_and_route_isa(
    page_table: &mut crate::paging::PageTableManager,
    frame_alloc: &mut crate::allocator::FrameAllocator,
    dest_apic_id: u32,
) -> Result<(), IoApicError> {
    let base = IOAPIC_BASE.load(Ordering::Acquire);
    if base == 0 {
        return Err(IoApicError::NoIoApic);
    }
    let page = base & !0xfff;
    page_table
        .identity_map_mmio_page(page, frame_alloc)
        .map_err(|_| IoApicError::MapFailed)?;

    let ver = reg_read(base, IOAPICVER);
    let max_redir = ((ver >> 16) & 0xff) as u32;
    MAX_REDIR.store(max_redir, Ordering::Release);
    let _ = reg_read(base, IOAPICID);

    // Default: identity IRQ→GSI unless ISO overrides.
    route_irq(0, 0x20, dest_apic_id)?;
    route_irq(1, 0x21, dest_apic_id)?;

    READY.store(true, Ordering::Release);
    crate::println!(
        "IOAPIC: base={:#x} id={} gsi_base={} max_redir={} dest_apic={}",
        base,
        IOAPIC_ID.load(Ordering::Relaxed),
        GSI_BASE.load(Ordering::Relaxed),
        max_redir,
        dest_apic_id
    );
    Ok(())
}

fn gsi_for_irq(irq: u8) -> u32 {
    let o = OVERRIDES.lock();
    if let Some(iso) = o.iter().find(|e| e.irq == irq) {
        return iso.gsi;
    }
    GSI_BASE.load(Ordering::Relaxed) + irq as u32
}

/// Program (or reprogram) an ISA IRQ to `vector` delivered to `dest_apic_id`.
pub fn route_irq(irq: u8, vector: u8, dest_apic_id: u32) -> Result<(), IoApicError> {
    let base = IOAPIC_BASE.load(Ordering::Acquire);
    if base == 0 {
        return Err(IoApicError::NoIoApic);
    }
    let gsi = gsi_for_irq(irq);
    let gsi_base = GSI_BASE.load(Ordering::Relaxed);
    if gsi < gsi_base {
        return Err(IoApicError::BadIrq);
    }
    let index = gsi - gsi_base;
    let max = MAX_REDIR.load(Ordering::Acquire);
    if max != 0 && index > max {
        return Err(IoApicError::BadIrq);
    }

    // Delivery mode Fixed, dest mode physical, active-high, edge, unmasked.
    let low = vector as u32;
    let high = dest_apic_id << 24;
    write_rte(base, index, low, high);
    Ok(())
}

/// Console helper: change affinity for an ISA IRQ.
pub fn set_irq_affinity(irq: u8, dest_apic_id: u32) -> Result<(), IoApicError> {
    if !is_ready() {
        return Err(IoApicError::NotReady);
    }
    let vector = 0x20u8.saturating_add(irq);
    route_irq(irq, vector, dest_apic_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_ioapic_records_base() {
        note_ioapic(0, 0xFEC0_0000, 0);
        assert_eq!(mmio_base(), 0xFEC0_0000);
        note_iso(0, 2, 0);
        assert_eq!(gsi_for_irq(0), 2);
        assert_eq!(gsi_for_irq(1), 1);
    }
}
