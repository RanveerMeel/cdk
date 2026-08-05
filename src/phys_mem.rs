//! Physical-memory mapping helpers.
//!
//! The bootloader can map physical memory at a configurable virtual offset.
//! Store that offset at boot and use these helpers whenever converting a
//! physical frame address to a dereferenceable virtual pointer.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static PHYS_OFFSET: AtomicU64 = AtomicU64::new(0);
static PHYS_OFFSET_READY: AtomicBool = AtomicBool::new(false);

pub fn set_physical_memory_offset(offset: u64) {
    PHYS_OFFSET.store(offset, Ordering::Release);
    PHYS_OFFSET_READY.store(true, Ordering::Release);
}

pub fn physical_memory_offset() -> Option<u64> {
    if PHYS_OFFSET_READY.load(Ordering::Acquire) {
        Some(PHYS_OFFSET.load(Ordering::Acquire))
    } else {
        None
    }
}

#[inline]
pub fn phys_to_virt_addr(phys: u64) -> u64 {
    match physical_memory_offset() {
        Some(offset) => phys.saturating_add(offset),
        None => phys,
    }
}

#[inline]
pub fn phys_to_mut_ptr<T>(phys: u64) -> *mut T {
    phys_to_virt_addr(phys) as *mut T
}

#[inline]
pub fn phys_to_ptr<T>(phys: u64) -> *const T {
    phys_to_virt_addr(phys) as *const T
}
