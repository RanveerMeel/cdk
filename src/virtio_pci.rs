//! Virtio-PCI modern capability discovery and common-config helpers.
//!
//! Parses vendor-specific PCI capabilities (cap id `0x09`) to locate
//! common / notify / ISR / device-cfg MMIO windows for virtio 1.0 devices.

use crate::pci::{self, PciAddress, PciError};

/// PCI capability id: vendor specific.
pub const PCI_CAP_ID_VNDR: u8 = 0x09;

pub const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
pub const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
pub const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
pub const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// VIRTIO_F_VERSION_1 (bit 32).
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// virtio_pci_common_cfg field offsets
pub const COMMON_DEVICE_FEATURE_SELECT: u64 = 0x00;
pub const COMMON_DEVICE_FEATURE: u64 = 0x04;
pub const COMMON_DRIVER_FEATURE_SELECT: u64 = 0x08;
pub const COMMON_DRIVER_FEATURE: u64 = 0x0c;
pub const COMMON_MSIX_CONFIG: u64 = 0x10;
pub const COMMON_NUM_QUEUES: u64 = 0x12;
pub const COMMON_DEVICE_STATUS: u64 = 0x14;
pub const COMMON_CONFIG_GENERATION: u64 = 0x15;
pub const COMMON_QUEUE_SELECT: u64 = 0x16;
pub const COMMON_QUEUE_SIZE: u64 = 0x18;
pub const COMMON_QUEUE_MSIX_VECTOR: u64 = 0x1a;
pub const COMMON_QUEUE_ENABLE: u64 = 0x1c;
pub const COMMON_QUEUE_NOTIFY_OFF: u64 = 0x1e;
pub const COMMON_QUEUE_DESC: u64 = 0x20;
pub const COMMON_QUEUE_DRIVER: u64 = 0x28; // avail
pub const COMMON_QUEUE_DEVICE: u64 = 0x30; // used

pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_FAILED: u8 = 0x80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioPciCap {
    pub cfg_type: u8,
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
    /// Present for NOTIFY_CFG only.
    pub notify_off_multiplier: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioModernBars {
    pub common: VirtioPciCap,
    pub notify: VirtioPciCap,
    pub isr: Option<VirtioPciCap>,
    pub device: Option<VirtioPciCap>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioPciError {
    NoCapabilities,
    MissingCommon,
    MissingNotify,
    BadBar,
    Pci(PciError),
}

/// Decode a virtio vendor capability from raw PCI config bytes at `pos`.
///
/// Layout (16 bytes + optional notify multiplier):
/// `vndr, next, len, cfg_type, bar, pad[3], offset, length [, notify_mult]`.
pub fn parse_cap_bytes(bytes: &[u8]) -> Option<VirtioPciCap> {
    if bytes.len() < 16 {
        return None;
    }
    if bytes[0] != PCI_CAP_ID_VNDR {
        return None;
    }
    let cfg_type = bytes[3];
    let bar = bytes[4];
    let offset = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let length = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let notify_off_multiplier = if cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG && bytes.len() >= 20 {
        u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]])
    } else {
        0
    };
    Some(VirtioPciCap {
        cfg_type,
        bar,
        offset,
        length,
        notify_off_multiplier,
    })
}

/// Absolute MMIO address for a capability given BAR bases `[bar0..bar5]`.
pub fn cap_mmio(cap: &VirtioPciCap, bars: &[u64; 6]) -> Result<u64, VirtioPciError> {
    if (cap.bar as usize) >= 6 {
        return Err(VirtioPciError::BadBar);
    }
    let base = bars[cap.bar as usize];
    if base == 0 {
        return Err(VirtioPciError::BadBar);
    }
    Ok(base.wrapping_add(cap.offset as u64))
}

/// Read all six memory BARs (0 if absent / I/O).
pub fn read_all_bars(addr: PciAddress) -> [u64; 6] {
    let mut bars = [0u64; 6];
    let mut i = 0u8;
    while i < 6 {
        match pci::read_mem_bar(addr, i) {
            Ok((base, is_64)) => {
                bars[i as usize] = base;
                i = if is_64 { i + 2 } else { i + 1 };
            }
            Err(_) => {
                i += 1;
            }
        }
    }
    bars
}

/// Walk the PCI capability list and collect virtio modern caps.
pub fn discover_modern(addr: PciAddress) -> Result<VirtioModernBars, VirtioPciError> {
    let status = pci::cfg_read16(addr, 0x06);
    if status & (1 << 4) == 0 {
        return Err(VirtioPciError::NoCapabilities);
    }
    let mut pos = pci::cfg_read8(addr, 0x34);
    let mut common: Option<VirtioPciCap> = None;
    let mut notify: Option<VirtioPciCap> = None;
    let mut isr: Option<VirtioPciCap> = None;
    let mut device: Option<VirtioPciCap> = None;

    for _ in 0..48 {
        if pos < 0x40 || pos == 0xFF {
            break;
        }
        let id = pci::cfg_read8(addr, pos);
        let next = pci::cfg_read8(addr, pos.wrapping_add(1));
        if id == PCI_CAP_ID_VNDR {
            let mut raw = [0u8; 20];
            for (i, b) in raw.iter_mut().enumerate() {
                *b = pci::cfg_read8(addr, pos.wrapping_add(i as u8));
            }
            if let Some(cap) = parse_cap_bytes(&raw) {
                match cap.cfg_type {
                    VIRTIO_PCI_CAP_COMMON_CFG => common = Some(cap),
                    VIRTIO_PCI_CAP_NOTIFY_CFG => notify = Some(cap),
                    VIRTIO_PCI_CAP_ISR_CFG => isr = Some(cap),
                    VIRTIO_PCI_CAP_DEVICE_CFG => device = Some(cap),
                    _ => {}
                }
            }
        }
        if next == 0 || next == pos {
            break;
        }
        pos = next;
    }

    Ok(VirtioModernBars {
        common: common.ok_or(VirtioPciError::MissingCommon)?,
        notify: notify.ok_or(VirtioPciError::MissingNotify)?,
        isr,
        device,
    })
}

/// Map every page touched by a capability window.
pub fn map_cap_window(
    page_table: &mut crate::paging::PageTableManager,
    frame_alloc: &mut crate::allocator::FrameAllocator,
    mmio_base: u64,
    length: u32,
) {
    let start = mmio_base & !0xfff;
    let end = mmio_base
        .wrapping_add(length as u64)
        .wrapping_add(0xfff)
        & !0xfff;
    let mut page = start;
    while page < end {
        let _ = page_table.identity_map_mmio_page(page, frame_alloc);
        crate::paging::flush_tlb_page(page);
        page = page.wrapping_add(0x1000);
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod mmio {
    #[inline]
    pub unsafe fn read32(base: u64, off: u64) -> u32 {
        core::ptr::read_volatile((base + off) as *const u32)
    }
    #[inline]
    pub unsafe fn write32(base: u64, off: u64, v: u32) {
        core::ptr::write_volatile((base + off) as *mut u32, v)
    }
    #[inline]
    pub unsafe fn read16(base: u64, off: u64) -> u16 {
        core::ptr::read_volatile((base + off) as *const u16)
    }
    #[inline]
    pub unsafe fn write16(base: u64, off: u64, v: u16) {
        core::ptr::write_volatile((base + off) as *mut u16, v)
    }
    #[inline]
    pub unsafe fn read8(base: u64, off: u64) -> u8 {
        core::ptr::read_volatile((base + off) as *const u8)
    }
    #[inline]
    pub unsafe fn write8(base: u64, off: u64, v: u8) {
        core::ptr::write_volatile((base + off) as *mut u8, v)
    }
    #[inline]
    pub unsafe fn write64(base: u64, off: u64, v: u64) {
        write32(base, off, v as u32);
        write32(base, off + 4, (v >> 32) as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_common_cap() {
        let mut raw = [0u8; 20];
        raw[0] = PCI_CAP_ID_VNDR;
        raw[1] = 0;
        raw[2] = 16;
        raw[3] = VIRTIO_PCI_CAP_COMMON_CFG;
        raw[4] = 0; // bar0
        raw[8..12].copy_from_slice(&0x2000u32.to_le_bytes());
        raw[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
        let cap = parse_cap_bytes(&raw).unwrap();
        assert_eq!(cap.cfg_type, VIRTIO_PCI_CAP_COMMON_CFG);
        assert_eq!(cap.bar, 0);
        assert_eq!(cap.offset, 0x2000);
        assert_eq!(cap.length, 0x1000);
    }

    #[test]
    fn parse_notify_cap_with_multiplier() {
        let mut raw = [0u8; 20];
        raw[0] = PCI_CAP_ID_VNDR;
        raw[3] = VIRTIO_PCI_CAP_NOTIFY_CFG;
        raw[4] = 1;
        raw[8..12].copy_from_slice(&0x3000u32.to_le_bytes());
        raw[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
        raw[16..20].copy_from_slice(&4u32.to_le_bytes());
        let cap = parse_cap_bytes(&raw).unwrap();
        assert_eq!(cap.notify_off_multiplier, 4);
        let bars = [0xE000_0000, 0xE001_0000, 0, 0, 0, 0];
        assert_eq!(cap_mmio(&cap, &bars).unwrap(), 0xE001_0000 + 0x3000);
    }
}
