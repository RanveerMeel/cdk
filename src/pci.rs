//! Minimal PCI configuration-space access (Type-1 via ports 0xCF8/0xCFC).
//!
//! Enough to discover a virtio-gpu function and read its BARs for the GPU
//! bring-up path. Not a full PCI subsystem.

/// PCI vendor: Red Hat / virtio.
pub const VENDOR_VIRTIO: u16 = 0x1AF4;
/// Modern virtio-gpu PCI device id.
pub const DEVICE_VIRTIO_GPU: u16 = 0x1050;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciDevice {
    pub addr: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    /// BAR0 physical base (memory), 0 if I/O or unset.
    pub bar0: u64,
    pub bar0_size_hint: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciError {
    NotFound,
    BadBar,
}

#[inline]
fn config_addr(addr: PciAddress, offset: u8) -> u32 {
    let off = (offset as u32) & 0xFC;
    0x8000_0000
        | ((addr.bus as u32) << 16)
        | ((addr.device as u32) << 11)
        | ((addr.function as u32) << 8)
        | off
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn cfg_read32(addr: PciAddress, offset: u8) -> u32 {
    unsafe {
        let a = config_addr(addr, offset);
        core::arch::asm!("out dx, eax", in("dx") 0xCF8u16, in("eax") a, options(nostack, preserves_flags));
        let mut val: u32;
        core::arch::asm!("in eax, dx", in("dx") 0xCFCu16, out("eax") val, options(nostack, preserves_flags));
        val
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn cfg_write32(addr: PciAddress, offset: u8, value: u32) {
    unsafe {
        let a = config_addr(addr, offset);
        core::arch::asm!("out dx, eax", in("dx") 0xCF8u16, in("eax") a, options(nostack, preserves_flags));
        core::arch::asm!("out dx, eax", in("dx") 0xCFCu16, in("eax") value, options(nostack, preserves_flags));
    }
}

#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
fn cfg_read32(_addr: PciAddress, _offset: u8) -> u32 {
    0xFFFF_FFFF
}

#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
fn cfg_write32(_addr: PciAddress, _offset: u8, _value: u32) {}

pub fn read_vendor_device(addr: PciAddress) -> (u16, u16) {
    let v = cfg_read32(addr, 0x00);
    ((v & 0xFFFF) as u16, (v >> 16) as u16)
}

/// Byte read from PCI config space (via aligned dword access).
pub fn cfg_read8(addr: PciAddress, offset: u8) -> u8 {
    let v = cfg_read32(addr, offset & !3);
    ((v >> ((offset & 3) * 8)) & 0xff) as u8
}

/// 16-bit read from PCI config space.
pub fn cfg_read16(addr: PciAddress, offset: u8) -> u16 {
    let v = cfg_read32(addr, offset & !3);
    let shift = (offset & 2) * 8;
    ((v >> shift) & 0xffff) as u16
}

/// Enable memory + bus master in the PCI command register.
pub fn enable_mem_bus_master(addr: PciAddress) {
    let mut cmd = cfg_read32(addr, 0x04);
    cmd |= 0x6; // Memory Space | Bus Master
    cfg_write32(addr, 0x04, cmd);
}

/// Read a 32-bit or 64-bit memory BAR at `bar_index` (0..5).
pub fn read_mem_bar(addr: PciAddress, bar_index: u8) -> Result<(u64, bool), PciError> {
    let off = 0x10 + bar_index * 4;
    let bar = cfg_read32(addr, off);
    if bar == 0 || bar == 0xFFFF_FFFF {
        return Err(PciError::BadBar);
    }
    if (bar & 1) != 0 {
        return Err(PciError::BadBar); // I/O BAR
    }
    let is_64 = ((bar >> 1) & 0b11) == 0b10;
    let mut base = (bar as u64) & !0xF;
    if is_64 {
        let high = cfg_read32(addr, off + 4) as u64;
        base |= high << 32;
    }
    Ok((base, is_64))
}

/// Scan buses 0..7 for vendor/device match.
pub fn find_device(vendor: u16, device: u16) -> Option<PciDevice> {
    for bus in 0u8..8 {
        for dev in 0u8..32 {
            for func in 0u8..8 {
                let addr = PciAddress {
                    bus,
                    device: dev,
                    function: func,
                };
                let (vid, did) = read_vendor_device(addr);
                if vid == 0xFFFF {
                    if func == 0 {
                        break; // no device on this slot
                    }
                    continue;
                }
                if vid == vendor && did == device {
                    let bar0 = read_mem_bar(addr, 0).map(|(b, _)| b).unwrap_or(0);
                    return Some(PciDevice {
                        addr,
                        vendor_id: vid,
                        device_id: did,
                        bar0,
                        bar0_size_hint: 0,
                    });
                }
                // Only multi-function devices use func > 0.
                if func == 0 {
                    let header = (cfg_read32(addr, 0x0C) >> 16) as u8;
                    if header & 0x80 == 0 {
                        break;
                    }
                }
            }
        }
    }
    None
}

pub fn find_virtio_gpu() -> Option<PciDevice> {
    find_device(VENDOR_VIRTIO, DEVICE_VIRTIO_GPU)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_addr_packs_bdf_and_offset() {
        let a = PciAddress {
            bus: 1,
            device: 2,
            function: 3,
        };
        assert_eq!(config_addr(a, 0x10), 0x8001_1310);
    }

    #[test]
    fn host_find_returns_none() {
        assert!(find_virtio_gpu().is_none());
    }
}
