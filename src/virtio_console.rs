//! virtio-console (port 0) as a byte-stream link to the host (roadmap 3.1).
//!
//! QEMU exposes it with `-device virtio-serial-pci -device virtconsole,
//! chardev=…` backed by a host Unix socket, so no host privileges are needed
//! (unlike vhost-vsock). The driver negotiates only `VIRTIO_F_VERSION_1` —
//! no multiport — so port 0 uses queue 0 (receive) and queue 1 (transmit).
//!
//! All rings and buffers live in page-aligned statics, each fitting inside a
//! single page, so one page-table lookup gives a valid physical address for
//! the device (kernel statics are not guaranteed physically contiguous
//! across pages). The driver polls; it takes no interrupts.

use spin::Mutex;

/// Transitional and modern PCI device ids for virtio-console.
pub const DEVICE_IDS: [u16; 2] = [0x1003, 0x1043];

const QSIZE: usize = 8;
const RX_BUFS: usize = 4;
const RX_BUF_LEN: usize = 1024;
const DESC_OFF: usize = 0;
const AVAIL_OFF: usize = 512;
const USED_OFF: usize = 2048;
const DESC_F_WRITE: u16 = 2;
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

#[repr(C, align(4096))]
struct Page([u8; 4096]);

static mut RX_RING: Page = Page([0; 4096]);
static mut TX_RING: Page = Page([0; 4096]);
static mut RX_BUF: Page = Page([0; 4096]);
static mut TX_BUF: Page = Page([0; 4096]);

/// Link statistics.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_timeouts: u64,
}

struct Device {
    notify: u64,
    notify_mult: u32,
    rx_notify_off: u16,
    tx_notify_off: u16,
    rx_ring_phys: u64,
    tx_ring_phys: u64,
    rx_buf_phys: u64,
    tx_buf_phys: u64,
    rx_avail_idx: u16,
    rx_last_used: u16,
    tx_avail_idx: u16,
    tx_last_used: u16,
    stats: Stats,
}

static DEVICE: Mutex<Option<Device>> = Mutex::new(None);

/// Whether the link device was found and initialized.
pub fn is_ready() -> bool {
    DEVICE.lock().is_some()
}

pub fn stats() -> Stats {
    DEVICE.lock().as_ref().map(|d| d.stats).unwrap_or_default()
}

/// Find, map, and initialize the virtio-console device.
pub fn init(
    page_table: &mut crate::paging::PageTableManager,
    frame_alloc: &mut crate::allocator::FrameAllocator,
) -> Result<(), &'static str> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (page_table, frame_alloc);
        Err("virtio-console: host stub")
    }
    #[cfg(target_os = "none")]
    {
        let dev = hw::probe(page_table, frame_alloc)?;
        *DEVICE.lock() = Some(dev);
        Ok(())
    }
}

/// Send all of `bytes` (blocks until the device consumed each chunk).
pub fn write_all(bytes: &[u8]) -> Result<(), &'static str> {
    let mut guard = DEVICE.lock();
    let dev = guard.as_mut().ok_or("link not ready")?;
    #[cfg(target_os = "none")]
    {
        for chunk in bytes.chunks(4096) {
            unsafe { hw::transmit(dev, chunk)? };
        }
        Ok(())
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (dev, bytes);
        Err("virtio-console: host stub")
    }
}

/// Hand every received byte to `sink`; returns how many bytes arrived.
/// Non-blocking.
pub fn poll(mut sink: impl FnMut(&[u8])) -> usize {
    let mut guard = DEVICE.lock();
    let Some(dev) = guard.as_mut() else {
        return 0;
    };
    #[cfg(target_os = "none")]
    unsafe {
        hw::receive(dev, &mut sink)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (dev, &mut sink);
        0
    }
}

#[cfg(target_os = "none")]
mod hw {
    use super::*;
    use crate::pci;
    use crate::virtio_pci::{self, mmio::*, *};

    unsafe fn page_ptr(p: *mut Page) -> *mut u8 {
        p as *mut u8
    }

    fn phys_of(pt: &crate::paging::PageTableManager, virt: u64) -> Result<u64, &'static str> {
        pt.translate(virt)
            .map(|page| page | (virt & 0xfff))
            .map_err(|_| "virtio-console: buffer not mapped")
    }

    unsafe fn write_desc(ring: *mut u8, i: usize, addr: u64, len: u32, flags: u16) {
        let d = ring.add(DESC_OFF + i * 16);
        core::ptr::write_volatile(d as *mut u64, addr);
        core::ptr::write_volatile(d.add(8) as *mut u32, len);
        core::ptr::write_volatile(d.add(12) as *mut u16, flags);
        core::ptr::write_volatile(d.add(14) as *mut u16, 0);
    }

    unsafe fn avail_push(ring: *mut u8, idx: &mut u16, desc: u16) {
        let slot = (*idx as usize) % QSIZE;
        core::ptr::write_volatile(ring.add(AVAIL_OFF + 4 + slot * 2) as *mut u16, desc);
        *idx = idx.wrapping_add(1);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(ring.add(AVAIL_OFF + 2) as *mut u16, *idx);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }

    unsafe fn used_idx(ring: *const u8) -> u16 {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::read_volatile(ring.add(USED_OFF + 2) as *const u16)
    }

    unsafe fn used_elem(ring: *const u8, i: u16) -> (u32, u32) {
        let e = ring.add(USED_OFF + 4 + (i as usize % QSIZE) * 8);
        (
            core::ptr::read_volatile(e as *const u32),
            core::ptr::read_volatile(e.add(4) as *const u32),
        )
    }

    unsafe fn notify(dev: &Device, queue: u16, off: u16) {
        write16(dev.notify, off as u64 * dev.notify_mult as u64, queue);
    }

    unsafe fn setup_queue(common: u64, queue: u16, ring_phys: u64) -> Result<u16, &'static str> {
        write16(common, COMMON_QUEUE_SELECT, queue);
        let max = read16(common, COMMON_QUEUE_SIZE);
        if (max as usize) < QSIZE {
            return Err("virtio-console: queue too small");
        }
        write16(common, COMMON_QUEUE_SIZE, QSIZE as u16);
        write64(common, COMMON_QUEUE_DESC, ring_phys + DESC_OFF as u64);
        write64(common, COMMON_QUEUE_DRIVER, ring_phys + AVAIL_OFF as u64);
        write64(common, COMMON_QUEUE_DEVICE, ring_phys + USED_OFF as u64);
        let off = read16(common, COMMON_QUEUE_NOTIFY_OFF);
        write16(common, COMMON_QUEUE_ENABLE, 1);
        Ok(off)
    }

    pub fn probe(
        pt: &mut crate::paging::PageTableManager,
        fa: &mut crate::allocator::FrameAllocator,
    ) -> Result<Device, &'static str> {
        let dev = DEVICE_IDS
            .iter()
            .find_map(|&id| pci::find_device(pci::VENDOR_VIRTIO, id))
            .ok_or("no virtio-console device")?;
        pci::enable_mem_bus_master(dev.addr);
        let bars = virtio_pci::read_all_bars(dev.addr);
        let caps = virtio_pci::discover_modern(dev.addr)
            .map_err(|_| "virtio-console: modern caps missing")?;
        for cap in [Some(caps.common), Some(caps.notify), caps.isr, caps.device]
            .into_iter()
            .flatten()
        {
            let base = virtio_pci::cap_mmio(&cap, &bars).map_err(|_| "virtio-console: bad BAR")?;
            virtio_pci::map_cap_window(pt, fa, base, cap.length);
        }
        let common = virtio_pci::cap_mmio(&caps.common, &bars).map_err(|_| "common")?;
        let notify_base = virtio_pci::cap_mmio(&caps.notify, &bars).map_err(|_| "notify")?;

        let (rx_ring, tx_ring, rx_buf, tx_buf) = unsafe {
            (
                page_ptr(&raw mut RX_RING),
                page_ptr(&raw mut TX_RING),
                page_ptr(&raw mut RX_BUF),
                page_ptr(&raw mut TX_BUF),
            )
        };
        let mut d = Device {
            notify: notify_base,
            notify_mult: caps.notify.notify_off_multiplier,
            rx_notify_off: 0,
            tx_notify_off: 0,
            rx_ring_phys: phys_of(pt, rx_ring as u64)?,
            tx_ring_phys: phys_of(pt, tx_ring as u64)?,
            rx_buf_phys: phys_of(pt, rx_buf as u64)?,
            tx_buf_phys: phys_of(pt, tx_buf as u64)?,
            rx_avail_idx: 0,
            rx_last_used: 0,
            tx_avail_idx: 0,
            tx_last_used: 0,
            stats: Stats::default(),
        };
        unsafe {
            core::ptr::write_bytes(rx_ring, 0, 4096);
            core::ptr::write_bytes(tx_ring, 0, 4096);
            write8(common, COMMON_DEVICE_STATUS, 0);
            write8(
                common,
                COMMON_DEVICE_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER,
            );
            write32(common, COMMON_DEVICE_FEATURE_SELECT, 1);
            if read32(common, COMMON_DEVICE_FEATURE) & 1 == 0 {
                write8(common, COMMON_DEVICE_STATUS, STATUS_FAILED);
                return Err("virtio-console: no VIRTIO_F_VERSION_1");
            }
            // Accept VERSION_1 only: no multiport, so port 0 = queues 0/1.
            write32(common, COMMON_DRIVER_FEATURE_SELECT, 0);
            write32(common, COMMON_DRIVER_FEATURE, 0);
            write32(common, COMMON_DRIVER_FEATURE_SELECT, 1);
            write32(common, COMMON_DRIVER_FEATURE, 1);
            write8(
                common,
                COMMON_DEVICE_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
            );
            if read8(common, COMMON_DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
                return Err("virtio-console: FEATURES_OK rejected");
            }
            d.rx_notify_off = setup_queue(common, RX_QUEUE, d.rx_ring_phys)?;
            d.tx_notify_off = setup_queue(common, TX_QUEUE, d.tx_ring_phys)?;
            write8(
                common,
                COMMON_DEVICE_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
            );
            // Post every receive buffer (device-writable).
            for i in 0..RX_BUFS {
                let addr = d.rx_buf_phys + (i * RX_BUF_LEN) as u64;
                write_desc(rx_ring, i, addr, RX_BUF_LEN as u32, DESC_F_WRITE);
                avail_push(rx_ring, &mut d.rx_avail_idx, i as u16);
            }
            notify(&d, RX_QUEUE, d.rx_notify_off);
        }
        Ok(d)
    }

    /// TSC cycles to wait for the device (~2 GHz assumed: coarse on purpose).
    const TX_TIMEOUT_CYCLES: u64 = 2_000_000_000;

    pub unsafe fn transmit(dev: &mut Device, chunk: &[u8]) -> Result<(), &'static str> {
        let tx_ring = page_ptr(&raw mut TX_RING);
        let tx_buf = page_ptr(&raw mut TX_BUF);
        core::ptr::copy_nonoverlapping(chunk.as_ptr(), tx_buf, chunk.len());
        write_desc(tx_ring, 0, dev.tx_buf_phys, chunk.len() as u32, 0);
        avail_push(tx_ring, &mut dev.tx_avail_idx, 0);
        notify(dev, TX_QUEUE, dev.tx_notify_off);
        let start = crate::cpu::rdtsc();
        while used_idx(tx_ring) == dev.tx_last_used {
            if crate::cpu::rdtsc().wrapping_sub(start) > TX_TIMEOUT_CYCLES {
                dev.stats.tx_timeouts += 1;
                return Err("virtio-console: transmit timeout (host not reading?)");
            }
            core::hint::spin_loop();
        }
        dev.tx_last_used = used_idx(tx_ring);
        dev.stats.tx_bytes += chunk.len() as u64;
        Ok(())
    }

    pub unsafe fn receive(dev: &mut Device, sink: &mut impl FnMut(&[u8])) -> usize {
        let rx_ring = page_ptr(&raw mut RX_RING);
        let rx_buf = page_ptr(&raw mut RX_BUF);
        let mut total = 0;
        let mut reposted = false;
        while used_idx(rx_ring) != dev.rx_last_used {
            let (id, len) = used_elem(rx_ring, dev.rx_last_used);
            dev.rx_last_used = dev.rx_last_used.wrapping_add(1);
            let id = id as usize;
            if id >= RX_BUFS {
                continue;
            }
            let len = (len as usize).min(RX_BUF_LEN);
            let data = core::slice::from_raw_parts(rx_buf.add(id * RX_BUF_LEN), len);
            sink(data);
            total += len;
            // Give the buffer back to the device.
            let addr = dev.rx_buf_phys + (id * RX_BUF_LEN) as u64;
            write_desc(rx_ring, id, addr, RX_BUF_LEN as u32, DESC_F_WRITE);
            avail_push(rx_ring, &mut dev.rx_avail_idx, id as u16);
            reposted = true;
        }
        if reposted {
            notify(dev, RX_QUEUE, dev.rx_notify_off);
        }
        dev.stats.rx_bytes += total as u64;
        total
    }
}
