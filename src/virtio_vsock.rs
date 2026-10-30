//! virtio-vsock as the link to the gateway (roadmap 5.2) — the transport
//! Firecracker, Kata Containers, KubeVirt and QEMU's `vhost-vsock-pci`
//! provide, so CDK can run as a micro-VM with its gateway in a sidecar.
//!
//! CDK *listens* on [`LINK_PORT`]; the gateway connects to it from the host
//! (CID 2), as it connects to the virtio-console socket. One connection at a
//! time: a new one replaces the old (the gateway restarted), which is reset.
//! The link layer above is unchanged — the same frames, handshake and sealed
//! channel — so the transport is not trusted any more than the console is.
//!
//! [`Endpoint`] is the stream protocol (virtio spec 5.10: connection
//! requests, credit-based flow control, shutdown and reset) as plain code,
//! tested on the host; `hw` moves packets through the three virtqueues
//! (receive, transmit, event) with page-aligned static rings and buffers,
//! polled like the console driver. Unlike the console, a vsock peer waits
//! for answers (a connection request times out in about two seconds), so
//! [`service`] — called while the console waits for input — answers control
//! packets and buffers stream bytes until the link layer [`poll`]s them.
//! Credit counts only bytes the link layer took, so the buffer never
//! exceeds what CDK advertised.

use spin::Mutex;

/// Modern PCI device id of virtio-vsock (device type 19).
pub const DEVICE_ID: u16 = 0x1053;
/// The vsock port CDK listens on for its gateway ("CD").
pub const LINK_PORT: u32 = 0x4344;
/// The host's context id.
pub const HOST_CID: u64 = 2;
/// Packet header length.
pub const HDR_LEN: usize = 44;
/// Receive space CDK advertises (it consumes data as it arrives).
pub const BUF_ALLOC: u32 = 64 * 1024;

const TYPE_STREAM: u16 = 1;

/// Packet operations.
pub mod op {
    pub const REQUEST: u16 = 1;
    pub const RESPONSE: u16 = 2;
    pub const RST: u16 = 3;
    pub const SHUTDOWN: u16 = 4;
    pub const RW: u16 = 5;
    pub const CREDIT_UPDATE: u16 = 6;
    pub const CREDIT_REQUEST: u16 = 7;
}

/// `struct virtio_vsock_hdr` (little-endian).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    pub len: u32,
    pub typ: u16,
    pub op: u16,
    pub flags: u32,
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
}

impl Header {
    /// The 44-byte wire form.
    pub fn encode(&self) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        b[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        b[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        b[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        b[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..30].copy_from_slice(&self.typ.to_le_bytes());
        b[30..32].copy_from_slice(&self.op.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        b[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        b
    }

    /// The header at the start of `b`, if `b` is long enough.
    pub fn decode(b: &[u8]) -> Option<Header> {
        let b = b.get(..HDR_LEN)?;
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]));
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap_or([0; 4]));
        let u16_at = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap_or([0; 2]));
        Some(Header {
            src_cid: u64_at(0),
            dst_cid: u64_at(8),
            src_port: u32_at(16),
            dst_port: u32_at(20),
            len: u32_at(24),
            typ: u16_at(28),
            op: u16_at(30),
            flags: u32_at(32),
            buf_alloc: u32_at(36),
            fwd_cnt: u32_at(40),
        })
    }
}

/// What to do with a received packet.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Action {
    /// Packets to send back (at most two: a reset of a replaced connection
    /// and the answer).
    pub replies: heapless::Vec<Header, 2>,
    /// Hand the payload to the link layer.
    pub deliver: bool,
}

/// One listening stream endpoint on [`LINK_PORT`] with at most one peer.
#[derive(Debug)]
pub struct Endpoint {
    /// This VM's context id.
    pub cid: u64,
    /// `(cid, port)` of the connected gateway.
    pub peer: Option<(u64, u32)>,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    /// Payload bytes sent to the peer, and consumed from it (wrapping).
    tx_cnt: u32,
    fwd_cnt: u32,
    /// `fwd_cnt` as last told to the peer.
    reported_fwd: u32,
}

impl Endpoint {
    /// A listening endpoint for this VM's context id `cid`.
    pub const fn new(cid: u64) -> Self {
        Endpoint {
            cid,
            peer: None,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
            tx_cnt: 0,
            fwd_cnt: 0,
            reported_fwd: 0,
        }
    }

    /// A header from us to `(cid, port)` carrying our credit.
    fn to(&self, cid: u64, port: u32, op: u16, len: u32) -> Header {
        Header {
            src_cid: self.cid,
            dst_cid: cid,
            src_port: LINK_PORT,
            dst_port: port,
            len,
            typ: TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc: BUF_ALLOC,
            fwd_cnt: self.fwd_cnt,
        }
    }

    /// A reset answering `h`, from the port it was addressed to.
    fn reset_for(&self, h: &Header) -> Header {
        let mut r = self.to(h.src_cid, h.src_port, op::RST, 0);
        r.src_port = h.dst_port;
        r
    }

    /// Process one received packet (`h.len` payload bytes follow it).
    pub fn on_packet(&mut self, h: &Header) -> Action {
        let mut a = Action::default();
        if h.dst_cid != self.cid || h.typ != TYPE_STREAM {
            return a; // not ours; nothing to answer
        }
        if h.op == op::RST {
            if self.peer == Some((h.src_cid, h.src_port)) {
                self.peer = None;
            }
            return a; // never answer a reset
        }
        if h.dst_port != LINK_PORT {
            let _ = a.replies.push(self.reset_for(h));
            return a;
        }
        if h.op == op::REQUEST {
            if let Some((cid, port)) = self.peer.take() {
                let _ = a.replies.push(self.to(cid, port, op::RST, 0));
            }
            self.peer = Some((h.src_cid, h.src_port));
            self.tx_cnt = 0;
            self.fwd_cnt = 0;
            self.reported_fwd = 0;
            self.peer_buf_alloc = h.buf_alloc;
            self.peer_fwd_cnt = h.fwd_cnt;
            let _ = a.replies.push(self.to(h.src_cid, h.src_port, op::RESPONSE, 0));
            return a;
        }
        if self.peer != Some((h.src_cid, h.src_port)) {
            let _ = a.replies.push(self.reset_for(h));
            return a;
        }
        self.peer_buf_alloc = h.buf_alloc;
        self.peer_fwd_cnt = h.fwd_cnt;
        match h.op {
            op::RW => a.deliver = true,
            op::CREDIT_REQUEST => {
                let _ = a.replies.push(self.credit_update());
            }
            op::CREDIT_UPDATE => {}
            op::SHUTDOWN => {
                let _ = a.replies.push(self.to(h.src_cid, h.src_port, op::RST, 0));
                self.peer = None;
            }
            _ => {
                // RESPONSE (CDK never connects) or unknown: reset.
                let _ = a.replies.push(self.to(h.src_cid, h.src_port, op::RST, 0));
                self.peer = None;
            }
        }
        a
    }

    /// The link layer took `n` received bytes (they count as forwarded).
    pub fn consumed(&mut self, n: u32) {
        self.fwd_cnt = self.fwd_cnt.wrapping_add(n);
    }

    /// Bytes the peer can take now.
    pub fn credit(&self) -> u32 {
        self.peer_buf_alloc
            .saturating_sub(self.tx_cnt.wrapping_sub(self.peer_fwd_cnt))
    }

    /// The header for sending `len` payload bytes (counted as sent), if
    /// connected and the peer has room for them.
    pub fn data(&mut self, len: u32) -> Option<Header> {
        let (cid, port) = self.peer?;
        if len > self.credit() {
            return None;
        }
        let h = self.to(cid, port, op::RW, len);
        self.tx_cnt = self.tx_cnt.wrapping_add(len);
        self.reported_fwd = self.fwd_cnt;
        Some(h)
    }

    /// Ask the peer how much room it has.
    pub fn credit_request(&self) -> Option<Header> {
        let (cid, port) = self.peer?;
        Some(self.to(cid, port, op::CREDIT_REQUEST, 0))
    }

    /// Tell the peer how much we consumed.
    pub fn credit_update(&mut self) -> Header {
        let (cid, port) = self.peer.unwrap_or((HOST_CID, 0));
        self.reported_fwd = self.fwd_cnt;
        self.to(cid, port, op::CREDIT_UPDATE, 0)
    }

    /// Whether enough was consumed since we last said so that the peer may
    /// be waiting for room.
    pub fn credit_update_due(&self) -> bool {
        self.peer.is_some() && self.fwd_cnt.wrapping_sub(self.reported_fwd) >= BUF_ALLOC / 2
    }
}

/// Link statistics.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_timeouts: u64,
    pub connections: u64,
}

#[cfg(target_os = "none")]
static DEVICE: Mutex<Option<hw::Device>> = Mutex::new(None);
#[cfg(not(target_os = "none"))]
static DEVICE: Mutex<Option<()>> = Mutex::new(None);

/// Whether the vsock device was found and initialized.
pub fn is_ready() -> bool {
    DEVICE.lock().is_some()
}

/// This VM's context id, once the device is up.
pub fn guest_cid() -> Option<u64> {
    #[cfg(target_os = "none")]
    {
        DEVICE.lock().as_ref().map(|d| d.ep.cid)
    }
    #[cfg(not(target_os = "none"))]
    {
        None
    }
}

/// Whether a gateway is connected.
pub fn connected() -> bool {
    #[cfg(target_os = "none")]
    {
        DEVICE.lock().as_ref().is_some_and(|d| d.ep.peer.is_some())
    }
    #[cfg(not(target_os = "none"))]
    {
        false
    }
}

/// Transfer and connection counters.
pub fn stats() -> Stats {
    #[cfg(target_os = "none")]
    {
        DEVICE.lock().as_ref().map(|d| d.stats).unwrap_or_default()
    }
    #[cfg(not(target_os = "none"))]
    {
        Stats::default()
    }
}

/// Find, map, and initialize the virtio-vsock device.
pub fn init(
    page_table: &mut crate::paging::PageTableManager,
    frame_alloc: &mut crate::allocator::FrameAllocator,
) -> Result<u64, &'static str> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (page_table, frame_alloc);
        Err("virtio-vsock: host stub")
    }
    #[cfg(target_os = "none")]
    {
        let dev = hw::probe(page_table, frame_alloc)?;
        let cid = dev.ep.cid;
        *DEVICE.lock() = Some(dev);
        Ok(cid)
    }
}

/// Send all of `bytes` to the connected gateway (blocks while it has no
/// room, up to a timeout).
pub fn write_all(bytes: &[u8]) -> Result<(), &'static str> {
    #[cfg(target_os = "none")]
    {
        let mut guard = DEVICE.lock();
        let dev = guard.as_mut().ok_or("link not ready")?;
        unsafe { hw::write_all(dev, bytes) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = bytes;
        Err("virtio-vsock: host stub")
    }
}

/// Answer pending control packets (connection requests above all) and
/// buffer stream bytes; non-blocking. Called while the console is idle.
pub fn service() {
    #[cfg(target_os = "none")]
    if let Some(mut guard) = DEVICE.try_lock() {
        if let Some(dev) = guard.as_mut() {
            unsafe { hw::receive(dev) };
        }
    }
}

/// Hand every received stream byte to `sink`; returns how many arrived.
/// Non-blocking.
pub fn poll(mut sink: impl FnMut(&[u8])) -> usize {
    #[cfg(target_os = "none")]
    {
        let mut guard = DEVICE.lock();
        let Some(dev) = guard.as_mut() else {
            return 0;
        };
        unsafe { hw::poll(dev, &mut sink) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = &mut sink;
        0
    }
}

#[cfg(target_os = "none")]
mod hw {
    extern crate alloc;

    use super::*;
    use crate::pci;
    use crate::virtio_pci::{self, mmio::*, *};

    const QSIZE: usize = 8;
    const RX_BUFS: usize = 4;
    const RX_BUF_LEN: usize = 1024;
    const DESC_OFF: usize = 0;
    const AVAIL_OFF: usize = 512;
    const USED_OFF: usize = 2048;
    /// The event queue's one buffer, inside its ring page.
    const EVT_BUF_OFF: usize = 3072;
    const DESC_F_WRITE: u16 = 2;
    const RX_QUEUE: u16 = 0;
    const TX_QUEUE: u16 = 1;
    const EVT_QUEUE: u16 = 2;
    /// Largest payload in one transmitted packet (one page with its header).
    const MAX_TX_PAYLOAD: usize = 4096 - HDR_LEN;
    /// TSC cycles to wait for the device or for credit (~2 GHz: coarse).
    const TIMEOUT_CYCLES: u64 = 4_000_000_000;

    #[repr(C, align(4096))]
    struct Page([u8; 4096]);

    static mut RX_RING: Page = Page([0; 4096]);
    static mut TX_RING: Page = Page([0; 4096]);
    static mut EVT_RING: Page = Page([0; 4096]);
    static mut RX_BUF: Page = Page([0; 4096]);
    static mut TX_BUF: Page = Page([0; 4096]);

    pub struct Device {
        pub ep: Endpoint,
        pub stats: Stats,
        notify: u64,
        notify_mult: u32,
        notify_off: [u16; 3],
        rx_ring_phys: u64,
        tx_ring_phys: u64,
        evt_ring_phys: u64,
        rx_buf_phys: u64,
        tx_buf_phys: u64,
        rx_avail_idx: u16,
        rx_last_used: u16,
        tx_avail_idx: u16,
        tx_last_used: u16,
        evt_avail_idx: u16,
        evt_last_used: u16,
        /// Stream bytes received but not yet taken by the link layer (at
        /// most [`BUF_ALLOC`], which is all the credit the peer gets).
        pending: alloc::vec::Vec<u8>,
    }

    /// The ring page of queue `q`.
    unsafe fn ring(q: u16) -> *mut u8 {
        match q {
            RX_QUEUE => (&raw mut RX_RING) as *mut u8,
            TX_QUEUE => (&raw mut TX_RING) as *mut u8,
            _ => (&raw mut EVT_RING) as *mut u8,
        }
    }

    /// Physical address of a kernel virtual address.
    fn phys_of(pt: &crate::paging::PageTableManager, virt: u64) -> Result<u64, &'static str> {
        pt.translate(virt)
            .map(|page| page | (virt & 0xfff))
            .map_err(|_| "virtio-vsock: buffer not mapped")
    }

    /// Fill descriptor `i` of `ring`.
    unsafe fn write_desc(ring: *mut u8, i: usize, addr: u64, len: u32, flags: u16) {
        let d = ring.add(DESC_OFF + i * 16);
        core::ptr::write_volatile(d as *mut u64, addr);
        core::ptr::write_volatile(d.add(8) as *mut u32, len);
        core::ptr::write_volatile(d.add(12) as *mut u16, flags);
        core::ptr::write_volatile(d.add(14) as *mut u16, 0);
    }

    /// Offer descriptor `desc` to the device.
    unsafe fn avail_push(ring: *mut u8, idx: &mut u16, desc: u16) {
        let slot = (*idx as usize) % QSIZE;
        core::ptr::write_volatile(ring.add(AVAIL_OFF + 4 + slot * 2) as *mut u16, desc);
        *idx = idx.wrapping_add(1);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(ring.add(AVAIL_OFF + 2) as *mut u16, *idx);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// How many buffers the device has used so far.
    unsafe fn used_idx(ring: *const u8) -> u16 {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::read_volatile(ring.add(USED_OFF + 2) as *const u16)
    }

    /// `(descriptor, length)` of used element `i`.
    unsafe fn used_elem(ring: *const u8, i: u16) -> (u32, u32) {
        let e = ring.add(USED_OFF + 4 + (i as usize % QSIZE) * 8);
        (
            core::ptr::read_volatile(e as *const u32),
            core::ptr::read_volatile(e.add(4) as *const u32),
        )
    }

    /// Tell the device that `queue` has new buffers.
    unsafe fn notify(dev: &Device, queue: u16) {
        let off = dev.notify_off[queue as usize];
        write16(dev.notify, off as u64 * dev.notify_mult as u64, queue);
    }

    /// Configure and enable `queue`; returns its notify offset.
    unsafe fn setup_queue(common: u64, queue: u16, ring_phys: u64) -> Result<u16, &'static str> {
        write16(common, COMMON_QUEUE_SELECT, queue);
        let max = read16(common, COMMON_QUEUE_SIZE);
        if (max as usize) < QSIZE {
            return Err("virtio-vsock: queue too small");
        }
        write16(common, COMMON_QUEUE_SIZE, QSIZE as u16);
        write64(common, COMMON_QUEUE_DESC, ring_phys + DESC_OFF as u64);
        write64(common, COMMON_QUEUE_DRIVER, ring_phys + AVAIL_OFF as u64);
        write64(common, COMMON_QUEUE_DEVICE, ring_phys + USED_OFF as u64);
        let off = read16(common, COMMON_QUEUE_NOTIFY_OFF);
        write16(common, COMMON_QUEUE_ENABLE, 1);
        Ok(off)
    }

    /// Find the device on PCI, negotiate features, read the CID, set up
    /// the three queues and post the receive buffers.
    pub fn probe(
        pt: &mut crate::paging::PageTableManager,
        fa: &mut crate::allocator::FrameAllocator,
    ) -> Result<Device, &'static str> {
        let dev = pci::find_device(pci::VENDOR_VIRTIO, DEVICE_ID).ok_or("no virtio-vsock device")?;
        pci::enable_mem_bus_master(dev.addr);
        let bars = virtio_pci::read_all_bars(dev.addr);
        let caps = virtio_pci::discover_modern(dev.addr).map_err(|_| "virtio-vsock: modern caps missing")?;
        let device_cap = caps.device.ok_or("virtio-vsock: no device config")?;
        for cap in [Some(caps.common), Some(caps.notify), caps.isr, caps.device]
            .into_iter()
            .flatten()
        {
            let base = virtio_pci::cap_mmio(&cap, &bars).map_err(|_| "virtio-vsock: bad BAR")?;
            virtio_pci::map_cap_window(pt, fa, base, cap.length);
        }
        let common = virtio_pci::cap_mmio(&caps.common, &bars).map_err(|_| "common")?;
        let notify_base = virtio_pci::cap_mmio(&caps.notify, &bars).map_err(|_| "notify")?;
        let device_cfg = virtio_pci::cap_mmio(&device_cap, &bars).map_err(|_| "device config")?;

        let mut d = unsafe {
            Device {
                ep: Endpoint::new(0),
                stats: Stats::default(),
                notify: notify_base,
                notify_mult: caps.notify.notify_off_multiplier,
                notify_off: [0; 3],
                rx_ring_phys: phys_of(pt, ring(RX_QUEUE) as u64)?,
                tx_ring_phys: phys_of(pt, ring(TX_QUEUE) as u64)?,
                evt_ring_phys: phys_of(pt, ring(EVT_QUEUE) as u64)?,
                rx_buf_phys: phys_of(pt, (&raw mut RX_BUF) as u64)?,
                tx_buf_phys: phys_of(pt, (&raw mut TX_BUF) as u64)?,
                rx_avail_idx: 0,
                rx_last_used: 0,
                tx_avail_idx: 0,
                tx_last_used: 0,
                evt_avail_idx: 0,
                evt_last_used: 0,
                pending: alloc::vec::Vec::new(),
            }
        };
        unsafe {
            for q in [RX_QUEUE, TX_QUEUE, EVT_QUEUE] {
                core::ptr::write_bytes(ring(q), 0, 4096);
            }
            write8(common, COMMON_DEVICE_STATUS, 0);
            write8(common, COMMON_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
            write32(common, COMMON_DEVICE_FEATURE_SELECT, 1);
            if read32(common, COMMON_DEVICE_FEATURE) & 1 == 0 {
                write8(common, COMMON_DEVICE_STATUS, STATUS_FAILED);
                return Err("virtio-vsock: no VIRTIO_F_VERSION_1");
            }
            // VERSION_1 only: stream sockets, no seqpacket.
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
                return Err("virtio-vsock: FEATURES_OK rejected");
            }
            let lo = read32(device_cfg, 0) as u64;
            let hi = read32(device_cfg, 4) as u64;
            d.ep = Endpoint::new(lo | (hi << 32));
            d.notify_off[0] = setup_queue(common, RX_QUEUE, d.rx_ring_phys)?;
            d.notify_off[1] = setup_queue(common, TX_QUEUE, d.tx_ring_phys)?;
            d.notify_off[2] = setup_queue(common, EVT_QUEUE, d.evt_ring_phys)?;
            write8(
                common,
                COMMON_DEVICE_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
            );
            for i in 0..RX_BUFS {
                post_rx(&mut d, i);
            }
            notify(&d, RX_QUEUE);
            post_evt(&mut d);
            notify(&d, EVT_QUEUE);
        }
        Ok(d)
    }

    /// Give receive buffer `i` to the device.
    unsafe fn post_rx(d: &mut Device, i: usize) {
        let addr = d.rx_buf_phys + (i * RX_BUF_LEN) as u64;
        write_desc(ring(RX_QUEUE), i, addr, RX_BUF_LEN as u32, DESC_F_WRITE);
        avail_push(ring(RX_QUEUE), &mut d.rx_avail_idx, i as u16);
    }

    /// Give the event buffer to the device.
    unsafe fn post_evt(d: &mut Device) {
        let addr = d.evt_ring_phys + EVT_BUF_OFF as u64;
        write_desc(ring(EVT_QUEUE), 0, addr, 4, DESC_F_WRITE);
        avail_push(ring(EVT_QUEUE), &mut d.evt_avail_idx, 0);
    }

    /// Send one packet and wait until the device has taken it.
    unsafe fn transmit(d: &mut Device, h: &Header, payload: &[u8]) -> Result<(), &'static str> {
        let buf = (&raw mut TX_BUF) as *mut u8;
        core::ptr::copy_nonoverlapping(h.encode().as_ptr(), buf, HDR_LEN);
        core::ptr::copy_nonoverlapping(payload.as_ptr(), buf.add(HDR_LEN), payload.len());
        write_desc(ring(TX_QUEUE), 0, d.tx_buf_phys, (HDR_LEN + payload.len()) as u32, 0);
        avail_push(ring(TX_QUEUE), &mut d.tx_avail_idx, 0);
        notify(d, TX_QUEUE);
        let start = crate::cpu::rdtsc();
        while used_idx(ring(TX_QUEUE)) == d.tx_last_used {
            if crate::cpu::rdtsc().wrapping_sub(start) > TIMEOUT_CYCLES {
                d.stats.tx_timeouts += 1;
                return Err("virtio-vsock: transmit timeout");
            }
            core::hint::spin_loop();
        }
        d.tx_last_used = used_idx(ring(TX_QUEUE));
        Ok(())
    }

    /// Process received packets: answer control packets and buffer stream
    /// bytes in `pending`. Returns the payload bytes buffered.
    pub unsafe fn receive(d: &mut Device) -> usize {
        // A transport reset (e.g. after migration) drops every connection.
        let mut evt = false;
        while used_idx(ring(EVT_QUEUE)) != d.evt_last_used {
            d.evt_last_used = d.evt_last_used.wrapping_add(1);
            evt = true;
        }
        if evt {
            d.ep.peer = None;
            post_evt(d);
            notify(d, EVT_QUEUE);
        }
        let rx_buf = (&raw mut RX_BUF) as *const u8;
        let mut total = 0;
        let mut reposted = false;
        while used_idx(ring(RX_QUEUE)) != d.rx_last_used {
            let (id, len) = used_elem(ring(RX_QUEUE), d.rx_last_used);
            d.rx_last_used = d.rx_last_used.wrapping_add(1);
            let id = id as usize;
            if id >= RX_BUFS {
                continue;
            }
            let len = (len as usize).min(RX_BUF_LEN);
            let packet = core::slice::from_raw_parts(rx_buf.add(id * RX_BUF_LEN), len);
            if let Some(h) = Header::decode(packet) {
                let before = d.ep.peer;
                let action = d.ep.on_packet(&h);
                if d.ep.peer.is_some() && d.ep.peer != before {
                    // A new gateway: what the old one sent is void.
                    d.stats.connections += 1;
                    d.pending.clear();
                }
                if action.deliver {
                    let payload = &packet[HDR_LEN..(HDR_LEN + h.len as usize).min(len)];
                    if d.pending.len() + payload.len() <= BUF_ALLOC as usize {
                        d.pending.extend_from_slice(payload);
                        total += payload.len();
                    }
                }
                for r in action.replies.iter() {
                    let _ = transmit(d, r, &[]);
                }
            }
            post_rx(d, id);
            reposted = true;
        }
        if reposted {
            notify(d, RX_QUEUE);
        }
        d.stats.rx_bytes += total as u64;
        total
    }

    /// Hand buffered stream bytes to the link layer, and tell the peer
    /// once enough room has opened up.
    pub unsafe fn poll(d: &mut Device, sink: &mut dyn FnMut(&[u8])) -> usize {
        receive(d);
        let held = core::mem::take(&mut d.pending);
        if !held.is_empty() {
            sink(&held);
            d.ep.consumed(held.len() as u32);
        }
        if d.ep.credit_update_due() {
            let h = d.ep.credit_update();
            let _ = transmit(d, &h, &[]);
        }
        held.len()
    }

    /// Send `bytes` as stream packets within the peer's credit.
    pub unsafe fn write_all(d: &mut Device, mut bytes: &[u8]) -> Result<(), &'static str> {
        if d.ep.peer.is_none() {
            // Take a pending connection request first.
            receive(d);
            if d.ep.peer.is_none() {
                return Err("no gateway connected over vsock");
            }
        }
        let start = crate::cpu::rdtsc();
        let mut asked = false;
        while !bytes.is_empty() {
            let n = bytes.len().min(MAX_TX_PAYLOAD).min(d.ep.credit() as usize);
            if n == 0 {
                // No room at the gateway: ask once, then wait for its credit
                // (keeping any stream bytes for the next poll).
                if crate::cpu::rdtsc().wrapping_sub(start) > TIMEOUT_CYCLES {
                    d.stats.tx_timeouts += 1;
                    return Err("virtio-vsock: the gateway gives no credit");
                }
                if !asked {
                    if let Some(h) = d.ep.credit_request() {
                        transmit(d, &h, &[])?;
                    }
                    asked = true;
                }
                receive(d);
                if d.ep.peer.is_none() {
                    return Err("the gateway disconnected");
                }
                core::hint::spin_loop();
                continue;
            }
            let h = d.ep.data(n as u32).ok_or("the gateway disconnected")?;
            transmit(d, &h, &bytes[..n])?;
            d.stats.tx_bytes += n as u64;
            bytes = &bytes[n..];
            asked = false;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: u64 = 3;

    /// A packet from the host's `port` to CDK's link port.
    fn from_host(op: u16, port: u32, len: u32, buf_alloc: u32, fwd_cnt: u32) -> Header {
        Header {
            src_cid: HOST_CID,
            dst_cid: ME,
            src_port: port,
            dst_port: LINK_PORT,
            len,
            typ: TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc,
            fwd_cnt,
        }
    }

    /// Headers round-trip in the 44-byte little-endian layout.
    #[test]
    fn header_layout() {
        let h = from_host(op::RW, 1234, 5, 65536, 7);
        let b = h.encode();
        assert_eq!(b.len(), 44);
        assert_eq!(&b[0..8], &2u64.to_le_bytes());
        assert_eq!(&b[30..32], &op::RW.to_le_bytes());
        assert_eq!(Header::decode(&b), Some(h));
        assert!(Header::decode(&b[..43]).is_none());
    }

    /// A request to the link port is accepted; data flows with credit;
    /// shutdown resets the connection.
    #[test]
    fn connect_exchange_shutdown() {
        let mut ep = Endpoint::new(ME);
        let a = ep.on_packet(&from_host(op::REQUEST, 9000, 0, 1000, 0));
        assert_eq!(a.replies.len(), 1);
        let r = a.replies[0];
        assert_eq!((r.op, r.dst_cid, r.dst_port, r.src_port), (op::RESPONSE, HOST_CID, 9000, LINK_PORT));
        assert_eq!(r.buf_alloc, BUF_ALLOC);
        assert_eq!(ep.peer, Some((HOST_CID, 9000)));

        // Inbound data is delivered; it counts once the link layer took it.
        let a = ep.on_packet(&from_host(op::RW, 9000, 100, 1000, 0));
        assert!(a.deliver && a.replies.is_empty());
        ep.consumed(100);

        // Outbound data is limited by the peer's credit.
        assert_eq!(ep.credit(), 1000);
        let h = ep.data(600).unwrap();
        assert_eq!((h.op, h.len, h.fwd_cnt), (op::RW, 600, 100));
        assert_eq!(ep.credit(), 400);
        assert!(ep.data(401).is_none(), "beyond the peer's room");
        ep.on_packet(&from_host(op::CREDIT_UPDATE, 9000, 0, 1000, 600));
        assert_eq!(ep.credit(), 1000);

        // A credit request is answered with our consumption.
        let a = ep.on_packet(&from_host(op::CREDIT_REQUEST, 9000, 0, 1000, 600));
        assert_eq!((a.replies[0].op, a.replies[0].fwd_cnt), (op::CREDIT_UPDATE, 100));

        let a = ep.on_packet(&from_host(op::SHUTDOWN, 9000, 0, 1000, 600));
        assert_eq!(a.replies[0].op, op::RST);
        assert_eq!(ep.peer, None);
        assert!(ep.data(1).is_none(), "not connected");
    }

    /// Wrong port, strangers and stray responses are reset; resets are
    /// never answered; packets for another CID are ignored.
    #[test]
    fn strangers_are_reset() {
        let mut ep = Endpoint::new(ME);
        let mut wrong = from_host(op::REQUEST, 9000, 0, 1000, 0);
        wrong.dst_port = 22;
        let a = ep.on_packet(&wrong);
        assert_eq!((a.replies[0].op, a.replies[0].src_port), (op::RST, 22));
        assert_eq!(ep.peer, None);

        ep.on_packet(&from_host(op::REQUEST, 9000, 0, 1000, 0));
        let a = ep.on_packet(&from_host(op::RW, 9001, 10, 1000, 0));
        assert!(!a.deliver, "data from another connection");
        assert_eq!(a.replies[0].op, op::RST);
        assert_eq!(ep.peer, Some((HOST_CID, 9000)), "the gateway stays connected");

        assert!(ep.on_packet(&from_host(op::RST, 9001, 0, 0, 0)).replies.is_empty());
        let mut other = from_host(op::RW, 9000, 10, 1000, 0);
        other.dst_cid = 99;
        assert_eq!(ep.on_packet(&other), Action::default());

        let a = ep.on_packet(&from_host(op::RST, 9000, 0, 0, 0));
        assert!(a.replies.is_empty());
        assert_eq!(ep.peer, None);
    }

    /// A new connection replaces the old one, which is reset, and starts
    /// with fresh counters.
    #[test]
    fn reconnect_replaces_and_resets() {
        let mut ep = Endpoint::new(ME);
        ep.on_packet(&from_host(op::REQUEST, 9000, 0, 1000, 0));
        ep.on_packet(&from_host(op::RW, 9000, 50, 1000, 0));
        ep.consumed(50);
        let _ = ep.data(300);
        let a = ep.on_packet(&from_host(op::REQUEST, 9100, 0, 2000, 0));
        assert_eq!(a.replies.len(), 2);
        assert_eq!((a.replies[0].op, a.replies[0].dst_port), (op::RST, 9000));
        assert_eq!((a.replies[1].op, a.replies[1].dst_port), (op::RESPONSE, 9100));
        assert_eq!(a.replies[1].fwd_cnt, 0, "fresh counters");
        assert_eq!(ep.credit(), 2000);
    }

    /// Consumption is reported once half the advertised space was used.
    #[test]
    fn credit_updates_when_half_consumed() {
        let mut ep = Endpoint::new(ME);
        ep.on_packet(&from_host(op::REQUEST, 9000, 0, 1000, 0));
        ep.on_packet(&from_host(op::RW, 9000, BUF_ALLOC / 2, 1000, 0));
        assert!(!ep.credit_update_due(), "received is not yet consumed");
        ep.consumed(BUF_ALLOC / 2 - 1);
        assert!(!ep.credit_update_due());
        ep.consumed(1);
        assert!(ep.credit_update_due());
        let h = ep.credit_update();
        assert_eq!(h.fwd_cnt, BUF_ALLOC / 2);
        assert!(!ep.credit_update_due());
    }
}
