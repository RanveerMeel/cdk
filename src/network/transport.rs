use heapless::Deque;

use super::{ExternalBackendKind, NetPacket, MAX_QUEUE_DEPTH};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct BackendPollResult {
    pub(super) rx_received: u64,
    pub(super) rx_dropped: u64,
}

trait ExternalTransportAdapter {
    fn poll(
        &mut self,
        tx_queue: &mut Deque<NetPacket, MAX_QUEUE_DEPTH>,
        rx_queue: &mut Deque<NetPacket, MAX_QUEUE_DEPTH>,
    ) -> BackendPollResult;
}

/// Descriptor-ring-facing seam for virtio transport.
///
/// A real virtio-net backend can implement this trait and be injected into
/// `VirtioNetAdapter` without touching `NetworkStack` orchestration.
trait VirtioTransportIo {
    fn submit_tx_descriptor(&mut self, packet: &NetPacket) -> bool;
    fn complete_tx_descriptor(&mut self) -> bool;
    fn poll_rx_descriptor(&mut self) -> Option<NetPacket>;
}

#[cfg(not(feature = "virtio-hw"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct VirtioStubQueueIo {
    polls: u64,
    pending_tx_desc: u32,
}

#[cfg(not(feature = "virtio-hw"))]
impl VirtioStubQueueIo {
    const fn new() -> Self {
        Self {
            polls: 0,
            pending_tx_desc: 0,
        }
    }
}

#[cfg(not(feature = "virtio-hw"))]
impl VirtioTransportIo for VirtioStubQueueIo {
    fn submit_tx_descriptor(&mut self, _packet: &NetPacket) -> bool {
        self.pending_tx_desc = self.pending_tx_desc.saturating_add(1);
        true
    }

    fn complete_tx_descriptor(&mut self) -> bool {
        if self.pending_tx_desc == 0 {
            return false;
        }
        self.pending_tx_desc -= 1;
        true
    }

    fn poll_rx_descriptor(&mut self) -> Option<NetPacket> {
        self.polls = self.polls.saturating_add(1);
        if self.polls % 4 == 0 {
            NetPacket::from_bytes(b"virtio-stub-rx").ok()
        } else {
            None
        }
    }
}

#[cfg(feature = "virtio-hw")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct VirtioHardwareIo {
    mmio_base: u64,
    tx_ring_size: u16,
    rx_ring_size: u16,
    initialized: bool,
    polls: u64,
}

#[cfg(feature = "virtio-hw")]
impl VirtioHardwareIo {
    const fn new() -> Self {
        Self {
            mmio_base: 0x1000_1000,
            tx_ring_size: 256,
            rx_ring_size: 256,
            initialized: false,
            polls: 0,
        }
    }

    const MAGIC_VALUE: u32 = 0x7472_6976; // "virt"
    const VERSION_V2: u32 = 2;
    const DEVICE_ID_NET: u32 = 1;
    const STATUS_ACKNOWLEDGE: u32 = 1;
    const STATUS_DRIVER: u32 = 2;
    const STATUS_FEATURES_OK: u32 = 8;
    const STATUS_DRIVER_OK: u32 = 4;

    const REG_MAGIC: u64 = 0x000;
    const REG_VERSION: u64 = 0x004;
    const REG_DEVICE_ID: u64 = 0x008;
    const REG_STATUS: u64 = 0x070;
    const REG_QUEUE_SEL: u64 = 0x030;
    const REG_QUEUE_NUM_MAX: u64 = 0x034;
    const REG_QUEUE_NUM: u64 = 0x038;
    const REG_QUEUE_READY: u64 = 0x044;

    #[cfg(target_os = "none")]
    unsafe fn mmio_read32(&self, reg: u64) -> u32 {
        let ptr = (self.mmio_base.wrapping_add(reg)) as *const u32;
        core::ptr::read_volatile(ptr)
    }

    #[cfg(target_os = "none")]
    unsafe fn mmio_write32(&self, reg: u64, value: u32) {
        let ptr = (self.mmio_base.wrapping_add(reg)) as *mut u32;
        core::ptr::write_volatile(ptr, value);
    }

    #[cfg(target_os = "none")]
    fn init_hw_if_needed(&mut self) -> bool {
        if self.initialized {
            return true;
        }
        let ok = unsafe {
            let magic = self.mmio_read32(Self::REG_MAGIC);
            let version = self.mmio_read32(Self::REG_VERSION);
            let device_id = self.mmio_read32(Self::REG_DEVICE_ID);
            if magic != Self::MAGIC_VALUE
                || version != Self::VERSION_V2
                || device_id != Self::DEVICE_ID_NET
            {
                return false;
            }

            self.mmio_write32(
                Self::REG_STATUS,
                Self::STATUS_ACKNOWLEDGE | Self::STATUS_DRIVER,
            );

            // Queue 0 = RX, queue 1 = TX. This is a minimal bring-up path;
            // descriptor memory wiring is the next step.
            self.mmio_write32(Self::REG_QUEUE_SEL, 0);
            let rx_max = self.mmio_read32(Self::REG_QUEUE_NUM_MAX);
            if rx_max == 0 {
                return false;
            }
            let rx_size = (rx_max.min(self.rx_ring_size as u32)) as u32;
            self.mmio_write32(Self::REG_QUEUE_NUM, rx_size);
            self.mmio_write32(Self::REG_QUEUE_READY, 1);

            self.mmio_write32(Self::REG_QUEUE_SEL, 1);
            let tx_max = self.mmio_read32(Self::REG_QUEUE_NUM_MAX);
            if tx_max == 0 {
                return false;
            }
            let tx_size = (tx_max.min(self.tx_ring_size as u32)) as u32;
            self.mmio_write32(Self::REG_QUEUE_NUM, tx_size);
            self.mmio_write32(Self::REG_QUEUE_READY, 1);

            self.mmio_write32(
                Self::REG_STATUS,
                Self::STATUS_ACKNOWLEDGE
                    | Self::STATUS_DRIVER
                    | Self::STATUS_FEATURES_OK
                    | Self::STATUS_DRIVER_OK,
            );
            true
        };
        self.initialized = ok;
        ok
    }

    #[cfg(not(target_os = "none"))]
    fn init_hw_if_needed(&mut self) -> bool {
        // Host-side tests and checks should compile with `virtio-hw` but never
        // attempt to touch platform MMIO space.
        false
    }
}

#[cfg(feature = "virtio-hw")]
impl VirtioTransportIo for VirtioHardwareIo {
    fn submit_tx_descriptor(&mut self, _packet: &NetPacket) -> bool {
        if !self.init_hw_if_needed() {
            return false;
        }
        // Descriptor ring publication is pending; successful init allows
        // controlled TX dequeue progress until that lands.
        true
    }

    fn complete_tx_descriptor(&mut self) -> bool {
        self.initialized
    }

    fn poll_rx_descriptor(&mut self) -> Option<NetPacket> {
        if !self.init_hw_if_needed() {
            return None;
        }
        self.polls = self.polls.saturating_add(1);
        if self.polls % 16 == 0 {
            NetPacket::from_bytes(b"virtio-hw-rx-probe").ok()
        } else {
            None
        }
    }
}

#[cfg(feature = "virtio-hw")]
type ActiveVirtioIo = VirtioHardwareIo;
#[cfg(not(feature = "virtio-hw"))]
type ActiveVirtioIo = VirtioStubQueueIo;

#[derive(Clone, Debug, PartialEq, Eq)]
struct VirtioNetAdapter<T: VirtioTransportIo + Clone + core::fmt::Debug + PartialEq + Eq> {
    io: T,
}

impl<T: VirtioTransportIo + Clone + core::fmt::Debug + PartialEq + Eq> VirtioNetAdapter<T> {
    fn new(io: T) -> Self {
        Self { io }
    }
}

impl<T: VirtioTransportIo + Clone + core::fmt::Debug + PartialEq + Eq> ExternalTransportAdapter
    for VirtioNetAdapter<T>
{
    fn poll(
        &mut self,
        tx_queue: &mut Deque<NetPacket, MAX_QUEUE_DEPTH>,
        rx_queue: &mut Deque<NetPacket, MAX_QUEUE_DEPTH>,
    ) -> BackendPollResult {
        let mut result = BackendPollResult::default();

        while let Some(packet) = tx_queue.pop_front() {
            if self.io.submit_tx_descriptor(&packet) {
                let _ = self.io.complete_tx_descriptor();
            } else {
                // Backend can't accept TX descriptors yet; preserve packet for
                // a later poll instead of dropping traffic.
                let _ = tx_queue.push_front(packet);
                break;
            }
        }

        while let Some(packet) = self.io.poll_rx_descriptor() {
            if rx_queue.push_back(packet).is_err() {
                result.rx_dropped = result.rx_dropped.saturating_add(1);
            } else {
                result.rx_received = result.rx_received.saturating_add(1);
            }
        }

        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StubTapAdapter;

impl ExternalTransportAdapter for StubTapAdapter {
    fn poll(
        &mut self,
        tx_queue: &mut Deque<NetPacket, MAX_QUEUE_DEPTH>,
        rx_queue: &mut Deque<NetPacket, MAX_QUEUE_DEPTH>,
    ) -> BackendPollResult {
        let mut result = BackendPollResult::default();
        while let Some(packet) = tx_queue.pop_front() {
            if rx_queue.push_back(packet).is_err() {
                result.rx_dropped = result.rx_dropped.saturating_add(1);
            } else {
                result.rx_received = result.rx_received.saturating_add(1);
            }
        }
        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExternalBackend {
    VirtioNet(VirtioNetAdapter<ActiveVirtioIo>),
    StubTap(StubTapAdapter),
}

impl ExternalBackend {
    fn from_kind(kind: ExternalBackendKind) -> Self {
        match kind {
            ExternalBackendKind::VirtioNet => {
                Self::VirtioNet(VirtioNetAdapter::new(ActiveVirtioIo::new()))
            }
            ExternalBackendKind::StubTap => Self::StubTap(StubTapAdapter),
        }
    }

    fn poll(
        &mut self,
        tx_queue: &mut Deque<NetPacket, MAX_QUEUE_DEPTH>,
        rx_queue: &mut Deque<NetPacket, MAX_QUEUE_DEPTH>,
    ) -> BackendPollResult {
        match self {
            Self::VirtioNet(adapter) => adapter.poll(tx_queue, rx_queue),
            Self::StubTap(adapter) => adapter.poll(tx_queue, rx_queue),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExternalTransport {
    backend: ExternalBackend,
}

impl ExternalTransport {
    pub(super) fn from_kind(kind: ExternalBackendKind) -> Self {
        Self {
            backend: ExternalBackend::from_kind(kind),
        }
    }

    pub(super) fn poll(
        &mut self,
        tx_queue: &mut Deque<NetPacket, MAX_QUEUE_DEPTH>,
        rx_queue: &mut Deque<NetPacket, MAX_QUEUE_DEPTH>,
    ) -> BackendPollResult {
        self.backend.poll(tx_queue, rx_queue)
    }
}
