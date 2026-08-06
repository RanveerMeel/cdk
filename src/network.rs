use core::str::FromStr;
use heapless::{Deque, FnvIndexMap, String, Vec};

mod transport;
use self::transport::ExternalTransport;

const MAX_INTERFACES: usize = 4;
const MAX_IFACE_NAME: usize = 16;
const MAX_PACKET_BYTES: usize = 256;
const MAX_QUEUE_DEPTH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetPacket {
    pub payload: Vec<u8, MAX_PACKET_BYTES>,
}

impl NetPacket {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NetError> {
        let mut payload = Vec::<u8, MAX_PACKET_BYTES>::new();
        payload
            .extend_from_slice(bytes)
            .map_err(|_| NetError::PayloadTooLarge)?;
        Ok(Self { payload })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InterfaceStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_dropped: u64,
    pub rx_dropped: u64,
    pub tx_high_watermark: usize,
    pub rx_high_watermark: usize,
    pub backend_polls: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetError {
    InterfaceExists,
    InterfaceNotFound,
    InvalidInterfaceName,
    QueueFull,
    PayloadTooLarge,
    InvalidBackend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalBackendKind {
    VirtioNet,
    StubTap,
}

impl ExternalBackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VirtioNet => "virtio-net",
            Self::StubTap => "stub-tap",
        }
    }

    pub fn parse(input: &str) -> Option<Self> {
        match input {
            "virtio-net" | "virtio" => Some(Self::VirtioNet),
            "stub-tap" | "stub" | "tap" => Some(Self::StubTap),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceKind {
    Loopback,
    External(ExternalBackendKind),
}

impl InterfaceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::External(kind) => kind.as_str(),
        }
    }
}

pub struct NetworkInterface {
    name: String<MAX_IFACE_NAME>,
    kind: InterfaceKind,
    backend: Option<ExternalTransport>,
    tx_queue: Deque<NetPacket, MAX_QUEUE_DEPTH>,
    rx_queue: Deque<NetPacket, MAX_QUEUE_DEPTH>,
    stats: InterfaceStats,
}

impl NetworkInterface {
    fn new(name: &str, kind: InterfaceKind) -> Result<Self, NetError> {
        let name = String::from_str(name).map_err(|_| NetError::InvalidInterfaceName)?;
        Ok(Self {
            name,
            kind,
            backend: match kind {
                InterfaceKind::Loopback => None,
                InterfaceKind::External(backend) => Some(ExternalTransport::from_kind(backend)),
            },
            tx_queue: Deque::new(),
            rx_queue: Deque::new(),
            stats: InterfaceStats::default(),
        })
    }

    fn enqueue_tx(&mut self, packet: NetPacket) -> Result<(), NetError> {
        if self.tx_queue.push_back(packet).is_err() {
            self.stats.tx_dropped = self.stats.tx_dropped.saturating_add(1);
            return Err(NetError::QueueFull);
        }
        self.stats.tx_high_watermark = self.stats.tx_high_watermark.max(self.tx_queue.len());
        self.stats.tx_packets = self.stats.tx_packets.saturating_add(1);
        Ok(())
    }

    fn dequeue_rx(&mut self) -> Option<NetPacket> {
        self.rx_queue.pop_front()
    }

    fn service_io(&mut self) {
        match self.kind {
            InterfaceKind::Loopback => {
                while let Some(packet) = self.tx_queue.pop_front() {
                    if self.rx_queue.push_back(packet).is_err() {
                        self.stats.rx_dropped = self.stats.rx_dropped.saturating_add(1);
                    } else {
                        self.stats.rx_high_watermark =
                            self.stats.rx_high_watermark.max(self.rx_queue.len());
                        self.stats.rx_packets = self.stats.rx_packets.saturating_add(1);
                    }
                }
            }
            InterfaceKind::External(_) => {
                self.stats.backend_polls = self.stats.backend_polls.saturating_add(1);
                if let Some(backend) = self.backend.as_mut() {
                    let result = backend.poll(&mut self.tx_queue, &mut self.rx_queue);
                    self.stats.rx_packets =
                        self.stats.rx_packets.saturating_add(result.rx_received);
                    self.stats.rx_dropped = self.stats.rx_dropped.saturating_add(result.rx_dropped);
                    self.stats.rx_high_watermark =
                        self.stats.rx_high_watermark.max(self.rx_queue.len());
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkSummary {
    pub interfaces: usize,
    pub external_interfaces: usize,
    pub service_ticks: u64,
    pub total_tx_packets: u64,
    pub total_rx_packets: u64,
    pub total_tx_dropped: u64,
    pub total_rx_dropped: u64,
    pub total_tx_queue_depth: usize,
    pub total_rx_queue_depth: usize,
}

pub struct NetworkStack {
    interfaces: FnvIndexMap<String<MAX_IFACE_NAME>, NetworkInterface, MAX_INTERFACES>,
    service_ticks: u64,
}

impl NetworkStack {
    pub const fn new() -> Self {
        Self {
            interfaces: FnvIndexMap::new(),
            service_ticks: 0,
        }
    }

    pub fn add_loopback_interface(&mut self, name: &str) -> Result<(), NetError> {
        self.add_interface(name, InterfaceKind::Loopback)
    }

    pub fn add_external_interface(
        &mut self,
        name: &str,
        backend: ExternalBackendKind,
    ) -> Result<(), NetError> {
        self.add_interface(name, InterfaceKind::External(backend))
    }

    fn add_interface(&mut self, name: &str, kind: InterfaceKind) -> Result<(), NetError> {
        let key = String::from_str(name).map_err(|_| NetError::InvalidInterfaceName)?;
        if self.interfaces.contains_key(&key) {
            return Err(NetError::InterfaceExists);
        }
        let iface = NetworkInterface::new(name, kind)?;
        self.interfaces
            .insert(key, iface)
            .map_err(|_| NetError::QueueFull)?;
        Ok(())
    }

    pub fn send_bytes(&mut self, iface: &str, bytes: &[u8]) -> Result<(), NetError> {
        let key = String::from_str(iface).map_err(|_| NetError::InvalidInterfaceName)?;
        let packet = NetPacket::from_bytes(bytes)?;
        let iface = self
            .interfaces
            .get_mut(&key)
            .ok_or(NetError::InterfaceNotFound)?;
        iface.enqueue_tx(packet)
    }

    pub fn recv_packet(&mut self, iface: &str) -> Result<Option<NetPacket>, NetError> {
        let key = String::from_str(iface).map_err(|_| NetError::InvalidInterfaceName)?;
        let iface = self
            .interfaces
            .get_mut(&key)
            .ok_or(NetError::InterfaceNotFound)?;
        Ok(iface.dequeue_rx())
    }

    pub fn service(&mut self) {
        self.service_ticks = self.service_ticks.saturating_add(1);
        for iface in self.interfaces.values_mut() {
            iface.service_io();
        }
    }

    pub fn summary(&self) -> NetworkSummary {
        let mut out = NetworkSummary {
            interfaces: self.interfaces.len(),
            service_ticks: self.service_ticks,
            ..NetworkSummary::default()
        };
        for iface in self.interfaces.values() {
            if matches!(iface.kind, InterfaceKind::External(_)) {
                out.external_interfaces = out.external_interfaces.saturating_add(1);
            }
            out.total_tx_packets = out.total_tx_packets.saturating_add(iface.stats.tx_packets);
            out.total_rx_packets = out.total_rx_packets.saturating_add(iface.stats.rx_packets);
            out.total_tx_dropped = out.total_tx_dropped.saturating_add(iface.stats.tx_dropped);
            out.total_rx_dropped = out.total_rx_dropped.saturating_add(iface.stats.rx_dropped);
            out.total_tx_queue_depth = out
                .total_tx_queue_depth
                .saturating_add(iface.tx_queue.len());
            out.total_rx_queue_depth = out
                .total_rx_queue_depth
                .saturating_add(iface.rx_queue.len());
        }
        out
    }

    pub fn for_each_interface(
        &self,
        mut f: impl FnMut(&str, InterfaceKind, InterfaceStats, usize, usize),
    ) {
        for iface in self.interfaces.values() {
            f(
                iface.name.as_str(),
                iface.kind,
                iface.stats,
                iface.tx_queue.len(),
                iface.rx_queue.len(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_loopback_registers_interface() {
        let mut stack = NetworkStack::new();
        stack.add_loopback_interface("lo").unwrap();
        assert_eq!(stack.summary().interfaces, 1);
    }

    #[test]
    fn add_external_registers_interface() {
        let mut stack = NetworkStack::new();
        stack
            .add_external_interface("eth0", ExternalBackendKind::VirtioNet)
            .unwrap();
        let summary = stack.summary();
        assert_eq!(summary.interfaces, 1);
        assert_eq!(summary.external_interfaces, 1);
    }

    #[test]
    fn duplicate_interface_rejected() {
        let mut stack = NetworkStack::new();
        stack.add_loopback_interface("lo").unwrap();
        let second = stack.add_loopback_interface("lo");
        assert!(matches!(second, Err(NetError::InterfaceExists)));
    }

    #[test]
    fn loopback_delivery_round_trip() {
        let mut stack = NetworkStack::new();
        stack.add_loopback_interface("lo").unwrap();
        stack.send_bytes("lo", b"ping").unwrap();
        stack.service();
        let pkt = stack.recv_packet("lo").unwrap().unwrap();
        assert_eq!(pkt.payload.as_slice(), b"ping");
    }

    #[test]
    fn payload_limit_enforced() {
        let mut stack = NetworkStack::new();
        stack.add_loopback_interface("lo").unwrap();
        let big = [7u8; MAX_PACKET_BYTES + 1];
        let result = stack.send_bytes("lo", &big);
        assert!(matches!(result, Err(NetError::PayloadTooLarge)));
    }

    #[test]
    fn summary_tracks_tx_and_rx() {
        let mut stack = NetworkStack::new();
        stack.add_loopback_interface("lo").unwrap();
        stack.send_bytes("lo", b"a").unwrap();
        stack.send_bytes("lo", b"b").unwrap();
        stack.service();
        let summary = stack.summary();
        assert_eq!(summary.service_ticks, 1);
        assert_eq!(summary.total_tx_packets, 2);
        assert_eq!(summary.total_rx_packets, 2);
    }

    #[test]
    fn tracks_queue_high_watermarks() {
        let mut stack = NetworkStack::new();
        stack.add_loopback_interface("lo").unwrap();
        for _ in 0..4 {
            stack.send_bytes("lo", b"x").unwrap();
        }
        let mut tx_high = 0usize;
        stack.for_each_interface(|_, _, stats, _, _| {
            tx_high = stats.tx_high_watermark;
        });
        assert_eq!(tx_high, 4);
    }

    #[test]
    fn external_interfaces_record_backend_polls() {
        let mut stack = NetworkStack::new();
        stack
            .add_external_interface("eth0", ExternalBackendKind::StubTap)
            .unwrap();
        stack.service();
        stack.service();
        let mut polls = 0u64;
        stack.for_each_interface(|name, _, stats, _, _| {
            if name == "eth0" {
                polls = stats.backend_polls;
            }
        });
        assert_eq!(polls, 2);
    }

    #[test]
    fn stub_tap_moves_tx_into_rx() {
        let mut stack = NetworkStack::new();
        stack
            .add_external_interface("eth0", ExternalBackendKind::StubTap)
            .unwrap();
        stack.send_bytes("eth0", b"ping-ext").unwrap();
        stack.service();
        let pkt = stack.recv_packet("eth0").unwrap().unwrap();
        assert_eq!(pkt.payload.as_slice(), b"ping-ext");
    }

    #[cfg(not(feature = "virtio-hw"))]
    #[test]
    fn virtio_stub_injects_periodic_rx_packet() {
        let mut stack = NetworkStack::new();
        stack
            .add_external_interface("eth1", ExternalBackendKind::VirtioNet)
            .unwrap();
        for _ in 0..4 {
            stack.service();
        }
        let pkt = stack.recv_packet("eth1").unwrap().unwrap();
        assert_eq!(pkt.payload.as_slice(), b"virtio-stub-rx");
    }

    #[cfg(feature = "virtio-hw")]
    #[test]
    fn virtio_hw_host_poll_keeps_rx_empty_without_mmio() {
        let mut stack = NetworkStack::new();
        stack
            .add_external_interface("eth1", ExternalBackendKind::VirtioNet)
            .unwrap();
        for _ in 0..32 {
            stack.service();
        }
        assert!(stack.recv_packet("eth1").unwrap().is_none());
    }
}
