use core::str::FromStr;
use heapless::{Deque, FnvIndexMap, String, Vec};

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetError {
    InterfaceExists,
    InterfaceNotFound,
    InvalidInterfaceName,
    QueueFull,
    PayloadTooLarge,
}

pub struct NetworkInterface {
    name: String<MAX_IFACE_NAME>,
    loopback: bool,
    tx_queue: Deque<NetPacket, MAX_QUEUE_DEPTH>,
    rx_queue: Deque<NetPacket, MAX_QUEUE_DEPTH>,
    stats: InterfaceStats,
}

impl NetworkInterface {
    fn loopback(name: &str) -> Result<Self, NetError> {
        let name = String::from_str(name).map_err(|_| NetError::InvalidInterfaceName)?;
        Ok(Self {
            name,
            loopback: true,
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
        self.stats.tx_packets = self.stats.tx_packets.saturating_add(1);
        Ok(())
    }

    fn dequeue_rx(&mut self) -> Option<NetPacket> {
        self.rx_queue.pop_front()
    }

    fn service_io(&mut self) {
        if !self.loopback {
            return;
        }
        while let Some(packet) = self.tx_queue.pop_front() {
            if self.rx_queue.push_back(packet).is_err() {
                self.stats.rx_dropped = self.stats.rx_dropped.saturating_add(1);
            } else {
                self.stats.rx_packets = self.stats.rx_packets.saturating_add(1);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkSummary {
    pub interfaces: usize,
    pub total_tx_packets: u64,
    pub total_rx_packets: u64,
    pub total_tx_dropped: u64,
    pub total_rx_dropped: u64,
}

pub struct NetworkStack {
    interfaces: FnvIndexMap<String<MAX_IFACE_NAME>, NetworkInterface, MAX_INTERFACES>,
}

impl NetworkStack {
    pub const fn new() -> Self {
        Self {
            interfaces: FnvIndexMap::new(),
        }
    }

    pub fn add_loopback_interface(&mut self, name: &str) -> Result<(), NetError> {
        let key = String::from_str(name).map_err(|_| NetError::InvalidInterfaceName)?;
        if self.interfaces.contains_key(&key) {
            return Err(NetError::InterfaceExists);
        }
        let iface = NetworkInterface::loopback(name)?;
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
        for iface in self.interfaces.values_mut() {
            iface.service_io();
        }
    }

    pub fn summary(&self) -> NetworkSummary {
        let mut out = NetworkSummary {
            interfaces: self.interfaces.len(),
            ..NetworkSummary::default()
        };
        for iface in self.interfaces.values() {
            out.total_tx_packets = out.total_tx_packets.saturating_add(iface.stats.tx_packets);
            out.total_rx_packets = out.total_rx_packets.saturating_add(iface.stats.rx_packets);
            out.total_tx_dropped = out.total_tx_dropped.saturating_add(iface.stats.tx_dropped);
            out.total_rx_dropped = out.total_rx_dropped.saturating_add(iface.stats.rx_dropped);
        }
        out
    }

    pub fn for_each_interface(&self, mut f: impl FnMut(&str, InterfaceStats)) {
        for iface in self.interfaces.values() {
            f(iface.name.as_str(), iface.stats);
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
        assert_eq!(summary.total_tx_packets, 2);
        assert_eq!(summary.total_rx_packets, 2);
    }
}
