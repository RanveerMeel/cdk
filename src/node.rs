// Distributed kernel node - cloud/edge aware
use heapless::String;
use heapless::FnvIndexMap;
use core::str::FromStr;

const MAX_NODES: usize = 8;
const MAX_ID_LEN: usize = 64;
const MAX_ADDR_LEN: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Local,
    Edge,
    Cloud,
}

pub struct RemoteNode {
    pub node_id: String<MAX_ID_LEN>,
    pub node_type: NodeType,
    pub address: String<MAX_ADDR_LEN>,
    pub latency_ms: u32,
    pub last_seen: u64, // Timestamp
}

pub struct KernelNode {
    node_id: String<MAX_ID_LEN>,
    node_type: NodeType,
    known_nodes: FnvIndexMap<String<MAX_ID_LEN>, RemoteNode, MAX_NODES>,
    node_counter: u64,
}

impl KernelNode {
    pub fn new() -> Self {
        let node_id = Self::generate_node_id(0);
        Self {
            node_id,
            node_type: NodeType::Local,
            known_nodes: FnvIndexMap::new(),
            node_counter: 0,
        }
    }

    /// Const-compatible constructor for use in `static` items.
    pub const fn new_const() -> Self {
        Self {
            node_id: String::new(),
            node_type: NodeType::Local,
            known_nodes: FnvIndexMap::new(),
            node_counter: 0,
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn node_type(&self) -> NodeType {
        self.node_type
    }

    pub fn set_node_type(&mut self, node_type: NodeType) {
        self.node_type = node_type;
    }

    pub fn discover_node(
        &mut self,
        node_id: &str,
        node_type: NodeType,
        address: &str,
        latency_ms: u32,
    ) {
        let id: String<MAX_ID_LEN> = String::from_str(node_id).unwrap_or_default();
        let addr: String<MAX_ADDR_LEN> = String::from_str(address).unwrap_or_default();
        
        let remote_node = RemoteNode {
            node_id: id.clone(),
            node_type,
            address: addr,
            latency_ms,
            last_seen: self.node_counter, // Use counter as simple timestamp
        };
        
        let _ = self.known_nodes.insert(id, remote_node);
    }

    pub fn get_node(&self, node_id: &str) -> Option<&RemoteNode> {
        let key: String<MAX_ID_LEN> = String::from_str(node_id).unwrap_or_default();
        self.known_nodes.get(&key)
    }

    pub fn known_nodes_count(&self) -> usize {
        self.known_nodes.len()
    }

    pub fn find_best_node(&self, preferred_type: NodeType) -> Option<&RemoteNode> {
        self.known_nodes
            .values()
            .filter(|node| node.node_type == preferred_type)
            .min_by_key(|node| node.latency_ms)
    }

    fn generate_node_id(counter: u64) -> String<MAX_ID_LEN> {
        // Simple ID generation (replace with proper crypto RNG in production)
        let mut id = String::new();
        let _ = id.push_str("node-");
        let _ = write_number(&mut id, counter);
        if id.is_empty() {
            // Fallback if generation fails
            let _ = id.push_str("0");
        }
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_node_starts_with_no_known_nodes() {
        let node = KernelNode::new();
        assert_eq!(node.known_nodes_count(), 0);
    }

    #[test]
    fn new_node_type_is_local() {
        let node = KernelNode::new();
        assert_eq!(node.node_type(), NodeType::Local);
    }

    #[test]
    fn discover_node_adds_to_known_nodes() {
        let mut node = KernelNode::new();
        node.discover_node("remote-1", NodeType::Edge, "10.0.0.1", 20);
        assert_eq!(node.known_nodes_count(), 1);
    }

    #[test]
    fn get_node_returns_correct_entry() {
        let mut node = KernelNode::new();
        node.discover_node("edge-42", NodeType::Edge, "192.168.1.1", 15);
        let found = node.get_node("edge-42").unwrap();
        assert_eq!(found.node_id.as_str(), "edge-42");
        assert_eq!(found.latency_ms, 15);
        assert_eq!(found.node_type, NodeType::Edge);
    }

    #[test]
    fn get_node_missing_returns_none() {
        let node = KernelNode::new();
        assert!(node.get_node("ghost").is_none());
    }

    #[test]
    fn discover_node_overwrites_existing_entry() {
        let mut node = KernelNode::new();
        node.discover_node("n1", NodeType::Edge, "addr-a", 50);
        node.discover_node("n1", NodeType::Cloud, "addr-b", 5);
        assert_eq!(node.known_nodes_count(), 1);
        let n = node.get_node("n1").unwrap();
        assert_eq!(n.latency_ms, 5);
        assert_eq!(n.node_type, NodeType::Cloud);
    }

    #[test]
    fn find_best_node_picks_lowest_latency_of_preferred_type() {
        let mut node = KernelNode::new();
        node.discover_node("edge-fast", NodeType::Edge, "a", 10);
        node.discover_node("edge-slow", NodeType::Edge, "b", 100);
        node.discover_node("cloud-1",   NodeType::Cloud, "c", 5);

        let best_edge = node.find_best_node(NodeType::Edge).unwrap();
        assert_eq!(best_edge.node_id.as_str(), "edge-fast");

        let best_cloud = node.find_best_node(NodeType::Cloud).unwrap();
        assert_eq!(best_cloud.node_id.as_str(), "cloud-1");
    }

    #[test]
    fn find_best_node_returns_none_when_type_absent() {
        let mut node = KernelNode::new();
        node.discover_node("only-edge", NodeType::Edge, "x", 1);
        assert!(node.find_best_node(NodeType::Cloud).is_none());
    }

    #[test]
    fn set_node_type_changes_type() {
        let mut node = KernelNode::new();
        assert_eq!(node.node_type(), NodeType::Local);
        node.set_node_type(NodeType::Edge);
        assert_eq!(node.node_type(), NodeType::Edge);
    }
}

fn write_number(s: &mut String<MAX_ID_LEN>, n: u64) -> Result<(), ()> {
    if n == 0 {
        return s.push_str("0");
    }
    
    let mut num = n;
    let mut digits = heapless::Vec::<u8, 20>::new();
    
    while num > 0 {
        digits.push((num % 10) as u8 + b'0').map_err(|_| ())?;
        num /= 10;
    }
    
    for &digit in digits.iter().rev() {
        s.push(digit as char).map_err(|_| ())?;
    }
    
    Ok(())
}

