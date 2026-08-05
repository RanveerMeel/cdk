use crate::{
    capability::{Capability, CapabilityError, Permission},
    message::{Message, MessagePayload},
    network::{NetError, NetPacket, NetworkStack},
    object::KernelObject,
    scheduler::Scheduler,
};
use core::str::FromStr;
use heapless::FnvIndexMap;
use heapless::String;

const MAX_OBJECTS: usize = 16;
const MAX_ID_LEN: usize = 64;
const MAX_IFACE_LEN: usize = 16;

#[derive(Debug, Clone)]
pub enum KernelError {
    InvalidCapability,
    ObjectNotFound,
    PermissionDenied,
    MessageQueueFull,
    InvalidSignature,
    NetworkError,
    PayloadTooLarge,
    UnsupportedPayload,
    BindingTableFull,
    InvalidBinding,
}

pub type KernelResult<T> = Result<T, KernelError>;

#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkCapabilityStats {
    pub send_ok: u64,
    pub send_err: u64,
    pub recv_ok: u64,
    pub recv_empty: u64,
    pub recv_err: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BridgeTelemetry {
    pub ingress_moved: u64,
    pub egress_moved: u64,
    pub ingress_errors: u64,
    pub egress_errors: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BridgeTickResult {
    pub ingress_moved: u64,
    pub egress_moved: u64,
    pub ingress_errors: u64,
    pub egress_errors: u64,
}

pub struct Kernel {
    objects: FnvIndexMap<String<MAX_ID_LEN>, KernelObject, MAX_OBJECTS>,
    scheduler: Scheduler,
    network_stats: FnvIndexMap<String<MAX_ID_LEN>, NetworkCapabilityStats, MAX_OBJECTS>,
    bridge_ingress: FnvIndexMap<String<MAX_IFACE_LEN>, String<MAX_ID_LEN>, MAX_OBJECTS>,
    bridge_egress: FnvIndexMap<String<MAX_ID_LEN>, String<MAX_IFACE_LEN>, MAX_OBJECTS>,
    bridge_telemetry: BridgeTelemetry,
}

impl Kernel {
    pub const fn new() -> Self {
        Self {
            objects: FnvIndexMap::new(),
            scheduler: Scheduler::new(),
            network_stats: FnvIndexMap::new(),
            bridge_ingress: FnvIndexMap::new(),
            bridge_egress: FnvIndexMap::new(),
            bridge_telemetry: BridgeTelemetry {
                ingress_moved: 0,
                egress_moved: 0,
                ingress_errors: 0,
                egress_errors: 0,
            },
        }
    }

    pub fn register_object(&mut self, obj: KernelObject) -> Capability {
        let cap = Capability::new(&obj);
        let id = obj.id.clone();
        let _ = self.objects.insert(id, obj);
        let _ = self
            .network_stats
            .insert(cap.object_id.clone(), NetworkCapabilityStats::default());
        cap
    }

    /// Sign a capability with a freshly-generated Ed25519 key.
    ///
    /// Returns the 32-byte signing key (secret — caller must store it) and
    /// updates the capability in place with the signature + verifying key.
    pub fn sign_capability(cap: &mut Capability) -> Result<[u8; 32], CapabilityError> {
        let (sk, _vk) = Capability::generate_key();
        cap.sign(&sk)?;
        Ok(sk)
    }

    /// Verify a capability's Ed25519 signature.
    ///
    /// Returns `Ok(true)` when valid, `Ok(false)` when unsigned,
    /// `Err` when the stored key or signature bytes are malformed.
    pub fn verify_capability(cap: &Capability) -> Result<bool, CapabilityError> {
        cap.verify()
    }

    pub fn execute(&mut self, cap: &Capability) -> KernelResult<()> {
        Self::check_signature(cap)?;

        if !cap.has_permission(&Permission::Execute) {
            return Err(KernelError::PermissionDenied);
        }

        let obj = self
            .objects
            .get(&cap.object_id)
            .ok_or(KernelError::ObjectNotFound)?;

        self.scheduler.schedule(obj);
        Ok(())
    }

    pub fn send_message(
        &mut self,
        from_cap: &Capability,
        to_object_id: &str,
        msg: Message,
    ) -> KernelResult<()> {
        Self::check_signature(from_cap)?;

        if !from_cap.has_permission(&Permission::SendMessage) {
            return Err(KernelError::PermissionDenied);
        }

        let key: String<MAX_ID_LEN> = String::from_str(to_object_id).unwrap_or_default();
        let to_obj = self
            .objects
            .get_mut(&key)
            .ok_or(KernelError::ObjectNotFound)?;

        // Check if message queue is full
        if to_obj.message_count() >= 8 {
            return Err(KernelError::MessageQueueFull);
        }

        to_obj
            .receive_message(msg)
            .map_err(|_| KernelError::MessageQueueFull)?;
        Ok(())
    }

    pub fn receive_message(&mut self, cap: &Capability) -> KernelResult<Option<Message>> {
        Self::check_signature(cap)?;

        if !cap.has_permission(&Permission::ReceiveMessage) {
            return Err(KernelError::PermissionDenied);
        }

        let obj = self
            .objects
            .get_mut(&cap.object_id)
            .ok_or(KernelError::ObjectNotFound)?;

        Ok(obj.pop_message())
    }

    pub fn network_send(
        &mut self,
        cap: &Capability,
        network: &mut NetworkStack,
        iface: &str,
        payload: &[u8],
    ) -> KernelResult<()> {
        if let Err(e) = Self::check_signature(cap) {
            self.bump_net_send_err(&cap.object_id);
            return Err(e);
        }
        if !self.objects.contains_key(&cap.object_id) {
            self.bump_net_send_err(&cap.object_id);
            return Err(KernelError::InvalidCapability);
        }
        if !cap.has_permission(&Permission::SendMessage) {
            self.bump_net_send_err(&cap.object_id);
            return Err(KernelError::PermissionDenied);
        }
        match network
            .send_bytes(iface, payload)
            .map_err(Self::map_net_error)
        {
            Ok(()) => {
                self.bump_net_send_ok(&cap.object_id);
                Ok(())
            }
            Err(e) => {
                self.bump_net_send_err(&cap.object_id);
                Err(e)
            }
        }
    }

    pub fn network_receive(
        &mut self,
        cap: &Capability,
        network: &mut NetworkStack,
        iface: &str,
    ) -> KernelResult<Option<NetPacket>> {
        if let Err(e) = Self::check_signature(cap) {
            self.bump_net_recv_err(&cap.object_id);
            return Err(e);
        }
        if !self.objects.contains_key(&cap.object_id) {
            self.bump_net_recv_err(&cap.object_id);
            return Err(KernelError::InvalidCapability);
        }
        if !cap.has_permission(&Permission::ReceiveMessage) {
            self.bump_net_recv_err(&cap.object_id);
            return Err(KernelError::PermissionDenied);
        }
        match network.recv_packet(iface).map_err(Self::map_net_error) {
            Ok(Some(packet)) => {
                self.bump_net_recv_ok(&cap.object_id);
                Ok(Some(packet))
            }
            Ok(None) => {
                self.bump_net_recv_empty(&cap.object_id);
                Ok(None)
            }
            Err(e) => {
                self.bump_net_recv_err(&cap.object_id);
                Err(e)
            }
        }
    }

    pub fn bridge_network_to_object(
        &mut self,
        cap: &Capability,
        network: &mut NetworkStack,
        iface: &str,
        target_object_id: &str,
    ) -> KernelResult<bool> {
        let packet = self.network_receive(cap, network, iface)?;
        let Some(packet) = packet else {
            return Ok(false);
        };

        let mut data = heapless::Vec::<u8, 64>::new();
        data.extend_from_slice(packet.payload.as_slice())
            .map_err(|_| KernelError::PayloadTooLarge)?;
        let msg = Message::new("net-bridge", target_object_id, MessagePayload::Data(data))
            .map_err(|_| KernelError::PayloadTooLarge)?;
        self.send_message_direct(target_object_id, msg)?;
        Ok(true)
    }

    pub fn bridge_object_to_network(
        &mut self,
        cap: &Capability,
        network: &mut NetworkStack,
        source_object_id: &str,
        iface: &str,
    ) -> KernelResult<bool> {
        let maybe_msg = self.receive_message_direct(source_object_id)?;
        let Some(msg) = maybe_msg else {
            return Ok(false);
        };

        let bytes: heapless::Vec<u8, 64> = match msg.payload {
            MessagePayload::Data(data) => data,
            MessagePayload::Text(text) | MessagePayload::Command(text) => {
                let mut out = heapless::Vec::<u8, 64>::new();
                out.extend_from_slice(text.as_bytes())
                    .map_err(|_| KernelError::PayloadTooLarge)?;
                out
            }
            MessagePayload::Request { .. } | MessagePayload::Response { .. } => {
                return Err(KernelError::UnsupportedPayload);
            }
        };

        self.network_send(cap, network, iface, bytes.as_slice())?;
        Ok(true)
    }

    pub fn execute_next(&mut self) -> Option<String<MAX_ID_LEN>> {
        self.scheduler.execute_next()
    }

    /// Advance the scheduler clock by one timer tick.
    ///
    /// If the running task's time slice has expired, it is evicted and the
    /// next queued task is dispatched.  Returns `Some(id)` on a context
    /// switch, `None` otherwise.
    pub fn preempt_tick(&mut self, current_tick: u64) -> Option<String<MAX_ID_LEN>> {
        self.scheduler.preempt_if_expired(current_tick)
    }

    /// Object id of the task currently occupying the CPU (if any).
    pub fn running_task_id(&self) -> Option<&str> {
        self.scheduler
            .running_task()
            .map(|rt| rt.task.object_id.as_str())
    }

    pub fn get_object(&self, cap: &Capability) -> KernelResult<&KernelObject> {
        Self::check_signature(cap)?;

        if !cap.has_permission(&Permission::Read) {
            return Err(KernelError::PermissionDenied);
        }

        self.objects
            .get(&cap.object_id)
            .ok_or(KernelError::ObjectNotFound)
    }

    pub fn delete_object(&mut self, cap: &Capability) -> KernelResult<()> {
        Self::check_signature(cap)?;

        if !cap.has_permission(&Permission::Delete) {
            return Err(KernelError::PermissionDenied);
        }

        self.objects
            .remove(&cap.object_id)
            .ok_or(KernelError::ObjectNotFound)?;
        Ok(())
    }

    pub fn scheduler_queue_size(&self) -> usize {
        self.scheduler.queue_size()
    }

    pub fn validate_capability(&self, cap: &Capability) -> KernelResult<()> {
        Self::check_signature(cap)?;

        if !self.objects.contains_key(&cap.object_id) {
            return Err(KernelError::InvalidCapability);
        }
        Ok(())
    }

    pub fn network_stats_for(&self, object_id: &str) -> Option<NetworkCapabilityStats> {
        let key: String<MAX_ID_LEN> = String::from_str(object_id).ok()?;
        self.network_stats.get(&key).copied()
    }

    pub fn for_each_network_stats(&self, mut f: impl FnMut(&str, NetworkCapabilityStats)) {
        for (object_id, stats) in self.network_stats.iter() {
            f(object_id.as_str(), *stats);
        }
    }

    pub fn bridge_bind_ingress(&mut self, iface: &str, object_id: &str) -> KernelResult<()> {
        if self.for_each_object_find(object_id).is_none() {
            return Err(KernelError::ObjectNotFound);
        }
        let iface_key: String<MAX_IFACE_LEN> =
            String::from_str(iface).map_err(|_| KernelError::InvalidBinding)?;
        let object_key: String<MAX_ID_LEN> =
            String::from_str(object_id).map_err(|_| KernelError::InvalidBinding)?;
        self.bridge_ingress
            .insert(iface_key, object_key)
            .map_err(|_| KernelError::BindingTableFull)?;
        Ok(())
    }

    pub fn bridge_bind_egress(&mut self, object_id: &str, iface: &str) -> KernelResult<()> {
        if self.for_each_object_find(object_id).is_none() {
            return Err(KernelError::ObjectNotFound);
        }
        let object_key: String<MAX_ID_LEN> =
            String::from_str(object_id).map_err(|_| KernelError::InvalidBinding)?;
        let iface_key: String<MAX_IFACE_LEN> =
            String::from_str(iface).map_err(|_| KernelError::InvalidBinding)?;
        self.bridge_egress
            .insert(object_key, iface_key)
            .map_err(|_| KernelError::BindingTableFull)?;
        Ok(())
    }

    pub fn bridge_clear_bindings(&mut self) {
        self.bridge_ingress.clear();
        self.bridge_egress.clear();
    }

    pub fn bridge_telemetry(&self) -> BridgeTelemetry {
        self.bridge_telemetry
    }

    pub fn bridge_binding_counts(&self) -> (usize, usize) {
        (self.bridge_ingress.len(), self.bridge_egress.len())
    }

    pub fn for_each_bridge_ingress_binding(&self, mut f: impl FnMut(&str, &str)) {
        for (iface, object_id) in self.bridge_ingress.iter() {
            f(iface.as_str(), object_id.as_str());
        }
    }

    pub fn for_each_bridge_egress_binding(&self, mut f: impl FnMut(&str, &str)) {
        for (object_id, iface) in self.bridge_egress.iter() {
            f(object_id.as_str(), iface.as_str());
        }
    }

    pub fn bridge_tick(
        &mut self,
        cap: &Capability,
        network: &mut NetworkStack,
    ) -> KernelResult<BridgeTickResult> {
        Self::check_signature(cap)?;
        if !self.objects.contains_key(&cap.object_id) {
            return Err(KernelError::InvalidCapability);
        }

        network.service();
        let mut result = BridgeTickResult::default();

        let mut ingress =
            heapless::Vec::<(String<MAX_IFACE_LEN>, String<MAX_ID_LEN>), MAX_OBJECTS>::new();
        for (iface, obj) in self.bridge_ingress.iter() {
            let _ = ingress.push((iface.clone(), obj.clone()));
        }
        for (iface, object_id) in ingress.iter() {
            match self.bridge_network_to_object(cap, network, iface.as_str(), object_id.as_str()) {
                Ok(true) => result.ingress_moved = result.ingress_moved.saturating_add(1),
                Ok(false) => {}
                Err(_) => result.ingress_errors = result.ingress_errors.saturating_add(1),
            }
        }

        let mut egress =
            heapless::Vec::<(String<MAX_ID_LEN>, String<MAX_IFACE_LEN>), MAX_OBJECTS>::new();
        for (obj, iface) in self.bridge_egress.iter() {
            let _ = egress.push((obj.clone(), iface.clone()));
        }
        for (object_id, iface) in egress.iter() {
            match self.bridge_object_to_network(cap, network, object_id.as_str(), iface.as_str()) {
                Ok(true) => result.egress_moved = result.egress_moved.saturating_add(1),
                Ok(false) => {}
                Err(_) => result.egress_errors = result.egress_errors.saturating_add(1),
            }
        }

        network.service();

        self.bridge_telemetry.ingress_moved = self
            .bridge_telemetry
            .ingress_moved
            .saturating_add(result.ingress_moved);
        self.bridge_telemetry.egress_moved = self
            .bridge_telemetry
            .egress_moved
            .saturating_add(result.egress_moved);
        self.bridge_telemetry.ingress_errors = self
            .bridge_telemetry
            .ingress_errors
            .saturating_add(result.ingress_errors);
        self.bridge_telemetry.egress_errors = self
            .bridge_telemetry
            .egress_errors
            .saturating_add(result.egress_errors);

        Ok(result)
    }

    // --- Console-friendly helpers (operate by string id, no capability needed) ---

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn for_each_object(&self, mut f: impl FnMut(&KernelObject)) {
        for obj in self.objects.values() {
            f(obj);
        }
    }

    /// Find an object by its string ID, returning a shared reference.
    pub fn for_each_object_find(&self, id: &str) -> Option<&KernelObject> {
        let key: String<MAX_ID_LEN> = String::from_str(id).unwrap_or_default();
        self.objects.get(&key)
    }

    pub fn schedule_by_id(&mut self, id: &str) -> KernelResult<()> {
        let key: String<MAX_ID_LEN> = String::from_str(id).unwrap_or_default();
        let obj = self.objects.get(&key).ok_or(KernelError::ObjectNotFound)?;
        self.scheduler.schedule(obj);
        Ok(())
    }

    pub fn send_message_direct(&mut self, to_id: &str, msg: Message) -> KernelResult<()> {
        let key: String<MAX_ID_LEN> = String::from_str(to_id).unwrap_or_default();
        let obj = self
            .objects
            .get_mut(&key)
            .ok_or(KernelError::ObjectNotFound)?;
        if obj.message_count() >= 8 {
            return Err(KernelError::MessageQueueFull);
        }
        obj.receive_message(msg)
            .map_err(|_| KernelError::MessageQueueFull)
    }

    pub fn receive_message_direct(&mut self, id: &str) -> KernelResult<Option<Message>> {
        let key: String<MAX_ID_LEN> = String::from_str(id).unwrap_or_default();
        let obj = self
            .objects
            .get_mut(&key)
            .ok_or(KernelError::ObjectNotFound)?;
        Ok(obj.pop_message())
    }

    /// If the capability carries a signature, verify it.
    ///
    /// Returns `Err(InvalidSignature)` when the signature is present but
    /// invalid; returns `Ok(())` when unsigned or when the signature checks
    /// out.
    fn check_signature(cap: &Capability) -> KernelResult<()> {
        if cap.signature.is_none() {
            return Ok(());
        }
        match cap.verify() {
            Ok(true) => Ok(()),
            Ok(false) => Err(KernelError::InvalidSignature),
            Err(_) => Err(KernelError::InvalidSignature),
        }
    }

    fn map_net_error(_err: NetError) -> KernelError {
        KernelError::NetworkError
    }

    fn bump_net_send_ok(&mut self, object_id: &str) {
        if let Some(stats) = self.net_stats_mut(object_id) {
            stats.send_ok = stats.send_ok.saturating_add(1);
        }
    }

    fn bump_net_send_err(&mut self, object_id: &str) {
        if let Some(stats) = self.net_stats_mut(object_id) {
            stats.send_err = stats.send_err.saturating_add(1);
        }
    }

    fn bump_net_recv_ok(&mut self, object_id: &str) {
        if let Some(stats) = self.net_stats_mut(object_id) {
            stats.recv_ok = stats.recv_ok.saturating_add(1);
        }
    }

    fn bump_net_recv_empty(&mut self, object_id: &str) {
        if let Some(stats) = self.net_stats_mut(object_id) {
            stats.recv_empty = stats.recv_empty.saturating_add(1);
        }
    }

    fn bump_net_recv_err(&mut self, object_id: &str) {
        if let Some(stats) = self.net_stats_mut(object_id) {
            stats.recv_err = stats.recv_err.saturating_add(1);
        }
    }

    fn net_stats_mut(&mut self, object_id: &str) -> Option<&mut NetworkCapabilityStats> {
        let key: String<MAX_ID_LEN> = String::from_str(object_id).ok()?;
        self.network_stats.get_mut(&key)
    }

    pub fn delete_by_id(&mut self, id: &str) -> KernelResult<()> {
        let key: String<MAX_ID_LEN> = String::from_str(id).unwrap_or_default();
        self.objects
            .remove(&key)
            .ok_or(KernelError::ObjectNotFound)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use crate::object::KernelObject;

    fn make_obj(name: &str, intent: &str) -> KernelObject {
        KernelObject::new_compute(name, intent)
    }

    #[test]
    fn register_object_increments_count() {
        let mut k = Kernel::new();
        assert_eq!(k.object_count(), 0);
        k.register_object(make_obj("a", "normal"));
        assert_eq!(k.object_count(), 1);
        k.register_object(make_obj("b", "batch"));
        assert_eq!(k.object_count(), 2);
    }

    #[test]
    fn execute_schedules_object_and_execute_next_drains_queue() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("worker", "low_latency"));
        k.execute(&cap).unwrap();
        assert_eq!(k.scheduler_queue_size(), 1);
        let id = k.execute_next();
        assert!(id.is_some());
        assert_eq!(k.scheduler_queue_size(), 0);
    }

    #[test]
    fn execute_requires_execute_permission() {
        let mut k = Kernel::new();
        let obj = make_obj("x", "normal");
        // Build a read-only capability manually.
        let cap = Capability::with_permissions(&obj, &[Permission::Read]);
        let _ = k.register_object(obj);
        let result = k.execute(&cap);
        assert!(matches!(result, Err(KernelError::PermissionDenied)));
    }

    #[test]
    fn execute_returns_error_for_unknown_object() {
        let mut k = Kernel::new();
        // Create a capability for an object that was never registered.
        let obj = make_obj("ghost", "normal");
        let cap = Capability::new(&obj);
        let result = k.execute(&cap);
        assert!(matches!(result, Err(KernelError::ObjectNotFound)));
    }

    #[test]
    fn send_and_receive_message_direct() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("inbox", "normal"));
        let id = cap.object_id.as_str().to_owned();

        let msg = Message::text("console", &id, "ping").unwrap();
        k.send_message_direct(&id, msg).unwrap();

        let received = k.receive_message_direct(&id).unwrap();
        assert!(received.is_some());
        let m = received.unwrap();
        assert_eq!(m.from.as_str(), "console");
    }

    #[test]
    fn message_queue_full_returns_error() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("full", "batch"));
        let id = cap.object_id.as_str().to_owned();

        for _ in 0..8 {
            let msg = Message::text("src", &id, "fill").unwrap();
            k.send_message_direct(&id, msg).unwrap();
        }
        // 9th message must fail
        let msg = Message::text("src", &id, "overflow").unwrap();
        let result = k.send_message_direct(&id, msg);
        assert!(matches!(result, Err(KernelError::MessageQueueFull)));
    }

    #[test]
    fn receive_on_empty_queue_returns_none() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("empty", "normal"));
        let id = cap.object_id.as_str().to_owned();
        let result = k.receive_message_direct(&id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn delete_by_id_removes_object() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("del", "normal"));
        let id = cap.object_id.clone();
        assert_eq!(k.object_count(), 1);
        k.delete_by_id(id.as_str()).unwrap();
        assert_eq!(k.object_count(), 0);
    }

    #[test]
    fn delete_nonexistent_returns_error() {
        let mut k = Kernel::new();
        let result = k.delete_by_id("does-not-exist");
        assert!(matches!(result, Err(KernelError::ObjectNotFound)));
    }

    #[test]
    fn schedule_by_id_on_missing_object_returns_error() {
        let mut k = Kernel::new();
        let result = k.schedule_by_id("no-such-id");
        assert!(matches!(result, Err(KernelError::ObjectNotFound)));
    }

    #[test]
    fn for_each_object_visits_all_objects() {
        let mut k = Kernel::new();
        k.register_object(make_obj("a", "normal"));
        k.register_object(make_obj("b", "batch"));
        let mut count = 0usize;
        k.for_each_object(|_| count += 1);
        assert_eq!(count, 2);
    }

    #[test]
    fn validate_capability_succeeds_for_registered_object() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("v", "normal"));
        assert!(k.validate_capability(&cap).is_ok());
    }

    #[test]
    fn validate_capability_fails_for_unknown_object() {
        let k = Kernel::new();
        let obj = make_obj("ghost", "normal");
        let cap = Capability::new(&obj);
        assert!(matches!(
            k.validate_capability(&cap),
            Err(KernelError::InvalidCapability)
        ));
    }

    #[test]
    fn network_send_and_receive_with_capability_permissions() {
        let mut k = Kernel::new();
        let obj = make_obj("net-service", "interactive");
        let mut cap = Capability::with_permissions(
            &obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        let _ = k.register_object(obj);

        let mut net = NetworkStack::new();
        net.add_loopback_interface("lo").unwrap();
        k.network_send(&cap, &mut net, "lo", b"hello").unwrap();
        net.service();
        let pkt = k.network_receive(&cap, &mut net, "lo").unwrap().unwrap();
        assert_eq!(pkt.payload.as_slice(), b"hello");

        cap.remove_permission(&Permission::ReceiveMessage);
        let denied = k.network_receive(&cap, &mut net, "lo");
        assert!(matches!(denied, Err(KernelError::PermissionDenied)));

        let stats = k.network_stats_for(cap.object_id.as_str()).unwrap();
        assert_eq!(stats.send_ok, 1);
        assert_eq!(stats.send_err, 0);
        assert_eq!(stats.recv_ok, 1);
        assert_eq!(stats.recv_err, 1);
    }

    #[test]
    fn network_receive_empty_updates_telemetry() {
        let mut k = Kernel::new();
        let obj = make_obj("net-empty", "interactive");
        let cap = Capability::with_permissions(
            &obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        let _ = k.register_object(obj);
        let mut net = NetworkStack::new();
        net.add_loopback_interface("lo").unwrap();
        let got = k.network_receive(&cap, &mut net, "lo").unwrap();
        assert!(got.is_none());
        let stats = k.network_stats_for(cap.object_id.as_str()).unwrap();
        assert_eq!(stats.recv_empty, 1);
    }

    #[test]
    fn bridge_network_to_object_delivers_data_message() {
        let mut k = Kernel::new();
        let net_obj = make_obj("net-service", "interactive");
        let net_cap = Capability::with_permissions(
            &net_obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        let _ = k.register_object(net_obj);

        let inbox_obj = make_obj("inbox", "normal");
        let inbox_cap = k.register_object(inbox_obj);
        let inbox_id = inbox_cap.object_id.as_str().to_owned();

        let mut net = NetworkStack::new();
        net.add_loopback_interface("lo").unwrap();
        k.network_send(&net_cap, &mut net, "lo", b"abc").unwrap();
        net.service();
        let moved = k
            .bridge_network_to_object(&net_cap, &mut net, "lo", &inbox_id)
            .unwrap();
        assert!(moved);

        let msg = k.receive_message_direct(&inbox_id).unwrap().unwrap();
        match msg.payload {
            MessagePayload::Data(bytes) => assert_eq!(bytes.as_slice(), b"abc"),
            _ => panic!("expected Data payload"),
        }
    }

    #[test]
    fn bridge_object_to_network_sends_text_payload() {
        let mut k = Kernel::new();
        let net_obj = make_obj("net-service", "interactive");
        let net_cap = Capability::with_permissions(
            &net_obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        let _ = k.register_object(net_obj);

        let worker_obj = make_obj("worker", "normal");
        let worker_cap = k.register_object(worker_obj);
        let worker_id = worker_cap.object_id.as_str().to_owned();
        let outbound = Message::text("src", &worker_id, "payload").unwrap();
        k.send_message_direct(&worker_id, outbound).unwrap();

        let mut net = NetworkStack::new();
        net.add_loopback_interface("lo").unwrap();
        let moved = k
            .bridge_object_to_network(&net_cap, &mut net, &worker_id, "lo")
            .unwrap();
        assert!(moved);

        net.service();
        let pkt = k
            .network_receive(&net_cap, &mut net, "lo")
            .unwrap()
            .unwrap();
        assert_eq!(pkt.payload.as_slice(), b"payload");
    }

    #[test]
    fn bridge_tick_moves_bound_ingress_and_egress() {
        let mut k = Kernel::new();
        let net_obj = make_obj("net-service", "interactive");
        let net_cap = Capability::with_permissions(
            &net_obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        let _ = k.register_object(net_obj);

        let inbox = make_obj("inbox", "normal");
        let inbox_cap = k.register_object(inbox);
        let inbox_id = inbox_cap.object_id.as_str().to_owned();

        let outbox = make_obj("outbox", "normal");
        let outbox_cap = k.register_object(outbox);
        let outbox_id = outbox_cap.object_id.as_str().to_owned();

        k.bridge_bind_ingress("lo", &inbox_id).unwrap();
        k.bridge_bind_egress(&outbox_id, "lo").unwrap();

        let mut net = NetworkStack::new();
        net.add_loopback_interface("lo").unwrap();
        k.network_send(&net_cap, &mut net, "lo", b"from-net")
            .unwrap();

        let outbound = Message::text("src", &outbox_id, "from-obj").unwrap();
        k.send_message_direct(&outbox_id, outbound).unwrap();

        let tick = k.bridge_tick(&net_cap, &mut net).unwrap();
        assert_eq!(tick.ingress_moved, 1);
        assert_eq!(tick.egress_moved, 1);

        let inbox_msg = k.receive_message_direct(&inbox_id).unwrap().unwrap();
        match inbox_msg.payload {
            MessagePayload::Data(bytes) => assert_eq!(bytes.as_slice(), b"from-net"),
            _ => panic!("expected Data payload"),
        }

        let pkt = k
            .network_receive(&net_cap, &mut net, "lo")
            .unwrap()
            .unwrap();
        assert_eq!(pkt.payload.as_slice(), b"from-obj");
    }
}
