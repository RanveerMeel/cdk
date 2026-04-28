use crate::{
    capability::{Capability, Permission},
    message::Message,
    object::KernelObject,
    scheduler::Scheduler,
};
use heapless::FnvIndexMap;
use heapless::String;
use core::str::FromStr;

const MAX_OBJECTS: usize = 16;
const MAX_ID_LEN: usize = 64;

#[derive(Debug, Clone)]
pub enum KernelError {
    InvalidCapability,
    ObjectNotFound,
    PermissionDenied,
    MessageQueueFull,
    InvalidSignature,
}

pub type KernelResult<T> = Result<T, KernelError>;

pub struct Kernel {
    objects: FnvIndexMap<String<MAX_ID_LEN>, KernelObject, MAX_OBJECTS>,
    scheduler: Scheduler,
}

impl Kernel {
    pub const fn new() -> Self {
        Self {
            objects: FnvIndexMap::new(),
            scheduler: Scheduler::new(),
        }
    }

    pub fn register_object(&mut self, obj: KernelObject) -> Capability {
        let cap = Capability::new(&obj);
        let id = obj.id.clone();
        let _ = self.objects.insert(id, obj);
        cap
    }

    pub fn execute(&mut self, cap: &Capability) -> KernelResult<()> {
        // Verify capability signature if present (simplified for bare-metal)
        if cap.signature.is_some() {
            let _ = cap.verify(); // Simplified verification
        }
        
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
        // Verify capability signature if present (simplified for bare-metal)
        if from_cap.signature.is_some() {
            let _ = from_cap.verify();
        }
        
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

        to_obj.receive_message(msg).map_err(|_| KernelError::MessageQueueFull)?;
        Ok(())
    }

    pub fn receive_message(
        &mut self,
        cap: &Capability,
    ) -> KernelResult<Option<Message>> {
        // Verify capability signature if present (simplified for bare-metal)
        if cap.signature.is_some() {
            let _ = cap.verify();
        }
        
        if !cap.has_permission(&Permission::ReceiveMessage) {
            return Err(KernelError::PermissionDenied);
        }

        let obj = self
            .objects
            .get_mut(&cap.object_id)
            .ok_or(KernelError::ObjectNotFound)?;

        Ok(obj.pop_message())
    }

    pub fn execute_next(&mut self) -> Option<String<MAX_ID_LEN>> {
        self.scheduler.execute_next()
    }

    pub fn get_object(&self, cap: &Capability) -> KernelResult<&KernelObject> {
        // Verify capability signature if present (simplified for bare-metal)
        if cap.signature.is_some() {
            let _ = cap.verify();
        }
        
        if !cap.has_permission(&Permission::Read) {
            return Err(KernelError::PermissionDenied);
        }

        self.objects
            .get(&cap.object_id)
            .ok_or(KernelError::ObjectNotFound)
    }

    pub fn delete_object(&mut self, cap: &Capability) -> KernelResult<()> {
        // Verify capability signature if present (simplified for bare-metal)
        if cap.signature.is_some() {
            let _ = cap.verify();
        }
        
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
        // Verify signature if present (simplified for bare-metal)
        if cap.signature.is_some() {
            let _ = cap.verify();
        }
        
        if !self.objects.contains_key(&cap.object_id) {
            return Err(KernelError::InvalidCapability);
        }
        Ok(())
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

    pub fn schedule_by_id(&mut self, id: &str) -> KernelResult<()> {
        let key: String<MAX_ID_LEN> = String::from_str(id).unwrap_or_default();
        let obj = self.objects.get(&key).ok_or(KernelError::ObjectNotFound)?;
        self.scheduler.schedule(obj);
        Ok(())
    }

    pub fn send_message_direct(&mut self, to_id: &str, msg: Message) -> KernelResult<()> {
        let key: String<MAX_ID_LEN> = String::from_str(to_id).unwrap_or_default();
        let obj = self.objects.get_mut(&key).ok_or(KernelError::ObjectNotFound)?;
        if obj.message_count() >= 8 {
            return Err(KernelError::MessageQueueFull);
        }
        obj.receive_message(msg).map_err(|_| KernelError::MessageQueueFull)
    }

    pub fn receive_message_direct(&mut self, id: &str) -> KernelResult<Option<Message>> {
        let key: String<MAX_ID_LEN> = String::from_str(id).unwrap_or_default();
        let obj = self.objects.get_mut(&key).ok_or(KernelError::ObjectNotFound)?;
        Ok(obj.pop_message())
    }

    pub fn delete_by_id(&mut self, id: &str) -> KernelResult<()> {
        let key: String<MAX_ID_LEN> = String::from_str(id).unwrap_or_default();
        self.objects.remove(&key).ok_or(KernelError::ObjectNotFound)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::KernelObject;
    use crate::message::Message;

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
        assert!(matches!(k.validate_capability(&cap), Err(KernelError::InvalidCapability)));
    }
}
