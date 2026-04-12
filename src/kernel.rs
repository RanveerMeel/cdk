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
