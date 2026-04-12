// Memory object graph - tracks memory objects and their relationships
use heapless::FnvIndexMap;
use heapless::String;
use core::str::FromStr;

const MAX_OBJECTS: usize = 16;
const MAX_ID_LEN: usize = 64;

pub struct MemoryObject {
    pub object_id: String<MAX_ID_LEN>,
    pub size: usize,
    pub references: usize,
}

pub struct MemoryGraph {
    objects: FnvIndexMap<String<MAX_ID_LEN>, MemoryObject, MAX_OBJECTS>,
    total_memory: usize,
}

impl MemoryGraph {
    pub const fn new() -> Self {
        Self {
            objects: FnvIndexMap::new(),
            total_memory: 0,
        }
    }

    pub fn register_object(&mut self, object_id: &str, size: usize) {
        let id: String<MAX_ID_LEN> = String::from_str(object_id).unwrap_or_default();
        let obj = MemoryObject {
            object_id: id.clone(),
            size,
            references: 0,
        };
        
        if self.objects.insert(id, obj).is_ok() {
            self.total_memory += size;
        }
    }

    pub fn add_reference(&mut self, object_id: &str) {
        let key: String<MAX_ID_LEN> = String::from_str(object_id).unwrap_or_default();
        if let Some(obj) = self.objects.get_mut(&key) {
            obj.references += 1;
        }
    }

    pub fn remove_reference(&mut self, object_id: &str) {
        let key: String<MAX_ID_LEN> = String::from_str(object_id).unwrap_or_default();
        if let Some(obj) = self.objects.get_mut(&key) {
            if obj.references > 0 {
                obj.references -= 1;
            }
        }
    }

    pub fn remove_object(&mut self, object_id: &str) -> Option<usize> {
        let key: String<MAX_ID_LEN> = String::from_str(object_id).unwrap_or_default();
        if let Some(obj) = self.objects.remove(&key) {
            self.total_memory = self.total_memory.saturating_sub(obj.size);
            Some(obj.size)
        } else {
            None
        }
    }

    pub fn get_object_size(&self, object_id: &str) -> Option<usize> {
        let key: String<MAX_ID_LEN> = String::from_str(object_id).unwrap_or_default();
        self.objects.get(&key).map(|obj| obj.size)
    }

    pub fn total_memory(&self) -> usize {
        self.total_memory
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }
}

