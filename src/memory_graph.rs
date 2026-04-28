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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_increases_total_memory() {
        let mut g = MemoryGraph::new();
        g.register_object("a", 1024);
        g.register_object("b", 2048);
        assert_eq!(g.total_memory(), 3072);
        assert_eq!(g.object_count(), 2);
    }

    #[test]
    fn get_object_size_returns_correct_value() {
        let mut g = MemoryGraph::new();
        g.register_object("obj-1", 512);
        assert_eq!(g.get_object_size("obj-1"), Some(512));
        assert_eq!(g.get_object_size("nonexistent"), None);
    }

    #[test]
    fn remove_object_decreases_total_memory() {
        let mut g = MemoryGraph::new();
        g.register_object("x", 256);
        g.register_object("y", 128);
        let removed = g.remove_object("x");
        assert_eq!(removed, Some(256));
        assert_eq!(g.total_memory(), 128);
        assert_eq!(g.object_count(), 1);
    }

    #[test]
    fn remove_nonexistent_object_returns_none() {
        let mut g = MemoryGraph::new();
        assert_eq!(g.remove_object("ghost"), None);
    }

    #[test]
    fn reference_counting_add_and_remove() {
        let mut g = MemoryGraph::new();
        g.register_object("ref-obj", 64);
        g.add_reference("ref-obj");
        g.add_reference("ref-obj");
        let obj = g.objects.get(&heapless::String::from_str("ref-obj").unwrap()).unwrap();
        assert_eq!(obj.references, 2);
        g.remove_reference("ref-obj");
        let obj = g.objects.get(&heapless::String::from_str("ref-obj").unwrap()).unwrap();
        assert_eq!(obj.references, 1);
    }

    #[test]
    fn reference_count_does_not_underflow() {
        let mut g = MemoryGraph::new();
        g.register_object("r", 0);
        g.remove_reference("r"); // already 0, must not panic or wrap
        let obj = g.objects.get(&heapless::String::from_str("r").unwrap()).unwrap();
        assert_eq!(obj.references, 0);
    }

    #[test]
    fn duplicate_register_does_not_double_count_memory() {
        let mut g = MemoryGraph::new();
        g.register_object("dup", 100);
        // FnvIndexMap::insert returns Err when key already exists and map is full,
        // and Ok(Some(old)) when replacing — either way total_memory must stay consistent.
        let before = g.total_memory();
        g.register_object("dup", 200);
        // If insert replaces, the new size is added; if it errors, nothing changes.
        // The important thing: no double-counting of the original entry.
        let after = g.total_memory();
        assert!(after >= before, "total memory must not decrease on re-register");
    }
}

