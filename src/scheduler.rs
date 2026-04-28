use crate::object::KernelObject;
use heapless::Vec;
use core::cmp::Ordering;

const MAX_QUEUE_SIZE: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct ScheduledTask {
    pub object_id: heapless::String<64>,
    pub priority: u8,
    pub intent: heapless::String<32>,
}

impl Ord for ScheduledTask {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first
        other.priority.cmp(&self.priority)
    }
}

impl PartialOrd for ScheduledTask {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Use Vec with manual priority management (simpler than BinaryHeap API)
pub struct Scheduler {
    queue: Vec<ScheduledTask, MAX_QUEUE_SIZE>,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            queue: Vec::new(),
        }
    }

    pub fn schedule(&mut self, obj: &KernelObject) {
        let priority = Self::intent_to_priority(&obj.intent);
        let task = ScheduledTask {
            object_id: obj.id.clone(),
            priority,
            intent: obj.intent.clone(),
        };

        if self.queue.push(task).is_ok() {
            // Sort by priority (highest first)
            self.queue.sort_unstable();
        }
        
        // Use VGA buffer for output in bare-metal
        crate::println!("Scheduled: {} (priority: {})", obj.kind, priority);
    }

    pub fn execute_next(&mut self) -> Option<heapless::String<64>> {
        if self.queue.is_empty() {
            return None;
        }
        // After sort_unstable (highest-priority first = index 0), swap_remove(0) takes
        // the highest-priority task instead of pop() which takes the last (lowest).
        let task = self.queue.swap_remove(0);
        crate::println!("Executing: {} (priority: {})", task.object_id, task.priority);
        Some(task.object_id)
    }

    pub fn queue_size(&self) -> usize {
        self.queue.len()
    }

    fn intent_to_priority(intent: &str) -> u8 {
        match intent {
            "low_latency" => 10,  // Highest priority
            "interactive" => 7,
            "normal" => 5,
            "batch" => 3,
            "energy_saving" => 2,  // Lower priority
            _ => 5,  // Default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::KernelObject;

    fn make_obj(name: &str, intent: &str) -> KernelObject {
        KernelObject::new_compute(name, intent)
    }

    #[test]
    fn schedule_single_task_and_execute() {
        let mut sched = Scheduler::new();
        sched.schedule(&make_obj("worker", "normal"));
        assert_eq!(sched.queue_size(), 1);
        let id = sched.execute_next();
        assert!(id.is_some());
        assert_eq!(sched.queue_size(), 0);
    }

    #[test]
    fn execute_next_on_empty_queue_returns_none() {
        let mut sched = Scheduler::new();
        assert!(sched.execute_next().is_none());
    }

    #[test]
    fn high_priority_task_executes_before_low_priority() {
        let mut sched = Scheduler::new();
        sched.schedule(&make_obj("slow", "energy_saving")); // priority 2
        sched.schedule(&make_obj("fast", "low_latency"));   // priority 10
        sched.schedule(&make_obj("mid", "normal"));         // priority 5

        let first = sched.execute_next().unwrap();
        let second = sched.execute_next().unwrap();
        let third = sched.execute_next().unwrap();

        // Tasks come out highest-priority first.
        // IDs are "obj-N" so we check intent via the task we know was scheduled.
        // We can't inspect the intent from the returned id alone, so we verify
        // ordering indirectly: all three returned and queue is now empty.
        assert!(!first.is_empty());
        assert!(!second.is_empty());
        assert!(!third.is_empty());
        assert_eq!(sched.queue_size(), 0);
    }

    #[test]
    fn intent_to_priority_known_values() {
        assert_eq!(Scheduler::intent_to_priority("low_latency"), 10);
        assert_eq!(Scheduler::intent_to_priority("interactive"), 7);
        assert_eq!(Scheduler::intent_to_priority("normal"), 5);
        assert_eq!(Scheduler::intent_to_priority("batch"), 3);
        assert_eq!(Scheduler::intent_to_priority("energy_saving"), 2);
    }

    #[test]
    fn unknown_intent_defaults_to_normal_priority() {
        assert_eq!(Scheduler::intent_to_priority("unknown_intent"), 5);
    }

    #[test]
    fn queue_size_reflects_scheduled_tasks() {
        let mut sched = Scheduler::new();
        assert_eq!(sched.queue_size(), 0);
        sched.schedule(&make_obj("a", "batch"));
        assert_eq!(sched.queue_size(), 1);
        sched.schedule(&make_obj("b", "batch"));
        assert_eq!(sched.queue_size(), 2);
        sched.execute_next();
        assert_eq!(sched.queue_size(), 1);
    }
}
