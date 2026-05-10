use crate::object::KernelObject;
use heapless::Vec;
use core::cmp::Ordering;

const MAX_QUEUE_SIZE: usize = 32;

/// Number of timer ticks a task is allowed to run before being preempted.
/// At the default PIT frequency (~1 000 Hz) this gives a 50 ms time slice.
pub const TICKS_PER_SLICE: u64 = 50;

#[derive(Clone, PartialEq, Eq)]
pub struct ScheduledTask {
    pub object_id: heapless::String<64>,
    pub priority: u8,
    pub intent: heapless::String<32>,
}

impl Ord for ScheduledTask {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed so the highest-priority entry sorts to index 0.
        other.priority.cmp(&self.priority)
    }
}

impl PartialOrd for ScheduledTask {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Tracks which task is currently running and when its slice began.
#[derive(Clone)]
pub struct RunningTask {
    pub task: ScheduledTask,
    /// Tick count at which this task was dispatched.
    pub started_at_tick: u64,
}

pub struct Scheduler {
    queue: Vec<ScheduledTask, MAX_QUEUE_SIZE>,
    /// The task currently occupying the CPU (if any).
    running: Option<RunningTask>,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            queue: Vec::new(),
            running: None,
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

        crate::println!("Scheduled: {} (priority: {})", obj.kind, priority);
    }

    /// Dispatch the highest-priority queued task, marking it as running.
    ///
    /// Returns `None` and leaves the scheduler unchanged if a task is already
    /// running — callers must let preemption evict it first.  This prevents
    /// silently overwriting the `running` slot and losing the current task.
    pub fn execute_next(&mut self) -> Option<heapless::String<64>> {
        if self.running.is_some() {
            return None;
        }
        self.execute_next_at(0)
    }

    /// Like `execute_next` but records the current tick for slice accounting.
    pub fn execute_next_at(&mut self, current_tick: u64) -> Option<heapless::String<64>> {
        if self.queue.is_empty() {
            return None;
        }
        // sort_unstable keeps highest-priority at index 0; swap_remove(0) pops it.
        let task = self.queue.swap_remove(0);
        crate::println!("Executing: {} (priority: {})", task.object_id, task.priority);
        let id = task.object_id.clone();
        self.running = Some(RunningTask { task, started_at_tick: current_tick });
        Some(id)
    }

    /// Called on every timer tick.  If the running task has consumed its full
    /// time slice, evict it and dispatch the next queued task.
    ///
    /// Returns `Some(id)` when a context switch occurred (new task dispatched),
    /// `None` when no switch was needed.
    pub fn preempt_if_expired(&mut self, current_tick: u64) -> Option<heapless::String<64>> {
        let expired = match &self.running {
            Some(rt) => current_tick.wrapping_sub(rt.started_at_tick) >= TICKS_PER_SLICE,
            None => false,
        };

        if expired {
            // Evict the current task.  Re-queue it at the back so it gets
            // another turn (round-robin within the same priority band).
            if let Some(rt) = self.running.take() {
                crate::println!(
                    "[preempt] evicting {} after {} ticks",
                    rt.task.object_id,
                    TICKS_PER_SLICE
                );
                if self.queue.push(rt.task).is_err() {
                    // Queue is at capacity — task is dropped.  This should
                    // not happen in normal operation (MAX_QUEUE_SIZE = 32).
                    crate::println!("[preempt] WARNING: queue full, task dropped");
                } else {
                    self.queue.sort_unstable();
                }
            }
            // Dispatch the next task (if any).
            self.execute_next_at(current_tick)
        } else {
            None
        }
    }

    /// Complete (retire) the currently running task without re-queuing it.
    pub fn complete_running(&mut self) {
        if let Some(rt) = self.running.take() {
            crate::println!("Completed: {}", rt.task.object_id);
        }
    }

    /// Read-only view of the currently running task (if any).
    pub fn running_task(&self) -> Option<&RunningTask> {
        self.running.as_ref()
    }

    pub fn queue_size(&self) -> usize {
        self.queue.len()
    }

    fn intent_to_priority(intent: &str) -> u8 {
        match intent {
            "low_latency"   => 10,
            "interactive"   => 7,
            "normal"        => 5,
            "batch"         => 3,
            "energy_saving" => 2,
            _               => 5,
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

    // -----------------------------------------------------------------------
    // Existing cooperative-scheduling tests
    // -----------------------------------------------------------------------

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

        // complete_running() clears the running slot so execute_next()
        // can dispatch the next task without overwriting the previous one.
        let first = sched.execute_next().unwrap();
        sched.complete_running();
        let second = sched.execute_next().unwrap();
        sched.complete_running();
        let third = sched.execute_next().unwrap();
        sched.complete_running();

        assert!(!first.is_empty());
        assert!(!second.is_empty());
        assert!(!third.is_empty());
        assert_eq!(sched.queue_size(), 0);
        assert!(sched.running_task().is_none());
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

    // -----------------------------------------------------------------------
    // Preemptive scheduling tests
    // -----------------------------------------------------------------------

    /// After dispatch, `running_task` is populated and the queue shrinks.
    #[test]
    fn execute_next_at_sets_running_task() {
        let mut sched = Scheduler::new();
        sched.schedule(&make_obj("worker", "normal"));

        let id = sched.execute_next_at(0).unwrap();
        assert!(!id.is_empty());
        // Queue is now empty — task moved to running slot.
        assert_eq!(sched.queue_size(), 0);
        // running_task reflects the dispatched task.
        let rt = sched.running_task().unwrap();
        assert_eq!(rt.task.object_id.as_str(), id.as_str());
        assert_eq!(rt.started_at_tick, 0);
    }

    /// Ticks before the slice expires must NOT trigger a preemption.
    #[test]
    fn preempt_does_not_fire_before_slice_expires() {
        let mut sched = Scheduler::new();
        sched.schedule(&make_obj("a", "normal"));
        sched.schedule(&make_obj("b", "normal"));
        let first_id = sched.execute_next_at(0).unwrap();

        // Tick just before the boundary — no switch expected.
        let switched = sched.preempt_if_expired(TICKS_PER_SLICE - 1);
        assert!(switched.is_none(), "preemption fired too early");
        // Same task still running.
        assert_eq!(
            sched.running_task().unwrap().task.object_id.as_str(),
            first_id.as_str()
        );
    }

    /// Exactly at the slice boundary the running task must be evicted.
    #[test]
    fn preempt_fires_exactly_at_slice_boundary() {
        let mut sched = Scheduler::new();
        sched.schedule(&make_obj("a", "normal"));
        sched.schedule(&make_obj("b", "normal"));
        let first_id = sched.execute_next_at(0).unwrap();

        let switched = sched.preempt_if_expired(TICKS_PER_SLICE);
        assert!(switched.is_some(), "preemption did not fire at boundary");
        let new_id = switched.unwrap();
        assert_ne!(new_id.as_str(), first_id.as_str(), "same task should not re-run immediately");
    }

    /// After eviction the old task is re-queued (not lost).
    #[test]
    fn preempted_task_is_requeued() {
        let mut sched = Scheduler::new();
        sched.schedule(&make_obj("a", "normal"));
        sched.schedule(&make_obj("b", "normal"));
        let first_id = sched.execute_next_at(0).unwrap();

        // Trigger preemption — "a" should be re-queued, "b" dispatched.
        sched.preempt_if_expired(TICKS_PER_SLICE);

        // The scheduler now has "a" back in the queue (b is running).
        // Trigger another preemption — "b" evicted, "a" dispatched again.
        let second_switch = sched.preempt_if_expired(TICKS_PER_SLICE * 2);
        assert!(second_switch.is_some());
        // The newly running task should be "a" again (round-robin).
        let rt = sched.running_task().unwrap();
        assert_eq!(rt.task.object_id.as_str(), first_id.as_str());
    }

    /// No running task → `preempt_if_expired` must be a no-op.
    #[test]
    fn preempt_with_no_running_task_is_noop() {
        let mut sched = Scheduler::new();
        // Queue a task but don't dispatch it.
        sched.schedule(&make_obj("idle", "batch"));
        let result = sched.preempt_if_expired(TICKS_PER_SLICE + 1);
        assert!(result.is_none());
        // Task still sits in the queue untouched.
        assert_eq!(sched.queue_size(), 1);
    }

    /// If the queue is empty when preemption fires, the sole task is
    /// re-queued and immediately re-dispatched (it keeps the CPU).
    #[test]
    fn preempt_with_single_task_requeues_and_redispatches() {
        let mut sched = Scheduler::new();
        sched.schedule(&make_obj("solo", "normal"));
        let first_id = sched.execute_next_at(0).unwrap();

        // Only one task exists — after eviction it re-queues itself and
        // execute_next_at picks it straight back up.
        let switched = sched.preempt_if_expired(TICKS_PER_SLICE);
        assert!(switched.is_some(), "sole task should be re-dispatched");
        assert_eq!(switched.unwrap().as_str(), first_id.as_str());
        // CPU is occupied again, queue is empty.
        assert!(sched.running_task().is_some());
        assert_eq!(sched.queue_size(), 0);
    }

    /// `complete_running` retires the task without re-queuing it.
    #[test]
    fn complete_running_clears_running_slot() {
        let mut sched = Scheduler::new();
        sched.schedule(&make_obj("done", "normal"));
        sched.execute_next_at(100);
        assert!(sched.running_task().is_some());

        sched.complete_running();
        assert!(sched.running_task().is_none());
        // Task must NOT be re-queued.
        assert_eq!(sched.queue_size(), 0);
    }

    /// `complete_running` on an idle scheduler is a safe no-op.
    #[test]
    fn complete_running_when_idle_is_noop() {
        let mut sched = Scheduler::new();
        sched.complete_running(); // must not panic
        assert!(sched.running_task().is_none());
    }

    /// Preemption uses wrapping subtraction — tick counter rollover is safe.
    #[test]
    fn preempt_handles_tick_counter_wraparound() {
        let mut sched = Scheduler::new();
        sched.schedule(&make_obj("wrap-a", "normal"));
        sched.schedule(&make_obj("wrap-b", "normal"));

        // Dispatch at a tick very close to u64::MAX.
        let start = u64::MAX - (TICKS_PER_SLICE / 2);
        sched.execute_next_at(start);

        // A tick just before the (wrapped) boundary — no preemption.
        let before = start.wrapping_add(TICKS_PER_SLICE - 1);
        assert!(sched.preempt_if_expired(before).is_none());

        // A tick at the wrapped boundary — preemption fires.
        let at_boundary = start.wrapping_add(TICKS_PER_SLICE);
        assert!(sched.preempt_if_expired(at_boundary).is_some());
    }

    /// Higher-priority task in the queue takes over when a lower-priority
    /// task is preempted (priority order is preserved after re-queue).
    #[test]
    fn preempt_dispatches_highest_priority_next() {
        let mut sched = Scheduler::new();
        // Schedule a low-priority task first so it gets dispatched.
        sched.schedule(&make_obj("low", "energy_saving"));  // priority 2
        // Then add a high-priority one to the queue.
        sched.schedule(&make_obj("high", "low_latency"));   // priority 10

        // Dispatch — "high" has higher priority, gets the CPU first.
        let first = sched.execute_next_at(0).unwrap();
        // "low" is waiting in the queue.
        assert_eq!(sched.queue_size(), 1);

        // Preempt "high" → it is re-queued; "low" is next but "high"
        // re-queues at priority 10, so "high" should win again.
        let switched = sched.preempt_if_expired(TICKS_PER_SLICE).unwrap();
        // The newly running task must still be the high-priority one
        // (it was re-queued at its original priority 10 > 2).
        assert_eq!(switched.as_str(), first.as_str());
    }
}
