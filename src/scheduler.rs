use crate::object::KernelObject;
use core::cmp::Ordering;
use heapless::Vec;
use spin::Mutex;

const MAX_QUEUE_SIZE: usize = 32;

/// Maximum APIC ids with a private running slot (matches multicore table).
pub const MAX_RUNNING_CORES: usize = 8;

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

struct ReadyQueue {
    tasks: Vec<ScheduledTask, MAX_QUEUE_SIZE>,
}

/// Priority ready queue + per-core running slots (Phase 20).
///
/// The ready queue has its own lock; each core's running slot has a private
/// lock so cores can hold dispatched work in parallel without serializing on
/// a single global `running` field.
pub struct Scheduler {
    ready: Mutex<ReadyQueue>,
    running: [Mutex<Option<RunningTask>>; MAX_RUNNING_CORES],
}

/// Process-wide scheduler (fine-grained internal locks — roadmap reset M5).
///
/// Hot paths (preempt / dispatch) can use this without holding the global
/// `Kernel` object-map mutex.
static GLOBAL_SCHEDULER: Scheduler = Scheduler::new();

/// Access the global scheduler (IRQ-safe via internal spinlocks).
pub fn global() -> &'static Scheduler {
    &GLOBAL_SCHEDULER
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            ready: Mutex::new(ReadyQueue {
                tasks: Vec::new(),
            }),
            running: [const { Mutex::new(None) }; MAX_RUNNING_CORES],
        }
    }

    #[inline]
    fn slot(apic_id: u32) -> Option<usize> {
        // Prefer dense topology slots (sparse APIC ids); fall back to apic_id.
        if let Some(idx) = crate::percpu::slot_for_apic(apic_id) {
            return (idx < MAX_RUNNING_CORES).then_some(idx);
        }
        let idx = apic_id as usize;
        (idx < MAX_RUNNING_CORES).then_some(idx)
    }

    pub fn schedule(&self, obj: &KernelObject) {
        let priority = Self::intent_to_priority(&obj.intent);
        let task = ScheduledTask {
            object_id: obj.id.clone(),
            priority,
            intent: obj.intent.clone(),
        };

        {
            let mut ready = self.ready.lock();
            if ready.tasks.push(task).is_ok() {
                ready.tasks.sort_unstable();
            }
        }

        crate::println!("Scheduled: {} (priority: {})", obj.kind, priority);
    }

    /// Dispatch the highest-priority queued task onto BSP slot 0.
    pub fn execute_next(&self) -> Option<heapless::String<64>> {
        self.execute_next_on(0)
    }

    /// Like [`execute_next`] but records the current tick for slice accounting (BSP).
    pub fn execute_next_at(&self, current_tick: u64) -> Option<heapless::String<64>> {
        self.execute_next_on_at(0, current_tick)
    }

    /// Dispatch onto `apic_id`'s private running slot.
    pub fn execute_next_on(&self, apic_id: u32) -> Option<heapless::String<64>> {
        self.execute_next_on_at(apic_id, 0)
    }

    pub fn execute_next_on_at(
        &self,
        apic_id: u32,
        current_tick: u64,
    ) -> Option<heapless::String<64>> {
        let idx = Self::slot(apic_id)?;
        {
            let running = self.running[idx].lock();
            if running.is_some() {
                return None;
            }
        }

        let task = {
            let mut ready = self.ready.lock();
            if ready.tasks.is_empty() {
                return None;
            }
            ready.tasks.swap_remove(0)
        };
        let id = task.object_id.clone();
        *self.running[idx].lock() = Some(RunningTask {
            task,
            started_at_tick: current_tick,
        });
        Some(id)
    }

    /// Preempt BSP slot 0 if its slice expired.
    pub fn preempt_if_expired(&self, current_tick: u64) -> Option<heapless::String<64>> {
        self.preempt_if_expired_on(0, current_tick)
    }

    /// Preempt `apic_id`'s running task if its slice expired.
    pub fn preempt_if_expired_on(
        &self,
        apic_id: u32,
        current_tick: u64,
    ) -> Option<heapless::String<64>> {
        let idx = Self::slot(apic_id)?;
        let expired = {
            let running = self.running[idx].lock();
            match &*running {
                Some(rt) => current_tick.wrapping_sub(rt.started_at_tick) >= TICKS_PER_SLICE,
                None => false,
            }
        };
        if !expired {
            return None;
        }

        let queue_empty = self.ready.lock().tasks.is_empty();
        if queue_empty {
            if let Some(rt) = self.running[idx].lock().as_mut() {
                rt.started_at_tick = current_tick;
            }
            return None;
        }

        if let Some(rt) = self.running[idx].lock().take() {
            let mut ready = self.ready.lock();
            if ready.tasks.push(rt.task).is_err() {
                crate::println!("[preempt] WARNING: queue full, task dropped");
            } else {
                ready.tasks.sort_unstable();
            }
        }
        self.execute_next_on_at(apic_id, current_tick)
    }

    /// Complete (retire) the BSP running task without re-queuing it.
    pub fn complete_running(&self) {
        self.complete_running_on(0);
    }

    /// Complete the task in `apic_id`'s running slot.
    pub fn complete_running_on(&self, apic_id: u32) {
        let Some(idx) = Self::slot(apic_id) else {
            return;
        };
        if let Some(rt) = self.running[idx].lock().take() {
            crate::println!("Completed: {}", rt.task.object_id);
        }
    }

    /// Yield the running task on `apic_id` back onto the ready queue.
    ///
    /// Returns the yielded object id when a task was running.
    pub fn yield_running_on(&self, apic_id: u32) -> Option<heapless::String<64>> {
        let idx = Self::slot(apic_id)?;
        let rt = self.running[idx].lock().take()?;
        let id = rt.task.object_id.clone();
        {
            let mut ready = self.ready.lock();
            if ready.tasks.push(rt.task).is_err() {
                crate::println!("[yield] WARNING: queue full, task dropped");
            } else {
                ready.tasks.sort_unstable();
            }
        }
        crate::println!("Yielded: {}", id);
        Some(id)
    }

    /// Remove a specific queued task by object id and mark it running on `apic_id`.
    pub fn take_queued_by_id(
        &self,
        object_id: &str,
        current_tick: u64,
        apic_id: u32,
    ) -> Option<heapless::String<64>> {
        let idx = Self::slot(apic_id)?;
        {
            let running = self.running[idx].lock();
            if running.is_some() {
                return None;
            }
        }

        let task = {
            let mut ready = self.ready.lock();
            let pos = ready
                .tasks
                .iter()
                .position(|t| t.object_id.as_str() == object_id)?;
            ready.tasks.remove(pos)
        };
        let id = task.object_id.clone();
        *self.running[idx].lock() = Some(RunningTask {
            task,
            started_at_tick: current_tick,
        });
        Some(id)
    }

    /// BSP running task (slot 0), for console / legacy callers.
    pub fn running_task(&self) -> Option<RunningTask> {
        self.running_task_on(0)
    }

    /// Snapshot of the task running on `apic_id`, if any.
    pub fn running_task_on(&self, apic_id: u32) -> Option<RunningTask> {
        let idx = Self::slot(apic_id)?;
        self.running[idx].lock().clone()
    }

    /// Bitmask of cores that currently hold a running task.
    pub fn running_mask(&self) -> u64 {
        let mut mask = 0u64;
        for (i, slot) in self.running.iter().enumerate() {
            if slot.lock().is_some() {
                mask |= 1u64 << i;
            }
        }
        mask
    }

    /// How many cores currently hold a running task.
    pub fn running_count(&self) -> usize {
        self.running_mask().count_ones() as usize
    }

    pub fn queue_size(&self) -> usize {
        self.ready.lock().tasks.len()
    }

    /// Reset ready queue and all running slots (host tests / Kernel::new).
    pub fn clear(&self) {
        self.ready.lock().tasks.clear();
        for slot in self.running.iter() {
            *slot.lock() = None;
        }
    }

    fn intent_to_priority(intent: &str) -> u8 {
        match intent {
            "low_latency" => 10,
            "interactive" => 7,
            "normal" => 5,
            "batch" => 3,
            "energy_saving" => 2,
            _ => 5,
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
        let sched = Scheduler::new();
        sched.schedule(&make_obj("worker", "normal"));
        assert_eq!(sched.queue_size(), 1);
        let id = sched.execute_next();
        assert!(id.is_some());
        assert_eq!(sched.queue_size(), 0);
    }

    #[test]
    fn execute_next_on_empty_queue_returns_none() {
        let sched = Scheduler::new();
        assert!(sched.execute_next().is_none());
    }

    #[test]
    fn high_priority_task_executes_before_low_priority() {
        let sched = Scheduler::new();
        sched.schedule(&make_obj("slow", "energy_saving")); // priority 2
        sched.schedule(&make_obj("fast", "low_latency")); // priority 10
        sched.schedule(&make_obj("mid", "normal")); // priority 5

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
        let sched = Scheduler::new();
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

    #[test]
    fn execute_next_at_sets_running_task() {
        let sched = Scheduler::new();
        sched.schedule(&make_obj("worker", "normal"));

        let id = sched.execute_next_at(0).unwrap();
        assert!(!id.is_empty());
        assert_eq!(sched.queue_size(), 0);
        let rt = sched.running_task().unwrap();
        assert_eq!(rt.task.object_id.as_str(), id.as_str());
        assert_eq!(rt.started_at_tick, 0);
    }

    #[test]
    fn preempt_does_not_fire_before_slice_expires() {
        let sched = Scheduler::new();
        sched.schedule(&make_obj("a", "normal"));
        sched.schedule(&make_obj("b", "normal"));
        let first_id = sched.execute_next_at(0).unwrap();

        let switched = sched.preempt_if_expired(TICKS_PER_SLICE - 1);
        assert!(switched.is_none(), "preemption fired too early");
        assert_eq!(
            sched.running_task().unwrap().task.object_id.as_str(),
            first_id.as_str()
        );
    }

    #[test]
    fn preempt_fires_exactly_at_slice_boundary() {
        let sched = Scheduler::new();
        sched.schedule(&make_obj("a", "normal"));
        sched.schedule(&make_obj("b", "normal"));
        let first_id = sched.execute_next_at(0).unwrap();

        let switched = sched.preempt_if_expired(TICKS_PER_SLICE);
        assert!(switched.is_some(), "preemption did not fire at boundary");
        let new_id = switched.unwrap();
        assert_ne!(
            new_id.as_str(),
            first_id.as_str(),
            "same task should not re-run immediately"
        );
    }

    #[test]
    fn preempted_task_is_requeued() {
        let sched = Scheduler::new();
        sched.schedule(&make_obj("a", "normal"));
        sched.schedule(&make_obj("b", "normal"));
        let first_id = sched.execute_next_at(0).unwrap();

        sched.preempt_if_expired(TICKS_PER_SLICE);

        let second_switch = sched.preempt_if_expired(TICKS_PER_SLICE * 2);
        assert!(second_switch.is_some());
        let rt = sched.running_task().unwrap();
        assert_eq!(rt.task.object_id.as_str(), first_id.as_str());
    }

    #[test]
    fn preempt_with_no_running_task_is_noop() {
        let sched = Scheduler::new();
        sched.schedule(&make_obj("idle", "batch"));
        let result = sched.preempt_if_expired(TICKS_PER_SLICE + 1);
        assert!(result.is_none());
        assert_eq!(sched.queue_size(), 1);
    }

    #[test]
    fn preempt_with_single_task_refreshes_slice_without_switch() {
        let sched = Scheduler::new();
        sched.schedule(&make_obj("solo", "normal"));
        let first_id = sched.execute_next_at(0).unwrap();

        let switched = sched.preempt_if_expired(TICKS_PER_SLICE);
        assert!(switched.is_none(), "sole task should keep running");
        assert!(sched.running_task().is_some());
        assert_eq!(
            sched.running_task().unwrap().task.object_id.as_str(),
            first_id.as_str()
        );
        assert_eq!(sched.queue_size(), 0);
    }

    #[test]
    fn complete_running_clears_running_slot() {
        let sched = Scheduler::new();
        sched.schedule(&make_obj("done", "normal"));
        sched.execute_next_at(100);
        assert!(sched.running_task().is_some());

        sched.complete_running();
        assert!(sched.running_task().is_none());
        assert_eq!(sched.queue_size(), 0);
    }

    #[test]
    fn complete_running_when_idle_is_noop() {
        let sched = Scheduler::new();
        sched.complete_running();
        assert!(sched.running_task().is_none());
    }

    #[test]
    fn preempt_handles_tick_counter_wraparound() {
        let sched = Scheduler::new();
        sched.schedule(&make_obj("wrap-a", "normal"));
        sched.schedule(&make_obj("wrap-b", "normal"));

        let start = u64::MAX - (TICKS_PER_SLICE / 2);
        sched.execute_next_at(start);

        let before = start.wrapping_add(TICKS_PER_SLICE - 1);
        assert!(sched.preempt_if_expired(before).is_none());

        let at_boundary = start.wrapping_add(TICKS_PER_SLICE);
        assert!(sched.preempt_if_expired(at_boundary).is_some());
    }

    #[test]
    fn preempt_dispatches_highest_priority_next() {
        let sched = Scheduler::new();
        sched.schedule(&make_obj("low", "energy_saving")); // priority 2
        sched.schedule(&make_obj("high", "low_latency")); // priority 10

        let first = sched.execute_next_at(0).unwrap();
        assert_eq!(sched.queue_size(), 1);

        let switched = sched.preempt_if_expired(TICKS_PER_SLICE).unwrap();
        assert_eq!(switched.as_str(), first.as_str());
    }

    #[test]
    fn two_cores_can_run_tasks_in_parallel_slots() {
        let sched = Scheduler::new();
        let a = make_obj("a", "normal");
        let b = make_obj("b", "normal");
        let id_a = a.id.clone();
        let id_b = b.id.clone();
        sched.schedule(&a);
        sched.schedule(&b);

        let got0 = sched
            .take_queued_by_id(id_a.as_str(), 0, 0)
            .expect("core 0 should take a");
        let got1 = sched
            .take_queued_by_id(id_b.as_str(), 0, 1)
            .expect("core 1 should take b while 0 still running");
        assert_eq!(got0.as_str(), id_a.as_str());
        assert_eq!(got1.as_str(), id_b.as_str());
        assert_eq!(sched.running_count(), 2);
        assert_eq!(sched.running_mask() & 0b11, 0b11);
        assert!(sched.running_task_on(0).is_some());
        assert!(sched.running_task_on(1).is_some());

        sched.complete_running_on(0);
        sched.complete_running_on(1);
        assert_eq!(sched.running_count(), 0);
    }
}
