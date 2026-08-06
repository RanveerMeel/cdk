//! Kernel thread context switch (M10).

use core::sync::atomic::{AtomicU32, Ordering};
use heapless::String;
use spin::Mutex;

const MAX_THREADS: usize = 16;
const THREAD_STACK_SIZE: usize = 8 * 1024;
const MAX_ID_LEN: usize = 64;

/// Callee-saved registers + control state for cooperative kernel switches.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuContext {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Free,
    Ready,
    Running,
    Done,
}

pub struct Thread {
    pub id: u16,
    pub state: ThreadState,
    pub object_id: String<MAX_ID_LEN>,
    pub apic_id: u32,
    pub context: CpuContext,
    pub stack_top: u64,
}

struct ThreadTable {
    threads: [Option<Thread>; MAX_THREADS],
    stacks: [[u8; THREAD_STACK_SIZE]; MAX_THREADS],
}

static TABLE: Mutex<ThreadTable> = Mutex::new(ThreadTable {
    threads: [const { None }; MAX_THREADS],
    stacks: [[0u8; THREAD_STACK_SIZE]; MAX_THREADS],
});

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

static IDLE_CTX: Mutex<[CpuContext; 8]> = Mutex::new([CpuContext {
    r15: 0,
    r14: 0,
    r13: 0,
    r12: 0,
    rbx: 0,
    rbp: 0,
    rip: 0,
    rsp: 0,
    rflags: 0x202,
}; 8]);

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .global cdk_switch_context
    .type cdk_switch_context, @function
    cdk_switch_context:
        mov [rdi + 0x00], r15
        mov [rdi + 0x08], r14
        mov [rdi + 0x10], r13
        mov [rdi + 0x18], r12
        mov [rdi + 0x20], rbx
        mov [rdi + 0x28], rbp
        lea rax, [rip + 2f]
        mov [rdi + 0x30], rax
        mov [rdi + 0x38], rsp
        pushfq
        pop rax
        mov [rdi + 0x40], rax
        mov r15, [rsi + 0x00]
        mov r14, [rsi + 0x08]
        mov r13, [rsi + 0x10]
        mov r12, [rsi + 0x18]
        mov rbx, [rsi + 0x20]
        mov rbp, [rsi + 0x28]
        mov rsp, [rsi + 0x38]
        mov rax, [rsi + 0x40]
        push rax
        popfq
        mov rax, [rsi + 0x30]
        jmp rax
    2:
        ret
    "#
);

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn cdk_switch_context(old: *mut CpuContext, new: *mut CpuContext);
}

/// Allocate a kernel thread that starts at `entry` with `object_id` metadata.
pub fn spawn_kernel_thread(apic_id: u32, object_id: &str, entry: u64) -> Option<u16> {
    let mut table = TABLE.lock();
    let slot = table.threads.iter().position(|t| t.is_none())?;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed) as u16;
    let stack = &mut table.stacks[slot];
    let stack_top = (stack.as_mut_ptr() as u64 + THREAD_STACK_SIZE as u64) & !0xfu64;

    let mut oid = String::new();
    let _ = oid.push_str(object_id);
    table.threads[slot] = Some(Thread {
        id,
        state: ThreadState::Ready,
        object_id: oid,
        apic_id,
        context: CpuContext {
            rip: entry,
            rsp: stack_top,
            rflags: 0x202,
            ..CpuContext::default()
        },
        stack_top,
    });
    Some(id)
}

pub fn thread_stack_top(thread_id: u16) -> Option<u64> {
    let table = TABLE.lock();
    table
        .threads
        .iter()
        .flatten()
        .find(|t| t.id == thread_id)
        .map(|t| t.stack_top)
}

pub fn mark_running(thread_id: u16) {
    let mut table = TABLE.lock();
    if let Some(t) = table.threads.iter_mut().flatten().find(|t| t.id == thread_id) {
        t.state = ThreadState::Running;
    }
}

pub fn mark_done(thread_id: u16) {
    let mut table = TABLE.lock();
    if let Some(slot) = table
        .threads
        .iter()
        .position(|t| t.as_ref().map(|x| x.id) == Some(thread_id))
    {
        table.threads[slot] = None;
    }
}

/// Switch from the idle context of topology `slot` into `thread_id`.
pub fn switch_to_thread(slot: usize, thread_id: u16) {
    #[cfg(target_os = "none")]
    {
        let mut table = TABLE.lock();
        let Some(thread) = table
            .threads
            .iter_mut()
            .flatten()
            .find(|t| t.id == thread_id)
        else {
            return;
        };
        thread.state = ThreadState::Running;
        let new_ctx = &mut thread.context as *mut CpuContext;
        drop(table);
        let mut idles = IDLE_CTX.lock();
        if slot >= idles.len() {
            return;
        }
        let old = &mut idles[slot] as *mut CpuContext;
        unsafe {
            cdk_switch_context(old, new_ctx);
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = slot;
        mark_running(thread_id);
    }
}

/// Switch from `thread_id` back to the idle context of `slot`.
pub fn switch_to_idle(slot: usize, thread_id: u16) {
    #[cfg(target_os = "none")]
    {
        let mut table = TABLE.lock();
        let Some(thread) = table
            .threads
            .iter_mut()
            .flatten()
            .find(|t| t.id == thread_id)
        else {
            return;
        };
        let old = &mut thread.context as *mut CpuContext;
        drop(table);
        let mut idles = IDLE_CTX.lock();
        if slot >= idles.len() {
            return;
        }
        let new_ctx = &mut idles[slot] as *mut CpuContext;
        unsafe {
            cdk_switch_context(old, new_ctx);
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = slot;
        mark_done(thread_id);
    }
}

/// Entry RIP for spawned compute threads: complete scheduler slot then return to idle.
pub extern "C" fn compute_thread_entry() -> ! {
    let apic = crate::percpu::current_apic_id();
    let slot = crate::percpu::slot_for_apic(apic).unwrap_or(0);
    let tid = crate::percpu::current_local()
        .map(|l| l.current_thread as u16)
        .unwrap_or(0);
    crate::scheduler::global().complete_running_on(apic);
    crate::percpu::set_current_thread(slot, None);
    if tid != 0 {
        switch_to_idle(slot, tid);
        mark_done(tid);
    }
    loop {
        unsafe {
            core::arch::asm!("sti; hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Prepare a thread + RSP0 for a newly dispatched object on `apic_id`.
pub fn prepare_dispatch(apic_id: u32, object_id: &str) -> Option<u16> {
    let tid = spawn_kernel_thread(
        apic_id,
        object_id,
        compute_thread_entry as *const () as usize as u64,
    )?;
    if let Some(slot) = crate::percpu::slot_for_apic(apic_id) {
        crate::percpu::set_current_thread(slot, Some(tid));
    }
    #[cfg(target_os = "none")]
    {
        if let Some(top) = thread_stack_top(tid) {
            crate::gdt::set_rsp0(apic_id, top);
        }
    }
    Some(tid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_and_mark_thread_on_host() {
        let id = spawn_kernel_thread(0, "obj-test", compute_thread_entry as usize as u64).unwrap();
        assert!(thread_stack_top(id).is_some());
        switch_to_thread(0, id);
        mark_done(id);
    }
}
