#![no_std]
#![no_main]

use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use spin::Mutex;

use cdk::allocator::FrameAllocator;
use cdk::kernel::Kernel;
use cdk::memory_graph::MemoryGraph;
use cdk::node::KernelNode;
use cdk::object::KernelObject;
use cdk::paging::PageTableManager;

static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.kernel_stack_size = 100 * 1024;
    config
};

static KERNEL: Mutex<Kernel> = Mutex::new(Kernel::new());
static MEM_GRAPH: Mutex<MemoryGraph> = Mutex::new(MemoryGraph::new());
static NODE: Mutex<KernelNode> = Mutex::new(KernelNode::new_const());
static FRAME_ALLOCATOR: Mutex<FrameAllocator> = Mutex::new(FrameAllocator::new());
static PAGE_TABLE: Mutex<Option<PageTableManager>> = Mutex::new(None);

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

/// Preemption callback invoked by the timer ISR on every tick.
///
/// Uses `try_lock` so the ISR never spins waiting for the kernel lock — if the
/// lock is held by the console or boot code the tick is silently skipped and
/// the scheduler catches up on the next one.
fn on_timer_tick(tick: u64) {
    if let Some(mut k) = KERNEL.try_lock() {
        k.preempt_tick(tick);
    }
}

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    cdk::serial::init();
    // Register the preemption hook *before* enabling interrupts so the very
    // first timer IRQ already has a valid callback.
    cdk::interrupts::set_preempt_hook(on_timer_tick);
    cdk::interrupts::init();

    // Initialise the physical frame allocator from the bootloader memory map.
    {
        let mut fa = FRAME_ALLOCATOR.lock();
        cdk::allocator::boot::init(&mut fa, &boot_info.memory_regions);
        cdk::println!("Frame allocator: {} KiB usable, {} KiB free",
            fa.usable_bytes() / 1024,
            fa.free_bytes() / 1024);
    }

    // Build the initial kernel page-table hierarchy.
    {
        let mut fa = FRAME_ALLOCATOR.lock();
        match PageTableManager::new(&mut *fa) {
            Some(pt) => {
                cdk::println!("Page table: PML4 root at {:#x}", pt.pml4_phys());
                *PAGE_TABLE.lock() = Some(pt);
            }
            None => cdk::println!("Page table: WARNING — could not allocate PML4 frame"),
        }
    }

    cdk::println!("CDK - Cognitive Distributed Kernel");
    cdk::println!("Booting on bare metal...");
    cdk::println!("");

    {
        let mut kernel = KERNEL.lock();
        let mut mem_graph = MEM_GRAPH.lock();

        let compute1 = KernelObject::new_compute("ai_inference", "low_latency");
        let cap1 = kernel.register_object(compute1);

        let compute2 = KernelObject::new_compute("data_processing", "batch");
        let cap2 = kernel.register_object(compute2);

        cdk::println!("=== Scheduling Objects ===");
        kernel.execute(&cap1).expect("Failed to execute");
        kernel.execute(&cap2).expect("Failed to execute");

        cdk::println!("\n=== Executing from Priority Queue ===");
        while let Some(obj_id) = kernel.execute_next() {
            cdk::println!("Completed: {}", obj_id.as_str());
        }

        cdk::println!("\n=== Memory Graph ===");
        mem_graph.register_object(cap1.object_id.as_str(), 1024);
        mem_graph.register_object(cap2.object_id.as_str(), 2048);
        cdk::println!("Total memory tracked: {} bytes", mem_graph.total_memory());
    }

    cdk::println!("\nKernel initialized successfully!");
    cdk::println!("System ready.");

    {
        let node = NODE.lock();
        cdk::println!("Node ID: {}", node.node_id());
    }

    cdk::console::run_static(&KERNEL, &MEM_GRAPH, &NODE, &FRAME_ALLOCATOR, &PAGE_TABLE);
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    cdk::println!("PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
