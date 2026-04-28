#![no_std]
#![no_main]

use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use spin::Mutex;

use cdk::kernel::Kernel;
use cdk::memory_graph::MemoryGraph;
use cdk::node::KernelNode;
use cdk::object::KernelObject;

static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.kernel_stack_size = 100 * 1024;
    config
};

static KERNEL: Mutex<Kernel> = Mutex::new(Kernel::new());
static MEM_GRAPH: Mutex<MemoryGraph> = Mutex::new(MemoryGraph::new());
static NODE: Mutex<KernelNode> = Mutex::new(KernelNode::new_const());

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(_boot_info: &'static mut BootInfo) -> ! {
    cdk::serial::init();
    cdk::interrupts::init();

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

    cdk::console::run_static(&KERNEL, &MEM_GRAPH, &NODE);
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    cdk::println!("PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
