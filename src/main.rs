#![no_std]
#![no_main]

use bootloader_api::config::Mapping;
use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use spin::Mutex;

use cdk::allocator::FrameAllocator;
use cdk::capability::{Capability, Permission};
use cdk::kernel::{Kernel, RuntimeDriveMode};
use cdk::memory_graph::MemoryGraph;
use cdk::multicore::CoreRole;
use cdk::network::{ExternalBackendKind, NetworkStack};
use cdk::node::KernelNode;
use cdk::object::KernelObject;
use cdk::paging::PageTableManager;
use heapless::Vec;

static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.kernel_stack_size = 100 * 1024;
    // The kernel dereferences physical frame addresses through a configured
    // physical-memory mapping offset from BootInfo.
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

static KERNEL: Mutex<Kernel> = Mutex::new(Kernel::new());
static MEM_GRAPH: Mutex<MemoryGraph> = Mutex::new(MemoryGraph::new());
static NODE: Mutex<KernelNode> = Mutex::new(KernelNode::new_const());
static NETWORK: Mutex<NetworkStack> = Mutex::new(NetworkStack::new());
static NETWORK_CAP: Mutex<Option<Capability>> = Mutex::new(None);
static FRAME_ALLOCATOR: Mutex<FrameAllocator> = Mutex::new(FrameAllocator::new());
static PAGE_TABLE: Mutex<Option<PageTableManager>> = Mutex::new(None);
static AP_RUNTIME_CORES: Mutex<Vec<u32, 8>> = Mutex::new(Vec::new());

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

/// Preemption callback invoked by the timer ISR on every tick.
///
/// Uses `try_lock` so the ISR never spins waiting for the kernel lock — if the
/// lock is held by the console or boot code the tick is silently skipped and
/// the scheduler catches up on the next one.
fn on_timer_tick(tick: u64) {
    if let Some(mut k) = KERNEL.try_lock() {
        let _ = k.preempt_tick_on_core(tick, 0);
        service_ap_runtime_cores(&mut k, tick);
    }
}

fn on_local_apic_timer_tick(apic_id: u32) {
    if let Some(mut k) = KERNEL.try_lock() {
        if let Some(task) = k.on_local_apic_timer_tick(apic_id) {
            let local_tick = k.runtime_tick_cursor(apic_id);
            cdk::println!(
                "SMP: LAPIC timer apic_id={} local_tick={} dispatched={}",
                apic_id,
                local_tick,
                task.as_str()
            );
        }
    }
}

fn ap_trampoline_entry_stub(apic_id: u32, startup_seq: u32) {
    let mut activated = false;
    if let Some(mut k) = KERNEL.try_lock() {
        match k.ap_trampoline_entry_hook(apic_id, startup_seq) {
            Ok(()) => {
                activated = true;
                k.activate_ap_local_timer(apic_id);
                cdk::println!(
                    "SMP: AP entry hook acknowledged (apic_id={}, seq={})",
                    apic_id,
                    startup_seq
                )
            }
            Err(e) => cdk::println!("SMP: WARNING — AP entry hook failed: {:?}", e),
        }
    } else {
        cdk::println!(
            "SMP: WARNING — AP entry hook lock busy (apic_id={}, seq={})",
            apic_id,
            startup_seq
        );
    }
    if activated {
        register_ap_runtime_core(apic_id);
    }
}

fn register_ap_runtime_core(apic_id: u32) {
    let mut active = AP_RUNTIME_CORES.lock();
    if active.iter().any(|id| *id == apic_id) {
        return;
    }
    if active.push(apic_id).is_ok() {
        cdk::println!("SMP: AP runtime core activated (apic_id={})", apic_id);
    } else {
        cdk::println!(
            "SMP: WARNING — AP runtime registry full, skipping apic_id={}",
            apic_id
        );
    }
}

fn service_ap_runtime_cores(kernel: &mut Kernel, tick: u64) {
    let mut snapshot = [0u32; 8];
    let count = {
        let active = AP_RUNTIME_CORES.lock();
        let mut n = 0usize;
        for apic_id in active.iter() {
            if n >= snapshot.len() {
                break;
            }
            snapshot[n] = *apic_id;
            n += 1;
        }
        n
    };
    for apic_id in snapshot.iter().take(count).copied() {
        if !matches!(
            kernel.runtime_drive_mode(apic_id),
            RuntimeDriveMode::BspProxy
        ) {
            continue;
        }
        if let Some(task) = kernel.service_core_runtime_step_if_bsp_proxy(apic_id) {
            let local_tick = kernel.runtime_tick_cursor(apic_id);
            cdk::println!(
                "SMP: AP runtime bsp_tick={} apic_id={} local_tick={} dispatched={}",
                tick,
                apic_id,
                local_tick,
                task.as_str()
            );
        }
    }
}

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    cdk::serial::init();

    let phys_map_ready = match boot_info.physical_memory_offset.into_option() {
        Some(offset) => {
            cdk::phys_mem::set_physical_memory_offset(offset);
            cdk::println!("Phys map offset: {:#x}", offset);
            true
        }
        None => {
            cdk::println!("Phys map: WARNING — no physical memory mapping offset provided");
            false
        }
    };

    // Init the pixel framebuffer early so boot messages appear on screen.
    if let Some(fb) = boot_info.framebuffer.as_mut() {
        let (width, height) = {
            let info = fb.info();
            (info.width, info.height)
        };
        cdk::framebuffer::init(fb);
        cdk::println!("Framebuffer: {}x{} pixels", width, height);
    }

    // Register the preemption hook *before* enabling interrupts so the very
    // first timer IRQ already has a valid callback.
    cdk::interrupts::set_preempt_hook(on_timer_tick);
    cdk::interrupts::set_local_apic_tick_hook(on_local_apic_timer_tick);
    cdk::interrupts::init();

    // Initialise the physical frame allocator from the bootloader memory map.
    {
        let mut fa = FRAME_ALLOCATOR.lock();
        cdk::allocator::boot::init(&mut fa, &boot_info.memory_regions);
        cdk::println!(
            "Frame allocator: {} KiB usable, {} KiB free",
            fa.usable_bytes() / 1024,
            fa.free_bytes() / 1024
        );
    }

    // Initialise the kernel heap: 512 frames = 2 MiB.
    //
    // Done before any alloc type is used and before the page-table setup
    // which may eventually use Box for interior tables.
    let _ = phys_map_ready;
    cdk::println!("Heap: WARNING — init temporarily disabled (boot stability mode)");

    // Build the initial kernel page-table hierarchy.
    cdk::println!("Page table: WARNING — init temporarily disabled (boot stability mode)");

    cdk::println!("CDK - Cognitive Distributed Kernel");
    cdk::println!("Booting on bare metal...");
    cdk::println!("");

    let ap_entry_phys = ap_trampoline_entry_stub as *const () as usize as u64;
    let pml4_root_phys = PAGE_TABLE
        .lock()
        .as_ref()
        .map(|pt| pt.pml4_phys())
        .unwrap_or(0);
    let boot_ap_ack: Option<(u32, u32)> = None;

    {
        let mut kernel = KERNEL.lock();
        let mut mem_graph = MEM_GRAPH.lock();

        let _ = (ap_entry_phys, pml4_root_phys, phys_map_ready);

        match kernel.register_core(0, CoreRole::Bootstrap) {
            Ok(()) => cdk::println!("SMP: bootstrap core registered (apic_id=0)"),
            Err(e) => cdk::println!("SMP: WARNING — bootstrap core registration failed: {:?}", e),
        }
        match kernel.register_core(1, CoreRole::Application) {
            Ok(()) => cdk::println!("SMP: application core discovered (apic_id=1)"),
            Err(e) => cdk::println!("SMP: WARNING — AP discovery failed: {:?}", e),
        }
        cdk::println!("SMP: WARNING — AP startup temporarily disabled (boot stability mode)");

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

        let net_obj = KernelObject::new_compute("net0", "interactive");
        let net_cap = Capability::with_permissions(
            &net_obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        kernel.register_object(net_obj);
        *NETWORK_CAP.lock() = Some(net_cap);
    }

    if let Some((apic_id, startup_seq)) = boot_ap_ack {
        ap_trampoline_entry_stub(apic_id, startup_seq);
    }

    cdk::println!("\nKernel initialized successfully!");
    cdk::println!("System ready.");

    {
        let node = NODE.lock();
        cdk::println!("Node ID: {}", node.node_id());
    }
    {
        let mut net = NETWORK.lock();
        match net.add_loopback_interface("lo") {
            Ok(()) => cdk::println!("Network: loopback interface 'lo' registered"),
            Err(e) => cdk::println!("Network: WARNING — loopback init failed: {:?}", e),
        }
        let ext_backend = if cfg!(feature = "virtio-hw") {
            ExternalBackendKind::VirtioNet
        } else {
            ExternalBackendKind::StubTap
        };
        match net.add_external_interface("eth0", ext_backend) {
            Ok(()) => cdk::println!(
                "Network: external interface 'eth0' registered ({})",
                ext_backend.as_str()
            ),
            Err(e) => cdk::println!("Network: WARNING — external iface init failed: {:?}", e),
        }
    }

    cdk::console::run_static(
        &KERNEL,
        &MEM_GRAPH,
        &NODE,
        &NETWORK,
        &NETWORK_CAP,
        &FRAME_ALLOCATOR,
        &PAGE_TABLE,
    );
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    cdk::println!("PANIC: {}", info);
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
