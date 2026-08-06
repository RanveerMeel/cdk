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
        // M11: when BSP is lapic-local, PIT only maintains ticks() — no dual schedule.
        if !matches!(
            k.runtime_drive_mode(0),
            RuntimeDriveMode::LocalApic
        ) {
            let _ = k.preempt_tick_on_core(tick, 0);
        }
        service_ap_runtime_cores(&mut k, tick);
    }
}

fn on_local_apic_timer_tick(apic_id: u32) {
    cdk::percpu::note_tick(apic_id);
    if let Some(mut k) = KERNEL.try_lock() {
        // M7: log only on new dispatch / preemption switch.
        if let Some(task) = k.on_local_apic_timer_tick(apic_id) {
            cdk::println!(
                "SMP: dispatch apic_id={} context={}",
                apic_id,
                task.as_str()
            );
        }
    } else if cdk::scheduler::global().running_task_on(apic_id).is_none() {
        // Soft-pending only when idle — avoid IPI storms while a context runs.
        cdk::multicore::request_reschedule(apic_id);
    }
}

fn on_reschedule_ipi(apic_id: u32) {
    if let Some(mut k) = KERNEL.try_lock() {
        if let Some(task) = k.on_reschedule_ipi(apic_id) {
            cdk::println!(
                "SMP: wake-dispatch apic_id={} context={}",
                apic_id,
                task.as_str()
            );
        }
    } else {
        let _ = cdk::multicore::note_wake_if_idle(apic_id);
        let _ = cdk::multicore::take_reschedule(apic_id);
    }
}

fn on_tlb_shootdown_ipi(apic_id: u32) {
    // Always apply + ACK without Kernel lock (M6).
    if let Some(page) = cdk::multicore::take_tlb_shootdown(apic_id) {
        cdk::paging::apply_tlb_shootdown(page);
    }
}

fn ap_trampoline_entry_stub(apic_id: u32, startup_seq: u32) {
    #[cfg(target_os = "none")]
    {
        match cdk::gdt::init_for_ap(apic_id) {
            Ok(()) => cdk::println!(
                "SMP: AP private TSS/IST ready (apic_id={}, slot={:?})",
                apic_id,
                cdk::gdt::ap_tss_slot(apic_id)
            ),
            Err(e) => {
                cdk::println!(
                    "SMP: WARNING — AP TSS init failed ({:?}); falling back to shared GDT",
                    e
                );
                cdk::gdt::reload_for_ap();
            }
        }
        if let Some(slot) = cdk::percpu::slot_for_apic(apic_id) {
            cdk::percpu::load_gs_for_slot(slot);
        }
        cdk::interrupts::load_idt();
    }

    // M1: signal online via atomics — never requires KERNEL.lock.
    cdk::percpu::signal_ap_ready(apic_id, startup_seq);
    cdk::println!(
        "SMP: AP ready mailbox posted (apic_id={}, seq={})",
        apic_id,
        startup_seq
    );

    // Best-effort Kernel bookkeeping if the BSP has released the lock.
    if let Some(mut k) = KERNEL.try_lock() {
        match k.ap_trampoline_entry_hook(apic_id, startup_seq) {
            Ok(()) => {
                k.activate_ap_local_timer(apic_id);
                cdk::println!(
                    "SMP: AP entry hook acknowledged (apic_id={}, seq={})",
                    apic_id,
                    startup_seq
                );
            }
            Err(e) => cdk::println!("SMP: WARNING — AP entry hook failed: {:?}", e),
        }
    } else {
        cdk::println!(
            "SMP: AP online via mailbox; Kernel sync deferred (apic_id={})",
            apic_id
        );
    }

    // Arm LAPIC using BSP-published count (no Kernel lock required).
    let config = cdk::local_apic::LocalApicTimerConfig::periodic_from_count(
        cdk::percpu::bsp_timer_count(),
    );
    if cdk::local_apic::arm_current_core_runtime_timer_with(config) {
        cdk::println!(
            "SMP: LAPIC timer armed (apic_id={}, vector={:#x}, count={})",
            apic_id,
            cdk::local_apic::LOCAL_APIC_TIMER_VECTOR,
            config.initial_count
        );
    } else {
        cdk::println!(
            "SMP: WARNING — failed to arm LAPIC timer on apic_id={}",
            apic_id
        );
    }
    register_ap_runtime_core(apic_id);
}

/// 64-bit C ABI entry reached from the AP long-mode trampoline stub.
#[no_mangle]
pub extern "C" fn ap_kernel_entry(apic_id: u32, startup_seq: u32) -> ! {
    ap_trampoline_entry_stub(apic_id, startup_seq);
    ap_idle_loop(apic_id)
}

/// Phase 18: park in `sti; hlt` until a reschedule / timer / TLB IPI wakes us.
fn ap_idle_loop(apic_id: u32) -> ! {
    loop {
        // Drain work that the IPI handler may have skipped (kernel lock busy).
        on_reschedule_ipi(apic_id);
        on_tlb_shootdown_ipi(apic_id);

        cdk::multicore::idle_enter(apic_id);
        unsafe {
            core::arch::asm!("sti; hlt", options(nomem, nostack, preserves_flags));
        }
        let _ = cdk::multicore::idle_leave(apic_id);
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
    cdk::interrupts::set_reschedule_ipi_hook(on_reschedule_ipi);
    cdk::interrupts::set_tlb_shootdown_ipi_hook(on_tlb_shootdown_ipi);
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

    // Initialise the kernel heap: 512 frames = 2 MiB (via phys→virt mapping).
    if phys_map_ready {
        let mut fa = FRAME_ALLOCATOR.lock();
        match cdk::heap::KERNEL_HEAP.init(&mut fa, 512) {
            Ok(()) => cdk::println!(
                "Heap: {} KiB ready ({} used)",
                cdk::heap::KERNEL_HEAP.total_bytes() / 1024,
                cdk::heap::KERNEL_HEAP.used_bytes()
            ),
            Err(e) => cdk::println!("Heap: WARNING — init failed: {:?}", e),
        }
    } else {
        cdk::println!("Heap: WARNING — skipped (no physical memory map offset)");
    }

    // Adopt the bootloader page tables (do not replace CR3) and identity-map
    // the AP trampoline page (+ LAPIC MMIO when not using x2APIC).
    let cr3 = {
        #[cfg(target_os = "none")]
        {
            let value: u64;
            unsafe {
                core::arch::asm!("mov {}, cr3", out(reg) value, options(nostack, preserves_flags));
            }
            value
        }
        #[cfg(not(target_os = "none"))]
        {
            0u64
        }
    };
    let x2apic = cdk::local_apic::try_enable_x2apic();
    if x2apic {
        cdk::println!("SMP: x2APIC enabled (MSR register file)");
    }
    {
        let mut pt = PageTableManager::from_pml4_phys(cr3);
        let trampoline_page = cdk::multicore::MultiCoreManager::trampoline_page_phys();
        let lapic_page = cdk::local_apic::XAPIC_BASE;
        let mut fa = FRAME_ALLOCATOR.lock();
        match pt.identity_map_page(trampoline_page, &mut *fa) {
            Ok(()) => {
                cdk::paging::flush_tlb_page(trampoline_page);
                cdk::println!(
                    "Page table: adopted CR3={:#x}, identity-mapped trampoline {:#x}",
                    pt.pml4_phys(),
                    trampoline_page
                );
            }
            Err(e) => cdk::println!(
                "Page table: WARNING — trampoline identity map failed: {:?}",
                e
            ),
        }
        if !x2apic {
            match pt.identity_map_mmio_page(lapic_page, &mut *fa) {
                Ok(()) => {
                    cdk::paging::flush_tlb_page(lapic_page);
                    cdk::println!(
                        "Page table: identity-mapped LAPIC MMIO {:#x} (uncached)",
                        lapic_page
                    );
                }
                Err(e) => cdk::println!(
                    "Page table: WARNING — LAPIC MMIO map failed: {:?} (APIC access will fault)",
                    e
                ),
            }
        }
        *PAGE_TABLE.lock() = Some(pt);
    }

    // Phase 16 / M11: calibrate BSP LAPIC, arm it, drive BSP via lapic-local.
    {
        let apic = cdk::local_apic::XApicController::new();
        #[cfg(target_os = "none")]
        let cfg = apic.calibrate_periodic_timer(
            cdk::local_apic::TARGET_RUNTIME_TIMER_HZ,
            cdk::interrupts::ticks,
        );
        #[cfg(not(target_os = "none"))]
        let cfg = apic.calibrate_periodic_timer(cdk::local_apic::TARGET_RUNTIME_TIMER_HZ, || 0);
        {
            let mut k = KERNEL.lock();
            k.set_timer_calibration(0, cfg);
            k.set_runtime_drive_mode(0, RuntimeDriveMode::LocalApic);
        }
        cdk::percpu::publish_bsp_timer_count(cfg.initial_count);
        let _ = cdk::local_apic::arm_current_core_runtime_timer_with(cfg);
        cdk::println!(
            "SMP: BSP LAPIC calibrated+armed (target_hz={}, count={}, drive=lapic-local)",
            cdk::local_apic::TARGET_RUNTIME_TIMER_HZ,
            cfg.initial_count
        );
    }

    cdk::println!("CDK - Cognitive Distributed Kernel");
    cdk::println!("Booting on bare metal...");
    cdk::println!("");

    let ap_entry = ap_kernel_entry as *const () as usize as u64;

    // M2: MADT topology (fallback BSP0+AP1 when RSDP missing).
    let topology = match boot_info.rsdp_addr.into_option() {
        Some(rsdp) => match cdk::acpi::discover_cpus_from_rsdp(rsdp) {
            Ok(t) => {
                cdk::println!(
                    "SMP: MADT topology ({} CPU(s), lapic={:#x})",
                    t.cpus.len(),
                    t.lapic_address
                );
                t
            }
            Err(e) => {
                cdk::println!("SMP: MADT parse failed ({:?}); using fallback topology", e);
                cdk::acpi::fallback_topology()
            }
        },
        None => {
            cdk::println!("SMP: no RSDP; using fallback topology");
            cdk::acpi::fallback_topology()
        }
    };
    cdk::percpu::init_topology(topology);
    cdk::percpu::load_gs_for_slot(0);
    cdk::syscall::init();

    // M13: IOAPIC route ISA IRQs; mask 8259 when successful.
    {
        let mut pt_guard = PAGE_TABLE.lock();
        let mut fa = FRAME_ALLOCATOR.lock();
        if let Some(pt) = pt_guard.as_mut() {
            match cdk::ioapic::init_and_route_isa(pt, &mut *fa, 0) {
                Ok(()) => cdk::interrupts::mask_all_pic(),
                Err(e) => cdk::println!("IOAPIC: skipped ({:?}) — keeping 8259 PIC", e),
            }
        }
    }

    // GPU: soft command pipeline (+ virtio-hw probe when enabled).
    {
        let mut pt_guard = PAGE_TABLE.lock();
        let mut fa = FRAME_ALLOCATOR.lock();
        cdk::gpu::init(pt_guard.as_mut(), Some(&mut *fa));
    }
    {
        let s = cdk::um::status();
        cdk::println!(
            "UM: ready (iommu={}, max_region={} KiB)",
            s.iommu.mode,
            cdk::um::MAX_REGION_BYTES / 1024
        );
    }

    // Publish BSP timer calibration for APs before INIT/SIPI (no Kernel lock on AP path).
    {
        let k = KERNEL.lock();
        if let Some(cfg) = k.timer_calibration(0) {
            cdk::percpu::publish_bsp_timer_count(cfg.initial_count);
        }
    }

    // M1: plan under Kernel lock, then drop it before INIT/SIPI + wait.
    let ap_plan = {
        let mut kernel = KERNEL.lock();
        kernel.configure_ap_handoff(ap_entry, cr3);
        cdk::println!(
            "SMP: AP handoff configured (entry={:#x}, cr3={:#x})",
            ap_entry,
            cr3
        );

        cdk::percpu::for_each_cpu(|cpu| {
            let role = if cpu.is_bsp {
                CoreRole::Bootstrap
            } else {
                CoreRole::Application
            };
            match kernel.register_core(cpu.apic_id, role) {
                Ok(()) => cdk::println!(
                    "SMP: registered {} apic_id={} (slot={:?})",
                    if cpu.is_bsp { "BSP" } else { "AP" },
                    cpu.apic_id,
                    cdk::percpu::slot_for_apic(cpu.apic_id)
                ),
                Err(e) => cdk::println!(
                    "SMP: WARNING — register apic_id={} failed: {:?}",
                    cpu.apic_id,
                    e
                ),
            }
        });
        // M11: keep BSP on lapic-local after topology registration.
        kernel.set_runtime_drive_mode(0, RuntimeDriveMode::LocalApic);

        cdk::percpu::first_application_apic().and_then(|apic| {
            cdk::println!("SMP: planning AP startup for apic_id={} ...", apic);
            match kernel.plan_ap_startup(apic) {
                Ok(plan) => {
                    cdk::println!(
                        "SMP: trampoline installed @ {:#x} vector={:#x} seq={}",
                        plan.trampoline_phys,
                        plan.sipi_vector,
                        plan.startup_seq
                    );
                    Some(plan)
                }
                Err(e) => {
                    cdk::println!("SMP: WARNING — AP plan failed: {:?}", e);
                    None
                }
            }
        })
    }; // KERNEL.lock dropped here — AP can try_lock / use mailbox

    if let Some(plan) = ap_plan {
        cdk::println!(
            "SMP: issuing INIT/SIPI to apic_id={} vector={:#x} ...",
            plan.apic_id,
            plan.sipi_vector
        );
        let mut apic = cdk::local_apic::XApicController::new();
        use cdk::local_apic::ApicIpiController;
        if apic.bringup_ap(plan.apic_id, plan.sipi_vector) {
            cdk::println!(
                "SMP: INIT/SIPI issued for apic_id={} seq={} (waiting for AP ready mailbox)",
                plan.apic_id,
                plan.startup_seq
            );
            let mut status = 0u32;
            for i in 0..200_000u32 {
                status = cdk::multicore::MultiCoreManager::read_trampoline_status_global();
                if cdk::percpu::ap_ready(plan.apic_id) {
                    break;
                }
                if i % 20_000 == 0 {
                    cdk::println!(
                        "SMP: waiting... tramp_status={} ready_mask={:#x}",
                        status,
                        cdk::percpu::ap_ready_mask()
                    );
                }
                cdk::local_apic::spin_delay(500);
            }
            let ready = cdk::percpu::ap_ready(plan.apic_id);
            cdk::println!(
                "SMP: trampoline status={} ap_ready={} ready_mask={:#x}",
                status,
                ready,
                cdk::percpu::ap_ready_mask()
            );
            // Sync Kernel online state now that AP has posted the mailbox.
            if ready {
                let mut k = KERNEL.lock();
                let seq = cdk::percpu::ap_ready_seq(plan.apic_id).unwrap_or(plan.startup_seq);
                match k.ap_trampoline_entry_hook(plan.apic_id, seq) {
                    Ok(()) => {
                        k.activate_ap_local_timer(plan.apic_id);
                        cdk::println!(
                            "SMP: Kernel synced AP online (apic_id={}, seq={})",
                            plan.apic_id,
                            seq
                        );
                    }
                    Err(e) => cdk::println!("SMP: WARNING — Kernel sync failed: {:?}", e),
                }
            }
        } else {
            cdk::println!("SMP: WARNING — INIT/SIPI bring-up returned false");
        }
    }

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

        cdk::println!("\n=== Dispatching contexts (M4: stay running until complete) ===");
        while let Some(obj_id) = kernel.execute_next() {
            cdk::println!("Dispatched: {}", obj_id.as_str());
            for apic in 0u32..8 {
                if kernel.running_task_id_on(apic).as_deref() == Some(obj_id.as_str()) {
                    kernel.complete_running_on_core(apic);
                    cdk::println!("Completed on apic_id={}: {}", apic, obj_id.as_str());
                    break;
                }
            }
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
