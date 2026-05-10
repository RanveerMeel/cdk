//! Interactive serial console — reads lines from COM1 and dispatches commands.

use crate::serial;
use crate::allocator::FrameAllocator;
use crate::capability::Capability;
use crate::heap::KERNEL_HEAP;
use crate::kernel::Kernel;
use crate::memory_graph::MemoryGraph;
use crate::node::KernelNode;
use crate::object::KernelObject;
use crate::message::Message;
use crate::paging::{MapFlags, PageTableManager};
use spin::Mutex;

const MAX_LINE: usize = 128;

/// Entry point that borrows static Mutex-wrapped state.
pub fn run_static(
    kernel: &'static Mutex<Kernel>,
    mem_graph: &'static Mutex<MemoryGraph>,
    node: &'static Mutex<KernelNode>,
    frame_alloc: &'static Mutex<FrameAllocator>,
    page_table: &'static Mutex<Option<PageTableManager>>,
) -> ! {
    crate::println!("\n--- CDK Serial Console ---");
    crate::println!("Type 'help' for available commands.\n");

    let mut buf = [0u8; MAX_LINE];

    loop {
        print_prompt();
        let len = read_line(&mut buf);
        let line = core::str::from_utf8(&buf[..len]).unwrap_or("");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        dispatch(
            line,
            &mut kernel.lock(),
            &mut mem_graph.lock(),
            &mut node.lock(),
            &mut frame_alloc.lock(),
            &mut page_table.lock(),
        );
    }
}

fn print_prompt() {
    use core::fmt::Write;
    let _ = write!(serial::SerialPort, "cdk> ");
}

fn read_line(buf: &mut [u8; MAX_LINE]) -> usize {
    let mut pos = 0usize;
    loop {
        let b = serial::read_byte();
        match b {
            b'\r' | b'\n' => {
                serial::write_byte(b'\r');
                serial::write_byte(b'\n');
                return pos;
            }
            // Backspace / DEL
            0x08 | 0x7f => {
                if pos > 0 {
                    pos -= 1;
                    serial::write_byte(0x08);
                    serial::write_byte(b' ');
                    serial::write_byte(0x08);
                }
            }
            // Ctrl-C — abandon current line
            0x03 => {
                serial::write_byte(b'^');
                serial::write_byte(b'C');
                serial::write_byte(b'\r');
                serial::write_byte(b'\n');
                return 0;
            }
            // Printable ASCII
            0x20..=0x7e => {
                if pos < MAX_LINE {
                    buf[pos] = b;
                    pos += 1;
                    serial::write_byte(b);
                }
            }
            _ => {}
        }
    }
}

fn dispatch(
    line: &str,
    kernel: &mut Kernel,
    mem_graph: &mut MemoryGraph,
    node: &mut KernelNode,
    frame_alloc: &mut FrameAllocator,
    page_table: &mut Option<PageTableManager>,
) {
    let mut parts = line.splitn(4, ' ');
    let cmd = parts.next().unwrap_or("");
    let arg1 = parts.next().unwrap_or("");
    let arg2 = parts.next().unwrap_or("");
    let arg3 = parts.next().unwrap_or("");

    match cmd {
        "help" | "?" => cmd_help(),
        "status" => cmd_status(kernel, mem_graph, node, page_table),
        "create" => cmd_create(arg1, arg2, kernel, mem_graph),
        "list" => cmd_list(kernel),
        "schedule" => cmd_schedule(arg1, kernel),
        "run" => cmd_run_next(kernel),
        "send" => cmd_send(arg1, arg2, kernel),
        "recv" => cmd_recv(arg1, kernel),
        "delete" => cmd_delete(arg1, kernel, mem_graph),
        "mem" => cmd_mem(mem_graph),
        "node" => cmd_node(node),
        "discover" => cmd_discover(arg1, arg2, node),
        #[cfg(target_os = "none")]
        "ticks" => crate::println!("Timer ticks: {}", crate::interrupts::ticks()),
        #[cfg(not(target_os = "none"))]
        "ticks" => crate::println!("Timer ticks: (unavailable outside bare-metal)"),
        "timeslice" => cmd_timeslice(),
        "running"   => cmd_running(kernel),
        "frames"     => cmd_frames(frame_alloc),
        "heapinfo"   => cmd_heapinfo(),
        "palloc"     => cmd_palloc(frame_alloc),
        "pfree"      => cmd_pfree(arg1, frame_alloc),
        "capsign"    => cmd_capsign(arg1, kernel),
        "capverify"  => cmd_capverify(arg1, kernel),
        "vmmap"      => cmd_vmmap(arg1, arg2, arg3, page_table, frame_alloc),
        "vmunmap"    => cmd_vmunmap(arg1, page_table),
        "vmtranslate"=> cmd_vmtranslate(arg1, page_table),
        "vminfo"     => cmd_vminfo(page_table),
        "echo" => crate::println!("{} {}", arg1, arg2),
        "panic" => panic!("user-triggered panic"),
        _ => crate::println!("Unknown command: '{}'. Type 'help'.", cmd),
    }
}

fn cmd_help() {
    crate::println!("Commands:");
    crate::println!("  help              Show this message");
    crate::println!("  status            Kernel overview (includes preemption info)");
    crate::println!("  create <name> <intent>");
    crate::println!("                    Create a compute object (intents: low_latency,");
    crate::println!("                    interactive, normal, batch, energy_saving)");
    crate::println!("  list              List registered objects");
    crate::println!("  schedule <id>     Queue an object for execution");
    crate::println!("  run               Manually dispatch next task (ignores preemption)");
    crate::println!("  running           Show the currently running task");
    crate::println!("  send <id> <text>  Send a text message to an object");
    crate::println!("  recv <id>         Receive next message from an object");
    crate::println!("  delete <id>       Delete an object");
    crate::println!("  mem               Memory graph summary");
    crate::println!("  node              Show this node's info");
    crate::println!("  discover <id> <latency_ms>");
    crate::println!("                    Simulate discovering a remote node");
    crate::println!("  ticks             Show PIT timer tick count since boot");
    crate::println!("  timeslice         Show the preemptive time-slice length (ticks)");
    crate::println!("  capsign <id>      Sign a fresh capability for object <id> and verify it");
    crate::println!("  capverify <id>    Create + sign + verify a capability for object <id>");
    crate::println!("  heapinfo          Kernel heap usage (total / used / free)");
    crate::println!("  frames            Physical frame allocator summary");
    crate::println!("  palloc            Allocate one physical frame, print address");
    crate::println!("  pfree <addr>      Free a physical frame by base address (hex)");
    crate::println!("  vminfo            Virtual memory: PML4 address + mapped page count");
    crate::println!("  vmmap <virt> <phys> [flags]");
    crate::println!("                    Map virtual page to physical frame");
    crate::println!("                    flags: krx (default), krw, urw");
    crate::println!("  vmunmap <virt>    Remove mapping for virtual page");
    crate::println!("  vmtranslate <virt> Resolve virtual address to physical");
    crate::println!("  echo <text>       Echo text back");
    crate::println!("  panic             Trigger a kernel panic (test)");
}

fn cmd_status(kernel: &mut Kernel, mem_graph: &MemoryGraph, node: &KernelNode, page_table: &Option<PageTableManager>) {
    crate::println!("=== CDK Kernel Status ===");
    crate::println!("  Node:         {}", node.node_id());
    crate::println!("  Objects:      {}", kernel.object_count());
    crate::println!("  Sched queue:  {}", kernel.scheduler_queue_size());
    match kernel.running_task_id() {
        Some(id) => crate::println!("  Running task: {}", id),
        None      => crate::println!("  Running task: (idle)"),
    }
    crate::println!("  Time slice:   {} ticks (~{}ms at 1kHz)",
        crate::scheduler::TICKS_PER_SLICE,
        crate::scheduler::TICKS_PER_SLICE);
    crate::println!("  Memory:       {} bytes tracked", mem_graph.total_memory());
    crate::println!("  Mem objects:  {}", mem_graph.object_count());
    crate::println!("  Known nodes:  {}", node.known_nodes_count());
    match page_table {
        Some(pt) => crate::println!("  VM pages:     {} mapped (PML4 @ {:#x})",
            pt.mapped_pages(), pt.pml4_phys()),
        None => crate::println!("  VM pages:     (page table not initialised)"),
    }
    if KERNEL_HEAP.is_initialised() {
        crate::println!("  Heap:         {} KiB used / {} KiB total",
            KERNEL_HEAP.used_bytes() / 1024,
            KERNEL_HEAP.total_bytes() / 1024);
    } else {
        crate::println!("  Heap:         (not initialised)");
    }
}

fn cmd_timeslice() {
    crate::println!("Time slice: {} ticks (~{}ms at default PIT ~1kHz)",
        crate::scheduler::TICKS_PER_SLICE,
        crate::scheduler::TICKS_PER_SLICE);
}

fn cmd_running(kernel: &Kernel) {
    match kernel.running_task_id() {
        Some(id) => crate::println!("Running: {}", id),
        None      => crate::println!("(idle — no task currently running)"),
    }
}

/// Sign a fresh capability for the given object ID and immediately verify it.
///
/// The signing key is ephemeral — this command demonstrates that signing +
/// verification works end-to-end. Persistent key management is a future feature.
fn cmd_capsign(id: &str, kernel: &mut Kernel) {
    if id.is_empty() {
        crate::println!("Usage: capsign <object-id>");
        return;
    }
    // Build a fresh capability for the object (verifies the ID exists).
    let obj = kernel.for_each_object_find(id);
    let obj_ref = match obj {
        Some(o) => o,
        None => {
            crate::println!("Error: object '{}' not found", id);
            return;
        }
    };
    let mut cap = Capability::new(obj_ref);
    match Kernel::sign_capability(&mut cap) {
        Ok(_sk) => {
            crate::println!("Signed capability for '{}'", id);
            match cap.verify() {
                Ok(true)  => crate::println!("  Signature valid ✓"),
                Ok(false) => crate::println!("  WARNING: signature not present"),
                Err(e)    => crate::println!("  ERROR: verification failed: {:?}", e),
            }
        }
        Err(e) => crate::println!("Error: signing failed: {:?}", e),
    }
}

fn cmd_capverify(id: &str, kernel: &mut Kernel) {
    if id.is_empty() {
        crate::println!("Usage: capverify <object-id>");
        return;
    }
    let obj = kernel.for_each_object_find(id);
    let obj_ref = match obj {
        Some(o) => o,
        None => {
            crate::println!("Error: object '{}' not found", id);
            return;
        }
    };
    // Unsigned capability: verify returns false (not an error).
    let cap = Capability::new(obj_ref);
    match Kernel::verify_capability(&cap) {
        Ok(true)  => crate::println!("Capability for '{}': signature valid", id),
        Ok(false) => crate::println!("Capability for '{}': unsigned (no signature)", id),
        Err(e)    => crate::println!("Capability for '{}': error: {:?}", id, e),
    }
}

fn cmd_create(name: &str, intent: &str, kernel: &mut Kernel, mem_graph: &mut MemoryGraph) {
    if name.is_empty() {
        crate::println!("Usage: create <name> <intent>");
        return;
    }
    let intent = if intent.is_empty() { "normal" } else { intent };
    let obj = KernelObject::new_compute(name, intent);
    let id_str: heapless::String<64> = obj.id.clone();
    let cap = kernel.register_object(obj);
    mem_graph.register_object(cap.object_id.as_str(), 0);
    crate::println!("Created object '{}' (id={}, intent={})", name, id_str, intent);
}

fn cmd_list(kernel: &Kernel) {
    if kernel.object_count() == 0 {
        crate::println!("(no objects)");
        return;
    }
    crate::println!("{:<12} {:<16} {:<12} msgs", "ID", "Kind", "Intent");
    crate::println!("{}", "--------------------------------------------");
    kernel.for_each_object(|obj| {
        crate::println!(
            "{:<12} {:<16} {:<12} {}",
            obj.id.as_str(),
            obj.kind.as_str(),
            obj.intent.as_str(),
            obj.message_count(),
        );
    });
}

fn cmd_schedule(id: &str, kernel: &mut Kernel) {
    if id.is_empty() {
        crate::println!("Usage: schedule <id>");
        return;
    }
    match kernel.schedule_by_id(id) {
        Ok(()) => {}
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_run_next(kernel: &mut Kernel) {
    match kernel.execute_next() {
        Some(id) => crate::println!("Dispatched: {}", id),
        None => match kernel.running_task_id() {
            Some(id) => crate::println!("(task '{}' already running — wait for preemption)", id),
            None     => crate::println!("(scheduler queue empty)"),
        },
    }
}

fn cmd_send(id: &str, text: &str, kernel: &mut Kernel) {
    if id.is_empty() || text.is_empty() {
        crate::println!("Usage: send <id> <text>");
        return;
    }
    match Message::text("console", id, text) {
        Ok(msg) => match kernel.send_message_direct(id, msg) {
            Ok(()) => crate::println!("Sent to {}", id),
            Err(e) => crate::println!("Error: {:?}", e),
        },
        Err(_) => crate::println!("Error: message too long"),
    }
}

fn cmd_recv(id: &str, kernel: &mut Kernel) {
    if id.is_empty() {
        crate::println!("Usage: recv <id>");
        return;
    }
    match kernel.receive_message_direct(id) {
        Ok(Some(msg)) => {
            crate::println!("From: {}", msg.from);
            crate::println!("Payload: {:?}", msg.payload);
        }
        Ok(None) => crate::println!("(no messages)"),
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_delete(id: &str, kernel: &mut Kernel, mem_graph: &mut MemoryGraph) {
    if id.is_empty() {
        crate::println!("Usage: delete <id>");
        return;
    }
    match kernel.delete_by_id(id) {
        Ok(()) => {
            mem_graph.remove_object(id);
            crate::println!("Deleted {}", id);
        }
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_mem(mem_graph: &MemoryGraph) {
    crate::println!("Memory: {} bytes across {} objects",
        mem_graph.total_memory(), mem_graph.object_count());
}

fn cmd_node(node: &KernelNode) {
    let type_str = match node.node_type() {
        crate::node::NodeType::Local => "Local",
        crate::node::NodeType::Edge => "Edge",
        crate::node::NodeType::Cloud => "Cloud",
    };
    crate::println!("Node ID:    {}", node.node_id());
    crate::println!("Type:       {}", type_str);
    crate::println!("Known nodes: {}", node.known_nodes_count());
}

fn cmd_discover(id: &str, latency_str: &str, node: &mut KernelNode) {
    if id.is_empty() {
        crate::println!("Usage: discover <node-id> <latency_ms>");
        return;
    }
    let latency: u32 = parse_u32(latency_str).unwrap_or(100);
    node.discover_node(id, crate::node::NodeType::Edge, "simulated", latency);
    crate::println!("Discovered node '{}' (latency={}ms)", id, latency);
}

fn cmd_heapinfo() {
    if !KERNEL_HEAP.is_initialised() {
        crate::println!("Heap: not initialised");
        return;
    }
    let total = KERNEL_HEAP.total_bytes();
    let used  = KERNEL_HEAP.used_bytes();
    let free  = KERNEL_HEAP.free_bytes();
    crate::println!("=== Kernel Heap ===");
    crate::println!("  Total : {} KiB", total / 1024);
    crate::println!("  Used  : {} KiB ({} bytes)", used / 1024, used);
    crate::println!("  Free  : {} KiB ({} bytes)", free / 1024, free);
}

fn cmd_frames(fa: &FrameAllocator) {
    crate::println!("=== Physical Frame Allocator ===");
    crate::println!("  Total frames : {}", fa.total_frames());
    crate::println!("  Free  frames : {}", fa.free_frames());
    crate::println!("  Used  frames : {}", fa.used_frames());
    crate::println!("  Reserved     : {}", fa.reserved_frames());
    crate::println!("  Usable       : {} KiB", fa.usable_bytes() / 1024);
    crate::println!("  Free         : {} KiB", fa.free_bytes() / 1024);
}

fn cmd_palloc(fa: &mut FrameAllocator) {
    match fa.alloc() {
        Ok(frame) => crate::println!("Allocated frame at {:#x}", frame.base_addr()),
        Err(_) => crate::println!("Error: out of physical memory"),
    }
}

fn cmd_pfree(addr_str: &str, fa: &mut FrameAllocator) {
    if addr_str.is_empty() {
        crate::println!("Usage: pfree <hex-address>");
        return;
    }
    let addr = parse_hex(addr_str);
    match addr {
        Some(a) => match fa.free(crate::allocator::PhysFrame(a)) {
            Ok(()) => crate::println!("Freed frame at {:#x}", a),
            Err(e) => crate::println!("Error: {:?}", e),
        },
        None => crate::println!("Error: invalid hex address '{}'", addr_str),
    }
}

fn cmd_vminfo(page_table: &Option<PageTableManager>) {
    match page_table {
        Some(pt) => {
            crate::println!("=== Virtual Memory ===");
            crate::println!("  PML4 root : {:#x}", pt.pml4_phys());
            crate::println!("  Mapped    : {} pages ({} KiB)",
                pt.mapped_pages(),
                pt.mapped_pages() as u64 * crate::paging::PAGE_SIZE / 1024);
        }
        None => crate::println!("Page table not initialised."),
    }
}

fn cmd_vmmap(
    virt_str: &str,
    phys_str: &str,
    flags_str: &str,
    page_table: &mut Option<PageTableManager>,
    frame_alloc: &mut FrameAllocator,
) {
    if virt_str.is_empty() || phys_str.is_empty() {
        crate::println!("Usage: vmmap <virt_hex> <phys_hex> [flags: krx|krw|urw]");
        return;
    }
    let virt = match parse_hex(virt_str) {
        Some(v) => v,
        None => { crate::println!("Invalid virtual address '{}'", virt_str); return; }
    };
    let phys = match parse_hex(phys_str) {
        Some(p) => p,
        None => { crate::println!("Invalid physical address '{}'", phys_str); return; }
    };
    let flags = match flags_str {
        "krw" => MapFlags::kernel_rw(),
        "urw" => MapFlags::user_rw(),
        _     => MapFlags::kernel_rx(), // default
    };
    match page_table {
        Some(pt) => match pt.map(virt, phys, flags, frame_alloc) {
            Ok(()) => crate::println!("Mapped {:#x} -> {:#x}", virt, phys),
            Err(e) => crate::println!("Error: {:?}", e),
        },
        None => crate::println!("Page table not initialised."),
    }
}

fn cmd_vmunmap(virt_str: &str, page_table: &mut Option<PageTableManager>) {
    if virt_str.is_empty() {
        crate::println!("Usage: vmunmap <virt_hex>");
        return;
    }
    let virt = match parse_hex(virt_str) {
        Some(v) => v,
        None => { crate::println!("Invalid address '{}'", virt_str); return; }
    };
    match page_table {
        Some(pt) => match pt.unmap(virt) {
            Ok(()) => crate::println!("Unmapped {:#x}", virt),
            Err(e) => crate::println!("Error: {:?}", e),
        },
        None => crate::println!("Page table not initialised."),
    }
}

fn cmd_vmtranslate(virt_str: &str, page_table: &Option<PageTableManager>) {
    if virt_str.is_empty() {
        crate::println!("Usage: vmtranslate <virt_hex>");
        return;
    }
    let virt = match parse_hex(virt_str) {
        Some(v) => v,
        None => { crate::println!("Invalid address '{}'", virt_str); return; }
    };
    match page_table {
        Some(pt) => match pt.translate(virt) {
            Ok(phys) => crate::println!("{:#x} -> {:#x}", virt, phys),
            Err(e)   => crate::println!("Error: {:?}", e),
        },
        None => crate::println!("Page table not initialised."),
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for b in s.bytes() {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'a'..=b'f' => (b - b'a') as u64 + 10,
            b'A'..=b'F' => (b - b'A') as u64 + 10,
            _ => return None,
        };
        n = n.checked_mul(16)?.checked_add(digit)?;
    }
    Some(n)
}

fn parse_u32(s: &str) -> Option<u32> {
    let mut n: u32 = 0;
    if s.is_empty() {
        return None;
    }
    for b in s.bytes() {
        match b {
            b'0'..=b'9' => {
                n = n.checked_mul(10)?.checked_add((b - b'0') as u32)?;
            }
            _ => return None,
        }
    }
    Some(n)
}
