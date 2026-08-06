//! Interactive serial console — reads lines from COM1 and dispatches commands.

use crate::allocator::FrameAllocator;
use crate::capability::Capability;
use crate::framebuffer::FRAMEBUFFER;
use crate::heap::KERNEL_HEAP;
use crate::kernel::{Kernel, RuntimeDriveMode};
use crate::local_apic::{ApicIpiController, XApicController};
use crate::memory_graph::MemoryGraph;
use crate::message::Message;
use crate::network::{ExternalBackendKind, NetworkStack};
use crate::node::KernelNode;
use crate::object::KernelObject;
use crate::paging::{MapFlags, PageTableManager};
use crate::serial;
use spin::Mutex;

const MAX_LINE: usize = 128;
/// How many prior commands ↑/↓ can scroll through.
const HISTORY_CAP: usize = 32;

/// Ring of recent command lines for arrow-key navigation.
struct CmdHistory {
    slots: [[u8; MAX_LINE]; HISTORY_CAP],
    lens: [usize; HISTORY_CAP],
    /// Valid entry count (`0..=HISTORY_CAP`).
    count: usize,
}

impl CmdHistory {
    const fn new() -> Self {
        Self {
            slots: [[0u8; MAX_LINE]; HISTORY_CAP],
            lens: [0usize; HISTORY_CAP],
            count: 0,
        }
    }

    fn push(&mut self, line: &[u8]) {
        if line.is_empty() {
            return;
        }
        // Skip consecutive duplicates (bash-style).
        if self.count > 0 {
            let n = self.count - 1;
            let prev = &self.slots[n][..self.lens[n]];
            if prev == line {
                return;
            }
        }
        if self.count == HISTORY_CAP {
            for i in 0..HISTORY_CAP - 1 {
                self.slots[i] = self.slots[i + 1];
                self.lens[i] = self.lens[i + 1];
            }
            self.count = HISTORY_CAP - 1;
        }
        let i = self.count;
        let n = line.len().min(MAX_LINE);
        self.slots[i][..n].copy_from_slice(&line[..n]);
        self.lens[i] = n;
        self.count += 1;
    }

    fn get(&self, index: usize) -> Option<(&[u8], usize)> {
        if index >= self.count {
            return None;
        }
        let n = self.lens[index];
        Some((&self.slots[index][..n], n))
    }
}

const COMMANDS: &[&str] = &[
    "help",
    "?",
    "status",
    "clear",
    "create",
    "list",
    "schedule",
    "complete",
    "yield",
    "run",
    "running",
    "user-smoke",
    "elf-spawn",
    "elf-smoke",
    "ps",
    "reap",
    "irq-route",
    "send",
    "recv",
    "delete",
    "mem",
    "node",
    "discover",
    "net",
    "net-status",
    "netsend",
    "netrecv",
    "nettick",
    "netcaps",
    "netbind-in",
    "netbind-out",
    "netbind-list",
    "netbind-clear",
    "netadd-ext",
    "netpump",
    "net2obj",
    "obj2net",
    "cpus",
    "cpu-add-ap",
    "cpu-start-ap",
    "cpu-ack-ap",
    "cpu-arm-timer",
    "cpu-calibrate",
    "cpu-ipi-resched",
    "cpu-ipi-tlb",
    "cpu-step-ap",
    "cpu-halt",
    "ticks",
    "timeslice",
    "frames",
    "heapinfo",
    "palloc",
    "pfree",
    "fbinfo",
    "gpuinfo",
    "gpusmoke",
    "uminfo",
    "umalloc",
    "umfree",
    "um-smoke",
    "capsign",
    "capverify",
    "vmmap",
    "vmunmap",
    "vmtranslate",
    "vminfo",
    "echo",
    "panic",
];

/// Entry point that borrows static Mutex-wrapped state.
pub fn run_static(
    kernel: &'static Mutex<Kernel>,
    mem_graph: &'static Mutex<MemoryGraph>,
    node: &'static Mutex<KernelNode>,
    network: &'static Mutex<NetworkStack>,
    network_cap: &'static Mutex<Option<Capability>>,
    frame_alloc: &'static Mutex<FrameAllocator>,
    page_table: &'static Mutex<Option<PageTableManager>>,
) -> ! {
    crate::println!("\n--- CDK Serial Console ---");
    crate::println!("Type 'help' for available commands.\n");

    let mut buf = [0u8; MAX_LINE];
    let mut history = CmdHistory::new();

    loop {
        print_prompt();
        let len = read_line(&mut buf, &history);
        let line = core::str::from_utf8(&buf[..len]).unwrap_or("");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        history.push(line.as_bytes());
        dispatch(
            line,
            &mut kernel.lock(),
            &mut mem_graph.lock(),
            &mut node.lock(),
            &mut network.lock(),
            &network_cap.lock(),
            &mut frame_alloc.lock(),
            &mut page_table.lock(),
        );
    }
}

fn print_prompt() {
    use core::fmt::Write;
    let _ = write!(serial::SerialPort, "cdk> ");
}

fn ansi_cursor_left() {
    serial::write_byte(0x1b);
    serial::write_byte(b'[');
    serial::write_byte(b'D');
}

fn ansi_cursor_right() {
    serial::write_byte(0x1b);
    serial::write_byte(b'[');
    serial::write_byte(b'C');
}

/// Clear the displayed line back to an empty prompt input (cursor at column 0 of input).
fn clear_input_display(len: usize, cursor: usize) {
    // Move to end, then rub out each character.
    for _ in cursor..len {
        ansi_cursor_right();
    }
    for _ in 0..len {
        serial::write_byte(0x08);
        serial::write_byte(b' ');
        serial::write_byte(0x08);
    }
}

/// After buffer[cursor..len] changed, reprint that tail and park the cursor at `cursor`.
fn redraw_tail(buf: &[u8], cursor: usize, len: usize) {
    for i in cursor..len {
        serial::write_byte(buf[i]);
    }
    // Erase any leftover glyph from a shorter previous tail.
    serial::write_byte(b' ');
    // Physical cursor is at len+1; walk back to `cursor`.
    for _ in 0..(len + 1 - cursor) {
        ansi_cursor_left();
    }
}

fn apply_history_line(buf: &mut [u8; MAX_LINE], len: &mut usize, cursor: &mut usize, src: &[u8]) {
    clear_input_display(*len, *cursor);
    let copy_len = src.len().min(MAX_LINE);
    for i in 0..copy_len {
        buf[i] = src[i];
        serial::write_byte(src[i]);
    }
    *len = copy_len;
    *cursor = copy_len;
}

fn read_line(buf: &mut [u8; MAX_LINE], history: &CmdHistory) -> usize {
    let mut len = 0usize;
    let mut cursor = 0usize;
    // None = editing a fresh/draft line; Some(i) = viewing history[i] (0 = oldest).
    let mut hist_nav: Option<usize> = None;
    // Draft saved the first time ↑ leaves a non-history line (restored by ↓ past newest).
    let mut draft = [0u8; MAX_LINE];
    let mut draft_len = 0usize;

    loop {
        let b = serial::read_byte();
        match b {
            b'\r' | b'\n' => {
                serial::write_byte(b'\r');
                serial::write_byte(b'\n');
                return len;
            }
            // Backspace / DEL — delete the character before the cursor.
            0x08 | 0x7f => {
                if cursor == 0 {
                    continue;
                }
                hist_nav = None;
                cursor -= 1;
                for i in cursor..len.saturating_sub(1) {
                    buf[i] = buf[i + 1];
                }
                len -= 1;
                ansi_cursor_left();
                redraw_tail(buf, cursor, len);
            }
            // Ctrl-C — abandon current line
            0x03 => {
                serial::write_byte(b'^');
                serial::write_byte(b'C');
                serial::write_byte(b'\r');
                serial::write_byte(b'\n');
                return 0;
            }
            // Ctrl-A / Ctrl-E — home / end (handy when arrows are awkward).
            0x01 => {
                while cursor > 0 {
                    cursor -= 1;
                    ansi_cursor_left();
                }
            }
            0x05 => {
                while cursor < len {
                    ansi_cursor_right();
                    cursor += 1;
                }
            }
            // Ctrl-U — clear entire line.
            0x15 => {
                clear_input_display(len, cursor);
                len = 0;
                cursor = 0;
                hist_nav = None;
            }
            // Tab: command autocomplete (first token only).
            0x09 => {
                // Autocomplete only when the cursor is at the end of the first token.
                if cursor == len {
                    autocomplete_command(buf, &mut len);
                    cursor = len;
                    hist_nav = None;
                }
            }
            // ANSI escape sequence (arrow keys, Home/End/Delete).
            0x1b => {
                let b1 = serial::read_byte();
                if b1 != b'[' {
                    continue;
                }
                let mut b2 = serial::read_byte();
                // CSI params like `3~` (Delete) or `1~`/`4~` (Home/End).
                let mut param: u32 = 0;
                let mut saw_digit = false;
                while b2.is_ascii_digit() {
                    saw_digit = true;
                    param = param
                        .saturating_mul(10)
                        .saturating_add((b2 - b'0') as u32);
                    b2 = serial::read_byte();
                }
                match b2 {
                    // Up arrow: older history.
                    b'A' => {
                        if history.count == 0 {
                            continue;
                        }
                        let next = match hist_nav {
                            None => {
                                draft[..len].copy_from_slice(&buf[..len]);
                                draft_len = len;
                                Some(history.count - 1)
                            }
                            Some(0) => Some(0), // already at oldest
                            Some(i) => Some(i - 1),
                        };
                        if let Some(i) = next {
                            if let Some((src, _)) = history.get(i) {
                                apply_history_line(buf, &mut len, &mut cursor, src);
                                hist_nav = Some(i);
                            }
                        }
                    }
                    // Down arrow: newer history, then draft/empty.
                    b'B' => {
                        match hist_nav {
                            None => {
                                // Already on draft — stay (optionally clear like bash empty).
                            }
                            Some(i) if i + 1 < history.count => {
                                let i = i + 1;
                                if let Some((src, _)) = history.get(i) {
                                    apply_history_line(buf, &mut len, &mut cursor, src);
                                    hist_nav = Some(i);
                                }
                            }
                            Some(_) => {
                                // Past newest → restore draft.
                                apply_history_line(buf, &mut len, &mut cursor, &draft[..draft_len]);
                                hist_nav = None;
                            }
                        }
                    }
                    // Right arrow.
                    b'C' => {
                        if cursor < len {
                            ansi_cursor_right();
                            cursor += 1;
                        }
                    }
                    // Left arrow.
                    b'D' => {
                        if cursor > 0 {
                            cursor -= 1;
                            ansi_cursor_left();
                        }
                    }
                    // Home.
                    b'H' => {
                        while cursor > 0 {
                            cursor -= 1;
                            ansi_cursor_left();
                        }
                    }
                    // End.
                    b'F' => {
                        while cursor < len {
                            ansi_cursor_right();
                            cursor += 1;
                        }
                    }
                    // `ESC [ n ~` — Delete / Home / End variants.
                    b'~' if saw_digit => match param {
                        1 | 7 => {
                            while cursor > 0 {
                                cursor -= 1;
                                ansi_cursor_left();
                            }
                        }
                        3 => {
                            // Forward-delete character under the cursor.
                            if cursor < len {
                                hist_nav = None;
                                for i in cursor..len.saturating_sub(1) {
                                    buf[i] = buf[i + 1];
                                }
                                len -= 1;
                                redraw_tail(buf, cursor, len);
                            }
                        }
                        4 | 8 => {
                            while cursor < len {
                                ansi_cursor_right();
                                cursor += 1;
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            // Printable ASCII — insert at cursor (or append at end).
            0x20..=0x7e => {
                if len >= MAX_LINE {
                    continue;
                }
                hist_nav = None;
                if cursor == len {
                    buf[len] = b;
                    len += 1;
                    cursor += 1;
                    serial::write_byte(b);
                } else {
                    for i in (cursor..len).rev() {
                        buf[i + 1] = buf[i];
                    }
                    buf[cursor] = b;
                    len += 1;
                    redraw_tail(buf, cursor, len);
                    ansi_cursor_right();
                    cursor += 1;
                }
            }
            _ => {}
        }
    }
}

fn autocomplete_command(buf: &mut [u8; MAX_LINE], pos: &mut usize) {
    // Autocomplete only the command token (before first space).
    if buf[..*pos].contains(&b' ') {
        return;
    }
    let Ok(prefix) = core::str::from_utf8(&buf[..*pos]) else {
        return;
    };
    if prefix.is_empty() {
        return;
    }

    let mut matches = 0usize;
    let mut first_match = "";
    let mut common_len = 0usize;

    for cmd in COMMANDS.iter().copied() {
        if !cmd.starts_with(prefix) {
            continue;
        }
        if matches == 0 {
            first_match = cmd;
            common_len = cmd.len();
        } else {
            common_len = common_prefix_len(&first_match.as_bytes()[..common_len], cmd.as_bytes());
        }
        matches += 1;
    }

    if matches == 0 {
        return;
    }

    let prefix_len = prefix.len();
    let target_len = if matches == 1 {
        first_match.len()
    } else {
        common_len
    };

    if target_len > prefix_len {
        let bytes = first_match.as_bytes();
        for &b in &bytes[prefix_len..target_len] {
            if *pos >= MAX_LINE {
                break;
            }
            buf[*pos] = b;
            *pos += 1;
            serial::write_byte(b);
        }
    }

    // For a unique match, append a trailing space to move to args.
    if matches == 1 && *pos < MAX_LINE {
        buf[*pos] = b' ';
        *pos += 1;
        serial::write_byte(b' ');
    }
}

fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    let mut i = 0usize;
    let max = core::cmp::min(a.len(), b.len());
    while i < max && a[i] == b[i] {
        i += 1;
    }
    i
}

fn dispatch(
    line: &str,
    kernel: &mut Kernel,
    mem_graph: &mut MemoryGraph,
    node: &mut KernelNode,
    network: &mut NetworkStack,
    network_cap: &Option<Capability>,
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
        "status" => cmd_status(kernel, mem_graph, node, network, network_cap, page_table),
        "clear" => cmd_clear(),
        "create" => cmd_create(arg1, arg2, kernel, mem_graph),
        "list" => cmd_list(kernel),
        "schedule" => cmd_schedule(arg1, kernel),
        "complete" => cmd_complete(arg1, kernel),
        "yield" => cmd_yield(arg1, kernel),
        "run" => cmd_run_next(kernel),
        "user-smoke" => cmd_user_smoke(page_table, frame_alloc),
        "elf-spawn" => cmd_elf_spawn(page_table, frame_alloc, false),
        "elf-smoke" => cmd_elf_spawn(page_table, frame_alloc, true),
        "ps" => cmd_ps(),
        "reap" => cmd_reap(arg1),
        "irq-route" => cmd_irq_route(arg1, arg2),
        "send" => cmd_send(arg1, arg2, kernel),
        "recv" => cmd_recv(arg1, kernel),
        "delete" => cmd_delete(arg1, kernel, mem_graph),
        "mem" => cmd_mem(mem_graph),
        "node" => cmd_node(node),
        "discover" => cmd_discover(arg1, arg2, node),
        "net" | "net-status" => cmd_net_status(network),
        "netsend" => cmd_net_send(arg1, arg2, kernel, network, network_cap),
        "netrecv" => cmd_net_recv(arg1, kernel, network, network_cap),
        "nettick" => cmd_net_tick(kernel, network, network_cap),
        "netcaps" => cmd_netcaps(kernel, network_cap),
        "netbind-in" => cmd_netbind_in(arg1, arg2, kernel),
        "netbind-out" => cmd_netbind_out(arg1, arg2, kernel),
        "netbind-list" => cmd_netbind_list(kernel),
        "netbind-clear" => cmd_netbind_clear(kernel),
        "netadd-ext" => cmd_netadd_ext(arg1, arg2, network),
        "netpump" => cmd_netpump(arg1, kernel, network, network_cap),
        "net2obj" => cmd_net_to_obj(arg1, arg2, kernel, network, network_cap),
        "obj2net" => cmd_obj_to_net(arg1, arg2, kernel, network, network_cap),
        "cpus" => cmd_cpus(kernel),
        "cpu-add-ap" => cmd_cpu_add_ap(arg1, kernel),
        "cpu-start-ap" => cmd_cpu_start_ap(arg1, arg2, kernel),
        "cpu-ack-ap" => cmd_cpu_ack_ap(arg1, arg2, kernel),
        "cpu-arm-timer" => cmd_cpu_arm_timer(kernel),
        "cpu-calibrate" => cmd_cpu_calibrate(arg1, kernel),
        "cpu-ipi-resched" => cmd_cpu_ipi_resched(arg1, kernel),
        "cpu-ipi-tlb" => cmd_cpu_ipi_tlb(arg1, arg2, kernel),
        "cpu-step-ap" => cmd_cpu_step_ap(arg1, arg2, kernel),
        "cpu-halt" => cmd_cpu_halt(arg1, kernel),
        #[cfg(target_os = "none")]
        "ticks" => crate::println!("Timer ticks: {}", crate::interrupts::ticks()),
        #[cfg(not(target_os = "none"))]
        "ticks" => crate::println!("Timer ticks: (unavailable outside bare-metal)"),
        "timeslice" => cmd_timeslice(),
        "running" => cmd_running(kernel),
        "frames" => cmd_frames(frame_alloc),
        "heapinfo" => cmd_heapinfo(),
        "palloc" => cmd_palloc(frame_alloc),
        "pfree" => cmd_pfree(arg1, frame_alloc),
        "fbinfo" => cmd_fbinfo(),
        "gpuinfo" => cmd_gpuinfo(),
        "gpusmoke" => cmd_gpusmoke(),
        "uminfo" => cmd_uminfo(),
        "umalloc" => cmd_umalloc(arg1, frame_alloc),
        "umfree" => cmd_umfree(arg1, frame_alloc),
        "um-smoke" => cmd_um_smoke(frame_alloc),
        "capsign" => cmd_capsign(arg1, kernel),
        "capverify" => cmd_capverify(arg1, kernel),
        "vmmap" => cmd_vmmap(arg1, arg2, arg3, page_table, frame_alloc, kernel),
        "vmunmap" => cmd_vmunmap(arg1, page_table, kernel),
        "vmtranslate" => cmd_vmtranslate(arg1, page_table),
        "vminfo" => cmd_vminfo(page_table),
        "echo" => crate::println!("{} {}", arg1, arg2),
        "panic" => panic!("user-triggered panic"),
        _ => crate::println!("Unknown command: '{}'. Type 'help'.", cmd),
    }
}

fn cmd_help() {
    crate::println!("Commands:");
    crate::println!("  Line edit: ←/→ move, Home/End, Del, ↑/↓ history ({} cmds)", HISTORY_CAP);
    crate::println!("             Backspace, Ctrl-A/E home/end, Ctrl-U wipe, Ctrl-C abort");
    crate::println!("  help              Show this message");
    crate::println!("  status            Kernel overview (includes preemption info)");
    crate::println!("  clear             Clear serial screen");
    crate::println!("  create <name> <intent>");
    crate::println!("                    Create a compute object (intents: low_latency,");
    crate::println!("                    interactive, normal, batch, energy_saving)");
    crate::println!("  list              List registered objects");
    crate::println!("  schedule <ref>    Queue object by id, name (kind), or intent");
    crate::println!("  complete [apic]   Retire running task (default apic 0)");
    crate::println!("  yield [apic]      Requeue running task (default apic 0)");
    crate::println!("  run               Manually dispatch next task (ignores preemption)");
    crate::println!("  running           Show the currently running task");
    crate::println!("  user-smoke        Ring-3 smoke test (syscall exit)");
    crate::println!("  elf-spawn         Load smoke ELF into process table (no enter)");
    crate::println!("  elf-smoke         Load smoke ELF and enter ring-3");
    crate::println!("  ps                List processes");
    crate::println!("  reap <pid>        Reap a Zombie process");
    crate::println!("  irq-route <irq> <apic>  Route IOAPIC IRQ affinity");
    crate::println!("  send <id> <text>  Send a text message to an object");
    crate::println!("  recv <id>         Receive next message from an object");
    crate::println!("  delete <id>       Delete an object");
    crate::println!("  mem               Memory graph summary");
    crate::println!("  node              Show this node's info");
    crate::println!("  discover <id> <latency_ms>");
    crate::println!("                    Simulate discovering a remote node");
    crate::println!("  net / net-status  Show network interface and packet stats");
    crate::println!("  netsend <if> <text>");
    crate::println!("                    Queue packet bytes to interface");
    crate::println!("  netrecv <if>      Receive one packet from interface RX queue");
    crate::println!("  nettick           Service network + run one bridge routing cycle");
    crate::println!("  netcaps           Show capability-attributed network telemetry");
    crate::println!("  netbind-in <if> <obj>");
    crate::println!("                    Bind interface ingress to object queue");
    crate::println!("  netbind-out <obj> <if>");
    crate::println!("                    Bind object egress to interface TX");
    crate::println!("  netbind-list      List active bridge bindings");
    crate::println!("  netbind-clear     Clear all bridge bindings");
    crate::println!("  netadd-ext <if> <backend>");
    crate::println!(
        "                    Register external interface backend (virtio-net|stub-tap)"
    );
    crate::println!("  netpump <n>       Run N automated bridge routing cycles (default 1)");
    crate::println!("  net2obj <if> <obj>");
    crate::println!("                    Bridge one received packet into object queue");
    crate::println!("  obj2net <obj> <if>");
    crate::println!("                    Bridge one object message out as packet bytes");
    crate::println!("  cpus              Show multi-core topology and telemetry");
    crate::println!("  cpu-add-ap <id>   Register application core by APIC id");
    crate::println!("  cpu-start-ap <id> [force]");
    crate::println!("                    Launch AP (wait for trampoline status; force=BSP ack)");
    crate::println!("  cpu-ack-ap <id> <seq>");
    crate::println!("                    Mark AP startup sequence as entry-reached/online");
    crate::println!("  cpu-arm-timer     Arm this CPU's local APIC timer (vector 0xF0)");
    crate::println!("  cpu-calibrate [hz]");
    crate::println!("                    Calibrate this CPU's LAPIC timer against PIT ticks");
    crate::println!("  cpu-ipi-resched <id>");
    crate::println!("                    Send Fixed reschedule IPI to APIC id");
    crate::println!("  cpu-ipi-tlb <id|all> [page|#]");
    crate::println!("                    Send Fixed TLB shootdown IPI (0xF2); # = full flush");
    crate::println!("  cpu-step-ap <id> <n>");
    crate::println!("                    Debug: software-inject N local timer ticks");
    crate::println!("  cpu-halt <id>     Mark core halted by APIC id");
    crate::println!("  ticks             Show PIT timer tick count since boot");
    crate::println!("  timeslice         Show the preemptive time-slice length (ticks)");
    crate::println!("  fbinfo            Pixel framebuffer info (resolution, format)");
    crate::println!("  gpuinfo           GPU backend / resource / flush telemetry");
    crate::println!("  gpusmoke          Fill+flush test pattern via GPU pipeline");
    crate::println!("  uminfo            Unified memory regions + IOMMU stub");
    crate::println!("  umalloc <bytes>   Alloc contiguous CPU/GPU shared region");
    crate::println!("  umfree <id>       Free a unified memory region");
    crate::println!("  um-smoke          Alloc+fill+fence(+GPU attach) smoke");
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
    crate::println!("  (Tip) ↑/↓ scroll command history, Tab autocompletes command");
}

fn cmd_clear() {
    use core::fmt::Write;
    let _ = write!(serial::SerialPort, "\x1b[2J\x1b[H");
}

fn cmd_status(
    kernel: &mut Kernel,
    mem_graph: &MemoryGraph,
    node: &KernelNode,
    network: &NetworkStack,
    network_cap: &Option<Capability>,
    page_table: &Option<PageTableManager>,
) {
    crate::println!("=== CDK Kernel Status ===");
    crate::println!("  Node:         {}", node.node_id());
    crate::println!("  Objects:      {}", kernel.object_count());
    crate::println!("  Sched queue:  {}", kernel.scheduler_queue_size());
    crate::println!(
        "  Running:       count={} mask={:#x}",
        kernel.scheduler_running_count(),
        kernel.scheduler_running_mask()
    );
    match kernel.running_task_id() {
        Some(id) => crate::println!("  BSP task:      {}", id),
        None => crate::println!("  BSP task:      (idle)"),
    }
    crate::println!(
        "  Time slice:   {} ticks (~{}ms at 1kHz)",
        crate::scheduler::TICKS_PER_SLICE,
        crate::scheduler::TICKS_PER_SLICE
    );
    crate::println!("  Memory:       {} bytes tracked", mem_graph.total_memory());
    crate::println!("  Mem objects:  {}", mem_graph.object_count());
    crate::println!("  Known nodes:  {}", node.known_nodes_count());
    let cores = kernel.multicore_summary();
    match cores.bsp_apic_id {
        Some(bsp) => crate::println!(
            "  CPU cores:     known={} online={} booting={} bsp={}",
            cores.known_cores,
            cores.online_cores,
            cores.booting_cores,
            bsp
        ),
        None => crate::println!(
            "  CPU cores:     known={} online={} booting={} bsp=(none)",
            cores.known_cores,
            cores.online_cores,
            cores.booting_cores
        ),
    }
    crate::println!(
        "  CPU telemetry: ticks={} dispatches={} completions={} steals={}",
        cores.total_ticks_seen,
        cores.total_dispatches,
        cores.total_completions,
        cores.total_steals
    );
    let net = network.summary();
    crate::println!(
        "  Network:      {} iface(s), {} external, tx={}, rx={}, ticks={}",
        net.interfaces,
        net.external_interfaces,
        net.total_tx_packets,
        net.total_rx_packets,
        net.service_ticks
    );
    crate::println!(
        "  Net queues:   tx_depth={}, rx_depth={}",
        net.total_tx_queue_depth,
        net.total_rx_queue_depth
    );
    if let Some(cap) = network_cap.as_ref() {
        if let Some(stats) = kernel.network_stats_for(cap.object_id.as_str()) {
            crate::println!(
                "  Net cap '{}': send(ok={}, err={}) recv(ok={}, empty={}, err={})",
                cap.object_id.as_str(),
                stats.send_ok,
                stats.send_err,
                stats.recv_ok,
                stats.recv_empty,
                stats.recv_err
            );
        }
    }
    let (in_bindings, out_bindings) = kernel.bridge_binding_counts();
    let bridge = kernel.bridge_telemetry();
    crate::println!(
        "  Bridge:       in_bindings={} out_bindings={} in_moved={} out_moved={}",
        in_bindings,
        out_bindings,
        bridge.ingress_moved,
        bridge.egress_moved
    );
    match page_table {
        Some(pt) => crate::println!(
            "  VM pages:     {} mapped (PML4 @ {:#x})",
            pt.mapped_pages(),
            pt.pml4_phys()
        ),
        None => crate::println!("  VM pages:     (page table not initialised)"),
    }
    if KERNEL_HEAP.is_initialised() {
        crate::println!(
            "  Heap:         {} KiB used / {} KiB total",
            KERNEL_HEAP.used_bytes() / 1024,
            KERNEL_HEAP.total_bytes() / 1024
        );
    } else {
        crate::println!("  Heap:         (not initialised)");
    }
    match FRAMEBUFFER.lock().as_ref() {
        Some(fb) => crate::println!(
            "  Framebuffer:  {}x{} px ({}x{} chars)",
            fb.width(),
            fb.height(),
            fb.cols(),
            fb.rows()
        ),
        None => crate::println!("  Framebuffer:  (not initialised)"),
    }
}

fn cmd_timeslice() {
    crate::println!(
        "Time slice: {} ticks (~{}ms at default PIT ~1kHz)",
        crate::scheduler::TICKS_PER_SLICE,
        crate::scheduler::TICKS_PER_SLICE
    );
}

fn cmd_running(kernel: &Kernel) {
    let mask = kernel.scheduler_running_mask();
    if mask == 0 {
        crate::println!("(idle — no task currently running)");
        return;
    }
    crate::println!(
        "Running slots: count={} mask={:#x}",
        kernel.scheduler_running_count(),
        mask
    );
    for apic in 0u32..8 {
        if let Some(id) = kernel.running_task_id_on(apic) {
            crate::println!("  apic_id={} task={}", apic, id);
        }
    }
}

fn cmd_gpuinfo() {
    let s = crate::gpu::status();
    crate::println!("=== GPU ===");
    crate::println!(
        "  Ready:     {}  backend={}",
        s.ready,
        crate::gpu::backend_name(s.backend)
    );
    crate::println!("  Display:   {}x{}", s.width, s.height);
    crate::println!(
        "  Resource:  id={} scanout={}",
        s.resource_id,
        s.scanout_id
    );
    crate::println!("  Flushes:   {}", s.flushes);
    crate::println!(
        "  HW probe:  {}  mmio={:#x}",
        s.hw_probed,
        s.hw_mmio
    );
    if let Some(e) = s.last_error {
        crate::println!("  Last err:  {}", e);
    }
}

fn cmd_gpusmoke() {
    match crate::gpu::smoke_fill() {
        Ok(()) => {
            let s = crate::gpu::status();
            crate::println!(
                "GPU smoke OK ({}x{}, flushes={}, backend={})",
                s.width,
                s.height,
                s.flushes,
                crate::gpu::backend_name(s.backend)
            );
        }
        Err(e) => crate::println!("GPU smoke failed: {}", e),
    }
}

fn cmd_uminfo() {
    let s = crate::um::status();
    crate::println!("=== Unified Memory ===");
    crate::println!("  Regions:   {}", s.regions);
    crate::println!("  Bytes:     {}", s.bytes_total);
    crate::println!("  Next id:   {}", s.next_id);
    crate::println!(
        "  IOMMU:     present={} mode={}",
        s.iommu.present,
        s.iommu.mode
    );
    crate::um::for_each(|r| {
        crate::println!(
            "  - id={} phys={:#x} va={:#x} len={} frames={}",
            r.id,
            r.guest_phys,
            r.cpu_va,
            r.len,
            r.frame_count
        );
        if let Some(gid) = r.gpu_resource_id {
            crate::println!("      gpu_resource_id={}", gid);
        }
    });
}

fn cmd_umalloc(bytes_str: &str, frame_alloc: &mut FrameAllocator) {
    let Some(bytes) = parse_u32(bytes_str) else {
        crate::println!("Usage: umalloc <bytes>");
        return;
    };
    match crate::um::alloc(frame_alloc, bytes as usize) {
        Ok(r) => crate::println!(
            "UM alloc id={} phys={:#x} va={:#x} len={} frames={}",
            r.id,
            r.guest_phys,
            r.cpu_va,
            r.len,
            r.frame_count
        ),
        Err(e) => crate::println!("UM alloc failed: {:?}", e),
    }
}

fn cmd_umfree(id_str: &str, frame_alloc: &mut FrameAllocator) {
    let Some(id) = parse_u32(id_str) else {
        crate::println!("Usage: umfree <id>");
        return;
    };
    match crate::um::free(frame_alloc, id) {
        Ok(()) => crate::println!("UM freed id={}", id),
        Err(e) => crate::println!("UM free failed: {:?}", e),
    }
}

fn cmd_um_smoke(frame_alloc: &mut FrameAllocator) {
    match crate::um::smoke(frame_alloc) {
        Ok(r) => crate::println!(
            "UM smoke done id={} phys={:#x} gpu_res={:?}",
            r.id,
            r.guest_phys,
            r.gpu_resource_id
        ),
        Err(e) => crate::println!("UM smoke failed: {:?}", e),
    }
}

fn cmd_fbinfo() {
    match FRAMEBUFFER.lock().as_ref() {
        Some(fb) => {
            crate::println!("=== Pixel Framebuffer ===");
            crate::println!("  Resolution : {}x{} px", fb.width(), fb.height());
            crate::println!(
                "  Text grid  : {}x{} chars ({}x{} px/char)",
                fb.cols(),
                fb.rows(),
                crate::framebuffer::CHAR_W,
                crate::framebuffer::CHAR_H
            );
        }
        None => crate::println!("Framebuffer: not initialised"),
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
                Ok(true) => crate::println!("  Signature valid ✓"),
                Ok(false) => crate::println!("  WARNING: signature not present"),
                Err(e) => crate::println!("  ERROR: verification failed: {:?}", e),
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
        Ok(true) => crate::println!("Capability for '{}': signature valid", id),
        Ok(false) => crate::println!("Capability for '{}': unsigned (no signature)", id),
        Err(e) => crate::println!("Capability for '{}': error: {:?}", id, e),
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
    crate::println!(
        "Created object '{}' (id={}, intent={})",
        name,
        id_str,
        intent
    );
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
        crate::println!("Usage: schedule <id|name|intent>");
        return;
    }
    match kernel.schedule_by_id(id) {
        Ok(()) => {}
        Err(crate::kernel::KernelError::ObjectAmbiguous) => crate::println!(
            "Error: ObjectAmbiguous — more than one object matches '{}'; use obj-N id",
            id
        ),
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_complete(apic_str: &str, kernel: &mut Kernel) {
    let apic = if apic_str.is_empty() {
        0
    } else {
        match parse_u32(apic_str) {
            Some(v) => v,
            None => {
                crate::println!("Usage: complete [apic-id]");
                return;
            }
        }
    };
    if kernel.running_task_id_on(apic).is_none() {
        crate::println!("(no running task on apic_id={})", apic);
        return;
    }
    kernel.complete_running_on_core(apic);
}

fn cmd_yield(apic_str: &str, kernel: &mut Kernel) {
    let apic = if apic_str.is_empty() {
        0
    } else {
        match parse_u32(apic_str) {
            Some(v) => v,
            None => {
                crate::println!("Usage: yield [apic-id]");
                return;
            }
        }
    };
    match kernel.yield_running_on_core(apic) {
        Some(id) => crate::println!("Yielded {} on apic_id={}", id, apic),
        None => crate::println!("(no running task on apic_id={})", apic),
    }
}

fn cmd_run_next(kernel: &mut Kernel) {
    match kernel.execute_next() {
        Some(id) => crate::println!("Dispatched: {}", id),
        None => match kernel.running_task_id() {
            Some(id) => crate::println!("(task '{}' already running — wait for preemption)", id),
            None => crate::println!("(scheduler queue empty)"),
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
    crate::println!(
        "Memory: {} bytes across {} objects",
        mem_graph.total_memory(),
        mem_graph.object_count()
    );
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

fn cmd_cpus(kernel: &Kernel) {
    let summary = kernel.multicore_summary();
    crate::println!("=== CPU Topology ===");
    crate::println!("  Known cores : {}", summary.known_cores);
    crate::println!("  Online cores: {}", summary.online_cores);
    match summary.bsp_apic_id {
        Some(id) => crate::println!("  BSP apic_id : {}", id),
        None => crate::println!("  BSP apic_id : (not registered)"),
    }
    crate::println!(
        "  Telemetry   : ticks={} dispatches={} completions={} steals={}",
        summary.total_ticks_seen,
        summary.total_dispatches,
        summary.total_completions,
        summary.total_steals
    );
    let mailbox = kernel.startup_mailbox();
    let layout = kernel.trampoline_layout();
    crate::println!(
        "  Startup box : trampoline={:#x} vector={:#x} entry={:#x} stack_top={:#x} handoff={:#x}/{}B installed={}@seq{} pending={:?} acked={:?} seq={}",
        mailbox.trampoline_phys,
        mailbox.sipi_vector,
        mailbox.trampoline_entry_phys,
        mailbox.stack_top_phys,
        mailbox.handoff_phys,
        mailbox.handoff_size_bytes,
        mailbox.trampoline_installed,
        mailbox.trampoline_installed_seq,
        mailbox.pending_apic_id,
        mailbox.last_acked_apic_id,
        mailbox.startup_seq
    );
    crate::println!(
        "  Trampoline  : slot={:#x}/{}B code={:#x}/{}B(blob={}B csum={:#x}) mailbox={:#x}/{}B stack={}B",
        layout.slot_base_phys,
        layout.slot_size_bytes,
        layout.code_base_phys,
        layout.code_size_bytes,
        layout.trampoline_blob_size_bytes,
        mailbox.trampoline.checksum,
        layout.mailbox_base_phys,
        layout.mailbox_size_bytes,
        layout.stack_size_bytes
    );
    crate::println!(
        "  AP handoff  : sig={:#x} apic={} kernel_entry={:#x} pt_root={:#x} tramp_status={}",
        mailbox.handoff.signature,
        mailbox.handoff.target_apic_id,
        mailbox.handoff.kernel_entry_phys,
        mailbox.handoff.page_table_root_phys,
        kernel.read_trampoline_status()
    );
    kernel.for_each_core(|core| {
        let role = match core.role {
            crate::multicore::CoreRole::Bootstrap => "bsp",
            crate::multicore::CoreRole::Application => "ap",
        };
        let state = match core.state {
            crate::multicore::CoreState::Registered => "registered",
            crate::multicore::CoreState::Booting => "booting",
            crate::multicore::CoreState::Online => "online",
            crate::multicore::CoreState::Halted => "halted",
        };
        let drive = match kernel.runtime_drive_mode(core.apic_id) {
            RuntimeDriveMode::BspProxy => "bsp-proxy",
            RuntimeDriveMode::LocalApic => "lapic-local",
        };
        crate::println!(
            "  - apic_id={} role={} state={} drive={} rq={} steals={} run={} starts={} ticks={} dispatches={} completions={} rtick={} tcal={} tss={} rsp0={:#x} ipi={} idle={} wake={} tlb={}",
            core.apic_id,
            role,
            state,
            drive,
            core.run_queue_depth,
            core.steals,
            if kernel.running_task_id_on(core.apic_id).is_some() {
                "busy"
            } else {
                "-"
            },
            core.startup_attempts,
            core.ticks_seen,
            core.dispatches,
            core.completions,
            kernel.runtime_tick_cursor(core.apic_id),
            kernel
                .timer_calibration(core.apic_id)
                .map(|c| c.initial_count)
                .unwrap_or(0),
            {
                #[cfg(target_os = "none")]
                {
                    if core.apic_id == 0 {
                        "bsp"
                    } else if crate::gdt::ap_tss_ready(core.apic_id) {
                        "private"
                    } else if crate::gdt::ap_tss_supported(core.apic_id) {
                        "pending"
                    } else {
                        "none"
                    }
                }
                #[cfg(not(target_os = "none"))]
                {
                    if core.apic_id == 0 {
                        "bsp"
                    } else {
                        "host"
                    }
                }
            },
            {
                #[cfg(target_os = "none")]
                {
                    crate::gdt::kernel_stack_top(core.apic_id).unwrap_or(0)
                }
                #[cfg(not(target_os = "none"))]
                {
                    0u64
                }
            },
            if crate::multicore::reschedule_pending(core.apic_id) {
                "pend"
            } else {
                "-"
            },
            if crate::multicore::is_idle(core.apic_id) {
                "hlt"
            } else {
                "-"
            },
            crate::multicore::wake_count(core.apic_id),
            if crate::multicore::tlb_shootdown_pending(core.apic_id) {
                "pend"
            } else {
                "-"
            }
        );
    });
}

fn cmd_cpu_add_ap(apic_id_str: &str, kernel: &mut Kernel) {
    let Some(id) = parse_u32(apic_id_str) else {
        crate::println!("Usage: cpu-add-ap <apic-id>");
        return;
    };
    match kernel.register_core(id, crate::multicore::CoreRole::Application) {
        Ok(()) => crate::println!("Registered AP core apic_id={}", id),
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_cpu_start_ap(apic_id_str: &str, mode_str: &str, kernel: &mut Kernel) {
    let Some(id) = parse_u32(apic_id_str) else {
        crate::println!("Usage: cpu-start-ap <apic-id> [force]");
        return;
    };
    let force = mode_str == "force";
    match kernel.plan_ap_startup(id) {
        Ok(plan) => {
            let mut apic = XApicController::new();
            if !apic.bringup_ap(plan.apic_id, plan.sipi_vector) {
                crate::println!(
                    "AP startup plan issued but INIT/SIPI not acknowledged: apic_id={} vector={:#x}",
                    plan.apic_id,
                    plan.sipi_vector
                );
                return;
            }

            crate::println!(
                "AP INIT/SIPI issued: apic_id={} vector={:#x} seq={} entry={:#x} (waiting for trampoline status)",
                plan.apic_id,
                plan.sipi_vector,
                plan.startup_seq,
                plan.entry_phys
            );

            if force {
                match kernel.ap_trampoline_entry_hook(plan.apic_id, plan.startup_seq) {
                    Ok(()) => {
                        kernel.activate_ap_local_timer(plan.apic_id);
                        crate::println!(
                            "AP force-acked on BSP: apic_id={} seq={} drive=lapic-local (debug path)",
                            plan.apic_id,
                            plan.startup_seq
                        );
                    }
                    Err(e) => crate::println!("Error force-acking AP: {:?}", e),
                }
                return;
            }

            // Phase 14: wait for the AP to publish trampoline status instead of
            // immediately soft-acking on the BSP.
            let mut status = 0u32;
            for _ in 0..500_000u32 {
                status = kernel.read_trampoline_status();
                if Kernel::trampoline_status_entered(status)
                    || status == crate::multicore::AP_STATUS_BAD_SIGNATURE
                {
                    break;
                }
                crate::local_apic::spin_delay(50);
            }

            if crate::multicore::MultiCoreManager::trampoline_status_handoff(status) {
                crate::println!(
                    "AP trampoline long-mode handoff: apic_id={} status={}",
                    plan.apic_id,
                    status
                );
            } else if Kernel::trampoline_status_entered(status) {
                crate::println!(
                    "AP trampoline executed: apic_id={} status={} (use cpu-ack-ap {} {} if AP did not self-online)",
                    plan.apic_id,
                    status,
                    plan.apic_id,
                    plan.startup_seq
                );
            } else if status == crate::multicore::AP_STATUS_BAD_SIGNATURE {
                crate::println!(
                    "AP trampoline reported bad handoff signature (status={:#x})",
                    status
                );
            } else {
                crate::println!(
                    "AP trampoline status timeout (status={}); INIT/SIPI may have failed — try cpu-start-ap {} force or cpu-ack-ap {} {}",
                    status,
                    plan.apic_id,
                    plan.apic_id,
                    plan.startup_seq
                );
            }
        }
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_cpu_ack_ap(apic_id_str: &str, seq_str: &str, kernel: &mut Kernel) {
    let Some(id) = parse_u32(apic_id_str) else {
        crate::println!("Usage: cpu-ack-ap <apic-id> <startup-seq>");
        return;
    };
    let Some(seq) = parse_u32(seq_str) else {
        crate::println!("Usage: cpu-ack-ap <apic-id> <startup-seq>");
        return;
    };
    match kernel.ap_entry_reached_with_seq(id, seq) {
        Ok(()) => {
            kernel.activate_ap_local_timer(id);
            crate::println!(
                "AP online acknowledged: apic_id={} seq={} drive=lapic-local tramp_status={}",
                id,
                seq,
                kernel.read_trampoline_status()
            );
            crate::println!(
                "  note: arm hardware with cpu-arm-timer / cpu-calibrate on that core; cpu-step-ap remains debug inject"
            );
        }
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_cpu_arm_timer(kernel: &mut Kernel) {
    let apic = XApicController::new();
    let local_id = apic.local_apic_id();
    let config = if local_id == 0 {
        kernel.timer_config_for_core(local_id)
    } else {
        kernel.ensure_ap_timer_calibration(local_id)
    };
    if !apic.arm_ap_runtime_timer_with(config) {
        crate::println!("Error: failed to program local APIC timer");
        return;
    }
    kernel.activate_ap_local_timer(local_id);
    crate::println!(
        "LAPIC timer armed: local_apic={} vector={:#x} divide=16 count={} drive=lapic-local",
        local_id,
        crate::local_apic::LOCAL_APIC_TIMER_VECTOR,
        config.initial_count
    );
}

fn cmd_cpu_calibrate(hz_str: &str, kernel: &mut Kernel) {
    let target_hz = if hz_str.is_empty() {
        crate::local_apic::TARGET_RUNTIME_TIMER_HZ
    } else {
        let Some(v) = parse_u32(hz_str) else {
            crate::println!("Usage: cpu-calibrate [hz]");
            return;
        };
        if v == 0 {
            crate::println!("Usage: cpu-calibrate [hz]");
            return;
        }
        v
    };

    let apic = XApicController::new();
    let local_id = apic.local_apic_id();
    #[cfg(target_os = "none")]
    let config = apic.calibrate_periodic_timer(target_hz, crate::interrupts::ticks);
    #[cfg(not(target_os = "none"))]
    let config = apic.calibrate_periodic_timer(target_hz, || 0);

    kernel.set_timer_calibration(local_id, config);
    if !apic.arm_ap_runtime_timer_with(config) {
        crate::println!(
            "Calibrated count={} but failed to arm timer (apic={})",
            config.initial_count,
            local_id
        );
        return;
    }
    kernel.activate_ap_local_timer(local_id);
    crate::println!(
        "LAPIC timer calibrated: local_apic={} target_hz={} count={} vector={:#x} drive=lapic-local",
        local_id,
        target_hz,
        config.initial_count,
        crate::local_apic::LOCAL_APIC_TIMER_VECTOR
    );
}

fn cmd_cpu_ipi_resched(apic_id_str: &str, kernel: &mut Kernel) {
    let Some(id) = parse_u32(apic_id_str) else {
        crate::println!("Usage: cpu-ipi-resched <apic-id>");
        return;
    };
    kernel.request_reschedule_ipi(id);
    crate::println!(
        "Reschedule IPI queued: apic_id={} vector={:#x} pending={} idle={} wake={} mask={:#x}",
        id,
        crate::local_apic::RESCHEDULE_IPI_VECTOR,
        crate::multicore::reschedule_pending(id),
        crate::multicore::is_idle(id),
        crate::multicore::wake_count(id),
        crate::multicore::reschedule_pending_mask()
    );
}

fn cmd_cpu_ipi_tlb(target_str: &str, page_str: &str, kernel: &mut Kernel) {
    if target_str.is_empty() {
        crate::println!("Usage: cpu-ipi-tlb <apic-id|all> [page|#]");
        crate::println!("  page=# or omitted → full TLB flush; else invalidate that VA");
        return;
    }
    let page = if page_str.is_empty() || page_str == "#" {
        0u64
    } else {
        match parse_hex(page_str) {
            Some(v) => v,
            None => {
                crate::println!("Usage: cpu-ipi-tlb <apic-id|all> [page|#]");
                return;
            }
        }
    };
    if target_str == "all" {
        let sent = kernel.broadcast_tlb_shootdown(page, 0);
        crate::println!(
            "TLB shootdown broadcast: page={:#x} vector={:#x} targets={} pending_mask={:#x}",
            page,
            crate::local_apic::TLB_SHOOTDOWN_IPI_VECTOR,
            sent,
            crate::multicore::tlb_shootdown_pending_mask()
        );
        return;
    }
    let Some(id) = parse_u32(target_str) else {
        crate::println!("Usage: cpu-ipi-tlb <apic-id|all> [page|#]");
        return;
    };
    kernel.request_tlb_shootdown_ipi(id, page);
    crate::println!(
        "TLB shootdown IPI queued: apic_id={} page={:#x} vector={:#x} pending={}",
        id,
        page,
        crate::local_apic::TLB_SHOOTDOWN_IPI_VECTOR,
        crate::multicore::tlb_shootdown_pending(id)
    );
}

fn cmd_cpu_step_ap(apic_id_str: &str, steps_str: &str, kernel: &mut Kernel) {
    let Some(id) = parse_u32(apic_id_str) else {
        crate::println!("Usage: cpu-step-ap <apic-id> <steps>");
        return;
    };
    let steps = if steps_str.is_empty() {
        1
    } else {
        let Some(v) = parse_u32(steps_str) else {
            crate::println!("Usage: cpu-step-ap <apic-id> <steps>");
            return;
        };
        if v == 0 {
            crate::println!("Usage: cpu-step-ap <apic-id> <steps>");
            return;
        }
        v
    };

    let mut dispatched = 0u32;
    for _ in 0..steps {
        // Direct kernel step (console already holds KERNEL); preferred
        // production path is hardware LAPIC IRQ after cpu-arm-timer / AP entry.
        if kernel.on_local_apic_timer_tick(id).is_some() {
            dispatched = dispatched.saturating_add(1);
        }
    }
    let drive = match kernel.runtime_drive_mode(id) {
        RuntimeDriveMode::BspProxy => "bsp-proxy",
        RuntimeDriveMode::LocalApic => "lapic-local",
    };
    crate::println!(
        "AP runtime software-stepped: apic_id={} steps={} drive={} local_tick={} dispatched={} (prefer hardware LAPIC timer)",
        id,
        steps,
        drive,
        kernel.runtime_tick_cursor(id),
        dispatched
    );
}

fn cmd_cpu_halt(apic_id_str: &str, kernel: &mut Kernel) {
    let Some(id) = parse_u32(apic_id_str) else {
        crate::println!("Usage: cpu-halt <apic-id>");
        return;
    };
    match kernel.halt_core(id) {
        Ok(()) => crate::println!("Core halted: apic_id={}", id),
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_net_status(network: &NetworkStack) {
    let summary = network.summary();
    crate::println!("=== Network ===");
    crate::println!("  Interfaces: {}", summary.interfaces);
    crate::println!(
        "  Totals: tx={} rx={} tx_drop={} rx_drop={} ticks={}",
        summary.total_tx_packets,
        summary.total_rx_packets,
        summary.total_tx_dropped,
        summary.total_rx_dropped,
        summary.service_ticks
    );
    crate::println!(
        "  Queue depth: tx={} rx={}",
        summary.total_tx_queue_depth,
        summary.total_rx_queue_depth
    );
    network.for_each_interface(|name, kind, stats, tx_depth, rx_depth| {
        crate::println!(
            "  - {} [{}]: tx={} rx={} tx_drop={} rx_drop={} tx_q={} rx_q={} tx_hwm={} rx_hwm={} polls={}",
            name,
            kind.as_str(),
            stats.tx_packets,
            stats.rx_packets,
            stats.tx_dropped,
            stats.rx_dropped,
            tx_depth,
            rx_depth,
            stats.tx_high_watermark,
            stats.rx_high_watermark,
            stats.backend_polls
        );
    });
}

fn cmd_netadd_ext(iface: &str, backend: &str, network: &mut NetworkStack) {
    if iface.is_empty() || backend.is_empty() {
        crate::println!("Usage: netadd-ext <if> <backend>");
        return;
    }
    let Some(kind) = ExternalBackendKind::parse(backend) else {
        crate::println!("Error: unsupported backend '{}'", backend);
        crate::println!("Supported: virtio-net, stub-tap");
        return;
    };
    match network.add_external_interface(iface, kind) {
        Ok(()) => crate::println!("Added external interface '{}' ({})", iface, kind.as_str()),
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_net_send(
    iface: &str,
    text: &str,
    kernel: &mut Kernel,
    network: &mut NetworkStack,
    network_cap: &Option<Capability>,
) {
    if iface.is_empty() || text.is_empty() {
        crate::println!("Usage: netsend <if> <text>");
        return;
    }
    let Some(cap) = network_cap.as_ref() else {
        crate::println!("Error: network capability is not initialised");
        return;
    };
    match kernel.network_send(cap, network, iface, text.as_bytes()) {
        Ok(()) => crate::println!("Queued {} byte(s) on '{}'", text.len(), iface),
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_net_recv(
    iface: &str,
    kernel: &mut Kernel,
    network: &mut NetworkStack,
    network_cap: &Option<Capability>,
) {
    if iface.is_empty() {
        crate::println!("Usage: netrecv <if>");
        return;
    }
    let Some(cap) = network_cap.as_ref() else {
        crate::println!("Error: network capability is not initialised");
        return;
    };
    match kernel.network_receive(cap, network, iface) {
        Ok(Some(packet)) => match core::str::from_utf8(packet.payload.as_slice()) {
            Ok(text) => {
                crate::println!("RX '{}': {} byte(s): {}", iface, packet.payload.len(), text)
            }
            Err(_) => crate::println!(
                "RX '{}': {} byte(s) (non-utf8 payload)",
                iface,
                packet.payload.len()
            ),
        },
        Ok(None) => crate::println!("RX '{}': (no packets)", iface),
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_net_tick(kernel: &mut Kernel, network: &mut NetworkStack, network_cap: &Option<Capability>) {
    let Some(cap) = network_cap.as_ref() else {
        crate::println!("Error: network capability is not initialised");
        return;
    };
    match kernel.bridge_tick(cap, network) {
        Ok(tick) => {
            let summary = network.summary();
            crate::println!(
                "Network tick: tx={} rx={} ticks={} | bridge in={} out={} err_in={} err_out={}",
                summary.total_tx_packets,
                summary.total_rx_packets,
                summary.service_ticks,
                tick.ingress_moved,
                tick.egress_moved,
                tick.ingress_errors,
                tick.egress_errors
            );
        }
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_netcaps(kernel: &Kernel, network_cap: &Option<Capability>) {
    crate::println!("=== Network Capability Telemetry ===");
    if let Some(cap) = network_cap.as_ref() {
        crate::println!("  Active capability object: {}", cap.object_id.as_str());
    } else {
        crate::println!("  Active capability object: (not initialised)");
    }
    kernel.for_each_network_stats(|object_id, stats| {
        if stats.send_ok == 0
            && stats.send_err == 0
            && stats.recv_ok == 0
            && stats.recv_empty == 0
            && stats.recv_err == 0
        {
            return;
        }
        crate::println!(
            "  - {}: send(ok={}, err={}) recv(ok={}, empty={}, err={})",
            object_id,
            stats.send_ok,
            stats.send_err,
            stats.recv_ok,
            stats.recv_empty,
            stats.recv_err
        );
    });
}

fn cmd_netbind_in(iface: &str, object_id: &str, kernel: &mut Kernel) {
    if iface.is_empty() || object_id.is_empty() {
        crate::println!("Usage: netbind-in <if> <obj>");
        return;
    }
    match kernel.bridge_bind_ingress(iface, object_id) {
        Ok(()) => crate::println!("Bound ingress '{}' -> '{}'", iface, object_id),
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_netbind_out(object_id: &str, iface: &str, kernel: &mut Kernel) {
    if iface.is_empty() || object_id.is_empty() {
        crate::println!("Usage: netbind-out <obj> <if>");
        return;
    }
    match kernel.bridge_bind_egress(object_id, iface) {
        Ok(()) => crate::println!("Bound egress '{}' -> '{}'", object_id, iface),
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_netbind_list(kernel: &Kernel) {
    crate::println!("=== Net Bridge Bindings ===");
    let (in_count, out_count) = kernel.bridge_binding_counts();
    crate::println!("  Ingress bindings: {}", in_count);
    kernel.for_each_bridge_ingress_binding(|iface, object_id| {
        crate::println!("    {} -> {}", iface, object_id);
    });
    crate::println!("  Egress bindings: {}", out_count);
    kernel.for_each_bridge_egress_binding(|object_id, iface| {
        crate::println!("    {} -> {}", object_id, iface);
    });
}

fn cmd_netbind_clear(kernel: &mut Kernel) {
    kernel.bridge_clear_bindings();
    crate::println!("Cleared all bridge bindings.");
}

fn cmd_netpump(
    cycles_str: &str,
    kernel: &mut Kernel,
    network: &mut NetworkStack,
    network_cap: &Option<Capability>,
) {
    let Some(cap) = network_cap.as_ref() else {
        crate::println!("Error: network capability is not initialised");
        return;
    };
    let cycles = if cycles_str.is_empty() {
        1
    } else {
        match parse_u32(cycles_str) {
            Some(n) if n > 0 => n,
            _ => {
                crate::println!("Usage: netpump <positive-cycle-count>");
                return;
            }
        }
    };

    let mut total_in = 0u64;
    let mut total_out = 0u64;
    let mut total_err_in = 0u64;
    let mut total_err_out = 0u64;

    for _ in 0..cycles {
        match kernel.bridge_tick(cap, network) {
            Ok(tick) => {
                total_in = total_in.saturating_add(tick.ingress_moved);
                total_out = total_out.saturating_add(tick.egress_moved);
                total_err_in = total_err_in.saturating_add(tick.ingress_errors);
                total_err_out = total_err_out.saturating_add(tick.egress_errors);
            }
            Err(e) => {
                crate::println!("Error: {:?}", e);
                return;
            }
        }
    }
    let summary = network.summary();
    crate::println!(
        "Bridge pump ({} cycles): in={} out={} err_in={} err_out={} net_ticks={}",
        cycles,
        total_in,
        total_out,
        total_err_in,
        total_err_out,
        summary.service_ticks
    );
}

fn cmd_net_to_obj(
    iface: &str,
    object_id: &str,
    kernel: &mut Kernel,
    network: &mut NetworkStack,
    network_cap: &Option<Capability>,
) {
    if iface.is_empty() || object_id.is_empty() {
        crate::println!("Usage: net2obj <if> <obj>");
        return;
    }
    let Some(cap) = network_cap.as_ref() else {
        crate::println!("Error: network capability is not initialised");
        return;
    };
    match kernel.bridge_network_to_object(cap, network, iface, object_id) {
        Ok(true) => crate::println!(
            "Bridged one packet from '{}' into object '{}'",
            iface,
            object_id
        ),
        Ok(false) => crate::println!("No packet available on '{}'", iface),
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_obj_to_net(
    object_id: &str,
    iface: &str,
    kernel: &mut Kernel,
    network: &mut NetworkStack,
    network_cap: &Option<Capability>,
) {
    if iface.is_empty() || object_id.is_empty() {
        crate::println!("Usage: obj2net <obj> <if>");
        return;
    }
    let Some(cap) = network_cap.as_ref() else {
        crate::println!("Error: network capability is not initialised");
        return;
    };
    match kernel.bridge_object_to_network(cap, network, object_id, iface) {
        Ok(true) => crate::println!(
            "Bridged one message from object '{}' to interface '{}'",
            object_id,
            iface
        ),
        Ok(false) => crate::println!("No message available in object '{}'", object_id),
        Err(e) => crate::println!("Error: {:?}", e),
    }
}

fn cmd_heapinfo() {
    if !KERNEL_HEAP.is_initialised() {
        crate::println!("Heap: not initialised");
        return;
    }
    let total = KERNEL_HEAP.total_bytes();
    let used = KERNEL_HEAP.used_bytes();
    let free = KERNEL_HEAP.free_bytes();
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
            crate::println!(
                "  Mapped    : {} pages ({} KiB)",
                pt.mapped_pages(),
                pt.mapped_pages() as u64 * crate::paging::PAGE_SIZE / 1024
            );
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
    kernel: &Kernel,
) {
    if virt_str.is_empty() || phys_str.is_empty() {
        crate::println!("Usage: vmmap <virt_hex> <phys_hex> [flags: krx|krw|urw]");
        return;
    }
    let virt = match parse_hex(virt_str) {
        Some(v) => v,
        None => {
            crate::println!("Invalid virtual address '{}'", virt_str);
            return;
        }
    };
    let phys = match parse_hex(phys_str) {
        Some(p) => p,
        None => {
            crate::println!("Invalid physical address '{}'", phys_str);
            return;
        }
    };
    let flags = match flags_str {
        "krw" => MapFlags::kernel_rw(),
        "urw" => MapFlags::user_rw(),
        _ => MapFlags::kernel_rx(), // default
    };
    match page_table {
        Some(pt) => match pt.map(virt, phys, flags, frame_alloc) {
            Ok(()) => {
                let sent = kernel.broadcast_tlb_shootdown(virt, 0);
                crate::println!(
                    "Mapped {:#x} -> {:#x} (TLB shootdown targets={})",
                    virt,
                    phys,
                    sent
                );
            }
            Err(e) => crate::println!("Error: {:?}", e),
        },
        None => crate::println!("Page table not initialised."),
    }
}

fn cmd_vmunmap(virt_str: &str, page_table: &mut Option<PageTableManager>, kernel: &Kernel) {
    if virt_str.is_empty() {
        crate::println!("Usage: vmunmap <virt_hex>");
        return;
    }
    let virt = match parse_hex(virt_str) {
        Some(v) => v,
        None => {
            crate::println!("Invalid address '{}'", virt_str);
            return;
        }
    };
    match page_table {
        Some(pt) => match pt.unmap(virt) {
            Ok(()) => {
                let sent = kernel.broadcast_tlb_shootdown(virt, 0);
                crate::println!("Unmapped {:#x} (TLB shootdown targets={})", virt, sent);
            }
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
        None => {
            crate::println!("Invalid address '{}'", virt_str);
            return;
        }
    };
    match page_table {
        Some(pt) => match pt.translate(virt) {
            Ok(phys) => crate::println!("{:#x} -> {:#x}", virt, phys),
            Err(e) => crate::println!("Error: {:?}", e),
        },
        None => crate::println!("Page table not initialised."),
    }
}

fn cmd_user_smoke(
    page_table: &mut Option<PageTableManager>,
    frame_alloc: &mut FrameAllocator,
) {
    match page_table {
        Some(pt) => match crate::syscall::run_user_smoke(pt, frame_alloc) {
            Ok(()) => {}
            Err(e) => crate::println!("user-smoke failed: {}", e),
        },
        None => crate::println!("Page table not initialised."),
    }
}

fn cmd_elf_spawn(
    page_table: &mut Option<PageTableManager>,
    frame_alloc: &mut FrameAllocator,
    enter: bool,
) {
    let Some(pt) = page_table.as_mut() else {
        crate::println!("Page table not initialised.");
        return;
    };
    match crate::process::spawn_smoke_elf(pt, frame_alloc) {
        Ok(proc) => {
            crate::println!(
                "elf: spawned pid={} entry={:#x} stack={:#x} cr3={:#x}",
                proc.pid,
                proc.entry,
                proc.stack_top,
                proc.pml4_phys
            );
            if enter {
                if let Err(e) = crate::process::enter(&proc) {
                    crate::println!("elf-smoke enter failed: {:?}", e);
                }
            }
        }
        Err(e) => crate::println!("elf-spawn failed: {:?}", e),
    }
}

fn cmd_ps() {
    let procs = crate::process::list();
    if procs.is_empty() {
        crate::println!("ps: (no processes)");
        return;
    }
    crate::println!("PID   STATE     EXIT  ENTRY      CR3");
    for p in procs.iter() {
        let state = match p.state {
            crate::process::ProcessState::Free => "Free",
            crate::process::ProcessState::Running => "Running",
            crate::process::ProcessState::Zombie => "Zombie",
        };
        crate::println!(
            "{:<5} {:<9} {:<5} {:#010x} {:#x}",
            p.pid,
            state,
            p.exit_code,
            p.entry,
            p.pml4_phys
        );
    }
    if let Some(cur) = crate::process::current_pid() {
        crate::println!("current={}", cur);
    }
}

fn cmd_reap(pid_str: &str) {
    let Some(pid) = parse_u32(pid_str) else {
        crate::println!("Usage: reap <pid>");
        return;
    };
    match crate::process::reap(pid) {
        Ok(code) => crate::println!("reaped pid={} exit={}", pid, code),
        Err(e) => crate::println!("reap failed: {:?}", e),
    }
}

fn cmd_irq_route(irq_str: &str, apic_str: &str) {
    let Some(irq) = parse_u32(irq_str).map(|v| v as u8) else {
        crate::println!("Usage: irq-route <irq> <apic-id>");
        return;
    };
    let Some(apic) = parse_u32(apic_str) else {
        crate::println!("Usage: irq-route <irq> <apic-id>");
        return;
    };
    match crate::ioapic::set_irq_affinity(irq, apic) {
        Ok(()) => crate::println!("IOAPIC: IRQ {} → apic_id={}", irq, apic),
        Err(e) => crate::println!("IOAPIC route error: {:?}", e),
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
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
