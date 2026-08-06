use core::str::FromStr;
use core::sync::atomic::{AtomicU64, Ordering};
use heapless::{String, Vec};

const MAX_CORES: usize = 8;
const MAX_CORE_RQ: usize = 16;
const MAX_TASK_ID_LEN: usize = 64;
const AP_TRAMPOLINE_PHYS_BASE: u64 = 0x8000;
const AP_STARTUP_VECTOR: u8 = (AP_TRAMPOLINE_PHYS_BASE >> 12) as u8;
const AP_TRAMPOLINE_SLOT_BYTES: u64 = 4096;
const AP_TRAMPOLINE_CODE_BYTES: u64 = 512;
const AP_TRAMPOLINE_MAILBOX_BYTES: u64 = 256;
const AP_TRAMPOLINE_STACK_BYTES: u64 = 2048;
const AP_TRAMPOLINE_HANDOFF_BYTES: u64 = 64;
const AP_HANDOFF_SIGNATURE: u32 = 0x4344_4B41; // "CDKA"
const AP_TRAMPOLINE_ENTRY_OFFSET: u16 = 0;

/// Handoff status word offset from trampoline base (`0x8000 + 0x200 + 48`).
const AP_STATUS_OFFSET: u64 = AP_TRAMPOLINE_CODE_BYTES + 48;

/// Offsets within the trampoline page (absolute phys = base + offset).
const OFF_REAL: usize = 0x0000;
const OFF_PROT: usize = 0x00A0;
const OFF_LONG: usize = 0x0120;
const OFF_GDT: usize = 0x0180;
const OFF_GDTR: usize = 0x01B0;

/// AP has not entered the trampoline yet.
pub const AP_STATUS_IDLE: u32 = 0;
/// Real-mode trampoline is running on the AP (stack loaded, signature OK).
pub const AP_STATUS_ENTERED: u32 = 1;
/// Signature check failed.
pub const AP_STATUS_BAD_SIGNATURE: u32 = 0xFFFF_FFFF;
/// CR3 / kernel entry missing — parked in real-mode HLT after signaling ENTERED.
pub const AP_STATUS_PARKED: u32 = 2;
/// Protected/long-mode transition started (CR3 + entry were present).
pub const AP_STATUS_MODE_SWITCH: u32 = 3;
/// About to call the 64-bit kernel entry (long mode reached).
pub const AP_STATUS_HANDOFF: u32 = 4;

/// Real-mode SIPI entry at `0x8000` (Phase 15): validate handoff, then enter PE.
#[rustfmt::skip]
const AP_TRAMPOLINE_REAL: &[u8] = &[
    0xFA, 0x31, 0xC0, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0x66, 0x67, 0xA1,
    0x10, 0x82, 0x00, 0x00, 0x66, 0x89, 0xC4, 0x66, 0x67, 0xA1, 0x00, 0x82,
    0x00, 0x00, 0x66, 0x3D, 0x41, 0x4B, 0x44, 0x43, 0x75, 0x63, 0x66, 0xB8,
    0x01, 0x00, 0x00, 0x00, 0x66, 0x67, 0xA3, 0x30, 0x82, 0x00, 0x00, 0x66,
    0x67, 0xA1, 0x28, 0x82, 0x00, 0x00, 0x66, 0x67, 0x0B, 0x05, 0x2C, 0x82,
    0x00, 0x00, 0x74, 0x35, 0x66, 0x67, 0xA1, 0x20, 0x82, 0x00, 0x00, 0x66,
    0x67, 0x0B, 0x05, 0x24, 0x82, 0x00, 0x00, 0x74, 0x24, 0x66, 0xB8, 0x03,
    0x00, 0x00, 0x00, 0x66, 0x67, 0xA3, 0x30, 0x82, 0x00, 0x00, 0x0F, 0x01,
    0x16, 0xB0, 0x81, 0x0F, 0x20, 0xC0, 0x66, 0x83, 0xC8, 0x01, 0x0F, 0x22,
    0xC0, 0x66, 0xEA, 0xA0, 0x80, 0x00, 0x00, 0x08, 0x00, 0x66, 0xB8, 0x02,
    0x00, 0x00, 0x00, 0x66, 0x67, 0xA3, 0x30, 0x82, 0x00, 0x00, 0xF4, 0xEB,
    0xFD, 0x66, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0x66, 0x67, 0xA3, 0x30, 0x82,
    0x00, 0x00, 0xF4, 0xEB, 0xFD,
];

/// 32-bit protected-mode path at `0x80A0`: enable PAE + LME + NXE + paging, enter long mode.
///
/// EFER must set both LME (bit 8) and NXE (bit 11). Bootloader page tables use
/// the NX bit; without NXE the AP takes a reserved-bit #PF and triple-faults
/// immediately after the long-mode far jump.
#[rustfmt::skip]
const AP_TRAMPOLINE_PROT: &[u8] = &[
    0x66, 0xB8, 0x10, 0x00, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0x8E, 0xE0,
    0x8E, 0xE8, 0x67, 0xA1, 0x10, 0x82, 0x00, 0x00, 0x89, 0xC4, 0x67, 0xA1,
    0x28, 0x82, 0x00, 0x00, 0x0F, 0x22, 0xD8, 0x0F, 0x20, 0xE0, 0x83, 0xC8,
    0x20, 0x0F, 0x22, 0xE0, 0xB9, 0x80, 0x00, 0x00, 0xC0, 0x0F, 0x32, 0x0D,
    0x00, 0x09, 0x00, 0x00, 0x0F, 0x30, 0x0F, 0x20, 0xC0, 0x0D, 0x01, 0x00,
    0x00, 0x80, 0x0F, 0x22, 0xC0, 0xEA, 0x20, 0x81, 0x00, 0x00, 0x18, 0x00,
];

/// 64-bit long-mode stub at `0x8120` (requires identity map of this page).
#[rustfmt::skip]
const AP_TRAMPOLINE_LONG: &[u8] = &[
    0x66, 0xB8, 0x20, 0x00, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0x48, 0x8B,
    0x24, 0x25, 0x10, 0x82, 0x00, 0x00, 0xC7, 0x04, 0x25, 0x30, 0x82, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x8B, 0x3C, 0x25, 0x08, 0x82, 0x00, 0x00,
    0x8B, 0x34, 0x25, 0x04, 0x82, 0x00, 0x00, 0x48, 0xA1, 0x20, 0x82, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0xF4, 0xEB, 0xFD,
];

/// Combined blob length used for checksum / metadata (real + prot + long).
const fn trampoline_code_len() -> usize {
    AP_TRAMPOLINE_REAL.len() + AP_TRAMPOLINE_PROT.len() + AP_TRAMPOLINE_LONG.len()
}

/// Checksum over all trampoline code sections.
fn trampoline_checksum_bytes() -> u32 {
    AP_TRAMPOLINE_REAL
        .iter()
        .chain(AP_TRAMPOLINE_PROT.iter())
        .chain(AP_TRAMPOLINE_LONG.iter())
        .fold(0u32, |sum, b| sum.wrapping_add(*b as u32))
}

/// SIPI entry view (real-mode section starts at `0x8000`).
const AP_TRAMPOLINE_CODE_BLOB: &[u8] = AP_TRAMPOLINE_REAL;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreRole {
    Bootstrap,
    Application,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreState {
    Registered,
    Booting,
    Online,
    Halted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreInfo {
    pub apic_id: u32,
    pub role: CoreRole,
    pub state: CoreState,
    pub startup_attempts: u32,
    pub run_queue_depth: u16,
    pub ticks_seen: u64,
    pub dispatches: u64,
    pub completions: u64,
    /// Times this core successfully stole work from another core (Phase 19).
    pub steals: u64,
}

impl CoreInfo {
    const fn new(apic_id: u32, role: CoreRole) -> Self {
        Self {
            apic_id,
            role,
            state: match role {
                CoreRole::Bootstrap => CoreState::Online,
                CoreRole::Application => CoreState::Registered,
            },
            startup_attempts: 0,
            run_queue_depth: 0,
            ticks_seen: 0,
            dispatches: 0,
            completions: 0,
            steals: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreSummary {
    pub known_cores: usize,
    pub online_cores: usize,
    pub booting_cores: usize,
    pub total_ticks_seen: u64,
    pub total_dispatches: u64,
    pub total_completions: u64,
    pub bsp_apic_id: Option<u32>,
    pub startup_pending_apic: Option<u32>,
    pub total_run_queue_depth: u64,
    pub total_steals: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiCoreError {
    CoreExists,
    CoreNotFound,
    CoreTableFull,
    InvalidTransition,
    NotApplicationCore,
    StartupMailboxBusy,
    StartupMailboxMismatch,
    StartupSequenceMismatch,
    TrampolineInstallFailed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApTrampolineImage {
    pub code_base_phys: u64,
    pub code_len_bytes: u16,
    pub entry_offset: u16,
    pub checksum: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApEntryContext {
    pub signature: u32,
    pub startup_seq: u32,
    pub target_apic_id: u32,
    pub stack_top_phys: u64,
    pub handoff_phys: u64,
    pub kernel_entry_phys: u64,
    pub page_table_root_phys: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StartupMailbox {
    pub trampoline_phys: u64,
    pub sipi_vector: u8,
    pub trampoline_entry_phys: u64,
    pub mailbox_phys: u64,
    pub stack_top_phys: u64,
    pub handoff_phys: u64,
    pub handoff_size_bytes: u16,
    pub trampoline: ApTrampolineImage,
    pub handoff: ApEntryContext,
    pub trampoline_installed: bool,
    pub trampoline_installed_seq: u32,
    pub pending_apic_id: Option<u32>,
    pub last_acked_apic_id: Option<u32>,
    pub startup_seq: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApStartupPlan {
    pub apic_id: u32,
    pub trampoline_phys: u64,
    pub sipi_vector: u8,
    pub entry_phys: u64,
    pub stack_top_phys: u64,
    pub trampoline: ApTrampolineImage,
    pub handoff: ApEntryContext,
    pub startup_seq: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrampolineLayout {
    pub slot_base_phys: u64,
    pub slot_size_bytes: u64,
    pub code_base_phys: u64,
    pub code_size_bytes: u64,
    pub mailbox_base_phys: u64,
    pub mailbox_size_bytes: u64,
    pub handoff_size_bytes: u64,
    pub trampoline_blob_size_bytes: u64,
    pub stack_top_phys: u64,
    pub stack_size_bytes: u64,
    pub sipi_vector: u8,
}

pub struct MultiCoreManager {
    cores: Vec<CoreInfo, MAX_CORES>,
    /// Per-core object-id run queues (index matches `cores` slot).
    run_queues: [Vec<String<MAX_TASK_ID_LEN>, MAX_CORE_RQ>; MAX_CORES],
    startup_mailbox: StartupMailbox,
}

/// Bitmask of cores with a pending cross-core reschedule request (Phase 17).
static RESCHEDULE_PENDING: AtomicU64 = AtomicU64::new(0);

/// Mark `apic_id` as needing a runtime service pass (software + IPI path).
pub fn request_reschedule(apic_id: u32) {
    if apic_id >= 64 {
        return;
    }
    RESCHEDULE_PENDING.fetch_or(1u64 << apic_id, Ordering::Release);
}

/// Clear and return whether `apic_id` had a pending reschedule request.
pub fn take_reschedule(apic_id: u32) -> bool {
    if apic_id >= 64 {
        return false;
    }
    let bit = 1u64 << apic_id;
    let prev = RESCHEDULE_PENDING.fetch_and(!bit, Ordering::AcqRel);
    prev & bit != 0
}

/// Peek without clearing.
pub fn reschedule_pending(apic_id: u32) -> bool {
    if apic_id >= 64 {
        return false;
    }
    RESCHEDULE_PENDING.load(Ordering::Acquire) & (1u64 << apic_id) != 0
}

/// Snapshot of the pending bitmask (for tests / console).
pub fn reschedule_pending_mask() -> u64 {
    RESCHEDULE_PENDING.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Phase 18 — AP idle tracking + TLB shootdown pending
// ---------------------------------------------------------------------------

/// Bitmask of cores currently parked in the AP idle (`sti; hlt`) loop.
static IDLE_MASK: AtomicU64 = AtomicU64::new(0);

/// Per-core wake counts (APIC IDs `0..MAX_CORES`).
static WAKE_COUNTS: [AtomicU64; MAX_CORES] = [const { AtomicU64::new(0) }; MAX_CORES];

/// Bitmask of cores with a pending TLB shootdown request.
static TLB_SHOOTDOWN_PENDING: AtomicU64 = AtomicU64::new(0);

/// Bitmask of cores that have acknowledged the current shootdown generation.
static TLB_SHOOTDOWN_ACK: AtomicU64 = AtomicU64::new(0);

/// Monotonic shootdown generation (bumped on each broadcast).
static TLB_SHOOTDOWN_GEN: AtomicU64 = AtomicU64::new(0);

/// Page virtual address for the active shootdown (`0` = full TLB flush).
static TLB_SHOOTDOWN_PAGE: AtomicU64 = AtomicU64::new(0);

/// Mark `apic_id` as entered into the idle HLT loop.
pub fn idle_enter(apic_id: u32) {
    if apic_id >= 64 {
        return;
    }
    IDLE_MASK.fetch_or(1u64 << apic_id, Ordering::Release);
}

/// Clear idle bit; returns whether the core was idle.
pub fn idle_leave(apic_id: u32) -> bool {
    if apic_id >= 64 {
        return false;
    }
    let bit = 1u64 << apic_id;
    let prev = IDLE_MASK.fetch_and(!bit, Ordering::AcqRel);
    prev & bit != 0
}

/// Whether `apic_id` is currently marked idle (parked in HLT).
pub fn is_idle(apic_id: u32) -> bool {
    if apic_id >= 64 {
        return false;
    }
    IDLE_MASK.load(Ordering::Acquire) & (1u64 << apic_id) != 0
}

/// Snapshot of the idle bitmask.
pub fn idle_mask() -> u64 {
    IDLE_MASK.load(Ordering::Acquire)
}

/// Record a wake event for an idle core (reschedule / timer IPI).
pub fn note_wake(apic_id: u32) {
    if (apic_id as usize) >= MAX_CORES {
        return;
    }
    WAKE_COUNTS[apic_id as usize].fetch_add(1, Ordering::Relaxed);
}

/// Number of recorded wake events for `apic_id`.
pub fn wake_count(apic_id: u32) -> u64 {
    if (apic_id as usize) >= MAX_CORES {
        return 0;
    }
    WAKE_COUNTS[apic_id as usize].load(Ordering::Relaxed)
}

/// If `apic_id` is idle, record a wake (used by the reschedule IPI path).
pub fn note_wake_if_idle(apic_id: u32) -> bool {
    if is_idle(apic_id) {
        note_wake(apic_id);
        true
    } else {
        false
    }
}

/// Begin a new shootdown generation and mark targets pending (clears ACKs).
pub fn begin_tlb_shootdown(page_virt: u64, target_mask: u64) -> u64 {
    let gen = TLB_SHOOTDOWN_GEN.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    TLB_SHOOTDOWN_PAGE.store(page_virt, Ordering::Release);
    TLB_SHOOTDOWN_ACK.store(0, Ordering::Release);
    TLB_SHOOTDOWN_PENDING.store(target_mask, Ordering::Release);
    gen
}

/// Queue a TLB shootdown for `apic_id`.
///
/// `page_virt == 0` means a full TLB flush; otherwise invalidate that page.
pub fn request_tlb_shootdown(apic_id: u32, page_virt: u64) {
    if apic_id >= 64 {
        return;
    }
    let _ = begin_tlb_shootdown(page_virt, 1u64 << apic_id);
}

/// Clear pending, ACK the core, and return the shootdown page VA if queued.
pub fn take_tlb_shootdown(apic_id: u32) -> Option<u64> {
    if apic_id >= 64 {
        return None;
    }
    let bit = 1u64 << apic_id;
    let prev = TLB_SHOOTDOWN_PENDING.fetch_and(!bit, Ordering::AcqRel);
    if prev & bit == 0 {
        return None;
    }
    TLB_SHOOTDOWN_ACK.fetch_or(bit, Ordering::Release);
    Some(TLB_SHOOTDOWN_PAGE.load(Ordering::Acquire))
}

/// Wait until all bits in `target_mask` are acknowledged (or spins exhausted).
pub fn wait_tlb_shootdown_ack(target_mask: u64, max_spins: u32) -> bool {
    if target_mask == 0 {
        return true;
    }
    for _ in 0..max_spins {
        if TLB_SHOOTDOWN_ACK.load(Ordering::Acquire) & target_mask == target_mask {
            return true;
        }
        core::hint::spin_loop();
    }
    TLB_SHOOTDOWN_ACK.load(Ordering::Acquire) & target_mask == target_mask
}

pub fn tlb_shootdown_ack_mask() -> u64 {
    TLB_SHOOTDOWN_ACK.load(Ordering::Acquire)
}

pub fn tlb_shootdown_gen() -> u64 {
    TLB_SHOOTDOWN_GEN.load(Ordering::Acquire)
}

/// Peek without clearing.
pub fn tlb_shootdown_pending(apic_id: u32) -> bool {
    if apic_id >= 64 {
        return false;
    }
    TLB_SHOOTDOWN_PENDING.load(Ordering::Acquire) & (1u64 << apic_id) != 0
}

/// Snapshot of the TLB shootdown pending bitmask.
pub fn tlb_shootdown_pending_mask() -> u64 {
    TLB_SHOOTDOWN_PENDING.load(Ordering::Acquire)
}

/// Page VA associated with the current shootdown request (`0` = full flush).
pub fn tlb_shootdown_page() -> u64 {
    TLB_SHOOTDOWN_PAGE.load(Ordering::Acquire)
}

impl MultiCoreManager {
    pub const fn new() -> Self {
        Self {
            cores: Vec::new(),
            run_queues: [const { Vec::new() }; MAX_CORES],
            startup_mailbox: StartupMailbox {
                trampoline_phys: AP_TRAMPOLINE_PHYS_BASE,
                sipi_vector: AP_STARTUP_VECTOR,
                trampoline_entry_phys: AP_TRAMPOLINE_PHYS_BASE,
                mailbox_phys: AP_TRAMPOLINE_PHYS_BASE + AP_TRAMPOLINE_CODE_BYTES,
                stack_top_phys: AP_TRAMPOLINE_PHYS_BASE + AP_TRAMPOLINE_SLOT_BYTES,
                handoff_phys: AP_TRAMPOLINE_PHYS_BASE + AP_TRAMPOLINE_CODE_BYTES,
                handoff_size_bytes: AP_TRAMPOLINE_HANDOFF_BYTES as u16,
                trampoline: ApTrampolineImage {
                    code_base_phys: AP_TRAMPOLINE_PHYS_BASE,
                    code_len_bytes: trampoline_code_len() as u16,
                    entry_offset: AP_TRAMPOLINE_ENTRY_OFFSET,
                    checksum: 0,
                },
                handoff: ApEntryContext {
                    signature: AP_HANDOFF_SIGNATURE,
                    startup_seq: 0,
                    target_apic_id: 0,
                    stack_top_phys: AP_TRAMPOLINE_PHYS_BASE + AP_TRAMPOLINE_SLOT_BYTES,
                    handoff_phys: AP_TRAMPOLINE_PHYS_BASE + AP_TRAMPOLINE_CODE_BYTES,
                    kernel_entry_phys: AP_TRAMPOLINE_PHYS_BASE,
                    page_table_root_phys: 0,
                },
                trampoline_installed: false,
                trampoline_installed_seq: 0,
                pending_apic_id: None,
                last_acked_apic_id: None,
                startup_seq: 0,
            },
        }
    }

    pub fn register_core(&mut self, apic_id: u32, role: CoreRole) -> Result<(), MultiCoreError> {
        if self.cores.iter().any(|c| c.apic_id == apic_id) {
            return Err(MultiCoreError::CoreExists);
        }
        self.cores
            .push(CoreInfo::new(apic_id, role))
            .map_err(|_| MultiCoreError::CoreTableFull)
    }

    pub fn set_online(&mut self, apic_id: u32, online: bool) -> Result<(), MultiCoreError> {
        let core = self
            .cores
            .iter_mut()
            .find(|c| c.apic_id == apic_id)
            .ok_or(MultiCoreError::CoreNotFound)?;
        core.state = if online {
            CoreState::Online
        } else {
            CoreState::Halted
        };
        Ok(())
    }

    pub fn begin_ap_startup(&mut self, apic_id: u32) -> Result<(), MultiCoreError> {
        let core = self
            .cores
            .iter_mut()
            .find(|c| c.apic_id == apic_id)
            .ok_or(MultiCoreError::CoreNotFound)?;
        if !matches!(core.role, CoreRole::Application) {
            return Err(MultiCoreError::NotApplicationCore);
        }
        if !matches!(core.state, CoreState::Registered | CoreState::Halted) {
            return Err(MultiCoreError::InvalidTransition);
        }
        core.state = CoreState::Booting;
        core.startup_attempts = core.startup_attempts.saturating_add(1);
        Ok(())
    }

    pub fn plan_ap_startup(&mut self, apic_id: u32) -> Result<ApStartupPlan, MultiCoreError> {
        if let Some(pending) = self.startup_mailbox.pending_apic_id {
            if pending != apic_id {
                return Err(MultiCoreError::StartupMailboxBusy);
            }
        }
        self.begin_ap_startup(apic_id)?;
        self.startup_mailbox.pending_apic_id = Some(apic_id);
        self.startup_mailbox.startup_seq = self.startup_mailbox.startup_seq.saturating_add(1);
        self.startup_mailbox.trampoline.checksum = trampoline_checksum_bytes();
        self.startup_mailbox.trampoline.code_len_bytes = trampoline_code_len() as u16;
        self.startup_mailbox.handoff.startup_seq = self.startup_mailbox.startup_seq;
        self.startup_mailbox.handoff.target_apic_id = apic_id;
        self.startup_mailbox.handoff.stack_top_phys = self.startup_mailbox.stack_top_phys;
        self.startup_mailbox.handoff.handoff_phys = self.startup_mailbox.handoff_phys;
        self.install_trampoline_slot()?;
        Ok(ApStartupPlan {
            apic_id,
            trampoline_phys: self.startup_mailbox.trampoline_phys,
            sipi_vector: self.startup_mailbox.sipi_vector,
            entry_phys: self.startup_mailbox.trampoline_entry_phys,
            stack_top_phys: self.startup_mailbox.stack_top_phys,
            trampoline: self.startup_mailbox.trampoline,
            handoff: self.startup_mailbox.handoff,
            startup_seq: self.startup_mailbox.startup_seq,
        })
    }

    pub fn complete_ap_startup(&mut self, apic_id: u32) -> Result<(), MultiCoreError> {
        self.complete_ap_startup_with_seq(apic_id, self.startup_mailbox.startup_seq)
    }

    pub fn complete_ap_startup_with_seq(
        &mut self,
        apic_id: u32,
        startup_seq: u32,
    ) -> Result<(), MultiCoreError> {
        let core = self
            .cores
            .iter_mut()
            .find(|c| c.apic_id == apic_id)
            .ok_or(MultiCoreError::CoreNotFound)?;
        if !matches!(core.role, CoreRole::Application) {
            return Err(MultiCoreError::NotApplicationCore);
        }
        // Idempotent: AP may have already completed via try_lock before BSP sync.
        if matches!(core.state, CoreState::Online)
            && self.startup_mailbox.last_acked_apic_id == Some(apic_id)
        {
            return Ok(());
        }
        if !matches!(core.state, CoreState::Booting) {
            return Err(MultiCoreError::InvalidTransition);
        }
        if self.startup_mailbox.pending_apic_id != Some(apic_id) {
            return Err(MultiCoreError::StartupMailboxMismatch);
        }
        if self.startup_mailbox.startup_seq != startup_seq {
            return Err(MultiCoreError::StartupSequenceMismatch);
        }
        core.state = CoreState::Online;
        core.run_queue_depth = 0;
        self.startup_mailbox.pending_apic_id = None;
        self.startup_mailbox.last_acked_apic_id = Some(apic_id);
        Ok(())
    }

    pub fn halt_core(&mut self, apic_id: u32) -> Result<(), MultiCoreError> {
        let idx = self.core_index(apic_id).ok_or(MultiCoreError::CoreNotFound)?;
        self.cores[idx].state = CoreState::Halted;
        self.cores[idx].run_queue_depth = 0;
        self.run_queues[idx].clear();
        Ok(())
    }

    fn core_index(&self, apic_id: u32) -> Option<usize> {
        self.cores.iter().position(|c| c.apic_id == apic_id)
    }

    /// Pick the lightest online core; tie-break by fewest dispatches (fairness).
    pub fn select_dispatch_core(&self) -> Option<u32> {
        let mut best: Option<(u32, u16, u64)> = None;
        for core in self.cores.iter() {
            if !matches!(core.state, CoreState::Online) {
                continue;
            }
            let key = (core.run_queue_depth, core.dispatches);
            match best {
                Some((_, d, disp)) if (d, disp) <= key => {}
                _ => best = Some((core.apic_id, key.0, key.1)),
            }
        }
        best.map(|(id, _, _)| id)
    }

    /// Enqueue an object id onto `apic_id`'s per-core run queue.
    pub fn enqueue_core_task(
        &mut self,
        apic_id: u32,
        object_id: &str,
    ) -> Result<(), MultiCoreError> {
        let idx = self.core_index(apic_id).ok_or(MultiCoreError::CoreNotFound)?;
        let id = String::from_str(object_id).map_err(|_| MultiCoreError::CoreTableFull)?;
        self.run_queues[idx]
            .push(id)
            .map_err(|_| MultiCoreError::CoreTableFull)?;
        self.cores[idx].run_queue_depth = self.run_queues[idx].len() as u16;
        Ok(())
    }

    /// Depth-only enqueue (tests / legacy counters). Prefer [`enqueue_core_task`].
    pub fn enqueue_core_runqueue(&mut self, apic_id: u32) -> Result<(), MultiCoreError> {
        self.enqueue_core_task(apic_id, "_")
    }

    /// Pop the front task from `apic_id`'s local queue.
    pub fn take_local_task(&mut self, apic_id: u32) -> Option<String<MAX_TASK_ID_LEN>> {
        let idx = self.core_index(apic_id)?;
        if self.run_queues[idx].is_empty() {
            return None;
        }
        let task = self.run_queues[idx].remove(0);
        self.cores[idx].run_queue_depth = self.run_queues[idx].len() as u16;
        Some(task)
    }

    /// Steal one task from the busiest online victim (depth ≥ 1).
    pub fn steal_task(
        &mut self,
        thief_apic_id: u32,
    ) -> Option<(u32, String<MAX_TASK_ID_LEN>)> {
        let thief_idx = self.core_index(thief_apic_id)?;
        let mut victim: Option<(usize, u16)> = None;
        for (idx, core) in self.cores.iter().enumerate() {
            if idx == thief_idx || !matches!(core.state, CoreState::Online) {
                continue;
            }
            let depth = core.run_queue_depth;
            if depth == 0 {
                continue;
            }
            match victim {
                Some((_, best)) if best >= depth => {}
                _ => victim = Some((idx, depth)),
            }
        }
        let (vidx, _) = victim?;
        if self.run_queues[vidx].is_empty() {
            return None;
        }
        // Steal from the back (newest) to reduce contention with local FIFO pops.
        let last = self.run_queues[vidx].len() - 1;
        let task = self.run_queues[vidx].remove(last);
        self.cores[vidx].run_queue_depth = self.run_queues[vidx].len() as u16;
        self.cores[thief_idx].steals = self.cores[thief_idx].steals.saturating_add(1);
        Some((self.cores[vidx].apic_id, task))
    }

    /// Take local work, otherwise steal from another online core.
    pub fn take_task_for_core(&mut self, apic_id: u32) -> Option<String<MAX_TASK_ID_LEN>> {
        if let Some(task) = self.take_local_task(apic_id) {
            return Some(task);
        }
        self.steal_task(apic_id).map(|(_, task)| task)
    }

    pub fn run_queue_depth(&self, apic_id: u32) -> u16 {
        self.core_index(apic_id)
            .map(|idx| self.cores[idx].run_queue_depth)
            .unwrap_or(0)
    }

    pub fn steal_count(&self, apic_id: u32) -> u64 {
        self.core_index(apic_id)
            .map(|idx| self.cores[idx].steals)
            .unwrap_or(0)
    }

    pub fn dequeue_core_runqueue(&mut self, apic_id: u32) -> Result<(), MultiCoreError> {
        if self.core_index(apic_id).is_none() {
            return Err(MultiCoreError::CoreNotFound);
        }
        let _ = self.take_local_task(apic_id);
        Ok(())
    }

    pub fn note_tick(&mut self, apic_id: u32) -> Result<(), MultiCoreError> {
        let core = self
            .cores
            .iter_mut()
            .find(|c| c.apic_id == apic_id)
            .ok_or(MultiCoreError::CoreNotFound)?;
        core.ticks_seen = core.ticks_seen.saturating_add(1);
        Ok(())
    }

    pub fn note_dispatch(&mut self, apic_id: u32) -> Result<(), MultiCoreError> {
        let core = self
            .cores
            .iter_mut()
            .find(|c| c.apic_id == apic_id)
            .ok_or(MultiCoreError::CoreNotFound)?;
        core.dispatches = core.dispatches.saturating_add(1);
        Ok(())
    }

    pub fn note_completion(&mut self, apic_id: u32) -> Result<(), MultiCoreError> {
        let core = self
            .cores
            .iter_mut()
            .find(|c| c.apic_id == apic_id)
            .ok_or(MultiCoreError::CoreNotFound)?;
        core.completions = core.completions.saturating_add(1);
        Ok(())
    }

    pub fn summary(&self) -> CoreSummary {
        let mut out = CoreSummary {
            known_cores: self.cores.len(),
            ..CoreSummary::default()
        };
        for core in self.cores.iter() {
            if matches!(core.state, CoreState::Online) {
                out.online_cores = out.online_cores.saturating_add(1);
            }
            if matches!(core.state, CoreState::Booting) {
                out.booting_cores = out.booting_cores.saturating_add(1);
            }
            if matches!(core.role, CoreRole::Bootstrap) && out.bsp_apic_id.is_none() {
                out.bsp_apic_id = Some(core.apic_id);
            }
            out.total_ticks_seen = out.total_ticks_seen.saturating_add(core.ticks_seen);
            out.total_dispatches = out.total_dispatches.saturating_add(core.dispatches);
            out.total_completions = out.total_completions.saturating_add(core.completions);
            out.total_run_queue_depth = out
                .total_run_queue_depth
                .saturating_add(core.run_queue_depth as u64);
            out.total_steals = out.total_steals.saturating_add(core.steals);
        }
        out.startup_pending_apic = self.startup_mailbox.pending_apic_id;
        out
    }

    pub fn for_each_core(&self, mut f: impl FnMut(CoreInfo)) {
        for core in self.cores.iter() {
            f(*core);
        }
    }

    pub fn startup_mailbox(&self) -> StartupMailbox {
        self.startup_mailbox
    }

    pub fn configure_ap_handoff(&mut self, kernel_entry_phys: u64, page_table_root_phys: u64) {
        self.startup_mailbox.handoff.kernel_entry_phys = kernel_entry_phys;
        self.startup_mailbox.handoff.page_table_root_phys = page_table_root_phys;
    }

    pub fn trampoline_blob(&self) -> &'static [u8] {
        &AP_TRAMPOLINE_CODE_BLOB
    }

    fn install_trampoline_slot(&mut self) -> Result<(), MultiCoreError> {
        #[cfg(target_os = "none")]
        let image = self.build_trampoline_slot_image();
        #[cfg(not(target_os = "none"))]
        let _ = self.build_trampoline_slot_image();
        #[cfg(target_os = "none")]
        unsafe {
            let dst = crate::phys_mem::phys_to_mut_ptr::<u8>(self.startup_mailbox.trampoline_phys);
            core::ptr::copy_nonoverlapping(image.as_ptr(), dst, image.len());
        }
        self.startup_mailbox.trampoline_installed = true;
        self.startup_mailbox.trampoline_installed_seq = self.startup_mailbox.startup_seq;
        if !self.startup_mailbox.trampoline_installed {
            return Err(MultiCoreError::TrampolineInstallFailed);
        }
        Ok(())
    }

    fn build_trampoline_slot_image(&self) -> [u8; AP_TRAMPOLINE_SLOT_BYTES as usize] {
        let mut out = [0u8; AP_TRAMPOLINE_SLOT_BYTES as usize];
        out[OFF_REAL..OFF_REAL + AP_TRAMPOLINE_REAL.len()].copy_from_slice(AP_TRAMPOLINE_REAL);
        out[OFF_PROT..OFF_PROT + AP_TRAMPOLINE_PROT.len()].copy_from_slice(AP_TRAMPOLINE_PROT);
        out[OFF_LONG..OFF_LONG + AP_TRAMPOLINE_LONG.len()].copy_from_slice(AP_TRAMPOLINE_LONG);

        // Minimal GDT: null, code32, data32, code64, data64.
        let gdt = [
            0u8, 0, 0, 0, 0, 0, 0, 0, // null
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xCF, 0x00, // code32
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x92, 0xCF, 0x00, // data32
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xAF, 0x00, // code64
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x92, 0xAF, 0x00, // data64
        ];
        out[OFF_GDT..OFF_GDT + gdt.len()].copy_from_slice(&gdt);
        // GDTR: limit = 39, base = 0x8180
        out[OFF_GDTR] = (gdt.len() as u16 - 1) as u8;
        out[OFF_GDTR + 1] = ((gdt.len() as u16 - 1) >> 8) as u8;
        let gdt_phys = AP_TRAMPOLINE_PHYS_BASE + OFF_GDT as u64;
        Self::write_u32(&mut out, OFF_GDTR + 2, gdt_phys as u32);

        let handoff_offset =
            (self.startup_mailbox.handoff_phys - self.startup_mailbox.trampoline_phys) as usize;
        Self::write_u32(
            &mut out,
            handoff_offset,
            self.startup_mailbox.handoff.signature,
        );
        Self::write_u32(
            &mut out,
            handoff_offset + 4,
            self.startup_mailbox.handoff.startup_seq,
        );
        Self::write_u32(
            &mut out,
            handoff_offset + 8,
            self.startup_mailbox.handoff.target_apic_id,
        );
        Self::write_u64(
            &mut out,
            handoff_offset + 16,
            self.startup_mailbox.handoff.stack_top_phys,
        );
        Self::write_u64(
            &mut out,
            handoff_offset + 24,
            self.startup_mailbox.handoff.handoff_phys,
        );
        Self::write_u64(
            &mut out,
            handoff_offset + 32,
            self.startup_mailbox.handoff.kernel_entry_phys,
        );
        Self::write_u64(
            &mut out,
            handoff_offset + 40,
            self.startup_mailbox.handoff.page_table_root_phys,
        );
        // Status word published by the AP trampoline (starts IDLE).
        Self::write_u32(&mut out, handoff_offset + 48, AP_STATUS_IDLE);
        out
    }

    /// Physical address of the AP trampoline status word.
    pub fn trampoline_status_phys() -> u64 {
        AP_TRAMPOLINE_PHYS_BASE + AP_STATUS_OFFSET
    }

    /// Physical base of the trampoline page (for identity mapping).
    pub fn trampoline_page_phys() -> u64 {
        AP_TRAMPOLINE_PHYS_BASE
    }

    /// Read the AP-published trampoline status word (0 on host / if unmapped).
    pub fn read_trampoline_status(&self) -> u32 {
        let _ = self;
        Self::read_trampoline_status_global()
    }

    /// Lock-free trampoline status read (safe during AP bring-up wait).
    pub fn read_trampoline_status_global() -> u32 {
        #[cfg(target_os = "none")]
        unsafe {
            let ptr = crate::phys_mem::phys_to_ptr::<u32>(Self::trampoline_status_phys());
            return core::ptr::read_volatile(ptr);
        }
        #[cfg(not(target_os = "none"))]
        {
            AP_STATUS_IDLE
        }
    }

    /// True when the AP has entered the trampoline (any successful non-idle status).
    pub fn trampoline_status_entered(status: u32) -> bool {
        matches!(
            status,
            AP_STATUS_ENTERED
                | AP_STATUS_PARKED
                | AP_STATUS_MODE_SWITCH
                | AP_STATUS_HANDOFF
        )
    }

    /// True when the AP reached long mode and is calling / has called kernel entry.
    pub fn trampoline_status_handoff(status: u32) -> bool {
        status == AP_STATUS_HANDOFF
    }

    fn write_u32(dst: &mut [u8], offset: usize, value: u32) {
        dst[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(dst: &mut [u8], offset: usize, value: u64) {
        dst[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    pub fn trampoline_layout(&self) -> TrampolineLayout {
        TrampolineLayout {
            slot_base_phys: AP_TRAMPOLINE_PHYS_BASE,
            slot_size_bytes: AP_TRAMPOLINE_SLOT_BYTES,
            code_base_phys: AP_TRAMPOLINE_PHYS_BASE,
            code_size_bytes: AP_TRAMPOLINE_CODE_BYTES,
            mailbox_base_phys: AP_TRAMPOLINE_PHYS_BASE + AP_TRAMPOLINE_CODE_BYTES,
            mailbox_size_bytes: AP_TRAMPOLINE_MAILBOX_BYTES,
            handoff_size_bytes: AP_TRAMPOLINE_HANDOFF_BYTES,
            trampoline_blob_size_bytes: AP_TRAMPOLINE_CODE_BLOB.len() as u64,
            stack_top_phys: AP_TRAMPOLINE_PHYS_BASE + AP_TRAMPOLINE_SLOT_BYTES,
            stack_size_bytes: AP_TRAMPOLINE_STACK_BYTES,
            sipi_vector: AP_STARTUP_VECTOR,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_core_updates_summary() {
        let mut m = MultiCoreManager::new();
        m.register_core(0, CoreRole::Bootstrap).unwrap();
        m.register_core(1, CoreRole::Application).unwrap();
        let s = m.summary();
        assert_eq!(s.known_cores, 2);
        assert_eq!(s.online_cores, 1);
        assert_eq!(s.bsp_apic_id, Some(0));
    }

    #[test]
    fn per_core_counters_accumulate() {
        let mut m = MultiCoreManager::new();
        m.register_core(0, CoreRole::Bootstrap).unwrap();
        m.note_tick(0).unwrap();
        m.note_dispatch(0).unwrap();
        m.note_completion(0).unwrap();
        let s = m.summary();
        assert_eq!(s.total_ticks_seen, 1);
        assert_eq!(s.total_dispatches, 1);
        assert_eq!(s.total_completions, 1);
    }

    #[test]
    fn ap_startup_transitions_progress_state() {
        let mut m = MultiCoreManager::new();
        m.register_core(1, CoreRole::Application).unwrap();
        m.plan_ap_startup(1).unwrap();
        assert_eq!(m.summary().booting_cores, 1);
        assert_eq!(m.summary().startup_pending_apic, Some(1));
        m.complete_ap_startup(1).unwrap();
        assert_eq!(m.summary().online_cores, 1);
    }

    #[test]
    fn ap_startup_plan_sets_mailbox_and_vector() {
        let mut m = MultiCoreManager::new();
        m.register_core(1, CoreRole::Application).unwrap();
        let plan = m.plan_ap_startup(1).unwrap();
        assert_eq!(plan.sipi_vector, AP_STARTUP_VECTOR);
        assert_eq!(plan.entry_phys, AP_TRAMPOLINE_PHYS_BASE);
        assert_eq!(
            plan.trampoline.code_len_bytes as usize,
            trampoline_code_len()
        );
        assert_eq!(plan.handoff.target_apic_id, 1);
        assert_eq!(plan.handoff.signature, AP_HANDOFF_SIGNATURE);
        let mb = m.startup_mailbox();
        assert_eq!(mb.pending_apic_id, Some(1));
        assert!(mb.trampoline_installed);
        assert_eq!(mb.trampoline_installed_seq, plan.startup_seq);
        m.complete_ap_startup(1).unwrap();
        assert_eq!(m.startup_mailbox().last_acked_apic_id, Some(1));
    }

    #[test]
    fn trampoline_blob_metadata_is_reported() {
        let m = MultiCoreManager::new();
        let layout = m.trampoline_layout();
        assert_eq!(
            layout.trampoline_blob_size_bytes as usize,
            m.trampoline_blob().len()
        );
        assert_eq!(layout.handoff_size_bytes, AP_TRAMPOLINE_HANDOFF_BYTES);
        assert!(m.trampoline_blob().len() > 16);
        assert_eq!(m.trampoline_blob()[0], 0xFA); // cli
        assert!(trampoline_code_len() > AP_TRAMPOLINE_REAL.len());
        let image = MultiCoreManager::new().build_trampoline_slot_image();
        assert_eq!(image[OFF_PROT], AP_TRAMPOLINE_PROT[0]);
        assert_eq!(image[OFF_LONG], AP_TRAMPOLINE_LONG[0]);
        assert_eq!(image[OFF_GDT + 13], 0x9A); // code32 access byte
    }

    #[test]
    fn trampoline_slot_image_clears_status_word() {
        let mut m = MultiCoreManager::new();
        m.register_core(1, CoreRole::Application).unwrap();
        m.configure_ap_handoff(0x1000, 0x2000);
        let plan = m.plan_ap_startup(1).unwrap();
        let image = {
            // Re-build to inspect (plan already installed on bare-metal only).
            let mut tmp = MultiCoreManager::new();
            tmp.register_core(1, CoreRole::Application).unwrap();
            tmp.configure_ap_handoff(0x1000, 0x2000);
            let _ = tmp.plan_ap_startup(1).unwrap();
            tmp.build_trampoline_slot_image()
        };
        let status_off = (AP_STATUS_OFFSET) as usize;
        let status = u32::from_le_bytes(image[status_off..status_off + 4].try_into().unwrap());
        assert_eq!(status, AP_STATUS_IDLE);
        assert_eq!(plan.handoff.page_table_root_phys, 0x2000);
        assert_eq!(plan.handoff.kernel_entry_phys, 0x1000);
        assert!(MultiCoreManager::trampoline_status_entered(
            AP_STATUS_ENTERED
        ));
        assert!(!MultiCoreManager::trampoline_status_entered(AP_STATUS_IDLE));
    }

    #[test]
    fn select_dispatch_core_prefers_lightest_online_core() {
        let mut m = MultiCoreManager::new();
        m.register_core(0, CoreRole::Bootstrap).unwrap();
        m.register_core(1, CoreRole::Application).unwrap();
        m.plan_ap_startup(1).unwrap();
        m.complete_ap_startup(1).unwrap();
        m.enqueue_core_runqueue(0).unwrap();
        assert_eq!(m.select_dispatch_core(), Some(1));
    }

    #[test]
    fn take_task_for_core_steals_from_busiest_victim() {
        let mut m = MultiCoreManager::new();
        m.register_core(0, CoreRole::Bootstrap).unwrap();
        m.register_core(1, CoreRole::Application).unwrap();
        m.plan_ap_startup(1).unwrap();
        m.complete_ap_startup(1).unwrap();
        m.enqueue_core_task(0, "t0").unwrap();
        m.enqueue_core_task(0, "t1").unwrap();
        assert_eq!(m.run_queue_depth(0), 2);
        assert_eq!(m.run_queue_depth(1), 0);

        let stolen = m.take_task_for_core(1).unwrap();
        assert_eq!(stolen.as_str(), "t1"); // stolen from back
        assert_eq!(m.steal_count(1), 1);
        assert_eq!(m.run_queue_depth(0), 1);
        assert_eq!(m.take_local_task(0).unwrap().as_str(), "t0");
    }

    #[test]
    fn ap_startup_ack_requires_matching_sequence() {
        let mut m = MultiCoreManager::new();
        m.register_core(1, CoreRole::Application).unwrap();
        let plan = m.plan_ap_startup(1).unwrap();
        let wrong = m.complete_ap_startup_with_seq(1, plan.startup_seq + 1);
        assert!(matches!(
            wrong,
            Err(MultiCoreError::StartupSequenceMismatch)
        ));
        m.complete_ap_startup_with_seq(1, plan.startup_seq).unwrap();
    }

    #[test]
    fn handoff_configuration_updates_mailbox_defaults() {
        let mut m = MultiCoreManager::new();
        m.configure_ap_handoff(0x1234_5000, 0x2000);
        let mb = m.startup_mailbox();
        assert_eq!(mb.handoff.kernel_entry_phys, 0x1234_5000);
        assert_eq!(mb.handoff.page_table_root_phys, 0x2000);
    }

    #[test]
    fn reschedule_pending_bitmask_set_and_take() {
        // Clear any leftover bits from other tests.
        let _ = take_reschedule(3);
        assert!(!reschedule_pending(3));
        request_reschedule(3);
        assert!(reschedule_pending(3));
        assert!(take_reschedule(3));
        assert!(!reschedule_pending(3));
        assert!(!take_reschedule(3));
    }

    #[test]
    fn idle_wake_on_reschedule_integration() {
        let _ = take_reschedule(2);
        let _ = idle_leave(2);
        let before = wake_count(2);

        idle_enter(2);
        assert!(is_idle(2));
        assert_eq!(idle_mask() & (1 << 2), 1 << 2);

        request_reschedule(2);
        assert!(note_wake_if_idle(2));
        assert!(take_reschedule(2));
        assert!(idle_leave(2));
        assert!(!is_idle(2));
        assert_eq!(wake_count(2), before + 1);
        assert!(!note_wake_if_idle(2));
    }

    #[test]
    fn tlb_shootdown_pending_set_and_take() {
        let _ = take_tlb_shootdown(4);
        assert!(!tlb_shootdown_pending(4));
        request_tlb_shootdown(4, 0xABCD_0000);
        assert!(tlb_shootdown_pending(4));
        assert_eq!(tlb_shootdown_page(), 0xABCD_0000);
        assert_eq!(take_tlb_shootdown(4), Some(0xABCD_0000));
        assert!(!tlb_shootdown_pending(4));
        assert!(take_tlb_shootdown(4).is_none());

        request_tlb_shootdown(4, 0);
        assert_eq!(take_tlb_shootdown(4), Some(0));
    }

    #[test]
    fn tlb_shootdown_ack_wait_succeeds_after_take() {
        let mask = 1u64 << 5;
        let _ = begin_tlb_shootdown(0x1000, mask);
        assert!(!wait_tlb_shootdown_ack(mask, 10));
        assert_eq!(take_tlb_shootdown(5), Some(0x1000));
        assert!(wait_tlb_shootdown_ack(mask, 10));
    }
}
