use heapless::Vec;

const MAX_CORES: usize = 8;
const AP_TRAMPOLINE_PHYS_BASE: u64 = 0x8000;
const AP_STARTUP_VECTOR: u8 = (AP_TRAMPOLINE_PHYS_BASE >> 12) as u8;
const AP_TRAMPOLINE_SLOT_BYTES: u64 = 4096;
const AP_TRAMPOLINE_CODE_BYTES: u64 = 512;
const AP_TRAMPOLINE_MAILBOX_BYTES: u64 = 256;
const AP_TRAMPOLINE_STACK_BYTES: u64 = 2048;
const AP_TRAMPOLINE_HANDOFF_BYTES: u64 = 64;
const AP_HANDOFF_SIGNATURE: u32 = 0x4344_4B41; // "CDKA"
const AP_TRAMPOLINE_ENTRY_OFFSET: u16 = 0;
const AP_TRAMPOLINE_CODE_BLOB: [u8; 16] = [
    0xFA, // cli
    0x31, 0xC0, // xor ax, ax
    0x8E, 0xD8, // mov ds, ax
    0x8E, 0xC0, // mov es, ax
    0x8E, 0xD0, // mov ss, ax
    0x66, 0xBC, 0x00, 0x80, // mov sp, 0x8000 (placeholder stack)
    0xF4, // hlt
    0xEB, 0xFD, // jmp $
];

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
    startup_mailbox: StartupMailbox,
}

impl MultiCoreManager {
    pub const fn new() -> Self {
        Self {
            cores: Vec::new(),
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
                    code_len_bytes: AP_TRAMPOLINE_CODE_BLOB.len() as u16,
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
        self.startup_mailbox.trampoline.checksum = Self::trampoline_checksum();
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
        let core = self
            .cores
            .iter_mut()
            .find(|c| c.apic_id == apic_id)
            .ok_or(MultiCoreError::CoreNotFound)?;
        core.state = CoreState::Halted;
        core.run_queue_depth = 0;
        Ok(())
    }

    pub fn select_dispatch_core(&self) -> Option<u32> {
        let mut best: Option<(u32, u16)> = None;
        for core in self.cores.iter() {
            if !matches!(core.state, CoreState::Online) {
                continue;
            }
            let depth = core.run_queue_depth;
            match best {
                Some((_, best_depth)) if best_depth <= depth => {}
                _ => best = Some((core.apic_id, depth)),
            }
        }
        best.map(|(id, _)| id)
    }

    pub fn enqueue_core_runqueue(&mut self, apic_id: u32) -> Result<(), MultiCoreError> {
        let core = self
            .cores
            .iter_mut()
            .find(|c| c.apic_id == apic_id)
            .ok_or(MultiCoreError::CoreNotFound)?;
        core.run_queue_depth = core.run_queue_depth.saturating_add(1);
        Ok(())
    }

    pub fn dequeue_core_runqueue(&mut self, apic_id: u32) -> Result<(), MultiCoreError> {
        let core = self
            .cores
            .iter_mut()
            .find(|c| c.apic_id == apic_id)
            .ok_or(MultiCoreError::CoreNotFound)?;
        core.run_queue_depth = core.run_queue_depth.saturating_sub(1);
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
        let code = &AP_TRAMPOLINE_CODE_BLOB;
        out[..code.len()].copy_from_slice(code);

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
        out
    }

    fn write_u32(dst: &mut [u8], offset: usize, value: u32) {
        dst[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(dst: &mut [u8], offset: usize, value: u64) {
        dst[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn trampoline_checksum() -> u32 {
        AP_TRAMPOLINE_CODE_BLOB
            .iter()
            .fold(0u32, |sum, byte| sum.wrapping_add(*byte as u32))
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
            AP_TRAMPOLINE_CODE_BLOB.len()
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
}
