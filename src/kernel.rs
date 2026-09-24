use crate::{
    capability::{Capability, CapabilityError, Permission},
    local_apic::LocalApicTimerConfig,
    message::{Message, MessagePayload},
    multicore::{
        ApEntryContext, ApStartupPlan, ApTrampolineImage, CoreInfo, CoreRole, CoreSummary,
        MultiCoreError, MultiCoreManager, StartupMailbox, TrampolineLayout,
    },
    network::{NetError, NetPacket, NetworkStack},
    object::KernelObject,
    scheduler::Scheduler,
};
use core::str::FromStr;
use heapless::{FnvIndexMap, String, Vec};

const MAX_OBJECTS: usize = 16;
const MAX_ID_LEN: usize = 64;
const MAX_IFACE_LEN: usize = 16;
const MAX_RUNTIME_TICK_CURSORS: usize = 8;
const MAX_RUNTIME_DRIVE_MODES: usize = 8;
const MAX_TIMER_CALIBRATIONS: usize = 8;

#[derive(Debug, Clone)]
pub enum KernelError {
    InvalidCapability,
    ObjectNotFound,
    /// More than one object matched a kind/intent lookup.
    ObjectAmbiguous,
    PermissionDenied,
    MessageQueueFull,
    InvalidSignature,
    NetworkError,
    PayloadTooLarge,
    UnsupportedPayload,
    BindingTableFull,
    InvalidBinding,
    CoreAlreadyRegistered,
    CoreNotFound,
    CoreTableFull,
    CoreInvalidTransition,
    CoreRoleMismatch,
    StartupMailboxBusy,
    StartupMailboxMismatch,
    StartupSequenceMismatch,
    TrampolineInstallFailed,
}

pub type KernelResult<T> = Result<T, KernelError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeDriveMode {
    BspProxy,
    LocalApic,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkCapabilityStats {
    pub send_ok: u64,
    pub send_err: u64,
    pub recv_ok: u64,
    pub recv_empty: u64,
    pub recv_err: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BridgeTelemetry {
    pub ingress_moved: u64,
    pub egress_moved: u64,
    pub ingress_errors: u64,
    pub egress_errors: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BridgeTickResult {
    pub ingress_moved: u64,
    pub egress_moved: u64,
    pub ingress_errors: u64,
    pub egress_errors: u64,
}

pub struct Kernel {
    objects: FnvIndexMap<String<MAX_ID_LEN>, KernelObject, MAX_OBJECTS>,
    /// Fine-grained internal locks (ready queue + per-core running slots).
    scheduler: Scheduler,
    network_stats: FnvIndexMap<String<MAX_ID_LEN>, NetworkCapabilityStats, MAX_OBJECTS>,
    bridge_ingress: FnvIndexMap<String<MAX_IFACE_LEN>, String<MAX_ID_LEN>, MAX_OBJECTS>,
    bridge_egress: FnvIndexMap<String<MAX_ID_LEN>, String<MAX_IFACE_LEN>, MAX_OBJECTS>,
    bridge_telemetry: BridgeTelemetry,
    multicore: MultiCoreManager,
    runtime_tick_cursors: Vec<(u32, u64), MAX_RUNTIME_TICK_CURSORS>,
    runtime_drive_modes: Vec<(u32, RuntimeDriveMode), MAX_RUNTIME_DRIVE_MODES>,
    timer_calibrations: Vec<(u32, LocalApicTimerConfig), MAX_TIMER_CALIBRATIONS>,
}

impl Kernel {
    pub const fn new() -> Self {
        Self {
            objects: FnvIndexMap::new(),
            scheduler: Scheduler::new(),
            network_stats: FnvIndexMap::new(),
            bridge_ingress: FnvIndexMap::new(),
            bridge_egress: FnvIndexMap::new(),
            bridge_telemetry: BridgeTelemetry {
                ingress_moved: 0,
                egress_moved: 0,
                ingress_errors: 0,
                egress_errors: 0,
            },
            multicore: MultiCoreManager::new(),
            runtime_tick_cursors: Vec::new(),
            runtime_drive_modes: Vec::new(),
            timer_calibrations: Vec::new(),
        }
    }

    #[inline]
    fn sched(&self) -> &Scheduler {
        &self.scheduler
    }

    pub fn register_object(&mut self, obj: KernelObject) -> Capability {
        let mut cap = Capability::new(&obj);
        // Kernel-issued tokens are always signed; unsigned caps are rejected
        // by check_signature on privileged paths.
        let _ = cap.issue();
        let id = obj.id.clone();
        let _ = self.objects.insert(id, obj);
        let _ = self
            .network_stats
            .insert(cap.object_id.clone(), NetworkCapabilityStats::default());
        cap
    }

    /// Issue `cap` under the kernel issuer (hybrid Ed25519 + ML-DSA-65).
    pub fn sign_capability(cap: &mut Capability) -> Result<(), CapabilityError> {
        cap.issue()
    }

    /// Verify a capability against the kernel issuer.
    ///
    /// Returns `Ok(true)` when valid, `Ok(false)` when unsigned or the
    /// signature does not verify, `Err` for a foreign issuer or unknown format.
    pub fn verify_capability(cap: &Capability) -> Result<bool, CapabilityError> {
        cap.verify()
    }

    pub fn execute(&mut self, cap: &Capability) -> KernelResult<()> {
        Self::check_signature(cap)?;

        if !cap.has_permission(&Permission::Execute) {
            return Err(KernelError::PermissionDenied);
        }

        let obj = self
            .objects
            .get(&cap.object_id)
            .ok_or(KernelError::ObjectNotFound)?;
        let object_id = obj.id.clone();

        self.sched().schedule(obj);
        self.queue_task_to_core(object_id.as_str());
        Ok(())
    }

    pub fn send_message(
        &mut self,
        from_cap: &Capability,
        to_object_id: &str,
        msg: Message,
    ) -> KernelResult<()> {
        Self::check_signature(from_cap)?;

        if !from_cap.has_permission(&Permission::SendMessage) {
            return Err(KernelError::PermissionDenied);
        }

        let key: String<MAX_ID_LEN> = String::from_str(to_object_id).unwrap_or_default();
        let to_obj = self
            .objects
            .get_mut(&key)
            .ok_or(KernelError::ObjectNotFound)?;

        // Check if message queue is full
        if to_obj.message_count() >= 8 {
            return Err(KernelError::MessageQueueFull);
        }

        to_obj
            .receive_message(msg)
            .map_err(|_| KernelError::MessageQueueFull)?;
        Ok(())
    }

    pub fn receive_message(&mut self, cap: &Capability) -> KernelResult<Option<Message>> {
        Self::check_signature(cap)?;

        if !cap.has_permission(&Permission::ReceiveMessage) {
            return Err(KernelError::PermissionDenied);
        }

        let obj = self
            .objects
            .get_mut(&cap.object_id)
            .ok_or(KernelError::ObjectNotFound)?;

        Ok(obj.pop_message())
    }

    pub fn network_send(
        &mut self,
        cap: &Capability,
        network: &mut NetworkStack,
        iface: &str,
        payload: &[u8],
    ) -> KernelResult<()> {
        if let Err(e) = Self::check_signature(cap) {
            self.bump_net_send_err(&cap.object_id);
            return Err(e);
        }
        if !self.objects.contains_key(&cap.object_id) {
            self.bump_net_send_err(&cap.object_id);
            return Err(KernelError::InvalidCapability);
        }
        if !cap.has_permission(&Permission::SendMessage) {
            self.bump_net_send_err(&cap.object_id);
            return Err(KernelError::PermissionDenied);
        }
        match network
            .send_bytes(iface, payload)
            .map_err(Self::map_net_error)
        {
            Ok(()) => {
                self.bump_net_send_ok(&cap.object_id);
                Ok(())
            }
            Err(e) => {
                self.bump_net_send_err(&cap.object_id);
                Err(e)
            }
        }
    }

    pub fn network_receive(
        &mut self,
        cap: &Capability,
        network: &mut NetworkStack,
        iface: &str,
    ) -> KernelResult<Option<NetPacket>> {
        if let Err(e) = Self::check_signature(cap) {
            self.bump_net_recv_err(&cap.object_id);
            return Err(e);
        }
        if !self.objects.contains_key(&cap.object_id) {
            self.bump_net_recv_err(&cap.object_id);
            return Err(KernelError::InvalidCapability);
        }
        if !cap.has_permission(&Permission::ReceiveMessage) {
            self.bump_net_recv_err(&cap.object_id);
            return Err(KernelError::PermissionDenied);
        }
        match network.recv_packet(iface).map_err(Self::map_net_error) {
            Ok(Some(packet)) => {
                self.bump_net_recv_ok(&cap.object_id);
                Ok(Some(packet))
            }
            Ok(None) => {
                self.bump_net_recv_empty(&cap.object_id);
                Ok(None)
            }
            Err(e) => {
                self.bump_net_recv_err(&cap.object_id);
                Err(e)
            }
        }
    }

    /// Bridge one network packet into an object's message queue.
    ///
    /// The bridging capability acts with delegated authority over bound
    /// objects: ingress requires it to hold `ReceiveMessage` (checked inside
    /// `network_receive`) **and** `SendMessage` (checked by `send_message`
    /// on delivery), so network-sourced traffic cannot be injected with a
    /// receive-only capability.
    pub fn bridge_network_to_object(
        &mut self,
        cap: &Capability,
        network: &mut NetworkStack,
        iface: &str,
        target_object_id: &str,
    ) -> KernelResult<bool> {
        let packet = self.network_receive(cap, network, iface)?;
        let Some(packet) = packet else {
            return Ok(false);
        };

        let mut data = heapless::Vec::<u8, 64>::new();
        data.extend_from_slice(packet.payload.as_slice())
            .map_err(|_| KernelError::PayloadTooLarge)?;
        let msg = Message::new("net-bridge", target_object_id, MessagePayload::Data(data))
            .map_err(|_| KernelError::PayloadTooLarge)?;
        self.send_message(cap, target_object_id, msg)?;
        Ok(true)
    }

    /// Bridge one queued object message out to the network.
    ///
    /// Draining the source object is a receive on its queue performed with
    /// the bridging capability's delegated authority, so `ReceiveMessage`
    /// is required up front (`network_send` then enforces `SendMessage`).
    pub fn bridge_object_to_network(
        &mut self,
        cap: &Capability,
        network: &mut NetworkStack,
        source_object_id: &str,
        iface: &str,
    ) -> KernelResult<bool> {
        Self::check_signature(cap)?;
        if !cap.has_permission(&Permission::ReceiveMessage) {
            return Err(KernelError::PermissionDenied);
        }
        let maybe_msg = self.receive_message_direct(source_object_id)?;
        let Some(msg) = maybe_msg else {
            return Ok(false);
        };

        let bytes: heapless::Vec<u8, 64> = match msg.payload {
            MessagePayload::Data(data) => data,
            MessagePayload::Text(text) | MessagePayload::Command(text) => {
                let mut out = heapless::Vec::<u8, 64>::new();
                out.extend_from_slice(text.as_bytes())
                    .map_err(|_| KernelError::PayloadTooLarge)?;
                out
            }
            MessagePayload::Request { .. } | MessagePayload::Response { .. } => {
                return Err(KernelError::UnsupportedPayload);
            }
        };

        self.network_send(cap, network, iface, bytes.as_slice())?;
        Ok(true)
    }

    pub fn execute_next(&mut self) -> Option<String<MAX_ID_LEN>> {
        // No topology registered yet — drain the global scheduler directly.
        if self.multicore.summary().known_cores == 0 {
            return self.sched().execute_next();
        }
        // Drain from the lightest online core first, then any other online core.
        if let Some(apic) = self.multicore.select_dispatch_core() {
            if let Some(id) = self.execute_next_on_core(apic) {
                return Some(id);
            }
        }
        let mut tried = [0u32; 8];
        let mut n = 0usize;
        self.multicore.for_each_core(|core| {
            if n < tried.len() && matches!(core.state, crate::multicore::CoreState::Online) {
                tried[n] = core.apic_id;
                n += 1;
            }
        });
        for &apic in tried.iter().take(n) {
            if let Some(id) = self.execute_next_on_core(apic) {
                return Some(id);
            }
        }
        // Fallback if RQ bookkeeping is empty but the global queue still has work.
        self.sched().execute_next()
    }

    /// Dispatch the next task assigned to `apic_id`, stealing from a busier
    /// core when the local run queue is empty (Phase 19).
    pub fn execute_next_on_core(&mut self, apic_id: u32) -> Option<String<MAX_ID_LEN>> {
        let object_id = self.multicore.take_task_for_core(apic_id)?;
        // Empty placeholder ids are depth-only test stubs — skip scheduler.
        if object_id.is_empty() || object_id.as_str() == "_" {
            let _ = self.multicore.note_dispatch(apic_id);
            return Some(object_id);
        }
        match self
            .sched()
            .take_queued_by_id(object_id.as_str(), 0, apic_id)
        {
            Some(id) => {
                let _ = self.multicore.note_dispatch(apic_id);
                let _ = crate::context::prepare_dispatch(apic_id, id.as_str());
                Some(id)
            }
            None => {
                // Scheduler desync: put the id back on this core.
                let _ = self.multicore.enqueue_core_task(apic_id, object_id.as_str());
                None
            }
        }
    }

    pub fn complete_running_on_core(&mut self, apic_id: u32) {
        self.sched().complete_running_on(apic_id);
        let _ = self.multicore.note_completion(apic_id);
    }

    /// Yield the running task on `apic_id` back to the ready/core queues.
    pub fn yield_running_on_core(&mut self, apic_id: u32) -> Option<String<MAX_ID_LEN>> {
        let id = self.sched().yield_running_on(apic_id)?;
        self.queue_task_to_core(id.as_str());
        Some(id)
    }

    pub fn service_core_runtime_step(&mut self, apic_id: u32) -> Option<String<MAX_ID_LEN>> {
        let runtime_tick = self.next_runtime_tick(apic_id);
        self.service_core_runtime_step_with_tick(apic_id, runtime_tick)
    }

    pub fn service_core_runtime_step_if_bsp_proxy(
        &mut self,
        apic_id: u32,
    ) -> Option<String<MAX_ID_LEN>> {
        if !matches!(self.runtime_drive_mode(apic_id), RuntimeDriveMode::BspProxy) {
            return None;
        }
        self.service_core_runtime_step(apic_id)
    }

    /// Preempt / dispatch on `apic_id`.
    ///
    /// Returns `Some(id)` only on a **new** dispatch or preemption switch so
    /// ISR paths can stay quiet while a context keeps running (M7).
    pub fn service_core_runtime_step_with_tick(
        &mut self,
        apic_id: u32,
        current_tick: u64,
    ) -> Option<String<MAX_ID_LEN>> {
        if let Some(switched) = self.preempt_tick_on_core(current_tick, apic_id) {
            return Some(switched);
        }
        if self.sched().running_task_on(apic_id).is_some() {
            return None;
        }
        self.execute_next_on_core(apic_id)
    }

    pub fn runtime_tick_cursor(&self, apic_id: u32) -> u64 {
        self.runtime_tick_cursors
            .iter()
            .find(|(id, _)| *id == apic_id)
            .map(|(_, tick)| *tick)
            .unwrap_or(0)
    }

    pub fn runtime_drive_mode(&self, apic_id: u32) -> RuntimeDriveMode {
        self.runtime_drive_modes
            .iter()
            .find(|(id, _)| *id == apic_id)
            .map(|(_, mode)| *mode)
            .unwrap_or(RuntimeDriveMode::BspProxy)
    }

    pub fn set_runtime_drive_mode(&mut self, apic_id: u32, mode: RuntimeDriveMode) {
        for (id, current) in self.runtime_drive_modes.iter_mut() {
            if *id == apic_id {
                *current = mode;
                return;
            }
        }
        let _ = self.runtime_drive_modes.push((apic_id, mode));
    }

    /// Mark `apic_id` as driven by local-APIC timer IRQs.
    ///
    /// Hardware arming must happen on that core itself via
    /// [`crate::local_apic::arm_current_core_runtime_timer`] (AP entry path).
    /// Console `cpu-step-ap` remains a software fallback until the AP timer is live.
    pub fn activate_ap_local_timer(&mut self, apic_id: u32) {
        self.set_runtime_drive_mode(apic_id, RuntimeDriveMode::LocalApic);
    }

    pub fn set_timer_calibration(&mut self, apic_id: u32, config: LocalApicTimerConfig) {
        if apic_id == 0 {
            crate::percpu::publish_bsp_timer_count(config.initial_count);
        }
        for (id, current) in self.timer_calibrations.iter_mut() {
            if *id == apic_id {
                *current = config;
                return;
            }
        }
        let _ = self.timer_calibrations.push((apic_id, config));
    }

    pub fn timer_calibration(&self, apic_id: u32) -> Option<LocalApicTimerConfig> {
        self.timer_calibrations
            .iter()
            .find(|(id, _)| *id == apic_id)
            .map(|(_, cfg)| *cfg)
    }

    pub fn timer_config_for_core(&self, apic_id: u32) -> LocalApicTimerConfig {
        self.timer_calibration(apic_id)
            .unwrap_or_else(LocalApicTimerConfig::ap_runtime_default)
    }

    /// Resolve a timer config for an AP after handoff.
    ///
    /// PIT IRQs only interrupt the BSP, so APs cannot calibrate against
    /// `ticks()` directly. Phase 16 inherits the BSP (apic 0) calibration when
    /// present, otherwise installs the default periodic seed and stores it.
    pub fn ensure_ap_timer_calibration(&mut self, apic_id: u32) -> LocalApicTimerConfig {
        if let Some(cfg) = self.timer_calibration(apic_id) {
            return cfg;
        }
        let inherited = self
            .timer_calibration(0)
            .unwrap_or_else(LocalApicTimerConfig::ap_runtime_default);
        self.set_timer_calibration(apic_id, inherited);
        inherited
    }

    pub fn read_trampoline_status(&self) -> u32 {
        self.multicore.read_trampoline_status()
    }

    pub fn trampoline_status_entered(status: u32) -> bool {
        MultiCoreManager::trampoline_status_entered(status)
    }

    pub fn on_local_apic_timer_tick(&mut self, apic_id: u32) -> Option<String<MAX_ID_LEN>> {
        if !matches!(
            self.runtime_drive_mode(apic_id),
            RuntimeDriveMode::LocalApic
        ) {
            return None;
        }
        self.service_core_runtime_step(apic_id)
    }

    /// Advance the scheduler clock by one timer tick.
    ///
    /// If the running task's time slice has expired, it is evicted and the
    /// next queued task is dispatched.  Returns `Some(id)` on a context
    /// switch, `None` otherwise.
    pub fn preempt_tick(&mut self, current_tick: u64) -> Option<String<MAX_ID_LEN>> {
        self.preempt_tick_on_core(current_tick, 0)
    }

    pub fn preempt_tick_on_core(
        &mut self,
        current_tick: u64,
        apic_id: u32,
    ) -> Option<String<MAX_ID_LEN>> {
        let _ = self.multicore.note_tick(apic_id);
        let switched = self.sched().preempt_if_expired_on(apic_id, current_tick);
        if switched.is_some() {
            let _ = self.multicore.note_dispatch(apic_id);
        }
        switched
    }

    /// Object id of the BSP (apic 0) running task, if any.
    pub fn running_task_id(&self) -> Option<heapless::String<MAX_ID_LEN>> {
        self.running_task_id_on(0)
    }

    /// Object id of the task running on `apic_id`, if any.
    pub fn running_task_id_on(&self, apic_id: u32) -> Option<heapless::String<MAX_ID_LEN>> {
        self.sched()
            .running_task_on(apic_id)
            .map(|rt| rt.task.object_id)
    }

    /// Bitmask of cores with an occupied running slot.
    pub fn scheduler_running_mask(&self) -> u64 {
        self.sched().running_mask()
    }

    /// Number of cores currently holding a running task.
    pub fn scheduler_running_count(&self) -> usize {
        self.sched().running_count()
    }

    pub fn get_object(&self, cap: &Capability) -> KernelResult<&KernelObject> {
        Self::check_signature(cap)?;

        if !cap.has_permission(&Permission::Read) {
            return Err(KernelError::PermissionDenied);
        }

        self.objects
            .get(&cap.object_id)
            .ok_or(KernelError::ObjectNotFound)
    }

    pub fn delete_object(&mut self, cap: &Capability) -> KernelResult<()> {
        Self::check_signature(cap)?;

        if !cap.has_permission(&Permission::Delete) {
            return Err(KernelError::PermissionDenied);
        }

        self.objects
            .remove(&cap.object_id)
            .ok_or(KernelError::ObjectNotFound)?;
        Ok(())
    }

    pub fn scheduler_queue_size(&self) -> usize {
        self.sched().queue_size()
    }

    pub fn validate_capability(&self, cap: &Capability) -> KernelResult<()> {
        Self::check_signature(cap)?;

        if !self.objects.contains_key(&cap.object_id) {
            return Err(KernelError::InvalidCapability);
        }
        Ok(())
    }

    pub fn network_stats_for(&self, object_id: &str) -> Option<NetworkCapabilityStats> {
        let key: String<MAX_ID_LEN> = String::from_str(object_id).ok()?;
        self.network_stats.get(&key).copied()
    }

    pub fn for_each_network_stats(&self, mut f: impl FnMut(&str, NetworkCapabilityStats)) {
        for (object_id, stats) in self.network_stats.iter() {
            f(object_id.as_str(), *stats);
        }
    }

    pub fn bridge_bind_ingress(&mut self, iface: &str, object_id: &str) -> KernelResult<()> {
        if self.for_each_object_find(object_id).is_none() {
            return Err(KernelError::ObjectNotFound);
        }
        let iface_key: String<MAX_IFACE_LEN> =
            String::from_str(iface).map_err(|_| KernelError::InvalidBinding)?;
        let object_key: String<MAX_ID_LEN> =
            String::from_str(object_id).map_err(|_| KernelError::InvalidBinding)?;
        self.bridge_ingress
            .insert(iface_key, object_key)
            .map_err(|_| KernelError::BindingTableFull)?;
        Ok(())
    }

    pub fn bridge_bind_egress(&mut self, object_id: &str, iface: &str) -> KernelResult<()> {
        if self.for_each_object_find(object_id).is_none() {
            return Err(KernelError::ObjectNotFound);
        }
        let object_key: String<MAX_ID_LEN> =
            String::from_str(object_id).map_err(|_| KernelError::InvalidBinding)?;
        let iface_key: String<MAX_IFACE_LEN> =
            String::from_str(iface).map_err(|_| KernelError::InvalidBinding)?;
        self.bridge_egress
            .insert(object_key, iface_key)
            .map_err(|_| KernelError::BindingTableFull)?;
        Ok(())
    }

    pub fn bridge_clear_bindings(&mut self) {
        self.bridge_ingress.clear();
        self.bridge_egress.clear();
    }

    pub fn bridge_telemetry(&self) -> BridgeTelemetry {
        self.bridge_telemetry
    }

    pub fn bridge_binding_counts(&self) -> (usize, usize) {
        (self.bridge_ingress.len(), self.bridge_egress.len())
    }

    pub fn for_each_bridge_ingress_binding(&self, mut f: impl FnMut(&str, &str)) {
        for (iface, object_id) in self.bridge_ingress.iter() {
            f(iface.as_str(), object_id.as_str());
        }
    }

    pub fn for_each_bridge_egress_binding(&self, mut f: impl FnMut(&str, &str)) {
        for (object_id, iface) in self.bridge_egress.iter() {
            f(object_id.as_str(), iface.as_str());
        }
    }

    pub fn bridge_tick(
        &mut self,
        cap: &Capability,
        network: &mut NetworkStack,
    ) -> KernelResult<BridgeTickResult> {
        Self::check_signature(cap)?;
        if !self.objects.contains_key(&cap.object_id) {
            return Err(KernelError::InvalidCapability);
        }

        network.service();
        let mut result = BridgeTickResult::default();

        let mut ingress =
            heapless::Vec::<(String<MAX_IFACE_LEN>, String<MAX_ID_LEN>), MAX_OBJECTS>::new();
        for (iface, obj) in self.bridge_ingress.iter() {
            let _ = ingress.push((iface.clone(), obj.clone()));
        }
        for (iface, object_id) in ingress.iter() {
            match self.bridge_network_to_object(cap, network, iface.as_str(), object_id.as_str()) {
                Ok(true) => result.ingress_moved = result.ingress_moved.saturating_add(1),
                Ok(false) => {}
                Err(_) => result.ingress_errors = result.ingress_errors.saturating_add(1),
            }
        }

        let mut egress =
            heapless::Vec::<(String<MAX_ID_LEN>, String<MAX_IFACE_LEN>), MAX_OBJECTS>::new();
        for (obj, iface) in self.bridge_egress.iter() {
            let _ = egress.push((obj.clone(), iface.clone()));
        }
        for (object_id, iface) in egress.iter() {
            match self.bridge_object_to_network(cap, network, object_id.as_str(), iface.as_str()) {
                Ok(true) => result.egress_moved = result.egress_moved.saturating_add(1),
                Ok(false) => {}
                Err(_) => result.egress_errors = result.egress_errors.saturating_add(1),
            }
        }

        network.service();

        self.bridge_telemetry.ingress_moved = self
            .bridge_telemetry
            .ingress_moved
            .saturating_add(result.ingress_moved);
        self.bridge_telemetry.egress_moved = self
            .bridge_telemetry
            .egress_moved
            .saturating_add(result.egress_moved);
        self.bridge_telemetry.ingress_errors = self
            .bridge_telemetry
            .ingress_errors
            .saturating_add(result.ingress_errors);
        self.bridge_telemetry.egress_errors = self
            .bridge_telemetry
            .egress_errors
            .saturating_add(result.egress_errors);

        Ok(result)
    }

    // --- Console-friendly helpers (operate by string id, no capability needed) ---

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn for_each_object(&self, mut f: impl FnMut(&KernelObject)) {
        for obj in self.objects.values() {
            f(obj);
        }
    }

    /// Find an object by its string ID, returning a shared reference.
    pub fn for_each_object_find(&self, id: &str) -> Option<&KernelObject> {
        let key: String<MAX_ID_LEN> = String::from_str(id).unwrap_or_default();
        self.objects.get(&key)
    }

    /// Resolve `ref_name` to an object id.
    ///
    /// Lookup order: exact id → unique `kind` (create name) → unique `intent`.
    pub fn resolve_object_ref(&self, ref_name: &str) -> KernelResult<String<MAX_ID_LEN>> {
        if ref_name.is_empty() {
            return Err(KernelError::ObjectNotFound);
        }
        if let Some(obj) = self.for_each_object_find(ref_name) {
            return Ok(obj.id.clone());
        }

        let mut kind_match: Option<String<MAX_ID_LEN>> = None;
        let mut kind_ambiguous = false;
        let mut intent_match: Option<String<MAX_ID_LEN>> = None;
        let mut intent_ambiguous = false;
        for obj in self.objects.values() {
            if obj.kind.as_str() == ref_name {
                if kind_match.is_some() {
                    kind_ambiguous = true;
                } else {
                    kind_match = Some(obj.id.clone());
                }
            }
            if obj.intent.as_str() == ref_name {
                if intent_match.is_some() {
                    intent_ambiguous = true;
                } else {
                    intent_match = Some(obj.id.clone());
                }
            }
        }

        if let Some(id) = kind_match {
            if kind_ambiguous {
                return Err(KernelError::ObjectAmbiguous);
            }
            return Ok(id);
        }
        if let Some(id) = intent_match {
            if intent_ambiguous {
                return Err(KernelError::ObjectAmbiguous);
            }
            return Ok(id);
        }
        Err(KernelError::ObjectNotFound)
    }

    pub fn schedule_by_id(&mut self, id: &str) -> KernelResult<()> {
        let key = self.resolve_object_ref(id)?;
        let obj = self.objects.get(&key).ok_or(KernelError::ObjectNotFound)?;
        let object_id = obj.id.clone();
        self.sched().schedule(obj);
        self.queue_task_to_core(object_id.as_str());
        Ok(())
    }

    pub fn send_message_direct(&mut self, to_id: &str, msg: Message) -> KernelResult<()> {
        let key: String<MAX_ID_LEN> = String::from_str(to_id).unwrap_or_default();
        let obj = self
            .objects
            .get_mut(&key)
            .ok_or(KernelError::ObjectNotFound)?;
        if obj.message_count() >= 8 {
            return Err(KernelError::MessageQueueFull);
        }
        obj.receive_message(msg)
            .map_err(|_| KernelError::MessageQueueFull)
    }

    pub fn receive_message_direct(&mut self, id: &str) -> KernelResult<Option<Message>> {
        let key: String<MAX_ID_LEN> = String::from_str(id).unwrap_or_default();
        let obj = self
            .objects
            .get_mut(&key)
            .ok_or(KernelError::ObjectNotFound)?;
        Ok(obj.pop_message())
    }

    /// Require a valid kernel-issued proof on `cap`.
    ///
    /// Unsigned, forged, foreign-issuer, and tampered tokens all map to
    /// [`KernelError::InvalidSignature`]. Privileged kernel entry points call
    /// this before checking permissions or looking up objects.
    fn check_signature(cap: &Capability) -> KernelResult<()> {
        match cap.verify() {
            Ok(true) => Ok(()),
            Ok(false) => Err(KernelError::InvalidSignature),
            Err(_) => Err(KernelError::InvalidSignature),
        }
    }

    fn map_net_error(_err: NetError) -> KernelError {
        KernelError::NetworkError
    }

    fn bump_net_send_ok(&mut self, object_id: &str) {
        if let Some(stats) = self.net_stats_mut(object_id) {
            stats.send_ok = stats.send_ok.saturating_add(1);
        }
    }

    fn bump_net_send_err(&mut self, object_id: &str) {
        if let Some(stats) = self.net_stats_mut(object_id) {
            stats.send_err = stats.send_err.saturating_add(1);
        }
    }

    fn bump_net_recv_ok(&mut self, object_id: &str) {
        if let Some(stats) = self.net_stats_mut(object_id) {
            stats.recv_ok = stats.recv_ok.saturating_add(1);
        }
    }

    fn bump_net_recv_empty(&mut self, object_id: &str) {
        if let Some(stats) = self.net_stats_mut(object_id) {
            stats.recv_empty = stats.recv_empty.saturating_add(1);
        }
    }

    fn bump_net_recv_err(&mut self, object_id: &str) {
        if let Some(stats) = self.net_stats_mut(object_id) {
            stats.recv_err = stats.recv_err.saturating_add(1);
        }
    }

    fn net_stats_mut(&mut self, object_id: &str) -> Option<&mut NetworkCapabilityStats> {
        let key: String<MAX_ID_LEN> = String::from_str(object_id).ok()?;
        self.network_stats.get_mut(&key)
    }

    pub fn delete_by_id(&mut self, id: &str) -> KernelResult<()> {
        let key: String<MAX_ID_LEN> = String::from_str(id).unwrap_or_default();
        self.objects
            .remove(&key)
            .ok_or(KernelError::ObjectNotFound)?;
        Ok(())
    }

    pub fn register_core(&mut self, apic_id: u32, role: CoreRole) -> KernelResult<()> {
        self.multicore
            .register_core(apic_id, role)
            .map_err(Self::map_multicore_error)
    }

    pub fn set_core_online(&mut self, apic_id: u32, online: bool) -> KernelResult<()> {
        self.multicore
            .set_online(apic_id, online)
            .map_err(Self::map_multicore_error)
    }

    pub fn begin_ap_startup(&mut self, apic_id: u32) -> KernelResult<()> {
        self.multicore
            .begin_ap_startup(apic_id)
            .map_err(Self::map_multicore_error)
    }

    pub fn plan_ap_startup(&mut self, apic_id: u32) -> KernelResult<ApStartupPlan> {
        self.multicore
            .plan_ap_startup(apic_id)
            .map_err(Self::map_multicore_error)
    }

    pub fn ap_entry_reached(&mut self, apic_id: u32) -> KernelResult<()> {
        self.complete_ap_startup(apic_id)
    }

    pub fn ap_entry_reached_with_seq(
        &mut self,
        apic_id: u32,
        startup_seq: u32,
    ) -> KernelResult<()> {
        self.multicore
            .complete_ap_startup_with_seq(apic_id, startup_seq)
            .map_err(Self::map_multicore_error)
    }

    pub fn complete_ap_startup(&mut self, apic_id: u32) -> KernelResult<()> {
        self.multicore
            .complete_ap_startup(apic_id)
            .map_err(Self::map_multicore_error)
    }

    pub fn halt_core(&mut self, apic_id: u32) -> KernelResult<()> {
        self.multicore
            .halt_core(apic_id)
            .map_err(Self::map_multicore_error)
    }

    pub fn multicore_summary(&self) -> CoreSummary {
        self.multicore.summary()
    }

    pub fn for_each_core(&self, f: impl FnMut(CoreInfo)) {
        self.multicore.for_each_core(f);
    }

    pub fn startup_mailbox(&self) -> StartupMailbox {
        self.multicore.startup_mailbox()
    }

    pub fn configure_ap_handoff(&mut self, kernel_entry_phys: u64, page_table_root_phys: u64) {
        self.multicore
            .configure_ap_handoff(kernel_entry_phys, page_table_root_phys);
    }

    pub fn ap_trampoline_entry_hook(&mut self, apic_id: u32, startup_seq: u32) -> KernelResult<()> {
        self.ap_entry_reached_with_seq(apic_id, startup_seq)
    }

    pub fn trampoline_blob(&self) -> &'static [u8] {
        self.multicore.trampoline_blob()
    }

    pub fn trampoline_layout(&self) -> TrampolineLayout {
        self.multicore.trampoline_layout()
    }

    pub fn ap_handoff_context(&self) -> ApEntryContext {
        self.multicore.startup_mailbox().handoff
    }

    pub fn trampoline_image(&self) -> ApTrampolineImage {
        self.multicore.startup_mailbox().trampoline
    }

    fn map_multicore_error(err: MultiCoreError) -> KernelError {
        match err {
            MultiCoreError::CoreExists => KernelError::CoreAlreadyRegistered,
            MultiCoreError::CoreNotFound => KernelError::CoreNotFound,
            MultiCoreError::CoreTableFull => KernelError::CoreTableFull,
            MultiCoreError::InvalidTransition => KernelError::CoreInvalidTransition,
            MultiCoreError::NotApplicationCore => KernelError::CoreRoleMismatch,
            MultiCoreError::StartupMailboxBusy => KernelError::StartupMailboxBusy,
            MultiCoreError::StartupMailboxMismatch => KernelError::StartupMailboxMismatch,
            MultiCoreError::StartupSequenceMismatch => KernelError::StartupSequenceMismatch,
            MultiCoreError::TrampolineInstallFailed => KernelError::TrampolineInstallFailed,
        }
    }

    fn queue_task_to_core(&mut self, object_id: &str) {
        if self.multicore.summary().known_cores == 0 {
            return;
        }
        let target = self.multicore.select_dispatch_core().unwrap_or(0);
        let _ = self.multicore.enqueue_core_task(target, object_id);
        // Nudge LocalApic cores that may be idle in HLT.
        if matches!(
            self.runtime_drive_mode(target),
            RuntimeDriveMode::LocalApic
        ) {
            self.request_reschedule_ipi(target);
        }
    }

    /// Mark a software pending bit and send a Fixed reschedule IPI (when available).
    pub fn request_reschedule_ipi(&self, apic_id: u32) {
        crate::multicore::request_reschedule(apic_id);
        let _ = crate::local_apic::send_reschedule_ipi(apic_id);
    }

    /// Handle an incoming reschedule IPI (or software inject) on `apic_id`.
    pub fn on_reschedule_ipi(&mut self, apic_id: u32) -> Option<String<MAX_ID_LEN>> {
        let _ = crate::multicore::note_wake_if_idle(apic_id);
        let _ = crate::multicore::take_reschedule(apic_id);
        self.service_core_runtime_step(apic_id)
    }

    /// Queue a TLB shootdown and send Fixed IPI `0xF2` to `apic_id`.
    ///
    /// `page_virt == 0` requests a full local TLB flush on the target.
    pub fn request_tlb_shootdown_ipi(&self, apic_id: u32, page_virt: u64) {
        crate::multicore::request_tlb_shootdown(apic_id, page_virt);
        let _ = crate::local_apic::send_tlb_shootdown_ipi(apic_id);
    }

    /// Broadcast a TLB shootdown to all online cores except `exclude_apic_id`.
    ///
    /// Applies locally, sends Fixed IPIs, then waits briefly for ACKs (M6).
    pub fn broadcast_tlb_shootdown(&self, page_virt: u64, exclude_apic_id: u32) -> usize {
        crate::paging::apply_tlb_shootdown(page_virt);
        let mut target_mask = 0u64;
        let mut targets = [0u32; 8];
        let mut n = 0usize;
        self.multicore.for_each_core(|core| {
            if core.apic_id == exclude_apic_id {
                return;
            }
            if !matches!(core.state, crate::multicore::CoreState::Online) {
                return;
            }
            if core.apic_id < 64 {
                target_mask |= 1u64 << core.apic_id;
            }
            if n < targets.len() {
                targets[n] = core.apic_id;
                n += 1;
            }
        });
        let _gen = crate::multicore::begin_tlb_shootdown(page_virt, target_mask);
        for &apic_id in targets.iter().take(n) {
            let _ = crate::local_apic::send_tlb_shootdown_ipi(apic_id);
        }
        let _ = crate::multicore::wait_tlb_shootdown_ack(target_mask, 50_000);
        n
    }

    /// Handle an incoming TLB shootdown IPI (or software inject).
    pub fn on_tlb_shootdown_ipi(&self, apic_id: u32) -> Option<u64> {
        let page = crate::multicore::take_tlb_shootdown(apic_id)?;
        crate::paging::apply_tlb_shootdown(page);
        Some(page)
    }

    fn next_runtime_tick(&mut self, apic_id: u32) -> u64 {
        for (id, tick) in self.runtime_tick_cursors.iter_mut() {
            if *id == apic_id {
                *tick = tick.saturating_add(1);
                return *tick;
            }
        }
        if self.runtime_tick_cursors.push((apic_id, 1)).is_ok() {
            return 1;
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use crate::multicore::CoreRole;
    use crate::object::KernelObject;

    fn make_obj(name: &str, intent: &str) -> KernelObject {
        KernelObject::new_compute(name, intent)
    }

    /// Build a signed capability with an explicit permission set (tests only).
    fn signed_perms(obj: &KernelObject, perms: &[Permission]) -> Capability {
        let mut cap = Capability::with_permissions(obj, perms);
        cap.issue().unwrap();
        cap
    }

    #[test]
    fn register_object_returns_signed_capability() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("signed", "normal"));
        assert!(cap.is_signed());
        assert_eq!(cap.verify().unwrap(), true);
        assert!(k.validate_capability(&cap).is_ok());
    }

    #[test]
    fn unsigned_capability_is_rejected() {
        let mut k = Kernel::new();
        let obj = make_obj("u", "normal");
        let unsigned = Capability::new(&obj);
        let _ = k.register_object(obj);
        assert!(!unsigned.is_signed());
        assert!(matches!(
            k.execute(&unsigned),
            Err(KernelError::InvalidSignature)
        ));
        assert!(matches!(
            k.validate_capability(&unsigned),
            Err(KernelError::InvalidSignature)
        ));
    }

    #[test]
    fn register_object_increments_count() {
        let mut k = Kernel::new();
        assert_eq!(k.object_count(), 0);
        k.register_object(make_obj("a", "normal"));
        assert_eq!(k.object_count(), 1);
        k.register_object(make_obj("b", "batch"));
        assert_eq!(k.object_count(), 2);
    }

    #[test]
    fn execute_schedules_object_and_execute_next_drains_queue() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("worker", "low_latency"));
        k.execute(&cap).unwrap();
        assert_eq!(k.scheduler_queue_size(), 1);
        let id = k.execute_next();
        assert!(id.is_some());
        assert_eq!(k.scheduler_queue_size(), 0);
    }

    #[test]
    fn execute_requires_execute_permission() {
        let mut k = Kernel::new();
        let obj = make_obj("x", "normal");
        // Build a read-only capability manually (must still be signed).
        let cap = signed_perms(&obj, &[Permission::Read]);
        let _ = k.register_object(obj);
        let result = k.execute(&cap);
        assert!(matches!(result, Err(KernelError::PermissionDenied)));
    }

    #[test]
    fn execute_returns_error_for_unknown_object() {
        let mut k = Kernel::new();
        // Create a signed capability for an object that was never registered.
        let obj = make_obj("ghost", "normal");
        let mut cap = Capability::new(&obj);
        cap.issue().unwrap();
        let result = k.execute(&cap);
        assert!(matches!(result, Err(KernelError::ObjectNotFound)));
    }

    #[test]
    fn send_and_receive_message_direct() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("inbox", "normal"));
        let id = cap.object_id.as_str().to_owned();

        let msg = Message::text("console", &id, "ping").unwrap();
        k.send_message_direct(&id, msg).unwrap();

        let received = k.receive_message_direct(&id).unwrap();
        assert!(received.is_some());
        let m = received.unwrap();
        assert_eq!(m.from.as_str(), "console");
    }

    #[test]
    fn message_queue_full_returns_error() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("full", "batch"));
        let id = cap.object_id.as_str().to_owned();

        for _ in 0..8 {
            let msg = Message::text("src", &id, "fill").unwrap();
            k.send_message_direct(&id, msg).unwrap();
        }
        // 9th message must fail
        let msg = Message::text("src", &id, "overflow").unwrap();
        let result = k.send_message_direct(&id, msg);
        assert!(matches!(result, Err(KernelError::MessageQueueFull)));
    }

    #[test]
    fn receive_on_empty_queue_returns_none() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("empty", "normal"));
        let id = cap.object_id.as_str().to_owned();
        let result = k.receive_message_direct(&id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn delete_by_id_removes_object() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("del", "normal"));
        let id = cap.object_id.clone();
        assert_eq!(k.object_count(), 1);
        k.delete_by_id(id.as_str()).unwrap();
        assert_eq!(k.object_count(), 0);
    }

    #[test]
    fn delete_nonexistent_returns_error() {
        let mut k = Kernel::new();
        let result = k.delete_by_id("does-not-exist");
        assert!(matches!(result, Err(KernelError::ObjectNotFound)));
    }

    #[test]
    fn schedule_by_id_on_missing_object_returns_error() {
        let mut k = Kernel::new();
        let result = k.schedule_by_id("no-such-id");
        assert!(matches!(result, Err(KernelError::ObjectNotFound)));
    }

    #[test]
    fn schedule_resolves_unique_intent_and_kind() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("worker", "t1"));
        assert!(k.schedule_by_id("t1").is_ok());
        assert!(k.schedule_by_id("worker").is_ok());
        assert!(k.schedule_by_id(cap.object_id.as_str()).is_ok());
    }

    #[test]
    fn schedule_ambiguous_intent_returns_error() {
        let mut k = Kernel::new();
        k.register_object(make_obj("a", "shared"));
        k.register_object(make_obj("b", "shared"));
        assert!(matches!(
            k.schedule_by_id("shared"),
            Err(KernelError::ObjectAmbiguous)
        ));
    }

    #[test]
    fn for_each_object_visits_all_objects() {
        let mut k = Kernel::new();
        k.register_object(make_obj("a", "normal"));
        k.register_object(make_obj("b", "batch"));
        let mut count = 0usize;
        k.for_each_object(|_| count += 1);
        assert_eq!(count, 2);
    }

    #[test]
    fn validate_capability_succeeds_for_registered_object() {
        let mut k = Kernel::new();
        let cap = k.register_object(make_obj("v", "normal"));
        assert!(k.validate_capability(&cap).is_ok());
    }

    #[test]
    fn validate_capability_fails_for_unknown_object() {
        let k = Kernel::new();
        let obj = make_obj("ghost", "normal");
        let mut cap = Capability::new(&obj);
        cap.issue().unwrap();
        assert!(matches!(
            k.validate_capability(&cap),
            Err(KernelError::InvalidCapability)
        ));
    }

    #[test]
    fn network_send_and_receive_with_capability_permissions() {
        let mut k = Kernel::new();
        let obj = make_obj("net-service", "interactive");
        let mut cap = signed_perms(
            &obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        let _ = k.register_object(obj);

        let mut net = NetworkStack::new();
        net.add_loopback_interface("lo").unwrap();
        k.network_send(&cap, &mut net, "lo", b"hello").unwrap();
        net.service();
        let pkt = k.network_receive(&cap, &mut net, "lo").unwrap().unwrap();
        assert_eq!(pkt.payload.as_slice(), b"hello");

        cap.remove_permission(&Permission::ReceiveMessage);
        // Mutation clears the signature — re-sign so permission denial is tested.
        cap.issue().unwrap();
        let denied = k.network_receive(&cap, &mut net, "lo");
        assert!(matches!(denied, Err(KernelError::PermissionDenied)));

        let stats = k.network_stats_for(cap.object_id.as_str()).unwrap();
        assert_eq!(stats.send_ok, 1);
        assert_eq!(stats.send_err, 0);
        assert_eq!(stats.recv_ok, 1);
        assert_eq!(stats.recv_err, 1);
    }

    #[test]
    fn network_receive_empty_updates_telemetry() {
        let mut k = Kernel::new();
        let obj = make_obj("net-empty", "interactive");
        let cap = signed_perms(
            &obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        let _ = k.register_object(obj);
        let mut net = NetworkStack::new();
        net.add_loopback_interface("lo").unwrap();
        let got = k.network_receive(&cap, &mut net, "lo").unwrap();
        assert!(got.is_none());
        let stats = k.network_stats_for(cap.object_id.as_str()).unwrap();
        assert_eq!(stats.recv_empty, 1);
    }

    #[test]
    fn bridge_network_to_object_delivers_data_message() {
        let mut k = Kernel::new();
        let net_obj = make_obj("net-service", "interactive");
        let net_cap = signed_perms(
            &net_obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        let _ = k.register_object(net_obj);

        let inbox_obj = make_obj("inbox", "normal");
        let inbox_cap = k.register_object(inbox_obj);
        let inbox_id = inbox_cap.object_id.as_str().to_owned();

        let mut net = NetworkStack::new();
        net.add_loopback_interface("lo").unwrap();
        k.network_send(&net_cap, &mut net, "lo", b"abc").unwrap();
        net.service();
        let moved = k
            .bridge_network_to_object(&net_cap, &mut net, "lo", &inbox_id)
            .unwrap();
        assert!(moved);

        let msg = k.receive_message_direct(&inbox_id).unwrap().unwrap();
        match msg.payload {
            MessagePayload::Data(bytes) => assert_eq!(bytes.as_slice(), b"abc"),
            _ => panic!("expected Data payload"),
        }
    }

    #[test]
    fn bridge_requires_send_and_receive_permissions() {
        let mut k = Kernel::new();
        let net_obj = make_obj("net-service", "interactive");
        // Receive-only: enough to poll the network, not to inject into objects.
        let recv_only = signed_perms(&net_obj, &[Permission::ReceiveMessage]);
        let send_only = signed_perms(&net_obj, &[Permission::SendMessage]);
        let full = signed_perms(
            &net_obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        let _ = k.register_object(net_obj);

        let inbox_cap = k.register_object(make_obj("inbox", "normal"));
        let inbox_id = inbox_cap.object_id.as_str().to_owned();

        let mut net = NetworkStack::new();
        net.add_loopback_interface("lo").unwrap();
        k.network_send(&full, &mut net, "lo", b"abc").unwrap();
        net.service();

        // Ingress with a receive-only cap must not deliver into the object.
        let denied = k.bridge_network_to_object(&recv_only, &mut net, "lo", &inbox_id);
        assert!(matches!(denied, Err(KernelError::PermissionDenied)));
        assert!(k.receive_message_direct(&inbox_id).unwrap().is_none());

        // Egress with a send-only cap must not drain the source object.
        let msg = Message::text("src", &inbox_id, "out").unwrap();
        k.send_message_direct(&inbox_id, msg).unwrap();
        let denied = k.bridge_object_to_network(&send_only, &mut net, &inbox_id, "lo");
        assert!(matches!(denied, Err(KernelError::PermissionDenied)));
        assert!(k.receive_message_direct(&inbox_id).unwrap().is_some());
    }

    #[test]
    fn bridge_object_to_network_sends_text_payload() {
        let mut k = Kernel::new();
        let net_obj = make_obj("net-service", "interactive");
        let net_cap = signed_perms(
            &net_obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        let _ = k.register_object(net_obj);

        let worker_obj = make_obj("worker", "normal");
        let worker_cap = k.register_object(worker_obj);
        let worker_id = worker_cap.object_id.as_str().to_owned();
        let outbound = Message::text("src", &worker_id, "payload").unwrap();
        k.send_message_direct(&worker_id, outbound).unwrap();

        let mut net = NetworkStack::new();
        net.add_loopback_interface("lo").unwrap();
        let moved = k
            .bridge_object_to_network(&net_cap, &mut net, &worker_id, "lo")
            .unwrap();
        assert!(moved);

        net.service();
        let pkt = k
            .network_receive(&net_cap, &mut net, "lo")
            .unwrap()
            .unwrap();
        assert_eq!(pkt.payload.as_slice(), b"payload");
    }

    #[test]
    fn bridge_tick_moves_bound_ingress_and_egress() {
        let mut k = Kernel::new();
        let net_obj = make_obj("net-service", "interactive");
        let net_cap = signed_perms(
            &net_obj,
            &[Permission::SendMessage, Permission::ReceiveMessage],
        );
        let _ = k.register_object(net_obj);

        let inbox = make_obj("inbox", "normal");
        let inbox_cap = k.register_object(inbox);
        let inbox_id = inbox_cap.object_id.as_str().to_owned();

        let outbox = make_obj("outbox", "normal");
        let outbox_cap = k.register_object(outbox);
        let outbox_id = outbox_cap.object_id.as_str().to_owned();

        k.bridge_bind_ingress("lo", &inbox_id).unwrap();
        k.bridge_bind_egress(&outbox_id, "lo").unwrap();

        let mut net = NetworkStack::new();
        net.add_loopback_interface("lo").unwrap();
        k.network_send(&net_cap, &mut net, "lo", b"from-net")
            .unwrap();

        let outbound = Message::text("src", &outbox_id, "from-obj").unwrap();
        k.send_message_direct(&outbox_id, outbound).unwrap();

        let tick = k.bridge_tick(&net_cap, &mut net).unwrap();
        assert_eq!(tick.ingress_moved, 1);
        assert_eq!(tick.egress_moved, 1);

        let inbox_msg = k.receive_message_direct(&inbox_id).unwrap().unwrap();
        match inbox_msg.payload {
            MessagePayload::Data(bytes) => assert_eq!(bytes.as_slice(), b"from-net"),
            _ => panic!("expected Data payload"),
        }

        let pkt = k
            .network_receive(&net_cap, &mut net, "lo")
            .unwrap()
            .unwrap();
        assert_eq!(pkt.payload.as_slice(), b"from-obj");
    }

    #[test]
    fn register_core_and_collect_multicore_summary() {
        let mut k = Kernel::new();
        k.register_core(0, CoreRole::Bootstrap).unwrap();
        k.register_core(1, CoreRole::Application).unwrap();
        let summary = k.multicore_summary();
        assert_eq!(summary.known_cores, 2);
        assert_eq!(summary.online_cores, 1);
        assert_eq!(summary.bsp_apic_id, Some(0));
    }

    #[test]
    fn preempt_tick_on_core_updates_tick_telemetry() {
        let mut k = Kernel::new();
        k.register_core(0, CoreRole::Bootstrap).unwrap();
        let _ = k.preempt_tick_on_core(1, 0);
        let summary = k.multicore_summary();
        assert_eq!(summary.total_ticks_seen, 1);
    }

    #[test]
    fn application_core_startup_lifecycle_transitions() {
        let mut k = Kernel::new();
        k.register_core(1, CoreRole::Application).unwrap();
        let plan = k.plan_ap_startup(1).unwrap();
        assert_eq!(plan.apic_id, 1);
        assert_eq!(k.multicore_summary().booting_cores, 1);
        k.complete_ap_startup(1).unwrap();
        assert_eq!(k.multicore_summary().online_cores, 1);
        k.halt_core(1).unwrap();
        assert_eq!(k.multicore_summary().online_cores, 0);
    }

    #[test]
    fn startup_mailbox_tracks_pending_and_ack() {
        let mut k = Kernel::new();
        k.register_core(1, CoreRole::Application).unwrap();
        k.plan_ap_startup(1).unwrap();
        assert_eq!(k.startup_mailbox().pending_apic_id, Some(1));
        k.complete_ap_startup(1).unwrap();
        let mb = k.startup_mailbox();
        assert_eq!(mb.pending_apic_id, None);
        assert_eq!(mb.last_acked_apic_id, Some(1));
    }

    #[test]
    fn ap_entry_hook_requires_matching_sequence() {
        let mut k = Kernel::new();
        k.register_core(1, CoreRole::Application).unwrap();
        let plan = k.plan_ap_startup(1).unwrap();
        let wrong = k.ap_trampoline_entry_hook(1, plan.startup_seq + 1);
        assert!(matches!(wrong, Err(KernelError::StartupSequenceMismatch)));
        k.ap_trampoline_entry_hook(1, plan.startup_seq).unwrap();
    }

    #[test]
    fn dispatch_queue_split_tracks_core_runqueue_depth() {
        let mut k = Kernel::new();
        k.register_core(0, CoreRole::Bootstrap).unwrap();
        k.register_core(1, CoreRole::Application).unwrap();
        k.plan_ap_startup(1).unwrap();
        k.complete_ap_startup(1).unwrap();

        let cap_a = k.register_object(make_obj("a", "normal"));
        let cap_b = k.register_object(make_obj("b", "normal"));
        k.execute(&cap_a).unwrap();
        k.execute(&cap_b).unwrap();
        assert_eq!(k.multicore_summary().total_run_queue_depth, 2);

        let _ = k.execute_next();
        assert_eq!(k.multicore_summary().total_run_queue_depth, 1);
    }

    #[test]
    fn execute_next_on_core_runs_local_assigned_tasks_independently() {
        let mut k = Kernel::new();
        k.register_core(0, CoreRole::Bootstrap).unwrap();
        k.register_core(1, CoreRole::Application).unwrap();
        let plan = k.plan_ap_startup(1).unwrap();
        k.ap_trampoline_entry_hook(1, plan.startup_seq).unwrap();

        let cap_a = k.register_object(make_obj("a", "normal"));
        let cap_b = k.register_object(make_obj("b", "normal"));
        k.execute(&cap_a).unwrap();
        k.execute(&cap_b).unwrap();

        // Phase 19/20: each core dispatches into its own running slot;
        // both can be occupied at once.
        assert!(k.execute_next_on_core(1).is_some());
        assert!(k.execute_next_on_core(0).is_some());
        assert_eq!(k.scheduler_running_count(), 2);
        assert_eq!(k.scheduler_running_mask() & 0b11, 0b11);
        k.complete_running_on_core(1);
        k.complete_running_on_core(0);
        assert_eq!(k.scheduler_running_count(), 0);
    }

    #[test]
    fn service_core_runtime_step_runs_and_completes_assigned_work() {
        let mut k = Kernel::new();
        k.register_core(0, CoreRole::Bootstrap).unwrap();
        k.register_core(1, CoreRole::Application).unwrap();
        let plan = k.plan_ap_startup(1).unwrap();
        k.ap_trampoline_entry_hook(1, plan.startup_seq).unwrap();

        let cap_a = k.register_object(make_obj("a", "normal"));
        let cap_b = k.register_object(make_obj("b", "normal"));
        k.execute(&cap_a).unwrap();
        k.execute(&cap_b).unwrap();

        // Core 1 can run its local assignment independently (M4 contexts stay live).
        assert!(k.service_core_runtime_step(1).is_some());
        assert_eq!(k.runtime_tick_cursor(1), 1);
        assert!(k.scheduler_running_count() >= 1);
        // Core 0 may still dispatch its assignment while core 1 holds a slot.
        assert!(k.service_core_runtime_step(0).is_some());
        assert_eq!(k.runtime_tick_cursor(0), 1);
        k.complete_running_on_core(0);
        k.complete_running_on_core(1);
        assert_eq!(k.scheduler_queue_size(), 0);
    }

    #[test]
    fn idle_core_steals_work_from_busy_core() {
        let mut k = Kernel::new();
        k.register_core(0, CoreRole::Bootstrap).unwrap();
        k.register_core(1, CoreRole::Application).unwrap();
        let plan = k.plan_ap_startup(1).unwrap();
        k.ap_trampoline_entry_hook(1, plan.startup_seq).unwrap();

        // Pin both tasks onto core 0 by halting AP while queueing.
        k.halt_core(1).unwrap();
        let cap_a = k.register_object(make_obj("a", "normal"));
        let cap_b = k.register_object(make_obj("b", "normal"));
        k.execute(&cap_a).unwrap();
        k.execute(&cap_b).unwrap();
        assert_eq!(k.multicore_summary().total_run_queue_depth, 2);

        // Bring AP back online with an empty RQ — it should steal.
        k.set_core_online(1, true).unwrap();
        assert!(k.execute_next_on_core(1).is_some());
        assert!(k.multicore_summary().total_steals >= 1);
        k.complete_running_on_core(1);
    }

    #[test]
    fn local_apic_tick_only_runs_when_local_drive_mode_active() {
        let mut k = Kernel::new();
        k.register_core(0, CoreRole::Bootstrap).unwrap();
        k.register_core(1, CoreRole::Application).unwrap();
        let plan = k.plan_ap_startup(1).unwrap();
        k.ap_trampoline_entry_hook(1, plan.startup_seq).unwrap();

        let cap_a = k.register_object(make_obj("a", "normal"));
        let cap_b = k.register_object(make_obj("b", "normal"));
        k.execute(&cap_a).unwrap();
        k.execute(&cap_b).unwrap();

        assert!(k.on_local_apic_timer_tick(1).is_none());
        assert!(k.service_core_runtime_step_if_bsp_proxy(0).is_some());
        k.complete_running_on_core(0);
        k.activate_ap_local_timer(1);
        assert!(matches!(
            k.runtime_drive_mode(1),
            RuntimeDriveMode::LocalApic
        ));
        assert!(k.on_local_apic_timer_tick(1).is_some());
        k.complete_running_on_core(1);
        assert_eq!(k.scheduler_queue_size(), 0);
    }

    #[test]
    fn ap_timer_calibration_inherits_bsp_rate() {
        let mut k = Kernel::new();
        let bsp = LocalApicTimerConfig::periodic_from_count(123_456);
        k.set_timer_calibration(0, bsp);
        let ap = k.ensure_ap_timer_calibration(1);
        assert_eq!(ap.initial_count, 123_456);
        assert_eq!(k.timer_calibration(1).unwrap().initial_count, 123_456);
        // Second call keeps the per-AP entry.
        assert_eq!(k.ensure_ap_timer_calibration(1).initial_count, 123_456);
    }

    #[test]
    fn ap_timer_calibration_falls_back_to_default_without_bsp() {
        let mut k = Kernel::new();
        let ap = k.ensure_ap_timer_calibration(2);
        assert_eq!(
            ap.initial_count,
            LocalApicTimerConfig::ap_runtime_default().initial_count
        );
        assert!(k.timer_calibration(2).is_some());
    }

    #[test]
    fn queue_to_local_apic_core_sets_reschedule_pending() {
        let mut k = Kernel::new();
        k.register_core(0, CoreRole::Bootstrap).unwrap();
        k.register_core(1, CoreRole::Application).unwrap();
        let plan = k.plan_ap_startup(1).unwrap();
        k.ap_trampoline_entry_hook(1, plan.startup_seq).unwrap();
        k.activate_ap_local_timer(1);
        k.halt_core(0).unwrap(); // force dispatch onto AP 1
        let _ = crate::multicore::take_reschedule(1);

        let cap = k.register_object(make_obj("w", "normal"));
        k.execute(&cap).unwrap();
        assert!(crate::multicore::reschedule_pending(1));
        assert!(k.on_reschedule_ipi(1).is_some());
        assert!(!crate::multicore::reschedule_pending(1));
    }

    #[test]
    fn broadcast_tlb_shootdown_marks_online_aps() {
        let mut k = Kernel::new();
        k.register_core(0, CoreRole::Bootstrap).unwrap();
        k.register_core(1, CoreRole::Application).unwrap();
        k.set_core_online(1, true).unwrap();
        let _ = crate::multicore::take_tlb_shootdown(1);

        let sent = k.broadcast_tlb_shootdown(0x4000, 0);
        assert_eq!(sent, 1);
        assert!(crate::multicore::tlb_shootdown_pending(1));
        assert_eq!(crate::multicore::tlb_shootdown_page(), 0x4000);
        assert_eq!(k.on_tlb_shootdown_ipi(1), Some(0x4000));
        assert!(!crate::multicore::tlb_shootdown_pending(1));
    }

    #[test]
    fn reschedule_ipi_notes_wake_when_idle() {
        let mut k = Kernel::new();
        k.register_core(0, CoreRole::Bootstrap).unwrap();
        k.register_core(1, CoreRole::Application).unwrap();
        let plan = k.plan_ap_startup(1).unwrap();
        k.ap_trampoline_entry_hook(1, plan.startup_seq).unwrap();
        k.activate_ap_local_timer(1);
        let _ = crate::multicore::idle_leave(1);
        let before = crate::multicore::wake_count(1);
        crate::multicore::idle_enter(1);
        crate::multicore::request_reschedule(1);
        let _ = k.on_reschedule_ipi(1);
        assert_eq!(crate::multicore::wake_count(1), before + 1);
        let _ = crate::multicore::idle_leave(1);
    }
}
