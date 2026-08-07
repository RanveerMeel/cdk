/// Local APIC IPI controller and per-core timer programming used by SMP code.
///
/// Phase 13 arms the local APIC timer on each AP so vector
/// [`LOCAL_APIC_TIMER_VECTOR`] is delivered by hardware instead of console
/// `cpu-step-ap` software injection.

/// Vector delivered by the local APIC timer (must match the IDT slot).
pub const LOCAL_APIC_TIMER_VECTOR: u8 = 0xF0;

/// Vector used for cross-core reschedule IPIs (must match the IDT slot).
pub const RESCHEDULE_IPI_VECTOR: u8 = 0xF1;

/// Vector used for TLB shootdown IPIs (must match the IDT slot).
pub const TLB_SHOOTDOWN_IPI_VECTOR: u8 = 0xF2;

/// Default xAPIC MMIO base (Intel legacy mapping).
pub const XAPIC_BASE: u64 = 0xFEE0_0000;

use core::sync::atomic::{AtomicBool, Ordering};

/// True when the BSP enabled x2APIC mode (MSR register file).
static X2APIC_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether the current boot is using x2APIC MSRs instead of MMIO.
pub fn x2apic_enabled() -> bool {
    X2APIC_ENABLED.load(Ordering::Acquire)
}

/// Enable x2APIC when CPUID reports support. Returns true if enabled.
pub fn try_enable_x2apic() -> bool {
    #[cfg(target_os = "none")]
    {
        if !crate::cpu::cpuid_has_x2apic() {
            return false;
        }
        let mut apic_base = crate::cpu::rdmsr(crate::cpu::IA32_APIC_BASE);
        apic_base |= crate::cpu::APIC_BASE_GLOBAL_ENABLE | crate::cpu::APIC_BASE_X2APIC_ENABLE;
        crate::cpu::wrmsr(crate::cpu::IA32_APIC_BASE, apic_base);
        X2APIC_ENABLED.store(true, Ordering::Release);
        return true;
    }
    #[cfg(not(target_os = "none"))]
    {
        false
    }
}

#[cfg(target_os = "none")]
const REG_ID: u64 = 0x20;
#[cfg(target_os = "none")]
const REG_EOI: u64 = 0xB0;
#[cfg(target_os = "none")]
const REG_SVR: u64 = 0xF0;
#[cfg(target_os = "none")]
const REG_LVT_TIMER: u64 = 0x320;
#[cfg(target_os = "none")]
const REG_TIMER_INIT: u64 = 0x380;
#[cfg(target_os = "none")]
const REG_TIMER_CURRENT: u64 = 0x390;
#[cfg(target_os = "none")]
const REG_TIMER_DIVIDE: u64 = 0x3E0;

#[cfg(target_os = "none")]
#[inline]
fn x2apic_msr(offset: u64) -> u32 {
    crate::cpu::X2APIC_MSR_BASE + (offset / 0x10) as u32
}

/// Spurious interrupt vector used while enabling the APIC (must be ≥ 0x10).
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const SPURIOUS_VECTOR: u8 = 0xFF;

/// Bit 8 of SVR software-enables the local APIC.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const SVR_APIC_ENABLE: u32 = 1 << 8;

/// LVT timer mode: periodic.
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
/// LVT mask bit.
const LVT_MASKED: u32 = 1 << 16;

/// Default divide value for AP runtime ticks (bus clock / 16).
pub const DEFAULT_TIMER_DIVIDE: TimerDivide = TimerDivide::By16;

/// Default initial-count seed for periodic AP runtime ticks.
///
/// Absolute Hz depends on the platform bus/APIC timer clock; this is a
/// conservative starting point that produces regular interrupts on QEMU
/// without drowning the serial console. Prefer [`calibrate_periodic_timer`].
pub const DEFAULT_TIMER_INITIAL_COUNT: u32 = 20_000_000;

/// Target AP runtime timer rate after calibration (~matches a gentle tick).
pub const TARGET_RUNTIME_TIMER_HZ: u32 = 20;

/// Approximate PIT IRQ0 rate when the PIT is left at its power-on divisor.
pub const PIT_APPROX_HZ: u32 = 18;

/// How many PIT ticks to observe while measuring LAPIC countdown.
pub const CALIBRATION_PIT_TICKS: u32 = 2;

/// Max oneshot count used while measuring bus/APIC timer rate.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const CALIBRATION_ONESHOT_COUNT: u32 = 0xFFFF_FFFF;

/// ICR Delivery Status bit (set while the local APIC is sending an IPI).
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const ICR_DELIVERY_PENDING: u32 = 1 << 12;

pub trait ApicIpiController {
    fn send_init_ipi(&mut self, apic_id: u32) -> bool;
    fn send_startup_ipi(&mut self, apic_id: u32, vector: u8) -> bool;

    /// Fixed-delivery IPI to `apic_id` with the given vector (edge-triggered).
    fn send_fixed_ipi(&mut self, apic_id: u32, vector: u8) -> bool {
        let _ = (apic_id, vector);
        false
    }

    fn bringup_ap(&mut self, apic_id: u32, vector: u8) -> bool {
        if !self.send_init_ipi(apic_id) {
            return false;
        }
        if !self.send_startup_ipi(apic_id, vector) {
            return false;
        }
        // Intel SMP startup recommends a second SIPI shortly after the first.
        self.send_startup_ipi(apic_id, vector)
    }
}

/// Divide-configuration encodings for the local APIC timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimerDivide {
    By2 = 0b0000,
    By4 = 0b0001,
    By8 = 0b0010,
    By16 = 0b0011,
    By32 = 0b1000,
    By64 = 0b1001,
    By128 = 0b1010,
    By1 = 0b1011,
}

impl TimerDivide {
    pub const fn dcr_value(self) -> u32 {
        self as u32
    }
}

/// Configuration for programming the current core's local APIC timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalApicTimerConfig {
    pub vector: u8,
    pub divide: TimerDivide,
    pub initial_count: u32,
    pub periodic: bool,
}

impl LocalApicTimerConfig {
    /// Runtime defaults used when an AP enters local-APIC drive mode.
    pub const fn ap_runtime_default() -> Self {
        Self {
            vector: LOCAL_APIC_TIMER_VECTOR,
            divide: DEFAULT_TIMER_DIVIDE,
            initial_count: DEFAULT_TIMER_INITIAL_COUNT,
            periodic: true,
        }
    }

    /// Build a periodic config from a calibrated initial-count.
    pub const fn periodic_from_count(initial_count: u32) -> Self {
        Self {
            vector: LOCAL_APIC_TIMER_VECTOR,
            divide: DEFAULT_TIMER_DIVIDE,
            initial_count,
            periodic: true,
        }
    }

    /// Pack the LVT Timer register value for this config (unmasked).
    pub const fn lvt_value(self) -> u32 {
        let mut value = self.vector as u32;
        if self.periodic {
            value |= LVT_TIMER_PERIODIC;
        }
        value
    }
}

/// Convert a measured oneshot countdown into a periodic initial-count for `target_hz`.
pub fn initial_count_from_calibration(
    counts_consumed: u32,
    pit_ticks_observed: u32,
    target_hz: u32,
) -> Option<u32> {
    if counts_consumed == 0 || pit_ticks_observed == 0 || target_hz == 0 {
        return None;
    }
    let counts_per_sec = (counts_consumed as u64)
        .saturating_mul(PIT_APPROX_HZ as u64)
        / pit_ticks_observed as u64;
    let initial = counts_per_sec / target_hz as u64;
    if initial == 0 || initial > u32::MAX as u64 {
        None
    } else {
        Some(initial as u32)
    }
}

/// Busy-wait helper used between INIT/SIPI (approx. scale, not wall-timed).
pub fn spin_delay(iterations: u32) {
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}

pub struct XApicController {
    base: u64,
}

impl XApicController {
    pub const fn new() -> Self {
        Self { base: XAPIC_BASE }
    }

    pub const fn with_base(base: u64) -> Self {
        Self { base }
    }

    #[inline]
    #[cfg(target_os = "none")]
    fn reg_ptr(&self, offset: u64) -> *mut u32 {
        (self.base + offset) as *mut u32
    }

    #[cfg(target_os = "none")]
    unsafe fn write(&self, offset: u64, value: u32) {
        if x2apic_enabled() {
            crate::cpu::wrmsr(x2apic_msr(offset), value as u64);
        } else {
            core::ptr::write_volatile(self.reg_ptr(offset), value);
        }
    }

    #[cfg(target_os = "none")]
    unsafe fn read(&self, offset: u64) -> u32 {
        if x2apic_enabled() {
            crate::cpu::rdmsr(x2apic_msr(offset)) as u32
        } else {
            core::ptr::read_volatile(self.reg_ptr(offset))
        }
    }

    #[cfg(target_os = "none")]
    unsafe fn write_icr(&self, dest_apic: u32, low: u32) -> bool {
        if x2apic_enabled() {
            // x2APIC ICR is a single 64-bit MSR: dest in high 32 bits.
            let value = ((dest_apic as u64) << 32) | low as u64;
            crate::cpu::wrmsr(x2apic_msr(0x300), value);
            return true;
        }
        let _ = self.wait_icr_idle();
        self.write(0x310, dest_apic << 24);
        self.write(0x300, low);
        true
    }

    /// Best-effort wait for ICR Delivery Status clear (xAPIC MMIO only).
    pub fn wait_icr_idle(&self) -> bool {
        #[cfg(target_os = "none")]
        unsafe {
            if x2apic_enabled() {
                return true;
            }
            for _ in 0..64u32 {
                if self.read(0x300) & ICR_DELIVERY_PENDING == 0 {
                    return true;
                }
                core::hint::spin_loop();
            }
            return true;
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = self.base;
            true
        }
    }

    /// Read the local APIC ID of the current CPU.
    pub fn local_apic_id(&self) -> u32 {
        #[cfg(target_os = "none")]
        unsafe {
            if x2apic_enabled() {
                // IA32_X2APIC_APICID
                return crate::cpu::rdmsr(0x802) as u32;
            }
            (self.read(REG_ID) >> 24) & 0xff
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = self.base;
            0
        }
    }

    /// Software-enable the local APIC via the Spurious Interrupt Vector Register.
    pub fn enable_software(&self) -> bool {
        #[cfg(target_os = "none")]
        unsafe {
            let svr = (SPURIOUS_VECTOR as u32) | SVR_APIC_ENABLE;
            self.write(REG_SVR, svr);
            return true;
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = self.base;
            true
        }
    }

    /// Program and start the local APIC timer on the current CPU.
    pub fn program_timer(&self, config: LocalApicTimerConfig) -> bool {
        if config.initial_count == 0 {
            return false;
        }
        #[cfg(target_os = "none")]
        unsafe {
            // Mask while reprogramming, then unmask with the final LVT value.
            self.write(REG_LVT_TIMER, LVT_MASKED | config.vector as u32);
            self.write(REG_TIMER_DIVIDE, config.divide.dcr_value());
            self.write(REG_TIMER_INIT, config.initial_count);
            self.write(REG_LVT_TIMER, config.lvt_value());
            return true;
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (self.base, config);
            true
        }
    }

    /// Mask the local APIC timer (stops delivery; count may continue).
    pub fn mask_timer(&self) {
        #[cfg(target_os = "none")]
        unsafe {
            let current = self.read(REG_LVT_TIMER);
            self.write(REG_LVT_TIMER, current | LVT_MASKED);
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = self.base;
        }
    }

    /// Stop the timer by masking and clearing the initial count.
    pub fn stop_timer(&self) {
        #[cfg(target_os = "none")]
        unsafe {
            self.write(REG_LVT_TIMER, LVT_MASKED | LOCAL_APIC_TIMER_VECTOR as u32);
            self.write(REG_TIMER_INIT, 0);
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = self.base;
        }
    }

    /// Read the current countdown value (0 when idle/unsupported on host).
    pub fn timer_current_count(&self) -> u32 {
        #[cfg(target_os = "none")]
        unsafe {
            self.read(REG_TIMER_CURRENT)
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = self.base;
            0
        }
    }

    /// Enable the APIC and arm the default periodic AP runtime timer.
    pub fn arm_ap_runtime_timer(&self) -> bool {
        self.arm_ap_runtime_timer_with(LocalApicTimerConfig::ap_runtime_default())
    }

    /// Enable the APIC and arm a specific periodic timer config.
    pub fn arm_ap_runtime_timer_with(&self, config: LocalApicTimerConfig) -> bool {
        if !self.enable_software() {
            return false;
        }
        self.program_timer(config)
    }

    /// Measure LAPIC countdown over `pit_ticks` PIT IRQs and build a periodic config.
    ///
    /// `ticks_fn` should return the BSP PIT tick counter (e.g. `interrupts::ticks`).
    pub fn calibrate_periodic_timer<F>(&self, target_hz: u32, ticks_fn: F) -> LocalApicTimerConfig
    where
        F: Fn() -> u64,
    {
        let fallback = LocalApicTimerConfig::ap_runtime_default();
        if target_hz == 0 {
            return fallback;
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (&ticks_fn, self.base);
            return LocalApicTimerConfig::periodic_from_count(
                initial_count_from_calibration(
                    DEFAULT_TIMER_INITIAL_COUNT,
                    CALIBRATION_PIT_TICKS,
                    target_hz,
                )
                .unwrap_or(DEFAULT_TIMER_INITIAL_COUNT),
            );
        }
        #[cfg(target_os = "none")]
        {
            if !self.enable_software() {
                return fallback;
            }
            // Masked oneshot: consume counts without delivering vector 0xF0.
            unsafe {
                self.write(
                    REG_LVT_TIMER,
                    LVT_MASKED | LOCAL_APIC_TIMER_VECTOR as u32,
                );
                self.write(REG_TIMER_DIVIDE, DEFAULT_TIMER_DIVIDE.dcr_value());
                self.write(REG_TIMER_INIT, CALIBRATION_ONESHOT_COUNT);
            }
            let start_tick = ticks_fn();
            while ticks_fn().saturating_sub(start_tick) < CALIBRATION_PIT_TICKS as u64 {
                core::hint::spin_loop();
            }
            let remaining = self.timer_current_count();
            let consumed = CALIBRATION_ONESHOT_COUNT.saturating_sub(remaining);
            match initial_count_from_calibration(consumed, CALIBRATION_PIT_TICKS, target_hz) {
                Some(count) => LocalApicTimerConfig::periodic_from_count(count),
                None => fallback,
            }
        }
    }

    /// Write EOI to the local APIC.
    pub fn eoi(&self) {
        #[cfg(target_os = "none")]
        unsafe {
            self.write(REG_EOI, 0);
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = self.base;
        }
    }
}

/// Arm the current CPU's local APIC timer for AP runtime vector delivery.
pub fn arm_current_core_runtime_timer() -> bool {
    XApicController::new().arm_ap_runtime_timer()
}

/// Arm the current CPU's local APIC timer with an explicit config.
pub fn arm_current_core_runtime_timer_with(config: LocalApicTimerConfig) -> bool {
    XApicController::new().arm_ap_runtime_timer_with(config)
}

/// Stop the current CPU's local APIC timer.
pub fn stop_current_core_runtime_timer() {
    XApicController::new().stop_timer();
}

/// Send a reschedule Fixed IPI to `apic_id` (vector [`RESCHEDULE_IPI_VECTOR`]).
pub fn send_reschedule_ipi(apic_id: u32) -> bool {
    let mut apic = XApicController::new();
    apic.send_fixed_ipi(apic_id, RESCHEDULE_IPI_VECTOR)
}

/// Send a TLB shootdown Fixed IPI to `apic_id` (vector [`TLB_SHOOTDOWN_IPI_VECTOR`]).
pub fn send_tlb_shootdown_ipi(apic_id: u32) -> bool {
    let mut apic = XApicController::new();
    apic.send_fixed_ipi(apic_id, TLB_SHOOTDOWN_IPI_VECTOR)
}

/// Calibrate the current CPU's local APIC timer against the PIT tick counter.
pub fn calibrate_current_core_runtime_timer<F>(target_hz: u32, ticks_fn: F) -> LocalApicTimerConfig
where
    F: Fn() -> u64,
{
    XApicController::new().calibrate_periodic_timer(target_hz, ticks_fn)
}

impl ApicIpiController for XApicController {
    fn send_init_ipi(&mut self, apic_id: u32) -> bool {
        #[cfg(target_os = "none")]
        unsafe {
            // Edge-triggered INIT (DM=101).
            let low = 0b101u32 << 8;
            return self.write_icr(apic_id, low);
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (apic_id, self.base);
            false
        }
    }

    fn send_startup_ipi(&mut self, apic_id: u32, vector: u8) -> bool {
        #[cfg(target_os = "none")]
        unsafe {
            let low = (0b110u32 << 8) | vector as u32;
            return self.write_icr(apic_id, low);
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (apic_id, vector, self.base);
            false
        }
    }

    fn send_fixed_ipi(&mut self, apic_id: u32, vector: u8) -> bool {
        #[cfg(target_os = "none")]
        unsafe {
            let low = vector as u32;
            return self.write_icr(apic_id, low);
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (apic_id, vector, self.base);
            true
        }
    }

    fn bringup_ap(&mut self, apic_id: u32, vector: u8) -> bool {
        // Ensure software-enable before ICR traffic.
        let _ = self.enable_software();
        crate::println!("SMP: INIT IPI → apic_id={}", apic_id);
        if !self.send_init_ipi(apic_id) {
            crate::println!("SMP: WARNING — INIT IPI failed (ICR busy/timeout)");
            return false;
        }
        // ~10ms INIT settle (spin scale; not wall-clock precise).
        spin_delay(2_000_000);
        crate::println!("SMP: SIPI #1 → apic_id={} vector={:#x}", apic_id, vector);
        if !self.send_startup_ipi(apic_id, vector) {
            crate::println!("SMP: WARNING — SIPI #1 failed (ICR busy/timeout)");
            return false;
        }
        // Give the AP time to enter the trampoline before the second SIPI.
        spin_delay(200_000);
        let st = crate::multicore::MultiCoreManager::read_trampoline_status_global();
        crate::println!("SMP: after SIPI #1 tramp_status={}", st);
        crate::println!("SMP: SIPI #2 → apic_id={} vector={:#x}", apic_id, vector);
        if !self.send_startup_ipi(apic_id, vector) {
            crate::println!("SMP: WARNING — SIPI #2 failed (ICR busy/timeout)");
            return false;
        }
        spin_delay(200_000);
        let st = crate::multicore::MultiCoreManager::read_trampoline_status_global();
        crate::println!("SMP: after SIPI #2 tramp_status={}", st);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockApic {
        init_ok: bool,
        sipi_ok: bool,
        init_calls: u32,
        sipi_calls: u32,
    }

    impl MockApic {
        fn new(init_ok: bool, sipi_ok: bool) -> Self {
            Self {
                init_ok,
                sipi_ok,
                init_calls: 0,
                sipi_calls: 0,
            }
        }
    }

    impl ApicIpiController for MockApic {
        fn send_init_ipi(&mut self, _apic_id: u32) -> bool {
            self.init_calls += 1;
            self.init_ok
        }

        fn send_startup_ipi(&mut self, _apic_id: u32, _vector: u8) -> bool {
            self.sipi_calls += 1;
            self.sipi_ok
        }
    }

    #[test]
    fn bringup_ap_sends_init_and_two_sipis() {
        let mut apic = MockApic::new(true, true);
        assert!(apic.bringup_ap(1, 0x08));
        assert_eq!(apic.init_calls, 1);
        assert_eq!(apic.sipi_calls, 2);
    }

    #[test]
    fn timer_divide_encodings_match_intel_dcr() {
        assert_eq!(TimerDivide::By1.dcr_value(), 0b1011);
        assert_eq!(TimerDivide::By2.dcr_value(), 0b0000);
        assert_eq!(TimerDivide::By16.dcr_value(), 0b0011);
        assert_eq!(TimerDivide::By128.dcr_value(), 0b1010);
    }

    #[test]
    fn ap_runtime_timer_config_targets_timer_vector() {
        let cfg = LocalApicTimerConfig::ap_runtime_default();
        assert_eq!(cfg.vector, LOCAL_APIC_TIMER_VECTOR);
        assert!(cfg.periodic);
        assert_eq!(cfg.divide, TimerDivide::By16);
        assert_ne!(cfg.initial_count, 0);
        let lvt = cfg.lvt_value();
        assert_eq!(lvt & 0xff, LOCAL_APIC_TIMER_VECTOR as u32);
        assert_ne!(lvt & LVT_TIMER_PERIODIC, 0);
        assert_eq!(lvt & LVT_MASKED, 0);
    }

    #[test]
    fn oneshot_lvt_omits_periodic_bit() {
        let cfg = LocalApicTimerConfig {
            vector: 0xF0,
            divide: TimerDivide::By1,
            initial_count: 1000,
            periodic: false,
        };
        assert_eq!(cfg.lvt_value(), 0xF0);
    }

    #[test]
    fn program_timer_rejects_zero_count() {
        let apic = XApicController::new();
        let cfg = LocalApicTimerConfig {
            vector: 0xF0,
            divide: TimerDivide::By16,
            initial_count: 0,
            periodic: true,
        };
        assert!(!apic.program_timer(cfg));
    }

    #[test]
    fn arm_ap_runtime_timer_succeeds_on_host_stub() {
        assert!(arm_current_core_runtime_timer());
    }

    #[test]
    fn calibration_math_scales_with_target_hz() {
        let for_20hz =
            initial_count_from_calibration(1_800_000, CALIBRATION_PIT_TICKS, 20).unwrap();
        let for_10hz =
            initial_count_from_calibration(1_800_000, CALIBRATION_PIT_TICKS, 10).unwrap();
        assert!(for_10hz > for_20hz);
        assert_eq!(
            initial_count_from_calibration(0, 2, 20),
            None
        );
    }

    #[test]
    fn host_calibrate_returns_periodic_config() {
        let cfg = calibrate_current_core_runtime_timer(TARGET_RUNTIME_TIMER_HZ, || 0);
        assert!(cfg.periodic);
        assert_eq!(cfg.vector, LOCAL_APIC_TIMER_VECTOR);
        assert_ne!(cfg.initial_count, 0);
    }
}
