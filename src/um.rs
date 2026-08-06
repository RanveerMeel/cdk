//! Unified memory — shared CPU/GPU guest-physical regions.
//!
//! ## Model
//!
//! A [`UmRegion`] is a **contiguous** physical span allocated from the frame
//! allocator, visible to the CPU via the bootloader phys→virt map, and
//! attachable as virtio-gpu resource backing (same guest phys).
//!
//! Coherency: x86 + QEMU virtio-gpu is typically host-coherent; [`fence`]
//! documents the flush point before GPU reads. IOMMU is stubbed (identity).

use core::sync::atomic::{AtomicU32, Ordering};
use heapless::Vec;
use spin::Mutex;

use crate::allocator::{AllocError, FrameAllocator, PhysFrame, FRAME_SIZE};

pub const MAX_REGIONS: usize = 8;
/// Cap a single region so soft/GPU tests stay bounded (16 MiB).
pub const MAX_REGION_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UmError {
    ZeroSize,
    TooLarge,
    OutOfMemory,
    Full,
    NotFound,
    BadId,
    GpuAttach(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UmRegion {
    pub id: u32,
    pub guest_phys: u64,
    pub cpu_va: u64,
    pub len: usize,
    pub frame_count: usize,
    /// Optional virtio-gpu resource id after attach.
    pub gpu_resource_id: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IommuStatus {
    /// VT-d / IOMMU hardware present (always false in this slice).
    pub present: bool,
    /// Translation mode description.
    pub mode: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UmStatus {
    pub regions: usize,
    pub bytes_total: usize,
    pub next_id: u32,
    pub iommu: IommuStatus,
}

struct UmState {
    regions: Vec<UmRegion, MAX_REGIONS>,
    next_id: u32,
}

impl UmState {
    const fn new() -> Self {
        Self {
            regions: Vec::new(),
            next_id: 1,
        }
    }
}

static UM: Mutex<UmState> = Mutex::new(UmState::new());
static NEXT_GPU_RES: AtomicU32 = AtomicU32::new(100);

fn iommu_stub() -> IommuStatus {
    IommuStatus {
        present: false,
        mode: "identity-stub",
    }
}

/// Round `bytes` up to a whole number of frames (at least one).
pub fn frames_for_bytes(bytes: usize) -> usize {
    if bytes == 0 {
        return 0;
    }
    let fs = FRAME_SIZE as usize;
    (bytes + fs - 1) / fs
}

/// Allocate a contiguous unified-memory region.
pub fn alloc(fa: &mut FrameAllocator, bytes: usize) -> Result<UmRegion, UmError> {
    if bytes == 0 {
        return Err(UmError::ZeroSize);
    }
    if bytes > MAX_REGION_BYTES {
        return Err(UmError::TooLarge);
    }
    let n = frames_for_bytes(bytes);
    let first = fa.alloc_contiguous(n).map_err(|e| match e {
        AllocError::OutOfMemory => UmError::OutOfMemory,
        _ => UmError::OutOfMemory,
    })?;
    let phys = first.base_addr();
    let len = n * FRAME_SIZE as usize;
    let cpu_va = crate::phys_mem::phys_to_virt_addr(phys);

    // Zero for predictable CPU/GPU contents (bare-metal phys map only).
    #[cfg(target_os = "none")]
    unsafe {
        let p = crate::phys_mem::phys_to_mut_ptr::<u8>(phys);
        core::ptr::write_bytes(p, 0, len);
    }

    let mut st = UM.lock();
    if st.regions.is_full() {
        // Roll back frames.
        for i in 0..n {
            let _ = fa.free(PhysFrame(phys + (i as u64) * FRAME_SIZE));
        }
        return Err(UmError::Full);
    }
    let id = st.next_id;
    st.next_id = st.next_id.saturating_add(1);
    let region = UmRegion {
        id,
        guest_phys: phys,
        cpu_va,
        len,
        frame_count: n,
        gpu_resource_id: None,
    };
    let _ = st.regions.push(region);
    Ok(region)
}

/// Free a region by id (returns frames to the allocator).
pub fn free(fa: &mut FrameAllocator, id: u32) -> Result<(), UmError> {
    let mut st = UM.lock();
    let idx = st
        .regions
        .iter()
        .position(|r| r.id == id)
        .ok_or(UmError::NotFound)?;
    let region = st.regions.swap_remove(idx);
    drop(st);
    for i in 0..region.frame_count {
        let _ = fa.free(PhysFrame(
            region.guest_phys + (i as u64) * FRAME_SIZE,
        ));
    }
    Ok(())
}

pub fn get(id: u32) -> Option<UmRegion> {
    UM.lock().regions.iter().copied().find(|r| r.id == id)
}

pub fn for_each(mut f: impl FnMut(&UmRegion)) {
    let st = UM.lock();
    for r in st.regions.iter() {
        f(r);
    }
}

pub fn status() -> UmStatus {
    let st = UM.lock();
    let bytes_total = st.regions.iter().map(|r| r.len).sum();
    UmStatus {
        regions: st.regions.len(),
        bytes_total,
        next_id: st.next_id,
        iommu: iommu_stub(),
    }
}

pub fn iommu_status() -> IommuStatus {
    iommu_stub()
}

/// CPU→device coherency point before the GPU reads a region.
pub fn fence(cpu_va: u64, len: usize) {
    core::sync::atomic::fence(Ordering::SeqCst);
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        // Best-effort clflush of touched lines (no-op if len is 0).
        let start = cpu_va & !0x3f;
        let end = cpu_va.saturating_add(len as u64);
        let mut addr = start;
        while addr < end {
            unsafe {
                core::arch::asm!("clflush [{}]", in(reg) addr, options(nostack, preserves_flags));
            }
            addr = addr.saturating_add(64);
        }
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    {
        let _ = (cpu_va, len);
    }
}

pub fn fence_region(id: u32) -> Result<(), UmError> {
    let r = get(id).ok_or(UmError::NotFound)?;
    fence(r.cpu_va, r.len);
    Ok(())
}

/// Fill a region with a solid BGRA8 pattern (CPU side).
pub fn cpu_fill_bgra(id: u32, b: u8, g: u8, r: u8, a: u8) -> Result<(), UmError> {
    let region = get(id).ok_or(UmError::NotFound)?;
    if region.len < 4 {
        return Ok(());
    }
    #[cfg(target_os = "none")]
    unsafe {
        let p = region.cpu_va as *mut u8;
        let mut off = 0usize;
        while off + 4 <= region.len {
            *p.add(off) = b;
            *p.add(off + 1) = g;
            *p.add(off + 2) = r;
            *p.add(off + 3) = a;
            off += 4;
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (b, g, r, a);
    }
    fence(region.cpu_va, region.len);
    Ok(())
}

/// Attach region as a virtio-gpu 2D resource (when HW ready); records resource id.
pub fn attach_gpu(id: u32, width: u32, height: u32) -> Result<u32, UmError> {
    let region = get(id).ok_or(UmError::NotFound)?;
    let need = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul(4);
    if need == 0 || need > region.len {
        return Err(UmError::TooLarge);
    }
    fence(region.cpu_va, need);
    let res_id = NEXT_GPU_RES.fetch_add(1, Ordering::Relaxed);
    crate::gpu::um_attach_resource(res_id, width, height, region.guest_phys, need as u32)
        .map_err(UmError::GpuAttach)?;
    let mut st = UM.lock();
    if let Some(r) = st.regions.iter_mut().find(|r| r.id == id) {
        r.gpu_resource_id = Some(res_id);
    }
    Ok(res_id)
}

/// End-to-end smoke: alloc → CPU fill → fence → optional GPU attach → report.
pub fn smoke(fa: &mut FrameAllocator) -> Result<UmRegion, UmError> {
    // 64×64 BGRA tile (16 KiB) — small contiguous region.
    let region = alloc(fa, 64 * 64 * 4)?;
    cpu_fill_bgra(region.id, 0x30, 0x90, 0xD0, 0xFF)?;
    match attach_gpu(region.id, 64, 64) {
        Ok(res) => {
            crate::println!(
                "UM: smoke ok id={} phys={:#x} va={:#x} gpu_res={}",
                region.id,
                region.guest_phys,
                region.cpu_va,
                res
            );
        }
        Err(UmError::GpuAttach(e)) => {
            crate::println!(
                "UM: smoke cpu-ok id={} phys={:#x} (gpu attach: {})",
                region.id,
                region.guest_phys,
                e
            );
        }
        Err(e) => {
            let _ = free(fa, region.id);
            return Err(e);
        }
    }
    get(region.id).ok_or(UmError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allocator::FrameAllocator;

    fn fa_with(frames: usize) -> FrameAllocator {
        let mut a = FrameAllocator::new();
        a.init_from_regions(&[(0, frames as u64 * FRAME_SIZE, true)]);
        a
    }

    #[test]
    fn frames_for_bytes_rounds_up() {
        assert_eq!(frames_for_bytes(0), 0);
        assert_eq!(frames_for_bytes(1), 1);
        assert_eq!(frames_for_bytes(4096), 1);
        assert_eq!(frames_for_bytes(4097), 2);
    }

    #[test]
    fn alloc_free_roundtrip() {
        let mut fa = fa_with(64);
        let before = fa.free_frames();
        let r = alloc(&mut fa, 8192).unwrap();
        assert_eq!(r.frame_count, 2);
        assert_eq!(r.guest_phys % FRAME_SIZE, 0);
        assert_eq!(fa.free_frames(), before - 2);
        free(&mut fa, r.id).unwrap();
        assert_eq!(fa.free_frames(), before);
        assert!(get(r.id).is_none());
    }

    #[test]
    fn alloc_rejects_zero_and_huge() {
        let mut fa = fa_with(8);
        assert_eq!(alloc(&mut fa, 0), Err(UmError::ZeroSize));
        assert_eq!(
            alloc(&mut fa, MAX_REGION_BYTES + 1),
            Err(UmError::TooLarge)
        );
    }

    #[test]
    fn status_tracks_bytes() {
        let mut fa = fa_with(32);
        // Drain any leftover regions from earlier tests in this process.
        let leftover: heapless::Vec<u32, MAX_REGIONS> = {
            let mut ids = heapless::Vec::new();
            for_each(|r| {
                let _ = ids.push(r.id);
            });
            ids
        };
        for id in leftover {
            let _ = free(&mut fa, id);
        }
        let r = alloc(&mut fa, 4096).unwrap();
        let s = status();
        assert_eq!(s.regions, 1);
        assert_eq!(s.bytes_total, 4096);
        assert!(!s.iommu.present);
        assert_eq!(s.iommu.mode, "identity-stub");
        free(&mut fa, r.id).unwrap();
    }
}
