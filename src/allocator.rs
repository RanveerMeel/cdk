//! Physical frame allocator.
//!
//! Uses a fixed-size bitmap where each bit represents one 4 KiB page frame.
//! `0` = free, `1` = used.
//!
//! The allocator is initialised from the bootloader's memory map
//! (`BootInfo::memory_regions`).  Only regions marked `Usable` are made
//! available; everything else (firmware, MMIO, the kernel image itself, …)
//! starts as reserved.
//!
//! Capacity: `MAX_FRAMES` frames × 4 KiB = 512 MiB of addressable physical
//! memory.  Increase `MAX_FRAMES` if you need more.

/// Size of a physical page frame in bytes.
pub const FRAME_SIZE: u64 = 4096;

/// Maximum number of frames tracked by the bitmap (128 Ki frames = 512 MiB).
const MAX_FRAMES: usize = 128 * 1024; // 128 Ki frames

/// Number of `u64` words needed to store the bitmap.
const BITMAP_WORDS: usize = MAX_FRAMES / 64;

/// Returned by [`FrameAllocator::alloc`] on success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysFrame(pub u64); // physical base address of the 4 KiB frame

impl PhysFrame {
    /// Physical base address of this frame.
    pub fn base_addr(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    OutOfMemory,
    AlreadyFree,
    OutOfRange,
}

pub struct FrameAllocator {
    /// One bit per frame. `1` = used/reserved, `0` = free.
    bitmap: [u64; BITMAP_WORDS],
    /// Total frames tracked (may be < MAX_FRAMES if RAM < 512 MiB).
    total_frames: usize,
    /// Frames currently marked free.
    free_frames: usize,
    /// Frames permanently reserved (firmware / kernel / holes).
    reserved_frames: usize,
}

impl FrameAllocator {
    pub const fn new() -> Self {
        // Start with everything reserved (all bits set to 1).
        // init() will clear bits for usable regions.
        Self {
            bitmap: [u64::MAX; BITMAP_WORDS],
            total_frames: 0,
            free_frames: 0,
            reserved_frames: 0,
        }
    }

    // -----------------------------------------------------------------
    // Initialisation from bootloader memory map
    // -----------------------------------------------------------------

    /// Initialise the allocator from a slice of `(base, len, usable)` tuples.
    ///
    /// Each entry describes a contiguous physical memory region.
    /// `usable == true` means the region may be freely allocated.
    ///
    /// This signature avoids a direct dependency on `bootloader_api` types so
    /// the allocator can be unit-tested on a host without bare-metal imports.
    pub fn init_from_regions(&mut self, regions: &[(u64, u64, bool)]) {
        // First pass — find the highest address to size total_frames.
        let mut max_addr: u64 = 0;
        for &(base, len, _) in regions {
            let end = base.saturating_add(len);
            if end > max_addr {
                max_addr = end;
            }
        }

        // Clamp to our bitmap capacity.
        let max_frame = ((max_addr + FRAME_SIZE - 1) / FRAME_SIZE) as usize;
        self.total_frames = max_frame.min(MAX_FRAMES);

        // Mark every frame in range as reserved to start.
        for i in 0..self.total_frames {
            self.set_used(i);
        }

        // Second pass — free frames that fall inside usable regions.
        for &(base, len, usable) in regions {
            if !usable || len == 0 {
                continue;
            }
            let first = (base / FRAME_SIZE) as usize;
            let last = ((base + len).saturating_sub(1) / FRAME_SIZE) as usize;
            for frame in first..=last {
                if frame < self.total_frames {
                    self.set_free(frame);
                }
            }
        }

        // Recount after init.
        self.free_frames = self.count_free();
        self.reserved_frames = self.total_frames - self.free_frames;
    }

    // -----------------------------------------------------------------
    // Alloc / free
    // -----------------------------------------------------------------

    /// Allocate the next free physical frame.
    /// Returns `Err(AllocError::OutOfMemory)` when no frames are available.
    pub fn alloc(&mut self) -> Result<PhysFrame, AllocError> {
        for word_idx in 0..BITMAP_WORDS {
            let word = self.bitmap[word_idx];
            if word == u64::MAX {
                continue; // all 64 bits used
            }
            // Find lowest 0 bit.
            let bit = word.trailing_ones() as usize;
            let frame = word_idx * 64 + bit;
            if frame >= self.total_frames {
                break;
            }
            self.set_used(frame);
            self.free_frames = self.free_frames.saturating_sub(1);
            return Ok(PhysFrame(frame as u64 * FRAME_SIZE));
        }
        Err(AllocError::OutOfMemory)
    }

    /// Free a previously allocated frame.
    pub fn free(&mut self, frame: PhysFrame) -> Result<(), AllocError> {
        let idx = (frame.0 / FRAME_SIZE) as usize;
        if idx >= self.total_frames {
            return Err(AllocError::OutOfRange);
        }
        if !self.is_used(idx) {
            return Err(AllocError::AlreadyFree);
        }
        self.set_free(idx);
        self.free_frames += 1;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------

    pub fn total_frames(&self) -> usize { self.total_frames }
    pub fn free_frames(&self) -> usize  { self.free_frames }
    pub fn used_frames(&self) -> usize  { self.total_frames - self.free_frames }
    pub fn reserved_frames(&self) -> usize { self.reserved_frames }

    /// Total usable memory in bytes (free + allocated, excludes reserved).
    pub fn usable_bytes(&self) -> u64 {
        (self.total_frames - self.reserved_frames) as u64 * FRAME_SIZE
    }

    /// Free memory in bytes.
    pub fn free_bytes(&self) -> u64 {
        self.free_frames as u64 * FRAME_SIZE
    }

    // -----------------------------------------------------------------
    // Bitmap helpers
    // -----------------------------------------------------------------

    #[inline]
    fn set_used(&mut self, frame: usize) {
        self.bitmap[frame / 64] |= 1u64 << (frame % 64);
    }

    #[inline]
    fn set_free(&mut self, frame: usize) {
        self.bitmap[frame / 64] &= !(1u64 << (frame % 64));
    }

    #[inline]
    fn is_used(&self, frame: usize) -> bool {
        (self.bitmap[frame / 64] >> (frame % 64)) & 1 == 1
    }

    fn count_free(&self) -> usize {
        if self.total_frames == 0 {
            return 0;
        }
        let full_words = self.total_frames / 64;
        let remainder = self.total_frames % 64;

        // Count zeros in complete 64-bit words.
        let mut n = 0usize;
        for &w in &self.bitmap[..full_words] {
            n += w.count_zeros() as usize;
        }

        // Count zeros in the partial last word (only the valid bits).
        if remainder > 0 {
            // Mask keeps only the `remainder` lowest bits.
            let mask = (1u64 << remainder) - 1;
            n += (self.bitmap[full_words] & mask).count_zeros() as usize
                - (64 - remainder); // subtract the upper phantom bits counted by count_zeros
        }
        n
    }
}

// -----------------------------------------------------------------
// Bare-metal init helper (only compiled for the kernel target)
// -----------------------------------------------------------------

#[cfg(target_os = "none")]
pub mod boot {
    use super::FrameAllocator;
    use bootloader_api::info::{MemoryRegionKind, MemoryRegions};

    /// Populate a [`FrameAllocator`] from the bootloader's memory map.
    pub fn init(allocator: &mut FrameAllocator, regions: &MemoryRegions) {
        // Collect regions into the generic tuple format init_from_regions expects.
        // We use a heapless Vec to avoid dynamic allocation during boot.
        let mut entries: heapless::Vec<(u64, u64, bool), 64> = heapless::Vec::new();
        for region in regions.iter() {
            let usable = region.kind == MemoryRegionKind::Usable;
            let _ = entries.push((region.start, region.end - region.start, usable));
        }
        allocator.init_from_regions(&entries);
    }
}

// -----------------------------------------------------------------
// Unit tests (host-only)
// -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_allocator(regions: &[(u64, u64, bool)]) -> FrameAllocator {
        let mut a = FrameAllocator::new();
        a.init_from_regions(regions);
        a
    }

    #[test]
    fn alloc_from_single_usable_region() {
        // One usable region: frames 0..4 (16 KiB)
        let mut a = make_allocator(&[(0, 4 * FRAME_SIZE, true)]);
        assert_eq!(a.free_frames(), 4);
        let f0 = a.alloc().unwrap();
        let f1 = a.alloc().unwrap();
        assert_ne!(f0, f1);
        assert_eq!(a.free_frames(), 2);
    }

    #[test]
    fn alloc_returns_out_of_memory_when_exhausted() {
        let mut a = make_allocator(&[(0, FRAME_SIZE, true)]); // 1 frame
        let _ = a.alloc().unwrap();
        assert!(matches!(a.alloc(), Err(AllocError::OutOfMemory)));
    }

    #[test]
    fn free_recycles_frame() {
        let mut a = make_allocator(&[(0, 2 * FRAME_SIZE, true)]);
        let f = a.alloc().unwrap();
        assert_eq!(a.free_frames(), 1);
        a.free(f).unwrap();
        assert_eq!(a.free_frames(), 2);
        // Should be allocatable again.
        let f2 = a.alloc().unwrap();
        assert_eq!(f2.base_addr() % FRAME_SIZE, 0);
    }

    #[test]
    fn double_free_returns_error() {
        let mut a = make_allocator(&[(0, FRAME_SIZE, true)]);
        let f = a.alloc().unwrap();
        a.free(f).unwrap();
        assert!(matches!(a.free(f), Err(AllocError::AlreadyFree)));
    }

    #[test]
    fn free_out_of_range_returns_error() {
        let mut a = make_allocator(&[(0, FRAME_SIZE, true)]);
        let ghost = PhysFrame(1024 * FRAME_SIZE); // beyond total_frames
        assert!(matches!(a.free(ghost), Err(AllocError::OutOfRange)));
    }

    #[test]
    fn non_usable_regions_are_reserved() {
        // Mix of usable and reserved regions.
        let regions = [
            (0,              FRAME_SIZE,      false), // reserved
            (FRAME_SIZE,     2 * FRAME_SIZE,  true),  // usable: frames 1..3
            (3 * FRAME_SIZE, FRAME_SIZE,      false), // reserved
        ];
        let mut a = make_allocator(&regions);
        assert_eq!(a.free_frames(), 2);
        // First allocation must NOT return frame 0 (reserved).
        let f = a.alloc().unwrap();
        assert!(f.base_addr() >= FRAME_SIZE, "should not allocate reserved frame 0");
    }

    #[test]
    fn statistics_are_consistent_after_alloc_and_free() {
        let region_frames = 8u64;
        let mut a = make_allocator(&[(0, region_frames * FRAME_SIZE, true)]);
        let total = a.total_frames();
        assert_eq!(a.free_frames() + a.used_frames(), total);

        let frames: heapless::Vec<PhysFrame, 8> = (0..4)
            .map(|_| a.alloc().unwrap())
            .collect();
        assert_eq!(a.used_frames(), 4);
        assert_eq!(a.free_frames(), 4);

        for f in frames {
            a.free(f).unwrap();
        }
        assert_eq!(a.free_frames(), total);
        assert_eq!(a.used_frames(), 0);
    }

    #[test]
    fn frame_base_addresses_are_page_aligned() {
        let mut a = make_allocator(&[(0, 16 * FRAME_SIZE, true)]);
        for _ in 0..16 {
            let f = a.alloc().unwrap();
            assert_eq!(f.base_addr() % FRAME_SIZE, 0, "frame not page-aligned");
        }
    }

    #[test]
    fn usable_and_free_bytes_match_frames() {
        let mut a = make_allocator(&[(0, 4 * FRAME_SIZE, true)]);
        assert_eq!(a.free_bytes(), 4 * FRAME_SIZE);
        assert_eq!(a.usable_bytes(), 4 * FRAME_SIZE);
        let _ = a.alloc().unwrap();
        assert_eq!(a.free_bytes(), 3 * FRAME_SIZE);
    }
}
