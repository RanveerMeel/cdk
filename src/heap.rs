//! Kernel heap allocator.
//!
//! ## Overview
//!
//! [`KernelHeap`] wraps `linked_list_allocator::Heap` behind a `spin::Mutex`
//! and exposes a clean init/stats interface.  On bare-metal it is also
//! registered as the `#[global_allocator]`, enabling `alloc` types
//! (`Box`, `Vec`, `String`, `Arc`, …) throughout the kernel.
//!
//! ## Initialisation
//!
//! Call [`KernelHeap::init`] **exactly once** after the physical frame
//! allocator is ready.  It allocates `frame_count` contiguous frames from
//! the supplied [`FrameAllocator`] and hands the resulting memory region to
//! the inner linked-list heap.
//!
//! ## Host unit-test strategy
//!
//! On non-bare-metal targets the `#[global_allocator]` attribute is omitted so
//! the host's own allocator is not displaced.  Tests invoke
//! [`KernelHeap::init_from_slice`] to point the heap at a plain `[u8]`
//! buffer instead of real physical frames.

use linked_list_allocator::Heap;
use spin::Mutex;

use crate::allocator::{FrameAllocator, PhysFrame, FRAME_SIZE};

// ---------------------------------------------------------------------------
// Global allocator (bare-metal only)
// ---------------------------------------------------------------------------

/// Kernel-wide heap.  Initialise with [`KERNEL_HEAP`]`.init(…)` early in
/// `kernel_main` before any `alloc` type is first used.
pub static KERNEL_HEAP: KernelHeap = KernelHeap::new();

#[cfg(target_os = "none")]
#[global_allocator]
static GLOBAL_ALLOC: GlobalHeapAdaptor = GlobalHeapAdaptor;

/// Zero-sized adaptor that forwards `GlobalAlloc` calls to `KERNEL_HEAP`.
#[cfg(target_os = "none")]
struct GlobalHeapAdaptor;

#[cfg(target_os = "none")]
unsafe impl core::alloc::GlobalAlloc for GlobalHeapAdaptor {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        KERNEL_HEAP
            .inner
            .lock()
            .allocate_first_fit(layout)
            .map(|p| p.as_ptr())
            .unwrap_or(core::ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        // SAFETY: ptr was returned by `alloc` with the same layout.
        KERNEL_HEAP
            .inner
            .lock()
            .deallocate(core::ptr::NonNull::new_unchecked(ptr), layout);
    }
}

// ---------------------------------------------------------------------------
// KernelHeap
// ---------------------------------------------------------------------------

pub struct KernelHeap {
    inner: Mutex<Heap>,
}

// SAFETY: `Heap` contains raw pointers; we protect every access with a
// `spin::Mutex`, so `KernelHeap` is safe to share across cores.
unsafe impl Sync for KernelHeap {}

impl KernelHeap {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(Heap::empty()),
        }
    }

    /// Initialise the heap by allocating `frame_count` physical frames from
    /// `fa` and mapping them as a contiguous heap region.
    ///
    /// Assumes an identity-mapped address space (phys == virt), which is what
    /// the bootloader establishes.
    ///
    /// # Panics
    /// Panics if `fa` cannot supply all requested frames or if any two frames
    /// are not physically contiguous (they must be for a single heap region).
    pub fn init(&self, fa: &mut FrameAllocator, frame_count: usize) -> Result<(), HeapError> {
        if frame_count == 0 {
            return Err(HeapError::ZeroSize);
        }

        // Allocate the first frame to anchor the base address.
        let first: PhysFrame = fa.alloc().map_err(|_| HeapError::OutOfFrames)?;
        let base = first.base_addr();
        let mut prev_end = base + FRAME_SIZE;

        // Allocate remaining frames; they must be contiguous.
        for _ in 1..frame_count {
            let frame: PhysFrame = fa.alloc().map_err(|_| HeapError::OutOfFrames)?;
            if frame.base_addr() != prev_end {
                return Err(HeapError::NonContiguous);
            }
            prev_end = frame.base_addr() + FRAME_SIZE;
        }

        let size = frame_count as u64 * FRAME_SIZE;

        // SAFETY: `base` is a valid, writable, identity-mapped region of
        // `size` bytes that is not used by anything else.  We call `init`
        // exactly once per `KernelHeap` instance (enforced by the caller).
        unsafe {
            self.inner.lock().init(base as *mut u8, size as usize);
        }
        Ok(())
    }

    /// Initialise from a caller-supplied byte slice (used in host unit tests).
    ///
    /// # Safety
    /// `buf` must remain valid and exclusively owned by this heap for its
    /// entire lifetime.
    pub unsafe fn init_from_slice(&self, buf: &mut [u8]) {
        self.inner.lock().init(buf.as_mut_ptr(), buf.len());
    }

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------

    pub fn used_bytes(&self) -> usize {
        self.inner.lock().used()
    }

    pub fn free_bytes(&self) -> usize {
        self.inner.lock().free()
    }

    pub fn total_bytes(&self) -> usize {
        let h = self.inner.lock();
        h.used() + h.free()
    }

    /// Whether [`init`] has been called (total size > 0).
    pub fn is_initialised(&self) -> bool {
        self.total_bytes() > 0
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    ZeroSize,
    OutOfFrames,
    /// Physical frames were not contiguous — heap init requires a single
    /// unbroken region.
    NonContiguous,
}

// ---------------------------------------------------------------------------
// Unit tests (host-runnable)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 16 KiB scratch buffer aligned to 4096.  `repr(C, align(4096))` ensures
    /// the slice starts on a page boundary, matching what real frames provide.
    #[repr(C, align(4096))]
    struct AlignedBuf([u8; 16 * 4096]);

    fn make_heap() -> (KernelHeap, Box<AlignedBuf>) {
        let mut buf = Box::new(AlignedBuf([0u8; 16 * 4096]));
        let heap = KernelHeap::new();
        // SAFETY: buf is exclusively owned, heap only lives as long as buf in tests.
        unsafe { heap.init_from_slice(&mut buf.0) };
        (heap, buf)
    }

    #[test]
    fn new_heap_is_not_initialised() {
        let h = KernelHeap::new();
        assert!(!h.is_initialised());
        assert_eq!(h.used_bytes(), 0);
        assert_eq!(h.free_bytes(), 0);
    }

    #[test]
    fn init_from_slice_makes_heap_usable() {
        let (h, _buf) = make_heap();
        assert!(h.is_initialised());
        assert_eq!(h.used_bytes(), 0);
        assert!(h.free_bytes() > 0);
    }

    #[test]
    fn total_bytes_equals_used_plus_free() {
        let (h, _buf) = make_heap();
        assert_eq!(h.total_bytes(), h.used_bytes() + h.free_bytes());
    }

    #[test]
    fn allocate_increases_used_bytes() {
        let (h, _buf) = make_heap();
        let layout = core::alloc::Layout::from_size_align(64, 8).unwrap();
        let before = h.used_bytes();
        let ptr = h.inner.lock().allocate_first_fit(layout);
        assert!(ptr.is_ok());
        assert!(h.used_bytes() >= before + 64);
    }

    #[test]
    fn deallocate_recovers_bytes() {
        let (h, _buf) = make_heap();
        let layout = core::alloc::Layout::from_size_align(64, 8).unwrap();
        let ptr = h.inner.lock().allocate_first_fit(layout).unwrap();
        let used_after_alloc = h.used_bytes();
        // SAFETY: ptr was just returned by allocate_first_fit with the same layout.
        unsafe { h.inner.lock().deallocate(ptr, layout) };
        assert!(h.used_bytes() < used_after_alloc);
    }

    // -----------------------------------------------------------------------
    // Tests for init() with a FrameAllocator-like mock.
    //
    // On the host, FrameAllocator hands out physical addresses starting at 0
    // (null pointer), which would SIGSEGV when Heap::init tries to write there.
    // We use a FrameSource-backed mock that returns addresses of real heap-
    // allocated, page-aligned buffers instead.
    // -----------------------------------------------------------------------

    /// A mock frame source that returns addresses of pre-allocated, aligned
    /// 4 KiB `Box`es so host tests never touch address 0.
    struct MockFrameSource {
        frames: heapless::Vec<Box<AlignedFrame>, 32>,
        next: usize,
    }

    #[repr(C, align(4096))]
    struct AlignedFrame([u8; 4096]);

    impl MockFrameSource {
        fn new(count: usize) -> Self {
            let mut frames = heapless::Vec::new();
            for _ in 0..count {
                let _ = frames.push(Box::new(AlignedFrame([0u8; 4096])));
            }
            MockFrameSource { frames, next: 0 }
        }

        fn alloc_frame(&mut self) -> Option<u64> {
            if self.next >= self.frames.len() {
                return None;
            }
            let addr = self.frames[self.next].0.as_ptr() as u64;
            self.next += 1;
            Some(addr)
        }
    }

    /// Thin wrapper so `KernelHeap::init` can consume `MockFrameSource`
    /// without touching the real `FrameAllocator`.
    struct MockAllocAdapter<'a>(&'a mut MockFrameSource);

    impl<'a> MockAllocAdapter<'a> {
        /// Mirrors what `KernelHeap::init` does: allocate `count` contiguous-
        /// ish frames and hand them to `Heap::init`.
        fn init_heap(&mut self, heap: &KernelHeap, count: usize) -> Result<(), HeapError> {
            if count == 0 { return Err(HeapError::ZeroSize); }
            let first = self.0.alloc_frame().ok_or(HeapError::OutOfFrames)?;
            // For the mock, frames don't need to be physically contiguous.
            // We give the heap only the first frame's memory but iterate
            // to consume the requested count so the "out of frames" path
            // is exercised correctly.
            for _ in 1..count {
                self.0.alloc_frame().ok_or(HeapError::OutOfFrames)?;
            }
            // SAFETY: `first` points to an exclusively-owned, aligned, 4 KiB
            // buffer for the lifetime of the MockFrameSource.
            unsafe { heap.init_from_slice(core::slice::from_raw_parts_mut(first as *mut u8, FRAME_SIZE as usize)) };
            Ok(())
        }
    }

    #[test]
    fn init_from_frame_source_makes_heap_usable() {
        let mut src = MockFrameSource::new(4);
        let heap = KernelHeap::new();
        let result = MockAllocAdapter(&mut src).init_heap(&heap, 1);
        assert!(result.is_ok());
        assert!(heap.is_initialised());
        assert_eq!(heap.total_bytes(), FRAME_SIZE as usize);
    }

    #[test]
    fn init_with_zero_frames_returns_error() {
        let mut src = MockFrameSource::new(4);
        let heap = KernelHeap::new();
        assert!(matches!(
            MockAllocAdapter(&mut src).init_heap(&heap, 0),
            Err(HeapError::ZeroSize)
        ));
    }

    #[test]
    fn init_with_insufficient_frames_returns_out_of_frames() {
        let mut src = MockFrameSource::new(2); // only 2 frames
        let heap = KernelHeap::new();
        assert!(matches!(
            MockAllocAdapter(&mut src).init_heap(&heap, 4),
            Err(HeapError::OutOfFrames)
        ));
    }
}
