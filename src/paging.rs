//! Virtual memory manager — 4-level x86_64 page table (PML4).
//!
//! ## Overview
//!
//! [`PageTableManager`] owns a single PML4 root frame and walks / creates the
//! four-level hierarchy (PML4 → PDPT → PD → PT) on demand.  Every interior
//! table node is itself a 4 KiB frame supplied by a [`FrameSource`] — a
//! thin trait so the real [`crate::allocator::FrameAllocator`] can be used
//! at runtime and a simple mock can be used in host unit tests.
//!
//! ## Page-table flags
//!
//! [`MapFlags`] encodes the subset of page-table entry bits used by the kernel:
//!
//! | Flag | PTE bit | Meaning |
//! |---|---|---|
//! | `PRESENT` | 0 | Entry is valid |
//! | `WRITABLE` | 1 | Page is read-write |
//! | `USER` | 2 | Accessible from CPL 3 |
//! | `NO_EXEC` | 63 (NX) | Execution disabled |
//!
//! ## Safety model
//!
//! All physical addresses stored in page-table entries are treated as
//! **identity-mapped** — physical address N lives at virtual address N.
//! This is the mapping the bootloader establishes before jumping to
//! `kernel_main`, so it is always valid for kernel use.
//!
//! ## Host unit-test strategy
//!
//! The `paging` module compiles on the host (`aarch64-apple-darwin`) as well
//! as on the bare-metal target.  The `x86_64` crate types are conditionally
//! replaced by lightweight newtypes when `target_os != "none"` so that
//! `cargo test-host` works without `x86_64-unknown-none` installed on the
//! CI runner.

// ---------------------------------------------------------------------------
// Conditional imports: real x86_64 types on bare-metal, thin stubs on host
// ---------------------------------------------------------------------------

#[cfg(target_os = "none")]
use x86_64::{
    structures::paging::{
        PageTableEntry, PageTableFlags as X86Flags,
    },
    PhysAddr, VirtAddr,
};

#[cfg(not(target_os = "none"))]
#[allow(dead_code)]
mod host_stubs {
    //! Minimal replacements for x86_64 paging types used in unit tests.

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PhysAddr(pub u64);
    impl PhysAddr {
        pub fn new(v: u64) -> Self { Self(v) }
        pub fn as_u64(self)  -> u64 { self.0 }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    pub struct X86Flags(pub u64);
    impl X86Flags {
        pub const PRESENT:          X86Flags = X86Flags(1 << 0);
        pub const WRITABLE:         X86Flags = X86Flags(1 << 1);
        pub const USER_ACCESSIBLE:  X86Flags = X86Flags(1 << 2);
        pub const NO_EXECUTE:       X86Flags = X86Flags(1 << 63);

        pub fn bits(self) -> u64 { self.0 }
        pub fn from_bits_truncate(v: u64) -> Self { Self(v) }
        pub fn contains(self, other: X86Flags) -> bool { self.0 & other.0 == other.0 }
    }
    impl core::ops::BitOr for X86Flags {
        type Output = Self;
        fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
    }
    impl core::ops::BitOrAssign for X86Flags {
        fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
    }

    /// Index into a 512-entry page table level.
    #[derive(Clone, Copy, Debug)]
    pub struct PageTableIndex(u16);
    impl PageTableIndex {
        pub fn new(v: u16) -> Self { Self(v & 0x1ff) }
        pub fn into_usize(self) -> usize { self.0 as usize }
    }

    /// One 8-byte page-table entry.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct PageTableEntry {
        bits: u64,
    }
    impl PageTableEntry {
        pub fn is_unused(&self) -> bool { self.bits == 0 }
        pub fn set_unused(&mut self) { self.bits = 0; }
        pub fn flags(&self) -> X86Flags { X86Flags::from_bits_truncate(self.bits) }
        pub fn addr(&self) -> PhysAddr {
            PhysAddr::new(self.bits & 0x000f_ffff_ffff_f000)
        }
        pub fn set_addr(&mut self, addr: PhysAddr, flags: X86Flags) {
            self.bits = addr.as_u64() | flags.bits();
        }
    }

    /// 512-entry page table (one per level, 4 KiB total).
    #[repr(C, align(4096))]
    pub struct X86PageTable {
        pub entries: [PageTableEntry; 512],
    }
    impl X86PageTable {
        pub const fn new() -> Self {
            Self { entries: [PageTableEntry { bits: 0 }; 512] }
        }
    }
    impl core::ops::Index<PageTableIndex> for X86PageTable {
        type Output = PageTableEntry;
        fn index(&self, idx: PageTableIndex) -> &Self::Output {
            &self.entries[idx.into_usize()]
        }
    }
    impl core::ops::IndexMut<PageTableIndex> for X86PageTable {
        fn index_mut(&mut self, idx: PageTableIndex) -> &mut Self::Output {
            &mut self.entries[idx.into_usize()]
        }
    }
}

#[cfg(not(target_os = "none"))]
use host_stubs::{PhysAddr, X86Flags, X86PageTable, PageTableEntry};


// ---------------------------------------------------------------------------
// Page size
// ---------------------------------------------------------------------------

/// Size of a 4 KiB page in bytes.
pub const PAGE_SIZE: u64 = 4096;

// ---------------------------------------------------------------------------
// MapFlags
// ---------------------------------------------------------------------------

/// Kernel-level mapping flags passed to [`PageTableManager::map`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MapFlags {
    pub writable: bool,
    pub user:     bool,
    pub no_exec:  bool,
}

impl MapFlags {
    pub const fn kernel_rx() -> Self {
        Self { writable: false, user: false, no_exec: false }
    }
    pub const fn kernel_rw() -> Self {
        Self { writable: true, user: false, no_exec: true }
    }
    pub const fn user_rw() -> Self {
        Self { writable: true, user: true, no_exec: true }
    }

    fn to_x86_leaf(&self) -> X86Flags {
        let mut f = X86Flags::PRESENT;
        if self.writable { f |= X86Flags::WRITABLE; }
        if self.user     { f |= X86Flags::USER_ACCESSIBLE; }
        if self.no_exec  { f |= X86Flags::NO_EXECUTE; }
        f
    }

    /// Flags for an interior table node (always present + writable so the
    /// walk can descend regardless of the leaf permissions).
    fn interior() -> X86Flags {
        X86Flags::PRESENT | X86Flags::WRITABLE
    }
}

// ---------------------------------------------------------------------------
// FrameSource trait
// ---------------------------------------------------------------------------

/// Minimal interface the page-table walker needs from a frame allocator.
///
/// Implemented by the real [`crate::allocator::FrameAllocator`] at runtime
/// and by a lightweight array-backed mock in unit tests.
pub trait FrameSource {
    /// Allocate one zeroed 4 KiB frame.  Returns the physical base address.
    fn alloc_zeroed(&mut self) -> Option<u64>;
}

// ---------------------------------------------------------------------------
// FrameAllocator impl of FrameSource
// ---------------------------------------------------------------------------

// On bare-metal: identity-mapped RAM lets us zero via the physical address.
#[cfg(target_os = "none")]
impl FrameSource for crate::allocator::FrameAllocator {
    fn alloc_zeroed(&mut self) -> Option<u64> {
        let frame = self.alloc().ok()?;
        let phys = frame.base_addr();
        unsafe {
            core::ptr::write_bytes(phys as *mut u8, 0, PAGE_SIZE as usize);
        }
        Some(phys)
    }
}

// On the host (test build): FrameAllocator bitmap starts at address 0, so
// dereferencing its frame addresses would SIGSEGV.  Provide a stub that
// satisfies the trait bound without being called in tests (tests use MockAlloc).
#[cfg(not(target_os = "none"))]
impl FrameSource for crate::allocator::FrameAllocator {
    fn alloc_zeroed(&mut self) -> Option<u64> {
        // Never called on the host — MockAlloc is used instead.
        None
    }
}

// ---------------------------------------------------------------------------
// Paging error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingError {
    /// Frame allocator returned no memory.
    OutOfMemory,
    /// The virtual address is not 4 KiB aligned.
    UnalignedAddress,
    /// The physical address is not 4 KiB aligned.
    UnalignedPhysical,
    /// The virtual address is already mapped.
    AlreadyMapped,
    /// The virtual address is not mapped (unmap / translate on absent entry).
    NotMapped,
}

pub type PagingResult<T> = Result<T, PagingError>;

// ---------------------------------------------------------------------------
// Virtual address decomposition
// ---------------------------------------------------------------------------

/// Decompose a 64-bit virtual address into four 9-bit page-table indices
/// and a 12-bit page offset.
///
/// ```text
/// Bits 63–48 : sign extension (must equal bit 47)
/// Bits 47–39 : PML4 index
/// Bits 38–30 : PDPT index
/// Bits 29–21 : PD   index
/// Bits 20–12 : PT   index
/// Bits 11– 0 : page offset
/// ```
#[derive(Debug, Clone, Copy)]
struct VirtIndices {
    pml4: usize,
    pdpt: usize,
    pd:   usize,
    pt:   usize,
    offset: u64,
}

impl VirtIndices {
    fn from_u64(addr: u64) -> Self {
        Self {
            pml4:   ((addr >> 39) & 0x1ff) as usize,
            pdpt:   ((addr >> 30) & 0x1ff) as usize,
            pd:     ((addr >> 21) & 0x1ff) as usize,
            pt:     ((addr >> 12) & 0x1ff) as usize,
            offset:  (addr        & 0xfff),
        }
    }
}

// ---------------------------------------------------------------------------
// PageTableManager
// ---------------------------------------------------------------------------

/// Manages a single 4-level x86_64 page-table hierarchy.
///
/// Interior table nodes are allocated lazily on first use.  The root PML4
/// frame is allocated during construction.
///
/// All physical addresses are assumed to be identity-mapped in virtual space
/// (the bootloader sets this up before calling `kernel_main`).
pub struct PageTableManager {
    /// Physical (= virtual, identity-mapped) address of the PML4 root table.
    pml4_phys: u64,
    /// Number of 4 KiB pages currently mapped.
    mapped_pages: usize,
}

impl PageTableManager {
    /// Create a new, empty page-table hierarchy.
    ///
    /// Allocates and zeroes the PML4 root frame from `alloc`.
    pub fn new<A: FrameSource>(alloc: &mut A) -> Option<Self> {
        let pml4_phys = alloc.alloc_zeroed()?;
        Some(Self { pml4_phys, mapped_pages: 0 })
    }

    /// Physical address of the PML4 root (load into `CR3` to activate).
    pub fn pml4_phys(&self) -> u64 {
        self.pml4_phys
    }

    /// Number of 4 KiB pages currently mapped.
    pub fn mapped_pages(&self) -> usize {
        self.mapped_pages
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Map `virt` → `phys` with the given flags.
    ///
    /// Both addresses must be 4 KiB aligned.
    /// Returns `Err(AlreadyMapped)` if the virtual address is already present.
    pub fn map<A: FrameSource>(
        &mut self,
        virt: u64,
        phys: u64,
        flags: MapFlags,
        alloc: &mut A,
    ) -> PagingResult<()> {
        if virt & 0xfff != 0 { return Err(PagingError::UnalignedAddress); }
        if phys & 0xfff != 0 { return Err(PagingError::UnalignedPhysical); }

        let idx = VirtIndices::from_u64(virt);

        // Walk PML4 → PDPT → PD → PT, creating tables on demand.
        let pdpt_phys = self.get_or_create(self.pml4_phys, idx.pml4, alloc)?;
        let pd_phys   = self.get_or_create(pdpt_phys,      idx.pdpt, alloc)?;
        let pt_phys   = self.get_or_create(pd_phys,        idx.pd,   alloc)?;

        // Write the leaf PTE.  We take the mutable reference only here,
        // after all interior tables are fully resolved, so no two `&mut`
        // references to the same frame can exist simultaneously.
        // SAFETY: pt_phys is a valid, aligned, identity-mapped frame from FrameSource;
        //         idx.pt is always in 0..512.
        let entry = unsafe { &mut *Self::entry_ptr_mut(pt_phys, idx.pt) };

        if !entry.is_unused() {
            return Err(PagingError::AlreadyMapped);
        }

        entry.set_addr(PhysAddr::new(phys), flags.to_x86_leaf());
        self.mapped_pages += 1;
        Ok(())
    }

    /// Remove the mapping for `virt`, zeroing the leaf PTE.
    ///
    /// Does not reclaim interior table frames (they may still hold other
    /// mappings).  Returns `Err(NotMapped)` if the address has no mapping.
    pub fn unmap(&mut self, virt: u64) -> PagingResult<()> {
        if virt & 0xfff != 0 { return Err(PagingError::UnalignedAddress); }

        let idx = VirtIndices::from_u64(virt);

        let pdpt_phys = self.descend(self.pml4_phys, idx.pml4)?;
        let pd_phys   = self.descend(pdpt_phys,      idx.pdpt)?;
        let pt_phys   = self.descend(pd_phys,        idx.pd)?;

        // SAFETY: pt_phys is a valid, aligned, identity-mapped frame from FrameSource;
        //         idx.pt is always in 0..512.
        let entry = unsafe { &mut *Self::entry_ptr_mut(pt_phys, idx.pt) };

        if entry.is_unused() {
            return Err(PagingError::NotMapped);
        }

        entry.set_unused();
        self.mapped_pages -= 1;
        Ok(())
    }

    /// Translate a virtual address to its mapped physical address.
    ///
    /// Returns the physical address of the *page* (page offset is stripped).
    /// Returns `Err(NotMapped)` if any level of the walk is absent.
    pub fn translate(&self, virt: u64) -> PagingResult<u64> {
        let idx = VirtIndices::from_u64(virt);

        let pdpt_phys = self.descend(self.pml4_phys, idx.pml4)?;
        let pd_phys   = self.descend(pdpt_phys,      idx.pdpt)?;
        let pt_phys   = self.descend(pd_phys,        idx.pd)?;

        // SAFETY: pt_phys is a valid, aligned, identity-mapped frame from FrameSource;
        //         idx.pt is always in 0..512.
        let entry = unsafe { &*Self::entry_ptr(pt_phys, idx.pt) };

        if entry.is_unused() {
            return Err(PagingError::NotMapped);
        }

        Ok(entry.addr().as_u64())
    }

    // -----------------------------------------------------------------------
    // Private walk helpers
    // -----------------------------------------------------------------------

    /// Get or create the child table pointed to by `parent[child_idx]`.
    /// Returns the physical address of the child table.
    fn get_or_create<A: FrameSource>(
        &self,
        parent_phys: u64,
        child_idx: usize,
        alloc: &mut A,
    ) -> PagingResult<u64> {
        // SAFETY: parent_phys is a valid, aligned, identity-mapped frame;
        //         child_idx is always in 0..512.
        let entry = unsafe { &mut *Self::entry_ptr_mut(parent_phys, child_idx) };
        if entry.is_unused() {
            let child_phys = alloc.alloc_zeroed().ok_or(PagingError::OutOfMemory)?;
            entry.set_addr(PhysAddr::new(child_phys), MapFlags::interior());
            Ok(child_phys)
        } else {
            Ok(entry.addr().as_u64())
        }
    }

    /// Walk down one level; return the child frame address or `NotMapped`.
    fn descend(&self, parent_phys: u64, child_idx: usize) -> PagingResult<u64> {
        // SAFETY: parent_phys is a valid, aligned, identity-mapped frame;
        //         child_idx is always in 0..512.
        let entry = unsafe { &*Self::entry_ptr(parent_phys, child_idx) };
        if entry.is_unused() {
            Err(PagingError::NotMapped)
        } else {
            Ok(entry.addr().as_u64())
        }
    }

    // -----------------------------------------------------------------------
    // Raw pointer helpers (identity-mapped: phys == virt)
    // -----------------------------------------------------------------------

    /// Return a raw mutable pointer to a specific entry inside the page table
    /// at `phys`.
    ///
    /// `idx` must be 0–511.  Using a pointer (rather than `&mut table[idx]`)
    /// avoids the "implicit autoref of raw pointer deref" lint on nightly.
    ///
    /// # Safety
    /// `phys` must be a valid, 4 KiB-aligned, identity-mapped frame.
    /// The caller is responsible for ensuring unique access.
    unsafe fn entry_ptr_mut(phys: u64, idx: usize) -> *mut PageTableEntry {
        // SAFETY: caller guarantees phys is a valid, aligned frame; idx < 512.
        (phys as *mut PageTableEntry).add(idx)
    }

    /// Same as `entry_ptr_mut` but returns a shared pointer.
    unsafe fn entry_ptr(phys: u64, idx: usize) -> *const PageTableEntry {
        (phys as *const PageTableEntry).add(idx)
    }
}

// ---------------------------------------------------------------------------
// Unit tests (host-runnable)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Mock frame allocator backed by individually Box-allocated page tables
    //
    // Each "frame" is a separately Box-allocated X86PageTable, which the
    // allocator guarantees is PAGE_SIZE-aligned (the type is #[repr(align(4096))]).
    // We store the raw pointer so PageTableManager can cast it back safely.
    // -----------------------------------------------------------------------

    const MOCK_FRAMES: usize = 64;

    struct MockAlloc {
        // Each element owns a heap-allocated, 4096-byte-aligned page-table frame.
        frames: Vec<Box<X86PageTable>>,
    }

    impl MockAlloc {
        fn new() -> Self {
            Self { frames: Vec::new() }
        }
    }

    impl FrameSource for MockAlloc {
        fn alloc_zeroed(&mut self) -> Option<u64> {
            if self.frames.len() >= MOCK_FRAMES {
                return None;
            }
            // X86PageTable is repr(C, align(4096)) so Box guarantees alignment.
            let frame = Box::new(X86PageTable::new());
            let addr = frame.entries.as_ptr() as u64;
            // Verify alignment at test time.
            assert_eq!(addr % PAGE_SIZE, 0, "frame not page-aligned");
            self.frames.push(frame);
            Some(addr)
        }
    }

    fn make_mgr() -> (PageTableManager, MockAlloc) {
        let mut alloc = MockAlloc::new();
        let mgr = PageTableManager::new(&mut alloc).expect("alloc failed");
        (mgr, alloc)
    }

    // Virtual addresses in distinct PT slots (1 MiB apart).
    const VA1: u64 = 0x0000_0000_0010_0000; // 1 MiB
    const VA2: u64 = 0x0000_0000_0020_0000; // 2 MiB
    const VA3: u64 = 0x0000_0000_0030_0000; // 3 MiB

    /// Allocate a frame from `alloc` to use as a physical target in tests.
    /// On the host these are real 4 KiB-aligned heap addresses.
    fn alloc_phys(alloc: &mut MockAlloc) -> u64 {
        alloc.alloc_zeroed().expect("ran out of mock frames")
    }

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    #[test]
    fn new_manager_has_zero_mapped_pages() {
        let (mgr, _alloc) = make_mgr();
        assert_eq!(mgr.mapped_pages(), 0);
    }

    #[test]
    fn pml4_phys_is_non_zero_and_aligned() {
        let (mgr, _alloc) = make_mgr();
        assert_ne!(mgr.pml4_phys(), 0);
        assert_eq!(mgr.pml4_phys() % PAGE_SIZE, 0);
    }

    // -----------------------------------------------------------------------
    // map
    // -----------------------------------------------------------------------

    #[test]
    fn map_single_page_succeeds() {
        let (mut mgr, mut alloc) = make_mgr();
        let phys = alloc_phys(&mut alloc);
        assert!(mgr.map(VA1, phys, MapFlags::kernel_rw(), &mut alloc).is_ok());
        assert_eq!(mgr.mapped_pages(), 1);
    }

    #[test]
    fn map_multiple_distinct_pages_succeeds() {
        let (mut mgr, mut alloc) = make_mgr();
        let p1 = alloc_phys(&mut alloc);
        let p2 = alloc_phys(&mut alloc);
        let p3 = alloc_phys(&mut alloc);
        mgr.map(VA1, p1, MapFlags::kernel_rw(), &mut alloc).unwrap();
        mgr.map(VA2, p2, MapFlags::kernel_rw(), &mut alloc).unwrap();
        mgr.map(VA3, p3, MapFlags::kernel_rw(), &mut alloc).unwrap();
        assert_eq!(mgr.mapped_pages(), 3);
    }

    #[test]
    fn map_unaligned_virt_returns_error() {
        let (mut mgr, mut alloc) = make_mgr();
        let phys = alloc_phys(&mut alloc);
        let result = mgr.map(VA1 + 1, phys, MapFlags::kernel_rw(), &mut alloc);
        assert_eq!(result, Err(PagingError::UnalignedAddress));
    }

    #[test]
    fn map_unaligned_phys_returns_error() {
        let (mut mgr, mut alloc) = make_mgr();
        let phys = alloc_phys(&mut alloc);
        let result = mgr.map(VA1, phys + 7, MapFlags::kernel_rw(), &mut alloc);
        assert_eq!(result, Err(PagingError::UnalignedPhysical));
    }

    #[test]
    fn map_same_virt_twice_returns_already_mapped() {
        let (mut mgr, mut alloc) = make_mgr();
        let p1 = alloc_phys(&mut alloc);
        let p2 = alloc_phys(&mut alloc);
        mgr.map(VA1, p1, MapFlags::kernel_rw(), &mut alloc).unwrap();
        let result = mgr.map(VA1, p2, MapFlags::kernel_rw(), &mut alloc);
        assert_eq!(result, Err(PagingError::AlreadyMapped));
    }

    #[test]
    fn map_out_of_frames_returns_out_of_memory() {
        // Give the manager exactly one frame (for the PML4 root).
        // The next alloc (for the PDPT) returns None → OutOfMemory.
        struct OneFrameAlloc { frame: Box<X86PageTable>, used: bool }
        impl OneFrameAlloc {
            fn new() -> Self { Self { frame: Box::new(X86PageTable::new()), used: false } }
        }
        impl FrameSource for OneFrameAlloc {
            fn alloc_zeroed(&mut self) -> Option<u64> {
                if !self.used {
                    self.used = true;
                    Some(self.frame.entries.as_ptr() as u64)
                } else {
                    None
                }
            }
        }
        let mut one = OneFrameAlloc::new();
        let mut mgr = PageTableManager::new(&mut one).unwrap();
        // Pre-allocate a valid physical target (unrelated to the page walker).
        let target = Box::new(X86PageTable::new());
        let phys = target.entries.as_ptr() as u64;
        let result = mgr.map(VA1, phys, MapFlags::kernel_rw(), &mut one);
        assert_eq!(result, Err(PagingError::OutOfMemory));
    }

    // -----------------------------------------------------------------------
    // translate
    // -----------------------------------------------------------------------

    #[test]
    fn translate_mapped_page_returns_correct_phys() {
        let (mut mgr, mut alloc) = make_mgr();
        let phys = alloc_phys(&mut alloc);
        mgr.map(VA1, phys, MapFlags::kernel_rw(), &mut alloc).unwrap();
        assert_eq!(mgr.translate(VA1).unwrap(), phys);
    }

    #[test]
    fn translate_unmapped_address_returns_not_mapped() {
        let (mgr, _alloc) = make_mgr();
        assert_eq!(mgr.translate(VA1), Err(PagingError::NotMapped));
    }

    #[test]
    fn translate_multiple_independent_mappings() {
        let (mut mgr, mut alloc) = make_mgr();
        let p1 = alloc_phys(&mut alloc);
        let p2 = alloc_phys(&mut alloc);
        mgr.map(VA1, p1, MapFlags::kernel_rx(), &mut alloc).unwrap();
        mgr.map(VA2, p2, MapFlags::kernel_rw(), &mut alloc).unwrap();
        assert_eq!(mgr.translate(VA1).unwrap(), p1);
        assert_eq!(mgr.translate(VA2).unwrap(), p2);
    }

    // -----------------------------------------------------------------------
    // unmap
    // -----------------------------------------------------------------------

    #[test]
    fn unmap_mapped_page_succeeds() {
        let (mut mgr, mut alloc) = make_mgr();
        let phys = alloc_phys(&mut alloc);
        mgr.map(VA1, phys, MapFlags::kernel_rw(), &mut alloc).unwrap();
        assert!(mgr.unmap(VA1).is_ok());
        assert_eq!(mgr.mapped_pages(), 0);
    }

    #[test]
    fn unmap_makes_address_untranslatable() {
        let (mut mgr, mut alloc) = make_mgr();
        let phys = alloc_phys(&mut alloc);
        mgr.map(VA1, phys, MapFlags::kernel_rw(), &mut alloc).unwrap();
        mgr.unmap(VA1).unwrap();
        assert_eq!(mgr.translate(VA1), Err(PagingError::NotMapped));
    }

    #[test]
    fn unmap_unmapped_address_returns_not_mapped() {
        let (mut mgr, _alloc) = make_mgr();
        assert_eq!(mgr.unmap(VA1), Err(PagingError::NotMapped));
    }

    #[test]
    fn unmap_unaligned_address_returns_error() {
        let (mut mgr, _alloc) = make_mgr();
        assert_eq!(mgr.unmap(VA1 + 1), Err(PagingError::UnalignedAddress));
    }

    #[test]
    fn remap_after_unmap_succeeds() {
        let (mut mgr, mut alloc) = make_mgr();
        let p1 = alloc_phys(&mut alloc);
        let p2 = alloc_phys(&mut alloc);
        mgr.map(VA1, p1, MapFlags::kernel_rw(), &mut alloc).unwrap();
        mgr.unmap(VA1).unwrap();
        assert!(mgr.map(VA1, p2, MapFlags::kernel_rw(), &mut alloc).is_ok());
        assert_eq!(mgr.translate(VA1).unwrap(), p2);
    }

    // -----------------------------------------------------------------------
    // VirtIndices
    // -----------------------------------------------------------------------

    #[test]
    fn virt_indices_decompose_correctly() {
        // 0x0000_CAFE_1234_5000  →  manually computed indices
        //   bits 47-39 = (0x0000_CAFE_1234_5000 >> 39) & 0x1ff
        let addr: u64 = 0x0000_0040_0020_1000;
        let vi = VirtIndices::from_u64(addr);
        assert_eq!(vi.pml4,   (addr >> 39) as usize & 0x1ff);
        assert_eq!(vi.pdpt,   (addr >> 30) as usize & 0x1ff);
        assert_eq!(vi.pd,     (addr >> 21) as usize & 0x1ff);
        assert_eq!(vi.pt,     (addr >> 12) as usize & 0x1ff);
        assert_eq!(vi.offset,  addr & 0xfff);
    }

    #[test]
    fn page_size_alignment_constant() {
        assert_eq!(PAGE_SIZE, 4096);
        assert_eq!(PAGE_SIZE % 4096, 0);
    }

    // -----------------------------------------------------------------------
    // MapFlags
    // -----------------------------------------------------------------------

    #[test]
    fn map_flags_presets_are_distinct() {
        let rx = MapFlags::kernel_rx();
        let rw = MapFlags::kernel_rw();
        let ur = MapFlags::user_rw();
        assert!(!rx.writable && !rx.user && !rx.no_exec);
        assert!( rw.writable && !rw.user &&  rw.no_exec);
        assert!( ur.writable &&  ur.user &&  ur.no_exec);
    }
}
