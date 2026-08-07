//! Software IOMMU / DMA translation (identity domain).
//!
//! Real VT-d / DMAR parse is deferred. This module maintains an explicit
//! identity map of guest-physical DMA windows (typically UM regions) so device
//! drivers can resolve IOVAs through one API before hardware IOMMU lands.

use heapless::Vec;
use spin::Mutex;

use crate::allocator::FRAME_SIZE;

pub const MAX_WINDOWS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuError {
    Full,
    NotFound,
    Unaligned,
    Overlap,
    ZeroSize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaWindow {
    pub guest_phys: u64,
    pub len: u64,
    /// Device-visible base (identity today).
    pub device_phys: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IommuInfo {
    /// Hardware VT-d / DMAR present (always false in this slice).
    pub hw_present: bool,
    pub mode: &'static str,
    pub windows: usize,
    pub translates: u64,
}

struct State {
    windows: Vec<DmaWindow, MAX_WINDOWS>,
    translates: u64,
}

impl State {
    const fn new() -> Self {
        Self {
            windows: Vec::new(),
            translates: 0,
        }
    }
}

static IOMMU: Mutex<State> = Mutex::new(State::new());

fn ranges_overlap(a: u64, a_len: u64, b: u64, b_len: u64) -> bool {
    let a_end = a.saturating_add(a_len);
    let b_end = b.saturating_add(b_len);
    a < b_end && b < a_end
}

/// Register an identity DMA window `[guest_phys, guest_phys+len)`.
pub fn map_identity(guest_phys: u64, len: u64) -> Result<(), IommuError> {
    if len == 0 {
        return Err(IommuError::ZeroSize);
    }
    if guest_phys % FRAME_SIZE != 0 || len % FRAME_SIZE != 0 {
        return Err(IommuError::Unaligned);
    }
    let mut st = IOMMU.lock();
    for w in st.windows.iter() {
        if ranges_overlap(guest_phys, len, w.guest_phys, w.len) {
            return Err(IommuError::Overlap);
        }
    }
    st.windows
        .push(DmaWindow {
            guest_phys,
            len,
            device_phys: guest_phys,
        })
        .map_err(|_| IommuError::Full)
}

/// Remove the window that starts at `guest_phys`.
pub fn unmap(guest_phys: u64) -> Result<(), IommuError> {
    let mut st = IOMMU.lock();
    let idx = st
        .windows
        .iter()
        .position(|w| w.guest_phys == guest_phys)
        .ok_or(IommuError::NotFound)?;
    st.windows.swap_remove(idx);
    Ok(())
}

/// Translate a device IOVA through the identity domain.
///
/// Returns `device_phys` for addresses covered by a registered window, or
/// `None` if unmapped (strict mode — no implicit passthrough).
pub fn translate_dma(iova: u64) -> Option<u64> {
    let mut st = IOMMU.lock();
    st.translates = st.translates.saturating_add(1);
    for w in st.windows.iter() {
        if iova >= w.guest_phys && iova < w.guest_phys.saturating_add(w.len) {
            let off = iova - w.guest_phys;
            return Some(w.device_phys.saturating_add(off));
        }
    }
    None
}

/// Like [`translate_dma`], but identity-passthrough when no window matches
/// (useful while migrating drivers onto explicit maps).
pub fn translate_or_identity(iova: u64) -> u64 {
    translate_dma(iova).unwrap_or(iova)
}

pub fn info() -> IommuInfo {
    let st = IOMMU.lock();
    IommuInfo {
        hw_present: false,
        mode: "software-identity",
        windows: st.windows.len(),
        translates: st.translates,
    }
}

pub fn for_each_window(mut f: impl FnMut(&DmaWindow)) {
    let st = IOMMU.lock();
    for w in st.windows.iter() {
        f(w);
    }
}

/// Host-test helper: clear all windows (process-global).
#[cfg(test)]
pub fn reset_for_test() {
    let mut st = IOMMU.lock();
    st.windows.clear();
    st.translates = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_map_and_translate() {
        reset_for_test();
        map_identity(0x1000, 0x2000).unwrap();
        assert_eq!(translate_dma(0x1000), Some(0x1000));
        assert_eq!(translate_dma(0x1FFF), Some(0x1FFF));
        assert_eq!(translate_dma(0x3000), None);
        assert_eq!(translate_or_identity(0x3000), 0x3000);
        unmap(0x1000).unwrap();
        assert_eq!(translate_dma(0x1000), None);
    }

    #[test]
    fn rejects_overlap_and_unaligned() {
        reset_for_test();
        map_identity(0x1000, 0x2000).unwrap();
        assert_eq!(map_identity(0x2000, 0x1000), Err(IommuError::Overlap));
        assert_eq!(map_identity(0x1001, 0x1000), Err(IommuError::Unaligned));
        assert_eq!(map_identity(0x4000, 0), Err(IommuError::ZeroSize));
    }
}
