//! Minimal ELF64 loader (ET_EXEC / ET_DYN with PT_LOAD).
//!
//! Parses little-endian ELF64 headers, maps loadable segments into an
//! [`crate::paging::AddressSpace`], and returns the entry point. Host-testable
//! via [`parse`] / [`build_smoke_elf`].

use crate::allocator::{FrameAllocator, FRAME_SIZE};
use crate::paging::{AddressSpace, MapFlags, PageTableManager, PagingError};

pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_X86_64: u16 = 62;
pub const PT_LOAD: u32 = 1;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

const EI_NIDENT: usize = 16;
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    Truncated,
    BadMagic,
    BadClass,
    BadEndian,
    BadMachine,
    BadType,
    BadPhdr,
    Map(PagingError),
    OutOfFrames,
    SegmentOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElfImage<'a> {
    pub entry: u64,
    pub phoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

fn read_u16(b: &[u8], off: usize) -> Result<u16, ElfError> {
    let s = b.get(off..off + 2).ok_or(ElfError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(b: &[u8], off: usize) -> Result<u32, ElfError> {
    let s = b.get(off..off + 4).ok_or(ElfError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(b: &[u8], off: usize) -> Result<u64, ElfError> {
    let s = b.get(off..off + 8).ok_or(ElfError::Truncated)?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// Parse an ELF64 image header (does not load segments).
pub fn parse(bytes: &[u8]) -> Result<ElfImage<'_>, ElfError> {
    if bytes.len() < EHDR_SIZE {
        return Err(ElfError::Truncated);
    }
    if bytes[0..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }
    if bytes[4] != ELFCLASS64 {
        return Err(ElfError::BadClass);
    }
    if bytes[5] != ELFDATA2LSB {
        return Err(ElfError::BadEndian);
    }
    let e_type = read_u16(bytes, 16)?;
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(ElfError::BadType);
    }
    let e_machine = read_u16(bytes, 18)?;
    if e_machine != EM_X86_64 {
        return Err(ElfError::BadMachine);
    }
    let entry = read_u64(bytes, 24)?;
    let phoff = read_u64(bytes, 32)?;
    let phentsize = read_u16(bytes, 54)?;
    let phnum = read_u16(bytes, 56)?;
    if phentsize as usize != PHDR_SIZE {
        return Err(ElfError::BadPhdr);
    }
    Ok(ElfImage {
        entry,
        phoff,
        phentsize,
        phnum,
        bytes,
    })
}

pub fn program_header(img: &ElfImage<'_>, index: usize) -> Result<ProgramHeader, ElfError> {
    if index >= img.phnum as usize {
        return Err(ElfError::BadPhdr);
    }
    let off = (img.phoff as usize)
        .checked_add(index.checked_mul(PHDR_SIZE).ok_or(ElfError::SegmentOverflow)?)
        .ok_or(ElfError::SegmentOverflow)?;
    let b = img.bytes;
    Ok(ProgramHeader {
        p_type: read_u32(b, off)?,
        p_flags: read_u32(b, off + 4)?,
        p_offset: read_u64(b, off + 8)?,
        p_vaddr: read_u64(b, off + 16)?,
        p_filesz: read_u64(b, off + 32)?,
        p_memsz: read_u64(b, off + 40)?,
        p_align: read_u64(b, off + 48)?,
    })
}

fn flags_to_map(flags: u32) -> MapFlags {
    let exec = (flags & PF_X) != 0;
    let write = (flags & PF_W) != 0;
    if write {
        MapFlags::user_rw()
    } else if exec {
        MapFlags::user_rx()
    } else {
        MapFlags::user_rw() // read-only: use RW without exec; no dedicated RO helper
    }
}

fn map_zeroed_page(
    aspace: &mut AddressSpace,
    fa: &mut FrameAllocator,
    virt: u64,
    flags: MapFlags,
) -> Result<u64, ElfError> {
    let phys = fa.alloc().map_err(|_| ElfError::OutOfFrames)?.base_addr();
    unsafe {
        let p = crate::phys_mem::phys_to_mut_ptr::<u8>(phys);
        core::ptr::write_bytes(p, 0, FRAME_SIZE as usize);
    }
    aspace
        .tables()
        .map(virt, phys, flags, fa)
        .map_err(ElfError::Map)?;
    Ok(phys)
}

/// Load all `PT_LOAD` segments into `aspace` (page-aligned map + copy/zero).
pub fn load_into(
    img: &ElfImage<'_>,
    aspace: &mut AddressSpace,
    fa: &mut FrameAllocator,
) -> Result<u64, ElfError> {
    for i in 0..img.phnum as usize {
        let ph = program_header(img, i)?;
        if ph.p_type != PT_LOAD {
            continue;
        }
        if ph.p_memsz < ph.p_filesz {
            return Err(ElfError::SegmentOverflow);
        }
        let flags = flags_to_map(ph.p_flags);
        let start = ph.p_vaddr & !(FRAME_SIZE - 1);
        let end = ph
            .p_vaddr
            .checked_add(ph.p_memsz)
            .ok_or(ElfError::SegmentOverflow)?
            .wrapping_add(FRAME_SIZE - 1)
            & !(FRAME_SIZE - 1);
        let mut page = start;
        while page < end {
            let phys = match aspace.tables().translate(page) {
                Ok(p) => p,
                Err(_) => map_zeroed_page(aspace, fa, page, flags)?,
            };
            // Copy file bytes that land in this page.
            let seg_off = page.saturating_sub(ph.p_vaddr);
            if seg_off < ph.p_filesz {
                let file_off = ph
                    .p_offset
                    .checked_add(seg_off)
                    .ok_or(ElfError::SegmentOverflow)? as usize;
                let page_off = (ph.p_vaddr + seg_off - page) as usize;
                let avail = (ph.p_filesz - seg_off) as usize;
                let space = FRAME_SIZE as usize - page_off;
                let n = avail.min(space);
                let src = img
                    .bytes
                    .get(file_off..file_off + n)
                    .ok_or(ElfError::Truncated)?;
                unsafe {
                    let dst = crate::phys_mem::phys_to_mut_ptr::<u8>(phys).add(page_off);
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, n);
                }
            }
            page = page.wrapping_add(FRAME_SIZE);
        }
    }
    Ok(img.entry)
}

/// Build a tiny ELF64 ET_EXEC that maps code at `0x400000` and runs SYS_exit(0).
pub fn build_smoke_elf(out: &mut [u8]) -> Result<usize, ElfError> {
    // Layout: [Ehdr][Phdr][code...]
    const CODE_VADDR: u64 = 0x400000;
    const CODE: &[u8] = &[
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1  (SYS_EXIT)
        0x31, 0xFF, // xor edi, edi
        0x0F, 0x05, // syscall
        0x0F, 0x0B, // ud2
    ];
    let phoff = EHDR_SIZE as u64;
    let code_off = (EHDR_SIZE + PHDR_SIZE) as u64;
    let total = code_off as usize + CODE.len();
    if out.len() < total {
        return Err(ElfError::Truncated);
    }
    out[..total].fill(0);

    // e_ident
    out[0..4].copy_from_slice(&ELF_MAGIC);
    out[4] = ELFCLASS64;
    out[5] = ELFDATA2LSB;
    out[6] = 1; // EV_CURRENT
    // e_type, e_machine, e_version
    out[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    out[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[24..32].copy_from_slice(&CODE_VADDR.to_le_bytes());
    out[32..40].copy_from_slice(&phoff.to_le_bytes());
    out[52..54].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
    out[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
    out[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum

    // Phdr PT_LOAD
    let ph = &mut out[EHDR_SIZE..EHDR_SIZE + PHDR_SIZE];
    ph[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
    ph[4..8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    ph[8..16].copy_from_slice(&code_off.to_le_bytes());
    ph[16..24].copy_from_slice(&CODE_VADDR.to_le_bytes());
    ph[24..32].copy_from_slice(&CODE_VADDR.to_le_bytes()); // paddr
    let fsz = CODE.len() as u64;
    ph[32..40].copy_from_slice(&fsz.to_le_bytes());
    ph[40..48].copy_from_slice(&fsz.to_le_bytes());
    ph[48..56].copy_from_slice(&FRAME_SIZE.to_le_bytes());

    out[code_off as usize..total].copy_from_slice(CODE);
    let _ = EI_NIDENT;
    Ok(total)
}

/// Load smoke ELF into a fresh address space cloned from `kernel_pt`.
pub fn load_smoke(
    kernel_pt: &PageTableManager,
    fa: &mut FrameAllocator,
) -> Result<(AddressSpace, u64, u64), ElfError> {
    let mut blob = [0u8; 256];
    let n = build_smoke_elf(&mut blob)?;
    let img = parse(&blob[..n])?;
    let mut aspace = AddressSpace::from_kernel(kernel_pt, fa).map_err(ElfError::Map)?;
    let entry = load_into(&img, &mut aspace, fa)?;

    // User stack page just below 0x800000.
    const STACK_TOP: u64 = 0x800000;
    const STACK_PAGE: u64 = STACK_TOP - FRAME_SIZE;
    let _ = map_zeroed_page(&mut aspace, fa, STACK_PAGE, MapFlags::user_rw())?;
    Ok((aspace, entry, STACK_TOP))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_smoke_elf() {
        let mut blob = [0u8; 256];
        let n = build_smoke_elf(&mut blob).unwrap();
        let img = parse(&blob[..n]).unwrap();
        assert_eq!(img.entry, 0x400000);
        assert_eq!(img.phnum, 1);
        let ph = program_header(&img, 0).unwrap();
        assert_eq!(ph.p_type, PT_LOAD);
        assert_eq!(ph.p_vaddr, 0x400000);
        assert!(ph.p_filesz > 0);
    }

    #[test]
    fn reject_bad_magic() {
        let mut blob = [0u8; 64];
        assert_eq!(parse(&blob), Err(ElfError::BadMagic));
        blob[0..4].copy_from_slice(&ELF_MAGIC);
        blob[4] = 1; // 32-bit
        assert_eq!(parse(&blob), Err(ElfError::BadClass));
    }
}
