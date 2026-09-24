//! Boot ramdisk: a POSIX `ustar` archive of user programs (roadmap 2.1).
//!
//! `run_qemu.sh` builds the programs in `user/`, packs them reproducibly with
//! `tar --format=ustar`, and the bootloader loads the archive next to the
//! kernel. [`init`] adopts it from `BootInfo`; [`find`] and [`files`] expose
//! the regular files it contains.
//!
//! The archive is untrusted input, so the parser is strict: every header's
//! checksum is verified, sizes are bounds-checked against the archive, names
//! must be printable, and anything that is not a regular file is skipped.
//! Parsing stops at the first malformed header.

use spin::Once;

const BLOCK: usize = 512;
/// Longest file name kept (prefix + "/" + name, after stripping "./").
pub const MAX_NAME: usize = 64;

/// A regular file in the archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct File<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TarError {
    /// Header checksum does not match (offset of the header).
    BadChecksum(usize),
    /// Size field is not valid octal (offset of the header).
    BadSize(usize),
    /// File data would run past the end of the archive (offset of the header).
    Truncated(usize),
    /// Name is empty, too long, or not printable ASCII (offset of the header).
    BadName(usize),
    /// Missing `ustar` magic (offset of the header).
    NotUstar(usize),
}

/// Iterator over the regular files of a `ustar` archive.
pub struct Files<'a> {
    archive: &'a [u8],
    offset: usize,
    done: bool,
}

/// Iterate the regular files in `archive`. Yields `Err` once and then stops
/// if a header is malformed.
pub fn parse(archive: &[u8]) -> Files<'_> {
    Files {
        archive,
        offset: 0,
        done: false,
    }
}

impl<'a> Iterator for Files<'a> {
    type Item = Result<File<'a>, TarError>;

    fn next(&mut self) -> Option<Self::Item> {
        let archive = self.archive;
        while !self.done {
            let at = self.offset;
            let Some(header) = archive.get(at..at + BLOCK) else {
                self.done = true;
                return None;
            };
            // End of archive: a zero block.
            if header.iter().all(|&b| b == 0) {
                self.done = true;
                return None;
            }
            if &header[257..262] != b"ustar" {
                return self.fail(TarError::NotUstar(at));
            }
            if !checksum_ok(header) {
                return self.fail(TarError::BadChecksum(at));
            }
            let Some(size) = octal(&header[124..136]) else {
                return self.fail(TarError::BadSize(at));
            };
            let data_start = at + BLOCK;
            let data_end = match data_start.checked_add(size) {
                Some(end) if end <= archive.len() => end,
                _ => return self.fail(TarError::Truncated(at)),
            };
            self.offset = data_start + size.div_ceil(BLOCK) * BLOCK;

            // Only regular files ('0' or legacy NUL); skip dirs, links, etc.
            let typeflag = header[156];
            if typeflag != b'0' && typeflag != 0 {
                continue;
            }
            let Some(name) = file_name(header) else {
                return self.fail(TarError::BadName(at));
            };
            return Some(Ok(File {
                name,
                data: &archive[data_start..data_end],
            }));
        }
        None
    }
}

impl Files<'_> {
    /// Report `e` once and stop iterating.
    fn fail<T>(&mut self, e: TarError) -> Option<Result<T, TarError>> {
        self.done = true;
        Some(Err(e))
    }
}

/// Header checksum: sum of all bytes with the checksum field read as spaces.
fn checksum_ok(header: &[u8]) -> bool {
    let Some(stored) = octal(&header[148..156]) else {
        return false;
    };
    let sum: usize = header
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                b' ' as usize
            } else {
                b as usize
            }
        })
        .sum();
    sum == stored
}

/// Parse a NUL/space-terminated octal field.
fn octal(field: &[u8]) -> Option<usize> {
    let mut value: usize = 0;
    let mut digits = 0;
    for &b in field {
        match b {
            b'0'..=b'7' => {
                value = value.checked_mul(8)?.checked_add((b - b'0') as usize)?;
                digits += 1;
            }
            b' ' | 0 if digits == 0 => continue,
            b' ' | 0 => break,
            _ => return None,
        }
    }
    (digits > 0).then_some(value)
}

/// The file's name (without a leading "./"). Names with a ustar prefix are
/// rejected rather than joined, to keep borrowing simple and names short.
fn file_name(header: &[u8]) -> Option<&str> {
    if header[345] != 0 {
        return None;
    }
    let raw = &header[..100];
    let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let name = core::str::from_utf8(&raw[..len]).ok()?;
    let name = name.strip_prefix("./").unwrap_or(name);
    let ok =
        !name.is_empty() && name.len() <= MAX_NAME && name.bytes().all(|b| b.is_ascii_graphic());
    ok.then_some(name)
}

static RAMDISK: Once<&'static [u8]> = Once::new();

/// Adopt the ramdisk the bootloader mapped at `addr` (virtual) with `len`
/// bytes. Call once at boot.
///
/// # Safety
/// `addr..addr+len` must be mapped, readable, and never written or freed.
pub unsafe fn init(addr: u64, len: u64) {
    RAMDISK.call_once(|| core::slice::from_raw_parts(addr as *const u8, len as usize));
}

/// The raw ramdisk (empty if none was loaded).
pub fn archive() -> &'static [u8] {
    RAMDISK.get().copied().unwrap_or(&[])
}

/// Regular files in the ramdisk.
pub fn files() -> Files<'static> {
    parse(archive())
}

/// Look up a file by name.
pub fn find(name: &str) -> Option<File<'static>> {
    files().filter_map(Result::ok).find(|f| f.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    /// Build a ustar header + padded data for one entry.
    fn entry(name: &str, data: &[u8], typeflag: u8) -> Vec<u8> {
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        let size = std::format!("{:011o}\0", data.len());
        h[124..136].copy_from_slice(size.as_bytes());
        h[156] = typeflag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: usize = h.iter().map(|&b| b as usize).sum();
        h[148..156].copy_from_slice(std::format!("{:06o}\0 ", sum).as_bytes());
        let mut out = h.to_vec();
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
        out
    }

    fn archive(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out: Vec<u8> = entries.concat();
        out.extend_from_slice(&[0u8; 2 * BLOCK]);
        out
    }

    #[test]
    fn lists_regular_files_and_skips_directories() {
        let a = archive(&[
            entry("./", b"", b'5'),
            entry("./hello", b"\x7fELF-hello", b'0'),
            entry("./checksum", &[7u8; 700], b'0'),
        ]);
        let files: Vec<_> = parse(&a).collect::<Result<_, _>>().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "hello");
        assert_eq!(files[0].data, b"\x7fELF-hello");
        assert_eq!(files[1].name, "checksum");
        assert_eq!(files[1].data.len(), 700);
    }

    #[test]
    fn empty_archive_has_no_files() {
        assert_eq!(parse(&[]).count(), 0);
        assert_eq!(parse(&[0u8; 1024]).count(), 0);
    }

    #[test]
    fn bad_checksum_is_rejected() {
        let mut a = archive(&[entry("x", b"data", b'0')]);
        a[0] = b'y'; // change the name without fixing the checksum
        assert_eq!(parse(&a).next(), Some(Err(TarError::BadChecksum(0))));
    }

    #[test]
    fn size_past_end_is_rejected() {
        let e = entry("big", &[1u8; 600], b'0');
        let a = &e[..BLOCK + 100]; // cut the data short
        assert_eq!(parse(a).next(), Some(Err(TarError::Truncated(0))));
    }

    #[test]
    fn non_ustar_and_bad_names_are_rejected() {
        let mut a = archive(&[entry("x", b"", b'0')]);
        a[257] = b'X';
        assert_eq!(parse(&a).next(), Some(Err(TarError::NotUstar(0))));

        let a = archive(&[entry("bad name", b"", b'0')]);
        assert_eq!(parse(&a).next(), Some(Err(TarError::BadName(0))));
    }

    #[test]
    fn parsing_stops_after_an_error() {
        let mut a = archive(&[entry("a", b"1", b'0'), entry("b", b"2", b'0')]);
        a[BLOCK * 2] ^= 1; // corrupt the second header
        let results: Vec<_> = parse(&a).collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert_eq!(results[1], Err(TarError::BadChecksum(BLOCK * 2)));
    }

    #[test]
    fn octal_fields() {
        assert_eq!(octal(b"00000000017\0"), Some(15));
        assert_eq!(octal(b"  17 \0"), Some(15));
        assert_eq!(octal(b"\0\0\0"), None);
        assert_eq!(octal(b"0009"), None);
    }
}
