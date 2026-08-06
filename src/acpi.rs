//! Minimal ACPI MADT parser for CPU / LAPIC discovery (roadmap reset M2).
//!
//! Walks RSDP → RSDT/XSDT → MADT and collects enabled local APICs.
//! Host unit tests use synthetic table bytes; bare metal maps via
//! [`crate::phys_mem`].

use heapless::Vec;

/// Maximum CPU entries we retain from MADT.
pub const MAX_MADT_CPUS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MadtCpu {
    pub apic_id: u32,
    pub enabled: bool,
    pub is_bsp: bool,
}

#[derive(Clone, Debug, Default)]
pub struct CpuTopology {
    pub cpus: Vec<MadtCpu, MAX_MADT_CPUS>,
    pub lapic_address: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    NoRsdp,
    BadSignature,
    BadChecksum,
    Truncated,
    NoMadt,
    TableFull,
}

type AcpiResult<T> = Result<T, AcpiError>;

/// Discover CPUs from an RSDP physical address.
pub fn discover_cpus_from_rsdp(rsdp_phys: u64) -> AcpiResult<CpuTopology> {
    let rsdp = read_bytes(rsdp_phys, 36)?;
    if &rsdp[0..8] != b"RSD PTR " {
        return Err(AcpiError::BadSignature);
    }
    if !checksum_ok(&rsdp[0..20]) {
        return Err(AcpiError::BadChecksum);
    }

    let revision = rsdp[15];
    let madt_phys = if revision >= 2 && rsdp.len() >= 36 && checksum_ok(&rsdp[0..36]) {
        let xsdt = u64_from_le(&rsdp[24..32]);
        find_madt_in_xsdt(xsdt)?
    } else {
        let rsdt = u32_from_le(&rsdp[16..20]) as u64;
        find_madt_in_rsdt(rsdt)?
    };
    parse_madt(madt_phys)
}

/// Parse a MADT at `madt_phys`.
pub fn parse_madt(madt_phys: u64) -> AcpiResult<CpuTopology> {
    let header = read_bytes(madt_phys, 44)?;
    if &header[0..4] != b"APIC" {
        return Err(AcpiError::BadSignature);
    }
    let length = u32_from_le(&header[4..8]) as usize;
    if length < 44 {
        return Err(AcpiError::Truncated);
    }
    let table = read_bytes(madt_phys, length)?;
    if !checksum_ok(&table) {
        return Err(AcpiError::BadChecksum);
    }

    let lapic_address = u32_from_le(&table[36..40]) as u64;
    let mut topo = CpuTopology {
        cpus: Vec::new(),
        lapic_address,
    };

    let mut off = 44usize;
    let mut first = true;
    while off + 2 <= table.len() {
        let entry_type = table[off];
        let entry_len = table[off + 1] as usize;
        if entry_len < 2 || off + entry_len > table.len() {
            break;
        }
        match entry_type {
            0 if entry_len >= 8 => {
                // Processor Local APIC
                let apic_id = table[off + 3] as u32;
                let flags = u32_from_le(&table[off + 4..off + 8]);
                let enabled = flags & 1 != 0;
                if enabled {
                    push_cpu(
                        &mut topo,
                        MadtCpu {
                            apic_id,
                            enabled,
                            is_bsp: first,
                        },
                    )?;
                    first = false;
                }
            }
            9 if entry_len >= 16 => {
                // Processor Local x2APIC
                let apic_id = u32_from_le(&table[off + 4..off + 8]);
                let flags = u32_from_le(&table[off + 8..off + 12]);
                let enabled = flags & 1 != 0;
                if enabled {
                    push_cpu(
                        &mut topo,
                        MadtCpu {
                            apic_id,
                            enabled,
                            is_bsp: first,
                        },
                    )?;
                    first = false;
                }
            }
            1 if entry_len >= 12 => {
                // I/O APIC
                let id = table[off + 2];
                let address = u32_from_le(&table[off + 4..off + 8]) as u64;
                let gsi_base = u32_from_le(&table[off + 8..off + 12]);
                crate::ioapic::note_ioapic(id, address, gsi_base);
            }
            2 if entry_len >= 10 => {
                // Interrupt Source Override
                let irq = table[off + 3];
                let gsi = u32_from_le(&table[off + 4..off + 8]);
                let flags = u16::from_le_bytes([table[off + 8], table[off + 9]]);
                crate::ioapic::note_iso(irq, gsi, flags);
            }
            _ => {}
        }
        off += entry_len;
    }

    if topo.cpus.is_empty() {
        return Err(AcpiError::NoMadt);
    }
    // MADT entry order is not guaranteed to start with the boot CPU; re-mark
    // the BSP from the APIC id of the core actually running this code. When
    // no entry matches (or on host), the first-enabled marking above stands.
    mark_bsp_by_apic_id(&mut topo, crate::cpu::cpuid_apic_id());
    Ok(topo)
}

/// Mark the CPU with `boot_apic_id` as BSP (clearing others) if present.
fn mark_bsp_by_apic_id(topo: &mut CpuTopology, boot_apic_id: u32) {
    if !topo.cpus.iter().any(|c| c.apic_id == boot_apic_id) {
        return;
    }
    for cpu in topo.cpus.iter_mut() {
        cpu.is_bsp = cpu.apic_id == boot_apic_id;
    }
}

/// Fallback topology when MADT is unavailable (BSP 0 + AP 1).
pub fn fallback_topology() -> CpuTopology {
    let mut topo = CpuTopology {
        cpus: Vec::new(),
        lapic_address: 0xFEE0_0000,
    };
    let _ = topo.cpus.push(MadtCpu {
        apic_id: 0,
        enabled: true,
        is_bsp: true,
    });
    let _ = topo.cpus.push(MadtCpu {
        apic_id: 1,
        enabled: true,
        is_bsp: false,
    });
    topo
}

fn push_cpu(topo: &mut CpuTopology, cpu: MadtCpu) -> AcpiResult<()> {
    if topo.cpus.iter().any(|c| c.apic_id == cpu.apic_id) {
        return Ok(());
    }
    topo.cpus.push(cpu).map_err(|_| AcpiError::TableFull)
}

fn find_madt_in_rsdt(rsdt_phys: u64) -> AcpiResult<u64> {
    let header = read_bytes(rsdt_phys, 36)?;
    if &header[0..4] != b"RSDT" {
        return Err(AcpiError::BadSignature);
    }
    let length = u32_from_le(&header[4..8]) as usize;
    let table = read_bytes(rsdt_phys, length)?;
    if !checksum_ok(&table) {
        return Err(AcpiError::BadChecksum);
    }
    let mut off = 36usize;
    while off + 4 <= table.len() {
        let entry = u32_from_le(&table[off..off + 4]) as u64;
        if let Ok(sig) = read_bytes(entry, 4) {
            if &sig == b"APIC" {
                return Ok(entry);
            }
        }
        off += 4;
    }
    Err(AcpiError::NoMadt)
}

fn find_madt_in_xsdt(xsdt_phys: u64) -> AcpiResult<u64> {
    let header = read_bytes(xsdt_phys, 36)?;
    if &header[0..4] != b"XSDT" {
        return Err(AcpiError::BadSignature);
    }
    let length = u32_from_le(&header[4..8]) as usize;
    let table = read_bytes(xsdt_phys, length)?;
    if !checksum_ok(&table) {
        return Err(AcpiError::BadChecksum);
    }
    let mut off = 36usize;
    while off + 8 <= table.len() {
        let entry = u64_from_le(&table[off..off + 8]);
        if let Ok(sig) = read_bytes(entry, 4) {
            if &sig == b"APIC" {
                return Ok(entry);
            }
        }
        off += 8;
    }
    Err(AcpiError::NoMadt)
}

fn read_bytes(phys: u64, len: usize) -> AcpiResult<Vec<u8, 4096>> {
    if len == 0 || len > 4096 {
        return Err(AcpiError::Truncated);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = phys;
        // Host tests inject via `parse_madt_bytes`.
        return Err(AcpiError::NoRsdp);
    }
    #[cfg(target_os = "none")]
    {
        let mut out = Vec::new();
        let ptr = crate::phys_mem::phys_to_ptr::<u8>(phys);
        for i in 0..len {
            // SAFETY: phys mapping established at boot; ACPI tables are readable.
            let b = unsafe { core::ptr::read_volatile(ptr.add(i)) };
            out.push(b).map_err(|_| AcpiError::Truncated)?;
        }
        Ok(out)
    }
}

fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b)) == 0
}

fn u32_from_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn u64_from_le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Host-test helper: parse MADT from a byte buffer (identity "phys" = pointer).
#[cfg(test)]
pub fn parse_madt_bytes(buf: &[u8]) -> AcpiResult<CpuTopology> {
    if buf.len() < 44 || &buf[0..4] != b"APIC" {
        return Err(AcpiError::BadSignature);
    }
    if !checksum_ok(buf) {
        return Err(AcpiError::BadChecksum);
    }
    let lapic_address = u32_from_le(&buf[36..40]) as u64;
    let mut topo = CpuTopology {
        cpus: Vec::new(),
        lapic_address,
    };
    let mut off = 44usize;
    let mut first = true;
    while off + 2 <= buf.len() {
        let entry_type = buf[off];
        let entry_len = buf[off + 1] as usize;
        if entry_len < 2 || off + entry_len > buf.len() {
            break;
        }
        if entry_type == 0 && entry_len >= 8 {
            let apic_id = buf[off + 3] as u32;
            let flags = u32_from_le(&buf[off + 4..off + 8]);
            if flags & 1 != 0 {
                push_cpu(
                    &mut topo,
                    MadtCpu {
                        apic_id,
                        enabled: true,
                        is_bsp: first,
                    },
                )?;
                first = false;
            }
        }
        off += entry_len;
    }
    if topo.cpus.is_empty() {
        Err(AcpiError::NoMadt)
    } else {
        Ok(topo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn madt_with_two_cpus() -> heapless::Vec<u8, 64> {
        let mut buf = heapless::Vec::<u8, 64>::new();
        // Standard ACPI SDT header (36) + MADT fields (8) = 44, then 2×8 entries.
        buf.extend_from_slice(b"APIC").unwrap();
        buf.extend_from_slice(&60u32.to_le_bytes()).unwrap();
        buf.push(1).unwrap(); // revision
        buf.push(0).unwrap(); // checksum placeholder
        buf.extend_from_slice(b"CDKOEM").unwrap(); // oem id (6)
        buf.extend_from_slice(b"TESTMADT").unwrap(); // oem table id (8)
        buf.extend_from_slice(&1u32.to_le_bytes()).unwrap(); // oem rev
        buf.extend_from_slice(b"CDKR").unwrap(); // creator id (4)
        buf.extend_from_slice(&1u32.to_le_bytes()).unwrap(); // creator rev
        buf.extend_from_slice(&0xFEE0_0000u32.to_le_bytes()).unwrap();
        buf.extend_from_slice(&0u32.to_le_bytes()).unwrap(); // flags
        assert_eq!(buf.len(), 44);
        // Local APIC #0
        buf.push(0).unwrap();
        buf.push(8).unwrap();
        buf.push(0).unwrap();
        buf.push(0).unwrap(); // apic id 0
        buf.extend_from_slice(&1u32.to_le_bytes()).unwrap();
        // Local APIC #1
        buf.push(0).unwrap();
        buf.push(8).unwrap();
        buf.push(1).unwrap();
        buf.push(1).unwrap(); // apic id 1
        buf.extend_from_slice(&1u32.to_le_bytes()).unwrap();
        assert_eq!(buf.len(), 60);
        let sum: u8 = buf.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        buf[9] = buf[9].wrapping_sub(sum);
        buf
    }

    #[test]
    fn parse_madt_bytes_finds_two_enabled_cpus() {
        let buf = madt_with_two_cpus();
        let topo = parse_madt_bytes(&buf).unwrap();
        assert_eq!(topo.cpus.len(), 2);
        assert_eq!(topo.cpus[0].apic_id, 0);
        assert!(topo.cpus[0].is_bsp);
        assert_eq!(topo.cpus[1].apic_id, 1);
        assert!(!topo.cpus[1].is_bsp);
        assert_eq!(topo.lapic_address, 0xFEE0_0000);
    }

    #[test]
    fn fallback_topology_has_bsp_and_ap() {
        let t = fallback_topology();
        assert_eq!(t.cpus.len(), 2);
        assert!(t.cpus[0].is_bsp);
    }

    #[test]
    fn bsp_remark_matches_boot_apic_id() {
        let buf = madt_with_two_cpus();
        let mut topo = parse_madt_bytes(&buf).unwrap();
        // Boot CPU is apic 1, not the first MADT entry.
        mark_bsp_by_apic_id(&mut topo, 1);
        assert!(!topo.cpus[0].is_bsp);
        assert!(topo.cpus[1].is_bsp);
        // Unknown boot id leaves the existing marking untouched.
        mark_bsp_by_apic_id(&mut topo, 99);
        assert!(topo.cpus[1].is_bsp);
    }
}
