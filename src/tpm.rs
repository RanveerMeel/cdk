//! TPM 2.0 driver (roadmap 4.2, hardware root): the TIS interface at the
//! standard MMIO address (QEMU `tpm-tis` with swtpm, and real TPM chips
//! in TIS mode), and the commands CDK needs:
//!
//! * `TPM2_Startup` (if the firmware did not already start the TPM);
//! * `TPM2_PCR_Extend` — CDK's three boot measurements into PCRs 8, 9, 10;
//! * `TPM2_CreatePrimary` — an attestation key (AK) under the endorsement
//!   hierarchy: a *restricted* ECDSA P-256 signing key, so the TPM will
//!   only sign structures it generated itself (quotes), never data CDK
//!   supplies; the same template gives the same key on every boot; `noDA`
//!   since its authorization is empty;
//! * `TPM2_PCR_Read` and `TPM2_Quote` — PCRs 0..=12 signed over the
//!   gateway's nonce.
//!
//! Commands are built by hand (big-endian, TPM 2.0 Part 3) with the empty
//! password session, since CDK sets no TPM authorization values.

extern crate alloc;

use alloc::vec::Vec;

/// TIS locality 0.
pub const TIS_BASE: u64 = 0xFED4_0000;
const ACCESS: u64 = 0x00;
const STS: u64 = 0x18;
const DATA_FIFO: u64 = 0x24;
const DID_VID: u64 = 0xF00;

const ACCESS_VALID: u8 = 0x80;
const ACCESS_ACTIVE: u8 = 0x20;
const ACCESS_REQUEST_USE: u8 = 0x02;
const STS_VALID: u32 = 0x80;
const STS_COMMAND_READY: u32 = 0x40;
const STS_GO: u32 = 0x20;
const STS_DATA_AVAIL: u32 = 0x10;
const STS_EXPECT: u32 = 0x08;

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const CC_STARTUP: u32 = 0x144;
const CC_PCR_EXTEND: u32 = 0x182;
const CC_PCR_READ: u32 = 0x17E;
const CC_CREATE_PRIMARY: u32 = 0x131;
const CC_QUOTE: u32 = 0x158;
const RH_ENDORSEMENT: u32 = 0x4000_000B;
const RS_PW: u32 = 0x4000_0009;
const ALG_SHA256: u16 = 0x000B;
const ALG_ECC: u16 = 0x0023;
const ALG_ECDSA: u16 = 0x0018;
const ALG_NULL: u16 = 0x0010;
const ECC_NIST_P256: u16 = 0x0003;
/// fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA |
/// restricted | sign. `noDA`: the key has an empty authorization value, so
/// there is nothing to guess; without it the TPM's dictionary-attack
/// protection, which counts every unclean power-off, eventually refuses
/// quotes (TPM_RC_LOCKOUT).
const AK_ATTRIBUTES: u32 =
    0x0000_0002 | 0x0000_0010 | 0x0000_0020 | 0x0000_0040 | 0x0000_0400 | 0x0001_0000 | 0x0004_0000;
/// TPM_RC_INITIALIZE: TPM2_Startup was already done (by the firmware).
const RC_INITIALIZE: u32 = 0x100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpmError {
    /// Nothing answers at the TIS address.
    Absent,
    Timeout,
    /// The TPM returned a non-zero response code.
    Rc(u32),
    /// A response shorter or longer than its header says, or malformed.
    BadResponse,
}

pub type Result<T> = core::result::Result<T, TpmError>;

fn reg(off: u64) -> u64 {
    TIS_BASE + off
}

fn r8(off: u64) -> u8 {
    // SAFETY: TIS registers are identity-mapped uncached (see `main.rs`)
    // before any function here is called.
    unsafe { core::ptr::read_volatile(reg(off) as *const u8) }
}

fn w8(off: u64, v: u8) {
    unsafe { core::ptr::write_volatile(reg(off) as *mut u8, v) }
}

fn r32(off: u64) -> u32 {
    unsafe { core::ptr::read_volatile(reg(off) as *const u32) }
}

fn wait(mut done: impl FnMut() -> bool) -> Result<()> {
    let start = crate::cpu::rdtsc();
    // ~5 s at the 2 GHz the kernel assumes elsewhere; key generation is the
    // slowest command.
    while !done() {
        if crate::cpu::rdtsc().wrapping_sub(start) > 10_000_000_000 {
            return Err(TpmError::Timeout);
        }
        core::hint::spin_loop();
    }
    Ok(())
}

fn burst_count() -> usize {
    ((r32(STS) >> 8) & 0xFFFF) as usize
}

/// Whether a TPM answers at the TIS address. The page must be mapped.
pub fn probe() -> bool {
    let id = r32(DID_VID);
    id != 0 && id != 0xFFFF_FFFF
}

/// Vendor and device id (for the boot log).
pub fn did_vid() -> u32 {
    r32(DID_VID)
}

fn request_locality() -> Result<()> {
    if r8(ACCESS) & (ACCESS_VALID | ACCESS_ACTIVE) == (ACCESS_VALID | ACCESS_ACTIVE) {
        return Ok(());
    }
    w8(ACCESS, ACCESS_REQUEST_USE);
    wait(|| r8(ACCESS) & (ACCESS_VALID | ACCESS_ACTIVE) == (ACCESS_VALID | ACCESS_ACTIVE))
}

/// TPM_RC_YIELDED, TPM_RC_TESTING, TPM_RC_RETRY: warnings that mean "send
/// the same command again".
const RC_TRY_AGAIN: [u32; 3] = [0x908, 0x90A, 0x922];

/// Send one command and return the whole response, checking its response
/// code; commands the TPM asks to retry are retried a few times.
fn transmit(cmd: &[u8]) -> Result<Vec<u8>> {
    let mut tries = 0;
    loop {
        match transmit_once(cmd) {
            Err(TpmError::Rc(rc)) if RC_TRY_AGAIN.contains(&rc) && tries < 20 => {
                tries += 1;
                let start = crate::cpu::rdtsc();
                while crate::cpu::rdtsc().wrapping_sub(start) < 20_000_000 {
                    core::hint::spin_loop(); // ~10 ms
                }
            }
            r => return r,
        }
    }
}

fn transmit_once(cmd: &[u8]) -> Result<Vec<u8>> {
    request_locality()?;
    w8(STS, STS_COMMAND_READY as u8);
    wait(|| r32(STS) & STS_COMMAND_READY != 0)?;
    let mut i = 0;
    while i < cmd.len() {
        wait(|| burst_count() > 0)?;
        let n = burst_count().min(cmd.len() - i);
        for &b in &cmd[i..i + n] {
            w8(DATA_FIFO, b);
        }
        i += n;
    }
    // The TPM has the whole command when it no longer expects data.
    wait(|| {
        let s = r32(STS);
        s & STS_VALID != 0 && s & STS_EXPECT == 0
    })?;
    w8(STS, STS_GO as u8);
    wait(|| r32(STS) & (STS_VALID | STS_DATA_AVAIL) == (STS_VALID | STS_DATA_AVAIL))?;
    let mut resp = Vec::new();
    let mut want = 10usize;
    while resp.len() < want {
        wait(|| burst_count() > 0 || r32(STS) & STS_DATA_AVAIL == 0)?;
        if r32(STS) & STS_DATA_AVAIL == 0 {
            break;
        }
        let n = burst_count().min(want - resp.len());
        for _ in 0..n {
            resp.push(r8(DATA_FIFO));
        }
        if resp.len() >= 6 && want == 10 {
            want = u32::from_be_bytes(resp[2..6].try_into().unwrap_or([0; 4])) as usize;
            if !(10..=4096).contains(&want) {
                return Err(TpmError::BadResponse);
            }
        }
    }
    w8(STS, STS_COMMAND_READY as u8);
    if resp.len() != want || resp.len() < 10 {
        return Err(TpmError::BadResponse);
    }
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap_or([0; 4]));
    if rc != 0 {
        return Err(TpmError::Rc(rc));
    }
    Ok(resp)
}

/// Command builder: header filled in by [`Cmd::finish`].
struct Cmd(Vec<u8>);

impl Cmd {
    fn new(tag: u16, cc: u32) -> Self {
        let mut v = Vec::with_capacity(128);
        v.extend_from_slice(&tag.to_be_bytes());
        v.extend_from_slice(&[0; 4]);
        v.extend_from_slice(&cc.to_be_bytes());
        Cmd(v)
    }
    fn u8(mut self, x: u8) -> Self {
        self.0.push(x);
        self
    }
    fn u16(mut self, x: u16) -> Self {
        self.0.extend_from_slice(&x.to_be_bytes());
        self
    }
    fn u32(mut self, x: u32) -> Self {
        self.0.extend_from_slice(&x.to_be_bytes());
        self
    }
    fn bytes(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }
    fn tpm2b(self, b: &[u8]) -> Self {
        self.u16(b.len() as u16).bytes(b)
    }
    /// Authorization area with the empty password session.
    fn password_session(self) -> Self {
        self.u32(9).u32(RS_PW).u16(0).u8(0).u16(0)
    }
    /// One SHA-256 PCR selection.
    fn pcr_selection(self, select: &[u8]) -> Self {
        self.u32(1)
            .u16(ALG_SHA256)
            .u8(select.len() as u8)
            .bytes(select)
    }
    fn finish(mut self) -> Vec<u8> {
        let len = (self.0.len() as u32).to_be_bytes();
        self.0[2..6].copy_from_slice(&len);
        self.0
    }
}

/// Response reader.
struct Resp<'a>(&'a [u8], usize);

impl<'a> Resp<'a> {
    fn new(r: &'a [u8]) -> Self {
        Resp(r, 10)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self
            .0
            .get(self.1..self.1 + n)
            .ok_or(TpmError::BadResponse)?;
        self.1 += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| TpmError::BadResponse)?,
        ))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| TpmError::BadResponse)?,
        ))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// `TPM2_Startup(CLEAR)`; fine if the firmware already did it.
pub fn startup() -> Result<()> {
    match transmit(&Cmd::new(ST_NO_SESSIONS, CC_STARTUP).u16(0).finish()) {
        Ok(_) | Err(TpmError::Rc(RC_INITIALIZE)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// `TPM2_PCR_Extend(pcr, sha256 digest)`.
pub fn pcr_extend(pcr: u32, digest: &[u8; 32]) -> Result<()> {
    let cmd = Cmd::new(ST_SESSIONS, CC_PCR_EXTEND)
        .u32(pcr)
        .password_session()
        .u32(1)
        .u16(ALG_SHA256)
        .bytes(digest)
        .finish();
    transmit(&cmd).map(|_| ())
}

/// SHA-256 PCR values for the PCRs set in `select` (at most 8 per call, as
/// TPMs return).
fn pcr_read_one(select: &[u8; 3]) -> Result<Vec<[u8; 32]>> {
    let r = transmit(
        &Cmd::new(ST_NO_SESSIONS, CC_PCR_READ)
            .pcr_selection(select)
            .finish(),
    )?;
    let mut p = Resp::new(&r);
    p.u32()?; // pcrUpdateCounter
    let count = p.u32()?; // pcrSelectionOut
    for _ in 0..count {
        p.u16()?;
        let n = p.u8()? as usize;
        p.take(n)?;
    }
    let n = p.u32()? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(p.tpm2b()?.try_into().map_err(|_| TpmError::BadResponse)?);
    }
    Ok(out)
}

/// The quoted PCRs 0..=12 (SHA-256).
pub fn pcr_read_quoted() -> Result<[[u8; 32]; cdk_link::tpm::QUOTED_PCRS]> {
    let mut v = pcr_read_one(&[0xFF, 0x00, 0x00])?;
    v.extend(pcr_read_one(&[0x00, 0x1F, 0x00])?);
    let mut out = [[0u8; 32]; cdk_link::tpm::QUOTED_PCRS];
    if v.len() != out.len() {
        return Err(TpmError::BadResponse);
    }
    out.copy_from_slice(&v);
    Ok(out)
}

/// The attestation key: a transient handle and its public point.
#[derive(Clone, Copy)]
pub struct Ak {
    pub handle: u32,
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// `TPM2_CreatePrimary` of the AK under the endorsement hierarchy.
pub fn create_ak() -> Result<Ak> {
    let mut public = Cmd::new(0, 0); // reuse the builder for the TPMT_PUBLIC body
    public.0.clear();
    let public = public
        .u16(ALG_ECC)
        .u16(ALG_SHA256)
        .u32(AK_ATTRIBUTES)
        .u16(0) // authPolicy
        .u16(ALG_NULL) // symmetric
        .u16(ALG_ECDSA)
        .u16(ALG_SHA256) // scheme
        .u16(ECC_NIST_P256)
        .u16(ALG_NULL) // kdf
        .u16(0)
        .u16(0) // unique x, y
        .0;
    let cmd = Cmd::new(ST_SESSIONS, CC_CREATE_PRIMARY)
        .u32(RH_ENDORSEMENT)
        .password_session()
        .u16(4)
        .u16(0)
        .u16(0) // inSensitive: empty auth and data
        .tpm2b(&public)
        .u16(0) // outsideInfo
        .u32(0) // creationPCR
        .finish();
    let r = transmit(&cmd)?;
    let mut p = Resp::new(&r);
    let handle = p.u32()?;
    p.u32()?; // parameterSize
    let pubarea = p.tpm2b()?;
    let mut q = Resp(pubarea, 0);
    if q.u16()? != ALG_ECC {
        return Err(TpmError::BadResponse);
    }
    q.u16()?; // nameAlg
    q.u32()?; // attributes
    q.tpm2b()?; // authPolicy
    if q.u16()? != ALG_NULL {
        return Err(TpmError::BadResponse); // symmetric must be NULL for a signing key
    }
    if q.u16()? != ALG_ECDSA {
        return Err(TpmError::BadResponse);
    }
    q.u16()?; // scheme hash
    if q.u16()? != ECC_NIST_P256 {
        return Err(TpmError::BadResponse);
    }
    if q.u16()? != ALG_NULL {
        return Err(TpmError::BadResponse); // kdf
    }
    let x: [u8; 32] = q.tpm2b()?.try_into().map_err(|_| TpmError::BadResponse)?;
    let y: [u8; 32] = q.tpm2b()?.try_into().map_err(|_| TpmError::BadResponse)?;
    Ok(Ak { handle, x, y })
}

/// `TPM2_Quote` of PCRs 0..=12 with `nonce` as qualifying data. Returns the
/// `TPMS_ATTEST` and the ECDSA signature `(r, s)`.
pub fn quote(ak: &Ak, nonce: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let cmd = Cmd::new(ST_SESSIONS, CC_QUOTE)
        .u32(ak.handle)
        .password_session()
        .tpm2b(nonce)
        .u16(ALG_NULL) // use the key's scheme
        .pcr_selection(&cdk_link::tpm::PCR_SELECT)
        .finish();
    let r = transmit(&cmd)?;
    let mut p = Resp::new(&r);
    p.u32()?; // parameterSize
    let attest = p.tpm2b()?.to_vec();
    if p.u16()? != ALG_ECDSA {
        return Err(TpmError::BadResponse);
    }
    p.u16()?; // hash
    let sig_r = p.tpm2b()?.to_vec();
    let sig_s = p.tpm2b()?.to_vec();
    Ok((attest, sig_r, sig_s))
}
