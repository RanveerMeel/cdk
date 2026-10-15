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
//!   gateway's nonce;
//! * endorsement (`cdk-gateway --tpm-ca`): `TPM2_NV_Read` of the
//!   manufacturer's EK certificate, `TPM2_CreatePrimary` of the standard
//!   ECC endorsement key, and `TPM2_ActivateCredential` (authorized by a
//!   `PolicySecret(endorsement)` session) to answer the gateway's challenge.
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
const CC_NV_READ_PUBLIC: u32 = 0x169;
const CC_NV_READ: u32 = 0x14E;
const CC_START_AUTH_SESSION: u32 = 0x176;
const CC_POLICY_SECRET: u32 = 0x151;
const CC_ACTIVATE_CREDENTIAL: u32 = 0x147;
const CC_FLUSH_CONTEXT: u32 = 0x165;
const RH_NULL: u32 = 0x4000_0007;
const SE_POLICY: u8 = 0x01;
const RH_ENDORSEMENT: u32 = 0x4000_000B;
const RS_PW: u32 = 0x4000_0009;
const ALG_SHA256: u16 = 0x000B;
const ALG_ECDSA: u16 = 0x0018;
const ALG_NULL: u16 = 0x0010;
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

/// `TPM2_CreatePrimary` under the endorsement hierarchy with `template`;
/// returns the handle and the public area the TPM created.
fn create_primary(template: &[u8]) -> Result<(u32, Vec<u8>)> {
    let cmd = Cmd::new(ST_SESSIONS, CC_CREATE_PRIMARY)
        .u32(RH_ENDORSEMENT)
        .password_session()
        .u16(4)
        .u16(0)
        .u16(0) // inSensitive: empty auth and data
        .tpm2b(template)
        .u16(0) // outsideInfo
        .u32(0) // creationPCR
        .finish();
    let r = transmit(&cmd)?;
    let mut p = Resp::new(&r);
    let handle = p.u32()?;
    p.u32()?; // parameterSize
    Ok((handle, p.tpm2b()?.to_vec()))
}

/// The P-256 point at the end of an ECC public area (`unique`).
fn ecc_point(public: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let n = public.len();
    let tail = public
        .get(n.wrapping_sub(68)..)
        .ok_or(TpmError::BadResponse)?;
    if tail[..2] != [0, 32] || tail[34..36] != [0, 32] {
        return Err(TpmError::BadResponse);
    }
    let x = tail[2..34].try_into().map_err(|_| TpmError::BadResponse)?;
    let y = tail[36..68].try_into().map_err(|_| TpmError::BadResponse)?;
    Ok((x, y))
}

/// `TPM2_CreatePrimary` of the AK under the endorsement hierarchy. The
/// public area the TPM returns must be exactly the template with a point.
pub fn create_ak() -> Result<Ak> {
    let (handle, public) = create_primary(&cdk_link::tpm::ak_public(None))?;
    let (x, y) = ecc_point(&public)?;
    if public != cdk_link::tpm::ak_public(Some((&x, &y))) {
        return Err(TpmError::BadResponse);
    }
    Ok(Ak { handle, x, y })
}

/// The endorsement key (standard template L-2) as a transient object.
pub struct Ek {
    pub handle: u32,
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// `TPM2_CreatePrimary` of the EK. Flush it with [`flush`] after use.
pub fn create_ek() -> Result<Ek> {
    let (handle, public) = create_primary(&cdk_link::tpm::ek_public(&[0; 32], &[0; 32]))?;
    let checked = ecc_point(&public).and_then(|(x, y)| {
        if public == cdk_link::tpm::ek_public(&x, &y) {
            Ok((x, y))
        } else {
            Err(TpmError::BadResponse)
        }
    });
    match checked {
        Ok((x, y)) => Ok(Ek { handle, x, y }),
        Err(e) => {
            let _ = flush(handle);
            Err(e)
        }
    }
}

/// `TPM2_FlushContext`.
pub fn flush(handle: u32) -> Result<()> {
    transmit(
        &Cmd::new(ST_NO_SESSIONS, CC_FLUSH_CONTEXT)
            .u32(handle)
            .finish(),
    )
    .map(|_| ())
}

/// The contents of an NV index readable with its own (empty) authorization,
/// such as the manufacturer's EK certificate.
pub fn nv_read(index: u32, max: usize) -> Result<Vec<u8>> {
    let r = transmit(
        &Cmd::new(ST_NO_SESSIONS, CC_NV_READ_PUBLIC)
            .u32(index)
            .finish(),
    )?;
    let mut p = Resp::new(&r);
    let public = p.tpm2b()?;
    let mut q = Resp(public, 0);
    q.u32()?; // nvIndex
    q.u16()?; // nameAlg
    q.u32()?; // attributes
    q.tpm2b()?; // authPolicy
    let size = q.u16()? as usize;
    if size == 0 || size > max {
        return Err(TpmError::BadResponse);
    }
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        let n = (size - out.len()).min(512);
        let cmd = Cmd::new(ST_SESSIONS, CC_NV_READ)
            .u32(index) // authHandle: the index itself
            .u32(index)
            .password_session()
            .u16(n as u16)
            .u16(out.len() as u16)
            .finish();
        let r = transmit(&cmd)?;
        let mut p = Resp::new(&r);
        p.u32()?; // parameterSize
        let data = p.tpm2b()?;
        if data.is_empty() || data.len() > n {
            return Err(TpmError::BadResponse);
        }
        out.extend_from_slice(data);
    }
    Ok(out)
}

/// `TPM2_ActivateCredential`: recover the gateway's secret, which only the
/// TPM holding both `ek` and `ak` can. The EK's policy is
/// `PolicySecret(TPM_RH_ENDORSEMENT)`, satisfied in a fresh policy session.
pub fn activate_credential(ak: &Ak, ek: &Ek, id_object: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    let r = transmit(
        &Cmd::new(ST_NO_SESSIONS, CC_START_AUTH_SESSION)
            .u32(RH_NULL) // tpmKey: unsalted
            .u32(RH_NULL) // bind: unbound
            .tpm2b(&[0x5A; 16]) // nonceCaller (no HMAC is computed)
            .u16(0) // encryptedSalt
            .u8(SE_POLICY)
            .u16(ALG_NULL) // symmetric
            .u16(ALG_SHA256)
            .finish(),
    )?;
    let session = Resp::new(&r).u32()?;
    let result = (|| {
        transmit(
            &Cmd::new(ST_SESSIONS, CC_POLICY_SECRET)
                .u32(RH_ENDORSEMENT)
                .u32(session)
                .password_session()
                .u16(0) // nonceTPM
                .u16(0) // cpHashA
                .u16(0) // policyRef
                .u32(0) // expiration
                .finish(),
        )?;
        let cmd = Cmd::new(ST_SESSIONS, CC_ACTIVATE_CREDENTIAL)
            .u32(ak.handle) // activateHandle (ADMIN role: the AK's empty password)
            .u32(ek.handle) // keyHandle (USER role: the policy session)
            .u32(18)
            .u32(RS_PW)
            .u16(0)
            .u8(0)
            .u16(0)
            .u32(session)
            .u16(0)
            .u8(0) // continueSession clear: the TPM ends the session
            .u16(0)
            .tpm2b(id_object)
            .tpm2b(secret)
            .finish();
        let r = transmit(&cmd)?;
        let mut p = Resp::new(&r);
        p.u32()?; // parameterSize
        Ok(p.tpm2b()?.to_vec())
    })();
    if result.is_err() {
        let _ = flush(session);
    }
    result
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
