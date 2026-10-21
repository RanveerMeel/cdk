//! Distributed capabilities (roadmap 3.5), kernel side. Formats and the
//! trust model: [`cdk_link::peer`].
//!
//! * The registry's public key is pinned in the release-signed ramdisk
//!   (`registry.pub`, covered by the boot manifest).
//! * After the gateway accepts this node's attestation it sends a
//!   [`NodeCert`] for this boot's issuer key ([`on_node_cert`]); it must name
//!   *our* key and verify against the pinned registry.
//! * `cap-export` ([`export`]) turns an agent's handle into a
//!   [`PortableCap`] for one named peer node, signed by our issuer; the
//!   gateway writes it to its outbox.
//! * `cap-import` ([`check_import`]) verifies a peer's portable capability
//!   and the policy's `trust` rules; the console then grants the agent a
//!   handle on the local proxy object `peer:<node>/<object>` through the
//!   normal policy review, and only then marks the import used
//!   ([`mark_imported`]).
//!
//! Stage 2 ([`sync`], console `peer-sync`): an agent's messages on a proxy
//! object travel to the owning node as signed [`PeerMessage`]s through the
//! gateways' outbox/inbox, and incoming ones are verified *at the owning
//! node* — the sender's certificate, this node's own delegation to it (by
//! name, so it outlives this node's reboots until it expires), both
//! signatures, `send` permission, replay, and revocation ([`revoke`],
//! console `cap-revoke`) — before they are delivered to the named object.

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

use cdk_link::peer::{self, NodeCert, PeerMessage, PortableCap};
use cdk_link::secure::{Identity, Signature};
use spin::Mutex;

use crate::audit::{self, EventKind};
use crate::issuer::{self, SigDomain};

pub const REGISTRY_FILE: &str = "registry.pub";

static MY_CERT: Mutex<Option<NodeCert>> = Mutex::new(None);
/// Imports one boot can record; more are refused (see [`replay_check`]).
const REPLAY_CAPACITY: usize = 64;
/// `(issuer id, serial)` of every portable capability imported this boot.
static IMPORTED: Mutex<heapless::Vec<([u8; 16], u64), REPLAY_CAPACITY>> =
    Mutex::new(heapless::Vec::new());
static EXPORTS: AtomicU64 = AtomicU64::new(0);
/// The delegation behind each proxy object: `(proxy kind, PortableCap)`.
static GRANTS: Mutex<heapless::Vec<(heapless::String<32>, alloc::vec::Vec<u8>), 16>> =
    Mutex::new(heapless::Vec::new());
/// Serials of delegations this node revoked (from the gateway at
/// certification, plus `cap-revoke`).
static REVOKED: Mutex<heapless::Vec<u64, 128>> = Mutex::new(heapless::Vec::new());
/// Inbound messages one boot can record; more are refused.
const SEEN_CAPACITY: usize = 256;
/// `(sender issuer id, seq)` of every peer message delivered this boot.
static SEEN: Mutex<heapless::Vec<([u8; 16], u64), SEEN_CAPACITY>> = Mutex::new(heapless::Vec::new());
/// Sequence numbers of this boot's outbound peer messages.
static OUT_SEQ: AtomicU64 = AtomicU64::new(1);

/// Why an import was refused (audit `cap-import-rejected` detail).
pub mod reject {
    pub const NO_REGISTRY: u64 = 1;
    pub const BAD_SIGNATURE: u64 = 2;
    pub const NOT_FOR_US: u64 = 3;
    pub const REPLAYED: u64 = 4;
    pub const NOT_TRUSTED: u64 = 5;
    pub const MALFORMED: u64 = 6;
    pub const EXPIRED: u64 = 7;
    /// Peer messages: the delegation does not allow `send`.
    pub const NO_SEND: u64 = 8;
    /// Peer messages: the delegation was revoked.
    pub const REVOKED: u64 = 9;
    /// Peer messages: no object of that name on this node.
    pub const NO_OBJECT: u64 = 10;
}

/// The pinned registry key, if the ramdisk carries one.
pub fn registry() -> Option<Identity> {
    crate::initrd::find(REGISTRY_FILE).and_then(|f| Identity::from_bytes(f.data))
}

/// This boot's issuer public key in link form.
fn my_identity() -> Identity {
    let p = issuer::kernel().public();
    Identity {
        ed: p.ed25519,
        ml: p.mldsa65.clone(),
    }
}

/// This node's certified name, if certified.
pub fn node_name() -> Option<alloc::string::String> {
    MY_CERT.lock().as_ref().map(|c| c.name.clone())
}

/// `(name, serial, registry id)` of this node's certificate.
pub fn certificate() -> Option<(alloc::string::String, u64, [u8; 16])> {
    MY_CERT
        .lock()
        .as_ref()
        .map(|c| (c.name.clone(), c.serial, c.registry))
}

/// A certificate from the gateway for this boot.
pub fn on_node_cert(bytes: &[u8]) -> Result<alloc::string::String, &'static str> {
    let cert = NodeCert::decode(bytes).ok_or("malformed node certificate")?;
    let registry = registry().ok_or("no registry key pinned in the ramdisk")?;
    if cert.issuer != my_identity() {
        return Err("the certificate is for another key, not this boot's issuer");
    }
    if !issuer::crypto_stack::run(|| cert.verify(&registry)) {
        return Err("the certificate does not verify against the pinned registry");
    }
    let name = cert.name.clone();
    audit::record_fmt(
        EventKind::NodeCertified,
        format_args!("node:{}", name),
        cert.serial,
    );
    *MY_CERT.lock() = Some(cert);
    Ok(name)
}

/// Delegate `pid`'s handle `handle` to node `audience`, with `perms` (a
/// subset of the handle's; `None` = all of them). `object_name` maps the
/// handle's object id to its name; the caller holds the kernel (the console
/// does, so this must not lock it).
pub fn export(
    pid: u32,
    handle: u64,
    audience: &str,
    perms: Option<u64>,
    object_name: impl FnOnce(&str) -> Option<alloc::string::String>,
) -> Result<PortableCap, &'static str> {
    let cert = MY_CERT
        .lock()
        .clone()
        .ok_or("this node has no certificate (gateway with --registry-key, then link-secure)")?;
    if !peer::valid_node_name(audience) {
        return Err("node names: a-z 0-9 - _ (at most 16)");
    }
    if audience == cert.name {
        return Err("that is this node");
    }
    let cap = crate::agent::handle_cap(pid, handle).map_err(|_| "no such handle")?;
    let object = object_name(&cap.object_id).ok_or("the handle's object is gone")?;
    if object.starts_with(crate::policy::PEER_PREFIX) {
        return Err("re-delegating a peer's object is not supported (stage 1)");
    }
    if !peer::valid_object_name(&object) {
        return Err("only objects named with letters, digits, - _ . (at most 10) can be exported");
    }
    let held = cap.permission_mask();
    let mask = match perms {
        Some(p) if p & !held != 0 => return Err("cannot export permissions the handle does not hold"),
        Some(p) => p | (held & crate::policy::APPROVAL), // the approval gate stays
        None => held,
    };
    if mask & !crate::policy::APPROVAL == 0 {
        return Err("nothing to export");
    }
    let serial = {
        use rand_core::RngCore;
        (crate::rng::KernelRng.next_u64() & !0xFFFF) | (EXPORTS.fetch_add(1, Ordering::Relaxed) & 0xFFFF)
    };
    let mut pcap = PortableCap {
        cert: cert.clone(),
        object: object.clone(),
        perms: mask,
        audience: audience.into(),
        serial,
        not_after: cert.not_after,
        signature: Signature::from_slice(&[0; cdk_link::secure::SIG_LEN]).expect("length"),
    };
    let digest = pcap.digest();
    let sig = issuer::kernel().sign(SigDomain::PortableCap, &digest);
    pcap.signature = Signature {
        ed: sig.ed25519,
        ml: sig.mldsa65,
    };
    audit::record_fmt(
        EventKind::CapExported,
        format_args!("{}>{}:pid-{}", object, audience, pid),
        mask,
    );
    Ok(pcap)
}

/// A verified import, before the grant.
pub struct Accepted {
    pub node: alloc::string::String,
    pub object: alloc::string::String,
    /// `peer:<node>/<object>`.
    pub proxy: heapless::String<32>,
    /// Permissions to grant (with the approval bit if gated).
    pub mask: u64,
    /// Seconds until it expires (by the gateway's clock).
    pub valid_s: u64,
    issuer: [u8; 16],
    serial: u64,
    /// The portable capability, kept as the proxy's delegation.
    grant: alloc::vec::Vec<u8>,
}

/// Audit a refused import (`cap-import-rejected` with `reason`) and return the message for the console.
fn refused(subject: &str, reason: u64, msg: &'static str) -> &'static str {
    audit::record_fmt(EventKind::CapImportRejected, format_args!("{}", subject), reason);
    msg
}

/// Verify a peer's portable capability — `now u64 | capability` as the
/// gateway delivers it: certificate, signature, audience, expiry, replay,
/// and this node's `trust` policy.
pub fn check_import(delivered: &[u8]) -> Result<Accepted, &'static str> {
    let (now, bytes) = match delivered.split_at_checked(8) {
        Some((t, rest)) => (u64::from_le_bytes(t.try_into().unwrap_or([0; 8])), rest),
        None => return Err(refused("peer", reject::MALFORMED, "not a portable capability")),
    };
    let pcap = PortableCap::decode(bytes)
        .ok_or_else(|| refused("peer", reject::MALFORMED, "not a portable capability"))?;
    let subject = alloc::format!("peer:{}/{}", pcap.cert.name, pcap.object);
    let registry = registry()
        .ok_or_else(|| refused(&subject, reject::NO_REGISTRY, "no registry key pinned in the ramdisk"))?;
    let me = node_name()
        .ok_or_else(|| refused(&subject, reject::NOT_FOR_US, "this node has no certificate yet"))?;
    issuer::crypto_stack::run(|| pcap.verify(&registry, &me, now))
        .map_err(|e| refused(&subject, verify_reason(e), e))?;
    let issuer_id = pcap.cert.issuer.id();
    replay_check(&IMPORTED.lock(), issuer_id, pcap.serial)
        .map_err(|e| refused(&subject, reject::REPLAYED, e))?;
    let trusted = crate::policy::policy().trusted(&pcap.cert.name, &pcap.object);
    let mask = grant_mask(pcap.perms, trusted).ok_or_else(|| {
        refused(
            &subject,
            reject::NOT_TRUSTED,
            "policy does not trust that node for that object (trust <node> <object> <perms>)",
        )
    })?;
    let proxy = proxy_name(&pcap.cert.name, &pcap.object)
        .ok_or_else(|| refused(&subject, reject::MALFORMED, "proxy name too long"))?;
    Ok(Accepted {
        node: pcap.cert.name.clone(),
        object: pcap.object.clone(),
        proxy,
        mask,
        valid_s: pcap.not_after.saturating_sub(now),
        issuer: issuer_id,
        serial: pcap.serial,
        grant: bytes.to_vec(),
    })
}

/// Record a granted import so the same token cannot be used again.
/// `check_import` refuses imports once the list is full, so the push
/// cannot fail; nothing is ever evicted (that would reopen replay).
pub fn mark_imported(a: &Accepted) {
    if IMPORTED.lock().push((a.issuer, a.serial)).is_err() {
        crate::println!("peer: replay list full; import not recorded");
    }
    // The newest delegation backs the proxy's outbound messages.
    let mut grants = GRANTS.lock();
    grants.retain(|(p, _)| p != &a.proxy);
    if grants.push((a.proxy.clone(), a.grant.clone())).is_err() {
        crate::println!("peer: too many proxies; messages on {} cannot be forwarded", a.proxy);
    }
    drop(grants);
    audit::record_fmt(EventKind::CapImported, format_args!("{}", a.proxy), a.mask);
}

/// The reject code for an error from [`PortableCap::verify`].
fn verify_reason(e: &str) -> u64 {
    if e.contains("addressed") || e.contains("this node") {
        reject::NOT_FOR_US
    } else if e.contains("expired") || e.contains("outlives") {
        reject::EXPIRED
    } else {
        reject::BAD_SIGNATURE
    }
}

/// Refuse a capability imported before this boot, and fail closed once the
/// replay list is full (at most its capacity of imports per boot).
fn replay_check(seen: &[([u8; 16], u64)], issuer: [u8; 16], serial: u64) -> Result<(), &'static str> {
    if seen.iter().any(|(i, s)| *i == issuer && *s == serial) {
        return Err("already imported");
    }
    if seen.len() >= REPLAY_CAPACITY {
        return Err("replay list full: no more imports this boot");
    }
    Ok(())
}

/// What to grant for a peer's `offered` permissions and the policy's
/// `trusted` ones: their intersection, gated if either side asks for
/// approval; `None` if nothing effective remains.
fn grant_mask(offered: u64, trusted: u64) -> Option<u64> {
    let effect = offered & trusted & !crate::policy::APPROVAL;
    let gate = (offered | trusted) & crate::policy::APPROVAL;
    (effect != 0).then_some(effect | gate)
}

/// `peer:<node>/<object>`, or `None` if it does not fit an object kind.
fn proxy_name(node: &str, object: &str) -> Option<heapless::String<32>> {
    let mut proxy = heapless::String::new();
    core::fmt::write(&mut proxy, format_args!("{}{}/{}", crate::policy::PEER_PREFIX, node, object)).ok()?;
    Some(proxy)
}

// ---------------------------------------------------------------------------
// Transfers through the gateway (its capability outbox/inbox)
// ---------------------------------------------------------------------------

/// The gateway's answer to a request.
enum Answer {
    /// A successful status, with its note.
    Done(alloc::string::String),
    /// A blob of the requested kind.
    Blob(alloc::vec::Vec<u8>),
}

/// Wait up to `ms` for the gateway's answer: a status (a failed one is
/// `Err`), or a blob of `kind`. Revocation lists are applied as they come.
fn wait_answer(ms: u64, kind: u8) -> Result<Answer, alloc::string::String> {
    let start = crate::cpu::rdtsc();
    let mut asm = peer::BlobAssembler::default();
    let mut out: Option<Result<Answer, alloc::string::String>> = None;
    while out.is_none() && crate::cpu::rdtsc().wrapping_sub(start) < ms * 2_000_000 {
        crate::link::recv(|m| {
            let crate::link::Incoming::Sealed(p) = m else {
                return;
            };
            if cdk_link::approval::is_approval(p) {
                crate::approvals::on_message(p);
                return;
            }
            if let Some((ok, text)) = peer::decode_status(p) {
                out = Some(if ok { Ok(Answer::Done(text.into())) } else { Err(text.into()) });
            } else if p.first() == Some(&peer::BLOB) {
                if let Ok(Some((k, data))) = asm.push(p) {
                    if k == peer::kind::REVOCATIONS {
                        on_revocations(&data);
                    } else if k == kind {
                        out = Some(Ok(Answer::Blob(data)));
                    }
                }
            }
        });
        core::hint::spin_loop();
    }
    out.unwrap_or_else(|| Err("the gateway did not answer".into()))
}

/// Hand an exported capability to the gateway, which writes
/// `<file>.pcap` to its outbox. Returns the gateway's note.
pub fn send_export(file: &str, pcap: &PortableCap) -> Result<alloc::string::String, alloc::string::String> {
    if !crate::link::is_secure() {
        return Err("no secure link (run link-secure)".into());
    }
    if !peer::valid_file_name(file) {
        return Err("file names: letters, digits, - _ (at most 32)".into());
    }
    let mut payload = alloc::vec![file.len() as u8];
    payload.extend_from_slice(file.as_bytes());
    payload.extend_from_slice(&pcap.encode());
    for m in peer::encode_blob(peer::kind::EXPORT, &payload).ok_or("too large")? {
        if !matches!(crate::link::send_data(&m), Ok(true)) {
            return Err("send failed".into());
        }
    }
    match wait_answer(5_000, 0)? {
        Answer::Done(note) => Ok(note),
        Answer::Blob(_) => Err("unexpected answer".into()),
    }
}

/// Ask the gateway for `<file>.pcap` from its inbox.
pub fn fetch_import(file: &str) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
    if !crate::link::is_secure() {
        return Err("no secure link (run link-secure)".into());
    }
    if !peer::valid_file_name(file) {
        return Err("file names: letters, digits, - _ (at most 32)".into());
    }
    if !matches!(crate::link::send_data(&peer::encode_import_request(file)), Ok(true)) {
        return Err("send failed".into());
    }
    match wait_answer(5_000, peer::kind::IMPORT)? {
        Answer::Blob(b) => Ok(b),
        Answer::Done(_) => Err("unexpected answer".into()),
    }
}

/// Wait (during attestation) for the gateway's certificate for this boot.
pub fn await_certificate(ms: u64) {
    match wait_answer(ms, peer::kind::NODE_CERT) {
        Ok(Answer::Done(_)) => crate::println!("link: no node certificate (unexpected answer)"),
        Ok(Answer::Blob(bytes)) => match on_node_cert(&bytes) {
            Ok(name) => {
                let id = issuer::kernel().id();
                crate::println!(
                    "link: node certified as '{}' by the registry (issuer {:02x}{:02x}{:02x}{:02x}…)",
                    name,
                    id[0],
                    id[1],
                    id[2],
                    id[3]
                )
            }
            Err(e) => crate::println!("link: node certificate REJECTED: {}", e),
        },
        Err(e) => crate::println!("link: no node certificate ({})", e),
    }
}

// ---------------------------------------------------------------------------
// Stage 2: messages to peers' objects, and revocation
// ---------------------------------------------------------------------------

/// Apply a revocation list from the gateway (union with ours).
fn on_revocations(bytes: &[u8]) {
    let Some(serials) = peer::decode_revocations(bytes) else {
        crate::println!("peer: malformed revocation list ignored");
        return;
    };
    let mut r = REVOKED.lock();
    for s in serials {
        if !r.contains(&s) && r.push(s).is_err() {
            crate::println!("peer: revocation list full");
            break;
        }
    }
}

/// Serials this node has revoked.
pub fn revoked() -> heapless::Vec<u64, 128> {
    REVOKED.lock().clone()
}

/// Proxies with a delegation behind them.
pub fn proxies() -> heapless::Vec<heapless::String<32>, 16> {
    GRANTS.lock().iter().map(|(p, _)| p.clone()).collect()
}

/// Revoke this node's delegation `serial`: messages under it are refused
/// from now on; the gateway records it so later boots refuse them too.
pub fn revoke(serial: u64) -> Result<alloc::string::String, alloc::string::String> {
    {
        let mut r = REVOKED.lock();
        if !r.contains(&serial) {
            r.push(serial).map_err(|_| "revocation list full")?;
        }
    }
    audit::record_fmt(EventKind::CapRevoked, format_args!("serial"), serial);
    if !crate::link::is_secure() {
        return Ok("revoked for this boot only (no secure link to record it)".into());
    }
    if !matches!(crate::link::send_data(&peer::encode_revoke(serial)), Ok(true)) {
        return Ok("revoked for this boot only (send failed)".into());
    }
    match wait_answer(5_000, 0) {
        Ok(Answer::Done(note)) => Ok(note),
        Ok(Answer::Blob(_)) => Ok("revoked (unexpected answer)".into()),
        Err(e) => Ok(alloc::format!("revoked for this boot only ({e})")),
    }
}

/// What `peer-sync` did.
#[derive(Default)]
pub struct SyncReport {
    pub sent: usize,
    pub delivered: usize,
    pub rejected: usize,
}

/// Send the agents' messages on proxy objects to their owning nodes, then
/// deliver the messages waiting in the gateway's inbox. The caller holds
/// the kernel (the console), so it is passed in.
pub fn sync(kernel: &mut crate::kernel::Kernel) -> Result<SyncReport, alloc::string::String> {
    if !crate::link::is_secure() {
        return Err("no secure link (run link-secure)".into());
    }
    let me = MY_CERT
        .lock()
        .clone()
        .ok_or("this node has no certificate (gateway with --registry-key, then link-secure)")?;
    let mut report = SyncReport::default();

    // Outbound: each proxy's queue, under the delegation behind it.
    let grants = GRANTS.lock().clone();
    for (proxy, grant) in grants.iter() {
        let Some(grant) = PortableCap::decode(grant) else {
            continue;
        };
        let Ok(id) = kernel.resolve_object_ref(proxy) else {
            continue;
        };
        while let Ok(Some(msg)) = kernel.receive_message_direct(&id) {
            let payload: alloc::vec::Vec<u8> = match &msg.payload {
                crate::message::MessagePayload::Data(d) => d.to_vec(),
                crate::message::MessagePayload::Text(t)
                | crate::message::MessagePayload::Command(t) => t.as_bytes().to_vec(),
                _ => continue,
            };
            if payload.is_empty() || payload.len() > peer::MAX_MESSAGE {
                continue;
            }
            let from = if peer::valid_sender(&msg.from) { msg.from.as_str() } else { "agent" };
            let mut m = PeerMessage {
                sender: me.clone(),
                grant: grant.clone(),
                seq: OUT_SEQ.fetch_add(1, Ordering::Relaxed),
                from: from.into(),
                payload,
                signature: Signature::from_slice(&[0; cdk_link::secure::SIG_LEN]).expect("length"),
            };
            let sig = issuer::kernel().sign(SigDomain::PeerMessage, &m.digest());
            m.signature = Signature {
                ed: sig.ed25519,
                ml: sig.mldsa65,
            };
            for chunk in peer::encode_blob(peer::kind::OUTBOUND, &m.encode()).ok_or("message too large")? {
                if !matches!(crate::link::send_data(&chunk), Ok(true)) {
                    return Err("send failed (a drained message was lost)".into());
                }
            }
            match wait_answer(5_000, 0) {
                Ok(_) => {
                    report.sent += 1;
                    audit::record_fmt(
                        EventKind::PeerMessageSent,
                        format_args!("{}>{}", m.from, proxy),
                        m.seq,
                    );
                }
                Err(e) => return Err(alloc::format!("the gateway did not take a message: {e}")),
            }
        }
    }

    // Inbound: one at a time, each filed by the gateway as done or rejected.
    for _ in 0..64 {
        if !matches!(crate::link::send_data(&peer::encode_next_inbound()), Ok(true)) {
            return Err("send failed".into());
        }
        let data = match wait_answer(5_000, peer::kind::INBOUND)? {
            Answer::Done(_) => break, // inbox empty
            Answer::Blob(b) => b,
        };
        let Some((&n, rest)) = data.split_first() else {
            break;
        };
        let n = n as usize;
        let Some(name) = rest.get(..n).and_then(|b| core::str::from_utf8(b).ok()) else {
            break;
        };
        let name: heapless::String<32> = heapless::String::try_from(name).unwrap_or_default();
        let ok = match deliver(kernel, &rest[n..]) {
            Ok((from, object)) => {
                crate::println!("peer-sync: delivered a message from {} to {}", from, object);
                report.delivered += 1;
                true
            }
            Err(e) => {
                crate::println!("peer-sync: REFUSED {}: {}", name, e);
                report.rejected += 1;
                false
            }
        };
        let _ = crate::link::send_data(&peer::encode_inbound_done(&name, ok));
    }
    Ok(report)
}

/// Audit a refused inbound message and return the message.
fn refused_msg(subject: &str, reason: u64, msg: &'static str) -> &'static str {
    audit::record_fmt(EventKind::PeerMessageRejected, format_args!("{}", subject), reason);
    msg
}

/// Verify an inbound `now u64 | PeerMessage` and deliver it to the named
/// object. Returns `(sender label, object)`.
fn deliver(
    kernel: &mut crate::kernel::Kernel,
    delivered: &[u8],
) -> Result<(alloc::string::String, alloc::string::String), &'static str> {
    let (now, bytes) = match delivered.split_at_checked(8) {
        Some((t, rest)) => (u64::from_le_bytes(t.try_into().unwrap_or([0; 8])), rest),
        None => return Err(refused_msg("peer", reject::MALFORMED, "not a peer message")),
    };
    let m = PeerMessage::decode(bytes)
        .ok_or_else(|| refused_msg("peer", reject::MALFORMED, "not a peer message"))?;
    let label = alloc::format!("peer:{}/{}", m.sender.name, m.from);
    let subject = alloc::format!("{}>{}", label, m.grant.object);
    let registry = registry()
        .ok_or_else(|| refused_msg(&subject, reject::NO_REGISTRY, "no registry key pinned in the ramdisk"))?;
    let me = node_name()
        .ok_or_else(|| refused_msg(&subject, reject::NOT_FOR_US, "this node has no certificate yet"))?;
    issuer::crypto_stack::run(|| m.verify(&registry, &me, now))
        .map_err(|e| refused_msg(&subject, message_reason(e), e))?;
    message_policy(&m, &REVOKED.lock()).map_err(|(r, e)| refused_msg(&subject, r, e))?;
    let sender = m.sender.issuer.id();
    {
        let mut seen = SEEN.lock();
        if seen.iter().any(|(i, s)| *i == sender && *s == m.seq) {
            return Err(refused_msg(&subject, reject::REPLAYED, "already delivered"));
        }
        if seen.push((sender, m.seq)).is_err() {
            return Err(refused_msg(&subject, reject::REPLAYED, "replay list full: no more messages this boot"));
        }
    }
    let id = kernel
        .resolve_object_ref(&m.grant.object)
        .map_err(|_| refused_msg(&subject, reject::NO_OBJECT, "no object of that name on this node"))?;
    let msg = crate::message::Message::new(
        &label,
        &id,
        crate::message::MessagePayload::Data(
            heapless::Vec::from_slice(&m.payload).map_err(|_| "payload too large")?,
        ),
    )
    .map_err(|_| refused_msg(&subject, reject::MALFORMED, "message fields too long"))?;
    kernel
        .send_message_direct(&id, msg)
        .map_err(|_| refused_msg(&subject, reject::NO_OBJECT, "the object's queue is full"))?;
    audit::record_fmt(
        EventKind::PeerMessageDelivered,
        format_args!("{}", subject),
        m.payload.len() as u64,
    );
    Ok((label, m.grant.object.clone()))
}

/// The reject code for an error from [`PeerMessage::verify`].
fn message_reason(e: &str) -> u64 {
    if e.contains("expired") {
        reject::EXPIRED
    } else if e.contains("issued by this node") || e.contains("another node") {
        reject::NOT_FOR_US
    } else {
        reject::BAD_SIGNATURE
    }
}

/// This node's own checks on a verified message: the delegation allows
/// `send`, and it has not been revoked.
fn message_policy(m: &PeerMessage, revoked: &[u64]) -> Result<(), (u64, &'static str)> {
    let send = 1u64 << crate::capability::Permission::SendMessage.tag();
    if m.grant.perms & send == 0 {
        return Err((reject::NO_SEND, "the delegation does not allow send"));
    }
    if revoked.contains(&m.grant.serial) {
        return Err((reject::REVOKED, "the delegation was revoked"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Permission;

    fn bit(p: Permission) -> u64 {
        1 << p.tag()
    }

    /// The grant is the intersection, gated if either side asks.
    #[test]
    fn grant_is_the_intersection_and_keeps_the_gate() {
        let (send, recv, exec) = (
            bit(Permission::SendMessage),
            bit(Permission::ReceiveMessage),
            bit(Permission::Execute),
        );
        let gate = crate::policy::APPROVAL;
        assert_eq!(grant_mask(send | recv, send), Some(send), "only what both allow");
        assert_eq!(grant_mask(send, send | gate), Some(send | gate), "policy forces approval");
        assert_eq!(grant_mask(send | gate, send), Some(send | gate), "the peer's gate is kept");
        assert_eq!(grant_mask(exec, send), None, "nothing in common");
        assert_eq!(grant_mask(send, 0), None, "untrusted node or object");
        assert_eq!(grant_mask(gate, gate | send), None, "a gate alone grants nothing");
    }

    /// Every error from `PortableCap::verify` maps to its audit reason.
    #[test]
    fn verify_errors_map_to_reasons() {
        for (e, want) in [
            ("the node certificate is not signed by the pinned registry", reject::BAD_SIGNATURE),
            ("outlives its node certificate", reject::EXPIRED),
            ("expired", reject::EXPIRED),
            ("issued by this node", reject::NOT_FOR_US),
            ("addressed to another node", reject::NOT_FOR_US),
            ("grants no permission", reject::BAD_SIGNATURE),
            ("the issuing node's signature does not verify", reject::BAD_SIGNATURE),
        ] {
            assert_eq!(verify_reason(e), want, "{e}");
        }
    }

    /// Replays are refused, and a full list refuses rather than forgets.
    #[test]
    fn replay_list_fails_closed() {
        let mut seen: heapless::Vec<([u8; 16], u64), REPLAY_CAPACITY> = heapless::Vec::new();
        assert_eq!(replay_check(&seen, [1; 16], 7), Ok(()));
        seen.push(([1; 16], 7)).unwrap();
        assert_eq!(replay_check(&seen, [1; 16], 7), Err("already imported"));
        assert_eq!(replay_check(&seen, [2; 16], 7), Ok(()), "another issuer");
        while !seen.is_full() {
            let n = seen.len() as u64;
            seen.push(([3; 16], n)).unwrap();
        }
        assert!(replay_check(&seen, [9; 16], 1).is_err(), "full: refused");
        assert_eq!(replay_check(&seen, [1; 16], 7), Err("already imported"), "never forgotten");
    }

    /// The longest node and object names still fit an object kind.
    #[test]
    fn proxy_names_fit() {
        let node = "n".repeat(cdk_link::peer::MAX_NODE_NAME);
        let object = "o".repeat(cdk_link::peer::MAX_OBJECT_NAME);
        let p = proxy_name(&node, &object).unwrap();
        assert_eq!(p.len(), 32);
        assert!(proxy_name(&node, "toolongobject").is_none());
        assert_eq!(proxy_name("hq", "alerts").unwrap().as_str(), "peer:hq/alerts");
    }

    /// A verified message still needs `send` in the delegation and must not
    /// be revoked; verify errors map to their audit reasons.
    #[test]
    fn message_policy_and_reasons() {
        use cdk_link::peer::{NodeCert, PortableCap};
        use cdk_link::secure::hybrid::Keypair;
        let k = Keypair::from_seeds(&[1; 32], &[2; 32]);
        let zero = Signature::from_slice(&[0; cdk_link::secure::SIG_LEN]).unwrap();
        let cert = NodeCert {
            name: "hq".into(),
            issuer: k.public().clone(),
            registry: [0; 16],
            serial: 1,
            attested: [0; 32],
            not_after: 10,
            signature: zero.clone(),
        };
        let send = 1u64 << crate::capability::Permission::SendMessage.tag();
        let grant = |perms: u64, serial: u64| PortableCap {
            cert: cert.clone(),
            object: "alerts".into(),
            perms,
            audience: "branch".into(),
            serial,
            not_after: 10,
            signature: zero.clone(),
        };
        let msg = |g: PortableCap| PeerMessage {
            sender: cert.clone(),
            grant: g,
            seq: 1,
            from: "pid-1".into(),
            payload: alloc::vec![1],
            signature: zero.clone(),
        };
        assert_eq!(message_policy(&msg(grant(send, 5)), &[]), Ok(()));
        assert_eq!(
            message_policy(&msg(grant(1 << crate::capability::Permission::ReceiveMessage.tag(), 5)), &[]),
            Err((reject::NO_SEND, "the delegation does not allow send"))
        );
        assert_eq!(
            message_policy(&msg(grant(send, 5)), &[4, 5]),
            Err((reject::REVOKED, "the delegation was revoked"))
        );
        for (e, want) in [
            ("the sender's certificate is not signed by the pinned registry", reject::BAD_SIGNATURE),
            ("the sender's certificate has expired", reject::EXPIRED),
            ("the delegation's certificate is not signed by the pinned registry", reject::BAD_SIGNATURE),
            ("the delegation was not issued by this node", reject::NOT_FOR_US),
            ("the delegation was issued to another node", reject::NOT_FOR_US),
            ("the delegation has expired", reject::EXPIRED),
            ("the delegation's signature does not verify", reject::BAD_SIGNATURE),
            ("the sender's signature does not verify", reject::BAD_SIGNATURE),
        ] {
            assert_eq!(message_reason(e), want, "{e}");
        }
    }
}
