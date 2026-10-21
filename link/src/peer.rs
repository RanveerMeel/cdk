//! Distributed capabilities (roadmap 3.5): node certificates and portable
//! capabilities, shared by the kernel and the gateway.
//!
//! **Node certificates.** A CDK kernel's issuer key is generated at every
//! boot, so peers cannot pin it. Instead a *registry authority* (the
//! gateway, holding the registry key) certifies it right after the node's
//! attestation has been accepted: [`NodeCert`] binds a node name to this
//! boot's issuer public key, hybrid-signed by the registry (FIPS 204 context
//! [`NODE_CONTEXT`]). Every node pins the registry's public key in its
//! release-signed ramdisk (`registry.pub`). A reboot means a new key and a
//! new certificate; tokens from the previous boot stop verifying.
//!
//! **Portable capabilities.** [`PortableCap`] lets node A delegate a
//! capability on one of its objects (named by the object's stable name) to
//! node B: the node certificate, the object name, the permissions, the
//! audience (B's node name) and a serial, hybrid-signed by A's issuer
//! (context [`PORTABLE_CONTEXT`]). B accepts it only if the certificate
//! chains to the registry, the signature verifies under the certified key,
//! B is the audience, it has not expired, the serial was not used before
//! (this boot), and B's policy trusts A for that object (`trust <node>
//! <object> <perms>`).
//!
//! **Expiry.** Kernels have no trusted clock; gateways do, and the gateway
//! is the registry authority here. A certificate is valid until its
//! `not_after` (Unix seconds, set by the registry); a portable capability
//! carries its own `not_after`, never later than its certificate's. The
//! importing gateway supplies the current time with the capability. Until
//! then a capability can be imported once per boot of the receiving node
//! (its agents' handles do not survive a reboot either).
//!
//! ```text
//! NodeCert    : "CDK-NODE-CERT-v1" | name_len u8 | name | issuer ed [32] | issuer ml [1952]
//!               | registry id [16] | serial u64 | attested [32] | not_after u64  (signed)
//!               | signature [3373]
//! PortableCap : "CDK-PCAP-v1" | cert_len u16 | cert | obj_len u8 | object | perms u64
//!               | aud_len u8 | audience | serial u64 | not_after u64       (signed)
//!               | signature [3373]
//! Blob chunk  : 0x44 | kind u8 | total u16 | offset u16 | bytes     (link messages)
//! ImportReq   : 0x45 | name_len u8 | name
//! Import blob : now u64 (the gateway's clock, Unix seconds) | portable capability
//! PeerStatus  : 0x46 | ok u8 | text
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::secure::{hybrid, Identity, Signature, IDENTITY_LEN, SIG_LEN};

/// FIPS 204 context of registry signatures on node certificates.
pub const NODE_CONTEXT: &[u8] = b"CDK-NODE-v1";
/// FIPS 204 context of a node's signature on a portable capability.
pub const PORTABLE_CONTEXT: &[u8] = b"CDK-PCAP-v1";
const CERT_MAGIC: &[u8] = b"CDK-NODE-CERT-v1";
const PCAP_MAGIC: &[u8] = b"CDK-PCAP-v1";

pub const MAX_NODE_NAME: usize = 16;
/// Longest object name a portable capability carries (so that
/// `peer:<node>/<object>` fits a 32-byte object kind on the importer).
pub const MAX_OBJECT_NAME: usize = 10;
/// Largest portable capability or certificate accepted.
pub const MAX_BLOB: usize = 16 * 1024;
const BLOB_DATA: usize = 512;

pub const BLOB: u8 = 0x44;
pub const IMPORT_REQUEST: u8 = 0x45;
pub const PEER_STATUS: u8 = 0x46;
/// Attestation-request flag: the gateway will certify this node.
pub const CERTIFY: u8 = 0x02;

/// Blob kinds.
pub mod kind {
    /// Gateway → CDK: this node's certificate.
    pub const NODE_CERT: u8 = 1;
    /// CDK → gateway: `name_len u8 | file name | portable capability`.
    pub const EXPORT: u8 = 2;
    /// Gateway → CDK: a portable capability read from the inbox.
    pub const IMPORT: u8 = 3;
}

/// Node names: 1..=16 of `a-z 0-9 - _`.
pub fn valid_node_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NODE_NAME
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
}

/// Object names in portable capabilities: 1..=10 of `a-z A-Z 0-9 - _ .`.
pub fn valid_object_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_OBJECT_NAME
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// The next `n` bytes, or `None` if fewer remain.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    /// One byte.
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    /// A little-endian `u16`.
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    /// A little-endian `u64`.
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    /// A length-prefixed UTF-8 name that `valid` accepts.
    fn name(&mut self, valid: fn(&str) -> bool) -> Option<String> {
        let n = self.u8()? as usize;
        let s = core::str::from_utf8(self.take(n)?).ok()?;
        valid(s).then(|| String::from(s))
    }
}

/// A registry's certificate for one boot of one node.
#[derive(Clone, Debug)]
pub struct NodeCert {
    pub name: String,
    pub issuer: Identity,
    /// Id of the registry key that signed it.
    pub registry: [u8; 16],
    pub serial: u64,
    /// What the registry attested before certifying (a digest of the
    /// node's measured-boot registers and TPM PCRs).
    pub attested: [u8; 32],
    /// Valid until (Unix seconds).
    pub not_after: u64,
    pub signature: Signature,
}

impl NodeCert {
    /// The fields the registry signs, in order (`CDK-NODE-CERT-v1` ...).
    fn signed_part(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(CERT_MAGIC.len() + 1 + self.name.len() + IDENTITY_LEN + 56);
        v.extend_from_slice(CERT_MAGIC);
        v.push(self.name.len() as u8);
        v.extend_from_slice(self.name.as_bytes());
        let mut id = alloc::vec![0u8; IDENTITY_LEN];
        self.issuer.write_to(&mut id);
        v.extend_from_slice(&id);
        v.extend_from_slice(&self.registry);
        v.extend_from_slice(&self.serial.to_le_bytes());
        v.extend_from_slice(&self.attested);
        v.extend_from_slice(&self.not_after.to_le_bytes());
        v
    }

    /// The digest the registry signs.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.signed_part()).into()
    }

    /// The certificate's wire form: the signed part, then the signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.signed_part();
        let mut sig = alloc::vec![0u8; SIG_LEN];
        self.signature.write_to(&mut sig);
        v.extend_from_slice(&sig);
        v
    }

    /// Strict decoding (canonical: exactly one encoding per certificate).
    pub fn decode(b: &[u8]) -> Option<NodeCert> {
        let mut r = Reader(b);
        if r.take(CERT_MAGIC.len())? != CERT_MAGIC {
            return None;
        }
        let name = r.name(valid_node_name)?;
        let issuer = Identity::from_bytes(r.take(IDENTITY_LEN)?)?;
        let registry = r.take(16)?.try_into().ok()?;
        let serial = r.u64()?;
        let attested = r.take(32)?.try_into().ok()?;
        let not_after = r.u64()?;
        let signature = Signature::from_slice(r.take(SIG_LEN)?)?;
        r.0.is_empty().then_some(NodeCert {
            name,
            issuer,
            registry,
            serial,
            attested,
            not_after,
            signature,
        })
    }

    /// Signed by `registry` (and naming it).
    pub fn verify(&self, registry: &Identity) -> bool {
        self.registry == registry.id()
            && hybrid::verify_with(registry, &self.digest(), &self.signature, NODE_CONTEXT)
    }
}

/// A capability one node delegates to another.
#[derive(Clone, Debug)]
pub struct PortableCap {
    pub cert: NodeCert,
    /// The object's name on the issuing node.
    pub object: String,
    /// Permission mask (the kernel's capability permission bits).
    pub perms: u64,
    /// The only node that may import it.
    pub audience: String,
    /// Unique per issuer, so each export is imported at most once.
    pub serial: u64,
    /// Valid until (Unix seconds); at most the certificate's.
    pub not_after: u64,
    pub signature: Signature,
}

impl PortableCap {
    /// The fields the issuing node signs, in order, including the encoded certificate.
    fn signed_part(&self, cert: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(PCAP_MAGIC.len() + 2 + cert.len() + 48);
        v.extend_from_slice(PCAP_MAGIC);
        v.extend_from_slice(&(cert.len() as u16).to_le_bytes());
        v.extend_from_slice(cert);
        v.push(self.object.len() as u8);
        v.extend_from_slice(self.object.as_bytes());
        v.extend_from_slice(&self.perms.to_le_bytes());
        v.push(self.audience.len() as u8);
        v.extend_from_slice(self.audience.as_bytes());
        v.extend_from_slice(&self.serial.to_le_bytes());
        v.extend_from_slice(&self.not_after.to_le_bytes());
        v
    }

    /// The digest the issuing node signs (covers the certificate too).
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.signed_part(&self.cert.encode())).into()
    }

    /// The portable capability's wire form: the signed part, then the signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.signed_part(&self.cert.encode());
        let mut sig = alloc::vec![0u8; SIG_LEN];
        self.signature.write_to(&mut sig);
        v.extend_from_slice(&sig);
        v
    }

    /// Strict decoding (canonical: exactly one encoding per capability).
    pub fn decode(b: &[u8]) -> Option<PortableCap> {
        if b.len() > MAX_BLOB {
            return None;
        }
        let mut r = Reader(b);
        if r.take(PCAP_MAGIC.len())? != PCAP_MAGIC {
            return None;
        }
        let cert_len = r.u16()? as usize;
        let cert = NodeCert::decode(r.take(cert_len)?)?;
        let object = r.name(valid_object_name)?;
        let perms = r.u64()?;
        let audience = r.name(valid_node_name)?;
        let serial = r.u64()?;
        let not_after = r.u64()?;
        let signature = Signature::from_slice(r.take(SIG_LEN)?)?;
        r.0.is_empty().then_some(PortableCap {
            cert,
            object,
            perms,
            audience,
            serial,
            not_after,
            signature,
        })
    }

    /// Everything except the importer's policy and replay: the certificate
    /// chains to `registry`, the issuer signed this, it is addressed to
    /// `me` and not from `me`, and it has not expired at `now`.
    pub fn verify(&self, registry: &Identity, me: &str, now: u64) -> Result<(), &'static str> {
        if !self.cert.verify(registry) {
            return Err("the node certificate is not signed by the pinned registry");
        }
        if self.not_after > self.cert.not_after {
            return Err("outlives its node certificate");
        }
        if now > self.not_after {
            return Err("expired");
        }
        if self.cert.name == me {
            return Err("issued by this node");
        }
        if self.audience != me {
            return Err("addressed to another node");
        }
        if self.perms == 0 {
            return Err("grants no permission");
        }
        if !hybrid::verify_with(
            &self.cert.issuer,
            &self.digest(),
            &self.signature,
            PORTABLE_CONTEXT,
        ) {
            return Err("the issuing node's signature does not verify");
        }
        Ok(())
    }
}

/// Split `data` into blob chunk messages of `kind`.
pub fn encode_blob(kind: u8, data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.is_empty() || data.len() > MAX_BLOB {
        return None;
    }
    let total = data.len() as u16;
    Some(
        data.chunks(BLOB_DATA)
            .enumerate()
            .map(|(i, c)| {
                let mut m = Vec::with_capacity(6 + c.len());
                m.push(BLOB);
                m.push(kind);
                m.extend_from_slice(&total.to_le_bytes());
                m.extend_from_slice(&((i * BLOB_DATA) as u16).to_le_bytes());
                m.extend_from_slice(c);
                m
            })
            .collect(),
    )
}

/// Reassembles blob chunks (in order; a chunk at offset 0 restarts).
#[derive(Default)]
pub struct BlobAssembler {
    kind: u8,
    total: usize,
    data: Vec<u8>,
}

impl BlobAssembler {
    /// Add a chunk; returns `(kind, data)` when the blob is complete.
    pub fn push(&mut self, msg: &[u8]) -> Result<Option<(u8, Vec<u8>)>, &'static str> {
        let r = msg.strip_prefix(&[BLOB]).ok_or("not a blob chunk")?;
        if r.len() < 6 {
            return Err("short blob chunk");
        }
        let kind = r[0];
        let total = u16::from_le_bytes([r[1], r[2]]) as usize;
        let offset = u16::from_le_bytes([r[3], r[4]]) as usize;
        let data = &r[5..];
        if total == 0 || total > MAX_BLOB || data.is_empty() || data.len() > BLOB_DATA {
            return Err("blob chunk with a bad size");
        }
        if offset == 0 {
            self.kind = kind;
            self.total = total;
            self.data.clear();
        }
        if kind != self.kind
            || total != self.total
            || offset != self.data.len()
            || offset + data.len() > total
        {
            self.total = 0;
            self.data.clear();
            return Err("blob chunk out of order");
        }
        self.data.extend_from_slice(data);
        if self.data.len() == self.total {
            self.total = 0;
            return Ok(Some((self.kind, core::mem::take(&mut self.data))));
        }
        Ok(None)
    }
}

/// `ImportReq` for the inbox file `name`.
pub fn encode_import_request(name: &str) -> Vec<u8> {
    let mut m = alloc::vec![IMPORT_REQUEST, name.len() as u8];
    m.extend_from_slice(name.as_bytes());
    m
}

/// The file name of an `ImportReq`, if well formed.
pub fn decode_import_request(b: &[u8]) -> Option<&str> {
    let r = b.strip_prefix(&[IMPORT_REQUEST])?;
    let (&n, rest) = r.split_first()?;
    let s = core::str::from_utf8(rest).ok()?;
    (rest.len() == n as usize && valid_file_name(s)).then_some(s)
}

/// File names in the gateway's capability inbox/outbox: 1..=32 of
/// `a-z A-Z 0-9 - _`.
pub fn valid_file_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

/// `PeerStatus`: success or failure, with a short note (at most 200 bytes).
pub fn encode_status(ok: bool, text: &str) -> Vec<u8> {
    let mut m = alloc::vec![PEER_STATUS, ok as u8];
    // Cut at a character boundary, or the receiver's UTF-8 check fails.
    let mut end = text.len().min(200);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    m.extend_from_slice(&text.as_bytes()[..end]);
    m
}

/// `(ok, note)` of a `PeerStatus`.
pub fn decode_status(b: &[u8]) -> Option<(bool, &str)> {
    let r = b.strip_prefix(&[PEER_STATUS])?;
    let (&ok, text) = r.split_first()?;
    Some((ok == 1, core::str::from_utf8(text).ok()?))
}

/// Messages of this module.
pub fn is_peer(msg: &[u8]) -> bool {
    matches!(msg.first(), Some(&(BLOB | IMPORT_REQUEST | PEER_STATUS)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::hybrid::Keypair;

    /// A node certificate for `node`'s key, signed by `registry`.
    fn cert(registry: &Keypair, node: &Keypair, name: &str) -> NodeCert {
        let mut c = NodeCert {
            name: name.into(),
            issuer: node.public().clone(),
            registry: registry.public().id(),
            serial: 7,
            attested: [3; 32],
            not_after: 2_000,
            signature: Signature::from_slice(&[0; SIG_LEN]).unwrap(),
        };
        c.signature = registry.sign_with(&c.digest(), NODE_CONTEXT);
        c
    }

    /// A portable capability on `object` for `audience`, signed by `node`.
    fn pcap(node: &Keypair, cert: NodeCert, object: &str, audience: &str) -> PortableCap {
        let mut p = PortableCap {
            cert,
            object: object.into(),
            perms: 0b11_0000,
            audience: audience.into(),
            serial: 42,
            not_after: 1_500,
            signature: Signature::from_slice(&[0; SIG_LEN]).unwrap(),
        };
        p.signature = node.sign_with(&p.digest(), PORTABLE_CONTEXT);
        p
    }

    /// Certificates and portable capabilities round-trip, verify, and refuse every tampering, wrong audience and expiry.
    #[test]
    fn certificates_and_portable_capabilities() {
        let registry = Keypair::from_seeds(&[1; 32], &[2; 32]);
        let hq = Keypair::from_seeds(&[3; 32], &[4; 32]);
        let c = cert(&registry, &hq, "hq");
        assert!(c.verify(registry.public()));
        let enc = c.encode();
        let back = NodeCert::decode(&enc).unwrap();
        assert_eq!(back.encode(), enc);
        assert!(back.verify(registry.public()));

        // Another registry, or a tampered name: refused.
        let other = Keypair::from_seeds(&[5; 32], &[6; 32]);
        assert!(!c.verify(other.public()));
        let mut renamed = c.clone();
        renamed.name = "branch".into();
        assert!(!renamed.verify(registry.public()));

        let p = pcap(&hq, c.clone(), "alerts", "branch");
        let enc = p.encode();
        let back = PortableCap::decode(&enc).unwrap();
        assert_eq!(back.encode(), enc);
        assert_eq!(back.verify(registry.public(), "branch", 1_000), Ok(()));
        assert_eq!(
            back.verify(registry.public(), "other", 1_000),
            Err("addressed to another node")
        );
        assert_eq!(
            back.verify(registry.public(), "hq", 1_000),
            Err("issued by this node")
        );
        assert!(back.verify(other.public(), "branch", 1_000).is_err());

        // Expired, or claiming to outlive the certificate: refused.
        assert_eq!(
            back.verify(registry.public(), "branch", 1_501),
            Err("expired")
        );
        let mut longer_lived = back.clone();
        longer_lived.not_after = 3_000;
        assert_eq!(
            longer_lived.verify(registry.public(), "branch", 1_000),
            Err("outlives its node certificate")
        );
        // Widened permissions, another object, or a forged issuer: refused.
        let mut wider = back.clone();
        wider.perms |= 1 << 3;
        assert!(wider.verify(registry.public(), "branch", 1_000).is_err());
        let mut moved = back.clone();
        moved.object = "ledger".into();
        assert!(moved.verify(registry.public(), "branch", 1_000).is_err());
        let mallory = Keypair::from_seeds(&[9; 32], &[9; 32]);
        let forged = pcap(&mallory, c, "alerts", "branch");
        assert!(forged.verify(registry.public(), "branch", 1_000).is_err());

        // Truncated or extended encodings: rejected.
        assert!(PortableCap::decode(&enc[..enc.len() - 1]).is_none());
        let mut longer = enc.clone();
        longer.push(0);
        assert!(PortableCap::decode(&longer).is_none());
    }

    /// Name rules, blob reassembly (in order, bounded) and the small message codecs.
    #[test]
    fn names_and_blobs() {
        assert!(valid_node_name("hq-1") && !valid_node_name("HQ") && !valid_node_name(""));
        assert!(!valid_node_name("a-very-long-node-name"));
        assert!(valid_object_name("alerts") && !valid_object_name("a/b"));
        assert!(valid_file_name("to-branch_1") && !valid_file_name("../x"));
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let msgs = encode_blob(kind::EXPORT, &data).unwrap();
        assert!(msgs.iter().all(|m| m.len() <= crate::secure::MAX_PLAINTEXT));
        let mut a = BlobAssembler::default();
        let mut out = None;
        for m in &msgs {
            out = a.push(m).unwrap();
        }
        assert_eq!(out, Some((kind::EXPORT, data)));
        let mut a = BlobAssembler::default();
        a.push(&msgs[0]).unwrap();
        assert!(a.push(&msgs[2]).is_err());
        assert_eq!(
            decode_import_request(&encode_import_request("x1")),
            Some("x1")
        );
        assert_eq!(
            decode_status(&encode_status(true, "ok")),
            Some((true, "ok"))
        );
        // A long non-ASCII note is cut at a character boundary and decodes.
        let long = "€".repeat(100); // 300 bytes; byte 200 is inside a '€'
        let status = encode_status(false, &long);
        let (ok, note) = decode_status(&status).unwrap();
        assert!(!ok && note.len() == 198 && note.chars().all(|c| c == '€'));
    }
}
