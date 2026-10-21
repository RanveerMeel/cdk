//! Registry authority for distributed capabilities (roadmap 3.5).
//!
//! With `--registry-key FILE --registry-auth FILE`, the gateway certifies
//! the CDK it serves: once that CDK's attestation is accepted, it signs a
//! [`NodeCert`] binding its node name to the issuer key CDK used in this
//! session's handshake, and sends it to CDK. Certifying needs attestation
//! (`--expect`, `--tpm` or `--tpm-ca`), so only a measured, verified boot
//! gets a name.
//!
//! The gateway holds only its own certifying key and a [`NodeAuthority`]
//! for **one node name**, signed by the registry root (`cdk-sign
//! node-authority NAME --root ROOT-KEY`). The root key (`cdk-sign init`)
//! stays offline; its public half is every node's `registry.pub`. A
//! compromised gateway can therefore certify only its own node.
//!
//! The gateway also carries portable capabilities and peer messages
//! between nodes: CDK's exports go to `--cap-dir DIR/outbox/<file>.pcap`,
//! imports are read from `DIR/inbox/<file>.pcap`; outbound messages go to
//! `DIR/outbox/msg-*.pmsg`, inbound ones are read from `DIR/inbox/*.pmsg`
//! and filed under `inbox/done/` or `inbox/rejected/` once CDK has decided.
//! It is only a courier — CDK verifies everything. It also keeps this
//! node's revocations (`DIR/revoked`) and hands them to CDK with each
//! certificate; a courier can only add revocations, never remove CDK's.

use std::path::{Path, PathBuf};

use cdk_link::peer::{self, NodeCert, PortableCap};
use cdk_link::secure::{hybrid, Identity, Signature, SIG_LEN};
use rand_core::{OsRng, RngCore};

/// Default certificate lifetime: 24 hours.
pub const DEFAULT_VALIDITY_S: u64 = 24 * 3600;

/// The gateway's clock in Unix seconds (0 if the clock is before 1970).
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub struct Registry {
    key: hybrid::Keypair,
    authority: peer::NodeAuthority,
    pub node: String,
    /// Certificate lifetime in seconds (capped by the authority's).
    pub validity_s: u64,
}

/// Load a 64-byte hybrid seed file (0600).
pub fn load_key(path: &Path) -> Result<hybrid::Keypair, String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{} must not be readable by group or others (chmod 600)",
            path.display()
        ));
    }
    let seeds = zeroize::Zeroizing::new(std::fs::read(path).map_err(|e| e.to_string())?);
    if seeds.len() != 64 {
        return Err(format!("{} is not a 64-byte hybrid key", path.display()));
    }
    let (mut ed, mut ml) = ([0u8; 32], [0u8; 32]);
    ed.copy_from_slice(&seeds[..32]);
    ml.copy_from_slice(&seeds[32..]);
    let key = hybrid::Keypair::from_seeds(&ed, &ml);
    zeroize::Zeroize::zeroize(&mut ed);
    zeroize::Zeroize::zeroize(&mut ml);
    Ok(key)
}

impl Registry {
    /// Load this gateway's certifying key and its node authority; `node`,
    /// if given, must be the authority's name.
    pub fn load(key: &Path, authority: &Path, node: Option<&str>) -> Result<Registry, String> {
        let key = load_key(key)?;
        let auth = std::fs::read(authority).map_err(|e| format!("{}: {e}", authority.display()))?;
        let authority = peer::NodeAuthority::decode(&auth).ok_or_else(|| {
            format!(
                "{} is not a node authority (cdk-sign node-authority)",
                authority.display()
            )
        })?;
        if &authority.key != key.public() {
            return Err("the node authority is for another key than --registry-key".into());
        }
        if let Some(n) = node {
            if n != authority.node {
                return Err(format!(
                    "--node {n}, but the authority is for node '{}'",
                    authority.node
                ));
            }
        }
        if authority.not_after <= now() {
            return Err("the node authority has expired".into());
        }
        Ok(Registry {
            node: authority.node.clone(),
            key,
            authority,
            validity_s: DEFAULT_VALIDITY_S,
        })
    }

    /// The id of the registry root this gateway's authority chains to.
    pub fn root_id(&self) -> [u8; 16] {
        self.authority.root
    }

    /// Certify `issuer` (the key CDK proved in this session's handshake)
    /// after an attestation summarized by `attested`.
    pub fn certify(&self, issuer: &Identity, attested: [u8; 32]) -> NodeCert {
        let mut cert = NodeCert {
            name: self.node.clone(),
            issuer: issuer.clone(),
            registry: self.authority.root,
            serial: OsRng.next_u64(),
            attested,
            not_after: (now() + self.validity_s).min(self.authority.not_after),
            authority: self.authority.clone(),
            signature: Signature::from_slice(&[0; SIG_LEN]).expect("length"),
        };
        cert.signature = self.key.sign_with(&cert.digest(), peer::NODE_CONTEXT);
        cert
    }
}

/// The gateway's capability outbox/inbox.
pub struct CapDir(pub PathBuf);

impl CapDir {
    /// Queue an outbound peer message as `outbox/msg-<time>-<random>.pmsg`.
    pub fn write_outbound(&self, pmsg: &[u8]) -> Result<String, String> {
        let m = peer::PeerMessage::decode(pmsg).ok_or("not a peer message")?;
        let dir = self.0.join("outbox");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let name = format!("msg-{}-{:08x}", now(), OsRng.next_u32());
        let tmp = dir.join(format!("{name}.tmp"));
        std::fs::write(&tmp, pmsg).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, dir.join(format!("{name}.pmsg"))).map_err(|e| e.to_string())?;
        eprintln!(
            "gateway: peer message from '{}' ({}) to '{}' on '{}' -> outbox/{name}.pmsg",
            m.sender.name, m.from, m.grant.cert.name, m.grant.object
        );
        Ok(name)
    }

    /// The oldest inbound peer message as `name_len | name | now | message`.
    pub fn next_inbound(&self) -> Option<Vec<u8>> {
        let dir = self.0.join("inbox");
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .ok()?
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().into_string().ok()?;
                let stem = n.strip_suffix(".pmsg")?;
                peer::valid_file_name(stem).then(|| stem.to_string())
            })
            .collect();
        names.sort();
        for name in names {
            let Ok(data) = std::fs::read(dir.join(format!("{name}.pmsg"))) else {
                continue;
            };
            if data.len() + 64 > peer::MAX_BLOB {
                let _ = self.file_inbound(&name, false);
                continue;
            }
            let mut out = vec![name.len() as u8];
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&now().to_le_bytes());
            out.extend_from_slice(&data);
            return Some(out);
        }
        None
    }

    /// File an inbound message under `inbox/done/` or `inbox/rejected/`.
    pub fn file_inbound(&self, name: &str, accepted: bool) -> Result<(), String> {
        if !peer::valid_file_name(name) {
            return Err("bad file name".into());
        }
        let inbox = self.0.join("inbox");
        let to = inbox.join(if accepted { "done" } else { "rejected" });
        std::fs::create_dir_all(&to).map_err(|e| e.to_string())?;
        let file = format!("{name}.pmsg");
        std::fs::rename(inbox.join(&file), to.join(&file)).map_err(|e| e.to_string())
    }

    /// This node's revocations, recorded by `cap-revoke`.
    pub fn revocations(&self) -> Vec<u64> {
        std::fs::read_to_string(self.0.join("revoked"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| u64::from_str_radix(l.trim(), 16).ok())
            .collect()
    }

    /// Record a revocation (idempotent).
    pub fn add_revocation(&self, serial: u64) -> Result<(), String> {
        if self.revocations().contains(&serial) {
            return Ok(());
        }
        std::fs::create_dir_all(&self.0).map_err(|e| e.to_string())?;
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.0.join("revoked"))
            .and_then(|mut f| writeln!(f, "{serial:016x}"))
            .map_err(|e| e.to_string())
    }

    /// Write an export (`name_len | name | portable capability`) to the
    /// outbox; returns the path.
    pub fn write_export(&self, payload: &[u8]) -> Result<PathBuf, String> {
        let (&n, rest) = payload.split_first().ok_or("empty export")?;
        let n = n as usize;
        let name = std::str::from_utf8(rest.get(..n).ok_or("short export")?)
            .ok()
            .filter(|s| peer::valid_file_name(s))
            .ok_or("bad file name")?;
        let pcap = &rest[n..];
        let p = PortableCap::decode(pcap).ok_or("not a portable capability")?;
        let dir = self.0.join("outbox");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("{name}.pcap"));
        let tmp = dir.join(format!("{name}.tmp"));
        std::fs::write(&tmp, pcap).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        eprintln!(
            "gateway: exported capability '{}' from node '{}' for node '{}', valid {} more s -> {}",
            p.object,
            p.cert.name,
            p.audience,
            p.not_after.saturating_sub(now()),
            path.display()
        );
        Ok(path)
    }

    /// Read `<name>.pcap` from the inbox, prefixed with the current time
    /// (Unix seconds, little-endian u64) for CDK's expiry check.
    pub fn read_import(&self, name: &str) -> Result<Vec<u8>, String> {
        if !peer::valid_file_name(name) {
            return Err("bad file name".into());
        }
        let path = self.0.join("inbox").join(format!("{name}.pcap"));
        let data = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if data.len() + 8 > peer::MAX_BLOB {
            return Err("file too large".into());
        }
        let mut out = now().to_le_bytes().to_vec();
        out.extend_from_slice(&data);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `bytes` to `path` as an owner-only file.
    fn write_private(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    /// A registry for `node` whose gateway key is authorized by `root`.
    fn registry(root: &hybrid::Keypair, node: &str, seed: u8) -> Registry {
        let key = hybrid::Keypair::from_seeds(&[seed; 32], &[seed + 1; 32]);
        let authority = peer::NodeAuthority::issue(root, node, key.public().clone(), now() + 3600);
        Registry {
            node: node.into(),
            key,
            authority,
            validity_s: DEFAULT_VALIDITY_S,
        }
    }

    /// Whether a fresh certificate expires one default lifetime from now.
    fn cert_expires_in_a_day(reg: &Registry) -> bool {
        let node = hybrid::Keypair::from_seeds(&[3; 32], &[4; 32]);
        let c = reg.certify(node.public(), [0; 32]);
        c.not_after.abs_diff(now() + DEFAULT_VALIDITY_S) < 5
    }

    /// Certificates name the session's key; exports round-trip through the outbox and inbox; bad file names are refused.
    #[test]
    fn certifies_the_session_key_and_carries_exports() {
        let dir = std::env::temp_dir().join(format!("cdk-registry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = hybrid::Keypair::from_seeds(&[9; 32], &[9; 32]);
        let keyf = dir.join("node-hq.key");
        let authf = dir.join("node-hq.auth");
        write_private(&keyf, &[7u8; 64]);
        let gw = load_key(&keyf).unwrap();
        let auth = peer::NodeAuthority::issue(&root, "hq", gw.public().clone(), now() + 7 * 86400);
        std::fs::write(&authf, auth.encode()).unwrap();
        assert!(Registry::load(&keyf, &authf, Some("branch")).is_err());
        let reg = Registry::load(&keyf, &authf, None).unwrap();
        assert_eq!(reg.node, "hq");
        assert_eq!(reg.root_id(), root.public().id());
        // An authority for another key is refused.
        let other = dir.join("other.auth");
        let wrong = hybrid::Keypair::from_seeds(&[8; 32], &[8; 32]);
        std::fs::write(
            &other,
            peer::NodeAuthority::issue(&root, "hq", wrong.public().clone(), now() + 3600).encode(),
        )
        .unwrap();
        assert!(Registry::load(&keyf, &other, Some("hq")).is_err());
        let node = hybrid::Keypair::from_seeds(&[1; 32], &[2; 32]);
        let cert = reg.certify(node.public(), [5; 32]);
        assert!(cert.verify(root.public()));
        assert_eq!(&cert.issuer, node.public());

        // A portable capability signed by that node goes through the
        // outbox and comes back from the inbox byte for byte.
        let mut p = PortableCap {
            cert,
            object: "alerts".into(),
            perms: 1 << 4,
            audience: "branch".into(),
            serial: 1,
            not_after: now() + 60,
            signature: Signature::from_slice(&[0; SIG_LEN]).unwrap(),
        };
        p.signature = node.sign_with(&p.digest(), peer::PORTABLE_CONTEXT);
        let mut payload = vec![2u8];
        payload.extend_from_slice(b"t1");
        payload.extend_from_slice(&p.encode());
        let caps = CapDir(dir.clone());
        let out = caps.write_export(&payload).unwrap();
        std::fs::create_dir_all(dir.join("inbox")).unwrap();
        std::fs::copy(&out, dir.join("inbox/t1.pcap")).unwrap();
        let back = caps.read_import("t1").unwrap();
        let at = u64::from_le_bytes(back[..8].try_into().unwrap());
        assert!(at.abs_diff(now()) < 5, "import carries the gateway's clock");
        assert_eq!(
            PortableCap::decode(&back[8..])
                .unwrap()
                .verify(root.public(), "branch", at),
            Ok(())
        );
        assert!(cert_expires_in_a_day(&reg));
        // Certificates never outlive the authority that signed them.
        let short = registry(&root, "hq", 30);
        let c = short.certify(node.public(), [0; 32]);
        assert_eq!(c.not_after, short.authority.not_after);
        assert!(c.verify(root.public()));
        assert!(caps.read_import("../registry").is_err());
        let mut bad = payload.clone();
        bad[1] = b'/';
        assert!(caps.write_export(&bad).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Outbound messages are queued, inbound ones served oldest first and
    /// filed; revocations persist and are idempotent.
    #[test]
    fn peer_messages_and_revocations_on_disk() {
        let dir = std::env::temp_dir().join(format!("cdk-capdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let caps = CapDir(dir.clone());
        let root = hybrid::Keypair::from_seeds(&[1; 32], &[2; 32]);
        let hq = hybrid::Keypair::from_seeds(&[3; 32], &[4; 32]);
        let branch = hybrid::Keypair::from_seeds(&[5; 32], &[6; 32]);
        let cert = |k: &hybrid::Keypair, name: &str| {
            registry(&root, name, 20).certify(k.public(), [0; 32])
        };
        let mut grant = PortableCap {
            cert: cert(&hq, "hq"),
            object: "alerts".into(),
            perms: 1 << 4,
            audience: "branch".into(),
            serial: 9,
            not_after: now() + 60,
            signature: Signature::from_slice(&[0; SIG_LEN]).unwrap(),
        };
        grant.signature = hq.sign_with(&grant.digest(), peer::PORTABLE_CONTEXT);
        let mut m = peer::PeerMessage {
            sender: cert(&branch, "branch"),
            grant,
            seq: 1,
            from: "pid-1".into(),
            payload: b"ALERT".to_vec(),
            signature: Signature::from_slice(&[0; SIG_LEN]).unwrap(),
        };
        m.signature = branch.sign_with(&m.digest(), peer::MESSAGE_CONTEXT);

        assert!(caps.write_outbound(b"junk").is_err());
        let name = caps.write_outbound(&m.encode()).unwrap();
        std::fs::create_dir_all(dir.join("inbox")).unwrap();
        std::fs::copy(
            dir.join(format!("outbox/{name}.pmsg")),
            dir.join(format!("inbox/{name}.pmsg")),
        )
        .unwrap();
        let next = caps.next_inbound().unwrap();
        let n = next[0] as usize;
        assert_eq!(&next[1..1 + n], name.as_bytes());
        let at = u64::from_le_bytes(next[1 + n..9 + n].try_into().unwrap());
        let back = peer::PeerMessage::decode(&next[9 + n..]).unwrap();
        assert_eq!(back.verify(root.public(), "hq", at), Ok(()));
        caps.file_inbound(&name, true).unwrap();
        assert!(caps.next_inbound().is_none(), "filed under done/");
        assert!(dir.join(format!("inbox/done/{name}.pmsg")).exists());
        assert!(caps.file_inbound("../x", false).is_err());

        assert!(caps.revocations().is_empty());
        caps.add_revocation(9).unwrap();
        caps.add_revocation(9).unwrap();
        caps.add_revocation(u64::MAX).unwrap();
        assert_eq!(caps.revocations(), vec![9, u64::MAX]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
