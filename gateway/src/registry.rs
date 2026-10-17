//! Registry authority for distributed capabilities (roadmap 3.5).
//!
//! With `--registry-key FILE --node NAME`, the gateway certifies the CDK it
//! serves: once that CDK's attestation is accepted, it signs a
//! [`NodeCert`] binding NAME to the issuer key CDK used in this session's
//! handshake, and sends it to CDK. Certifying needs attestation
//! (`--expect`, `--tpm` or `--tpm-ca`), so only a measured, verified boot
//! gets a name. The registry key is a hybrid key made with `cdk-sign init
//! --key FILE --pub-out FILE`; its public half goes into every node's
//! ramdisk as `registry.pub`. In production the registry is a separate
//! service holding its key in an HSM; here each gateway may hold it.
//!
//! The gateway also carries portable capabilities between nodes: CDK's
//! exports go to `--cap-dir DIR/outbox/<file>.pcap`, imports are read from
//! `DIR/inbox/<file>.pcap`. It is only a courier — CDK verifies everything.

use std::path::{Path, PathBuf};

use cdk_link::peer::{self, NodeCert, PortableCap};
use cdk_link::secure::{hybrid, Identity, Signature, SIG_LEN};
use rand_core::{OsRng, RngCore};

/// Default certificate lifetime: 24 hours.
pub const DEFAULT_VALIDITY_S: u64 = 24 * 3600;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub struct Registry {
    key: hybrid::Keypair,
    pub node: String,
    /// Certificate lifetime in seconds.
    pub validity_s: u64,
}

impl Registry {
    /// Load the 64-byte hybrid seed file made by `cdk-sign init`.
    pub fn load(path: &Path, node: &str) -> Result<Registry, String> {
        use std::os::unix::fs::MetadataExt;
        if !peer::valid_node_name(node) {
            return Err("--node: a-z 0-9 - _ (at most 16)".into());
        }
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.mode() & 0o077 != 0 {
            return Err(format!(
                "{} must not be readable by group or others (chmod 600)",
                path.display()
            ));
        }
        let seeds = zeroize::Zeroizing::new(std::fs::read(path).map_err(|e| e.to_string())?);
        if seeds.len() != 64 {
            return Err(format!(
                "{} is not a 64-byte hybrid key (cdk-sign init)",
                path.display()
            ));
        }
        let (mut ed, mut ml) = ([0u8; 32], [0u8; 32]);
        ed.copy_from_slice(&seeds[..32]);
        ml.copy_from_slice(&seeds[32..]);
        let key = hybrid::Keypair::from_seeds(&ed, &ml);
        zeroize::Zeroize::zeroize(&mut ed);
        zeroize::Zeroize::zeroize(&mut ml);
        Ok(Registry {
            key,
            node: node.to_string(),
            validity_s: DEFAULT_VALIDITY_S,
        })
    }

    pub fn public(&self) -> &Identity {
        self.key.public()
    }

    /// Certify `issuer` (the key CDK proved in this session's handshake)
    /// after an attestation summarized by `attested`.
    pub fn certify(&self, issuer: &Identity, attested: [u8; 32]) -> NodeCert {
        let mut cert = NodeCert {
            name: self.node.clone(),
            issuer: issuer.clone(),
            registry: self.key.public().id(),
            serial: OsRng.next_u64(),
            attested,
            not_after: now() + self.validity_s,
            signature: Signature::from_slice(&[0; SIG_LEN]).expect("length"),
        };
        cert.signature = self.key.sign_with(&cert.digest(), peer::NODE_CONTEXT);
        cert
    }
}

/// The gateway's capability outbox/inbox.
pub struct CapDir(pub PathBuf);

impl CapDir {
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

    fn cert_expires_in_a_day(reg: &Registry) -> bool {
        let node = hybrid::Keypair::from_seeds(&[3; 32], &[4; 32]);
        let c = reg.certify(node.public(), [0; 32]);
        c.not_after.abs_diff(now() + DEFAULT_VALIDITY_S) < 5
    }

    #[test]
    fn certifies_the_session_key_and_carries_exports() {
        let dir = std::env::temp_dir().join(format!("cdk-registry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let keyf = dir.join("registry.key");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&keyf)
                .unwrap()
                .write_all(&[7u8; 64])
                .unwrap();
        }
        assert!(Registry::load(&keyf, "Bad Name").is_err());
        let reg = Registry::load(&keyf, "hq").unwrap();
        let node = hybrid::Keypair::from_seeds(&[1; 32], &[2; 32]);
        let cert = reg.certify(node.public(), [5; 32]);
        assert!(cert.verify(reg.public()));
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
                .verify(reg.public(), "branch", at),
            Ok(())
        );
        assert!(cert_expires_in_a_day(&reg));
        assert!(caps.read_import("../registry").is_err());
        let mut bad = payload.clone();
        bad[1] = b'/';
        assert!(caps.write_export(&bad).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
