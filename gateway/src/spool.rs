//! Approval spool (roadmap 2.8): where the gateway leaves CDK's signed-
//! approval requests for operators and picks up their signed decisions.
//!
//! ```text
//! <dir>/pending/<id>.req     request bytes from CDK (cdk-approve list / approve / deny)
//! <dir>/decisions/*.dec      decisions written by cdk-approve:
//!                            id u32 LE | operator id [16] | approve u8 | signature
//! <dir>/sent/, done/, stale/ bookkeeping
//! ```
//!
//! The gateway is only a courier: it cannot produce a valid decision (CDK
//! verifies every signature against its pinned operator keys), so the spool
//! can live on shared or synced storage, and `cdk-approve` can run on a
//! separate machine that holds the operator key.

use std::fs;
use std::path::{Path, PathBuf};

use cdk_link::approval::{self, Message};
use cdk_link::secure::SIG_LEN;

#[allow(dead_code)] // cdk-approve uses only the file formats
pub struct Spool {
    dir: PathBuf,
}

/// A decision file's contents.
pub struct Decision {
    pub id: u32,
    pub operator: [u8; 16],
    pub approve: bool,
    pub signature: Vec<u8>,
}

impl Decision {
    pub const LEN: usize = 4 + 16 + 1 + SIG_LEN;

    #[allow(dead_code)] // used by cdk-approve
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::LEN);
        b.extend_from_slice(&self.id.to_le_bytes());
        b.extend_from_slice(&self.operator);
        b.push(self.approve as u8);
        b.extend_from_slice(&self.signature);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != Self::LEN || b[20] > 1 {
            return None;
        }
        Some(Decision {
            id: u32::from_le_bytes(b[..4].try_into().ok()?),
            operator: b[4..20].try_into().ok()?,
            approve: b[20] == 1,
            signature: b[21..].to_vec(),
        })
    }
}

#[allow(dead_code)]
impl Spool {
    /// Open (creating) the spool. Requests left by an earlier session are
    /// moved to `stale/`: request ids restart with every CDK boot.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        for sub in ["pending", "decisions", "sent", "done", "stale"] {
            fs::create_dir_all(dir.join(sub))?;
        }
        let s = Spool {
            dir: dir.to_path_buf(),
        };
        s.retire_pending()?;
        Ok(s)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn retire_pending(&self) -> std::io::Result<()> {
        for e in fs::read_dir(self.dir.join("pending"))?.flatten() {
            let _ = fs::rename(e.path(), self.dir.join("stale").join(e.file_name()));
        }
        Ok(())
    }

    /// Handle an approval message from CDK.
    pub fn on_message(&self, msg: &[u8]) {
        match approval::decode(msg) {
            Ok(Message::Request(r)) => {
                let path = self.dir.join("pending").join(format!("{}.req", r.id));
                match fs::write(&path, msg) {
                    Ok(()) => eprintln!(
                        "gateway: <- approval request #{} ({}, quorum {}, {} s): {}",
                        r.id,
                        if r.kind == approval::KIND_POLICY {
                            "policy change"
                        } else {
                            "agent action"
                        },
                        r.quorum,
                        r.ttl_s,
                        r.text
                            .lines()
                            .map(str::trim)
                            .find(|l| l.starts_with("action") || l.starts_with(['+', '-', '~']))
                            .unwrap_or("")
                    ),
                    Err(e) => eprintln!("gateway: spool {}: {e}", path.display()),
                }
            }
            Ok(Message::Resolved { id, outcome }) => {
                let word = match outcome {
                    approval::OUTCOME_APPROVED => "approved",
                    approval::OUTCOME_DENIED => "denied",
                    _ => "timed-out",
                };
                let from = self.dir.join("pending").join(format!("{id}.req"));
                let _ = fs::rename(&from, self.dir.join("done").join(format!("{id}.{word}")));
                eprintln!("gateway: <- approval request #{id} closed: {word}");
            }
            _ => eprintln!("gateway: malformed approval message ignored"),
        }
    }

    /// Decisions written since the last call (moved to `sent/`).
    pub fn take_decisions(&self) -> Vec<Decision> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(self.dir.join("decisions")) else {
            return out;
        };
        let mut paths: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "dec"))
            .collect();
        paths.sort();
        for p in paths {
            let bytes = fs::read(&p).unwrap_or_default();
            let _ = fs::rename(
                &p,
                self.dir
                    .join("sent")
                    .join(p.file_name().unwrap_or_default()),
            );
            match Decision::from_bytes(&bytes) {
                Some(d) => out.push(d),
                None => eprintln!("gateway: malformed decision file {} ignored", p.display()),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk_link::approval::{
        encode_request, encode_resolved, Request, KIND_ACTION, OUTCOME_APPROVED,
    };

    #[test]
    fn requests_and_decisions_round_trip() {
        let dir = std::env::temp_dir().join(format!("cdk-spool-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("pending")).unwrap();
        fs::write(dir.join("pending/99.req"), b"old").unwrap();
        let spool = Spool::open(&dir).unwrap();
        assert!(
            dir.join("stale/99.req").exists(),
            "earlier session's requests are retired"
        );

        let req = Request {
            id: 4,
            issuer: [1; 16],
            kind: KIND_ACTION,
            quorum: 1,
            ttl_s: 60,
            payload_digest: [2; 32],
            text: "action : call tool 'echo'",
        };
        let msg = encode_request(&req).unwrap();
        spool.on_message(&msg);
        assert_eq!(fs::read(dir.join("pending/4.req")).unwrap(), msg);

        let d = Decision {
            id: 4,
            operator: [7; 16],
            approve: true,
            signature: vec![5; SIG_LEN],
        };
        fs::write(dir.join("decisions/4-07070707.dec"), d.to_bytes()).unwrap();
        fs::write(dir.join("decisions/bad.dec"), b"junk").unwrap();
        let got = spool.take_decisions();
        assert_eq!(got.len(), 1);
        assert_eq!(
            (got[0].id, got[0].operator, got[0].approve),
            (4, [7; 16], true)
        );
        assert_eq!(got[0].signature, vec![5; SIG_LEN]);
        assert!(
            spool.take_decisions().is_empty(),
            "each decision is forwarded once"
        );

        spool.on_message(&encode_resolved(4, OUTCOME_APPROVED));
        assert!(dir.join("done/4.approved").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
