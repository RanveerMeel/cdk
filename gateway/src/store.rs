//! The sealed store's file (roadmap 4.5): the gateway keeps CDK's
//! envelope, which it can neither read nor change undetected — the key is
//! sealed in CDK's TPM, the records are authenticated, and a TPM counter
//! catches an old copy (`cdk_link::store`). Writes are durable before CDK
//! is told they succeeded, because CDK then commits the TPM counter.

use std::io::Write;
use std::path::{Path, PathBuf};

use cdk_link::store::Envelope;

pub struct StoreFile(pub PathBuf);

impl StoreFile {
    /// The stored envelope, `None` if there is none yet.
    pub fn read(&self) -> Result<Option<Vec<u8>>, String> {
        match std::fs::read(&self.0) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", self.0.display())),
        }
    }

    /// Replace the envelope durably (temporary file, fsync, rename, fsync
    /// of the directory). Returns its counter.
    pub fn write(&self, bytes: &[u8]) -> Result<u64, String> {
        let env = Envelope::decode(bytes).ok_or("not a sealed-store envelope")?;
        let dir = self
            .0
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let tmp = self.0.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.0).map_err(|e| e.to_string())?;
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(env.counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk_link::store::{Records, NONCE_LEN};

    /// Envelopes round-trip through the file; junk is refused and the
    /// stored envelope kept.
    #[test]
    fn writes_envelopes_durably_and_refuses_junk() {
        let dir = std::env::temp_dir().join(format!("cdk-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let f = StoreFile(dir.join("sealed-store.bin"));
        assert_eq!(f.read(), Ok(None));
        let env = Envelope::seal(
            &[1; 32],
            7,
            b"p",
            b"q",
            &[],
            [2; NONCE_LEN],
            &Records::default(),
        )
        .unwrap();
        assert_eq!(f.write(&env.encode()), Ok(7));
        assert_eq!(f.read(), Ok(Some(env.encode())));
        assert!(f.write(b"junk").is_err());
        assert_eq!(f.read(), Ok(Some(env.encode())), "kept");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
