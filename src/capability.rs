//! Capability tokens for kernel objects.
//!
//! Each token records which [`Permission`]s the holder has on a given object
//! and can optionally carry an Ed25519 signature over a SHA-256 digest of the
//! token contents.
//!
//! ## Signing model
//!
//! ```text
//! message = SHA-256(object_id_bytes ‖ sorted_permission_bytes)
//! signature = Ed25519-Sign(signing_key, message)
//! ```
//!
//! The verifying (public) key is stored inline in the token so verification
//! is self-contained.  There is no PKI or certificate chain — capabilities are
//! issued by the kernel and verified by the kernel.
//!
//! ## Key generation
//!
//! `Capability::generate_key()` draws entropy from [`crate::rng::KernelRng`]
//! (RDRAND on bare-metal, OS entropy on host).

use heapless::FnvIndexSet;
use heapless::String;
use core::str::FromStr;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use rand_core::RngCore;

use crate::rng::KernelRng;

const MAX_PERMISSIONS: usize = 16;
const MAX_ID_LEN: usize = 64;

// Ed25519 signature is 64 bytes, verifying key is 32 bytes.
const SIG_LEN: usize = 64;
const KEY_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Permission {
    Read,
    Write,
    Execute,
    SendMessage,
    ReceiveMessage,
    Delete,
}

impl Permission {
    /// Stable byte tag used in the signable message digest.
    fn tag(&self) -> u8 {
        match self {
            Permission::Read           => 0x01,
            Permission::Write          => 0x02,
            Permission::Execute        => 0x03,
            Permission::SendMessage    => 0x04,
            Permission::ReceiveMessage => 0x05,
            Permission::Delete         => 0x06,
        }
    }
}

#[derive(Clone)]
pub struct Capability {
    pub object_id: String<MAX_ID_LEN>,
    pub permissions: FnvIndexSet<Permission, MAX_PERMISSIONS>,
    /// Ed25519 signature over the SHA-256 digest of this token.
    pub signature: Option<[u8; SIG_LEN]>,
    /// Ed25519 verifying (public) key of the signer.
    pub signer_key: Option<[u8; KEY_LEN]>,
}

impl Capability {
    /// Create a new unsigned capability with the default permission set
    /// (Read, Execute, SendMessage, ReceiveMessage).
    pub fn new(obj: &crate::object::KernelObject) -> Self {
        let mut perms = FnvIndexSet::new();
        let _ = perms.insert(Permission::Read);
        let _ = perms.insert(Permission::Execute);
        let _ = perms.insert(Permission::SendMessage);
        let _ = perms.insert(Permission::ReceiveMessage);

        Self {
            object_id: String::from_str(&obj.id).unwrap_or_default(),
            permissions: perms,
            signature: None,
            signer_key: None,
        }
    }

    /// Create a new unsigned capability with a caller-supplied permission set.
    pub fn with_permissions(
        obj: &crate::object::KernelObject,
        permissions: &[Permission],
    ) -> Self {
        let mut perms = FnvIndexSet::new();
        for perm in permissions {
            let _ = perms.insert(perm.clone());
        }

        Self {
            object_id: String::from_str(&obj.id).unwrap_or_default(),
            permissions: perms,
            signature: None,
            signer_key: None,
        }
    }

    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    /// Generate a fresh Ed25519 signing key using the kernel RNG.
    ///
    /// Returns `(signing_key_bytes, verifying_key_bytes)`.  The signing key
    /// must be kept secret; only the verifying key is stored in the capability.
    pub fn generate_key() -> ([u8; 32], [u8; KEY_LEN]) {
        let mut seed = [0u8; 32];
        KernelRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        (seed, signing_key.verifying_key().to_bytes())
    }

    // -----------------------------------------------------------------------
    // Signing
    // -----------------------------------------------------------------------

    /// Sign this capability with the provided Ed25519 signing key bytes.
    ///
    /// Stores the signature and the corresponding verifying key in the token.
    /// Calling this a second time overwrites the previous signature.
    pub fn sign(&mut self, signing_key_bytes: &[u8; 32]) -> Result<(), CapabilityError> {
        let signing_key = SigningKey::from_bytes(signing_key_bytes);
        let msg = self.signable_message();
        let sig: Signature = signing_key.sign(&msg);
        self.signature  = Some(sig.to_bytes());
        self.signer_key = Some(signing_key.verifying_key().to_bytes());
        Ok(())
    }

    /// Verify the token's signature.
    ///
    /// Returns `Ok(true)` when the signature is present and valid,
    /// `Ok(false)` when no signature has been set, and `Err` when the
    /// stored key or signature bytes are malformed.
    pub fn verify(&self) -> Result<bool, CapabilityError> {
        let sig_bytes  = match self.signature  { Some(s) => s, None => return Ok(false) };
        let key_bytes  = match self.signer_key { Some(k) => k, None => return Ok(false) };

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| CapabilityError::InvalidKey)?;
        let signature = Signature::from_bytes(&sig_bytes);
        let msg = self.signable_message();

        Ok(verifying_key.verify(&msg, &signature).is_ok())
    }

    // -----------------------------------------------------------------------
    // Permission management
    // -----------------------------------------------------------------------

    pub fn has_permission(&self, perm: &Permission) -> bool {
        self.permissions.contains(perm)
    }

    pub fn add_permission(&mut self, perm: Permission) -> Result<(), CapabilityError> {
        if self.permissions.insert(perm).is_err() {
            return Err(CapabilityError::PermissionSetFull);
        }
        Ok(())
    }

    pub fn remove_permission(&mut self, perm: &Permission) {
        self.permissions.remove(perm);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build the canonical byte sequence that is hashed before signing.
    ///
    /// Format: `SHA-256(object_id_bytes ‖ sorted_permission_tags)`
    ///
    /// Permission tags are sorted so the digest is deterministic regardless
    /// of insertion order.
    fn signable_message(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.object_id.as_bytes());

        // Sort permission tags for a canonical, order-independent digest.
        let mut tags: heapless::Vec<u8, MAX_PERMISSIONS> = heapless::Vec::new();
        for p in self.permissions.iter() {
            let _ = tags.push(p.tag());
        }
        tags.sort_unstable();
        hasher.update(&tags);

        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    InvalidKey,
    InvalidSignature,
    PermissionSetFull,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::KernelObject;

    fn dummy_obj(name: &str) -> KernelObject {
        KernelObject::new_compute(name, "normal")
    }

    #[test]
    fn new_capability_has_default_permissions() {
        let cap = Capability::new(&dummy_obj("worker"));
        assert!(cap.has_permission(&Permission::Read));
        assert!(cap.has_permission(&Permission::Execute));
        assert!(cap.has_permission(&Permission::SendMessage));
        assert!(cap.has_permission(&Permission::ReceiveMessage));
        assert!(!cap.has_permission(&Permission::Delete));
    }

    #[test]
    fn add_permission_grants_access() {
        let mut cap = Capability::new(&dummy_obj("obj"));
        assert!(!cap.has_permission(&Permission::Write));
        cap.add_permission(Permission::Write).unwrap();
        assert!(cap.has_permission(&Permission::Write));
    }

    #[test]
    fn remove_permission_revokes_access() {
        let mut cap = Capability::new(&dummy_obj("obj"));
        assert!(cap.has_permission(&Permission::Execute));
        cap.remove_permission(&Permission::Execute);
        assert!(!cap.has_permission(&Permission::Execute));
    }

    #[test]
    fn with_permissions_respects_supplied_set() {
        let obj = dummy_obj("restricted");
        let cap = Capability::with_permissions(&obj, &[Permission::Read]);
        assert!(cap.has_permission(&Permission::Read));
        assert!(!cap.has_permission(&Permission::Execute));
        assert!(!cap.has_permission(&Permission::SendMessage));
    }

    #[test]
    fn verify_returns_false_without_signature() {
        let cap = Capability::new(&dummy_obj("x"));
        assert_eq!(cap.verify().unwrap(), false);
    }

    #[test]
    fn capability_object_id_matches_object() {
        let obj = dummy_obj("myobj");
        let id = obj.id.clone();
        let cap = Capability::new(&obj);
        assert_eq!(cap.object_id, id);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut cap = Capability::new(&dummy_obj("signed"));
        let (sk, _vk) = Capability::generate_key();
        cap.sign(&sk).unwrap();
        assert!(cap.signature.is_some());
        assert!(cap.signer_key.is_some());
        assert_eq!(cap.verify().unwrap(), true);
    }

    #[test]
    fn verify_fails_after_permission_change() {
        let mut cap = Capability::new(&dummy_obj("tampered"));
        let (sk, _vk) = Capability::generate_key();
        cap.sign(&sk).unwrap();
        assert_eq!(cap.verify().unwrap(), true);

        // Add a permission post-signing — the message digest changes.
        cap.add_permission(Permission::Delete).unwrap();
        assert_eq!(cap.verify().unwrap(), false);
    }

    #[test]
    fn verify_fails_after_signature_corruption() {
        let mut cap = Capability::new(&dummy_obj("corrupt"));
        let (sk, _vk) = Capability::generate_key();
        cap.sign(&sk).unwrap();

        // Flip one bit in the signature.
        if let Some(ref mut sig) = cap.signature {
            sig[0] ^= 0x01;
        }
        assert_eq!(cap.verify().unwrap(), false);
    }

    #[test]
    fn different_keys_produce_different_signatures() {
        let obj = dummy_obj("multi-key");
        let mut cap1 = Capability::new(&obj);
        let mut cap2 = Capability::new(&obj);

        let (sk1, _) = Capability::generate_key();
        let (sk2, _) = Capability::generate_key();
        cap1.sign(&sk1).unwrap();
        cap2.sign(&sk2).unwrap();

        assert_ne!(cap1.signature, cap2.signature);
        // Each verifies with its own key.
        assert_eq!(cap1.verify().unwrap(), true);
        assert_eq!(cap2.verify().unwrap(), true);
    }

    #[test]
    fn sign_is_deterministic_for_same_key() {
        // Ed25519 (RFC 8032) — same key + same message must produce identical
        // signatures.  Clone a single capability so both sides share the same
        // object_id and permission set.
        let mut cap1 = Capability::new(&dummy_obj("det"));
        let mut cap2 = cap1.clone();
        let (sk, _) = Capability::generate_key();
        cap1.sign(&sk).unwrap();
        cap2.sign(&sk).unwrap();
        assert_eq!(cap1.object_id, cap2.object_id);
        assert_eq!(cap1.signature, cap2.signature);
    }

    #[test]
    fn permission_tags_are_unique() {
        let tags = [
            Permission::Read.tag(),
            Permission::Write.tag(),
            Permission::Execute.tag(),
            Permission::SendMessage.tag(),
            Permission::ReceiveMessage.tag(),
            Permission::Delete.tag(),
        ];
        let mut seen = heapless::FnvIndexSet::<u8, 16>::new();
        for t in tags {
            assert!(seen.insert(t).is_ok(), "duplicate tag {}", t);
        }
    }
}
