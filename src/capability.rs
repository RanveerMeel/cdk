//! Capability tokens for kernel objects.
//!
//! Each token records which [`Permission`]s the holder has on a given object
//! and carries a [`CapabilityProof`]: a hybrid **Ed25519 + ML-DSA-65**
//! (FIPS 204) signature made by the kernel [`Issuer`](crate::issuer::Issuer).
//! Privileged kernel entry points reject tokens without a valid proof.
//!
//! ## Trust model
//!
//! Verification checks the proof against the **pinned kernel issuer**, never
//! against a key carried inside the token. (Format v0 embedded the signer's
//! public key and accepted any self-signed token, so anyone could mint a
//! capability. v1 closes that hole.) Tokens from other issuers — e.g. other
//! CDK nodes — are verified explicitly with [`Capability::verify_with`].
//!
//! ## Token format v1
//!
//! ```text
//! digest = SHA-256( "CDK-CAP" ‖ format ‖ algorithm ‖ issuer_id[16]
//!                   ‖ u16_le(len(object_id)) ‖ object_id
//!                   ‖ u8(count) ‖ sorted_permission_tags )
//! proof  = { format, algorithm, issuer_id, Ed25519(digest), ML-DSA-65(digest, ctx="CDK-CAP-v1") }
//! ```
//!
//! Both signatures must verify. `format` and `algorithm` are covered by the
//! digest, so a token cannot be downgraded to a weaker algorithm.
//!
//! ## Verified-proof cache
//!
//! ML-DSA verification is the expensive part of every capability check, and
//! agents present the same tokens repeatedly. [`verify_cache`] remembers
//! proofs that verified against the kernel issuer, keyed by
//! `SHA-256("CDK-CAP-CACHE" ‖ digest ‖ ed25519_sig ‖ mldsa65_sig)`, so a hit
//! requires a byte-identical token and proof. Only successes are cached, and
//! the kernel issuer never changes within a boot; when revocation arrives,
//! revoking must call [`verify_cache::clear`].

use core::str::FromStr;
use heapless::FnvIndexSet;
use heapless::String;

use sha2::{Digest, Sha256};

use crate::issuer::{self, HybridSignature, Issuer, IssuerId, IssuerPublic, SigDomain};

const MAX_PERMISSIONS: usize = 16;
const MAX_ID_LEN: usize = 64;

/// Current capability token format.
pub const TOKEN_FORMAT_V1: u8 = 1;
const TOKEN_DOMAIN: &[u8] = b"CDK-CAP";

/// Signature algorithm recorded in a token (crypto agility: new algorithms
/// get new identifiers; verifiers reject identifiers they do not know).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    /// Ed25519 and ML-DSA-65; both must verify.
    HybridEd25519MlDsa65 = 0x01,
}

impl SignatureAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            SignatureAlgorithm::HybridEd25519MlDsa65 => "Ed25519+ML-DSA-65",
        }
    }
}

/// Issuer-signed proof attached to a capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityProof {
    pub format: u8,
    pub algorithm: SignatureAlgorithm,
    pub issuer_id: IssuerId,
    pub signature: HybridSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Permission {
    Read,
    Write,
    Execute,
    SendMessage,
    ReceiveMessage,
    Delete,
    /// Constraint, not a right: every outbound action through this token
    /// (currently `send`) waits for a human to approve it. Covered by the
    /// signature like any permission, and inherited by derived handles.
    RequiresApproval,
}

impl Permission {
    /// Stable byte tag used in the signable message digest and permission masks.
    pub fn tag(&self) -> u8 {
        match self {
            Permission::Read => 0x01,
            Permission::Write => 0x02,
            Permission::Execute => 0x03,
            Permission::SendMessage => 0x04,
            Permission::ReceiveMessage => 0x05,
            Permission::Delete => 0x06,
            Permission::RequiresApproval => 0x07,
        }
    }
}

#[derive(Clone)]
pub struct Capability {
    pub object_id: String<MAX_ID_LEN>,
    pub permissions: FnvIndexSet<Permission, MAX_PERMISSIONS>,
    /// Issuer signature; `None` until [`issue`](Self::issue)d.
    pub proof: Option<CapabilityProof>,
}

impl Capability {
    /// Create a new unsigned capability with the default permission set
    /// (Read, Execute, SendMessage, ReceiveMessage).
    pub fn new(obj: &crate::object::KernelObject) -> Self {
        Self::with_permissions(
            obj,
            &[
                Permission::Read,
                Permission::Execute,
                Permission::SendMessage,
                Permission::ReceiveMessage,
            ],
        )
    }

    /// Create a new unsigned capability with a caller-supplied permission set.
    pub fn with_permissions(obj: &crate::object::KernelObject, permissions: &[Permission]) -> Self {
        let mut perms = FnvIndexSet::new();
        for perm in permissions {
            let _ = perms.insert(perm.clone());
        }

        Self {
            object_id: String::from_str(&obj.id).unwrap_or_default(),
            permissions: perms,
            proof: None,
        }
    }

    // -----------------------------------------------------------------------
    // Issuance
    // -----------------------------------------------------------------------

    /// Sign this capability with the kernel issuer and record it in the
    /// audit log.
    ///
    /// Calling this again replaces the previous proof.
    pub fn issue(&mut self) -> Result<(), CapabilityError> {
        self.issue_with(issuer::kernel())?;
        crate::audit::record(
            crate::audit::EventKind::CapIssued,
            &self.object_id,
            self.permission_mask(),
        );
        Ok(())
    }

    /// Sign this capability with a specific issuer.
    pub fn issue_with(&mut self, issuer: &Issuer) -> Result<(), CapabilityError> {
        let algorithm = SignatureAlgorithm::HybridEd25519MlDsa65;
        let digest = self.signable_digest(TOKEN_FORMAT_V1, algorithm, issuer.id());
        self.proof = Some(CapabilityProof {
            format: TOKEN_FORMAT_V1,
            algorithm,
            issuer_id: *issuer.id(),
            signature: issuer.sign(SigDomain::Capability, &digest),
        });
        Ok(())
    }

    /// Whether this token currently carries a proof.
    pub fn is_signed(&self) -> bool {
        self.proof.is_some()
    }

    // -----------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------

    /// Verify the token against the kernel issuer.
    ///
    /// Returns `Ok(true)` when the proof is valid, `Ok(false)` when there is
    /// no proof or the signature does not verify, and `Err` when the token
    /// names another issuer or an unsupported format.
    pub fn verify(&self) -> Result<bool, CapabilityError> {
        let kernel = issuer::kernel();
        self.verify_by(kernel.id(), |digest, sig| {
            let key = verify_cache::key(digest, sig);
            if verify_cache::lookup(&key) {
                return true;
            }
            let ok = kernel.verify(SigDomain::Capability, digest, sig);
            if ok {
                verify_cache::insert(key);
            }
            ok
        })
    }

    /// Verify against the kernel issuer, bypassing the cache (benchmarks).
    pub fn verify_uncached(&self) -> Result<bool, CapabilityError> {
        let kernel = issuer::kernel();
        self.verify_by(kernel.id(), |digest, sig| {
            kernel.verify(SigDomain::Capability, digest, sig)
        })
    }

    /// Verify the token against an explicitly trusted issuer public key.
    pub fn verify_with(&self, issuer: &IssuerPublic) -> Result<bool, CapabilityError> {
        self.verify_by(&issuer.id, |digest, sig| {
            issuer.verify(SigDomain::Capability, digest, sig)
        })
    }

    fn verify_by(
        &self,
        trusted: &IssuerId,
        check: impl FnOnce(&[u8; 32], &HybridSignature) -> bool,
    ) -> Result<bool, CapabilityError> {
        let Some(proof) = &self.proof else {
            return Ok(false);
        };
        if proof.format != TOKEN_FORMAT_V1 {
            return Err(CapabilityError::UnsupportedFormat);
        }
        if proof.issuer_id != *trusted {
            return Err(CapabilityError::UnknownIssuer);
        }
        let digest = self.signable_digest(proof.format, proof.algorithm, &proof.issuer_id);
        Ok(check(&digest, &proof.signature))
    }

    // -----------------------------------------------------------------------
    // Permission management
    // -----------------------------------------------------------------------

    /// Bitmask of held permissions (bit = permission tag), for audit records.
    pub fn permission_mask(&self) -> u64 {
        self.permissions
            .iter()
            .fold(0u64, |mask, p| mask | (1u64 << p.tag()))
    }

    pub fn has_permission(&self, perm: &Permission) -> bool {
        self.permissions.contains(perm)
    }

    pub fn add_permission(&mut self, perm: Permission) -> Result<(), CapabilityError> {
        if self.permissions.insert(perm).is_err() {
            return Err(CapabilityError::PermissionSetFull);
        }
        // Permission set changed — the proof no longer covers the token.
        self.proof = None;
        Ok(())
    }

    pub fn remove_permission(&mut self, perm: &Permission) {
        self.permissions.remove(perm);
        self.proof = None;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Canonical, domain-separated digest covered by the proof (see module docs).
    fn signable_digest(
        &self,
        format: u8,
        algorithm: SignatureAlgorithm,
        issuer_id: &IssuerId,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(TOKEN_DOMAIN);
        hasher.update([format, algorithm as u8]);
        hasher.update(issuer_id);
        let id = self.object_id.as_bytes();
        hasher.update((id.len() as u16).to_le_bytes());
        hasher.update(id);

        // Sort permission tags for a canonical, order-independent digest.
        let mut tags: heapless::Vec<u8, MAX_PERMISSIONS> = heapless::Vec::new();
        for p in self.permissions.iter() {
            let _ = tags.push(p.tag());
        }
        tags.sort_unstable();
        hasher.update([tags.len() as u8]);
        hasher.update(&tags);

        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

// ---------------------------------------------------------------------------
// Verified-proof cache
// ---------------------------------------------------------------------------

/// Cache of proofs that verified against the kernel issuer (see module docs).
pub mod verify_cache {
    use sha2::{Digest, Sha256};
    use spin::Mutex;

    use crate::issuer::HybridSignature;

    /// Entries kept; the oldest is replaced first.
    pub const CAPACITY: usize = 64;
    const DOMAIN: &[u8] = b"CDK-CAP-CACHE";

    pub type Key = [u8; 32];

    struct Cache {
        keys: [Key; CAPACITY],
        len: usize,
        next: usize,
        hits: u64,
        misses: u64,
    }

    static CACHE: Mutex<Cache> = Mutex::new(Cache {
        keys: [[0; 32]; CAPACITY],
        len: 0,
        next: 0,
        hits: 0,
        misses: 0,
    });

    /// Cache key: binds the full signed digest and both signatures.
    pub fn key(digest: &[u8; 32], sig: &HybridSignature) -> Key {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(digest);
        h.update(sig.ed25519);
        h.update(&sig.mldsa65[..]);
        h.finalize().into()
    }

    pub fn lookup(key: &Key) -> bool {
        let mut c = CACHE.lock();
        let hit = c.keys[..c.len].iter().any(|k| k == key);
        if hit {
            c.hits += 1;
        } else {
            c.misses += 1;
        }
        hit
    }

    pub fn insert(key: Key) {
        let mut c = CACHE.lock();
        let slot = c.next;
        c.keys[slot] = key;
        c.next = (slot + 1) % CAPACITY;
        c.len = (c.len + 1).min(CAPACITY);
    }

    /// Forget every cached proof (call on revocation or issuer change).
    pub fn clear() {
        let mut c = CACHE.lock();
        c.len = 0;
        c.next = 0;
    }

    /// `(hits, misses, entries)`.
    pub fn stats() -> (u64, u64, usize) {
        let c = CACHE.lock();
        (c.hits, c.misses, c.len)
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    PermissionSetFull,
    /// The proof names an issuer the verifier does not trust.
    UnknownIssuer,
    /// The proof uses a token format this kernel does not understand.
    UnsupportedFormat,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::Issuer;
    use crate::object::KernelObject;
    use crate::rng::EntropySource;

    fn dummy_obj(name: &str) -> KernelObject {
        KernelObject::new_compute(name, "normal")
    }

    fn attacker() -> Issuer {
        Issuer::from_seeds(&[0xAA; 32], &[0xBB; 32], EntropySource::Os)
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
    fn capability_object_id_matches_object() {
        let obj = dummy_obj("myobj");
        let id = obj.id.clone();
        let cap = Capability::new(&obj);
        assert_eq!(cap.object_id, id);
    }

    #[test]
    fn unsigned_token_does_not_verify() {
        let cap = Capability::new(&dummy_obj("x"));
        assert_eq!(cap.verify(), Ok(false));
        assert!(!cap.is_signed());
    }

    #[test]
    fn issued_token_verifies_with_hybrid_proof() {
        let mut cap = Capability::new(&dummy_obj("issued"));
        cap.issue().unwrap();
        let proof = cap.proof.as_ref().unwrap();
        assert_eq!(proof.format, TOKEN_FORMAT_V1);
        assert_eq!(proof.algorithm, SignatureAlgorithm::HybridEd25519MlDsa65);
        assert_eq!(&proof.issuer_id, issuer::kernel().id());
        assert_eq!(cap.verify(), Ok(true));
    }

    /// Regression test for the v0 forgery hole: a token signed by any key
    /// other than the kernel issuer must be rejected.
    #[test]
    fn self_signed_token_is_rejected() {
        let mut forged = Capability::with_permissions(&dummy_obj("victim"), &[Permission::Delete]);
        forged.issue_with(&attacker()).unwrap();
        assert_eq!(forged.verify(), Err(CapabilityError::UnknownIssuer));

        // Relabelling the forged proof with the kernel issuer id does not help.
        forged.proof.as_mut().unwrap().issuer_id = *issuer::kernel().id();
        assert_eq!(forged.verify(), Ok(false));
    }

    #[test]
    fn foreign_issuer_verifies_only_when_trusted_explicitly() {
        let other = attacker();
        let mut cap = Capability::new(&dummy_obj("remote"));
        cap.issue_with(&other).unwrap();
        assert_eq!(cap.verify_with(other.public()), Ok(true));
        assert_eq!(
            cap.verify_with(issuer::kernel().public()),
            Err(CapabilityError::UnknownIssuer)
        );
    }

    #[test]
    fn permission_mutation_clears_proof() {
        let mut cap = Capability::new(&dummy_obj("mut"));
        cap.issue().unwrap();
        cap.add_permission(Permission::Delete).unwrap();
        assert!(!cap.is_signed());
        assert_eq!(cap.verify(), Ok(false));
    }

    #[test]
    fn tampering_with_fields_invalidates_proof() {
        let mut cap = Capability::with_permissions(&dummy_obj("t"), &[Permission::Read]);
        cap.issue().unwrap();

        // Escalate permissions behind the API's back.
        let mut escalated = cap.clone();
        let _ = escalated.permissions.insert(Permission::Delete);
        assert_eq!(escalated.verify(), Ok(false));

        // Point the token at another object.
        let mut retargeted = cap.clone();
        retargeted.object_id = String::from_str("obj-999").unwrap();
        assert_eq!(retargeted.verify(), Ok(false));
    }

    #[test]
    fn both_signature_halves_are_checked() {
        let mut cap = Capability::new(&dummy_obj("halves"));
        cap.issue().unwrap();

        let mut bad_ed = cap.clone();
        bad_ed.proof.as_mut().unwrap().signature.ed25519[5] ^= 1;
        assert_eq!(bad_ed.verify(), Ok(false));

        let mut bad_ml = cap.clone();
        bad_ml.proof.as_mut().unwrap().signature.mldsa65[5] ^= 1;
        assert_eq!(bad_ml.verify(), Ok(false));
    }

    #[test]
    fn verified_proofs_are_cached_but_tampering_still_fails() {
        let mut cap = Capability::with_permissions(&dummy_obj("cache"), &[Permission::Read]);
        cap.issue().unwrap();
        let digest = cap.signable_digest(
            TOKEN_FORMAT_V1,
            SignatureAlgorithm::HybridEd25519MlDsa65,
            issuer::kernel().id(),
        );
        let key = verify_cache::key(&digest, &cap.proof.as_ref().unwrap().signature);

        assert_eq!(cap.verify(), Ok(true)); // populates the cache
        assert!(verify_cache::lookup(&key));
        assert_eq!(cap.verify(), Ok(true)); // served from the cache

        // A cached token with escalated permissions has a different digest.
        let mut escalated = cap.clone();
        let _ = escalated.permissions.insert(Permission::Delete);
        assert_eq!(escalated.verify(), Ok(false));

        // Same digest, corrupted signature: different key, full check fails.
        let mut corrupted = cap.clone();
        corrupted.proof.as_mut().unwrap().signature.mldsa65[9] ^= 1;
        assert_eq!(corrupted.verify(), Ok(false));

        // Cached and uncached paths agree.
        assert_eq!(cap.verify_uncached(), Ok(true));
        assert_eq!(corrupted.verify_uncached(), Ok(false));
    }

    #[test]
    fn unsupported_format_is_rejected() {
        let mut cap = Capability::new(&dummy_obj("fmt"));
        cap.issue().unwrap();
        cap.proof.as_mut().unwrap().format = 99;
        assert_eq!(cap.verify(), Err(CapabilityError::UnsupportedFormat));
    }

    #[test]
    fn digest_is_order_independent_and_length_prefixed() {
        let obj = dummy_obj("d");
        let a = Capability::with_permissions(&obj, &[Permission::Read, Permission::Write]);
        let b = Capability::with_permissions(&obj, &[Permission::Write, Permission::Read]);
        let alg = SignatureAlgorithm::HybridEd25519MlDsa65;
        let id = [7u8; 16];
        assert_eq!(
            a.signable_digest(1, alg, &id),
            b.signable_digest(1, alg, &id)
        );
        assert_ne!(
            a.signable_digest(1, alg, &id),
            a.signable_digest(2, alg, &id)
        );
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
            Permission::RequiresApproval.tag(),
        ];
        let mut seen = heapless::FnvIndexSet::<u8, 16>::new();
        for t in tags {
            assert!(seen.insert(t).is_ok(), "duplicate tag {}", t);
        }
    }
}
