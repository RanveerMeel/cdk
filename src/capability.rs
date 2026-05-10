//! Capability tokens for kernel objects.
//!
//! Each token records which [`Permission`]s the holder has on a given object.
//! Cryptographic signing (`ed25519-dalek`) is omitted — the bare-metal target
//! has no RNG. The `signature` / `signer_key` fields are reserved for when a
//! hardware RNG (RDRAND) is wired up.
use heapless::FnvIndexSet;
use heapless::String;
use core::str::FromStr;

const MAX_PERMISSIONS: usize = 16;
const MAX_ID_LEN: usize = 64;
const MAX_SIG_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Permission {
    Read,
    Write,
    Execute,
    SendMessage,
    ReceiveMessage,
    Delete,
}

#[derive(Clone)]
pub struct Capability {
    pub object_id: String<MAX_ID_LEN>,
    pub permissions: FnvIndexSet<Permission, MAX_PERMISSIONS>,
    pub signature: Option<[u8; MAX_SIG_LEN]>,
    pub signer_key: Option<[u8; 32]>,
}

impl Capability {
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

    /// Returns `Ok(true)` only when a signature blob is present.
    /// Full Ed25519 verification is deferred until RDRAND is available.
    pub fn verify(&self) -> Result<bool, CapabilityError> {
        Ok(self.signature.is_some())
    }

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
}

#[derive(Debug)]
pub enum CapabilityError {
    NoSignature,
    NoSignerKey,
    InvalidKey,
    InvalidSignature,
    PermissionSetFull,
}

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
}
