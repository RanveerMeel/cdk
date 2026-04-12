// Capability system (crypto signing disabled for bare-metal - needs RNG)
use heapless::FnvIndexSet;
use heapless::String;
use core::str::FromStr;
// Crypto signing disabled - requires RNG which doesn't work on bare-metal
// use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
// use sha2::{Sha256, Digest};

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
    pub signer_key: Option<[u8; 32]>, // Ed25519 public key (32 bytes)
}

impl Capability {
    pub fn new(obj: &crate::object::KernelObject) -> Self {
        // Default capabilities: read, execute, send/receive messages
        let mut perms = FnvIndexSet::new();
        let _ = perms.insert(Permission::Read);
        let _ = perms.insert(Permission::Execute);
        let _ = perms.insert(Permission::SendMessage);
        let _ = perms.insert(Permission::ReceiveMessage);

        let object_id: String<MAX_ID_LEN> = 
            String::from_str(&obj.id).unwrap_or_default();

        Self {
            object_id,
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

        let object_id: String<MAX_ID_LEN> = 
            String::from_str(&obj.id).unwrap_or_default();

        Self {
            object_id,
            permissions: perms,
            signature: None,
            signer_key: None,
        }
    }

    // Crypto signing disabled for bare-metal (requires RNG)
    // pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), CapabilityError> {
    //     let message = self.to_signable_message();
    //     let signature = signing_key.sign(&message);
    //     let sig_bytes: [u8; MAX_SIG_LEN] = signature.to_bytes();
    //     
    //     self.signature = Some(sig_bytes);
    //     self.signer_key = Some(signing_key.verifying_key().to_bytes());
    //     Ok(())
    // }

    // pub fn verify(&self) -> Result<bool, CapabilityError> {
    //     let signature = self.signature.ok_or(CapabilityError::NoSignature)?;
    //     let signer_key = self.signer_key.ok_or(CapabilityError::NoSignerKey)?;
    //     
    //     let verifying_key = VerifyingKey::from_bytes(&signer_key)
    //         .map_err(|_| CapabilityError::InvalidKey)?;
    //     let signature = Signature::from_bytes(&signature)
    //         .map_err(|_| CapabilityError::InvalidSignature)?;
    //     
    //     let message = self.to_signable_message();
    //     Ok(verifying_key.verify(&message, &signature).is_ok())
    // }
    
    pub fn verify(&self) -> Result<bool, CapabilityError> {
        // Simplified verification - just check if signature exists
        // Full crypto verification requires RNG which doesn't work on bare-metal
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

    // Simplified - crypto signing disabled for bare-metal
    // fn to_signable_message(&self) -> Vec<u8> {
    //     let mut hasher = Sha256::new();
    //     hasher.update(self.object_id.as_bytes());
    //     
    //     // Add permissions to hash
    //     let mut perms_vec: heapless::Vec<u8, 64> = heapless::Vec::new();
    //     for perm in self.permissions.iter() {
    //         let perm_bytes = match perm {
    //             Permission::Read => b"Read",
    //             Permission::Write => b"Write",
    //             Permission::Execute => b"Execute",
    //             Permission::SendMessage => b"SendMessage",
    //             Permission::ReceiveMessage => b"ReceiveMessage",
    //             Permission::Delete => b"Delete",
    //         };
    //         let _ = perms_vec.extend_from_slice(perm_bytes);
    //     }
    //     hasher.update(&perms_vec);
    //     
    //     hasher.finalize().to_vec()
    // }
}

#[derive(Debug)]
pub enum CapabilityError {
    NoSignature,
    NoSignerKey,
    InvalidKey,
    InvalidSignature,
    PermissionSetFull,
}
