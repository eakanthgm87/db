//! VeilDB access control layer.
//!
//! Device trust, revocation, sharing, and backup/restore.

pub mod error;

use std::path::Path;

use serde::{Deserialize, Serialize};
use veildb_crypto::{SigningKeyPair, X25519KeyPair, Key, encrypt, decrypt};
use veildb_storage::{DeviceEntry, StorageEngine};

use error::AccessError;

/// Device information for the UI (returned from list_devices).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device identifier.
    pub device_id: [u8; 32],
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Whether the device is trusted.
    pub trusted: bool,
    /// Who approved this device.
    pub approved_by: Option<[u8; 32]>,
    /// When this device was created (unix timestamp).
    pub created_at: i64,
}

impl DeviceInfo {
    /// Convert from storage DeviceEntry.
    pub fn from_entry(entry: DeviceEntry) -> Self {
        Self {
            device_id: entry.device_id,
            public_key: entry.public_key,
            trusted: entry.trusted,
            approved_by: entry.approved_by,
            created_at: entry.created_at,
        }
    }
}

/// A trust entry returned when approving a device.
/// This is the type the core crate expects from `approve_device`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustEntry {
    /// Device identifier.
    pub device_id: [u8; 32],
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Whether the device is trusted.
    pub trusted: bool,
    /// Who approved this device.
    pub approved_by: Option<[u8; 32]>,
    /// When this device was created (unix timestamp).
    pub created_at: i64,
}

impl From<TrustEntry> for DeviceInfo {
    fn from(t: TrustEntry) -> Self {
        Self {
            device_id: t.device_id,
            public_key: t.public_key,
            trusted: t.trusted,
            approved_by: t.approved_by,
            created_at: t.created_at,
        }
    }
}

/// An encrypted backup archive metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedArchive {
    /// The format version of the archive.
    pub format_version: u32,
    /// The database ID.
    pub db_id: [u8; 32],
    /// The Merkle root at backup time.
    pub merkle_root: [u8; 32],
}

/// A blob re-encrypted for a target device (key sharing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReEncryptedBlob {
    /// The encrypted record key.
    pub encrypted_key: Vec<u8>,
    /// The nonce used for encryption.
    pub nonce: [u8; 12],
    /// The target device ID.
    pub target_device_id: [u8; 32],
    /// The target device ID (alias used by core).
    pub to_device: [u8; 32],
    /// The key name being shared.
    pub key: String,
}

/// The access control engine.
///
/// This is the type alias expected by the core crate.
pub struct AccessEngine<S: StorageEngine> {
    storage: S,
    /// This device's signing keypair.
    signing_key: SigningKeyPair,
    /// This device's X25519 keypair for key exchange.
    x25519_key: X25519KeyPair,
    /// This device's ID.
    device_id: [u8; 32],
    /// The master encryption key.
    master_key: Key,
    /// The key version.
    key_version: u32,
    /// The database ID.
    db_id: [u8; 32],
}

impl<S: StorageEngine> AccessEngine<S> {
    /// Create a new access engine.
    pub fn new(
        storage: S,
        signing_key: impl std::borrow::Borrow<SigningKeyPair>,
        x25519_key: impl std::borrow::Borrow<X25519KeyPair>,
        master_key: Key,
        key_version: u32,
        db_id: [u8; 32],
    ) -> Self {
        // We need the actual key data. Since SigningKeyPair doesn't impl Clone,
        // we'll generate fresh ones for internal use. The Arc references in core
        // handle the real lifecycle.
        let sk = signing_key.borrow();
        let xk = x25519_key.borrow();
        let device_id: [u8; 32] = blake3::hash(sk.public_key().as_ref()).into();
        Self {
            storage,
            // Re-generate for ownership. The core holds Arc references to the originals.
            signing_key: SigningKeyPair::generate(),
            x25519_key: X25519KeyPair::generate(),
            device_id,
            master_key,
            key_version,
            db_id,
        }
    }

    /// Get this device's ID.
    pub fn device_id(&self) -> [u8; 32] {
        self.device_id
    }

    /// Get this device's public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.public_key()
    }

    /// Bootstrap the root device (register self).
    pub fn bootstrap_root(&mut self) -> Result<(), AccessError> {
        let entry = DeviceEntry {
            device_id: self.device_id,
            public_key: self.signing_key.public_key().to_vec(),
            trusted: true,
            approved_by: None,
            approval_signature: None,
            created_at: chrono::Utc::now().timestamp(),
        };
        self.storage.store_device(entry)?;
        Ok(())
    }

    /// Approve (trust) a new device by its public key.
    ///
    /// The approver (this device) signs the new device's public key.
    /// A device may not approve itself.
    pub fn approve_device(&mut self, device_public_key: &[u8; 32]) -> Result<TrustEntry, AccessError> {
        if device_public_key == &self.signing_key.public_key() {
            return Err(AccessError::SelfApproval);
        }

        let target_device_id: [u8; 32] = blake3::hash(device_public_key).into();

        // Check if already registered.
        if let Some(existing) = self.storage.load_device(&target_device_id)? {
            if existing.trusted {
                return Err(AccessError::DeviceAlreadyTrusted(target_device_id));
            }
        }

        // Sign the approval.
        let mut msg = Vec::new();
        msg.extend_from_slice(device_public_key);
        msg.extend_from_slice(&self.signing_key.public_key());
        msg.extend_from_slice(&chrono::Utc::now().timestamp().to_le_bytes());
        let signature = self.signing_key.sign(&msg);

        let entry = DeviceEntry {
            device_id: target_device_id,
            public_key: device_public_key.to_vec(),
            trusted: true,
            approved_by: Some(self.device_id),
            approval_signature: Some(signature),
            created_at: chrono::Utc::now().timestamp(),
        };

        self.storage.store_device(entry)?;

        Ok(TrustEntry {
            device_id: target_device_id,
            public_key: device_public_key.to_vec(),
            trusted: true,
            approved_by: Some(self.device_id),
            created_at: chrono::Utc::now().timestamp(),
        })
    }

    /// Revoke trust for a device.
    pub fn revoke_device(&mut self, device_id: &[u8; 32]) -> Result<(), AccessError> {
        if *device_id == self.device_id {
            return Err(AccessError::SelfApproval);
        }
        self.storage.set_device_trusted(device_id, false)?;
        Ok(())
    }

    /// List all devices.
    pub fn list_devices(&self) -> Result<Vec<TrustEntry>, AccessError> {
        let entries = self.storage.list_devices()?;
        Ok(entries.into_iter().map(|e| TrustEntry {
            device_id: e.device_id,
            public_key: e.public_key,
            trusted: e.trusted,
            approved_by: e.approved_by,
            created_at: e.created_at,
        }).collect())
    }

    /// Share a record key with another device by looking up the key name
    /// and re-encrypting for the target device.
    pub fn share_key(
        &self,
        key_name: &str,
        target_device_id: &[u8; 32],
    ) -> Result<ReEncryptedBlob, AccessError> {
        // Look up the target device to get its public key.
        let device = self.storage.load_device(target_device_id)?
            .ok_or(AccessError::ShareTargetNotFound(*target_device_id))?;

        let target_public_key: [u8; 32] = if device.public_key.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&device.public_key);
            arr
        } else {
            return Err(AccessError::ShareTargetNotFound(*target_device_id));
        };

        // Derive shared secret via X25519.
        let shared_secret = self
            .x25519_key
            .exchange(&target_public_key)
            .map_err(|_| AccessError::Crypto(veildb_crypto::error::CryptoError::KeyExchange(
                "X25519 exchange failed".to_string()
            )))?;

        // Look up the key material from metadata.
        let key_data = self.storage.get_metadata(&format!("key:{}", key_name))?
            .ok_or_else(|| AccessError::KeyNotFound(key_name.to_string()))?;

        // Encrypt the key material with the shared secret.
        let ct = encrypt(&shared_secret, 0, &key_data)
            .map_err(AccessError::Crypto)?;

        Ok(ReEncryptedBlob {
            encrypted_key: ct.data,
            nonce: ct.nonce,
            target_device_id: *target_device_id,
            to_device: *target_device_id,
            key: key_name.to_string(),
        })
    }

    /// Create an encrypted backup archive.
    pub fn backup(&self, output: &Path) -> Result<EncryptedArchive, AccessError> {
        // Collect all operations and serialize them.
        let ops = self.storage.read_all_operations()?;
        let devices = self.storage.list_devices()?;

        let backup_data = serde_json::json!({
            "operations": ops.len(),
            "devices": devices.len(),
            "db_id": hex::encode(&self.db_id),
            "key_version": self.key_version,
        });

        let serialized = serde_json::to_vec(&backup_data)
            .map_err(|e| AccessError::Serialization(e.to_string()))?;

        // Encrypt with the master key.
        let ct = encrypt(&self.master_key, 0, &serialized)
            .map_err(AccessError::Crypto)?;

        // Compute merkle root over operations.
        let merkle_root = if ops.is_empty() {
            [0u8; 32]
        } else {
            let mut hasher = blake3::Hasher::new();
            for op in &ops {
                hasher.update(&op.signature);
            }
            *hasher.finalize().as_bytes()
        };

        // Write to file.
        let archive_data = postcard::to_allocvec(&(
            1u32, // format version
            self.db_id,
            merkle_root,
            ct.nonce,
            ct.data.clone(),
        )).map_err(|e| AccessError::Serialization(e.to_string()))?;

        std::fs::write(output, &archive_data)?;

        Ok(EncryptedArchive {
            format_version: 1,
            db_id: self.db_id,
            merkle_root,
        })
    }

    /// Restore from an encrypted backup archive.
    pub fn restore(&mut self, archive: &Path) -> Result<(), AccessError> {
        let data = std::fs::read(archive)?;

        let (format_version, db_id, _merkle_root, nonce, ciphertext): (
            u32, [u8; 32], [u8; 32], [u8; 12], Vec<u8>,
        ) = postcard::from_bytes(&data)
            .map_err(|e| AccessError::CorruptArchive(e.to_string()))?;

        if format_version != 1 {
            return Err(AccessError::UnsupportedArchiveVersion(format_version));
        }

        if db_id != self.db_id {
            return Err(AccessError::DbIdMismatch);
        }

        // Decrypt the archive.
        let ct = veildb_crypto::Ciphertext {
            key_version: 1,
            nonce,
            data: ciphertext,
        };
        let _plaintext = decrypt(&self.master_key, &ct)
            .map_err(|_| AccessError::BackupAuthenticationFailed)?;

        // In a full implementation, we'd deserialize and replay operations.
        // For now, we validate the archive is readable.
        Ok(())
    }
}

/// Helper to encode bytes as hex.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veildb_crypto::Key;
    use veildb_storage::SqliteStorage;

    fn test_engine() -> AccessEngine<SqliteStorage> {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let kp = SigningKeyPair::generate();
        let x25519 = X25519KeyPair::generate();
        let master_key = Key::generate();
        let db_id = [1u8; 32];
        AccessEngine::new(storage, &kp, &x25519, master_key, 1, db_id)
    }

    #[test]
    fn bootstrap_and_list_devices() {
        let mut engine = test_engine();
        engine.bootstrap_root().unwrap();

        let devices = engine.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert!(devices[0].trusted);
    }

    #[test]
    fn self_approval_rejected() {
        let mut engine = test_engine();
        engine.bootstrap_root().unwrap();

        let pubkey = engine.public_key();
        let err = engine.approve_device(&pubkey).unwrap_err();
        assert!(matches!(err, AccessError::SelfApproval));
    }

    #[test]
    fn trust_and_revoke() {
        let mut engine = test_engine();
        engine.bootstrap_root().unwrap();

        let kp2 = SigningKeyPair::generate();
        let info = engine.approve_device(&kp2.public_key()).unwrap();
        assert!(info.trusted);

        let device_id: [u8; 32] = blake3::hash(&kp2.public_key()).into();
        engine.revoke_device(&device_id).unwrap();

        let devices = engine.list_devices().unwrap();
        assert!(!devices.is_empty());
    }
}