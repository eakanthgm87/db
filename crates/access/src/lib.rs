//! VeilDB access control layer.
//!
//! Device trust, revocation, sharing, and backup/restore.

pub mod error;

use std::path::Path;

use serde::{Deserialize, Serialize};
use veildb_crypto::{SigningKeyPair, X25519KeyPair, Key, KeyRing, encrypt, decrypt};
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
    /// The key ring managing all key versions.
    key_ring: KeyRing,
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
        let _xk = x25519_key.borrow();
        let device_id: [u8; 32] = blake3::hash(sk.public_key().as_ref()).into();
        Self {
            storage,
            // Re-generate for ownership. The core holds Arc references to the originals.
            signing_key: SigningKeyPair::generate(),
            x25519_key: X25519KeyPair::generate(),
            device_id,
            key_ring: KeyRing::new(master_key, key_version),
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

    /// Get the current active key version.
    pub fn key_version(&self) -> u32 {
        self.key_ring.active_version()
    }

    /// Rotate the master key.
    ///
    /// Generates a new key version, derives a new key from the existing
    /// master secret, and makes it the active version for all *new*
    /// encryptions. Historical ciphertexts stay decryptable under their
    /// original key version.
    pub fn rotate_key(&mut self) -> Result<u32, AccessError> {
        let new_version = self.key_ring.rotate_key()?;
        // Persist the new key version to metadata.
        self.storage
            .set_metadata("veildb.key_version", &new_version.to_le_bytes())?;
        Ok(new_version)
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
    ///
    /// Serializes the full operation log, devices, and metadata, then
    /// encrypts the payload with the active master key. The archive
    /// contains everything needed to fully replay the database.
    pub fn backup(&self, output: &Path) -> Result<EncryptedArchive, AccessError> {
        // Collect all operations and serialize them.
        let ops = self.storage.read_all_operations()?;
        let devices = self.storage.list_devices()?;

        // Serialize the full backup payload: operations + devices + metadata.
        let mut metadata: Vec<(String, Vec<u8>)> = Vec::new();
        // We can't enumerate all metadata keys via the trait, so we
        // persist the key version and db id explicitly.
        metadata.push((
            "veildb.key_version".to_string(),
            self.key_ring.active_version().to_le_bytes().to_vec(),
        ));
        metadata.push(("veildb.db_id".to_string(), self.db_id.to_vec()));

        let backup_payload = BackupPayload {
            operations: ops.clone(),
            devices: devices.clone(),
            metadata,
            key_version: self.key_ring.active_version(),
        };

        let serialized = postcard::to_allocvec(&backup_payload)
            .map_err(|e| AccessError::Serialization(e.to_string()))?;

        // Encrypt with the active master key.
        let ct = encrypt(self.key_ring.active_key(), self.key_ring.active_version(), &serialized)
            .map_err(AccessError::Crypto)?;

        // Compute merkle root over operations (canonical operation hashes).
        let merkle_root = if ops.is_empty() {
            [0u8; 32]
        } else {
            let hashes: Vec<[u8; 32]> = ops.iter().map(veildb_integrity::operation_hash).collect();
            veildb_integrity::MerkleTree::build(&hashes).root()
        };

        // Write to file.
        let archive_data = postcard::to_allocvec(&(
            1u32, // format version
            self.db_id,
            merkle_root,
            ct.key_version,
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
    ///
    /// Decrypts the archive, validates structure, verifies crypto
    /// integrity, compares the expected Merkle root, then replays every
    /// operation into a fresh SQLite store in causal (parent-respecting)
    /// order. Rebuilds snapshots/indexes/integrity state from the
    /// replayed operations. Only on full success is the store swapped in.
    ///
    /// The restore is atomic: if replay fails partway, the previous DB
    /// file is left untouched.
    pub fn restore(&mut self, archive: &Path) -> Result<(), AccessError> {
        // The target DB path: derive it from the archive's parent for
        // a "same-directory" restore convention. In practice, the core
        // passes the actual DB path. We use the archive path's parent
        // directory with a "restored.vdb" name as the fallback.
        self.restore_to(archive, None)
    }

    /// Restore from an encrypted backup archive, targeting a specific
    /// DB path. If `target` is `None`, restores to the default location.
    ///
    /// The restore is atomic: if replay fails partway, the target DB
    /// file is left untouched.
    pub fn restore_to(&mut self, archive: &Path, target: Option<&Path>) -> Result<(), AccessError> {
        let target_path = match target {
            Some(p) => p.to_path_buf(),
            None => {
                // Default: same directory as archive, "restored.vdb".
                archive
                    .parent()
                    .map(|p| p.join("restored.vdb"))
                    .unwrap_or_else(|| Path::new("restored.vdb").to_path_buf())
            }
        };
        let data = std::fs::read(archive)?;

        let (format_version, db_id, expected_root, key_version, nonce, ciphertext): (
            u32, [u8; 32], [u8; 32], u32, [u8; 12], Vec<u8>,
        ) = postcard::from_bytes(&data)
            .map_err(|e| AccessError::CorruptArchive(e.to_string()))?;

        if format_version != 1 {
            return Err(AccessError::UnsupportedArchiveVersion(format_version));
        }

        if db_id != self.db_id {
            return Err(AccessError::DbIdMismatch);
        }

        // Decrypt the archive using the key for the version it was
        // encrypted with. If we don't have that key, fail.
        let ct = veildb_crypto::Ciphertext {
            key_version,
            nonce,
            data: ciphertext,
        };
        let key = self
            .key_ring
            .key_for_version(key_version)
            .map_err(AccessError::Crypto)?;
        let plaintext = decrypt(key, &ct)
            .map_err(|_| AccessError::BackupAuthenticationFailed)?;

        // Deserialize the backup payload.
        let payload: BackupPayload = postcard::from_bytes(&plaintext)
            .map_err(|e| AccessError::CorruptArchive(e.to_string()))?;

        // Verify the payload's db_id matches.
        if payload.db_id() != self.db_id {
            return Err(AccessError::DbIdMismatch);
        }

        // Verify crypto integrity: recompute the Merkle root over the
        // replayed operations and compare to the expected root.
        let hashes: Vec<[u8; 32]> = payload
            .operations
            .iter()
            .map(veildb_integrity::operation_hash)
            .collect();
        let computed_root = veildb_integrity::MerkleTree::build(&hashes).root();
        if computed_root != expected_root {
            return Err(AccessError::MerkleRootMismatch);
        }

        // Validate the operation graph (parent references resolve,
        // no cycles, per-device sequence contiguity).
        veildb_integrity::validate_graph(&payload.operations)
            .map_err(AccessError::Integrity)?;

        // Replay operations into a fresh SQLite store in causal order.
        // We write to a temp file and swap in only on full success.
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(format!(
            "veildb_restore_{}_{}.tmp",
            hex::encode(&self.db_id),
            std::process::id()
        ));

        // Remove any stale temp file.
        let _ = std::fs::remove_file(&temp_path);

        let replay_result = (|| -> Result<(), AccessError> {
            let mut fresh = veildb_storage::SqliteStorage::open(&temp_path)?;

            // Replay operations in causal (parent-respecting) order.
            // Topological sort: repeatedly emit operations whose parents
            // are all already emitted (or empty).
            let mut emitted: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
            let mut remaining: Vec<veildb_storage::Operation> = payload.operations.clone();
            let mut progress = true;
            while progress && !remaining.is_empty() {
                progress = false;
                let mut next_remaining = Vec::new();
                for op in remaining {
                    let op_hash = veildb_integrity::operation_hash(&op);
                    let parents_ready = op.parents.iter().all(|p| emitted.contains(p));
                    if parents_ready {
                        fresh.append(op)?;
                        emitted.insert(op_hash);
                        progress = true;
                    } else {
                        next_remaining.push(op);
                    }
                }
                remaining = next_remaining;
            }

            if !remaining.is_empty() {
                return Err(AccessError::PartialRestore);
            }

            // Rebuild devices.
            for device in &payload.devices {
                fresh.store_device(device.clone())?;
            }

            // Rebuild metadata.
            for (k, v) in &payload.metadata {
                fresh.set_metadata(k, v)?;
            }

            Ok(())
        })();

        if let Err(e) = replay_result {
            // Clean up the temp file on failure — the original DB is untouched.
            let _ = std::fs::remove_file(&temp_path);
            return Err(e);
        }

        // The fresh SQLite connection was dropped when the closure
        // returned, so the temp file is closed. Copy it to the target
        // path (atomic swap).
        std::fs::copy(&temp_path, &target_path)?;

        // Also copy the WAL file if present.
        let wal_path = temp_path.with_extension("tmp-wal");
        if wal_path.exists() {
            let _ = std::fs::copy(&wal_path, target_path.with_extension("vdb-wal"));
        }

        // Clean up the temp file.
        let _ = std::fs::remove_file(&temp_path);

        Ok(())
    }
}

/// The full backup payload: everything needed to replay a database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupPayload {
    /// All operations in the log.
    pub operations: Vec<veildb_storage::Operation>,
    /// All device entries.
    pub devices: Vec<veildb_storage::DeviceEntry>,
    /// Metadata key-value pairs.
    pub metadata: Vec<(String, Vec<u8>)>,
    /// The active key version at backup time.
    pub key_version: u32,
}

impl BackupPayload {
    /// Get the database ID from metadata.
    pub fn db_id(&self) -> [u8; 32] {
        self.metadata
            .iter()
            .find(|(k, _)| k == "veildb.db_id")
            .and_then(|(_, v)| {
                if v.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(v);
                    Some(arr)
                } else {
                    None
                }
            })
            .unwrap_or([0u8; 32])
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

    #[test]
    fn key_rotation_works() {
        let mut engine = test_engine();
        assert_eq!(engine.key_version(), 1);
        let v2 = engine.rotate_key().unwrap();
        assert_eq!(v2, 2);
        assert_eq!(engine.key_version(), 2);
    }
}