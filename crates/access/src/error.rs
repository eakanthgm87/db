//! Error types for the access control layer.

use thiserror::Error;

/// Errors that can occur in the access control layer.
#[derive(Debug, Error)]
pub enum AccessError {
    /// The device is not trusted.
    #[error("Device not trusted: {0:?}")]
    DeviceNotTrusted([u8; 32]),

    /// The device is already trusted.
    #[error("Device already trusted: {0:?}")]
    DeviceAlreadyTrusted([u8; 32]),

    /// A device attempted to approve itself.
    #[error("Device cannot approve itself")]
    SelfApproval,

    /// The device was not found.
    #[error("Device not found: {0:?}")]
    DeviceNotFound([u8; 32]),

    /// The root device has not been bootstrapped.
    #[error("Root device not bootstrapped")]
    NotBootstrapped,

    /// The root device is already bootstrapped.
    #[error("Root device already bootstrapped")]
    AlreadyBootstrapped,

    /// The target device for sharing was not found.
    #[error("Share target device not found: {0:?}")]
    ShareTargetNotFound([u8; 32]),

    /// The key to share was not found.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// The backup archive is corrupt.
    #[error("Corrupt backup archive: {0}")]
    CorruptArchive(String),

    /// The backup archive format is unsupported.
    #[error("Unsupported archive format version: {0}")]
    UnsupportedArchiveVersion(u32),

    /// The backup archive's Merkle root does not match.
    #[error("Backup Merkle root mismatch")]
    MerkleRootMismatch,

    /// The backup archive's database ID does not match.
    #[error("Backup database ID mismatch")]
    DbIdMismatch,

    /// The backup archive failed authentication/decryption.
    #[error("Backup authentication failed")]
    BackupAuthenticationFailed,

    /// The restore would leave the database in a partial state.
    #[error("Restore would leave partial state")]
    PartialRestore,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Storage error.
    #[error("Storage error: {0}")]
    Storage(#[from] veildb_storage::StorageError),

    /// Crypto error.
    #[error("Crypto error: {0}")]
    Crypto(#[from] veildb_crypto::error::CryptoError),

    /// Integrity error.
    #[error("Integrity error: {0}")]
    Integrity(#[from] veildb_integrity::error::IntegrityError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<postcard::Error> for AccessError {
    fn from(e: postcard::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}