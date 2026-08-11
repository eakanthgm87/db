//! Error types for the query layer.

use thiserror::Error;

/// Errors that can occur in the query layer.
#[derive(Debug, Error)]
pub enum QueryError {
    /// The requested key was not found.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Failed to decrypt an index token.
    #[error("Index decryption failed: {0}")]
    IndexDecryption(String),

    /// The logical clock is invalid.
    #[error("Invalid logical clock")]
    InvalidClock,

    /// No snapshot exists at or before the requested clock.
    #[error("No snapshot found at or before the requested clock")]
    NoSnapshotFound,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Storage error.
    #[error("Storage error: {0}")]
    Storage(#[from] veildb_storage::StorageError),

    /// Crypto error.
    #[error("Crypto error: {0}")]
    Crypto(#[from] veildb_crypto::error::CryptoError),
}

impl From<postcard::Error> for QueryError {
    fn from(e: postcard::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}