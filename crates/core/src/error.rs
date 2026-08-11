//! Error types for the core facade.

use thiserror::Error;

/// Errors that can occur in the core layer.
#[derive(Debug, Error)]
pub enum CoreError {
    /// The database is not initialized.
    #[error("Database not initialized")]
    NotInitialized,

    /// The database is already initialized.
    #[error("Database already initialized")]
    AlreadyInitialized,

    /// Invalid passphrase.
    #[error("Invalid passphrase")]
    InvalidPassphrase,

    /// The database file already exists but no passphrase was provided.
    #[error("Database exists but no passphrase provided")]
    MissingPassphrase,

    /// The database file does not exist.
    #[error("Database file not found: {0}")]
    DbNotFound(String),

    /// Storage error.
    #[error("Storage error: {0}")]
    Storage(#[from] veildb_storage::StorageError),

    /// Crypto error.
    #[error("Crypto error: {0}")]
    Crypto(#[from] veildb_crypto::error::CryptoError),

    /// Integrity error.
    #[error("Integrity error: {0}")]
    Integrity(#[from] veildb_integrity::error::IntegrityError),

    /// Query error.
    #[error("Query error: {0}")]
    Query(#[from] veildb_query::error::QueryError),

    /// Access error.
    #[error("Access error: {0}")]
    Access(#[from] veildb_access::error::AccessError),

    /// Sync error.
    #[error("Sync error: {0}")]
    Sync(#[from] veildb_sync::error::SyncError),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The requested operation was not found.
    #[error("Operation not found")]
    OperationNotFound,
}

impl From<postcard::Error> for CoreError {
    fn from(e: postcard::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}