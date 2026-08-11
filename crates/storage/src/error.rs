//! Error types for the storage layer.

use thiserror::Error;

/// Errors that can occur in the storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    /// SQLite returned an error.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Failed to serialize/deserialize data.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// An operation with the same ID already exists.
    #[error("Duplicate operation: {0:?}")]
    DuplicateOperation(crate::types::OperationId),

    /// A device with the same ID already exists.
    #[error("Duplicate device: {0:?}")]
    DuplicateDevice([u8; 32]),

    /// The requested operation was not found.
    #[error("Operation not found: {0:?}")]
    OperationNotFound(crate::types::OperationId),

    /// The requested snapshot was not found.
    #[error("Snapshot not found: {0}")]
    SnapshotNotFound(crate::types::SnapshotId),

    /// The requested device was not found.
    #[error("Device not found: {0:?}")]
    DeviceNotFound([u8; 32]),

    /// The database is in an inconsistent state.
    #[error("Database integrity violation: {0}")]
    IntegrityViolation(String),

    /// The database is locked by another connection.
    #[error("Database is locked")]
    DatabaseLocked,

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The database path is invalid.
    #[error("Invalid database path: {0}")]
    InvalidPath(String),

    /// The database schema version is not supported.
    #[error("Unsupported schema version: {0}")]
    UnsupportedSchemaVersion(i32),

    /// A migration failed.
    #[error("Migration failed: {0}")]
    MigrationFailed(String),
}

impl From<postcard::Error> for StorageError {
    fn from(e: postcard::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}