//! Error types for the integrity layer.

use thiserror::Error;

/// Errors that can occur in the integrity layer.
#[derive(Debug, Error)]
pub enum IntegrityError {
    /// An operation hash did not match its recomputed value.
    #[error("Operation hash mismatch for {0:?}")]
    OperationHashMismatch(veildb_storage::OperationId),

    /// A Merkle proof failed to verify.
    #[error("Merkle proof verification failed")]
    ProofVerificationFailed,

    /// The Merkle tree is empty.
    #[error("Merkle tree is empty")]
    EmptyTree,

    /// A leaf was not found in the tree.
    #[error("Leaf not found")]
    LeafNotFound,

    /// The operation graph has a cycle.
    #[error("Operation graph contains a cycle")]
    GraphCycle,

    /// A parent operation is missing.
    #[error("Missing parent operation: {0:?}")]
    MissingParent([u8; 32]),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Storage error.
    #[error("Storage error: {0}")]
    Storage(#[from] veildb_storage::StorageError),
}

impl From<postcard::Error> for IntegrityError {
    fn from(e: postcard::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}