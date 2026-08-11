//! Error types for the crypto layer.

use thiserror::Error;

/// Errors that can occur in the crypto layer.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AES-GCM encryption/decryption failed.
    #[error("AEAD error: {0}")]
    Aead(String),

    /// Invalid key length.
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),

    /// Invalid nonce length.
    #[error("Invalid nonce length: {0}")]
    InvalidNonceLength(usize),

    /// Invalid signature.
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid public key.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid secret key.
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// Key derivation failed.
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    /// Key exchange failed.
    #[error("Key exchange failed: {0}")]
    KeyExchange(String),

    /// Random number generation failed.
    #[error("RNG failure: {0}")]
    Rng(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Unsupported key version.
    #[error("Unsupported key version: {0}")]
    UnsupportedKeyVersion(u32),
}

impl From<postcard::Error> for CryptoError {
    fn from(e: postcard::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}