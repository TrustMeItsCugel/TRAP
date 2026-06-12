//! Cryptographic operations: commitments, field signatures with chaining,
//! and timelock encryption wrappers around ideal-lab5/timelock.

pub mod hash;
pub mod sign;
pub mod timelock;

pub use sign::Identity;

/// Errors from cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("timelock encryption failed: {0}")]
    TimelockEncrypt(String),
    #[error("timelock decryption failed: {0}")]
    TimelockDecrypt(String),
    #[error("timelock payload malformed: {0}")]
    TimelockPayload(String),
}
