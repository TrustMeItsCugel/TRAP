//! The TRAP protocol state machines and proof verification. Spec §3, §5.

pub mod client;
pub mod server;
pub mod verify;

pub mod fields;

use crate::beacon::BeaconError;
use crate::crypto::CryptoError;
use crate::types::contents::ContentsError;
use crate::types::messages::ProofDocument;

/// Errors arising during protocol execution.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Beacon(#[from] BeaconError),
    #[error(transparent)]
    Contents(#[from] ContentsError),
    #[error("invalid state: expected {expected}, got {got}")]
    InvalidState {
        expected: &'static str,
        got: &'static str,
    },
    #[error("commitment mismatch: {field}")]
    CommitmentMismatch { field: String },
    #[error("beacon value is for round {got}, session targets round {expected}")]
    WrongBeaconRound { expected: u64, got: u64 },
    #[error("message refers to session {got}, expected {expected}")]
    SessionIdMismatch { expected: String, got: String },
    #[error("invalid message: {0}")]
    InvalidMessage(String),
}

/// A protocol failure that preserves the evidence accumulated so far.
/// "The protocol fails cleanly": when a transition aborts, the proof
/// document up to that point is the record of what happened.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct ProtocolFailure {
    #[source]
    pub error: ProtocolError,
    /// The proof document at the moment of failure.
    pub proof: Box<ProofDocument>,
}
