//! Canonical signature field construction for each protocol message.
//!
//! Both signing (state machines) and verification (verify module) MUST
//! build field lists through these helpers so coverage always agrees.
//! Spec §5.2–5.3.

use crate::crypto::hash::{canonical_contents_bytes, canonical_outcome_bytes};
use crate::types::contents::Outcome;
use crate::types::messages::{
    ClientCommitment, ClientReveal, ContentsReveal, ServerCommitment, ServerReveal,
};

/// Recorded prior-signature names, by step.
pub const PRIOR_SERVER_COMMITMENT: &str = "signatures.server_commitment";
pub const PRIOR_CLIENT_COMMITMENT: &str = "signatures.client_commitment";
pub const PRIOR_CONTENTS_REVEAL: &str = "signatures.contents_reveal";
pub const PRIOR_CLIENT_REVEAL: &str = "signatures.client_reveal";

/// Owned field values that back the (&str, &[u8]) slices.
pub struct FieldBuf {
    pairs: Vec<(&'static str, Vec<u8>)>,
}

impl FieldBuf {
    pub fn as_fields(&self) -> Vec<(&str, &[u8])> {
        self.pairs
            .iter()
            .map(|(n, v)| (*n, v.as_slice()))
            .collect()
    }
}

/// Step 0 fields: everything in the server commitment except the signature.
#[allow(clippy::too_many_arguments)]
pub fn server_commitment_fields(
    version: &str,
    session_id: &str,
    server_commitment: &[u8; 32],
    contents_commitment: &[u8; 32],
    server_nonce_commitment: &[u8; 32],
    server_timelock_encrypted: &[u8],
    drand_round: u64,
    metadata: Option<&serde_json::Value>,
) -> FieldBuf {
    let mut pairs: Vec<(&'static str, Vec<u8>)> = vec![
        ("version", version.as_bytes().to_vec()),
        ("session_id", session_id.as_bytes().to_vec()),
        ("server_commitment", server_commitment.to_vec()),
        ("contents_commitment", contents_commitment.to_vec()),
        ("server_nonce_commitment", server_nonce_commitment.to_vec()),
        (
            "server_timelock_encrypted",
            server_timelock_encrypted.to_vec(),
        ),
        ("drand_round", drand_round.to_be_bytes().to_vec()),
    ];
    if let Some(m) = metadata {
        pairs.push((
            "metadata",
            serde_json::to_vec(m).expect("metadata serialisation"),
        ));
    }
    FieldBuf { pairs }
}

pub fn server_commitment_fields_of(msg: &ServerCommitment) -> FieldBuf {
    server_commitment_fields(
        &msg.version,
        &msg.session_id,
        &msg.server_commitment,
        &msg.contents_commitment,
        &msg.server_nonce_commitment,
        &msg.server_timelock_encrypted,
        msg.drand_round,
        msg.metadata.as_ref(),
    )
}

/// Step 1 fields.
pub fn client_commitment_fields(
    client_commitment: &[u8; 32],
    client_timelock_encrypted: &[u8],
) -> FieldBuf {
    FieldBuf {
        pairs: vec![
            ("client_commitment", client_commitment.to_vec()),
            (
                "client_timelock_encrypted",
                client_timelock_encrypted.to_vec(),
            ),
        ],
    }
}

pub fn client_commitment_fields_of(msg: &ClientCommitment) -> FieldBuf {
    client_commitment_fields(&msg.client_commitment, &msg.client_timelock_encrypted)
}

/// Step 2 fields: the revealed contents and the live nonce.
pub fn contents_reveal_fields(
    contents: &crate::types::contents::Contents,
    server_nonce: &[u8; 32],
) -> FieldBuf {
    FieldBuf {
        pairs: vec![
            ("contents", canonical_contents_bytes(contents)),
            ("server_nonce", server_nonce.to_vec()),
        ],
    }
}

pub fn contents_reveal_fields_of(msg: &ContentsReveal) -> FieldBuf {
    contents_reveal_fields(&msg.contents, &msg.server_nonce)
}

/// Step 3 fields.
pub fn client_reveal_fields(client_secret: &[u8; 32]) -> FieldBuf {
    FieldBuf {
        pairs: vec![("client_secret", client_secret.to_vec())],
    }
}

pub fn client_reveal_fields_of(msg: &ClientReveal) -> FieldBuf {
    client_reveal_fields(&msg.client_secret)
}

/// Step 4 fields.
pub fn server_reveal_fields(
    server_secret: &[u8; 32],
    combined_randomness: &[u8; 32],
    outcome: &Outcome,
) -> FieldBuf {
    FieldBuf {
        pairs: vec![
            ("server_secret", server_secret.to_vec()),
            ("combined_randomness", combined_randomness.to_vec()),
            ("outcome", canonical_outcome_bytes(outcome)),
        ],
    }
}

pub fn server_reveal_fields_of(msg: &ServerReveal) -> FieldBuf {
    server_reveal_fields(&msg.server_secret, &msg.combined_randomness, &msg.outcome)
}
