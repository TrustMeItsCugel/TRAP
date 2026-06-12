//! Standalone proof verification. Spec §4.3, test scenarios V1–V8.
//!
//! Verification is stateless: any party holding a proof document (and,
//! for timelock-resolved sessions, the round's beacon value) can confirm
//! every signature, every commitment-reveal binding, and the outcome.

use super::fields;
use super::ProtocolError;
use crate::beacon::BeaconValue;
use crate::crypto::hash::{combine_secrets, commit_contents, verify_commitment};
use crate::crypto::sign::verify_field_signature;
use crate::crypto::timelock::{decrypt_secret, decrypt_server_payload};
use crate::outcome::evaluate;
use crate::types::contents::Outcome;
use crate::types::messages::ProofDocument;
use serde::{Deserialize, Serialize};

/// How far the session progressed, as evidenced by the document.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionProgress {
    ServerCommitted,
    ClientCommitted,
    ContentsRevealed,
    ClientRevealed,
    Complete,
}

/// The result of verifying a proof document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub progress: SessionProgress,
    /// All present signatures verified, in chain order.
    pub signatures_valid: bool,
    /// All present reveals match their commitments.
    pub commitments_match: bool,
    /// The outcome (recomputed when determinable).
    pub outcome: Option<Outcome>,
    /// True when `outcome` was independently recomputed and, where the
    /// document claims one, matches the claim.
    pub outcome_verified: bool,
}

/// Verify a proof document. For documents without a cooperative Step 4,
/// supplying the target round's `beacon` lets verification resolve and
/// check timelock payloads (V8); without it, verification covers the
/// signatures and any present reveals (V7).
pub fn verify_proof(
    proof: &ProofDocument,
    beacon: Option<&BeaconValue>,
) -> Result<VerifyResult, ProtocolError> {
    let sc = &proof.server_commitment;
    let session_id = &sc.session_id;

    // ---- signature chain (V1, V2, V6) ----
    let buf = fields::server_commitment_fields_of(sc);
    verify_field_signature(&sc.signature, &buf.as_fields(), &[], None)?;
    let server_signer = sc.signature.signer;

    let mut progress = SessionProgress::ServerCommitted;

    if let Some(cc) = &proof.client_commitment {
        let buf = fields::client_commitment_fields_of(cc);
        verify_field_signature(&cc.signature, &buf.as_fields(), &[&sc.signature], None)?;
        progress = SessionProgress::ClientCommitted;
    }

    if let Some(cr) = &proof.contents_reveal {
        let cc = proof
            .client_commitment
            .as_ref()
            .ok_or_else(|| ProtocolError::InvalidMessage("contents reveal without client commitment".into()))?;
        let buf = fields::contents_reveal_fields_of(cr);
        verify_field_signature(
            &cr.signature,
            &buf.as_fields(),
            &[&sc.signature, &cc.signature],
            Some(&server_signer),
        )?;
        progress = SessionProgress::ContentsRevealed;
    }

    if let Some(clr) = &proof.client_reveal {
        let cc = proof.client_commitment.as_ref().ok_or_else(|| {
            ProtocolError::InvalidMessage("client reveal without client commitment".into())
        })?;
        let cr = proof.contents_reveal.as_ref().ok_or_else(|| {
            ProtocolError::InvalidMessage("client reveal without contents reveal".into())
        })?;
        let buf = fields::client_reveal_fields_of(clr);
        verify_field_signature(
            &clr.signature,
            &buf.as_fields(),
            &[&sc.signature, &cc.signature, &cr.signature],
            Some(&cc.signature.signer),
        )?;
        progress = SessionProgress::ClientRevealed;
    }

    if let Some(sr) = &proof.server_reveal {
        let cc = proof.client_commitment.as_ref().ok_or_else(|| {
            ProtocolError::InvalidMessage("server reveal without client commitment".into())
        })?;
        let cr = proof.contents_reveal.as_ref().ok_or_else(|| {
            ProtocolError::InvalidMessage("server reveal without contents reveal".into())
        })?;
        let clr = proof.client_reveal.as_ref().ok_or_else(|| {
            ProtocolError::InvalidMessage("server reveal without client reveal".into())
        })?;
        let buf = fields::server_reveal_fields_of(sr);
        verify_field_signature(
            &sr.signature,
            &buf.as_fields(),
            &[&sc.signature, &cc.signature, &cr.signature, &clr.signature],
            Some(&server_signer),
        )?;
        progress = SessionProgress::Complete;
    }
    let signatures_valid = true; // any failure above already returned Err

    // ---- commitment-reveal consistency (V3, V4) ----
    let mut commitments_match = true;
    if let Some(cr) = &proof.contents_reveal {
        if commit_contents(&cr.contents, session_id) != sc.contents_commitment {
            commitments_match = false;
        }
    }
    if let (Some(cc), Some(clr)) = (&proof.client_commitment, &proof.client_reveal) {
        if !verify_commitment(&clr.client_secret, &cc.client_commitment) {
            commitments_match = false;
        }
    }
    if let Some(sr) = &proof.server_reveal {
        if !verify_commitment(&sr.server_secret, &sc.server_commitment) {
            commitments_match = false;
        }
    }

    // ---- outcome recomputation (V5, V8) ----
    let mut outcome: Option<Outcome> = None;
    let mut outcome_verified = false;

    // Cooperative path: both secrets revealed in-document.
    if let (Some(clr), Some(sr), Some(cr), true) = (
        &proof.client_reveal,
        &proof.server_reveal,
        &proof.contents_reveal,
        commitments_match,
    ) {
        let combined = combine_secrets(&clr.client_secret, &sr.server_secret);
        if combined == sr.combined_randomness {
            if let Ok(o) = evaluate(&cr.contents, &combined) {
                outcome_verified = o == sr.outcome;
                outcome = Some(o);
            }
        }
    }
    // Timelock path: resolve from ciphertexts using the beacon (V8).
    else if let (Some(beacon), true) = (beacon, commitments_match) {
        if beacon.round == sc.drand_round {
            // Server bundle gives secret + contents.
            if let Ok(payload) =
                decrypt_server_payload(&sc.server_timelock_encrypted, &beacon.signature)
            {
                let secret_ok =
                    verify_commitment(&payload.secret, &sc.server_commitment);
                let contents_ok =
                    commit_contents(&payload.contents, session_id) == sc.contents_commitment;
                if !(secret_ok && contents_ok) {
                    commitments_match = false;
                } else {
                    // Client secret: prefer in-document reveal, else timelock.
                    let client_secret = if let Some(clr) = &proof.client_reveal {
                        Some(clr.client_secret)
                    } else if let Some(cc) = &proof.client_commitment {
                        match decrypt_secret(&cc.client_timelock_encrypted, &beacon.signature) {
                            Ok(s) if verify_commitment(&s, &cc.client_commitment) => Some(s),
                            Ok(_) => {
                                commitments_match = false;
                                None
                            }
                            Err(_) => {
                                commitments_match = false;
                                None
                            }
                        }
                    } else {
                        None
                    };
                    if let Some(cs) = client_secret {
                        let combined = combine_secrets(&cs, &payload.secret);
                        if let Ok(o) = evaluate(&payload.contents, &combined) {
                            outcome = Some(o);
                            outcome_verified = true;
                        }
                    }
                }
            } else {
                commitments_match = false;
            }
        }
    }

    Ok(VerifyResult {
        progress,
        signatures_valid,
        commitments_match,
        outcome,
        outcome_verified,
    })
}
