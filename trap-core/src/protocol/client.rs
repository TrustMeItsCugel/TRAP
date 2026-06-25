//! Client-side session state machine. Spec §3.
//!
//! The client commits blind (Step 1, before seeing contents), verifies the
//! contents and nonce revealed at the live Step 2, and — once that live
//! reveal has happened — can resolve unilaterally from the server's
//! timelock-escrowed secret after expiry (U4).

use super::fields::{self};
use super::{ProtocolError, ProtocolFailure};
use crate::beacon::{validate_target_round, BeaconValue, ChainInfo, RoundPolicy};
use crate::crypto::hash::{combine_secrets, commit, commit_contents, verify_commitment};
use crate::crypto::sign::{sign_fields, verify_field_signature};
use crate::crypto::timelock::{decrypt_secret, encrypt_secret};
use crate::crypto::Identity;
use crate::outcome::evaluate;
use crate::types::contents::Outcome;
use crate::types::messages::{
    ClientCommitment, ClientReveal, ContentsReveal, ProofDocument, ResolutionMethod,
    ServerCommitment, ServerReveal,
};
use rand::RngCore;

enum State {
    /// Step 1 sent; awaiting the contents reveal.
    AwaitingContents,
    /// Step 3 sent; awaiting the server reveal.
    AwaitingServerReveal,
    Complete { outcome: Outcome },
}

impl State {
    fn name(&self) -> &'static str {
        match self {
            State::AwaitingContents => "AwaitingContents",
            State::AwaitingServerReveal => "AwaitingServerReveal",
            State::Complete { .. } => "Complete",
        }
    }
}

/// The client's view of one protocol session.
pub struct ClientSession {
    client_secret: [u8; 32],
    /// Pinned server signer key from Step 0; later steps must match.
    server_signer: [u8; 32],
    drand_round: u64,
    session_id: String,
    proof: ProofDocument,
    state: State,
}

/// Freshness check for the server-chosen timelock round, supplied to
/// [`ClientSession::accept`]. A production client MUST validate the round
/// before committing (Spec §7.1) — a server that names an already-elapsed or
/// out-of-policy round would otherwise undermine the timelock.
pub struct RoundCheck<'a> {
    pub chain: &'a ChainInfo,
    /// Current time, unix seconds.
    pub now_unix: u64,
    pub policy: RoundPolicy,
}

impl ClientSession {
    /// Step 0→1: verify and accept the server's commitment, produce ours.
    ///
    /// The client commits *blind* — the contents are not yet revealed.
    ///
    /// The server-chosen `drand_round` is validated against `round_check`
    /// (Spec §7.1) and the session is rejected if the round is already
    /// elapsed or out of policy. This is mandatory because the timelock only
    /// protects the client's secret while the round's beacon does not yet
    /// exist; skipping it forfeits that guarantee. The bypass —
    /// [`ClientSession::accept_unchecked`] — exists only for fixed-round test
    /// and replay scenarios and is named loudly on purpose.
    pub fn accept(
        identity: &Identity,
        msg: ServerCommitment,
        beacon_public_key: &[u8],
        round_check: &RoundCheck,
    ) -> Result<(Self, ClientCommitment), ProtocolError> {
        Self::accept_impl(identity, msg, beacon_public_key, Some(round_check))
    }

    /// Like [`ClientSession::accept`] but **without** the round-freshness
    /// check. Use ONLY when the `drand_round` is validated out of band, or in
    /// fixed-round test/replay flows. In production this re-opens the
    /// stall-then-decrypt window the round check closes — prefer `accept`.
    pub fn accept_unchecked(
        identity: &Identity,
        msg: ServerCommitment,
        beacon_public_key: &[u8],
    ) -> Result<(Self, ClientCommitment), ProtocolError> {
        Self::accept_impl(identity, msg, beacon_public_key, None)
    }

    fn accept_impl(
        identity: &Identity,
        msg: ServerCommitment,
        beacon_public_key: &[u8],
        round_check: Option<&RoundCheck>,
    ) -> Result<(Self, ClientCommitment), ProtocolError> {
        // Verify the server's Step 0 signature before trusting any of its
        // fields (the round we are about to check among them).
        let buf = fields::server_commitment_fields_of(&msg);
        verify_field_signature(&msg.signature, &buf.as_fields(), &[], None)?;

        // Reject an unacceptable timelock horizon before committing anything.
        if let Some(rc) = round_check {
            validate_target_round(rc.chain, msg.drand_round, rc.now_unix, &rc.policy)?;
        }

        let mut client_secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_secret);

        let client_commitment = commit(&client_secret);
        let client_timelock_encrypted =
            encrypt_secret(&client_secret, msg.drand_round, beacon_public_key)?;

        let buf = fields::client_commitment_fields(&client_commitment, &client_timelock_encrypted);
        let priors = [&msg.signature];
        let signature = sign_fields(
            identity,
            &buf.as_fields(),
            &priors,
            &[fields::PRIOR_SERVER_COMMITMENT],
        );

        let commitment = ClientCommitment {
            client_commitment,
            client_timelock_encrypted,
            signature,
        };

        let session = ClientSession {
            client_secret,
            server_signer: msg.signature.signer,
            drand_round: msg.drand_round,
            session_id: msg.session_id.clone(),
            proof: ProofDocument {
                server_commitment: msg,
                client_commitment: Some(commitment.clone()),
                contents_reveal: None,
                client_reveal: None,
                server_reveal: None,
                resolution: None,
            },
            state: State::AwaitingContents,
        };
        Ok((session, commitment))
    }

    fn fail(self, error: ProtocolError) -> ProtocolFailure {
        ProtocolFailure {
            error,
            proof: Box::new(self.proof),
        }
    }

    /// Steps 2→3: verify the contents reveal, produce our reveal.
    pub fn receive_contents(
        mut self,
        identity: &Identity,
        msg: ContentsReveal,
    ) -> Result<(Self, ClientReveal), ProtocolFailure> {
        if !matches!(self.state, State::AwaitingContents) {
            let got = self.state.name();
            return Err(self.fail(ProtocolError::InvalidState {
                expected: "AwaitingContents",
                got,
            }));
        }

        // Server must sign with the same key as Step 0, over the chain.
        let buf = fields::contents_reveal_fields_of(&msg);
        let priors = [
            &self.proof.server_commitment.signature,
            &self.proof.client_commitment.as_ref().expect("state").signature,
        ];
        if let Err(e) = verify_field_signature(
            &msg.signature,
            &buf.as_fields(),
            &priors,
            Some(&self.server_signer),
        ) {
            return Err(self.fail(e.into()));
        }

        // U7: revealed contents must match the Step 0 commitment.
        let expected = self.proof.server_commitment.contents_commitment;
        if commit_contents(&msg.contents, &self.session_id) != expected {
            self.proof.contents_reveal = Some(msg); // evidence of the mismatch
            return Err(self.fail(ProtocolError::CommitmentMismatch {
                field: "contents_commitment".into(),
            }));
        }

        // The live nonce must match its Step 0 commitment too.
        let expected_nonce = self.proof.server_commitment.server_nonce_commitment;
        if !verify_commitment(&msg.server_nonce, &expected_nonce) {
            self.proof.contents_reveal = Some(msg); // evidence of the mismatch
            return Err(self.fail(ProtocolError::CommitmentMismatch {
                field: "server_nonce_commitment".into(),
            }));
        }

        self.proof.contents_reveal = Some(msg);

        // Step 3: reveal our secret.
        let buf = fields::client_reveal_fields(&self.client_secret);
        let priors = [
            &self.proof.server_commitment.signature,
            &self.proof.client_commitment.as_ref().unwrap().signature,
            &self.proof.contents_reveal.as_ref().unwrap().signature,
        ];
        let signature = sign_fields(
            identity,
            &buf.as_fields(),
            &priors,
            &[
                fields::PRIOR_SERVER_COMMITMENT,
                fields::PRIOR_CLIENT_COMMITMENT,
                fields::PRIOR_CONTENTS_REVEAL,
            ],
        );
        let reveal = ClientReveal {
            client_secret: self.client_secret,
            signature,
        };
        self.proof.client_reveal = Some(reveal.clone());
        self.state = State::AwaitingServerReveal;
        Ok((self, reveal))
    }

    /// Step 4: verify the server's reveal and independently confirm the
    /// outcome computation.
    pub fn receive_server_reveal(
        mut self,
        msg: ServerReveal,
    ) -> Result<(Self, Outcome), ProtocolFailure> {
        if !matches!(self.state, State::AwaitingServerReveal) {
            let got = self.state.name();
            return Err(self.fail(ProtocolError::InvalidState {
                expected: "AwaitingServerReveal",
                got,
            }));
        }

        let buf = fields::server_reveal_fields_of(&msg);
        let priors = [
            &self.proof.server_commitment.signature,
            &self.proof.client_commitment.as_ref().expect("state").signature,
            &self.proof.contents_reveal.as_ref().expect("state").signature,
            &self.proof.client_reveal.as_ref().expect("state").signature,
        ];
        if let Err(e) = verify_field_signature(
            &msg.signature,
            &buf.as_fields(),
            &priors,
            Some(&self.server_signer),
        ) {
            return Err(self.fail(e.into()));
        }

        // U9: revealed secret must match the Step 0 commitment.
        if !verify_commitment(
            &msg.server_secret,
            &self.proof.server_commitment.server_commitment,
        ) {
            self.proof.server_reveal = Some(msg);
            return Err(self.fail(ProtocolError::CommitmentMismatch {
                field: "server_commitment".into(),
            }));
        }

        // Independently recompute the combined randomness and outcome.
        let server_nonce = self.proof.contents_reveal.as_ref().expect("state").server_nonce;
        let combined = combine_secrets(&self.client_secret, &msg.server_secret, &server_nonce);
        if combined != msg.combined_randomness {
            self.proof.server_reveal = Some(msg);
            return Err(self.fail(ProtocolError::CommitmentMismatch {
                field: "combined_randomness".into(),
            }));
        }
        let contents = &self.proof.contents_reveal.as_ref().expect("state").contents;
        let outcome = match evaluate(contents, &combined) {
            Ok(o) => o,
            Err(e) => return Err(self.fail(e.into())),
        };
        if outcome != msg.outcome {
            self.proof.server_reveal = Some(msg);
            return Err(self.fail(ProtocolError::CommitmentMismatch {
                field: "outcome".into(),
            }));
        }

        self.proof.server_reveal = Some(msg);
        self.proof.resolution = Some(ResolutionMethod::Cooperative);
        self.state = State::Complete {
            outcome: outcome.clone(),
        };
        Ok((self, outcome))
    }

    /// Unhappy path (U4): the server revealed the contents and nonce at the
    /// live Step 2 but then stopped (no Step 4). After expiry the client
    /// decrypts the server secret from its timelock and resolves.
    ///
    /// Note the deliberate asymmetry with the old design: the server's
    /// timelock now escrows only its secret, never the contents or nonce.
    /// If the server ghosts *before* the live reveal (no `contents_reveal`
    /// in the document), the session is unresolvable and voids cleanly —
    /// which is harmless, because the server never disclosed anything
    /// outcome-determining and could not have known the client secret, so
    /// it gained no advantage by aborting.
    pub fn resolve_with_beacon(
        mut self,
        beacon: &BeaconValue,
    ) -> Result<(Self, Outcome), ProtocolFailure> {
        if matches!(self.state, State::Complete { .. }) {
            return Err(self.fail(ProtocolError::InvalidState {
                expected: "AwaitingServerReveal",
                got: "Complete",
            }));
        }

        if beacon.round != self.drand_round {
            let expected = self.drand_round;
            return Err(self.fail(ProtocolError::WrongBeaconRound {
                expected,
                got: beacon.round,
            }));
        }

        // Pre-reveal server ghost: nothing to resolve, session voids cleanly.
        let (contents, server_nonce) = match &self.proof.contents_reveal {
            Some(cr) => (cr.contents.clone(), cr.server_nonce),
            None => {
                return Err(self.fail(ProtocolError::InvalidState {
                    expected: "ContentsRevealed",
                    got: "AwaitingContents (server ghosted before the live reveal)",
                }))
            }
        };

        // Decrypt the server secret. Parse failure or commitment mismatch is
        // cryptographic proof of misbehaviour (U5).
        let server_secret = match decrypt_secret(
            &self.proof.server_commitment.server_timelock_encrypted,
            &beacon.signature,
        ) {
            Ok(s) => s,
            Err(e) => return Err(self.fail(e.into())),
        };

        if !verify_commitment(
            &server_secret,
            &self.proof.server_commitment.server_commitment,
        ) {
            return Err(self.fail(ProtocolError::CommitmentMismatch {
                field: "server_commitment (timelock payload was junk)".into(),
            }));
        }

        let combined = combine_secrets(&self.client_secret, &server_secret, &server_nonce);
        let outcome = match evaluate(&contents, &combined) {
            Ok(o) => o,
            Err(e) => return Err(self.fail(e.into())),
        };

        self.proof.resolution = Some(ResolutionMethod::TimelockServerPayload);
        self.state = State::Complete {
            outcome: outcome.clone(),
        };
        Ok((self, outcome))
    }

    /// The proof document at the current state.
    pub fn proof(&self) -> &ProofDocument {
        &self.proof
    }

    /// The outcome, if the session is complete.
    pub fn outcome(&self) -> Option<&Outcome> {
        match &self.state {
            State::Complete { outcome } => Some(outcome),
            _ => None,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSession")
            .field("session_id", &self.session_id)
            .field("state", &self.state.name())
            .field("client_secret", &"[redacted]")
            .finish()
    }
}
