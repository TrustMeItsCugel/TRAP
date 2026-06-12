//! Client-side session state machine. Spec §3.
//!
//! The client commits blind (Step 1, before seeing contents), verifies the
//! contents reveal against the Step 0 commitment, and can resolve
//! unilaterally from the server's timelock bundle after expiry (U3/U4).

use super::fields::{self};
use super::{ProtocolError, ProtocolFailure};
use crate::beacon::BeaconValue;
use crate::crypto::hash::{combine_secrets, commit, commit_contents, verify_commitment};
use crate::crypto::sign::{sign_fields, verify_field_signature};
use crate::crypto::timelock::{decrypt_server_payload, encrypt_secret};
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

impl ClientSession {
    /// Step 0→1: verify and accept the server's commitment, produce ours.
    ///
    /// The client commits *blind* — the contents are not yet revealed.
    pub fn accept(
        identity: &Identity,
        msg: ServerCommitment,
        beacon_public_key: &[u8],
    ) -> Result<(Self, ClientCommitment), ProtocolError> {
        // Verify the server's Step 0 signature.
        let buf = fields::server_commitment_fields_of(&msg);
        verify_field_signature(&msg.signature, &buf.as_fields(), &[], None)?;

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
        let combined = combine_secrets(&self.client_secret, &msg.server_secret);
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

    /// Unhappy path (U3/U4): the server stopped responding. Decrypt the
    /// server's timelock bundle with the round's beacon, verify both the
    /// secret and contents against the Step 0 commitments, and resolve.
    pub fn resolve_with_beacon(
        mut self,
        beacon: &BeaconValue,
    ) -> Result<(Self, Outcome), ProtocolFailure> {
        if matches!(self.state, State::Complete { .. }) {
            return Err(self.fail(ProtocolError::InvalidState {
                expected: "AwaitingContents or AwaitingServerReveal",
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

        // Decrypt the {secret, contents} bundle. Parse failure or
        // commitment mismatch is cryptographic proof of misbehaviour (U5).
        let payload = match decrypt_server_payload(
            &self.proof.server_commitment.server_timelock_encrypted,
            &beacon.signature,
        ) {
            Ok(p) => p,
            Err(e) => return Err(self.fail(e.into())),
        };

        if !verify_commitment(
            &payload.secret,
            &self.proof.server_commitment.server_commitment,
        ) {
            return Err(self.fail(ProtocolError::CommitmentMismatch {
                field: "server_commitment (timelock payload was junk)".into(),
            }));
        }
        let expected = self.proof.server_commitment.contents_commitment;
        if commit_contents(&payload.contents, &self.session_id) != expected {
            return Err(self.fail(ProtocolError::CommitmentMismatch {
                field: "contents_commitment (timelock payload was junk)".into(),
            }));
        }

        // U4 consistency: if contents were already revealed at Step 2, the
        // bundle must agree.
        if let Some(revealed) = &self.proof.contents_reveal {
            if revealed.contents != payload.contents {
                return Err(self.fail(ProtocolError::CommitmentMismatch {
                    field: "contents (bundle disagrees with Step 2 reveal)".into(),
                }));
            }
        }

        let combined = combine_secrets(&self.client_secret, &payload.secret);
        let outcome = match evaluate(&payload.contents, &combined) {
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
