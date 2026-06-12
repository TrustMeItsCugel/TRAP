//! Server-side session state machine. Spec §3.
//!
//! Transitions consume `self`; a session cannot be advanced twice from the
//! same state. On failure, `ProtocolFailure` carries the proof document
//! accumulated so far — the protocol fails cleanly, preserving evidence.

use super::fields::{self, FieldBuf};
use super::{ProtocolError, ProtocolFailure};
use crate::beacon::BeaconValue;
use crate::crypto::hash::{combine_secrets, commit, commit_contents, verify_commitment};
use crate::crypto::sign::{sign_fields, verify_field_signature};
use crate::crypto::timelock::{
    decrypt_secret, encrypt_server_payload, ServerTimelockPayload,
};
use crate::crypto::Identity;
use crate::outcome::evaluate;
use crate::types::contents::{Contents, Outcome};
use crate::types::messages::{
    ClientCommitment, ClientReveal, ContentsReveal, ProofDocument, ResolutionMethod,
    ServerCommitment, ServerReveal, SessionConfig,
};
use rand::RngCore;

enum State {
    /// Step 0 sent; awaiting the client's commitment.
    AwaitingClientCommitment,
    /// Steps 0–2 done; awaiting the client's reveal.
    AwaitingClientReveal,
    /// Outcome determined (cooperatively or via timelock).
    Complete { outcome: Outcome },
}

impl State {
    fn name(&self) -> &'static str {
        match self {
            State::AwaitingClientCommitment => "AwaitingClientCommitment",
            State::AwaitingClientReveal => "AwaitingClientReveal",
            State::Complete { .. } => "Complete",
        }
    }
}

/// The server's view of one protocol session.
pub struct ServerSession {
    server_secret: [u8; 32],
    contents: Contents,
    config: SessionConfig,
    proof: ProofDocument,
    state: State,
}

impl ServerSession {
    /// Step 0: create a session and produce the server commitment.
    ///
    /// Generates the server secret, commits to it and the contents, and
    /// timelock-encrypts the {secret, contents} bundle to the target round.
    pub fn initiate(
        identity: &Identity,
        contents: Contents,
        config: SessionConfig,
        beacon_public_key: &[u8],
    ) -> Result<(Self, ServerCommitment), ProtocolError> {
        contents.validate()?;

        let mut server_secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut server_secret);

        let server_commitment = commit(&server_secret);
        let contents_commitment = commit_contents(&contents, &config.session_id);
        let server_timelock_encrypted = encrypt_server_payload(
            &ServerTimelockPayload {
                secret: server_secret,
                contents: contents.clone(),
            },
            config.drand_round,
            beacon_public_key,
        )?;

        let buf: FieldBuf = fields::server_commitment_fields(
            &config.version,
            &config.session_id,
            &server_commitment,
            &contents_commitment,
            &server_timelock_encrypted,
            config.drand_round,
            config.metadata.as_ref(),
        );
        let signature = sign_fields(identity, &buf.as_fields(), &[], &[]);

        let msg = ServerCommitment {
            version: config.version.clone(),
            session_id: config.session_id.clone(),
            server_commitment,
            contents_commitment,
            server_timelock_encrypted,
            drand_round: config.drand_round,
            metadata: config.metadata.clone(),
            signature,
        };

        let session = ServerSession {
            server_secret,
            contents,
            config,
            proof: ProofDocument {
                server_commitment: msg.clone(),
                client_commitment: None,
                contents_reveal: None,
                client_reveal: None,
                server_reveal: None,
                resolution: None,
            },
            state: State::AwaitingClientCommitment,
        };
        Ok((session, msg))
    }

    fn fail(self, error: ProtocolError) -> ProtocolFailure {
        ProtocolFailure {
            error,
            proof: Box::new(self.proof),
        }
    }

    /// Steps 1→2: accept the client's commitment, reveal the contents.
    pub fn receive_client_commitment(
        mut self,
        identity: &Identity,
        msg: ClientCommitment,
    ) -> Result<(Self, ContentsReveal), ProtocolFailure> {
        if !matches!(self.state, State::AwaitingClientCommitment) {
            let got = self.state.name();
            return Err(self.fail(ProtocolError::InvalidState {
                expected: "AwaitingClientCommitment",
                got,
            }));
        }

        // Verify the client signed its commitment over our Step 0 signature.
        let buf = fields::client_commitment_fields_of(&msg);
        let priors = [&self.proof.server_commitment.signature];
        if let Err(e) = verify_field_signature(&msg.signature, &buf.as_fields(), &priors, None) {
            return Err(self.fail(e.into()));
        }

        self.proof.client_commitment = Some(msg);

        // Step 2: reveal contents, signed over the chain so far.
        let buf = fields::contents_reveal_fields(&self.contents);
        let cc_sig = &self.proof.client_commitment.as_ref().unwrap().signature;
        let priors = [&self.proof.server_commitment.signature, cc_sig];
        let signature = sign_fields(
            identity,
            &buf.as_fields(),
            &priors,
            &[
                fields::PRIOR_SERVER_COMMITMENT,
                fields::PRIOR_CLIENT_COMMITMENT,
            ],
        );
        let reveal = ContentsReveal {
            contents: self.contents.clone(),
            signature,
        };
        self.proof.contents_reveal = Some(reveal.clone());
        self.state = State::AwaitingClientReveal;
        Ok((self, reveal))
    }

    /// Steps 3→4: accept the client's reveal, produce ours plus the outcome.
    pub fn receive_client_reveal(
        mut self,
        identity: &Identity,
        msg: ClientReveal,
    ) -> Result<(Self, ServerReveal), ProtocolFailure> {
        if !matches!(self.state, State::AwaitingClientReveal) {
            let got = self.state.name();
            return Err(self.fail(ProtocolError::InvalidState {
                expected: "AwaitingClientReveal",
                got,
            }));
        }
        let client_commitment = self.proof.client_commitment.as_ref().expect("state");

        // Signature over the chain.
        let buf = fields::client_reveal_fields_of(&msg);
        let priors = [
            &self.proof.server_commitment.signature,
            &client_commitment.signature,
            &self.proof.contents_reveal.as_ref().expect("state").signature,
        ];
        if let Err(e) = verify_field_signature(&msg.signature, &buf.as_fields(), &priors, None) {
            return Err(self.fail(e.into()));
        }

        // U8: revealed secret must match the Step 1 commitment.
        if !verify_commitment(&msg.client_secret, &client_commitment.client_commitment) {
            return Err(self.fail(ProtocolError::CommitmentMismatch {
                field: "client_commitment".into(),
            }));
        }

        let client_secret = msg.client_secret;
        self.proof.client_reveal = Some(msg);

        let combined = combine_secrets(&client_secret, &self.server_secret);
        let outcome = match evaluate(&self.contents, &combined) {
            Ok(o) => o,
            Err(e) => return Err(self.fail(e.into())),
        };

        let buf = fields::server_reveal_fields(&self.server_secret, &combined, &outcome);
        let priors = [
            &self.proof.server_commitment.signature,
            &self.proof.client_commitment.as_ref().unwrap().signature,
            &self.proof.contents_reveal.as_ref().unwrap().signature,
            &self.proof.client_reveal.as_ref().unwrap().signature,
        ];
        let signature = sign_fields(
            identity,
            &buf.as_fields(),
            &priors,
            &[
                fields::PRIOR_SERVER_COMMITMENT,
                fields::PRIOR_CLIENT_COMMITMENT,
                fields::PRIOR_CONTENTS_REVEAL,
                fields::PRIOR_CLIENT_REVEAL,
            ],
        );
        let reveal = ServerReveal {
            server_secret: self.server_secret,
            combined_randomness: combined,
            outcome: outcome.clone(),
            signature,
        };
        self.proof.server_reveal = Some(reveal.clone());
        self.proof.resolution = Some(ResolutionMethod::Cooperative);
        self.state = State::Complete {
            outcome,
        };
        Ok((self, reveal))
    }

    /// Unhappy path: the client committed but never revealed (U1).
    /// Decrypt the client's timelock payload with the round's beacon and
    /// resolve the outcome unilaterally.
    pub fn resolve_with_beacon(
        mut self,
        beacon: &BeaconValue,
    ) -> Result<(Self, Outcome), ProtocolFailure> {
        let client_commitment = match &self.state {
            // SM6: resolution requires the client to have committed.
            State::AwaitingClientCommitment => {
                return Err(self.fail(ProtocolError::InvalidState {
                    expected: "AwaitingClientReveal",
                    got: "AwaitingClientCommitment",
                }))
            }
            State::Complete { .. } => {
                return Err(self.fail(ProtocolError::InvalidState {
                    expected: "AwaitingClientReveal",
                    got: "Complete",
                }))
            }
            State::AwaitingClientReveal => self.proof.client_commitment.as_ref().expect("state"),
        };

        if beacon.round != self.config.drand_round {
            let expected = self.config.drand_round;
            return Err(self.fail(ProtocolError::WrongBeaconRound {
                expected,
                got: beacon.round,
            }));
        }

        // Decrypt the client's secret from its timelock ciphertext.
        let client_secret =
            match decrypt_secret(&client_commitment.client_timelock_encrypted, &beacon.signature)
            {
                Ok(s) => s,
                Err(e) => return Err(self.fail(e.into())),
            };

        // U6: decrypted secret must match the client's commitment, else the
        // client provably committed junk.
        if !verify_commitment(&client_secret, &client_commitment.client_commitment) {
            return Err(self.fail(ProtocolError::CommitmentMismatch {
                field: "client_commitment (timelock payload was junk)".into(),
            }));
        }

        let combined = combine_secrets(&client_secret, &self.server_secret);
        let outcome = match evaluate(&self.contents, &combined) {
            Ok(o) => o,
            Err(e) => return Err(self.fail(e.into())),
        };

        self.proof.resolution = Some(ResolutionMethod::TimelockClientPayload);
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
        &self.config.session_id
    }
}

impl std::fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerSession")
            .field("session_id", &self.config.session_id)
            .field("state", &self.state.name())
            .field("server_secret", &"[redacted]")
            .finish()
    }
}
