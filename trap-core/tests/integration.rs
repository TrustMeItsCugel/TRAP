//! Integration tests: full protocol flows against the test-scenario list.
//! Uses the real recorded Quicknet round-1000 beacon signature so timelock
//! paths run fully offline.

use trap_core::beacon::{BeaconClient, BeaconValue, ChainInfo, MockBeaconClient};
use trap_core::crypto::hash::{commit, verify_commitment};
use trap_core::crypto::sign::sign_fields;
use trap_core::crypto::timelock::{decrypt_secret, encrypt_secret};
use trap_core::crypto::Identity;
use trap_core::protocol::client::ClientSession;
use trap_core::protocol::server::ServerSession;
use trap_core::protocol::verify::{verify_proof, SessionProgress};
use trap_core::protocol::{fields, ProtocolError};
use trap_core::types::contents::{Contents, Operation, OperationType, RangeParams};
use trap_core::types::messages::{
    ClientReveal, ContentsReveal, ResolutionMethod, ServerCommitment, SessionConfig,
};
use trap_core::PROTOCOL_VERSION;

// ---- shared fixtures ----

const QUICKNET_PK_HEX: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
const ROUND_1000_SIG_HEX: &str = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";
const ROUND: u64 = 1000;

fn pk() -> Vec<u8> {
    hex::decode(QUICKNET_PK_HEX).unwrap()
}

fn beacon_1000() -> BeaconValue {
    BeaconValue {
        round: ROUND,
        signature: hex::decode(ROUND_1000_SIG_HEX).unwrap(),
    }
}

fn mock_client() -> MockBeaconClient {
    MockBeaconClient::new(ChainInfo::quicknet())
        .with_beacon(ROUND, hex::decode(ROUND_1000_SIG_HEX).unwrap())
}

fn sample_contents() -> Contents {
    Contents {
        operations: vec![
            Operation {
                id: "tier".into(),
                depends_on: None,
                op: OperationType::Distribution {
                    outcomes: [
                        ("common".to_string(), 7000u64),
                        ("rare".to_string(), 2500),
                        ("epic".to_string(), 500),
                    ]
                    .into_iter()
                    .collect(),
                },
            },
            Operation {
                id: "quality".into(),
                depends_on: None,
                op: OperationType::Range {
                    range: RangeParams { min: 1, max: 100 },
                },
            },
        ],
    }
}

fn config(session_id: &str) -> SessionConfig {
    SessionConfig {
        session_id: session_id.into(),
        drand_round: ROUND,
        version: PROTOCOL_VERSION.into(),
        metadata: None,
    }
}

struct Parties {
    server_id: Identity,
    client_id: Identity,
}

fn parties() -> Parties {
    Parties {
        server_id: Identity::generate(),
        client_id: Identity::generate(),
    }
}

// ---- P: happy path ----

#[test]
fn p1_full_cooperative_flow() {
    let p = parties();
    // Step 0
    let (server, step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("p1"), &pk()).unwrap();
    // Step 1 (client commits blind)
    let (client, step1) = ClientSession::accept(&p.client_id, step0, &pk()).unwrap();
    // Step 2
    let (server, step2) = server
        .receive_client_commitment(&p.server_id, step1)
        .unwrap();
    // Step 3
    let (client, step3) = client.receive_contents(&p.client_id, step2).unwrap();
    // Step 4
    let (server, step4) = server.receive_client_reveal(&p.server_id, step3).unwrap();
    let (client, client_outcome) = client.receive_server_reveal(step4).unwrap();

    // Both parties computed identical outcomes.
    assert_eq!(server.outcome().unwrap(), &client_outcome);
    assert_eq!(
        client.proof().resolution,
        Some(ResolutionMethod::Cooperative)
    );

    // Both proofs verify standalone, without any beacon — and authenticate
    // against the known server key.
    for proof in [server.proof(), client.proof()] {
        let r = verify_proof(proof, None, Some(&p.server_id.public_key())).unwrap();
        assert_eq!(r.progress, SessionProgress::Complete);
        assert!(r.signatures_valid);
        assert!(r.commitments_match);
        assert!(r.outcome_verified);
        assert_eq!(r.outcome.as_ref().unwrap(), &client_outcome);
    }
}

#[test]
fn p2_session_ids_isolate_sessions() {
    // Same contents in two sessions -> different contents commitments
    // (salted) and independently random outcomes structure-wise.
    let p = parties();
    let (_, a) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("s-a"), &pk()).unwrap();
    let (_, b) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("s-b"), &pk()).unwrap();
    assert_ne!(a.contents_commitment, b.contents_commitment);
    assert_ne!(a.server_commitment, b.server_commitment); // fresh secrets
}

// ---- U: unhappy paths ----

#[test]
fn u1_client_ghosts_server_resolves_via_timelock() {
    let p = parties();
    let (server, step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("u1"), &pk()).unwrap();
    let (client, step1) = ClientSession::accept(&p.client_id, step0, &pk()).unwrap();
    let (server, step2) = server
        .receive_client_commitment(&p.server_id, step1)
        .unwrap();
    // Client processes the live reveal but ghosts at Step 3 (never sends it
    // to the server). After expiry the server fetches the beacon.
    let (client, _step3) = client.receive_contents(&p.client_id, step2).unwrap();
    let beacon = mock_client().beacon(ROUND).unwrap();
    let (server, outcome) = server.resolve_with_beacon(&beacon).unwrap();

    assert_eq!(server.outcome().unwrap(), &outcome);
    assert_eq!(
        server.proof().resolution,
        Some(ResolutionMethod::TimelockClientPayload)
    );
    // The honest client, holding the live reveal, resolves to the same
    // outcome from the server's escrowed secret.
    let (_, client_outcome) = client.resolve_with_beacon(&beacon).unwrap();
    assert_eq!(outcome, client_outcome);
}

#[test]
fn u3_server_ghosts_before_live_reveal_voids_cleanly() {
    // New semantics: the server's timelock escrows only its secret — never
    // the contents or nonce. A server that ghosts before the live Step 2
    // reveal leaves a session that CANNOT be resolved, and that is the
    // intended, harmless outcome: the server disclosed nothing
    // outcome-determining and never learned the client secret, so it gained
    // no advantage. (This is what removes the stall-then-grind incentive.)
    let p = parties();
    let (_server, step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("u3"), &pk()).unwrap();
    let (client, _step1) = ClientSession::accept(&p.client_id, step0, &pk()).unwrap();
    // Server ghosts immediately after Step 0/1 — no contents reveal exists.
    let failure = client.resolve_with_beacon(&beacon_1000()).unwrap_err();
    assert!(matches!(
        failure.error,
        ProtocolError::InvalidState { expected: "ContentsRevealed", .. }
    ));
}

#[test]
fn u4_server_ghosts_after_contents_bundle_must_agree() {
    let p = parties();
    let (server, step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("u4"), &pk()).unwrap();
    let (client, step1) = ClientSession::accept(&p.client_id, step0, &pk()).unwrap();
    let (server, step2) = server
        .receive_client_commitment(&p.server_id, step1)
        .unwrap();
    let (client, step3) = client.receive_contents(&p.client_id, step2).unwrap();
    // Server ghosts at Step 4.
    let beacon = beacon_1000();
    let (client, client_outcome) = client.resolve_with_beacon(&beacon).unwrap();
    assert_eq!(
        client.proof().resolution,
        Some(ResolutionMethod::TimelockServerPayload)
    );
    // Server, resolving its own side with the client's Step 3 in hand,
    // agrees on the outcome.
    let (server, server_outcome) = server.receive_client_reveal(&p.server_id, step3).unwrap();
    assert_eq!(server_outcome.outcome, client_outcome);
    assert_eq!(server.outcome().unwrap(), &client_outcome);
}

#[test]
fn u5_server_junk_escrow_is_provable() {
    // Malicious server: commitments are well-formed, but the timelock
    // escrows a DIFFERENT secret than committed. The fraud surfaces when the
    // client resolves a post-reveal server ghost (Step 4 missing).
    let p = parties();
    let real_secret = [0x11u8; 32];
    let junk_secret = [0x22u8; 32];
    let server_nonce = [0x33u8; 32];
    let contents = sample_contents();
    let session_id = "u5";

    let server_commitment = commit(&real_secret);
    let contents_commitment = trap_core::crypto::hash::commit_contents(&contents, session_id);
    let server_nonce_commitment = commit(&server_nonce);
    let ct = encrypt_secret(&junk_secret, ROUND, &pk()).unwrap(); // <- fraud

    let buf = fields::server_commitment_fields(
        PROTOCOL_VERSION,
        session_id,
        &server_commitment,
        &contents_commitment,
        &server_nonce_commitment,
        &ct,
        ROUND,
        None,
    );
    let signature = sign_fields(&p.server_id, &buf.as_fields(), &[], &[]);
    let step0 = ServerCommitment {
        version: PROTOCOL_VERSION.into(),
        session_id: session_id.into(),
        server_commitment,
        contents_commitment,
        server_nonce_commitment,
        server_timelock_encrypted: ct,
        drand_round: ROUND,
        metadata: None,
        signature,
    };

    // The client cannot detect the fraud at commitment time...
    let (client, _step1) = ClientSession::accept(&p.client_id, step0, &pk()).unwrap();

    // The server performs an honest-looking live reveal (contents + nonce),
    // signed and chained, so the client advances past Step 2.
    let proof = client.proof().clone();
    let cr_buf = fields::contents_reveal_fields(&contents, &server_nonce);
    let priors = [
        &proof.server_commitment.signature,
        &proof.client_commitment.as_ref().unwrap().signature,
    ];
    let cr_sig = sign_fields(
        &p.server_id,
        &cr_buf.as_fields(),
        &priors,
        &[
            fields::PRIOR_SERVER_COMMITMENT,
            fields::PRIOR_CLIENT_COMMITMENT,
        ],
    );
    let reveal = ContentsReveal {
        contents,
        server_nonce,
        signature: cr_sig,
    };
    let (client, _step3) = client.receive_contents(&p.client_id, reveal).unwrap();

    // ...but at expiry, the junk escrow is self-evidencing.
    let failure = client.resolve_with_beacon(&beacon_1000()).unwrap_err();
    assert!(matches!(
        failure.error,
        ProtocolError::CommitmentMismatch { ref field } if field.contains("server_commitment")
    ));
    // The evidence (signed junk escrow + reveal) is preserved in the proof.
    assert!(verify_proof(&failure.proof, None, None).is_ok());
}

#[test]
fn u6_client_junk_payload_is_provable() {
    // Malicious client: commits to secret A but timelock-encrypts secret B.
    let p = parties();
    let (server, step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("u6"), &pk()).unwrap();

    let committed = [0xAAu8; 32];
    let encrypted = [0xBBu8; 32]; // <- fraud
    let client_commitment = commit(&committed);
    let ct = encrypt_secret(&encrypted, ROUND, &pk()).unwrap();
    let buf = fields::client_commitment_fields(&client_commitment, &ct);
    let priors = [&step0.signature];
    let signature = sign_fields(
        &p.client_id,
        &buf.as_fields(),
        &priors,
        &[fields::PRIOR_SERVER_COMMITMENT],
    );
    let step1 = trap_core::types::messages::ClientCommitment {
        client_commitment,
        client_timelock_encrypted: ct,
        signature,
    };

    let (server, _step2) = server
        .receive_client_commitment(&p.server_id, step1)
        .unwrap();
    // Client ghosts; server resolves and the junk is exposed.
    let failure = server.resolve_with_beacon(&beacon_1000()).unwrap_err();
    assert!(matches!(
        failure.error,
        ProtocolError::CommitmentMismatch { ref field } if field.contains("client_commitment")
    ));
}

#[test]
fn u7_contents_reveal_mismatch_detected() {
    // Server reveals contents that don't match the Step 0 commitment.
    let p = parties();
    let (server, step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("u7"), &pk()).unwrap();
    let (client, step1) = ClientSession::accept(&p.client_id, step0, &pk()).unwrap();
    let (_server, step2) = server
        .receive_client_commitment(&p.server_id, step1)
        .unwrap();

    // Forge a different ContentsReveal, properly signed by the server.
    let mut other = sample_contents();
    other.operations[0].id = "tier_switched".into();
    let nonce = [0u8; 32];
    let buf = fields::contents_reveal_fields(&other, &nonce);
    let proof = client.proof().clone();
    let priors = [
        &proof.server_commitment.signature,
        &proof.client_commitment.as_ref().unwrap().signature,
    ];
    let signature = sign_fields(
        &p.server_id,
        &buf.as_fields(),
        &priors,
        &[
            fields::PRIOR_SERVER_COMMITMENT,
            fields::PRIOR_CLIENT_COMMITMENT,
        ],
    );
    let forged = ContentsReveal {
        contents: other,
        server_nonce: nonce,
        signature,
    };
    drop(step2);

    let failure = client.receive_contents(&p.client_id, forged).unwrap_err();
    assert!(matches!(
        failure.error,
        ProtocolError::CommitmentMismatch { ref field } if field == "contents_commitment"
    ));
    // The mismatching reveal is kept as evidence.
    assert!(failure.proof.contents_reveal.is_some());
}

#[test]
fn u8_client_reveal_mismatch_rejected() {
    let p = parties();
    let (server, step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("u8"), &pk()).unwrap();
    let (client, step1) = ClientSession::accept(&p.client_id, step0, &pk()).unwrap();
    let (server, step2) = server
        .receive_client_commitment(&p.server_id, step1)
        .unwrap();
    let (client, _step3) = client.receive_contents(&p.client_id, step2).unwrap();

    // Forge a Step 3 with the wrong secret, properly signed and chained.
    let proof = client.proof().clone();
    let wrong = [0xEEu8; 32];
    let buf = fields::client_reveal_fields(&wrong);
    let priors = [
        &proof.server_commitment.signature,
        &proof.client_commitment.as_ref().unwrap().signature,
        &proof.contents_reveal.as_ref().unwrap().signature,
    ];
    let signature = sign_fields(
        &p.client_id,
        &buf.as_fields(),
        &priors,
        &[
            fields::PRIOR_SERVER_COMMITMENT,
            fields::PRIOR_CLIENT_COMMITMENT,
            fields::PRIOR_CONTENTS_REVEAL,
        ],
    );
    let forged = ClientReveal {
        client_secret: wrong,
        signature,
    };

    let failure = server
        .receive_client_reveal(&p.server_id, forged)
        .unwrap_err();
    assert!(matches!(
        failure.error,
        ProtocolError::CommitmentMismatch { ref field } if field == "client_commitment"
    ));
}

#[test]
fn stall_grind_resistance_server_tlock_leaks_only_secret() {
    // The stall-then-grind attack: a malicious client delays Step 1 until the
    // server's timelock expires, decrypts the escrow, and grinds a favourable
    // client_secret. This is defeated structurally — the escrow holds ONLY the
    // server secret, never the contents or the nonce — so even with public
    // odds the stalling client cannot predict the outcome. And to learn the
    // contents/nonce it must first reach the live Step 2, which requires
    // having already committed (Catch-22).
    let p = parties();
    let (_server, step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("grind"), &pk()).unwrap();

    // Decrypt the escrow exactly as a stalling client holding the beacon would.
    let leaked =
        decrypt_secret(&step0.server_timelock_encrypted, &beacon_1000().signature).unwrap();

    // What leaks is precisely the committed server secret (32 bytes) — and
    // nothing more. The contents and nonce are present at Step 0 only as
    // hashes (commitments); no preimage is escrowed to grind against.
    assert!(verify_commitment(&leaked, &step0.server_commitment));
    assert_ne!(step0.contents_commitment, [0u8; 32]);
    assert_ne!(step0.server_nonce_commitment, [0u8; 32]);
}

// ---- SM: state machine ----

#[test]
fn sm6_server_cannot_resolve_before_client_commits() {
    let p = parties();
    let (server, _step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("sm6"), &pk()).unwrap();
    let failure = server.resolve_with_beacon(&beacon_1000()).unwrap_err();
    assert!(matches!(
        failure.error,
        ProtocolError::InvalidState { .. }
    ));
}

#[test]
fn sm_wrong_beacon_round_rejected() {
    let p = parties();
    let (_server, step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("smr"), &pk()).unwrap();
    let (client, _step1) = ClientSession::accept(&p.client_id, step0, &pk()).unwrap();
    let wrong = BeaconValue {
        round: 999,
        signature: hex::decode(ROUND_1000_SIG_HEX).unwrap(),
    };
    let failure = client.resolve_with_beacon(&wrong).unwrap_err();
    assert!(matches!(
        failure.error,
        ProtocolError::WrongBeaconRound {
            expected: 1000,
            got: 999
        }
    ));
}

#[test]
fn sm_session_isolation_signatures_dont_transfer() {
    // A Step 1 produced for session A must be rejected by session B's
    // server: the chained Step 0 signature differs.
    let p = parties();
    let (_sa, step0_a) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("iso-a"), &pk()).unwrap();
    let (sb, _step0_b) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("iso-b"), &pk()).unwrap();
    let (_client, step1_for_a) = ClientSession::accept(&p.client_id, step0_a, &pk()).unwrap();
    // Replay the Step 1 against session B.
    let failure = sb
        .receive_client_commitment(&p.server_id, step1_for_a)
        .unwrap_err();
    assert!(matches!(failure.error, ProtocolError::Crypto(_)));
}

// ---- V: verification ----

fn complete_proof() -> trap_core::types::messages::ProofDocument {
    let p = parties();
    let (server, step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("v"), &pk()).unwrap();
    let (client, step1) = ClientSession::accept(&p.client_id, step0, &pk()).unwrap();
    let (server, step2) = server
        .receive_client_commitment(&p.server_id, step1)
        .unwrap();
    let (client, step3) = client.receive_contents(&p.client_id, step2).unwrap();
    let (_server, step4) = server.receive_client_reveal(&p.server_id, step3).unwrap();
    let (client, _) = client.receive_server_reveal(step4).unwrap();
    client.proof().clone()
}

#[test]
fn v6_tampered_midchain_signature_detected() {
    let mut proof = complete_proof();
    proof
        .client_commitment
        .as_mut()
        .unwrap()
        .signature
        .signature[5] ^= 0xFF;
    assert!(verify_proof(&proof, None, None).is_err());
}

#[test]
fn v6b_tampered_field_detected() {
    let mut proof = complete_proof();
    proof.server_reveal.as_mut().unwrap().server_secret[0] ^= 0xFF;
    // Either the signature check fails outright or commitments mismatch.
    match verify_proof(&proof, None, None) {
        Err(_) => {}
        Ok(r) => assert!(!r.commitments_match || !r.outcome_verified),
    }
}

#[test]
fn v6c_swapped_outcome_detected() {
    let mut proof = complete_proof();
    // Tamper the claimed outcome (e.g. upgrade tier) without re-signing.
    let sr = proof.server_reveal.as_mut().unwrap();
    let first = sr.outcome.results.keys().next().unwrap().clone();
    sr.outcome.results.insert(
        first,
        trap_core::types::contents::OutcomeValue::Selected("epic_forged".into()),
    );
    assert!(verify_proof(&proof, None, None).is_err());
}

#[test]
fn v7_partial_proof_verifies_to_last_step() {
    let mut proof = complete_proof();
    proof.contents_reveal = None;
    proof.client_reveal = None;
    proof.server_reveal = None;
    proof.resolution = None;
    let r = verify_proof(&proof, None, None).unwrap();
    assert_eq!(r.progress, SessionProgress::ClientCommitted);
    assert!(r.signatures_valid);
    assert!(r.outcome.is_none());
}

#[test]
fn v8_third_party_verifies_timelock_resolution() {
    // Build a U4-style abandoned session (server reveals contents+nonce at
    // the live Step 2, then ghosts), then verify as an outsider holding only
    // the proof document and the public beacon value.
    let p = parties();
    let (server, step0) =
        ServerSession::initiate(&p.server_id, sample_contents(), config("v8"), &pk()).unwrap();
    let (client, step1) = ClientSession::accept(&p.client_id, step0, &pk()).unwrap();
    let (_server, step2) = server
        .receive_client_commitment(&p.server_id, step1)
        .unwrap();
    let (client, _step3) = client.receive_contents(&p.client_id, step2).unwrap();
    let (client, outcome) = client.resolve_with_beacon(&beacon_1000()).unwrap();

    let r = verify_proof(client.proof(), Some(&beacon_1000()), None).unwrap();
    assert!(r.signatures_valid);
    assert!(r.commitments_match);
    assert!(r.outcome_verified);
    assert_eq!(r.outcome.unwrap(), outcome);

    // Without the beacon, the same proof verifies signatures but cannot
    // produce an outcome.
    let r2 = verify_proof(client.proof(), None, None).unwrap();
    assert!(r2.signatures_valid);
    assert!(r2.outcome.is_none());
}

#[test]
fn v9_verifier_authenticates_server_key() {
    // A proof is internally consistent regardless of who signed Step 0;
    // authentication requires pinning the expected server key.
    let proof = complete_proof();
    let real_server = proof.server_commitment.signature.signer;

    // Right key: authenticates.
    let r = verify_proof(&proof, None, Some(&real_server)).unwrap();
    assert_eq!(r.progress, SessionProgress::Complete);

    // Wrong key: rejected outright, even though the document is self-consistent.
    let imposter = Identity::generate().public_key();
    assert!(verify_proof(&proof, None, Some(&imposter)).is_err());

    // No expected key: still verifies as internally consistent (but this
    // does NOT establish origin).
    assert!(verify_proof(&proof, None, None).is_ok());
}

// ---- SER: serialisation ----

#[test]
fn ser1_proof_document_round_trips_and_reverifies() {
    let proof = complete_proof();
    let json = serde_json::to_string_pretty(&proof).unwrap();
    let back: trap_core::types::messages::ProofDocument = serde_json::from_str(&json).unwrap();
    let r = verify_proof(&back, None, None).unwrap();
    assert_eq!(r.progress, SessionProgress::Complete);
    assert!(r.outcome_verified);
}
