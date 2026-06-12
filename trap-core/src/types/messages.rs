//! Protocol messages for Steps 0–4 and the proof document.
//! See Protocol Spec §3 (flow) and §5 (message format & signature chaining).

use super::contents::{Contents, Outcome};
use serde::{Deserialize, Serialize};

/// Configuration for a new session, chosen by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub session_id: String,
    /// Target drand round for timelock encryption.
    pub drand_round: u64,
    /// Protocol version string.
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metadata: Option<serde_json::Value>,
}

/// An Ed25519 signature with explicit field coverage and chaining.
///
/// `signed_fields` lists exactly which named fields the signature covers,
/// in order. The signing payload also includes all prior signatures'
/// bytes, chaining the document immutably (see crypto::sign).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldSignature {
    /// Ed25519 signature bytes (64), hex-encoded in JSON.
    #[serde(with = "super::hexvec")]
    pub signature: Vec<u8>,
    pub signed_fields: Vec<String>,
    pub algorithm: String,
    /// Signer's Ed25519 public key (32 bytes), hex-encoded in JSON.
    #[serde(with = "super::hex32")]
    pub signer: [u8; 32],
}

/// Step 0: the server initiates a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCommitment {
    pub version: String,
    pub session_id: String,
    /// SHA256(server_secret)
    #[serde(with = "super::hex32")]
    pub server_commitment: [u8; 32],
    /// SHA256(canonical_json(contents) || session_id)
    #[serde(with = "super::hex32")]
    pub contents_commitment: [u8; 32],
    /// Timelock ciphertext of the bundle {server_secret, contents}.
    #[serde(with = "super::hexvec")]
    pub server_timelock_encrypted: Vec<u8>,
    pub drand_round: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metadata: Option<serde_json::Value>,
    pub signature: FieldSignature,
}

/// Step 1: the client commits, blind to the contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCommitment {
    /// SHA256(client_secret)
    #[serde(with = "super::hex32")]
    pub client_commitment: [u8; 32],
    /// Timelock ciphertext of the client secret (32 bytes).
    #[serde(with = "super::hexvec")]
    pub client_timelock_encrypted: Vec<u8>,
    pub signature: FieldSignature,
}

/// Step 2: the server reveals the contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentsReveal {
    pub contents: Contents,
    pub signature: FieldSignature,
}

/// Step 3: the client reveals its secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientReveal {
    #[serde(with = "super::hex32")]
    pub client_secret: [u8; 32],
    pub signature: FieldSignature,
}

/// Step 4: the server reveals its secret and the computed outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerReveal {
    #[serde(with = "super::hex32")]
    pub server_secret: [u8; 32],
    /// SHA256(client_secret || server_secret)
    #[serde(with = "super::hex32")]
    pub combined_randomness: [u8; 32],
    pub outcome: Outcome,
    pub signature: FieldSignature,
}

/// How a session's outcome was determined.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMethod {
    /// All five steps completed cooperatively.
    Cooperative,
    /// Resolved by decrypting the counterparty's timelock payload
    /// after the target round's beacon became available.
    TimelockClientPayload,
    TimelockServerPayload,
}

/// The complete, self-contained record of a session. Verifiable by any
/// party; self-resolving after timelock expiry (Spec §7.2, Appendix B).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofDocument {
    pub server_commitment: ServerCommitment,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub client_commitment: Option<ClientCommitment>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub contents_reveal: Option<ContentsReveal>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub client_reveal: Option<ClientReveal>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub server_reveal: Option<ServerReveal>,
    /// Present once the holder has determined the outcome.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resolution: Option<ResolutionMethod>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_sig() -> FieldSignature {
        FieldSignature {
            signature: vec![0u8; 64],
            signed_fields: vec!["a".into()],
            algorithm: "Ed25519".into(),
            signer: [0u8; 32],
        }
    }

    #[test]
    fn server_commitment_json_round_trip() {
        let msg = ServerCommitment {
            version: "0.1.0".into(),
            session_id: "s-1".into(),
            server_commitment: [1u8; 32],
            contents_commitment: [2u8; 32],
            server_timelock_encrypted: vec![3, 4, 5],
            drand_round: 1000,
            metadata: None,
            signature: dummy_sig(),
        };
        let json = serde_json::to_string_pretty(&msg).unwrap();
        let back: ServerCommitment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.server_commitment, [1u8; 32]);
        assert_eq!(back.drand_round, 1000);
        // hashes serialize as hex strings
        assert!(json.contains(&hex::encode([1u8; 32])));
    }

    #[test]
    fn unknown_fields_tolerated() {
        // forward-compat: extra fields must not break deserialisation (SER3)
        let json = r#"{
            "client_secret": "0101010101010101010101010101010101010101010101010101010101010101",
            "future_field": true,
            "signature": {"signature":"00","signed_fields":[],"algorithm":"Ed25519",
                "signer":"0000000000000000000000000000000000000000000000000000000000000000"}
        }"#;
        let msg: ClientReveal = serde_json::from_str(json).unwrap();
        assert_eq!(msg.client_secret, [1u8; 32]);
    }

    #[test]
    fn missing_required_field_fails() {
        // SER4
        let json = r#"{"signature":{"signature":"00","signed_fields":[],
            "algorithm":"Ed25519",
            "signer":"0000000000000000000000000000000000000000000000000000000000000000"}}"#;
        assert!(serde_json::from_str::<ClientReveal>(json).is_err());
    }
}
