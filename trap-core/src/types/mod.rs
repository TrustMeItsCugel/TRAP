//! Core data structures for the TRAP protocol.
//!
//! All types are pure data with serde support — no business logic.
//! Hashes and secrets are fixed 32-byte arrays serialised as hex strings
//! for JSON readability.

pub mod contents;
pub mod messages;

pub use contents::{Contents, Operation, OperationType, Outcome, OutcomeValue, RangeParams};
pub use messages::{
    ClientCommitment, ClientReveal, ContentsReveal, FieldSignature, ProofDocument,
    ServerCommitment, ServerReveal, SessionConfig,
};

/// Serde helpers: `[u8; 32]` <-> lowercase hex string.
pub(crate) mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// Serde helpers: `Vec<u8>` <-> lowercase hex string.
pub(crate) mod hexvec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
