//! Ed25519 field signatures with explicit coverage and chaining. Spec §5.2–5.3.
//!
//! Signing payload construction (deterministic):
//!   for each (name, value) in fields, in order:
//!       u32_be(len(name)) || name || u32_be(len(value)) || value
//!   then for each prior signature, in order:
//!       u32_be(len(canonical_json(prior))) || canonical_json(prior)
//!
//! Including prior signatures' full canonical form chains the document:
//! any tamper to an earlier signature invalidates all later ones (S6, S7).

use super::CryptoError;
use crate::types::messages::FieldSignature;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const ALGORITHM: &str = "Ed25519";

/// A party's signing identity.
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a fresh identity from OS randomness.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    /// Construct from existing 32 secret-key bytes.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(secret),
        }
    }

    /// The public verifying key (32 bytes).
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

fn signing_payload(fields: &[(&str, &[u8])], priors: &[&FieldSignature]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (name, value) in fields {
        buf.extend_from_slice(&(name.len() as u32).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buf.extend_from_slice(value);
    }
    for prior in priors {
        let json = serde_json::to_vec(prior).expect("FieldSignature serialisation");
        buf.extend_from_slice(&(json.len() as u32).to_be_bytes());
        buf.extend_from_slice(&json);
    }
    buf
}

/// Sign the named fields plus the chain of prior signatures.
///
/// `field_names_for_record` lets the caller record self-describing names
/// (e.g. including "signatures.server_commitment" entries for priors) in
/// the resulting `signed_fields`; verification is positional and driven by
/// the caller supplying the same `fields` and `priors`.
pub fn sign_fields(
    identity: &Identity,
    fields: &[(&str, &[u8])],
    priors: &[&FieldSignature],
    recorded_prior_names: &[&str],
) -> FieldSignature {
    let payload = signing_payload(fields, priors);
    let sig: Signature = identity.signing_key.sign(&payload);
    let mut signed_fields: Vec<String> = fields.iter().map(|(n, _)| n.to_string()).collect();
    signed_fields.extend(recorded_prior_names.iter().map(|s| s.to_string()));
    FieldSignature {
        signature: sig.to_bytes().to_vec(),
        signed_fields,
        algorithm: ALGORITHM.to_string(),
        signer: identity.public_key(),
    }
}

/// Verify a field signature over the given fields and prior chain.
/// `expected_signer`, when provided, additionally pins the signer key.
pub fn verify_field_signature(
    signature: &FieldSignature,
    fields: &[(&str, &[u8])],
    priors: &[&FieldSignature],
    expected_signer: Option<&[u8; 32]>,
) -> Result<(), CryptoError> {
    if signature.algorithm != ALGORITHM {
        return Err(CryptoError::InvalidSignature);
    }
    if let Some(expected) = expected_signer {
        if &signature.signer != expected {
            return Err(CryptoError::InvalidSignature);
        }
    }
    let key =
        VerifyingKey::from_bytes(&signature.signer).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig_bytes: [u8; 64] = signature
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let payload = signing_payload(fields, priors);
    key.verify(&payload, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s1_sign_verify_round_trip() {
        let id = Identity::generate();
        let fields: &[(&str, &[u8])] = &[("a", b"hello"), ("b", b"world")];
        let sig = sign_fields(&id, fields, &[], &[]);
        assert!(verify_field_signature(&sig, fields, &[], Some(&id.public_key())).is_ok());
    }

    #[test]
    fn s2_tampered_field_fails() {
        let id = Identity::generate();
        let sig = sign_fields(&id, &[("a", b"hello"), ("b", b"world")], &[], &[]);
        assert!(verify_field_signature(
            &sig,
            &[("a", b"TAMPERED"), ("b", b"world")],
            &[],
            None
        )
        .is_err());
    }

    #[test]
    fn s3_s4_missing_or_extra_field_fails() {
        let id = Identity::generate();
        let sig = sign_fields(&id, &[("a", b"1"), ("b", b"2"), ("c", b"3")], &[], &[]);
        assert!(verify_field_signature(&sig, &[("a", b"1"), ("b", b"2")], &[], None).is_err());
        let sig2 = sign_fields(&id, &[("a", b"1"), ("b", b"2")], &[], &[]);
        assert!(verify_field_signature(
            &sig2,
            &[("a", b"1"), ("b", b"2"), ("c", b"3")],
            &[],
            None
        )
        .is_err());
    }

    #[test]
    fn s5_wrong_signer_pin_fails() {
        let a = Identity::generate();
        let b = Identity::generate();
        let sig = sign_fields(&a, &[("x", b"y")], &[], &[]);
        assert!(verify_field_signature(&sig, &[("x", b"y")], &[], Some(&b.public_key())).is_err());
    }

    #[test]
    fn s6_chain_tamper_detected() {
        let a = Identity::generate();
        let b = Identity::generate();
        let sig1 = sign_fields(&a, &[("a", b"1")], &[], &[]);
        let sig2 = sign_fields(&b, &[("b", b"2")], &[&sig1], &["signatures.first"]);
        // verifies against the genuine chain
        assert!(verify_field_signature(&sig2, &[("b", b"2")], &[&sig1], None).is_ok());
        // tamper sig1 after the fact
        let mut tampered = sig1.clone();
        tampered.signature[0] ^= 0xFF;
        assert!(verify_field_signature(&sig2, &[("b", b"2")], &[&tampered], None).is_err());
    }

    #[test]
    fn s7_chain_order_matters() {
        let a = Identity::generate();
        let sig1 = sign_fields(&a, &[("a", b"1")], &[], &[]);
        let sig2 = sign_fields(&a, &[("b", b"2")], &[], &[]);
        let sig3 = sign_fields(&a, &[("c", b"3")], &[&sig1, &sig2], &[]);
        assert!(verify_field_signature(&sig3, &[("c", b"3")], &[&sig1, &sig2], None).is_ok());
        assert!(verify_field_signature(&sig3, &[("c", b"3")], &[&sig2, &sig1], None).is_err());
    }
}
