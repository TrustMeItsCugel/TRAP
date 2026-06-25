//! SHA-256 commitments and randomness derivation. Spec §6.
//!
//! Canonical form: `Contents` and `Outcome` are hashed/signed over their
//! compact `serde_json` serialisation. Both parties MUST derive these bytes
//! via the functions here, never from raw wire bytes.

use crate::types::contents::{Contents, Outcome};
use sha2::{Digest, Sha256};

/// Canonical byte form of contents for hashing and signing.
pub fn canonical_contents_bytes(contents: &Contents) -> Vec<u8> {
    serde_json::to_vec(contents).expect("contents serialisation is infallible")
}

/// Canonical byte form of an outcome for signing.
pub fn canonical_outcome_bytes(outcome: &Outcome) -> Vec<u8> {
    serde_json::to_vec(outcome).expect("outcome serialisation is infallible")
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Commitment to a 32-byte secret: SHA256(secret).
pub fn commit(secret: &[u8; 32]) -> [u8; 32] {
    sha256(&[secret])
}

/// Commitment to contents, salted with the session id (Spec §5.4):
/// SHA256(canonical_json(contents) || session_id).
pub fn commit_contents(contents: &Contents, session_id: &str) -> [u8; 32] {
    sha256(&[&canonical_contents_bytes(contents), session_id.as_bytes()])
}

/// Combine both parties' secrets with the server's live-revealed nonce
/// (Spec §6.1): SHA256(client_secret || server_secret || server_nonce).
/// Order is fixed.
///
/// `server_nonce` is committed at Step 0 but, unlike `server_secret`, is
/// NOT escrowed under timelock — it is disclosed only at the live contents
/// reveal (Step 2). Folding it into the randomness is what defeats the
/// stall-then-grind attack even when the contents distribution is public:
/// a client that decrypts `server_secret` early still cannot predict the
/// outcome without the nonce, and the nonce does not exist for it until
/// after it has irrevocably committed its own secret.
pub fn combine_secrets(
    client_secret: &[u8; 32],
    server_secret: &[u8; 32],
    server_nonce: &[u8; 32],
) -> [u8; 32] {
    sha256(&[client_secret, server_secret, server_nonce])
}

/// Derive an operation-specific random value (Spec §6.3):
/// SHA256(combined_randomness || operation_id).
pub fn derive_operation_random(combined: &[u8; 32], operation_id: &str) -> [u8; 32] {
    sha256(&[combined, operation_id.as_bytes()])
}

/// Constant-time-ish commitment check (length is fixed; we rely on the
/// hash making timing attacks moot for this use case).
pub fn verify_commitment(secret: &[u8; 32], commitment: &[u8; 32]) -> bool {
    commit(secret) == *commitment
}

/// Interpret 32 bytes as a big-endian unsigned integer and reduce mod n.
/// Used for outcome mapping (Spec §6.2). n must be non-zero.
pub fn reduce_mod(value: &[u8; 32], n: u64) -> u64 {
    assert!(n != 0, "modulus must be non-zero");
    let n128 = n as u128;
    let mut acc: u128 = 0;
    for &b in value.iter() {
        acc = ((acc << 8) | b as u128) % n128;
    }
    acc as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::contents::{Operation, OperationType};

    fn sample_contents() -> Contents {
        Contents {
            operations: vec![Operation {
                id: "tier".into(),
                depends_on: None,
                op: OperationType::Distribution {
                    outcomes: [("common".to_string(), 7000u64), ("rare".to_string(), 3000)]
                        .into_iter()
                        .collect(),
                },
            }],
        }
    }

    #[test]
    fn h1_commit_deterministic() {
        let s = [0xAB; 32];
        assert_eq!(commit(&s), commit(&s));
    }

    #[test]
    fn h3_different_secrets_different_commitments() {
        assert_ne!(commit(&[1; 32]), commit(&[2; 32]));
    }

    #[test]
    fn h4_contents_commitment_salted_by_session() {
        let c = sample_contents();
        assert_ne!(commit_contents(&c, "session-a"), commit_contents(&c, "session-b"));
    }

    #[test]
    fn h5_contents_commitment_deterministic() {
        let c = sample_contents();
        assert_eq!(commit_contents(&c, "s"), commit_contents(&c, "s"));
    }

    #[test]
    fn h6_combine_order_dependent() {
        let a = [1; 32];
        let b = [2; 32];
        let n = [3; 32];
        assert_ne!(combine_secrets(&a, &b, &n), combine_secrets(&b, &a, &n));
    }

    #[test]
    fn h7_combine_deterministic() {
        let a = [1; 32];
        let b = [2; 32];
        let n = [3; 32];
        assert_eq!(combine_secrets(&a, &b, &n), combine_secrets(&a, &b, &n));
    }

    #[test]
    fn h12_combine_depends_on_nonce() {
        // The live-revealed nonce must change the outcome randomness; this is
        // what blocks stall-then-grind when the distribution is public.
        let a = [1; 32];
        let b = [2; 32];
        assert_ne!(combine_secrets(&a, &b, &[3; 32]), combine_secrets(&a, &b, &[4; 32]));
    }

    #[test]
    fn h8_operation_derivation_unique_per_id() {
        let c = [9; 32];
        assert_ne!(
            derive_operation_random(&c, "tier"),
            derive_operation_random(&c, "item")
        );
    }

    #[test]
    fn h9_operation_derivation_deterministic() {
        let c = [9; 32];
        assert_eq!(
            derive_operation_random(&c, "tier"),
            derive_operation_random(&c, "tier")
        );
    }

    #[test]
    fn h10_h11_verify_commitment() {
        let s = [7; 32];
        let c = commit(&s);
        assert!(verify_commitment(&s, &c));
        assert!(!verify_commitment(&[8; 32], &c));
    }

    #[test]
    fn r1_reduce_mod_covers_range() {
        // 1000 pseudo-random values over n=10 must hit every residue.
        let mut seen = [false; 10];
        for i in 0u64..1000 {
            let v = derive_operation_random(&[0; 32], &format!("op{i}"));
            seen[reduce_mod(&v, 10) as usize] = true;
        }
        assert!(seen.iter().all(|&x| x));
    }

    #[test]
    fn reduce_mod_known_values() {
        // 0x...01 mod anything = 1
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(reduce_mod(&one, 7), 1);
        // max u256 mod 2 = 1 (2^256 - 1 is odd)
        assert_eq!(reduce_mod(&[0xFF; 32], 2), 1);
    }
}
