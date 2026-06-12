//! Timelock encryption wrappers around ideal-lab5/timelock (drand Quicknet,
//! BLS12-381, Boneh-Franklin IBE with AES-GCM hybrid). Spec §2.2, §3.
//!
//! Identity for Quicknet round N is SHA256(N.to_be_bytes()) under the
//! empty context, matching drand's tlock construction.

use super::CryptoError;
use crate::types::contents::Contents;
use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use timelock::{
    block_ciphers::AESGCMBlockCipherProvider,
    engines::{drand::TinyBLS381, EngineBLS},
    ibe::fullident::Identity as TlockIdentity,
    tlock::{tld, tle},
};

/// The server's timelock payload: secret and contents bundled so the
/// proof document is fully self-resolving (Spec §3, Appendix B).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerTimelockPayload {
    #[serde(with = "crate::types::hex32")]
    pub secret: [u8; 32],
    pub contents: Contents,
}

fn quicknet_identity(round: u64) -> TlockIdentity {
    let mut h = Sha256::new();
    h.update(round.to_be_bytes());
    let msg = h.finalize().to_vec();
    TlockIdentity::new(b"", &msg)
}

fn deserialize_pk(
    beacon_public_key: &[u8],
) -> Result<<TinyBLS381 as EngineBLS>::PublicKeyGroup, CryptoError> {
    <TinyBLS381 as EngineBLS>::PublicKeyGroup::deserialize_compressed(beacon_public_key)
        .map_err(|e| CryptoError::TimelockEncrypt(format!("bad beacon public key: {e:?}")))
}

fn deserialize_sig(
    beacon_signature: &[u8],
) -> Result<<TinyBLS381 as EngineBLS>::SignatureGroup, CryptoError> {
    <TinyBLS381 as EngineBLS>::SignatureGroup::deserialize_compressed(beacon_signature)
        .map_err(|e| CryptoError::TimelockDecrypt(format!("bad beacon signature: {e:?}")))
}

fn tle_bytes(
    plaintext: &[u8],
    round: u64,
    beacon_public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use ark_serialize::CanonicalSerialize;
    let pk = deserialize_pk(beacon_public_key)?;
    let esk: [u8; 32] = rand::random();
    let ct = tle::<TinyBLS381, AESGCMBlockCipherProvider, _>(
        pk,
        esk,
        plaintext,
        quicknet_identity(round),
        rand::rngs::OsRng,
    )
    .map_err(|e| CryptoError::TimelockEncrypt(format!("{e:?}")))?;
    let mut out = Vec::new();
    ct.serialize_compressed(&mut out)
        .map_err(|e| CryptoError::TimelockEncrypt(format!("ciphertext serialise: {e:?}")))?;
    Ok(out)
}

fn tld_bytes(ciphertext: &[u8], beacon_signature: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use timelock::tlock::TLECiphertext;
    let ct = TLECiphertext::<TinyBLS381>::deserialize_compressed(ciphertext)
        .map_err(|e| CryptoError::TimelockDecrypt(format!("ciphertext parse: {e:?}")))?;
    let sig = deserialize_sig(beacon_signature)?;
    tld::<TinyBLS381, AESGCMBlockCipherProvider>(ct, sig)
        .map_err(|e| CryptoError::TimelockDecrypt(format!("{e:?}")))
}

/// Timelock-encrypt a 32-byte secret (client payload) to a drand round.
pub fn encrypt_secret(
    secret: &[u8; 32],
    round: u64,
    beacon_public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    tle_bytes(secret, round, beacon_public_key)
}

/// Decrypt a 32-byte secret with the round's beacon signature.
pub fn decrypt_secret(
    ciphertext: &[u8],
    beacon_signature: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let pt = tld_bytes(ciphertext, beacon_signature)?;
    pt.as_slice()
        .try_into()
        .map_err(|_| CryptoError::TimelockPayload("expected 32-byte secret".into()))
}

/// Timelock-encrypt the server bundle {secret, contents} to a drand round.
pub fn encrypt_server_payload(
    payload: &ServerTimelockPayload,
    round: u64,
    beacon_public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let bytes = serde_json::to_vec(payload)
        .map_err(|e| CryptoError::TimelockEncrypt(format!("payload serialise: {e}")))?;
    tle_bytes(&bytes, round, beacon_public_key)
}

/// Decrypt and parse the server bundle with the round's beacon signature.
pub fn decrypt_server_payload(
    ciphertext: &[u8],
    beacon_signature: &[u8],
) -> Result<ServerTimelockPayload, CryptoError> {
    let pt = tld_bytes(ciphertext, beacon_signature)?;
    serde_json::from_slice(&pt)
        .map_err(|e| CryptoError::TimelockPayload(format!("payload parse: {e}")))
}

#[cfg(test)]
pub(crate) mod test_vectors {
    //! Real, immutable drand Quicknet values usable offline.
    /// Quicknet chain public key (static).
    pub const QUICKNET_PK_HEX: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
    /// Real recorded signature for Quicknet round 1000.
    pub const ROUND_1000_SIG_HEX: &str = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";
    pub const ROUND_1000: u64 = 1000;
}

#[cfg(test)]
mod tests {
    use super::test_vectors::*;
    use super::*;
    use crate::types::contents::{Operation, OperationType};

    fn pk() -> Vec<u8> {
        hex::decode(QUICKNET_PK_HEX).unwrap()
    }
    fn sig1000() -> Vec<u8> {
        hex::decode(ROUND_1000_SIG_HEX).unwrap()
    }
    fn sample_contents() -> Contents {
        Contents {
            operations: vec![Operation {
                id: "tier".into(),
                depends_on: None,
                op: OperationType::Distribution {
                    outcomes: [("common".to_string(), 9000u64), ("rare".to_string(), 1000)]
                        .into_iter()
                        .collect(),
                },
            }],
        }
    }

    #[test]
    fn t1_t3_secret_round_trip_with_real_beacon() {
        let secret = [42u8; 32];
        let ct = encrypt_secret(&secret, ROUND_1000, &pk()).unwrap();
        assert!(!ct.is_empty());
        let back = decrypt_secret(&ct, &sig1000()).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn t1b_t3b_server_payload_round_trip() {
        let payload = ServerTimelockPayload {
            secret: [7u8; 32],
            contents: sample_contents(),
        };
        let ct = encrypt_server_payload(&payload, ROUND_1000, &pk()).unwrap();
        let back = decrypt_server_payload(&ct, &sig1000()).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn t2_encrypt_nondeterministic() {
        let s = [1u8; 32];
        let a = encrypt_secret(&s, ROUND_1000, &pk()).unwrap();
        let b = encrypt_secret(&s, ROUND_1000, &pk()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn t4_wrong_round_signature_rejected() {
        // encrypt to round 1001; round 1000's signature must not decrypt it
        let s = [3u8; 32];
        let ct = encrypt_secret(&s, 1001, &pk()).unwrap();
        assert!(decrypt_secret(&ct, &sig1000()).is_err());
    }

    #[test]
    fn t5_garbage_beacon_rejected() {
        let s = [4u8; 32];
        let ct = encrypt_secret(&s, ROUND_1000, &pk()).unwrap();
        assert!(decrypt_secret(&ct, &[0xAA; 48]).is_err());
    }

    #[test]
    fn junk_ciphertext_rejected() {
        assert!(decrypt_secret(&[0u8; 64], &sig1000()).is_err());
    }
}
