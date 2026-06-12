//! drand beacon interaction: chain info, local round calculation, and
//! beacon value retrieval. Spec §2.2, §7.
//!
//! Interaction model: chain info is fetched once and cached (static for a
//! given network); round numbers are calculated locally; beacon values are
//! fetched only when resolving an expired timelock (unhappy path).

use serde::{Deserialize, Serialize};

/// drand Quicknet constants (public, immutable).
pub mod quicknet {
    pub const CHAIN_HASH: &str =
        "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
    pub const PUBLIC_KEY_HEX: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
    pub const GENESIS_TIME: u64 = 1692803367;
    pub const PERIOD_SECONDS: u64 = 3;
    pub const BASE_URL: &str = "https://api.drand.sh";
}

/// Static parameters of a drand network.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainInfo {
    /// BLS12-381 G2 public key, hex-decoded bytes.
    #[serde(with = "crate::types::hexvec")]
    pub public_key: Vec<u8>,
    pub genesis_time: u64,
    /// Seconds between rounds.
    pub period: u64,
    pub chain_hash: String,
}

impl ChainInfo {
    /// Quicknet's well-known parameters, constructed offline.
    pub fn quicknet() -> Self {
        ChainInfo {
            public_key: hex::decode(quicknet::PUBLIC_KEY_HEX).expect("static hex"),
            genesis_time: quicknet::GENESIS_TIME,
            period: quicknet::PERIOD_SECONDS,
            chain_hash: quicknet::CHAIN_HASH.to_string(),
        }
    }
}

/// A single round's beacon output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconValue {
    pub round: u64,
    /// BLS signature bytes for the round (the timelock decryption key).
    #[serde(with = "crate::types::hexvec")]
    pub signature: Vec<u8>,
}

/// Errors from beacon interaction.
#[derive(Debug, thiserror::Error)]
pub enum BeaconError {
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("beacon for round {0} not yet available")]
    NotYetAvailable(u64),
}

/// Source of beacon values. Implementations: `MockBeaconClient` for tests
/// and offline demos; `DrandHttpClient` (feature `live`) for real fetches.
pub trait BeaconClient {
    fn chain_info(&self) -> Result<ChainInfo, BeaconError>;
    fn beacon(&self, round: u64) -> Result<BeaconValue, BeaconError>;
}

// ---- round calculation (Spec §7.1) ----

/// Round number in effect at `timestamp` (unix seconds).
pub fn round_at_time(chain: &ChainInfo, timestamp: u64) -> u64 {
    if timestamp < chain.genesis_time {
        return 0;
    }
    (timestamp - chain.genesis_time) / chain.period + 1
}

/// Unix timestamp at which `round` becomes available.
pub fn round_to_time(chain: &ChainInfo, round: u64) -> u64 {
    chain.genesis_time + round.saturating_sub(1) * chain.period
}

/// Current round per the system clock.
#[cfg(feature = "std")]
pub fn current_round(chain: &ChainInfo) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_secs();
    round_at_time(chain, now)
}

/// Target round for a timelock of `duration_seconds` from now.
/// Enforces the protocol minimum of 10 rounds (Spec §7.1).
#[cfg(feature = "std")]
pub fn target_round(chain: &ChainInfo, duration_seconds: u64) -> u64 {
    let rounds = (duration_seconds / chain.period).max(10);
    current_round(chain) + rounds
}

/// Mock client for tests and offline demos: serves pre-loaded values.
pub struct MockBeaconClient {
    chain: ChainInfo,
    beacons: std::collections::HashMap<u64, BeaconValue>,
}

impl MockBeaconClient {
    pub fn new(chain: ChainInfo) -> Self {
        Self {
            chain,
            beacons: Default::default(),
        }
    }

    pub fn with_beacon(mut self, round: u64, signature: Vec<u8>) -> Self {
        self.beacons.insert(round, BeaconValue { round, signature });
        self
    }
}

impl BeaconClient for MockBeaconClient {
    fn chain_info(&self) -> Result<ChainInfo, BeaconError> {
        Ok(self.chain.clone())
    }

    fn beacon(&self, round: u64) -> Result<BeaconValue, BeaconError> {
        self.beacons
            .get(&round)
            .cloned()
            .ok_or(BeaconError::NotYetAvailable(round))
    }
}

/// Live HTTP client against the drand API (feature `live`).
#[cfg(feature = "live")]
pub struct DrandHttpClient {
    base_url: String,
    chain_hash: String,
}

#[cfg(feature = "live")]
impl DrandHttpClient {
    pub fn quicknet() -> Self {
        Self {
            base_url: quicknet::BASE_URL.to_string(),
            chain_hash: quicknet::CHAIN_HASH.to_string(),
        }
    }
}

#[cfg(feature = "live")]
impl BeaconClient for DrandHttpClient {
    fn chain_info(&self) -> Result<ChainInfo, BeaconError> {
        let url = format!("{}/{}/info", self.base_url, self.chain_hash);
        let resp: serde_json::Value = ureq::get(&url)
            .call()
            .map_err(|e| BeaconError::Network(e.to_string()))?
            .into_json()
            .map_err(|e| BeaconError::InvalidResponse(e.to_string()))?;
        let pk_hex = resp["public_key"]
            .as_str()
            .ok_or_else(|| BeaconError::InvalidResponse("missing public_key".into()))?;
        Ok(ChainInfo {
            public_key: hex::decode(pk_hex)
                .map_err(|e| BeaconError::InvalidResponse(e.to_string()))?,
            genesis_time: resp["genesis_time"]
                .as_u64()
                .ok_or_else(|| BeaconError::InvalidResponse("missing genesis_time".into()))?,
            period: resp["period"]
                .as_u64()
                .ok_or_else(|| BeaconError::InvalidResponse("missing period".into()))?,
            chain_hash: self.chain_hash.clone(),
        })
    }

    fn beacon(&self, round: u64) -> Result<BeaconValue, BeaconError> {
        let url = format!("{}/{}/public/{}", self.base_url, self.chain_hash, round);
        let resp: serde_json::Value = ureq::get(&url)
            .call()
            .map_err(|e| BeaconError::Network(e.to_string()))?
            .into_json()
            .map_err(|e| BeaconError::InvalidResponse(e.to_string()))?;
        let sig_hex = resp["signature"]
            .as_str()
            .ok_or_else(|| BeaconError::InvalidResponse("missing signature".into()))?;
        Ok(BeaconValue {
            round,
            signature: hex::decode(sig_hex)
                .map_err(|e| BeaconError::InvalidResponse(e.to_string()))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(genesis: u64, period: u64) -> ChainInfo {
        ChainInfo {
            public_key: vec![],
            genesis_time: genesis,
            period,
            chain_hash: "test".into(),
        }
    }

    #[test]
    fn b1_round_at_time() {
        // genesis 1000, period 3, t=1030 -> floor(30/3)+1 = 11
        assert_eq!(round_at_time(&chain(1000, 3), 1030), 11);
    }

    #[test]
    fn b3_round_at_genesis_is_1() {
        assert_eq!(round_at_time(&chain(1000, 3), 1000), 1);
    }

    #[test]
    fn b4_round_to_time() {
        assert_eq!(round_to_time(&chain(1000, 3), 11), 1030);
        assert_eq!(round_to_time(&chain(1000, 3), 1), 1000);
    }

    #[test]
    fn round_time_inverse() {
        let c = chain(1_692_803_367, 3);
        for round in [1u64, 2, 100, 1000, 12345678] {
            assert_eq!(round_at_time(&c, round_to_time(&c, round)), round);
        }
    }

    #[test]
    fn bc4_mock_serves_configured_values() {
        let mock = MockBeaconClient::new(ChainInfo::quicknet()).with_beacon(1000, vec![1, 2, 3]);
        assert_eq!(mock.chain_info().unwrap().period, 3);
        assert_eq!(mock.beacon(1000).unwrap().signature, vec![1, 2, 3]);
        assert!(matches!(
            mock.beacon(2000),
            Err(BeaconError::NotYetAvailable(2000))
        ));
    }
}
