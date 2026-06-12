//! # TRAP: Trustless Random Agreement Protocol
//!
//! Reference implementation. Two mutually distrusting parties agree on a
//! random value; neither can predict, influence, or retroactively
//! manipulate the outcome after commitment.
//!
//! - Bilateral commit-reveal with drand timelock enforcement
//! - Self-resolving proof documents (no cooperation needed after expiry)
//! - Entirely off-chain; zero network calls on the happy path
//!
//! Entry points: [`protocol::server::ServerSession`],
//! [`protocol::client::ClientSession`], [`protocol::verify::verify_proof`].

pub mod beacon;
pub mod crypto;
pub mod outcome;
pub mod protocol;
pub mod types;

pub const PROTOCOL_VERSION: &str = "0.1.0";
