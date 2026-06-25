# TRAP: Architecture Document

**Version:** 0.1.0-draft
**Companion to:** TRAP Protocol Specification v0.1.0-draft

---

## 1. Overview

TRAP is implemented as a Rust library crate (`trap`), accompanied by a demonstration binary that exercises the full protocol. The library is the primary deliverable; the demo exists to prove the protocol works end-to-end.

### 1.1 Deliverables

| Deliverable | Type | Purpose |
|-------------|------|---------|
| `trap` | Rust library crate | Core protocol implementation |
| `trap-demo` | Rust binary crate | End-to-end demonstration of the protocol |

### 1.2 Design Principles

- **The library is the product.** The demo is disposable; the library API must be clean.
- **State machine driven.** The protocol is modelled as an explicit state machine with typed transitions. Invalid state transitions are compile-time errors where possible, runtime errors otherwise.
- **No async in the core.** The library is synchronous. Async concerns (network I/O, timers) belong to the consumer. The one exception is the beacon module, which performs HTTP requests — this is isolated behind a trait so consumers can provide their own implementation.
- **Minimal dependencies.** Only pull in what's necessary. Prefer well-established, audited crates for cryptographic operations.

---

## 2. Workspace Structure

```
trap/
├── Cargo.toml              # Workspace root
├── trap-core/              # Library crate
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          # Public API re-exports
│       ├── outcome.rs      # Outcome evaluation (randomness → results)
│       ├── types/          # Data structures & serialisation
│       │   ├── mod.rs
│       │   ├── messages.rs # Protocol messages, ProofDocument, SessionConfig
│       │   └── contents.rs # Application-layer content & outcome types
│       ├── crypto/         # Cryptographic operations
│       │   ├── mod.rs
│       │   ├── hash.rs     # SHA-256 commitments
│       │   ├── sign.rs     # Ed25519 signing & verification
│       │   └── timelock.rs # drand timelock encrypt/decrypt
│       ├── beacon/         # drand network interaction
│       │   └── mod.rs      # ChainInfo, BeaconValue, MockBeaconClient, round calc
│       └── protocol/       # Protocol state machine
│           ├── mod.rs
│           ├── fields.rs   # Field serialisation for signature chaining
│           ├── server.rs   # Server-side session state machine
│           ├── client.rs   # Client-side session state machine
│           └── verify.rs   # Standalone proof verification
├── trap-demo/              # Demo binary crate
│   ├── Cargo.toml
│   └── src/
│       └── main.rs         # End-to-end protocol demonstration
└── README.md
```

---

## 3. Module Design

### 3.1 `types` — Data Structures

All protocol data structures live here. These are pure data types with serialisation support — no business logic.

**Key types:**

```rust
/// Configuration for a new session (server-provided)
pub struct SessionConfig {
    pub session_id: String,
    pub drand_round: u64,
    pub version: String,
    pub metadata: Option<serde_json::Value>,
}

/// A party's cryptographic identity
pub struct Identity {
    pub signing_key: ed25519_dalek::SigningKey,   // private
    pub verifying_key: ed25519_dalek::VerifyingKey, // public
}

/// Signature with explicit field coverage
pub struct FieldSignature {
    pub signature: ed25519_dalek::Signature,
    pub signed_fields: Vec<String>,
    pub algorithm: String,  // always "Ed25519"
    pub signer: ed25519_dalek::VerifyingKey,
}

/// Step 0: Server's initial commitment
pub struct ServerCommitment {
    pub version: String,
    pub session_id: String,
    pub server_commitment: [u8; 32],     // SHA256(server_secret)
    pub contents_commitment: [u8; 32],   // SHA256(contents || session_id)
    pub server_nonce_commitment: [u8; 32], // SHA256(server_nonce) — revealed live at Step 2
    pub server_timelock_encrypted: Vec<u8>, // timelock(server_secret) — secret only
    pub drand_round: u64,
    pub metadata: Option<serde_json::Value>,
    pub signature: FieldSignature,
}

/// Step 1: Client's commitment
pub struct ClientCommitment {
    pub client_commitment: [u8; 32],     // SHA256(client_secret)
    pub client_timelock_encrypted: Vec<u8>,
    pub signature: FieldSignature,
}

/// Step 2: Server reveals contents and nonce
pub struct ContentsReveal {
    pub contents: Contents,
    pub server_nonce: [u8; 32],          // committed at Step 0, revealed here
    pub signature: FieldSignature,
}

/// Step 3: Client reveals secret
pub struct ClientReveal {
    pub client_secret: [u8; 32],
    pub signature: FieldSignature,
}

/// Step 4: Server reveals secret and outcome
pub struct ServerReveal {
    pub server_secret: [u8; 32],
    pub combined_randomness: [u8; 32],
    pub outcome: Outcome,
    pub signature: FieldSignature,
}

/// Complete proof document (all steps)
pub struct ProofDocument {
    pub server_commitment: ServerCommitment,
    pub client_commitment: ClientCommitment,
    pub contents_reveal: Option<ContentsReveal>,
    pub client_reveal: Option<ClientReveal>,
    pub server_reveal: Option<ServerReveal>,
}
```

**Contents types (application layer):**

```rust
pub struct Contents {
    pub operations: Vec<Operation>,
}

pub struct Operation {
    pub id: String,
    pub op_type: OperationType,
    pub depends_on: Option<String>,
}

pub enum OperationType {
    Distribution { outcomes: IndexMap<String, u64> },
    Range { min: i64, max: i64 },
    DependentDistribution { outcomes: IndexMap<String, IndexMap<String, u64>> },
    DependentRange { ranges: IndexMap<String, RangeParams> },
}

pub struct RangeParams {
    pub min: i64,
    pub max: i64,
}

pub struct Outcome {
    pub results: IndexMap<String, OutcomeValue>,
}

pub enum OutcomeValue {
    Selected(String),
    Number(i64),
    Decimal(f64),
}
```

All message types derive `Serialize`, `Deserialize`, `Clone`, `Debug`.

### 3.2 `crypto` — Cryptographic Operations

Pure functions. No state, no I/O. Each sub-module has a focused responsibility.

**`hash.rs`:**
```rust
pub fn commit(secret: &[u8; 32]) -> [u8; 32];
pub fn commit_contents(contents: &Contents, session_id: &str) -> [u8; 32];
pub fn combine_secrets(client_secret: &[u8; 32], server_secret: &[u8; 32], server_nonce: &[u8; 32]) -> [u8; 32];
pub fn derive_operation_random(combined: &[u8; 32], operation_id: &str) -> [u8; 32];
pub fn verify_commitment(secret: &[u8; 32], commitment: &[u8; 32]) -> bool;
```

**`sign.rs`:**
```rust
pub fn sign_fields(
    key: &SigningKey,
    fields: &[(&str, &[u8])],
    prior_signatures: &[&FieldSignature],
) -> FieldSignature;

pub fn verify_field_signature(
    signature: &FieldSignature,
    fields: &[(&str, &[u8])],
    prior_signatures: &[&FieldSignature],
) -> Result<(), VerifyError>;
```

**`timelock.rs`:**
```rust
pub fn encrypt_secret(
    secret: &[u8; 32],
    round: u64,
    beacon_public_key: &[u8],
) -> Result<Vec<u8>, CryptoError>;

pub fn decrypt_secret(
    ciphertext: &[u8],
    beacon_signature: &[u8],
) -> Result<[u8; 32], CryptoError>;
```

### 3.3 `beacon` — drand Network Interaction

This module handles all interaction with the drand network. The HTTP client is behind a trait to allow testing and consumer-provided implementations. Everything lives in `mod.rs`.

```rust
pub struct ChainInfo {
    pub public_key: Vec<u8>,
    pub genesis_time: u64,
    pub period: u64,       // seconds between rounds (3 for Quicknet)
    pub chain_hash: String,
}

pub struct BeaconValue {
    pub round: u64,
    pub signature: Vec<u8>,
}

pub trait BeaconClient {
    fn chain_info(&self) -> Result<ChainInfo, BeaconError>;
    fn beacon(&self, round: u64) -> Result<BeaconValue, BeaconError>;
}

// Round calculation
pub fn round_at_time(chain: &ChainInfo, timestamp: u64) -> u64;
pub fn round_to_time(chain: &ChainInfo, round: u64) -> u64;
pub fn current_round(chain: &ChainInfo) -> u64;        // feature = "std"
pub fn target_round(chain: &ChainInfo, duration_seconds: u64) -> u64; // feature = "std"

// Implementations
pub struct MockBeaconClient { ... }   // for tests and offline demos
pub struct DrandHttpClient { ... }    // feature = "live"; HTTP against drand API

impl DrandHttpClient {
    pub fn quicknet() -> Self;
}
```

### 3.4 `protocol` — State Machine

The protocol is modelled as two separate state machines: one for the server role and one for the client role. Each state machine consumes incoming messages and produces outgoing messages, enforcing valid transitions.

**`server.rs`:**
```rust
pub struct ServerSession { ... }

impl ServerSession {
    /// Step 0: Create a new session and produce the server commitment.
    /// Generates server secret, computes commitment, encrypts under timelock.
    pub fn initiate(
        identity: &Identity,
        contents: Contents,
        config: SessionConfig,
        chain_info: &ChainInfo,
    ) -> Result<(Self, ServerCommitment), ProtocolError>;

    /// Step 1→2: Receive client commitment, produce contents reveal.
    pub fn receive_client_commitment(
        self,
        msg: ClientCommitment,
    ) -> Result<(Self, ContentsReveal), ProtocolError>;

    /// Step 3→4: Receive client reveal, produce server reveal + outcome.
    pub fn receive_client_reveal(
        self,
        msg: ClientReveal,
    ) -> Result<(Self, ServerReveal), ProtocolError>;

    /// Unhappy path: Resolve after timelock expiry when client ghosted.
    pub fn resolve_with_beacon(
        self,
        beacon: &BeaconValue,
    ) -> Result<(Self, Outcome), ProtocolError>;

    /// Export the proof document at current state.
    pub fn proof(&self) -> ProofDocument;
}
```

**`client.rs`:**
```rust
pub struct ClientSession { ... }

impl ClientSession {
    /// Step 0→1: Receive server commitment, produce client commitment.
    /// Generates client secret, computes commitment, encrypts under timelock.
    pub fn accept(
        identity: &Identity,
        msg: ServerCommitment,
        chain_info: &ChainInfo,
    ) -> Result<(Self, ClientCommitment), ProtocolError>;

    /// Step 2→3: Receive contents reveal, verify against commitment,
    /// produce client reveal.
    pub fn receive_contents(
        self,
        msg: ContentsReveal,
    ) -> Result<(Self, ClientReveal), ProtocolError>;

    /// Step 4: Receive server reveal, verify and compute outcome.
    pub fn receive_server_reveal(
        self,
        msg: ServerReveal,
    ) -> Result<(Self, Outcome), ProtocolError>;

    /// Unhappy path: Resolve after timelock expiry when server ghosted.
    pub fn resolve_with_beacon(
        self,
        beacon: &BeaconValue,
    ) -> Result<(Self, Outcome), ProtocolError>;

    /// Export the proof document at current state.
    pub fn proof(&self) -> ProofDocument;
}
```

**State machine transitions consume `self` by value.** This ensures at the type level that a session cannot be advanced twice from the same state. Each method returns a new `Self` representing the next state.

**`verify.rs`:**
```rust
/// Standalone proof verification — no session state needed.
/// Verifies all signatures, commitment-reveal consistency,
/// and outcome computation from a proof document.
pub fn verify_proof(proof: &ProofDocument) -> Result<VerifyResult, VerifyError>;

pub struct VerifyResult {
    pub outcome: Outcome,
    pub all_signatures_valid: bool,
    pub all_commitments_match: bool,
    pub outcome_correctly_computed: bool,
}
```

---

## 4. Dependency Map

### 4.1 External Crates

| Crate | Purpose | Module |
|-------|---------|--------|
| `sha2` | SHA-256 hashing | `crypto::hash` |
| `ed25519-dalek` | Ed25519 signing/verification | `crypto::sign` |
| `ideal-lab5/timelock` | drand timelock encrypt/decrypt | `crypto::timelock` |
| `serde` + `serde_json` | Serialisation | `types` |
| `indexmap` | Order-preserving maps for contents/outcomes | `types` |
| `ureq` or `reqwest` (blocking) | HTTP client for drand | `beacon::client` |
| `rand` | Cryptographic random secret generation | `protocol` |
| `hex` | Hex encoding for display/debug | various |
| `thiserror` | Error type derivation | various |

### 4.2 Internal Dependency Flow

```
protocol ──→ crypto ──→ (external crypto crates)
    │           │
    │           └──→ types
    │
    └──→ beacon ──→ types
            │
            └──→ (HTTP crate)

types ──→ (serde, indexmap)
```

Key constraints:
- `types` depends on nothing internal (leaf module).
- `crypto` depends only on `types` and external crypto crates.
- `beacon` depends only on `types` and an HTTP crate.
- `protocol` depends on `crypto`, `beacon`, and `types`.

---

## 5. Error Handling

Each module defines its own error type. The protocol module unifies them.

```rust
// crypto/mod.rs
pub enum CryptoError {
    InvalidSignature,
    InvalidPublicKey,
    TimelockEncrypt(String),
    TimelockDecrypt(String),
    TimelockPayload(String),
}

// beacon/mod.rs
pub enum BeaconError {
    NetworkError(String),
    InvalidResponse(String),
    ChainInfoUnavailable,
}

// protocol/mod.rs
pub enum ProtocolError {
    Crypto(CryptoError),
    Beacon(BeaconError),
    InvalidState { expected: &'static str, got: &'static str },
    CommitmentMismatch { field: String },
    InvalidContents,
    SessionExpired,
    InvalidMessage(String),
}
```

---

## 6. Demo Binary

The demo is a minimal `main.rs` that exercises both protocol roles in-process with no networking. Its purpose is to let someone `cargo run` and see the protocol work. The test suite is the comprehensive demonstration of correctness; the demo is just a visual walkthrough.

### 6.1 What It Does

1. Fetches drand chain info (or uses mock)
2. Generates server and client identities
3. Runs the happy path: all 5 steps, prints each step, writes the proof document to `proof_happy.json`
4. Runs a timelock resolution scenario: one party ghosts, the other resolves via beacon, writes proof to `proof_resolved.json`
5. Runs standalone proof verification on the written files

### 6.2 Mock vs Live

By default, the demo uses a `MockBeaconClient` with pre-computed values for instant, deterministic execution. A `--live` flag switches to real drand Quicknet with a 30-second timelock for proving the protocol works against live infrastructure.

### 6.3 Scope Constraints

The demo does NOT include:
- Networking or IPC of any kind
- Persistent storage
- Interactive CLI
- Multiple scenarios beyond the minimum needed to show the protocol works

A networked client/server demo is a separate future project. Design notes for that are archived in `TRAP_FUTURE_NETWORKED_DEMO.md`.

---

## 7. Build & Output

### 7.1 Library Outputs

```bash
cargo build --release
```

Produces:
- `libtrap_core.rlib` — Rust library
- `trap-demo` — Demo binary

### 7.2 Cargo Features

| Feature | Default | Effect |
|---------|---------|--------|
| `demo-live` | off | Enables live drand integration in demo |

---

## 8. Testing Strategy

### 8.1 Unit Tests

Each module has co-located tests:
- `crypto::hash` — Known-answer tests for commitment and derivation functions.
- `crypto::sign` — Round-trip sign/verify, tamper detection.
- `crypto::timelock` — Encrypt/decrypt with test vectors (requires mock or recorded beacon data).
- `beacon::calc` — Round calculation from known chain info + timestamps.
- `protocol::server` / `protocol::client` — State machine transitions, invalid transition rejection.
- `protocol::verify` — Proof verification with valid and tampered proofs.

### 8.2 Integration Tests

Full protocol flows as integration tests in `tests/`:
- Happy path end-to-end.
- Each unhappy path with simulated timelock resolution.
- Cross-verification: client and server independently compute same outcome.
- Serialisation round-trip: message → JSON → message for all types.

### 8.3 Property Tests

Where valuable (e.g., randomness derivation):
- For any two distinct secret pairs, outcomes differ (with high probability).
- Combined randomness is deterministic given the same inputs.
- Modulo mapping covers the full outcome space.
