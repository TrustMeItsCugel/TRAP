# TRAP: Test Scenarios

**Version:** 0.1.0-draft
**Companion to:** TRAP Protocol Specification & Architecture Document

---

## 1. Conventions

Each scenario follows the format:

- **Given:** Preconditions and setup state
- **When:** The action or event being tested
- **Then:** Expected outcome and assertions

Scenarios are grouped by module. Scenarios marked **[INTEGRATION]** require multiple modules working together. Scenarios marked **[LIVE]** require a real drand connection and are only run with the `demo-live` feature.

---

## 2. Crypto Module

### 2.1 Hashing (`crypto::hash`)

**H1 — Commitment is deterministic:**
Given a secret `0xaabbccdd...` (32 bytes)
When `commit(secret)` is called twice
Then both calls return identical 32-byte output.

**H2 — Commitment is one-way:**
Given a commitment value
When compared against `commit()` of 2^16 random secrets
Then none produce a collision (probabilistic; validates the function isn't trivially broken).

**H3 — Different secrets produce different commitments:**
Given two distinct 32-byte secrets
When both are committed
Then the commitments differ.

**H4 — Contents commitment includes session salt:**
Given identical contents but different session IDs
When `commit_contents(contents, session_id)` is called for each
Then the commitments differ.

**H5 — Contents commitment is deterministic:**
Given the same contents and session ID
When `commit_contents()` is called twice
Then both calls return identical output.

**H6 — Combine secrets is order-dependent:**
Given `client_secret` and `server_secret`
When `combine_secrets(client, server)` and `combine_secrets(server, client)` are called
Then the results differ (concatenation order matters).

**H7 — Combine secrets is deterministic:**
Given the same client and server secrets
When `combine_secrets()` is called twice
Then both calls return identical output.

**H8 — Operation derivation produces unique values:**
Given a combined randomness value
When `derive_operation_random(combined, "tier")` and `derive_operation_random(combined, "item")` are called
Then the derived values differ.

**H9 — Operation derivation is deterministic:**
Given the same combined randomness and operation ID
When `derive_operation_random()` is called twice
Then both calls return identical output.

**H10 — Verify commitment succeeds on match:**
Given a secret and its commitment
When `verify_commitment(secret, commitment)` is called
Then it returns true.

**H11 — Verify commitment fails on mismatch:**
Given a secret and a different secret's commitment
When `verify_commitment(secret, wrong_commitment)` is called
Then it returns false.

---

### 2.2 Signatures (`crypto::sign`)

**S1 — Sign and verify round-trip:**
Given a keypair and a set of named fields
When `sign_fields()` then `verify_field_signature()` are called
Then verification succeeds.

**S2 — Verification fails on tampered field value:**
Given a valid signature over fields `[("a", b"hello"), ("b", b"world")]`
When verification is attempted with `[("a", b"TAMPERED"), ("b", b"world")]`
Then verification fails.

**S3 — Verification fails on missing field:**
Given a valid signature over fields `["a", "b", "c"]`
When verification is attempted with only `["a", "b"]`
Then verification fails.

**S4 — Verification fails on extra field:**
Given a valid signature over fields `["a", "b"]`
When verification is attempted with `["a", "b", "c"]`
Then verification fails.

**S5 — Verification fails with wrong public key:**
Given a signature created with key A
When verification is attempted with key B
Then verification fails.

**S6 — Signature chaining includes prior signatures:**
Given a first signature `sig1` over fields `["a"]`
And a second signature `sig2` over fields `["a", "b"]` with `prior_signatures: [sig1]`
When `sig1` is tampered with after `sig2` was created
Then verification of `sig2` fails.

**S7 — Signature chaining order matters:**
Given two signatures chained in order `[sig1, sig2]`
When verification is attempted with `[sig2, sig1]`
Then verification fails.

---

### 2.3 Timelock (`crypto::timelock`)

**T1 — Encrypt secret produces non-empty ciphertext:**
Given a 32-byte plaintext, a round number, and the drand public key
When `encrypt_secret()` is called
Then it returns a non-empty ciphertext that differs from the plaintext.

**T1b — Encrypt server payload produces non-empty ciphertext:**
Given a `ServerTimelockPayload` containing a secret and contents, a round number, and the drand public key
When `encrypt_server_payload()` is called
Then it returns a non-empty ciphertext.

**T2 — Encrypt is non-deterministic:**
Given the same plaintext and round
When `encrypt_secret()` is called twice
Then the ciphertexts differ (timelock encryption should include randomness).

**T3 — Decrypt recovers secret with correct beacon:**
Given ciphertext encrypted to round N via `encrypt_secret()`
And the real beacon value for round N
When `decrypt_secret(ciphertext, beacon)` is called
Then it returns the original plaintext.

**T3b — Decrypt recovers server payload with correct beacon:**
Given ciphertext encrypted to round N via `encrypt_server_payload()`
And the real beacon value for round N
When `decrypt_server_payload(ciphertext, beacon)` is called
Then it returns the original secret and contents.

**T4 — Decrypt fails with wrong beacon:**
Given ciphertext encrypted to round N
And the beacon value for round M (M ≠ N)
When `decrypt(ciphertext, beacon)` is called
Then it returns an error.

**T5 — Decrypt fails with garbage beacon:**
Given valid ciphertext
And a random byte array as the beacon value
When `decrypt()` is called
Then it returns an error.

**T6 — [LIVE] Round-trip with real drand:**
Given a plaintext encrypted to a near-future drand round
When that round arrives and the beacon is fetched
Then decryption recovers the original plaintext.

---

## 3. Beacon Module

### 3.1 Round Calculation (`beacon::calc`)

**B1 — Current round calculation:**
Given chain info with `genesis_time = 1000`, `period = 3`
And a current time of `1030`
When `current_round()` is called
Then it returns `11` (floor((1030 - 1000) / 3) + 1).

**B2 — Target round calculation:**
Given chain info with `period = 3`
And a desired duration of 900 seconds (15 minutes)
When `target_round()` is called
Then it returns `current_round + 300`.

**B3 — Round at genesis is 1:**
Given current time equals genesis time
When `current_round()` is called
Then it returns 1.

**B4 — Round to time:**
Given chain info with `genesis_time = 1000`, `period = 3`
When `round_to_time(chain_info, 11)` is called
Then it returns `1030`.

**B5 — Minimum duration respected:**
Given a desired duration of 30 seconds and `period = 3`
When `target_round()` is called
Then it returns `current_round + 10` (at least 10 rounds).

### 3.2 Beacon Client (`beacon::client`)

**BC1 — [LIVE] Fetch chain info from Quicknet:**
Given a `DrandHttpClient::quicknet()`
When `get_chain_info()` is called
Then it returns a `ChainInfo` with a non-empty public key, genesis_time > 0, and period = 3.

**BC2 — [LIVE] Fetch historical beacon:**
Given a known past round number
When `get_beacon(round)` is called
Then it returns a `BeaconValue` with matching round number and non-empty signature.

**BC3 — Fetch non-existent future round fails gracefully:**
Given a round number far in the future
When `get_beacon(round)` is called
Then it returns a `BeaconError` (not a panic).

**BC4 — Mock client returns configured values:**
Given a `MockBeaconClient` configured with specific chain info and beacon values
When `get_chain_info()` and `get_beacon(round)` are called
Then they return the pre-configured values.

---

## 4. Protocol Module — Happy Path

### 4.1 Full Happy Path

**P1 — [INTEGRATION] Complete 5-step exchange:**
Given a server identity, client identity, chain info, and contents
When the full protocol is executed:
  1. Server calls `ServerSession::initiate()` → produces `ServerCommitment`
  2. Client calls `ClientSession::accept(server_commitment)` → produces `ClientCommitment`
  3. Server calls `receive_client_commitment(client_commitment)` → produces `ContentsReveal`
  4. Client calls `receive_contents(contents_reveal)` → produces `ClientReveal`
  5. Server calls `receive_client_reveal(client_reveal)` → produces `ServerReveal`
  6. Client calls `receive_server_reveal(server_reveal)` → produces `Outcome`
Then:
  - Both parties compute the same outcome.
  - The outcome is deterministic (repeating with same secrets yields same result).
  - The proof document contains all 5 steps.
  - `verify_proof(proof)` succeeds.

**P2 — [INTEGRATION] Outcome varies with different secrets:**
Given two complete protocol runs with different client secrets (same server secret and contents)
When outcomes are compared
Then they differ (with overwhelming probability).

**P3 — [INTEGRATION] Outcome varies with different server secrets:**
Given two complete protocol runs with different server secrets (same client secret and contents)
When outcomes are compared
Then they differ (with overwhelming probability).

**P4 — [INTEGRATION] Outcome is deterministic for same secrets:**
Given two protocol runs with identical client and server secrets and identical contents
When outcomes are compared
Then they are identical.

---

## 5. Protocol Module — Unhappy Paths

### 5.1 Client Ghosts After Step 1

**U1 — [INTEGRATION] Server resolves via timelock:**
Given a protocol that has completed Steps 0 and 1
And the client does not send Step 3 (reveal)
When the server resolves with the beacon value for the target round:
  1. Server decrypts client's timelock-encrypted secret
  2. Server verifies decrypted secret matches client's commitment
  3. Server computes outcome from both secrets
Then:
  - The outcome matches what the happy path would have produced.
  - The server's proof document records the resolution method.

**U2 — [INTEGRATION] Server resolves — outcome matches happy path:**
Given the same secrets used in a successful happy-path run
When the server resolves via timelock instead of receiving the client reveal
Then the computed outcome is identical to the happy-path outcome.

### 5.2 Server Ghosts After Step 1

**U3 — [INTEGRATION] Client resolves via timelock (server ghosts before contents reveal):**
Given a protocol that has completed Steps 0 and 1
And the server does not send Step 2 (contents reveal)
When the client resolves with the beacon value for the target round:
  1. Client decrypts server's timelock-encrypted bundle
  2. Client extracts the server secret and the contents from the bundle
  3. Client verifies `SHA256(secret)` matches `server_commitment` from Step 0
  4. Client verifies `SHA256(contents || session_id)` matches `contents_commitment` from Step 0
  5. Client computes outcome using both secrets and the contents
Then:
  - The outcome matches what the happy path would have produced.
  - The proof document is fully self-resolving without server cooperation.

### 5.3 Server Ghosts After Step 2

**U4 — [INTEGRATION] Client resolves after receiving contents:**
Given a protocol that has completed Steps 0, 1, and 2
And the server does not send Step 4 (server reveal)
When the client resolves with the beacon value:
  1. Client decrypts server's timelock-encrypted bundle
  2. Client extracts the server secret (contents already received at Step 2)
  3. Client verifies decrypted secret matches server's commitment
  4. Client computes outcome using both secrets and the revealed contents
Then:
  - The outcome matches what the happy path would have produced.
  - The contents from the bundle match the contents revealed at Step 2 (additional consistency check).

### 5.4 Junk Timelock Encryption

**U5 — [INTEGRATION] Server encrypted junk bundle — detected on resolution:**
Given a server that encrypts random garbage (not the real secret and contents) under timelock
And the protocol proceeds through Steps 0 and 1
When the client resolves via timelock:
  1. Client decrypts the server's timelock ciphertext
  2. Client attempts to parse the decrypted payload as a `{secret, contents}` bundle
  3. If parsing succeeds, client verifies `SHA256(secret)` against `server_commitment` and `SHA256(contents || session_id)` against `contents_commitment`
Then:
  - Either parsing fails or commitment verification fails.
  - This constitutes cryptographic proof of server misbehaviour.
  - The proof document records the mismatch.

**U6 — [INTEGRATION] Client encrypted junk — detected on resolution:**
Given a client that encrypts random garbage under timelock
And the protocol proceeds through Steps 0 and 1
When the server resolves via timelock:
  1. Server decrypts the client's timelock ciphertext
  2. Server computes `SHA256(decrypted_value)`
  3. Server compares against `client_commitment` from Step 1
Then:
  - The comparison fails.
  - This constitutes cryptographic proof of client misbehaviour.

### 5.5 Contents Hash Mismatch

**U7 — Server reveals different contents than committed:**
Given a server that commits to `SHA256(contents_A || session_id)` in Step 0
But reveals `contents_B` in Step 2
When the client verifies `SHA256(contents_B || session_id)` against the Step 0 commitment
Then:
  - Verification fails.
  - The client aborts the session.
  - The proof document (Steps 0-2) serves as evidence of server misbehaviour.

### 5.6 Reveal Hash Mismatch

**U8 — Client reveals wrong secret:**
Given a client that committed `SHA256(secret_A)` in Step 1
But reveals `secret_B` in Step 3
When the server verifies `SHA256(secret_B)` against the Step 1 commitment
Then:
  - Verification fails.
  - The server rejects the reveal.
  - The server can resolve via timelock to obtain the real committed secret.

**U9 — Server reveals wrong secret:**
Given a server that committed `SHA256(secret_A)` in Step 0
But reveals `secret_B` in Step 4
When the client verifies `SHA256(secret_B)` against the Step 0 commitment
Then:
  - Verification fails.
  - The client can resolve via timelock to obtain the real committed secret.
  - The proof document records the mismatch.

---

## 6. Protocol Module — State Machine

### 6.1 Valid Transitions

**SM1 — Server session follows correct step order:**
Given a new `ServerSession::initiate()`
When methods are called in order: `receive_client_commitment()` → `receive_client_reveal()`
Then each transition succeeds.

**SM2 — Client session follows correct step order:**
Given a new `ClientSession::accept()`
When methods are called in order: `receive_contents()` → `receive_server_reveal()`
Then each transition succeeds.

### 6.2 Invalid Transitions

**SM3 — Server cannot skip steps:**
Given a `ServerSession` at Step 0 (just initiated)
When `receive_client_reveal()` is called (skipping `receive_client_commitment()`)
Then it returns `ProtocolError::InvalidState`.

**SM4 — Client cannot skip steps:**
Given a `ClientSession` at Step 1 (just accepted)
When `receive_server_reveal()` is called (skipping `receive_contents()`)
Then it returns `ProtocolError::InvalidState`.

**SM5 — Session cannot be reused after completion:**
Given a `ServerSession` that has completed Step 4
When any transition method is called
Then it returns `ProtocolError::InvalidState` (or is prevented at compile time via ownership).

**SM6 — Timelock resolution is only available after commitment:**
Given a `ServerSession` at Step 0 (before client commitment received)
When `resolve_with_beacon()` is called
Then it returns `ProtocolError::InvalidState`.

**SM7 — Timelock resolution is available after Step 1:**
Given a `ServerSession` that has received a client commitment (Step 1 complete)
When `resolve_with_beacon()` is called with a valid beacon
Then it succeeds and produces an outcome.

---

## 7. Proof Verification

**V1 — Valid proof verifies:**
Given a proof document from a completed happy-path run
When `verify_proof()` is called
Then it returns `VerifyResult` with all checks passing.

**V2 — Tampered commitment is detected:**
Given a valid proof document
When the `server_commitment` hash is modified
Then `verify_proof()` fails with a signature verification error.

**V3 — Tampered contents is detected:**
Given a valid proof document
When a field in `contents` is modified
Then `verify_proof()` fails with a contents commitment mismatch.

**V4 — Tampered reveal is detected:**
Given a valid proof document
When `client_secret` is modified
Then `verify_proof()` fails with a commitment-reveal mismatch.

**V5 — Tampered outcome is detected:**
Given a valid proof document
When the `outcome` field is modified
Then `verify_proof()` fails because the recomputed outcome doesn't match.

**V6 — Swapped signatures are detected:**
Given a valid proof document
When two signatures are swapped in position
Then `verify_proof()` fails due to signature chain breakage.

**V7 — Partial proof verifies up to its last step:**
Given a proof document containing only Steps 0 and 1 (client ghosted)
When `verify_proof()` is called
Then it verifies Steps 0 and 1 are internally consistent, and reports the session as incomplete.

**V8 — Proof from timelock resolution verifies:**
Given a proof document where the outcome was resolved via timelock
When `verify_proof()` is called
Then it verifies the decrypted secret matches the commitment and the outcome was correctly computed.

---

## 8. Serialisation

**SER1 — All message types round-trip through JSON:**
Given each message type (`ServerCommitment`, `ClientCommitment`, `ContentsReveal`, `ClientReveal`, `ServerReveal`, `ProofDocument`)
When serialised to JSON then deserialised back
Then the resulting struct is identical to the original.

**SER2 — Proof document is self-contained JSON:**
Given a completed proof document
When serialised to JSON
Then it can be written to a file, read back by a separate process, and verified without any additional context (except public keys).

**SER3 — Unknown fields are tolerated:**
Given a serialised message with extra fields not in the spec
When deserialised
Then it succeeds (forward compatibility). Unknown fields are ignored.

**SER4 — Missing required fields fail:**
Given a serialised message with a required field removed
When deserialised
Then it returns a clear deserialisation error.

---

## 9. Randomness Derivation & Outcome Mapping

**R1 — Modulo mapping covers full range:**
Given 1000 random `combined_randomness` values and `n = 10` outcomes
When `uint256(combined) % n` is computed for each
Then all 10 outcomes appear at least once.

**R2 — Distribution mapping respects weights:**
Given contents with outcomes weighted `{"a": 9000, "b": 1000}`
And 10,000 random combined values
When outcomes are computed for each
Then outcome "a" appears approximately 90% of the time (within statistical tolerance).

**R3 — Range mapping stays within bounds:**
Given a range operation with `min = 10, max = 20`
And 1000 random derived values
When outcomes are computed
Then all results are between 10 and 20 inclusive.

**R4 — Dependent operation uses parent result:**
Given operations: `tier` (distribution) → `item` (dependent distribution)
When a combined randomness is processed
Then `item` selects from the subset corresponding to the `tier` result.

**R5 — Maximum dependency depth of 6:**
Given contents with 7 levels of chained dependencies
When the contents are validated
Then validation fails with an error indicating maximum depth exceeded.

**R6 — Circular dependencies are rejected:**
Given contents where operation A depends on B and B depends on A
When the contents are validated
Then validation fails with an error indicating circular dependency.

---

## 10. Demo Scenarios

The demo is minimal — just enough to show the protocol works visually. The test suite provides comprehensive coverage.

**D1 — Happy path demo:**
The demo runs the full 5-step exchange in-process, printing each step with session ID, commitment hashes (truncated), revealed secrets, combined randomness, computed outcome, and proof verification result. Writes `proof_happy.json` to disk.

**D2 — Timelock resolution demo:**
The demo simulates one party ghosting. The other party resolves via (mock) beacon, showing decrypted values, commitment verification, and computed outcome. Writes `proof_resolved.json` to disk.

**D3 — Proof verification demo:**
The demo loads a proof JSON from disk and runs standalone verification, printing signature chain validity, commitment-reveal consistency, and outcome computation correctness.

**D4 — [LIVE] Real drand demo:**
When run with `--live` flag, uses real drand Quicknet with a 30-second timelock, actually waits for expiry, and fetches real beacon. Proves the protocol works against live infrastructure.
