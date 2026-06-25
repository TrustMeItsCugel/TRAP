# TRAP: Trustless Random Agreement Protocol

**Version:** 0.2.0-draft
**Status:** Draft
**License:** MIT

---

## 1. Introduction

TRAP is a cryptographic protocol that enables two mutually distrusting parties to agree on a random value where neither party can predict, influence, or retroactively manipulate the outcome after commitment.

TRAP is a **reference implementation and protocol demonstration**, not a production framework. It exists to show that trustless randomness agreement is technically achievable using existing cryptographic primitives, and to document the design considerations involved.

### 1.1 The Problem

Existing "provably fair" systems (common in online gambling) typically use a unilateral commit-reveal scheme: the server commits to a seed, the client provides a seed, and outcomes are derived from their combination. The server reveals its seed after the round for verification.

This approach has a fundamental weakness: it only proves the server didn't change its seed *after* commitment. It cannot prove the server didn't *select* its seed with foreknowledge of likely client seeds, nor can it prevent selective revelation — the server may simply not reveal outcomes it doesn't like.

TRAP addresses both weaknesses through **bilateral commit-reveal** with **timelock encryption** enforcement.

### 1.2 The Asymmetry Requirement

TRAP relies on an inherent power asymmetry between participants: one party (the **server**) possesses something the other party (the **client**) wants (e.g., a game item, a payout, a resource allocation). This asymmetry creates natural incentive alignment:

- The **server** cannot benefit from abandoning a session because it has already committed to the contents under timelock encryption. Ghosting gains nothing; the client can resolve the outcome unilaterally when the timelock expires.
- The **client** cannot benefit from abandoning a session because they want the resource the server controls. Walking away means forfeiting the item they initiated the session to obtain.

**This asymmetry is essential.** In a symmetric scenario (two equal peers with nothing at stake), either party can ghost after seeing an unfavourable commitment, and there is no natural cost to doing so. Solving the symmetric case requires zero-knowledge proofs on timelock-friendly curves (see [Section 9: Limitations](#9-limitations--future-work)), which is beyond the scope of this protocol.

### 1.3 Design Philosophy

- **Fail cleanly.** The protocol is designed so that every failure mode resolves deterministically. There are no ambiguous states.
- **Presumption of server innocence.** A server implementing TRAP has voluntarily opted into cryptographic accountability. The protocol assumes good faith and is designed to prove fault only when fault exists.
- **Protocol provides evidence, not enforcement.** TRAP produces cryptographically verifiable proof documents. What applications or communities do with those proofs is outside the protocol's scope.
- **Domain-agnostic.** The core protocol produces an agreed-upon random value. How that value maps to application-specific outcomes is an application-layer concern (see [Section 8: Application Layer](#8-application-layer)).
- **High throughput by design.** The protocol operates entirely off-chain. After a one-time fetch of drand chain info at startup, the happy path requires **zero external network calls** — only standard cryptographic operations (SHA-256 hashes, Ed25519 signatures) exchanged directly between two parties, with timelock encryption performed locally using cached parameters. There is no blockchain consensus, no transaction fees, and no block confirmation delays. The drand network is only contacted to fetch a beacon value on the unhappy path when resolving an expired timelock. This makes TRAP suitable for high-frequency scenarios where blockchain-based solutions would be prohibitively slow or expensive.

---

## 2. Cryptographic Primitives

| Primitive | Choice | Rationale |
|-----------|--------|-----------|
| Hash function | SHA-256 | Ubiquitous, well-understood, sufficient output size |
| Signature scheme | Ed25519 | Fast, simple, modern; excellent library support across C, C++, C#, JavaScript |
| Timelock encryption | drand Quicknet (BLS12-381) | Proven reliability, years of perfect uptime, 3-second round intervals |
| Timelock library | ideal-lab5/timelock (Rust) | Existing relationship; previously contributed C FFI bindings |

### 2.1 Key Management

- **Server keys:** Persistent Ed25519 keypairs with standard rotation schedules. Server public keys MUST be publicly discoverable to enable third-party proof verification.
- **Client keys:** Persistent Ed25519 keypairs with the option to rotate at the client's discretion.
- **No ephemeral session keys.** Simplicity is preferred. Identity keys are used directly for signing protocol messages.

### 2.2 drand Integration

- **Network:** Quicknet (unchained mode) — the only drand network supporting timelock encryption, as it uses round numbers only.
- **Round selection:** Server-defined. The server specifies the drand round number used for timelock encryption in its initial commitment (Step 0).
- **Beacon interaction model:** The TRAP library embeds a minimal HTTP client for drand network interaction. Chain info (public key, genesis time, period) is fetched **once at startup** and cached — these values are static for a given drand network. Target round numbers are **calculated locally** from the cached chain info and wall clock: `current_round = floor((now - genesis_time) / period) + 1`. Timelock encryption uses the cached public key with the calculated target round. **No network calls are required during session creation or the happy path.** Beacon values are fetched from drand only on the unhappy path, when a specific round's value is needed to decrypt an expired timelock.
- **Fallback:** If drand chain info cannot be fetched at startup, the library MUST NOT initiate sessions. The protocol fails closed. For sessions already in progress where the unhappy path requires a beacon fetch and drand is temporarily unreachable, the library should retry with backoff — the beacon value is immutable and will be available once drand recovers.

---

## 3. Protocol Flow

The protocol consists of 5 steps. The server initiates by committing to both its secret and the session contents (hashed). The client commits blindly — before seeing the contents — preventing selective participation. Contents are revealed only after both parties are committed.

### 3.1 Happy Path

```
Step 0: Server → Client    Server Commitment
Step 1: Client → Server    Client Commitment
Step 2: Server → Client    Contents Reveal
Step 3: Client → Server    Client Reveal
Step 4: Server → Client    Server Reveal + Outcome
```

**Step 0 — Server Commitment:**
The server initiates a session and commits to:
- A server secret (as a SHA-256 hash)
- The session contents (as a SHA-256 hash)
- A server nonce (as a SHA-256 hash) — live entropy, disclosed only at Step 2
- A timelock-encrypted copy of the server secret **only** (encrypted to a future drand round)
- The target drand round number

All fields are signed with the server's Ed25519 key. The contents and the nonce are deliberately **not** placed under timelock: they are withheld until the live Step 2 reveal. This is what defeats the stall-then-grind attack (§6.1) — a client that delays Step 1 to decrypt the escrow after expiry learns only the server secret, which is useless for predicting the outcome without the contents and nonce. The trade-off is that the proof document is no longer self-resolving *before* the live reveal; see §3.2.

**Step 1 — Client Commitment:**
The client, without knowledge of the contents, commits to:
- A client secret (as a SHA-256 hash)
- A timelock-encrypted copy of the client secret (encrypted to the same drand round)

All fields are signed with the client's Ed25519 key. At this point, both parties are irrevocably committed.

**Step 2 — Contents Reveal (the live step):**
The server reveals the actual session contents **and the server nonce**. The client verifies that `SHA256(contents || session_id) == contents_commitment` and `SHA256(server_nonce) == server_nonce_commitment` from Step 0. If either fails, the client MUST abort and retain the proof document for dispute evidence. This is the protocol's only genuinely-live step: it is the point at which outcome-determining information first exists, and it can only be reached *after* the client has irrevocably committed (Step 1), so neither party can grind.

**Step 3 — Client Reveal:**
The client reveals their secret in plaintext. The server verifies that `SHA256(client_secret) == client_commitment` from Step 1.

**Step 4 — Server Reveal + Outcome:**
The server reveals their secret in plaintext. Both parties can now independently compute the outcome:
```
combined_randomness = SHA256(client_secret || server_secret || server_nonce)
```
The server includes the computed outcome in the message, signed. The client verifies the computation independently.

### 3.2 Unhappy Paths

**Client ghosts after Step 1 (does not reveal at Step 3):**
The server waits for the timelock to expire, decrypts the client's timelock-encrypted secret, verifies it against the client's commitment, and computes the outcome. The server's own proof document contains everything needed; no additional storage is required for abandoned sessions.

**Server ghosts *before* the live reveal (no Step 2):**
The session cannot be resolved and voids cleanly. This is harmless: the server disclosed nothing outcome-determining (the contents and nonce were never revealed) and never learned the client secret, so it gained no advantage by aborting. There is no favourable outcome being withheld, because no outcome was ever determined.

**Server ghosts *after* the live reveal (Step 2 done, no Step 4):**
The client waits for the timelock to expire, decrypts the server secret from its escrow, verifies it against the Step 0 commitment, and resolves the outcome using the secret together with the contents and nonce already disclosed at Step 2. The server gains no advantage from ghosting here — by Step 2 it had already revealed everything except its secret, which the timelock surrenders. No server cooperation is needed after expiry.

**Contents verification fails at Step 2:**
The client aborts the session. The proof document (Steps 0–2) constitutes cryptographic evidence that the server committed to one set of contents but revealed another. This is a binary, unambiguous proof of server misbehaviour.

**Reveal verification fails at Step 3 or Step 4:**
If either party's revealed secret does not match their commitment hash, the session is invalid. The timelock-encrypted values serve as the ground truth — when the timelock expires, the encrypted values are decrypted and compared against the commitments.

---

## 4. Trust Architecture

The TRAP protocol is bilateral — both parties perform cryptographic operations that the other party cannot control or observe prematurely. This property is only meaningful if each party's implementation is genuinely independent.

### 4.1 Independent Client Implementation

The client-side protocol participation — generating secrets, creating commitments, verifying server signatures, resolving timelocks — **MUST** be handled by software that is:

- **Independent of the server.** The server operator MUST NOT provide the client-side TRAP implementation. A server-provided client could leak secrets, skip verification, or otherwise undermine the protocol while presenting a trustworthy interface to the user.
- **Open-source and auditable.** The client implementation's source code MUST be publicly available so that its correctness can be independently verified.
- **User-chosen.** The client selects which TRAP implementation to use. Multiple independent implementations are encouraged.

Without this separation, the protocol degenerates into a unilateral system where the server controls both sides of the exchange. The cryptographic guarantees become theatre.

### 4.2 Server Implementation

Server-side TRAP implementations have no equivalent independence requirement — the server is already a known, identified party whose behaviour the protocol is designed to make accountable. A server's TRAP implementation may be open-source or proprietary; the protocol's verification properties hold regardless, since all server commitments are independently verifiable from the proof document.

### 4.3 Verification Tools

Proof verification — confirming that signatures are valid, commitments match reveals, and outcomes were correctly computed — is a stateless, deterministic operation on a self-contained document. Verification tools SHOULD be independent of both the server and the client implementation, providing a third point of trust.

A verifier MUST authenticate the document against the **known, publicly-discoverable server public key** (§2.1) by pinning the Step 0 signer to it; this transitively authenticates the whole signature chain. Checking only internal consistency — that the signatures and commitments agree among themselves, without pinning the server key — does **not** establish origin: anyone could mint a self-consistent document with their own key. (In this implementation, `verify_proof` takes an `expected_server_key`; supplying it performs the authentication, and passing `None` is the consistency-only mode.)

---

## 5. Message Format & Signature Chaining

### 5.1 Message Structure

All protocol messages are JSON documents. Each step builds on the previous state by appending new fields to the document. The complete document at any step contains the full history of the session.

### 5.2 Signature Method

Signatures follow an explicit field-listing approach (inspired by DNAEDOT): each signature specifies exactly which fields it covers, and includes a hash of all previous signatures, creating a tamper-evident chain.

```json
{
  "version": "0.2.0",
  "session_id": "<unique session identifier>",
  "server_commitment": "<SHA256 hash of server secret>",
  "contents_commitment": "<SHA256 hash of contents || session_id>",
  "server_nonce_commitment": "<SHA256 hash of server nonce>",
  "server_timelock_encrypted": "<timelock ciphertext of the server secret>",
  "drand_round": 1234567,
  "metadata": { },
  "signatures": {
    "server_commitment": {
      "signature": "<Ed25519 signature>",
      "signed_fields": [
        "version", "session_id", "server_commitment",
        "contents_commitment", "server_nonce_commitment",
        "server_timelock_encrypted", "drand_round"
      ],
      "algorithm": "Ed25519",
      "signer": "<server public key>"
    }
  }
}
```

Each subsequent step appends fields and a new signature entry. The new signature covers all previous fields **and** the previous signatures, chaining them immutably.

### 5.3 Signature Chaining Example

At Step 1, the client's signature covers:
```json
"signed_fields": [
  "version", "session_id", "server_commitment",
  "contents_commitment", "server_timelock_encrypted",
  "drand_round", "signatures.server_commitment",
  "client_commitment", "client_timelock_encrypted"
]
```

By including `signatures.server_commitment` in the signed fields, the client attests to having seen and accepted the server's commitment before making their own.

### 5.4 Contents Commitment Salt

The contents commitment includes the session ID as a salt to prevent reuse of identical content hashes across sessions:
```
contents_commitment = SHA256(contents || session_id)
```

### 5.5 Proof Document

The **proof document** is the complete JSON document at any step. It is self-contained and independently verifiable — any party with the document can verify every signature in the chain, confirm commitment-reveal consistency, and compute the outcome.

### 5.6 Protocol Versioning

The `version` field is included in all messages and is covered by all signatures. This enables future protocol evolution while maintaining backward verification of existing proofs.

Any change to the on-wire schema (adding or removing required fields) or to the randomness derivation formula constitutes a **breaking protocol change**. Implementations that introduce such changes MUST increment the `PROTOCOL_VERSION` constant (in `trap-core/src/lib.rs`) and update the `version` field emitted in all messages accordingly. Old and new peers sharing the same version string will interpret messages differently and MUST NOT be allowed to interoperate.

---

## 6. Randomness Derivation

### 6.1 Combining Secrets

```
combined_randomness = SHA256(client_secret || server_secret || server_nonce)
```

All three inputs are 32 bytes (256 bits) of cryptographically random data. The concatenation order is fixed (client, server, nonce) to ensure deterministic results.

The **server nonce** is the critical defence against the stall-then-grind attack. Consider a malicious client that delays its Step 1 commitment until the server's timelock round elapses, decrypts the escrow, and then grinds candidate `client_secret` values toward a favourable outcome. Two ingredients are required to grind: the server secret *and* the ability to map randomness to an outcome. The server secret leaks on expiry, and for regulated applications the distribution is often **public** — so secrecy of the contents alone is not enough. By folding a committed-but-not-escrowed nonce into the randomness, the outcome is unpredictable until Step 2, which the client can only reach *after* irrevocably committing. The nonce is never placed under timelock; a stalling client therefore gains nothing, and the grinding incentive is removed structurally rather than by policing commit timing.

### 6.2 Mapping to Outcomes

For a single outcome selection from `n` possible outcomes:
```
outcome_index = uint256(combined_randomness) % n
```

The modulo bias is negligible (on the order of 10^-73 even for 10,000 outcomes) and is accepted for simplicity.

### 6.3 Multiple Derived Values

When an application requires multiple random values from a single session (e.g., selecting a category then an item within that category), each value is derived independently from the combined randomness using a domain separator:
```
value_for_operation = SHA256(combined_randomness || operation_id)
```

Where `operation_id` is a deterministic, application-defined string. This ensures each derived value is independent while remaining deterministically reproducible from the proof document.

---

## 7. Timelock Parameters

### 7.1 Configuration

| Parameter | Value |
|-----------|-------|
| Minimum duration | 30 seconds (~10 drand rounds) |
| Maximum duration | 2 months (~1,728,000 rounds) |
| Default duration | 15 minutes (~300 rounds) |
| Symmetry | Both parties use the same drand round |

The server specifies the target drand round in Step 0. The target round is calculated locally from cached chain info:
```
current_round = floor((now - genesis_time) / period) + 1
target_round = current_round + (desired_duration_seconds / period)
```
Before committing at Step 1, the client **MUST** validate the server-chosen `target_round` against its own clock and policy, rejecting a round that is already elapsed, too soon (below the minimum lead), or too far (above the maximum). This is a security requirement, not a comfort preference: the timelock only protects the client's secret while the target round's beacon does not yet exist, so a server that names an elapsed or imminent round could decrypt the client's Step 1 secret immediately. Validating only at the moment of receipt is insufficient — a malicious client's attack is to *stall* — so the bound must be enforced relative to the client's current time at commit. (In this implementation, `ClientSession::accept` takes an optional `RoundCheck`; `beacon::validate_target_round` performs the check.)

Timelock durations are expressed as drand round numbers, not wall-clock time. This avoids clock synchronisation issues between parties.

### 7.2 Timelock Expiry Resolution

When a session stalls and the timelock expires:

1. The waiting party fetches the beacon value for the target drand round from the drand network.
2. Using the beacon value, the waiting party decrypts the other party's timelock-encrypted secret (the server's escrow yields its secret; the client's yields the client secret). The contents and the server nonce are taken from the live Step 2 reveal already present in the proof document.
3. The waiting party verifies the decrypted secret against the commitment hash from the protocol exchange.
4. If verification passes, the outcome is computed normally from both secrets, the nonce, and the contents.
5. If verification fails (the encrypted value was junk), this constitutes cryptographic proof of misbehaviour by the committing party.

A proof document is resolvable in this way only once the live Step 2 reveal has occurred (it then carries the contents and nonce in plaintext). A server that ghosts before Step 2 leaves a void, unresolvable session by design — see §3.2 and Appendix B.

---

## 8. Application Layer

The TRAP protocol produces an agreed-upon random value (or set of derived values). How that value maps to meaningful outcomes is an application-layer concern. This section describes a reference approach for structured outcome selection, but applications are free to implement their own mapping.

### 8.1 Contents Format (Reference)

Applications that use TRAP for item selection (e.g., loot boxes, raffles, resource allocation) can structure their contents using operations with optional dependencies:

```json
{
  "contents": {
    "operations": [
      {
        "id": "tier",
        "type": "distribution",
        "outcomes": {
          "common": 7000,
          "rare": 2500,
          "epic": 500
        }
      },
      {
        "id": "item",
        "type": "distribution",
        "depends_on": "tier",
        "outcomes": {
          "common": { "item_a": 50, "item_b": 30, "item_c": 20 },
          "rare": { "item_d": 40, "item_e": 40, "item_f": 20 },
          "epic": { "item_g": 33, "item_h": 33, "item_i": 34 }
        }
      },
      {
        "id": "quality",
        "type": "range",
        "depends_on": "tier",
        "ranges": {
          "common": { "min": 1, "max": 50 },
          "rare": { "min": 40, "max": 80 },
          "epic": { "min": 75, "max": 100 }
        }
      }
    ]
  }
}
```

**Supported operation types:**
- `distribution` — Weighted random selection from a set of outcomes. Weights are integers; the outcome is selected by `uint256(derived_value) % total_weight` mapped against cumulative weights.
- `range` — Random integer within a range (inclusive). Computed as `min + (uint256(derived_value) % (max - min + 1))`.
- `float` — Random decimal within a range.

**Dependencies** allow operations to reference the result of a previous operation, enabling cascaded selections (e.g., select a tier, then select an item within that tier). Maximum dependency depth is 6 levels.

Each operation derives its random value using:
```
operation_random = SHA256(combined_randomness || operation_id)
```

### 8.2 Verification

The contents are committed (hashed) at Step 0 and revealed at Step 2. Any verifier with the proof document can:

1. Verify the contents hash matches the Step 0 commitment.
2. Recompute each operation's derived random value from the combined randomness.
3. Confirm the outcome matches the claimed result.

This makes outcomes fully and independently verifiable from the proof document alone.

---

## 9. Limitations & Future Work

### 9.1 Asymmetric Scenarios Only

TRAP requires a natural power asymmetry between participants. In symmetric peer-to-peer scenarios (two equal parties with no resource at stake), either party can ghost after commitment if they calculate an unfavourable outcome, with no natural penalty for doing so.

### 9.2 The General Solution

The general two-party randomness agreement problem (without asymmetry) requires proving that a committed value is *valid* without revealing it. This would prevent ghosting from being useful — if you've proven your commitment is legitimate, walking away doesn't let you change it.

This requires **zero-knowledge proofs** compatible with **timelock encryption curves**. Specifically, ZK-SNARKs on BLS12-377 curves (which are SNARK-friendly) combined with timelock encryption would provide a complete solution. However:

- drand's Quicknet uses BLS12-381 (not SNARK-friendly).
- No production timelock beacon exists on BLS12-377.
- The ZK-SNARK tooling for this specific combination is immature.

TRAP demonstrates what is achievable *today* with existing infrastructure, and points toward what would be possible with better cryptographic tooling.

### 9.3 Comparison to Blockchain-Based Solutions

Existing provably fair systems typically rely on blockchain infrastructure — smart contracts, on-chain randomness oracles, or verifiable random functions (VRFs) tied to consensus mechanisms. These approaches inherit the throughput and cost constraints of their underlying chains: block confirmation times (seconds to minutes), transaction fees (variable, potentially significant under congestion), and global consensus overhead for every individual outcome.

TRAP requires none of this. After a one-time fetch of drand chain info at startup, the happy path involves zero external network calls. Session creation, commitment, and reveal are direct message exchanges between two parties using standard cryptographic operations that execute in microseconds. Timelock encryption is performed locally using cached drand parameters. There is no on-chain state, no gas cost, and no dependency on network congestion. Throughput is bounded only by the communication channel between the parties and their local compute — in practice, thousands of sessions per second on commodity hardware.

The drand network is contacted only on the unhappy path, when a beacon value is needed to decrypt an expired timelock. This means TRAP's normal operation has zero external dependencies beyond the two participants.

### 9.4 Not a Production Framework

TRAP is a protocol demonstration and reference implementation. It does not include:

- Production deployment infrastructure
- Rate limiting or DoS prevention
- Database schemas for session management
- User-facing application interfaces
- Service discovery or orchestration

These are implementation concerns for anyone building on the protocol, not properties of the protocol itself.

---

## Appendix A: Replay Protection

All signatures include the `session_id` field, binding every message to a specific session. Session IDs MUST be unique and SHOULD be generated by the server as cryptographically random values.

Contents commitments are salted with the session ID (`SHA256(contents || session_id)`), preventing reuse of identical content hashes across sessions even when the same contents are offered.

## Appendix B: Storage & Self-Resolving Proofs

A proof document is self-resolving **once the live Step 2 reveal has occurred**: it then contains the contents and nonce in plaintext, and the server's secret is recoverable from its timelock escrow at expiry. Any party holding such a document can compute the outcome without cooperation from either participant.

Before Step 2, the document is deliberately **not** self-resolving — the contents and nonce exist only as commitments, and the server's escrow holds the secret alone. A server that ghosts that early produces an unresolvable, void session (§3.2). This is the price of stall-then-grind resistance (§6.1), and it is a fair one: the unresolvable window is exactly the window in which no outcome-determining information has been disclosed, so nothing of value is lost.

This eliminates server-side storage for abandoned sessions. If a client ghosts after the live reveal and later returns with a proof document, the server can recompute the outcome from the proof. If the client never returns, there is nothing to store.

For the client's timelock payload (which contains only the 32-byte client secret), server-side resolution of a client ghost requires only the beacon value — everything else is in the proof document the server already holds from the protocol exchange.

## Appendix C: Attack Vectors & Mitigations

| Attack | Mitigation |
|--------|------------|
| Server delays response after seeing client commitment | Server commits first (Step 0); cannot adapt after seeing client's Step 1 |
| Client selectively participates based on favourable contents | Client commits (Step 1) before contents are revealed (Step 2) |
| Server commits junk under timelock | Timelock expiry reveals the junk secret, mismatching the Step 0 commitment — cryptographic proof of misbehaviour |
| Client ghosts after seeing unfavourable outcome potential | Timelock expiry lets server decrypt client secret and resolve unilaterally |
| **Client stalls Step 1 to decrypt the escrow and grind a favourable outcome** | Server escrows only its secret; the contents and nonce are revealed only at the live Step 2, reachable only *after* the client has committed. With the nonce folded into the randomness (§6.1), an early-decrypted secret is insufficient to predict the outcome, even for public distributions |
| Replay of old session messages | Session ID included in all signatures; contents commitment salted with session ID |
| Server publishes different contents to different clients | Allowed — TRAP ensures fairness of the randomness for disclosed contents, not uniformity of contents across clients |
