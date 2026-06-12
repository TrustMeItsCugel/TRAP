# TRAP — Trustless Randomness Agreement Protocol

A reference implementation of bilateral commit-reveal with timelock
enforcement: two mutually distrusting parties agree on a random value, and
neither can predict, influence, or retroactively manipulate the outcome —
or escape it by going silent.

```
Step 0  Server → Client   commit(secret_S), commit(contents), tlock{secret_S, contents}
Step 1  Client → Server   commit(secret_C), tlock{secret_C}          (blind)
Step 2  Server → Client   reveal contents
Step 3  Client → Server   reveal secret_C
Step 4  Server → Client   reveal secret_S, outcome
```

The outcome is `SHA256(secret_C || secret_S)` mapped through the committed
contents. If either party stops responding after the commitments are
exchanged, the other waits for the [drand](https://drand.love) beacon round
the timelocks targeted and decrypts the absent party's payload — no
cooperation, arbitration, or blockchain required.

## Properties

- **No information advantage.** Both parties commit before either reveals.
  The client commits *blind*, before seeing what it might win.
- **Ghosting doesn't work.** Commitments are timelock-encrypted to a drand
  round chosen at session start. Going silent only delays the outcome.
- **Cheating is binary and provable.** A commitment either matches its
  reveal or it doesn't. A timelock payload that decrypts to junk is
  cryptographic proof of fraud, signed by the party that produced it.
- **Self-resolving proofs.** The server's timelock bundle contains both
  its secret *and* the contents, so a proof document resolves unilaterally
  after expiry even if the server vanished before revealing anything. The
  server needs no storage for abandoned sessions.
- **High throughput, fully off-chain.** Chain info is fetched once at
  startup; round numbers are computed locally. The happy path makes zero
  network calls. The beacon is contacted only to resolve an abandoned
  session.

## What this is (and isn't)

This is a protocol demonstration: a clean, tested instantiation of timed
commitments using modern primitives (SHA-256, Ed25519, drand Quicknet
timelock encryption via [ideal-lab5/timelock](https://github.com/ideal-lab5/timelock)).
The idea that commit-reveal's ghosting problem can be closed with
time-released cryptography goes back to Boneh and Naor's *Timed
Commitments* (CRYPTO 2000); TRAP is a practical modern realisation on top
of a production randomness beacon rather than sequential-squaring puzzles.

The protocol is honest about its scope: it requires an **asymmetric**
relationship — a server that has something the client wants, giving the
server a reason to follow through and the client a reason to engage. The
symmetric peer-to-peer case needs zero-knowledge proofs over
timelock-friendly curves and is out of scope here (see the spec's
limitations section).

## Layout

- `trap-core/` — the library: types, crypto, beacon interaction, the two
  session state machines, and standalone proof verification.
- `trap-demo/` — an in-process demo running three scenarios (cooperative,
  client ghosts, server ghosts) and writing verifiable proof documents.
- `docs/` — protocol specification, architecture, and test scenarios.

## Running

```sh
# all tests, fully offline (uses a recorded Quicknet beacon)
cargo test

# the demo, offline
cargo run -p trap-demo

# the demo against the real drand network (30-second timelock)
cargo run -p trap-demo --features live -- --live
```

Offline operation works because drand beacon values are public and
immutable: round 1000's signature is embedded as a test vector and the
timelock ciphertexts produced today decrypt against it just as they would
against a freshly fetched value.

## Verifying a proof

```rust
use trap_core::protocol::verify::verify_proof;

let proof: ProofDocument = serde_json::from_str(&json)?;
// Completed sessions verify standalone:
let result = verify_proof(&proof, None)?;
// Abandoned sessions verify with the (public) beacon for the target round:
let result = verify_proof(&proof, Some(&beacon))?;
assert!(result.signatures_valid && result.commitments_match && result.outcome_verified);
```

## Status

Reference implementation, v0.1.0. MIT licensed. No long-term support
intended — the point is to show the construction works.
