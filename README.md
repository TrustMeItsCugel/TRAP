# TRAP — Trustless Randomness Agreement Protocol

"Drop rate: *Legendary* 0.5%." Says who?

Every loot box, gacha pull and loot roll runs on randomness you have to
take on faith. The standing excuse is that provable fairness is
impractical without a blockchain. TRAP is a working demonstration that it
isn't: two mutually distrusting parties agree on a random outcome,
entirely off-chain, and neither can predict it, influence it,
retroactively manipulate it — or dodge it by going silent.

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
cooperation, no arbitration, no chain. On the happy path the only traffic
is the five messages above — no beacon, no oracle, no third party — so
throughput is bounded by how fast a CPU can hash and sign, not by block
time or consensus.

## The receipt

The protocol's worst case is the server ghosting mid-session, so that's
the proof worth showing. At Step 0 the server committed to this — real
odds, hashed and signed, before the client put anything on the table:

```jsonc
// contents — committed at Step 0 (weights per 10,000)
{
  "operations": [
    { "id": "tier", "type": "distribution",
      "outcomes": { "common": 7000, "rare": 2500, "epic": 500 } },     // 70% / 25% / 5%
    { "id": "item", "depends_on": "tier", "type": "dependent_distribution",
      "outcomes": {
        "common": { "rusty_sword": 60, "wooden_shield": 40 },
        "rare":   { "silver_blade": 70, "enchanted_bow": 30 },
        "epic":   { "dragonfang": 100 } } },
    { "id": "quality", "type": "range", "min": 1, "max": 100 }
  ]
}
```

Then the server vanished — never revealed the table, never revealed its
secret, never answered again. This is everything the client is left
holding (`ghost-server.proof.json`, hex elided):

```jsonc
{
  "server_commitment": {                          // Step 0 — signed by the server
    "version": "0.1.0",
    "session_id": "demo-ghost-server",
    "server_commitment":   "c41b…9a07",           // SHA256(server_secret)
    "contents_commitment": "5f2e…d8b3",           // SHA256(canonical_json(contents) || session_id)
    "server_timelock_encrypted": "a91c…44e0",     // tlock{server_secret, contents} → round 1000
    "drand_round": 1000,
    "signature": { "algorithm": "Ed25519", "signer": "37dd…", "signed_fields": ["…"], "signature": "…" }
  },
  "client_commitment": {                          // Step 1 — signed by the client, blind
    "client_commitment": "08aa…61fc",             // SHA256(client_secret)
    "client_timelock_encrypted": "f33b…0c9d",     // tlock{client_secret} → round 1000
    "signature": { "…": "chains over the server's signature" }
  },
  "resolution": "timelock_server_payload"
}
```

No contents, no secrets, no outcome — and that's the point. A verifier
takes the public drand beacon for round 1000, decrypts both timelock
payloads, checks them against the signed commitments, and recomputes the
result: `{"tier": "epic", "item": "dragonfang", "quality": 73}`. The 5%
drop, delivered by a dead server. The proof can't misstate the odds or
the outcome because it contains neither; both are consequences of
commitments signed by the party they would accuse. And a payload that
decrypts to junk is itself the verdict — fraud, signed by its author.

`cargo run -p trap-demo` reproduces this proof, plus the cooperative and
client-ghosting variants, fully offline.

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
startup; round numbers are computed locally. The happy path touches no
third party. The beacon is contacted only to resolve an abandoned
session.

## What this is (and isn't)

A protocol demonstration: a clean, tested instantiation of timed
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

# the demo, offline — writes {cooperative,ghost-client,ghost-server}.proof.json
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
