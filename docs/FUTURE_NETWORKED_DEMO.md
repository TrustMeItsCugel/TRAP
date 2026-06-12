# TRAP: Future Work — Networked Client/Server Demo

**Status:** Archived design decisions. Not in scope for the current project.
**Context:** These notes were developed during the TRAP protocol design phase and cover infrastructure that would be needed for a networked demonstration or production deployment of TRAP. They are preserved here for a potential future `trap-demo-networked` project.

---

## 1. TRAP Manager Concept

The TRAP Manager is a local background service that handles the client side of the protocol independently from any specific game or application. It runs as a persistent process on the user's machine.

### 1.1 Why It Exists

The TRAP protocol requires the client-side implementation to be independent of the server (see Protocol Spec §4: Trust Architecture). The Manager is the mechanism for this — games delegate their TRAP participation to the Manager rather than implementing the client role themselves.

### 1.2 Key Properties

- **Invisible to the user.** The Manager runs in the background. Users don't interact with it unless something goes wrong.
- **Persistent.** It survives game restarts, tracks in-progress sessions, and handles timelock resolution automatically.
- **Independent.** It is not provided by any game server operator.
- **Open source.** Multiple independent implementations are encouraged.

### 1.3 Originally Planned Stack

- **Desktop app:** Tauri (Rust backend + web frontend)
- **Persistence:** SQLite for session and proof storage
- **Service discovery:** Well-known ports — 8435 (gRPC), 8436 (HTTP fallback)
- **Security:** Local-only binding (127.0.0.1), optional auth token

---

## 2. Communication Protocol

### 2.1 gRPC (Primary)

Selected for bidirectional communication, type safety, performance, and broad language support (C++, C#, JS, etc.).

**Proto definitions (draft):**

```proto
service TRAPManager {
  // Game → Manager (standard flow)
  rpc CreateSession(CreateSessionRequest) returns (Commitment);
  rpc SubmitServerResponse(ServerResponse) returns (Reveal);
  rpc GetProofHistory(Query) returns (stream ProofDocument);

  // Manager → Game (critical notifications via event stream)
  rpc SubscribeToEvents(Subscribe) returns (stream Event);
}

service TRAPGame {
  // Manager queries game for contextual info
  rpc GetGameInfo() returns (GameInfo);
  rpc GetSessionContext(SessionId) returns (SessionContext);
  rpc NotifyUserAction(UserAction) returns (Empty);
}

message Event {
  oneof event {
    SessionResumed resumed = 1;      // "You have an incomplete session"
    TimelockResolved resolved = 2;   // "Timelock expired, here's outcome"
    DisputeDetected dispute = 3;     // "Server cheated, here's proof"
  }
}
```

### 2.2 HTTP/JSON Fallback

For browser-based games and simpler integrations:

```
POST /generate-commitment
POST /generate-reveal
GET  /session-status/{id}
GET  /notifications
```

WebSocket for the event stream, or polling with exponential backoff.

### 2.3 Why Bidirectional Matters

Two critical use cases require the Manager to push to the game:

**Session resumption:** User's computer crashes mid-session. Game restarts, needs to know about in-progress sessions. Manager tells the game: "Session XYZ is in progress at state 3."

**Auto-dispute resolution:** Timelock expires while the game is running. Manager decrypts the other party's payload, resolves the outcome, and notifies the game: "Session XYZ resolved via timelock, here's the outcome."

---

## 3. Server-Side Infrastructure

### 3.1 Database Schema (Draft)

```sql
-- Core session tracking
CREATE TABLE trap_sessions (
    session_id VARCHAR PRIMARY KEY,
    user_pubkey VARCHAR NOT NULL,
    state INTEGER NOT NULL,         -- protocol step (0-4)
    drand_round BIGINT NOT NULL,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    expires_at TIMESTAMP,
    -- State data (JSON)
    user_commitment TEXT,
    server_commitment TEXT,
    user_timelock TEXT,
    server_timelock TEXT,
    contents TEXT,
    user_reveal TEXT,
    server_reveal TEXT,
    outcome TEXT,
    INDEX idx_expires (expires_at),
    INDEX idx_state (state),
    INDEX idx_user (user_pubkey)
);

-- Completed outcomes (minimal storage)
CREATE TABLE trap_outcomes (
    session_id VARCHAR PRIMARY KEY,
    user_pubkey VARCHAR NOT NULL,
    outcome TEXT NOT NULL,
    completed_at TIMESTAMP,
    INDEX idx_user_completed (user_pubkey, completed_at)
);
```

### 3.2 Rate Limiting

- Max 10 new sessions per minute per user
- Max 100 sessions per hour per user
- Max 1000 active sessions per user
- Tie to existing game authentication

### 3.3 Dual-Mode Operation

The server-side TRAP lib handles both TRAP-enabled and non-TRAP clients transparently:

**With TRAP Manager present:**
- Game's lib contacts TRAP Manager for real user commitments
- Full bilateral commit-reveal, trustless

**Without TRAP Manager:**
- Game sends empty/null commitment or special flag
- Server generates both commitments (trust-the-server fallback)
- One API, one code path, graceful degradation

---

## 4. Demo Architecture (Two-Process)

If building a networked demo, the architecture would be:

### 4.1 Components

- **`trap-demo-server`** — A minimal server binary that:
  - Listens on a TCP/gRPC port
  - Accepts session initiation requests
  - Runs the server side of the protocol
  - Can be configured to misbehave (ghost, send junk) for demonstration

- **`trap-demo-client`** — A minimal client binary that:
  - Connects to the server
  - Runs the client side of the protocol
  - Handles timelock resolution automatically
  - Writes proof documents to disk

### 4.2 Demo Scenarios

**D1 — Happy path:**
Start server, start client, watch the 5-step exchange happen over the network. Proof document written to disk.

**D2 — Client ghost:**
Start server, start client, client exits after Step 1. Server waits for timelock, resolves.

**D3 — Server ghost:**
Start server, start client, server exits after Step 1. Client waits for timelock, decrypts bundle, resolves.

**D4 — Server misbehaviour:**
Start server with `--cheat` flag (encrypts junk). Client detects mismatch on timelock resolution.

**D5 — Proof verification:**
A standalone `trap-verify` binary that reads a proof JSON from disk and verifies it.

### 4.3 Timelock Handling in Demo

Two modes:
- **Mock mode (default):** Uses pre-computed beacon values, runs instantly, deterministic.
- **Live mode (`--live` flag):** Uses real drand Quicknet with 30-second timelocks, actually waits, fetches real beacons.

### 4.4 Suggested Output Format

Each step printed to terminal with:
- Step number and direction (Server → Client, Client → Server)
- Commitment hashes (truncated for readability)
- Revealed values
- Verification results
- Final outcome and proof verification status

---

## 5. Browser Extension (Very Future)

For web-based games, the TRAP Manager could run as a browser extension rather than a desktop service. The extension would:
- Intercept TRAP protocol messages in web traffic
- Handle client-side commitments and timelock encryption
- Store proofs in extension local storage
- Provide a popup UI for viewing session status and proof history

This was discussed but explicitly deferred as beyond the scope of even the networked demo.

---

## 6. Trust & Reputation Notes

These design principles were established but not fully specified. They apply to any deployment scenario:

- Protocol provides evidence, not enforcement
- Presumption of server innocence — implementing TRAP is itself evidence of good faith
- Technical failures (downtime, network issues) are normal and expected
- Only cryptographically proven misbehaviour (junk timelock encryption) constitutes evidence of fault
- Proofs are portable and self-verifying — users can publish them anywhere
- What communities or regulators do with proofs is outside the protocol's scope
- The protocol should not prescribe social or business consequences
