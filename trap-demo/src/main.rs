//! trap-demo: in-process demonstration of the TRAP protocol.
//!
//! Runs three scenarios — cooperative completion, client ghosting, and
//! server ghosting — and writes each proof document to disk. By default,
//! everything is offline using a recorded Quicknet beacon (round 1000).
//! With `--live` (requires the `live` feature and network access), the
//! timelock targets a real future round and resolution waits for it.

use trap_core::beacon::{BeaconClient, BeaconValue, ChainInfo, MockBeaconClient};
use trap_core::crypto::Identity;
use trap_core::protocol::client::ClientSession;
use trap_core::protocol::server::ServerSession;
use trap_core::protocol::verify::verify_proof;
use trap_core::types::contents::{Contents, Operation, OperationType, RangeParams};
use trap_core::types::messages::{ProofDocument, SessionConfig};
use trap_core::PROTOCOL_VERSION;

// Recorded Quicknet round-1000 vectors (public, immutable) for offline use.
const ROUND_1000_SIG_HEX: &str = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";
const OFFLINE_ROUND: u64 = 1000;

fn sample_contents() -> Contents {
    Contents {
        operations: vec![
            Operation {
                id: "tier".into(),
                depends_on: None,
                op: OperationType::Distribution {
                    outcomes: [
                        ("common".to_string(), 7000u64),
                        ("rare".to_string(), 2500),
                        ("epic".to_string(), 500),
                    ]
                    .into_iter()
                    .collect(),
                },
            },
            Operation {
                id: "item".into(),
                depends_on: Some("tier".into()),
                op: OperationType::DependentDistribution {
                    outcomes: [
                        (
                            "common".to_string(),
                            [
                                ("rusty_sword".to_string(), 60u64),
                                ("wooden_shield".to_string(), 40),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                        (
                            "rare".to_string(),
                            [
                                ("silver_blade".to_string(), 70u64),
                                ("enchanted_bow".to_string(), 30),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                        (
                            "epic".to_string(),
                            [("dragonfang".to_string(), 100u64)].into_iter().collect(),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                },
            },
            Operation {
                id: "quality".into(),
                depends_on: None,
                op: OperationType::Range {
                    range: RangeParams { min: 1, max: 100 },
                },
            },
        ],
    }
}

struct Env {
    chain: ChainInfo,
    round: u64,
    beacon_fetch: Box<dyn Fn() -> BeaconValue>,
}

fn offline_env() -> Env {
    let mock = MockBeaconClient::new(ChainInfo::quicknet())
        .with_beacon(OFFLINE_ROUND, hex::decode(ROUND_1000_SIG_HEX).unwrap());
    let chain = mock.chain_info().unwrap();
    Env {
        chain,
        round: OFFLINE_ROUND,
        beacon_fetch: Box::new(move || mock.beacon(OFFLINE_ROUND).unwrap()),
    }
}

#[cfg(feature = "live")]
fn live_env() -> Env {
    use trap_core::beacon::{round_to_time, target_round, DrandHttpClient};
    let client = DrandHttpClient::quicknet();
    let chain = client.chain_info().expect("fetch chain info");
    // Short timelock so the demo resolves quickly: 30 seconds (protocol
    // minimum of 10 rounds applies).
    let round = target_round(&chain, 30);
    println!("(live) chain {} | targeting round {round}", chain.chain_hash);
    let chain_clone = chain.clone();
    Env {
        chain,
        round,
        beacon_fetch: Box::new(move || {
            let when = round_to_time(&chain_clone, round);
            loop {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now < when {
                    let wait = when - now;
                    println!("(live) waiting {wait}s for round {round}...");
                    std::thread::sleep(std::time::Duration::from_secs(wait.clamp(1, 5)));
                    continue;
                }
                match DrandHttpClient::quicknet().beacon(round) {
                    Ok(b) => return b,
                    Err(e) => {
                        println!("(live) beacon not ready ({e}); retrying...");
                        std::thread::sleep(std::time::Duration::from_secs(2));
                    }
                }
            }
        }),
    }
}

fn config(session_id: &str, round: u64) -> SessionConfig {
    SessionConfig {
        session_id: session_id.into(),
        drand_round: round,
        version: PROTOCOL_VERSION.into(),
        metadata: None,
    }
}

fn write_proof(name: &str, proof: &ProofDocument) {
    let path = format!("{name}.proof.json");
    std::fs::write(&path, serde_json::to_string_pretty(proof).unwrap()).expect("write proof");
    println!("  proof written to {path}");
}

fn show_verify(proof: &ProofDocument, beacon: Option<&BeaconValue>, server_key: &[u8; 32]) {
    match verify_proof(proof, beacon, Some(server_key)) {
        Ok(r) => println!(
            "  verify: progress={:?} signatures={} commitments={} authenticated={} outcome_verified={} outcome={}",
            r.progress,
            r.signatures_valid,
            r.commitments_match,
            r.server_authenticated,
            r.outcome_verified,
            r.outcome
                .map(|o| serde_json::to_string(&o).unwrap())
                .unwrap_or_else(|| "n/a".into())
        ),
        Err(e) => println!("  verify: FAILED — {e}"),
    }
}

fn main() {
    let live = std::env::args().any(|a| a == "--live");
    let env = if live {
        #[cfg(feature = "live")]
        {
            live_env()
        }
        #[cfg(not(feature = "live"))]
        {
            eprintln!(
                "--live requires building with: cargo run -p trap-demo --features live -- --live"
            );
            std::process::exit(1);
        }
    } else {
        offline_env()
    };

    println!("TRAP demo — protocol v{PROTOCOL_VERSION}");
    println!(
        "mode: {} | drand round: {}\n",
        if live {
            "LIVE (api.drand.sh)"
        } else {
            "offline (recorded beacon)"
        },
        env.round
    );

    let server_id = Identity::generate();
    let client_id = Identity::generate();
    let pk = &env.chain.public_key;

    // ---------- Scenario 1: cooperative completion ----------
    println!("[1] Cooperative session (all five steps)");
    let (server, step0) = ServerSession::initiate(
        &server_id,
        sample_contents(),
        config("demo-coop", env.round),
        pk,
    )
    .unwrap();
    let (client, step1) = ClientSession::accept_unchecked(&client_id, step0, pk).unwrap();
    let (server, step2) = server.receive_client_commitment(&server_id, step1).unwrap();
    let (client, step3) = client.receive_contents(&client_id, step2).unwrap();
    let (_server, step4) = server.receive_client_reveal(&server_id, step3).unwrap();
    let (client, outcome) = client.receive_server_reveal(step4).unwrap();
    println!("  outcome: {}", serde_json::to_string(&outcome).unwrap());
    show_verify(client.proof(), None, &server_id.public_key());
    write_proof("cooperative", client.proof());

    // ---------- Scenario 2: client ghosts; server resolves ----------
    println!("\n[2] Client ghosts after committing; server resolves via timelock");
    let (server, step0) = ServerSession::initiate(
        &server_id,
        sample_contents(),
        config("demo-ghost-client", env.round),
        pk,
    )
    .unwrap();
    let (_client, step1) = ClientSession::accept_unchecked(&client_id, step0, pk).unwrap();
    let (server, _step2) = server.receive_client_commitment(&server_id, step1).unwrap();
    println!("  (client never sends Step 3 — waiting out the timelock)");
    let beacon = (env.beacon_fetch)();
    let (server, outcome) = server.resolve_with_beacon(&beacon).unwrap();
    println!("  outcome: {}", serde_json::to_string(&outcome).unwrap());
    show_verify(server.proof(), Some(&beacon), &server_id.public_key());
    write_proof("ghost-client", server.proof());

    // ---------- Scenario 3: server ghosts after the live reveal ----------
    println!("\n[3] Server reveals contents+nonce, then ghosts; client resolves via timelock");
    let (server, step0) = ServerSession::initiate(
        &server_id,
        sample_contents(),
        config("demo-ghost-server", env.round),
        pk,
    )
    .unwrap();
    let (client, step1) = ClientSession::accept_unchecked(&client_id, step0, pk).unwrap();
    // Live Step 2: the server discloses contents and nonce...
    let (_server, step2) = server.receive_client_commitment(&server_id, step1).unwrap();
    let (client, _step3) = client.receive_contents(&client_id, step2).unwrap();
    println!("  (server never sends Step 4 — client resolves the server's escrowed secret)");
    let beacon = (env.beacon_fetch)();
    let (client, outcome) = client.resolve_with_beacon(&beacon).unwrap();
    println!("  outcome: {}", serde_json::to_string(&outcome).unwrap());
    show_verify(client.proof(), Some(&beacon), &server_id.public_key());
    write_proof("ghost-server", client.proof());

    println!("\nDone. Three proof documents written; any third party can verify them.");
}
