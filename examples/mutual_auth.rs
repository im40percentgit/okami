//! Mutual authentication example: two agents verify each other and exchange a delegation token.
//!
//! Run with: cargo run --example mutual_auth
//!
//! This demonstrates the core okami workflow:
//!   1. Each agent generates a PQC identity (SPIFFE ID + keypair)
//!   2. Agents exchange credentials (public material only)
//!   3. Each verifies the peer's credential is well-formed and not expired
//!   4. The orchestrator issues a delegation token to the worker
//!   5. The worker verifies the token and inspects its scopes
//!   6. An audit event is generated for each significant action
//!
// @decision DEC-OKAMI-011 Example uses in-memory credential exchange — accepted.
// Rationale: a real deployment would use mTLS or a credential registry. For
// the SDK example, direct in-memory exchange keeps the focus on the okami API
// rather than transport concerns.

use okami::audit::AuditEvent;
use okami::delegation::{Capability, DelegationChain, DelegationToken};
use okami::identity::AgentIdentity;
use serde_json::json;
use std::time::Duration;

fn separator(label: &str) {
    println!("\n--- {label} ---");
}

fn main() {
    println!("=== Okami Mutual Authentication Example ===\n");

    // ── Step 1: Generate agent identities ─────────────────────────────────────

    separator("Step 1: Generate agent identities");

    // Both agents are in the same trust domain.
    let orchestrator = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| AgentIdentity::new("example.com", "orchestrator").unwrap())
        .unwrap()
        .join()
        .unwrap();

    let worker = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| AgentIdentity::new("example.com", "worker/1").unwrap())
        .unwrap()
        .join()
        .unwrap();

    println!("Orchestrator : {}", orchestrator.spiffe_id());
    println!("Worker       : {}", worker.spiffe_id());

    // ── Step 2: Exchange credentials (public material) ────────────────────────

    separator("Step 2: Exchange credentials");

    let orchestrator_cred = orchestrator.credential();
    let worker_cred = worker.credential();

    println!(
        "Orchestrator credential algo : v{}",
        orchestrator_cred.algo
    );
    println!(
        "Worker credential algo       : v{}",
        worker_cred.algo
    );
    println!(
        "Orchestrator verifying key   : {} bytes",
        orchestrator_cred.verifying_key_bytes.len()
    );

    // ── Step 3: Mutual credential verification ────────────────────────────────

    separator("Step 3: Mutual credential verification");

    // Worker verifies orchestrator's credential.
    match AgentIdentity::verify_peer(&orchestrator_cred) {
        Ok(()) => println!("Worker verified orchestrator credential: OK"),
        Err(e) => {
            eprintln!("Worker could not verify orchestrator: {e}");
            std::process::exit(1);
        }
    }

    // Orchestrator verifies worker's credential.
    match AgentIdentity::verify_peer(&worker_cred) {
        Ok(()) => println!("Orchestrator verified worker credential: OK"),
        Err(e) => {
            eprintln!("Orchestrator could not verify worker: {e}");
            std::process::exit(1);
        }
    }

    // ── Step 4: Sign and verify a message ────────────────────────────────────

    separator("Step 4: Sign and verify a message");

    let message = b"hello from orchestrator";
    let signature = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || orchestrator.sign(message).unwrap())
        .unwrap()
        .join()
        .unwrap();

    println!("Orchestrator signed message ({} bytes)", message.len());
    println!("Signature length: {} bytes", signature.len());

    // Worker verifies using orchestrator's embedded verifying key.
    let vk = lupine::sign::HybridVerifyingKey65::from_bytes(
        &orchestrator_cred.verifying_key_bytes,
    )
    .unwrap();
    let valid = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || lupine::easy::verify(&vk, message, &signature).unwrap())
        .unwrap()
        .join()
        .unwrap();
    println!("Worker verified orchestrator's signature: {valid}");
    assert!(valid, "signature must verify");

    // ── Step 5: Issue a delegation token ──────────────────────────────────────

    separator("Step 5: Issue delegation token (orchestrator -> worker)");

    let worker_spiffe_id = worker.spiffe_id().clone();
    let scopes = vec![
        Capability::new("read:db").unwrap(),
        Capability::new("invoke:llm").unwrap(),
    ];
    let issuer_scopes = scopes.clone();

    let orchestrator2 = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| AgentIdentity::new("example.com", "orchestrator").unwrap())
        .unwrap()
        .join()
        .unwrap();

    let token = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            DelegationToken::issue(
                &orchestrator2,
                worker_spiffe_id,
                scopes,
                &issuer_scopes,
                Duration::from_secs(3600),
                None,
            )
            .unwrap()
        })
        .unwrap()
        .join()
        .unwrap();

    println!("Token issued by : {}", token.issuer);
    println!("Token subject   : {}", token.subject);
    println!("Token depth     : {}", token.depth);
    println!(
        "Token scopes    : {}",
        token
            .scopes
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("Token expires   : {}", token.expires_at);

    // ── Step 6: Worker verifies the delegation token ──────────────────────────

    separator("Step 6: Worker verifies delegation token");

    let token_for_chain = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            token.verify(None).unwrap();
            token
        })
        .unwrap()
        .join()
        .unwrap();

    println!("Worker verified delegation token: OK");

    // Build a chain (single-hop in this example).
    let chain = DelegationChain::new(vec![token_for_chain]);
    println!(
        "Effective scopes at chain leaf: {}",
        chain
            .effective_scopes()
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    println!("\nDelegation chain tree:");
    print!("{}", chain.ascii_tree());

    // ── Step 7: Emit audit events ─────────────────────────────────────────────

    separator("Step 7: Emit audit events");

    let worker2 = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| AgentIdentity::new("example.com", "worker/1").unwrap())
        .unwrap()
        .join()
        .unwrap();

    let worker_id = worker2.spiffe_id().clone();
    let worker_vk = worker2.credential().verifying_key_bytes.clone();

    let ev1 = AuditEvent::new(
        worker_id.clone(),
        "delegation.received",
        json!({
            "issuer": "spiffe://example.com/orchestrator",
            "scopes": ["read:db", "invoke:llm"]
        }),
        None,
    );

    let (signed1, hash1) = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            let signed = ev1.sign(&worker2).unwrap();
            let hash = signed.hash_hex().unwrap();
            (signed, hash)
        })
        .unwrap()
        .join()
        .unwrap();

    println!(
        "Audit event 1: action={:?} chain_hash={:?}",
        signed1.event.action, signed1.event.chain_hash
    );
    println!("Event 1 hash (for chain): {}...", &hash1[..16]);

    let worker3 = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| AgentIdentity::new("example.com", "worker/1").unwrap())
        .unwrap()
        .join()
        .unwrap();

    let worker3_id = worker3.spiffe_id().clone();
    let worker3_vk = worker3.credential().verifying_key_bytes.clone();

    let ev2 = AuditEvent::new(
        worker3_id,
        "db.query.executed",
        json!({"table": "users", "rows_returned": 42}),
        Some(hash1),
    );

    let signed2 = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || ev2.sign(&worker3).unwrap())
        .unwrap()
        .join()
        .unwrap();

    println!(
        "Audit event 2: action={:?} chain_hash={}...",
        signed2.event.action,
        &signed2.event.chain_hash[..16]
    );

    // Verify audit chain.
    okami::audit::verify_audit_chain(
        &[signed1, signed2],
        &[worker_vk, worker3_vk],
    )
    .unwrap();
    println!("Audit chain verified: OK");

    println!("\n=== Example complete ===");
}
