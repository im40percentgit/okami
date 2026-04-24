/// Boundary-behavior test for DelegationToken size cap (MAX_TOKEN_BYTES = 8 KiB).
///
/// Verifies:
/// 1. A valid token round-trips fine (it's well under 8 KiB).
/// 2. A valid token whose serialization exceeds 8 KiB is rejected by from_bytes.
///
/// Run: cargo run --example boundary_check
fn main() {
    use okami::delegation::{Capability, DelegationToken, MAX_TOKEN_BYTES};
    use okami::identity::{AgentIdentity, SpiffeId};
    use std::time::Duration;

    // -- Setup: create a signing identity.
    let subject_id = SpiffeId::new("example.com", "/subject").unwrap();
    let issuer = AgentIdentity::new("example.com", "/issuer").unwrap();

    // -- Part 1: A normal token should round-trip.
    let scopes = vec![
        Capability::new("read:db").unwrap(),
        Capability::new("invoke:llm").unwrap(),
    ];
    let issuer_scopes = scopes.clone();
    let token = DelegationToken::issue(
        &issuer,
        subject_id.clone(),
        scopes,
        &issuer_scopes,
        Duration::from_secs(3600),
        None,
    )
    .expect("issue failed");

    let bytes = token.to_bytes().expect("to_bytes failed");
    println!(
        "Normal token serialized size: {} bytes (limit: {})",
        bytes.len(),
        MAX_TOKEN_BYTES
    );
    assert!(
        bytes.len() < MAX_TOKEN_BYTES as usize,
        "Normal token unexpectedly exceeds limit: {} >= {}",
        bytes.len(),
        MAX_TOKEN_BYTES
    );

    let rt = DelegationToken::from_bytes(&bytes).expect("round-trip failed for normal token");
    println!("Round-trip OK: issuer = {}", rt.issuer);

    // -- Part 2: Construct a valid token with many scopes so serialized size > 8 KiB.
    // 500 scopes of 20 chars each = ~10 KiB of scope strings alone.
    let big_scopes: Vec<Capability> = (0..500)
        .map(|i| Capability::new(&format!("scope:aaaaaaaaaaa{i:04}")).unwrap())
        .collect();
    // Cap to issuer's perspective — all those are the issuer's scopes too.
    let big_issuer_scopes = big_scopes.clone();

    let big_token = DelegationToken::issue(
        &issuer,
        subject_id,
        big_scopes.clone(),
        &big_issuer_scopes,
        Duration::from_secs(3600),
        None,
    )
    .expect("issue big token failed");

    let big_bytes = big_token.to_bytes().expect("to_bytes failed for big token");
    println!(
        "Oversized token serialized size: {} bytes (limit: {})",
        big_bytes.len(),
        MAX_TOKEN_BYTES
    );

    if big_bytes.len() <= MAX_TOKEN_BYTES as usize {
        println!(
            "WARNING: oversized token ({} bytes) is still under the limit — \
             try increasing scope count",
            big_bytes.len()
        );
    } else {
        let result = DelegationToken::from_bytes(&big_bytes);
        println!("from_bytes result for oversized valid token: {result:?}");
        assert!(
            result.is_err(),
            "Expected Err for oversized token, got Ok — limit not enforced on valid data!"
        );
        println!("PASS: oversized valid token rejected correctly.");
    }
}
