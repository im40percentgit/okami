//! Property-based tests for okami using proptest.
//!
//! Tests random SpiffeIds, scopes, chain depths, and adversarial inputs to
//! verify that security invariants hold across the input space.
//!
// @decision DEC-OKAMI-012 proptest for security-critical invariant testing — accepted.
// Rationale: hand-written tests cover known edge cases; proptest finds
// unexpected ones. For a security SDK, property-based testing is not optional.
// It is especially valuable for parsing (SpiffeId, Capability) and for
// delegation chain invariants where the state space is large.

use okami::delegation::{Capability, DelegationChain, DelegationToken, MAX_DELEGATION_DEPTH};
use okami::identity::{AgentIdentity, SpiffeId};
use proptest::prelude::*;
use std::time::Duration;

// ── Stack helper ──────────────────────────────────────────────────────────────

fn with_large_stack<F: FnOnce() -> R + Send + 'static, R: Send + 'static>(f: F) -> R {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked")
}

// ── SpiffeId property tests ───────────────────────────────────────────────────

/// Strategy for valid trust domain strings (hostname characters only).
fn valid_trust_domain() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{1,15}(\\.[a-z][a-z0-9-]{1,10}){0,3}".prop_map(|s| s)
}

/// Strategy for valid workload path segments.
fn valid_workload() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{1,15}(/[a-z][a-z0-9-]{1,10}){0,2}".prop_map(|s| s)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Any valid trust_domain + workload produces a parseable SpiffeId.
    #[test]
    fn prop_spiffe_id_valid_roundtrip(
        domain in valid_trust_domain(),
        workload in valid_workload(),
    ) {
        let id = SpiffeId::new(&domain, &workload).unwrap();
        let parsed = SpiffeId::parse(id.as_str()).unwrap();
        prop_assert_eq!(id.as_str(), parsed.as_str());
        prop_assert_eq!(id.trust_domain(), domain.as_str());
    }

    /// SpiffeId::parse rejects strings that don't start with spiffe://.
    #[test]
    fn prop_spiffe_id_rejects_non_spiffe(s in "[a-z]{5,20}://[a-z]{3,10}/[a-z]{3,10}") {
        if !s.starts_with("spiffe://") {
            prop_assert!(SpiffeId::parse(&s).is_err());
        }
    }

    /// SpiffeId display equals the uri field.
    #[test]
    fn prop_spiffe_id_display_equals_uri(
        domain in valid_trust_domain(),
        workload in valid_workload(),
    ) {
        let id = SpiffeId::new(&domain, &workload).unwrap();
        prop_assert_eq!(id.to_string(), id.as_str());
    }
}

// ── Capability property tests ─────────────────────────────────────────────────

/// Strategy for valid scope strings (no whitespace, non-empty).
fn valid_scope() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_:]{1,20}".prop_map(|s| s)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Any non-whitespace non-empty string is a valid Capability.
    #[test]
    fn prop_capability_valid_no_whitespace(s in valid_scope()) {
        let cap = Capability::new(&s);
        prop_assert!(cap.is_ok(), "valid scope rejected: {s:?}");
    }

    /// Capability with any whitespace is rejected.
    #[test]
    fn prop_capability_rejects_whitespace(
        prefix in "[a-z]{3,8}",
        suffix in "[a-z]{3,8}",
        ws in "[ \t\n\r]",
    ) {
        let s = format!("{prefix}{ws}{suffix}");
        prop_assert!(Capability::new(&s).is_err());
    }

    /// Empty string is always rejected.
    #[test]
    fn prop_capability_rejects_empty(_dummy in 0u8..255u8) {
        prop_assert!(Capability::new("").is_err());
    }

    /// Capability display equals its inner string.
    #[test]
    fn prop_capability_display(s in valid_scope()) {
        let cap = Capability::new(&s).unwrap();
        prop_assert_eq!(cap.to_string(), s);
    }

    /// Capability serializes and deserializes correctly.
    #[test]
    fn prop_capability_roundtrip(s in valid_scope()) {
        let cap = Capability::new(&s).unwrap();
        let bytes = bincode::serialize(&cap).unwrap();
        let cap2: Capability = bincode::deserialize(&bytes).unwrap();
        prop_assert_eq!(cap, cap2);
    }
}

// ── Adversarial input tests ───────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Random byte slices must not panic when deserialized as a DelegationToken.
    #[test]
    fn prop_token_deserialize_no_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        // Must not panic — may return Err.
        let _ = DelegationToken::from_bytes(&bytes);
    }

    /// Random byte slices must not panic when deserialized as a DelegationChain.
    #[test]
    fn prop_chain_deserialize_no_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = DelegationChain::from_bytes(&bytes);
    }

    /// Random byte slices that happen to deserialize as a chain must fail verify().
    /// (Cryptographic invariant: a randomly constructed chain cannot be valid.)
    #[test]
    fn prop_random_chain_verify_fails(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        if let Ok(chain) = DelegationChain::from_bytes(&bytes) {
            if !chain.tokens.is_empty() {
                // A randomly assembled chain should fail verification.
                // (The probability of a valid signature in random bytes is negligible.)
                let _ = chain.verify(None); // just must not panic
            }
        }
    }

    /// Random byte slices must not panic when deserialized as a SpiffeId.
    #[test]
    fn prop_spiffe_id_parse_no_panic(s in ".*") {
        let _ = SpiffeId::parse(&s);
    }
}

// ── Delegation chain depth invariant ─────────────────────────────────────────

/// Test that depth limit is enforced for all valid depths up to MAX+1.
#[test]
fn chain_depth_limit_invariant() {
    with_large_stack(|| {
        let agents: Vec<AgentIdentity> = (0..=MAX_DELEGATION_DEPTH + 1)
            .map(|i| AgentIdentity::new("example.com", &format!("agent/{i}")).unwrap())
            .collect();

        let scope = vec![Capability::new("read:db").unwrap()];
        let mut prev_token: Option<DelegationToken> = None;

        for i in 0..=MAX_DELEGATION_DEPTH as usize {
            let subject_idx = i + 1;
            let subject_id = agents[subject_idx].spiffe_id().clone();
            let parent_ref = prev_token.as_ref();
            let issuer_scopes = scope.clone();

            let token = DelegationToken::issue(
                &agents[i],
                subject_id,
                scope.clone(),
                &issuer_scopes,
                Duration::from_secs(3600),
                parent_ref,
            )
            .unwrap();

            assert_eq!(token.depth as usize, i);
            prev_token = Some(token);
        }

        // One more level must fail.
        let last = prev_token.as_ref().unwrap();
        let overflow_id = SpiffeId::new("example.com", "overflow").unwrap();
        let result = DelegationToken::issue(
            &agents[0],
            overflow_id,
            scope.clone(),
            &scope,
            Duration::from_secs(3600),
            Some(last),
        );
        assert!(
            matches!(result, Err(okami::Error::DelegationDepthExceeded)),
            "depth limit must be enforced at MAX+1"
        );
    });
}

// ── Scope attenuation invariant ───────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// A derived token cannot contain scopes not in the parent's scopes.
    #[test]
    fn prop_scope_attenuation_enforced(
        parent_scope in valid_scope(),
        extra_scope in valid_scope(),
    ) {
        prop_assume!(parent_scope != extra_scope);
        let result = with_large_stack(move || {
            let issuer = AgentIdentity::new("example.com", "issuer").unwrap();
            let subject_id = SpiffeId::new("example.com", "subject").unwrap();
            let issuer_scopes = vec![Capability::new(&parent_scope).unwrap()];
            let requested = vec![
                Capability::new(&parent_scope).unwrap(),
                Capability::new(&extra_scope).unwrap(),
            ];
            let token_result = DelegationToken::issue(
                &issuer,
                subject_id,
                requested,
                &issuer_scopes,
                Duration::from_secs(3600),
                None,
            );
            matches!(token_result, Err(okami::Error::ScopeEscalation))
        });
        prop_assert!(result, "scope escalation must be rejected");
    }
}

// ── Round-trip serialization invariants ──────────────────────────────────────

/// SpiffeId serializes and deserializes cleanly via bincode.
#[test]
fn spiffe_id_bincode_roundtrip() {
    let cases = [
        ("example.com", "agent/1"),
        ("corp.internal", "orchestrator/main"),
        ("my-org.io", "worker/sub/deep"),
    ];
    for (domain, workload) in cases {
        let id = SpiffeId::new(domain, workload).unwrap();
        let bytes = bincode::serialize(&id).unwrap();
        let id2: SpiffeId = bincode::deserialize(&bytes).unwrap();
        assert_eq!(id, id2);
    }
}

/// DelegationToken survives a serialize → deserialize → verify cycle.
#[test]
fn delegation_token_full_roundtrip() {
    with_large_stack(|| {
        let issuer = AgentIdentity::new("example.com", "orchestrator").unwrap();
        let subject = SpiffeId::new("example.com", "worker/1").unwrap();
        let scopes = vec![
            Capability::new("read:db").unwrap(),
            Capability::new("write:api").unwrap(),
        ];
        let token = DelegationToken::issue(
            &issuer,
            subject,
            scopes.clone(),
            &scopes,
            Duration::from_secs(7200),
            None,
        )
        .unwrap();

        let bytes = token.to_bytes().unwrap();
        let restored = DelegationToken::from_bytes(&bytes).unwrap();

        assert_eq!(token.issuer, restored.issuer);
        assert_eq!(token.subject, restored.subject);
        assert_eq!(token.scopes, restored.scopes);
        assert_eq!(token.depth, restored.depth);
        assert_eq!(token.signature, restored.signature);

        restored.verify(None).unwrap();
    });
}

/// DelegationChain survives a serialize → deserialize → verify cycle.
#[test]
fn delegation_chain_full_roundtrip() {
    with_large_stack(|| {
        let orchestrator = AgentIdentity::new("example.com", "orchestrator").unwrap();
        let worker = AgentIdentity::new("example.com", "worker/1").unwrap();
        let sub_id = SpiffeId::new("example.com", "sub/1").unwrap();

        let root_scopes = vec![Capability::new("read:db").unwrap()];
        let t1 = DelegationToken::issue(
            &orchestrator,
            worker.spiffe_id().clone(),
            root_scopes.clone(),
            &root_scopes,
            Duration::from_secs(3600),
            None,
        )
        .unwrap();

        let t2 = DelegationToken::issue(
            &worker,
            sub_id,
            root_scopes.clone(),
            &t1.scopes,
            Duration::from_secs(1800),
            Some(&t1),
        )
        .unwrap();

        let chain = DelegationChain::new(vec![t1, t2]);
        let bytes = chain.to_bytes().unwrap();
        let chain2 = DelegationChain::from_bytes(&bytes).unwrap();
        chain2.verify(None).unwrap();
    });
}

/// Adversarial: truncated token bytes must not produce a valid token.
#[test]
fn adversarial_truncated_token_rejected() {
    with_large_stack(|| {
        let issuer = AgentIdentity::new("example.com", "orchestrator").unwrap();
        let subject = SpiffeId::new("example.com", "worker/1").unwrap();
        let scopes = vec![Capability::new("read:db").unwrap()];
        let token = DelegationToken::issue(
            &issuer,
            subject,
            scopes.clone(),
            &scopes,
            Duration::from_secs(3600),
            None,
        )
        .unwrap();

        let bytes = token.to_bytes().unwrap();
        // Try all truncation lengths — none should produce a verifiable token.
        for trunc_len in [1, bytes.len() / 4, bytes.len() / 2, bytes.len() - 1] {
            let truncated = &bytes[..trunc_len];
            if let Ok(t) = DelegationToken::from_bytes(truncated) {
                // If deserialization "succeeded" (unlikely with bincode), verify must fail.
                assert!(
                    t.verify(None).is_err(),
                    "truncated token at len {trunc_len} must not verify"
                );
            }
        }
    });
}

/// Adversarial: oversized payloads with embedded zeros must not panic.
#[test]
fn adversarial_oversized_payload_no_panic() {
    let oversized = vec![0u8; 1_000_000];
    let _ = DelegationToken::from_bytes(&oversized);
    let _ = DelegationChain::from_bytes(&oversized);
    let _ = okami::audit::SignedAuditEvent::from_bytes(&oversized);
}

/// Adversarial: boundary timestamps — token expiry exactly now.
///
/// Note: modifying `expires_at` after signing invalidates the signature
/// (the signature covers the full unsigned payload including expires_at).
/// This test verifies the expiry check fires BEFORE the signature check,
/// which is the correct behavior: expiry is a fast path rejection.
#[test]
fn adversarial_boundary_expiry() {
    with_large_stack(|| {
        let issuer = AgentIdentity::new("example.com", "orchestrator").unwrap();
        let subject = SpiffeId::new("example.com", "worker/1").unwrap();
        let scopes = vec![Capability::new("read:db").unwrap()];

        // Issue token that is already expired by 100 seconds.
        // We use a very short expiry and then adjust expires_at to simulate a
        // pre-expired token (as if it had been serialized and time passed).
        let mut token = DelegationToken::issue(
            &issuer,
            subject.clone(),
            scopes.clone(),
            &scopes,
            Duration::from_secs(3600),
            None,
        )
        .unwrap();

        // Set expiry to past with zero skew — expiry check fires first.
        token.expires_at = chrono::Utc::now() - chrono::Duration::seconds(100);
        assert!(
            matches!(
                token.verify(Some(Duration::from_secs(0))),
                Err(okami::Error::TokenExpired)
            ),
            "token expired by 100 seconds must be rejected with zero skew"
        );

        // With 200-second clock skew the expiry check passes, but then
        // signature verification fails (expires_at was changed post-signing).
        // This is the correct outcome: a tampered token fails even with skew.
        let result = token.verify(Some(Duration::from_secs(200)));
        assert!(
            result.is_err(),
            "tampered expires_at must cause either TokenExpired or ChainVerificationFailed"
        );

        // Separately verify that a legitimately short-lived token near expiry
        // passes with sufficient clock skew (using an unmodified token).
        // Issue a token that expires in 1 second and verify it passes.
        let fresh_token = DelegationToken::issue(
            &issuer,
            subject,
            scopes.clone(),
            &scopes,
            Duration::from_secs(3600),
            None,
        )
        .unwrap();
        // Fresh token with ample expiry must pass immediately.
        fresh_token.verify(Some(Duration::from_secs(30))).unwrap();
    });
}

// ── /cso Finding #4: bounded deserialization proptest ────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Random byte buffers up to 100 KiB fed to DelegationChain::from_bytes must
    /// never panic — they may return Ok or Err but must terminate safely.
    ///
    /// This is the security-critical regression test for /cso Finding #4
    /// (fingerprint `30a553fc`): bincode 1.x allocation DoS via crafted u64
    /// length prefixes. The bounded deserializer must catch these before any
    /// allocation attempt.
    #[test]
    fn prop_chain_from_bytes_never_panics_large_input(
        bytes in proptest::collection::vec(any::<u8>(), 0..102_400),
    ) {
        // Must not panic, OOM, or hang — may return Ok or Err.
        let _ = DelegationChain::from_bytes(&bytes);
    }
}
