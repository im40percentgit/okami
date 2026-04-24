//! Delegation tokens and chains for OAuth-style capability passing between agents.
//!
//! This module implements the core delegation mechanism of okami:
//! Capability, DelegationToken, and DelegationChain.
//!
//! Delegation follows the principle of attenuation: a delegator can only grant
//! a subset of its own scopes. Chains are limited to depth 3.
//!
// @decision DEC-OKAMI-005 bincode for token serialization — accepted.
// Rationale: compact binary, clean serde integration. JWTs carry HTTP/JSON
// baggage. The token is signed over its bincode-serialized unsigned portion.
//
// @decision DEC-OKAMI-006 Scope as validated string (not enum) — accepted.
// Rationale: OAuth-style string scopes are familiar and composable with IAM.
// An enum would require knowing every possible scope in advance.
//
// @decision DEC-OKAMI-007 Clock skew tolerance: configurable, default 30s — accepted.
// Rationale: distributed systems have clock drift. 30s prevents spurious failures
// in well-behaved environments. Operators can set it to zero.

use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::identity::{AgentIdentity, PqcCredential, SpiffeId};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum delegation chain depth (depth field in token, 0-indexed).
/// A root token has depth 0; its delegate depth 1; maximum is depth 2.
pub const MAX_DELEGATION_DEPTH: u32 = 2;

/// Default clock skew tolerance in seconds.
pub const DEFAULT_CLOCK_SKEW_SECS: u64 = 30;

// ── Capability ────────────────────────────────────────────────────────────────

/// A validated OAuth-style capability scope string (e.g. `read:db`, `write:api`).
///
/// Scopes must be non-empty strings without whitespace. The conventional format
/// is `action:resource` but any non-empty whitespace-free string is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Capability(String);

impl Capability {
    /// Parse and validate a capability scope string.
    ///
    /// Returns [`Error::InvalidScope`] if the string is empty or contains whitespace.
    pub fn new(scope: &str) -> Result<Self> {
        if scope.is_empty() {
            return Err(Error::InvalidScope("scope must not be empty".to_string()));
        }
        if scope.chars().any(|c| c.is_whitespace()) {
            return Err(Error::InvalidScope(format!(
                "scope must not contain whitespace: {:?}",
                scope
            )));
        }
        Ok(Capability(scope.to_string()))
    }

    /// Return the scope string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Capability {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Capability::new(s)
    }
}

// ── UnsignedToken ─────────────────────────────────────────────────────────────

/// The unsigned payload of a delegation token (the bytes that are signed over).
///
/// Separated from [`DelegationToken`] so the signature covers only data fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsignedToken {
    issuer: SpiffeId,
    subject: SpiffeId,
    scopes: Vec<Capability>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    parent_token_hash: Option<[u8; 32]>,
    depth: u32,
}

// ── DelegationToken ───────────────────────────────────────────────────────────

/// A signed delegation token granting scoped capabilities from issuer to subject.
///
/// Contains: issuer SPIFFE ID, subject SPIFFE ID, scopes, validity window,
/// parent chain linkage, embedded issuer credential, and PQC signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    /// Issuer SPIFFE ID.
    pub issuer: SpiffeId,
    /// Subject SPIFFE ID (who receives the capabilities).
    pub subject: SpiffeId,
    /// Capabilities granted to the subject.
    pub scopes: Vec<Capability>,
    /// When this token was issued.
    pub issued_at: DateTime<Utc>,
    /// When this token expires.
    pub expires_at: DateTime<Utc>,
    /// SHA-256 of the parent token bytes (None for root tokens).
    pub parent_token_hash: Option<[u8; 32]>,
    /// Chain depth (0 = root, max = MAX_DELEGATION_DEPTH).
    pub depth: u32,
    /// The issuer's public credential, embedded for self-contained verification.
    pub issuer_credential: PqcCredential,
    /// PQC signature over the bincode-serialized unsigned payload.
    pub signature: Vec<u8>,
}

impl DelegationToken {
    /// Issue a new delegation token.
    ///
    /// Scopes must be a subset of `issuer_scopes` (attenuation enforced).
    /// Depth must not exceed [`MAX_DELEGATION_DEPTH`].
    ///
    /// # Parameters
    ///
    /// - `issuer` — the signing identity of the issuer
    /// - `subject_spiffe_id` — who receives the capabilities
    /// - `scopes` — capabilities to grant (subset of `issuer_scopes`)
    /// - `issuer_scopes` — the full scopes the issuer holds
    /// - `expiry` — how long until the token expires
    /// - `parent` — the parent token in the chain (None for root tokens)
    ///
    /// # Errors
    ///
    /// - [`Error::DelegationDepthExceeded`] if depth would exceed [`MAX_DELEGATION_DEPTH`]
    /// - [`Error::ScopeEscalation`] if requested scopes exceed issuer scopes
    /// - [`Error::Crypto`] if signing fails
    pub fn issue(
        issuer: &AgentIdentity,
        subject_spiffe_id: SpiffeId,
        scopes: Vec<Capability>,
        issuer_scopes: &[Capability],
        expiry: StdDuration,
        parent: Option<&DelegationToken>,
    ) -> Result<Self> {
        let depth = match parent {
            None => 0,
            Some(p) => p.depth + 1,
        };

        if depth > MAX_DELEGATION_DEPTH {
            return Err(Error::DelegationDepthExceeded);
        }

        // Attenuation: requested scopes must be a subset of issuer scopes.
        for scope in &scopes {
            if !issuer_scopes.contains(scope) {
                return Err(Error::ScopeEscalation);
            }
        }

        // Compute parent token hash.
        let parent_token_hash = parent
            .map(|p| -> Result<[u8; 32]> {
                let bytes = p.to_bytes()?;
                Ok(Sha256::digest(&bytes).into())
            })
            .transpose()?;

        let now = Utc::now();
        let expiry_secs: i64 = expiry.as_secs().try_into().unwrap_or(i64::MAX);
        let expires_at = now + Duration::seconds(expiry_secs);

        let unsigned = UnsignedToken {
            issuer: issuer.spiffe_id().clone(),
            subject: subject_spiffe_id.clone(),
            scopes: scopes.clone(),
            issued_at: now,
            expires_at,
            parent_token_hash,
            depth,
        };

        let payload_bytes = bincode::serialize(&unsigned)
            .map_err(|e| Error::Serialization(format!("token payload serialize: {e}")))?;

        let signature = issuer.sign(&payload_bytes)?;

        Ok(DelegationToken {
            issuer: issuer.spiffe_id().clone(),
            subject: subject_spiffe_id,
            scopes,
            issued_at: now,
            expires_at,
            parent_token_hash,
            depth,
            issuer_credential: issuer.credential(),
            signature,
        })
    }

    /// Verify this token's signature and validity window.
    ///
    /// Checks: issuer/credential binding, not expired, not issued in the far
    /// future, PQC signature valid.
    ///
    /// # Parameters
    ///
    /// - `clock_skew` — grace period (default: 30 seconds)
    //
    // @decision DEC-OKAMI-014
    // @title Verify embedded credential SPIFFE ID matches claimed issuer
    // @status accepted
    // @rationale DelegationToken::verify uses the verifying key from the embedded
    //   issuer_credential. Without checking that issuer_credential.spiffe_id matches
    //   the claimed issuer, any keypair holder could forge tokens claiming any issuer
    //   identity: they generate their own AgentIdentity, set issuer = <victim SPIFFE ID>,
    //   embed their own credential, sign the UnsignedToken with their key, and
    //   verify() returns Ok because the signature check only validates that the
    //   payload was signed by the embedded key — not that the embedded key belongs
    //   to the claimed issuer. The check is placed before time-window validation so
    //   the error is stable regardless of system clock state.
    //   See /cso report 2026-04-24 Finding #1
    //   (fingerprint fc51b5488084256e84c03c389a26d5899f5424399d8d4fe99fc9e0e5ff8baeb8).
    pub fn verify(&self, clock_skew: Option<StdDuration>) -> Result<()> {
        // Invariant: the claimed issuer must be the subject of the embedded credential.
        // A token whose issuer field names entity X but embeds Y's verifying key is
        // a forgery — reject before touching the clock.
        if self.issuer != self.issuer_credential.spiffe_id {
            return Err(Error::ChainVerificationFailed(format!(
                "issuer {} does not match embedded credential subject {}",
                self.issuer, self.issuer_credential.spiffe_id
            )));
        }

        let skew_secs = clock_skew
            .unwrap_or(StdDuration::from_secs(DEFAULT_CLOCK_SKEW_SECS))
            .as_secs() as i64;
        let skew = Duration::seconds(skew_secs);
        let now = Utc::now();

        if now > self.expires_at + skew {
            return Err(Error::TokenExpired);
        }
        if self.issued_at > now + skew {
            return Err(Error::TokenNotYetValid);
        }

        let unsigned = UnsignedToken {
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            scopes: self.scopes.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            parent_token_hash: self.parent_token_hash,
            depth: self.depth,
        };
        let payload_bytes = bincode::serialize(&unsigned)
            .map_err(|e| Error::Serialization(format!("token payload serialize: {e}")))?;

        let vk = lupine::sign::HybridVerifyingKey65::from_bytes(
            &self.issuer_credential.verifying_key_bytes,
        )?;

        let valid = lupine::easy::verify(&vk, &payload_bytes, &self.signature)
            .map_err(|_| Error::Crypto(lupine_core::Error::Verification))?;

        if !valid {
            return Err(Error::ChainVerificationFailed(format!(
                "signature invalid for token from {} to {}",
                self.issuer, self.subject
            )));
        }

        Ok(())
    }

    /// Serialize this token to bytes (bincode).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Serialization(format!("token serialize: {e}")))
    }

    /// Deserialize a token from bytes (bincode).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| Error::Serialization(format!("token deserialize: {e}")))
    }

    /// Return a SHA-256 hash of this token's serialized bytes.
    pub fn hash(&self) -> Result<[u8; 32]> {
        let bytes = self.to_bytes()?;
        Ok(Sha256::digest(&bytes).into())
    }
}

// ── DelegationChain ───────────────────────────────────────────────────────────

/// An ordered list of delegation tokens forming a verifiable trust chain.
///
/// The chain is ordered root-first. Verification checks each token individually
/// plus structural integrity: parent hash linkage, scope attenuation, depth
/// limit, and issuer/subject linkage across hops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationChain {
    /// Ordered tokens, root at index 0.
    pub tokens: Vec<DelegationToken>,
}

impl DelegationChain {
    /// Create a chain from an ordered list of tokens (root first).
    pub fn new(tokens: Vec<DelegationToken>) -> Self {
        DelegationChain { tokens }
    }

    /// Verify the entire delegation chain.
    ///
    /// Checks per-token validity then structural integrity across all links.
    pub fn verify(&self, clock_skew: Option<StdDuration>) -> Result<()> {
        if self.tokens.is_empty() {
            return Err(Error::ChainVerificationFailed("chain is empty".to_string()));
        }

        let mut prev_token: Option<&DelegationToken> = None;

        for (i, token) in self.tokens.iter().enumerate() {
            // Per-token verification (signature + expiry).
            token.verify(clock_skew)?;

            // Depth must match position in chain.
            if token.depth as usize != i {
                return Err(Error::ChainVerificationFailed(format!(
                    "token at index {i} has depth {} (expected {i})",
                    token.depth
                )));
            }

            if let Some(prev) = prev_token {
                // Parent hash linkage.
                let expected_hash = prev.hash()?;
                match token.parent_token_hash {
                    None => {
                        return Err(Error::ChainVerificationFailed(format!(
                            "token at index {i} missing parent_token_hash"
                        )));
                    }
                    Some(h) if h != expected_hash => {
                        return Err(Error::ChainVerificationFailed(format!(
                            "token at index {i} parent_token_hash mismatch"
                        )));
                    }
                    _ => {}
                }

                // Scope attenuation.
                for scope in &token.scopes {
                    if !prev.scopes.contains(scope) {
                        return Err(Error::ChainVerificationFailed(format!(
                            "scope escalation at index {i}: {scope} not in parent scopes"
                        )));
                    }
                }

                // Issuer/subject linkage.
                if token.issuer != prev.subject {
                    return Err(Error::ChainVerificationFailed(format!(
                        "chain broken at index {i}: token issuer {} != prev subject {}",
                        token.issuer, prev.subject
                    )));
                }
            } else {
                // Root token must have no parent hash.
                if token.parent_token_hash.is_some() {
                    return Err(Error::ChainVerificationFailed(
                        "root token (index 0) must not have a parent_token_hash".to_string(),
                    ));
                }
            }

            prev_token = Some(token);
        }

        Ok(())
    }

    /// Return the final (leaf) token in the chain.
    pub fn leaf(&self) -> Option<&DelegationToken> {
        self.tokens.last()
    }

    /// Return the effective scopes at the end of the chain (leaf token scopes).
    pub fn effective_scopes(&self) -> &[Capability] {
        self.leaf().map(|t| t.scopes.as_slice()).unwrap_or(&[])
    }

    /// Serialize this chain to bytes (bincode).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| Error::Serialization(format!("chain serialize: {e}")))
    }

    /// Deserialize a chain from bytes (bincode).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| Error::Serialization(format!("chain deserialize: {e}")))
    }

    /// Render an ASCII tree visualization of this chain.
    ///
    /// Example:
    ///   [0] spiffe://example.com/orchestrator [read:db, write:api]
    ///    -> [1] spiffe://example.com/worker [read:db]
    ///        -> [2] spiffe://example.com/sub-worker [read:db]
    pub fn ascii_tree(&self) -> String {
        let mut out = String::new();
        for (i, token) in self.tokens.iter().enumerate() {
            let indent = "    ".repeat(i);
            let connector = if i == 0 { "" } else { "-> " };
            let scopes: Vec<&str> = token.scopes.iter().map(|s| s.as_str()).collect();
            let scopes_str = if scopes.is_empty() {
                "(no scopes)".to_string()
            } else {
                format!("[{}]", scopes.join(", "))
            };
            out.push_str(&format!(
                "{indent}{connector}[{i}] {} {scopes_str}\n",
                token.subject
            ));
        }
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentIdentity;

    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── Capability ────────────────────────────────────────────────────────────

    #[test]
    fn capability_valid_scopes() {
        assert!(Capability::new("read:db").is_ok());
        assert!(Capability::new("write:api").is_ok());
        assert!(Capability::new("invoke:llm").is_ok());
        assert!(Capability::new("admin").is_ok());
        assert!(Capability::new("read:db:table1").is_ok());
    }

    #[test]
    fn capability_empty_scope_rejected() {
        assert!(matches!(Capability::new(""), Err(Error::InvalidScope(_))));
    }

    #[test]
    fn capability_whitespace_rejected() {
        assert!(matches!(
            Capability::new("read db"),
            Err(Error::InvalidScope(_))
        ));
        assert!(matches!(
            Capability::new("read\tdb"),
            Err(Error::InvalidScope(_))
        ));
        assert!(matches!(
            Capability::new("read\ndb"),
            Err(Error::InvalidScope(_))
        ));
    }

    #[test]
    fn capability_display() {
        let c = Capability::new("read:db").unwrap();
        assert_eq!(c.to_string(), "read:db");
    }

    #[test]
    fn capability_from_str() {
        let c: Capability = "write:api".parse().unwrap();
        assert_eq!(c.as_str(), "write:api");
    }

    #[test]
    fn capability_serialize_roundtrip() {
        let c = Capability::new("read:db").unwrap();
        let bytes = bincode::serialize(&c).unwrap();
        let c2: Capability = bincode::deserialize(&bytes).unwrap();
        assert_eq!(c, c2);
    }

    // ── DelegationToken ───────────────────────────────────────────────────────

    #[test]
    fn delegation_token_issue_and_verify() {
        with_large_stack(|| {
            let issuer = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let subject_id = SpiffeId::new("example.com", "worker/1").unwrap();
            let scopes = vec![
                Capability::new("read:db").unwrap(),
                Capability::new("write:api").unwrap(),
            ];
            let token = DelegationToken::issue(
                &issuer,
                subject_id,
                scopes.clone(),
                &scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();
            token.verify(None).unwrap();
            assert_eq!(token.depth, 0);
            assert!(token.parent_token_hash.is_none());
        });
    }

    #[test]
    fn delegation_token_serialize_roundtrip() {
        with_large_stack(|| {
            let issuer = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let subject_id = SpiffeId::new("example.com", "worker/1").unwrap();
            let scopes = vec![Capability::new("read:db").unwrap()];
            let token = DelegationToken::issue(
                &issuer,
                subject_id,
                scopes.clone(),
                &scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();
            let bytes = token.to_bytes().unwrap();
            let token2 = DelegationToken::from_bytes(&bytes).unwrap();
            assert_eq!(token.issuer, token2.issuer);
            assert_eq!(token.subject, token2.subject);
            assert_eq!(token.scopes, token2.scopes);
            assert_eq!(token.depth, token2.depth);
            token2.verify(None).unwrap();
        });
    }

    #[test]
    fn delegation_token_scope_escalation_rejected() {
        with_large_stack(|| {
            let issuer = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let subject_id = SpiffeId::new("example.com", "worker/1").unwrap();
            let issuer_scopes = vec![Capability::new("read:db").unwrap()];
            let requested = vec![
                Capability::new("read:db").unwrap(),
                Capability::new("admin").unwrap(),
            ];
            let result = DelegationToken::issue(
                &issuer,
                subject_id,
                requested,
                &issuer_scopes,
                StdDuration::from_secs(3600),
                None,
            );
            assert!(matches!(result, Err(Error::ScopeEscalation)));
        });
    }

    #[test]
    fn delegation_token_verify_rejects_tampered_signature() {
        with_large_stack(|| {
            let issuer = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let subject_id = SpiffeId::new("example.com", "worker/1").unwrap();
            let scopes = vec![Capability::new("read:db").unwrap()];
            let mut token = DelegationToken::issue(
                &issuer,
                subject_id,
                scopes.clone(),
                &scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();
            token.signature[0] ^= 0xFF;
            let result = token.verify(None);
            assert!(matches!(
                result,
                Err(Error::ChainVerificationFailed(_)) | Err(Error::Crypto(_))
            ));
        });
    }

    #[test]
    fn delegation_token_verify_rejects_expired() {
        with_large_stack(|| {
            let issuer = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let subject_id = SpiffeId::new("example.com", "worker/1").unwrap();
            let scopes = vec![Capability::new("read:db").unwrap()];
            let mut token = DelegationToken::issue(
                &issuer,
                subject_id,
                scopes.clone(),
                &scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();
            token.expires_at = Utc::now() - Duration::seconds(100);
            let result = token.verify(Some(StdDuration::from_secs(0)));
            assert!(matches!(result, Err(Error::TokenExpired)));
        });
    }

    #[test]
    fn delegation_token_empty_scopes_allowed() {
        with_large_stack(|| {
            let issuer = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let subject_id = SpiffeId::new("example.com", "worker/1").unwrap();
            let issuer_scopes: Vec<Capability> = vec![];
            let token = DelegationToken::issue(
                &issuer,
                subject_id,
                vec![],
                &issuer_scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();
            token.verify(None).unwrap();
        });
    }

    // ── DelegationChain ───────────────────────────────────────────────────────

    #[test]
    fn delegation_chain_two_hops() {
        with_large_stack(|| {
            let orchestrator = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let worker = AgentIdentity::new("example.com", "worker/1").unwrap();
            let sub_id = SpiffeId::new("example.com", "sub-worker/1").unwrap();

            let root_scopes = vec![
                Capability::new("read:db").unwrap(),
                Capability::new("write:api").unwrap(),
            ];

            let token1 = DelegationToken::issue(
                &orchestrator,
                worker.spiffe_id().clone(),
                root_scopes.clone(),
                &root_scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();

            let worker_scopes = vec![Capability::new("read:db").unwrap()];
            let token2 = DelegationToken::issue(
                &worker,
                sub_id,
                worker_scopes,
                &token1.scopes,
                StdDuration::from_secs(1800),
                Some(&token1),
            )
            .unwrap();

            assert_eq!(token2.depth, 1);
            assert!(token2.parent_token_hash.is_some());

            let chain = DelegationChain::new(vec![token1, token2]);
            chain.verify(None).unwrap();
        });
    }

    #[test]
    fn delegation_chain_max_depth_enforced() {
        with_large_stack(|| {
            let a = AgentIdentity::new("example.com", "agent/a").unwrap();
            let b = AgentIdentity::new("example.com", "agent/b").unwrap();
            let c = AgentIdentity::new("example.com", "agent/c").unwrap();

            let scopes = vec![Capability::new("read:db").unwrap()];

            let t1 = DelegationToken::issue(
                &a,
                b.spiffe_id().clone(),
                scopes.clone(),
                &scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();

            let t2 = DelegationToken::issue(
                &b,
                c.spiffe_id().clone(),
                scopes.clone(),
                &t1.scopes,
                StdDuration::from_secs(3600),
                Some(&t1),
            )
            .unwrap();

            let d_id = SpiffeId::new("example.com", "agent/d").unwrap();
            let t3 = DelegationToken::issue(
                &c,
                d_id,
                scopes.clone(),
                &t2.scopes,
                StdDuration::from_secs(3600),
                Some(&t2),
            )
            .unwrap();

            assert_eq!(t3.depth, 2);

            // Attempting depth 3 must fail.
            let e_id = SpiffeId::new("example.com", "agent/e").unwrap();
            let result = DelegationToken::issue(
                &c,
                e_id,
                scopes.clone(),
                &t3.scopes,
                StdDuration::from_secs(3600),
                Some(&t3),
            );
            assert!(matches!(result, Err(Error::DelegationDepthExceeded)));
        });
    }

    #[test]
    fn delegation_chain_broken_parent_hash_rejected() {
        with_large_stack(|| {
            let orchestrator = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let worker = AgentIdentity::new("example.com", "worker/1").unwrap();
            let sub_id = SpiffeId::new("example.com", "sub-worker/1").unwrap();
            let scopes = vec![Capability::new("read:db").unwrap()];

            let token1 = DelegationToken::issue(
                &orchestrator,
                worker.spiffe_id().clone(),
                scopes.clone(),
                &scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();

            let mut token2 = DelegationToken::issue(
                &worker,
                sub_id,
                scopes.clone(),
                &token1.scopes,
                StdDuration::from_secs(1800),
                Some(&token1),
            )
            .unwrap();

            if let Some(ref mut h) = token2.parent_token_hash {
                h[0] ^= 0xFF;
            }

            let chain = DelegationChain::new(vec![token1, token2]);
            assert!(matches!(
                chain.verify(None),
                Err(Error::ChainVerificationFailed(_))
            ));
        });
    }

    #[test]
    fn delegation_chain_scope_escalation_in_chain_rejected() {
        with_large_stack(|| {
            let orchestrator = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let worker = AgentIdentity::new("example.com", "worker/1").unwrap();
            let sub_id = SpiffeId::new("example.com", "sub-worker/1").unwrap();
            let root_scopes = vec![Capability::new("read:db").unwrap()];

            let token1 = DelegationToken::issue(
                &orchestrator,
                worker.spiffe_id().clone(),
                root_scopes.clone(),
                &root_scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();

            let mut token2 = DelegationToken::issue(
                &worker,
                sub_id,
                root_scopes.clone(),
                &root_scopes,
                StdDuration::from_secs(1800),
                Some(&token1),
            )
            .unwrap();

            // Inject escalated scope post-issuance to simulate tampering.
            token2.scopes.push(Capability::new("admin").unwrap());

            let chain = DelegationChain::new(vec![token1, token2]);
            assert!(matches!(
                chain.verify(None),
                Err(Error::ChainVerificationFailed(_))
            ));
        });
    }

    #[test]
    fn delegation_chain_ascii_tree_nonempty() {
        with_large_stack(|| {
            let orchestrator = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let worker_id = SpiffeId::new("example.com", "worker/1").unwrap();
            let scopes = vec![Capability::new("read:db").unwrap()];
            let token = DelegationToken::issue(
                &orchestrator,
                worker_id,
                scopes.clone(),
                &scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();
            let chain = DelegationChain::new(vec![token]);
            let tree = chain.ascii_tree();
            assert!(tree.contains("read:db"));
            assert!(tree.contains("worker/1"));
        });
    }

    #[test]
    fn delegation_chain_empty_fails_verify() {
        let chain = DelegationChain::new(vec![]);
        assert!(matches!(
            chain.verify(None),
            Err(Error::ChainVerificationFailed(_))
        ));
    }

    #[test]
    fn delegation_chain_serialize_roundtrip() {
        with_large_stack(|| {
            let orchestrator = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let worker_id = SpiffeId::new("example.com", "worker/1").unwrap();
            let scopes = vec![Capability::new("read:db").unwrap()];
            let token = DelegationToken::issue(
                &orchestrator,
                worker_id,
                scopes.clone(),
                &scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();
            let chain = DelegationChain::new(vec![token]);
            let bytes = chain.to_bytes().unwrap();
            let chain2 = DelegationChain::from_bytes(&bytes).unwrap();
            chain2.verify(None).unwrap();
        });
    }

    #[test]
    fn delegation_chain_effective_scopes() {
        with_large_stack(|| {
            let orchestrator = AgentIdentity::new("example.com", "orchestrator").unwrap();
            let worker_id = SpiffeId::new("example.com", "worker/1").unwrap();
            let scopes = vec![
                Capability::new("read:db").unwrap(),
                Capability::new("write:api").unwrap(),
            ];
            let token = DelegationToken::issue(
                &orchestrator,
                worker_id,
                scopes.clone(),
                &scopes,
                StdDuration::from_secs(3600),
                None,
            )
            .unwrap();
            let chain = DelegationChain::new(vec![token]);
            assert_eq!(chain.effective_scopes().len(), 2);
        });
    }

    // ── Security regression: issuer/credential mismatch (Finding #1) ──────────

    /// An attacker with their own valid keypair forges a token claiming to be
    /// issued by a different SPIFFE ID. The signature is cryptographically valid
    /// (the attacker signs with their own key), but the issuer field names a
    /// different identity than the embedded credential. verify() must reject it.
    #[test]
    fn delegation_token_verify_rejects_issuer_credential_mismatch() {
        with_large_stack(|| {
            // Attacker generates a legitimate keypair for their own identity.
            let attacker = AgentIdentity::new("example.com", "attacker").unwrap();
            // Victim identity the attacker wants to impersonate.
            let victim_id = SpiffeId::new("example.com", "victim").unwrap();
            let subject_id = SpiffeId::new("example.com", "subject").unwrap();

            let scopes = vec![Capability::new("read:db").unwrap()];
            let now = chrono::Utc::now();

            // Build the UnsignedToken as the attacker would: claiming victim as issuer.
            let unsigned = UnsignedToken {
                issuer: victim_id.clone(),
                subject: subject_id.clone(),
                scopes: scopes.clone(),
                issued_at: now,
                expires_at: now + chrono::Duration::seconds(3600),
                parent_token_hash: None,
                depth: 0,
            };
            let payload_bytes = bincode::serialize(&unsigned).unwrap();

            // Attacker signs with their own key — signature is valid for the payload.
            let signature = attacker.sign(&payload_bytes).unwrap();

            // Construct a token where issuer claims to be victim but embeds attacker's
            // credential (whose spiffe_id == attacker, not victim).
            let forged = DelegationToken {
                issuer: victim_id.clone(),
                subject: subject_id,
                scopes,
                issued_at: now,
                expires_at: now + chrono::Duration::seconds(3600),
                parent_token_hash: None,
                depth: 0,
                issuer_credential: attacker.credential(), // attacker's cred, not victim's
                signature,
            };

            let result = forged.verify(None);
            assert!(
                matches!(result, Err(Error::ChainVerificationFailed(ref msg)) if msg.contains("does not match")),
                "expected ChainVerificationFailed(\"does not match ...\"), got: {result:?}"
            );
        });
    }

    /// End-to-end chain variant: a root token with mismatched issuer/credential
    /// must cause chain.verify() to fail at the root, even when a legitimate-
    /// looking child token chains off it.
    #[test]
    fn delegation_chain_rejects_forged_root_with_mismatched_credential() {
        with_large_stack(|| {
            let attacker = AgentIdentity::new("example.com", "attacker").unwrap();
            let legitimate_worker = AgentIdentity::new("example.com", "worker/1").unwrap();
            let victim_id = SpiffeId::new("example.com", "victim").unwrap();
            let subject_id = legitimate_worker.spiffe_id().clone();

            let scopes = vec![Capability::new("read:db").unwrap()];
            let now = chrono::Utc::now();

            // Forge the root token: issuer claims victim but embeds attacker's credential.
            let unsigned_root = UnsignedToken {
                issuer: victim_id.clone(),
                subject: subject_id.clone(),
                scopes: scopes.clone(),
                issued_at: now,
                expires_at: now + chrono::Duration::seconds(3600),
                parent_token_hash: None,
                depth: 0,
            };
            let root_payload = bincode::serialize(&unsigned_root).unwrap();
            let root_sig = attacker.sign(&root_payload).unwrap();

            let forged_root = DelegationToken {
                issuer: victim_id,
                subject: subject_id,
                scopes: scopes.clone(),
                issued_at: now,
                expires_at: now + chrono::Duration::seconds(3600),
                parent_token_hash: None,
                depth: 0,
                issuer_credential: attacker.credential(),
                signature: root_sig,
            };

            // Build a legitimate child token that chains off the forged root.
            let leaf_subject = SpiffeId::new("example.com", "leaf").unwrap();
            let child = DelegationToken::issue(
                &legitimate_worker,
                leaf_subject,
                scopes.clone(),
                &scopes,
                StdDuration::from_secs(1800),
                Some(&forged_root),
            )
            .unwrap();

            let chain = DelegationChain::new(vec![forged_root, child]);
            let result = chain.verify(None);
            assert!(
                matches!(result, Err(Error::ChainVerificationFailed(_))),
                "expected ChainVerificationFailed, got: {result:?}"
            );
        });
    }
}
