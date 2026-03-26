//! Agent identity: SPIFFE IDs, PQC credentials, and key lifecycle.
//!
//! This module provides the core identity primitives for okami agents:
//!
//! - [`SpiffeId`] — parsed and validated SPIFFE identifier
//! - [`PqcCredential`] — shareable credential containing a verifying key and metadata
//! - [`AgentIdentity`] — full identity with signing capability, key rotation, and revocation
//!
//! # Quick start
//!
//! ```rust,no_run
//! use okami::identity::AgentIdentity;
//!
//! let identity = AgentIdentity::new("example.com", "my-agent").unwrap();
//! let credential = identity.credential();
//! let sig = identity.sign(b"hello world").unwrap();
//! assert!(identity.verify(b"hello world", &sig).unwrap());
//! ```
//!
//! @decision DEC-OKAMI-002
//! @title Separate PqcCredential (public) from AgentIdentity (private+public)
//! @status accepted
//! @rationale `PqcCredential` contains only public material (verifying key,
//!   SPIFFE ID, timestamps) and is safe to share with peers. `AgentIdentity`
//!   holds the signing key and is never serialized as a whole. This separation
//!   mirrors X.509 cert vs. private key: you distribute the cert, not the key.
//!
//! @decision DEC-OKAMI-003
//! @title Raw verifying key bytes for DER encoding (no standard hybrid OID yet)
//! @status accepted
//! @rationale The NIST/IETF OID for hybrid Ed25519+ML-DSA composite keys is
//!   not yet standardized (draft-ounsworth-pq-composite-sigs). Rather than
//!   inventing an OID, we store raw verifying key bytes with an algorithm tag.
//!   This is pragmatic for Phase 1; Phase 2 can adopt the composite OID when
//!   standardized without breaking the on-disk format (version byte in credential).
//!
//! @decision DEC-OKAMI-004
//! @title 0600 file permission enforcement (SSH model)
//! @status accepted
//! @rationale Private key files must not be readable by other users. Refusing
//!   to load keys with permissions wider than 0600 forces operators to handle
//!   key material correctly. This matches the SSH convention, which users
//!   already understand. Windows support is deferred (no equivalent ACL model).

use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default credential validity duration: 365 days.
pub const DEFAULT_VALIDITY_DAYS: i64 = 365;

/// Algorithm tag stored in PqcCredential to identify the key type.
/// Version 1 = Hybrid Ed25519 + ML-DSA-65.
const CREDENTIAL_ALGO_V1: u8 = 0x01;

// ── SpiffeId ──────────────────────────────────────────────────────────────────

/// A validated SPIFFE ID of the form `spiffe://trust-domain/workload-id`.
///
/// SPIFFE IDs provide a URI-based namespace for workload identity.
/// See <https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/> for the spec.
///
/// # Validation rules
///
/// - Must start with `spiffe://`
/// - Trust domain must be non-empty and contain only valid hostname characters
/// - Path (workload ID) must be non-empty
/// - No query strings or fragments allowed
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpiffeId {
    /// The full URI string, e.g. `spiffe://example.com/agent/worker-1`.
    uri: String,
    /// Index into `uri` where the trust domain starts (after `spiffe://`).
    trust_domain_end: usize,
}

impl SpiffeId {
    /// Parse and validate a SPIFFE ID string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSpiffeId`] if the string does not conform to
    /// the SPIFFE URI format.
    pub fn parse(s: &str) -> Result<Self> {
        Self::validate_and_build(s)
    }

    /// Construct a SPIFFE ID from trust domain and workload path components.
    ///
    /// The workload path should not start with `/`; one will be inserted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSpiffeId`] if either component contains invalid characters.
    pub fn new(trust_domain: &str, workload_path: &str) -> Result<Self> {
        let uri = format!("spiffe://{trust_domain}/{workload_path}");
        Self::validate_and_build(&uri)
    }

    /// Return the full SPIFFE URI string.
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// Return the trust domain portion (e.g. `example.com`).
    pub fn trust_domain(&self) -> &str {
        // "spiffe://" is 9 bytes
        &self.uri[9..self.trust_domain_end]
    }

    /// Return the workload path portion (e.g. `/agent/worker-1`).
    pub fn workload_path(&self) -> &str {
        &self.uri[self.trust_domain_end..]
    }

    fn validate_and_build(s: &str) -> Result<Self> {
        // Must start with spiffe://
        let rest = s
            .strip_prefix("spiffe://")
            .ok_or_else(|| Error::InvalidSpiffeId(format!("must start with 'spiffe://': {s}")))?;

        if rest.is_empty() {
            return Err(Error::InvalidSpiffeId(
                "trust domain is empty".to_string(),
            ));
        }

        // No query strings or fragments.
        if s.contains('?') || s.contains('#') {
            return Err(Error::InvalidSpiffeId(
                "SPIFFE IDs must not contain query strings or fragments".to_string(),
            ));
        }

        // Split trust domain from path.
        let slash_pos = rest.find('/').ok_or_else(|| {
            Error::InvalidSpiffeId(
                "missing workload path (no '/' after trust domain)".to_string(),
            )
        })?;

        let trust_domain = &rest[..slash_pos];
        let path = &rest[slash_pos..]; // includes leading '/'

        if trust_domain.is_empty() {
            return Err(Error::InvalidSpiffeId("trust domain is empty".to_string()));
        }

        // Trust domain: hostname chars only (alphanumeric, hyphen, dot).
        for ch in trust_domain.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '.' {
                return Err(Error::InvalidSpiffeId(format!(
                    "trust domain contains invalid character '{ch}'"
                )));
            }
        }

        // Workload path must be non-empty (more than just "/").
        if path.len() <= 1 {
            return Err(Error::InvalidSpiffeId(
                "workload path is empty".to_string(),
            ));
        }

        // 9 = len("spiffe://"), slash_pos gives end of trust domain within `rest`
        let trust_domain_end = 9 + slash_pos;

        Ok(SpiffeId {
            uri: s.to_string(),
            trust_domain_end,
        })
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri)
    }
}

impl std::str::FromStr for SpiffeId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        SpiffeId::parse(s)
    }
}

// ── PqcCredential ─────────────────────────────────────────────────────────────

/// A shareable PQC credential containing a verifying key and identity metadata.
///
/// `PqcCredential` contains only public material and is safe to share with
/// peers. It does not contain the signing key. Think of it as the
/// post-quantum equivalent of an X.509 certificate.
///
/// # Wire format
///
/// Serialized with serde/bincode. The `algo` field identifies the key type
/// for forward compatibility. Version 1 uses hybrid Ed25519+ML-DSA-65.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcCredential {
    /// SPIFFE ID identifying the agent this credential belongs to.
    pub spiffe_id: SpiffeId,
    /// Algorithm version byte (0x01 = hybrid Ed25519+ML-DSA-65).
    pub algo: u8,
    /// Raw serialized verifying key bytes (format determined by `algo`).
    pub verifying_key_bytes: Vec<u8>,
    /// When this credential was created.
    pub created_at: DateTime<Utc>,
    /// When this credential expires.
    pub expires_at: DateTime<Utc>,
}

impl PqcCredential {
    /// Check whether this credential has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check whether this credential is valid at the given time.
    pub fn is_valid_at(&self, t: DateTime<Utc>) -> bool {
        t >= self.created_at && t <= self.expires_at
    }

    /// Serialize this credential to bytes (bincode).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if bincode encoding fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| Error::Serialization(format!("credential serialize: {e}")))
    }

    /// Deserialize a credential from bytes (bincode).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if bincode decoding fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| Error::Serialization(format!("credential deserialize: {e}")))
    }
}

// ── Revocation statement ──────────────────────────────────────────────────────

/// A signed statement revoking a credential.
///
/// Produced by [`AgentIdentity::revoke`]. The `target_credential_bytes` field
/// contains the bincode-serialized [`PqcCredential`] being revoked; the
/// `signature` covers those bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationStatement {
    /// The bincode bytes of the credential being revoked.
    pub target_credential_bytes: Vec<u8>,
    /// Timestamp of revocation.
    pub revoked_at: DateTime<Utc>,
    /// PQC signature over `target_credential_bytes || revoked_at_timestamp_secs`.
    pub signature: Vec<u8>,
}

// ── AgentIdentity ─────────────────────────────────────────────────────────────

/// Full agent identity: SPIFFE ID + PQC signing capability.
///
/// `AgentIdentity` holds the private signing key and is the source of all
/// cryptographic operations (sign, delegate, revoke). It is never serialized
/// as a whole; only the [`PqcCredential`] (public part) is shared.
///
/// # Key lifecycle
///
/// - [`AgentIdentity::new`] — generate a fresh keypair
/// - [`AgentIdentity::from_stored`] — load from stored signing key bytes
/// - [`AgentIdentity::rotate`] — generate a new keypair, returning the old identity
///   for a transition period
/// - [`AgentIdentity::revoke`] — produce a signed revocation statement
/// - [`AgentIdentity::is_expired`] — check if the current credential is expired
pub struct AgentIdentity {
    spiffe_id: SpiffeId,
    signing_key: lupine::sign::HybridSigningKey65,
    credential: PqcCredential,
}

impl AgentIdentity {
    /// Generate a fresh agent identity with a new PQC keypair.
    ///
    /// The credential is valid for [`DEFAULT_VALIDITY_DAYS`] days from now.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSpiffeId`] if the SPIFFE ID is malformed, or
    /// [`Error::Crypto`] if key generation fails.
    pub fn new(trust_domain: &str, workload_id: &str) -> Result<Self> {
        let spiffe_id = SpiffeId::new(trust_domain, workload_id)?;
        Self::generate_for(spiffe_id)
    }

    /// Load an agent identity from a stored signing key.
    ///
    /// `spiffe_id_str` is parsed as a SPIFFE URI. `signing_key_bytes` must be
    /// in the format produced by [`AgentIdentity::signing_key_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSpiffeId`] if the SPIFFE ID is malformed, or
    /// [`Error::Crypto`] if the signing key bytes are invalid.
    pub fn from_stored(spiffe_id_str: &str, signing_key_bytes: &[u8]) -> Result<Self> {
        let spiffe_id = SpiffeId::parse(spiffe_id_str)?;
        let signing_key = lupine::sign::HybridSigningKey65::from_bytes(signing_key_bytes)?;
        let verifying_key = signing_key.verifying_key();
        let verifying_key_bytes = verifying_key.to_bytes();
        let now = Utc::now();
        let credential = PqcCredential {
            spiffe_id: spiffe_id.clone(),
            algo: CREDENTIAL_ALGO_V1,
            verifying_key_bytes,
            created_at: now,
            expires_at: now + Duration::days(DEFAULT_VALIDITY_DAYS),
        };
        Ok(AgentIdentity {
            spiffe_id,
            signing_key,
            credential,
        })
    }

    /// Return a reference to this identity's SPIFFE ID.
    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Return a clone of this identity's shareable [`PqcCredential`].
    pub fn credential(&self) -> PqcCredential {
        self.credential.clone()
    }

    /// Return the raw signing key bytes (secret material — store securely).
    pub fn signing_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes()
    }

    /// Sign `data` with the agent's PQC signing key.
    ///
    /// Returns the serialized composite signature bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if signing fails.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        lupine::easy::sign(&self.signing_key, data).map_err(|_e| {
            Error::Crypto(lupine_core::Error::Signing)
        })
    }

    /// Verify a signature over `data` using this identity's verifying key.
    ///
    /// Returns `true` if the signature is valid, `false` if it is not.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the signature bytes are structurally invalid.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let vk = self.signing_key.verifying_key();
        lupine::easy::verify(&vk, data, signature).map_err(|_e| {
            Error::Crypto(lupine_core::Error::Verification)
        })
    }

    /// Verify a peer's credential using the peer's own embedded verifying key.
    ///
    /// This checks that the credential is structurally valid (not expired) and
    /// that we can deserialize the verifying key. It does NOT verify a
    /// chain-of-trust — that is the job of [`crate::delegation::DelegationChain`].
    ///
    /// Returns `Ok(())` if the credential is current and well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the verifying key bytes are invalid, or
    /// [`Error::ChainVerificationFailed`] if the credential is expired.
    pub fn verify_peer(peer_credential: &PqcCredential) -> Result<()> {
        if peer_credential.is_expired() {
            return Err(Error::ChainVerificationFailed(format!(
                "peer credential for {} is expired",
                peer_credential.spiffe_id
            )));
        }
        // Validate we can deserialize the verifying key.
        lupine::sign::HybridVerifyingKey65::from_bytes(&peer_credential.verifying_key_bytes)?;
        Ok(())
    }

    /// Check whether this identity's credential has expired.
    pub fn is_expired(&self) -> bool {
        self.credential.is_expired()
    }

    /// Rotate the keypair: generate a new identity with the same SPIFFE ID,
    /// returning the old identity for use during a transition period.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if key generation fails.
    pub fn rotate(self) -> Result<(AgentIdentity, AgentIdentity)> {
        let new_identity = Self::generate_for(self.spiffe_id.clone())?;
        Ok((new_identity, self))
    }

    /// Produce a signed revocation statement for the current credential.
    ///
    /// The statement contains the credential bytes and is signed by the
    /// current signing key, so verifiers can confirm the revocation is
    /// authentic (the agent itself is asserting the credential is revoked).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if credential serialization fails,
    /// or [`Error::Crypto`] if signing fails.
    pub fn revoke(&self) -> Result<RevocationStatement> {
        let cred_bytes = self.credential.to_bytes()?;
        let revoked_at = Utc::now();
        let ts_secs = revoked_at.timestamp().to_le_bytes();
        let mut to_sign = cred_bytes.clone();
        to_sign.extend_from_slice(&ts_secs);
        let signature = self.sign(&to_sign)?;
        Ok(RevocationStatement {
            target_credential_bytes: cred_bytes,
            revoked_at,
            signature,
        })
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn generate_for(spiffe_id: SpiffeId) -> Result<Self> {
        let keypair = lupine::easy::generate_keys().map_err(|_| {
            Error::Crypto(lupine_core::Error::KeyGeneration)
        })?;
        let verifying_key_bytes = keypair.sign_pk.to_bytes();
        let now = Utc::now();
        let credential = PqcCredential {
            spiffe_id: spiffe_id.clone(),
            algo: CREDENTIAL_ALGO_V1,
            verifying_key_bytes,
            created_at: now,
            expires_at: now + Duration::days(DEFAULT_VALIDITY_DAYS),
        };
        Ok(AgentIdentity {
            spiffe_id,
            signing_key: keypair.sign_sk,
            credential,
        })
    }
}

impl fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("spiffe_id", &self.spiffe_id)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

// ── File I/O helpers ──────────────────────────────────────────────────────────

/// Save signing key bytes to a file, enforcing 0600 permissions.
///
/// On Unix, the file is created with mode 0600. On non-Unix platforms,
/// the file is written without permission enforcement (a warning is logged).
///
/// # Errors
///
/// Returns [`Error::IoError`] if the file cannot be created or written.
pub fn save_signing_key(path: &std::path::Path, key_bytes: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(key_bytes)?;
    }

    #[cfg(not(unix))]
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.write_all(key_bytes)?;
    }

    Ok(())
}

/// Load signing key bytes from a file, refusing if permissions are wider than 0600.
///
/// On Unix, checks that the file mode does not include group/other read bits.
/// On non-Unix platforms, skips the permission check.
///
/// # Errors
///
/// Returns [`Error::InsecureKeyPermissions`] if Unix permissions are too wide,
/// or [`Error::IoError`] if the file cannot be read.
pub fn load_signing_key(path: &std::path::Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        // Mode bits: mask off type bits, check that group+other read/write/exec are clear.
        // 0o177 = 0b01111111 — any bit in group/other position means too-wide.
        if meta.mode() & 0o177 != 0 {
            return Err(Error::InsecureKeyPermissions);
        }
    }

    Ok(std::fs::read(path)?)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // All tests that touch ML-DSA need a large stack.
    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── SpiffeId ──────────────────────────────────────────────────────────────

    #[test]
    fn spiffe_id_parse_valid() {
        let id = SpiffeId::parse("spiffe://example.com/agent/worker").unwrap();
        assert_eq!(id.trust_domain(), "example.com");
        assert_eq!(id.workload_path(), "/agent/worker");
        assert_eq!(id.as_str(), "spiffe://example.com/agent/worker");
    }

    #[test]
    fn spiffe_id_new_builds_uri() {
        let id = SpiffeId::new("corp.internal", "orchestrator/main").unwrap();
        assert_eq!(id.as_str(), "spiffe://corp.internal/orchestrator/main");
        assert_eq!(id.trust_domain(), "corp.internal");
        assert_eq!(id.workload_path(), "/orchestrator/main");
    }

    #[test]
    fn spiffe_id_display() {
        let id = SpiffeId::new("example.com", "agent/1").unwrap();
        assert_eq!(id.to_string(), "spiffe://example.com/agent/1");
    }

    #[test]
    fn spiffe_id_reject_no_prefix() {
        assert!(SpiffeId::parse("http://example.com/agent").is_err());
        assert!(SpiffeId::parse("example.com/agent").is_err());
    }

    #[test]
    fn spiffe_id_reject_empty_trust_domain() {
        assert!(SpiffeId::parse("spiffe:///agent").is_err());
        assert!(SpiffeId::parse("spiffe://").is_err());
    }

    #[test]
    fn spiffe_id_reject_empty_path() {
        assert!(SpiffeId::parse("spiffe://example.com").is_err());
        assert!(SpiffeId::parse("spiffe://example.com/").is_err());
    }

    #[test]
    fn spiffe_id_reject_query_and_fragment() {
        assert!(SpiffeId::parse("spiffe://example.com/agent?x=1").is_err());
        assert!(SpiffeId::parse("spiffe://example.com/agent#frag").is_err());
    }

    #[test]
    fn spiffe_id_reject_invalid_trust_domain_chars() {
        // Underscore not allowed in trust domain
        assert!(SpiffeId::parse("spiffe://bad_domain/agent").is_err());
        // Space not allowed
        assert!(SpiffeId::parse("spiffe://bad domain/agent").is_err());
    }

    #[test]
    fn spiffe_id_from_str() {
        let id: SpiffeId = "spiffe://example.com/foo/bar".parse().unwrap();
        assert_eq!(id.trust_domain(), "example.com");
    }

    #[test]
    fn spiffe_id_serialize_roundtrip() {
        let id = SpiffeId::new("example.com", "agent/1").unwrap();
        let bytes = bincode::serialize(&id).unwrap();
        let id2: SpiffeId = bincode::deserialize(&bytes).unwrap();
        assert_eq!(id, id2);
    }

    // ── AgentIdentity ─────────────────────────────────────────────────────────

    #[test]
    fn agent_identity_new_and_sign_verify() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let data = b"hello okami";
            let sig = identity.sign(data).unwrap();
            assert!(identity.verify(data, &sig).unwrap());
        });
    }

    #[test]
    fn agent_identity_wrong_data_fails_verify() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let sig = identity.sign(b"original").unwrap();
            assert!(!identity.verify(b"tampered", &sig).unwrap());
        });
    }

    #[test]
    fn agent_identity_credential_is_not_expired_initially() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            assert!(!identity.is_expired());
            let cred = identity.credential();
            assert!(!cred.is_expired());
        });
    }

    #[test]
    fn agent_identity_spiffe_id_matches() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            assert_eq!(identity.spiffe_id().as_str(), "spiffe://example.com/agent/test");
        });
    }

    #[test]
    fn agent_identity_credential_has_correct_algo() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let cred = identity.credential();
            assert_eq!(cred.algo, CREDENTIAL_ALGO_V1);
        });
    }

    #[test]
    fn agent_identity_from_stored_roundtrip() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/roundtrip").unwrap();
            let spiffe_str = identity.spiffe_id().to_string();
            let key_bytes = identity.signing_key_bytes();

            let identity2 = AgentIdentity::from_stored(&spiffe_str, &key_bytes).unwrap();
            // Both identities should produce signatures verifiable by the other's credential.
            let data = b"round-trip test";
            let sig = identity2.sign(data).unwrap();
            assert!(identity2.verify(data, &sig).unwrap());
            // Also verify that the signing key is the same by checking signatures match.
            let sig1 = identity.sign(data).unwrap();
            let sig2 = identity2.sign(data).unwrap();
            assert_eq!(sig1, sig2, "deterministic signing: same key must produce same sig");
        });
    }

    #[test]
    fn agent_identity_verify_peer_valid() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/peer").unwrap();
            let cred = identity.credential();
            AgentIdentity::verify_peer(&cred).unwrap();
        });
    }

    #[test]
    fn agent_identity_verify_peer_expired_fails() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/peer").unwrap();
            let mut cred = identity.credential();
            // Manually expire the credential.
            cred.expires_at = Utc::now() - Duration::seconds(1);
            let result = AgentIdentity::verify_peer(&cred);
            assert!(matches!(result, Err(Error::ChainVerificationFailed(_))));
        });
    }

    #[test]
    fn agent_identity_rotate() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/rotate").unwrap();
            let old_key_bytes = identity.signing_key_bytes();
            let (new_identity, old_identity) = identity.rotate().unwrap();
            // New identity has the same SPIFFE ID.
            assert_eq!(new_identity.spiffe_id(), old_identity.spiffe_id());
            // But different signing keys.
            assert_ne!(new_identity.signing_key_bytes(), old_key_bytes);
            // Old identity's key is old_key_bytes.
            assert_eq!(old_identity.signing_key_bytes(), old_key_bytes);
        });
    }

    #[test]
    fn agent_identity_revoke_produces_statement() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/revoke").unwrap();
            let stmt = identity.revoke().unwrap();
            assert!(!stmt.signature.is_empty());
            assert!(!stmt.target_credential_bytes.is_empty());
        });
    }

    // ── PqcCredential ─────────────────────────────────────────────────────────

    #[test]
    fn pqc_credential_serialize_roundtrip() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/cred").unwrap();
            let cred = identity.credential();
            let bytes = cred.to_bytes().unwrap();
            let cred2 = PqcCredential::from_bytes(&bytes).unwrap();
            assert_eq!(cred.spiffe_id, cred2.spiffe_id);
            assert_eq!(cred.algo, cred2.algo);
            assert_eq!(cred.verifying_key_bytes, cred2.verifying_key_bytes);
        });
    }

    #[test]
    fn pqc_credential_is_valid_at() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/valid").unwrap();
            let cred = identity.credential();
            assert!(cred.is_valid_at(Utc::now()));
            assert!(!cred.is_valid_at(Utc::now() + Duration::days(400)));
            assert!(!cred.is_valid_at(Utc::now() - Duration::days(1)));
        });
    }

    // ── File I/O ──────────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn save_and_load_signing_key_roundtrip() {
        with_large_stack(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("signing.key");
            let identity = AgentIdentity::new("example.com", "agent/fileio").unwrap();
            let key_bytes = identity.signing_key_bytes();
            save_signing_key(&path, &key_bytes).unwrap();
            let loaded = load_signing_key(&path).unwrap();
            assert_eq!(key_bytes, loaded);
        });
    }

    #[cfg(unix)]
    #[test]
    fn load_signing_key_rejects_wide_permissions() {
        with_large_stack(|| {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("insecure.key");
            std::fs::write(&path, b"fake key bytes").unwrap();
            // Set permissions to 0644 (world-readable).
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let result = load_signing_key(&path);
            assert!(matches!(result, Err(Error::InsecureKeyPermissions)));
        });
    }
}
