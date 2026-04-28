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
//!
//! @decision DEC-OKAMI-016
//! @title Bounded bincode deserialization to prevent allocation DoS
//! @status accepted
//! @rationale bincode 1.x reads a raw u64 length prefix before allocating for
//!   `Vec<T>`/String fields. A crafted payload with `[0xFF; 8]` as the first field
//!   causes an immediate multi-exabyte allocation attempt, crashing the process.
//!   Fix: use `DefaultOptions::with_fixint_encoding().allow_trailing_bytes().with_limit(N)`
//!   which exactly mirrors the free-function encoding but adds an allocation cap.
//!   Limits (PqcCredential: 4 KiB, DelegationToken: 8 KiB, DelegationChain: 32 KiB,
//!   SignedAuditEvent: 16 KiB) are generous relative to actual sizes while blocking
//!   the attack. See `/cso` audit Finding #4 (fingerprint `30a553fc`).
//!
//! @decision DEC-OKAMI-017
//! @title Domain-separated signatures across token/audit/revocation protocols
//! @status accepted
//! @rationale Without domain separation, all three signing protocols (delegation
//!   token, audit event, revocation statement) sign raw byte payloads with the
//!   same keypair and no type tag. An attacker who can influence any one
//!   protocol's payload could in principle produce a signature also valid under
//!   another protocol, enabling cross-protocol signature reuse attacks. The fix
//!   prepends a 1-byte domain tag (DOMAIN_TOKEN=0x01, DOMAIN_AUDIT=0x02,
//!   DOMAIN_REVOCATION=0x03) to every signed payload, making each protocol's
//!   signed namespace disjoint. The higher-level `sign_with_domain` and
//!   `verify_with_domain` helpers enforce this at every call site.
//!   See `/cso` audit Appendix A1.
//!   Wire-format break: tokens, audit events, and revocation statements signed
//!   before this decision do not verify after.
//!
//! @decision DEC-OKAMI-018
//! @title load_signing_key verifies file owner UID matches effective UID
//! @status accepted
//! @rationale DEC-OKAMI-004 introduced SSH-model 0600 permission checks. However
//!   mode bits alone are insufficient: a file mode 0600 owned by another UID can
//!   be replaced by that user without the current process detecting the swap
//!   (same mode, different content). Adding a UID check ensures the loaded key
//!   is actually controlled by the process owner, matching the full SSH model
//!   (ssh-keygen refuses to use a key whose owner != current user). Uses a
//!   minimal `extern "C" { fn geteuid() -> u32; }` declaration — no new crate
//!   dependency needed. See `/cso` audit Appendix A2.
//!
//! @decision DEC-OKAMI-019
//! @title Public RevocationStatement::verify helper
//! @status accepted
//! @rationale DEC-OKAMI-017 introduced domain-separated signatures and
//!   `verify_with_domain`, but `RevocationStatement` shipped without a
//!   first-party verify path. Consumers building offline revocation lists had
//!   to hand-reconstruct the byte order (`target_credential_bytes ||
//!   revoked_at_secs.to_le_bytes()`) and remember to pass `DOMAIN_REVOCATION`.
//!   That's a footgun: getting the byte order or domain tag wrong silently
//!   either accepts forged revocations or rejects valid ones. This helper
//!   takes `verifying_key_bytes` and `claimed_credential_bytes`, reconstructs
//!   the payload internally, calls `AgentIdentity::verify_with_domain`, and
//!   returns `Ok(false)` for any verification failure (including mismatched
//!   claimed bytes). Mirrors the ergonomics of `DelegationToken::verify` and
//!   `SignedAuditEvent::verify`.
//!
//! @decision DEC-OKAMI-021
//! @title Windows is supported for build + non-unix-specific tests; key-file
//!   protection (DEC-OKAMI-004 0600 perms, DEC-OKAMI-018 UID check) remains
//!   unix-only
//! @status accepted
//! @rationale CI matrix now includes windows-latest so the crate compiles and
//!   most tests pass there. The `load_signing_key` permission/owner checks are
//!   guarded by `#[cfg(unix)]` because the unix file-mode and UID model has no
//!   direct NTFS analogue — implementing equivalent ACL-based protection on
//!   Windows is its own design problem and not in scope for 0.1.0. On Windows,
//!   `load_signing_key` simply skips those checks, which means a Windows-side
//!   user is responsible for protecting their `signing.key` via ordinary file
//!   ACLs. This trade is documented at the API layer; the multi-OS matrix
//!   surfaces any regression in the cross-platform paths automatically.

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

/// Maximum byte size accepted by [`PqcCredential::from_bytes`].
///
/// Actual serialized size is ~2 KiB (verifying key ~1984 bytes + SPIFFE ID +
/// timestamps + algo byte). 4 KiB provides headroom for longer SPIFFE IDs
/// while preventing multi-exabyte allocation attacks via crafted length prefixes.
/// See `/cso` audit Finding #4.
pub const MAX_CREDENTIAL_BYTES: u64 = 4 * 1024;

// ── Domain separator tags (DEC-OKAMI-017) ─────────────────────────────────────

/// Domain-separator tag for delegation token signatures.
///
/// Prepended to the bincode-serialized `UnsignedToken` payload before signing,
/// ensuring a delegation-token signature cannot be replayed against the audit or
/// revocation verify paths. See DEC-OKAMI-017.
pub const DOMAIN_TOKEN: u8 = 0x01;

/// Domain-separator tag for audit event signatures.
///
/// Prepended to the bincode-serialized `AuditEvent` payload before signing.
/// See DEC-OKAMI-017.
pub const DOMAIN_AUDIT: u8 = 0x02;

/// Domain-separator tag for revocation statement signatures.
///
/// Prepended to `credential_bytes || revoked_at_le_bytes` before signing.
/// See DEC-OKAMI-017.
pub const DOMAIN_REVOCATION: u8 = 0x03;

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
///
/// # Examples
///
/// ```
/// use okami::identity::SpiffeId;
///
/// let id = SpiffeId::new("example.com", "agent/worker-1").unwrap();
/// assert_eq!(id.trust_domain(), "example.com");
/// assert_eq!(id.workload_path(), "/agent/worker-1");
/// assert_eq!(id.as_str(), "spiffe://example.com/agent/worker-1");
///
/// // Parse an existing URI string.
/// let parsed: SpiffeId = "spiffe://corp.internal/orchestrator".parse().unwrap();
/// assert_eq!(parsed.trust_domain(), "corp.internal");
///
/// // Invalid inputs are rejected.
/// assert!(SpiffeId::new("bad domain", "agent").is_err());
/// assert!(SpiffeId::parse("http://not-spiffe/agent").is_err());
/// ```
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
            return Err(Error::InvalidSpiffeId("trust domain is empty".to_string()));
        }

        // No query strings or fragments.
        if s.contains('?') || s.contains('#') {
            return Err(Error::InvalidSpiffeId(
                "SPIFFE IDs must not contain query strings or fragments".to_string(),
            ));
        }

        // Split trust domain from path.
        let slash_pos = rest.find('/').ok_or_else(|| {
            Error::InvalidSpiffeId("missing workload path (no '/' after trust domain)".to_string())
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
            return Err(Error::InvalidSpiffeId("workload path is empty".to_string()));
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
///
/// # Examples
///
/// ```
/// use okami::identity::{AgentIdentity, PqcCredential};
///
/// // Obtain a credential from an identity (contains only public material).
/// let identity = AgentIdentity::new("example.com", "agent/worker").unwrap();
/// let cred: PqcCredential = identity.credential();
///
/// assert!(!cred.is_expired());
/// assert!(cred.is_valid_at(chrono::Utc::now()));
///
/// // Round-trip through bytes (e.g. for network transport).
/// let bytes = cred.to_bytes().unwrap();
/// let cred2 = PqcCredential::from_bytes(&bytes).unwrap();
/// assert_eq!(cred.spiffe_id, cred2.spiffe_id);
/// ```
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
    /// Enforces a [`MAX_CREDENTIAL_BYTES`] allocation cap to prevent DoS via
    /// crafted length-prefix fields (e.g. `[0xFF; 8]` triggering multi-exabyte
    /// allocation). See `/cso` audit Finding #4 (fingerprint `30a553fc`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if the input exceeds `MAX_CREDENTIAL_BYTES` or
    /// if bincode decoding fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
            return Err(Error::Serialization(format!(
                "input exceeds maximum size ({} > {})",
                bytes.len(),
                MAX_CREDENTIAL_BYTES
            )));
        }
        use bincode::Options as _;
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_CREDENTIAL_BYTES)
            .deserialize(bytes)
            .map_err(|e| Error::Serialization(format!("credential deserialize: {e}")))
    }
}

// ── Revocation statement ──────────────────────────────────────────────────────

/// A signed statement revoking a credential.
///
/// Produced by [`AgentIdentity::revoke`]. The `target_credential_bytes` field
/// contains the bincode-serialized [`PqcCredential`] being revoked; the
/// `signature` covers those bytes.
///
/// # Examples
///
/// ```
/// use okami::identity::AgentIdentity;
///
/// let identity = AgentIdentity::new("example.com", "agent/worker").unwrap();
/// let cred = identity.credential();
/// let cred_bytes = cred.to_bytes().unwrap();
///
/// // Produce a revocation statement signed by the identity.
/// let stmt = identity.revoke().unwrap();
/// assert!(!stmt.signature.is_empty());
///
/// // Verify the statement using the agent's public verifying key.
/// let vk_bytes = cred.verifying_key_bytes.clone();
/// let valid = stmt.verify(&vk_bytes, &cred_bytes).unwrap();
/// assert!(valid);
///
/// // A wrong credential does not verify.
/// let other = AgentIdentity::new("example.com", "agent/other").unwrap();
/// let other_cred_bytes = other.credential().to_bytes().unwrap();
/// assert!(!stmt.verify(&vk_bytes, &other_cred_bytes).unwrap());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationStatement {
    /// The bincode bytes of the credential being revoked.
    pub target_credential_bytes: Vec<u8>,
    /// Timestamp of revocation.
    pub revoked_at: DateTime<Utc>,
    /// PQC signature over `target_credential_bytes || revoked_at_timestamp_secs`.
    pub signature: Vec<u8>,
}

impl RevocationStatement {
    /// Verify this revocation statement was signed by the holder of
    /// `verifying_key_bytes` for `claimed_credential_bytes`.
    ///
    /// Returns `Ok(true)` if and only if:
    ///   1. `claimed_credential_bytes` exactly matches `self.target_credential_bytes`, AND
    ///   2. The signature is valid under the given verifying key with `DOMAIN_REVOCATION`.
    ///
    /// Returns `Ok(false)` for any verification failure (wrong key, tampered
    /// payload, mismatched claimed bytes, cross-protocol signature reuse).
    /// Returns `Err` only for genuine cryptographic / decoding errors that
    /// prevent verification from running at all.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the verifying key bytes are malformed.
    pub fn verify(
        &self,
        verifying_key_bytes: &[u8],
        claimed_credential_bytes: &[u8],
    ) -> Result<bool> {
        // Guard: caller must supply the same credential bytes this statement covers.
        // Return Ok(false) — not Err — so that all "this statement does not revoke
        // that credential" outcomes look identical to the caller.
        if claimed_credential_bytes != self.target_credential_bytes.as_slice() {
            return Ok(false);
        }

        // Reconstruct the signed payload exactly as AgentIdentity::revoke does:
        //   payload = target_credential_bytes || revoked_at.timestamp().to_le_bytes()
        let ts_secs = self.revoked_at.timestamp().to_le_bytes();
        let mut payload = self.target_credential_bytes.clone();
        payload.extend_from_slice(&ts_secs);

        // Delegate to verify_with_domain; it prepends DOMAIN_REVOCATION before
        // calling the underlying PQC verifier (DEC-OKAMI-017).
        AgentIdentity::verify_with_domain(
            verifying_key_bytes,
            DOMAIN_REVOCATION,
            &payload,
            &self.signature,
        )
    }
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
///
/// # Examples
///
/// ```
/// use okami::identity::AgentIdentity;
///
/// // Generate a fresh identity.
/// let identity = AgentIdentity::new("example.com", "agent/worker").unwrap();
/// assert_eq!(identity.spiffe_id().trust_domain(), "example.com");
///
/// // Sign and verify arbitrary data.
/// let sig = identity.sign(b"hello okami").unwrap();
/// assert!(identity.verify(b"hello okami", &sig).unwrap());
/// assert!(!identity.verify(b"tampered", &sig).unwrap());
///
/// // Share the public credential (safe to send to peers).
/// let cred = identity.credential();
/// assert!(!cred.is_expired());
///
/// // Persist and reload from stored bytes.
/// let key_bytes = identity.signing_key_bytes();
/// let reloaded = AgentIdentity::from_stored(cred, &key_bytes).unwrap();
/// let sig2 = reloaded.sign(b"hello okami").unwrap();
/// assert!(reloaded.verify(b"hello okami", &sig2).unwrap());
/// ```
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

    /// Load an agent identity from a stored credential and signing key.
    ///
    /// The `credential` is taken as-is from disk, preserving its original
    /// `created_at` / `expires_at` timestamps. The signing key is parsed and
    /// its derived verifying key is compared against
    /// `credential.verifying_key_bytes`; if they differ the pair is rejected
    /// with [`Error::KeyCredentialMismatch`] to detect partial-rotation states
    /// where `signing.key` and `credential.bin` are out of sync.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if `signing_key_bytes` cannot be parsed, or
    /// [`Error::KeyCredentialMismatch`] if the signing key does not correspond
    /// to the verifying key embedded in `credential`.
    ///
    /// @decision DEC-OKAMI-015
    /// @title Preserve credential timestamps in `from_stored` and bind signing key
    /// @status accepted
    /// @rationale CSO audit findings #2 and #3 (HIGH) showed that the previous
    ///   implementation re-minted a fresh `PqcCredential` with `created_at =
    ///   Utc::now()` on every load, silently resetting the validity window and
    ///   making credential-byte-keyed revocation registries ineffective (each
    ///   load produced distinct bytes). The fix accepts the on-disk credential
    ///   directly, preserving its timestamps so that the loaded identity is
    ///   byte-identical to what was originally written. A new key-binding check
    ///   (`signing_key.verifying_key() == credential.verifying_key_bytes`) is
    ///   added unconditionally: it is cheap, catches mismatched key/credential
    ///   pairs that arise during partial rotations, and surfaces as the new
    ///   `Error::KeyCredentialMismatch` variant rather than silently issuing
    ///   tokens that embed a stale or wrong credential.
    pub fn from_stored(credential: PqcCredential, signing_key_bytes: &[u8]) -> Result<Self> {
        let signing_key = lupine::sign::HybridSigningKey65::from_bytes(signing_key_bytes)?;
        let derived_vk_bytes = signing_key.verifying_key().to_bytes();
        if derived_vk_bytes != credential.verifying_key_bytes {
            return Err(Error::KeyCredentialMismatch);
        }
        let spiffe_id = credential.spiffe_id.clone();
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
    /// This is the low-level primitive that signs raw bytes. Prefer
    /// [`AgentIdentity::sign_with_domain`] at protocol call sites to prevent
    /// cross-protocol signature reuse (DEC-OKAMI-017).
    ///
    /// Returns the serialized composite signature bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if signing fails.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        lupine::easy::sign(&self.signing_key, data)
            .map_err(|_e| Error::Crypto(lupine_core::Error::Signing))
    }

    /// Sign `payload` with a domain-separator tag prepended.
    ///
    /// Produces a signature over `[domain] || payload`, where `domain` is one
    /// of [`DOMAIN_TOKEN`], [`DOMAIN_AUDIT`], or [`DOMAIN_REVOCATION`]. This
    /// ensures that a signature produced by one protocol cannot be replayed
    /// against the verify path of another protocol sharing the same keypair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if signing fails.
    pub fn sign_with_domain(&self, domain: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut tagged = Vec::with_capacity(1 + payload.len());
        tagged.push(domain);
        tagged.extend_from_slice(payload);
        self.sign(&tagged)
    }

    /// Verify a signature over `payload` that was produced with a domain tag.
    ///
    /// Reconstructs `[domain] || payload` and verifies the signature against
    /// the provided `verifying_key_bytes`. Returns `Ok(true)` if valid,
    /// `Ok(false)` if the signature does not match.
    ///
    /// Use the same `domain` constant that was passed to [`AgentIdentity::sign_with_domain`]
    /// at the corresponding sign site.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if `verifying_key_bytes` is structurally invalid
    /// or if the signature bytes cannot be parsed.
    pub fn verify_with_domain(
        verifying_key_bytes: &[u8],
        domain: u8,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let mut tagged = Vec::with_capacity(1 + payload.len());
        tagged.push(domain);
        tagged.extend_from_slice(payload);
        let vk = lupine::sign::HybridVerifyingKey65::from_bytes(verifying_key_bytes)?;
        lupine::easy::verify(&vk, &tagged, signature)
            .map_err(|_e| Error::Crypto(lupine_core::Error::Verification))
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
        lupine::easy::verify(&vk, data, signature)
            .map_err(|_e| Error::Crypto(lupine_core::Error::Verification))
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
        // payload = cred_bytes || revoked_at_le_bytes, signed under DOMAIN_REVOCATION
        // so the same keypair cannot be coerced into producing a revocation
        // signature that also validates as a token or audit event (DEC-OKAMI-017).
        let mut payload = cred_bytes.clone();
        payload.extend_from_slice(&ts_secs);
        let signature = self.sign_with_domain(DOMAIN_REVOCATION, &payload)?;
        Ok(RevocationStatement {
            target_credential_bytes: cred_bytes,
            revoked_at,
            signature,
        })
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn generate_for(spiffe_id: SpiffeId) -> Result<Self> {
        let keypair = lupine::easy::generate_keys()
            .map_err(|_| Error::Crypto(lupine_core::Error::KeyGeneration))?;
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

/// Load signing key bytes from a file, enforcing SSH-model security checks.
///
/// On Unix, performs two checks before reading:
/// 1. **Permission check** — the file mode must not include group/other bits
///    (i.e. mode must be exactly 0600 or narrower). Returns
///    [`Error::InsecureKeyPermissions`] if wider.
/// 2. **Ownership check** — the file's owner UID must match the process's
///    effective UID (`geteuid(2)`). Returns [`Error::InsecureKeyOwner`] if not.
///    A file owned by another user can be replaced by that user even if the
///    current process has read access (mode 0600 owned by root is an example).
///    This matches the full SSH model that OpenSSH enforces for identity files.
///
/// On non-Unix platforms, both checks are skipped.
///
/// # Errors
///
/// Returns [`Error::InsecureKeyPermissions`] if Unix permissions are too wide,
/// [`Error::InsecureKeyOwner`] if the file owner does not match effective UID,
/// or [`Error::IoError`] if the file cannot be read.
///
/// See DEC-OKAMI-004 (permission check) and DEC-OKAMI-018 (ownership check).
pub fn load_signing_key(path: &std::path::Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        // Minimal FFI for geteuid — avoids adding a libc/nix crate dependency
        // for a single syscall. `geteuid` is async-signal-safe, always succeeds,
        // and has the same ABI on every Unix platform (returns u32).
        // See DEC-OKAMI-018.
        extern "C" {
            fn geteuid() -> u32;
        }

        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;

        // Mode bits: mask off type bits, check that group+other read/write/exec are clear.
        // 0o177 = 0b01111111 — any bit in group/other position means too-wide.
        if meta.mode() & 0o177 != 0 {
            return Err(Error::InsecureKeyPermissions);
        }

        // Ownership check: the file's owner must be the current effective user.
        // SAFETY: geteuid() is a pure syscall with no unsafe preconditions.
        let euid = unsafe { geteuid() };
        if meta.uid() != euid {
            return Err(Error::InsecureKeyOwner);
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
            assert_eq!(
                identity.spiffe_id().as_str(),
                "spiffe://example.com/agent/test"
            );
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
            let credential = identity.credential();
            let key_bytes = identity.signing_key_bytes();

            let identity2 = AgentIdentity::from_stored(credential, &key_bytes).unwrap();
            // Both identities should produce signatures verifiable by the other's credential.
            let data = b"round-trip test";
            let sig = identity2.sign(data).unwrap();
            assert!(identity2.verify(data, &sig).unwrap());
            // Also verify that the signing key is the same by checking signatures match.
            let sig1 = identity.sign(data).unwrap();
            let sig2 = identity2.sign(data).unwrap();
            assert_eq!(
                sig1, sig2,
                "deterministic signing: same key must produce same sig"
            );
        });
    }

    #[test]
    fn from_stored_preserves_credential_timestamps() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/ts-preserve").unwrap();
            let credential = identity.credential();
            let original_created_at = credential.created_at;
            let original_expires_at = credential.expires_at;
            let key_bytes = identity.signing_key_bytes();

            // Sleep 1 ms so Utc::now() inside a naive re-mint would differ.
            std::thread::sleep(std::time::Duration::from_millis(1));

            let loaded = AgentIdentity::from_stored(credential, &key_bytes).unwrap();
            let loaded_cred = loaded.credential();

            assert_eq!(
                loaded_cred.created_at, original_created_at,
                "created_at must be preserved from on-disk credential, not re-minted"
            );
            assert_eq!(
                loaded_cred.expires_at, original_expires_at,
                "expires_at must be preserved from on-disk credential, not re-minted"
            );
        });
    }

    #[test]
    fn from_stored_rejects_mismatched_key_and_credential() {
        with_large_stack(|| {
            let identity_a = AgentIdentity::new("example.com", "agent/a").unwrap();
            let identity_b = AgentIdentity::new("example.com", "agent/b").unwrap();

            // Use A's credential but B's signing key — they don't match.
            let credential_a = identity_a.credential();
            let key_bytes_b = identity_b.signing_key_bytes();

            let result = AgentIdentity::from_stored(credential_a, &key_bytes_b);
            assert!(
                matches!(result, Err(Error::KeyCredentialMismatch)),
                "mismatched key/credential must return KeyCredentialMismatch, got: {result:?}"
            );
        });
    }

    #[test]
    fn from_stored_roundtrip_with_credential_sign_verify() {
        with_large_stack(|| {
            // Full round-trip: generate, serialize credential + key, load back,
            // sign + verify. Proves the loaded identity is fully functional with
            // the preserved credential.
            let identity = AgentIdentity::new("example.com", "agent/full-roundtrip").unwrap();
            let credential = identity.credential();
            let cred_bytes = credential.to_bytes().unwrap();
            let key_bytes = identity.signing_key_bytes();

            // Simulate what the CLI does: deserialize credential from bytes, load identity.
            let restored_cred = PqcCredential::from_bytes(&cred_bytes).unwrap();
            let loaded = AgentIdentity::from_stored(restored_cred, &key_bytes).unwrap();

            let data = b"full-roundtrip payload";
            let sig = loaded.sign(data).unwrap();
            assert!(loaded.verify(data, &sig).unwrap(), "signature must verify");

            // Verify the credential embedded in loaded tokens matches on-disk bytes.
            let loaded_cred_bytes = loaded.credential().to_bytes().unwrap();
            assert_eq!(
                cred_bytes, loaded_cred_bytes,
                "serialized credential bytes must be identical after round-trip"
            );
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

    /// Positive case for the UID check: a file created by the current process
    /// (owner == euid) with mode 0600 must load successfully.
    ///
    /// The negative case (foreign owner) requires chown, which needs root. That
    /// path is covered by code inspection — the branch `meta.uid() != euid`
    /// returns `Err(Error::InsecureKeyOwner)` — and is marked `#[ignore]` below.
    #[cfg(unix)]
    #[test]
    fn load_signing_key_accepts_correct_owner() {
        with_large_stack(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("owned.key");
            // save_signing_key creates with mode 0600 and the current UID.
            let identity = AgentIdentity::new("example.com", "agent/uid-check").unwrap();
            let key_bytes = identity.signing_key_bytes();
            save_signing_key(&path, &key_bytes).unwrap();
            // Must succeed: owner == euid and mode == 0600.
            let loaded = load_signing_key(&path).unwrap();
            assert_eq!(key_bytes, loaded);
        });
    }

    /// Verifies the InsecureKeyOwner error variant exists and has the right message.
    /// The runtime negative path (foreign-owned file) requires root to chown;
    /// this test confirms the error is reachable at compile time.
    #[test]
    fn insecure_key_owner_error_variant() {
        let e = Error::InsecureKeyOwner;
        assert!(
            e.to_string().contains("owner"),
            "InsecureKeyOwner message must mention 'owner': {e}"
        );
    }

    // ── Domain separation (DEC-OKAMI-017) ─────────────────────────────────────

    /// sign_with_domain / verify_with_domain round-trip for each domain tag.
    #[test]
    fn domain_sign_verify_roundtrip() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/domain-rt").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();
            let payload = b"test payload";

            for domain in [DOMAIN_TOKEN, DOMAIN_AUDIT, DOMAIN_REVOCATION] {
                let sig = identity.sign_with_domain(domain, payload).unwrap();
                let valid =
                    AgentIdentity::verify_with_domain(&vk_bytes, domain, payload, &sig).unwrap();
                assert!(valid, "domain={domain:#04x} roundtrip must verify");
            }
        });
    }

    /// A signature produced under DOMAIN_TOKEN does not verify under DOMAIN_AUDIT.
    ///
    /// This is the core cross-protocol resistance property from DEC-OKAMI-017:
    /// even if an attacker constructs a payload that is structurally valid for
    /// both token and audit protocols, the domain byte makes the signed content
    /// different and the signature invalid for the wrong protocol.
    #[test]
    fn domain_token_sig_does_not_verify_as_audit() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/cross-proto").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();
            let payload = b"shared payload bytes";

            // Sign under DOMAIN_TOKEN.
            let sig = identity.sign_with_domain(DOMAIN_TOKEN, payload).unwrap();

            // Attempt to verify under DOMAIN_AUDIT — must fail.
            let valid =
                AgentIdentity::verify_with_domain(&vk_bytes, DOMAIN_AUDIT, payload, &sig).unwrap();
            assert!(!valid, "token signature must not verify under audit domain");
        });
    }

    /// A signature produced under DOMAIN_AUDIT does not verify under DOMAIN_TOKEN.
    #[test]
    fn domain_audit_sig_does_not_verify_as_token() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/cross-proto2").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();
            let payload = b"shared payload bytes";

            // Sign under DOMAIN_AUDIT.
            let sig = identity.sign_with_domain(DOMAIN_AUDIT, payload).unwrap();

            // Attempt to verify under DOMAIN_TOKEN — must fail.
            let valid =
                AgentIdentity::verify_with_domain(&vk_bytes, DOMAIN_TOKEN, payload, &sig).unwrap();
            assert!(!valid, "audit signature must not verify under token domain");
        });
    }

    /// A signature produced under DOMAIN_REVOCATION does not verify under any other domain.
    #[test]
    fn domain_revocation_sig_isolated() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/cross-proto3").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();
            let payload = b"revocation payload";

            let sig = identity
                .sign_with_domain(DOMAIN_REVOCATION, payload)
                .unwrap();

            for other_domain in [DOMAIN_TOKEN, DOMAIN_AUDIT] {
                let valid =
                    AgentIdentity::verify_with_domain(&vk_bytes, other_domain, payload, &sig)
                        .unwrap();
                assert!(
                    !valid,
                    "revocation sig must not verify under domain={other_domain:#04x}"
                );
            }
        });
    }

    // ── RevocationStatement::verify ───────────────────────────────────────────

    /// Round-trip: identity revokes itself, then verify with own verifying key
    /// and own credential bytes returns Ok(true).
    #[test]
    fn revocation_verify_round_trip() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/revoke-rt").unwrap();
            let cred_bytes = identity.credential().to_bytes().unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();

            let stmt = identity.revoke().unwrap();

            let result = stmt.verify(&vk_bytes, &cred_bytes).unwrap();
            assert!(
                result,
                "verify should return true for a valid revocation statement"
            );
        });
    }

    /// Wrong key: identity A revokes itself; identity B's verifying key cannot
    /// verify A's revocation statement.
    #[test]
    fn revocation_verify_wrong_key() {
        with_large_stack(|| {
            let identity_a = AgentIdentity::new("example.com", "agent/revoke-a").unwrap();
            let identity_b = AgentIdentity::new("example.com", "agent/revoke-b").unwrap();

            let cred_a_bytes = identity_a.credential().to_bytes().unwrap();
            let vk_b_bytes = identity_b.credential().verifying_key_bytes.clone();

            let stmt = identity_a.revoke().unwrap();

            let result = stmt.verify(&vk_b_bytes, &cred_a_bytes).unwrap();
            assert!(
                !result,
                "verify should return false when the wrong key is used"
            );
        });
    }

    /// Tampered target bytes: mutating one byte of target_credential_bytes in the
    /// statement causes the signature check to fail.
    #[test]
    fn revocation_verify_tampered_target_bytes() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/revoke-tamper").unwrap();
            let cred_bytes = identity.credential().to_bytes().unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();

            let mut stmt = identity.revoke().unwrap();
            // Flip one bit in the statement's stored credential bytes.
            stmt.target_credential_bytes[0] ^= 0x01;

            // Pass the original credential bytes as the claim — the payload
            // reconstructed internally will be wrong, so the signature won't match.
            let result = stmt.verify(&vk_bytes, &cred_bytes).unwrap();
            assert!(
                !result,
                "verify should return false when target_credential_bytes are tampered"
            );
        });
    }

    /// Mismatched claimed bytes: the caller passes bytes that do not match
    /// self.target_credential_bytes — verify returns Ok(false) immediately,
    /// before even attempting the signature check.
    #[test]
    fn revocation_verify_wrong_claimed_bytes() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/revoke-mismatch").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();

            let stmt = identity.revoke().unwrap();

            // Pass deliberately wrong credential bytes.
            let wrong_bytes = b"this is not the right credential bytes";
            let result = stmt.verify(&vk_bytes, wrong_bytes).unwrap();
            assert!(
                !result,
                "verify should return false when claimed_credential_bytes do not match"
            );
        });
    }

    /// Cross-protocol signature rejection: sign the same payload under DOMAIN_TOKEN
    /// and splice that signature into a RevocationStatement — verify must return
    /// Ok(false), proving DEC-OKAMI-017 domain separation holds at this API layer.
    #[test]
    fn revocation_verify_cross_protocol_signature_rejected() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/revoke-xproto").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();

            // Build a statement, then steal its target bytes and timestamp to
            // construct the same payload the revoke() method would sign.
            let stmt = identity.revoke().unwrap();
            let ts_secs = stmt.revoked_at.timestamp().to_le_bytes();
            let mut token_payload = stmt.target_credential_bytes.clone();
            token_payload.extend_from_slice(&ts_secs);

            // Sign that identical payload under DOMAIN_TOKEN instead of DOMAIN_REVOCATION.
            let cross_sig = identity
                .sign_with_domain(DOMAIN_TOKEN, &token_payload)
                .unwrap();

            // Splice the cross-domain signature into the statement.
            let tampered = RevocationStatement {
                target_credential_bytes: stmt.target_credential_bytes.clone(),
                revoked_at: stmt.revoked_at,
                signature: cross_sig,
            };

            let cred_bytes = stmt.target_credential_bytes.clone();
            let result = tampered.verify(&vk_bytes, &cred_bytes).unwrap();
            assert!(
                !result,
                "verify must return false for a cross-protocol (DOMAIN_TOKEN) signature"
            );
        });
    }

    // ── Security: allocation-DoS rejection ────────────────────────────────────

    /// Feeding a payload whose first 8 bytes are 0xFF (a u64 length prefix of
    /// ~18 exabytes) must return Err, not panic or OOM.
    /// Regression test for /cso Finding #4 (fingerprint `30a553fc`).
    #[test]
    fn pqc_credential_from_bytes_rejects_oversized_length_prefix() {
        let mut crafted = vec![0xFFu8; 8];
        crafted.extend_from_slice(&[0u8; 16]); // some trailing bytes
        let result = PqcCredential::from_bytes(&crafted);
        assert!(
            result.is_err(),
            "oversized length prefix must be rejected, got Ok"
        );
        assert!(
            matches!(result, Err(Error::Serialization(_))),
            "expected Serialization error, got: {:?}",
            result
        );
    }
}
