//! Audit events: tamper-evident signed event chain for agent actions.
//!
//! Provides AuditEvent, SignedAuditEvent, and chain-of-custody via SHA-256
//! hashing of previous events. Events are signed with the agent's PQC key.
//!
// @decision DEC-OKAMI-008 SHA-256 chain hash for tamper-evidence — accepted.
// Rationale: each event includes the hex SHA-256 hash of the previous
// SignedAuditEvent's bincode bytes. This makes the chain tamper-evident
// without requiring a central log server — any verifier can walk the chain
// and detect if any event was altered or deleted.
//
// @decision DEC-OKAMI-009 serde_json::Value for event details — accepted.
// Rationale: audit event details are schema-free at the SDK level. Different
// agent types emit different detail fields. JSON Value is the most flexible
// representation and integrates naturally with log aggregation tools that
// consume JSON (Datadog, Splunk, ELK). A formal JSON Schema (draft-07) is
// provided in schema/audit-event.json for monitoring tool integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::identity::{AgentIdentity, SpiffeId};

/// Version byte for audit event format. Version 1 = current format.
pub const AUDIT_EVENT_VERSION: u8 = 1;

/// Maximum byte size accepted by [`SignedAuditEvent::from_bytes`].
///
/// Events contain a `details_json` string (variable-length JSON), a PQC signature
/// (~3.3 KiB for ML-DSA-65), and metadata fields. 16 KiB allows generous JSON
/// detail blobs while blocking allocation-DoS via crafted length prefixes.
/// See `/cso` audit Finding #4.
pub const MAX_SIGNED_AUDIT_EVENT_BYTES: u64 = 16 * 1024;

// ── AuditEvent ────────────────────────────────────────────────────────────────

/// An unsigned audit event recording an agent action.
///
/// Events form a hash chain: each event includes the SHA-256 hex digest of the
/// previous [`SignedAuditEvent`]'s bincode bytes. The first event in a chain
/// uses an empty string as its `chain_hash`.
///
/// Sign an event with [`AuditEvent::sign`] to produce a [`SignedAuditEvent`].
///
/// # Bincode compatibility
///
/// `serde_json::Value` does not round-trip through bincode because bincode
/// requires typed deserialization but `Value` relies on `deserialize_any`.
/// The `details` field is therefore stored as a pre-serialized JSON string
/// (`details_json`). Use [`AuditEvent::details`] / [`AuditEvent::new`] for
/// ergonomic `serde_json::Value` access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Format version (currently 1).
    pub version: u8,
    /// When this event occurred (UTC).
    pub timestamp: DateTime<Utc>,
    /// SPIFFE ID of the agent that generated this event.
    pub agent_id: SpiffeId,
    /// Human-readable action label (e.g. "delegation.issued", "key.rotated").
    pub action: String,
    /// Structured details serialized as a JSON string (bincode-compatible).
    pub details_json: String,
    /// Hex SHA-256 of the previous SignedAuditEvent's bincode bytes.
    /// Empty string for the first event in a chain.
    pub chain_hash: String,
}

impl AuditEvent {
    /// Return the details field parsed as `serde_json::Value`.
    pub fn details(&self) -> serde_json::Value {
        serde_json::from_str(&self.details_json).unwrap_or(serde_json::Value::Null)
    }
}

impl AuditEvent {
    /// Construct a new audit event with auto-populated timestamp and version.
    ///
    /// # Parameters
    ///
    /// - `agent_id` — SPIFFE ID of the acting agent
    /// - `action` — action label (e.g. `"delegation.issued"`)
    /// - `details` — structured JSON details for this action
    /// - `previous_event_hash` — hex SHA-256 of the previous signed event bytes,
    ///   or `None` for the first event in a chain
    pub fn new(
        agent_id: SpiffeId,
        action: impl Into<String>,
        details: serde_json::Value,
        previous_event_hash: Option<String>,
    ) -> Self {
        let details_json = serde_json::to_string(&details).unwrap_or_else(|_| "null".to_string());
        AuditEvent {
            version: AUDIT_EVENT_VERSION,
            timestamp: Utc::now(),
            agent_id,
            action: action.into(),
            details_json,
            chain_hash: previous_event_hash.unwrap_or_default(),
        }
    }

    /// Sign this event with an agent identity's PQC signing key.
    ///
    /// The signature covers the bincode-serialized bytes of this `AuditEvent`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if bincode encoding fails, or
    /// [`Error::Crypto`] if signing fails.
    pub fn sign(self, identity: &AgentIdentity) -> Result<SignedAuditEvent> {
        let event_bytes = bincode::serialize(&self)
            .map_err(|e| Error::Serialization(format!("audit event serialize: {e}")))?;
        let signature = identity.sign(&event_bytes)?;
        Ok(SignedAuditEvent {
            event: self,
            signature,
        })
    }

    /// Compute the SHA-256 hex digest of this event's bincode bytes.
    ///
    /// Used to produce the `chain_hash` for the next event in a chain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if serialization fails.
    pub fn hash_hex(&self) -> Result<String> {
        let bytes = bincode::serialize(self)
            .map_err(|e| Error::Serialization(format!("audit event hash serialize: {e}")))?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
}

// ── SignedAuditEvent ──────────────────────────────────────────────────────────

/// A signed audit event: an [`AuditEvent`] plus PQC signature bytes.
///
/// Produced by [`AuditEvent::sign`]. Verify with [`SignedAuditEvent::verify`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAuditEvent {
    /// The audit event payload.
    pub event: AuditEvent,
    /// PQC signature over the bincode-serialized event bytes.
    pub signature: Vec<u8>,
}

impl SignedAuditEvent {
    /// Verify the PQC signature on this event.
    ///
    /// Serializes the event to bincode and verifies the signature against the
    /// provided verifying key.
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if not.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if the event cannot be re-serialized,
    /// or [`Error::Crypto`] if the verifying key is structurally invalid.
    pub fn verify(&self, verifying_key_bytes: &[u8]) -> Result<bool> {
        let event_bytes = bincode::serialize(&self.event)
            .map_err(|e| Error::Serialization(format!("audit event serialize: {e}")))?;
        let vk = lupine::sign::HybridVerifyingKey65::from_bytes(verifying_key_bytes)?;
        // lupine::easy::verify returns Err for structurally malformed signature bytes,
        // or Ok(false) for a valid structure that doesn't verify. Map Err to Ok(false)
        // since a tampered signature is a cryptographic failure, not a format error.
        match lupine::easy::verify(&vk, &event_bytes, &self.signature) {
            Ok(valid) => Ok(valid),
            Err(_) => Ok(false),
        }
    }

    /// Compute the SHA-256 hex digest of this signed event's bincode bytes.
    ///
    /// Pass the result as `previous_event_hash` to the next [`AuditEvent::new`]
    /// call to link the chain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if serialization fails.
    pub fn hash_hex(&self) -> Result<String> {
        let bytes = bincode::serialize(self)
            .map_err(|e| Error::Serialization(format!("signed event hash serialize: {e}")))?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }

    /// Serialize to bytes (bincode).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| Error::Serialization(format!("signed event serialize: {e}")))
    }

    /// Deserialize from bytes (bincode).
    ///
    /// Enforces a [`MAX_SIGNED_AUDIT_EVENT_BYTES`] allocation cap to prevent DoS
    /// via crafted length-prefix fields. See `/cso` audit Finding #4 (fingerprint
    /// `30a553fc`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if the input exceeds `MAX_SIGNED_AUDIT_EVENT_BYTES` or
    /// if bincode decoding fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_SIGNED_AUDIT_EVENT_BYTES {
            return Err(Error::Serialization(format!(
                "input exceeds maximum size ({} > {})",
                bytes.len(),
                MAX_SIGNED_AUDIT_EVENT_BYTES
            )));
        }
        use bincode::Options as _;
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_SIGNED_AUDIT_EVENT_BYTES)
            .deserialize(bytes)
            .map_err(|e| Error::Serialization(format!("signed event deserialize: {e}")))
    }
}

// ── AuditChain helper ─────────────────────────────────────────────────────────

/// Verify an ordered sequence of signed audit events form a valid hash chain.
///
/// Checks:
/// 1. Each event's signature is valid (using its agent's embedded credential is
///    NOT done here — callers pass the verifying key bytes per event).
/// 2. Each event's `chain_hash` matches the SHA-256 hex of the previous event's
///    bincode bytes.
/// 3. The first event has an empty `chain_hash`.
///
/// # Parameters
///
/// - `events` — ordered slice of signed events, oldest first
/// - `verifying_keys` — verifying key bytes for each event (parallel slice)
///
/// # Errors
///
/// Returns [`Error::AuditError`] if any structural check fails, or propagates
/// crypto/serialization errors.
pub fn verify_audit_chain(events: &[SignedAuditEvent], verifying_keys: &[Vec<u8>]) -> Result<()> {
    if events.len() != verifying_keys.len() {
        return Err(Error::AuditError(
            "events and verifying_keys slices must have the same length".to_string(),
        ));
    }

    let mut prev_hash: Option<String> = None;

    for (i, (event, vk_bytes)) in events.iter().zip(verifying_keys.iter()).enumerate() {
        // Verify signature.
        let valid = event.verify(vk_bytes)?;
        if !valid {
            return Err(Error::AuditError(format!(
                "signature invalid for event at index {i}"
            )));
        }

        // Chain hash check.
        match &prev_hash {
            None => {
                // First event: chain_hash must be empty.
                if !event.event.chain_hash.is_empty() {
                    return Err(Error::AuditError(
                        "first event must have empty chain_hash".to_string(),
                    ));
                }
            }
            Some(expected) => {
                if &event.event.chain_hash != expected {
                    return Err(Error::AuditError(format!(
                        "chain_hash mismatch at index {i}"
                    )));
                }
            }
        }

        prev_hash = Some(event.hash_hex()?);
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentIdentity;
    use serde_json::json;

    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── AuditEvent construction ───────────────────────────────────────────────

    #[test]
    fn audit_event_new_fields() {
        with_large_stack(|| {
            let id = SpiffeId::new("example.com", "agent/test").unwrap();
            let ev = AuditEvent::new(
                id.clone(),
                "delegation.issued",
                json!({"target": "worker/1"}),
                None,
            );
            assert_eq!(ev.version, AUDIT_EVENT_VERSION);
            assert_eq!(ev.action, "delegation.issued");
            assert_eq!(ev.chain_hash, "");
            assert_eq!(ev.agent_id, id);
        });
    }

    #[test]
    fn audit_event_with_chain_hash() {
        with_large_stack(|| {
            let id = SpiffeId::new("example.com", "agent/test").unwrap();
            let ev = AuditEvent::new(id, "key.rotated", json!({}), Some("deadbeef".to_string()));
            assert_eq!(ev.chain_hash, "deadbeef");
        });
    }

    // ── Sign and verify ───────────────────────────────────────────────────────

    #[test]
    fn audit_event_sign_and_verify() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();
            let ev = AuditEvent::new(
                identity.spiffe_id().clone(),
                "test.action",
                json!({"key": "value"}),
                None,
            );
            let signed = ev.sign(&identity).unwrap();
            assert!(signed.verify(&vk_bytes).unwrap());
        });
    }

    #[test]
    fn audit_event_verify_wrong_key_fails() {
        with_large_stack(|| {
            let signer = AgentIdentity::new("example.com", "agent/signer").unwrap();
            let other = AgentIdentity::new("example.com", "agent/other").unwrap();
            let vk_bytes = other.credential().verifying_key_bytes.clone();
            let ev = AuditEvent::new(signer.spiffe_id().clone(), "test.action", json!({}), None);
            let signed = ev.sign(&signer).unwrap();
            // Verify with wrong key should return Ok(false).
            assert!(!signed.verify(&vk_bytes).unwrap());
        });
    }

    #[test]
    fn audit_event_verify_tampered_signature_fails() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();
            let ev = AuditEvent::new(identity.spiffe_id().clone(), "test.action", json!({}), None);
            let mut signed = ev.sign(&identity).unwrap();
            signed.signature[0] ^= 0xFF;
            // Tampered signature: verify returns Ok(false).
            assert!(!signed.verify(&vk_bytes).unwrap());
        });
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn signed_event_serialize_roundtrip() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();
            let ev = AuditEvent::new(
                identity.spiffe_id().clone(),
                "test.action",
                json!({"round": "trip"}),
                None,
            );
            let signed = ev.sign(&identity).unwrap();
            let bytes = signed.to_bytes().unwrap();
            let signed2 = SignedAuditEvent::from_bytes(&bytes).unwrap();
            assert_eq!(signed.event.action, signed2.event.action);
            assert!(signed2.verify(&vk_bytes).unwrap());
        });
    }

    // ── Hash chain ────────────────────────────────────────────────────────────

    #[test]
    fn audit_event_hash_hex_is_64_chars() {
        with_large_stack(|| {
            let id = SpiffeId::new("example.com", "agent/test").unwrap();
            let ev = AuditEvent::new(id, "test.action", json!({}), None);
            let h = ev.hash_hex().unwrap();
            assert_eq!(h.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
        });
    }

    #[test]
    fn signed_event_hash_hex_is_64_chars() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let ev = AuditEvent::new(identity.spiffe_id().clone(), "test.action", json!({}), None);
            let signed = ev.sign(&identity).unwrap();
            let h = signed.hash_hex().unwrap();
            assert_eq!(h.len(), 64);
        });
    }

    #[test]
    fn audit_chain_verify_valid_chain() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();

            let ev1 = AuditEvent::new(identity.spiffe_id().clone(), "action.one", json!({}), None);
            let signed1 = ev1.sign(&identity).unwrap();
            let hash1 = signed1.hash_hex().unwrap();

            let ev2 = AuditEvent::new(
                identity.spiffe_id().clone(),
                "action.two",
                json!({}),
                Some(hash1),
            );
            let signed2 = ev2.sign(&identity).unwrap();

            verify_audit_chain(&[signed1, signed2], &[vk_bytes.clone(), vk_bytes]).unwrap();
        });
    }

    #[test]
    fn audit_chain_verify_tampered_chain_hash_rejected() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();

            let ev1 = AuditEvent::new(identity.spiffe_id().clone(), "action.one", json!({}), None);
            let signed1 = ev1.sign(&identity).unwrap();

            // Use wrong hash for ev2.
            let ev2 = AuditEvent::new(
                identity.spiffe_id().clone(),
                "action.two",
                json!({}),
                Some(
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ),
            );
            let signed2 = ev2.sign(&identity).unwrap();

            let result = verify_audit_chain(&[signed1, signed2], &[vk_bytes.clone(), vk_bytes]);
            assert!(matches!(result, Err(Error::AuditError(_))));
        });
    }

    #[test]
    fn audit_chain_first_event_nonempty_hash_rejected() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();

            // First event with non-empty chain_hash — invalid.
            let ev = AuditEvent::new(
                identity.spiffe_id().clone(),
                "action.one",
                json!({}),
                Some("notempty".to_string()),
            );
            let signed = ev.sign(&identity).unwrap();
            let result = verify_audit_chain(&[signed], &[vk_bytes]);
            assert!(matches!(result, Err(Error::AuditError(_))));
        });
    }

    #[test]
    fn audit_chain_mismatched_lengths_rejected() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();
            let ev = AuditEvent::new(identity.spiffe_id().clone(), "action.one", json!({}), None);
            let signed = ev.sign(&identity).unwrap();
            // Two events but one key — mismatch.
            let result = verify_audit_chain(&[signed], &[vk_bytes.clone(), vk_bytes]);
            assert!(matches!(result, Err(Error::AuditError(_))));
        });
    }

    #[test]
    fn audit_event_details_arbitrary_json() {
        with_large_stack(|| {
            let identity = AgentIdentity::new("example.com", "agent/test").unwrap();
            let vk_bytes = identity.credential().verifying_key_bytes.clone();
            let details = json!({
                "nested": {"key": "value"},
                "array": [1, 2, 3],
                "null_field": null
            });
            let ev = AuditEvent::new(
                identity.spiffe_id().clone(),
                "complex.event",
                details.clone(),
                None,
            );
            let signed = ev.sign(&identity).unwrap();
            assert!(signed.verify(&vk_bytes).unwrap());
            assert_eq!(signed.event.details(), details);
        });
    }

    // ── Security: allocation-DoS rejection ────────────────────────────────────

    /// Feeding a payload whose first 8 bytes are 0xFF (a u64 length prefix of
    /// ~18 exabytes) to SignedAuditEvent::from_bytes must return Err, not panic.
    /// Regression test for /cso Finding #4 (fingerprint `30a553fc`).
    #[test]
    fn signed_audit_event_from_bytes_rejects_oversized_length_prefix() {
        let mut crafted = vec![0xFFu8; 8];
        crafted.extend_from_slice(&[0u8; 16]);
        let result = SignedAuditEvent::from_bytes(&crafted);
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
