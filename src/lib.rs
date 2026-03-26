//! Okami — Post-quantum cryptographic identity for AI agents.
//!
//! This crate provides SPIFFE-based agent identity with hybrid PQC cryptography
//! (Ed25519 + ML-DSA-65), OAuth-style delegation tokens, and tamper-evident
//! audit events. It builds on the [lupine-pqc] PQC library.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use okami::identity::AgentIdentity;
//! use okami::delegation::{Capability, DelegationToken};
//! use std::time::Duration;
//!
//! // Create two agent identities.
//! let orchestrator = AgentIdentity::new("example.com", "orchestrator").unwrap();
//! let worker_id = okami::identity::SpiffeId::new("example.com", "worker/1").unwrap();
//!
//! // Issue a delegation token.
//! let scopes = vec![Capability::new("read:db").unwrap()];
//! let token = DelegationToken::issue(
//!     &orchestrator,
//!     worker_id,
//!     scopes.clone(),
//!     &scopes,
//!     Duration::from_secs(3600),
//!     None,
//! ).unwrap();
//!
//! // Verify the token.
//! token.verify(None).unwrap();
//! ```
//!
//! # Modules
//!
//! | Module | Contents |
//! |--------|---------|
//! | [`error`] | Unified [`Error`] type and [`Result`] alias |
//! | [`identity`] | [`AgentIdentity`], [`SpiffeId`], [`PqcCredential`] |
//! | [`delegation`] | [`DelegationToken`], [`DelegationChain`], [`Capability`] |
//! | [`audit`] | [`AuditEvent`], [`SignedAuditEvent`], audit chain verification |

pub mod audit;
pub mod delegation;
pub mod error;
pub mod identity;

pub use error::{Error, Result};
