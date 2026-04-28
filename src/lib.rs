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
//! | [`error`] | Unified [`enum@Error`] type and [`Result`] alias |
//! | [`identity`] | [`identity::AgentIdentity`], [`identity::SpiffeId`], [`identity::PqcCredential`] |
//! | [`delegation`] | [`delegation::DelegationToken`], [`delegation::DelegationChain`], [`delegation::Capability`] |
//! | [`audit`] | [`audit::AuditEvent`], [`audit::SignedAuditEvent`], audit chain verification |
//!
//! @decision DEC-OKAMI-020
//! @title Compile-enforced public API documentation coverage
//! @status accepted
//! @rationale Once published to crates.io (PR-1, issue #12), every `pub`
//!   symbol becomes a stable contract that downstream code can pin against.
//!   Undocumented or under-documented public items are a maintenance liability
//!   — they force consumers to read source, and they let API drift slip into
//!   releases without anyone noticing. `#![deny(missing_docs)]` at the crate
//!   root makes documentation gaps a compile error, not a code-review nice-to-
//!   have. The bar (top-level summary on all pub items; `# Errors` on every
//!   `Result`-returning function; `# Examples` on flagship types and their
//!   primary methods) is enforced partly by the compiler (`missing_docs`) and
//!   partly by `cargo test --doc` (every example must compile and run).
//!   The companion lint `#![deny(rustdoc::broken_intra_doc_links)]` makes
//!   ambiguous or stale doc references a build error too — without it, the
//!   only signal would be a `cargo doc` warning easy to overlook.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod audit;
pub mod delegation;
pub mod error;
pub mod identity;

pub use error::{Error, Result};
