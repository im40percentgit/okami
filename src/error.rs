//! Unified error type for the okami Agent Passport SDK.
//!
//! All okami operations surface errors through the single [`enum@Error`] enum.
//! This keeps the API simple: callers import one type and match on
//! meaningful variants without nested conversion chains.
//!
//! @decision DEC-OKAMI-001
//! @title Single error enum via thiserror
//! @status accepted
//! @rationale Mirrors the lupine-core pattern of a single unified Error enum.
//!   thiserror provides `Display` and `Error` derivations with zero boilerplate.
//!   A single enum makes `?` propagation straightforward across module
//!   boundaries without callers managing nested error types.

use thiserror::Error;

/// Errors that can arise from okami operations.
#[derive(Debug, Error)]
pub enum Error {
    /// An underlying PQC cryptographic operation failed (from lupine).
    #[error("crypto error: {0}")]
    Crypto(lupine_core::Error),

    /// A SPIFFE ID string was invalid (bad format, missing trust domain, etc).
    #[error("invalid SPIFFE ID: {0}")]
    InvalidSpiffeId(String),

    /// A delegation chain exceeds the maximum allowed depth (3).
    #[error("delegation depth limit (3) exceeded")]
    DelegationDepthExceeded,

    /// A capability scope string was invalid (empty, malformed, etc).
    #[error("invalid scope: {0}")]
    InvalidScope(String),

    /// Delegation chain verification failed.
    #[error("chain verification failed: {0}")]
    ChainVerificationFailed(String),

    /// An audit operation failed.
    #[error("audit error: {0}")]
    AuditError(String),

    /// An I/O operation failed.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Attempted to initialize an okami workspace that already exists.
    #[error("already initialized: .okami/ directory already exists")]
    AlreadyInitialized,

    /// A key file has permissions wider than 0600 and was refused to load.
    #[error("insecure key permissions: file must be mode 0600")]
    InsecureKeyPermissions,

    /// A key file is not owned by the current effective UID and was refused to load.
    ///
    /// Matches the SSH model: only the owning user should be able to possess a
    /// signing key. A file owned by another user (even if mode 0600) could be
    /// replaced by that user without the current process noticing.
    /// See `/cso` audit Appendix A2 and DEC-OKAMI-018.
    #[error("insecure key ownership: file owner does not match effective UID")]
    InsecureKeyOwner,

    /// The signing key and credential files on disk refer to different keys.
    ///
    /// This occurs when `signing.key` and `credential.bin` were generated at
    /// different times (e.g. a partial key rotation) and their verifying-key
    /// bytes do not match. Loading such a pair is refused to prevent issuing
    /// tokens whose embedded credential cannot be verified with the signing key.
    #[error("signing key does not match credential: verifying keys differ")]
    KeyCredentialMismatch,

    /// Serialization or deserialization of okami types failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A delegation token has expired.
    #[error("token expired")]
    TokenExpired,

    /// A delegation token was issued in the future (clock skew too large).
    #[error("token not yet valid (issued in the future beyond clock skew tolerance)")]
    TokenNotYetValid,

    /// Attempted to delegate with scopes that exceed the issuer's own scopes.
    #[error("scope escalation: requested scopes are not a subset of issuer scopes")]
    ScopeEscalation,
}

impl From<lupine_core::Error> for Error {
    fn from(e: lupine_core::Error) -> Self {
        Error::Crypto(e)
    }
}

/// Convenience alias for `Result<T, okami::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_variants() {
        let e = Error::DelegationDepthExceeded;
        assert!(e.to_string().contains("depth limit"));

        let e = Error::AlreadyInitialized;
        assert!(e.to_string().contains("already initialized"));

        let e = Error::InsecureKeyPermissions;
        assert!(e.to_string().contains("0600"));

        let e = Error::InvalidSpiffeId("bad".to_string());
        assert!(e.to_string().contains("bad"));

        let e = Error::InvalidScope("foo bar".to_string());
        assert!(e.to_string().contains("foo bar"));

        let e = Error::TokenExpired;
        assert!(e.to_string().contains("expired"));

        let e = Error::ScopeEscalation;
        assert!(e.to_string().contains("escalation"));
    }

    #[test]
    fn from_lupine_error() {
        let lupine_err = lupine_core::Error::Signing;
        let okami_err = Error::from(lupine_err);
        assert!(matches!(okami_err, Error::Crypto(_)));
        assert!(okami_err.to_string().contains("crypto error"));
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let okami_err: Error = io_err.into();
        assert!(matches!(okami_err, Error::IoError(_)));
        assert!(okami_err.to_string().contains("I/O error"));
    }

    #[test]
    fn error_is_debug() {
        let e = Error::DelegationDepthExceeded;
        let dbg = format!("{e:?}");
        assert!(!dbg.is_empty());
    }
}
