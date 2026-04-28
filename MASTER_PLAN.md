# Okami — Agent Identity with Post-Quantum Cryptography

## Original Intent

> A single sign on app that works for people and agents and uses post quantum cryptography, building on what we've done in /lupine.

As agents become more ubiquitous they need to be treated as first class for security. At the same time, post-quantum cryptography becomes more important because we will soon break our current cryptography. Okami addresses both trends: agent-first identity with PQC at the foundation.

## Project Overview

Okami is a purpose-built agent identity system with post-quantum cryptography at its foundation, designed to complement (not replace) existing human identity providers like Auth0/Okta.

**Phase 1 (Agent Passport SDK):** Open-source Rust crate giving AI agents PQC cryptographic identity, signed delegation credentials, mutual authentication, and audit-ready identity events.

**Phase 2 (Agent Identity Platform):** SaaS with dashboard, credential registry, delegation chain visualizer, Auth0/Okta integration. Gated on Phase 1 adoption.

## Architecture

- **Language:** Rust (single crate: `okami`)
- **Dependency:** lupine (PQC library, FIPS 203/204/205, hybrid PQC/classical)
- **Standards:** SPIFFE IDs for naming, mTLS for mutual auth, OAuth-style string scopes
- **PQC:** Hybrid X25519+ML-KEM-768 (key exchange), Ed25519+ML-DSA-65 (signing)

### Modules

| Module | Responsibility |
|--------|---------------|
| `identity` | AgentIdentity, SpiffeId, PqcCredential, key lifecycle (rotation, expiry, revocation) |
| `delegation` | DelegationToken, DelegationChain (max depth 3), OAuth-style scopes |
| `audit` | AuditEvent, signed tamper-evident event chain, JSON schema |
| `cli` | `init`, `keygen`, `inspect`, `delegate`, `verify-chain`, `tree` |
| `error` | Single `okami::Error` enum via thiserror |

### Key Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | SPIFFE ID + standalone PQC credential (not X.509 extensions) | X.509 PQC tooling is immature; clean separation |
| 2 | Delegation chain max depth 3 | Covers human→orchestrator→worker→sub-worker |
| 3 | OAuth-style string scopes | Familiar, composable with existing IAM |
| 4 | Key lifecycle in Phase 1 | Security product without rotation/revocation is a liability |
| 5 | ~112 tests with proptest | Security-critical code needs property-based + adversarial tests |
| 6 | CLI E2E via assert_cmd | Real binary tests catch issues library tests miss |
| 7 | 0600 file permissions on private keys | SSH model — refuse to load keys with wider permissions |

## Implementation Sequence

1. ~~Publish lupine to crates.io~~ (blocking dependency)
2. ~~Read IETF draft-klrc-aiagent-auth-00~~ (alignment)
3. ~~Scaffold okami: Cargo.toml, CI, README~~
4. ~~Implement identity module + tests~~
5. ~~Implement delegation module + tests~~
6. ~~Implement audit module + JSON schema + tests~~
7. ~~Implement CLI (init, keygen, inspect, delegate, verify-chain, tree) + E2E tests~~
8. ~~Write mutual auth example~~
9. ~~Property-based tests (proptest) + adversarial input tests~~
10. ~~Documentation + README with demo~~

## CEO Review Expansions (accepted)

- `okami init` — scaffolds `.okami/` with trust domain config and root PQC keypair
- `okami tree` — ASCII delegation chain visualizer
- Mutual auth example — two-agent demo
- Audit event JSON schema — formal schema for monitoring tool integration

## Critical Gaps (must address)

1. Clock skew tolerance for token expiry (configurable grace period)
2. Offline revocation checking (local revocation list)

## Resources

- Design doc: `~/.gstack/projects/okami/j-unknown-design-20260325-185103.md`
- CEO plan: `~/.gstack/projects/okami/ceo-plans/2026-03-25-agent-passport-sdk.md`
- Test plan: `~/.gstack/projects/okami/j-unknown-eng-review-test-plan-20260325-192148.md`

## Security Hardening Pass — 2026-04-24

A `/cso` audit (daily mode, 8/10 confidence gate) surfaced 7 findings: 1 CRITICAL, 2 HIGH, 4 MEDIUM. All shipped via separate PRs:

| PR | Severity | Closed |
|----|----------|--------|
| [#1](https://github.com/im40percentgit/okami/pull/1) | infra×3 | Findings #5 (Cargo.lock tracking), #6 (CI absent), #7 (cargo-audit not wired) |
| [#2](https://github.com/im40percentgit/okami/pull/2) | **CRITICAL** | Finding #1 — token issuer/credential SPIFFE ID mismatch was unchecked, allowing any keypair holder to forge tokens |
| [#3](https://github.com/im40percentgit/okami/pull/3) | HIGH × 2 | Findings #2 + #3 — `from_stored` re-minted credential timestamps; `cmd_delegate` discarded the on-disk credential |
| [#4](https://github.com/im40percentgit/okami/pull/4) | MEDIUM | Finding #4 — bincode 1.x deserialization without allocation cap |

Three appendix items below the daily gate (cross-protocol signature reuse, `load_signing_key` owner UID check, TOCTOU on permission check) are deferred for the next `/cso --comprehensive` pass.

A separate Dependabot alert (`GHSA-cq8v-f236-94qc`, `rand` low-severity unsoundness with custom loggers calling `rand::rng()`) is open but does not affect okami's code paths — random number generation goes through lupine, not `rand::rng()` directly.

Side effects of the pass:
- MSRV bumped from 1.75 to 1.85 (forced by `signature 3.0.0-rc.10` requiring `edition2024`).
- CI now runs on every push to main and every PR (test + clippy + fmt + cargo-audit).
- `Cargo.lock` is now tracked.
- 11 new tests across the four PRs (security-specific: issuer mismatch rejection, timestamp preservation, key/credential binding, bincode bounds, oversized-input rejection, plus a 64-case proptest for from_bytes safety).

## Production Readiness Backlog

Items the project will need before a public 1.0 release. Not blockers for current internal/early-adopter use; tracked here so they don't fall off.

| # | Item | Driver | Effort | Notes |
|---|------|--------|--------|-------|
| PR-1 | Publish to crates.io | maintainer must drive (irreversible) | 30 min | First publish at 0.1.0 once MASTER_PLAN intent + crate metadata are reviewed |
| PR-2 | `cargo-fuzz` integration with targets for `DelegationChain::from_bytes`, `SpiffeId::parse`, `PqcCredential::from_bytes`, `SignedAuditEvent::from_bytes` | implementer | half day | Existing proptest is partial coverage; libfuzzer goes deeper. Requires nightly toolchain in a separate CI workflow. |
| PR-3 | `cargo-deny` integration in CI | implementer | 1-2 hours | Wraps cargo-audit + license check + duplicate-dep check + advisory-db. Replaces / extends current `audit` job. |
| PR-4 | Multi-OS CI matrix (macOS + Windows for the test job) | implementer | 1 hour | Catches cfg(unix) leaks; especially important for `load_signing_key` UID/permission code which has `#[cfg(unix)]` guards. Windows behavior is currently undefined. |
| PR-5 | Doc-comment audit pass (run `cargo doc --no-deps --document-private-items`) | implementer | 2-3 hours | Confirm every public API has a `# Errors`, `# Panics` (where applicable), and at least one example block. Fix gaps. |
| PR-6 | Tighten `RevocationStatement` verify path | implementer | 1-2 hours | Currently no public verify helper; producers can sign but consumers must reconstruct the byte order manually. Add `RevocationStatement::verify(verifying_key, &claimed_credential_bytes) -> Result<bool>`. |
| PR-7 | Decide on Phase 2 scope (Agent Identity Platform SaaS) | maintainer | strategic | Currently gated on Phase 1 adoption per MASTER_PLAN. Adoption signal arrives → write a Phase 2 plan via `/plan-eng-review`. |

Appendix items A1 + A2 from the /cso 2026-04-24 audit have closed (PR #6, commit 6e6c738). A3 (TOCTOU on permission check) is accepted residual risk.

## Phase Status

| Phase | Status | Date |
|-------|--------|------|
| Phase 1 — Agent Passport SDK | **completed** | 2026-03-25 |
| Phase 2 — Agent Identity Platform | planned (gated on Phase 1 adoption) | — |

## Decision Log

| ID | Decision | Rationale | Source |
|----|----------|-----------|--------|
| DEC-OKAMI-001 | Single `okami::Error` enum via thiserror | Consistent error handling across all modules | `src/error.rs` |
| DEC-OKAMI-002 | SPIFFE ID + standalone PQC credential (not X.509) | X.509 PQC tooling is immature; clean separation | `src/identity.rs` |
| DEC-OKAMI-003 | Key lifecycle in Phase 1 (rotation, expiry, revocation) | Security product without rotation/revocation is a liability | `src/identity.rs` |
| DEC-OKAMI-004 | 0600 file permissions on private keys | SSH model — refuse to load keys with wider permissions | `src/identity.rs` |
| DEC-OKAMI-005 | bincode for token serialization | Compact binary format for delegation tokens | `src/delegation.rs` |
| DEC-OKAMI-006 | Scope as validated string (not enum) | OAuth-style composability with existing IAM | `src/delegation.rs` |
| DEC-OKAMI-007 | Clock skew tolerance: configurable, default 30s | Addresses Critical Gap #1 | `src/delegation.rs` |
| DEC-OKAMI-008 | SHA-256 chain hash for tamper-evidence | Standard, fast, sufficient for audit integrity | `src/audit.rs` |
| DEC-OKAMI-009 | serde_json::Value for event details | Flexible schema for diverse audit event types | `src/audit.rs` |
| DEC-OKAMI-010 | clap derive API for CLI | Type-safe, ergonomic CLI definition | `src/bin/okami.rs` |
| DEC-OKAMI-011 | Example uses in-memory credential exchange | Demonstrates concept without network dependency | `examples/mutual_auth.rs` |
| DEC-OKAMI-012 | proptest for security-critical invariant testing | Property-based testing catches edge cases unit tests miss | `tests/proptest_tests.rs` |
| DEC-OKAMI-013 | assert_cmd for CLI E2E tests | Real binary tests catch issues library tests miss | `tests/cli_e2e.rs` |
| DEC-OKAMI-014 | DelegationToken::verify rejects mismatched issuer/embedded-credential SPIFFE ID | Without this binding check the embedded credential can be from a different identity than the claimed issuer; allows full bypass of self-contained verification | `src/delegation.rs` |
| DEC-OKAMI-015 | AgentIdentity::from_stored takes a PqcCredential and verifies key/credential pairing | Re-minting timestamps on every load made expiry illusory and broke revocation-by-bytes; the binding check catches mismatched signing.key/credential.bin pairs | `src/identity.rs` |
| DEC-OKAMI-016 | Bounded bincode deserialization with per-type input-size caps + `with_limit` | Bincode 1.x has no default allocation cap; a crafted 8-byte length prefix triggers exabyte allocation; well-formed oversized inputs deserve rejection too | `src/delegation.rs`, `src/identity.rs`, `src/audit.rs` |
| DEC-OKAMI-017 | Domain-separated signatures across token / audit / revocation protocols (1-byte domain tag prepended before signing) | Without domain separation a signature crafted in one protocol could verify against another, enabling cross-protocol signature reuse. Wire-format break from pre-0.1.1 signatures. /cso Appendix A1. | `src/identity.rs`, `src/delegation.rs`, `src/audit.rs` |
| DEC-OKAMI-018 | `load_signing_key` verifies file owner UID matches effective UID via libc `geteuid()` | Mode-0600 alone is insufficient — a key file owned by another UID can be silently replaced by that user. UID check matches full SSH model (ssh-keygen refuses non-owner keys). No new crate dep. /cso Appendix A2. | `src/identity.rs` |
| DEC-OKAMI-019 | Public `RevocationStatement::verify(verifying_key_bytes, claimed_credential_bytes)` helper | Hand-reconstructing the signed payload (`target_bytes || revoked_at_secs.to_le_bytes()` under `DOMAIN_REVOCATION`) is a footgun that silently accepts forged revocations or rejects valid ones; first-party helper mirrors `DelegationToken::verify` and `SignedAuditEvent::verify` ergonomics. | `src/identity.rs` |
| DEC-OKAMI-020 | `#![deny(missing_docs)]` at crate root + `# Errors` on every Result-returning public function + `# Examples` on flagship public types | Once published to crates.io every `pub` item is a stable contract; compile-time enforcement prevents API surface drifting away from documentation. | `src/lib.rs` |

## Review Status

CEO + ENG CLEARED. Phase 1 complete. 20 decisions documented. Security hardening pass (/cso 2026-04-24) merged across PRs #1-#6.
