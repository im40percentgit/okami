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

## Review Status

CEO + ENG CLEARED. Phase 1 complete. 13 decisions documented.
