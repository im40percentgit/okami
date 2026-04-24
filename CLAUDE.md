# CLAUDE.md — Okami

## Project

Okami is a Rust crate providing post-quantum cryptographic identity for AI agents. It builds on [lupine](../lupine) for PQC primitives.

## Stack

- **Language:** Rust 2021 (MSRV 1.85)
- **Build:** Cargo
- **PQC:** lupine (FIPS 203/204/205, hybrid PQC/classical)
- **Testing:** cargo test, proptest, assert_cmd (CLI E2E)
- **CI:** GitHub Actions (cargo test, cargo clippy, cargo fmt)

## Commands

```bash
cargo build                    # Build library + CLI
cargo test                     # Run all tests
cargo test -- --nocapture      # Tests with output
cargo clippy                   # Lint
cargo fmt -- --check           # Format check
```

## Architecture

Single crate with modules: `identity`, `delegation`, `audit`, `error`, and a CLI binary.

See MASTER_PLAN.md for full architecture and decisions.

## Testing

Run `cargo test`. Tests include:
- Unit tests per module
- Property-based tests via proptest
- CLI E2E tests via assert_cmd
- Round-trip serialization tests
