//! CLI end-to-end tests using assert_cmd.
//!
//! Tests the okami binary commands: init, keygen, inspect, delegate,
//! verify-chain, and tree. Each test uses a temporary directory to avoid
//! polluting the filesystem.
//!
// @decision DEC-OKAMI-013 assert_cmd for CLI E2E tests — accepted.
// Rationale: assert_cmd runs the real compiled binary (not library code),
// catching issues that unit tests miss: argument parsing errors, exit codes,
// stdout/stderr content, and file system interactions. This matches how
// users actually invoke the tool.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn okami() -> Command {
    Command::cargo_bin("okami").expect("okami binary must be compiled")
}

// ── init ──────────────────────────────────────────────────────────────────────

#[test]
fn cli_init_creates_okami_dir() {
    let dir = TempDir::new().unwrap();
    okami()
        .current_dir(dir.path())
        .args(["init", "--trust-domain", "example.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Initialized .okami/"))
        .stdout(predicate::str::contains("example.com"));

    assert!(dir.path().join(".okami").exists(), ".okami/ must be created");
    assert!(
        dir.path().join(".okami/signing.key").exists(),
        "signing.key must be created"
    );
    assert!(
        dir.path().join(".okami/credential.bin").exists(),
        "credential.bin must be created"
    );
    assert!(
        dir.path().join(".okami/config.toml").exists(),
        "config.toml must be created"
    );
}

#[test]
fn cli_init_rejects_double_init() {
    let dir = TempDir::new().unwrap();
    // First init succeeds.
    okami()
        .current_dir(dir.path())
        .args(["init", "--trust-domain", "example.com"])
        .assert()
        .success();

    // Second init must fail.
    okami()
        .current_dir(dir.path())
        .args(["init", "--trust-domain", "example.com"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already initialized"));
}

#[test]
fn cli_init_signing_key_has_0600_permissions() {
    // Only meaningful on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        okami()
            .current_dir(dir.path())
            .args(["init", "--trust-domain", "example.com"])
            .assert()
            .success();

        let meta = std::fs::metadata(dir.path().join(".okami/signing.key")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "signing.key must have mode 0600, got {mode:o}");
    }
}

// ── keygen ────────────────────────────────────────────────────────────────────

#[test]
fn cli_keygen_creates_files() {
    let dir = TempDir::new().unwrap();
    okami()
        .args([
            "keygen",
            "--trust-domain",
            "example.com",
            "--workload",
            "worker/1",
            "--output",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated keypair"))
        .stdout(predicate::str::contains("spiffe://example.com/worker/1"));

    assert!(dir.path().join("signing.key").exists());
    assert!(dir.path().join("credential.bin").exists());
}

#[test]
fn cli_keygen_signing_key_permissions() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        okami()
            .args([
                "keygen",
                "--trust-domain",
                "example.com",
                "--workload",
                "agent/test",
                "--output",
                dir.path().to_str().unwrap(),
            ])
            .assert()
            .success();

        let meta = std::fs::metadata(dir.path().join("signing.key")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "signing.key must be mode 0600");
    }
}

// ── inspect ───────────────────────────────────────────────────────────────────

#[test]
fn cli_inspect_shows_credential_details() {
    let dir = TempDir::new().unwrap();
    // Generate a keypair first.
    okami()
        .args([
            "keygen",
            "--trust-domain",
            "example.com",
            "--workload",
            "inspector/1",
            "--output",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    okami()
        .args([
            "inspect",
            "--credential",
            dir.path().join("credential.bin").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("PQC Credential"))
        .stdout(predicate::str::contains("spiffe://example.com/inspector/1"))
        .stdout(predicate::str::contains("Expired"))
        .stdout(predicate::str::contains("no"));
}

#[test]
fn cli_inspect_rejects_missing_file() {
    okami()
        .args(["inspect", "--credential", "/nonexistent/credential.bin"])
        .assert()
        .failure();
}

// ── delegate ──────────────────────────────────────────────────────────────────

#[test]
fn cli_delegate_outputs_hex_token() {
    let dir = TempDir::new().unwrap();
    okami()
        .args([
            "keygen",
            "--trust-domain",
            "example.com",
            "--workload",
            "orchestrator",
            "--output",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    okami()
        .args([
            "delegate",
            "--from",
            dir.path().to_str().unwrap(),
            "--to",
            "spiffe://example.com/worker/1",
            "--scopes",
            "read:db,write:api",
            "--expiry",
            "3600",
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_match("[0-9a-f]{100,}").unwrap());
}

#[test]
fn cli_delegate_writes_to_file() {
    let dir = TempDir::new().unwrap();
    let token_file = dir.path().join("token.bin");

    okami()
        .args([
            "keygen",
            "--trust-domain",
            "example.com",
            "--workload",
            "orchestrator",
            "--output",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    okami()
        .args([
            "delegate",
            "--from",
            dir.path().to_str().unwrap(),
            "--to",
            "spiffe://example.com/worker/1",
            "--scopes",
            "read:db",
            "--expiry",
            "3600",
            "--output",
            token_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("written to"));

    assert!(token_file.exists(), "token file must be created");
    assert!(token_file.metadata().unwrap().len() > 0, "token file must be non-empty");
}

// ── verify-chain ──────────────────────────────────────────────────────────────

#[test]
fn cli_verify_chain_valid_single_token() {
    let dir = TempDir::new().unwrap();
    let chain_file = dir.path().join("chain.bin");

    // Generate issuer keypair.
    okami()
        .args([
            "keygen",
            "--trust-domain",
            "example.com",
            "--workload",
            "orchestrator",
            "--output",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // delegate now always writes a DelegationChain, so verify-chain succeeds.
    okami()
        .args([
            "delegate",
            "--from",
            dir.path().to_str().unwrap(),
            "--to",
            "spiffe://example.com/worker/1",
            "--scopes",
            "read:db",
            "--output",
            chain_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    okami()
        .args([
            "verify-chain",
            "--chain",
            chain_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Chain VALID"));
}

#[test]
fn cli_verify_chain_rejects_missing_file() {
    okami()
        .args(["verify-chain", "--chain", "/nonexistent/chain.bin"])
        .assert()
        .failure();
}

#[test]
fn cli_verify_chain_two_link_chain() {
    let dir = TempDir::new().unwrap();
    let worker_dir = dir.path().join("worker");
    let chain_file = dir.path().join("chain1.bin");
    let chain_file2 = dir.path().join("chain2.bin");

    // Generate orchestrator keypair.
    okami()
        .args([
            "keygen",
            "--trust-domain",
            "example.com",
            "--workload",
            "orchestrator",
            "--output",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // Generate worker keypair in a subdirectory.
    okami()
        .args([
            "keygen",
            "--trust-domain",
            "example.com",
            "--workload",
            "worker/1",
            "--output",
            worker_dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    // First delegation: orchestrator -> worker/1.
    okami()
        .args([
            "delegate",
            "--from",
            dir.path().to_str().unwrap(),
            "--to",
            "spiffe://example.com/worker/1",
            "--scopes",
            "read:db",
            "--output",
            chain_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Second delegation: worker/1 -> sub-worker/1 (extends existing chain).
    okami()
        .args([
            "delegate",
            "--from",
            worker_dir.to_str().unwrap(),
            "--to",
            "spiffe://example.com/sub-worker/1",
            "--scopes",
            "read:db",
            "--chain",
            chain_file.to_str().unwrap(),
            "--output",
            chain_file2.to_str().unwrap(),
        ])
        .assert()
        .success();

    // verify-chain must succeed and report 2 links.
    okami()
        .args([
            "verify-chain",
            "--chain",
            chain_file2.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Chain VALID"))
        .stdout(predicate::str::contains("Links  : 2"));
}

// ── tree ──────────────────────────────────────────────────────────────────────

#[test]
fn cli_tree_rejects_missing_file() {
    okami()
        .args(["tree", "--chain", "/nonexistent/chain.bin"])
        .assert()
        .failure();
}

#[test]
fn cli_tree_shows_spiffe_ids() {
    let dir = TempDir::new().unwrap();
    let chain_file = dir.path().join("chain.bin");

    // Generate issuer keypair.
    okami()
        .args([
            "keygen",
            "--trust-domain",
            "example.com",
            "--workload",
            "orchestrator",
            "--output",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // Create a single-token chain.
    okami()
        .args([
            "delegate",
            "--from",
            dir.path().to_str().unwrap(),
            "--to",
            "spiffe://example.com/worker/42",
            "--scopes",
            "read:db",
            "--output",
            chain_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    // tree output must contain the subject SPIFFE ID and scope.
    okami()
        .args(["tree", "--chain", chain_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("worker/42"))
        .stdout(predicate::str::contains("read:db"));
}

// ── help and version ──────────────────────────────────────────────────────────

#[test]
fn cli_help_succeeds() {
    okami().arg("--help").assert().success();
}

#[test]
fn cli_version_succeeds() {
    okami().arg("--version").assert().success();
}

#[test]
fn cli_no_args_shows_help() {
    // clap requires a subcommand — no args should show help and exit non-zero.
    okami().assert().failure();
}

#[test]
fn cli_unknown_subcommand_fails() {
    okami()
        .args(["nonexistent-command"])
        .assert()
        .failure();
}
