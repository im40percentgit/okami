//! Okami CLI — manage agent PQC identities, delegation tokens, and audit events.
//!
//! Commands:
//!   init          Create .okami/ workspace with trust domain config and root keypair
//!   keygen        Generate a new agent keypair
//!   inspect       Decode and print a PQC credential
//!   delegate      Issue a delegation token
//!   verify-chain  Verify a delegation chain file
//!   tree          Print ASCII tree of a delegation chain
//!
// @decision DEC-OKAMI-010 clap derive API for CLI — accepted.
// Rationale: clap derive produces consistent help text, auto-generated usage
// strings, and type-safe argument parsing with minimal boilerplate. The
// builder API would require more code for the same result.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

use okami::delegation::{Capability, DelegationChain, DelegationToken};
use okami::identity::{load_signing_key, save_signing_key, AgentIdentity, SpiffeId};

// ── CLI root ──────────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(
    name = "okami",
    about = "Post-quantum cryptographic identity for AI agents",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize a .okami/ workspace with trust domain config and root keypair.
    Init {
        /// Trust domain for this workspace (e.g. example.com).
        #[arg(long)]
        trust_domain: String,
    },
    /// Generate a new agent keypair and write it to files.
    Keygen {
        /// Trust domain for the new identity.
        #[arg(long)]
        trust_domain: String,
        /// Workload identifier (e.g. orchestrator, worker/1).
        #[arg(long)]
        workload: String,
        /// Output directory for key files (default: current directory).
        #[arg(long, default_value = ".")]
        output: PathBuf,
    },
    /// Decode and print a PQC credential file.
    Inspect {
        /// Path to the credential file (bincode-encoded PqcCredential).
        #[arg(long)]
        credential: PathBuf,
    },
    /// Issue a delegation token from one identity to another.
    ///
    /// The output is always a DelegationChain (bincode-encoded Vec of tokens).
    /// If --chain is supplied, the existing chain is loaded and the new token is
    /// appended; otherwise a single-token chain is created. Both verify-chain and
    /// tree consume the resulting chain file directly.
    Delegate {
        /// Directory containing the issuer's signing key and credential files.
        #[arg(long)]
        from: PathBuf,
        /// Subject SPIFFE ID to delegate to (e.g. spiffe://example.com/worker/1).
        #[arg(long)]
        to: String,
        /// Comma-separated list of scopes to grant (e.g. read:db,write:api).
        #[arg(long)]
        scopes: String,
        /// Token validity in seconds (default: 3600).
        #[arg(long, default_value = "3600")]
        expiry: u64,
        /// Existing chain file to extend (appends new token to the chain).
        /// When omitted a single-token chain is created.
        #[arg(long)]
        chain: Option<PathBuf>,
        /// Output file for the chain (default: stdout as hex).
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a delegation chain file.
    VerifyChain {
        /// Path to the chain file (bincode-encoded DelegationChain).
        #[arg(long)]
        chain: PathBuf,
    },
    /// Print an ASCII tree of a delegation chain.
    Tree {
        /// Path to the chain file (bincode-encoded DelegationChain).
        #[arg(long)]
        chain: PathBuf,
    },
}

// ── Key file naming conventions ───────────────────────────────────────────────

fn signing_key_path(dir: &std::path::Path) -> PathBuf {
    dir.join("signing.key")
}

fn credential_path(dir: &std::path::Path) -> PathBuf {
    dir.join("credential.bin")
}

fn config_path(dir: &std::path::Path) -> PathBuf {
    dir.join("config.toml")
}

// ── Command implementations ───────────────────────────────────────────────────

fn cmd_init(trust_domain: &str) -> anyhow::Result<()> {
    let okami_dir = std::path::Path::new(".okami");

    if okami_dir.exists() {
        return Err(okami::Error::AlreadyInitialized.into());
    }

    std::fs::create_dir(okami_dir)?;

    // Generate root identity.
    let identity = AgentIdentity::new(trust_domain, "root")?;
    let key_bytes = identity.signing_key_bytes();
    let cred_bytes = identity.credential().to_bytes()?;

    // Write signing key at 0600.
    save_signing_key(&signing_key_path(okami_dir), &key_bytes)?;

    // Write credential (public material — no permission restriction needed).
    std::fs::write(credential_path(okami_dir), &cred_bytes)?;

    // Write config.toml.
    let config = format!(
        "# Okami workspace configuration\ntrust_domain = {:?}\nspiffe_id = {:?}\n",
        trust_domain,
        identity.spiffe_id().as_str()
    );
    std::fs::write(config_path(okami_dir), config)?;

    println!("Initialized .okami/ workspace");
    println!("  Trust domain : {trust_domain}");
    println!("  SPIFFE ID    : {}", identity.spiffe_id());
    println!("  Signing key  : .okami/signing.key (mode 0600)");
    println!("  Credential   : .okami/credential.bin");

    Ok(())
}

fn cmd_keygen(trust_domain: &str, workload: &str, output: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(output)?;

    let identity = AgentIdentity::new(trust_domain, workload)?;
    let key_bytes = identity.signing_key_bytes();
    let cred_bytes = identity.credential().to_bytes()?;

    save_signing_key(&signing_key_path(output), &key_bytes)?;
    std::fs::write(credential_path(output), &cred_bytes)?;

    println!("Generated keypair");
    println!("  SPIFFE ID  : {}", identity.spiffe_id());
    println!("  Signing key: {}", signing_key_path(output).display());
    println!("  Credential : {}", credential_path(output).display());

    Ok(())
}

fn cmd_inspect(credential_path: &std::path::Path) -> anyhow::Result<()> {
    let bytes = std::fs::read(credential_path)?;
    let cred = okami::identity::PqcCredential::from_bytes(&bytes)?;

    println!("PQC Credential");
    println!("  SPIFFE ID      : {}", cred.spiffe_id);
    println!("  Algorithm      : v{} (hybrid Ed25519+ML-DSA-65)", cred.algo);
    println!("  Created at     : {}", cred.created_at);
    println!("  Expires at     : {}", cred.expires_at);
    println!(
        "  Expired        : {}",
        if cred.is_expired() { "YES" } else { "no" }
    );
    println!(
        "  Verifying key  : {} bytes",
        cred.verifying_key_bytes.len()
    );

    Ok(())
}

/// Issue a delegation token and produce a DelegationChain file.
///
/// If `existing_chain` is provided the chain is loaded and the new token is
/// appended (the leaf token becomes the parent). Otherwise a single-token
/// chain is created. The output is always a bincode-encoded DelegationChain
/// so that `verify-chain` and `tree` can consume it directly.
///
/// Issuer scopes when extending a chain are taken from the leaf token; for a
/// root (no parent chain) the issuer is assumed to hold all requested scopes.
fn cmd_delegate(
    from_dir: &std::path::Path,
    to_spiffe: &str,
    scopes_str: &str,
    expiry_secs: u64,
    existing_chain: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    // Load issuer identity.
    let sk_path = signing_key_path(from_dir);
    let cred_path = credential_path(from_dir);

    let key_bytes = load_signing_key(&sk_path)?;
    let cred_bytes = std::fs::read(&cred_path)?;
    let cred = okami::identity::PqcCredential::from_bytes(&cred_bytes)?;
    let spiffe_str = cred.spiffe_id.as_str().to_string();
    let issuer = AgentIdentity::from_stored(&spiffe_str, &key_bytes)?;

    // Parse subject.
    let subject_id = SpiffeId::parse(to_spiffe)?;

    // Parse requested scopes.
    let scopes: Vec<Capability> = scopes_str
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| Capability::new(s.trim()))
        .collect::<Result<_, _>>()?;

    // Load existing chain if provided; the leaf becomes the parent token.
    let existing: Option<DelegationChain> = existing_chain
        .map(|p| {
            let bytes = std::fs::read(p)?;
            DelegationChain::from_bytes(&bytes).map_err(anyhow::Error::from)
        })
        .transpose()?;

    // Issuer scopes are the leaf token's scopes when extending, or the
    // requested scopes themselves for a fresh root token.
    let issuer_scopes: Vec<Capability> = match &existing {
        Some(chain) => chain
            .leaf()
            .map(|t| t.scopes.clone())
            .unwrap_or_default(),
        None => scopes.clone(),
    };

    let parent: Option<&DelegationToken> = existing.as_ref().and_then(|c| c.leaf());

    let token = DelegationToken::issue(
        &issuer,
        subject_id,
        scopes,
        &issuer_scopes,
        Duration::from_secs(expiry_secs),
        parent,
    )?;

    // Build the output chain (clone existing tokens + new token).
    let mut chain_tokens: Vec<DelegationToken> = existing
        .map(|c| c.tokens)
        .unwrap_or_default();
    chain_tokens.push(token);
    let chain = DelegationChain::new(chain_tokens);

    let chain_bytes = chain.to_bytes()?;

    match output {
        Some(path) => {
            std::fs::write(path, &chain_bytes)?;
            println!("Chain written to {}", path.display());
        }
        None => {
            println!("{}", hex::encode(&chain_bytes));
        }
    }

    Ok(())
}

fn cmd_verify_chain(chain_path: &std::path::Path) -> anyhow::Result<()> {
    let bytes = std::fs::read(chain_path)?;
    let chain = DelegationChain::from_bytes(&bytes)?;

    match chain.verify(None) {
        Ok(()) => {
            println!("Chain VALID");
            println!("  Links  : {}", chain.tokens.len());
            let scopes: Vec<&str> = chain.effective_scopes().iter().map(|s| s.as_str()).collect();
            println!("  Scopes : {}", scopes.join(", "));
        }
        Err(e) => {
            eprintln!("Chain INVALID: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn cmd_tree(chain_path: &std::path::Path) -> anyhow::Result<()> {
    let bytes = std::fs::read(chain_path)?;
    let chain = DelegationChain::from_bytes(&bytes)?;
    print!("{}", chain.ascii_tree());
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let result: anyhow::Result<()> = match &cli.command {
        Commands::Init { trust_domain } => cmd_init(trust_domain),
        Commands::Keygen {
            trust_domain,
            workload,
            output,
        } => cmd_keygen(trust_domain, workload, output),
        Commands::Inspect { credential } => cmd_inspect(credential),
        Commands::Delegate {
            from,
            to,
            scopes,
            expiry,
            chain,
            output,
        } => cmd_delegate(from, to, scopes, *expiry, chain.as_deref(), output.as_deref()),
        Commands::VerifyChain { chain } => cmd_verify_chain(chain),
        Commands::Tree { chain } => cmd_tree(chain),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
