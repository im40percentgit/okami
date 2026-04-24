//! Verification helper: read a chain.bin and print the issuer_credential timestamps
//! from the first (root) token. Used by the tester to confirm that cmd_delegate
//! embeds the on-disk credential rather than re-minting it.
//!
//! Usage: cargo run --example inspect_chain_cred_timestamps -- <chain.bin>

use okami::delegation::DelegationChain;
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: inspect_chain_cred_timestamps <chain.bin>");
        std::process::exit(1);
    }

    let bytes = fs::read(&args[1]).expect("failed to read chain file");
    let chain = DelegationChain::from_bytes(&bytes).expect("failed to deserialize chain");

    if chain.tokens.is_empty() {
        eprintln!("Chain is empty");
        std::process::exit(1);
    }

    let token = &chain.tokens[0];
    let cred = &token.issuer_credential;

    println!(
        "Embedded issuer_credential.created_at : {}",
        cred.created_at
    );
    println!(
        "Embedded issuer_credential.expires_at : {}",
        cred.expires_at
    );
}
