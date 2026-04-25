//! Cross-protocol signature reuse attempt — regression witness.
//!
//! Run with: cargo run --example cross_protocol_attempt
//!
//! Proves that a signature produced under DOMAIN_TOKEN cannot be replayed
//! as a DOMAIN_AUDIT signature (and vice-versa). This is the live end-to-end
//! demonstration of the A1 (domain separation) fix in CSO Appendix A.
//!
//! Expected output:
//!   sign under DOMAIN_TOKEN          => ok
//!   verify DOMAIN_TOKEN  (same)      => Ok(true)   [PASS]
//!   verify DOMAIN_AUDIT  (wrong)     => Ok(false)  [PASS — cross-protocol blocked]

use okami::identity::{AgentIdentity, DOMAIN_AUDIT, DOMAIN_TOKEN};

fn main() {
    let identity =
        AgentIdentity::new("example.org", "agent/verifier").expect("identity generation failed");

    let vk_bytes = identity.credential().verifying_key_bytes.clone();
    let payload = b"sensitive-payload-for-cross-protocol-test";

    // Step 1: sign under DOMAIN_TOKEN
    println!("sign under DOMAIN_TOKEN          => ok");
    let sig = identity
        .sign_with_domain(DOMAIN_TOKEN, payload)
        .expect("sign_with_domain failed");

    // Step 2: verify with the CORRECT domain — must succeed
    let result_correct = AgentIdentity::verify_with_domain(&vk_bytes, DOMAIN_TOKEN, payload, &sig)
        .expect("verify_with_domain returned Err unexpectedly");
    print!("verify DOMAIN_TOKEN  (same)      => {:?}", result_correct);
    if result_correct {
        println!("  [PASS]");
    } else {
        println!("  [FAIL — same-domain verify returned false]");
        std::process::exit(1);
    }

    // Step 3: verify with the WRONG domain — must be rejected (Ok(false), not Err)
    let result_wrong = AgentIdentity::verify_with_domain(&vk_bytes, DOMAIN_AUDIT, payload, &sig)
        .expect("verify_with_domain returned Err unexpectedly");
    print!("verify DOMAIN_AUDIT  (wrong)     => {:?}", result_wrong);
    if !result_wrong {
        println!("  [PASS — cross-protocol blocked]");
    } else {
        println!("  [FAIL — cross-protocol replay succeeded, domain separation is broken]");
        std::process::exit(1);
    }

    println!("\nAll cross-protocol checks passed.");
}
