# okami

Post-quantum cryptographic identity for AI agents.

Okami gives AI agents a cryptographic identity using hybrid post-quantum
cryptography (Ed25519 + ML-DSA-65, NIST Security Level 3). It provides:

- **SPIFFE IDs** — standard workload identity URIs
- **PQC credentials** — shareable public credentials with verifying keys
- **Delegation tokens** — OAuth-style signed capability tokens with depth-limited chains
- **Audit events** — tamper-evident signed event chains
- **CLI** — `okami init`, `keygen`, `inspect`, `delegate`, `verify-chain`, `tree`

Built on [lupine](../lupine) for PQC primitives.

## Quick start

### Library

```rust
use okami::identity::AgentIdentity;
use okami::delegation::{Capability, DelegationToken};
use std::time::Duration;

// Generate agent identities.
let orchestrator = AgentIdentity::new("example.com", "orchestrator")?;
let worker_id = okami::identity::SpiffeId::new("example.com", "worker/1")?;

// Issue a delegation token.
let scopes = vec![Capability::new("read:db")?, Capability::new("invoke:llm")?];
let token = DelegationToken::issue(
    &orchestrator,
    worker_id,
    scopes.clone(),
    &scopes,
    Duration::from_secs(3600),
    None,
)?;

// Verify.
token.verify(None)?;
println!("Token valid for: {:?}", token.scopes);
```

### CLI

```bash
# Initialize a workspace with a root keypair.
okami init --trust-domain example.com

# Generate a worker keypair.
okami keygen --trust-domain example.com --workload worker/1 --output ./worker-keys/

# Inspect a credential.
okami inspect --credential ./worker-keys/credential.bin

# Issue a delegation token.
okami delegate \
  --from .okami/ \
  --to spiffe://example.com/worker/1 \
  --scopes read:db,invoke:llm \
  --expiry 3600 \
  --output token.bin

# Verify a chain.
okami verify-chain --chain chain.bin

# Visualize a chain.
okami tree --chain chain.bin
```

## Cryptography

| Operation | Algorithm | NIST Level |
|-----------|-----------|-----------|
| Key exchange | X25519 + ML-KEM-768 | 3 |
| Signing | Ed25519 + ML-DSA-65 | 3 |
| AEAD | ChaCha20-Poly1305 | — |
| Hashing | SHA-256 | — |

Private keys are handled by lupine types that zeroize on drop.
Key files are created with mode 0600; okami refuses to load keys with wider permissions.

## Delegation chains

Chains are depth-limited to 3 hops (human → orchestrator → worker → sub-worker).
Each token attenuates scopes — you can only grant capabilities you already hold.

```
[0] spiffe://example.com/orchestrator [read:db, write:api]
    -> [1] spiffe://example.com/worker/1 [read:db]
        -> [2] spiffe://example.com/sub-worker/1 [read:db]
```

## Building

```bash
cargo build
cargo test
cargo clippy
cargo run --example mutual_auth
```

## License

MIT OR Apache-2.0
