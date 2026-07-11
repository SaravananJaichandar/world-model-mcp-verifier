# world-model-mcp-verifier

Standalone reference verifier for the [world-model-mcp](https://github.com/SaravananJaichandar/world-model-mcp) v0.13+ tamper-evident audit log. **Python + TypeScript**, both languages tested against the same JSON test vectors so drift is caught at CI time.

Compliance auditors download this repo, pin the operator's public-key fingerprints, and verify audit-log inclusion proofs locally. Nothing here depends on the world-model-mcp server at runtime — that is the point. If the server can convince this verifier that a fact was recorded in a signed epoch, the fact was recorded. If it cannot, verification fails with a specific reason.

## What gets verified

Given an inclusion-proof bundle produced by the world-model-mcp server's `prove_entry_inclusion` MCP tool + the operator's Ed25519 and SLH-DSA-SHA2-128f public keys, the verifier confirms:

1. Every closed epoch in the chain has a hybrid signature that verifies under the operator's public keys against the canonical epoch payload.
2. Each epoch's `prev_epoch_root` matches the previous epoch's `merkle_root` (or `EPOCH_GENESIS_ROOT` for the first).
3. The RFC 6962 Merkle inclusion proof verifies for the entry's `row_hash` at the given `leaf_index` against the containing epoch's `merkle_root`.

Any single failure returns a specific reason — which epoch, which check. The verifier fails closed on every unexpected input.

## Algorithm choices

- **Hash function:** SHA-256 (FIPS 180-4).
- **Signature primitives:** Ed25519 (FIPS 186-5) + SLH-DSA-SHA2-128f (FIPS 205). Hybrid — both signatures required for verification.
- **Merkle tree:** RFC 6962 (same as Certificate Transparency).
- **Domain separation:** every signed message is prefixed with `world-model-mcp/audit-log/epoch-root/v1\0`.

Full rationale in [docs/AUDIT_LOG.md](https://github.com/SaravananJaichandar/world-model-mcp/blob/main/docs/AUDIT_LOG.md) on the main repo.

## Python

Install:

```bash
pip install world-model-mcp-verifier
```

Use:

```python
import json
from world_model_verifier import verify_inclusion_bundle

# 1. Get the bundle from the operator's world-model-mcp server via MCP.
bundle = json.loads(...)  # from prove_entry_inclusion

# 2. Load the operator's public keys from their public_keys.json.
ed25519_pubkey = bytes.fromhex(public_keys["ed25519"]["public_key_hex"])
slh_dsa_pubkey = bytes.fromhex(public_keys["slh_dsa"]["public_key_hex"])

# 3. Verify locally.
ok, reason = verify_inclusion_bundle(bundle, ed25519_pubkey, slh_dsa_pubkey)
if ok:
    print("Verified: fact was recorded in a signed epoch.")
else:
    print("Verification failed:", reason)
```

Development:

```bash
cd python
pip install -e .[dev]
pytest
```

## TypeScript

Install:

```bash
npm install @world-model-mcp/verifier
```

Use:

```typescript
import { verifyInclusionBundle } from "@world-model-mcp/verifier";

const bundle = /* prove_entry_inclusion response */;
const ed25519PublicKey = hexToBytes(publicKeys.ed25519.public_key_hex);
const slhDsaPublicKey  = hexToBytes(publicKeys.slh_dsa.public_key_hex);

const result = verifyInclusionBundle(bundle, ed25519PublicKey, slhDsaPublicKey);
if (result.ok) {
  console.log("Verified.");
} else {
  console.log("Verification failed:", result.reason);
}
```

Development:

```bash
cd typescript
npm install
npm test
```

## Shared test vectors

The [`vectors/`](./vectors/) directory holds JSON test vectors that both language implementations must pass. If Python and TypeScript ever produce different verification results for the same input, one of them has drifted. CI on both sides runs against these vectors.

Regenerate the vectors from a live world-model-mcp install:

```bash
pip install world-model-mcp>=0.13.0
python scripts/generate_vectors.py
```

Vectors currently cover:

- `canonical.json` — canonical JSON serialization outputs
- `merkle.json` — RFC 6962 leaf / node / root / inclusion proof outputs
- `inclusion-bundle.json` — a real inclusion bundle + operator public keys + expected verify=True

## Threat model

The verifier confirms what the audit log claims. It does NOT prove:

- The operator wrote every fact that should have been written. Selective non-inclusion is out of scope.
- The operator's public keys are the real operator's. The auditor is responsible for pinning fingerprints from a trusted channel.
- The operator's process was correct at write time. If the operator's server was compromised while running, the audit log records the malicious writes with legitimate signatures.

What the verifier DOES prove: given the operator's public keys, either (a) the specific fact under scrutiny was recorded in a signed epoch that chains back to genesis, or (b) verification fails with a specific reason pointing at a specific epoch or Merkle-inclusion problem. Nothing in between.

## License

MIT for code and vectors. See [LICENSE](./LICENSE).
