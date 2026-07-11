"""
world-model-mcp-verifier — standalone reference verifier.

Compliance auditors use this package to independently verify inclusion
proofs produced by a world-model-mcp server (v0.13+) opt-in
tamper-evident audit log.

Usage:

    from world_model_verifier import verify_inclusion_bundle

    ok, reason = verify_inclusion_bundle(
        bundle=inclusion_bundle_dict,
        ed25519_public_key=ed25519_pubkey_bytes,
        slh_dsa_public_key=slh_dsa_pubkey_bytes,
    )
    if ok:
        print("verified")
    else:
        print("verification failed:", reason)

Public keys are loaded from `public_keys.json` published by the
operator. The bundle is the JSON response of the server's MCP
`prove_entry_inclusion` tool.

License: MIT.
"""

from .canonical import canonical_json
from .hybrid import (
    DOMAIN_AUDIT_LOG_EPOCH_ROOT,
    SIGNATURE_ENVELOPE_VERSION,
    pubkey_fingerprint,
    verify_ed25519,
    verify_hybrid,
    verify_slh_dsa,
)
from .merkle import empty_root, leaf_hash, node_hash, verify_inclusion
from .verifier import EPOCH_GENESIS_ROOT, verify_inclusion_bundle

__version__ = "0.13.0"

__all__ = [
    "verify_inclusion_bundle",
    "verify_hybrid",
    "verify_ed25519",
    "verify_slh_dsa",
    "verify_inclusion",
    "canonical_json",
    "leaf_hash",
    "node_hash",
    "empty_root",
    "pubkey_fingerprint",
    "DOMAIN_AUDIT_LOG_EPOCH_ROOT",
    "SIGNATURE_ENVELOPE_VERSION",
    "EPOCH_GENESIS_ROOT",
    "__version__",
]
