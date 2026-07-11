"""
Inclusion-bundle verifier — the load-bearing function auditors call.

Given an inclusion-proof bundle from `prove_entry_inclusion` and the
operator's two public keys, returns (True, None) on successful
verification or (False, reason) on the first failure.

Reason strings name the specific failure so an auditor can trace back to
a particular epoch or Merkle-inclusion issue. This is the contract the
TypeScript implementation MUST reproduce byte-for-byte.

License: MIT.
"""

from __future__ import annotations

from typing import Optional

from . import hybrid, merkle
from .canonical import canonical_json


# Must match server's EPOCH_GENESIS_ROOT constant, which is seeded from
# a versioned string. Reproduced here as a hex-literal so the verifier
# does not import the server.
EPOCH_GENESIS_ROOT: str = "sha256:" + __import__("hashlib").sha256(
    b"world-model-mcp tamper-evident epochs v1"
).hexdigest()


def verify_inclusion_bundle(
    bundle: dict,
    ed25519_public_key: bytes,
    slh_dsa_public_key: bytes,
) -> tuple[bool, Optional[str]]:
    """
    Verify a full inclusion-proof bundle.

    Checks, in order:
      1. Every epoch in the chain has a signature envelope that verifies
         under the operator's public keys against the canonical epoch
         payload.
      2. Each `prev_epoch_root` matches the previous epoch's `merkle_root`
         (or `EPOCH_GENESIS_ROOT` for the first).
      3. The Merkle inclusion proof verifies for the entry's row_hash at
         `leaf_index` against the containing epoch's `merkle_root`.

    Returns (True, None) on success. On failure returns (False, reason)
    with a specific human-readable diagnostic.
    """

    prev_root = EPOCH_GENESIS_ROOT
    for e in bundle.get("epoch_chain", []):
        if e["prev_epoch_root"] != prev_root:
            return (
                False,
                f"epoch {e['seq']}: prev_epoch_root does not chain "
                f"(expected {prev_root}, got {e['prev_epoch_root']})",
            )
        payload = {
            "merkle_root": e["merkle_root"],
            "prev_epoch_root": e["prev_epoch_root"],
            "first_entry_seq": e["first_entry_seq"],
            "last_entry_seq": e["last_entry_seq"],
            "entry_count": e["entry_count"],
            "closed_at": e["closed_at"],
        }
        signed_bytes = canonical_json(payload)
        env = e["signature_envelope"]
        if not hybrid.verify_hybrid(
            envelope=env,
            message=signed_bytes,
            ed25519_public_key=ed25519_public_key,
            slh_dsa_public_key=slh_dsa_public_key,
        ):
            return False, f"epoch {e['seq']}: hybrid signature does not verify"
        prev_root = e["merkle_root"]

    epoch = bundle["epoch"]
    inclusion = bundle["inclusion"]
    row_hash_hex = bundle["row_hash"].split(":", 1)[1]
    leaf = merkle.leaf_hash(bytes.fromhex(row_hash_hex))
    proof_bytes = [bytes.fromhex(h) for h in inclusion["proof"]]
    expected_root_hex = epoch["merkle_root"].split(":", 1)[1]
    expected_root = bytes.fromhex(expected_root_hex)

    if not merkle.verify_inclusion(
        leaf=leaf,
        index=inclusion["leaf_index"],
        tree_size=inclusion["tree_size"],
        proof=proof_bytes,
        expected_root=expected_root,
    ):
        return (
            False,
            f"inclusion proof failed for row_id {bundle['row_id']!r} "
            f"at index {inclusion['leaf_index']} in epoch {epoch['seq']}",
        )

    return True, None
