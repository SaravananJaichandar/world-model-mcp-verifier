"""
Generate shared JSON test vectors for the reference verifier.

Both the Python and TypeScript implementations run their tests against
the same vectors. If either side drifts, its CI breaks — that is the
contract.

This script is checked in so anyone can regenerate the vectors from a
clean world-model-mcp install. Deterministic seeds are used where the
underlying algorithms support them; otherwise the vectors include the
signatures produced at generation time (SLH-DSA is nondeterministic in
pyspx's default configuration, so those signatures cannot be reproduced
bit-for-bit — but verification of the recorded signatures is still
deterministic).

Regenerate:
    python scripts/generate_vectors.py

License: MIT.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

# Ensure we can import world-model-mcp itself for the bundle generator.
try:
    from world_model_server import audit_keys, tamper_evident, merkle as srv_merkle
    from world_model_server.knowledge_graph import KnowledgeGraph
    from world_model_server.models import Event
except ImportError:
    print(
        "error: world-model-mcp must be installed to regenerate vectors.\n"
        "Install it via `pip install world-model-mcp>=0.13.0` and rerun."
    )
    sys.exit(1)


VECTORS_DIR = Path(__file__).resolve().parent.parent / "vectors"


def gen_canonical_vectors() -> list[dict]:
    """Static canonical JSON vectors. Byte-for-byte identical across languages."""
    from world_model_server.tamper_evident import canonical_json

    cases = [
        {"input": {}, "expected_hex": canonical_json({}).hex()},
        {
            "input": {"a": 1, "b": 2},
            "expected_hex": canonical_json({"a": 1, "b": 2}).hex(),
        },
        {
            # Key order should not affect output — sorted-keys is the contract.
            "input": {"z": 1, "a": 2, "m": 3},
            "expected_hex": canonical_json({"z": 1, "a": 2, "m": 3}).hex(),
        },
        {
            "input": {"outer": {"z": 1, "a": 2}},
            "expected_hex": canonical_json({"outer": {"z": 1, "a": 2}}).hex(),
        },
        {
            "input": {"strings": ["c", "b", "a"]},
            "expected_hex": canonical_json({"strings": ["c", "b", "a"]}).hex(),
        },
        {
            "input": {"unicode": "héllo"},
            "expected_hex": canonical_json({"unicode": "héllo"}).hex(),
        },
    ]
    return cases


def gen_merkle_vectors() -> dict:
    """RFC 6962 leaf / node / root vectors + inclusion-proof verifications."""
    leaves = [srv_merkle.leaf_hash(str(i).encode()) for i in range(8)]
    root = srv_merkle.merkle_root(leaves)

    proofs = []
    for i in range(len(leaves)):
        proof = srv_merkle.inclusion_proof(i, leaves)
        proofs.append({
            "leaf_index": i,
            "leaf_hex": leaves[i].hex(),
            "proof_hex": [p.hex() for p in proof],
            "expected_verify": True,
        })

    # Also include a known-fail case: same proof but wrong index.
    if len(leaves) >= 2:
        proofs.append({
            "leaf_index": 1,
            "leaf_hex": leaves[0].hex(),   # index says 1, leaf is from position 0
            "proof_hex": [p.hex() for p in srv_merkle.inclusion_proof(0, leaves)],
            "expected_verify": False,
        })

    return {
        "tree_size": len(leaves),
        "root_hex": root.hex(),
        "empty_root_hex": srv_merkle.empty_root().hex(),
        "leaf_hash_examples": [
            {"data_hex": "", "expected_hex": srv_merkle.leaf_hash(b"").hex()},
            {"data_hex": "48656c6c6f", "expected_hex": srv_merkle.leaf_hash(b"Hello").hex()},
        ],
        "node_hash_example": {
            "left_hex": leaves[0].hex(),
            "right_hex": leaves[1].hex(),
            "expected_hex": srv_merkle.node_hash(leaves[0], leaves[1]).hex(),
        },
        "inclusion_verifications": proofs,
    }


async def gen_inclusion_bundle_vector() -> dict:
    """Real inclusion bundle from a live epoch close."""
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["WORLD_MODEL_AUDIT_LOG"] = "on"
        os.environ["WORLD_MODEL_AUDIT_LOG_EPOCH_SIZE"] = "4"
        kg = KnowledgeGraph(tmp)
        await kg.initialize()

        events = [
            Event(
                session_id="vector-gen",
                event_type="file_edit",
                tool_name="Edit",
                entity_id=f"file-{i}",
                success=True,
            )
            for i in range(4)
        ]
        for e in events:
            await kg.create_event(e)

        # Rebuild proof for event index 2 (middle of the epoch).
        import aiosqlite
        async with aiosqlite.connect(kg.audit_db) as db:
            bundle = await tamper_evident.get_inclusion_proof(db, events[2].id)

        # Extract operator public keys for the vector.
        pk_payload = audit_keys.read_public_keys(kg.db_path)
        del os.environ["WORLD_MODEL_AUDIT_LOG"]
        del os.environ["WORLD_MODEL_AUDIT_LOG_EPOCH_SIZE"]

    return {
        "bundle": bundle,
        "operator_public_keys": {
            "ed25519_hex": pk_payload["ed25519"]["public_key_hex"],
            "slh_dsa_hex": pk_payload["slh_dsa"]["public_key_hex"],
        },
        "expected_verify": True,
    }


def main():
    VECTORS_DIR.mkdir(exist_ok=True)

    canonical = gen_canonical_vectors()
    (VECTORS_DIR / "canonical.json").write_text(
        json.dumps(canonical, indent=2) + "\n"
    )
    print(f"wrote canonical.json ({len(canonical)} cases)")

    merkle = gen_merkle_vectors()
    (VECTORS_DIR / "merkle.json").write_text(json.dumps(merkle, indent=2) + "\n")
    print(f"wrote merkle.json (tree_size={merkle['tree_size']})")

    bundle_vector = asyncio.run(gen_inclusion_bundle_vector())
    (VECTORS_DIR / "inclusion-bundle.json").write_text(
        json.dumps(bundle_vector, indent=2, default=str) + "\n"
    )
    print("wrote inclusion-bundle.json")


if __name__ == "__main__":
    main()
