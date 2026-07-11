"""
Test the Python reference verifier against the shared JSON vectors.

Both Python and TypeScript implementations run identical vector tests.
Any drift breaks CI on the drifting side.

License: MIT.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from world_model_verifier import (
    canonical_json,
    empty_root,
    leaf_hash,
    node_hash,
    verify_inclusion,
    verify_inclusion_bundle,
)


VECTORS_DIR = Path(__file__).resolve().parents[2] / "vectors"


def _load(name: str) -> dict | list:
    with open(VECTORS_DIR / name, "r", encoding="utf-8") as f:
        return json.load(f)


class TestCanonicalVectors:
    def test_every_case(self):
        cases = _load("canonical.json")
        for i, case in enumerate(cases):
            actual = canonical_json(case["input"]).hex()
            assert actual == case["expected_hex"], (
                f"canonical.json case {i}: input={case['input']!r} "
                f"expected {case['expected_hex']} got {actual}"
            )


class TestMerkleVectors:
    def test_empty_root(self):
        vectors = _load("merkle.json")
        assert empty_root().hex() == vectors["empty_root_hex"]

    def test_leaf_hash_examples(self):
        vectors = _load("merkle.json")
        for ex in vectors["leaf_hash_examples"]:
            data = bytes.fromhex(ex["data_hex"])
            assert leaf_hash(data).hex() == ex["expected_hex"]

    def test_node_hash_example(self):
        vectors = _load("merkle.json")
        ex = vectors["node_hash_example"]
        assert (
            node_hash(bytes.fromhex(ex["left_hex"]), bytes.fromhex(ex["right_hex"])).hex()
            == ex["expected_hex"]
        )

    def test_inclusion_verifications(self):
        vectors = _load("merkle.json")
        root = bytes.fromhex(vectors["root_hex"])
        tree_size = vectors["tree_size"]
        for i, case in enumerate(vectors["inclusion_verifications"]):
            leaf = bytes.fromhex(case["leaf_hex"])
            proof = [bytes.fromhex(p) for p in case["proof_hex"]]
            actual = verify_inclusion(
                leaf=leaf,
                index=case["leaf_index"],
                tree_size=tree_size,
                proof=proof,
                expected_root=root,
            )
            assert actual is case["expected_verify"], (
                f"merkle.json inclusion case {i}: "
                f"leaf_index={case['leaf_index']} "
                f"expected {case['expected_verify']} got {actual}"
            )


class TestInclusionBundleVector:
    def test_full_bundle_verifies(self):
        vector = _load("inclusion-bundle.json")
        bundle = vector["bundle"]
        ed_pub = bytes.fromhex(vector["operator_public_keys"]["ed25519_hex"])
        slh_pub = bytes.fromhex(vector["operator_public_keys"]["slh_dsa_hex"])
        ok, reason = verify_inclusion_bundle(bundle, ed_pub, slh_pub)
        assert ok, f"expected verify_inclusion_bundle to succeed, got: {reason}"

    def test_tampered_row_hash_fails(self):
        vector = _load("inclusion-bundle.json")
        bundle = dict(vector["bundle"])
        bundle["row_hash"] = "sha256:" + "00" * 32
        ed_pub = bytes.fromhex(vector["operator_public_keys"]["ed25519_hex"])
        slh_pub = bytes.fromhex(vector["operator_public_keys"]["slh_dsa_hex"])
        ok, reason = verify_inclusion_bundle(bundle, ed_pub, slh_pub)
        assert not ok
        assert "inclusion" in reason.lower()

    def test_stripped_slh_dsa_half_fails(self):
        """
        Attacker strips the post-quantum half from the envelope. Verifier
        MUST reject — the whole point of hybrid.
        """
        vector = _load("inclusion-bundle.json")
        bundle = json.loads(json.dumps(vector["bundle"]))  # deep copy
        bundle["epoch_chain"][0]["signature_envelope"]["slh_dsa"] = None
        ed_pub = bytes.fromhex(vector["operator_public_keys"]["ed25519_hex"])
        slh_pub = bytes.fromhex(vector["operator_public_keys"]["slh_dsa_hex"])
        ok, reason = verify_inclusion_bundle(bundle, ed_pub, slh_pub)
        assert not ok
        assert "signature" in reason.lower()
