"""
RFC 6962 Merkle tree primitives (verifier-only).

Includes leaf_hash / node_hash / verify_inclusion. The proof-generation
functions (inclusion_proof, consistency_proof) are deliberately NOT
included — the verifier only VERIFIES proofs the operator produced.
Shipping the generation code would let a curious auditor generate their
own proofs, but it also expands the surface they must audit. Keep it
lean.

License: MIT.
"""

from __future__ import annotations

import hashlib
from typing import Sequence


LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 §2.1: MTH({d}) = SHA-256(0x00 || d)."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 §2.1: internal = SHA-256(0x01 || left || right). Order matters."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def empty_root() -> bytes:
    """RFC 6962: MTH({}) = SHA-256("")."""
    return hashlib.sha256(b"").digest()


def verify_inclusion(
    leaf: bytes,
    index: int,
    tree_size: int,
    proof: Sequence[bytes],
    expected_root: bytes,
) -> bool:
    """
    RFC 6962 §2.1.1 audit-path verifier.

    Reconstructs the root from the leaf + sibling hashes, returns True
    if it matches expected_root.
    """
    if index < 0 or index >= tree_size:
        return False

    fn = leaf
    r = index
    sn = tree_size - 1

    for sibling in proof:
        if sn == 0:
            return False
        if r % 2 == 1 or r == sn:
            fn = node_hash(sibling, fn)
            while r % 2 == 0 and r != 0:
                r //= 2
                sn //= 2
        else:
            fn = node_hash(fn, sibling)
        r //= 2
        sn //= 2

    return sn == 0 and fn == expected_root
