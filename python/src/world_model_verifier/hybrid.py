"""
Hybrid signature verifier — Ed25519 + SLH-DSA-SHA2-128f, both required.

Verifier-only surface. No key generation, no signing. If an auditor
wants to verify epoch signatures, they need only these three functions
and the operator's two public keys.

License: MIT.
"""

from __future__ import annotations

import hashlib
from typing import Optional

import pyspx.sha2_128f as _slh_dsa
from cryptography.hazmat.primitives.asymmetric import ed25519


SIGNATURE_ENVELOPE_VERSION = 1

# MUST match world-model-mcp server's DOMAIN_AUDIT_LOG_EPOCH_ROOT.
DOMAIN_AUDIT_LOG_EPOCH_ROOT = b"world-model-mcp/audit-log/epoch-root/v1"

SLH_DSA_PUBLIC_KEY_BYTES = _slh_dsa.crypto_sign_PUBLICKEYBYTES
SLH_DSA_SIGNATURE_BYTES = _slh_dsa.crypto_sign_BYTES


def pubkey_fingerprint(public_key_bytes: bytes) -> str:
    """`sha256:` prefixed hex digest of a public key."""
    return "sha256:" + hashlib.sha256(public_key_bytes).hexdigest()


def domain_separate(domain: bytes, message: bytes) -> bytes:
    """Null-separated domain-message concatenation."""
    return domain + b"\x00" + message


def verify_ed25519(
    public_key_bytes: bytes,
    message: bytes,
    signature: bytes,
    domain: bytes = DOMAIN_AUDIT_LOG_EPOCH_ROOT,
) -> bool:
    """Verify Ed25519 over the domain-separated message. Fails closed on any error."""
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, domain_separate(domain, message))
        return True
    except Exception:
        return False


def verify_slh_dsa(
    public_key_bytes: bytes,
    message: bytes,
    signature: bytes,
    domain: bytes = DOMAIN_AUDIT_LOG_EPOCH_ROOT,
) -> bool:
    """Verify SLH-DSA-SHA2-128f over the domain-separated message. Fails closed."""
    if len(signature) != SLH_DSA_SIGNATURE_BYTES:
        return False
    if len(public_key_bytes) != SLH_DSA_PUBLIC_KEY_BYTES:
        return False
    try:
        return _slh_dsa.verify(
            domain_separate(domain, message), signature, public_key_bytes
        )
    except Exception:
        return False


def verify_hybrid(
    envelope: dict,
    message: bytes,
    ed25519_public_key: bytes,
    slh_dsa_public_key: bytes,
) -> bool:
    """
    Verify a HybridSigner envelope. Both signatures required. Returns True
    if and only if:

    - envelope["ed25519"] is valid under ed25519_public_key, AND
    - envelope["slh_dsa"] is valid under slh_dsa_public_key.

    An envelope missing either field, with a null slh_dsa (attempted
    downgrade to Ed25519-only), or with the wrong version is rejected.
    """
    if envelope.get("version") != SIGNATURE_ENVELOPE_VERSION:
        return False

    ed_hex = envelope.get("ed25519")
    slh_hex = envelope.get("slh_dsa")
    if not isinstance(ed_hex, str) or not isinstance(slh_hex, str):
        return False

    try:
        ed_sig = bytes.fromhex(ed_hex)
        slh_sig = bytes.fromhex(slh_hex)
    except ValueError:
        return False

    if not verify_ed25519(ed25519_public_key, message, ed_sig):
        return False
    if not verify_slh_dsa(slh_dsa_public_key, message, slh_sig):
        return False
    return True
