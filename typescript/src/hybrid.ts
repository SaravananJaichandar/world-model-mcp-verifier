/**
 * Hybrid signature verifier — Ed25519 + SLH-DSA-SHA2-128f, both required.
 *
 * Verifier-only. Byte-for-byte identical to Python reference.
 *
 * Uses @noble packages (same libraries the Suzhi PQ stack uses):
 *   - @noble/curves/ed25519 for Ed25519
 *   - @noble/post-quantum/slh-dsa for SLH-DSA-SHA2-128f
 *   - @noble/hashes/sha256 for pubkey fingerprints
 *
 * License: MIT.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha256.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { slh_dsa_sha2_128f } from "@noble/post-quantum/slh-dsa";

export const SIGNATURE_ENVELOPE_VERSION = 1;

/** MUST match world-model-mcp server's DOMAIN_AUDIT_LOG_EPOCH_ROOT. */
export const DOMAIN_AUDIT_LOG_EPOCH_ROOT = new TextEncoder().encode(
  "world-model-mcp/audit-log/epoch-root/v1",
);

export const SLH_DSA_PUBLIC_KEY_BYTES = 32;   // slh_dsa_sha2_128f public key
export const SLH_DSA_SIGNATURE_BYTES = 17088; // slh_dsa_sha2_128f signature

export interface SignatureEnvelope {
  version: number;
  ed25519: string;         // hex
  slh_dsa: string | null;  // hex, or null to trigger a null-check rejection
  ed25519_pubkey_fingerprint?: string;
  slh_dsa_pubkey_fingerprint?: string;
}

export function pubkeyFingerprint(publicKeyBytes: Uint8Array): string {
  const digest = sha256(publicKeyBytes);
  return "sha256:" + bytesToHex(digest);
}

export function domainSeparate(
  domain: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  return concatBytes(domain, new Uint8Array([0x00]), message);
}

export function verifyEd25519(
  publicKeyBytes: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  domain: Uint8Array = DOMAIN_AUDIT_LOG_EPOCH_ROOT,
): boolean {
  try {
    return ed25519.verify(
      signature,
      domainSeparate(domain, message),
      publicKeyBytes,
    );
  } catch {
    return false;
  }
}

export function verifySlhDsa(
  publicKeyBytes: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  domain: Uint8Array = DOMAIN_AUDIT_LOG_EPOCH_ROOT,
): boolean {
  if (signature.length !== SLH_DSA_SIGNATURE_BYTES) return false;
  if (publicKeyBytes.length !== SLH_DSA_PUBLIC_KEY_BYTES) return false;
  try {
    // Note: @noble/post-quantum's verify signature is
    // (publicKey, msg, sig) — different order from @noble/curves ed25519
    // which is (sig, msg, publicKey). Caught this footgun during verifier
    // build; both orderings are internally consistent but incompatible
    // across the two noble packages.
    return slh_dsa_sha2_128f.verify(
      publicKeyBytes,
      domainSeparate(domain, message),
      signature,
    );
  } catch {
    return false;
  }
}

/**
 * Verify a HybridSigner envelope. Both signatures required.
 *
 * Rejects on any error including:
 *   - wrong envelope version
 *   - missing / non-string / null slh_dsa (attempted downgrade)
 *   - malformed hex
 *   - either signature failing to verify
 */
export function verifyHybrid(params: {
  envelope: SignatureEnvelope;
  message: Uint8Array;
  ed25519PublicKey: Uint8Array;
  slhDsaPublicKey: Uint8Array;
}): boolean {
  const { envelope, message, ed25519PublicKey, slhDsaPublicKey } = params;
  if (envelope.version !== SIGNATURE_ENVELOPE_VERSION) return false;
  if (typeof envelope.ed25519 !== "string") return false;
  if (typeof envelope.slh_dsa !== "string") return false;

  let edSig: Uint8Array;
  let slhSig: Uint8Array;
  try {
    edSig = hexToBytes(envelope.ed25519);
    slhSig = hexToBytes(envelope.slh_dsa);
  } catch {
    return false;
  }

  if (!verifyEd25519(ed25519PublicKey, message, edSig)) return false;
  if (!verifySlhDsa(slhDsaPublicKey, message, slhSig)) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (s.length % 2 !== 0) throw new Error("odd-length hex string");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(s.substring(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("invalid hex character");
    out[i] = byte;
  }
  return out;
}
