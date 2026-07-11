/**
 * RFC 6962 Merkle tree primitives (verifier-only).
 *
 * Byte-for-byte identical to the Python reference. Shared vectors in
 * `../vectors/merkle.json` are the contract.
 *
 * License: MIT.
 */

import { sha256 } from "@noble/hashes/sha256.js";
import { concatBytes } from "@noble/hashes/utils.js";

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

/** RFC 6962 §2.1: MTH({d}) = SHA-256(0x00 || d). */
export function leafHash(data: Uint8Array): Uint8Array {
  return sha256(concatBytes(LEAF_PREFIX, data));
}

/** RFC 6962 §2.1: internal = SHA-256(0x01 || left || right). Order matters. */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(NODE_PREFIX, left, right));
}

/** RFC 6962: MTH({}) = SHA-256(""). */
export function emptyRoot(): Uint8Array {
  return sha256(new Uint8Array(0));
}

/**
 * RFC 6962 §2.1.1 audit-path verifier.
 * Reconstructs the root from the leaf + sibling hashes, returns true
 * if it matches expectedRoot.
 */
export function verifyInclusion(params: {
  leaf: Uint8Array;
  index: number;
  treeSize: number;
  proof: Uint8Array[];
  expectedRoot: Uint8Array;
}): boolean {
  const { leaf, index, treeSize, proof, expectedRoot } = params;
  if (index < 0 || index >= treeSize) return false;

  let fn = leaf;
  let r = index;
  let sn = treeSize - 1;

  for (const sibling of proof) {
    if (sn === 0) return false;
    if (r % 2 === 1 || r === sn) {
      fn = nodeHash(sibling, fn);
      while (r % 2 === 0 && r !== 0) {
        r = Math.floor(r / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      fn = nodeHash(fn, sibling);
    }
    r = Math.floor(r / 2);
    sn = Math.floor(sn / 2);
  }

  return sn === 0 && bytesEqual(fn, expectedRoot);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
