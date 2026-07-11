/**
 * Inclusion-bundle verifier — the load-bearing function auditors call.
 *
 * Byte-for-byte identical to the Python reference
 * (`world_model_verifier.verifier.verify_inclusion_bundle`).
 *
 * License: MIT.
 */

import { sha256 } from "@noble/hashes/sha256.js";

import { canonicalJson } from "./canonical.js";
import { hexToBytes, verifyHybrid, type SignatureEnvelope } from "./hybrid.js";
import { leafHash, verifyInclusion } from "./merkle.js";

/**
 * Genesis root for the epoch chain. Must match the Python reference's
 * `EPOCH_GENESIS_ROOT` constant.
 */
export const EPOCH_GENESIS_ROOT: string = (() => {
  const seed = new TextEncoder().encode(
    "world-model-mcp tamper-evident epochs v1",
  );
  const digest = sha256(seed);
  return "sha256:" + bytesToHexLocal(digest);
})();

function bytesToHexLocal(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export interface InclusionBundleEpoch {
  seq: number;
  merkle_root: string;
  prev_epoch_root: string;
  first_entry_seq: number;
  last_entry_seq: number;
  entry_count: number;
  signature_envelope: SignatureEnvelope;
  closed_at: string;
}

export interface InclusionBundle {
  row_id: string;
  entry_seq: number;
  entry_kind: string;
  row_hash: string;
  prev_hash: string;
  entry_hash: string;
  entry_ts: string;
  epoch: InclusionBundleEpoch;
  inclusion: {
    leaf_index: number;
    tree_size: number;
    proof: string[];  // hex
  };
  epoch_chain: InclusionBundleEpoch[];
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

/**
 * Verify a full inclusion-proof bundle.
 *
 * Checks, in order:
 *   1. Every epoch in the chain has a signature envelope that verifies
 *      under the operator's public keys against the canonical epoch
 *      payload.
 *   2. Each prev_epoch_root matches the previous epoch's merkle_root
 *      (or EPOCH_GENESIS_ROOT for the first).
 *   3. The Merkle inclusion proof verifies for the entry's row_hash at
 *      leaf_index against the containing epoch's merkle_root.
 *
 * Returns { ok: true } on success. On failure, { ok: false, reason }
 * with a specific human-readable diagnostic.
 */
export function verifyInclusionBundle(
  bundle: InclusionBundle,
  ed25519PublicKey: Uint8Array,
  slhDsaPublicKey: Uint8Array,
): VerifyResult {
  let prevRoot = EPOCH_GENESIS_ROOT;

  for (const e of bundle.epoch_chain ?? []) {
    if (e.prev_epoch_root !== prevRoot) {
      return {
        ok: false,
        reason:
          `epoch ${e.seq}: prev_epoch_root does not chain ` +
          `(expected ${prevRoot}, got ${e.prev_epoch_root})`,
      };
    }
    // Canonical JSON payload signed by the operator.
    const payload = {
      merkle_root: e.merkle_root,
      prev_epoch_root: e.prev_epoch_root,
      first_entry_seq: e.first_entry_seq,
      last_entry_seq: e.last_entry_seq,
      entry_count: e.entry_count,
      closed_at: e.closed_at,
    };
    const signedBytes = canonicalJson(payload);
    if (
      !verifyHybrid({
        envelope: e.signature_envelope,
        message: signedBytes,
        ed25519PublicKey,
        slhDsaPublicKey,
      })
    ) {
      return {
        ok: false,
        reason: `epoch ${e.seq}: hybrid signature does not verify`,
      };
    }
    prevRoot = e.merkle_root;
  }

  const epoch = bundle.epoch;
  const inclusion = bundle.inclusion;
  const rowHashHex = bundle.row_hash.split(":", 2)[1];
  const leaf = leafHash(hexToBytes(rowHashHex));
  const proofBytes = inclusion.proof.map((h) => hexToBytes(h));
  const expectedRootHex = epoch.merkle_root.split(":", 2)[1];
  const expectedRoot = hexToBytes(expectedRootHex);

  if (
    !verifyInclusion({
      leaf,
      index: inclusion.leaf_index,
      treeSize: inclusion.tree_size,
      proof: proofBytes,
      expectedRoot,
    })
  ) {
    return {
      ok: false,
      reason:
        `inclusion proof failed for row_id ${JSON.stringify(bundle.row_id)} ` +
        `at index ${inclusion.leaf_index} in epoch ${epoch.seq}`,
    };
  }

  return { ok: true };
}
