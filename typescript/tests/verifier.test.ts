/**
 * Test the TypeScript reference verifier against the shared JSON vectors.
 *
 * If a Python test passes and the corresponding TypeScript test fails
 * (or vice versa) on the same vector, the implementations have drifted.
 * CI runs both sides; drift breaks the release.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  bytesToHex,
  canonicalJson,
  emptyRoot,
  hexToBytes,
  leafHash,
  nodeHash,
  verifyInclusion,
  verifyInclusionBundle,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, "..", "..", "vectors");

function loadVector(name: string): unknown {
  return JSON.parse(readFileSync(resolve(VECTORS_DIR, name), "utf8"));
}

describe("canonical JSON vectors", () => {
  const cases = loadVector("canonical.json") as Array<{
    input: unknown;
    expected_hex: string;
  }>;

  it.each(cases.map((c, i) => [i, c.input, c.expected_hex]))(
    "case %i: canonicalJson matches Python bytes",
    (_i, input, expectedHex) => {
      const actual = bytesToHex(canonicalJson(input));
      expect(actual).toBe(expectedHex);
    },
  );
});

describe("Merkle vectors", () => {
  const v = loadVector("merkle.json") as {
    tree_size: number;
    root_hex: string;
    empty_root_hex: string;
    leaf_hash_examples: Array<{ data_hex: string; expected_hex: string }>;
    node_hash_example: {
      left_hex: string;
      right_hex: string;
      expected_hex: string;
    };
    inclusion_verifications: Array<{
      leaf_index: number;
      leaf_hex: string;
      proof_hex: string[];
      expected_verify: boolean;
    }>;
  };

  it("empty root", () => {
    expect(bytesToHex(emptyRoot())).toBe(v.empty_root_hex);
  });

  it.each(v.leaf_hash_examples.map((ex, i) => [i, ex.data_hex, ex.expected_hex]))(
    "leaf_hash case %i",
    (_i, dataHex, expectedHex) => {
      const data = hexToBytes(dataHex as string);
      expect(bytesToHex(leafHash(data))).toBe(expectedHex);
    },
  );

  it("node_hash example", () => {
    const left = hexToBytes(v.node_hash_example.left_hex);
    const right = hexToBytes(v.node_hash_example.right_hex);
    expect(bytesToHex(nodeHash(left, right))).toBe(
      v.node_hash_example.expected_hex,
    );
  });

  it.each(
    v.inclusion_verifications.map((c, i) => [
      i,
      c.leaf_index,
      c.leaf_hex,
      c.proof_hex,
      c.expected_verify,
    ]),
  )(
    "inclusion verification case %i (index=%i, expected=%s)",
    (_i, leafIndex, leafHex, proofHex, expected) => {
      const leaf = hexToBytes(leafHex as string);
      const proof = (proofHex as string[]).map((h) => hexToBytes(h));
      const root = hexToBytes(v.root_hex);
      const actual = verifyInclusion({
        leaf,
        index: leafIndex as number,
        treeSize: v.tree_size,
        proof,
        expectedRoot: root,
      });
      expect(actual).toBe(expected);
    },
  );
});

describe("inclusion bundle vector", () => {
  const vector = loadVector("inclusion-bundle.json") as {
    bundle: any;
    operator_public_keys: { ed25519_hex: string; slh_dsa_hex: string };
    expected_verify: boolean;
  };
  const edPub = hexToBytes(vector.operator_public_keys.ed25519_hex);
  const slhPub = hexToBytes(vector.operator_public_keys.slh_dsa_hex);

  it("full bundle verifies", () => {
    const result = verifyInclusionBundle(vector.bundle, edPub, slhPub);
    expect(result.ok).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it("tampered row_hash fails", () => {
    const tampered = JSON.parse(JSON.stringify(vector.bundle));
    tampered.row_hash = "sha256:" + "00".repeat(32);
    const result = verifyInclusionBundle(tampered, edPub, slhPub);
    expect(result.ok).toBe(false);
    expect(result.reason?.toLowerCase()).toContain("inclusion");
  });

  it("stripped slh_dsa half is rejected", () => {
    // Attacker sets the PQ half to null hoping the verifier falls back
    // to Ed25519-only. The verifier MUST reject.
    const tampered = JSON.parse(JSON.stringify(vector.bundle));
    tampered.epoch_chain[0].signature_envelope.slh_dsa = null;
    const result = verifyInclusionBundle(tampered, edPub, slhPub);
    expect(result.ok).toBe(false);
    expect(result.reason?.toLowerCase()).toContain("signature");
  });
});
