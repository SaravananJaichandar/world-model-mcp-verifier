/**
 * Canonical JSON serialization for the world-model-mcp audit log verifier.
 *
 * Byte-for-byte identical to the Python reference (`world_model_verifier.canonical.canonical_json`).
 * Shared JSON test vectors in `../vectors/canonical.json` are the contract.
 *
 * Rules:
 * - Keys sorted alphabetically at every level.
 * - Separators: no whitespace between tokens.
 * - Non-ASCII characters pass through as UTF-8 (NOT escaped to \uXXXX).
 * - `set` becomes a sorted array. TS Set is serialized as a sorted array
 *   of its elements (JSON has no set primitive; this matches the Python
 *   behavior for the shared vectors).
 *
 * License: MIT.
 */

export function canonicalJson(value: unknown): Uint8Array {
  const s = canonicalStringify(value);
  return new TextEncoder().encode(s);
}

function canonicalStringify(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("cannot canonicalize non-finite number");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    // ensureAscii=false in the Python reference. JSON.stringify escapes
    // non-ASCII to \uXXXX by default; we need to preserve UTF-8 to
    // match the Python bytes output.
    return quoteUtf8(value);
  }
  if (value instanceof Set) {
    const sorted = Array.from(value).sort();
    return "[" + sorted.map(canonicalStringify).join(",") + "]";
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalStringify).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return (
      "{" +
      keys.map((k) => quoteUtf8(k) + ":" + canonicalStringify(obj[k])).join(",") +
      "}"
    );
  }
  throw new TypeError(`cannot canonicalize value of type ${typeof value}`);
}

/**
 * JSON-quote a string while preserving non-ASCII code points as UTF-8.
 *
 * The Python reference uses `json.dumps(..., ensure_ascii=False)`.
 * JavaScript's built-in JSON.stringify has no equivalent flag, so we
 * hand-roll the minimum escape set (per RFC 8259) and let non-ASCII
 * survive.
 */
function quoteUtf8(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    switch (c) {
      case 0x22: out += "\\\""; break;
      case 0x5c: out += "\\\\"; break;
      case 0x08: out += "\\b"; break;
      case 0x09: out += "\\t"; break;
      case 0x0a: out += "\\n"; break;
      case 0x0c: out += "\\f"; break;
      case 0x0d: out += "\\r"; break;
      default:
        if (c < 0x20) {
          out += "\\u" + c.toString(16).padStart(4, "0");
        } else {
          out += s[i];
        }
    }
  }
  return out + '"';
}
