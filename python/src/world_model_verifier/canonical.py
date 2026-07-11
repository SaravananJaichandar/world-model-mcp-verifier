"""
Canonical JSON serialization for the world-model-mcp audit log verifier.

Byte-for-byte identical to `world_model_server.tamper_evident.canonical_json`.
Verifiers on any implementation MUST produce the same output for the same
input; the shared test vectors at `vectors/canonical.json` are the
contract.

License: MIT.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """
    Deterministic JSON serialization suitable for hashing.

    Rules (must match the world-model-mcp server implementation exactly):
    - Keys sorted alphabetically at every level.
    - Separators: no whitespace, `(",", ":")`.
    - Non-ASCII: pass through as UTF-8, not escaped.
    - datetime: normalized to UTC ISO-8601 with `Z` suffix and millisecond
      precision (trailing microseconds truncated to 3 digits).
    - set: serialized as a sorted list.
    - pydantic-style: objects with `model_dump()` are unwrapped through it.
    - Anything else: raises TypeError. Callers must render exotic types
      into a serializable shape before hashing.
    """
    return json.dumps(
        obj,
        default=_json_default,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if isinstance(value, set):
        return sorted(value)
    if hasattr(value, "model_dump"):
        return value.model_dump()
    raise TypeError(f"cannot canonicalize type {type(value)!r}")
