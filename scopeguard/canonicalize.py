"""
scopeguard.canonicalize
~~~~~~~~~~~~~~~~~~~~~~~
Deterministic, canonical JSON serialization.

Rules:
  - Keys are sorted lexicographically at every nesting level.
  - No whitespace (compact separators).
  - Non-ASCII characters are escaped (ensure_ascii=True).
  - datetime/date objects are serialized as ISO 8601 strings.
  - Sets are converted to sorted lists before serialization.

Identical inputs MUST produce bit-for-bit identical output.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any


def _canonical_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f"Type {type(obj).__name__!r} is not JSON serializable")


def canonical_json(obj: Any) -> str:
    """Serialize *obj* to a canonical JSON string.

    Properties guaranteed:
    - Keys sorted at all nesting levels.
    - No whitespace between tokens.
    - Non-ASCII characters escaped (ASCII-safe output).
    - Deterministic: identical inputs produce identical strings.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        default=_canonical_default,
        ensure_ascii=True,
    )


def canonical_json_bytes(obj: Any) -> bytes:
    """UTF-8-encoded bytes of :func:`canonical_json`."""
    return canonical_json(obj).encode("utf-8")
