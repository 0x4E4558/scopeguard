"""
scopeguard.scope_token
~~~~~~~~~~~~~~~~~~~~~~
HMAC-SHA256 scope token generation.

A scope token is a compact, verifiable credential that Nex's
ScopeTokenManager can validate without interpreting human-readable documents.

Token wire format (all fields canonical-JSON-serialized before signing):
  {
    "scope_id":          "<uuid5 string>",
    "operator_id":       "<sha256 hex>",
    "engagement_id":     "<string>",
    "nex_modules":       ["nex.scanner.port_scan@1.0", ...],
    "authorized_cidrs":  ["10.0.0.0/8", ...],
    "constraints": {
      "active_days":          [...],
      "active_hours_start":   "HH:MM TZ",
      "active_hours_end":     "HH:MM TZ",
      "time_window_start_utc": "<iso8601>",
      "time_window_end_utc":   "<iso8601>"
    },
    "scope_hash":        "<sha256 hex>",
    "issued_at":         "<iso8601 utc>",
    "expires_at":        "<iso8601 utc>"
  }

The HMAC signature is computed over the canonical JSON (sorted keys, no
whitespace) of the payload above using HMAC-SHA256.

Determinism guarantee: identical payload + identical key → identical signature.
"""

from __future__ import annotations

import hashlib
import hmac

from .canonicalize import canonical_json_bytes


ALGORITHM = "HMAC-SHA256"
TOKEN_SCHEMA_VERSION = "1.0"


def generate_scope_token(payload: dict, secret_key: bytes) -> dict:
    """Sign *payload* with HMAC-SHA256 and return an envelope dict.

    The returned dict is the complete scope token as stored in
    ``/var/lib/nex/artifacts/<scope_id>/scope_token.json``.

    Args:
        payload:    The token payload dict (see module docstring).
        secret_key: Raw bytes for the HMAC key.  Must be injected; never
                    derived at runtime from a non-deterministic source.

    Returns:
        ``{"algorithm": "HMAC-SHA256", "schema_version": "1.0",
           "payload": <payload>, "signature": "<hex>"}``
    """
    if not secret_key:
        raise ValueError("secret_key must not be empty")

    signed_bytes = canonical_json_bytes(payload)
    sig = hmac.new(secret_key, signed_bytes, hashlib.sha256).hexdigest()

    return {
        "algorithm": ALGORITHM,
        "schema_version": TOKEN_SCHEMA_VERSION,
        "payload": payload,
        "signature": sig,
    }


def verify_scope_token(token_envelope: dict, secret_key: bytes) -> bool:
    """Return True if the token envelope's signature is valid.

    Uses ``hmac.compare_digest`` for constant-time comparison.
    """
    try:
        payload = token_envelope["payload"]
        expected_sig = token_envelope["signature"]
    except (KeyError, TypeError):
        return False

    signed_bytes = canonical_json_bytes(payload)
    computed_sig = hmac.new(secret_key, signed_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_sig, expected_sig)
