"""
app.nex_export
~~~~~~~~~~~~~~
Phase 11 — Nex storage compatibility.

Writes a complete ScopeArtifact to the Nex artifact directory layout:

  <base_path>/<scope_id>/
      scope.json           — canonical scope definition
      scope_token.json     — HMAC-signed scope token
      audit.json           — full audit trail
      version_index.json   — append-only version history

All files are written atomically (write to temp, rename) and are never
mutated after creation.  Append-only versioning ensures immutability of
historical records (Phase 9).

Default base_path: /var/lib/nex/artifacts
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from scopeguard.canonicalize import canonical_json
from scopeguard.scope_compiler import ScopeArtifact

DEFAULT_NEX_ARTIFACTS_DIR = Path("/var/lib/nex/artifacts")

# Version index schema
VERSION_INDEX_SCHEMA = "1.0"


def _atomic_write(path: Path, content: str) -> None:
    """Write *content* to *path* atomically via a temp file + rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _canonical_write(path: Path, obj: Any) -> None:
    """Serialize *obj* as canonical JSON and write atomically to *path*."""
    _atomic_write(path, canonical_json(obj))


def _load_version_index(index_path: Path) -> dict:
    if index_path.exists():
        with open(index_path, encoding="utf-8") as fh:
            return json.load(fh)
    return {
        "schema_version": VERSION_INDEX_SCHEMA,
        "scope_id": None,
        "versions": [],
    }


def export_to_nex(
    artifact: ScopeArtifact,
    timestamp: datetime,
    base_path: Path | None = None,
) -> dict:
    """Write the scope artifact to the Nex artifact directory layout.

    Args:
        artifact:   Compiled ScopeArtifact from :func:`compile_scope`.
        timestamp:  Injected UTC datetime used as the version record timestamp.
        base_path:  Override for the Nex artifacts root.  Defaults to
                    :data:`DEFAULT_NEX_ARTIFACTS_DIR`.

    Returns:
        A manifest dict describing all written paths.

    Raises:
        OSError: If the target directory cannot be created or written to.
    """
    root = (base_path or DEFAULT_NEX_ARTIFACTS_DIR) / artifact.scope_id
    root.mkdir(parents=True, exist_ok=True)

    scope_path   = root / "scope.json"
    token_path   = root / "scope_token.json"
    audit_path   = root / "audit.json"
    index_path   = root / "version_index.json"

    # ── Write scope.json (fail if it already exists — append-only model) ──────
    # A scope_id must only be written once; re-compilation of the same
    # engagement produces a new scope_id (different timestamp propagates
    # through the token but not the scope_id, which is engagement-keyed).
    # If scope.json already exists and has the same scope_hash, skip.
    # If it has a different scope_hash, this is an amendment — a new version.
    scope_written = False
    if scope_path.exists():
        with open(scope_path, encoding="utf-8") as fh:
            existing = json.load(fh)
        if existing.get("scope_hash") != artifact.scope_hash:
            # Content changed — treat as amendment; write to versioned path
            version_n = len(_load_version_index(index_path)["versions"])
            scope_path  = root / f"scope.v{version_n}.json"
            token_path  = root / f"scope_token.v{version_n}.json"
            audit_path  = root / f"audit.v{version_n}.json"
            scope_written = True
    else:
        scope_written = True

    if scope_written:
        _canonical_write(scope_path, artifact.scope)
        _canonical_write(token_path, artifact.token)
        _canonical_write(audit_path, artifact.audit)

    # ── Update version_index.json (always, append-only) ───────────────────────
    version_index = _load_version_index(index_path)
    version_index["schema_version"] = VERSION_INDEX_SCHEMA
    version_index["scope_id"] = artifact.scope_id

    version_entry = {
        "scope_hash":   artifact.scope_hash,
        "timestamp":    timestamp.isoformat(),
        "scope_path":   str(scope_path.relative_to(root)),
        "token_path":   str(token_path.relative_to(root)),
        "audit_path":   str(audit_path.relative_to(root)),
        "operator_id":  artifact.operator_id,
    }

    # Supersedes: reference the previous version's scope_hash if present
    if version_index["versions"]:
        version_entry["supersedes"] = version_index["versions"][-1]["scope_hash"]
    else:
        version_entry["supersedes"] = None

    version_entry["version_index"] = len(version_index["versions"])
    version_index["versions"].append(version_entry)
    _canonical_write(index_path, version_index)

    manifest = {
        "scope_id":     artifact.scope_id,
        "scope_hash":   artifact.scope_hash,
        "operator_id":  artifact.operator_id,
        "artifact_dir": str(root),
        "files": {
            "scope":         str(scope_path),
            "token":         str(token_path),
            "audit":         str(audit_path),
            "version_index": str(index_path),
        },
        "version_index": version_entry["version_index"],
        "timestamp":     timestamp.isoformat(),
    }
    return manifest
