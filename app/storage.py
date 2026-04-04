"""
app.storage
~~~~~~~~~~~
SQLite persistence layer for Nex engagements.

Schema:
  engagements(id, engagement_id, created_at, updated_at, status, data_json)
  scope_artifacts(id, row_id, scope_id, scope_hash, operator_id,
                  version_index, supersedes, created_at, artifact_json)

'data_json' stores the full engagement as a JSON blob, keyed by section.
Sections save independently so partial work is never lost.

'artifact_json' stores the full ScopeArtifact (scope, token, audit) as a
JSON blob.  Rows are append-only; existing rows are never updated.
"""

import sqlite3
import json
import uuid
from contextlib import closing
from datetime import datetime, date, timezone
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent.parent / "data" / "nex.db"


def _json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with closing(get_connection()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS engagements (
                id           TEXT PRIMARY KEY,
                engagement_id TEXT,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'draft',
                data_json    TEXT NOT NULL DEFAULT '{}'
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_engagement_id
            ON engagements(engagement_id)
        """)
        # Append-only scope artifact versioning table (Phase 9)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scope_artifacts (
                id            TEXT PRIMARY KEY,
                row_id        TEXT NOT NULL,
                scope_id      TEXT NOT NULL,
                scope_hash    TEXT NOT NULL,
                operator_id   TEXT NOT NULL,
                version_index INTEGER NOT NULL,
                supersedes    TEXT,
                created_at    TEXT NOT NULL,
                artifact_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_scope_artifacts_row_id
            ON scope_artifacts(row_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_scope_artifacts_scope_id
            ON scope_artifacts(scope_id)
        """)
        conn.commit()


def create_engagement() -> str:
    """Create a new empty engagement record, return its UUID."""
    row_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    with closing(get_connection()) as conn:
        conn.execute(
            "INSERT INTO engagements (id, created_at, updated_at, data_json) VALUES (?, ?, ?, ?)",
            (row_id, now, now, "{}")
        )
        conn.commit()
    return row_id


def load_engagement(row_id: str) -> Optional[dict]:
    """Load a full engagement record. Returns None if not found."""
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT * FROM engagements WHERE id = ?", (row_id,)
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["data"] = json.loads(result.pop("data_json"))
    return result


def save_section(row_id: str, section: str, section_data: dict) -> None:
    """Save one section of an engagement. Merges into existing data."""
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT data_json FROM engagements WHERE id = ?", (row_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Engagement {row_id} not found")
        data = json.loads(row["data_json"])
        data[section] = section_data
        now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        conn.execute(
            "UPDATE engagements SET data_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(data, default=_json_serial), now, row_id)
        )
        conn.commit()


def migrate_technique_data() -> int:
    """Fix any engagement where techniques is stored as a flat dict instead of list of dicts.
    Returns number of engagements fixed."""
    fixed = 0
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT id, data_json FROM engagements"
        ).fetchall()
        for row in rows:
            data = json.loads(row["data_json"])
            techs = data.get("techniques")
            needs_fix = False
            if isinstance(techs, dict):
                # Flat dict — try to recover list of dicts from values
                recovered = [v for v in techs.values() if isinstance(v, dict) and v.get("technique_id")]
                data["techniques"] = recovered
                needs_fix = True
            elif isinstance(techs, list):
                # Filter out any non-dict items (strings, None, etc.)
                cleaned = [t for t in techs if isinstance(t, dict) and t.get("technique_id")]
                if len(cleaned) != len(techs):
                    data["techniques"] = cleaned
                    needs_fix = True
            if needs_fix:
                conn.execute(
                    "UPDATE engagements SET data_json = ? WHERE id = ?",
                    (json.dumps(data), row["id"])
                )
                fixed += 1
        if fixed:
            conn.commit()
    return fixed


def update_status(row_id: str, status: str) -> None:
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    with closing(get_connection()) as conn:
        conn.execute(
            "UPDATE engagements SET status = ?, updated_at = ? WHERE id = ?",
            (status, now, row_id)
        )
        conn.commit()


def list_engagements() -> list[dict]:
    """Return all engagements with summary fields, most recently updated first."""
    import json as _json
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT id, engagement_id, created_at, updated_at, status, data_json "
            "FROM engagements ORDER BY updated_at DESC"
        ).fetchall()

    results = []
    for r in rows:
        row = dict(r)
        # Extract display fields from data_json without loading full engagement
        data = {}
        if row.get("data_json"):
            try:
                data = _json.loads(row["data_json"])
            except Exception:
                pass
        identity = data.get("identity", {})
        row["client_name"]      = identity.get("client_org_legal_name", "")
        row["testing_firm"]     = identity.get("testing_firm_legal_name", "")
        row["engagement_type"]  = identity.get("engagement_type", "")
        row["document_status"]  = identity.get("document_status", "draft")
        row["classification"]   = identity.get("classification", "")
        # Count sections completed
        row["sections_done"]    = sum(1 for s in [
            "identity","period","contacts","in_scope_assets","techniques",
            "maintenance_windows","data_governance","social_engineering"
        ] if data.get(s))
        row["sections_total"]   = 8
        del row["data_json"]
        results.append(row)
    return results


def save_scope_artifact(row_id: str, artifact_data: dict) -> str:
    """Append a new scope artifact version for engagement *row_id*.

    This function is append-only: it never modifies an existing artifact row.
    Each call creates a new immutable record.

    Args:
        row_id:        SQLite primary key of the parent engagement record.
        artifact_data: Dict with keys: scope_id, scope_hash, operator_id,
                       scope (dict), token (dict), audit (dict).

    Returns:
        The new artifact record's UUID primary key.
    """
    scope_id    = artifact_data["scope_id"]
    scope_hash  = artifact_data["scope_hash"]
    operator_id = artifact_data["operator_id"]
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

    with closing(get_connection()) as conn:
        # Determine current version_index and supersedes
        existing = conn.execute(
            "SELECT version_index, scope_hash FROM scope_artifacts "
            "WHERE row_id = ? ORDER BY version_index DESC LIMIT 1",
            (row_id,)
        ).fetchone()

        if existing is None:
            version_index = 0
            supersedes = None
        else:
            version_index = existing["version_index"] + 1
            supersedes = existing["scope_hash"]

        artifact_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO scope_artifacts
               (id, row_id, scope_id, scope_hash, operator_id,
                version_index, supersedes, created_at, artifact_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                artifact_id, row_id, scope_id, scope_hash, operator_id,
                version_index, supersedes, now,
                json.dumps(artifact_data, default=_json_serial),
            ),
        )
        conn.commit()
    return artifact_id


def load_scope_artifacts(row_id: str) -> list[dict]:
    """Return all scope artifact versions for *row_id*, oldest first."""
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT * FROM scope_artifacts WHERE row_id = ? ORDER BY version_index ASC",
            (row_id,)
        ).fetchall()
    results = []
    for r in rows:
        entry = dict(r)
        entry["artifact"] = json.loads(entry.pop("artifact_json"))
        results.append(entry)
    return results


def load_latest_scope_artifact(row_id: str) -> Optional[dict]:
    """Return the most recent scope artifact for *row_id*, or None."""
    artifacts = load_scope_artifacts(row_id)
    return artifacts[-1] if artifacts else None


def delete_engagement(row_id: str) -> None:
    with closing(get_connection()) as conn:
        conn.execute("DELETE FROM scope_artifacts WHERE row_id = ?", (row_id,))
        conn.execute("DELETE FROM engagements WHERE id = ?", (row_id,))
        conn.commit()
