"""
app.storage
~~~~~~~~~~~
SQLite persistence layer for ScopeGuard engagements.

Schema:
  engagements(id, engagement_id, created_at, updated_at, status, data_json)

'data_json' stores the full engagement as a JSON blob, keyed by section.
Sections save independently so partial work is never lost.
"""

import sqlite3
import json
import uuid
from datetime import datetime, date
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent.parent / "data" / "scopeguard.db"


def _json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with get_connection() as conn:
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
        conn.commit()


def create_engagement() -> str:
    """Create a new empty engagement record, return its UUID."""
    row_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO engagements (id, created_at, updated_at, data_json) VALUES (?, ?, ?, ?)",
            (row_id, now, now, "{}")
        )
        conn.commit()
    return row_id


def load_engagement(row_id: str) -> Optional[dict]:
    """Load a full engagement record. Returns None if not found."""
    with get_connection() as conn:
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
    with get_connection() as conn:
        row = conn.execute(
            "SELECT data_json FROM engagements WHERE id = ?", (row_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Engagement {row_id} not found")
        data = json.loads(row["data_json"])
        data[section] = section_data
        now = datetime.utcnow().isoformat()
        conn.execute(
            "UPDATE engagements SET data_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(data, default=_json_serial), now, row_id)
        )
        conn.commit()


def migrate_technique_data() -> int:
    """Fix any engagement where techniques is stored as a flat dict instead of list of dicts.
    Returns number of engagements fixed."""
    fixed = 0
    with get_connection() as conn:
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
    now = datetime.utcnow().isoformat()
    with get_connection() as conn:
        conn.execute(
            "UPDATE engagements SET status = ?, updated_at = ? WHERE id = ?",
            (status, now, row_id)
        )
        conn.commit()


def list_engagements() -> list[dict]:
    """Return all engagements with summary fields, most recently updated first."""
    import json as _json
    with get_connection() as conn:
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


def delete_engagement(row_id: str) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM engagements WHERE id = ?", (row_id,))
        conn.commit()
