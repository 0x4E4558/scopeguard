"""
nex.schema_loader
~~~~~~~~~~~~~~~~~~~~~~~~
Reads YAML schema files at startup and exposes schema metadata.
Schema is data, not code — the application interprets the schema; it does not embody it.
"""

from __future__ import annotations
import yaml
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
SCHEMA_FILES = [
    "engagement.yaml",
    "period.yaml",
    "contacts.yaml",
    "assets.yaml",
    "techniques.yaml",
    "maintenance_windows.yaml",
    "data_governance.yaml",
    "social_engineering.yaml",
]


class SchemaLoader:
    def __init__(self, schema_dir: Path | str) -> None:
        self.schema_dir = Path(schema_dir)
        self._groups: dict[str, dict[str, Any]] = {}
        self._load_all()

    def _load_all(self) -> None:
        for filename in SCHEMA_FILES:
            path = self.schema_dir / filename
            if not path.exists():
                raise FileNotFoundError(f"Schema file not found: {path}")
            with path.open() as fh:
                data = yaml.safe_load(fh)
            group_name = data.get("group") or filename.removesuffix(".yaml")
            self._groups[group_name] = data

    def group(self, name: str) -> dict[str, Any]:
        if name not in self._groups:
            raise KeyError(f"Schema group '{name}' not loaded. Available: {list(self._groups)}")
        return self._groups[name]

    def all_groups(self) -> dict[str, dict[str, Any]]:
        return dict(self._groups)

    def version(self) -> str:
        return SCHEMA_VERSION
