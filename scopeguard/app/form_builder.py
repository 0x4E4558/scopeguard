"""
app.form_builder
~~~~~~~~~~~~~~~~
Converts schema YAML into structured field definitions for the intake form.
Each section becomes an ordered list of field specs the template renders.

Handles conditional visibility: fields that depend on other field values
export their conditions as JSON so the frontend JS can show/hide them.
"""

from __future__ import annotations
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))
from scopeguard.schema_loader import SchemaLoader

SCHEMA_DIR = Path(__file__).parent.parent / "schema"

# Section order mirrors the spec's group numbering
SECTIONS = [
    ("identity",            "Engagement Identity",        "engagement"),
    ("period",              "Engagement Period",           "period"),
    ("contacts",            "Contacts",                   "contacts"),
    ("in_scope_assets",     "In-Scope Assets",            "assets"),
    ("out_of_scope_assets", "Out-of-Scope Assets",        "assets"),
    ("physical_locations",  "Physical Locations",         "assets"),
    ("techniques",          "Technique Authorization",    "techniques"),
    ("maintenance_windows", "Maintenance Windows",        "maintenance_windows"),
    ("data_governance",     "Data Governance",            "data_governance"),
    ("social_engineering",  "Social Engineering",         "social_engineering"),
]

SECTION_IDS = [s[0] for s in SECTIONS]


def _field_spec(name: str, meta: dict[str, Any]) -> dict[str, Any]:
    """Normalize a single field from YAML metadata into a UI-ready spec."""
    ftype = meta.get("type", "string")

    spec: dict[str, Any] = {
        "name": name,
        "label": name.replace("_", " ").title(),
        "type": ftype,
        "required": meta.get("required", False),
        "description": meta.get("description", ""),
        "default": meta.get("default"),
        "validation": meta.get("validation"),
    }

    # Enum fields get their values list
    if ftype == "enum":
        spec["options"] = meta.get("values", [])

    # Buttongroup type — visible toggle buttons (like multiselect but single-select)
    if ftype == "buttongroup":
        spec["options"] = meta.get("values", [])
        spec["type"] = "buttongroup"

    # Direct multiselect type — values listed under "values" key
    if ftype == "multiselect":
        spec["options"] = meta.get("values", [])
        spec["type"] = "multiselect"

    # Array-of-enum gets options too
    if ftype == "array" and meta.get("item_type") == "enum":
        spec["options"] = meta.get("values", [])
        spec["type"] = "multiselect"

    # Boolean → checkbox
    if ftype == "boolean":
        spec["type"] = "checkbox"

    # Date/datetime → date input
    if ftype in ("date", "datetime_tz"):
        spec["type"] = "date"

    # Time with timezone → structured time picker
    if ftype == "time_tz":
        spec["type"] = "time_tz"

    # CIDR → mono text
    if ftype == "cidr":
        spec["type"] = "string"
        spec["mono"] = True

    # Reference → string (display as text for now)
    if ftype == "reference":
        spec["type"] = "string"

    # Conditional visibility
    cond = meta.get("conditional_on")
    if cond:
        spec["conditional_on"] = cond  # {field, value/condition}

    # Min/max for integers
    if ftype == "integer":
        if "min" in meta:
            spec["min"] = meta["min"]
        if "max" in meta:
            spec["max"] = meta["max"]

    # Min length for strings
    if ftype == "string" and "min_length" in meta:
        spec["min_length"] = meta["min_length"]

    return spec


def get_section_fields(section_id: str) -> list[dict]:
    """Return ordered field specs for a given section."""
    # Techniques now uses a custom matrix UI — no standard fields to return
    if section_id == 'techniques':
        return []
    loader = SchemaLoader(SCHEMA_DIR)

    # Map section IDs to schema group names and field keys
    group_map = {
        "identity":            ("engagement_identity", "fields"),
        "period":              ("engagement_period",   "fields"),
        "contacts":            ("contacts",            "contact_record_fields"),
        "in_scope_assets":     ("assets",              "in_scope_network_fields"),
        "out_of_scope_assets": ("assets",              "out_of_scope_network_fields"),
        "physical_locations":  ("assets",              "physical_location_fields"),
        "techniques":          ("techniques",          "fields"),
        "maintenance_windows": ("maintenance_windows", "fields"),
        "data_governance":     ("data_governance",     "fields"),
        "social_engineering":  ("social_engineering",  "fields"),
    }

    if section_id not in group_map:
        return []

    group_name, field_key = group_map[section_id]
    group = loader.group(group_name)

    # out_of_scope_assets: base in_scope fields first, then exclusion-specific fields
    if section_id == "out_of_scope_assets":
        base  = group.get("in_scope_network_fields", {})
        extra = group.get("out_of_scope_network_fields", {})
        raw_fields = {**base, **extra}
    else:
        raw_fields = group.get(field_key, {})

    specs = []
    for fname, fmeta in raw_fields.items():
        if fname.startswith("_"):
            continue
        # Derived/auto-populated fields are display-only, skip them
        if fmeta.get("auto_populate") or fmeta.get("derived"):
            continue
        # Auto-generate fields become hidden inputs so IDs survive save/load
        if fmeta.get("auto_generate"):
            specs.append({
                "name": fname,
                "label": fmeta.get("description", fname),
                "type": "hidden",
                "required": False,
                "description": "",
                "default": fmeta.get("default"),
                "validation": None,
            })
            continue
        specs.append(_field_spec(fname, fmeta))

    return specs


def get_all_sections() -> list[dict]:
    """Return all sections with their metadata."""
    return [
        {"id": sid, "label": label, "schema_group": sg}
        for sid, label, sg in SECTIONS
    ]
