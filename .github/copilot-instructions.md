# Copilot Instructions for ScopeGuard

## Project Overview

ScopeGuard is a **Python/Flask web application** that guides users through building legally-defensible penetration-test engagement documents: a Scope of Work (SOW) and a Rules of Engagement (ROE). Everything runs locally; no data ever leaves the machine.

## Architecture (3 Layers)

| Layer | Location | Responsibility |
|-------|----------|----------------|
| 1 – Intake form | `app/` | Flask web UI, SQLite persistence, YAML-driven form builder |
| 2 – Validation engine | `scopeguard/` (package) | 36 rules (VAL-001–020 field-level, XRF-001–016 cross-reference) |
| 3 – Document generation | `app/generator.py`, `app/legal.py` | `.docx` output via `python-docx` |

## Tech Stack

- **Python 3.10+** — standard library + third-party (`flask`, `python-docx`, `pyyaml`, `pytest`)
- **Flask** — web framework; single `app.py` entry point
- **SQLite** via `app/storage.py` — section-level autosave (600 ms debounce in the JS layer)
- **YAML schemas** in `schema/` — one file per schema group; parsed by `scopeguard/schema_loader.py`
- **Jinja2** templates in `app/templates/`
- **Python dataclasses** in `scopeguard/models.py` — typed data objects shared across all three layers

## Key Concepts

### Schema Groups (8 total)
`engagement`, `period`, `contacts`, `assets`, `techniques`, `maintenance_windows`, `data_governance`, `social_engineering`

### Engagement Types
Defined in `scopeguard/models.py` as `EngagementType` enum:
`external_only`, `internal_only`, `web_app`, `full_scope`, `red_team`, `vulnerability_assessment`

### Validation Rules
- **VAL-001–020**: field-level rules (CIDR notation, date ordering, email format, credential reporting window, etc.)
- **XRF-001–016**: cross-reference rules (CIDR overlap, dangling maintenance-window refs, missing required contacts, etc.)
- Each rule produces a `Finding` with severity `BLOCK | CLARIFY | MISSING | NOTE`
- Rule IDs in code **must match** the spec exactly — never renumber existing rules

### Finding Severity (in `scopeguard/finding.py`)
`BLOCK` > `CLARIFY` > `MISSING` > `NOTE`  
Only `BLOCK` findings prevent document download.

## Code Conventions

- Use **`from __future__ import annotations`** at the top of every Python module.
- Prefer **dataclasses** (not dicts or plain classes) for structured engagement data.
- Type-annotate all function signatures; use `Optional[X]` from `typing` — this is the convention already established throughout the codebase (e.g., `scopeguard/models.py`, `scopeguard/validator.py`).
- Module docstrings follow the `"""module.name\n~~~~~\nDescription."""` style — preserve this in new modules.
- Validation functions return `None` and append findings to a `FindingList`; they do **not** raise exceptions.
- Keep validation rules pure (no I/O, no DB access, no Flask context).
- JavaScript in `app/static/` uses vanilla JS (no framework); CSS uses IBM Plex Sans/Mono.

## Testing

```bash
bash run_tests.sh        # runs pytest via run_tests.py
```

- Tests live in `tests/` using **pytest**.
- `conftest.py` loads JSON fixtures from `tests/fixtures/`.
- `mcb.json` — canonical valid engagement (Meridian Community Bank); must pass all rules.
- `nexus_bad.json` — deliberately broken engagement; must trigger specific rule failures.
- Test file naming: `test_field_rules.py` (VAL-*), `test_xref_rules.py` (XRF-*), `test_v2_features.py`.
- When adding a new validation rule, add corresponding tests in the appropriate test file.
- Do **not** modify `mcb.json` or `nexus_bad.json` unless the schema itself changes; create new fixtures for new test scenarios.

## Setup & Running

```bash
bash setup.sh    # creates venv, installs deps (run once)
bash run.sh      # starts Flask on http://127.0.0.1:5000
```

## Common Tasks

### Adding a new validation rule
1. Assign the next available `VAL-XXX` or `XRF-XXX` ID.
2. Implement in `scopeguard/validator.py`; append findings via `findings.add(Finding(...))`.
3. Add unit tests in `tests/test_field_rules.py` or `tests/test_xref_rules.py`.
4. Update the rule count in `README.md` if relevant.

### Adding a new schema field
1. Add the field to the relevant YAML file in `schema/`.
2. Add a corresponding attribute to the dataclass in `scopeguard/models.py`.
3. Update `app/hydrator.py` to map storage JSON → dataclass.
4. Update `app/form_builder.py` if the field needs a custom form widget.
5. Add or update validation rules as needed.

### Generating documents
- SOW and ROE are generated in `app/generator.py` using `python-docx`.
- Legal clauses are assembled from `app/legal.py`; do not inline legal text in `generator.py`.
- Download is only available after all `BLOCK` findings are resolved.

## Security & Privacy

- ScopeGuard **never** makes external network connections.
- All engagement data is stored in `./data/scopeguard.db` (local SQLite only).
- Do not add any telemetry, analytics, or outbound HTTP calls.
- Generated documents may contain sensitive PII and legal language — handle carefully in tests (use anonymized fixtures).
