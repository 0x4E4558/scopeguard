#!/usr/bin/env bash
# ScopeGuard setup — creates a venv and installs dependencies
# Run once: bash setup.sh
# Then to start the app: bash run.sh

set -e

VENV_DIR=".venv"

echo ""
echo "  ScopeGuard setup"
echo "  ────────────────"

# Check Python version
PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
  echo "  ✗ Python not found. Install Python 3.10 or later."
  exit 1
fi

PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "  Python $PY_VERSION found at $PYTHON"

# Create venv
if [ -d "$VENV_DIR" ]; then
  echo "  venv already exists — skipping creation"
else
  echo "  Creating venv..."
  $PYTHON -m venv "$VENV_DIR"
  echo "  ✓ venv created"
fi

# Install dependencies
echo "  Installing dependencies..."
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet flask pyyaml
echo "  ✓ flask, pyyaml installed"

# Re-run to pick up python-docx if added after initial setup
"$VENV_DIR/bin/pip" install --quiet python-docx
echo "  ✓ python-docx installed"

# ─── Data directory & database ────────────────────────────────────────────────
mkdir -p data
echo "  ✓ data/ directory ready"

DB_FILE="data/scopeguard.db"

_sg_init_db() {
  "$VENV_DIR/bin/python" - <<'PYEOF'
import sys
sys.path.insert(0, '.')
from app.storage import init_db
init_db()
PYEOF
}

_sg_migrate_db() {
  "$VENV_DIR/bin/python" - <<'PYEOF'
import sys
sys.path.insert(0, '.')
from app.storage import init_db, migrate_technique_data
init_db()
fixed = migrate_technique_data()
if fixed:
    print(f"  ✓ Migrated {fixed} engagement(s)")
else:
    print("  ✓ Schema is up to date")
PYEOF
}

if [ -f "$DB_FILE" ]; then
  echo ""
  echo "  ────────────────────────────────────────────────────"
  echo "  An existing database was found: $DB_FILE"
  echo "  ────────────────────────────────────────────────────"

  if [ -t 0 ]; then
    # Interactive terminal — ask the user
    printf "  Keep existing data and apply schema updates? [Y/n]: "
    read -r _sg_keep
    echo ""
    case "$_sg_keep" in
      [Nn]*)
        echo "  ⚠  WARNING: Choosing NO will permanently delete all stored"
        echo "  ⚠  engagement data. This action cannot be undone."
        printf "  ⚠  Type 'yes' to confirm reset, or press Enter to cancel: "
        read -r _sg_confirm
        echo ""
        if [ "$_sg_confirm" = "yes" ]; then
          rm -f "$DB_FILE" "${DB_FILE}-shm" "${DB_FILE}-wal"
          echo "  ✓ Existing database removed"
          _sg_init_db
          echo "  ✓ Fresh database created at $DB_FILE"
        else
          echo "  Reset cancelled — keeping existing database"
          _sg_migrate_db
        fi
        ;;
      *)
        _sg_migrate_db
        ;;
    esac
  else
    # Non-interactive (e.g. CI) — keep and migrate silently
    _sg_migrate_db
  fi
else
  _sg_init_db
  echo "  ✓ Database created at $DB_FILE"
fi

echo ""
echo "  Setup complete."
echo "  To start ScopeGuard, run:"
echo ""
echo "    bash run.sh"
echo ""
