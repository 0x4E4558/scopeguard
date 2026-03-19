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

# Create data directory
mkdir -p data
echo "  ✓ data/ directory ready"

echo ""
echo "  Setup complete."
echo "  To start ScopeGuard, run:"
echo ""
echo "    bash run.sh"
echo ""

# Re-run to pick up python-docx if added after initial setup
"$VENV_DIR/bin/pip" install --quiet python-docx
echo "  ✓ python-docx installed"
