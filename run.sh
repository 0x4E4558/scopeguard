#!/usr/bin/env bash
# Start Nex
# Usage: bash run.sh

set -e

VENV_DIR=".venv"

if [ ! -d "$VENV_DIR" ]; then
  echo ""
  echo "  venv not found. Run setup first:"
  echo ""
  echo "    bash setup.sh"
  echo ""
  exit 1
fi

"$VENV_DIR/bin/python" app.py
