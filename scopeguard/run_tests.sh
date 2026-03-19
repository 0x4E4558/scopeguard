#!/usr/bin/env bash
# Run the Phase 1 validation test suite inside the venv
# Usage: bash run_tests.sh

set -e

VENV_DIR=".venv"

if [ ! -d "$VENV_DIR" ]; then
  echo "  venv not found — run: bash setup.sh"
  exit 1
fi

"$VENV_DIR/bin/python" run_tests.py
