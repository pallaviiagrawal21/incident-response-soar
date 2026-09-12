#!/usr/bin/env bash
# Run static checks and the test suite. Requires the [dev] extras:
#   pip install -e ".[dev]"
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== ruff (lint) ==="
ruff check src tests

echo
echo "=== mypy (type check) ==="
mypy src

echo
echo "=== pytest ==="
pytest --cov=ir_soar --cov-report=term-missing

echo
echo "All checks passed."
