#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_VENV_PACKAGES="$SCRIPT_DIR/python_client/.venv/lib/python3.12/site-packages"

echo "============================================================"
echo "SecureShare Test Runner"
echo "============================================================"

echo ""
echo "--- Python Tests ---"
cd "$SCRIPT_DIR/python_client"
PYTHONPATH="$PYTHON_VENV_PACKAGES" python3.12 -m pytest tests/ -v
cd "$SCRIPT_DIR"

echo ""
echo "--- Java Tests ---"
if command -v mvn >/dev/null 2>&1; then
    cd "$SCRIPT_DIR/java_client"
    mvn test -Dproject.root="$SCRIPT_DIR"
    cd "$SCRIPT_DIR"
else
    echo "WARNING: Maven not found. Skipping Java tests."
    echo "  Install Java 17 + Maven then run: cd java_client && mvn test"
fi

echo ""
echo "============================================================"
echo "Test runner finished."
echo "============================================================"
