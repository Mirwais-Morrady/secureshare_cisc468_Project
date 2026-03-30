#!/usr/bin/env bash
# =============================================================================
# SecureShare — Full Test Suite
# Run from the project root:  bash tests/run_all_tests.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0

green()  { printf "\033[32m%s\033[0m\n" "$*"; }
red()    { printf "\033[31m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

bold "============================================================"
bold "  CISC 468 SecureShare — Test Suite"
bold "============================================================"
echo ""

# ── Python tests (pytest via venv) ───────────────────────────────────────────
bold "── Python Unit Tests (97 tests, Requirements 2–10) ────────"
PYTEST="$ROOT/python_client/.venv/bin/pytest"
if [ ! -f "$PYTEST" ]; then
    red "[ERROR] Python venv not found at python_client/.venv/"
    red "        Run: cd python_client && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    FAIL=$((FAIL + 1))
else
    cd "$ROOT/python_client"
    if "$PYTEST" "$ROOT/tests/python/" -v --tb=short 2>&1; then
        green "[PASS] All Python tests passed"
        PASS=$((PASS + 1))
    else
        red "[FAIL] Some Python tests failed"
        FAIL=$((FAIL + 1))
    fi
fi

echo ""

# ── Java tests (Maven Surefire — 53 tests) ───────────────────────────────────
bold "── Java Unit Tests (53 tests, Requirements 2–10) ──────────"
cd "$ROOT/java_client"
if mvn test -q 2>&1; then
    green "[PASS] All Java tests passed"
    PASS=$((PASS + 1))
else
    red "[FAIL] Some Java tests failed"
    FAIL=$((FAIL + 1))
fi

echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
bold "============================================================"
echo ""
if [ "$FAIL" -gt 0 ]; then
    red "  RESULT: $PASS suite(s) passed, $FAIL suite(s) FAILED"
    exit 1
else
    green "  RESULT: $PASS suites passed — all 150 tests green"
fi
bold "============================================================"
