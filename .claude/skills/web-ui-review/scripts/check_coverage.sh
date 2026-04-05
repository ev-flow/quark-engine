#!/usr/bin/env bash
# check_coverage.sh
# Covers checklist §4:
#   [QA] Aim for 80%+ coverage on changed code
#
# Usage:
#   ./check_coverage.sh                       # runs full test suite with coverage
#   ./check_coverage.sh path/to/module        # reports coverage scoped to a module
#
# Supports: vitest, jest, or nyc/c8
# Configure test runner in package.json as needed.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

THRESHOLD="${COVERAGE_THRESHOLD:-80}"

log_info "Running tests with coverage (threshold: ${THRESHOLD}%)..."
echo "---"

SCOPE_ARG=""
if [ $# -ge 1 ]; then
    SCOPE_ARG="$1"
    log_info "Scoping to: $SCOPE_ARG"
fi

# Detect test runner
if [ -f vitest.config.ts ] || [ -f vitest.config.js ] || grep -q '"vitest"' package.json 2>/dev/null; then
    RUNNER="vitest"
    if [ -n "$SCOPE_ARG" ]; then
        npx vitest run --coverage --coverage.thresholds.statements="$THRESHOLD" "$SCOPE_ARG" 2>&1
    else
        npx vitest run --coverage --coverage.thresholds.statements="$THRESHOLD" 2>&1
    fi
elif grep -q '"jest"' package.json 2>/dev/null || [ -f jest.config.js ] || [ -f jest.config.ts ]; then
    RUNNER="jest"
    if [ -n "$SCOPE_ARG" ]; then
        npx jest --coverage --coverageThreshold="{\"global\":{\"statements\":$THRESHOLD}}" "$SCOPE_ARG" 2>&1
    else
        npx jest --coverage --coverageThreshold="{\"global\":{\"statements\":$THRESHOLD}}" 2>&1
    fi
else
    log_info "No test runner found (vitest or jest). Attempting npm test..."
    RUNNER="npm"
    npm test -- --coverage 2>&1
fi

EXIT_CODE=$?

echo "---"
if [ "$EXIT_CODE" -eq 0 ]; then
    log_pass "Coverage meets the ${THRESHOLD}% threshold (runner: $RUNNER)"
else
    log_fail "Coverage is below ${THRESHOLD}% — add tests to cover all modified/new code (runner: $RUNNER)"
    exit 1
fi
