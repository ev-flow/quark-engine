#!/usr/bin/env bash
# check_coverage.sh
# Covers review_standard.md §4:
#   [QA] New/modified functions are covered by tests
#   [QA] Aim for 100% coverage on changed code
#
# Usage:
#   ./check_coverage.sh                    # runs full test suite with coverage
#   ./check_coverage.sh path/to/module.py  # reports coverage for a specific module
#
# Requires: pytest, pytest-cov
# Configure pytest & coverage in pyproject.toml or setup.cfg as needed.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# Minimum acceptable coverage threshold (%)
THRESHOLD="${COVERAGE_THRESHOLD:-80}"

log_info "Running pytest with coverage (threshold: ${THRESHOLD}%)..."
echo "---"

if [ $# -ge 1 ]; then
    MODULE="$1"
    log_info "Scoping coverage report to: $MODULE"
    pytest --cov="$MODULE" --cov-report=term-missing --cov-fail-under="$THRESHOLD" 2>&1
else
    pytest --cov=quark --cov-report=term-missing --cov-fail-under="$THRESHOLD" 2>&1
fi

EXIT_CODE=$?

echo "---"
if [ "$EXIT_CODE" -eq 0 ]; then
    log_pass "Coverage meets the ${THRESHOLD}% threshold"
else
    log_fail "Coverage is below ${THRESHOLD}% — add tests to cover all modified/new code"
    exit 1
fi
