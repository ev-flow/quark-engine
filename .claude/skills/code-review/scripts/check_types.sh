#!/usr/bin/env bash
# check_types.sh
# Covers review_standard.md §3:
#   [Lang] All functions and variables have complete, correct type hints
# Covers review_standard.md §2:
#   [Lang] Function signatures have correct input/output types
#
# Usage:
#   ./check_types.sh                  # checks all changed .py files (git diff vs main)
#   ./check_types.sh path/to/file.py  # checks a specific file
#   ./check_types.sh path/to/dir/     # checks an entire directory

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# Resolve target
if [ $# -ge 1 ]; then
    TARGET="$1"
else
    BASE_BRANCH="${BASE_BRANCH:-main}"
    FILES=$(git diff --name-only "$BASE_BRANCH"...HEAD -- '*.py' 2>/dev/null || git diff --name-only HEAD -- '*.py')
    FILES=$(echo "$FILES" | xargs -I{} sh -c '[ -f "{}" ] && echo "{}"' | tr '\n' ' ')
    TARGET="${FILES}"
fi

if [ -z "${TARGET// }" ]; then
    log_info "No Python files to check."
    exit 0
fi

log_info "Running mypy (strict mode)..."
echo "Target: $TARGET"
echo "---"

# --ignore-missing-imports avoids noise from third-party libs without stubs
if mypy --strict --ignore-missing-imports $TARGET 2>&1; then
    log_pass "mypy: all type hints are complete and correct"
else
    log_fail "mypy: type errors found — add or fix type hints to resolve"
    exit 1
fi
