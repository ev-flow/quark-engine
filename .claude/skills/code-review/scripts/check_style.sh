#!/usr/bin/env bash
# check_style.sh
# Covers review_standard.md §3:
#   [Lang] Format with `black --line-length 79 quark/` before committing
#   [Lang] Run `pylint` on only the files changed in this PR
#   [Lang] No lines exceed 79 characters
#
# Usage:
#   ./check_style.sh                  # checks all changed .py files (git diff vs main)
#   ./check_style.sh path/to/file.py  # checks a specific file
#   ./check_style.sh path/to/dir/     # checks an entire directory

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# Resolve target files
if [ $# -ge 1 ]; then
    TARGET="$1"
    if [ -d "$TARGET" ]; then
        FILES=$(find "$TARGET" -name "*.py" | tr '\n' ' ')
    else
        FILES="$TARGET"
    fi
else
    BASE_BRANCH="${BASE_BRANCH:-main}"
    FILES=$(git diff --name-only "$BASE_BRANCH"...HEAD -- '*.py' 2>/dev/null || git diff --name-only HEAD -- '*.py')
    FILES=$(echo "$FILES" | xargs -I{} sh -c '[ -f "{}" ] && echo "{}"' | tr '\n' ' ')
fi

if [ -z "${FILES// }" ]; then
    log_info "No Python files to check."
    exit 0
fi

echo "Checking files: $FILES"
echo "---"

# --- black ---
log_info "Running black (--check --line-length 79)..."
if black --check --line-length 79 $FILES 2>&1; then
    log_pass "black: formatting is correct, no lines exceed 79 chars"
else
    log_fail "black: formatting issues found — run: black --line-length 79 <files>"
fi

echo "---"

# --- pylint ---
log_info "Running pylint..."
if pylint $FILES 2>&1; then
    log_pass "pylint: no issues found"
else
    log_fail "pylint: issues found — resolve all reported issues in the changed files"
fi

echo "---"
echo -e "Style check complete — ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
[ "$FAIL" -eq 0 ]
