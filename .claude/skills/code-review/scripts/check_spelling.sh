#!/usr/bin/env bash
# check_spelling.sh
# Covers review_standard.md §3:
#   [Lang] Run spell-checker on code
#
# Usage:
#   ./check_spelling.sh                  # checks all changed files (git diff vs main)
#   ./check_spelling.sh path/to/file.py  # checks a specific file
#   ./check_spelling.sh path/to/dir/     # checks an entire directory
#
# Requires: codespell  (`pip install codespell`)
# To add project-specific ignore words, create .codespellrc or pass --ignore-words-list

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
    FILES=$(git diff --name-only "$BASE_BRANCH"...HEAD 2>/dev/null || git diff --name-only HEAD)
    FILES=$(echo "$FILES" | xargs -I{} sh -c '[ -f "{}" ] && echo "{}"' | tr '\n' ' ')
    TARGET="${FILES}"
fi

if [ -z "${TARGET// }" ]; then
    log_info "No files to check."
    exit 0
fi

log_info "Running codespell..."
echo "Target: $TARGET"
echo "---"

# --skip: ignore common non-prose binary/generated dirs
# --quiet-level 2: suppress progress, show only errors
if codespell --skip="*.pyc,*.egg-info,.git,__pycache__" --quiet-level=2 $TARGET 2>&1; then
    log_pass "codespell: no spelling errors found"
else
    log_fail "codespell: spelling errors found — fix or add to .codespellrc ignore list if it is a legitimate technical term"
    exit 1
fi
