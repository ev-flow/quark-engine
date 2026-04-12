#!/usr/bin/env bash
# check_spelling.sh
# Covers checklist §3:
#   [Lang] Run spell-checker on code
#
# Usage:
#   ./check_spelling.sh                       # checks all changed files (git diff vs main)
#   ./check_spelling.sh path/to/file.tsx      # checks a specific file
#   ./check_spelling.sh path/to/dir/          # checks an entire directory
#
# Supports: cspell (preferred for frontend) or codespell (fallback)

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

log_info "Running spell check..."
echo "Target: $TARGET"
echo "---"

if command -v cspell &>/dev/null || [ -f node_modules/.bin/cspell ]; then
    if npx cspell --no-progress $TARGET 2>&1; then
        log_pass "cspell: no spelling errors found"
    else
        log_fail "cspell: spelling errors found — fix or add to cspell.json words list"
        exit 1
    fi
elif command -v codespell &>/dev/null; then
    if codespell --skip="node_modules,dist,build,.next,.nuxt,*.min.js,*.min.css,.git" --quiet-level=2 $TARGET 2>&1; then
        log_pass "codespell: no spelling errors found"
    else
        log_fail "codespell: spelling errors found — fix or add to .codespellrc ignore list"
        exit 1
    fi
else
    log_info "No spell checker found (cspell or codespell). Skipping."
    exit 0
fi
