#!/usr/bin/env bash
# check_types.sh
# Covers checklist §2:
#   [Lang] TypeScript types are correct and narrow (no `any` escapes)
#
# Usage:
#   ./check_types.sh                       # runs tsc --noEmit on the project
#   ./check_types.sh path/to/file.tsx      # checks specific file(s) for `any` usage
#   ./check_types.sh path/to/dir/          # checks a directory

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

# --- TypeScript compiler check ---
if [ -f tsconfig.json ] || [ -f tsconfig.app.json ]; then
    log_info "Running tsc --noEmit..."
    if npx tsc --noEmit 2>&1; then
        log_pass "tsc: no type errors"
    else
        log_fail "tsc: type errors found — fix all TypeScript compiler errors"
    fi
else
    log_info "No tsconfig.json found. Skipping tsc check."
fi

echo "---"

# --- Check for untyped `any` usage in changed files ---
if [ $# -ge 1 ]; then
    TARGET="$1"
    if [ -d "$TARGET" ]; then
        FILES=$(find "$TARGET" -type f \( -name "*.ts" -o -name "*.tsx" \) | tr '\n' ' ')
    else
        FILES="$TARGET"
    fi
else
    BASE_BRANCH="${BASE_BRANCH:-main}"
    FILES=$(git diff --name-only "$BASE_BRANCH"...HEAD -- '*.ts' '*.tsx' 2>/dev/null \
        || git diff --name-only HEAD -- '*.ts' '*.tsx')
    FILES=$(echo "$FILES" | xargs -I{} sh -c '[ -f "{}" ] && echo "{}"' | tr '\n' ' ')
fi

if [ -n "${FILES// }" ]; then
    log_info "Scanning for untyped 'any' usage in changed files..."
    # Match `: any`, `as any`, `<any>` but not inside comments or strings (best-effort)
    ANY_HITS=$(grep -nE ':\s*any\b|as\s+any\b|<any>' $FILES 2>/dev/null || true)
    if [ -z "$ANY_HITS" ]; then
        log_pass "No untyped 'any' found in changed files"
    else
        log_fail "Found 'any' type usage — replace with specific types or add justification comment:"
        echo "$ANY_HITS"
    fi
else
    log_info "No TypeScript files to scan for 'any'."
fi

echo "---"
echo -e "Type check complete — ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
[ "$FAIL" -eq 0 ]
