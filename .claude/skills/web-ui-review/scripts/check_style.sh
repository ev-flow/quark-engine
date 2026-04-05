#!/usr/bin/env bash
# check_style.sh
# Covers checklist §3:
#   [Lang] Format with project formatter (Prettier/Biome)
#   [Lang] Run linter (ESLint/Biome) on only the files changed in this PR
#
# Usage:
#   ./check_style.sh                       # checks all changed files (git diff vs main)
#   ./check_style.sh path/to/file.tsx      # checks a specific file
#   ./check_style.sh path/to/dir/          # checks an entire directory

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

FRONTEND_EXTS="ts,tsx,js,jsx,vue,svelte,css,scss,html"

# Resolve target files
if [ $# -ge 1 ]; then
    TARGET="$1"
    if [ -d "$TARGET" ]; then
        FILES=$(find "$TARGET" -type f \( -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" -o -name "*.vue" -o -name "*.svelte" -o -name "*.css" -o -name "*.scss" -o -name "*.html" \) | tr '\n' ' ')
    else
        FILES="$TARGET"
    fi
else
    BASE_BRANCH="${BASE_BRANCH:-main}"
    FILES=$(git diff --name-only "$BASE_BRANCH"...HEAD -- '*.ts' '*.tsx' '*.js' '*.jsx' '*.vue' '*.svelte' '*.css' '*.scss' '*.html' 2>/dev/null \
        || git diff --name-only HEAD -- '*.ts' '*.tsx' '*.js' '*.jsx' '*.vue' '*.svelte' '*.css' '*.scss' '*.html')
    FILES=$(echo "$FILES" | xargs -I{} sh -c '[ -f "{}" ] && echo "{}"' | tr '\n' ' ')
fi

if [ -z "${FILES// }" ]; then
    log_info "No frontend files to check."
    exit 0
fi

echo "Checking files: $FILES"
echo "---"

# --- Formatter (Prettier or Biome) ---
if command -v biome &>/dev/null || [ -f node_modules/.bin/biome ]; then
    FORMATTER="biome"
    log_info "Running biome format (--check)..."
    if npx biome format --check $FILES 2>&1; then
        log_pass "biome format: formatting is correct"
    else
        log_fail "biome format: formatting issues found — run: npx biome format --write <files>"
    fi
elif command -v prettier &>/dev/null || [ -f node_modules/.bin/prettier ]; then
    FORMATTER="prettier"
    log_info "Running prettier (--check)..."
    if npx prettier --check $FILES 2>&1; then
        log_pass "prettier: formatting is correct"
    else
        log_fail "prettier: formatting issues found — run: npx prettier --write <files>"
    fi
else
    log_info "No formatter found (prettier or biome). Skipping format check."
fi

echo "---"

# --- Linter (ESLint or Biome) ---
if command -v biome &>/dev/null || [ -f node_modules/.bin/biome ]; then
    log_info "Running biome lint..."
    if npx biome lint $FILES 2>&1; then
        log_pass "biome lint: no issues found"
    else
        log_fail "biome lint: issues found — resolve all reported issues in the changed files"
    fi
elif command -v eslint &>/dev/null || [ -f node_modules/.bin/eslint ]; then
    log_info "Running eslint..."
    if npx eslint $FILES 2>&1; then
        log_pass "eslint: no issues found"
    else
        log_fail "eslint: issues found — resolve all reported issues in the changed files"
    fi
else
    log_info "No linter found (eslint or biome). Skipping lint check."
fi

echo "---"
echo -e "Style check complete — ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
[ "$FAIL" -eq 0 ]
