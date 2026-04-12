#!/usr/bin/env bash
# check_security.sh
# Covers checklist §5:
#   [Lang] Run security audit on dependencies
#   [Lang] No dangerouslySetInnerHTML, eval(), document.write(), or innerHTML without sanitization
#
# Usage:
#   ./check_security.sh                       # audits deps + scans changed files
#   ./check_security.sh path/to/file.tsx      # scans a specific file for dangerous patterns
#   ./check_security.sh path/to/dir/          # scans a directory

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# --- Dependency audit ---
log_info "Running dependency security audit..."
echo "---"

if [ -f pnpm-lock.yaml ]; then
    if pnpm audit --prod 2>&1; then
        log_pass "pnpm audit: no known vulnerabilities"
    else
        log_fail "pnpm audit: vulnerabilities found — run pnpm audit for details"
    fi
elif [ -f yarn.lock ]; then
    if yarn audit --groups dependencies 2>&1; then
        log_pass "yarn audit: no known vulnerabilities"
    else
        log_fail "yarn audit: vulnerabilities found — run yarn audit for details"
    fi
elif [ -f package-lock.json ]; then
    if npm audit --omit=dev 2>&1; then
        log_pass "npm audit: no known vulnerabilities"
    else
        log_fail "npm audit: vulnerabilities found — run npm audit for details"
    fi
else
    log_info "No lockfile found. Skipping dependency audit."
fi

echo "---"

# --- Dangerous pattern scan in source files ---
if [ $# -ge 1 ]; then
    TARGET="$1"
    if [ -d "$TARGET" ]; then
        FILES=$(find "$TARGET" -type f \( -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" -o -name "*.vue" -o -name "*.svelte" \) -not -path "*/node_modules/*" | tr '\n' ' ')
    else
        FILES="$TARGET"
    fi
else
    BASE_BRANCH="${BASE_BRANCH:-main}"
    FILES=$(git diff --name-only "$BASE_BRANCH"...HEAD -- '*.ts' '*.tsx' '*.js' '*.jsx' '*.vue' '*.svelte' 2>/dev/null \
        || git diff --name-only HEAD -- '*.ts' '*.tsx' '*.js' '*.jsx' '*.vue' '*.svelte')
    FILES=$(echo "$FILES" | xargs -I{} sh -c '[ -f "{}" ] && echo "{}"' | tr '\n' ' ')
fi

if [ -n "${FILES// }" ]; then
    log_info "Scanning for dangerous patterns in source files..."

    DANGEROUS_PATTERNS=(
        'dangerouslySetInnerHTML'
        '\beval\s*('
        'document\.write\s*('
        '\.innerHTML\s*='
        'Function\s*('
        'new\s+Function\s*('
    )

    FOUND_ISSUES=0
    for pattern in "${DANGEROUS_PATTERNS[@]}"; do
        HITS=$(grep -rnE "$pattern" $FILES 2>/dev/null || true)
        if [ -n "$HITS" ]; then
            log_warn "Found potentially dangerous pattern: $pattern"
            echo "$HITS"
            FOUND_ISSUES=$((FOUND_ISSUES+1))
        fi
    done

    if [ "$FOUND_ISSUES" -eq 0 ]; then
        log_pass "No dangerous patterns found in changed files"
    else
        log_fail "Found $FOUND_ISSUES dangerous pattern(s) — each must be justified with explicit sanitization"
    fi
else
    log_info "No frontend source files to scan."
fi

echo "---"
echo -e "Security check complete — ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
[ "$FAIL" -eq 0 ]
