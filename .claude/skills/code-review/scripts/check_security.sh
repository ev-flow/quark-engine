#!/usr/bin/env bash
# check_security.sh
# Covers review_standard.md §5:
#   [Lang] Run language-level security scan (e.g., bandit) and confirm no vulnerabilities
#
# Usage:
#   ./check_security.sh                  # scans all changed .py files (git diff vs main)
#   ./check_security.sh path/to/file.py  # scans a specific file
#   ./check_security.sh path/to/dir/     # scans an entire directory
#
# Severity levels reported by bandit:
#   HIGH   — must fix before merge
#   MEDIUM — review and justify if not fixed
#   LOW    — informational

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

log_info "Running bandit security scan..."
echo "Target: $TARGET"
echo "---"

# -ll: report MEDIUM and HIGH severity only (suppress LOW noise)
# -ii: report MEDIUM and HIGH confidence only
# -r: recursive if directory
if bandit -ll -ii -r $TARGET 2>&1; then
    log_pass "bandit: no medium/high severity vulnerabilities found"
else
    log_fail "bandit: security issues found — each HIGH/MEDIUM finding must be fixed or documented with a concrete justification before merge"
    exit 1
fi
