#!/usr/bin/env bash
# check_commit.sh
# Covers checklist §11:
#   [Staff Eng] Commit message follows conventional commit format
#
# Validates the most recent commit message (or a provided message) against
# the Conventional Commits spec: https://www.conventionalcommits.org/
#
# Usage:
#   ./check_commit.sh                        # checks HEAD commit message
#   ./check_commit.sh "feat: add new modal"  # checks the provided message
#   ./check_commit.sh HEAD~3                 # checks a specific commit ref

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

CONVENTIONAL_COMMIT_REGEX='^(feat|fix|refactor|docs|test|chore|perf|ci|style|build|revert)(\(.+\))?(!)?: .{1,72}$'

# Resolve message to check
if [ $# -ge 1 ]; then
    ARG="$1"
    if git rev-parse --verify "$ARG" > /dev/null 2>&1; then
        MSG=$(git log -1 --pretty=%s "$ARG")
        log_info "Checking commit: $ARG"
    else
        MSG="$ARG"
        log_info "Checking provided message"
    fi
else
    MSG=$(git log -1 --pretty=%s HEAD)
    log_info "Checking HEAD commit"
fi

echo "Message: \"$MSG\""
echo "---"

if echo "$MSG" | grep -qE "$CONVENTIONAL_COMMIT_REGEX"; then
    log_pass "Commit message follows conventional commit format"
else
    log_fail "Commit message does not follow conventional commit format"
    echo ""
    echo "  Expected format:  <type>[optional scope]: <description>"
    echo "  Valid types:      feat, fix, refactor, docs, test, chore, perf, ci, style, build, revert"
    echo "  Examples:"
    echo "    feat: add responsive navigation drawer"
    echo "    fix(modal): prevent body scroll when dialog is open"
    echo "    docs: update component API reference"
    exit 1
fi
