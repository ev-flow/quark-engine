#!/usr/bin/env bash
# run_all.sh
# Master script — runs all automated checks from review_standard.md in sequence.
# Non-automatable items (logic errors, architecture, CSO exploit scenarios, etc.)
# are listed at the end as a reminder for manual review.
#
# Usage:
#   ./run_all.sh                   # checks git-changed files vs main
#   ./run_all.sh path/to/dir/      # checks a specific directory
#   BASE_BRANCH=develop ./run_all.sh  # diff against a different base branch

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

run_check() {
    local name="$1"
    local script="$2"
    shift 2
    echo -e "\n${BOLD}▶ ${name}${NC}"
    if bash "$SCRIPT_DIR/$script" "$@" 2>&1; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
    fi
}

echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD} Automated Review Checks${NC}"
echo -e "${BOLD}========================================${NC}"

# §3 Code Style
run_check "Code Style (black + pylint)"  check_style.sh    ${TARGET}
run_check "Type Hints (mypy)"            check_types.sh    ${TARGET}
run_check "Spelling (codespell)"         check_spelling.sh ${TARGET}

# §4 Testing & Regression Prevention
run_check "Test Coverage (pytest-cov)"  check_coverage.sh ${TARGET}

# §5 Security
run_check "Security Scan (bandit)"      check_security.sh ${TARGET}

# §7 PR Preparation
run_check "Commit Message Format"       check_commit.sh

# --- Summary ---
echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD} Results${NC}"
echo -e "${BOLD}========================================${NC}"
echo -e "  ${GREEN}Passed : ${PASS}${NC}"
echo -e "  ${RED}Failed : ${FAIL}${NC}"

echo ""
echo -e "${BOLD}Manual review required (cannot be automated):${NC}"
echo "  §1 [Staff Eng]   Logic errors that pass CI but fail in production"
echo "  §1 [Staff Eng]   Completeness gaps / missing edge cases"
echo "  §2 [Staff Eng]   Each function does exactly one thing"
echo "  §2 [Eng Manager] Architecture & data-flow boundaries explicitly defined"
echo "  §2 [Eng Manager] Edge cases and boundary conditions specified"
echo "  §4 [QA]          Tests cover both expected AND unexpected inputs"
echo "  §4 [QA]          Every bug fix has an accompanying regression test"
echo "  §5 [CSO]         Security warning confidence ≥ 8/10 before raising"
echo "  §5 [CSO]         Each vulnerability includes a concrete exploit scenario"
echo "  §6 [Debugger]    Root-cause investigation before every fix"
echo "  §6 [Debugger]    Stop after 3 failed attempts and escalate"
echo "  §7 [Staff Eng]   PR title/description references the relevant issue"
echo "  §7 [QA]          Smoke test counts updated if behavior counts changed"
echo "  §7 [Lang]        quark.script API docs updated if public API changed"

echo ""
[ "$FAIL" -eq 0 ] && echo -e "${GREEN}All automated checks passed.${NC}" || echo -e "${RED}${FAIL} check(s) failed — fix before requesting review.${NC}"
[ "$FAIL" -eq 0 ]
