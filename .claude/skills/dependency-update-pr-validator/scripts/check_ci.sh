#!/usr/bin/env bash
# Summarize all status checks for a PR. A PR counts as "all passed" when
# every check is pass or skipping (skipping is normal — e.g. kali-package.yml
# only runs on push to master, so it's always skipped on a PR).
#
# Usage: check_ci.sh <repo> <pr_number>
set -euo pipefail

REPO="$1"
PR="$2"

CHECKS=$(gh pr checks "$PR" --repo "$REPO" 2>/dev/null) || true

if [ -z "$CHECKS" ]; then
  echo "all_passed=unknown"
  echo "reason=no checks reported yet"
  exit 0
fi

FAILING=$(echo "$CHECKS" | awk -F'\t' '$2 != "pass" && $2 != "skipping" {print}')

if [ -z "$FAILING" ]; then
  echo "all_passed=yes"
else
  echo "all_passed=no"
  echo "--- failing checks ---"
  echo "$FAILING"
fi
