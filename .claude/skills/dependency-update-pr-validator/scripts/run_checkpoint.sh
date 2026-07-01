#!/usr/bin/env bash
# Prints the cheap checkpoint (no log digging): target package, before
# version, target version, and whether all CI checks passed. Run this first
# and show the result to the user before moving on to the slower step of
# digging through CI logs.
#
# Usage: run_checkpoint.sh <repo> <pr_number>
set -euo pipefail

REPO="$1"
PR="$2"

echo "=== PR info ==="
gh pr view "$PR" --repo "$REPO" --json title -q '.title'
"$(dirname "$0")/parse_pr.sh" "$REPO" "$PR"

echo "=== CI status ==="
"$(dirname "$0")/check_ci.sh" "$REPO" "$PR"
