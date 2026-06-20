#!/usr/bin/env bash
# Parse a dependabot dependency-update PR: package name, before/target
# version, and which files it touched. Which file changed (setup.py vs
# Pipfile/Pipfile.lock) does NOT tell you whether CI actually installs the
# target version — some setup.py-declared packages are overridden by a
# hardcoded pin elsewhere in the workflow (see check_workflow_pin.sh), and
# some Pipfile-only packages are unconstrained transitive deps that CI
# happily floats to the latest version anyway. Use check_actual_version.sh
# + check_workflow_pin.sh for that, not this script's changed_files.
#
# Usage: parse_pr.sh <repo> <pr_number>
set -euo pipefail

REPO="$1"
PR="$2"

TMP_BODY=$(mktemp)
trap 'rm -f "$TMP_BODY"' EXIT

gh pr view "$PR" --repo "$REPO" --json body -q '.body' > "$TMP_BODY"
FILES=$(gh pr view "$PR" --repo "$REPO" --json files -q '.files[].path')
HEAD_REF=$(gh pr view "$PR" --repo "$REPO" --json headRefName -q '.headRefName')

python3 - "$TMP_BODY" <<'PYEOF'
import re, sys

with open(sys.argv[1]) as f:
    body = f.read()

m = re.search(r"Bumps \[([^\]]+)\].*?\bfrom\s+(\S+)\s+to\s+(\S+)\.", body, re.DOTALL)
if m:
    print(f"package={m.group(1)}")
    print(f"before_version={m.group(2)}")
    print(f"target_version={m.group(3)}")
else:
    print("package=UNKNOWN")
    print("before_version=UNKNOWN")
    print("target_version=UNKNOWN")
PYEOF

echo "head_ref=$HEAD_REF"
echo "changed_files=$(echo "$FILES" | paste -sd, -)"
