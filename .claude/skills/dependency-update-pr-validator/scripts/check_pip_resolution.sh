#!/usr/bin/env bash
# Only meaningful when the PR changed setup.py. A dependabot PR can bump one
# pin in a requirements list (e.g. quarkAgentRequirements) while leaving its
# sibling pins untouched — that combination can be mutually unsatisfiable
# even though pytest.yml's hardcoded install step never notices (it installs
# its own separate hardcoded versions, see check_workflow_pin.sh). This is a
# stronger, more definitive signal than is_covered: if pip itself can't
# resolve the post-PR setup.py, the bump is broken for any real user
# regardless of what CI happened to test.
#
# Scoped to just the requirement list that declares <package>, so an
# unrelated pre-existing conflict elsewhere in setup.py doesn't get blamed
# on this PR.
#
# Usage: check_pip_resolution.sh <repo> <head_ref> <package>
set -euo pipefail

REPO="$1"
HEAD_REF="$2"
PACKAGE="$3"

TMP_SETUP=$(mktemp)
trap 'rm -f "$TMP_SETUP"' EXIT

gh api -H "Accept: application/vnd.github.raw" \
  "repos/$REPO/contents/setup.py?ref=$HEAD_REF" > "$TMP_SETUP"

REQ_LINE=$(python3 - "$TMP_SETUP" "$PACKAGE" <<'PYEOF'
import ast, sys

path, package = sys.argv[1], sys.argv[2]
with open(path) as f:
    tree = ast.parse(f.read())

for node in ast.walk(tree):
    if isinstance(node, ast.List):
        items = [n.value for n in node.elts if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        if not items or not all(any(op in s for op in ("==", ">=", "<=")) for s in items):
            continue
        names = [s.split("==")[0].split(">=")[0].split("<=")[0].strip() for s in items]
        if package in names:
            print(" ".join(items))
            break
PYEOF
)

if [ -z "$REQ_LINE" ]; then
  echo "pip_resolution=skipped"
  echo "reason=$PACKAGE not found in any pinned requirement list in setup.py"
  exit 0
fi

echo "checking: $REQ_LINE"
if OUT=$(pip install --dry-run --quiet $REQ_LINE 2>&1); then
  echo "pip_resolution=ok"
else
  echo "pip_resolution=conflict"
  echo "$OUT" | tail -15
fi
