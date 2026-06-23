#!/usr/bin/env bash
# Find the actual installed version of a package, as proven by the `build`
# job log (pytest.yml), which is the only workflow that runs `pip install .`
# against this repo's real install_requires (setup.py). Pipfile/Pipfile.lock
# changes are NOT consumed by any current CI workflow — see SKILL.md.
#
# Usage: check_actual_version.sh <repo> <head_ref> <package>
set -euo pipefail

REPO="$1"
HEAD_REF="$2"
PACKAGE="$3"

RUN_ID=$(gh run list --repo "$REPO" --workflow=pytest.yml --branch="$HEAD_REF" \
  --json databaseId,conclusion -q '.[0]')

if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "null" ]; then
  echo "actual_version=UNKNOWN"
  echo "reason=no pytest.yml run found for branch $HEAD_REF"
  exit 0
fi

DB_ID=$(echo "$RUN_ID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["databaseId"])')
CONCLUSION=$(echo "$RUN_ID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["conclusion"])')

echo "run_id=$DB_ID"
echo "run_conclusion=$CONCLUSION"

JOB_ID=$(gh run view "$DB_ID" --repo "$REPO" --json jobs -q '.jobs[] | select(.name=="build") | .databaseId' | head -1)
if [ -n "$JOB_ID" ]; then
  echo "proof_url=https://github.com/${REPO}/actions/runs/${DB_ID}/job/${JOB_ID}"
fi

if [ "$CONCLUSION" != "success" ]; then
  echo "actual_version=UNKNOWN"
  echo "reason=pytest.yml run did not succeed, install log is not a reliable signal"
  exit 0
fi

VERSION=$(gh run view "$DB_ID" --repo "$REPO" --log 2>/dev/null \
  | grep -i "Successfully installed" \
  | grep -oE "(^|[[:space:]])${PACKAGE}-[0-9][0-9A-Za-z.+-]*" \
  | head -1 \
  | sed -E "s/^[[:space:]]*${PACKAGE}-//")

if [ -z "$VERSION" ]; then
  echo "actual_version=UNKNOWN"
  echo "reason=package not found in 'Successfully installed' line (it may not be installed by pip install ., e.g. only declared in Pipfile)"
else
  echo "actual_version=$VERSION"
fi
