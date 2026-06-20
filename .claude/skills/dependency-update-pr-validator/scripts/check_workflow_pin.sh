#!/usr/bin/env bash
# Look for a hardcoded version pin of <package> inside this repo's GitHub
# Actions workflow files (e.g. pytest.yml has a standalone
# `pip install langchain==0.2.11 langchain-core==0.2.23 langchain-openai==0.1.17`
# step that is NOT driven by setup.py/Pipfile). If such a pin exists, it
# silently overrides whatever version setup.py/Pipfile declares, so bumping
# the declared version alone will never change what CI actually installs.
#
# Checks the local working tree's workflow files (current master/branch
# state), which is a reasonable approximation since workflow files rarely
# change between a dependabot PR and master.
#
# Usage: check_workflow_pin.sh <package>
set -euo pipefail

PACKAGE="$1"
REPO_ROOT="$(git rev-parse --show-toplevel)"

MATCHES=$(grep -rnE "(^|[^A-Za-z0-9_-])${PACKAGE}==[0-9]" "$REPO_ROOT/.github/workflows/" || true)

if [ -z "$MATCHES" ]; then
  echo "workflow_pin=none"
else
  echo "workflow_pin=found"
  echo "$MATCHES"
fi
