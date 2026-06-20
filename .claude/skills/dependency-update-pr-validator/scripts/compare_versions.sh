#!/usr/bin/env bash
# is_covered = actual installed version >= target version (PEP 440 semantics).
#
# Usage: compare_versions.sh <actual_version> <target_version>
set -euo pipefail

ACTUAL="$1"
TARGET="$2"

python3 -c "
from packaging.version import Version
import sys
try:
    print('yes' if Version('$ACTUAL') >= Version('$TARGET') else 'no')
except Exception as e:
    print('unknown', file=sys.stderr)
    sys.exit(1)
"
