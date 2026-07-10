#!/usr/bin/env bash
# run_analysis.sh — passthrough wrapper for quark CLI
# Usage: bash run_analysis.sh "<apk_path>" [quark_flags...]
# Handles APK path quoting, logs the exact command, captures stderr.

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage: run_analysis.sh <apk_path> [quark_flags...]" >&2
    exit 1
fi

APK_PATH="$1"
shift
EXTRA_FLAGS=("$@")

if [ ! -f "$APK_PATH" ]; then
    echo "Error: APK not found: $APK_PATH" >&2
    exit 1
fi

CMD=(quark -a "$APK_PATH" "${EXTRA_FLAGS[@]}")
echo "[run_analysis] Running: ${CMD[*]}" >&2

"${CMD[@]}"
