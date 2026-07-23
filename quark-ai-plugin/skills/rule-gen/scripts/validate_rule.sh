#!/usr/bin/env bash
# validate_rule.sh — check whether a Quark rule matches at least one behavior in an APK
# Usage: bash validate_rule.sh "<apk_path>" "<rule_path>"
# Exit 0: rule matched (crimes > 0)
# Exit 1: rule did not match (crimes == 0)
# Exit 2: usage error or file not found

set -uo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: validate_rule.sh <apk_path> <rule_path>" >&2
    exit 2
fi

APK_PATH="$1"
RULE_PATH="$2"
RESULT_FILE="/tmp/quark_validate_result_$$.json"

if [ ! -f "$APK_PATH" ]; then
    echo "Error: APK not found: $APK_PATH" >&2
    exit 2
fi

if [ ! -f "$RULE_PATH" ]; then
    echo "Error: Rule file not found: $RULE_PATH" >&2
    exit 2
fi

# Use -s <rule.json> (NOT -r) — the -r flag uses os.walk() which yields nothing
# for a file path, silently returning zero results every time.
echo "[validate_rule] Running: quark -s \"$RULE_PATH\" -a \"$APK_PATH\" -o $RESULT_FILE" >&2
quark -s "$RULE_PATH" -a "$APK_PATH" -o "$RESULT_FILE"

python3 -c "
import json, sys
with open('$RESULT_FILE') as f:
    data = json.load(f)
crimes = data.get('crimes', [])
# Every loaded rule appears in crimes, even unmatched ones (confidence 0%).
# A rule matched only when at least one stage passed: confidence > 0%.
matched = [c for c in crimes if c.get('confidence', '0%') != '0%']
print(f'Behaviors detected: {len(matched)}')
if matched:
    for c in matched:
        print(f'  - {c[\"crime\"]} (confidence: {c[\"confidence\"]})')
else:
    print('  (no stages passed — rule did not match this APK)')
sys.exit(0 if matched else 1)
"
EXIT_CODE=$?

rm -f "$RESULT_FILE"
exit $EXIT_CODE
