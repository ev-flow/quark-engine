#!/usr/bin/env bash
# check_bundle.sh
# Covers checklist §9:
#   [Staff Eng] Bundle impact is considered — no large library added for trivial functionality
#
# Analyzes bundle size using the project's build tool.
# Reports total bundle size and flags large chunks.
#
# Usage:
#   ./check_bundle.sh                    # build and report bundle size
#   BUNDLE_LIMIT_KB=500 ./check_bundle.sh  # fail if any chunk exceeds limit
#
# Supports: vite, next.js, webpack (via npm run build output)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

BUNDLE_LIMIT_KB="${BUNDLE_LIMIT_KB:-500}"

log_info "Building project and analyzing bundle size (chunk limit: ${BUNDLE_LIMIT_KB}KB)..."
echo "---"

# Run build and capture output
BUILD_OUTPUT=$(npm run build 2>&1) || {
    log_fail "Build failed — fix build errors before analyzing bundle"
    echo "$BUILD_OUTPUT"
    exit 1
}

echo "$BUILD_OUTPUT"
echo "---"

# Check for large files in the output directory
OUTPUT_DIRS=("dist" "build" ".next" "out")
FOUND_DIR=""

for dir in "${OUTPUT_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        FOUND_DIR="$dir"
        break
    fi
done

if [ -n "$FOUND_DIR" ]; then
    log_info "Checking file sizes in $FOUND_DIR/..."

    LARGE_FILES=$(find "$FOUND_DIR" -type f \( -name "*.js" -o -name "*.css" \) -size +"${BUNDLE_LIMIT_KB}k" 2>/dev/null || true)

    if [ -z "$LARGE_FILES" ]; then
        log_pass "No JS/CSS chunks exceed ${BUNDLE_LIMIT_KB}KB"
    else
        log_warn "Large chunks found (>${BUNDLE_LIMIT_KB}KB):"
        echo "$LARGE_FILES" | while read -r f; do
            SIZE=$(du -k "$f" | cut -f1)
            echo "  ${SIZE}KB  $f"
        done
        log_fail "Bundle contains chunks exceeding ${BUNDLE_LIMIT_KB}KB — consider code splitting or removing unnecessary dependencies"
    fi

    # Report total size
    TOTAL_JS=$(find "$FOUND_DIR" -name "*.js" -exec du -k {} + 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    TOTAL_CSS=$(find "$FOUND_DIR" -name "*.css" -exec du -k {} + 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    echo ""
    echo "  Total JS:  ${TOTAL_JS}KB"
    echo "  Total CSS: ${TOTAL_CSS}KB"
else
    log_info "No output directory found (checked: ${OUTPUT_DIRS[*]}). Skipping file-size analysis."
fi

echo "---"
echo -e "Bundle check complete — ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
[ "$FAIL" -eq 0 ]
