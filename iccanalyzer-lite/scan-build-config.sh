#!/bin/bash
# Scan-Build Configuration for iccAnalyzer-lite
# Purpose: Static analysis for security issues
# Date: 2026-02-07

set -e

# Configuration
SCAN_BUILD=$(which scan-build)
CCC_CC=$(which clang)
CCC_CXX=$(which clang++)
OUTPUT_DIR="scan-build-results"
REPORT_DIR="scan-build-report"

# Scan-build checkers
CHECKERS=(
    "alpha.security.ArrayBoundV2"
    "alpha.security.MallocOverflow"
    "alpha.security.ReturnPtrRange"
    "alpha.unix.cstring.BufferOverlap"
    "core.CallAndMessage"
    "core.DivideZero"
    "core.NonNullParamChecker"
    "core.NullDereference"
    "core.StackAddressEscape"
    "core.UndefinedBinaryOperatorResult"
    "core.VLASize"
    "core.uninitialized.ArraySubscript"
    "core.uninitialized.Assign"
    "core.uninitialized.Branch"
    "core.uninitialized.UndefReturn"
    "cplusplus.NewDelete"
    "cplusplus.NewDeleteLeaks"
    "deadcode.DeadStores"
    "security.FloatLoopCounter"
    "security.insecureAPI.UncheckedReturn"
    "security.insecureAPI.getpw"
    "security.insecureAPI.gets"
    "security.insecureAPI.mkstemp"
    "security.insecureAPI.mktemp"
    "security.insecureAPI.vfork"
    "unix.API"
    "unix.Malloc"
    "unix.MallocSizeof"
    "unix.MismatchedDeallocator"
    "unix.cstring.BadSizeArg"
    "unix.cstring.NullArg"
)

# Build checker arguments
CHECKER_ARGS=""
for checker in "${CHECKERS[@]}"; do
    CHECKER_ARGS="$CHECKER_ARGS -enable-checker $checker"
done

echo "[INFO] Scan-build configuration for iccAnalyzer-lite"
echo "[INFO] Output directory: $OUTPUT_DIR"
echo "[INFO] Checkers enabled: ${#CHECKERS[@]}"
echo "[INFO] Report directory: $REPORT_DIR"

# Clean previous results
rm -rf "$OUTPUT_DIR" "$REPORT_DIR"
mkdir -p "$OUTPUT_DIR"

# Run scan-build
echo "[INFO] Running scan-build analysis..."
$SCAN_BUILD \
    --use-cc="$CCC_CC" \
    --use-c++="$CCC_CXX" \
    -o "$OUTPUT_DIR" \
    $CHECKER_ARGS \
    -analyze-headers \
    -maxloop 10 \
    --status-bugs \
    -v \
    make clean all

# Generate report
echo "[INFO] Analysis complete"
if [ -d "$OUTPUT_DIR" ]; then
    LATEST_REPORT=$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -type d | sort -r | head -1)
    if [ -n "$LATEST_REPORT" ]; then
        mv "$LATEST_REPORT" "$REPORT_DIR"
        echo "[SUCCESS] Report available at: $REPORT_DIR/index.html"
        
        # Count issues
        ISSUE_COUNT=$(grep -c "Bug" "$REPORT_DIR/index.html" 2>/dev/null || echo "0")
        echo "[INFO] Issues found: $ISSUE_COUNT"
    else
        echo "[SUCCESS] No issues found"
    fi
fi

echo "[INFO] Scan-build analysis complete"
