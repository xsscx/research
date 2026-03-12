#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccApplySearch.sh — iccApplySearch envelope tests
# Usage: ./test-iccApplySearch.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

APPLYSRCH="$TOOLS/IccApplySearch/iccApplySearch"
echo "=== iccApplySearch ==="

# ApplySearch requires TWO profiles (source→destination)
run_test "search-01" "sRGB→sRGB encoding=0 relative" \
  "$APPLYSRCH" "$SRGB_CALC_DATA" 0 0 "$SRGB" 1 "$SRGB" 1
run_test "search-02" "sRGB→sRGB encoding=0 perceptual" \
  "$APPLYSRCH" "$SRGB_CALC_DATA" 0 0 "$SRGB" 0 "$SRGB" 0
run_test "search-03" "sRGB→DisplayP3 encoding=0 relative" \
  "$APPLYSRCH" "$SRGB_CALC_DATA" 0 0 "$SRGB" 1 "$DISPLAY_P3" 1
run_test "search-04" "sRGB→sRGB encoding=3 (Float)" \
  "$APPLYSRCH" "$TD/test-data-rgb-float.txt" 3 0 "$SRGB" 1 "$SRGB" 1

print_summary "iccApplySearch"
exit "$FAIL"
