#!/bin/bash
# test-iccApplySearch.sh — iccApplySearch envelope tests
# Usage: ./test-iccApplySearch.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

APPLYSRCH="$TOOLS/IccApplySearch/iccApplySearch"
echo "=== iccApplySearch ==="

run_test "search-01" "sRGB encoding=0 relative intent" \
  "$APPLYSRCH" "$SRGB_CALC_DATA" 0 0 "$SRGB" 1
run_test "search-02" "sRGB encoding=0 perceptual intent" \
  "$APPLYSRCH" "$SRGB_CALC_DATA" 0 0 "$SRGB" 0
run_test "search-03" "sRGB encoding=3 (Float)" \
  "$APPLYSRCH" "$TD/test-data-rgb-float.txt" 3 0 "$SRGB" 1
run_test "search-04" "sRGB→sRGB→sRGB 3-profile chain" \
  "$APPLYSRCH" "$SRGB_CALC_DATA" 0 0 "$SRGB" 1 "$SRGB" 1 "$SRGB" 1

print_summary "iccApplySearch"
exit $FAIL
