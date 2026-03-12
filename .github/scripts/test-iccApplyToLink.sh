#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccApplyToLink.sh — iccApplyToLink envelope tests
# Usage: ./test-iccApplyToLink.sh [--asan] [--quick]
# Note: LUT generation with gridpoints>=17 can take 10-30s
source "$(dirname "$0")/iccdev-test-common.sh"

APPLYLINK="$TOOLS/IccApplyToLink/iccApplyToLink"
echo "=== iccApplyToLink ==="

if [ "$QUICK_MODE" -eq 0 ]; then
  # Device Link (type=0) with varying LUT sizes
  run_test "link-01" "DeviceLink sRGB→sRGB LUT=9 v4" \
    "$APPLYLINK" "$OUTDIR/link_srgb_9.icc" 0 9 0 "sRGB-link" 0.0 1.0 0 0 "$SRGB" 1

  run_test "link-02" "DeviceLink sRGB→sRGB LUT=17 v5" \
    "$APPLYLINK" "$OUTDIR/link_srgb_17.icc" 0 17 1 "sRGB-link-v5" 0.0 1.0 0 0 "$SRGB" 1

  run_test "link-03" "DeviceLink sRGB→sRGB LUT=33" \
    "$APPLYLINK" "$OUTDIR/link_srgb_33.icc" 0 33 0 "sRGB-link-33" 0.0 1.0 0 0 "$SRGB" 1

  # .cube output (type=1)
  run_test "link-04" ".cube output sRGB LUT=9 precision=6" \
    "$APPLYLINK" "$OUTDIR/link_srgb.cube" 1 9 6 "sRGB-cube" 0.0 1.0 0 0 "$SRGB" 1

  # Tetrahedral interpolation
  run_test "link-05" "DeviceLink sRGB tetrahedral LUT=9" \
    "$APPLYLINK" "$OUTDIR/link_srgb_tet.icc" 0 9 0 "sRGB-tet" 0.0 1.0 0 1 "$SRGB" 1

  # Destination transform (first_transform=1)
  run_test "link-06" "DeviceLink first_transform=1 (dest)" \
    "$APPLYLINK" "$OUTDIR/link_srgb_dest.icc" 0 9 0 "sRGB-dest" 0.0 1.0 1 0 "$SRGB" 1

  # Two-profile chain
  run_test "link-07" "DeviceLink sRGB→DisplayP3 chain" \
    "$APPLYLINK" "$OUTDIR/link_srgb_p3.icc" 0 17 0 "sRGB-to-P3" 0.0 1.0 0 0 "$SRGB" 1 "$DISPLAY_P3" 1
else
  # Quick mode: smaller LUTs only
  run_test "link-01" "DeviceLink sRGB→sRGB LUT=5 (quick)" \
    "$APPLYLINK" "$OUTDIR/link_srgb_5.icc" 0 5 0 "sRGB-link-q" 0.0 1.0 0 0 "$SRGB" 1

  run_test "link-04" ".cube output sRGB LUT=5 (quick)" \
    "$APPLYLINK" "$OUTDIR/link_srgb_q.cube" 1 5 4 "sRGB-cube-q" 0.0 1.0 0 0 "$SRGB" 1
fi

print_summary "iccApplyToLink"
exit "$FAIL"
