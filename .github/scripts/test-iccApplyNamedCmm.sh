#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccApplyNamedCmm.sh — iccApplyNamedCmm envelope tests
# Usage: ./test-iccApplyNamedCmm.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

APPLYNCM="$TOOLS/IccApplyNamedCmm/iccApplyNamedCmm"
echo "=== iccApplyNamedCmm ==="

# Encoding variations with sRGB (0=Value, 1=Percent, 2=UnitFloat, 3=Float, 4=8Bit, 5=16Bit)
run_test "ncm-01" "sRGB encoding=0 (Value)" "$APPLYNCM" "$SRGB_CALC_DATA" 0 0 "$SRGB" 1
run_test "ncm-02" "sRGB encoding=1 (Percent)" "$APPLYNCM" "$SRGB_CALC_DATA" 1 0 "$SRGB" 1
run_test "ncm-03" "sRGB encoding=2 (UnitFloat)" "$APPLYNCM" "$SRGB_CALC_DATA" 2 0 "$SRGB" 1
run_test "ncm-04" "sRGB encoding=3 (Float)" "$APPLYNCM" "$SRGB_CALC_DATA" 3 0 "$SRGB" 1
run_test "ncm-05" "sRGB encoding=4 (8Bit)" "$APPLYNCM" "$SRGB_CALC_DATA" 4 0 "$SRGB" 1
run_test "ncm-06" "sRGB encoding=5 (16Bit)" "$APPLYNCM" "$SRGB_CALC_DATA" 5 0 "$SRGB" 1

# Interpolation
run_test "ncm-07" "sRGB tetrahedral interpolation" "$APPLYNCM" "$SRGB_CALC_DATA" 0 1 "$SRGB" 1

# Intent variations (0=perceptual, 1=relative, 2=saturation, 3=absolute)
run_test "ncm-08" "sRGB perceptual intent" "$APPLYNCM" "$SRGB_CALC_DATA" 0 0 "$SRGB" 0
run_test "ncm-09" "sRGB saturation intent" "$APPLYNCM" "$SRGB_CALC_DATA" 0 0 "$SRGB" 2
run_test "ncm-10" "sRGB absolute intent" "$APPLYNCM" "$SRGB_CALC_DATA" 0 0 "$SRGB" 3

# Chained profiles
run_test "ncm-11" "sRGB→sRGB chained transform" "$APPLYNCM" "$SRGB_CALC_DATA" 0 0 "$SRGB" 1 "$SRGB" 1

# CMYK data
run_test "ncm-12" "CMYK profile with CMYK data" "$APPLYNCM" "$CMYK_DATA" 0 0 "$CMYK" 1

# Custom data files
run_test "ncm-13" "Custom RGB float data" "$APPLYNCM" "$TD/test-data-rgb-float.txt" 3 0 "$SRGB" 1
run_test "ncm-14" "Custom RGB 16-bit data" "$APPLYNCM" "$TD/test-data-rgb-16bit.txt" 0 0 "$SRGB" 1

# Format precision
run_test "ncm-15" "sRGB encoding with precision 8:12" "$APPLYNCM" "$SRGB_CALC_DATA" "0:8:12" 0 "$SRGB" 1

# Cross-space transforms
if [ -f "$DISPLAY_P3" ]; then
  run_test "ncm-16" "sRGB→DisplayP3 cross-space" "$APPLYNCM" "$SRGB_CALC_DATA" 0 0 "$SRGB" 1 "$DISPLAY_P3" 1
fi

print_summary "iccApplyNamedCmm"
exit "$FAIL"
