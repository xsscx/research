#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccRoundTrip.sh — iccRoundTrip envelope tests
# Usage: ./test-iccRoundTrip.sh [--asan] [--quick]
# Note: CMYK round-trip can take >30s (CWE-400 EvaluateProfile grid iteration)
source "$(dirname "$0")/iccdev-test-common.sh"

ROUNDTRIP="$TOOLS/IccRoundTrip/iccRoundTrip"
echo "=== iccRoundTrip ==="

# All 4 intents with sRGB
run_test "rt-01" "RoundTrip sRGB perceptual (intent=0)" "$ROUNDTRIP" "$SRGB" 0
run_test "rt-02" "RoundTrip sRGB relative (intent=1)" "$ROUNDTRIP" "$SRGB" 1
run_test "rt-03" "RoundTrip sRGB saturation (intent=2)" "$ROUNDTRIP" "$SRGB" 2
run_test "rt-04" "RoundTrip sRGB absolute (intent=3)" "$ROUNDTRIP" "$SRGB" 3

# CMYK (may timeout — known CWE-400 pattern)
run_test "rt-05" "RoundTrip CMYK relative" "$ROUNDTRIP" "$CMYK" 1

# DisplayP3
run_test "rt-06" "RoundTrip DisplayP3 relative" "$ROUNDTRIP" "$DISPLAY_P3" 1

# MPE mode
run_test "rt-07" "RoundTrip sRGB with MPE (use_mpe=1)" "$ROUNDTRIP" "$SRGB" 1 1

if [ "$QUICK_MODE" -eq 0 ]; then
  run_test "rt-08" "RoundTrip AdobeRGB relative" "$ROUNDTRIP" "$ADOBE" 1

  # Additional profiles
  for icc in "$SRGB_500" "$CAT8"; do
    if [ -f "$icc" ]; then
      base=$(basename "$icc" .icc | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-30)
      run_test "rt-$base" "RoundTrip $base relative" "$ROUNDTRIP" "$icc" 1
    fi
  done
fi

print_summary "iccRoundTrip"
exit "$FAIL"
