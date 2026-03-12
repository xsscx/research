#!/bin/bash
# test-iccDumpProfile.sh — iccDumpProfile envelope tests
# Usage: ./test-iccDumpProfile.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

DUMP="$TOOLS/IccDumpProfile/iccDumpProfile"
echo "=== iccDumpProfile ==="

run_test "dump-01" "Dump sRGB v4 display profile" "$DUMP" "$SRGB"
run_test "dump-02" "Dump with validation (-v)" "$DUMP" -v "$SRGB"
run_test "dump-03" "Dump specific tag (desc)" "$DUMP" "$SRGB" desc
run_test "dump-04" "Dump ALL tags" "$DUMP" "$SRGB" ALL
run_test "dump-05" "Dump with verbosity=25" "$DUMP" 25 "$SRGB"
run_test "dump-06" "Dump CMYK output profile" "$DUMP" -v "$CMYK"
run_test "dump-07" "Dump v5 spectral profile" "$DUMP" -v "$REC2020"
run_test "dump-08" "Dump NamedColor profile" "$DUMP" -v "$NAMED"
run_test "dump-09" "Dump 17-channel profile" "$DUMP" -v "$MULTICHAN"
run_test "dump-10" "Dump MVIS profile" "$DUMP" -v "$MVIS"
run_test "dump-11" "Dump CameraModel profile" "$DUMP" -v "$CAMERA"
run_test "dump-12" "Dump DisplayP3 profile" "$DUMP" -v "$DISPLAY_P3"
run_test "dump-13" "Dump v5 LCDDisplay profile" "$DUMP" -v "$V5_DISPLAY"
run_test "dump-14" "Dump Cat8Lab spectral profile" "$DUMP" -v "$CAT8"

# Batch PoC profiles
POC_COUNT=0
for poc in "$TP"/hbo-*.icc "$TP"/sbo-*.icc "$TP"/segv-*.icc "$TP"/npd-*.icc \
           "$TP"/so-*.icc "$TP"/ub-*.icc "$TP"/oom-*.icc "$TP"/cve-*.icc \
           "$TP"/memcpy-*.icc "$TP"/DoubleFree*.icc "$TP"/CIccMpe*.icc \
           "$TP"/CIccTag*.icc "$TP"/CIccTone*.icc; do
  if [ -f "$poc" ] && [ "$POC_COUNT" -lt 25 ]; then
    base=$(basename "$poc" .icc | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    run_test "poc-$base" "PoC: $(basename "$poc" | cut -c1-50)" "$DUMP" "$poc"
    POC_COUNT=$((POC_COUNT + 1))
  fi
done

# Batch random profiles from test-profiles/
BATCH_COUNT=0
for icc in "$TP"/*.icc; do
  if [ -f "$icc" ] && [ "$BATCH_COUNT" -lt 10 ]; then
    base=$(basename "$icc" .icc | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    # Skip profiles already tested individually
    case "$base" in
      sRGB_D65_MAT|CMYK*|Rec2020*|NamedColor|17Chan*|CameraModel|Cat8*) continue ;;
    esac
    run_test "batch-$base" "Batch: $(basename "$icc" | cut -c1-50)" "$DUMP" -v "$icc"
    BATCH_COUNT=$((BATCH_COUNT + 1))
  fi
done

print_summary "iccDumpProfile"
exit $FAIL
