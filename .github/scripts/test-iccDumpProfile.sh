#!/bin/bash
# shellcheck source=iccdev-test-common.sh
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

# Batch PoC profiles (parallel)
POC_FILES=()
for poc in "$TP"/hbo-*.icc "$TP"/sbo-*.icc "$TP"/segv-*.icc "$TP"/npd-*.icc \
           "$TP"/so-*.icc "$TP"/ub-*.icc "$TP"/oom-*.icc "$TP"/cve-*.icc \
           "$TP"/memcpy-*.icc "$TP"/DoubleFree*.icc "$TP"/CIccMpe*.icc \
           "$TP"/CIccTag*.icc "$TP"/CIccTone*.icc; do
  [ -f "$poc" ] && POC_FILES+=("$poc")
done
if [ "${#POC_FILES[@]}" -gt 0 ]; then
  run_batch_parallel "poc" "PoC" "$DUMP" -- "${POC_FILES[@]}"
fi

# Batch random profiles from test-profiles/ (parallel)
BATCH_FILES=()
for icc in "$TP"/*.icc; do
  if [ -f "$icc" ]; then
    base=$(basename "$icc" .icc)
    case "$base" in
      sRGB_D65_MAT|CMYK*|Rec2020*|NamedColor|17Chan*|CameraModel|Cat8*) continue ;;
    esac
    BATCH_FILES+=("$icc")
  fi
done
if [ "${#BATCH_FILES[@]}" -gt 0 ]; then
  run_batch_parallel "batch" "Batch" "$DUMP" -v -- "${BATCH_FILES[@]}"
fi

print_summary "iccDumpProfile"
exit "$FAIL"
