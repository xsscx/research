#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccFromXml.sh — iccFromXml envelope tests
# Usage: ./test-iccFromXml.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

FROMXML="$TOOLS/IccFromXml/iccFromXml"
TOXML="$TOOLS/IccToXml/iccToXml"
echo "=== iccFromXml ==="

# Pre-generate XML inputs (if not already present from iccToXml run)
for profile_name in sRGB CMYK NamedColor Rec2020; do
  case "$profile_name" in
    sRGB) src="$SRGB" ;;
    CMYK) src="$CMYK" ;;
    NamedColor) src="$NAMED" ;;
    Rec2020) src="$REC2020" ;;
  esac
  if [ -f "$src" ] && [ ! -f "$OUTDIR/${profile_name}.xml" ]; then
    "$TOXML" "$src" "$OUTDIR/${profile_name}.xml" > /dev/null 2>&1 || true
  fi
done

run_test "fromxml-01" "Reconstruct sRGB from XML" \
  "$FROMXML" "$OUTDIR/sRGB.xml" "$OUTDIR/sRGB_rt.icc"

run_test "fromxml-02" "Reconstruct CMYK from XML" \
  "$FROMXML" "$OUTDIR/CMYK.xml" "$OUTDIR/CMYK_rt.icc"

run_test "fromxml-03" "Reconstruct NamedColor from XML" \
  "$FROMXML" "$OUTDIR/NamedColor.xml" "$OUTDIR/NamedColor_rt.icc"

run_test "fromxml-04" "Reconstruct v5 Rec2020 from XML" \
  "$FROMXML" "$OUTDIR/Rec2020.xml" "$OUTDIR/Rec2020_rt.icc"

if [ -f "$HYBRID_XML" ]; then
  run_test "fromxml-05" "Parse upstream LCDDisplay XML" \
    "$FROMXML" "$HYBRID_XML" "$OUTDIR/LCDDisplay_from_xml.icc"
fi

run_test "fromxml-06" "FromXml with -noid flag" \
  "$FROMXML" "$OUTDIR/sRGB.xml" "$OUTDIR/sRGB_noid.icc" -noid

# Batch fuzz XML corpus (parallel)
FUZZ_XML_FILES=()
for xml_file in "$REPO_ROOT"/fuzz/xml/icc/*.xml; do
  [ -f "$xml_file" ] && FUZZ_XML_FILES+=("$xml_file")
done
if [ "${#FUZZ_XML_FILES[@]}" -gt 0 ]; then
  _pids=() _tids=()
  for xml_file in "${FUZZ_XML_FILES[@]}"; do
    base=$(basename "$xml_file" .xml | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    tid="fromxml-fuzz-$base"
    logfile="$OUTDIR/${tid}.log"
    (
      ec=0; timeout 60 "$FROMXML" "$xml_file" "$OUTDIR/fuzz_${base}.icc" > "$logfile" 2>&1 || ec=$?
      _classify_result "$tid" "$(_safe_desc "Fuzz XML: $(basename "$xml_file" | cut -c1-45)")" "$ec" "$logfile"
    ) &
    _pids+=($!); _tids+=("$tid")
    [ "${#_pids[@]}" -ge "$NCPU" ] && { wait "${_pids[0]}" 2>/dev/null || true; _pids=("${_pids[@]:1}"); }
  done
  for p in "${_pids[@]}"; do wait "$p" 2>/dev/null || true; done
  for tid in "${_tids[@]}"; do
    rf="$_PARALLEL_DIR/$tid.result"
    if [ -f "$rf" ]; then
      IFS=$'\t' read -r status exit_code has_asan has_ubsan description note sanitizer_note < "$rf"
      TOTAL=$((TOTAL + 1))
      [ "$status" = "PASS" ] && PASS=$((PASS + 1)) || FAIL=$((FAIL + 1))
      [ "$has_asan" -eq 1 ] && ASAN_FINDINGS=$((ASAN_FINDINGS + 1))
      [ "$has_ubsan" -eq 1 ] && UBSAN_FINDINGS=$((UBSAN_FINDINGS + 1))
      printf "  [%-7s] %-55s exit=%-3d%s%s\n" "$status" "$description" "$exit_code" "$note" "$sanitizer_note"
    fi
  done
fi

# AFL-minimized XML corpus (parallel)
FUZZ_MIN_FILES=()
for xml_file in "$REPO_ROOT"/fuzz/xml/icc/minimized/*; do
  [ -f "$xml_file" ] && FUZZ_MIN_FILES+=("$xml_file")
done
if [ "${#FUZZ_MIN_FILES[@]}" -gt 0 ]; then
  _pids=() _tids=()
  for xml_file in "${FUZZ_MIN_FILES[@]}"; do
    base=$(basename "$xml_file" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    tid="fromxml-min-$base"
    logfile="$OUTDIR/${tid}.log"
    (
      ec=0; timeout 60 "$FROMXML" "$xml_file" "$OUTDIR/min_${base}.icc" > "$logfile" 2>&1 || ec=$?
      _classify_result "$tid" "$(_safe_desc "Minimized: $(basename "$xml_file" | cut -c1-45)")" "$ec" "$logfile"
    ) &
    _pids+=($!); _tids+=("$tid")
    [ "${#_pids[@]}" -ge "$NCPU" ] && { wait "${_pids[0]}" 2>/dev/null || true; _pids=("${_pids[@]:1}"); }
  done
  for p in "${_pids[@]}"; do wait "$p" 2>/dev/null || true; done
  for tid in "${_tids[@]}"; do
    rf="$_PARALLEL_DIR/$tid.result"
    if [ -f "$rf" ]; then
      IFS=$'\t' read -r status exit_code has_asan has_ubsan description note sanitizer_note < "$rf"
      TOTAL=$((TOTAL + 1))
      [ "$status" = "PASS" ] && PASS=$((PASS + 1)) || FAIL=$((FAIL + 1))
      [ "$has_asan" -eq 1 ] && ASAN_FINDINGS=$((ASAN_FINDINGS + 1))
      [ "$has_ubsan" -eq 1 ] && UBSAN_FINDINGS=$((UBSAN_FINDINGS + 1))
      printf "  [%-7s] %-55s exit=%-3d%s%s\n" "$status" "$description" "$exit_code" "$note" "$sanitizer_note"
    fi
  done
fi

print_summary "iccFromXml"
exit "$FAIL"
