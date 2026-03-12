#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccToXml.sh — iccToXml envelope tests
# Usage: ./test-iccToXml.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

TOXML="$TOOLS/IccToXml/iccToXml"
echo "=== iccToXml ==="

run_test "toxml-01" "Convert sRGB to XML" "$TOXML" "$SRGB" "$OUTDIR/sRGB.xml"
run_test "toxml-02" "Convert CMYK to XML" "$TOXML" "$CMYK" "$OUTDIR/CMYK.xml"
run_test "toxml-03" "Convert NamedColor to XML" "$TOXML" "$NAMED" "$OUTDIR/NamedColor.xml"
run_test "toxml-04" "Convert v5 Rec2020 spectral to XML" "$TOXML" "$REC2020" "$OUTDIR/Rec2020.xml"
run_test "toxml-05" "Convert 17-channel to XML" "$TOXML" "$MULTICHAN" "$OUTDIR/17Chan.xml"
run_test "toxml-06" "Convert DisplayP3 to XML" "$TOXML" "$DISPLAY_P3" "$OUTDIR/DisplayP3.xml"
run_test "toxml-07" "Convert v5 LCDDisplay to XML" "$TOXML" "$V5_DISPLAY" "$OUTDIR/LCDDisplay.xml"

# PoC profiles through XML serialization (parallel)
POC_XML_FILES=()
for poc in "$TP"/hbo-*.icc "$TP"/sbo-*.icc "$TP"/segv-*.icc "$TP"/ub-*.icc "$TP"/cve-*.icc; do
  [ -f "$poc" ] && POC_XML_FILES+=("$poc")
done
if [ "${#POC_XML_FILES[@]}" -gt 0 ]; then
  # ToXml needs unique output per file — run with background jobs
  _pids=() _tids=()
  for poc in "${POC_XML_FILES[@]}"; do
    base=$(basename "$poc" .icc | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    tid="toxml-poc-$base"
    logfile="$OUTDIR/${tid}.log"
    (
      ec=0; timeout 60 "$TOXML" "$poc" "$OUTDIR/poc_${base}.xml" > "$logfile" 2>&1 || ec=$?
      _classify_result "$tid" "$(_safe_desc "PoC→XML: $(basename "$poc" | cut -c1-45)")" "$ec" "$logfile"
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

print_summary "iccToXml"
exit "$FAIL"
