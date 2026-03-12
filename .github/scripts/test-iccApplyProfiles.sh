#!/bin/bash
# test-iccApplyProfiles.sh — iccApplyProfiles envelope tests
# Usage: ./test-iccApplyProfiles.sh [--asan] [--quick]
# Requires TIFF input files (catalyst-*.tiff from macOS agent)
source "$(dirname "$0")/iccdev-test-common.sh"

APPLYPROF="$TOOLS/IccApplyProfiles/iccApplyProfiles"
echo "=== iccApplyProfiles ==="
# Args: src dst dst_encoding dst_compress dst_planar dst_embed dst_interp profile intent
# dst_encoding: 0=same, 1=8bit, 2=16bit, 4=float
# dst_compress: 0=none, 1=LZW
# dst_planar: 0=contig, 1=separate
# dst_embed: 0=no, 1=embed
# dst_interp: 0=default, 1=tetrahedral

run_test "apply-01" "TIFF 8bit→8bit sRGB relative, no compress" \
  "$APPLYPROF" "$TIFF_8BIT" "$OUTDIR/applied_8bit.tiff" 0 0 0 0 0 "$SRGB" 1

run_test "apply-02" "TIFF 8bit→16bit sRGB relative, LZW" \
  "$APPLYPROF" "$TIFF_8BIT" "$OUTDIR/applied_16bit.tiff" 2 1 0 0 0 "$SRGB" 1

run_test "apply-03" "TIFF 8bit→float sRGB perceptual" \
  "$APPLYPROF" "$TIFF_8BIT" "$OUTDIR/applied_float.tiff" 4 0 0 0 0 "$SRGB" 0

run_test "apply-04" "TIFF 8bit with embedded ICC" \
  "$APPLYPROF" "$TIFF_8BIT" "$OUTDIR/applied_embed.tiff" 0 0 0 1 0 "$SRGB" 1

run_test "apply-05" "TIFF 8bit tetrahedral interpolation" \
  "$APPLYPROF" "$TIFF_8BIT" "$OUTDIR/applied_tet.tiff" 0 0 0 0 1 "$SRGB" 1

run_test "apply-06" "TIFF 16bit→8bit sRGB absolute" \
  "$APPLYPROF" "$TIFF_16BIT" "$OUTDIR/applied_from16.tiff" 1 0 0 0 0 "$SRGB" 2

# All 4 rendering intents
run_test "apply-07" "TIFF 8bit perceptual (intent=0)" \
  "$APPLYPROF" "$TIFF_8BIT" "$OUTDIR/applied_i0.tiff" 0 0 0 0 0 "$SRGB" 0

run_test "apply-08" "TIFF 8bit saturation (intent=2)" \
  "$APPLYPROF" "$TIFF_8BIT" "$OUTDIR/applied_i2.tiff" 0 0 0 0 0 "$SRGB" 2

run_test "apply-09" "TIFF 8bit absolute (intent=3)" \
  "$APPLYPROF" "$TIFF_8BIT" "$OUTDIR/applied_i3.tiff" 0 0 0 0 0 "$SRGB" 3

# Planar separation
run_test "apply-10" "TIFF 8bit planar separation" \
  "$APPLYPROF" "$TIFF_8BIT" "$OUTDIR/applied_planar.tiff" 0 0 1 0 0 "$SRGB" 1

# 32-bit float input
run_test "apply-11" "TIFF 32bit→16bit sRGB" \
  "$APPLYPROF" "$TIFF_32BIT" "$OUTDIR/applied_32to16.tiff" 2 0 0 0 0 "$SRGB" 1

# Profile chain: sRGB → DisplayP3
if [ -f "$DISPLAY_P3" ]; then
  run_test "apply-12" "TIFF 8bit sRGB→DisplayP3 chain" \
    "$APPLYPROF" "$TIFF_8BIT" "$OUTDIR/applied_chain.tiff" 0 0 0 0 0 "$SRGB" 1 "$DISPLAY_P3" 1
fi

# Combined flags: LZW + embed + tetrahedral
run_test "apply-13" "TIFF 8bit LZW+embed+tetrahedral" \
  "$APPLYPROF" "$TIFF_8BIT" "$OUTDIR/applied_combo.tiff" 0 1 0 1 1 "$SRGB" 1

# Mismatch/mutated TIFF inputs
if [ -f "$TIFF_MISMATCH" ]; then
  run_test "apply-14" "TIFF mismatch profile" \
    "$APPLYPROF" "$TIFF_MISMATCH" "$OUTDIR/applied_mismatch.tiff" 0 0 0 0 0 "$SRGB" 1
fi
if [ -f "$TIFF_MUTATED" ]; then
  run_test "apply-15" "TIFF mutated profile" \
    "$APPLYPROF" "$TIFF_MUTATED" "$OUTDIR/applied_mutated.tiff" 0 0 0 0 0 "$SRGB" 1
fi

# Batch macOS catalyst TIFFs (parallel)
CATALYST_APPLY=()
for tiff_img in "$TP_TIFF"/catalyst-*.tiff; do
  if [ -f "$tiff_img" ]; then
    base=$(basename "$tiff_img" .tiff | sed 's/catalyst-//' | cut -c1-30)
    case "$base" in
      8bit-ACESCG|16bit-ITU2020|32bit-ITU709|16bit-mismatch|16bit-mutated) continue ;;
    esac
    CATALYST_APPLY+=("$tiff_img")
  fi
done
if [ "${#CATALYST_APPLY[@]}" -gt 0 ]; then
  _pids=() _tids=()
  for tiff_img in "${CATALYST_APPLY[@]}"; do
    base=$(basename "$tiff_img" .tiff | sed 's/catalyst-//' | cut -c1-30)
    tid="apply-cat-$base"
    logfile="$OUTDIR/${tid}.log"
    (
      ec=0; timeout 60 "$APPLYPROF" "$tiff_img" "$OUTDIR/applied_${base}.tiff" 0 0 0 0 0 "$SRGB" 1 > "$logfile" 2>&1 || ec=$?
      _classify_result "$tid" "Catalyst TIFF: $base" "$ec" "$logfile"
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

print_summary "iccApplyProfiles"
exit $FAIL
