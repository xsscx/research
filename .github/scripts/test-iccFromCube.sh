#!/bin/bash
# test-iccFromCube.sh — iccFromCube envelope tests
# Usage: ./test-iccFromCube.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

FROMCUBE="$TOOLS/IccFromCube/iccFromCube"
echo "=== iccFromCube ==="

# Core .cube files
run_test "cube-01" "Identity LUT 2x2x2" \
  "$FROMCUBE" "$TD/test-identity.cube" "$OUTDIR/identity.icc"

run_test "cube-02" "Warm film LUT 5x5x5" \
  "$FROMCUBE" "$TD/test-warmfilm-5x5x5.cube" "$OUTDIR/warmfilm.icc"

# CFL corpus .cube files
for cube_file in "$REPO_ROOT"/cfl/corpus-icc_fromcube_fuzzer/warm_film_2x2x2.cube \
                 "$REPO_ROOT"/cfl/corpus-icc_fromcube_fuzzer/domain_with_input_range_2x2x2.cube \
                 "$REPO_ROOT"/cfl/corpus-icc_fromcube_fuzzer/negative_domain_3x3x3.cube; do
  if [ -f "$cube_file" ]; then
    base=$(basename "$cube_file" .cube)
    run_test "cube-${base}" "Corpus cube: $base" \
      "$FROMCUBE" "$cube_file" "$OUTDIR/cube_${base}.icc"
  fi
done

# Batch remaining .cube files from CFL corpus (parallel)
BATCH_CUBES=()
for cube_file in "$REPO_ROOT"/cfl/corpus-icc_fromcube_fuzzer/*.cube; do
  if [ -f "$cube_file" ]; then
    base=$(basename "$cube_file" .cube)
    case "$base" in
      warm_film*|domain_with*|negative_domain*|test-identity*|test-warmfilm*) continue ;;
    esac
    BATCH_CUBES+=("$cube_file")
  fi
done
if [ "${#BATCH_CUBES[@]}" -gt 0 ]; then
  _pids=() _tids=()
  for cube_file in "${BATCH_CUBES[@]}"; do
    base=$(basename "$cube_file" .cube | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    tid="cube-batch-$base"
    logfile="$OUTDIR/${tid}.log"
    (
      ec=0; timeout 60 "$FROMCUBE" "$cube_file" "$OUTDIR/cube_b_${base}.icc" > "$logfile" 2>&1 || ec=$?
      _classify_result "$tid" "Batch cube: $base" "$ec" "$logfile"
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

print_summary "iccFromCube"
exit $FAIL
