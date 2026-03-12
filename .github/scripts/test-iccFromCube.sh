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

# Batch remaining .cube files from CFL corpus
BATCH_COUNT=0
for cube_file in "$REPO_ROOT"/cfl/corpus-icc_fromcube_fuzzer/*.cube; do
  if [ -f "$cube_file" ] && [ "$BATCH_COUNT" -lt 15 ]; then
    base=$(basename "$cube_file" .cube | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    # Skip already tested
    case "$base" in
      warm_film*|domain_with*|negative_domain*|test-identity*|test-warmfilm*) continue ;;
    esac
    run_test "cube-batch-$base" "Batch cube: $base" \
      "$FROMCUBE" "$cube_file" "$OUTDIR/cube_b_${base}.icc"
    BATCH_COUNT=$((BATCH_COUNT + 1))
  fi
done

print_summary "iccFromCube"
exit $FAIL
