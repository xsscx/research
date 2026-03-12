#!/bin/bash
# test-iccTiffDump.sh — iccTiffDump envelope tests
# Usage: ./test-iccTiffDump.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

TIFFDUMP="$TOOLS/IccTiffDump/iccTiffDump"
echo "=== iccTiffDump ==="

# Catalyst TIFFs
for tiff_img in "$TP_TIFF"/catalyst-*.tiff; do
  if [ -f "$tiff_img" ]; then
    base=$(basename "$tiff_img" .tiff | sed 's/catalyst-//' | cut -c1-30)
    run_test "td-cat-$base" "Catalyst TIFF: $base" "$TIFFDUMP" "$tiff_img"
  fi
done

# macOS spectral TIFFs (5 sets: cg_wl, cg_8b, cg_lg, cg_icc, cg_digit)
SPECTRAL_DIR="$REPO_ROOT/fuzz/xnuimagegenerator/tiff/spectral"
if [ -d "$SPECTRAL_DIR" ]; then
  # Sample from each set (up to 3 per set in quick mode, all in normal)
  for prefix in cg_wl cg_8b cg_lg cg_icc cg_digit; do
    count=0
    max=99
    [ "$QUICK_MODE" -eq 1 ] && max=3
    for tiff_img in "$SPECTRAL_DIR"/${prefix}_*.tif; do
      if [ -f "$tiff_img" ] && [ "$count" -lt "$max" ]; then
        base=$(basename "$tiff_img" .tif | cut -c1-30)
        run_test "td-spec-$base" "Spectral: $base" "$TIFFDUMP" "$tiff_img"
        count=$((count + 1))
      fi
    done
  done
fi

# Batch fuzz TIFFs (random sample)
FUZZ_TIFF_DIR="$REPO_ROOT/fuzz/graphics/tif"
if [ -d "$FUZZ_TIFF_DIR" ]; then
  BATCH_COUNT=0
  MAX_BATCH=10
  [ "$QUICK_MODE" -eq 1 ] && MAX_BATCH=3
  for tiff_img in $(find "$FUZZ_TIFF_DIR" -maxdepth 1 -name '*.tif' -o -name '*.tiff' 2>/dev/null | shuf -n "$MAX_BATCH"); do
    base=$(basename "$tiff_img" | sed 's/\.[^.]*$//' | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    run_test "td-fuzz-$base" "Fuzz TIFF: $base" "$TIFFDUMP" "$tiff_img"
    BATCH_COUNT=$((BATCH_COUNT + 1))
  done
fi

print_summary "iccTiffDump"
exit $FAIL
