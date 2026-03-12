#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccTiffDump.sh — iccTiffDump envelope tests
# Usage: ./test-iccTiffDump.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

TIFFDUMP="$TOOLS/IccTiffDump/iccTiffDump"
echo "=== iccTiffDump ==="

# Seed TIFFs from TP_TIFF and TP_TIFF/general (works in both research and iccDEV)
SEED_TIFFS=()
for tiff_img in "$TP_TIFF"/*.tiff "$TP_TIFF"/*.tif "$TP_TIFF"/general/*.tiff "$TP_TIFF"/general/*.tif; do
  [ -f "$tiff_img" ] && SEED_TIFFS+=("$tiff_img")
done
if [ "${#SEED_TIFFS[@]}" -gt 0 ]; then
  run_batch_parallel "td-seed" "Seed TIFF" "$TIFFDUMP" -- "${SEED_TIFFS[@]}"
fi

# Seed spectral TIFFs (iccDEV Testing/Fuzzing/seeds/tiff/spectral/)
if [ -d "$TP_SPECTRAL" ]; then
  SPEC_TIFFS=()
  max=20
  [ "$QUICK_MODE" -eq 1 ] && max=5
  count=0
  for tiff_img in "$TP_SPECTRAL"/*.tif; do
    if [ -f "$tiff_img" ] && [ "$count" -lt "$max" ]; then
      SPEC_TIFFS+=("$tiff_img")
      count=$((count + 1))
    fi
  done
  if [ "${#SPEC_TIFFS[@]}" -gt 0 ]; then
    run_batch_parallel "td-spectral" "Spectral TIFF" "$TIFFDUMP" -- "${SPEC_TIFFS[@]}"
  fi
fi

# Catalyst TIFFs (parallel)
CATALYST_TIFFS=()
for tiff_img in "$TP_TIFF"/catalyst-*.tiff; do
  [ -f "$tiff_img" ] && CATALYST_TIFFS+=("$tiff_img")
done
if [ "${#CATALYST_TIFFS[@]}" -gt 0 ]; then
  run_batch_parallel "td-cat" "Catalyst TIFF" "$TIFFDUMP" -- "${CATALYST_TIFFS[@]}"
fi

# macOS spectral TIFFs (parallel per set)
SPECTRAL_DIR="$REPO_ROOT/fuzz/xnuimagegenerator/tiff/spectral"
if [ -d "$SPECTRAL_DIR" ]; then
  SPECTRAL_FILES=()
  for prefix in cg_wl cg_8b cg_lg cg_icc cg_digit; do
    count=0
    max=99
    [ "$QUICK_MODE" -eq 1 ] && max=3
    for tiff_img in "$SPECTRAL_DIR"/${prefix}_*.tif; do
      if [ -f "$tiff_img" ] && [ "$count" -lt "$max" ]; then
        SPECTRAL_FILES+=("$tiff_img")
        count=$((count + 1))
      fi
    done
  done
  if [ "${#SPECTRAL_FILES[@]}" -gt 0 ]; then
    run_batch_parallel "td-spec" "Spectral" "$TIFFDUMP" -- "${SPECTRAL_FILES[@]}"
  fi
fi

# Batch fuzz TIFFs (parallel)
FUZZ_TIFF_DIR="$REPO_ROOT/fuzz/graphics/tif"
if [ -d "$FUZZ_TIFF_DIR" ]; then
  MAX_BATCH=10
  [ "$QUICK_MODE" -eq 1 ] && MAX_BATCH=3
  FUZZ_TIFFS=()
  while IFS= read -r f; do FUZZ_TIFFS+=("$f"); done < <(find "$FUZZ_TIFF_DIR" -maxdepth 1 \( -name '*.tif' -o -name '*.tiff' \) 2>/dev/null | shuf -n "$MAX_BATCH")
  if [ "${#FUZZ_TIFFS[@]}" -gt 0 ]; then
    run_batch_parallel "td-fuzz" "Fuzz TIFF" "$TIFFDUMP" -- "${FUZZ_TIFFS[@]}"
  fi
fi

print_summary "iccTiffDump"
exit "$FAIL"
