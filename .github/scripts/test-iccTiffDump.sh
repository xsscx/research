#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccTiffDump.sh - iccTiffDump envelope tests
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

# Generated XNU -> libtiff storage matrix (classic TIFF + BigTIFF)
XNU_MATRIX_SCRIPT="$REPO_ROOT/.github/scripts/build-xnu-libtiff-matrix.py"
XNU_SOURCE_READY=0
for xnu_dir in \
  "$REPO_ROOT/xnuimagefuzzer/fuzzed-images" \
  "$REPO_ROOT/xnuimagetools/fuzzed-images"
do
  if [ -d "$xnu_dir" ] && find "$xnu_dir" -type f \( -iname '*.tif' -o -iname '*.tiff' \) -print -quit | grep -q .; then
    XNU_SOURCE_READY=1
    break
  fi
done

if [ -f "$XNU_MATRIX_SCRIPT" ] && [ "$XNU_SOURCE_READY" -eq 1 ]; then
  XNU_MATRIX_DIR="$OUTDIR/xnu-libtiff-matrix"
  XNU_MATRIX_LOG="$OUTDIR/td-xnu-matrix-build.log"
  XNU_MATRIX_CMD=(python3 "$XNU_MATRIX_SCRIPT" --outdir "$XNU_MATRIX_DIR")
  [ "$QUICK_MODE" -eq 1 ] && XNU_MATRIX_CMD+=(--quick)

  TOTAL=$((TOTAL + 1))
  build_exit=0
  timeout 60 "${XNU_MATRIX_CMD[@]}" > "$XNU_MATRIX_LOG" 2>&1 || build_exit=$?
  if [ "$build_exit" -eq 0 ]; then
    PASS=$((PASS + 1))
    printf "  [%-7s] %-55s exit=%-3d\n" "PASS" "XNU libtiff matrix build" "$build_exit"

    XNU_MATRIX_FILES=()
    XNU_MATRIX_OPTIONAL_FILES=()
    for tiff_img in "$XNU_MATRIX_DIR"/matrix/*.tiff "$XNU_MATRIX_DIR"/matrix/*.tif; do
      [ -f "$tiff_img" ] || continue
      case "$(basename "$tiff_img")" in
        classic-cmyk-planar-le-cmyk3dluts2.tiff|classic-rgb-tiled16-le-srgb.tiff|bigtiff-rgb-deflate-tiled-le-srgb.tiff)
          XNU_MATRIX_OPTIONAL_FILES+=("$tiff_img")
          ;;
        *)
          XNU_MATRIX_FILES+=("$tiff_img")
          ;;
      esac
    done
    if [ "${#XNU_MATRIX_FILES[@]}" -gt 0 ]; then
      run_batch_parallel "td-xnu-matrix" "XNU libtiff matrix" "$TIFFDUMP" -- "${XNU_MATRIX_FILES[@]}"
    fi
    for tiff_img in "${XNU_MATRIX_OPTIONAL_FILES[@]}"; do
      TOTAL=$((TOTAL + 1))
      base=$(basename "$tiff_img" | sed 's/\.[^.]*$//' | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
      logfile="$OUTDIR/td-xnu-matrix-optional-${base}.log"
      exit_code=0
      timeout 60 "$TIFFDUMP" "$tiff_img" > "$logfile" 2>&1 || exit_code=$?

      if [ "$exit_code" -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  [%-7s] %-55s exit=%-3d [supported]\n" \
          "PASS" "XNU libtiff matrix: $(basename "$tiff_img")" "$exit_code"
      elif [ "$exit_code" -eq 255 ]; then
        PASS=$((PASS + 1))
        printf "  [%-7s] %-55s exit=%-3d [expected reject]\n" \
          "PASS" "XNU libtiff matrix: $(basename "$tiff_img")" "$exit_code"
      elif [ "$exit_code" -eq 134 ] || [ "$exit_code" -eq 136 ] || \
           [ "$exit_code" -eq 137 ] || [ "$exit_code" -eq 139 ]; then
        CRASH=$((CRASH + 1))
        printf "  [%-7s] %-55s exit=%-3d [signal %d]\n" \
          "CRASH" "XNU libtiff matrix: $(basename "$tiff_img")" "$exit_code" "$((exit_code - 128))"
      else
        FAIL=$((FAIL + 1))
        printf "  [%-7s] %-55s exit=%-3d\n" \
          "FAIL" "XNU libtiff matrix: $(basename "$tiff_img")" "$exit_code"
      fi
    done
  else
    FAIL=$((FAIL + 1))
    printf "  [%-7s] %-55s exit=%-3d [see %s]\n" \
      "FAIL" "XNU libtiff matrix build" "$build_exit" "$(basename "$XNU_MATRIX_LOG")"
  fi
elif [ -f "$XNU_MATRIX_SCRIPT" ]; then
  printf "  [%-7s] %-55s\n" "SKIP" "XNU libtiff matrix build (local source repos unavailable)"
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
