#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccSpecSepToTiff.sh — iccSpecSepToTiff envelope tests
# Usage: ./test-iccSpecSepToTiff.sh [--asan] [--quick]
# Uses spectral TIFF sequences from macOS agent and generate-spectral-tiffs.py
source "$(dirname "$0")/iccdev-test-common.sh"

SPECSEP="$TOOLS/IccSpecSepToTiff/iccSpecSepToTiff"
echo "=== iccSpecSepToTiff ==="
# Args: output compress(0/1) sep(0/1) infile_fmt start end incr [profile]
# infile_fmt uses printf-style %d/%03d for wavelength/channel number

# Test spectral TIFFs (macOS CoreGraphics)
SPECTRAL_DIR="$REPO_ROOT/fuzz/xnuimagegenerator/tiff/spectral"
# Generated TIFFs
GEN_DIR="$REPO_ROOT/tmp/iccdev-tool-tests/spectral-tiffs"

# Use macOS spectral if available, else generated
if [ -d "$SPECTRAL_DIR" ] && ls "$SPECTRAL_DIR"/cg_wl_*.tif 1>/dev/null 2>&1; then
  WL_FMT="$SPECTRAL_DIR/cg_wl_%d.tif"
  WL_START=380
  WL_END=780
  WL_STEP=5
  HAS_WL=1
else
  HAS_WL=0
fi

if [ -d "$GEN_DIR" ] && ls "$GEN_DIR"/wl_*.tif 1>/dev/null 2>&1; then
  GWL_FMT="$GEN_DIR/wl_%d.tif"
  GWL_START=380
  GWL_END=780
  GWL_STEP=5
  HAS_GWL=1
else
  HAS_GWL=0
fi

# Merge with macOS spectral TIFFs
if [ "$HAS_WL" -eq 1 ]; then
  run_test "sep-01" "Merge wavelength 380-780 no compress" \
    "$SPECSEP" "$OUTDIR/merged_wl.tiff" 0 0 "$WL_FMT" "$WL_START" "$WL_END" "$WL_STEP"
  run_test "sep-02" "Merge wavelength 380-780 compressed" \
    "$SPECSEP" "$OUTDIR/merged_wl_c.tiff" 1 0 "$WL_FMT" "$WL_START" "$WL_END" "$WL_STEP"
  run_test "sep-03" "Merge wavelength 380-780 planar" \
    "$SPECSEP" "$OUTDIR/merged_wl_p.tiff" 0 1 "$WL_FMT" "$WL_START" "$WL_END" "$WL_STEP"
fi

# Merge with generated TIFFs
if [ "$HAS_GWL" -eq 1 ]; then
  run_test "sep-04" "Gen merge wavelength 380-780" \
    "$SPECSEP" "$OUTDIR/merged_gwl.tiff" 0 0 "$GWL_FMT" "$GWL_START" "$GWL_END" "$GWL_STEP"
fi

# 8-channel sets (cg_8b or generated ch8)
if [ -d "$SPECTRAL_DIR" ] && ls "$SPECTRAL_DIR"/cg_8b_*.tif 1>/dev/null 2>&1; then
  run_test "sep-05" "Merge 8-channel (cg_8b) 400-700" \
    "$SPECSEP" "$OUTDIR/merged_8ch.tiff" 0 0 "$SPECTRAL_DIR/cg_8b_%d.tif" 400 700 10
fi

if [ -d "$GEN_DIR" ] && ls "$GEN_DIR"/ch8_*.tif 1>/dev/null 2>&1; then
  run_test "sep-06" "Merge 8-channel (generated) 1-8" \
    "$SPECSEP" "$OUTDIR/merged_gen8ch.tiff" 0 0 "$GEN_DIR/ch8_%d.tif" 1 8 1
fi

# Small subset for quick tests
if [ "$QUICK_MODE" -eq 1 ]; then
  # Only first few wavelengths
  if [ "$HAS_WL" -eq 1 ]; then
    run_test "sep-07" "Quick merge wavelength 380-400" \
      "$SPECSEP" "$OUTDIR/merged_quick.tiff" 0 0 "$WL_FMT" 380 400 5
  fi
fi

# With ICC profile embed
if [ "$HAS_WL" -eq 1 ] && [ -f "$SRGB" ]; then
  run_test "sep-08" "Merge 380-780 with ICC embed" \
    "$SPECSEP" "$OUTDIR/merged_icc.tiff" 0 0 "$WL_FMT" "$WL_START" "$WL_END" "$WL_STEP" "$SRGB"
fi

print_summary "iccSpecSepToTiff"
exit "$FAIL"
