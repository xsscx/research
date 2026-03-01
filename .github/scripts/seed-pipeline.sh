#!/usr/bin/env bash
set -euo pipefail

# seed-pipeline.sh — Unified image+ICC seed corpus pipeline
#
# Takes raw images (from xnuimagefuzzer or any source), validates quality,
# embeds ICC profiles, crafts synthetic variants, and distributes to
# fuzzer seed corpuses.
#
# Usage:
#   .github/scripts/seed-pipeline.sh <image-dir> [--distribute] [--ramdisk]
#
# Options:
#   --distribute  Copy seeds to cfl/*_seed_corpus/ directories
#   --ramdisk     Also copy to /tmp/fuzz-ramdisk/corpus-*
#
# Prerequisites: exiftool, python3, tifffile, Pillow

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROFILE_DIR="$REPO_ROOT/test-profiles"
STAGING="$REPO_ROOT/temp/pipeline-staging"

# ── Configuration ──
MAX_SIZE=5242880  # 5MB (matches fuzzer.options max_len)
MIN_SIZE=64       # Reject truncated files
MIN_UNIQUE=5      # Minimum unique pixel values

# ICC profiles to embed (high-value selection)
ICC_PROFILES=(
  sRGB_v4_ICC_preference.icc
  Rec2020rgbColorimetric.icc
  Rec2100HlgFull.icc
  Rec2100HlgNarrow.icc
  LCDDisplay.icc
  RgbGSDF.icc
  GrayGSDF.icc
  Rec2020rgbSpectral.icc
  CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc
  crash-2390a7cf.icc
  crash-ndlut-null-apply.icc
  calcOverMem_tget.icc
  calcUnderStack_abs.icc
  crash-pushXYZConvert-heap-oob-profile1.icc
  crash-checkunderflowoverflow.icc
)

# ── Argument parsing ──
IMAGE_DIR=""
DISTRIBUTE=0
RAMDISK=0

for arg in "$@"; do
  case "$arg" in
    --distribute) DISTRIBUTE=1 ;;
    --ramdisk)    RAMDISK=1 ;;
    --help|-h)
      echo "Usage: $0 <image-dir> [--distribute] [--ramdisk]"
      exit 0
      ;;
    *)
      if [ -z "$IMAGE_DIR" ]; then
        IMAGE_DIR="$arg"
      else
        echo "Error: unexpected argument '$arg'" >&2
        exit 1
      fi
      ;;
  esac
done

if [ -z "$IMAGE_DIR" ]; then
  echo "Error: image directory required" >&2
  echo "Usage: $0 <image-dir> [--distribute] [--ramdisk]" >&2
  exit 1
fi

if [ ! -d "$IMAGE_DIR" ]; then
  echo "Error: '$IMAGE_DIR' is not a directory" >&2
  exit 1
fi

# ── Prerequisites ──
for cmd in exiftool python3; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: $cmd not found" >&2
    exit 1
  fi
done

python3 -c "import tifffile, PIL" 2>/dev/null || {
  echo "Error: python3 packages tifffile and Pillow required" >&2
  echo "  pip install tifffile Pillow" >&2
  exit 1
}

# ── Setup staging ──
rm -rf "$STAGING"
mkdir -p "$STAGING"/{valid,embedded,rejected}

echo "================================================================"
echo "  seed-pipeline.sh — Image+ICC Seed Corpus Pipeline"
echo "================================================================"
echo ""
echo "  Source:      $IMAGE_DIR"
echo "  Profiles:    ${#ICC_PROFILES[@]} ICC profiles"
echo "  Max size:    $MAX_SIZE bytes"
echo "  Distribute:  $([ $DISTRIBUTE -eq 1 ] && echo YES || echo NO)"
echo "  Ramdisk:     $([ $RAMDISK -eq 1 ] && echo YES || echo NO)"
echo ""

# ── Phase 1: Validate images ──
echo "=== Phase 1: Validate images ==="
total=0
valid=0
rejected=0

for f in "$IMAGE_DIR"/*.tiff "$IMAGE_DIR"/*.tif "$IMAGE_DIR"/*.png "$IMAGE_DIR"/*.jpg "$IMAGE_DIR"/*.jpeg "$IMAGE_DIR"/*.gif "$IMAGE_DIR"/*.bmp; do
  [ -f "$f" ] || continue
  total=$((total + 1))
  bn=$(basename "$f")
  sz=$(stat -c%s "$f")

  # Size checks
  if [ "$sz" -lt "$MIN_SIZE" ]; then
    echo "  REJECT (too small: ${sz}B): $bn"
    cp "$f" "$STAGING/rejected/"
    rejected=$((rejected + 1))
    continue
  fi
  if [ "$sz" -gt "$MAX_SIZE" ]; then
    echo "  REJECT (too large: ${sz}B): $bn"
    cp "$f" "$STAGING/rejected/"
    rejected=$((rejected + 1))
    continue
  fi

  # TIFF magic byte validation
  if [[ "$bn" =~ \.(tiff|tif)$ ]]; then
    header=$(xxd -p -l 4 "$f" 2>/dev/null)
    case "$header" in
      49492a00|4d4d002a|49492b00|4d4d002b) ;; # Valid TIFF/BigTIFF
      *)
        echo "  REJECT (bad TIFF magic: $header): $bn"
        cp "$f" "$STAGING/rejected/"
        rejected=$((rejected + 1))
        continue
        ;;
    esac
  fi

  # Pixel quality check (reject flat/near-flat images)
  quality=$(python3 -c "
from PIL import Image
import numpy as np
try:
    im = Image.open('$f')
    arr = np.array(im)
    uniq = len(np.unique(arr))
    print(f'{uniq}')
except:
    print('0')
" 2>/dev/null)

  if [ "${quality:-0}" -lt "$MIN_UNIQUE" ]; then
    echo "  REJECT (flat/near-flat: $quality unique vals): $bn"
    cp "$f" "$STAGING/rejected/"
    rejected=$((rejected + 1))
    continue
  fi

  cp "$f" "$STAGING/valid/"
  valid=$((valid + 1))
done

echo "  Total: $total, Valid: $valid, Rejected: $rejected"
echo ""

# ── Phase 2: Deduplicate by content hash ──
echo "=== Phase 2: Deduplicate ==="
before=$valid
python3 -c "
import hashlib, os, sys

valid_dir = '$STAGING/valid'
seen = {}
removed = 0
for f in sorted(os.listdir(valid_dir)):
    path = os.path.join(valid_dir, f)
    with open(path, 'rb') as fh:
        h = hashlib.md5(fh.read()).hexdigest()
    if h in seen:
        os.rename(path, os.path.join('$STAGING/rejected', f))
        removed += 1
    else:
        seen[h] = f
print(f'{removed}')
" 2>/dev/null
after=$(ls "$STAGING/valid/" 2>/dev/null | wc -l)
echo "  Deduplicated: $before → $after (removed $((before - after)) duplicates)"
echo ""

# ── Phase 3: Embed ICC profiles ──
echo "=== Phase 3: Embed ICC profiles ==="
embed_count=0

for img in "$STAGING/valid"/*; do
  [ -f "$img" ] || continue
  bn=$(basename "$img")
  base="${bn%.*}"
  ext="${bn##*.}"

  for icc_name in "${ICC_PROFILES[@]}"; do
    icc_path="$PROFILE_DIR/$icc_name"
    [ -f "$icc_path" ] || continue
    icc_tag="${icc_name%.icc}"
    icc_tag="${icc_tag:0:30}"
    out="$STAGING/embedded/${base}--${icc_tag}.${ext}"
    [ -f "$out" ] && continue

    cp "$img" "$out"
    exiftool -overwrite_original -ICC_Profile\<="$icc_path" "$out" >/dev/null 2>&1 || true
    embed_count=$((embed_count + 1))
  done
done

echo "  Created $embed_count ICC-embedded images"
echo ""

# ── Phase 4: Distribute to seed corpuses ──
if [ $DISTRIBUTE -eq 1 ]; then
  echo "=== Phase 4: Distribute to seed corpuses ==="

  # TIFFs → tiffdump fuzzer
  tiff_added=0
  for f in "$STAGING/embedded"/*.tiff "$STAGING/embedded"/*.tif; do
    [ -f "$f" ] || continue
    bn=$(basename "$f")
    target="$REPO_ROOT/cfl/icc_tiffdump_fuzzer_seed_corpus/$bn"
    if [ ! -f "$target" ]; then
      cp "$f" "$target"
      tiff_added=$((tiff_added + 1))
    fi
  done
  echo "  tiffdump: +$tiff_added TIFFs"

  # Extract ICC profiles and add to ICC fuzzer corpuses
  icc_added=0
  for f in "$STAGING/embedded"/*.tiff "$STAGING/embedded"/*.tif "$STAGING/embedded"/*.png "$STAGING/embedded"/*.jpg "$STAGING/embedded"/*.jpeg; do
    [ -f "$f" ] || continue
    bn=$(basename "$f")
    icc_out="$STAGING/${bn}.icc"
    exiftool -ICC_Profile -b "$f" > "$icc_out" 2>/dev/null || true
    if [ -s "$icc_out" ]; then
      for fuzzer in icc_profile_fuzzer icc_dump_fuzzer icc_apply_fuzzer icc_io_fuzzer; do
        target="$REPO_ROOT/cfl/${fuzzer}_seed_corpus/${bn}.icc"
        if [ ! -f "$target" ] && [ -d "$REPO_ROOT/cfl/${fuzzer}_seed_corpus" ]; then
          cp "$icc_out" "$target"
          icc_added=$((icc_added + 1))
        fi
      done
    fi
    rm -f "$icc_out"
  done
  echo "  ICC fuzzers: +$icc_added extracted profiles"

  # Ramdisk
  if [ $RAMDISK -eq 1 ] && [ -d /tmp/fuzz-ramdisk ]; then
    rd_added=0
    for f in "$STAGING/embedded"/*.tiff "$STAGING/embedded"/*.tif; do
      [ -f "$f" ] || continue
      bn=$(basename "$f")
      target="/tmp/fuzz-ramdisk/corpus-icc_tiffdump_fuzzer/$bn"
      if [ ! -f "$target" ]; then
        cp "$f" "$target"
        rd_added=$((rd_added + 1))
      fi
    done
    echo "  ramdisk: +$rd_added"
  fi
fi

echo ""
echo "================================================================"
echo "  Pipeline complete"
echo "  Staging: $STAGING"
echo "  Valid:    $(ls "$STAGING/valid/" 2>/dev/null | wc -l) source images"
echo "  Embedded: $(ls "$STAGING/embedded/" 2>/dev/null | wc -l) ICC-embedded seeds"
echo "  Rejected: $(ls "$STAGING/rejected/" 2>/dev/null | wc -l) rejected files"
echo "================================================================"
