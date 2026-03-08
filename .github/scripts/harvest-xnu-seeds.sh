#!/bin/bash
###############################################################
#
# harvest-xnu-seeds.sh — Harvest fuzzed images from
# xnuimagetools and xnuimagefuzzer into CFL fuzzer corpora
#
# Extracts ICC profiles from TIFF/PNG/JPEG images and
# distributes them + raw TIFF files to CFL seed corpora.
# Also copies raw images to format-specific fuzzer corpora.
#
# Usage:
#   .github/scripts/harvest-xnu-seeds.sh              # scan both repos
#   .github/scripts/harvest-xnu-seeds.sh --dry-run     # report only
#   .github/scripts/harvest-xnu-seeds.sh --ramdisk /tmp/fuzz-ramdisk
#
# Prerequisites:
#   - xnuimagetools/fuzzed-images/ must contain committed images
#   - xnuimagefuzzer/fuzzed-images/ must contain committed images
#   - cfl/corpus-* directories must exist
#   - python3 + extract-icc-seeds.py
#
###############################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CFL_DIR="$REPO_ROOT/cfl"
EXTRACT_SCRIPT="$REPO_ROOT/xnuimagetools/contrib/scripts/extract-icc-seeds.py"
OUTPUT_DIR="/tmp/harvest-xnu-seeds"
DRY_RUN=false
RAMDISK=""

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --ramdisk) RAMDISK="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--dry-run] [--ramdisk PATH]"
      echo ""
      echo "Harvests fuzzed images from xnuimagetools and xnuimagefuzzer"
      echo "into CFL fuzzer corpora for continued fuzzing."
      echo ""
      echo "Options:"
      echo "  --dry-run         Report what would be harvested without copying"
      echo "  --ramdisk PATH    Also copy seeds to ramdisk corpus directories"
      exit 0
      ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

banner() {
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "  $1"
  echo "════════════════════════════════════════════════════════"
}

# ── Validate prerequisites ───────────────────────────────────
[ -f "$EXTRACT_SCRIPT" ] || { echo "❌ extract-icc-seeds.py not found at $EXTRACT_SCRIPT"; exit 1; }
[ -d "$CFL_DIR" ] || { echo "❌ CFL directory not found at $CFL_DIR"; exit 1; }

# ── Source directories ───────────────────────────────────────
SOURCES=()
XNU_TOOLS="$REPO_ROOT/xnuimagetools/fuzzed-images"
XNU_FUZZER="$REPO_ROOT/xnuimagefuzzer/fuzzed-images"

if [ -d "$XNU_TOOLS" ]; then
  TOOLS_COUNT=$(find "$XNU_TOOLS" -type f -name "*.tif*" -o -name "*.png" -o -name "*.jpg" -o -name "*.jpeg" 2>/dev/null | wc -l | tr -d ' ')
  echo "xnuimagetools/fuzzed-images: $TOOLS_COUNT image files"
  SOURCES+=("$XNU_TOOLS")
else
  echo "⚠️  xnuimagetools/fuzzed-images/ not found"
fi

if [ -d "$XNU_FUZZER" ]; then
  FUZZER_COUNT=$(find "$XNU_FUZZER" -type f -name "*.tif*" -o -name "*.png" -o -name "*.jpg" -o -name "*.jpeg" 2>/dev/null | wc -l | tr -d ' ')
  echo "xnuimagefuzzer/fuzzed-images: $FUZZER_COUNT image files"
  SOURCES+=("$XNU_FUZZER")
else
  echo "⚠️  xnuimagefuzzer/fuzzed-images/ not found"
fi

if [ ${#SOURCES[@]} -eq 0 ]; then
  echo "❌ No source directories found"
  exit 1
fi

# ── Pre-harvest corpus counts ────────────────────────────────
banner "Pre-Harvest Corpus State"
declare -A PRE_COUNTS
CORPUS_DIRS=(
  "corpus-icc_profile_fuzzer"
  "corpus-icc_dump_fuzzer"
  "corpus-icc_deep_dump_fuzzer"
  "corpus-icc_toxml_fuzzer"
  "corpus-icc_tiffdump_fuzzer"
  "corpus-icc_specsep_fuzzer"
)
for d in "${CORPUS_DIRS[@]}"; do
  COUNT=$(find "$CFL_DIR/$d" -type f 2>/dev/null | wc -l | tr -d ' ')
  PRE_COUNTS[$d]=$COUNT
  printf "  %-40s %6s files\n" "$d" "$COUNT"
done

if [ "$DRY_RUN" = true ]; then
  banner "DRY RUN — would harvest from ${#SOURCES[@]} source(s)"
  for src in "${SOURCES[@]}"; do
    echo "  Source: $src"
    python3 "$EXTRACT_SCRIPT" --input "$src" --output "$OUTPUT_DIR" 2>&1 | grep -E "Results|Files|ICC|TIFF|Duplicates"
  done
  exit 0
fi

# ── Phase 1: Extract + Inject ICC profiles and TIFFs ─────────
banner "Phase 1: ICC Profile Extraction → CFL Corpora"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

TOTAL_ICC=0
TOTAL_TIFF=0

for src in "${SOURCES[@]}"; do
  echo ""
  echo "── Scanning: $src"
  python3 "$EXTRACT_SCRIPT" \
    --input "$src" \
    --output "$OUTPUT_DIR" \
    --inject-cfl "$CFL_DIR" \
    2>&1

  # Parse manifest for stats
  if [ -f "$OUTPUT_DIR/manifest.json" ]; then
    ICC=$(python3 -c "import json; m=json.load(open('$OUTPUT_DIR/manifest.json')); print(m['stats']['icc_extracted'])" 2>/dev/null || echo 0)
    TIFF=$(python3 -c "import json; m=json.load(open('$OUTPUT_DIR/manifest.json')); print(m['stats']['tiff_copied'])" 2>/dev/null || echo 0)
    TOTAL_ICC=$((TOTAL_ICC + ICC))
    TOTAL_TIFF=$((TOTAL_TIFF + TIFF))
  fi
done

# ── Phase 2: Copy to ramdisk if specified ────────────────────
if [ -n "$RAMDISK" ] && [ -d "$RAMDISK" ]; then
  banner "Phase 2: Distributing to Ramdisk ($RAMDISK)"

  for d in "${CORPUS_DIRS[@]}"; do
    SRC="$CFL_DIR/$d"
    DST="$RAMDISK/$d"
    if [ -d "$SRC" ] && [ -d "$DST" ]; then
      NEW=$(rsync -av --ignore-existing "$SRC/" "$DST/" 2>/dev/null | grep -c "\.icc\|\.tiff\|\.tif" || true)
      echo "  $d: +$NEW new files → ramdisk"
    fi
  done
fi

# ── Post-harvest corpus counts ───────────────────────────────
banner "Post-Harvest Corpus State"
echo ""
printf "  %-40s %8s  %8s  %8s\n" "Corpus" "Before" "After" "Δ"
printf "  %-40s %8s  %8s  %8s\n" "──────" "──────" "─────" "──"
for d in "${CORPUS_DIRS[@]}"; do
  POST=$(find "$CFL_DIR/$d" -type f 2>/dev/null | wc -l | tr -d ' ')
  PRE=${PRE_COUNTS[$d]}
  DELTA=$((POST - PRE))
  if [ "$DELTA" -gt 0 ]; then
    printf "  %-40s %8s  %8s  \e[32m+%s\e[0m\n" "$d" "$PRE" "$POST" "$DELTA"
  else
    printf "  %-40s %8s  %8s  %s\n" "$d" "$PRE" "$POST" "$DELTA"
  fi
done

echo ""
echo "── Summary ──"
echo "  ICC profiles harvested:  $TOTAL_ICC"
echo "  TIFF files harvested:    $TOTAL_TIFF"
echo "  Sources scanned:         ${#SOURCES[@]}"
echo ""
echo "✅ Harvest complete"
