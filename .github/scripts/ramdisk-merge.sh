#!/bin/bash
#
# ramdisk-merge.sh — Deduplicate and minimize fuzzer corpus on the ramdisk
#
# Usage:
#   .github/scripts/ramdisk-merge.sh                    # merge all 18 fuzzers
#   .github/scripts/ramdisk-merge.sh icc_profile_fuzzer  # merge one fuzzer
#   .github/scripts/ramdisk-merge.sh --jobs 4            # limit parallelism
#
# Runs LibFuzzer's -merge=1 on each fuzzer corpus to remove redundant inputs
# while preserving coverage. The merged corpus replaces the original.
#
# Requires: fuzzer binaries in cfl/bin/

set -euo pipefail

die() { echo "[FAIL] ERROR: $*" >&2; exit 1; }

RAMDISK="/tmp/fuzz-ramdisk"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CFL_DIR="$REPO_ROOT/cfl"
BIN_DIR="$CFL_DIR/bin"
MAX_JOBS=1

ALL_FUZZERS=(
  icc_apply_fuzzer
  icc_applynamedcmm_fuzzer
  icc_applyprofiles_fuzzer
  icc_calculator_fuzzer
  icc_deep_dump_fuzzer
  icc_dump_fuzzer
  icc_fromcube_fuzzer
  icc_fromxml_fuzzer
  icc_io_fuzzer
  icc_link_fuzzer
  icc_multitag_fuzzer
  icc_profile_fuzzer
  icc_roundtrip_fuzzer
  icc_specsep_fuzzer
  # icc_spectral_fuzzer  # Variant A — disabled for A/B test
  icc_spectral_b_fuzzer
  icc_tiffdump_fuzzer
  icc_toxml_fuzzer
  icc_v5dspobs_fuzzer
)

# ── Parse args ───────────────────────────────────────────────────────
SELECTED_FUZZERS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --jobs) MAX_JOBS="${2:?--jobs requires a number}"; shift 2 ;;
    --ramdisk) RAMDISK="${2:?--ramdisk requires a path}"; shift 2 ;;
    icc_*) SELECTED_FUZZERS+=("$1"); shift ;;
    *) die "Unknown argument: $1" ;;
  esac
done

FUZZERS=("${SELECTED_FUZZERS[@]:-${ALL_FUZZERS[@]}}")

[ -d "$RAMDISK" ] || die "Ramdisk not found: $RAMDISK"
[ -d "$BIN_DIR" ] || die "Binary dir not found: $BIN_DIR — run cfl/build.sh first"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                  Corpus Merge (deduplicate)                    ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Ramdisk:  $RAMDISK"
echo "  Binaries: $BIN_DIR"
echo "  Fuzzers:  ${#FUZZERS[@]}"
echo "  Jobs:     $MAX_JOBS (sequential per fuzzer — merge is single-threaded)"
echo ""

MERGED=0
SKIPPED=0
FAILED=0

for f in "${FUZZERS[@]}"; do
  fuzzer_bin="$BIN_DIR/$f"
  corpus_dir="$RAMDISK/corpus-${f}"
  merge_dir="$RAMDISK/merged-${f}"
  seed_dir="$CFL_DIR/${f}_seed_corpus"

  if [ ! -x "$fuzzer_bin" ]; then
    echo "  [WARN] $f — binary not found, skipping"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  if [ ! -d "$corpus_dir" ]; then
    echo "  ○ $f — no corpus dir, skipping"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  before=$(find "$corpus_dir" -type f 2>/dev/null | wc -l)
  if [ "$before" -eq 0 ]; then
    echo "  ○ $f — empty corpus, skipping"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  echo -n "  → $f ($before inputs) ... "

  # Create temp merge dir
  rm -rf "$merge_dir"
  mkdir -p "$merge_dir"

  # Build source list: current corpus + seed corpus (if exists)
  SOURCES=("$corpus_dir")
  [ -d "$seed_dir" ] && SOURCES+=("$seed_dir")

  # Run merge (suppress output — only care about exit code)
  if LLVM_PROFILE_FILE=/dev/null "$fuzzer_bin" \
       -merge=1 \
       -detect_leaks=0 \
       -rss_limit_mb=4096 \
       -timeout=30 \
       "$merge_dir" \
       "${SOURCES[@]}" \
       > "$RAMDISK/${f}-merge.log" 2>&1; then

    after=$(find "$merge_dir" -type f 2>/dev/null | wc -l)

    # Swap: replace corpus with merged result
    rm -rf "$corpus_dir"
    mv "$merge_dir" "$corpus_dir"

    reduction=$((before - after))
    pct=0
    [ "$before" -gt 0 ] && pct=$((reduction * 100 / before))
    echo "[OK] $after inputs (removed $reduction, -${pct}%)"
    MERGED=$((MERGED + 1))
  else
    echo "[FAIL] merge failed (see ${f}-merge.log)"
    rm -rf "$merge_dir"
    FAILED=$((FAILED + 1))
  fi

  # Clean up merge log on success
  [ -f "$RAMDISK/${f}-merge.log" ] && [ "$FAILED" -eq 0 ] && rm -f "$RAMDISK/${f}-merge.log"
done

echo ""
echo "── Summary ──────────────────────────────────────────────────────"
echo "  Merged:  $MERGED"
echo "  Skipped: $SKIPPED"
echo "  Failed:  $FAILED"

if mountpoint -q "$RAMDISK" 2>/dev/null; then
  echo "  Ramdisk: $(df -h "$RAMDISK" | tail -1 | awk '{print $4 " free"}')"
fi
echo ""

[ "$FAILED" -eq 0 ] || exit 1
