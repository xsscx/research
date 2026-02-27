#!/bin/bash
#
# ramdisk-merge.sh — Deduplicate and minimize fuzzer corpus on the ramdisk
#
# Usage:
#   .github/scripts/ramdisk-merge.sh                    # merge all 18 fuzzers (uses all CPUs)
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
MAX_JOBS=$(nproc 2>/dev/null || echo 4)

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
echo "  Jobs:     $MAX_JOBS (parallel merge workers)"
echo ""

RESULTS_DIR="$RAMDISK/.merge-results"
rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

# ── Per-fuzzer merge function (runs as background job) ──
merge_one() {
  local f="$1"
  local fuzzer_bin="$BIN_DIR/$f"
  local corpus_dir="$RAMDISK/corpus-${f}"
  local merge_dir="$RAMDISK/merged-${f}"
  local seed_dir="$CFL_DIR/${f}_seed_corpus"

  if [ ! -x "$fuzzer_bin" ]; then
    echo "skip" > "$RESULTS_DIR/$f"
    echo "  [WARN] $f — binary not found, skipping"
    return
  fi

  if [ ! -d "$corpus_dir" ]; then
    echo "skip" > "$RESULTS_DIR/$f"
    echo "  ○ $f — no corpus dir, skipping"
    return
  fi

  local before
  before=$(find "$corpus_dir" -type f 2>/dev/null | wc -l)
  if [ "$before" -eq 0 ]; then
    echo "skip" > "$RESULTS_DIR/$f"
    echo "  ○ $f — empty corpus, skipping"
    return
  fi

  echo "  → $f ($before inputs) merging..."

  rm -rf "$merge_dir"
  mkdir -p "$merge_dir"

  local SOURCES=("$corpus_dir")
  [ -d "$seed_dir" ] && SOURCES+=("$seed_dir")

  if ASAN_OPTIONS=detect_leaks=0 LLVM_PROFILE_FILE=/dev/null "$fuzzer_bin" \
       -merge=1 \
       -detect_leaks=0 \
       -rss_limit_mb=4096 \
       -timeout=30 \
       "$merge_dir" \
       "${SOURCES[@]}" \
       > "$RAMDISK/${f}-merge.log" 2>&1; then

    local after
    after=$(find "$merge_dir" -type f 2>/dev/null | wc -l)

    rm -rf "$corpus_dir"
    mv "$merge_dir" "$corpus_dir"

    local reduction=$((before - after))
    local pct=0
    [ "$before" -gt 0 ] && pct=$((reduction * 100 / before))
    echo "  ✓ $f [OK] $before → $after inputs (removed $reduction, -${pct}%)"
    echo "ok $before $after" > "$RESULTS_DIR/$f"
    rm -f "$RAMDISK/${f}-merge.log"
  else
    echo "  ✗ $f [FAIL] merge failed (see ${f}-merge.log)"
    rm -rf "$merge_dir"
    echo "fail" > "$RESULTS_DIR/$f"
  fi
}

# ── Launch merges in parallel, limited by MAX_JOBS ──
ACTIVE_PIDS=()

for f in "${FUZZERS[@]}"; do
  # Wait if at job limit
  while [ "${#ACTIVE_PIDS[@]}" -ge "$MAX_JOBS" ]; do
    # Wait for any one child to finish, then reap completed PIDs
    wait -n 2>/dev/null || true
    local_new=()
    for pid in "${ACTIVE_PIDS[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        local_new+=("$pid")
      fi
    done
    ACTIVE_PIDS=("${local_new[@]}")
  done

  merge_one "$f" &
  ACTIVE_PIDS+=($!)
done

# Wait for all remaining jobs
wait

# ── Tally results ──
MERGED=0
SKIPPED=0
FAILED=0
TOTAL_BEFORE=0
TOTAL_AFTER=0

for f in "${FUZZERS[@]}"; do
  result_file="$RESULTS_DIR/$f"
  if [ ! -f "$result_file" ]; then
    SKIPPED=$((SKIPPED + 1))
    continue
  fi
  status=$(head -1 "$result_file" | cut -d' ' -f1)
  case "$status" in
    ok)
      MERGED=$((MERGED + 1))
      before=$(head -1 "$result_file" | cut -d' ' -f2)
      after=$(head -1 "$result_file" | cut -d' ' -f3)
      TOTAL_BEFORE=$((TOTAL_BEFORE + before))
      TOTAL_AFTER=$((TOTAL_AFTER + after))
      ;;
    fail) FAILED=$((FAILED + 1)) ;;
    skip) SKIPPED=$((SKIPPED + 1)) ;;
  esac
done

rm -rf "$RESULTS_DIR"

echo ""
echo "── Summary ──────────────────────────────────────────────────────"
echo "  Merged:  $MERGED"
echo "  Skipped: $SKIPPED"
echo "  Failed:  $FAILED"
if [ "$TOTAL_BEFORE" -gt 0 ]; then
  TOTAL_RED=$((TOTAL_BEFORE - TOTAL_AFTER))
  TOTAL_PCT=$((TOTAL_RED * 100 / TOTAL_BEFORE))
  echo "  Total:   $TOTAL_BEFORE → $TOTAL_AFTER inputs (removed $TOTAL_RED, -${TOTAL_PCT}%)"
fi

if mountpoint -q "$RAMDISK" 2>/dev/null; then
  echo "  Ramdisk: $(df -h "$RAMDISK" | tail -1 | awk '{print $4 " free"}')"
fi
echo ""

[ "$FAILED" -eq 0 ] || exit 1
