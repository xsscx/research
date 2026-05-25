#!/bin/bash
#
# corpus-merge.sh - Deduplicate and minimize CFL fuzzer corpora.
#
# Usage:
#   .github/scripts/corpus-merge.sh                         # merge cfl/corpus-* in place
#   .github/scripts/corpus-merge.sh icc_dump_fuzzer         # merge one fuzzer corpus
#   .github/scripts/corpus-merge.sh --scratch /mnt/fuzzssd  # merge corpus-* under scratch
#   .github/scripts/corpus-merge.sh --jobs 4                # limit parallelism
#
# Runs LibFuzzer -merge=1 to keep coverage-increasing inputs while removing
# redundant corpus files. Stop fuzzers before merging any corpus they write to.
#
# Requires fuzzer binaries in cfl/bin/.

set -euo pipefail

die() { echo "[FAIL] ERROR: $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CFL_DIR="$REPO_ROOT/cfl"
BIN_DIR="$CFL_DIR/bin"
SCRATCH="$CFL_DIR"
MAX_JOBS=$(nproc 2>/dev/null || echo 4)
# shellcheck source=cfl/fuzzers.sh
source "$CFL_DIR/fuzzers.sh"

mapfile -t ALL_FUZZERS < <(cfl_list_fuzzers)

TARGETS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      sed -n '1,14p' "$0"
      exit 0
      ;;
    --jobs)
      MAX_JOBS="${2:?--jobs requires a number}"
      shift 2
      ;;
    --scratch|--corpus-root)
      SCRATCH="${2:?--scratch requires a path}"
      shift 2
      ;;
    --*) die "Unknown argument: $1" ;;
    *)
      TARGETS+=("$1")
      shift
      ;;
  esac
done

if ! [[ "$MAX_JOBS" =~ ^[0-9]+$ ]] || [ "$MAX_JOBS" -lt 1 ]; then
  die "--jobs must be a positive integer"
fi

if ! RESOLVED_FUZZERS=$(cfl_resolve_fuzzers "${TARGETS[@]:-all}"); then
  exit 1
fi
mapfile -t FUZZERS <<< "$RESOLVED_FUZZERS"

[ -d "$SCRATCH" ] || die "Scratch corpus root not found: $SCRATCH"
[ -d "$BIN_DIR" ] || die "Binary dir not found: $BIN_DIR - run cfl/build.sh first"

echo "=================================================================="
echo "                  Corpus Merge (deduplicate)"
echo "=================================================================="
echo ""
echo "  Scratch:  $SCRATCH"
echo "  Binaries: $BIN_DIR"
echo "  Fuzzers:  ${#FUZZERS[@]}"
echo "  Jobs:     $MAX_JOBS (parallel merge workers)"
echo ""

RESULTS_DIR="$SCRATCH/.merge-results"
rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

merge_one() {
  local f="$1"
  local fuzzer_bin="$BIN_DIR/$f"
  local corpus_dir="$SCRATCH/corpus-${f}"
  local merge_dir="$SCRATCH/merged-${f}"
  local seed_dir="$CFL_DIR/${f}_seed_corpus"

  if [ ! -x "$fuzzer_bin" ]; then
    echo "skip" > "$RESULTS_DIR/$f"
    echo "  [WARN] $f - binary not found, skipping"
    return
  fi

  if [ ! -d "$corpus_dir" ]; then
    echo "skip" > "$RESULTS_DIR/$f"
    echo "  [SKIP] $f - no corpus dir, skipping"
    return
  fi

  local before
  before=$(find "$corpus_dir" -type f 2>/dev/null | wc -l)
  if [ "$before" -eq 0 ]; then
    echo "skip" > "$RESULTS_DIR/$f"
    echo "  [SKIP] $f - empty corpus, skipping"
    return
  fi

  echo "  -> $f ($before inputs) merging..."

  rm -rf "$merge_dir"
  mkdir -p "$merge_dir"

  local sources=("$corpus_dir")
  [ -d "$seed_dir" ] && sources+=("$seed_dir")

  if ASAN_OPTIONS="$(cfl_asan_options "$f")" LLVM_PROFILE_FILE=/dev/null "$fuzzer_bin" \
       -merge=1 \
       -detect_leaks=0 \
       "-rss_limit_mb=$(cfl_option_rss_limit "$CFL_DIR" "$f")" \
       "-timeout=$(cfl_option_timeout "$CFL_DIR" "$f")" \
       "$merge_dir" \
       "${sources[@]}" \
       > "$SCRATCH/${f}-merge.log" 2>&1; then

    local after
    after=$(find "$merge_dir" -type f 2>/dev/null | wc -l)

    rm -rf "$corpus_dir"
    mv "$merge_dir" "$corpus_dir"

    local reduction=$((before - after))
    local pct=0
    if [ "$reduction" -ge 0 ]; then
      [ "$before" -gt 0 ] && pct=$((reduction * 100 / before))
      echo "  [OK] $f $before -> $after inputs (removed $reduction, -${pct}%)"
    else
      local added=$((after - before))
      [ "$before" -gt 0 ] && pct=$((added * 100 / before))
      echo "  [OK] $f $before -> $after inputs (added $added seed inputs, +${pct}%)"
    fi
    echo "ok $before $after" > "$RESULTS_DIR/$f"
    rm -f "$SCRATCH/${f}-merge.log"
  else
    echo "  [FAIL] $f merge failed (see ${f}-merge.log)"
    rm -rf "$merge_dir"
    echo "fail" > "$RESULTS_DIR/$f"
  fi
}

active_pids=()

for f in "${FUZZERS[@]}"; do
  while [ "${#active_pids[@]}" -ge "$MAX_JOBS" ]; do
    wait -n 2>/dev/null || true
    still_running=()
    for pid in "${active_pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        still_running+=("$pid")
      fi
    done
    active_pids=("${still_running[@]}")
  done

  merge_one "$f" &
  active_pids+=($!)
done

wait

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
echo "-- Summary ------------------------------------------------------"
echo "  Merged:  $MERGED"
echo "  Skipped: $SKIPPED"
echo "  Failed:  $FAILED"
if [ "$TOTAL_BEFORE" -gt 0 ]; then
  TOTAL_RED=$((TOTAL_BEFORE - TOTAL_AFTER))
  if [ "$TOTAL_RED" -ge 0 ]; then
    TOTAL_PCT=$((TOTAL_RED * 100 / TOTAL_BEFORE))
    echo "  Total:   $TOTAL_BEFORE -> $TOTAL_AFTER inputs (removed $TOTAL_RED, -${TOTAL_PCT}%)"
  else
    TOTAL_ADD=$((TOTAL_AFTER - TOTAL_BEFORE))
    TOTAL_PCT=$((TOTAL_ADD * 100 / TOTAL_BEFORE))
    echo "  Total:   $TOTAL_BEFORE -> $TOTAL_AFTER inputs (added $TOTAL_ADD seed inputs, +${TOTAL_PCT}%)"
  fi
fi
echo "  Scratch: $(df -h "$SCRATCH" | tail -1 | awk '{print $4 " free"}')"
echo ""

[ "$FAILED" -eq 0 ] || exit 1
