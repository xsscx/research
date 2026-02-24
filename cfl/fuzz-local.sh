#!/bin/bash
#
# fuzz-local.sh — Run ICC fuzzers on a pre-mounted ramdisk
#
# Runs one or more LibFuzzer harnesses entirely from ramdisk with zero
# disk I/O.  Assumes ramdisk is already mounted and seeded (ramdisk-fuzz.sh
# or .github/scripts/ramdisk-seed.sh).
#
# Usage:
#   ./fuzz-local.sh                           # all 18 fuzzers, 16 workers, 4h
#   ./fuzz-local.sh icc_dump_fuzzer           # single fuzzer
#   ./fuzz-local.sh -t 3600 icc_dump_fuzzer icc_profile_fuzzer
#   ./fuzz-local.sh -w 8 -t 600              # 8 workers, 10 min
#   ./fuzz-local.sh -j 4 icc_dump_fuzzer     # 4 parallel jobs per fuzzer
#
# Options:
#   -t SECONDS   max_total_time per fuzzer (default: 14400 = 4h)
#   -w WORKERS   number of worker processes (default: 16)
#   -j JOBS      LibFuzzer -jobs per fuzzer (default: same as -w)
#   -r RAMDISK   ramdisk mount point (default: /tmp/fuzz-ramdisk)
#   -m MB        RSS limit per fuzzer in MB (default: 4096)
#   -s           sequential mode: run fuzzers one at a time (default: parallel)
#   -h           show this help

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────
RAMDISK="/tmp/fuzz-ramdisk"
FUZZ_SECONDS=14400
WORKERS=16
JOBS=""
RSS_LIMIT=4096
SEQUENTIAL=false

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
  icc_spectral_fuzzer
  icc_tiffdump_fuzzer
  icc_toxml_fuzzer
  icc_v5dspobs_fuzzer
)

# ── Parse options ────────────────────────────────────────────────────
usage() {
  sed -n '3,24p' "$0" | sed 's/^# \?//'
  exit 0
}

while getopts "t:w:j:r:m:sh" opt; do
  case $opt in
    t) FUZZ_SECONDS="$OPTARG" ;;
    w) WORKERS="$OPTARG" ;;
    j) JOBS="$OPTARG" ;;
    r) RAMDISK="$OPTARG" ;;
    m) RSS_LIMIT="$OPTARG" ;;
    s) SEQUENTIAL=true ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

JOBS="${JOBS:-$WORKERS}"

# Remaining args are fuzzer names (default: all)
if [ $# -gt 0 ]; then
  FUZZERS=("$@")
else
  FUZZERS=("${ALL_FUZZERS[@]}")
fi

# ── Preflight checks ────────────────────────────────────────────────
if ! mountpoint -q "$RAMDISK" 2>/dev/null; then
  echo "[FAIL] Ramdisk not mounted at $RAMDISK"
  echo "       Run: sudo mount -t tmpfs -o size=4G tmpfs $RAMDISK"
  echo "       Then: cd cfl && sudo ./ramdisk-fuzz.sh   (to seed)"
  exit 1
fi

BIN_DIR="$RAMDISK/bin"
DICT_DIR="$RAMDISK/dict"
LOG_DIR="$RAMDISK/logs"
mkdir -p "$LOG_DIR"

missing=0
for f in "${FUZZERS[@]}"; do
  if [ ! -x "$BIN_DIR/$f" ]; then
    echo "[FAIL] Binary not found: $BIN_DIR/$f"
    missing=$((missing + 1))
  fi
done
if [ "$missing" -gt 0 ]; then
  echo "       Copy binaries: sudo cp cfl/bin/icc_*_fuzzer $BIN_DIR/"
  exit 1
fi

# ── Environment: suppress all disk I/O ──────────────────────────────
export FUZZ_TMPDIR="$RAMDISK"
export LLVM_PROFILE_FILE="$RAMDISK/profraw/%m.profraw"
mkdir -p "$RAMDISK/profraw"

# ── Helper: resolve dictionary ──────────────────────────────────────
resolve_dict() {
  local name="$1"
  for dict in "$DICT_DIR/${name}.dict" "$DICT_DIR/icc_core.dict" "$DICT_DIR/icc.dict"; do
    if [ -f "$dict" ]; then
      echo "$dict"
      return
    fi
  done
}

# ── Helper: run one fuzzer ──────────────────────────────────────────
run_fuzzer() {
  local name="$1"
  local corpus="$RAMDISK/corpus-${name}"
  mkdir -p "$corpus"

  local dict
  dict="$(resolve_dict "$name")"
  local dict_arg=""
  [ -n "$dict" ] && dict_arg="-dict=$dict"

  local log="$LOG_DIR/${name}.log"

  echo "[*] $name  workers=$WORKERS  time=${FUZZ_SECONDS}s  dict=$(basename "${dict:-none}")"

  timeout --kill-after=10s $((FUZZ_SECONDS + 60))s \
    "$BIN_DIR/$name" \
      -max_total_time="$FUZZ_SECONDS" \
      -print_final_stats=1 \
      -detect_leaks=0 \
      -timeout=30 \
      -rss_limit_mb="$RSS_LIMIT" \
      -use_value_profile=1 \
      -max_len=65536 \
      -jobs="$JOBS" \
      -workers="$WORKERS" \
      -artifact_prefix="$RAMDISK/" \
      $dict_arg \
      "$corpus" \
      > "$log" 2>&1
  local rc=$?

  # Extract final stats
  local cov execs crashes
  cov=$(grep -oP 'cov: \K[0-9]+' "$log" 2>/dev/null | tail -1 || echo "?")
  execs=$(grep -oP 'stat::number_of_executed_units:\s*\K[0-9]+' "$log" 2>/dev/null | tail -1 || echo "?")
  crashes=$(ls "$RAMDISK"/crash-* "$RAMDISK"/leak-* "$RAMDISK"/oom-* 2>/dev/null | wc -l)

  if [ $rc -eq 0 ]; then
    printf "    [OK]   %-35s cov=%-6s execs=%-10s crashes=%s\n" "$name" "$cov" "$execs" "$crashes"
  else
    printf "    [EXIT] %-35s exit=%d cov=%-6s crashes=%s\n" "$name" "$rc" "$cov" "$crashes"
  fi
  return $rc
}

# ── Banner ───────────────────────────────────────────────────────────
echo ""
echo "ICC LibFuzzer — Local Ramdisk Session"
echo "────────────────────────────────────────────────────────────────"
echo "  Ramdisk:    $RAMDISK ($(df -h "$RAMDISK" | tail -1 | awk '{print $4}') free)"
echo "  Fuzzers:    ${#FUZZERS[@]}"
echo "  Workers:    $WORKERS"
echo "  Jobs:       $JOBS"
echo "  Time:       ${FUZZ_SECONDS}s per fuzzer"
echo "  RSS limit:  ${RSS_LIMIT} MB"
echo "  Mode:       $([ "$SEQUENTIAL" = true ] && echo "sequential" || echo "parallel")"
echo "  Logs:       $LOG_DIR/"
echo "  Artifacts:  $RAMDISK/"
echo "  FUZZ_TMPDIR=$FUZZ_TMPDIR"
echo "  LLVM_PROFILE_FILE=$LLVM_PROFILE_FILE"
echo "────────────────────────────────────────────────────────────────"
echo ""

# ── Run ──────────────────────────────────────────────────────────────
PIDS=()
NAMES=()

if [ "$SEQUENTIAL" = true ]; then
  TOTAL=0
  PASS=0
  for f in "${FUZZERS[@]}"; do
    TOTAL=$((TOTAL + 1))
    if run_fuzzer "$f"; then
      PASS=$((PASS + 1))
    fi
  done
  echo ""
  echo "[*] Done. $PASS/$TOTAL fuzzers completed cleanly."
else
  for f in "${FUZZERS[@]}"; do
    run_fuzzer "$f" &
    PIDS+=($!)
    NAMES+=("$f")
  done

  echo ""
  echo "[*] Launched ${#PIDS[@]} fuzzers in background. Waiting..."
  echo "    Logs: tail -f $LOG_DIR/<fuzzer>.log"
  echo "    Monitor: watch -n5 'ls $RAMDISK/crash-* $RAMDISK/leak-* 2>/dev/null | wc -l'"
  echo ""

  FAIL=0
  for i in "${!PIDS[@]}"; do
    if ! wait "${PIDS[$i]}" 2>/dev/null; then
      FAIL=$((FAIL + 1))
    fi
  done

  echo ""
  echo "── Summary ──────────────────────────────────────────────────"
  for f in "${FUZZERS[@]}"; do
    log="$LOG_DIR/${f}.log"
    if [ -f "$log" ]; then
      cov=$(grep -oP 'cov: \K[0-9]+' "$log" 2>/dev/null | tail -1)
      execs=$(grep -oP 'stat::number_of_executed_units:\s*\K[0-9]+' "$log" 2>/dev/null | sort -rn | head -1)
      ubsan=$(grep -c 'runtime error' "$log" 2>/dev/null || true)
      printf "  %-35s cov=%-6s execs=%-12s ubsan=%s\n" "$f" "${cov:-?}" "${execs:-?}" "${ubsan:-0}"
    fi
  done
  echo ""
  crashes=$(ls "$RAMDISK"/crash-* "$RAMDISK"/leak-* "$RAMDISK"/oom-* 2>/dev/null | wc -l)
  echo "  Artifacts: $crashes crash/leak/oom files"
  echo "  Disk free: $(df -h "$RAMDISK" | tail -1 | awk '{print $4}')"
  echo ""
  echo "[*] Done. $((${#PIDS[@]} - FAIL))/${#PIDS[@]} fuzzers completed cleanly."
fi

# ── Reminder ─────────────────────────────────────────────────────────
echo ""
echo "Next steps:"
echo "  Sync corpus to disk:  .github/scripts/ramdisk-sync-to-disk.sh"
echo "  Check artifacts:      ls $RAMDISK/crash-* $RAMDISK/leak-*"
echo "  Merge corpus:         .github/scripts/ramdisk-merge.sh"
