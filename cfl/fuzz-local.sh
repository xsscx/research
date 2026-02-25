#!/bin/bash
#
# fuzz-local.sh — Run ICC fuzzers sequentially on a pre-mounted ramdisk
#
# Runs one or more LibFuzzer harnesses entirely from ramdisk with zero
# disk I/O.  Fuzzers run ONE AT A TIME to prevent OOM on WSL/constrained
# systems.  LibFuzzer -workers/-jobs handle per-fuzzer parallelism.
#
# Assumes ramdisk is already mounted and seeded (ramdisk-fuzz.sh or
# .github/scripts/ramdisk-seed.sh).
#
# Usage:
#   ./fuzz-local.sh                           # all 18 fuzzers, 4 workers, 4h each
#   ./fuzz-local.sh icc_dump_fuzzer           # single fuzzer
#   ./fuzz-local.sh -t 3600 icc_dump_fuzzer icc_profile_fuzzer
#   ./fuzz-local.sh -w 8 -t 600              # 8 workers per fuzzer, 10 min each
#
# Options:
#   -t SECONDS   max_total_time per fuzzer (default: 14400 = 4h)
#   -w WORKERS   LibFuzzer worker processes per fuzzer (default: 4)
#   -r RAMDISK   ramdisk mount point (default: /tmp/fuzz-ramdisk)
#   -m MB        RSS limit per worker in MB (default: 2048)
#   -h           show this help

# Do not use set -e: fuzzer non-zero exits are expected (crash findings)
set -uo pipefail

# ── Defaults ─────────────────────────────────────────────────────────
RAMDISK="/tmp/fuzz-ramdisk"
FUZZ_SECONDS=14400
WORKERS=4
RSS_LIMIT=2048

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

# ── Parse options ────────────────────────────────────────────────────
usage() {
  sed -n '3,23p' "$0" | sed 's/^# \?//'
  exit 0
}

while getopts "t:w:r:m:h" opt; do
  case $opt in
    t) FUZZ_SECONDS="$OPTARG" ;;
    w) WORKERS="$OPTARG" ;;
    r) RAMDISK="$OPTARG" ;;
    m) RSS_LIMIT="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

# Remaining args are fuzzer names (default: all)
if [ $# -gt 0 ]; then
  FUZZERS=("$@")
else
  FUZZERS=("${ALL_FUZZERS[@]}")
fi

# ── Safety check: total memory demand ────────────────────────────────
TOTAL_MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
TOTAL_MEM_MB=$((TOTAL_MEM_KB / 1024))
DEMAND_MB=$((WORKERS * RSS_LIMIT))
if [ "$DEMAND_MB" -gt "$((TOTAL_MEM_MB * 80 / 100))" ]; then
  echo "[FAIL] workers($WORKERS) x rss_limit(${RSS_LIMIT}MB) = ${DEMAND_MB}MB"
  echo "       exceeds 80% of system memory (${TOTAL_MEM_MB}MB)"
  echo "       Reduce -w or -m.  Example: -w $((TOTAL_MEM_MB * 70 / 100 / RSS_LIMIT)) -m $RSS_LIMIT"
  exit 1
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

# ── Per-fuzzer dict mapping (shared base dicts) ────────────────────
declare -A FUZZER_DICTS=(
  [icc_toxml_fuzzer]="icc_xml_consolidated.dict"
  [icc_io_fuzzer]="icc_core.dict"
  [icc_roundtrip_fuzzer]="icc_core.dict"
  [icc_spectral_fuzzer]="icc_core.dict"
  [icc_multitag_fuzzer]="icc_multitag.dict"
  [icc_profile_fuzzer]="icc_profile.dict"
)

# ── Helper: resolve dictionary ──────────────────────────────────────
resolve_dict() {
  local name="$1"
  local mapped="${FUZZER_DICTS[$name]:-}"
  for dict in "$DICT_DIR/${name}.dict" ${mapped:+"$DICT_DIR/$mapped"} "$DICT_DIR/icc_core.dict" "$DICT_DIR/icc.dict"; do
    if [ -f "$dict" ]; then
      echo "$dict"
      return
    fi
  done
}

# ── Banner ───────────────────────────────────────────────────────────
echo ""
echo "ICC LibFuzzer — Local Ramdisk Session"
echo "────────────────────────────────────────────────────────────────"
echo "  Ramdisk:    $RAMDISK ($(df -h "$RAMDISK" | tail -1 | awk '{print $4}') free)"
echo "  Fuzzers:    ${#FUZZERS[@]} (sequential, one at a time)"
echo "  Workers:    $WORKERS per fuzzer"
echo "  Time:       ${FUZZ_SECONDS}s per fuzzer"
echo "  RSS limit:  ${RSS_LIMIT} MB per worker"
echo "  Peak mem:   $((WORKERS * RSS_LIMIT)) MB (${WORKERS}w x ${RSS_LIMIT}MB)"
echo "  System mem: ${TOTAL_MEM_MB} MB"
echo "  Logs:       $LOG_DIR/"
echo "  Artifacts:  $RAMDISK/"
echo "  FUZZ_TMPDIR=$FUZZ_TMPDIR"
echo "────────────────────────────────────────────────────────────────"
echo ""

# ── Run fuzzers sequentially ─────────────────────────────────────────
TOTAL=0
PASS=0

for f in "${FUZZERS[@]}"; do
  TOTAL=$((TOTAL + 1))

  corpus="$RAMDISK/corpus-${f}"
  mkdir -p "$corpus"

  dict="$(resolve_dict "$f")"
  dict_arg=""
  [ -n "$dict" ] && dict_arg="-dict=$dict"

  log="$LOG_DIR/${f}.log"

  echo "[${TOTAL}/${#FUZZERS[@]}] $f  workers=$WORKERS  time=${FUZZ_SECONDS}s  dict=$(basename "${dict:-none}")"

  # Per-fuzzer timeout from .options file, default 30s
  FUZZER_TIMEOUT=30
  for optf in "$(cd "$(dirname "$0")" && pwd)/${f}.options"; do
    if [ -f "$optf" ]; then
      val=$(grep -m1 '^timeout' "$optf" | sed 's/[^0-9]//g')
      [ -n "$val" ] && FUZZER_TIMEOUT="$val"
      break
    fi
  done

  # Run fuzzer; capture exit code without aborting script
  rc=0
  timeout --kill-after=10s $((FUZZ_SECONDS + FUZZER_TIMEOUT))s \
    "$BIN_DIR/$f" \
      -max_total_time="$FUZZ_SECONDS" \
      -print_final_stats=1 \
      -detect_leaks=0 \
      -timeout="$FUZZER_TIMEOUT" \
      -rss_limit_mb="$RSS_LIMIT" \
      -use_value_profile=1 \
      -max_len=65536 \
      -jobs="$WORKERS" \
      -workers="$WORKERS" \
      -artifact_prefix="$RAMDISK/" \
      $dict_arg \
      "$corpus" \
      > "$log" 2>&1 || rc=$?

  # Extract final stats
  cov=$(grep -oP 'cov: \K[0-9]+' "$log" 2>/dev/null | tail -1)
  execs=$(grep -oP 'stat::number_of_executed_units:\s*\K[0-9]+' "$log" 2>/dev/null | sort -rn | head -1)
  ubsan=$(grep -c 'runtime error' "$log" 2>/dev/null || true)

  if [ "$rc" -eq 0 ]; then
    printf "    [OK]   cov=%-6s execs=%-12s ubsan=%s\n" "${cov:-?}" "${execs:-?}" "${ubsan:-0}"
    PASS=$((PASS + 1))
  else
    printf "    [EXIT] exit=%-4d cov=%-6s execs=%-12s ubsan=%s\n" "$rc" "${cov:-?}" "${execs:-?}" "${ubsan:-0}"
  fi
  echo ""
done

# ── Summary ──────────────────────────────────────────────────────────
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
artifacts=$(ls "$RAMDISK"/crash-* "$RAMDISK"/leak-* "$RAMDISK"/oom-* 2>/dev/null | wc -l)
echo "  Artifacts: $artifacts crash/leak/oom files"
echo "  Disk free: $(df -h "$RAMDISK" | tail -1 | awk '{print $4}')"
echo ""
echo "[*] Done. $PASS/$TOTAL fuzzers completed cleanly."
echo ""
echo "Next steps:"
echo "  Sync corpus to disk:  .github/scripts/ramdisk-sync-to-disk.sh"
echo "  Check artifacts:      ls $RAMDISK/crash-* $RAMDISK/leak-*"
echo "  Merge corpus:         .github/scripts/ramdisk-merge.sh"
