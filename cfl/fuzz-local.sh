#!/bin/bash
#
# fuzz-local.sh - Run ICC fuzzers sequentially on local or prepared storage
#
# Runs one or more LibFuzzer harnesses one at a time to prevent OOM on
# WSL/constrained systems. LibFuzzer -workers/-jobs handle per-fuzzer
# parallelism within each harness.
#
# Usage:
#   ./fuzz-local.sh                           # all fuzzers, 4 workers, 4h each
#   ./fuzz-local.sh icc_dump_fuzzer           # single fuzzer
#   ./fuzz-local.sh -t 3600 icc_dump_fuzzer icc_toxml_fuzzer
#   ./fuzz-local.sh -w 8 -t 600               # 8 workers per fuzzer, 10 min each
#
# Options:
#   -t SECONDS   max_total_time per fuzzer (default: 14400 = 4h)
#   -w WORKERS   LibFuzzer worker processes per fuzzer (default: 4)
#   -r DIR       storage root with bin/, dict/, corpus-* (default: cfl/)
#   -m MB        override RSS limit per worker in MB (default: fuzzer options)
#   -h           show this help

# Do not use set -e: fuzzer non-zero exits are expected when crashes are found.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=cfl/fuzzers.sh
source "$SCRIPT_DIR/fuzzers.sh"

STORAGE_DIR="$SCRIPT_DIR"
FUZZ_SECONDS=14400
WORKERS=4
RSS_LIMIT=""

usage() {
  sed -n '3,22p' "$0" | sed 's/^# \?//'
  exit 0
}

while getopts "t:w:r:m:h" opt; do
  case $opt in
    t) FUZZ_SECONDS="$OPTARG" ;;
    w) WORKERS="$OPTARG" ;;
    r) STORAGE_DIR="$OPTARG" ;;
    m) RSS_LIMIT="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

FUZZER_LIST="$(cfl_resolve_fuzzers "$@")" || exit 1
mapfile -t FUZZERS <<< "$FUZZER_LIST"

if [ ! -d "$STORAGE_DIR" ]; then
  echo "[FAIL] Fuzz storage directory not found: $STORAGE_DIR"
  exit 1
fi
STORAGE_DIR="$(cd "$STORAGE_DIR" && pwd)"

BIN_DIR="$STORAGE_DIR/bin"
if [ ! -d "$BIN_DIR" ]; then
  BIN_DIR="$SCRIPT_DIR/bin"
fi

DICT_DIR="$STORAGE_DIR/dict"
if [ ! -d "$DICT_DIR" ]; then
  DICT_DIR="$SCRIPT_DIR"
fi

if [ "$STORAGE_DIR" = "$SCRIPT_DIR" ]; then
  RUN_ROOT="$SCRIPT_DIR/runs/fuzz-local"
else
  RUN_ROOT="$STORAGE_DIR"
fi
LOG_DIR="$RUN_ROOT/logs"
PROFRAW_DIR="$RUN_ROOT/profraw"
ARTIFACT_DIR="$RUN_ROOT/artifacts"
mkdir -p "$LOG_DIR" "$PROFRAW_DIR" "$ARTIFACT_DIR"

missing=0
for f in "${FUZZERS[@]}"; do
  if [ ! -x "$BIN_DIR/$f" ]; then
    echo "[FAIL] Binary not found: $BIN_DIR/$f"
    missing=$((missing + 1))
  fi
done
if [ "$missing" -gt 0 ]; then
  echo "       Run: ./cfl/build.sh"
  exit 1
fi

TOTAL_MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
TOTAL_MEM_MB=$((TOTAL_MEM_KB / 1024))
MAX_RSS_LIMIT=0
for f in "${FUZZERS[@]}"; do
  fuzzer_rss="${RSS_LIMIT:-$(cfl_option_rss_limit "$SCRIPT_DIR" "$f")}"
  [ "$fuzzer_rss" -gt "$MAX_RSS_LIMIT" ] && MAX_RSS_LIMIT="$fuzzer_rss"
done
DEMAND_MB=$((WORKERS * MAX_RSS_LIMIT))
if [ "$DEMAND_MB" -gt "$((TOTAL_MEM_MB * 80 / 100))" ]; then
  echo "[FAIL] workers($WORKERS) x max rss_limit(${MAX_RSS_LIMIT}MB) = ${DEMAND_MB}MB"
  echo "       exceeds 80% of system memory (${TOTAL_MEM_MB}MB)"
  echo "       Reduce -w or override -m. Example: -w $((TOTAL_MEM_MB * 70 / 100 / MAX_RSS_LIMIT))"
  exit 1
fi

export FUZZ_TMPDIR="$RUN_ROOT"

echo ""
echo "ICC LibFuzzer - Local Session"
echo "----------------------------------------------------------------"
echo "  Storage:    $STORAGE_DIR ($(df -h "$STORAGE_DIR" | tail -1 | awk '{print $4}') free)"
echo "  Binaries:   $BIN_DIR"
echo "  Dicts:      $DICT_DIR"
echo "  Fuzzers:    ${#FUZZERS[@]} (sequential, one at a time)"
echo "  Workers:    $WORKERS per fuzzer"
echo "  Time:       ${FUZZ_SECONDS}s per fuzzer"
echo "  RSS limit:  per-fuzzer options${RSS_LIMIT:+ (override ${RSS_LIMIT}MB)}"
echo "  Peak mem:   ${DEMAND_MB} MB (${WORKERS}w x ${MAX_RSS_LIMIT}MB)"
echo "  System mem: ${TOTAL_MEM_MB} MB"
echo "  Logs:       $LOG_DIR/"
echo "  Artifacts:  $ARTIFACT_DIR/"
echo "  FUZZ_TMPDIR=$FUZZ_TMPDIR"
echo "----------------------------------------------------------------"
echo ""

TOTAL=0
PASS=0

for f in "${FUZZERS[@]}"; do
  TOTAL=$((TOTAL + 1))

  corpus=""
  if [ "$STORAGE_DIR" = "$SCRIPT_DIR" ]; then
    corpus="$(cfl_corpus_dir "$SCRIPT_DIR" "$f")"
  else
    corpus="$STORAGE_DIR/corpus-${f}"
  fi
  mkdir -p "$corpus"
  cfl_install_curated_seeds "$SCRIPT_DIR" "$f" "$corpus"

  dict=""
  if dict_candidate="$(cfl_resolve_dict "$DICT_DIR" "$f")"; then
    dict="$dict_candidate"
  elif dict_candidate="$(cfl_resolve_dict "$SCRIPT_DIR" "$f")"; then
    dict="$dict_candidate"
  fi
  dict_args=()
  [ -n "$dict" ] && dict_args=("-dict=$dict")

  log="$LOG_DIR/${f}.log"

  FUZZER_TIMEOUT="$(cfl_option_timeout "$SCRIPT_DIR" "$f")"
  FUZZER_RSS="${RSS_LIMIT:-$(cfl_option_rss_limit "$SCRIPT_DIR" "$f")}"
  FUZZER_MAX_LEN="$(cfl_effective_max_len \
    "$(cfl_option_max_len "$SCRIPT_DIR" "$f")" "$corpus")"
  FUZZER_ASAN="$(cfl_asan_options "$f")"

  echo "[${TOTAL}/${#FUZZERS[@]}] $f workers=$WORKERS time=${FUZZ_SECONDS}s timeout=${FUZZER_TIMEOUT}s rss=${FUZZER_RSS}MB max_len=${FUZZER_MAX_LEN} dict=$(basename "${dict:-none}")"

  export LLVM_PROFILE_FILE="$PROFRAW_DIR/${f}_%m_%p.profraw"
  export ASAN_OPTIONS="$FUZZER_ASAN"

  rc=0
  timeout --kill-after=10s $((FUZZ_SECONDS + FUZZER_TIMEOUT))s \
    "$BIN_DIR/$f" \
      -max_total_time="$FUZZ_SECONDS" \
      -print_final_stats=1 \
      -detect_leaks=0 \
      -timeout="$FUZZER_TIMEOUT" \
      -rss_limit_mb="$FUZZER_RSS" \
      -use_value_profile=1 \
      -max_len="$FUZZER_MAX_LEN" \
      -create_missing_dirs=1 \
      -jobs="$WORKERS" \
      -workers="$WORKERS" \
      -artifact_prefix="$ARTIFACT_DIR/" \
      "${dict_args[@]}" \
      "$corpus" \
      > "$log" 2>&1 || rc=$?

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

echo "-- Summary ------------------------------------------------------"
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
crashes=$(find "$ARTIFACT_DIR" -maxdepth 1 -type f -name 'crash-*' 2>/dev/null | wc -l)
leaks=$(find "$ARTIFACT_DIR" -maxdepth 1 -type f -name 'leak-*' 2>/dev/null | wc -l)
ooms=$(find "$ARTIFACT_DIR" -maxdepth 1 -type f -name 'oom-*' 2>/dev/null | wc -l)
timeouts=$(find "$ARTIFACT_DIR" -maxdepth 1 -type f -name 'timeout-*' 2>/dev/null | wc -l)
slow_units=$(find "$ARTIFACT_DIR" -maxdepth 1 -type f -name 'slow-unit-*' 2>/dev/null | wc -l)
artifacts=$((crashes + leaks + ooms + timeouts + slow_units))
echo "  Artifacts: $artifacts files (crash=$crashes leak=$leaks oom=$ooms timeout=$timeouts slow-unit=$slow_units)"
echo "  Disk free: $(df -h "$STORAGE_DIR" | tail -1 | awk '{print $4}')"
echo ""
echo "[*] Done. $PASS/$TOTAL fuzzers completed cleanly."
echo ""
echo "Next steps:"
echo "  Check artifacts:      find $ARTIFACT_DIR -maxdepth 1 -type f \\( -name 'crash-*' -o -name 'leak-*' -o -name 'oom-*' -o -name 'timeout-*' -o -name 'slow-unit-*' \\) -print"
