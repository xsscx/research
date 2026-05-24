#!/usr/bin/env bash
# cfl/start.sh - Start one or more CFL LibFuzzer binaries in the background.
#
# Usage:
#   ./cfl/start.sh <fuzzer|alias|all> [options]
#
# Examples:
#   ./cfl/start.sh dump
#   ./cfl/start.sh icc_dump_fuzzer --time 3600 --workers 4
#   ./cfl/start.sh all --time 600
#
# Options:
#   --time SECONDS     max_total_time; 0 means run until stopped (default: 0)
#   --workers N        LibFuzzer workers per fuzzer (default: 1)
#   --jobs N           LibFuzzer jobs per fuzzer (default: workers)
#   --rss MB           override rss_limit_mb per worker (default: fuzzer options)
#   --max-len BYTES    override max_len passed to LibFuzzer (default: fuzzer options)
#   --runs-dir DIR     run state directory (default: cfl/runs)
#   --foreground       run a single fuzzer in the foreground
#   -h, --help         show help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=cfl/fuzzers.sh
source "$SCRIPT_DIR/fuzzers.sh"

FUZZ_SECONDS=0
WORKERS=1
JOBS=""
RSS_LIMIT=""
MAX_LEN=""
RUNS_DIR="$SCRIPT_DIR/runs"
FOREGROUND=0
TARGETS=()

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \?//'
  echo ""
  echo "Available fuzzers:"
  cfl_list_fuzzers | sed 's/^/  /'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --time|-t) FUZZ_SECONDS="$2"; shift 2 ;;
    --workers|-w) WORKERS="$2"; shift 2 ;;
    --jobs|-j) JOBS="$2"; shift 2 ;;
    --rss|-m) RSS_LIMIT="$2"; shift 2 ;;
    --max-len) MAX_LEN="$2"; shift 2 ;;
    --runs-dir) RUNS_DIR="$2"; shift 2 ;;
    --foreground) FOREGROUND=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 1 ;;
    *) TARGETS+=("$1"); shift ;;
  esac
done

if [[ $# -gt 0 ]]; then
  TARGETS+=("$@")
fi

JOBS="${JOBS:-$WORKERS}"

FUZZER_LIST="$(cfl_resolve_fuzzers "${TARGETS[@]:-all}")" || exit 1
mapfile -t FUZZERS <<< "$FUZZER_LIST"
if [[ "$FOREGROUND" -eq 1 && ${#FUZZERS[@]} -ne 1 ]]; then
  echo "ERROR: --foreground requires exactly one fuzzer" >&2
  exit 1
fi

mkdir -p "$RUNS_DIR"

start_fuzzer() {
  local fuzzer="$1"
  local bin="$SCRIPT_DIR/bin/$fuzzer"
  local corpus
  local dict
  local dict_args=()
  local run_dir="$RUNS_DIR/$fuzzer"
  local artifact_dir="$run_dir/artifacts"
  local profraw_dir="$run_dir/profraw"
  local log="$run_dir/current.log"
  local pid_file="$run_dir/fuzzer.pid"
  local timeout_value
  local rss_limit
  local max_len
  local asan_options
  local cmd=()
  local pid

  if [[ ! -x "$bin" ]]; then
    echo "[FAIL] $fuzzer binary not found: $bin"
    echo "       Run ./cfl/build.sh first"
    return 1
  fi

  mkdir -p "$run_dir" "$artifact_dir" "$profraw_dir"

  if cfl_pid_is_running "$pid_file" "$fuzzer"; then
    pid=$(cat "$pid_file")
    echo "[SKIP] $fuzzer already running (pid $pid)"
    return 0
  fi

  corpus=$(cfl_corpus_dir "$SCRIPT_DIR" "$fuzzer")
  mkdir -p "$corpus"

  if dict=$(cfl_resolve_dict "$SCRIPT_DIR" "$fuzzer"); then
    dict_args=("-dict=$dict")
  fi

  timeout_value=$(cfl_option_timeout "$SCRIPT_DIR" "$fuzzer")
  rss_limit="${RSS_LIMIT:-$(cfl_option_rss_limit "$SCRIPT_DIR" "$fuzzer")}"
  max_len="${MAX_LEN:-$(cfl_option_max_len "$SCRIPT_DIR" "$fuzzer")}"
  asan_options="$(cfl_asan_options "$fuzzer")"

  cmd=(
    "$bin"
    -print_final_stats=1
    -detect_leaks=0
    "-timeout=$timeout_value"
    "-rss_limit_mb=$rss_limit"
    -use_value_profile=1
    "-max_len=$max_len"
    -create_missing_dirs=1
    "-artifact_prefix=$artifact_dir/"
    "-jobs=$JOBS"
    "-workers=$WORKERS"
  )

  if [[ "$FUZZ_SECONDS" != "0" ]]; then
    cmd+=("-max_total_time=$FUZZ_SECONDS")
  fi

  cmd+=("${dict_args[@]}" "$corpus")

  printf '%s\n' "${cmd[*]}" > "$run_dir/cmd.txt"
  date +%s > "$run_dir/start.time"
  rm -f "$run_dir/stop.time"

  if [[ "$FOREGROUND" -eq 1 ]]; then
    echo "[*] Starting $fuzzer in foreground"
    echo "[*] Corpus: $corpus"
    echo "[*] Options: timeout=$timeout_value rss_limit_mb=$rss_limit max_len=$max_len"
    echo "[*] Log: stdout/stderr"
    export FUZZ_TMPDIR="$run_dir"
    export LLVM_PROFILE_FILE="$profraw_dir/${fuzzer}_%m_%p.profraw"
    export ASAN_OPTIONS="$asan_options"
    export UBSAN_OPTIONS="halt_on_error=0,print_stacktrace=1"
    exec "${cmd[@]}"
  fi

  echo "[*] Starting $fuzzer"
  echo "    Corpus: $corpus"
  echo "    Options: timeout=$timeout_value rss_limit_mb=$rss_limit max_len=$max_len"
  echo "    Log:    $log"
  echo "    Runs:   $run_dir"

  setsid env \
    FUZZ_TMPDIR="$run_dir" \
    LLVM_PROFILE_FILE="$profraw_dir/${fuzzer}_%m_%p.profraw" \
    ASAN_OPTIONS="$asan_options" \
    UBSAN_OPTIONS="halt_on_error=0,print_stacktrace=1" \
    "${cmd[@]}" > "$log" 2>&1 &
  pid=$!
  echo "$pid" > "$pid_file"
  echo "    PID:    $pid"
}

ERRORS=0
for fuzzer in "${FUZZERS[@]}"; do
  start_fuzzer "$fuzzer" || ERRORS=$((ERRORS + 1))
done

if [[ "$ERRORS" -gt 0 ]]; then
  echo "[FAIL] $ERRORS fuzzer(s) failed to start"
  exit 1
fi

echo "[OK] Requested CFL fuzzers started"
