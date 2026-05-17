#!/usr/bin/env bash
# cfl/status.sh - Show status for CFL LibFuzzer sessions.
#
# Usage: ./cfl/status.sh [fuzzer|alias|all]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=cfl/fuzzers.sh
source "$SCRIPT_DIR/fuzzers.sh"

RUNS_DIR="$SCRIPT_DIR/runs"
TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs-dir) RUNS_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,5p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    -*) echo "ERROR: Unknown option: $1" >&2; exit 1 ;;
    *) TARGETS+=("$1"); shift ;;
  esac
done

FUZZER_LIST="$(cfl_resolve_fuzzers "${TARGETS[@]:-all}")" || exit 1
mapfile -t FUZZERS <<< "$FUZZER_LIST"

print_status() {
  local fuzzer="$1"
  local run_dir="$RUNS_DIR/$fuzzer"
  local pid_file="$run_dir/fuzzer.pid"
  local corpus
  local corpus_count=0
  local artifact_count=0
  local profraw_count=0
  local status="STOPPED"
  local pid="-"
  local runtime="-"
  local now
  local start_time
  local last_line=""

  if cfl_pid_is_running "$pid_file" "$fuzzer"; then
    pid=$(cat "$pid_file")
    status="RUNNING"
  elif [[ ! -d "$run_dir" ]]; then
    status="NOT STARTED"
  fi

  if [[ -f "$run_dir/start.time" ]]; then
    now=$(date +%s)
    start_time=$(cat "$run_dir/start.time")
    if [[ "$start_time" =~ ^[0-9]+$ ]]; then
      runtime="$((now - start_time))s"
    fi
  fi

  corpus=$(cfl_corpus_dir "$SCRIPT_DIR" "$fuzzer")
  if [[ -d "$corpus" ]]; then
    corpus_count=$(find "$corpus" -type f 2>/dev/null | wc -l)
  fi

  if [[ -d "$run_dir/artifacts" ]]; then
    artifact_count=$(find "$run_dir/artifacts" -type f 2>/dev/null | wc -l)
  fi
  if [[ -d "$run_dir/profraw" ]]; then
    profraw_count=$(find "$run_dir/profraw" -type f 2>/dev/null | wc -l)
  fi
  if [[ -f "$run_dir/current.log" ]]; then
    last_line=$(tail -n 1 "$run_dir/current.log" 2>/dev/null || true)
  fi

  echo "[$fuzzer] $status"
  echo "  PID:       $pid"
  echo "  Runtime:   $runtime"
  echo "  Corpus:    $corpus_count files ($corpus)"
  echo "  Artifacts: $artifact_count"
  echo "  Profraw:   $profraw_count"
  echo "  Log:       $run_dir/current.log"
  if [[ -n "$last_line" ]]; then
    echo "  Last:      $last_line"
  fi
  echo ""
}

for fuzzer in "${FUZZERS[@]}"; do
  print_status "$fuzzer"
done
