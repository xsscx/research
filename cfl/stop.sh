#!/usr/bin/env bash
# cfl/stop.sh - Stop running CFL LibFuzzer sessions.
#
# Usage: ./cfl/stop.sh [fuzzer|alias|all] [--force] [--reap] [--timeout SECONDS]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=cfl/fuzzers.sh
source "$SCRIPT_DIR/fuzzers.sh"

RUNS_DIR="$SCRIPT_DIR/runs"
STOP_TIMEOUT=10
FORCE=0
REAP=0
QUIET=0
TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    --reap) REAP=1; shift ;;
    --quiet) QUIET=1; shift ;;
    --timeout) STOP_TIMEOUT="$2"; shift 2 ;;
    --runs-dir) RUNS_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,5p' "$0" | sed 's/^# \?//'
      echo ""
      echo "Options:"
      echo "  --force            send TERM/KILL if SIGINT does not stop the process"
      echo "  --reap             remove stale pid files for non-running fuzzers"
      echo "  --timeout SECONDS  wait for graceful shutdown (default: 10)"
      echo "  --runs-dir DIR     run state directory (default: cfl/runs)"
      echo "  --quiet            suppress non-error output"
      exit 0
      ;;
    -*) echo "ERROR: Unknown option: $1" >&2; exit 1 ;;
    *) TARGETS+=("$1"); shift ;;
  esac
done

FUZZER_LIST="$(cfl_resolve_fuzzers "${TARGETS[@]:-all}")" || exit 1
mapfile -t FUZZERS <<< "$FUZZER_LIST"

say() {
  [[ "$QUIET" -eq 1 ]] || echo "$@"
}

stop_fuzzer() {
  local fuzzer="$1"
  local run_dir="$RUNS_DIR/$fuzzer"
  local pid_file="$run_dir/fuzzer.pid"
  local pid
  local waited=0

  if ! cfl_pid_is_running "$pid_file" "$fuzzer"; then
    if [[ "$REAP" -eq 1 && -f "$pid_file" ]]; then
      rm -f "$pid_file"
      [[ -d "$run_dir" ]] && date +%s > "$run_dir/stop.time"
      say "[OK] $fuzzer stale pid reaped"
    else
      say "[SKIP] $fuzzer not running"
      [[ -f "$pid_file" ]] && say "       stale pid file remains; use --reap to remove"
    fi
    return 0
  fi

  pid=$(cat "$pid_file")
  say "[*] Stopping $fuzzer (pid $pid)"
  kill -INT -- "-$pid" 2>/dev/null || kill -INT "$pid" 2>/dev/null || true

  while kill -0 "$pid" 2>/dev/null && [[ "$waited" -lt "$STOP_TIMEOUT" ]]; do
    sleep 1
    waited=$((waited + 1))
  done

  if kill -0 "$pid" 2>/dev/null; then
    if [[ "$FORCE" -eq 1 ]]; then
      say "[WARN] $fuzzer still running - force killing"
      kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
      sleep 2
      if kill -0 "$pid" 2>/dev/null; then
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
      fi
    else
      say "[WARN] $fuzzer still running after ${STOP_TIMEOUT}s; use --force if needed"
      return 1
    fi
  fi

  date +%s > "$run_dir/stop.time"
  rm -f "$pid_file"
  say "[OK] $fuzzer stopped"
}

ERRORS=0
for fuzzer in "${FUZZERS[@]}"; do
  stop_fuzzer "$fuzzer" || ERRORS=$((ERRORS + 1))
done

if [[ "$ERRORS" -gt 0 ]]; then
  echo "[FAIL] $ERRORS fuzzer(s) did not stop cleanly"
  exit 1
fi
