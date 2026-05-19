#!/usr/bin/env bash
# cfl/status.sh - Show actionable status for CFL LibFuzzer sessions.
#
# Usage: ./cfl/status.sh [fuzzer|alias|all] [--detail] [--json]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=cfl/fuzzers.sh
source "$SCRIPT_DIR/fuzzers.sh"

RUNS_DIR="$SCRIPT_DIR/runs"
DETAIL=0
JSON=0
TARGETS=()

usage() {
  sed -n '2,5p' "$0" | sed 's/^# \?//'
  echo ""
  echo "Options:"
  echo "  --runs-dir DIR   run state directory (default: cfl/runs)"
  echo "  --detail         show paths and latest actionable log event"
  echo "  --json           emit stable machine-readable status"
  echo "  -h, --help       show help"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs-dir) RUNS_DIR="$2"; shift 2 ;;
    --detail) DETAIL=1; shift ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "ERROR: Unknown option: $1" >&2; exit 1 ;;
    *) TARGETS+=("$1"); shift ;;
  esac
done

FUZZER_LIST="$(cfl_resolve_fuzzers "${TARGETS[@]:-all}")" || exit 1
mapfile -t FUZZERS <<< "$FUZZER_LIST"

json_escape() {
  local s="${1:-}"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

count_artifacts() {
  local dir="$1"
  local pattern="$2"
  find "$dir" -maxdepth 1 -type f -name "$pattern" 2>/dev/null | wc -l
}

latest_relevant_event() {
  local run_dir="$1"
  local event=""
  local log
  local candidate

  while IFS= read -r -d '' log; do
    while IFS= read -r candidate; do
      if [[ "$candidate" == *"artifact_prefix="* || "$candidate" == *"Test unit written to"* ]]; then
        [[ "$candidate" == *"$run_dir/"* ]] || continue
      fi
      event="$candidate"
      break
    done < <(
      LC_ALL=C grep -Eai \
        'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|libFuzzer)|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|libFuzzer)|runtime error:|DEADLYSIGNAL|Test unit written to|DEDUP_TOKEN:|ALARM:' \
        "$log" 2>/dev/null | tac || true
    )
    [[ -n "$event" ]] && break
  done < <(find "$run_dir" -maxdepth 1 \( -name 'current.log' -o -name 'fuzz-*.log' \) -type f -print0 2>/dev/null | sort -z)

  if [[ -z "$event" && -f "$run_dir/current.log" ]]; then
    event=$(tail -n 1 "$run_dir/current.log" 2>/dev/null || true)
  fi
  event=$(printf '%s' "$event" | LC_ALL=C tr -cd '\11\12\15\40-\176')
  printf '%s' "$event"
}

process_start_epoch() {
  local pid="$1"
  local etimes
  etimes=$(ps -p "$pid" -o etimes= 2>/dev/null | awk '{print $1}' || true)
  [[ "$etimes" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$(($(date +%s) - etimes))"
}

collect_status() {
  local fuzzer="$1"
  local run_dir="$RUNS_DIR/$fuzzer"
  local pid_file="$run_dir/fuzzer.pid"
  local corpus
  local corpus_count=0
  local profraw_count=0
  local status="STOPPED"
  local pid="-"
  local runtime="-"
  local now
  local start_time
  local stop_time=""
  local proc_start=""
  local artifact_dir="$run_dir/artifacts"
  local crash_count=0
  local leak_count=0
  local oom_count=0
  local timeout_count=0
  local slow_count=0
  local other_count=0
  local artifact_count=0
  local event=""
  local action=""
  local warn=""

  if cfl_pid_is_running "$pid_file" "$fuzzer"; then
    pid=$(cat "$pid_file")
    status="RUNNING"
    proc_start=$(process_start_epoch "$pid" || true)
  elif [[ ! -d "$run_dir" ]]; then
    status="NOT_STARTED"
  elif [[ -f "$pid_file" && ! -f "$run_dir/stop.time" ]]; then
    status="STALE"
  fi

  [[ -f "$run_dir/stop.time" ]] && stop_time=$(cat "$run_dir/stop.time" 2>/dev/null || true)
  if [[ -f "$run_dir/start.time" ]]; then
    now=$(date +%s)
    start_time=$(cat "$run_dir/start.time")
    if [[ "$start_time" =~ ^[0-9]+$ ]]; then
      if [[ "$status" == "RUNNING" && "$proc_start" =~ ^[0-9]+$ ]]; then
        runtime="$((now - proc_start))s"
        if (( start_time + 60 < proc_start )); then
          warn="start.time predates live process"
        fi
      elif [[ "$stop_time" =~ ^[0-9]+$ && "$stop_time" -ge "$start_time" ]]; then
        runtime="$((stop_time - start_time))s"
      else
        runtime="$((now - start_time))s"
      fi
    fi
  fi

  corpus=$(cfl_corpus_dir "$SCRIPT_DIR" "$fuzzer")
  if [[ -d "$corpus" ]]; then
    corpus_count=$(find "$corpus" -type f 2>/dev/null | wc -l)
  fi

  if [[ -d "$artifact_dir" ]]; then
    artifact_count=$(find "$artifact_dir" -maxdepth 1 -type f 2>/dev/null | wc -l)
    crash_count=$(count_artifacts "$artifact_dir" 'crash-*')
    leak_count=$(count_artifacts "$artifact_dir" 'leak-*')
    oom_count=$(count_artifacts "$artifact_dir" 'oom-*')
    timeout_count=$(count_artifacts "$artifact_dir" 'timeout-*')
    slow_count=$(count_artifacts "$artifact_dir" 'slow-unit-*')
    other_count=$((artifact_count - crash_count - leak_count - oom_count - timeout_count - slow_count))
    [[ "$other_count" -lt 0 ]] && other_count=0
  fi
  if [[ -d "$run_dir/profraw" ]]; then
    profraw_count=$(find "$run_dir/profraw" -maxdepth 1 -type f 2>/dev/null | wc -l)
  fi

  event=$(latest_relevant_event "$run_dir")
  event=${event//$'\t'/ }
  event=${event//$'\n'/ }

  if [[ "$crash_count" -gt 0 || "$leak_count" -gt 0 ]]; then
    action="$SCRIPT_DIR/status.sh $fuzzer --detail"
  elif [[ "$oom_count" -gt 0 || "$timeout_count" -gt 0 ]]; then
    action="find $artifact_dir -maxdepth 1 -type f \\( -name 'oom-*' -o -name 'timeout-*' \\) -print"
  elif [[ "$status" == "STALE" ]]; then
    action="$SCRIPT_DIR/stop.sh $fuzzer --reap"
  elif [[ "$status" == "STOPPED" ]]; then
    action="$SCRIPT_DIR/start.sh $fuzzer"
  elif [[ "$status" == "RUNNING" ]]; then
    action="$SCRIPT_DIR/stop.sh $fuzzer"
  else
    action="$SCRIPT_DIR/start.sh $fuzzer"
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$fuzzer" "$status" "$pid" "$runtime" "$corpus_count" "$artifact_count" \
    "$crash_count" "$leak_count" "$oom_count" "$timeout_count" "$slow_count" \
    "$other_count" "$profraw_count" "$corpus" "$run_dir" "$event" "$action" "$warn"
}

STATUSES=()
while IFS= read -r line; do
  STATUSES+=("$line")
done < <(
  for fuzzer in "${FUZZERS[@]}"; do
    collect_status "$fuzzer"
  done
)

if [[ "$JSON" -eq 1 ]]; then
  echo '{"schema_version":1,"fuzzers":['
  first=1
  for row in "${STATUSES[@]}"; do
    IFS=$'\t' read -r fuzzer status pid runtime corpus_count artifact_count crash_count leak_count oom_count timeout_count slow_count other_count profraw_count corpus run_dir event action warn <<< "$row"
    [[ "$first" -eq 0 ]] && echo ','
    first=0
    printf '  {"name":"%s","state":"%s","pid":"%s","runtime":"%s","corpus_count":%s,"artifacts":{"total":%s,"crash":%s,"leak":%s,"oom":%s,"timeout":%s,"slow_unit":%s,"other":%s},"profraw_count":%s,"corpus":"%s","run_dir":"%s","latest_event":"%s","action":"%s","warning":"%s"}' \
      "$(json_escape "$fuzzer")" "$(json_escape "$status")" "$(json_escape "$pid")" "$(json_escape "$runtime")" \
      "$corpus_count" "$artifact_count" "$crash_count" "$leak_count" "$oom_count" "$timeout_count" "$slow_count" "$other_count" "$profraw_count" \
      "$(json_escape "$corpus")" "$(json_escape "$run_dir")" "$(json_escape "$event")" "$(json_escape "$action")" "$(json_escape "$warn")"
  done
  echo ''
  echo ']}'
  exit 0
fi

printf "%-32s %-11s %8s %10s %9s %31s %7s\n" "Fuzzer" "State" "PID" "Runtime" "Corpus" "Artifacts c/l/o/t/s/other" "Profraw"
printf "%-32s %-11s %8s %10s %9s %31s %7s\n" "------" "-----" "---" "-------" "------" "---------------------------" "-------"
for row in "${STATUSES[@]}"; do
  IFS=$'\t' read -r fuzzer status pid runtime corpus_count artifact_count crash_count leak_count oom_count timeout_count slow_count other_count profraw_count corpus run_dir event action warn <<< "$row"
  printf "%-32s %-11s %8s %10s %9s %5s/%s/%s/%s/%s/%-5s %7s\n" \
    "$fuzzer" "$status" "$pid" "$runtime" "$corpus_count" \
    "$crash_count" "$leak_count" "$oom_count" "$timeout_count" "$slow_count" "$other_count" "$profraw_count"
done

echo ""
for row in "${STATUSES[@]}"; do
  IFS=$'\t' read -r fuzzer status pid runtime corpus_count artifact_count crash_count leak_count oom_count timeout_count slow_count other_count profraw_count corpus run_dir event action warn <<< "$row"
  if [[ "$status" == "STALE" || "$crash_count" -gt 0 || "$leak_count" -gt 0 || "$oom_count" -gt 0 || "$timeout_count" -gt 0 || -n "$warn" ]]; then
    echo "[$fuzzer] $status"
    [[ -n "$warn" ]] && echo "  [WARN] $warn"
    echo "  Artifacts: crash=$crash_count leak=$leak_count oom=$oom_count timeout=$timeout_count slow-unit=$slow_count other=$other_count"
    [[ -n "$event" ]] && echo "  Event:     $event"
    echo "  Action:    $action"
    echo ""
  fi
done

if [[ "$DETAIL" -eq 1 ]]; then
  for row in "${STATUSES[@]}"; do
    IFS=$'\t' read -r fuzzer status pid runtime corpus_count artifact_count crash_count leak_count oom_count timeout_count slow_count other_count profraw_count corpus run_dir event action warn <<< "$row"
    echo "[$fuzzer] $status"
    echo "  PID:       $pid"
    echo "  Runtime:   $runtime"
    echo "  Corpus:    $corpus_count files ($corpus)"
    echo "  Artifacts: total=$artifact_count crash=$crash_count leak=$leak_count oom=$oom_count timeout=$timeout_count slow-unit=$slow_count other=$other_count"
    echo "  Profraw:   $profraw_count"
    echo "  Log:       $run_dir/current.log"
    [[ -n "$event" ]] && echo "  Event:     $event"
    [[ -n "$warn" ]] && echo "  Warning:   $warn"
    echo "  Action:    $action"
    echo ""
  done
fi
