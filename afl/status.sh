#!/bin/bash
# afl/status.sh - Show actionable AFL++ fuzzer status
#
# Usage: ./afl/status.sh [target|all] [--detail] [--json]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
BIN_DIR="$AFL_BASE/bin"
TARGET=""
DETAIL=0
JSON=0

source "$AFL_BASE/targets.sh"

usage() {
    sed -n '2,5p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  --detail       show artifact paths and fuzzer_stats path"
    echo "  --json         emit stable machine-readable status"
    echo "  --help, -h     show help"
    echo ""
    afl_print_targets
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --detail) DETAIL=1; shift ;;
        --json) JSON=1; shift ;;
        --help|-h) usage; exit 0 ;;
        all) TARGET=""; shift ;;
        -*) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 1 ;;
        *) TARGET="$1"; shift ;;
    esac
done

json_escape() {
    local s="${1:-}"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

stat_value() {
    local stats="$1"
    local key="$2"
    awk -F: -v key="$key" '{
        k=$1
        gsub(/[ \t]+$/, "", k)
        if (k == key) {
            gsub(/^[ \t]+/, "", $2)
            print $2
            exit
        }
    }' "$stats" 2>/dev/null || true
}

fmt_runtime() {
    local seconds="${1:-0}"
    [[ "$seconds" =~ ^[0-9]+$ ]] || { printf '%s' "-"; return; }
    printf '%dh%dm%ds' "$((seconds / 3600))" "$(((seconds % 3600) / 60))" "$((seconds % 60))"
}

count_files() {
    local dir="$1"
    [[ -d "$dir" ]] || { printf '0'; return; }
    find "$dir" -maxdepth 1 -type f ! -name 'README*' 2>/dev/null | wc -l
}

target_output_dir() {
    local target="$1"
    if afl_configure_target "$target" >/dev/null 2>&1; then
        printf '%s/output' "$AFL_DIR"
        return 0
    fi
    return 1
}

collect_instance() {
    local target="$1"
    local inst_dir="$2"
    local inst_name stats pid state run_time runtime execs eps corpus found crashes hangs bitmap stability cycles age stats_mtime action
    local crash_files hang_files

    inst_name=$(basename "$inst_dir")
    stats="$inst_dir/fuzzer_stats"
    pid=$(stat_value "$stats" "fuzzer_pid")
    state="STOPPED"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
        state="RUNNING"
    fi

    run_time=$(stat_value "$stats" "run_time")
    runtime=$(fmt_runtime "$run_time")
    execs=$(stat_value "$stats" "execs_done")
    eps=$(stat_value "$stats" "execs_per_sec")
    corpus=$(stat_value "$stats" "corpus_count")
    found=$(stat_value "$stats" "corpus_found")
    crashes=$(stat_value "$stats" "saved_crashes")
    hangs=$(stat_value "$stats" "saved_hangs")
    bitmap=$(stat_value "$stats" "bitmap_cvg")
    stability=$(stat_value "$stats" "stability")
    cycles=$(stat_value "$stats" "cycles_done")
    stats_mtime=$(stat -c %Y "$stats" 2>/dev/null || echo 0)
    age=$(($(date +%s) - stats_mtime))
    crash_files=$(count_files "$inst_dir/crashes")
    hang_files=$(count_files "$inst_dir/hangs")

    crashes="${crashes:-$crash_files}"
    hangs="${hangs:-$hang_files}"
    execs="${execs:-0}"
    eps="${eps:-0}"
    corpus="${corpus:-0}"
    found="${found:-0}"
    bitmap="${bitmap:-0%}"
    stability="${stability:-0%}"
    cycles="${cycles:-0}"
    pid="${pid:-"-"}"

    if [[ "$crashes" -gt 0 || "$hangs" -gt 0 || "$crash_files" -gt 0 || "$hang_files" -gt 0 ]]; then
        action="$AFL_BASE/triage.sh $target"
    elif [[ "$state" == "STOPPED" ]]; then
        action="$AFL_BASE/start.sh $target"
    else
        action="$AFL_BASE/stop.sh $target"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$target" "$inst_name" "$state" "$pid" "$runtime" "$execs" "$eps" "$corpus" \
        "$found" "$bitmap" "$stability" "$cycles" "$crashes" "$hangs" "$crash_files" \
        "$hang_files" "$age" "$action"
}

collect_target() {
    local target="$1"
    local output_dir
    local instances=()
    local child

    if ! output_dir=$(target_output_dir "$target"); then
        echo "ERROR: Unknown target '$target'" >&2
        afl_print_targets >&2
        return 1
    fi

    if [[ ! -d "$output_dir" ]]; then
        printf '%s\t-\tNOT_STARTED\t-\t-\t0\t0\t0\t0\t0%%\t0%%\t0\t0\t0\t0\t0\t-\t%s/start.sh %s\n' "$target" "$AFL_BASE" "$target"
        return 0
    fi

    while IFS= read -r -d '' child; do
        [[ -f "$child/fuzzer_stats" ]] && instances+=("$child")
    done < <(find "$output_dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | sort -z)

    if [[ ${#instances[@]} -eq 0 ]]; then
        printf '%s\t-\tNO_STATS\t-\t-\t0\t0\t0\t0\t0%%\t0%%\t0\t0\t0\t0\t0\t-\t%s/start.sh %s\n' "$target" "$AFL_BASE" "$target"
        return 0
    fi

    for child in "${instances[@]}"; do
        collect_instance "$target" "$child"
    done
}

ROWS=()
if [[ -n "$TARGET" ]]; then
    if ! target_output_dir "$TARGET" >/dev/null; then
        echo "ERROR: Unknown target '$TARGET'" >&2
        afl_print_targets >&2
        exit 1
    fi
    while IFS= read -r row; do ROWS+=("$row"); done < <(collect_target "$TARGET")
else
    for t in "${AFL_TARGETS[@]}"; do
        while IFS= read -r row; do ROWS+=("$row"); done < <(collect_target "$t")
    done
fi

if [[ "$JSON" -eq 1 ]]; then
    echo '{"schema_version":1,"targets":['
    first=1
    for row in "${ROWS[@]}"; do
        IFS=$'\t' read -r target inst state pid runtime execs eps corpus found bitmap stability cycles crashes hangs crash_files hang_files age action <<< "$row"
        [[ "$first" -eq 0 ]] && echo ','
        first=0
        printf '  {"target":"%s","instance":"%s","state":"%s","pid":"%s","runtime":"%s","execs":%s,"execs_per_sec":"%s","corpus":%s,"found":%s,"coverage":"%s","stability":"%s","cycles":%s,"crashes":%s,"hangs":%s,"crash_files":%s,"hang_files":%s,"stats_age_seconds":"%s","action":"%s"}' \
            "$(json_escape "$target")" "$(json_escape "$inst")" "$(json_escape "$state")" "$(json_escape "$pid")" "$(json_escape "$runtime")" \
            "$execs" "$(json_escape "$eps")" "$corpus" "$found" "$(json_escape "$bitmap")" "$(json_escape "$stability")" "$cycles" "$crashes" "$hangs" "$crash_files" "$hang_files" "$(json_escape "$age")" "$(json_escape "$action")"
    done
    echo ''
    echo ']}'
    exit 0
fi

echo "=== AFL++ Fuzzer Status ==="
echo ""
printf "%-16s %-11s %-11s %8s %10s %12s %8s %9s %9s %7s\n" "Target" "Instance" "State" "PID" "Runtime" "Execs" "Corpus" "Crashes" "Hangs" "Age"
printf "%-16s %-11s %-11s %8s %10s %12s %8s %9s %9s %7s\n" "------" "--------" "-----" "---" "-------" "-----" "------" "-------" "-----" "---"
for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r target inst state pid runtime execs eps corpus found bitmap stability cycles crashes hangs crash_files hang_files age action <<< "$row"
    printf "%-16s %-11s %-11s %8s %10s %12s %8s %9s %9s %7s\n" "$target" "$inst" "$state" "$pid" "$runtime" "$execs" "$corpus" "$crashes" "$hangs" "$age"
done

echo ""
for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r target inst state pid runtime execs eps corpus found bitmap stability cycles crashes hangs crash_files hang_files age action <<< "$row"
    if [[ "$state" != "RUNNING" || "$crashes" -gt 0 || "$hangs" -gt 0 || "$crash_files" -gt 0 || "$hang_files" -gt 0 ]]; then
        echo "[$target/$inst] $state"
        echo "  Coverage:  $bitmap (stability: $stability, cycles: $cycles)"
        echo "  Findings:  crashes=$crashes hangs=$hangs crash_files=$crash_files hang_files=$hang_files"
        echo "  Action:    $action"
        echo ""
    fi
done

if [[ "$DETAIL" -eq 1 ]]; then
    for row in "${ROWS[@]}"; do
        IFS=$'\t' read -r target inst state pid runtime execs eps corpus found bitmap stability cycles crashes hangs crash_files hang_files age action <<< "$row"
        output_dir=$(target_output_dir "$target")
        inst_dir="$output_dir/$inst"
        echo "[$target/$inst] $state"
        echo "  PID:        $pid"
        echo "  Runtime:    $runtime"
        echo "  Execs:      $execs ($eps exec/s)"
        echo "  Corpus:     $corpus (found: $found)"
        echo "  Coverage:   $bitmap (stability: $stability, cycles: $cycles)"
        echo "  Stats age:  ${age}s"
        [[ "$inst" != "-" ]] && echo "  Stats:      $inst_dir/fuzzer_stats"
        if [[ "$crash_files" -gt 0 && -d "$inst_dir/crashes" ]]; then
            echo "  Crash files:"
            find "$inst_dir/crashes" -maxdepth 1 -type f ! -name 'README*' -printf '    %p\n' | sed -n '1,10p'
        fi
        if [[ "$hang_files" -gt 0 && -d "$inst_dir/hangs" ]]; then
            echo "  Hang files:"
            find "$inst_dir/hangs" -maxdepth 1 -type f ! -name 'README*' -printf '    %p\n' | sed -n '1,10p'
        fi
        echo "  Action:     $action"
        echo ""
    done
fi

echo "--- Active AFL processes ---"
ps -C afl-fuzz -o pid=,pcpu=,pmem=,comm= 2>/dev/null | awk '{printf "  PID %-8s CPU %-5s MEM %-5s %s\n", $1, $2, $3, $4}' || echo "  (none)"
