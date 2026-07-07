#!/bin/bash
# afl/status.sh - Show actionable AFL++ fuzzer status
#
# Usage: ./afl/status.sh [target|all] [--detail] [--json]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
BIN_DIR="${AFL_BIN_DIR:-$REPO_ROOT/afl/bin}"
TARGET=""
DETAIL=0
JSON=0

source "$REPO_ROOT/afl/targets.sh"

usage() {
    sed -n '2,5p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  --detail       show artifact paths, map density, and runtime details"
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

read_proc_cmdline() {
    local proc_cmdline="$1"

    dd if="$proc_cmdline" bs=4096 count=1 2>/dev/null | tr '\0' ' ' || true
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

setup_value() {
    local setup="$1"
    local key="$2"
    awk -F= -v key="$key" '$1 == key { print $2; exit }' "$setup" 2>/dev/null || true
}

fmt_percent() {
    local numerator="${1:-0}"
    local denominator="${2:-0}"
    if [[ "$numerator" =~ ^[0-9]+$ && "$denominator" =~ ^[0-9]+$ && "$denominator" -gt 0 ]]; then
        awk -v n="$numerator" -v d="$denominator" 'BEGIN { printf "%.2f%%", (n * 100.0) / d }'
    else
        printf '%s' "-"
    fi
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

count_finding_files() {
    local inst_dir="$1"
    local kind="$2"
    local count=0
    local dir

    while IFS= read -r -d '' dir; do
        count=$((count + $(count_files "$dir")))
    done < <(find "$inst_dir" -maxdepth 1 -type d \( -name "$kind" -o -name "$kind.*" \) -print0 2>/dev/null | sort -z)

    printf '%s' "$count"
}

print_finding_files() {
    local inst_dir="$1"
    local kind="$2"
    local dir

    while IFS= read -r -d '' dir; do
        find "$dir" -maxdepth 1 -type f ! -name 'README*' -printf '    %p\n' 2>/dev/null
    done < <(find "$inst_dir" -maxdepth 1 -type d \( -name "$kind" -o -name "$kind.*" \) -print0 2>/dev/null | sort -z)
}

live_afl_pid_for_output() {
    local output_dir="$1"
    local proc_cmdline
    local pid
    local cmdline

    while IFS= read -r -d '' proc_cmdline; do
        pid="${proc_cmdline#/proc/}"
        pid="${pid%/cmdline}"
        cmdline="$(read_proc_cmdline "$proc_cmdline")"
        if [[ "$cmdline" == *"afl-fuzz"* && "$cmdline" == *"$output_dir"* ]]; then
            printf '%s' "$pid"
            return 0
        fi
    done < <(find /proc -maxdepth 2 -path '/proc/[0-9]*/cmdline' -print0 2>/dev/null)

    return 1
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
    local inst_name stats setup pid state run_time runtime execs eps corpus found crashes hangs bitmap stability cycles age stats_mtime action
    local pending_favs pending_total total_tmout exec_timeout slowest_exec_ms peak_rss_mb edges_found total_edges edge_density map_size last_find last_find_age
    local crash_files hang_files
    local output_dir live_pid

    inst_name=$(basename "$inst_dir")
    output_dir=$(dirname "$inst_dir")
    stats="$inst_dir/fuzzer_stats"
    setup="$inst_dir/fuzzer_setup"
    pid=$(stat_value "$stats" "fuzzer_pid")
    state="STOPPED"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
        state="RUNNING"
    elif live_pid=$(live_afl_pid_for_output "$output_dir"); then
        pid="$live_pid"
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
    pending_favs=$(stat_value "$stats" "pending_favs")
    pending_total=$(stat_value "$stats" "pending_total")
    total_tmout=$(stat_value "$stats" "total_tmout")
    exec_timeout=$(stat_value "$stats" "exec_timeout")
    slowest_exec_ms=$(stat_value "$stats" "slowest_exec_ms")
    peak_rss_mb=$(stat_value "$stats" "peak_rss_mb")
    edges_found=$(stat_value "$stats" "edges_found")
    total_edges=$(stat_value "$stats" "total_edges")
    edge_density=$(fmt_percent "${edges_found:-0}" "${total_edges:-0}")
    map_size=$(setup_value "$setup" "AFL_MAP_SIZE")
    last_find=$(stat_value "$stats" "last_find")
    stats_mtime=$(stat -c %Y "$stats" 2>/dev/null || echo 0)
    age=$(($(date +%s) - stats_mtime))
    if [[ "$last_find" =~ ^[0-9]+$ && "$last_find" -gt 0 ]]; then
        last_find_age=$(($(date +%s) - last_find))
    else
        last_find_age="-"
    fi
    crash_files=$(count_finding_files "$inst_dir" "crashes")
    hang_files=$(count_finding_files "$inst_dir" "hangs")

    crashes="${crashes:-$crash_files}"
    hangs="${hangs:-$hang_files}"
    execs="${execs:-0}"
    eps="${eps:-0}"
    corpus="${corpus:-0}"
    found="${found:-0}"
    bitmap="${bitmap:-0%}"
    stability="${stability:-0%}"
    cycles="${cycles:-0}"
    pending_favs="${pending_favs:-0}"
    pending_total="${pending_total:-0}"
    total_tmout="${total_tmout:-0}"
    exec_timeout="${exec_timeout:-0}"
    slowest_exec_ms="${slowest_exec_ms:-0}"
    peak_rss_mb="${peak_rss_mb:-0}"
    edges_found="${edges_found:-0}"
    total_edges="${total_edges:-0}"
    edge_density="${edge_density:-"-"}"
    map_size="${map_size:-"-"}"
    pid="${pid:-"-"}"

    if [[ "$crashes" -gt 0 || "$hangs" -gt 0 || "$crash_files" -gt 0 || "$hang_files" -gt 0 ]]; then
        action="$REPO_ROOT/afl/triage.sh $target"
    elif [[ "$state" == "STOPPED" ]]; then
        action="$REPO_ROOT/afl/start.sh $target"
    else
        action="$REPO_ROOT/afl/stop.sh $target"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$target" "$inst_name" "$state" "$pid" "$runtime" "$execs" "$eps" "$corpus" \
        "$found" "$bitmap" "$stability" "$cycles" "$crashes" "$hangs" "$crash_files" \
        "$hang_files" "$age" "$action" "$pending_favs" "$pending_total" "$total_tmout" \
        "$exec_timeout" "$slowest_exec_ms" "$peak_rss_mb" "$edges_found" "$total_edges" \
        "$edge_density" "$map_size" "$last_find_age"
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
        printf '%s\t-\tNOT_STARTED\t-\t-\t0\t0\t0\t0\t0%%\t0%%\t0\t0\t0\t0\t0\t-\t%s/afl/start.sh %s\t0\t0\t0\t0\t0\t0\t0\t0\t-\t-\t-\n' "$target" "$REPO_ROOT" "$target"
        return 0
    fi

    while IFS= read -r -d '' child; do
        [[ -f "$child/fuzzer_stats" ]] && instances+=("$child")
    done < <(find "$output_dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | sort -z)

    if [[ ${#instances[@]} -eq 0 ]]; then
        printf '%s\t-\tNO_STATS\t-\t-\t0\t0\t0\t0\t0%%\t0%%\t0\t0\t0\t0\t0\t-\t%s/afl/start.sh %s\t0\t0\t0\t0\t0\t0\t0\t0\t-\t-\t-\n' "$target" "$REPO_ROOT" "$target"
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
        IFS=$'\t' read -r target inst state pid runtime execs eps corpus found bitmap stability cycles crashes hangs crash_files hang_files age action pending_favs pending_total total_tmout exec_timeout slowest_exec_ms peak_rss_mb edges_found total_edges edge_density map_size last_find_age <<< "$row"
        [[ "$first" -eq 0 ]] && echo ','
        first=0
        printf '  {"target":"%s","instance":"%s","state":"%s","pid":"%s","runtime":"%s","execs":%s,"execs_per_sec":"%s","corpus":%s,"found":%s,"coverage":"%s","stability":"%s","cycles":%s,"crashes":%s,"hangs":%s,"crash_files":%s,"hang_files":%s,"stats_age_seconds":"%s","pending_favored":%s,"pending_total":%s,"total_timeouts":%s,"exec_timeout_ms":%s,"slowest_exec_ms":%s,"peak_rss_mb":%s,"edges_found":%s,"total_edges":%s,"edge_density":"%s","map_size":"%s","last_find_age_seconds":"%s","action":"%s"}' \
            "$(json_escape "$target")" "$(json_escape "$inst")" "$(json_escape "$state")" "$(json_escape "$pid")" "$(json_escape "$runtime")" \
            "$execs" "$(json_escape "$eps")" "$corpus" "$found" "$(json_escape "$bitmap")" "$(json_escape "$stability")" "$cycles" "$crashes" "$hangs" "$crash_files" "$hang_files" "$(json_escape "$age")" \
            "$pending_favs" "$pending_total" "$total_tmout" "$exec_timeout" "$slowest_exec_ms" "$peak_rss_mb" "$edges_found" "$total_edges" "$(json_escape "$edge_density")" "$(json_escape "$map_size")" "$(json_escape "$last_find_age")" "$(json_escape "$action")"
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
    IFS=$'\t' read -r target inst state pid runtime execs eps corpus found bitmap stability cycles crashes hangs crash_files hang_files age action pending_favs pending_total total_tmout exec_timeout slowest_exec_ms peak_rss_mb edges_found total_edges edge_density map_size last_find_age <<< "$row"
    printf "%-16s %-11s %-11s %8s %10s %12s %8s %9s %9s %7s\n" "$target" "$inst" "$state" "$pid" "$runtime" "$execs" "$corpus" "$crashes" "$hangs" "$age"
done

echo ""
for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r target inst state pid runtime execs eps corpus found bitmap stability cycles crashes hangs crash_files hang_files age action pending_favs pending_total total_tmout exec_timeout slowest_exec_ms peak_rss_mb edges_found total_edges edge_density map_size last_find_age <<< "$row"
    if [[ "$state" != "RUNNING" || "$crashes" -gt 0 || "$hangs" -gt 0 || "$crash_files" -gt 0 || "$hang_files" -gt 0 ]]; then
        echo "[$target/$inst] $state"
        echo "  Coverage:  $bitmap (stability: $stability, cycles: $cycles)"
        echo "  Edges:     $edges_found/$total_edges ($edge_density, map_size=$map_size)"
        echo "  Findings:  crashes=$crashes hangs=$hangs crash_files=$crash_files hang_files=$hang_files"
        echo "  Action:    $action"
        echo ""
    fi
done

if [[ "$DETAIL" -eq 1 ]]; then
    for row in "${ROWS[@]}"; do
        IFS=$'\t' read -r target inst state pid runtime execs eps corpus found bitmap stability cycles crashes hangs crash_files hang_files age action pending_favs pending_total total_tmout exec_timeout slowest_exec_ms peak_rss_mb edges_found total_edges edge_density map_size last_find_age <<< "$row"
        output_dir=$(target_output_dir "$target")
        inst_dir="$output_dir/$inst"
        echo "[$target/$inst] $state"
        echo "  PID:        $pid"
        echo "  Runtime:    $runtime"
        echo "  Execs:      $execs ($eps exec/s)"
        echo "  Corpus:     $corpus (found: $found)"
        echo "  Coverage:   $bitmap (stability: $stability, cycles: $cycles)"
        echo "  Map:        map_size=$map_size edges=$edges_found/$total_edges ($edge_density)"
        echo "  Pending:    favored=$pending_favs total=$pending_total"
        echo "  Runtime:    timeout=${exec_timeout}ms slowest=${slowest_exec_ms}ms peak_rss=${peak_rss_mb}MB timeouts=$total_tmout last_find_age=${last_find_age}s"
        echo "  Stats age:  ${age}s"
        [[ "$inst" != "-" ]] && echo "  Stats:      $inst_dir/fuzzer_stats"
        if [[ "$crash_files" -gt 0 ]]; then
            echo "  Crash files:"
            print_finding_files "$inst_dir" "crashes" | sed -n '1,10p'
        fi
        if [[ "$hang_files" -gt 0 ]]; then
            echo "  Hang files:"
            print_finding_files "$inst_dir" "hangs" | sed -n '1,10p'
        fi
        echo "  Action:     $action"
        echo ""
    done
fi

echo "--- Active AFL processes ---"
ps -C afl-fuzz -o pid=,pcpu=,pmem=,comm= 2>/dev/null | awk '{printf "  PID %-8s CPU %-5s MEM %-5s %s\n", $1, $2, $3, $4}' || echo "  (none)"
