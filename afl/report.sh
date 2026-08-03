#!/bin/bash
# afl/report.sh - Generate stats, maps, triage, coverage, and reachability reports
#
# Usage: ./afl/report.sh [target|all] [--report-root DIR] [--jobs N] [--target-jobs N] [--target-timeout N]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
REPORT_ROOT="${AFL_REPORT_ROOT:-$AFL_BASE/reports/generated/afl-report-$(date -u +%Y%m%dT%H%M%SZ)}"
JOBS="${AFL_REPORT_JOBS:-2}"
TARGET_JOBS="${AFL_REPORT_TARGET_JOBS:-1}"
RUN_COVERAGE=1
RUN_REACHABILITY=1
RUN_MAPS=1
RUN_TRIAGE=1
MARKED_ONLY=0
REUSE_BUILD="${AFL_REPORT_REUSE_BUILD:-0}"
COVERAGE_TIMEOUT="${AFL_REPORT_COVERAGE_TIMEOUT:-5}"
TARGET_TIMEOUT="${AFL_REPORT_TARGET_TIMEOUT:-3600}"
TARGET_FILTER=""

source "$REPO_ROOT/afl/targets.sh"

if [[ -f "$HOME/work/copilot/tools/env.sh" ]]; then
    # shellcheck source=/dev/null
    source "$HOME/work/copilot/tools/env.sh"
fi

usage() {
    sed -n '2,5p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  --report-root DIR  write generated reports under DIR"
    echo "  --jobs N           replay/build jobs for coverage"
    echo "  --target-jobs N    run up to N targets concurrently; default ${TARGET_JOBS}"
    echo "  --stats-only       collect status/index files without map, triage, or coverage replay"
    echo "  --marked-only      triage only afl/marked/<target>; skip maps and coverage"
    echo "  --no-coverage      collect stats/maps/triage only"
    echo "  --no-reachability  run coverage without reachability annotation"
    echo "  --fresh-build      rebuild coverage/reachability artifacts"
    echo "  --reuse-build      reuse coverage/reachability build artifacts"
    echo "  --coverage-timeout N  cov-analysis per-input timeout; default ${COVERAGE_TIMEOUT}s"
    echo "  --target-timeout N whole coverage/reachability target timeout in seconds; 0 disables; default ${TARGET_TIMEOUT}s"
    echo "  --help, -h         show help"
    echo ""
    echo "Runtime notes:"
    echo "  all-target coverage runs targets in afl/targets.sh order and can take hours."
    echo "  use --target-jobs to run independent tool targets concurrently."
    echo "  each started target is bounded by --target-timeout; targets without AFL output"
    echo "  are recorded as not_started and skipped quickly."
    echo "  monitor with targets.tsv, logs/<target>-coverage.log, and ./afl/status.sh --json."
    echo ""
    afl_print_targets
}

target_known() {
    local needle="$1"
    local target
    for target in "${AFL_TARGETS[@]}"; do
        if [[ "$target" == "$needle" ]]; then
            return 0
        fi
    done
    return 1
}

sanitize_key() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9_.+-' '-'
}

update_latest_report_link() {
    local report_abs generated_abs link_name link_path

    report_abs="$(cd "$REPORT_ROOT" && pwd)"
    generated_abs="$(cd "$AFL_BASE/reports/generated" && pwd)"
    case "$report_abs" in
        "$generated_abs"/*) ;;
        *) return 0 ;;
    esac

    link_name="$(basename "$report_abs")"
    link_path="$generated_abs/latest"
    if [[ -e "$link_path" && ! -L "$link_path" ]]; then
        echo "WARN: latest report path exists and is not a symlink: $link_path" >&2
        return 0
    fi
    ln -sfn "$link_name" "$link_path"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        all) TARGET_FILTER=""; shift ;;
        --report-root) REPORT_ROOT="${2:-}"; shift 2 ;;
        --jobs)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
                echo "ERROR: --jobs requires a positive integer" >&2
                exit 1
            fi
            JOBS="$2"
            shift 2
            ;;
        --target-jobs)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
                echo "ERROR: --target-jobs requires a positive integer" >&2
                exit 1
            fi
            TARGET_JOBS="$2"
            shift 2
            ;;
        --no-coverage) RUN_COVERAGE=0; shift ;;
        --stats-only)
            RUN_COVERAGE=0
            RUN_MAPS=0
            RUN_TRIAGE=0
            shift
            ;;
        --marked-only)
            MARKED_ONLY=1
            RUN_COVERAGE=0
            RUN_MAPS=0
            RUN_TRIAGE=1
            shift
            ;;
        --no-reachability) RUN_REACHABILITY=0; shift ;;
        --fresh-build) REUSE_BUILD=0; shift ;;
        --reuse-build) REUSE_BUILD=1; shift ;;
        --coverage-timeout)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
                echo "ERROR: --coverage-timeout requires a positive integer" >&2
                exit 1
            fi
            COVERAGE_TIMEOUT="$2"
            shift 2
            ;;
        --target-timeout)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --target-timeout requires a non-negative integer" >&2
                exit 1
            fi
            TARGET_TIMEOUT="$2"
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        -*) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 1 ;;
        *) TARGET_FILTER="$1"; shift ;;
    esac
done

if [[ -n "$TARGET_FILTER" ]] && ! target_known "$TARGET_FILTER"; then
    echo "ERROR: Unknown target '$TARGET_FILTER'" >&2
    afl_print_targets >&2
    exit 1
fi

mkdir -p "$REPORT_ROOT"/{maps,triage,coverage,logs,target-rows}
mkdir -p "$AFL_BASE/reports/generated"
update_latest_report_link

STATUS_JSON="$REPORT_ROOT/status.json"
INDEX_MD="$REPORT_ROOT/index.md"
TARGETS_TSV="$REPORT_ROOT/targets.tsv"
SUMMARY_TSV="$REPORT_ROOT/summary.tsv"
TARGET_ROWS_DIR="$REPORT_ROOT/target-rows"

if [[ -n "$TARGET_FILTER" ]]; then
    "$REPO_ROOT/afl/status.sh" "$TARGET_FILTER" --json > "$STATUS_JSON"
else
    "$REPO_ROOT/afl/status.sh" all --json > "$STATUS_JSON"
fi

printf 'target\tstate\tqueue\tstats\tmap\ttriage\tcoverage\treachability\tstatic_reachable\tstatic_unreachable\tcovered\tnot_covered_reachable\tcovered_unreachable\tprofdata\n' > "$TARGETS_TSV"

targets=()
if [[ -n "$TARGET_FILTER" ]]; then
    targets=("$TARGET_FILTER")
else
    targets=("${AFL_TARGETS[@]}")
fi

process_target() {
    local target="$1"
    local row_file="$2"
    echo "[INFO] Reporting target: $target" >&2

    set +eu
    afl_configure_target "$target" >/dev/null 2>&1
    set -eu
    if [[ -z "${AFL_DIR:-}" || -z "${BINARY:-}" ]]; then
        printf '%s\tnot_configured\t\t\t\t\t\t\t\t\t\t\t\n' "$target" > "$row_file"
        echo "[WARN] Target not configured: $target" >&2
        return 0
    fi

    local output_dir tool_bin_name coverage_cache_key instance child
    local queue_dir stats_file map_file triage_file coverage_dir reachability_file
    local static_reachable_file static_unreachable_file covered_file
    local not_covered_reachable_file covered_unreachable_file profdata_file

    output_dir="$AFL_DIR/output"
    tool_bin_name="$(basename "$BINARY")"
    coverage_cache_key="$(sanitize_key "${AFL_COVERAGE_CACHE_KEY:-$tool_bin_name}")"
    instance="default"
    if [[ -f "$output_dir/main/fuzzer_stats" ]]; then
        instance="main"
    elif [[ -f "$output_dir/default/fuzzer_stats" ]]; then
        instance="default"
    else
        while IFS= read -r -d '' child; do
            if [[ -f "$child/fuzzer_stats" ]]; then
                instance="$(basename "$child")"
                break
            fi
        done < <(find "$output_dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | sort -z || true)
    fi

    queue_dir="$output_dir/$instance/queue"
    stats_file="$output_dir/$instance/fuzzer_stats"
    map_file=""
    triage_file=""
    coverage_dir=""
    reachability_file=""
    static_reachable_file=""
    static_unreachable_file=""
    covered_file=""
    not_covered_reachable_file=""
    covered_unreachable_file=""
    profdata_file=""

    if [[ ! -d "$queue_dir" || ! -f "$stats_file" ]]; then
        printf '%s\tnot_started\t\t\t\t\t\t\t\t\t\t\t\n' "$target" > "$row_file"
        echo "[INFO] Target has no AFL output: $target" >&2
        return 0
    fi

    map_file="$REPORT_ROOT/maps/$target-showmap.txt"
    triage_file="$REPORT_ROOT/triage/$target-triage.txt"

    if [[ "$RUN_MAPS" -eq 1 ]]; then
        if "$REPO_ROOT/afl/map.sh" "$target" --instance "$instance" --queue --out "$map_file" > "$REPORT_ROOT/logs/$target-map.log" 2>&1; then
            :
        else
            echo "WARN: map failed for $target; see $REPORT_ROOT/logs/$target-map.log" >&2
        fi
    else
        map_file=""
    fi

    if [[ "$RUN_TRIAGE" -eq 1 ]]; then
        local triage_input_dir=""
        if [[ "$MARKED_ONLY" -eq 1 ]]; then
            triage_input_dir="$AFL_BASE/marked/$target"
        fi
        if [[ "$MARKED_ONLY" -eq 0 || -d "$triage_input_dir" ]]; then
            if AFL_TRIAGE_INPUT_DIR="${triage_input_dir:-}" "$REPO_ROOT/afl/triage.sh" "$target" > "$triage_file" 2>&1; then
                :
            else
                echo "WARN: triage failed for $target; see $triage_file" >&2
            fi
        elif [[ "$MARKED_ONLY" -eq 1 ]]; then
            echo "No marked artifacts for $target" > "$triage_file"
            :
        fi
    else
        triage_file=""
    fi

    if [[ "$RUN_COVERAGE" -eq 1 ]]; then
        local coverage_args coverage_log coverage_exit
        coverage_args=("$target" "--report-root" "$REPORT_ROOT/coverage" "--report-name" "$target" "--instance" "$instance" "--jobs" "$JOBS")
        coverage_log="$REPORT_ROOT/logs/$target-coverage.log"
        coverage_exit=0
        if [[ "$RUN_REACHABILITY" -eq 0 ]]; then
            coverage_args+=("--no-reachability")
        fi
        if [[ "$REUSE_BUILD" -eq 1 ]]; then
            coverage_args+=("--reuse-build")
        fi
        if [[ "$TARGET_TIMEOUT" -gt 0 ]]; then
            AFL_COVERAGE_TIMEOUT="$COVERAGE_TIMEOUT" timeout "$TARGET_TIMEOUT" "$REPO_ROOT/afl/coverage.sh" "${coverage_args[@]}" > "$coverage_log" 2>&1 || coverage_exit=$?
        else
            AFL_COVERAGE_TIMEOUT="$COVERAGE_TIMEOUT" "$REPO_ROOT/afl/coverage.sh" "${coverage_args[@]}" > "$coverage_log" 2>&1 || coverage_exit=$?
        fi
        if [[ "$coverage_exit" -eq 0 ]]; then
            coverage_dir="$REPORT_ROOT/coverage/cov-$target-static"
            profdata_file="$coverage_dir/coverage.profdata"
            covered_file="$REPORT_ROOT/coverage/covered-$target.txt"
            if [[ "$RUN_REACHABILITY" -eq 1 ]]; then
                reachability_file="$REPORT_ROOT/coverage/reachability-$coverage_cache_key-static.json"
                static_reachable_file="$REPORT_ROOT/coverage/statically_reachable-$coverage_cache_key.txt"
                static_unreachable_file="$REPORT_ROOT/coverage/statically_unreachable-$coverage_cache_key.txt"
                not_covered_reachable_file="$REPORT_ROOT/coverage/not_covered_but_statically_reachable-$target.txt"
                covered_unreachable_file="$REPORT_ROOT/coverage/covered_but_statically_unreachable-$target.txt"
            fi
        elif [[ "$coverage_exit" -eq 124 ]]; then
            echo "WARN: coverage timed out for $target after ${TARGET_TIMEOUT}s; see $coverage_log" >&2
        else
            echo "WARN: coverage failed for $target (exit=$coverage_exit); see $coverage_log" >&2
        fi
    fi

    printf '%s\treported\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$target" "$queue_dir" "$stats_file" "$map_file" "$triage_file" \
        "$coverage_dir" "$reachability_file" "$static_reachable_file" \
        "$static_unreachable_file" "$covered_file" "$not_covered_reachable_file" \
        "$covered_unreachable_file" "$profdata_file" > "$row_file"
    echo "[INFO] Finished target: $target" >&2
}

active_jobs=0
target_failures=0

for i in "${!targets[@]}"; do
    target="${targets[$i]}"
    row_file="$TARGET_ROWS_DIR/$(printf '%04d' "$i")-$(sanitize_key "$target").tsv"

    if [[ "$TARGET_JOBS" -le 1 ]]; then
        if ! process_target "$target" "$row_file"; then
            target_failures=1
        fi
        continue
    fi

    process_target "$target" "$row_file" &
    active_jobs=$((active_jobs + 1))
    if [[ "$active_jobs" -ge "$TARGET_JOBS" ]]; then
        if ! wait -n; then
            target_failures=1
        fi
        active_jobs=$((active_jobs - 1))
    fi
done

while [[ "$active_jobs" -gt 0 ]]; do
    if ! wait -n; then
        target_failures=1
    fi
    active_jobs=$((active_jobs - 1))
done

while IFS= read -r row_file; do
    cat "$row_file" >> "$TARGETS_TSV"
done < <(find "$TARGET_ROWS_DIR" -maxdepth 1 -type f -name '*.tsv' | sort)

write_summary_tsv() {
    {
        printf 'metric\tvalue\n'
        printf 'targets_total\t%s\n' "$(tail -n +2 "$TARGETS_TSV" | wc -l)"
        awk -F '\t' '
            NR > 1 {
                state[$2]++
                if ($5 != "") maps++
                if ($6 != "") triage++
                if ($7 != "") coverage++
                if ($8 != "") reachability++
                if ($14 != "") profdata++
            }
            END {
                printf "targets_reported\t%d\n", state["reported"] + 0
                printf "targets_not_started\t%d\n", state["not_started"] + 0
                printf "targets_not_configured\t%d\n", state["not_configured"] + 0
                printf "map_artifacts\t%d\n", maps + 0
                printf "triage_artifacts\t%d\n", triage + 0
                printf "coverage_artifacts\t%d\n", coverage + 0
                printf "reachability_artifacts\t%d\n", reachability + 0
                printf "profdata_artifacts\t%d\n", profdata + 0
            }
        ' "$TARGETS_TSV"
        printf 'coverage_enabled\t%s\n' "$RUN_COVERAGE"
        printf 'reachability_enabled\t%s\n' "$RUN_REACHABILITY"
        printf 'map_enabled\t%s\n' "$RUN_MAPS"
        printf 'triage_enabled\t%s\n' "$RUN_TRIAGE"
        printf 'coverage_jobs\t%s\n' "$JOBS"
        printf 'target_jobs\t%s\n' "$TARGET_JOBS"
        printf 'target_timeout_seconds\t%s\n' "$TARGET_TIMEOUT"
        printf 'coverage_timeout_seconds\t%s\n' "$COVERAGE_TIMEOUT"
    } > "$SUMMARY_TSV"
}

write_summary_tsv

if [[ "$target_failures" -ne 0 ]]; then
    echo "WARN: one or more target report jobs failed; see logs under $REPORT_ROOT/logs" >&2
fi

{
    echo "# AFL Report"
    echo ""
    echo "- Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "- Repo: $REPO_ROOT"
    echo "- AFL base: $AFL_BASE"
    echo "- Report root: $REPORT_ROOT"
    echo "- Status JSON: $STATUS_JSON"
    echo "- Target TSV: $TARGETS_TSV"
    echo "- Summary TSV: $SUMMARY_TSV"
    if [[ "$RUN_MAPS" -eq 0 && "$RUN_TRIAGE" -eq 0 && "$RUN_COVERAGE" -eq 0 ]]; then
        echo "- Mode: stats-only"
    elif [[ "$MARKED_ONLY" -eq 1 ]]; then
        echo "- Mode: marked-only triage"
    fi
    if [[ "$RUN_COVERAGE" -eq 1 ]]; then
        echo "- Coverage build reuse: $([[ "$REUSE_BUILD" -eq 1 ]] && printf 'enabled' || printf 'disabled')"
        echo "- Per-target coverage jobs: $JOBS"
        echo "- Concurrent target jobs: $TARGET_JOBS"
        echo "- Coverage timeout: ${COVERAGE_TIMEOUT}s"
        echo "- Target timeout: $([[ "$TARGET_TIMEOUT" -gt 0 ]] && printf '%ss' "$TARGET_TIMEOUT" || printf 'disabled')"
    fi
    echo ""
    echo "## Summary"
    echo ""
    echo "| Metric | Value |"
    echo "|---|---:|"
    tail -n +2 "$SUMMARY_TSV" | while IFS=$'\t' read -r metric value; do
        printf "| \`%s\` | %s |\n" "$metric" "$value"
    done
    echo ""
    echo "| Target | State | Stats | Map | Triage | Coverage | Reachability | Runtime lists | Profdata |"
    echo "|---|---|---|---|---|---|---|---|---|"
    tail -n +2 "$TARGETS_TSV" | while IFS=$'\t' read -r target state queue stats map triage coverage reachability static_reachable static_unreachable covered not_covered_reachable covered_unreachable profdata; do
        runtime_lists=""
        if [[ -n "$covered" ]]; then
            runtime_lists+="covered: \`$covered\`"
        fi
        if [[ -n "$not_covered_reachable" ]]; then
            [[ -n "$runtime_lists" ]] && runtime_lists+="<br>"
            runtime_lists+="not covered reachable: \`$not_covered_reachable\`"
        fi
        if [[ -n "$covered_unreachable" ]]; then
            [[ -n "$runtime_lists" ]] && runtime_lists+="<br>"
            runtime_lists+="covered unreachable: \`$covered_unreachable\`"
        fi
        printf "| \`%s\` | %s | %s | %s | %s | %s | %s | %s | %s |\n" \
            "$target" "$state" \
            "$([[ -n "$stats" ]] && printf "\`%s\`" "$stats" || printf '-')" \
            "$([[ -n "$map" ]] && printf "\`%s\`" "$map" || printf '-')" \
            "$([[ -n "$triage" ]] && printf "\`%s\`" "$triage" || printf '-')" \
            "$([[ -n "$coverage" ]] && printf "\`%s\`" "$coverage" || printf '-')" \
            "$([[ -n "$reachability" ]] && printf "\`%s\`<br>static reachable: \`%s\`<br>static unreachable: \`%s\`" "$reachability" "$static_reachable" "$static_unreachable" || printf '-')" \
            "$([[ -n "$runtime_lists" ]] && printf '%s' "$runtime_lists" || printf '-')" \
            "$([[ -n "$profdata" ]] && printf "\`%s\`" "$profdata" || printf '-')"
    done
} > "$INDEX_MD"

echo "[OK] AFL report complete"
echo "     Index:  $INDEX_MD"
echo "     Status: $STATUS_JSON"
echo "     TSV:    $TARGETS_TSV"
echo "     Summary: $SUMMARY_TSV"
