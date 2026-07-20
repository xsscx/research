#!/bin/bash
# afl/run-all.sh - Run AFL++ targets from a fresh state, then report
#
# Usage: ./afl/run-all.sh [target|all] [--seconds N] [--report-root DIR]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
SECONDS_PER_TARGET="${AFL_RUN_ALL_SECONDS:-300}"
REPORT_ROOT="${AFL_RUN_ALL_REPORT_ROOT:-$AFL_BASE/reports/generated/afl-report-$(date -u +%Y%m%dT%H%M%SZ)}"
JOBS="${AFL_RUN_ALL_JOBS:-2}"
REPORT_TARGET_TIMEOUT="${AFL_RUN_ALL_REPORT_TARGET_TIMEOUT:-${AFL_REPORT_TARGET_TIMEOUT:-3600}}"
PARALLEL="${AFL_RUN_ALL_PARALLEL:-1}"
SCHEDULE="${AFL_RUN_ALL_SCHEDULE:-}"
MOPT_SECS="${AFL_RUN_ALL_MOPT_SECS:-}"
FRESH_MODE="${AFL_RUN_ALL_FRESH:-1}"
RESEED="${AFL_RUN_ALL_RESEED:-0}"
CMPLOG_AUTO="${AFL_RUN_ALL_CMPLOG_AUTO:-0}"
TESTCACHE_SIZE="${AFL_RUN_ALL_TESTCACHE_SIZE:-256}"
RUN_ALL_SEED_LIMIT="${AFL_RUN_ALL_SEED_LIMIT:-}"
RUN_ALL_SEED_MAX_BYTES="${AFL_RUN_ALL_SEED_MAX_BYTES:-}"
RUN_REPORT=1
RUN_COVERAGE=1
TARGET_FILTER=""
FILTER_NOT_STARTED=0
LOW_COVERAGE=""
DRY_RUN=0

source "$REPO_ROOT/afl/targets.sh"

usage() {
    sed -n '2,5p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  --seconds N       AFL_RUN_TIME per target; default ${SECONDS_PER_TARGET}"
    echo "  --report-root DIR write logs and generated report under DIR"
    echo "  --jobs N          report coverage replay/build jobs; default ${JOBS}"
    echo "  --report-target-timeout N  per-target report coverage timeout in seconds; 0 disables; default ${REPORT_TARGET_TIMEOUT}"
    echo "  --parallel N      AFL instances per target; default ${PARALLEL}"
    echo "  --schedule NAME   set AFL_POWER_SCHEDULE, for example rare or explore"
    echo "  --mopt-secs N     set AFL_MOPT_SECS for each target"
    echo "  --fresh           archive input/output before each target; default"
    echo "  --resume          resume existing queues instead of archiving outputs"
    echo "  --reseed          add configured target seeds before starting each target"
    echo "  --cmplog-auto     use matching afl/bin-cmplog binary when available"
    echo "  --testcache-size N  set AFL_TESTCACHE_SIZE in MB; default ${TESTCACHE_SIZE}"
    echo "  --seed-limit N    override per-directory seed sample size"
    echo "  --seed-max-bytes N  override target maximum seed size"
    echo "  --coverage-boost  preset: --resume --reseed --cmplog-auto --schedule rare --mopt-secs 0"
    echo "  --not-started     run only targets without existing fuzzer_stats"
    echo "  --low-coverage N  run only targets with best bitmap coverage below N percent"
    echo "  --no-report       run fuzzers only"
    echo "  --no-coverage     report stats/maps/triage only"
    echo "  --dry-run         print targets and commands without running"
    echo "  --help, -h        show help"
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

target_has_stats() {
    local output_dir="$1"
    find "$output_dir" -mindepth 2 -maxdepth 2 -name fuzzer_stats -type f -print -quit 2>/dev/null | grep -q .
}

target_best_bitmap() {
    local output_dir="$1"
    local stats value best="0"

    while IFS= read -r -d '' stats; do
        value="$(stat_value "$stats" bitmap_cvg)"
        value="${value%\%}"
        if [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            best="$(awk -v a="$best" -v b="$value" 'BEGIN { print (b > a) ? b : a }')"
        fi
    done < <(find "$output_dir" -mindepth 2 -maxdepth 2 -name fuzzer_stats -type f -print0 2>/dev/null || true)

    printf '%s' "$best"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        all) TARGET_FILTER=""; shift ;;
        --seconds)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
                echo "ERROR: --seconds requires a positive integer" >&2
                exit 1
            fi
            SECONDS_PER_TARGET="$2"
            shift 2
            ;;
        --report-root) REPORT_ROOT="${2:-}"; shift 2 ;;
        --jobs)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
                echo "ERROR: --jobs requires a positive integer" >&2
                exit 1
            fi
            JOBS="$2"
            shift 2
            ;;
        --report-target-timeout)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --report-target-timeout requires a non-negative integer" >&2
                exit 1
            fi
            REPORT_TARGET_TIMEOUT="$2"
            shift 2
            ;;
        --parallel)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
                echo "ERROR: --parallel requires a positive integer" >&2
                exit 1
            fi
            PARALLEL="$2"
            shift 2
            ;;
        --schedule) SCHEDULE="${2:-}"; shift 2 ;;
        --mopt-secs)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --mopt-secs requires a non-negative integer" >&2
                exit 1
            fi
            MOPT_SECS="$2"
            shift 2
            ;;
        --fresh) FRESH_MODE=1; shift ;;
        --resume) FRESH_MODE=0; shift ;;
        --reseed) RESEED=1; shift ;;
        --cmplog-auto) CMPLOG_AUTO=1; shift ;;
        --testcache-size)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --testcache-size requires a non-negative integer" >&2
                exit 1
            fi
            TESTCACHE_SIZE="$2"
            shift 2
            ;;
        --seed-limit)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --seed-limit requires a non-negative integer" >&2
                exit 1
            fi
            RUN_ALL_SEED_LIMIT="$2"
            shift 2
            ;;
        --seed-max-bytes)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --seed-max-bytes requires a non-negative integer" >&2
                exit 1
            fi
            RUN_ALL_SEED_MAX_BYTES="$2"
            shift 2
            ;;
        --coverage-boost)
            FRESH_MODE=0
            RESEED=1
            CMPLOG_AUTO=1
            [[ -z "$SCHEDULE" ]] && SCHEDULE="rare"
            [[ -z "$MOPT_SECS" ]] && MOPT_SECS="0"
            shift
            ;;
        --not-started) FILTER_NOT_STARTED=1; shift ;;
        --low-coverage)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
                echo "ERROR: --low-coverage requires a numeric percent threshold" >&2
                exit 1
            fi
            LOW_COVERAGE="$2"
            shift 2
            ;;
        --no-report) RUN_REPORT=0; shift ;;
        --no-coverage) RUN_COVERAGE=0; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
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

targets=()
if [[ -n "$TARGET_FILTER" ]]; then
    targets=("$TARGET_FILTER")
else
    for target in "${AFL_TARGETS[@]}"; do
        set +eu
        afl_configure_target "$target" >/dev/null 2>&1
        set -eu
        if [[ -z "${AFL_DIR:-}" ]]; then
            continue
        fi
        if [[ "$FILTER_NOT_STARTED" -eq 1 ]] && target_has_stats "$AFL_DIR/output"; then
            continue
        fi
        if [[ -n "$LOW_COVERAGE" ]]; then
            best_bitmap="$(target_best_bitmap "$AFL_DIR/output")"
            if ! awk -v best="$best_bitmap" -v limit="$LOW_COVERAGE" 'BEGIN { exit(best < limit ? 0 : 1) }'; then
                continue
            fi
        fi
        targets+=("$target")
    done
fi

mkdir -p "$REPORT_ROOT/logs"

echo "[*] AFL run-all"
echo "    Targets: ${#targets[@]}"
echo "    Seconds: $SECONDS_PER_TARGET per target"
echo "    Parallel: $PARALLEL instance(s)"
if [[ "$FRESH_MODE" -eq 0 ]]; then
    echo "    Mode: resume existing queues"
else
    echo "    Mode: fresh archived runs"
fi
if [[ -n "$SCHEDULE" ]]; then
    echo "    Schedule: $SCHEDULE"
fi
if [[ -n "$MOPT_SECS" ]]; then
    echo "    MOpt: $MOPT_SECS"
fi
if [[ "$RESEED" -ne 0 ]]; then
    echo "    Reseed: enabled"
fi
if [[ "$CMPLOG_AUTO" -ne 0 ]]; then
    echo "    CmpLog auto: enabled"
fi
if [[ "$TESTCACHE_SIZE" != "0" ]]; then
    echo "    Test cache: ${TESTCACHE_SIZE} MB"
fi
if [[ "$FILTER_NOT_STARTED" -eq 1 ]]; then
    echo "    Filter: not-started"
fi
if [[ -n "$LOW_COVERAGE" ]]; then
    echo "    Filter: best bitmap coverage < ${LOW_COVERAGE}%"
fi
echo "    AFL base: $AFL_BASE"
echo "    Report root: $REPORT_ROOT"

for target in "${targets[@]}"; do
    log="$REPORT_ROOT/logs/$target-fuzz.log"
    cmd=(env AFL_BASE="$AFL_BASE" AFL_FRESH="$FRESH_MODE" AFL_RESEED="$RESEED" AFL_RUN_TIME="$SECONDS_PER_TARGET" AFL_NO_UI=1 AFL_TESTCACHE_SIZE="$TESTCACHE_SIZE")
    if [[ -n "$SCHEDULE" ]]; then
        cmd+=(AFL_POWER_SCHEDULE="$SCHEDULE")
    fi
    if [[ -n "$MOPT_SECS" ]]; then
        cmd+=(AFL_MOPT_SECS="$MOPT_SECS")
    fi
    if [[ "$CMPLOG_AUTO" -ne 0 ]]; then
        cmd+=(AFL_CMPLOG_AUTO=1 AFL_CMPLOG_ONLY_NEW="${AFL_CMPLOG_ONLY_NEW:-1}")
    fi
    if [[ -n "$RUN_ALL_SEED_LIMIT" ]]; then
        cmd+=(AFL_SEED_LIMIT="$RUN_ALL_SEED_LIMIT")
    fi
    if [[ -n "$RUN_ALL_SEED_MAX_BYTES" ]]; then
        cmd+=(AFL_SEED_MAX_BYTES="$RUN_ALL_SEED_MAX_BYTES")
    fi
    cmd+=("$REPO_ROOT/afl/start.sh" "$target")
    if [[ "$PARALLEL" -gt 1 ]]; then
        cmd+=("--parallel" "$PARALLEL")
    fi
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '[dry-run] '
        printf '%q ' "${cmd[@]}"
        printf '\n'
        continue
    fi

    echo "[*] Running $target for ${SECONDS_PER_TARGET}s"
    if "${cmd[@]}" > "$log" 2>&1; then
        echo "    log: $log"
    else
        echo "WARN: $target failed; see $log" >&2
    fi
done

if [[ "$DRY_RUN" -eq 1 || "$RUN_REPORT" -eq 0 ]]; then
    exit 0
fi

report_args=(all "--report-root" "$REPORT_ROOT" "--jobs" "$JOBS")
if [[ "$RUN_COVERAGE" -eq 0 ]]; then
    report_args+=("--no-coverage")
else
    report_args+=("--target-timeout" "$REPORT_TARGET_TIMEOUT")
fi

"$REPO_ROOT/afl/report.sh" "${report_args[@]}"
