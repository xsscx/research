#!/usr/bin/env bash
# Write a minimized native FuzzTest corpus to a separate canonical tree.
#
# Usage: ./minimize-corpus.sh [--seconds N] [--target SUITE.TEST|all]
#                             [--jobs N] [--source DIR] [--output DIR]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${ICC_FUZZTEST_BUILD_DIR:-$SCRIPT_DIR/build}"
BINARY="$BUILD_DIR/icc_profile_fuzz_test"
BINARY_NAME="${BINARY##*/}"
SECONDS_TO_RUN="${ICC_FUZZTEST_MINIMIZE_SECONDS:-300}"
TARGET="${ICC_FUZZTEST_TARGET:-all}"
RUN_JOBS="${ICC_FUZZTEST_RUN_JOBS:-0}"
SOURCE_DIR="${ICC_FUZZTEST_CORPUS_DIR:-$SCRIPT_DIR/corpus}"
OUTPUT_DIR="${ICC_FUZZTEST_MINIMIZED_CORPUS_DIR:-}"

usage() {
    sed -n '2,6p' "$0" | sed 's/^# \?//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --seconds)
            if [[ $# -lt 2 || ! "$2" =~ ^[1-9][0-9]*$ ]]; then
                echo "[FAIL] --seconds requires a positive integer" >&2
                exit 1
            fi
            SECONDS_TO_RUN="$2"
            shift 2
            ;;
        --target)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "[FAIL] --target requires a FuzzTest name" >&2
                exit 1
            fi
            TARGET="$2"
            shift 2
            ;;
        --jobs)
            if [[ $# -lt 2 || ! "$2" =~ ^[1-9][0-9]*$ ]]; then
                echo "[FAIL] --jobs requires a positive integer" >&2
                exit 1
            fi
            RUN_JOBS="$2"
            shift 2
            ;;
        --source)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "[FAIL] --source requires a directory" >&2
                exit 1
            fi
            SOURCE_DIR="$2"
            shift 2
            ;;
        --output)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "[FAIL] --output requires a directory" >&2
                exit 1
            fi
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[FAIL] unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ ! "$RUN_JOBS" =~ ^[0-9]+$ ]]; then
    echo "[FAIL] ICC_FUZZTEST_RUN_JOBS must be zero or a positive integer" >&2
    exit 1
fi
if [[ ! -x "$BINARY" ]]; then
    echo "[FAIL] missing binary: $BINARY" >&2
    echo "       Run ./fuzztest/build.sh first." >&2
    exit 1
fi
if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "[FAIL] source corpus does not exist: $SOURCE_DIR" >&2
    exit 1
fi
if [[ -z "$OUTPUT_DIR" ]]; then
    run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    OUTPUT_DIR="$SCRIPT_DIR/corpus-minimized-$run_id"
fi
if [[ "$SOURCE_DIR" == "$OUTPUT_DIR" ]]; then
    echo "[FAIL] source and output corpus directories must differ" >&2
    exit 1
fi
if [[ -d "$OUTPUT_DIR" ]] &&
   [[ -n "$(find "$OUTPUT_DIR" -mindepth 1 -print -quit)" ]]; then
    echo "[FAIL] refusing to overwrite non-empty output: $OUTPUT_DIR" >&2
    exit 1
fi

export ICC_FUZZTEST_REPO_ROOT="$REPO_ROOT"
export ICC_FUZZTEST_SEED_MANIFEST="$SCRIPT_DIR/seeds.txt"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0,halt_on_error=1,abort_on_error=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1,print_stacktrace=1}"

mapfile -t AVAILABLE_TARGETS < <(
    "$BINARY" --list_fuzz_tests 2>&1 |
        sed -n 's/^\[\*\] Fuzz test: //p'
)
if [[ "$TARGET" == "all" ]]; then
    CANDIDATE_TARGETS=("${AVAILABLE_TARGETS[@]}")
else
    CANDIDATE_TARGETS=()
    for available_target in "${AVAILABLE_TARGETS[@]}"; do
        if [[ "$available_target" == "$TARGET" ]]; then
            CANDIDATE_TARGETS+=("$TARGET")
            break
        fi
    done
    if [[ ${#CANDIDATE_TARGETS[@]} -eq 0 ]]; then
        echo "[FAIL] unknown fuzz target: $TARGET" >&2
        exit 1
    fi
fi

RUN_TARGETS=()
SOURCE_COUNTS=()
for run_target in "${CANDIDATE_TARGETS[@]}"; do
    target_source="$SOURCE_DIR/$BINARY_NAME/$run_target/coverage"
    source_count=0
    if [[ -d "$target_source" ]]; then
        source_count="$(find "$target_source" -type f | wc -l)"
    fi
    if (( source_count == 0 )); then
        echo "[SKIP] No corpus inputs for $run_target"
        continue
    fi
    RUN_TARGETS+=("$run_target")
    SOURCE_COUNTS+=("$source_count")
done
if [[ ${#RUN_TARGETS[@]} -eq 0 ]]; then
    echo "[FAIL] no populated target corpora found below $SOURCE_DIR" >&2
    exit 1
fi

target_count=${#RUN_TARGETS[@]}
if (( RUN_JOBS == 0 )); then
    RUN_JOBS=$(nproc)
fi
if (( RUN_JOBS > target_count )); then
    RUN_JOBS=$target_count
fi
base_seconds=$((SECONDS_TO_RUN / target_count))
extra_seconds=$((SECONDS_TO_RUN % target_count))
if (( base_seconds == 0 )); then
    base_seconds=1
    extra_seconds=0
fi

mkdir -p "$OUTPUT_DIR"
log_dir="$SCRIPT_DIR/logs/minimize-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$log_dir"
summary_file="$log_dir/summary.tsv"
printf 'target\tbudget_seconds\texit_status\tsource_files\toutput_files\n' \
    >"$summary_file"

run_minimizer() {
    local run_target="$1"
    local target_seconds="$2"
    local target_log="$3"
    local target_source="$SOURCE_DIR/$BINARY_NAME/$run_target/coverage"
    local target_output="$OUTPUT_DIR/$BINARY_NAME/$run_target/coverage"

    mkdir -p "$target_output"
    exec env \
        FUZZTEST_MINIMIZE_TESTSUITE_DIR="$target_source" \
        FUZZTEST_TESTSUITE_OUT_DIR="$target_output" \
        timeout --kill-after=10s "$((target_seconds + 60))s" "$BINARY" \
        "--fuzz=$run_target" \
        "--fuzz_for=${target_seconds}s" \
        --corpus_database= \
        --rss_limit_mb=4096 \
        --stack_limit_kb=1024 \
        --time_limit_per_input=30s >"$target_log" 2>&1
}

echo "[*] Minimizing $target_count target corpus/corpora with $RUN_JOBS parallel job(s)"
overall_status=0
pids=()
cleanup_children() {
    local pid

    trap - HUP INT TERM
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    wait || true
    exit 130
}
trap cleanup_children HUP INT TERM

for ((batch_start = 0; batch_start < target_count; batch_start += RUN_JOBS)); do
    pids=()
    indices=()
    batch_end=$((batch_start + RUN_JOBS))
    if (( batch_end > target_count )); then
        batch_end=$target_count
    fi

    for ((target_index = batch_start; target_index < batch_end; ++target_index)); do
        run_target="${RUN_TARGETS[target_index]}"
        target_seconds="$base_seconds"
        if (( target_index < extra_seconds )); then
            target_seconds=$((target_seconds + 1))
        fi
        target_log="$log_dir/${run_target//[^[:alnum:]_-]/_}.log"
        run_minimizer "$run_target" "$target_seconds" "$target_log" &
        pids+=("$!")
        indices+=("$target_index")
    done

    for ((batch_index = 0; batch_index < ${#pids[@]}; ++batch_index)); do
        target_index="${indices[batch_index]}"
        run_target="${RUN_TARGETS[target_index]}"
        target_seconds="$base_seconds"
        if (( target_index < extra_seconds )); then
            target_seconds=$((target_seconds + 1))
        fi
        target_log="$log_dir/${run_target//[^[:alnum:]_-]/_}.log"
        set +e
        wait "${pids[batch_index]}"
        status=$?
        set -e
        sed -n '1,$p' "$target_log"
        target_output="$OUTPUT_DIR/$BINARY_NAME/$run_target/coverage"
        output_count="$(find "$target_output" -type f | wc -l)"
        source_count="${SOURCE_COUNTS[target_index]}"
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$run_target" "$target_seconds" "$status" \
            "$source_count" "$output_count" >>"$summary_file"
        if [[ "$status" != "0" || "$output_count" == "0" ||
              "$output_count" -gt "$source_count" ]]; then
            overall_status=1
        fi
    done
done
trap - HUP INT TERM

if [[ "$overall_status" != "0" ]]; then
    echo "[FAIL] Corpus minimization failed verification" >&2
    echo "       Partial output preserved at: $OUTPUT_DIR" >&2
    echo "       Logs: $log_dir" >&2
    exit 1
fi

echo "[OK] Minimized corpus: $OUTPUT_DIR"
echo "[OK] Verification summary: $summary_file"
echo "[*] Source corpus was not modified; inspect the summary before swapping."
