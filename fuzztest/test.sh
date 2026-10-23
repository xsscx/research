#!/usr/bin/env bash
# Run the ICC FuzzTest unit checks or a bounded coverage-guided smoke test.
#
# Usage: ./test.sh [--mode fuzzing|unit|libfuzzer] [--seconds N]
#                  [--target SUITE.TEST|all] [--jobs N] [--replay-inputs N]
#                  [--log-dir DIR]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MODE="${ICC_FUZZTEST_MODE:-fuzzing}"
SECONDS_TO_RUN="${ICC_FUZZTEST_SECONDS:-60}"
TARGET="${ICC_FUZZTEST_TARGET:-all}"
RUN_JOBS="${ICC_FUZZTEST_RUN_JOBS:-0}"
LOG_DIR="${ICC_FUZZTEST_LOG_DIR:-}"
MAX_REPLAY_INPUTS="${ICC_FUZZTEST_REPLAY_INPUTS:-64}"
FRAMEWORK_DIR="${ICC_FUZZTEST_FRAMEWORK_DIR:-$SCRIPT_DIR/upstream}"
ICCDEV_DIR="${ICC_FUZZTEST_ICCDEV_DIR:-$SCRIPT_DIR/iccDEV}"
LIBFUZZER_MAX_LEN=4194432

usage() {
    sed -n '2,6p' "$0" | sed 's/^# \?//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            if [[ $# -lt 2 ]]; then
                echo "[FAIL] --mode requires fuzzing, unit, or libfuzzer" >&2
                exit 1
            fi
            MODE="$2"
            shift 2
            ;;
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
        --log-dir)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "[FAIL] --log-dir requires a directory" >&2
                exit 1
            fi
            LOG_DIR="$2"
            shift 2
            ;;
        --replay-inputs)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "[FAIL] --replay-inputs requires a non-negative integer" >&2
                exit 1
            fi
            MAX_REPLAY_INPUTS="$2"
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
if [[ ! "$MAX_REPLAY_INPUTS" =~ ^[0-9]+$ ]]; then
    echo "[FAIL] ICC_FUZZTEST_REPLAY_INPUTS must be a non-negative integer" >&2
    exit 1
fi
if [[ "$MODE" == "fuzzing" ]] && ! command -v shuf >/dev/null 2>&1; then
    echo "[FAIL] required tool not found: shuf" >&2
    exit 1
fi

case "$MODE" in
    fuzzing) BUILD_DIR="${ICC_FUZZTEST_BUILD_DIR:-$SCRIPT_DIR/build}" ;;
    unit) BUILD_DIR="${ICC_FUZZTEST_BUILD_DIR:-$SCRIPT_DIR/build-unit}" ;;
    libfuzzer) BUILD_DIR="${ICC_FUZZTEST_BUILD_DIR:-$SCRIPT_DIR/build-libfuzzer}" ;;
    *)
        echo "[FAIL] unsupported mode '$MODE' (use fuzzing, unit, or libfuzzer)" >&2
        exit 1
        ;;
esac

BINARY="$BUILD_DIR/icc_profile_fuzz_test"
if [[ ! -x "$BINARY" ]]; then
    echo "[FAIL] missing binary: $BINARY" >&2
    echo "       Run ./fuzztest/build.sh --mode $MODE first." >&2
    exit 1
fi
BINARY_NAME="${BINARY##*/}"

export ICC_FUZZTEST_REPO_ROOT="$REPO_ROOT"
export ICC_FUZZTEST_SEED_MANIFEST="$SCRIPT_DIR/seeds.txt"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0,halt_on_error=1,abort_on_error=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1,print_stacktrace=1}"

if [[ "$MODE" == "unit" ]]; then
    echo "[*] Running unit-mode seed and property checks"
    ctest --test-dir "$BUILD_DIR" --output-on-failure
    echo "[OK] Unit-mode checks passed"
    exit 0
fi

mapfile -t AVAILABLE_TARGETS < <(
    "$BINARY" --list_fuzz_tests 2>&1 |
        sed -n 's/^\[\*\] Fuzz test: //p'
)
if [[ ${#AVAILABLE_TARGETS[@]} -eq 0 ]]; then
    echo "[FAIL] no registered fuzz targets found in $BINARY" >&2
    exit 1
fi

if [[ "$TARGET" == "all" ]]; then
    RUN_TARGETS=("${AVAILABLE_TARGETS[@]}")
else
    RUN_TARGETS=()
    for available_target in "${AVAILABLE_TARGETS[@]}"; do
        if [[ "$available_target" == "$TARGET" ]]; then
            RUN_TARGETS+=("$TARGET")
            break
        fi
    done
    if [[ ${#RUN_TARGETS[@]} -eq 0 ]]; then
        echo "[FAIL] unknown fuzz target: $TARGET" >&2
        echo "Available targets:" >&2
        printf '  %s\n' "${AVAILABLE_TARGETS[@]}" >&2
        exit 1
    fi
fi

if [[ "$MODE" == "libfuzzer" ]]; then
    CORPUS_DIR="${ICC_FUZZTEST_CORPUS_DIR:-$SCRIPT_DIR/corpus-libfuzzer}"
else
    CORPUS_DIR="${ICC_FUZZTEST_CORPUS_DIR:-$SCRIPT_DIR/corpus}"
fi
REPRODUCERS_DIR="${ICC_FUZZTEST_REPRODUCERS_DIR:-$SCRIPT_DIR/findings}"
mkdir -p "$CORPUS_DIR" "$REPRODUCERS_DIR"

target_count=${#RUN_TARGETS[@]}
if (( RUN_JOBS == 0 )); then
    RUN_JOBS=$(nproc)
fi
if (( RUN_JOBS > target_count )); then
    RUN_JOBS=$target_count
fi

if [[ -z "$LOG_DIR" ]]; then
    run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    LOG_DIR="$SCRIPT_DIR/logs/$run_id"
fi
mkdir -p "$LOG_DIR"
SUMMARY_FILE="$LOG_DIR/summary.tsv"
RUN_INFO_FILE="$LOG_DIR/run-info.txt"
printf 'target\tbudget_seconds\treplay_inputs\texit_status\telapsed\truns\tedges_covered\ttotal_edges\tcorpus_size\n' \
    >"$SUMMARY_FILE"
printf 'mode=%s\ntotal_budget_seconds=%s\njobs=%s\nmax_replay_inputs=%s\nbinary=%s\nresearch_revision=%s\nfuzztest_revision=%s\niccdev_revision=%s\n' \
    "$MODE" "$SECONDS_TO_RUN" "$RUN_JOBS" "$MAX_REPLAY_INPUTS" "$BINARY" \
    "$(git -C "$REPO_ROOT" rev-parse HEAD)" \
    "$(git -C "$FRAMEWORK_DIR" rev-parse HEAD)" \
    "$(git -C "$ICCDEV_DIR" rev-parse HEAD)" \
    >"$RUN_INFO_FILE"

if (( SECONDS_TO_RUN < target_count )); then
    base_seconds=1
    extra_seconds=0
else
    base_seconds=$((SECONDS_TO_RUN / target_count))
    extra_seconds=$((SECONDS_TO_RUN % target_count))
fi

declare -a TARGET_SECONDS=()
declare -a TARGET_LOGS=()
declare -a TARGET_INPUT_DIRS=()
declare -a TARGET_REPLAY_COUNTS=()
INPUT_ROOT=""
if [[ "$MODE" == "fuzzing" ]]; then
    INPUT_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/icc-fuzztest-input.XXXXXXXX")"
fi
for ((target_index = 0; target_index < target_count; ++target_index)); do
    target_seconds="$base_seconds"
    if (( target_index < extra_seconds )); then
        target_seconds=$((target_seconds + 1))
    fi
    target_corpus_name="${RUN_TARGETS[target_index]//[^[:alnum:]_-]/_}"
    TARGET_SECONDS+=("$target_seconds")
    TARGET_LOGS+=("$LOG_DIR/$target_corpus_name.log")
    target_input_dir=""
    replay_count=0
    if [[ "$MODE" == "fuzzing" ]]; then
        target_input_dir="$INPUT_ROOT/$target_corpus_name"
        target_corpus_dir="$CORPUS_DIR/$BINARY_NAME/${RUN_TARGETS[target_index]}/coverage"
        replay_limit=$((target_seconds / 10))
        if (( replay_limit > MAX_REPLAY_INPUTS )); then
            replay_limit=$MAX_REPLAY_INPUTS
        fi
        mkdir -p "$target_input_dir"
        if (( replay_limit > 0 )) && [[ -d "$target_corpus_dir" ]]; then
            mapfile -d '' -t replay_files < <(
                find "$target_corpus_dir" -maxdepth 1 -type f -print0 |
                    shuf -z -n "$replay_limit"
            )
            for replay_file in "${replay_files[@]}"; do
                ln -s "$replay_file" "$target_input_dir/${replay_file##*/}"
                printf '%s\n' "${replay_file##*/}" \
                    >>"$LOG_DIR/$target_corpus_name-replay-inputs.txt"
                replay_count=$((replay_count + 1))
            done
        fi
    fi
    TARGET_INPUT_DIRS+=("$target_input_dir")
    TARGET_REPLAY_COUNTS+=("$replay_count")
done

run_one_target() {
    local run_target="$1"
    local target_seconds="$2"
    local target_log="$3"
    local target_input_dir="$4"
    local target_corpus_name
    local target_corpus_dir
    local target_reproducers_dir

    target_corpus_name="${run_target//[^[:alnum:]_-]/_}"
    target_reproducers_dir="$REPRODUCERS_DIR/$target_corpus_name"
    mkdir -p "$target_reproducers_dir"

    if [[ "$MODE" == "libfuzzer" ]]; then
        target_corpus_dir="$CORPUS_DIR/$target_corpus_name"
        mkdir -p "$target_corpus_dir"
        exec timeout --kill-after=10s "${target_seconds}s" "$BINARY" \
            "--fuzz=$run_target" \
            --rss_limit_mb=4096 \
            --stack_limit_kb=1024 \
            --time_limit_per_input=30s \
            -- \
            "-max_len=$LIBFUZZER_MAX_LEN" \
            "-artifact_prefix=$target_reproducers_dir/" \
            "$target_corpus_dir" >"$target_log" 2>&1
    fi

    target_corpus_dir="$CORPUS_DIR/$BINARY_NAME/$run_target/coverage"
    mkdir -p "$target_corpus_dir"
    # Native FuzzTest applies --fuzz_for only after loading seeds and inputs.
    # Replay sampling bounds startup, and the outer timeout bounds the complete
    # seed, replay, and mutation campaign.
    exec env \
        FUZZTEST_TESTSUITE_IN_DIR="$target_input_dir" \
        FUZZTEST_TESTSUITE_OUT_DIR="$target_corpus_dir" \
        FUZZTEST_REPRODUCERS_OUT_DIR="$target_reproducers_dir" \
        timeout --kill-after=10s "$((target_seconds + 60))s" "$BINARY" \
        "--fuzz=$run_target" \
        "--fuzz_for=${target_seconds}s" \
        --corpus_database= \
        --rss_limit_mb=4096 \
        --stack_limit_kb=1024 \
        --time_limit_per_input=30s >"$target_log" 2>&1
}

read_metric() {
    local label="$1"
    local target_log="$2"

    sed -n "s/^${label}: //p" "$target_log" | tail -n 1
}

append_summary() {
    local run_target="$1"
    local target_seconds="$2"
    local replay_count="$3"
    local status="$4"
    local target_log="$5"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$run_target" \
        "$target_seconds" \
        "$replay_count" \
        "$status" \
        "$(read_metric 'Elapsed time' "$target_log")" \
        "$(read_metric 'Total runs' "$target_log")" \
        "$(read_metric 'Edges covered' "$target_log")" \
        "$(read_metric 'Total edges' "$target_log")" \
        "$(read_metric 'Corpus size' "$target_log")" \
        >>"$SUMMARY_FILE"
}

declare -a ACTIVE_PIDS=()
cleanup_children() {
    local pid

    trap - HUP INT TERM
    for pid in "${ACTIVE_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    wait || true
    if [[ -n "$INPUT_ROOT" && -d "$INPUT_ROOT" ]]; then
        cmake -E remove_directory "$INPUT_ROOT"
    fi
    exit 130
}
trap cleanup_children HUP INT TERM

echo "[*] Fuzzing $target_count target(s) for a ${SECONDS_TO_RUN}s total budget ($MODE, $RUN_JOBS parallel job(s))"
overall_status=0
for ((batch_start = 0; batch_start < target_count; batch_start += RUN_JOBS)); do
    ACTIVE_PIDS=()
    declare -a batch_indices=()
    batch_end=$((batch_start + RUN_JOBS))
    if (( batch_end > target_count )); then
        batch_end=$target_count
    fi

    for ((target_index = batch_start; target_index < batch_end; ++target_index)); do
        run_target="${RUN_TARGETS[target_index]}"
        target_seconds="${TARGET_SECONDS[target_index]}"
        target_log="${TARGET_LOGS[target_index]}"
        target_input_dir="${TARGET_INPUT_DIRS[target_index]}"
        echo "[*] Fuzzing $run_target for ${target_seconds}s"
        run_one_target "$run_target" "$target_seconds" "$target_log" \
            "$target_input_dir" &
        ACTIVE_PIDS+=("$!")
        batch_indices+=("$target_index")
    done

    for ((batch_index = 0; batch_index < ${#ACTIVE_PIDS[@]}; ++batch_index)); do
        target_index="${batch_indices[batch_index]}"
        run_target="${RUN_TARGETS[target_index]}"
        target_seconds="${TARGET_SECONDS[target_index]}"
        target_log="${TARGET_LOGS[target_index]}"
        replay_count="${TARGET_REPLAY_COUNTS[target_index]}"
        set +e
        wait "${ACTIVE_PIDS[batch_index]}"
        status=$?
        set -e
        printf '\n===== %s =====\n' "$run_target"
        sed -n '1,$p' "$target_log"
        append_summary "$run_target" "$target_seconds" "$replay_count" \
            "$status" "$target_log"

        if [[ "$MODE" == "libfuzzer" ]]; then
            if [[ "$status" != "0" && "$status" != "124" ]]; then
                overall_status="$status"
            fi
        elif [[ "$status" != "0" ]]; then
            overall_status="$status"
        fi
    done
    ACTIVE_PIDS=()

    if [[ "$overall_status" != "0" ]]; then
        break
    fi
done
trap - HUP INT TERM
if [[ -n "$INPUT_ROOT" && -d "$INPUT_ROOT" ]]; then
    cmake -E remove_directory "$INPUT_ROOT"
fi

if [[ "$overall_status" != "0" ]]; then
    echo "[FAIL] FuzzTest campaign exited with status $overall_status" >&2
    echo "       Logs: $LOG_DIR" >&2
    exit "$overall_status"
fi

echo "[OK] Bounded FuzzTest run passed for $target_count target(s)"
echo "[OK] Run summary: $SUMMARY_FILE"
