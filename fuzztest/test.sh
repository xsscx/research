#!/usr/bin/env bash
# Run the ICC FuzzTest unit checks or a bounded coverage-guided smoke test.
#
# Usage: ./test.sh [--mode fuzzing|unit|libfuzzer] [--seconds N]
#                  [--target SUITE.TEST|all]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MODE="${ICC_FUZZTEST_MODE:-fuzzing}"
SECONDS_TO_RUN="${ICC_FUZZTEST_SECONDS:-60}"
TARGET="${ICC_FUZZTEST_TARGET:-all}"
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
mkdir -p "$CORPUS_DIR"

target_count=${#RUN_TARGETS[@]}
if (( SECONDS_TO_RUN < target_count )); then
    base_seconds=1
    extra_seconds=0
else
    base_seconds=$((SECONDS_TO_RUN / target_count))
    extra_seconds=$((SECONDS_TO_RUN % target_count))
fi

echo "[*] Fuzzing $target_count target(s) for a ${SECONDS_TO_RUN}s total budget ($MODE)"
for ((target_index = 0; target_index < target_count; ++target_index)); do
    run_target="${RUN_TARGETS[target_index]}"
    target_seconds=$base_seconds
    if (( target_index < extra_seconds )); then
        target_seconds=$((target_seconds + 1))
    fi
    echo "[*] Fuzzing $run_target for ${target_seconds}s"

    if [[ "$MODE" == "libfuzzer" ]]; then
        target_corpus_name="${run_target//[^[:alnum:]_-]/_}"
        target_corpus_dir="$CORPUS_DIR/$target_corpus_name"
        mkdir -p "$target_corpus_dir"
        set +e
        timeout --kill-after=10s "${target_seconds}s" "$BINARY" \
            "--fuzz=$run_target" \
            --rss_limit_mb=4096 \
            --stack_limit_kb=1024 \
            --time_limit_per_input=30s \
            -- \
            "-max_len=$LIBFUZZER_MAX_LEN" \
            "$target_corpus_dir"
        status=$?
        set -e
        if [[ "$status" != "0" && "$status" != "124" ]]; then
            echo "[FAIL] $run_target exited with status $status" >&2
            exit "$status"
        fi
        continue
    fi

    set +e
    timeout --kill-after=10s "$((target_seconds + 60))s" "$BINARY" \
        "--fuzz=$run_target" \
        "--fuzz_for=${target_seconds}s" \
        "--corpus_database=$CORPUS_DIR" \
        --rss_limit_mb=4096 \
        --stack_limit_kb=1024 \
        --time_limit_per_input=30s
    status=$?
    set -e
    if [[ "$status" != "0" ]]; then
        echo "[FAIL] $run_target exited with status $status" >&2
        exit "$status"
    fi
done

echo "[OK] Bounded FuzzTest run passed for $target_count target(s)"
