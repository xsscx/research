#!/usr/bin/env bash
# Run the ICC FuzzTest unit checks or a bounded coverage-guided smoke test.
#
# Usage: ./test.sh [--mode fuzzing|unit|libfuzzer] [--seconds N]
#                  [--target SUITE.TEST]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MODE="${ICC_FUZZTEST_MODE:-fuzzing}"
SECONDS_TO_RUN="${ICC_FUZZTEST_SECONDS:-60}"
TARGET="${ICC_FUZZTEST_TARGET:-IccProfileFuzzTest.ProfileOperationsDoNotCrash}"

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

if [[ "$MODE" == "libfuzzer" ]]; then
    CORPUS_DIR="${ICC_FUZZTEST_CORPUS_DIR:-$SCRIPT_DIR/corpus-libfuzzer}"
else
    CORPUS_DIR="${ICC_FUZZTEST_CORPUS_DIR:-$SCRIPT_DIR/corpus}"
fi
mkdir -p "$CORPUS_DIR"

echo "[*] Fuzzing $TARGET for ${SECONDS_TO_RUN}s ($MODE)"
if [[ "$MODE" == "libfuzzer" ]]; then
    set +e
    timeout --kill-after=10s "${SECONDS_TO_RUN}s" "$BINARY" \
        "--fuzz=$TARGET" \
        --rss_limit_mb=4096 \
        --stack_limit_kb=1024 \
        --time_limit_per_input=30s \
        "$CORPUS_DIR"
    status=$?
    set -e
    if [[ "$status" != "0" && "$status" != "124" ]]; then
        echo "[FAIL] LibFuzzer compatibility run exited with status $status" >&2
        exit "$status"
    fi
    echo "[OK] Bounded FuzzTest run passed"
    exit 0
fi

timeout "$((SECONDS_TO_RUN + 60))s" "$BINARY" \
    "--fuzz=$TARGET" \
    "--fuzz_for=${SECONDS_TO_RUN}s" \
    "--corpus_database=$CORPUS_DIR" \
    --rss_limit_mb=4096 \
    --stack_limit_kb=1024 \
    --time_limit_per_input=30s

echo "[OK] Bounded FuzzTest run passed"
