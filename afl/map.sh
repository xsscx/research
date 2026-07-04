#!/bin/bash
# afl/map.sh - Collect AFL++ showmap coverage for a target corpus
#
# Usage: ./afl/map.sh <target> [--queue|--input|--crashes|--hangs] [--instance NAME] [--out FILE]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
BIN_DIR="${AFL_BIN_DIR:-$REPO_ROOT/afl/bin}"
TARGET=""
SOURCE="queue"
INSTANCE=""
OUT_FILE=""

source "$REPO_ROOT/afl/targets.sh"

usage() {
    sed -n '2,5p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  --queue         map the AFL queue corpus (default)"
    echo "  --input         map the initial input corpus"
    echo "  --crashes       map saved crashes"
    echo "  --hangs         map saved hangs"
    echo "  --instance NAME select output instance, for example default or main"
    echo "  --out FILE      write showmap output to FILE"
    echo "  --help, -h      show help"
    echo ""
    afl_print_targets
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --queue) SOURCE="queue"; shift ;;
        --input) SOURCE="input"; shift ;;
        --crashes) SOURCE="crashes"; shift ;;
        --hangs) SOURCE="hangs"; shift ;;
        --instance) INSTANCE="${2:-}"; shift 2 ;;
        --out) OUT_FILE="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        -*) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 1 ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    usage
    exit 1
fi

if ! command -v afl-showmap >/dev/null 2>&1; then
    echo "ERROR: afl-showmap not found in PATH" >&2
    exit 1
fi

if ! afl_configure_target "$TARGET"; then
    echo "ERROR: Unknown target '$TARGET'" >&2
    afl_print_targets >&2
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: Binary not found: $BINARY" >&2
    echo "Run ./afl/build.sh first" >&2
    exit 1
fi

for required_file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -e "$required_file" ]]; then
        echo "ERROR: Required support file not found: $required_file" >&2
        exit 1
    fi
done
afl_prepare_target_support_files "$TARGET"

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

first_instance() {
    local output_dir="$1"
    local child

    for name in default main; do
        if [[ -f "$output_dir/$name/fuzzer_stats" ]]; then
            printf '%s' "$name"
            return 0
        fi
    done

    while IFS= read -r -d '' child; do
        if [[ -f "$child/fuzzer_stats" ]]; then
            basename "$child"
            return 0
        fi
    done < <(find "$output_dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | sort -z)

    printf 'default'
}

if [[ -z "$INSTANCE" ]]; then
    INSTANCE="$(first_instance "$AFL_DIR/output")"
fi

case "$SOURCE" in
    input) INPUT_DIR="$AFL_DIR/input" ;;
    queue) INPUT_DIR="$AFL_DIR/output/$INSTANCE/queue" ;;
    crashes) INPUT_DIR="$AFL_DIR/output/$INSTANCE/crashes" ;;
    hangs) INPUT_DIR="$AFL_DIR/output/$INSTANCE/hangs" ;;
    *) echo "ERROR: Unknown source: $SOURCE" >&2; exit 1 ;;
esac

if [[ ! -d "$INPUT_DIR" ]]; then
    echo "ERROR: Input source not found: $INPUT_DIR" >&2
    exit 1
fi

if [[ -z "$OUT_FILE" ]]; then
    OUT_FILE="$AFL_DIR/showmap-${SOURCE}-${INSTANCE}.txt"
fi

mkdir -p "$(dirname "$OUT_FILE")"
TMP_ROOT="${TMPDIR:-${HOME:-$REPO_ROOT}/work/copilot/tmp}"
mkdir -p "$TMP_ROOT"
FILE_LIST="$(TMPDIR="$TMP_ROOT" mktemp)"
trap 'rm -f "$FILE_LIST"' EXIT
find "$INPUT_DIR" -maxdepth 1 -type f ! -name 'README*' -print | sort > "$FILE_LIST"
INPUT_COUNT=$(wc -l < "$FILE_LIST" | tr -d ' ')

if [[ "$INPUT_COUNT" -eq 0 ]]; then
    echo "ERROR: No input files found in $INPUT_DIR" >&2
    exit 1
fi

STATS="$AFL_DIR/output/$INSTANCE/fuzzer_stats"
SETUP="$AFL_DIR/output/$INSTANCE/fuzzer_setup"
MAP_SIZE="$(setup_value "$SETUP" "AFL_MAP_SIZE")"
TIMEOUT="$(stat_value "$STATS" "exec_timeout")"

export AFL_MAP_SIZE="${AFL_MAP_SIZE:-${MAP_SIZE:-1048576}}"
if command -v readelf >/dev/null 2>&1 && readelf -d "$BINARY" 2>/dev/null | grep -q 'Shared library: \[libIcc'; then
    export LD_LIBRARY_PATH="$BIN_DIR"
else
    unset LD_LIBRARY_PATH
fi
export ASAN_OPTIONS="detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=0,allocator_may_return_null=1"
export UBSAN_OPTIONS="halt_on_error=1,abort_on_error=1,print_stacktrace=0"

env -u AFL_BASE -u AFL_BIN_DIR \
    afl-showmap -q -C -e -I "$FILE_LIST" -o "$OUT_FILE" -m none -t "${AFL_TIMEOUT:-${TIMEOUT:-5000}}" -- "$BINARY" "${AFL_ARGS[@]}"

EDGE_COUNT=$(wc -l < "$OUT_FILE" | tr -d ' ')
echo "[OK] Mapped $INPUT_COUNT input(s) from $INPUT_DIR"
echo "     Target: $TARGET/$INSTANCE"
echo "     Edges:  $EDGE_COUNT"
echo "     Output: $OUT_FILE"
