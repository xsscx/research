#!/bin/bash
# afl/screen-corpus.sh - Filter a corpus before AFL resume.
#
# Usage: ./afl/screen-corpus.sh <target> --input DIR [--out DIR]
#
# Copies only seeds that match the target's size/type rules and, when requested
# by the target definition, replay without sanitizer crashes or timeouts.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
BIN_DIR="${AFL_BIN_DIR:-$REPO_ROOT/afl/bin}"
TARGET=""
INPUT_DIR=""
OUT_DIR=""
SCREEN_TIMEOUT="${AFL_SCREEN_TIMEOUT:-}"
SCREEN_MAX_EXEC_MS="${AFL_SCREEN_MAX_EXEC_MS:-0}"
SCREEN_LIMIT="${AFL_SCREEN_LIMIT:-0}"
KEEP_ORDER="${AFL_SCREEN_ORDER:-sorted}"

source "$REPO_ROOT/afl/targets.sh"
source "$REPO_ROOT/afl/sanitizer-env.sh"

usage() {
    sed -n '2,5p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  --input DIR       source corpus directory"
    echo "  --out DIR         output directory; default is target cmin-screened timestamp"
    echo "  --timeout SEC     per-seed replay timeout; default uses target dry-run timeout"
    echo "  --max-exec-ms N   reject seeds whose replay takes more than N ms; 0 disables"
    echo "  --limit N         stop after N kept seeds; 0 keeps all accepted seeds"
    echo "  --order MODE      sorted or random; default sorted"
    echo "  --help, -h        show help"
    echo ""
    afl_print_targets
}

option_arg() {
    local opt="$1"
    local value="${2:-}"

    if [[ -z "$value" || "$value" == --* ]]; then
        echo "ERROR: $opt requires a value" >&2
        exit 1
    fi
    printf '%s' "$value"
}

require_uint() {
    local name="$1"
    local value="$2"

    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        echo "ERROR: $name must be a non-negative integer: $value" >&2
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --input) INPUT_DIR="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --out) OUT_DIR="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --timeout) SCREEN_TIMEOUT="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --max-exec-ms) SCREEN_MAX_EXEC_MS="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --limit) SCREEN_LIMIT="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --order) KEEP_ORDER="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        -*)
            echo "ERROR: Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [[ -n "$TARGET" ]]; then
                echo "ERROR: multiple targets specified: $TARGET and $1" >&2
                exit 1
            fi
            TARGET="$1"
            shift
            ;;
    esac
done

if [[ -z "$TARGET" || -z "$INPUT_DIR" ]]; then
    usage
    exit 1
fi
if [[ ! -d "$INPUT_DIR" ]]; then
    echo "ERROR: input directory not found: $INPUT_DIR" >&2
    exit 1
fi
require_uint "AFL_SCREEN_MAX_EXEC_MS" "$SCREEN_MAX_EXEC_MS"
require_uint "AFL_SCREEN_LIMIT" "$SCREEN_LIMIT"
if [[ -n "$SCREEN_TIMEOUT" ]]; then
    require_uint "AFL_SCREEN_TIMEOUT" "$SCREEN_TIMEOUT"
fi
if [[ "$KEEP_ORDER" != "sorted" && "$KEEP_ORDER" != "random" ]]; then
    echo "ERROR: --order must be sorted or random: $KEEP_ORDER" >&2
    exit 1
fi

if ! afl_configure_target "$TARGET"; then
    echo "ERROR: Unknown target '$TARGET'" >&2
    afl_print_targets >&2
    exit 1
fi
require_uint "SEED_FIND_MAXDEPTH" "${SEED_FIND_MAXDEPTH:-1}"
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

if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="$AFL_DIR/cmin-screened-$(date -u +%Y%m%dT%H%M%SZ)"
fi
if [[ -e "$OUT_DIR" ]]; then
    echo "ERROR: output path already exists: $OUT_DIR" >&2
    exit 1
fi
mkdir -p "$OUT_DIR"

ICC_RUNTIME_LIB_PATH=""
if command -v readelf >/dev/null 2>&1 && readelf -d "$BINARY" 2>/dev/null | grep -q 'Shared library: \[libIcc'; then
    ICC_RUNTIME_LIB_PATH="$BIN_DIR"
fi

seed_file_size_allowed() {
    local seed_file="$1"
    local max_bytes="${SEED_MAX_BYTES:-0}"
    local seed_size

    if [[ "$max_bytes" -le 0 ]]; then
        return 0
    fi
    seed_size=$(stat -c %s -- "$seed_file" 2>/dev/null || echo 0)
    [[ "$seed_size" -lt "$max_bytes" ]]
}

seed_file_allowed() {
    local seed_file="$1"
    local seed_type

    if [[ -n "${SEED_INCLUDE_REGEX:-}" && ! "$(basename "$seed_file")" =~ $SEED_INCLUDE_REGEX ]]; then
        return 1
    fi
    if [[ -n "${SEED_EXCLUDE_REGEX:-}" && "$(basename "$seed_file")" =~ $SEED_EXCLUDE_REGEX ]]; then
        return 1
    fi
    if [[ -z "${SEED_FILE_TYPE_REGEX:-}" ]]; then
        return 0
    fi
    if ! command -v file >/dev/null 2>&1; then
        echo "ERROR: file(1) is required for target seed filtering" >&2
        exit 1
    fi
    seed_type=$(file -b -- "$seed_file" 2>/dev/null || true)
    [[ "$seed_type" =~ $SEED_FILE_TYPE_REGEX ]]
}

replay_seed() {
    local seed_file="$1"
    local timeout_sec="${SCREEN_TIMEOUT:-${SEED_DRY_RUN_TIMEOUT:-5}}"
    local start_ns end_ns elapsed_ms exit_code output arg
    local replay_args=()

    for arg in "${AFL_ARGS[@]}"; do
        if [[ "$arg" == "@@" ]]; then
            replay_args+=("$seed_file")
        else
            replay_args+=("$arg")
        fi
    done

    start_ns="$(date +%s%N)"
    output=$(
        cd "$AFL_WORK_DIR" && \
        LD_LIBRARY_PATH="$ICC_RUNTIME_LIB_PATH" \
        ASAN_OPTIONS="$AFL_ASAN_OPTIONS_TRIAGE" \
        UBSAN_OPTIONS="$AFL_UBSAN_OPTIONS_TRIAGE" \
        timeout "$timeout_sec" "$BINARY" "${replay_args[@]}" 2>&1
    ) || exit_code=$?
    exit_code="${exit_code:-0}"
    end_ns="$(date +%s%N)"
    elapsed_ms="$(((end_ns - start_ns) / 1000000))"

    if [[ "$exit_code" -eq 124 || ( "$exit_code" -ge 128 && "$exit_code" -ne 255 ) ]]; then
        REJECT_REASON="timeout_or_signal"
        return 1
    fi
    if printf '%s\n' "$output" | grep -Eaiq 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)|runtime error:'; then
        REJECT_REASON="sanitizer"
        return 1
    fi
    if [[ "${SEED_DRY_RUN_REQUIRE_ZERO_TARGET:-0}" -eq 1 && "$exit_code" -ne 0 ]]; then
        REJECT_REASON="nonzero_exit"
        return 1
    fi
    if [[ "$SCREEN_MAX_EXEC_MS" -gt 0 && "$elapsed_ms" -gt "$SCREEN_MAX_EXEC_MS" ]]; then
        REJECT_REASON="slow_${elapsed_ms}ms"
        return 1
    fi

    REJECT_REASON=""
    return 0
}

copy_accepted_seed() {
    local seed_file="$1"
    local base dest suffix

    base="$(basename "$seed_file")"
    dest="$OUT_DIR/$base"
    suffix=0
    while [[ -e "$dest" ]]; do
        suffix=$((suffix + 1))
        dest="$OUT_DIR/${base}.dup$suffix"
    done
    cp -- "$seed_file" "$dest"
}

SOURCE_COUNT=0
KEPT_COUNT=0
REJECT_SIZE=0
REJECT_TYPE=0
REJECT_REPLAY=0
REJECT_LIMIT=0
REJECT_REASON=""

echo "[*] Screening corpus"
echo "    Target:      $TARGET"
echo "    Source:      $INPUT_DIR"
echo "    Output:      $OUT_DIR"
echo "    Max bytes:   ${SEED_MAX_BYTES:-0}"
echo "    Max depth:   ${SEED_FIND_MAXDEPTH:-1}"
echo "    Max exec ms: $SCREEN_MAX_EXEC_MS"

if [[ "$KEEP_ORDER" == "random" ]]; then
    FIND_SORT=(shuf -z)
else
    FIND_SORT=(sort -z)
fi

while IFS= read -r -d '' seed_file; do
    SOURCE_COUNT=$((SOURCE_COUNT + 1))
    if ! seed_file_size_allowed "$seed_file"; then
        REJECT_SIZE=$((REJECT_SIZE + 1))
        continue
    fi
    if ! seed_file_allowed "$seed_file"; then
        REJECT_TYPE=$((REJECT_TYPE + 1))
        continue
    fi
    if ! replay_seed "$seed_file"; then
        REJECT_REPLAY=$((REJECT_REPLAY + 1))
        continue
    fi
    copy_accepted_seed "$seed_file"
    KEPT_COUNT=$((KEPT_COUNT + 1))
    if [[ "$SCREEN_LIMIT" -gt 0 && "$KEPT_COUNT" -ge "$SCREEN_LIMIT" ]]; then
        REJECT_LIMIT=1
        break
    fi
done < <(
    find "$INPUT_DIR" -maxdepth "${SEED_FIND_MAXDEPTH:-1}" \( -type f -o -type l \) ! -name 'README*' -print0 2>/dev/null | "${FIND_SORT[@]}"
)

echo "[OK] kept $KEPT_COUNT of $SOURCE_COUNT inspected seed(s)"
echo "     rejected_size=$REJECT_SIZE rejected_type=$REJECT_TYPE rejected_replay=$REJECT_REPLAY limit_reached=$REJECT_LIMIT"
echo "     output=$OUT_DIR"
