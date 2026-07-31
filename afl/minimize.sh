#!/bin/bash
# afl/minimize.sh - Minimize an AFL++ corpus for an iccDEV target tool
#
# Usage: ./afl/minimize.sh <target> [--queue|--input|--crashes|--hangs] [--instance NAME] [--out DIR] [--tmin] [--tmin-limit N]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
BIN_DIR="${AFL_BIN_DIR:-$REPO_ROOT/afl/bin}"
TARGET=""
SOURCE="queue"
INSTANCE=""
OUT_DIR=""
RUN_TMIN=0
TMIN_LIMIT=0
AFL_CMIN_BIN="${AFL_CMIN_BIN:-afl-cmin}"
AFL_CMIN_EXTRA_ARGS="${AFL_CMIN_EXTRA_ARGS:-}"
STAGED_INPUT_DIR=""

cleanup() {
    if [[ -n "$STAGED_INPUT_DIR" && -d "$STAGED_INPUT_DIR" ]]; then
        rm -rf "$STAGED_INPUT_DIR"
    fi
}
trap cleanup EXIT

source "$REPO_ROOT/afl/targets.sh"
source "$REPO_ROOT/afl/sanitizer-env.sh"

usage() {
    sed -n '2,5p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  --queue         minimize the AFL queue corpus (default)"
    echo "  --input         minimize the initial input corpus"
    echo "  --crashes       minimize saved crashes"
    echo "  --hangs         minimize saved hangs"
    echo "                  if the live crashes/hangs dir is empty, timestamped archives are used"
    echo "  --instance NAME select output instance, for example default or main"
    echo "  --out DIR       write minimized corpus to DIR"
    echo "  --tmin          run afl-tmin over afl-cmin results"
    echo "  --tmin-limit N  limit afl-tmin to the first N cmin outputs; 0 means all"
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
        --out) OUT_DIR="${2:-}"; shift 2 ;;
        --tmin) RUN_TMIN=1; shift ;;
        --tmin-limit)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --tmin-limit requires a non-negative integer" >&2
                exit 1
            fi
            TMIN_LIMIT="$2"
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        -*) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 1 ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    usage
    exit 1
fi

if ! command -v "$AFL_CMIN_BIN" >/dev/null 2>&1; then
    echo "ERROR: AFL_CMIN_BIN not found in PATH: $AFL_CMIN_BIN" >&2
    exit 1
fi
if [[ "$RUN_TMIN" -eq 1 ]] && ! command -v afl-tmin >/dev/null 2>&1; then
    echo "ERROR: afl-tmin not found in PATH" >&2
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

input_file_count() {
    local dir="$1"
    find "$dir" -maxdepth 1 \( -type f -o -type l \) ! -name 'README*' 2>/dev/null | wc -l | tr -d ' '
}

collect_rotated_source_dirs() {
    local output_dir="$1"
    local source="$2"
    local candidate

    while IFS= read -r -d '' candidate; do
        if [[ "$(input_file_count "$candidate")" -gt 0 ]]; then
            printf '%s\0' "$candidate"
        fi
    done < <(find "$output_dir" -mindepth 1 -maxdepth 1 -type d -name "$source.*" -print0 2>/dev/null | sort -z)
}

stage_rotated_sources() {
    local source="$1"
    shift
    local dirs=("$@")
    local dir file prefix base dest

    STAGED_INPUT_DIR="$AFL_DIR/.minimize-${source}-${INSTANCE}-$$"
    mkdir -p "$STAGED_INPUT_DIR"

    for dir in "${dirs[@]}"; do
        prefix="$(basename "$dir" | tr -c '[:alnum:]_.-' '_')"
        while IFS= read -r -d '' file; do
            base="$(basename "$file")"
            dest="$STAGED_INPUT_DIR/${prefix}__${base}"
            if ! ln "$file" "$dest" 2>/dev/null; then
                cp "$file" "$dest"
            fi
        done < <(find "$dir" -maxdepth 1 \( -type f -o -type l \) ! -name 'README*' -print0 2>/dev/null | sort -z)
    done
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

INPUT_NOTE=""
INPUT_COUNT="$(input_file_count "$INPUT_DIR")"
if [[ "$INPUT_COUNT" -eq 0 && ( "$SOURCE" == "crashes" || "$SOURCE" == "hangs" ) ]]; then
    ROTATED_DIRS=()
    while IFS= read -r -d '' rotated_dir; do
        ROTATED_DIRS+=("$rotated_dir")
    done < <(collect_rotated_source_dirs "$AFL_DIR/output/$INSTANCE" "$SOURCE")

    if [[ "${#ROTATED_DIRS[@]}" -eq 1 ]]; then
        INPUT_DIR="${ROTATED_DIRS[0]}"
        INPUT_COUNT="$(input_file_count "$INPUT_DIR")"
        INPUT_NOTE="    Note:     live $SOURCE dir was empty; using rotated archive $INPUT_DIR"
    elif [[ "${#ROTATED_DIRS[@]}" -gt 1 ]]; then
        stage_rotated_sources "$SOURCE" "${ROTATED_DIRS[@]}"
        INPUT_DIR="$STAGED_INPUT_DIR"
        INPUT_COUNT="$(input_file_count "$INPUT_DIR")"
        INPUT_NOTE="    Note:     live $SOURCE dir was empty; staged ${#ROTATED_DIRS[@]} rotated archives"
    fi
fi
if [[ "$INPUT_COUNT" -eq 0 ]]; then
    echo "ERROR: No input files found in $INPUT_DIR" >&2
    if [[ "$SOURCE" == "crashes" || "$SOURCE" == "hangs" ]]; then
        echo "       Checked for rotated archives matching $AFL_DIR/output/$INSTANCE/$SOURCE.*" >&2
    fi
    exit 1
fi

if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="$AFL_DIR/cmin-${SOURCE}-${INSTANCE}-$(date -u +%Y%m%dT%H%M%SZ)"
fi
if [[ -e "$OUT_DIR" ]]; then
    echo "ERROR: Output directory already exists: $OUT_DIR" >&2
    exit 1
fi

STATS="$AFL_DIR/output/$INSTANCE/fuzzer_stats"
SETUP="$AFL_DIR/output/$INSTANCE/fuzzer_setup"
MAP_SIZE="$(setup_value "$SETUP" "AFL_MAP_SIZE")"
TIMEOUT="$(stat_value "$STATS" "exec_timeout")"

for required_file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -e "$required_file" ]]; then
        echo "ERROR: Required support file not found: $required_file" >&2
        exit 1
    fi
done
afl_prepare_target_support_files "$TARGET"

export AFL_MAP_SIZE="${AFL_MAP_SIZE:-${MAP_SIZE:-1048576}}"
if command -v readelf >/dev/null 2>&1 && readelf -d "$BINARY" 2>/dev/null | grep -q 'Shared library: \[libIcc'; then
    export LD_LIBRARY_PATH="$BIN_DIR"
else
    unset LD_LIBRARY_PATH
fi
afl_export_fuzz_sanitizer_env

echo "[*] Minimizing $INPUT_COUNT input(s)"
echo "    Target:   $TARGET/$INSTANCE"
echo "    Source:   $INPUT_DIR"
echo "    Output:   $OUT_DIR"
echo "    Timeout:  ${AFL_TIMEOUT:-${TIMEOUT:-5000}}ms"
if [[ -n "$INPUT_NOTE" ]]; then
    echo "$INPUT_NOTE"
fi

AFL_CMIN_ARGS=()
if [[ -n "$AFL_CMIN_EXTRA_ARGS" ]]; then
    read -r -a AFL_CMIN_EXTRA_ARGS_ARRAY <<< "$AFL_CMIN_EXTRA_ARGS"
    AFL_CMIN_ARGS+=("${AFL_CMIN_EXTRA_ARGS_ARRAY[@]}")
fi

env -u AFL_BASE -u AFL_BIN_DIR -u AFL_CMIN_BIN -u AFL_CMIN_EXTRA_ARGS \
    bash -c 'cd "$1" && shift && exec "$@"' bash "$REPO_ROOT" \
    "$AFL_CMIN_BIN" "${AFL_CMIN_ARGS[@]}" -i "$INPUT_DIR" -o "$OUT_DIR" -m none -t "${AFL_TIMEOUT:-${TIMEOUT:-5000}}" -- "$BINARY" "${AFL_ARGS[@]}"

CMIN_COUNT=$(input_file_count "$OUT_DIR")
echo "[OK] afl-cmin kept $CMIN_COUNT of $INPUT_COUNT input(s)"
echo "     Output: $OUT_DIR"

if [[ "$RUN_TMIN" -ne 1 ]]; then
    exit 0
fi

TMIN_DIR="${OUT_DIR}.tmin"
if [[ -e "$TMIN_DIR" ]]; then
    echo "ERROR: tmin output directory already exists: $TMIN_DIR" >&2
    exit 1
fi
mkdir -p "$TMIN_DIR"

TMIN_DONE=0
while IFS= read -r -d '' f; do
    base="$(basename "$f")"
    env -u AFL_BASE -u AFL_BIN_DIR -u AFL_CMIN_BIN -u AFL_CMIN_EXTRA_ARGS \
        bash -c 'cd "$1" && shift && exec "$@"' bash "$REPO_ROOT" \
        afl-tmin -i "$f" -o "$TMIN_DIR/$base" -m none -t "${AFL_TIMEOUT:-${TIMEOUT:-5000}}" -- "$BINARY" "${AFL_ARGS[@]}"
    TMIN_DONE=$((TMIN_DONE + 1))
    if [[ "$TMIN_LIMIT" -gt 0 && "$TMIN_DONE" -ge "$TMIN_LIMIT" ]]; then
        break
    fi
done < <(find "$OUT_DIR" -maxdepth 1 \( -type f -o -type l \) ! -name 'README*' -print0 2>/dev/null | sort -z)

echo "[OK] afl-tmin minimized $TMIN_DONE input(s)"
echo "     Output: $TMIN_DIR"
