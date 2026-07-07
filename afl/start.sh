#!/bin/bash
# afl/start.sh - Start AFL++ fuzzer for an iccDEV target tool
#
# Usage: ./afl/start.sh <target> [options]
#
# Targets are defined in afl/targets.sh.
#
# Examples:
#   ./afl/start.sh dump                 # Single instance
#   ./afl/start.sh dump --parallel 4    # 4 parallel instances

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
AFL_TIMEOUT="${AFL_TIMEOUT:-5000}"
AFL_RUN_TIME="${AFL_RUN_TIME:-}"
AFL_MAP_SIZE_VAL="${AFL_MAP_SIZE:-1048576}"
AFL_AUTORESUME_VAL="${AFL_AUTORESUME:-1}"
AFL_FRESH="${AFL_FRESH:-0}"
AFL_IMPORT_FIRST_VAL="${AFL_IMPORT_FIRST:-1}"
AFL_POWER_SCHEDULE="${AFL_POWER_SCHEDULE:-}"
AFL_MOPT_SECS="${AFL_MOPT_SECS:-}"
AFL_CMPLOG_BINARY="${AFL_CMPLOG_BINARY:-}"
AFL_CMPLOG_OPTS="${AFL_CMPLOG_OPTS:-}"
AFL_EXEC_LIMIT="${AFL_EXEC_LIMIT:-}"
AFL_INPUT_FORMAT="${AFL_INPUT_FORMAT:-}"
AFL_MIN_LENGTH="${AFL_MIN_LENGTH:-}"
AFL_MAX_LENGTH="${AFL_MAX_LENGTH:-}"
AFL_SEQUENTIAL_QUEUE="${AFL_SEQUENTIAL_QUEUE:-0}"
AFL_SPLICE="${AFL_SPLICE:-0}"
AFL_EXTRA_DICTS="${AFL_EXTRA_DICTS:-}"
AFL_EXTRA_ARGS="${AFL_EXTRA_ARGS:-}"
AFL_INPUT_DIR="${AFL_INPUT_DIR:-}"
AFL_EXTRA_SEED_DIRS="${AFL_EXTRA_SEED_DIRS:-}"
AFL_RESEED="${AFL_RESEED:-0}"
AFL_SEED_ONLY="${AFL_SEED_ONLY:-0}"
AFL_SEED_LIMIT_OVERRIDE="${AFL_SEED_LIMIT:-}"
AFL_SEED_MAX_BYTES_OVERRIDE="${AFL_SEED_MAX_BYTES:-}"
AFL_SEED_ORDER="${AFL_SEED_ORDER:-random}"
AFL_DICT_OVERRIDE="${AFL_DICT:-${AFL_DICTIONARY:-}}"
BIN_DIR="${AFL_BIN_DIR:-$REPO_ROOT/afl/bin}"

source "$REPO_ROOT/afl/targets.sh"

TARGET=""
PARALLEL=1

usage() {
    echo "Usage: $0 <target> [options]"
    echo ""
    echo "Options:"
    echo "  --parallel N          start N AFL instances"
    echo "  --fresh               archive previous local input/output before start"
    echo "  --reseed              add target seed sources to the local input corpus"
    echo "  --seed-only           stage seeds and exit without starting AFL"
    echo "  --seed-limit N        override target per-directory seed sample size"
    echo "  --seed-max-bytes N    override target maximum seed size"
    echo "  --seed-order MODE     random or sorted; default: random"
    echo "  --extra-seed-dir DIR  add one seed directory; may be repeated"
    echo "  --input-dir DIR       use an external AFL -i directory"
    echo "  --dictionary FILE     override the target dictionary"
    echo "  --timeout MS          AFL execution timeout"
    echo "  --run-time SEC        stop fuzzing after SEC seconds"
    echo "  --map-size N          AFL map size"
    echo "  --cmplog-binary FILE  pass FILE to afl-fuzz -c"
    echo "  --cmplog-opts OPTS    pass OPTS to afl-fuzz -l"
    echo "  --power-schedule NAME pass NAME to afl-fuzz -p"
    echo "  --mopt-secs SEC       pass SEC to afl-fuzz -L"
    echo "  --exec-limit N        pass N to afl-fuzz -E"
    echo "  --input-format FMT    pass text or binary to afl-fuzz -a"
    echo "  --min-length N        pass N to afl-fuzz -g"
    echo "  --max-length N        pass N to afl-fuzz -G"
    echo "  --sequential-queue    pass -Z to afl-fuzz"
    echo "  --splice              pass -u to afl-fuzz"
    echo "  --extra-args ARGS     append shell-split extra afl-fuzz args"
    echo "  --help, -h            show this help"
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

while [[ $# -gt 0 ]]; do
    case "$1" in
        --parallel) PARALLEL="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --fresh) AFL_FRESH=1; shift ;;
        --reseed) AFL_RESEED=1; shift ;;
        --seed-only) AFL_SEED_ONLY=1; shift ;;
        --seed-limit) AFL_SEED_LIMIT_OVERRIDE="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --seed-max-bytes) AFL_SEED_MAX_BYTES_OVERRIDE="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --seed-order) AFL_SEED_ORDER="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --extra-seed-dir)
            extra_seed_dir="$(option_arg "$1" "${2:-}")"
            if [[ -n "$AFL_EXTRA_SEED_DIRS" ]]; then
                AFL_EXTRA_SEED_DIRS="${AFL_EXTRA_SEED_DIRS}:$extra_seed_dir"
            else
                AFL_EXTRA_SEED_DIRS="$extra_seed_dir"
            fi
            shift 2
            ;;
        --input-dir) AFL_INPUT_DIR="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --dictionary) AFL_DICT_OVERRIDE="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --timeout) AFL_TIMEOUT="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --run-time) AFL_RUN_TIME="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --map-size) AFL_MAP_SIZE_VAL="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --cmplog-binary) AFL_CMPLOG_BINARY="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --cmplog-opts) AFL_CMPLOG_OPTS="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --power-schedule) AFL_POWER_SCHEDULE="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --mopt-secs) AFL_MOPT_SECS="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --exec-limit) AFL_EXEC_LIMIT="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --input-format) AFL_INPUT_FORMAT="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --min-length) AFL_MIN_LENGTH="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --max-length) AFL_MAX_LENGTH="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --sequential-queue) AFL_SEQUENTIAL_QUEUE=1; shift ;;
        --splice) AFL_SPLICE=1; shift ;;
        --extra-args) AFL_EXTRA_ARGS="$(option_arg "$1" "${2:-}")"; shift 2 ;;
        --help|-h) TARGET="$1"; break ;;
        --list) TARGET="$1"; break ;;
        -*)
            echo "Unknown option: $1"
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

read_proc_cmdline() {
    local proc_cmdline="$1"

    dd if="$proc_cmdline" bs=4096 count=1 2>/dev/null | tr '\0' ' ' || true
}

if [[ -z "$TARGET" || "$TARGET" == "--list" || "$TARGET" == "--help" || "$TARGET" == "-h" ]]; then
    usage
    if [[ "$TARGET" == "--list" || "$TARGET" == "--help" || "$TARGET" == "-h" ]]; then
        exit 0
    fi
    exit 1
fi

output_has_live_afl() {
    local output_dir="$1"
    local proc_cmdline
    local cmdline

    while IFS= read -r -d '' proc_cmdline; do
        cmdline="$(read_proc_cmdline "$proc_cmdline")"
        if [[ "$cmdline" == *"afl-fuzz"* && "$cmdline" == *"$output_dir"* ]]; then
            return 0
        fi
    done < <(find /proc -maxdepth 2 -path '/proc/[0-9]*/cmdline' -print0 2>/dev/null)

    return 1
}

remove_stale_resume_state() {
    local output_dir="$1"
    local resume_removed=0
    local fastresume_removed=0
    local resume_dir
    local fastresume

    [[ -d "$output_dir" ]] || return 0
    if output_has_live_afl "$output_dir"; then
        return 0
    fi

    while IFS= read -r -d '' resume_dir; do
        rm -rf -- "$resume_dir"
        resume_removed=$((resume_removed + 1))
    done < <(find "$output_dir" -mindepth 2 -maxdepth 2 -type d -name _resume -print0 2>/dev/null)

    while IFS= read -r -d '' fastresume; do
        rm -f -- "$fastresume"
        fastresume_removed=$((fastresume_removed + 1))
    done < <(find "$output_dir" -mindepth 2 -maxdepth 2 -type f -name fastresume.bin -print0 2>/dev/null)

    if [[ "$resume_removed" -gt 0 ]]; then
        echo "[*] Removed $resume_removed stale AFL _resume director$(if [[ "$resume_removed" -eq 1 ]]; then printf 'y'; else printf 'ies'; fi)"
    fi
    if [[ "$fastresume_removed" -gt 0 ]]; then
        echo "[*] Removed $fastresume_removed stale AFL fastresume.bin file$(if [[ "$fastresume_removed" -eq 1 ]]; then printf ''; else printf 's'; fi)"
    fi
}

# Target-specific configuration
if ! afl_configure_target "$TARGET"; then
    echo "ERROR: Unknown target '$TARGET'"
    afl_print_targets
    exit 1
fi

if [[ -n "$AFL_INPUT_DIR" && ! -d "$AFL_INPUT_DIR" ]]; then
    echo "ERROR: AFL_INPUT_DIR is not a directory: $AFL_INPUT_DIR" >&2
    exit 1
fi

require_uint() {
    local name="$1"
    local value="$2"

    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        echo "ERROR: $name must be a non-negative integer: $value" >&2
        exit 1
    fi
}

archive_dir_once() {
    local dir="$1"
    local label="$2"
    local backup
    local suffix=0

    if [[ ! -d "$dir" ]] || ! find "$dir" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
        return 0
    fi

    backup="$dir.backup.$(date -u +%Y%m%dT%H%M%SZ)"
    while [[ -e "$backup" ]]; do
        suffix=$((suffix + 1))
        backup="$dir.backup.$(date -u +%Y%m%dT%H%M%SZ).$suffix"
    done
    mv "$dir" "$backup"
    echo "[*] Archived previous $label: $backup"
}

if [[ -n "$AFL_DICT_OVERRIDE" ]]; then
    if [[ ! -f "$AFL_DICT_OVERRIDE" ]]; then
        echo "ERROR: AFL_DICT is not a file: $AFL_DICT_OVERRIDE" >&2
        exit 1
    fi
    DICT="$AFL_DICT_OVERRIDE"
fi

require_uint "parallel" "$PARALLEL"
if [[ "$PARALLEL" -lt 1 ]]; then
    echo "ERROR: --parallel must be at least 1: $PARALLEL" >&2
    exit 1
fi
require_uint "AFL_TIMEOUT" "$AFL_TIMEOUT"
require_uint "AFL_MAP_SIZE" "$AFL_MAP_SIZE_VAL"
if [[ -n "$AFL_RUN_TIME" ]]; then
    require_uint "AFL_RUN_TIME" "$AFL_RUN_TIME"
fi
if [[ "$AFL_SEED_ORDER" != "random" && "$AFL_SEED_ORDER" != "sorted" ]]; then
    echo "ERROR: --seed-order must be random or sorted: $AFL_SEED_ORDER" >&2
    exit 1
fi
if [[ -n "$AFL_SEED_LIMIT_OVERRIDE" ]]; then
    require_uint "AFL_SEED_LIMIT" "$AFL_SEED_LIMIT_OVERRIDE"
    SEED_LIMIT="$AFL_SEED_LIMIT_OVERRIDE"
fi
if [[ -n "$AFL_SEED_MAX_BYTES_OVERRIDE" ]]; then
    require_uint "AFL_SEED_MAX_BYTES" "$AFL_SEED_MAX_BYTES_OVERRIDE"
    SEED_MAX_BYTES="$AFL_SEED_MAX_BYTES_OVERRIDE"
fi
if [[ -n "$AFL_EXTRA_SEED_DIRS" ]]; then
    IFS=':' read -r -a AFL_EXTRA_SEED_DIRS_ARRAY <<< "$AFL_EXTRA_SEED_DIRS"
    for seed_dir in "${AFL_EXTRA_SEED_DIRS_ARRAY[@]}"; do
        if [[ -z "$seed_dir" ]]; then
            continue
        fi
        if [[ ! -d "$seed_dir" ]]; then
            echo "ERROR: AFL_EXTRA_SEED_DIRS entry is not a directory: $seed_dir" >&2
            exit 1
        fi
        SEED_DIRS+=("$seed_dir")
    done
fi
if [[ -n "$AFL_EXEC_LIMIT" ]]; then
    require_uint "AFL_EXEC_LIMIT" "$AFL_EXEC_LIMIT"
fi
if [[ -n "$AFL_MIN_LENGTH" ]]; then
    require_uint "AFL_MIN_LENGTH" "$AFL_MIN_LENGTH"
fi
if [[ -n "$AFL_MAX_LENGTH" ]]; then
    require_uint "AFL_MAX_LENGTH" "$AFL_MAX_LENGTH"
fi
if [[ -n "$AFL_INPUT_FORMAT" && "$AFL_INPUT_FORMAT" != "text" && "$AFL_INPUT_FORMAT" != "binary" ]]; then
    echo "ERROR: AFL_INPUT_FORMAT must be 'text' or 'binary': $AFL_INPUT_FORMAT" >&2
    exit 1
fi

# Verify binary exists
if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: Binary not found: $BINARY"
    echo "Run ./afl/build.sh first"
    exit 1
fi

ICC_RUNTIME_LIB_PATH=""

# Verify iccDEV shared libraries needed by this binary are deployed. Static
# builds have no libIcc*.so dependencies and do not need LD_LIBRARY_PATH.
if command -v readelf >/dev/null 2>&1; then
    MISSING_LIBS=()
    while IFS= read -r lib; do
        if [[ ! -e "$BIN_DIR/$lib" && ! -L "$BIN_DIR/$lib" ]]; then
            MISSING_LIBS+=("$lib")
        fi
    done < <(readelf -d "$BINARY" 2>/dev/null | sed -n 's/.*Shared library: \[\(libIcc[^]]*\)\].*/\1/p')

    if [[ ${#MISSING_LIBS[@]} -gt 0 ]]; then
        echo "ERROR: Shared library not found in $BIN_DIR:"
        for lib in "${MISSING_LIBS[@]}"; do
            echo "  $lib"
        done
        echo "Run ./afl/build.sh first"
        exit 1
    fi
    if readelf -d "$BINARY" 2>/dev/null | grep -q 'Shared library: \[libIcc'; then
        ICC_RUNTIME_LIB_PATH="$BIN_DIR"
    fi
elif compgen -G "$BIN_DIR/libIccProfLib2*.so*" >/dev/null; then
    ICC_RUNTIME_LIB_PATH="$BIN_DIR"
fi

for required_file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -e "$required_file" ]]; then
        echo "ERROR: Required support file not found: $required_file"
        exit 1
    fi
done

afl_prepare_target_support_files "$TARGET"

# Set up AFL directories. AFL_FRESH archives prior local input/output state
# instead of deleting it, then stages a target-appropriate seed corpus.
if [[ "$AFL_FRESH" != "0" && -z "$AFL_INPUT_DIR" ]]; then
    archive_dir_once "$AFL_DIR/input" "input"
fi
mkdir -p "$AFL_DIR/input"
if [[ "$AFL_FRESH" != "0" ]]; then
    archive_dir_once "$AFL_DIR/output" "output"
fi
mkdir -p "$AFL_DIR/output"
remove_stale_resume_state "$AFL_DIR/output"

seed_file_allowed() {
    local seed_file="$1"
    local seed_type

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

prune_existing_seed_corpus() {
    local output_dir="$AFL_DIR/output"
    local prune_dir
    local pruned=0
    local dir
    local seed_file
    local rel
    local dest
    local corpus_dirs=("$AFL_DIR/input")

    if [[ "${AFL_PRUNE_BAD_SEEDS:-1}" == "0" ]]; then
        return 0
    fi
    if [[ "${SEED_MAX_BYTES:-0}" -le 0 && -z "${SEED_FILE_TYPE_REGEX:-}" ]]; then
        return 0
    fi
    if output_has_live_afl "$output_dir"; then
        return 0
    fi

    if [[ -d "$output_dir" ]]; then
        while IFS= read -r -d '' dir; do
            corpus_dirs+=("$dir")
        done < <(find "$output_dir" -mindepth 2 -maxdepth 2 -type d \( -name queue -o -name _resume \) -print0 2>/dev/null)
    fi

    prune_dir="$AFL_DIR/pruned-seeds-$(date -u +%Y%m%dT%H%M%SZ)"
    for dir in "${corpus_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' seed_file; do
            if seed_file_size_allowed "$seed_file" && seed_file_allowed "$seed_file"; then
                continue
            fi
            rel="${seed_file#"$AFL_DIR"/}"
            dest="$prune_dir/$rel"
            mkdir -p "$(dirname "$dest")"
            mv -- "$seed_file" "$dest"
            pruned=$((pruned + 1))
        done < <(
            find "$dir" -maxdepth 1 -type f ! -name 'README*' -print0 2>/dev/null
        )
    done

    if [[ "$pruned" -gt 0 ]]; then
        echo "[*] Pruned $pruned oversized or incompatible AFL seed(s) to $prune_dir"
    else
        rmdir "$prune_dir" 2>/dev/null || true
    fi
}

seed_file_dry_run_ok() {
    local seed_file="$1"
    local exit_code=0
    local output
    local dry_run_args=()
    local arg

    if [[ "${SEED_DRY_RUN_TARGET:-0}" -ne 1 ]]; then
        return 0
    fi

    for arg in "${AFL_ARGS[@]}"; do
        if [[ "$arg" == "@@" ]]; then
            dry_run_args+=("$seed_file")
        else
            dry_run_args+=("$arg")
        fi
    done

    output=$(
        LD_LIBRARY_PATH="$ICC_RUNTIME_LIB_PATH" \
        ASAN_OPTIONS="detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=0,allocator_may_return_null=1" \
        UBSAN_OPTIONS="halt_on_error=1,print_stacktrace=1" \
        timeout "${SEED_DRY_RUN_TIMEOUT:-5}" "$BINARY" "${dry_run_args[@]}" 2>&1
    ) || exit_code=$?

    if [[ "$exit_code" -eq 124 || ( "$exit_code" -ge 128 && "$exit_code" -ne 255 ) ]] ||
        printf '%s\n' "$output" | grep -Eaiq 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)|runtime error:'; then
        return 1
    fi

    if [[ "${SEED_DRY_RUN_REQUIRE_ZERO_TARGET:-0}" -eq 1 && "$exit_code" -ne 0 ]]; then
        return 1
    fi

    return 0
}

copy_seed_file() {
    local seed_file="$1"
    local skip_type_check="${2:-0}"

    if ! seed_file_size_allowed "$seed_file"; then
        return 1
    fi
    if [[ "$skip_type_check" -ne 1 ]] && ! seed_file_allowed "$seed_file"; then
        return 1
    fi
    if ! seed_file_dry_run_ok "$seed_file"; then
        SEED_DRY_RUN_REJECTED=$((SEED_DRY_RUN_REJECTED + 1))
        return 1
    fi

    cp --update=none -- "$seed_file" "$AFL_DIR/input/"
}

selected_seed_candidates() {
    local limit="${SEED_LIMIT:-200}"

    if [[ "$AFL_SEED_ORDER" == "sorted" ]]; then
        if [[ "$limit" -gt 0 ]]; then
            printf '%s\0' "${seed_candidates[@]}" | sort -z | head -z -n "$limit"
        else
            printf '%s\0' "${seed_candidates[@]}" | sort -z
        fi
        return 0
    fi

    if [[ "$limit" -gt 0 ]]; then
        printf '%s\0' "${seed_candidates[@]}" | shuf -z -n "$limit"
    else
        printf '%s\0' "${seed_candidates[@]}" | shuf -z
    fi
}

# Seed corpus - copy from all seed sources if input dir is empty. AFL_INPUT_DIR
# uses an external -i directory directly, matching ad hoc afl-fuzz workflows.
prune_existing_seed_corpus
INPUT_SEED_COUNT=$(find "$AFL_DIR/input" -mindepth 1 -maxdepth 1 -type f 2>/dev/null | wc -l)
if [[ -z "$AFL_INPUT_DIR" && ( "$INPUT_SEED_COUNT" -eq 0 || "$AFL_RESEED" != "0" ) ]]; then
    if [[ "$INPUT_SEED_COUNT" -eq 0 ]]; then
        echo "[*] Seeding input corpus..."
    else
        echo "[*] Reseeding input corpus..."
    fi
    SEED_DRY_RUN_REJECTED=0
    for seed_file in "${SEED_FILES[@]}"; do
        if [[ -f "$seed_file" ]]; then
            if copy_seed_file "$seed_file" 1; then
                echo "    $(dirname "$seed_file")/$(basename "$seed_file")"
            fi
        fi
    done
    for seed_dir in "${SEED_DIRS[@]}"; do
        if [[ -d "$seed_dir" ]]; then
            seed_find=(find "$seed_dir" -maxdepth 1 -type f)
            if [[ "${SEED_MAX_BYTES:-0}" -gt 0 ]]; then
                seed_find+=( -size "-${SEED_MAX_BYTES}c" )
            fi
            seed_candidates=()
            while IFS= read -r -d '' seed_candidate; do
                if seed_file_allowed "$seed_candidate"; then
                    seed_candidates+=("$seed_candidate")
                fi
            done < <("${seed_find[@]}" -print0 2>/dev/null)
            count=${#seed_candidates[@]}
            if [[ "${SEED_MAX_BYTES:-0}" -gt 0 ]]; then
                echo "    $seed_dir ($count eligible files <= ${SEED_MAX_BYTES} bytes)"
            else
                echo "    $seed_dir ($count eligible files)"
            fi
            if [[ "$count" -gt 0 ]]; then
                while IFS= read -r -d '' seed_candidate; do
                    if copy_seed_file "$seed_candidate"; then
                        :
                    fi
                done < <(selected_seed_candidates)
            fi
        fi
    done
    if [[ "${SEED_DRY_RUN_TARGET:-0}" -eq 1 ]]; then
        echo "    dry-run rejected $SEED_DRY_RUN_REJECTED crashing/hanging seed(s)"
    fi
fi

# Copy dictionary
if [[ -f "$DICT" ]]; then
    cp "$DICT" "$AFL_DIR/${TARGET}.dict"
fi

SEED_COUNT=$(find "$AFL_DIR/input" -mindepth 1 -maxdepth 1 -type f 2>/dev/null | wc -l)
echo "[*] Target:     $TARGET"
echo "[*] Binary:     $BINARY"
echo "[*] Seeds:      $SEED_COUNT files"
if [[ -n "$DICT" ]]; then
    echo "[*] Dictionary: $(basename "$DICT")"
else
    echo "[*] Dictionary: none"
fi
echo "[*] Output:     $AFL_DIR/output/"
echo "[*] Timeout:    ${AFL_TIMEOUT}ms"
if [[ -n "$AFL_RUN_TIME" ]]; then
    echo "[*] Run time:   ${AFL_RUN_TIME}s"
fi
echo "[*] Map size:   ${AFL_MAP_SIZE_VAL}"
if [[ "$AFL_FRESH" != "0" ]]; then
    echo "[*] Fresh:      archived previous local input/output before start"
fi
if [[ -n "$AFL_INPUT_DIR" ]]; then
    echo "[*] Input dir:  $AFL_INPUT_DIR"
fi
if [[ -n "$AFL_EXTRA_SEED_DIRS" ]]; then
    echo "[*] Extra seeds: $AFL_EXTRA_SEED_DIRS"
fi
if [[ "$AFL_RESEED" != "0" ]]; then
    echo "[*] Reseed:     enabled"
fi
if [[ -n "$AFL_SEED_LIMIT_OVERRIDE" ]]; then
    echo "[*] Seed limit: ${SEED_LIMIT}"
fi
if [[ -n "$AFL_SEED_MAX_BYTES_OVERRIDE" ]]; then
    echo "[*] Seed max:   ${SEED_MAX_BYTES} bytes"
fi
echo "[*] Seed order: ${AFL_SEED_ORDER}"
echo "[*] Parallel:   $PARALLEL instance(s)"
if [[ -n "$AFL_POWER_SCHEDULE" ]]; then
    echo "[*] Schedule:   $AFL_POWER_SCHEDULE"
fi
if [[ -n "$AFL_MOPT_SECS" ]]; then
    echo "[*] MOpt:       ${AFL_MOPT_SECS}s"
fi
if [[ -n "$AFL_CMPLOG_BINARY" ]]; then
    echo "[*] CMPLOG:     $AFL_CMPLOG_BINARY"
fi
if [[ -n "$AFL_CMPLOG_OPTS" ]]; then
    echo "[*] CMPLOG opts: $AFL_CMPLOG_OPTS"
fi
if [[ "$AFL_SEQUENTIAL_QUEUE" != "0" ]]; then
    echo "[*] Queue:      sequential"
fi
if [[ "$AFL_SPLICE" != "0" ]]; then
    echo "[*] Splicing:   enabled"
fi
if [[ -n "$AFL_EXEC_LIMIT" ]]; then
    echo "[*] Exec limit: ${AFL_EXEC_LIMIT}"
fi
if [[ -n "$AFL_INPUT_FORMAT" ]]; then
    echo "[*] Input fmt:  ${AFL_INPUT_FORMAT}"
fi
if [[ -n "$AFL_MIN_LENGTH" || -n "$AFL_MAX_LENGTH" ]]; then
    echo "[*] Gen length: min=${AFL_MIN_LENGTH:-default} max=${AFL_MAX_LENGTH:-default}"
fi
if [[ "${AFL_STATSD:-0}" != "0" ]]; then
    echo "[*] StatsD:     ${AFL_STATSD_HOST:-127.0.0.1}:${AFL_STATSD_PORT:-8125} tags=${AFL_STATSD_TAGS_FLAVOR:-none}"
fi
if [[ -n "$TARGET_NOTE" ]]; then
    echo "[WARN] $TARGET_NOTE"
fi
echo ""

if [[ -z "$AFL_INPUT_DIR" && "$SEED_COUNT" -eq 0 ]]; then
    echo "ERROR: No usable seed files staged in $AFL_DIR/input" >&2
    echo "Check the target SEED_FILES, SEED_DIRS, SEED_MAX_BYTES, and SEED_FILE_TYPE_REGEX settings." >&2
    exit 1
fi

if [[ "$AFL_SEED_ONLY" == "1" ]]; then
    echo "[OK] Seed-only mode complete"
    exit 0
fi

AFL_COMMON_ARGS=()
if [[ -n "$AFL_POWER_SCHEDULE" ]]; then
    AFL_COMMON_ARGS+=("-p" "$AFL_POWER_SCHEDULE")
fi
if [[ -n "$AFL_MOPT_SECS" ]]; then
    AFL_COMMON_ARGS+=("-L" "$AFL_MOPT_SECS")
fi
if [[ -n "$AFL_CMPLOG_BINARY" ]]; then
    if [[ "$AFL_CMPLOG_BINARY" != "0" && "$AFL_CMPLOG_BINARY" != "-" && ! -x "$AFL_CMPLOG_BINARY" ]]; then
        echo "ERROR: CMPLOG binary not executable: $AFL_CMPLOG_BINARY" >&2
        exit 1
    fi
    AFL_COMMON_ARGS+=("-c" "$AFL_CMPLOG_BINARY")
fi
if [[ -n "$AFL_CMPLOG_OPTS" ]]; then
    AFL_COMMON_ARGS+=("-l" "$AFL_CMPLOG_OPTS")
fi
if [[ "$AFL_SEQUENTIAL_QUEUE" != "0" ]]; then
    AFL_COMMON_ARGS+=("-Z")
fi
if [[ "$AFL_SPLICE" != "0" ]]; then
    AFL_COMMON_ARGS+=("-u")
fi
if [[ -n "$AFL_EXEC_LIMIT" ]]; then
    AFL_COMMON_ARGS+=("-E" "$AFL_EXEC_LIMIT")
fi
if [[ -n "$AFL_INPUT_FORMAT" ]]; then
    AFL_COMMON_ARGS+=("-a" "$AFL_INPUT_FORMAT")
fi
if [[ -n "$AFL_MIN_LENGTH" ]]; then
    AFL_COMMON_ARGS+=("-g" "$AFL_MIN_LENGTH")
fi
if [[ -n "$AFL_MAX_LENGTH" ]]; then
    AFL_COMMON_ARGS+=("-G" "$AFL_MAX_LENGTH")
fi
if [[ -f "$AFL_DIR/${TARGET}.dict" ]]; then
    AFL_COMMON_ARGS+=("-x" "$AFL_DIR/${TARGET}.dict")
fi
if [[ -n "$AFL_EXTRA_DICTS" ]]; then
    IFS=':' read -r -a AFL_EXTRA_DICTS_ARRAY <<< "$AFL_EXTRA_DICTS"
    DICT_COUNT=0
    for ((i = 0; i < ${#AFL_COMMON_ARGS[@]}; i++)); do
        [[ "${AFL_COMMON_ARGS[$i]}" == "-x" ]] && DICT_COUNT=$((DICT_COUNT + 1))
    done
    for dict_file in "${AFL_EXTRA_DICTS_ARRAY[@]}"; do
        if [[ -z "$dict_file" ]]; then
            continue
        fi
        if [[ ! -f "$dict_file" ]]; then
            echo "ERROR: AFL_EXTRA_DICTS entry is not a file: $dict_file" >&2
            exit 1
        fi
        DICT_COUNT=$((DICT_COUNT + 1))
        if [[ "$DICT_COUNT" -gt 4 ]]; then
            echo "ERROR: AFL++ supports at most four dictionaries via -x" >&2
            exit 1
        fi
        AFL_COMMON_ARGS+=("-x" "$dict_file")
    done
fi
if [[ -n "$AFL_EXTRA_ARGS" ]]; then
    read -r -a AFL_EXTRA_ARGS_ARRAY <<< "$AFL_EXTRA_ARGS"
    AFL_COMMON_ARGS+=("${AFL_EXTRA_ARGS_ARRAY[@]}")
fi
if [[ -n "$AFL_RUN_TIME" ]]; then
    AFL_COMMON_ARGS+=("-V" "$AFL_RUN_TIME")
fi

# Check for existing session (resume)
# Parallel mode uses output/main/, single mode uses output/default/.
if [[ "$PARALLEL" -gt 1 ]]; then
    if [[ -f "$AFL_DIR/output/main/fuzzer_stats" ]]; then
        echo "[*] Existing parallel session detected - AFL will auto-resume"
        INPUT_ARGS=("-i-")
    else
        for stale in "$AFL_DIR/output/main" "$AFL_DIR/output"/secondary_*; do
            [[ -d "$stale" && ! -f "$stale/fuzzer_stats" ]] && rm -rf "$stale"
        done
        INPUT_ARGS=("-i" "${AFL_INPUT_DIR:-$AFL_DIR/input}")
    fi
else
    if [[ -f "$AFL_DIR/output/default/fuzzer_stats" ]]; then
        echo "[*] Existing session detected - AFL will auto-resume"
        INPUT_ARGS=("-i-")
    else
        INPUT_ARGS=("-i" "${AFL_INPUT_DIR:-$AFL_DIR/input}")
    fi
fi

export AFL_MAP_SIZE="$AFL_MAP_SIZE_VAL"
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
if [[ "$AFL_AUTORESUME_VAL" != "0" ]]; then
    export AFL_AUTORESUME="$AFL_AUTORESUME_VAL"
else
    unset AFL_AUTORESUME
fi
if [[ "$AFL_IMPORT_FIRST_VAL" != "0" ]]; then
    export AFL_IMPORT_FIRST="$AFL_IMPORT_FIRST_VAL"
else
    unset AFL_IMPORT_FIRST
fi
if [[ "${AFL_DISABLE_TRIM_TARGET:-0}" -eq 1 || "${AFL_DISABLE_TRIM:-0}" != "0" ]]; then
    export AFL_DISABLE_TRIM=1
else
    unset AFL_DISABLE_TRIM
fi
if [[ "${AFL_FAST_CAL_TARGET:-0}" -eq 1 || "${AFL_FAST_CAL:-0}" != "0" ]]; then
    export AFL_FAST_CAL=1
else
    unset AFL_FAST_CAL
fi
if [[ -n "$ICC_RUNTIME_LIB_PATH" ]]; then
    export LD_LIBRARY_PATH="$ICC_RUNTIME_LIB_PATH"
else
    unset LD_LIBRARY_PATH
fi
export ASAN_OPTIONS="detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=0,allocator_may_return_null=1"
export UBSAN_OPTIONS="halt_on_error=1,abort_on_error=1,print_stacktrace=0"
unset MSAN_OPTIONS
export -n AFL_AUTORESUME_VAL AFL_BASE AFL_BIN_DIR AFL_CMPLOG_BINARY AFL_CMPLOG_OPTS AFL_DICT AFL_FRESH 2>/dev/null || true
export -n AFL_DICTIONARY AFL_EXEC_LIMIT AFL_EXTRA_ARGS AFL_EXTRA_DICTS AFL_EXTRA_SEED_DIRS AFL_INPUT_DIR 2>/dev/null || true
export -n AFL_DICT_OVERRIDE AFL_IMPORT_FIRST_VAL AFL_INPUT_FORMAT AFL_MAX_LENGTH AFL_MIN_LENGTH 2>/dev/null || true
export -n AFL_MOPT_SECS AFL_POWER_SCHEDULE AFL_RESEED AFL_RUN_TIME AFL_SEED_LIMIT AFL_SEED_MAX_BYTES AFL_SEED_ONLY AFL_SEED_ORDER 2>/dev/null || true
export -n AFL_SEQUENTIAL_QUEUE AFL_SPLICE AFL_TIMEOUT 2>/dev/null || true

if [[ "$PARALLEL" -eq 1 ]]; then
    echo "[*] Starting AFL (single instance)..."
    echo "    Press Ctrl+C to stop"
    echo ""
    exec afl-fuzz \
        "${INPUT_ARGS[@]}" \
        -o "$AFL_DIR/output" \
        "${AFL_COMMON_ARGS[@]}" \
        -m none \
        -t "$AFL_TIMEOUT" \
        -- "$BINARY" "${AFL_ARGS[@]}"
else
    echo "[*] Starting $PARALLEL AFL instances (1 main + $((PARALLEL-1)) secondary)..."

    afl-fuzz \
        "${INPUT_ARGS[@]}" \
        -o "$AFL_DIR/output" \
        -M main \
        "${AFL_COMMON_ARGS[@]}" \
        -m none \
        -t "$AFL_TIMEOUT" \
        -- "$BINARY" "${AFL_ARGS[@]}" &
    echo "    Main PID: $!"

    sleep 2

    for i in $(seq 2 "$PARALLEL"); do
        afl-fuzz \
            "${INPUT_ARGS[@]}" \
            -o "$AFL_DIR/output" \
            -S "secondary_$i" \
            "${AFL_COMMON_ARGS[@]}" \
            -m none \
            -t "$AFL_TIMEOUT" \
            -- "$BINARY" "${AFL_ARGS[@]}" &
        echo "    Secondary $i PID: $!"
        sleep 1
    done

    echo ""
    echo "[*] All $PARALLEL instances launched"
    echo "    Use ./afl/status.sh to monitor"
    echo "    Use ./afl/stop.sh $TARGET to stop all"
    wait
fi
