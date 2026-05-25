#!/bin/bash
# afl/start.sh - Start AFL++ fuzzer for an iccDEV target tool
#
# Usage: ./afl/start.sh <target> [--parallel N]
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
AFL_MAP_SIZE_VAL="${AFL_MAP_SIZE:-131072}"
BIN_DIR="$REPO_ROOT/afl/bin"

source "$AFL_BASE/targets.sh"

TARGET="${1:-}"
PARALLEL=1

# Parse --parallel
shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --parallel) PARALLEL="${2:-1}"; shift 2 ;;
        --help|-h) TARGET=""; break ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || "$TARGET" == "--list" || "$TARGET" == "--help" || "$TARGET" == "-h" ]]; then
    echo "Usage: $0 <target> [--parallel N]"
    echo ""
    afl_print_targets
    if [[ "$TARGET" == "--list" || "$TARGET" == "--help" || "$TARGET" == "-h" ]]; then
        exit 0
    fi
    exit 1
fi

# Target-specific configuration
if ! afl_configure_target "$TARGET"; then
    echo "ERROR: Unknown target '$TARGET'"
    afl_print_targets
    exit 1
fi

# Verify binary exists
if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: Binary not found: $BINARY"
    echo "Run ./afl/build.sh first"
    exit 1
fi

# Verify iccDEV shared libraries needed by this binary are deployed. Debug
# builds use a "d" suffix, so derive the required names from the binary.
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
elif ! compgen -G "$BIN_DIR/libIccProfLib2*.so*" >/dev/null; then
    echo "ERROR: Shared library not found: $BIN_DIR/libIccProfLib2*.so*"
    echo "Run ./afl/build.sh first"
    exit 1
fi

for required_file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -e "$required_file" ]]; then
        echo "ERROR: Required support file not found: $required_file"
        exit 1
    fi
done

if [[ "$TARGET" == "specseptotiff" || "$TARGET" == "spec" ]]; then
    spectral_prefix="${AFL_ARGS[3]}"
    for n in 1 2 3 4 5 6 7 8 9; do
        src="$REPO_ROOT/test-profiles/spectral/spec_00${n}.tif"
        dst="${spectral_prefix}${n}"
        if [[ ! -e "$dst" ]]; then
            cp "$src" "$dst"
        fi
    done
fi

# Set up AFL directories
mkdir -p "$AFL_DIR"/{input,output}

# Seed corpus - copy from all seed sources if input dir is empty
if [[ $(find "$AFL_DIR/input" -mindepth 1 -maxdepth 1 -type f 2>/dev/null | wc -l) -eq 0 ]]; then
    echo "[*] Seeding input corpus..."
    for seed_file in "${SEED_FILES[@]}"; do
        if [[ -f "$seed_file" ]]; then
            echo "    $(dirname "$seed_file")/$(basename "$seed_file")"
            cp --update=none "$seed_file" "$AFL_DIR/input/"
        fi
    done
    for seed_dir in "${SEED_DIRS[@]}"; do
        if [[ -d "$seed_dir" ]]; then
            seed_find=(find "$seed_dir" -maxdepth 1 -type f)
            if [[ "${SEED_MAX_BYTES:-0}" -gt 0 ]]; then
                seed_find+=( -size "-${SEED_MAX_BYTES}c" )
            fi
            count=$("${seed_find[@]}" 2>/dev/null | wc -l)
            if [[ "${SEED_MAX_BYTES:-0}" -gt 0 ]]; then
                echo "    $seed_dir ($count files <= ${SEED_MAX_BYTES} bytes)"
            else
                echo "    $seed_dir ($count files)"
            fi
            if [[ "$count" -gt "${SEED_LIMIT:-200}" ]]; then
                "${seed_find[@]}" | shuf -n "${SEED_LIMIT:-200}" | xargs -r -I{} cp --update=none {} "$AFL_DIR/input/"
            else
                "${seed_find[@]}" -exec cp --update=none {} "$AFL_DIR/input/" \;
            fi
        fi
    done
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
echo "[*] Parallel:   $PARALLEL instance(s)"
if [[ -n "$TARGET_NOTE" ]]; then
    echo "[WARN] $TARGET_NOTE"
fi
echo ""

# Build AFL command
DICT_ARG=""
if [[ -f "$AFL_DIR/${TARGET}.dict" ]]; then
    DICT_ARG="-x"
    DICT_PATH="$AFL_DIR/${TARGET}.dict"
else
    DICT_PATH=""
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
        INPUT_ARGS=("-i" "$AFL_DIR/input")
    fi
else
    if [[ -f "$AFL_DIR/output/default/fuzzer_stats" ]]; then
        echo "[*] Existing session detected - AFL will auto-resume"
        INPUT_ARGS=("-i-")
    else
        INPUT_ARGS=("-i" "$AFL_DIR/input")
    fi
fi

export AFL_MAP_SIZE="$AFL_MAP_SIZE_VAL"
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
if [[ "${AFL_DISABLE_TRIM_TARGET:-0}" -eq 1 ]]; then
    export AFL_DISABLE_TRIM=1
else
    unset AFL_DISABLE_TRIM
fi
if [[ "${AFL_FAST_CAL_TARGET:-0}" -eq 1 ]]; then
    export AFL_FAST_CAL=1
else
    unset AFL_FAST_CAL
fi
export LD_LIBRARY_PATH="$BIN_DIR"
export ASAN_OPTIONS="detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=0,allocator_may_return_null=1"
unset MSAN_OPTIONS

if [[ "$PARALLEL" -eq 1 ]]; then
    echo "[*] Starting AFL (single instance)..."
    echo "    Press Ctrl+C to stop"
    echo ""
    exec afl-fuzz \
        "${INPUT_ARGS[@]}" \
        -o "$AFL_DIR/output" \
        ${DICT_ARG:+"$DICT_ARG" "$DICT_PATH"} \
        -m none \
        -t "$AFL_TIMEOUT" \
        -- "$BINARY" "${AFL_ARGS[@]}"
else
    echo "[*] Starting $PARALLEL AFL instances (1 main + $((PARALLEL-1)) secondary)..."

    afl-fuzz \
        "${INPUT_ARGS[@]}" \
        -o "$AFL_DIR/output" \
        -M main \
        ${DICT_ARG:+"$DICT_ARG" "$DICT_PATH"} \
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
            ${DICT_ARG:+"$DICT_ARG" "$DICT_PATH"} \
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
