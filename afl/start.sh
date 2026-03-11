#!/bin/bash
# afl/start.sh — Start AFL++ fuzzer for an iccDEV target tool
#
# Usage: ./afl/start.sh <target> [--parallel N]
#
# Targets: fromcube
#
# Examples:
#   ./afl/start.sh fromcube              # Single instance
#   ./afl/start.sh fromcube --parallel 4  # 4 parallel instances

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_SSD="${AFL_SSD:-/mnt/g/fuzz-ssd}"
AFL_TIMEOUT="${AFL_TIMEOUT:-5000}"
AFL_MAP_SIZE_VAL="${AFL_MAP_SIZE:-131072}"
BIN_DIR="$REPO_ROOT/afl/bin"

TARGET="${1:-}"
PARALLEL=1

# Parse --parallel
shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --parallel) PARALLEL="${2:-1}"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target> [--parallel N]"
    echo ""
    echo "Available targets:"
    echo "  fromcube    — iccFromCube (.cube LUT parser)"
    exit 1
fi

# Target-specific configuration
case "$TARGET" in
    fromcube)
        BINARY="$BIN_DIR/iccFromCube"
        AFL_DIR="$AFL_SSD/afl-fromcube"
        DICT="$REPO_ROOT/cfl/icc_fromcube_fuzzer.dict"
        SEED_DIRS=(
            "$REPO_ROOT/cfl/icc_fromcube_fuzzer_seed_corpus"
            "$REPO_ROOT/cfl/corpus-icc_fromcube_fuzzer"
        )
        # iccFromCube <input.cube> <output.icc>
        AFL_ARGS="@@ /dev/null"
        ;;
    *)
        echo "ERROR: Unknown target '$TARGET'"
        echo "Available: fromcube"
        exit 1
        ;;
esac

# Verify binary exists
if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: Binary not found: $BINARY"
    echo "Run ./afl/build.sh first"
    exit 1
fi

# Verify shared library
if [[ ! -f "$BIN_DIR/libIccProfLib2.so" ]]; then
    echo "ERROR: Shared library not found: $BIN_DIR/libIccProfLib2.so"
    echo "Run ./afl/build.sh first"
    exit 1
fi

# Set up AFL directories
mkdir -p "$AFL_DIR"/{input,output}

# Seed corpus — copy from all seed sources if input dir is empty
if [[ $(ls "$AFL_DIR/input/" 2>/dev/null | wc -l) -eq 0 ]]; then
    for seed_dir in "${SEED_DIRS[@]}"; do
        if [[ -d "$seed_dir" ]]; then
            echo "[*] Seeding from $seed_dir"
            find "$seed_dir" -maxdepth 1 -type f -exec cp -n {} "$AFL_DIR/input/" \;
        fi
    done
fi

# Copy dictionary
if [[ -f "$DICT" ]]; then
    cp "$DICT" "$AFL_DIR/${TARGET}.dict"
fi

SEED_COUNT=$(ls "$AFL_DIR/input/" 2>/dev/null | wc -l)
echo "[*] Target:     $TARGET"
echo "[*] Binary:     $BINARY"
echo "[*] Seeds:      $SEED_COUNT files"
echo "[*] Dictionary: $(basename "$DICT" 2>/dev/null || echo 'none')"
echo "[*] Output:     $AFL_DIR/output/"
echo "[*] Timeout:    ${AFL_TIMEOUT}ms"
echo "[*] Parallel:   $PARALLEL instance(s)"
echo ""

# Build AFL command
DICT_ARG=""
if [[ -f "$AFL_DIR/${TARGET}.dict" ]]; then
    DICT_ARG="-x $AFL_DIR/${TARGET}.dict"
fi

# Check for existing session (resume)
if [[ -d "$AFL_DIR/output/default/queue" ]] && [[ $(ls "$AFL_DIR/output/default/queue/" 2>/dev/null | wc -l) -gt 0 ]]; then
    echo "[*] Existing session detected — AFL will auto-resume"
    INPUT_FLAG="-i-"
else
    INPUT_FLAG="-i $AFL_DIR/input"
fi

export AFL_MAP_SIZE="$AFL_MAP_SIZE_VAL"
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export LD_LIBRARY_PATH="$BIN_DIR"
export ASAN_OPTIONS="detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=0"

if [[ "$PARALLEL" -eq 1 ]]; then
    echo "[*] Starting AFL (single instance)..."
    echo "    Press Ctrl+C to stop"
    echo ""
    exec afl-fuzz \
        $INPUT_FLAG \
        -o "$AFL_DIR/output" \
        $DICT_ARG \
        -m none \
        -t "$AFL_TIMEOUT" \
        -- "$BINARY" $AFL_ARGS
else
    # Multi-instance: 1 master + (N-1) secondaries
    echo "[*] Starting $PARALLEL AFL instances (1 main + $((PARALLEL-1)) secondary)..."

    # Main instance
    afl-fuzz \
        $INPUT_FLAG \
        -o "$AFL_DIR/output" \
        -M main \
        $DICT_ARG \
        -m none \
        -t "$AFL_TIMEOUT" \
        -- "$BINARY" $AFL_ARGS &
    echo "    Main PID: $!"

    sleep 2

    # Secondary instances
    for i in $(seq 2 "$PARALLEL"); do
        afl-fuzz \
            $INPUT_FLAG \
            -o "$AFL_DIR/output" \
            -S "secondary_$i" \
            $DICT_ARG \
            -m none \
            -t "$AFL_TIMEOUT" \
            -- "$BINARY" $AFL_ARGS &
        echo "    Secondary $i PID: $!"
        sleep 1
    done

    echo ""
    echo "[*] All $PARALLEL instances launched"
    echo "    Use ./afl/status.sh to monitor"
    echo "    Use ./afl/stop.sh $TARGET to stop all"
    wait
fi
