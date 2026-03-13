#!/bin/bash
# afl/start.sh — Start AFL++ fuzzer for an iccDEV target tool
#
# Usage: ./afl/start.sh <target> [--parallel N]
#
# Targets: dump, toxml, fromxml, roundtrip, tiffdump, jpegdump, pngdump, fromcube
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
    echo "Available targets (single-file input):"
    echo "  dump        — iccDumpProfile (ICC binary → text dump)"
    echo "  toxml       — iccToXml (ICC binary → XML)"
    echo "  fromxml     — iccFromXml (ICC XML → binary)"
    echo "  roundtrip   — iccRoundTrip (ICC binary round-trip)"
    echo "  tiffdump    — iccTiffDump (TIFF → ICC extraction)"
    echo "  jpegdump    — iccJpegDump (JPEG → ICC extraction)"
    echo "  pngdump     — iccPngDump (PNG → ICC extraction)"
    echo "  fromcube    — iccFromCube (.cube LUT text → ICC)"
    exit 1
fi

# Target-specific configuration
case "$TARGET" in
    dump)
        BINARY="$BIN_DIR/iccDumpProfile"
        AFL_DIR="$AFL_BASE/afl-dump"
        DICT="$REPO_ROOT/cfl/icc_dump_fuzzer.dict"
        SEED_DIRS=(
            "$REPO_ROOT/test-profiles"
            "$REPO_ROOT/fuzz/graphics/icc"
        )
        # iccDumpProfile {-v} {int} profile {tagId/"ALL"}
        AFL_ARGS="@@ ALL"
        ;;
    toxml)
        BINARY="$BIN_DIR/iccToXml"
        AFL_DIR="$AFL_BASE/afl-toxml"
        DICT="$REPO_ROOT/cfl/icc_toxml_fuzzer.dict"
        SEED_DIRS=(
            "$REPO_ROOT/test-profiles"
            "$REPO_ROOT/fuzz/graphics/icc"
        )
        # IccToXml src_icc_profile dest_xml_file
        AFL_ARGS="@@ /dev/null"
        ;;
    fromxml)
        BINARY="$BIN_DIR/iccFromXml"
        AFL_DIR="$AFL_BASE/afl-fromxml"
        DICT="$REPO_ROOT/cfl/icc_fromxml_fuzzer.dict"
        SEED_DIRS=(
            "$REPO_ROOT/fuzz/xml/icc"
            "$REPO_ROOT/cfl/corpus-icc_fromxml_fuzzer"
        )
        # IccFromXml xml_file saved_profile_file
        AFL_ARGS="@@ /dev/null"
        ;;
    roundtrip)
        BINARY="$BIN_DIR/iccRoundTrip"
        AFL_DIR="$AFL_BASE/afl-roundtrip"
        DICT="$REPO_ROOT/cfl/icc_roundtrip_fuzzer.dict"
        SEED_DIRS=(
            "$REPO_ROOT/test-profiles"
            "$REPO_ROOT/fuzz/graphics/icc"
        )
        # iccRoundTrip profile {rendering_intent=1}
        AFL_ARGS="@@"
        ;;
    tiffdump)
        BINARY="$BIN_DIR/iccTiffDump"
        AFL_DIR="$AFL_BASE/afl-tiffdump"
        DICT="$REPO_ROOT/cfl/icc_tiffdump_fuzzer.dict"
        SEED_DIRS=(
            "$REPO_ROOT/fuzz/graphics/tif"
        )
        # iccTiffDump tiff_file
        AFL_ARGS="@@"
        ;;
    jpegdump)
        BINARY="$BIN_DIR/iccJpegDump"
        AFL_DIR="$AFL_BASE/afl-jpegdump"
        DICT="$REPO_ROOT/cfl/icc.dict"
        SEED_DIRS=(
            "$REPO_ROOT/fuzz/graphics/jpg"
        )
        # iccJpegDump input.jpg
        AFL_ARGS="@@"
        ;;
    pngdump)
        BINARY="$BIN_DIR/iccPngDump"
        AFL_DIR="$AFL_BASE/afl-pngdump"
        DICT="$REPO_ROOT/cfl/icc.dict"
        SEED_DIRS=(
            "$REPO_ROOT/fuzz/graphics/png"
        )
        # iccPngDump input.png
        AFL_ARGS="@@"
        ;;
    fromcube)
        BINARY="$BIN_DIR/iccFromCube"
        AFL_DIR="$AFL_BASE/afl-fromcube"
        DICT="$REPO_ROOT/cfl/icc_fromcube_fuzzer.dict"
        SEED_DIRS=(
            "$REPO_ROOT/cfl/icc_fromcube_fuzzer_seed_corpus"
            "$REPO_ROOT/cfl/corpus-icc_fromcube_fuzzer"
        )
        # iccFromCube input.cube output.icc
        AFL_ARGS="@@ /dev/null"
        ;;
    *)
        echo "ERROR: Unknown target '$TARGET'"
        echo "Available: dump toxml fromxml roundtrip tiffdump jpegdump pngdump fromcube"
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
    echo "[*] Seeding input corpus..."
    for seed_dir in "${SEED_DIRS[@]}"; do
        if [[ -d "$seed_dir" ]]; then
            count=$(find "$seed_dir" -maxdepth 1 -type f 2>/dev/null | wc -l)
            echo "    $seed_dir ($count files)"
            # For large directories, sample up to 200 seeds to keep AFL startup fast
            if [[ "$count" -gt 200 ]]; then
                find "$seed_dir" -maxdepth 1 -type f | shuf -n 200 | xargs -I{} cp -n {} "$AFL_DIR/input/"
            else
                find "$seed_dir" -maxdepth 1 -type f -exec cp -n {} "$AFL_DIR/input/" \;
            fi
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
# Only resume if fuzzer_stats exists — proves a valid prior session (not a stale/corrupt dir)
if [[ -f "$AFL_DIR/output/default/fuzzer_stats" ]]; then
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
