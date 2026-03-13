#!/bin/bash
# afl/triage.sh — Triage AFL++ crashes and hangs against unpatched upstream
#
# Usage: ./afl/triage.sh <target>
#
# Runs each crash/hang through the UNPATCHED upstream iccDEV tool (Build/)
# with ASAN+UBSAN to determine if it's a real upstream bug or AFL artifact.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target>"
    echo "Available: dump toxml fromxml roundtrip tiffdump jpegdump pngdump fromcube"
    exit 1
fi

# Target-specific: upstream binary and argument template
case "$TARGET" in
    dump)
        UPSTREAM_BIN="$REPO_ROOT/iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile"
        UPSTREAM_LIB="$REPO_ROOT/iccDEV/Build/IccProfLib:$REPO_ROOT/iccDEV/Build/IccXML"
        UPSTREAM_EXTRA_ARGS="ALL"
        ;;
    toxml)
        UPSTREAM_BIN="$REPO_ROOT/iccDEV/Build/Tools/IccToXml/iccToXml"
        UPSTREAM_LIB="$REPO_ROOT/iccDEV/Build/IccProfLib:$REPO_ROOT/iccDEV/Build/IccXML"
        UPSTREAM_EXTRA_ARGS="/dev/null"
        ;;
    fromxml)
        UPSTREAM_BIN="$REPO_ROOT/iccDEV/Build/Tools/IccFromXml/iccFromXml"
        UPSTREAM_LIB="$REPO_ROOT/iccDEV/Build/IccProfLib:$REPO_ROOT/iccDEV/Build/IccXML"
        UPSTREAM_EXTRA_ARGS="/dev/null"
        ;;
    roundtrip)
        UPSTREAM_BIN="$REPO_ROOT/iccDEV/Build/Tools/IccRoundTrip/iccRoundTrip"
        UPSTREAM_LIB="$REPO_ROOT/iccDEV/Build/IccProfLib:$REPO_ROOT/iccDEV/Build/IccXML"
        UPSTREAM_EXTRA_ARGS=""
        ;;
    tiffdump)
        UPSTREAM_BIN="$REPO_ROOT/iccDEV/Build/Tools/IccTiffDump/iccTiffDump"
        UPSTREAM_LIB="$REPO_ROOT/iccDEV/Build/IccProfLib:$REPO_ROOT/iccDEV/Build/IccXML"
        UPSTREAM_EXTRA_ARGS=""
        ;;
    jpegdump)
        UPSTREAM_BIN="$REPO_ROOT/iccDEV/Build/Tools/IccJpegDump/iccJpegDump"
        UPSTREAM_LIB="$REPO_ROOT/iccDEV/Build/IccProfLib:$REPO_ROOT/iccDEV/Build/IccXML"
        UPSTREAM_EXTRA_ARGS=""
        ;;
    pngdump)
        UPSTREAM_BIN="$REPO_ROOT/iccDEV/Build/Tools/IccPngDump/iccPngDump"
        UPSTREAM_LIB="$REPO_ROOT/iccDEV/Build/IccProfLib:$REPO_ROOT/iccDEV/Build/IccXML"
        UPSTREAM_EXTRA_ARGS=""
        ;;
    fromcube)
        UPSTREAM_BIN="$REPO_ROOT/iccDEV/Build/Tools/IccFromCube/iccFromCube"
        UPSTREAM_LIB="$REPO_ROOT/iccDEV/Build/IccProfLib:$REPO_ROOT/iccDEV/Build/IccXML"
        UPSTREAM_EXTRA_ARGS="/dev/null"
        ;;
    *)
        echo "ERROR: Unknown target '$TARGET'"
        exit 1
        ;;
esac

AFL_DIR="$AFL_BASE/afl-$TARGET/output"

# Verify upstream binary
if [[ ! -x "$UPSTREAM_BIN" ]]; then
    echo "ERROR: Upstream binary not found: $UPSTREAM_BIN"
    echo "Build with: cd iccDEV/Build && cmake Cmake && make -j\$(nproc)"
    exit 1
fi

export LD_LIBRARY_PATH="$UPSTREAM_LIB"
export ASAN_OPTIONS="halt_on_error=0,detect_leaks=0,symbolize=1"
export UBSAN_OPTIONS="halt_on_error=0,print_stacktrace=1"

triage_dir() {
    local kind="$1"  # "crashes" or "hangs"
    local timeout_sec="$2"

    local total=0
    local upstream_bug=0
    local fuzzer_only=0

    # Collect from all instances
    local files=()
    for d in "$AFL_DIR"/*/; do
        local artifact_dir="$d/$kind"
        [[ -d "$artifact_dir" ]] || continue
        while IFS= read -r -d '' f; do
            files+=("$f")
        done < <(find "$artifact_dir" -type f ! -name README.txt -print0 2>/dev/null)
    done

    if [[ ${#files[@]} -eq 0 ]]; then
        echo "  No $kind found"
        return
    fi

    echo "  Triaging ${#files[@]} $kind..."
    echo ""

    for f in "${files[@]}"; do
        total=$((total + 1))
        local fname=$(basename "$f")
        local exit_code=0

        # Run with timeout against upstream binary directly
        local output
        output=$(timeout "$timeout_sec" "$UPSTREAM_BIN" "$f" $UPSTREAM_EXTRA_ARGS 2>&1) || exit_code=$?

        if [[ $exit_code -ge 128 ]]; then
            # Signal termination — potential upstream bug
            local signal=$((exit_code - 128))
            echo "  [UPSTREAM BUG] $fname — signal $signal (exit $exit_code)"
            echo "    $output" | tail -3 | sed 's/^/    /'
            upstream_bug=$((upstream_bug + 1))
        elif [[ $exit_code -eq 124 ]]; then
            # Timeout
            echo "  [TIMEOUT]      $fname — hung for ${timeout_sec}s"
            upstream_bug=$((upstream_bug + 1))
        else
            # Graceful exit — fuzzer-only
            fuzzer_only=$((fuzzer_only + 1))
        fi
    done

    echo ""
    echo "  $kind summary: $total total, $upstream_bug upstream bugs, $fuzzer_only fuzzer-only"
}

echo "=== AFL Triage: $TARGET ==="
echo ""
echo "Upstream binary: $UPSTREAM_BIN"
echo ""

echo "--- Crashes ---"
triage_dir "crashes" 15
echo ""

echo "--- Hangs ---"
triage_dir "hangs" 30
echo ""

echo "[OK] Triage complete"
