#!/usr/bin/env bash
# test-iccdev-tools-comprehensive.sh — Cycle all iccDEV tools over research repo files
#
# Runs each iccDEV tool against all relevant test files in:
#   test-profiles/, extended-test-profiles/, fuzz/graphics/icc/,
#   iccDEV/Testing/Fuzzing/seeds/tiff/spectral/
#
# Reports: PASS/FAIL/ASAN/UBSAN per tool per file.
#
# Usage: ./test-iccdev-tools-comprehensive.sh [--tool TOOLNAME] [--max N] [--timeout T]
#
# Options:
#   --tool TOOLNAME  Test only this tool (e.g., iccDumpProfile)
#   --max N          Max files per tool (default: 50)
#   --timeout T      Per-file timeout in seconds (default: 30)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ICCDEV_BUILD="${ICCDEV_BUILD:-$REPO_ROOT/iccDEV/Build}"
export LD_LIBRARY_PATH="${ICCDEV_BUILD}/IccProfLib:${ICCDEV_BUILD}/IccXML"
export ASAN_OPTIONS="halt_on_error=0,detect_leaks=0"
export LLVM_PROFILE_FILE="/dev/null"

TOOL_FILTER=""
MAX_FILES=50
TIMEOUT=30

while [ $# -gt 0 ]; do
    case "$1" in
        --tool)    TOOL_FILTER="$2"; shift 2 ;;
        --max)     MAX_FILES="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--tool TOOLNAME] [--max N] [--timeout T]"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# ---------- Tool definitions ----------
# Format: tool_binary  args_template  input_type
# input_type: icc=ICC profiles, tiff=TIFF files, xml=ICC XML files

TOOLS_DIR="${ICCDEV_BUILD}/Tools"

declare -A TOOL_CMDS=(
    [iccDumpProfile]="${TOOLS_DIR}/IccDumpProfile/iccDumpProfile"
    [iccTiffDump]="${TOOLS_DIR}/IccTiffDump/iccTiffDump"
    [iccToXml]="${TOOLS_DIR}/IccToXml/iccToXml"
    [iccRoundTrip]="${TOOLS_DIR}/IccRoundTrip/iccRoundTrip"
)

declare -A TOOL_ARGS=(
    [iccDumpProfile]="{INPUT}"
    [iccTiffDump]="{INPUT}"
    [iccToXml]="{INPUT} /dev/null"
    [iccRoundTrip]="{INPUT}"
)

declare -A TOOL_INPUT_TYPE=(
    [iccDumpProfile]="icc"
    [iccTiffDump]="tiff"
    [iccToXml]="icc"
    [iccRoundTrip]="icc"
)

# ---------- File collection ----------
collect_icc_files() {
    {
        find "$REPO_ROOT/test-profiles" -maxdepth 1 -name '*.icc' -type f 2>/dev/null
        find "$REPO_ROOT/extended-test-profiles" -maxdepth 1 -name '*.icc' -type f 2>/dev/null
        find "$REPO_ROOT/fuzz/graphics/icc" -maxdepth 1 -name '*.icc' -type f 2>/dev/null | sort -R | head -20
    } | sort -u | head -"$MAX_FILES"
}

collect_tiff_files() {
    {
        find "$REPO_ROOT/iccDEV/Testing/Fuzzing/seeds/tiff" -name '*.tif' -type f 2>/dev/null
        find "$REPO_ROOT/fuzz/graphics/tif" -maxdepth 1 -name '*.tif' -type f 2>/dev/null | sort -R | head -10
        find "$REPO_ROOT/test-profiles/spectral" -name '*.tif' -type f 2>/dev/null
    } | sort -u | head -"$MAX_FILES"
}

collect_xml_files() {
    find "$REPO_ROOT/fuzz/xml/icc" -maxdepth 1 -name '*.xml' -type f 2>/dev/null | head -"$MAX_FILES"
}

# ---------- Execution ----------
TOTAL=0; PASS=0; FAIL=0; ASAN_HITS=0; TIMEOUTS=0

log() { echo "[$(date +%H:%M:%S)] $*"; }

run_tool() {
    local tool_name="$1"
    local input_file="$2"
    local cmd="${TOOL_CMDS[$tool_name]}"
    local args="${TOOL_ARGS[$tool_name]}"
    args="${args//\{INPUT\}/$input_file}"

    TOTAL=$((TOTAL+1))

    local output
    output=$(timeout "$TIMEOUT" $cmd $args 2>&1) || true
    local ec=$?

    local asan
    asan=$(echo "$output" | grep -c "ERROR: AddressSanitizer" || true)
    local ubsan
    ubsan=$(echo "$output" | grep -c "runtime error:" || true)
    local fname
    fname=$(basename "$input_file")

    if [ "$ec" -eq 124 ]; then
        TIMEOUTS=$((TIMEOUTS+1))
        echo "  [TIMEOUT] $tool_name: $fname (${TIMEOUT}s)"
    elif [ "$asan" -gt 0 ] || [ "$ubsan" -gt 0 ]; then
        ASAN_HITS=$((ASAN_HITS+1))
        FAIL=$((FAIL+1))
        echo "  [ASAN] $tool_name: $fname (asan=$asan ubsan=$ubsan ec=$ec)"
    elif [ "$ec" -gt 128 ]; then
        FAIL=$((FAIL+1))
        echo "  [CRASH] $tool_name: $fname (exit=$ec signal=$((ec-128)))"
    else
        PASS=$((PASS+1))
    fi
}

# ---------- Main loop ----------
log "iccDEV Tool Comprehensive Test"
log "Build: $ICCDEV_BUILD"
log "Max files/tool: $MAX_FILES  Timeout: ${TIMEOUT}s"
echo ""

for tool_name in "${!TOOL_CMDS[@]}"; do
    if [ -n "$TOOL_FILTER" ] && [ "$tool_name" != "$TOOL_FILTER" ]; then
        continue
    fi

    cmd="${TOOL_CMDS[$tool_name]}"
    if [ ! -x "$cmd" ]; then
        log "SKIP $tool_name (binary not found)"
        continue
    fi

    input_type="${TOOL_INPUT_TYPE[$tool_name]}"
    log "Testing $tool_name (input: $input_type)"

    case "$input_type" in
        icc)  files=$(collect_icc_files) ;;
        tiff) files=$(collect_tiff_files) ;;
        xml)  files=$(collect_xml_files) ;;
        *)    log "Unknown input type: $input_type"; continue ;;
    esac

    count=0
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        run_tool "$tool_name" "$f"
        count=$((count+1))
    done <<< "$files"
    log "  $tool_name: $count files tested"
    echo ""
done

# ---------- Summary ----------
echo ""
log "========================================="
log "Comprehensive Tool Test Summary"
log "========================================="
log "Total: $TOTAL  Pass: $PASS  Fail: $FAIL"
log "ASAN hits: $ASAN_HITS  Timeouts: $TIMEOUTS"

if [ "$ASAN_HITS" -eq 0 ] && [ "$FAIL" -eq 0 ]; then
    log "RESULT: ALL CLEAN"
    exit 0
else
    log "RESULT: $FAIL FAILURES ($ASAN_HITS ASAN)"
    exit 1
fi
