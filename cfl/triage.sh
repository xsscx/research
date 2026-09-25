#!/bin/bash
# Confirm a CFL finding with an independent unpatched iccDEV command-line tool.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CFL_ROOT="${CFL_ROOT:-$REPO_ROOT/cfl}"
SANITIZER="memory"
TIMEOUT_SEC="${CFL_TRIAGE_TIMEOUT:-60}"
MARK=0
MARK_DIR=""
FUZZER_INPUT=""
ARTIFACT=""

source "$CFL_ROOT/fuzzers.sh"

usage() {
    echo "Usage: $0 [--sanitizer memory] [--timeout N] [--mark] [--mark-dir DIR] <fuzzer> <artifact>"
    echo ""
    echo "Currently supported independent tool confirmation: icc_applynamedcmm_fuzzer"
}

require_value() {
    if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
        echo "ERROR: $1 requires a value" >&2
        exit 2
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sanitizer)
            require_value "$1" "${2:-}"
            SANITIZER="$2"
            shift 2
            ;;
        --timeout)
            require_value "$1" "${2:-}"
            if [[ ! "$2" =~ ^[1-9][0-9]*$ ]]; then
                echo "ERROR: --timeout requires a positive integer" >&2
                exit 2
            fi
            TIMEOUT_SEC="$2"
            shift 2
            ;;
        --mark)
            MARK=1
            shift
            ;;
        --mark-dir)
            require_value "$1" "${2:-}"
            MARK=1
            MARK_DIR="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        -*)
            echo "ERROR: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [[ -z "$FUZZER_INPUT" ]]; then
                FUZZER_INPUT="$1"
            elif [[ -z "$ARTIFACT" ]]; then
                ARTIFACT="$1"
            else
                echo "ERROR: unexpected argument: $1" >&2
                exit 2
            fi
            shift
            ;;
    esac
done

if [[ -z "$FUZZER_INPUT" || -z "$ARTIFACT" ]]; then
    usage >&2
    exit 2
fi
if [[ "$SANITIZER" != "memory" ]]; then
    echo "ERROR: independent CFL confirmation currently requires --sanitizer memory" >&2
    exit 2
fi
if [[ ! -f "$ARTIFACT" ]]; then
    echo "ERROR: artifact not found: $ARTIFACT" >&2
    exit 1
fi

FUZZER="$(cfl_normalize_fuzzer "$FUZZER_INPUT" 2>/dev/null || true)"
if [[ "$FUZZER" != "icc_applynamedcmm_fuzzer" ]]; then
    echo "ERROR: no verified standalone-tool mapping for: ${FUZZER:-$FUZZER_INPUT}" >&2
    exit 2
fi

FUZZER_BIN="${CFL_FUZZER_BIN:-$CFL_ROOT/bin-msan/$FUZZER}"
MSAN_BUILD_DIR="${ICCDEV_MSAN_BUILD_DIR:-$REPO_ROOT/iccDEV/Build-MSan}"
TOOL_BIN="${ICCDEV_MSAN_BIN:-$MSAN_BUILD_DIR/Tools/IccApplyNamedCmm/iccApplyNamedCmm}"
DATA_FILE="${CFL_APPLYNAMED_DATA:-$REPO_ROOT/docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt}"
MSAN_OPTIONS_VALUE="halt_on_error=1:abort_on_error=1:symbolize=1:exit_code=86"

for executable in "$FUZZER_BIN" "$TOOL_BIN"; do
    if [[ ! -x "$executable" ]]; then
        echo "ERROR: executable not found: $executable" >&2
        echo "Build independent tools with: ./afl/build-iccdev-msan.sh" >&2
        exit 1
    fi
    if ! nm "$executable" 2>/dev/null | grep '__msan_init' >/dev/null; then
        echo "ERROR: executable is not MSan-instrumented: $executable" >&2
        exit 1
    fi
done
if nm "$TOOL_BIN" 2>/dev/null | grep '__afl_' >/dev/null; then
    echo "ERROR: confirmation tool contains AFL instrumentation: $TOOL_BIN" >&2
    exit 1
fi
if ldd "$TOOL_BIN" 2>/dev/null | grep -Eq 'libstdc\+\+|libc\+\+'; then
    echo "ERROR: confirmation tool uses an uninstrumented shared C++ runtime: $TOOL_BIN" >&2
    exit 1
fi
if [[ ! -f "$DATA_FILE" ]]; then
    echo "ERROR: named-CMM data file not found: $DATA_FILE" >&2
    exit 1
fi
if [[ $(wc -c < "$ARTIFACT") -lt 132 ]]; then
    echo "ERROR: artifact is too small to be an ICC profile" >&2
    exit 1
fi

HEADER_INTENT="$(od -A n -t u4 --endian=big -j 64 -N 4 "$ARTIFACT" | tr -d ' ')"
TOOL_INTENT=$((40 + HEADER_INTENT % 4))
ARTIFACT_ABS="$(realpath "$ARTIFACT")"
SOURCE_COMMIT="$(git -C "$REPO_ROOT/iccDEV" rev-parse HEAD)"
if [[ ! -f "$MSAN_BUILD_DIR/.iccdev-source-commit" ]]; then
    echo "ERROR: missing independent-build source record: $MSAN_BUILD_DIR/.iccdev-source-commit" >&2
    exit 1
fi
BUILD_COMMIT="$(cat "$MSAN_BUILD_DIR/.iccdev-source-commit")"
if [[ "$BUILD_COMMIT" != "$SOURCE_COMMIT" ]]; then
    echo "ERROR: MSan tool commit $BUILD_COMMIT does not match iccDEV $SOURCE_COMMIT" >&2
    exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cfl-triage.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

run_and_capture() {
    local log_file="$1"
    shift
    local exit_code=0
    set +e
    MSAN_OPTIONS="$MSAN_OPTIONS_VALUE" LLVM_PROFILE_FILE=/dev/null \
        timeout "${TIMEOUT_SEC}s" "$@" >"$log_file" 2>&1
    exit_code=$?
    set -e
    printf '%s' "$exit_code"
}

has_msan_finding() {
    grep -Eq 'WARNING: MemorySanitizer:|SUMMARY: MemorySanitizer:' "$1"
}

first_frame_signature() {
    grep -E -m 1 '^[[:space:]]*#0 .* in .* /.*:[0-9]+:[0-9]+' "$1" |
        sed -E 's#^.* in (.*) /.*/([^/]+:[0-9]+:[0-9]+)$#\2 in \1#'
}

CANDIDATE_LOG="$TMP_DIR/candidate.log"
CANDIDATE_EXIT="$(run_and_capture "$CANDIDATE_LOG" "$FUZZER_BIN" -runs=1 "$ARTIFACT_ABS")"
if ! has_msan_finding "$CANDIDATE_LOG"; then
    echo "[UNCONFIRMED] CFL replay has no MemorySanitizer finding (exit $CANDIDATE_EXIT)"
    exit 1
fi

TOOL_LOG="$TMP_DIR/tool.log"
TOOL_EXIT="$(run_and_capture "$TOOL_LOG" "$TOOL_BIN" "$DATA_FILE" 0 1 "$ARTIFACT_ABS" "$TOOL_INTENT")"

echo "CFL candidate: MemorySanitizer finding (exit $CANDIDATE_EXIT)"
grep -E -m 2 'WARNING: MemorySanitizer:|SUMMARY: MemorySanitizer:' "$CANDIDATE_LOG" | sed 's/^/  /'
echo "Unpatched tool: $TOOL_BIN"
echo "iccDEV commit:  $SOURCE_COMMIT"
echo "Tool intent:    $TOOL_INTENT (BPC plus profile intent $((HEADER_INTENT % 4)))"

if ! has_msan_finding "$TOOL_LOG"; then
    echo "[UNCONFIRMED] unpatched iccDEV tool has no MemorySanitizer finding (exit $TOOL_EXIT)"
    exit 1
fi
CANDIDATE_SIGNATURE="$(first_frame_signature "$CANDIDATE_LOG")"
TOOL_SIGNATURE="$(first_frame_signature "$TOOL_LOG")"
if [[ -z "$CANDIDATE_SIGNATURE" || "$CANDIDATE_SIGNATURE" != "$TOOL_SIGNATURE" ]]; then
    echo "[UNCONFIRMED] sanitizer signatures differ" >&2
    echo "  CFL:  ${CANDIDATE_SIGNATURE:-<missing>}" >&2
    echo "  tool: ${TOOL_SIGNATURE:-<missing>}" >&2
    exit 1
fi

echo "[CONFIRMED] unpatched iccDEV tool reproduces the MemorySanitizer finding (exit $TOOL_EXIT)"
echo "  signature: $TOOL_SIGNATURE"
grep -E -m 4 'WARNING: MemorySanitizer:|GetNewApply|SUMMARY: MemorySanitizer:' "$TOOL_LOG" | sed 's/^/  /'

write_command() {
    local replay_artifact="$1"
    printf 'cd %q && MSAN_OPTIONS=%q timeout %qs %q %q 0 1 %q %q; printf '\''EXIT=%%s\\n'\'' "$?"' \
        "$REPO_ROOT" "$MSAN_OPTIONS_VALUE" "$TIMEOUT_SEC" "$TOOL_BIN" \
        "$DATA_FILE" "$replay_artifact" "$TOOL_INTENT"
}

echo "Reproduce with unpatched iccDEV tooling:"
printf '  '
write_command "$ARTIFACT_ABS"
printf '\n'
echo "Reproduce with the pinned upstream Docker image:"
printf '  %q %q; printf '\''EXIT=%%s\\n'\'' "$?"\n' \
    "$CFL_ROOT/reproduce-applynamedcmm-msan-docker.sh" "$ARTIFACT_ABS"

if [[ "$MARK" -eq 1 ]]; then
    MARK_DIR="${MARK_DIR:-$CFL_ROOT/marked/$FUZZER/crashes}"
    mkdir -p "$MARK_DIR"
    MARKED_ARTIFACT="$MARK_DIR/$(basename "$ARTIFACT")"
    cp -f "$ARTIFACT" "$MARKED_ARTIFACT"
    MARKED_ARTIFACT="$(realpath "$MARKED_ARTIFACT")"
    CMD_FILE="$MARKED_ARTIFACT.cmd"
    DOCKER_CMD_FILE="$MARKED_ARTIFACT.docker.cmd"
    {
        printf '# fuzzer=%s\n' "$FUZZER"
        printf '# classification=SANITIZER_CONFIRMED\n'
        printf '# sanitizer=memory\n'
        printf '# candidate_exit=%s\n' "$CANDIDATE_EXIT"
        printf '# tool_exit=%s\n' "$TOOL_EXIT"
        printf '# source=%s\n' "$ARTIFACT_ABS"
        printf '# iccdev_commit=%s\n' "$SOURCE_COMMIT"
        write_command "$MARKED_ARTIFACT"
        printf '\n'
    } > "$CMD_FILE"
    {
        printf '# fuzzer=%s\n' "$FUZZER"
        printf '# classification=SANITIZER_CONFIRMED\n'
        printf '# sanitizer=memory\n'
        printf '# container=ghcr.io/internationalcolorconsortium/iccdev@sha256:0504c43e0204e36aa36377fceee1de9c5f49468d578202c388525c75d42da079\n'
        printf '%q %q; printf '\''EXIT=%%s\\n'\'' "$?"\n' \
            "$CFL_ROOT/reproduce-applynamedcmm-msan-docker.sh" "$MARKED_ARTIFACT"
    } > "$DOCKER_CMD_FILE"
    echo "Marked artifact: $MARKED_ARTIFACT"
    echo "Reproducer:      $CMD_FILE"
    echo "Docker repro:    $DOCKER_CMD_FILE"
fi
