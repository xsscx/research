#!/bin/bash
# afl/triage.sh - Triage AFL++ crashes and hangs against isolated upstream
#
# Usage: ./afl/triage.sh <target>
#
# Runs each crash/hang through the isolated afl/iccDEV build deployed by
# afl/build.sh to determine if it is a real upstream bug or AFL artifact.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
BIN_DIR="${AFL_BIN_DIR:-$REPO_ROOT/afl/bin}"
TARGET="${1:-}"
TRIAGE_JOBS="${AFL_TRIAGE_JOBS:-$(nproc 2>/dev/null || echo 1)}"
TRIAGE_TIMEOUT="${AFL_TRIAGE_TIMEOUT:-15}"
TRIAGE_HANG_TIMEOUT="${AFL_TRIAGE_HANG_TIMEOUT:-30}"
TRIAGE_HANG_REPEATS="${AFL_TRIAGE_HANG_REPEATS:-1}"
TRIAGE_MARK_TIMEOUTS="${AFL_TRIAGE_MARK_TIMEOUTS:-1}"

source "$REPO_ROOT/afl/targets.sh"
source "$REPO_ROOT/afl/sanitizer-env.sh"

if [[ "$TARGET" == "--help" || "$TARGET" == "-h" ]]; then
    echo "Usage: $0 <target>"
    echo "       $0 <target> --jobs N"
    echo "       $0 <target> --mark [DIR]"
    echo ""
    afl_print_targets
    exit 0
fi

if [[ $# -gt 0 ]]; then
    TARGET="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --jobs)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
                echo "ERROR: --jobs requires a positive integer" >&2
                exit 1
            fi
            TRIAGE_JOBS="$2"
            shift 2
            ;;
        --mark)
            if [[ $# -ge 2 && "$2" != -* ]]; then
                AFL_MARK_DIR="$2"
                shift 2
            else
                AFL_MARK_DIR="$AFL_BASE/marked/$TARGET"
                shift
            fi
            ;;
        -*) echo "ERROR: Unknown option: $1" >&2; exit 1 ;;
        *) echo "ERROR: Unexpected argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target>"
    afl_print_targets
    exit 1
fi

if ! afl_configure_target "$TARGET"; then
    echo "ERROR: Unknown target '$TARGET'"
    afl_print_targets
    exit 1
fi

canonical_tool_dir() {
    local tool_name="$1"

    case "$tool_name" in
        iccApplyNamedCmm) echo "IccApplyNamedCmm" ;;
        iccApplyProfiles) echo "IccApplyProfiles" ;;
        iccApplySearch) echo "IccApplySearch" ;;
        iccApplyToLink) echo "IccApplyToLink" ;;
        iccDumpProfile) echo "IccDumpProfile" ;;
        iccFromCube) echo "IccFromCube" ;;
        iccFromJson) echo "IccFromJson" ;;
        iccFromXml) echo "IccFromXml" ;;
        iccJpegDump) echo "IccJpegDump" ;;
        iccPawgReport) echo "IccPawgReport" ;;
        iccPngDump) echo "IccPngDump" ;;
        iccProfileVisualize) echo "IccProfileVisualize" ;;
        iccRoundTrip) echo "IccRoundTrip" ;;
        iccSpecSepToTiff) echo "IccSpecSepToTiff" ;;
        iccTiffDump) echo "IccTiffDump" ;;
        iccToJson) echo "IccToJson" ;;
        iccToXml) echo "IccToXml" ;;
        iccV5DspObsToV4Dsp) echo "IccV5DspObsToV4Dsp" ;;
        *) return 1 ;;
    esac
}

join_existing_paths() {
    local out=""
    local sep=""
    local path

    for path in "$@"; do
        [[ -d "$path" ]] || continue
        out="${out}${sep}${path}"
        sep=":"
    done

    printf '%s' "$out"
}

select_replay_binary() {
    local tool_name
    local tool_dir
    local canonical_bin

    if [[ "${AFL_TRIAGE_CANONICAL_BUILD:-0}" != "1" && -x "$BINARY" ]]; then
        UPSTREAM_BIN="$BINARY"
        REPLAY_SOURCE="afl-bin"
        if command -v readelf >/dev/null 2>&1 && readelf -d "$BINARY" 2>/dev/null | grep -q 'Shared library: \[libIcc'; then
            REPLAY_LIB="$BIN_DIR"
        else
            REPLAY_LIB=""
        fi
        return
    fi

    tool_name="$(basename "$BINARY")"
    if tool_dir="$(canonical_tool_dir "$tool_name")"; then
        canonical_bin="$REPO_ROOT/iccDEV/Build/Tools/$tool_dir/$tool_name"
        if [[ -x "$canonical_bin" ]]; then
            UPSTREAM_BIN="$canonical_bin"
            REPLAY_SOURCE="canonical"
            if command -v readelf >/dev/null 2>&1 && readelf -d "$canonical_bin" 2>/dev/null | grep -q 'Shared library: \[libIcc'; then
                REPLAY_LIB="$(join_existing_paths \
                    "$REPO_ROOT/iccDEV/Build/IccProfLib" \
                    "$REPO_ROOT/iccDEV/Build/IccXML" \
                    "$REPO_ROOT/iccDEV/Build/IccJSON" \
                    "$REPO_ROOT/iccDEV/Build/IccConnect")"
            else
                REPLAY_LIB=""
            fi
            return
        fi
    fi

    UPSTREAM_BIN="$BINARY"
    REPLAY_SOURCE="afl-bin"
    if command -v readelf >/dev/null 2>&1 && readelf -d "$BINARY" 2>/dev/null | grep -q 'Shared library: \[libIcc'; then
        REPLAY_LIB="$BIN_DIR"
    else
        REPLAY_LIB=""
    fi
}

UPSTREAM_BIN=""
REPLAY_SOURCE=""
REPLAY_LIB=""
select_replay_binary
AFL_OUTPUT_DIR="$AFL_DIR/output"
AFL_MARK_DIR="${AFL_MARK_DIR:-}"
AFL_TRIAGE_INPUT_DIR="${AFL_TRIAGE_INPUT_DIR:-$AFL_OUTPUT_DIR}"

if [[ ! -x "$UPSTREAM_BIN" ]]; then
    echo "ERROR: Upstream binary not found: $UPSTREAM_BIN"
    echo "Build with: ./afl/build.sh"
    exit 1
fi

for required_file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -e "$required_file" ]]; then
        echo "ERROR: Required support file not found: $required_file"
        exit 1
    fi
done

afl_prepare_target_support_files "$TARGET"

if [[ -n "$REPLAY_LIB" ]]; then
    export LD_LIBRARY_PATH="$REPLAY_LIB"
else
    unset LD_LIBRARY_PATH
fi
afl_export_triage_sanitizer_env

quote_shell_arg() {
    local quoted
    printf -v quoted '%q' "$1"
    printf '%s' "$quoted"
}

write_marked_artifact() {
    local kind="$1"
    local classification="$2"
    local exit_code="$3"
    local source_file="$4"

    [[ -n "$AFL_MARK_DIR" ]] || return 0

    local mark_subdir="$AFL_MARK_DIR/$kind"
    local source_base
    local safe_base
    local marked_file
    local cmd_file
    local rel_marked_file
    local arg

    source_base="$(basename "$source_file")"
    safe_base="$(printf '%s' "$source_base" | tr -c 'A-Za-z0-9._,+-=' '_')"
    mkdir -p "$mark_subdir"
    marked_file="$mark_subdir/$safe_base"
    cp -f "$source_file" "$marked_file"
    cmd_file="$marked_file.cmd"

    rel_marked_file="${marked_file#$REPO_ROOT/}"
    {
        printf '# target=%s\n' "$TARGET"
        printf '# kind=%s\n' "$kind"
        printf '# classification=%s\n' "$classification"
        printf '# exit_code=%s\n' "$exit_code"
        printf '# source=%s\n' "$source_file"
        printf 'cd '
        quote_shell_arg "$REPO_ROOT"
        printf ' && '
        if [[ -n "${REPLAY_LIB:-}" ]]; then
            printf 'LD_LIBRARY_PATH='
            quote_shell_arg "$REPLAY_LIB"
            printf ' '
        fi
        printf 'ASAN_OPTIONS='
        quote_shell_arg "$ASAN_OPTIONS"
        printf ' UBSAN_OPTIONS='
        quote_shell_arg "$UBSAN_OPTIONS"
        printf ' timeout 60s '
        quote_shell_arg "$UPSTREAM_BIN"
        for arg in "${AFL_ARGS[@]}"; do
            printf ' '
            if [[ "$arg" == "@@" ]]; then
                quote_shell_arg "$rel_marked_file"
            else
                quote_shell_arg "$arg"
            fi
        done
        printf '\n'
    } > "$cmd_file"
}

classify_owner() {
    local output="$1"
    local frame

    while IFS= read -r frame; do
        case "$frame" in
            *"/iccanalyzer-lite/"*|*"/colorbleed_tools/"*|*"/cfl/"*)
                echo "OUR_CODE"
                return
                ;;
            *"/iccDEV/"*)
                echo "UPSTREAM"
                return
                ;;
        esac
    done < <(printf '%s\n' "$output" | grep -E '^\s*#[0-9]+ ' || true)

    echo "UNKNOWN"
}

classify_exit() {
    local exit_code="$1"
    local output="$2"

    if [[ "$exit_code" -eq 124 ]]; then
        if printf '%s\n' "$output" | grep -Eaiq 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)|runtime error:|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)'; then
            echo "TIMEOUT_WITH_SANITIZER"
        else
            echo "TIMEOUT"
        fi
    elif printf '%s\n' "$output" | grep -Eaiq 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)|runtime error:|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)'; then
        echo "SANITIZER"
    elif [[ "$exit_code" -eq 255 ]]; then
        echo "SOFT_FAIL"
    elif [[ "$exit_code" -ge 128 ]]; then
        echo "SIGNAL"
    elif [[ "$exit_code" -eq 0 ]]; then
        echo "CLEAN"
    else
        echo "SOFT_FAIL"
    fi
}

triage_dir() {
    local kind="$1"
    local timeout_sec="$2"

    local total=0
    local upstream_bug=0
    local fuzzer_only=0
    local soft_fail=0
    local clean=0
    local sanitizer=0
    local timeout_with_sanitizer=0
    local signal=0
    local timeout_count=0
    local files=()

    if [[ -d "$AFL_TRIAGE_INPUT_DIR/$kind" ]]; then
        while IFS= read -r -d '' f; do
            files+=("$f")
        done < <(find "$AFL_TRIAGE_INPUT_DIR/$kind" -maxdepth 1 -type f ! -name README.txt ! -name '*.cmd' -print0 2>/dev/null)
    fi

    for d in "$AFL_TRIAGE_INPUT_DIR"/*/; do
        local artifact_dir
        local d_base
        [[ -d "$d" ]] || continue
        d_base="$(basename "$d")"
        if [[ "$d_base" == "$kind" || "$d_base" == "$kind."* ]]; then
            continue
        fi
        while IFS= read -r -d '' artifact_dir; do
            while IFS= read -r -d '' f; do
                files+=("$f")
            done < <(find "$artifact_dir" -maxdepth 1 -type f ! -name README.txt ! -name '*.cmd' -print0 2>/dev/null)
        done < <(find "$d" -maxdepth 1 -type d \( -name "$kind" -o -name "$kind.*" \) -print0 2>/dev/null | sort -z)
    done

    if [[ ${#files[@]} -eq 0 ]]; then
        echo "  No $kind found"
        return
    fi

    echo "  Triaging ${#files[@]} $kind with ${TRIAGE_JOBS} job(s)..."
    echo ""

    local tmp_dir
    tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/afl-triage-${TARGET}-${kind}.XXXXXX")"

    triage_one() {
        local idx="$1"
        local f="$2"
        local exit_code=0
        local output=""
        local fname
        fname=$(basename "$f")

        local triage_args=()
        local arg
        for arg in "${AFL_ARGS[@]}"; do
            if [[ "$arg" == "@@" ]]; then
                triage_args+=("$f")
            else
                triage_args+=("$arg")
            fi
        done

        local run_count=1
        if [[ "$kind" == "hangs" ]]; then
            run_count="$TRIAGE_HANG_REPEATS"
        fi

        local run=1
        while [[ "$run" -le "$run_count" ]]; do
            local run_output=""
            local run_exit=0
            run_output=$(cd "$AFL_WORK_DIR" && timeout "$timeout_sec" "$UPSTREAM_BIN" "${triage_args[@]}" 2>&1) || run_exit=$?
            output="${output}${output:+
}=== replay ${run}/${run_count} exit=${run_exit} ===
${run_output}"
            if [[ "$run_exit" -ne 124 ]]; then
                exit_code="$run_exit"
                break
            fi
            exit_code="$run_exit"
            run=$((run + 1))
        done

        local classification
        local owner
        classification=$(classify_exit "$exit_code" "$output")
        owner=$(classify_owner "$output")

        {
            printf 'classification=%s\n' "$classification"
            printf 'owner=%s\n' "$owner"
            printf 'exit_code=%s\n' "$exit_code"
            printf 'fname=%s\n' "$fname"
            printf 'output<<EOF\n%s\nEOF\n' "$output"
        } > "$tmp_dir/$idx.result"
    }

    local active=0
    local idx=0
    for f in "${files[@]}"; do
        triage_one "$idx" "$f" &
        active=$((active + 1))
        idx=$((idx + 1))
        if [[ "$active" -ge "$TRIAGE_JOBS" ]]; then
            wait -n
            active=$((active - 1))
        fi
    done
    while [[ "$active" -gt 0 ]]; do
        wait -n
        active=$((active - 1))
    done

    for ((idx = 0; idx < ${#files[@]}; idx++)); do
        total=$((total + 1))
        local result="$tmp_dir/$idx.result"
        local classification owner exit_code fname output
        classification="$(sed -n 's/^classification=//p' "$result")"
        owner="$(sed -n 's/^owner=//p' "$result")"
        exit_code="$(sed -n 's/^exit_code=//p' "$result")"
        fname="$(sed -n 's/^fname=//p' "$result")"
        output="$(sed -n '/^output<<EOF$/,/^EOF$/p' "$result" | sed '1d;$d')"

        if [[ "$classification" == "SIGNAL" ]]; then
            local sig=$((exit_code - 128))
            echo "  [CRASH]       $fname - signal $sig (exit $exit_code, owner=$owner)"
            printf '%s\n' "$output" | tail -3 | sed 's/^/    /'
            write_marked_artifact "$kind" "$classification" "$exit_code" "${files[$idx]}"
            upstream_bug=$((upstream_bug + 1))
            signal=$((signal + 1))
        elif [[ "$classification" == "SANITIZER" ]]; then
            echo "  [SANITIZER]   $fname - sanitizer finding (exit $exit_code, owner=$owner)"
            printf '%s\n' "$output" | grep -Eai 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)|runtime error:|SUMMARY:' | tail -3 | sed 's/^/    /'
            write_marked_artifact "$kind" "$classification" "$exit_code" "${files[$idx]}"
            upstream_bug=$((upstream_bug + 1))
            sanitizer=$((sanitizer + 1))
        elif [[ "$classification" == "TIMEOUT_WITH_SANITIZER" ]]; then
            echo "  [TIMEOUT+SAN] $fname - sanitizer output before ${timeout_sec}s timeout (owner=$owner)"
            printf '%s\n' "$output" | grep -Eai 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)|runtime error:|SUMMARY:' | tail -3 | sed 's/^/    /'
            write_marked_artifact "$kind" "$classification" "$exit_code" "${files[$idx]}"
            upstream_bug=$((upstream_bug + 1))
            timeout_with_sanitizer=$((timeout_with_sanitizer + 1))
        elif [[ "$classification" == "TIMEOUT" ]]; then
            echo "  [TIMEOUT]     $fname - hung for ${timeout_sec}s"
            if [[ "$TRIAGE_MARK_TIMEOUTS" -eq 1 ]]; then
                write_marked_artifact "$kind" "$classification" "$exit_code" "${files[$idx]}"
                upstream_bug=$((upstream_bug + 1))
            fi
            timeout_count=$((timeout_count + 1))
        elif [[ "$classification" == "SOFT_FAIL" ]]; then
            echo "  [SOFT_FAIL]   $fname - graceful tool failure (exit $exit_code)"
            soft_fail=$((soft_fail + 1))
        else
            clean=$((clean + 1))
            fuzzer_only=$((fuzzer_only + 1))
        fi
    done
    rm -rf "$tmp_dir"

    echo ""
    echo "  $kind summary: $total total, $upstream_bug actionable, $fuzzer_only clean, $soft_fail soft-fail, $sanitizer sanitizer, $timeout_with_sanitizer timeout-with-sanitizer, $signal signal, $timeout_count timeout"
}

echo "=== AFL Triage: $TARGET ==="
echo ""
echo "Upstream binary: $UPSTREAM_BIN"
echo "Replay source:   $REPLAY_SOURCE"
echo "Library path:    ${REPLAY_LIB:-<tool runpath>}"
echo "Input directory: ${AFL_TRIAGE_INPUT_DIR}"
echo "Mark directory:  ${AFL_MARK_DIR:-<disabled>}"
echo ""

echo "--- Crashes ---"
triage_dir "crashes" "$TRIAGE_TIMEOUT"
echo ""

echo "--- Hangs ---"
triage_dir "hangs" "$TRIAGE_HANG_TIMEOUT"
echo ""

echo "[OK] Triage complete"
