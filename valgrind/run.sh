#!/usr/bin/env bash
# Run registered iccDEV targets under Memcheck, Helgrind, DRD, Massif, or Callgrind.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VG_SOURCE_DIR="${VALGRIND_ICCDEV_DIR:-$REPO_ROOT/iccDEV}"
VG_BUILD_DIR="${VALGRIND_BUILD_DIR:-$REPO_ROOT/valgrind/build}"
VG_OUTPUT_BASE="${VALGRIND_OUTPUT_DIR:-$REPO_ROOT/valgrind/output}"
VG_OUTPUT_EXPLICIT=0
VG_TOOL="memcheck"
VG_TIMEOUT=120
VG_ALLOW_FINDINGS=0
VG_SELECTED=()

# shellcheck source=valgrind/targets.sh
source "$REPO_ROOT/valgrind/targets.sh"

usage() {
    echo "Usage: $0 [options] TARGET [TARGET ...]"
    echo "       $0 [options] all"
    echo "Options:"
    echo "  --tool memcheck|helgrind|drd|massif|callgrind"
    echo "  --timeout N          per-target timeout in seconds (default: 120)"
    echo "  --source-dir DIR     iccDEV source tree"
    echo "  --build-dir DIR      non-sanitized Valgrind build tree"
    echo "  --output-dir DIR     new evidence directory"
    echo "  --allow-findings     return success after recording Valgrind findings"
    echo "  --list               list targets"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tool) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VG_TOOL="$2"; shift 2 ;;
        --timeout) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VG_TIMEOUT="$2"; shift 2 ;;
        --source-dir) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VG_SOURCE_DIR="$2"; shift 2 ;;
        --build-dir) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VG_BUILD_DIR="$2"; shift 2 ;;
        --output-dir) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VG_OUTPUT_BASE="$2"; VG_OUTPUT_EXPLICIT=1; shift 2 ;;
        --allow-findings) VG_ALLOW_FINDINGS=1; shift ;;
        --list) vg_print_targets; exit 0 ;;
        -h|--help) usage; exit 0 ;;
        --*) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) VG_SELECTED+=("$1"); shift ;;
    esac
done

case "$VG_TOOL" in
    memcheck|helgrind|drd|massif|callgrind) ;;
    *) echo "ERROR: unsupported Valgrind tool: $VG_TOOL" >&2; exit 2 ;;
esac
[[ "$VG_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: --timeout must be a positive integer" >&2; exit 2; }
[[ ${#VG_SELECTED[@]} -gt 0 ]] || { usage >&2; exit 2; }
command -v valgrind >/dev/null 2>&1 || { echo "ERROR: valgrind is not installed" >&2; exit 127; }
command -v timeout >/dev/null 2>&1 || { echo "ERROR: timeout is not installed" >&2; exit 127; }
command -v ldd >/dev/null 2>&1 || { echo "ERROR: ldd is not installed" >&2; exit 127; }
command -v nm >/dev/null 2>&1 || { echo "ERROR: nm is not installed" >&2; exit 127; }
[[ -d "$VG_SOURCE_DIR" ]] || { echo "ERROR: source directory not found: $VG_SOURCE_DIR" >&2; exit 2; }
[[ -d "$VG_BUILD_DIR" ]] || { echo "ERROR: build directory not found: $VG_BUILD_DIR" >&2; exit 2; }

if [[ "${VG_SELECTED[0]}" == "all" ]]; then
    [[ ${#VG_SELECTED[@]} -eq 1 ]] || { echo "ERROR: all cannot be combined with named targets" >&2; exit 2; }
    VG_SELECTED=("${VG_TARGETS[@]}")
fi

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$VG_TOOL-$$"
if [[ "$VG_OUTPUT_EXPLICIT" -eq 0 ]]; then
    VG_OUTPUT_BASE="$VG_OUTPUT_BASE/$run_id"
fi
if [[ -e "$VG_OUTPUT_BASE" ]]; then
    echo "ERROR: evidence directory already exists: $VG_OUTPUT_BASE" >&2
    exit 2
fi
mkdir -p "$VG_OUTPUT_BASE"
VG_OUTPUT_BASE="$(cd "$VG_OUTPUT_BASE" && pwd)"
summary="$VG_OUTPUT_BASE/summary.tsv"
printf 'target\ttool\trc\terrors\tresult\tlog\n' > "$summary"

runtime_library_path="$VG_BUILD_DIR/IccProfLib:$VG_BUILD_DIR/IccXML:$VG_BUILD_DIR/IccJSON:$VG_BUILD_DIR/IccConnect"
if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
    runtime_library_path="$runtime_library_path:$LD_LIBRARY_PATH"
fi

failures=0
declare -A target_runs=()
for target in "${VG_SELECTED[@]}"; do
    target_run=$(( ${target_runs[$target]:-0} + 1 ))
    target_runs[$target]="$target_run"
    target_dir_name="$target"
    if [[ "$target_run" -gt 1 ]]; then
        target_dir_name="$target-$target_run"
    fi
    VG_RUN_WORK="$VG_OUTPUT_BASE/$target_dir_name/work"
    if ! vg_configure_target "$target"; then
        echo "ERROR: unknown target: $target" >&2
        vg_print_targets >&2
        exit 2
    fi
    mkdir -p "$VG_RUN_WORK"
    target_dir="$VG_OUTPUT_BASE/$target_dir_name"
    vg_log="$target_dir/$VG_TOOL.log"
    stdout_log="$target_dir/stdout.log"
    stderr_log="$target_dir/stderr.log"
    prepare_stdout_log="$target_dir/prepare.stdout.log"
    prepare_stderr_log="$target_dir/prepare.stderr.log"
    verify_log="$target_dir/verify.log"

    [[ -x "$VG_BINARY" ]] || { echo "ERROR: missing binary for $target: $VG_BINARY" >&2; exit 2; }
    for required in "${VG_REQUIRED_FILES[@]}"; do
        [[ -e "$required" ]] || { echo "ERROR: missing input for $target: $required" >&2; exit 2; }
    done
    if vg_binary_uses_sanitizer "$VG_BINARY" "$runtime_library_path" "$VG_BUILD_DIR"; then
        echo "ERROR: Valgrind must not wrap a sanitizer binary: $VG_BINARY" >&2
        exit 2
    fi

    if [[ ${#VG_PREPARE[@]} -gt 0 ]]; then
        prepare_stdout="$prepare_stdout_log"
        if [[ -n "$VG_PREPARE_STDOUT" ]]; then
            prepare_stdout="$VG_PREPARE_STDOUT"
        fi
        set +e
        LD_LIBRARY_PATH="$runtime_library_path" \
            timeout -k 5s "${VG_TIMEOUT}s" "${VG_PREPARE[@]}" \
            >"$prepare_stdout" 2>"$prepare_stderr_log"
        prepare_rc=$?
        set -e
        prepare_result=""
        if [[ "$prepare_rc" -eq 124 || "$prepare_rc" -eq 137 ]]; then
            prepare_result="setup-timeout"
        elif [[ "$prepare_rc" -ne 0 ]]; then
            prepare_result="setup-failure"
        else
            for prepared in "${VG_PREPARED_FILES[@]}"; do
                if [[ ! -s "$prepared" ]]; then
                    echo "expected prepared input is missing: $prepared" >> "$prepare_stderr_log"
                    prepare_result="setup-failure"
                    break
                fi
            done
        fi
        if [[ -n "$prepare_result" ]]; then
            printf '%s\t%s\t%s\tNA\t%s\t%s\n' \
                "$target" "$VG_TOOL" "$prepare_rc" "$prepare_result" "$prepare_stderr_log" >> "$summary"
            echo "[FAIL] $target: $prepare_result (rc=$prepare_rc errors=NA)"
            failures=$((failures + 1))
            continue
        fi
    fi

    common_args=(--error-exitcode=86 --num-callers=40 -s "--log-file=$vg_log")
    case "$VG_TOOL" in
        memcheck)
            tool_args=(--tool=memcheck --leak-check=full --show-leak-kinds=all
                "--errors-for-leak-kinds=definite,indirect,possible" --track-origins=yes --fair-sched=yes)
            ;;
        helgrind)
            tool_args=(--tool=helgrind --history-level=full --fair-sched=yes)
            ;;
        drd)
            tool_args=(--tool=drd --check-stack-var=yes)
            ;;
        massif)
            common_args=(--tool=massif "--massif-out-file=$target_dir/massif.out" "--log-file=$vg_log")
            tool_args=(--stacks=yes)
            ;;
        callgrind)
            common_args=(--tool=callgrind "--callgrind-out-file=$target_dir/callgrind.out" "--log-file=$vg_log")
            tool_args=(--collect-jumps=yes)
            ;;
    esac

    echo "[*] $VG_TOOL $target: $VG_NOTE"
    if [[ "$VG_RECOMMENDED_TOOL" != "$VG_TOOL" ]]; then
        echo "[INFO] $target is usually most useful with $VG_RECOMMENDED_TOOL"
    fi
    set +e
    env DEBUGINFOD_URLS= "LD_LIBRARY_PATH=$runtime_library_path" "${VG_ENV[@]}" \
        timeout -k 5s "${VG_TIMEOUT}s" valgrind "${tool_args[@]}" "${common_args[@]}" \
        "$VG_BINARY" "${VG_ARGS[@]}" >"$stdout_log" 2>"$stderr_log"
    rc=$?
    set -e

    log_complete=1
    case "$VG_TOOL" in
        memcheck|helgrind|drd)
            errors="$(sed -n 's/.*ERROR SUMMARY: \([0-9][0-9]*\) errors.*/\1/p' "$vg_log" 2>/dev/null | tail -1 || true)"
            if [[ -z "$errors" ]]; then
                errors="NA"
                log_complete=0
            fi
            ;;
        massif)
            errors=0
            [[ -s "$target_dir/massif.out" ]] || log_complete=0
            ;;
        callgrind)
            errors=0
            [[ -s "$target_dir/callgrind.out" ]] || log_complete=0
            ;;
    esac
    result="clean"
    if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
        result="timeout"
        failures=$((failures + 1))
    elif [[ "$log_complete" -ne 1 ]]; then
        result="incomplete-log"
        failures=$((failures + 1))
    elif [[ "$rc" -ge 128 ]]; then
        result="signal"
        failures=$((failures + 1))
    elif [[ "$rc" -ne 0 && "$rc" -ne 86 ]]; then
        result="tool-failure"
        failures=$((failures + 1))
    elif [[ "$rc" -eq 86 && "$errors" -eq 0 ]]; then
        result="tool-failure"
        failures=$((failures + 1))
    elif [[ "$errors" -ne 0 ]]; then
        result="finding"
        [[ "$VG_ALLOW_FINDINGS" -eq 1 ]] || failures=$((failures + 1))
    elif ! vg_verify_target "$stdout_log" >"$verify_log" 2>&1; then
        result="verification-failure"
        failures=$((failures + 1))
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$target" "$VG_TOOL" "$rc" "$errors" "$result" "$vg_log" >> "$summary"
    case "$result" in
        clean) level="OK" ;;
        finding) level="WARN" ;;
        *) level="FAIL" ;;
    esac
    echo "[$level] $target: $result (rc=$rc errors=$errors)"
done

echo "Evidence: $VG_OUTPUT_BASE"
[[ "$failures" -eq 0 ]]
