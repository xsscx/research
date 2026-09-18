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
    echo "  --output-dir DIR     new evidence directory"
    echo "  --allow-findings     return success after recording Valgrind findings"
    echo "  --list               list targets"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tool) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VG_TOOL="$2"; shift 2 ;;
        --timeout) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VG_TIMEOUT="$2"; shift 2 ;;
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
for target in "${VG_SELECTED[@]}"; do
    VG_RUN_WORK="$VG_OUTPUT_BASE/$target/work"
    if ! vg_configure_target "$target"; then
        echo "ERROR: unknown target: $target" >&2
        vg_print_targets >&2
        exit 2
    fi
    mkdir -p "$VG_RUN_WORK"
    target_dir="$VG_OUTPUT_BASE/$target"
    vg_log="$target_dir/$VG_TOOL.log"
    stdout_log="$target_dir/stdout.log"
    stderr_log="$target_dir/stderr.log"

    [[ -x "$VG_BINARY" ]] || { echo "ERROR: missing binary for $target: $VG_BINARY" >&2; exit 2; }
    for required in "${VG_REQUIRED_FILES[@]}"; do
        [[ -e "$required" ]] || { echo "ERROR: missing input for $target: $required" >&2; exit 2; }
    done
    if ldd "$VG_BINARY" 2>/dev/null | grep -Eq 'libasan|libubsan|libtsan|clang_rt\.(asan|ubsan|tsan)'; then
        echo "ERROR: Valgrind must not wrap a sanitizer binary: $VG_BINARY" >&2
        exit 2
    fi

    if [[ ${#VG_PREPARE[@]} -gt 0 ]]; then
        LD_LIBRARY_PATH="$runtime_library_path" "${VG_PREPARE[@]}" >/dev/null
    fi

    common_args=(--error-exitcode=86 --num-callers=40 "--log-file=$vg_log")
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
        echo "[WARN] $target is usually most useful with $VG_RECOMMENDED_TOOL"
    fi
    set +e
    DEBUGINFOD_URLS='' LD_LIBRARY_PATH="$runtime_library_path" \
        timeout -k 5s "${VG_TIMEOUT}s" valgrind "${tool_args[@]}" "${common_args[@]}" \
        "$VG_BINARY" "${VG_ARGS[@]}" >"$stdout_log" 2>"$stderr_log"
    rc=$?
    set -e

    errors="$(sed -n 's/.*ERROR SUMMARY: \([0-9][0-9]*\) errors.*/\1/p' "$vg_log" 2>/dev/null | tail -1)"
    errors="${errors:-0}"
    result="clean"
    if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
        result="timeout"
        failures=$((failures + 1))
    elif [[ "$rc" -ne 0 || "$errors" -ne 0 ]]; then
        result="finding"
        [[ "$VG_ALLOW_FINDINGS" -eq 1 ]] || failures=$((failures + 1))
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$target" "$VG_TOOL" "$rc" "$errors" "$result" "$vg_log" >> "$summary"
    echo "[$([[ "$result" == clean ]] && echo OK || echo WARN)] $target: $result (rc=$rc errors=$errors)"
done

echo "Evidence: $VG_OUTPUT_BASE"
[[ "$failures" -eq 0 ]]
