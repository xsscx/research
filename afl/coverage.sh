#!/bin/bash
# afl/coverage.sh - Build static coverage binaries and report AFL corpus coverage
#
# Usage: ./afl/coverage.sh <target> [--no-reachability] [--report-root DIR]
#
# Builds a static LLVM source-coverage binary for the selected iccDEV tool,
# optionally builds a static gllvm reachability binary for the same tool, then
# runs AFLplusplus cov-analysis against that target's AFL output directory.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
BIN_DIR="${AFL_BIN_DIR:-$REPO_ROOT/afl/bin}"
ICCDEV_SRC="${AFL_COVERAGE_ICCDEV_DIR:-$REPO_ROOT/iccDEV}"
TARGET=""
RUN_REACHABILITY=1
JOBS="${AFL_COVERAGE_JOBS:-2}"
REPORT_ROOT="${AFL_COVERAGE_REPORT_ROOT:-}"
INSTANCE="${AFL_COVERAGE_INSTANCE:-}"
REUSE_BUILD="${AFL_COVERAGE_REUSE_BUILD:-0}"
OUTPUT_DIR_OVERRIDE="${AFL_COVERAGE_OUTPUT_DIR:-}"
REPORT_NAME="${AFL_COVERAGE_REPORT_NAME:-}"
COVERAGE_TIMEOUT="${AFL_COVERAGE_TIMEOUT:-5}"

source "$REPO_ROOT/afl/targets.sh"

if [[ -f "$HOME/work/copilot/tools/env.sh" ]]; then
    # Prefer locally-installed AFL++ analysis tools when available.
    # shellcheck source=/dev/null
    source "$HOME/work/copilot/tools/env.sh"
fi

usage() {
    sed -n '2,8p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  --no-reachability  run cov-analysis without fuzz-reachability annotation"
    echo "  --report-root DIR  write build and report artifacts under DIR"
    echo "  --output-dir DIR   use an explicit AFL++ output directory"
    echo "  --instance NAME    select AFL output instance; default auto-detects"
    echo "  --report-name NAME report directory suffix; default target name"
    echo "  --jobs N           build/replay jobs; default ${JOBS}"
    echo "  --reuse-build      keep existing coverage/reachability build dirs"
    echo "  AFL_COVERAGE_TIMEOUT=N  cov-analysis per-input timeout; default ${COVERAGE_TIMEOUT}s"
    echo "  AFL_COVERAGE_CC/CXX     override the clang/clang++ coverage compiler"
    echo "  --help, -h         show help"
    echo ""
    afl_print_targets
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-reachability) RUN_REACHABILITY=0; shift ;;
        --report-root) REPORT_ROOT="${2:-}"; shift 2 ;;
        --output-dir) OUTPUT_DIR_OVERRIDE="${2:-}"; shift 2 ;;
        --instance) INSTANCE="${2:-}"; shift 2 ;;
        --report-name) REPORT_NAME="${2:-}"; shift 2 ;;
        --jobs)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
                echo "ERROR: --jobs requires a positive integer" >&2
                exit 1
            fi
            JOBS="$2"
            shift 2
            ;;
        --reuse-build) REUSE_BUILD=1; shift ;;
        --help|-h) usage; exit 0 ;;
        -*) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 1 ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    usage
    exit 1
fi

if ! afl_configure_target "$TARGET"; then
    echo "ERROR: Unknown target '$TARGET'" >&2
    afl_print_targets >&2
    exit 1
fi

if [[ ! -f "$ICCDEV_SRC/Build/Cmake/CMakeLists.txt" ]]; then
    echo "ERROR: iccDEV CMake source not found: $ICCDEV_SRC/Build/Cmake" >&2
    exit 1
fi
if ! command -v cov-analysis >/dev/null 2>&1; then
    echo "ERROR: cov-analysis not found in PATH" >&2
    exit 1
fi
if [[ "$RUN_REACHABILITY" -eq 1 ]] && ! command -v reachability >/dev/null 2>&1; then
    echo "ERROR: reachability not found in PATH" >&2
    exit 1
fi

for required_file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -e "$required_file" ]]; then
        echo "ERROR: Required support file not found: $required_file" >&2
        exit 1
    fi
done
afl_prepare_target_support_files "$TARGET"

first_instance() {
    local output_dir="$1"
    local child

    for name in default main; do
        if [[ -d "$output_dir/$name/queue" ]]; then
            printf '%s' "$name"
            return 0
        fi
    done

    while IFS= read -r -d '' child; do
        if [[ -d "$child/queue" ]]; then
            basename "$child"
            return 0
        fi
    done < <(find "$output_dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | sort -z)

    printf 'default'
}

quote_cmd() {
    local out=""
    local sep=""
    local arg
    for arg in "$@"; do
        out+="$sep"
        printf -v arg '%q' "$arg"
        out+="$arg"
        sep=" "
    done
    printf '%s' "$out"
}

sanitize_key() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9_.+-' '-'
}

first_tool() {
    local tool
    for tool in "$@"; do
        if command -v "$tool" >/dev/null 2>&1; then
            command -v "$tool"
            return 0
        fi
    done
    return 1
}

demangle_symbol_file() {
    local in_file="$1"
    local out_file="$2"
    local demangler=""
    local line sym demangled

    [[ -s "$in_file" ]] || return 0
    demangler="$(first_tool llvm-cxxfilt-22 llvm-cxxfilt-21 llvm-cxxfilt c++filt || true)"
    [[ -n "$demangler" ]] || return 0

    : > "$out_file"
    while IFS= read -r line; do
        if [[ "$line" == fun:* ]]; then
            sym="${line#fun:}"
            demangled="$(printf '%s\n' "$sym" | "$demangler" 2>/dev/null || printf '%s' "$sym")"
            printf 'fun:%s\n' "$demangled" >> "$out_file"
        else
            printf '%s\n' "$line" >> "$out_file"
        fi
    done < "$in_file"
}

write_symbol_report() {
    local out_file="$1"
    local title="$2"
    local source_file="$3"

    {
        printf '# %s\n' "$title"
        printf '# Generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '# Target: %s\n' "$TARGET"
        printf '# Coverage report: %s\n' "$TARGET_REPORT_DIR"
        printf '# Entries use SanitizerCoverage fun: syntax for easy reuse.\n'
        sed 's/^/fun:/' "$source_file"
    } > "$out_file"
}

update_latest_report_link() {
    local report_abs generated_abs report_parent link_name link_path

    report_abs="$(cd "$REPORT_ROOT" && pwd)"
    generated_abs="$(cd "$AFL_BASE/reports/generated" && pwd)"
    report_parent="$(dirname "$report_abs")"
    [[ "$report_parent" == "$generated_abs" ]] || return 0

    link_name="$(basename "$report_abs")"
    link_path="$generated_abs/latest"
    if [[ -e "$link_path" && ! -L "$link_path" ]]; then
        echo "WARN: latest report path exists and is not a symlink: $link_path" >&2
        return 0
    fi
    ln -sfn "$link_name" "$link_path"
}

generate_runtime_function_reports() {
    local coverage_json="$TARGET_REPORT_DIR/coverage.json"
    local tmp_dir="$REPORT_ROOT/tmp/function-lists-$TARGET"
    local covered_raw="$tmp_dir/covered.raw"
    local present_raw="$tmp_dir/present.raw"
    local reachable_raw="$tmp_dir/statically_reachable.raw"
    local unreachable_raw="$tmp_dir/statically_unreachable.raw"
    local reachable_present_raw="$tmp_dir/statically_reachable_present.raw"
    local not_covered_reachable_raw="$tmp_dir/not_covered_but_statically_reachable.raw"
    local covered_unreachable_raw="$tmp_dir/covered_but_statically_unreachable.raw"

    if ! command -v jq >/dev/null 2>&1; then
        echo "WARN: jq not found; skipping target-sensitive function coverage lists" >&2
        return 0
    fi
    if [[ ! -s "$coverage_json" ]]; then
        echo "WARN: coverage JSON not found; skipping target-sensitive function coverage lists: $coverage_json" >&2
        return 0
    fi

    mkdir -p "$tmp_dir"
    jq -r '.data[]?.functions[]? | .name | sub("^[^:]*:"; "")' "$coverage_json" | sort -u > "$present_raw"
    jq -r '.data[]?.functions[]? | select(.count > 0) | .name | sub("^[^:]*:"; "")' "$coverage_json" | sort -u > "$covered_raw"
    write_symbol_report "$COVERED_TXT" "Runtime-covered functions from coverage.json" "$covered_raw"
    demangle_symbol_file "$COVERED_TXT" "$COVERED_DEMANGLED_TXT"

    if [[ "$RUN_REACHABILITY" -eq 1 && -s "$STATICALLY_REACHABLE_TXT" && -s "$STATICALLY_UNREACHABLE_TXT" ]]; then
        awk '/^fun:/ {print substr($0, 5)}' "$STATICALLY_REACHABLE_TXT" | sort -u > "$reachable_raw"
        awk '/^fun:/ {print substr($0, 5)}' "$STATICALLY_UNREACHABLE_TXT" | sort -u > "$unreachable_raw"
        comm -12 "$reachable_raw" "$present_raw" > "$reachable_present_raw"
        comm -23 "$reachable_present_raw" "$covered_raw" > "$not_covered_reachable_raw"
        comm -12 "$unreachable_raw" "$covered_raw" > "$covered_unreachable_raw"
        write_symbol_report "$NOT_COVERED_REACHABLE_TXT" "Target-present functions not covered but statically reachable" "$not_covered_reachable_raw"
        write_symbol_report "$COVERED_UNREACHABLE_TXT" "Runtime-covered functions classified statically unreachable" "$covered_unreachable_raw"
        demangle_symbol_file "$NOT_COVERED_REACHABLE_TXT" "$NOT_COVERED_REACHABLE_DEMANGLED_TXT"
        demangle_symbol_file "$COVERED_UNREACHABLE_TXT" "$COVERED_UNREACHABLE_DEMANGLED_TXT"
    fi
}

TOOL_BIN_NAME="$(basename "$BINARY")"
CMAKE_TARGET="$TOOL_BIN_NAME"
OUTPUT_DIR="${OUTPUT_DIR_OVERRIDE:-$AFL_DIR/output}"
if [[ ! -d "$OUTPUT_DIR" ]]; then
    echo "ERROR: AFL output directory not found: $OUTPUT_DIR" >&2
    exit 1
fi
if [[ -z "$INSTANCE" ]]; then
    INSTANCE="$(first_instance "$OUTPUT_DIR")"
fi
if [[ ! -d "$OUTPUT_DIR/$INSTANCE/queue" ]]; then
    echo "ERROR: AFL queue not found: $OUTPUT_DIR/$INSTANCE/queue" >&2
    exit 1
fi

if [[ -z "$REPORT_ROOT" ]]; then
    REPORT_ROOT="$AFL_BASE/reports/generated/afl-coverage-$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$REPORT_ROOT"
mkdir -p "$AFL_BASE/reports/generated"
update_latest_report_link
if [[ -z "$REPORT_NAME" ]]; then
    REPORT_NAME="$TARGET"
fi

instance_count=0
while IFS= read -r child; do
    if [[ -d "$child/queue" ]]; then
        instance_count=$((instance_count + 1))
    fi
done < <(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | sort)

COV_ANALYSIS_OUTPUT_DIR="$OUTPUT_DIR"
if [[ "$instance_count" -gt 1 ]]; then
    COV_ANALYSIS_OUTPUT_DIR="$REPORT_ROOT/tmp/cov-analysis-output-$TARGET-$INSTANCE"
    rm -rf "$COV_ANALYSIS_OUTPUT_DIR"
    mkdir -p "$COV_ANALYSIS_OUTPUT_DIR/$INSTANCE"
    if ! cp -al "$OUTPUT_DIR/$INSTANCE/." "$COV_ANALYSIS_OUTPUT_DIR/$INSTANCE/" 2>/dev/null; then
        cp -a "$OUTPUT_DIR/$INSTANCE/." "$COV_ANALYSIS_OUTPUT_DIR/$INSTANCE/"
    fi
    echo "[*] Isolated AFL instance for cov-analysis: $OUTPUT_DIR/$INSTANCE -> $COV_ANALYSIS_OUTPUT_DIR/$INSTANCE"
fi

COVERAGE_CACHE_KEY="$(sanitize_key "${AFL_COVERAGE_CACHE_KEY:-$TOOL_BIN_NAME}")"
COV_BUILD_DIR="$REPORT_ROOT/iccdev-cov-static-build-$COVERAGE_CACHE_KEY"
REACH_BUILD_DIR="$REPORT_ROOT/iccdev-reach-static-build-$COVERAGE_CACHE_KEY"
TARGET_REPORT_DIR="$REPORT_ROOT/cov-$REPORT_NAME-static"
REACH_JSON="$REPORT_ROOT/reachability-$COVERAGE_CACHE_KEY-static.json"
STATICALLY_REACHABLE_TXT="$REPORT_ROOT/statically_reachable-$COVERAGE_CACHE_KEY.txt"
STATICALLY_UNREACHABLE_TXT="$REPORT_ROOT/statically_unreachable-$COVERAGE_CACHE_KEY.txt"
STATICALLY_REACHABLE_DEMANGLED_TXT="$REPORT_ROOT/statically_reachable-$COVERAGE_CACHE_KEY.demangled.txt"
STATICALLY_UNREACHABLE_DEMANGLED_TXT="$REPORT_ROOT/statically_unreachable-$COVERAGE_CACHE_KEY.demangled.txt"
TARGET_REACH_JSON="$REPORT_ROOT/reachability-$TARGET-static.json"
COVERED_TXT="$REPORT_ROOT/covered-$TARGET.txt"
NOT_COVERED_REACHABLE_TXT="$REPORT_ROOT/not_covered_but_statically_reachable-$TARGET.txt"
COVERED_UNREACHABLE_TXT="$REPORT_ROOT/covered_but_statically_unreachable-$TARGET.txt"
COVERED_DEMANGLED_TXT="$REPORT_ROOT/covered-$TARGET.demangled.txt"
NOT_COVERED_REACHABLE_DEMANGLED_TXT="$REPORT_ROOT/not_covered_but_statically_reachable-$TARGET.demangled.txt"
COVERED_UNREACHABLE_DEMANGLED_TXT="$REPORT_ROOT/covered_but_statically_unreachable-$TARGET.demangled.txt"
TARGET_STATICALLY_REACHABLE_TXT="$REPORT_ROOT/statically_reachable-$TARGET.txt"
TARGET_STATICALLY_UNREACHABLE_TXT="$REPORT_ROOT/statically_unreachable-$TARGET.txt"
TARGET_STATICALLY_REACHABLE_DEMANGLED_TXT="$REPORT_ROOT/statically_reachable-$TARGET.demangled.txt"
TARGET_STATICALLY_UNREACHABLE_DEMANGLED_TXT="$REPORT_ROOT/statically_unreachable-$TARGET.demangled.txt"

if [[ "$REUSE_BUILD" -ne 1 ]]; then
    rm -rf "$COV_BUILD_DIR" "$REACH_BUILD_DIR" "$TARGET_REPORT_DIR" \
        "$REACH_JSON" "$STATICALLY_REACHABLE_TXT" "$STATICALLY_UNREACHABLE_TXT" \
        "$COVERED_TXT" "$NOT_COVERED_REACHABLE_TXT" "$COVERED_UNREACHABLE_TXT"
fi

echo "[*] Target:      $TARGET"
echo "[*] Tool:        $TOOL_BIN_NAME"
echo "[*] Cache key:   $COVERAGE_CACHE_KEY"
echo "[*] AFL output:  $OUTPUT_DIR ($INSTANCE)"
echo "[*] Report root: $REPORT_ROOT"
echo "[*] Link mode:   static"
echo "[*] Timeout:     ${COVERAGE_TIMEOUT}s"

COV_CC="${AFL_COVERAGE_CC:-$(first_tool clang-22 clang-21 clang)}"
COV_CXX="${AFL_COVERAGE_CXX:-$(first_tool clang++-22 clang++-21 clang++)}"
if [[ -z "$COV_CC" || -z "$COV_CXX" ]]; then
    echo "ERROR: clang/clang++ coverage compiler not found" >&2
    exit 1
fi
echo "[*] Compiler:    $COV_CC / $COV_CXX"
if [[ "$RUN_REACHABILITY" -eq 1 ]]; then
    echo "[*] Reachability: $(reachability check-toolchain | sed -n '1p')"
fi

echo "[*] Building static LLVM coverage binary..."
CC="$COV_CC" CXX="$COV_CXX" cov-analysis build \
    cmake -S "$ICCDEV_SRC/Build/Cmake" -B "$COV_BUILD_DIR" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_COMPILER="$COV_CC" \
        -DCMAKE_CXX_COMPILER="$COV_CXX" \
        -DENABLE_TOOLS=ON \
        -DENABLE_SHARED_LIBS=OFF \
        -DENABLE_STATIC_LIBS=ON
CC="$COV_CC" CXX="$COV_CXX" cov-analysis build \
    cmake --build "$COV_BUILD_DIR" --target "$CMAKE_TARGET" -j "$JOBS"

COV_BIN="$(find "$COV_BUILD_DIR/Tools" -path "*/$TOOL_BIN_NAME" -type f -perm -111 -print -quit)"
if [[ -z "$COV_BIN" || ! -x "$COV_BIN" ]]; then
    echo "ERROR: coverage binary not found for $TOOL_BIN_NAME under $COV_BUILD_DIR/Tools" >&2
    exit 1
fi
if command -v readelf >/dev/null 2>&1 && readelf -d "$COV_BIN" 2>/dev/null | grep -q 'Shared library: \[libIcc'; then
    echo "ERROR: coverage binary still links iccDEV shared libraries: $COV_BIN" >&2
    exit 1
fi

REACH_ARG=()
if [[ "$RUN_REACHABILITY" -eq 1 ]]; then
    if [[ "$REUSE_BUILD" -eq 1 && -s "$REACH_JSON" && -s "$STATICALLY_REACHABLE_TXT" && -s "$STATICALLY_UNREACHABLE_TXT" ]]; then
        echo "[*] Reusing reachability report: $REACH_JSON"
    else
        echo "[*] Building static reachability bitcode and report..."
        reach_build_cmd="$(quote_cmd cmake -S "$ICCDEV_SRC/Build/Cmake" -B "$REACH_BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=gclang -DCMAKE_CXX_COMPILER=gclang++ -DENABLE_TOOLS=ON -DENABLE_SHARED_LIBS=OFF -DENABLE_STATIC_LIBS=ON)"
        reach_build_cmd+=" && "
        reach_build_cmd+="$(quote_cmd cmake --build "$REACH_BUILD_DIR" --target "$CMAKE_TARGET" -j "$JOBS")"
        reachability run \
            --lang cpp \
            --project "$ICCDEV_SRC" \
            --build-cmd "$reach_build_cmd" \
            --artifact "$REACH_BUILD_DIR/Tools/$(basename "$(dirname "$COV_BIN")")/$TOOL_BIN_NAME" \
            --static-libs auto \
            --entry main \
            --reached "$STATICALLY_REACHABLE_TXT" \
            --not-reached "$STATICALLY_UNREACHABLE_TXT" \
            --out "$REACH_JSON"
    fi
    demangle_symbol_file "$STATICALLY_REACHABLE_TXT" "$STATICALLY_REACHABLE_DEMANGLED_TXT"
    demangle_symbol_file "$STATICALLY_UNREACHABLE_TXT" "$STATICALLY_UNREACHABLE_DEMANGLED_TXT"
    if [[ "$REACH_JSON" != "$TARGET_REACH_JSON" ]]; then
        ln -sf "$(basename "$REACH_JSON")" "$TARGET_REACH_JSON"
        ln -sf "$(basename "$STATICALLY_REACHABLE_TXT")" "$TARGET_STATICALLY_REACHABLE_TXT"
        ln -sf "$(basename "$STATICALLY_UNREACHABLE_TXT")" "$TARGET_STATICALLY_UNREACHABLE_TXT"
        ln -sf "$(basename "$STATICALLY_REACHABLE_DEMANGLED_TXT")" "$TARGET_STATICALLY_REACHABLE_DEMANGLED_TXT"
        ln -sf "$(basename "$STATICALLY_UNREACHABLE_DEMANGLED_TXT")" "$TARGET_STATICALLY_UNREACHABLE_DEMANGLED_TXT"
    fi
    REACH_ARG=(--reachability "$REACH_JSON")
fi

COV_CMD=("$COV_BIN")
for arg in "${AFL_ARGS[@]}"; do
    COV_CMD+=("$arg")
done
COV_CMD_STRING="$(quote_cmd "${COV_CMD[@]}")"

echo "[*] Running cov-analysis..."
export TMPDIR="$REPORT_ROOT/tmp"
mkdir -p "$TMPDIR"
CC="$COV_CC" CXX="$COV_CXX" cov-analysis \
    -d "$COV_ANALYSIS_OUTPUT_DIR" \
    -e "$COV_CMD_STRING" \
    -o "$TARGET_REPORT_DIR" \
    -t "$JOBS" \
    -T "$COVERAGE_TIMEOUT" \
    "${REACH_ARG[@]}"

generate_runtime_function_reports

echo ""
echo "[OK] Coverage workflow complete"
echo "     Coverage binary: $COV_BIN"
if [[ "$RUN_REACHABILITY" -eq 1 ]]; then
    echo "     Reachability:          $REACH_JSON"
    echo "     Static reachable:      $STATICALLY_REACHABLE_TXT"
    echo "     Static unreachable:    $STATICALLY_UNREACHABLE_TXT"
    echo "     Not covered reachable: $NOT_COVERED_REACHABLE_TXT"
    echo "     Covered unreachable:   $COVERED_UNREACHABLE_TXT"
    if [[ -s "$STATICALLY_REACHABLE_DEMANGLED_TXT" ]]; then
        echo "     Static reachable names:   $STATICALLY_REACHABLE_DEMANGLED_TXT"
    fi
    if [[ -s "$STATICALLY_UNREACHABLE_DEMANGLED_TXT" ]]; then
        echo "     Static unreachable names: $STATICALLY_UNREACHABLE_DEMANGLED_TXT"
    fi
fi
echo "     Covered functions: $COVERED_TXT"
echo "     Report:          $TARGET_REPORT_DIR"
