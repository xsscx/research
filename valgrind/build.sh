#!/usr/bin/env bash
# Configure and build a non-sanitized Debug iccDEV tree for Valgrind tools.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VG_SOURCE_DIR="${VALGRIND_ICCDEV_DIR:-$REPO_ROOT/iccDEV}"
VG_BUILD_DIR="${VALGRIND_BUILD_DIR:-$REPO_ROOT/valgrind/build}"
VG_JOBS="${VALGRIND_JOBS:-$(nproc)}"
VG_CLEAN=0
VG_REQUESTED_TARGETS=()

# shellcheck source=valgrind/targets.sh
source "$REPO_ROOT/valgrind/targets.sh"

usage() {
    echo "Usage: $0 [--clean] [--source-dir DIR] [--build-dir DIR] [--jobs N] [--target NAME]"
    echo "Builds every registered target unless --target is repeated to select targets."
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean) VG_CLEAN=1; shift ;;
        --source-dir) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VG_SOURCE_DIR="$2"; shift 2 ;;
        --build-dir) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VG_BUILD_DIR="$2"; shift 2 ;;
        --jobs) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VG_JOBS="$2"; shift 2 ;;
        --target) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VG_REQUESTED_TARGETS+=("$2"); shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ "$VG_JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: --jobs must be a positive integer" >&2; exit 2; }
[[ -f "$VG_SOURCE_DIR/Build/Cmake/CMakeLists.txt" ]] || { echo "ERROR: not an iccDEV source tree: $VG_SOURCE_DIR" >&2; exit 2; }

if [[ "$VG_CLEAN" -eq 1 && -e "$VG_BUILD_DIR" ]]; then
    resolved_build="$(realpath -m "$VG_BUILD_DIR")"
    resolved_repo="$(realpath -m "$REPO_ROOT")"
    if [[ "$resolved_build" == "/" || "$resolved_build" == "$resolved_repo" || "$resolved_build" != *valgrind* ]]; then
        echo "ERROR: refusing unsafe Valgrind build cleanup: $resolved_build" >&2
        exit 2
    fi
    rm -rf -- "$resolved_build"
fi

cmake_args=(
    -S "$VG_SOURCE_DIR/Build/Cmake"
    -B "$VG_BUILD_DIR"
    -DCMAKE_BUILD_TYPE=Debug
    -DENABLE_TESTS=ON
    -DENABLE_TOOLS=ON
    -DENABLE_SANITIZERS=OFF
    -DENABLE_ASAN=OFF
    -DENABLE_UBSAN=OFF
    -DENABLE_INTEGER_SANITIZER=OFF
    -DENABLE_FLOAT_SANITIZER=OFF
    -DENABLE_TSAN=OFF
    -DENABLE_MSAN=OFF
    -DENABLE_LSAN=OFF
    -DENABLE_FUZZING=OFF
    -DENABLE_LTO=OFF
)
if [[ ! -f "$VG_BUILD_DIR/CMakeCache.txt" ]] && command -v ninja >/dev/null 2>&1; then
    cmake_args+=(-G Ninja)
fi

cmake "${cmake_args[@]}"

build_targets=()
if [[ ${#VG_REQUESTED_TARGETS[@]} -eq 0 ]]; then
    build_targets=("${VG_BUILD_TARGETS[@]}")
else
    for requested in "${VG_REQUESTED_TARGETS[@]}"; do
        VG_RUN_WORK="$VG_BUILD_DIR/validation-work"
        if ! vg_configure_target "$requested"; then
            echo "ERROR: unknown target: $requested" >&2
            vg_print_targets >&2
            exit 2
        fi
        build_targets+=("$VG_CMAKE_TARGET")
        build_targets+=("${VG_EXTRA_CMAKE_TARGETS[@]}")
    done
fi

cmake --build "$VG_BUILD_DIR" --parallel "$VG_JOBS" --target "${build_targets[@]}"

for registered in "${VG_TARGETS[@]}"; do
    VG_RUN_WORK="$VG_BUILD_DIR/validation-work"
    vg_configure_target "$registered"
    if [[ " ${build_targets[*]} " == *" $VG_CMAKE_TARGET "* && ! -x "$VG_BINARY" ]]; then
        echo "ERROR: expected executable is missing: $VG_BINARY" >&2
        exit 1
    fi
    if [[ -x "$VG_BINARY" ]] && ldd "$VG_BINARY" 2>/dev/null | grep -Eq 'libasan|libubsan|libtsan|clang_rt\.(asan|ubsan|tsan)'; then
        echo "ERROR: sanitizer runtime found in Valgrind binary: $VG_BINARY" >&2
        exit 1
    fi
done

echo "[OK] Non-sanitized Debug build ready: $VG_BUILD_DIR"
