#!/bin/bash
# Build non-AFL, unpatched iccDEV tools with MemorySanitizer.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ICCDEV_DIR="${ICCDEV_MSAN_SOURCE_DIR:-$REPO_ROOT/iccDEV}"
BUILD_DIR="${ICCDEV_MSAN_BUILD_DIR:-$ICCDEV_DIR/Build-MSan}"
PREFIX="${ICCDEV_MSAN_PREFIX:-$REPO_ROOT/afl/third_party/install-canonical-msan}"
THIRD_PARTY_BUILD_DIR="${ICCDEV_MSAN_THIRD_PARTY_BUILD_DIR:-$REPO_ROOT/afl/third_party/build-canonical-msan}"
JOBS="${ICCDEV_MSAN_JOBS:-32}"
SKIP_DEPENDENCIES=0

usage() {
    echo "Usage: $0 [--jobs N] [--skip-dependencies]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --jobs)
            if [[ $# -lt 2 || ! "$2" =~ ^[1-9][0-9]*$ ]]; then
                echo "ERROR: --jobs requires a positive integer" >&2
                exit 2
            fi
            JOBS="$2"
            shift 2
            ;;
        --skip-dependencies)
            SKIP_DEPENDENCIES=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

for tool in clang-21 clang++-21 llvm-ar-21 llvm-ranlib-21 llvm-nm-21 cmake git; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool not found: $tool" >&2
        exit 1
    fi
done

CC_BIN="$(command -v clang-21)"
CXX_BIN="$(command -v clang++-21)"
AR_BIN="$(command -v llvm-ar-21)"
RANLIB_BIN="$(command -v llvm-ranlib-21)"
NM_BIN="$(command -v llvm-nm-21)"

for source_path in IccProfLib IccConnect IccJSON Tools/CmdLine/IccApplyNamedCmm Tools/CmdLine/IccApplyProfiles Build/Cmake; do
    if ! git -C "$ICCDEV_DIR" diff --quiet -- "$source_path" ||
       ! git -C "$ICCDEV_DIR" diff --cached --quiet -- "$source_path"; then
        echo "ERROR: tracked changes prevent an unpatched MSan build: $ICCDEV_DIR/$source_path" >&2
        exit 1
    fi
done

if [[ "$SKIP_DEPENDENCIES" -eq 0 ]]; then
    AFL_THIRD_PARTY_SOURCE_DIR="$REPO_ROOT/afl/third_party/sources" \
    AFL_THIRD_PARTY_BUILD_DIR="$THIRD_PARTY_BUILD_DIR" \
    AFL_THIRD_PARTY_PREFIX="$PREFIX" \
    AFL_THIRD_PARTY_SANITIZER=memory \
    AFL_THIRD_PARTY_JOBS="$JOBS" \
    AFL_CC="$CC_BIN" AFL_CXX="$CXX_BIN" \
    CC="$CC_BIN" CXX="$CXX_BIN" AR="$AR_BIN" RANLIB="$RANLIB_BIN" NM="$NM_BIN" \
        "$REPO_ROOT/afl/third_party/build.sh"
fi

for archive in libc++.a libz.a libjpeg.a libpng.a libtiff.a; do
    if [[ ! -f "$PREFIX/lib/$archive" ]]; then
        echo "ERROR: missing MSan dependency: $PREFIX/lib/$archive" >&2
        exit 1
    fi
    if ! "$NM_BIN" "$PREFIX/lib/$archive" 2>/dev/null | grep '__msan_' >/dev/null; then
        echo "ERROR: dependency is not MSan-instrumented: $PREFIX/lib/$archive" >&2
        exit 1
    fi
done

ICCDEV_MSAN_LIBCXX_DIR="$PREFIX" cmake \
    -S "$ICCDEV_DIR/Build/Cmake" -B "$BUILD_DIR" \
    -DCMAKE_C_COMPILER="$CC_BIN" \
    -DCMAKE_CXX_COMPILER="$CXX_BIN" \
    -DCMAKE_AR="$AR_BIN" \
    -DCMAKE_RANLIB="$RANLIB_BIN" \
    -DCMAKE_NM="$NM_BIN" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_PREFIX_PATH="$PREFIX" \
    -DCMAKE_C_FLAGS="-g -O0 -fPIE -fsanitize-memory-track-origins=2" \
    -DCMAKE_CXX_FLAGS="-g -O0 -fPIE -fsanitize-memory-track-origins=2 -stdlib=libc++ -nostdinc++ -isystem $PREFIX/include/c++/v1" \
    -DCMAKE_EXE_LINKER_FLAGS="-pie -stdlib=libc++ -L$PREFIX/lib" \
    -DENABLE_MSAN=ON \
    -DSANITIZER_RECOVER=OFF \
    -DENABLE_TOOLS=ON \
    -DENABLE_IMAGE_TOOLS=ON \
    -DENABLE_WXWIDGETS=OFF \
    -DENABLE_ICCXML=OFF \
    -DENABLE_ICCJSON=ON \
    -DENABLE_SHARED_LIBS=OFF \
    -DENABLE_STATIC_LIBS=ON \
    -DICC_USE_ZLIB=ON \
    -DTIFF_INCLUDE_DIR="$PREFIX/include" \
    -DTIFF_LIBRARY:STRING="$PREFIX/lib/libtiff.a;$PREFIX/lib/libjpeg.a;$PREFIX/lib/libz.a" \
    -DZLIB_ROOT="$PREFIX" \
    -DZLIB_INCLUDE_DIR="$PREFIX/include" \
    -DZLIB_LIBRARY="$PREFIX/lib/libz.a" \
    -DPNG_PNG_INCLUDE_DIR="$PREFIX/include" \
    -DPNG_LIBRARY="$PREFIX/lib/libpng.a" \
    -DJPEG_INCLUDE_DIR="$PREFIX/include" \
    -DJPEG_LIBRARY="$PREFIX/lib/libjpeg.a"

cmake --build "$BUILD_DIR" --target iccApplyNamedCmm iccApplyProfiles --parallel "$JOBS"

MSAN_BINS=(
    "$BUILD_DIR/Tools/IccApplyNamedCmm/iccApplyNamedCmm"
    "$BUILD_DIR/Tools/IccApplyProfiles/iccApplyProfiles"
)
for MSAN_BIN in "${MSAN_BINS[@]}"; do
    if [[ ! -x "$MSAN_BIN" ]] ||
       ! "$NM_BIN" "$MSAN_BIN" 2>/dev/null | grep '__msan_init' >/dev/null; then
        echo "ERROR: independent $(basename "$MSAN_BIN") is not MSan-instrumented" >&2
        exit 1
    fi
    if "$NM_BIN" "$MSAN_BIN" 2>/dev/null | grep '__afl_' >/dev/null; then
        echo "ERROR: independent $(basename "$MSAN_BIN") contains AFL instrumentation" >&2
        exit 1
    fi
    if ldd "$MSAN_BIN" 2>/dev/null | grep -Eq 'libstdc\+\+|libc\+\+'; then
        echo "ERROR: independent $(basename "$MSAN_BIN") uses an uninstrumented shared C++ runtime" >&2
        exit 1
    fi
done

printf 'memory\n' > "$BUILD_DIR/.sanitizer-mode"
git -C "$ICCDEV_DIR" rev-parse HEAD > "$BUILD_DIR/.iccdev-source-commit"
printf '[OK] Independent unpatched iccDEV MSan tool: %s\n' "${MSAN_BINS[@]}"
