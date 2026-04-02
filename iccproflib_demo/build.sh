#!/usr/bin/env bash
# build.sh — Build the IccProfLib demo against the research repo's iccDEV
#
# Usage:  cd iccproflib_demo && ./build.sh
#
# Prerequisites:
#   - clang++ 18 (or g++)
#   - iccDEV built at ../iccDEV/Build/ (static library + headers)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Locate iccDEV ────────────────────────────────────────────────────
ICCDEV_DIR="$REPO_ROOT/iccDEV"
PROFLIB_DIR="$ICCDEV_DIR/Build/IccProfLib"
SHARED_LIB="$PROFLIB_DIR/libIccProfLib2.so"
STATIC_LIB="$PROFLIB_DIR/libIccProfLib2-static.a"

if [ ! -f "$SHARED_LIB" ] && [ ! -f "$STATIC_LIB" ]; then
    echo "ERROR: IccProfLib not found at:"
    echo "  $PROFLIB_DIR"
    echo ""
    echo "Build iccDEV first:"
    echo "  cd $ICCDEV_DIR/Build && cmake Cmake && make -j\$(nproc)"
    exit 1
fi

# Prefer shared library -- the static archive may contain LLVM IR bitcode
# (when iccDEV is built with LTO/CMAKE_INTERPROCEDURAL_OPTIMIZATION) which
# requires -flto at link time.
USE_SHARED=0
LTO_FLAGS=""
if [ -f "$SHARED_LIB" ]; then
    USE_SHARED=1
    echo "Using IccProfLib shared library from: $PROFLIB_DIR"
else
    echo "Using IccProfLib static library from: $PROFLIB_DIR"
    # Check if static lib contains LLVM bitcode (LTO build)
    FIRST_OBJ=$(ar t "$STATIC_LIB" 2>/dev/null | head -1)
    if [ -n "$FIRST_OBJ" ]; then
        ar x "$STATIC_LIB" "$FIRST_OBJ" --output /tmp
        if file "/tmp/$FIRST_OBJ" 2>/dev/null | grep -q "LLVM IR bitcode"; then
            echo "Detected LLVM IR bitcode in static lib -- adding -flto"
            LTO_FLAGS="-flto"
        fi
        rm -f "/tmp/$FIRST_OBJ"
    fi
fi

# ── Choose compiler ──────────────────────────────────────────────────
CXX="${CXX:-}"
if [ -z "$CXX" ]; then
    if command -v clang++-18 &>/dev/null; then
        CXX="clang++-18"
    elif command -v clang++ &>/dev/null; then
        CXX="clang++"
    elif command -v g++ &>/dev/null; then
        CXX="g++"
    else
        echo "ERROR: No C++ compiler found (tried clang++-18, clang++, g++)"
        exit 1
    fi
fi
echo "Compiler: $CXX"

# ── Compile and link ─────────────────────────────────────────────────
INCLUDES=(
    "-I$ICCDEV_DIR/IccProfLib"
    "-I$PROFLIB_DIR"               # IccProfLibVer.h (generated)
)

# IccProfLib needs -lpthread for some platforms
LIBS=("-lpthread")

if [ "$USE_SHARED" -eq 1 ]; then
    LIBS=("-L$PROFLIB_DIR" "-lIccProfLib2" "-Wl,-rpath,$PROFLIB_DIR" "${LIBS[@]}")
else
    LIBS=("$STATIC_LIB" "${LIBS[@]}")
fi

OUTPUT="$SCRIPT_DIR/iccproflib_demo"

# Detect if the library was built with sanitizers
SANITIZER_FLAGS=""
if [ "$USE_SHARED" -eq 1 ]; then
    ASAN_COUNT=$(nm -D "$SHARED_LIB" 2>/dev/null | grep -c '__asan_report' || true)
else
    ASAN_COUNT=$(nm "$STATIC_LIB" 2>/dev/null | grep -c '__asan_report' || true)
fi
if [ "$ASAN_COUNT" -gt 0 ]; then
    echo "Detected ASAN+UBSAN in library ($ASAN_COUNT refs) -- adding sanitizer flags"
    SANITIZER_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
fi

echo "Building: iccproflib_demo.cpp"
$CXX -std=c++17 -O2 -Wall -Wextra \
    $SANITIZER_FLAGS \
    $LTO_FLAGS \
    "${INCLUDES[@]}" \
    "$SCRIPT_DIR/iccproflib_demo.cpp" \
    "${LIBS[@]}" \
    -o "$OUTPUT"

echo ""
echo "Built: $OUTPUT"
echo ""

# ── Quick verify: count linked IccProfLib symbols ────────────────────
SYMBOL_COUNT=$(nm "$OUTPUT" 2>/dev/null | grep -c 'CIcc' || true)
echo "IccProfLib symbols linked: $SYMBOL_COUNT"
echo ""

# ── Show usage ───────────────────────────────────────────────────────
echo "Run:"
echo "  cd $(basename "$SCRIPT_DIR") && ./iccproflib_demo"
echo "  ./iccproflib_demo ../test-profiles/sRGB_D65_MAT.icc"
echo "  ./iccproflib_demo ../iccDEV/Testing/sRGB_v4_ICC_preference.icc"
