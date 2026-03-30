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
STATIC_LIB="$PROFLIB_DIR/libIccProfLib2-static.a"

if [ ! -f "$STATIC_LIB" ]; then
    echo "ERROR: IccProfLib static library not found at:"
    echo "  $STATIC_LIB"
    echo ""
    echo "Build iccDEV first:"
    echo "  cd $ICCDEV_DIR/Build && cmake Cmake && make -j\$(nproc)"
    exit 1
fi

echo "Using IccProfLib from: $PROFLIB_DIR"

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
# The research repo builds iccDEV with ASAN+UBSAN, so we must link those runtimes
LIBS=(
    "$STATIC_LIB"
    "-lpthread"
)

OUTPUT="$SCRIPT_DIR/iccproflib_demo"

# Detect if static lib was built with sanitizers
SANITIZER_FLAGS=""
ASAN_COUNT=$(nm "$STATIC_LIB" 2>/dev/null | grep -c '__asan_report' || true)
if [ "$ASAN_COUNT" -gt 0 ]; then
    echo "Detected ASAN+UBSAN in static lib ($ASAN_COUNT refs) — adding sanitizer flags"
    SANITIZER_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
fi

echo "Building: iccproflib_demo.cpp"
$CXX -std=c++17 -O2 -Wall -Wextra \
    $SANITIZER_FLAGS \
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
