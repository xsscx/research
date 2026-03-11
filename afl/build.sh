#!/bin/bash
# afl/build.sh — Build iccDEV with AFL++ instrumentation (ASAN+UBSAN)
#
# Usage: ./afl/build.sh [--clean]
#
# Builds the full iccDEV library and tools using afl-clang-fast++ with
# AddressSanitizer and UndefinedBehaviorSanitizer enabled.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/iccDEV/Build-AFL"
CMAKE_DIR="$REPO_ROOT/iccDEV/Build/Cmake"
BIN_DIR="$REPO_ROOT/afl/bin"
JOBS=$(nproc)

# Verify AFL++ is installed
if ! command -v afl-clang-fast++ &>/dev/null; then
    echo "ERROR: afl-clang-fast++ not found. Install AFL++:"
    echo "  apt install afl++"
    exit 1
fi

# Clean build if requested
if [[ "${1:-}" == "--clean" ]]; then
    echo "[*] Cleaning Build-AFL directory..."
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "[*] Configuring iccDEV with AFL++ instrumentation..."
echo "    Compiler: afl-clang-fast++"
echo "    Sanitizers: ASAN + UBSAN"
echo "    Jobs: $JOBS"

AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
cmake "$CMAKE_DIR" \
    -DCMAKE_C_COMPILER=afl-clang-fast \
    -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-g -O0" \
    -DCMAKE_CXX_FLAGS="-g -O0" \
    2>&1 | tail -5

echo "[*] Building with $JOBS cores..."
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
make -j"$JOBS" 2>&1 | tail -3

echo ""
echo "[OK] AFL-instrumented iccDEV built successfully"
echo ""

# Deploy binaries to afl/bin/
echo "[*] Deploying to $BIN_DIR"
mkdir -p "$BIN_DIR"
for tool in "$BUILD_DIR"/Tools/*/; do
    name=$(basename "$tool")
    bin="$tool/$name"
    if [[ -x "$bin" ]]; then
        cp "$bin" "$BIN_DIR/"
        size=$(du -h "$BIN_DIR/$name" | cut -f1)
        echo "  $size  afl/bin/$name"
    fi
done

# Deploy shared library
cp "$BUILD_DIR"/IccProfLib/libIccProfLib2.so* "$BIN_DIR/"
echo ""
echo "Shared library:"
ls -lh "$BIN_DIR"/libIccProfLib2.so 2>/dev/null | awk '{print "  "$5"  "$9}'
