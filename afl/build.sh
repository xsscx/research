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
    -DENABLE_TOOLS=ON \
    -DENABLE_SHARED_LIBS=ON \
    2>&1 | tail -5

echo "[*] Building with $JOBS cores..."
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
make -j"$JOBS" 2>&1 | tail -3

echo ""
echo "[OK] AFL-instrumented iccDEV built successfully"
echo ""

# Deploy binaries to afl/bin/
# Note: cmake directory names use PascalCase (IccDumpProfile/) but binary
# names use camelCase (iccDumpProfile). Find the actual executable in each dir.
echo "[*] Deploying to $BIN_DIR"
mkdir -p "$BIN_DIR"
DEPLOYED=0
for tool_dir in "$BUILD_DIR"/Tools/*/; do
    while IFS= read -r bin; do
        bin_name=$(basename "$bin")
        cp "$bin" "$BIN_DIR/"
        size=$(du -h "$BIN_DIR/$bin_name" | cut -f1)
        echo "  $size  afl/bin/$bin_name"
        DEPLOYED=$((DEPLOYED + 1))
    done < <(find "$tool_dir" -maxdepth 1 -type f -executable 2>/dev/null)
done
echo "  $DEPLOYED tool binaries deployed"

# Deploy shared libraries
cp "$BUILD_DIR"/IccProfLib/libIccProfLib2.so* "$BIN_DIR/"
cp "$BUILD_DIR"/IccXML/libIccXML2.so* "$BIN_DIR/" 2>/dev/null || true
echo ""
echo "Shared libraries:"
ls -lh "$BIN_DIR"/libIccProfLib2.so 2>/dev/null | awk '{print "  "$5"  "$9}'
ls -lh "$BIN_DIR"/libIccXML2.so 2>/dev/null | awk '{print "  "$5"  "$9}'

echo ""
echo "[OK] $DEPLOYED AFL-instrumented tools deployed to afl/bin/"
