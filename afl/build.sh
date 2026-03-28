#!/bin/bash
# afl/build.sh — Build PATCHED iccDEV with AFL++ instrumentation (ASAN+UBSAN)
#
# Usage: ./afl/build.sh [--clean]
#
# Builds the full iccDEV library and tools using afl-clang-fast++ with
# AddressSanitizer and UndefinedBehaviorSanitizer enabled.
# Applies all CFL security patches from cfl/patches/ before building.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ICCDEV_DIR="$REPO_ROOT/iccDEV"
BUILD_DIR="$ICCDEV_DIR/Build-AFL"
CMAKE_DIR="$ICCDEV_DIR/Build/Cmake"
BIN_DIR="$REPO_ROOT/afl/bin"
PATCH_DIR="$REPO_ROOT/cfl/patches"
JOBS=$(nproc)

# Clone iccDEV if not present or incomplete
if [ ! -f "$CMAKE_DIR/CMakeLists.txt" ]; then
    echo "[*] Cloning iccDEV..."
    rm -rf "$ICCDEV_DIR"
    git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git "$ICCDEV_DIR"
fi
echo "[*] iccDEV commit: $(cd "$ICCDEV_DIR" && git rev-parse --short HEAD)"

# --- Apply CFL security patches ---
# Reset working tree to clean state, then apply all patches from cfl/patches/
echo "[*] Applying CFL security patches..."
(cd "$ICCDEV_DIR" && git checkout -- . 2>/dev/null)
if [ -d "$PATCH_DIR" ] && ls "$PATCH_DIR"/*.patch 1>/dev/null 2>&1; then
    PATCH_OK=0
    PATCH_FAIL=0
    for p in "$PATCH_DIR"/*.patch; do
        pname=$(basename "$p")
        if patch --dry-run -p1 -d "$ICCDEV_DIR" < "$p" > /dev/null 2>&1; then
            patch -p1 -d "$ICCDEV_DIR" < "$p" > /dev/null 2>&1
            PATCH_OK=$((PATCH_OK + 1))
        elif patch -R --dry-run -p1 -d "$ICCDEV_DIR" < "$p" > /dev/null 2>&1; then
            PATCH_OK=$((PATCH_OK + 1))
        else
            echo "  [FAIL] $pname"
            PATCH_FAIL=$((PATCH_FAIL + 1))
        fi
    done
    echo "  Patches: $PATCH_OK applied, $PATCH_FAIL failed"
    if [ "$PATCH_FAIL" -gt 0 ]; then
        echo "  WARNING: Some patches failed — check upstream changes"
    fi
else
    echo "  No patches found in $PATCH_DIR"
fi

# Verify AFL++ is installed
if ! command -v afl-clang-fast++ &>/dev/null; then
    echo "ERROR: afl-clang-fast++ not found. Install AFL++:"
    echo "  apt install afl++"
    exit 1
fi

# Clean build if requested or if patches changed the source
if [[ "${1:-}" == "--clean" ]]; then
    echo "[*] Cleaning Build-AFL directory..."
    rm -rf "$BUILD_DIR"
fi

# Delete stale cmake cache after patching (Anti-Pattern #15)
rm -f "$BUILD_DIR/CMakeCache.txt"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "[*] Configuring iccDEV with AFL++ instrumentation..."
echo "    Compiler: afl-clang-fast++"
echo "    Sanitizers: ASAN + UBSAN"
echo "    Jobs: $JOBS"

# Detect multiarch include/lib paths (Ubuntu puts headers in /usr/include/<arch>/)
ARCH_INCLUDE="/usr/include/$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"
ARCH_LIB="/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"

AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
cmake "$CMAKE_DIR" \
    -DCMAKE_C_COMPILER=afl-clang-fast \
    -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-g -O0 -I${ARCH_INCLUDE}" \
    -DCMAKE_CXX_FLAGS="-g -O0 -I${ARCH_INCLUDE}" \
    -DENABLE_TOOLS=ON \
    -DENABLE_SHARED_LIBS=ON \
    -DTIFF_INCLUDE_DIR="$ARCH_INCLUDE" \
    -DTIFF_LIBRARY="$ARCH_LIB/libtiff.so" \
    -DZLIB_INCLUDE_DIR=/usr/include \
    -DZLIB_LIBRARY="$ARCH_LIB/libz.so" \
    -DPNG_PNG_INCLUDE_DIR=/usr/include \
    -DPNG_LIBRARY="$ARCH_LIB/libpng.so" \
    -DJPEG_INCLUDE_DIR=/usr/include \
    -DJPEG_LIBRARY="$ARCH_LIB/libjpeg.so" \
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

# Deploy shared libraries (handle CMAKE_DEBUG_POSTFIX 'd' suffix)
for lib in IccProfLib IccXML; do
    for f in "$BUILD_DIR"/$lib/lib${lib}2*.so*; do
        [ -e "$f" ] && cp -P "$f" "$BIN_DIR/"
    done
done
echo ""
echo "Shared libraries:"
ls -lh "$BIN_DIR"/lib*.so 2>/dev/null | awk '{print "  "$5"  "$9}'

echo ""
echo "[OK] $DEPLOYED AFL-instrumented PATCHED tools deployed to afl/bin/"
