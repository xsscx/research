#!/bin/bash
# afl/build.sh - Build iccDEV with AFL++ instrumentation (ASAN+UBSAN)
#
# Usage: ./afl/build.sh [--clean]
#
# Builds the full iccDEV library and tools using afl-clang-fast++ with
# AddressSanitizer and UndefinedBehaviorSanitizer enabled.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ICCDEV_DIR="$REPO_ROOT/iccDEV"
BUILD_DIR="$ICCDEV_DIR/Build-AFL"
CMAKE_DIR="$ICCDEV_DIR/Build/Cmake"
BIN_DIR="$REPO_ROOT/afl/bin"
JOBS=$(nproc)

# Clone iccDEV if not present or incomplete. AFL tests use upstream iccDEV.
if [ ! -f "$CMAKE_DIR/CMakeLists.txt" ]; then
    echo "[*] Cloning iccDEV (unpatched upstream for AFL)..."
    rm -rf "$ICCDEV_DIR"
    git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git "$ICCDEV_DIR"
fi

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

# Detect multiarch include/lib paths. Ubuntu puts some headers in /usr/include/<arch>/.
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

# Deploy binaries to afl/bin/.
# CMake directory names use PascalCase, but binary names use camelCase.
echo "[*] Deploying to $BIN_DIR"
mkdir -p "$BIN_DIR"
find "$BIN_DIR" -mindepth 1 ! -name .gitignore -exec rm -rf {} +
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

# Deploy shared libraries. Debug builds use a "d" suffix in current iccDEV.
# Preserve the active symlink chain and ignore stale versioned artifacts.
deploy_shared_lib_family() {
    local lib_dir="$1"
    local root_glob="$2"
    local required="$3"
    local roots=()
    mapfile -t roots < <(compgen -G "$lib_dir/$root_glob" || true)

    if [[ ${#roots[@]} -eq 0 ]]; then
        if [[ "$required" == "1" ]]; then
            echo "[FAIL] No shared library found matching $lib_dir/$root_glob"
            exit 1
        fi
        return 0
    fi

    for root in "${roots[@]}"; do
        local src="$root"
        local hops=0
        while true; do
            cp -a "$src" "$BIN_DIR/"
            if [[ ! -L "$src" ]]; then
                break
            fi

            local target
            target="$(readlink "$src")"
            if [[ "$target" == /* ]]; then
                src="$target"
            else
                src="$(dirname "$src")/$target"
            fi

            hops=$((hops + 1))
            if [[ "$hops" -gt 16 ]]; then
                echo "[FAIL] Symlink chain too deep for $root"
                exit 1
            fi
        done
    done
}

rm -f "$BIN_DIR"/libIccProfLib2*.so* "$BIN_DIR"/libIccXML2*.so*
deploy_shared_lib_family "$BUILD_DIR/IccProfLib" "libIccProfLib2*.so" 1
deploy_shared_lib_family "$BUILD_DIR/IccXML" "libIccXML2*.so" 0

echo ""
echo "Shared libraries:"
find "$BIN_DIR" -maxdepth 1 -name 'lib*.so' -printf '  %s  %p\n' 2>/dev/null

echo ""
echo "[OK] $DEPLOYED AFL-instrumented tools deployed to afl/bin/"
