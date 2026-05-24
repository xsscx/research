#!/bin/bash
# afl/build.sh - Build iccDEV with AFL++ instrumentation (ASAN+UBSAN)
#
# Usage: ./afl/build.sh [--clean] [--no-patches|--patches] [--refresh-iccdev]
#
# Builds the full iccDEV library and tools using afl-clang-fast++ with
# AddressSanitizer and UndefinedBehaviorSanitizer enabled.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$REPO_ROOT/afl"
ICCDEV_DIR="$SCRIPT_DIR/iccDEV"
BUILD_DIR="$ICCDEV_DIR/Build-AFL"
CMAKE_DIR="$ICCDEV_DIR/Build/Cmake"
BIN_DIR="$SCRIPT_DIR/bin"
JOBS=$(nproc)
PATCH_DIR="$REPO_ROOT/cfl/patches"
APPLY_PATCHES="${AFL_APPLY_PATCHES:-0}"
REFRESH_ICCDEV="${AFL_REFRESH_ICCDEV:-0}"
KEEP_ICCDEV="${AFL_KEEP_ICCDEV:-0}"
SELECTED_PATCHES=()

usage() {
    sed -n '2,8p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  --clean           remove Build-AFL before building"
    echo "  --no-patches      build upstream iccDEV without CFL patches (default)"
    echo "  --patches         apply cfl/patches before building for A/B comparison"
    echo "  --patch-file FILE apply one patch file; may be repeated"
    echo "  --refresh-iccdev  fetch origin/master and reset the nested checkout"
    echo "  --keep-iccdev     preserve current afl/iccDEV source edits"
}

CLEAN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean|clean)
            CLEAN=1
            shift
            ;;
        --patches)
            APPLY_PATCHES=1
            shift
            ;;
        --no-patches)
            APPLY_PATCHES=0
            shift
            ;;
        --patch-file|--patch)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: $1 requires a patch path or cfl/patches filename"
                exit 1
            fi
            APPLY_PATCHES=selected
            SELECTED_PATCHES+=("$2")
            shift 2
            ;;
        --refresh-iccdev)
            REFRESH_ICCDEV=1
            shift
            ;;
        --keep-iccdev)
            KEEP_ICCDEV=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ "$REFRESH_ICCDEV" = "1" && "$KEEP_ICCDEV" = "1" ]]; then
    echo "ERROR: --refresh-iccdev and --keep-iccdev are mutually exclusive"
    exit 1
fi

# Clone iccDEV if not present or incomplete. AFL tests use an isolated
# upstream checkout so the root iccDEV/ source tree stays untouched.
if [ -d "$ICCDEV_DIR/.git" ] && [ -f "$CMAKE_DIR/CMakeLists.txt" ]; then
    echo "[*] Using isolated iccDEV checkout: $(cd "$ICCDEV_DIR" && git rev-parse --short HEAD)"
elif [ ! -f "$CMAKE_DIR/CMakeLists.txt" ]; then
    echo "[*] Cloning iccDEV into afl/iccDEV (unpatched upstream for AFL)..."
    rm -rf "$ICCDEV_DIR"
    git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git "$ICCDEV_DIR"
fi

if [[ "$REFRESH_ICCDEV" = "1" ]]; then
    echo "[*] Refreshing AFL iccDEV checkout from origin/master..."
    git -C "$ICCDEV_DIR" fetch origin master
    git -C "$ICCDEV_DIR" reset --hard origin/master
    git -C "$ICCDEV_DIR" clean -fd
elif [[ "$KEEP_ICCDEV" != "1" ]]; then
    git -C "$ICCDEV_DIR" checkout -- . 2>/dev/null || true
fi

if [[ "$APPLY_PATCHES" = "0" ]]; then
    echo "[*] Patch application disabled for AFL build"
elif [[ "$APPLY_PATCHES" = "selected" ]]; then
    PATCH_OK=0
    PATCH_FAIL=0
    for p in "${SELECTED_PATCHES[@]}"; do
        if [[ -f "$p" ]]; then
            patch_path="$p"
        elif [[ -f "$PATCH_DIR/$p" ]]; then
            patch_path="$PATCH_DIR/$p"
        else
            echo "[FAIL] Patch not found: $p"
            exit 1
        fi
        pname="$(basename "$patch_path")"
        if patch --no-backup-if-mismatch --dry-run -p1 -d "$ICCDEV_DIR" < "$patch_path" >/dev/null 2>&1; then
            patch --no-backup-if-mismatch -p1 -d "$ICCDEV_DIR" < "$patch_path" >/dev/null 2>&1
            echo "[OK] Applied: $pname"
            PATCH_OK=$((PATCH_OK + 1))
        elif patch --no-backup-if-mismatch -R --dry-run -p1 -d "$ICCDEV_DIR" < "$patch_path" >/dev/null 2>&1; then
            echo "[OK] Already applied: $pname"
            PATCH_OK=$((PATCH_OK + 1))
        else
            echo "[FAIL] Cannot apply: $pname"
            PATCH_FAIL=$((PATCH_FAIL + 1))
        fi
    done
    echo "[*] AFL patches: $PATCH_OK OK, $PATCH_FAIL FAIL"
    [[ "$PATCH_FAIL" -eq 0 ]] || exit 1
elif [[ -d "$PATCH_DIR" ]] && ls "$PATCH_DIR"/*.patch >/dev/null 2>&1; then
    PATCH_OK=0
    PATCH_FAIL=0
    for p in "$PATCH_DIR"/*.patch; do
        pname="$(basename "$p")"
        if patch --no-backup-if-mismatch --dry-run -p1 -d "$ICCDEV_DIR" < "$p" >/dev/null 2>&1; then
            patch --no-backup-if-mismatch -p1 -d "$ICCDEV_DIR" < "$p" >/dev/null 2>&1
            echo "[OK] Applied: $pname"
            PATCH_OK=$((PATCH_OK + 1))
        elif patch --no-backup-if-mismatch -R --dry-run -p1 -d "$ICCDEV_DIR" < "$p" >/dev/null 2>&1; then
            echo "[OK] Already applied: $pname"
            PATCH_OK=$((PATCH_OK + 1))
        else
            echo "[FAIL] Cannot apply: $pname"
            PATCH_FAIL=$((PATCH_FAIL + 1))
        fi
    done
    echo "[*] AFL patches: $PATCH_OK OK, $PATCH_FAIL FAIL"
    [[ "$PATCH_FAIL" -eq 0 ]] || exit 1
else
    echo "[*] No AFL patches to apply"
fi

# Verify AFL++ is installed
if ! command -v afl-clang-fast++ &>/dev/null; then
    echo "ERROR: afl-clang-fast++ not found. Install AFL++:"
    echo "  apt install afl++"
    exit 1
fi

# Clean build if requested
if [[ "$CLEAN" == "1" ]]; then
    echo "[*] Cleaning Build-AFL directory..."
    rm -rf "$BUILD_DIR"
fi

echo "[*] Configuring iccDEV with AFL++ instrumentation..."
echo "    Compiler: afl-clang-fast++"
echo "    Sanitizers: ASAN + UBSAN"
if [[ "$APPLY_PATCHES" = "0" ]]; then
    echo "    Patch mode: unpatched upstream"
elif [[ "$APPLY_PATCHES" = "selected" ]]; then
    echo "    Patch mode: selected CFL patch files"
else
    echo "    Patch mode: all CFL patches"
fi
echo "    Jobs: $JOBS"

# Detect multiarch include/lib paths. Ubuntu puts some headers in /usr/include/<arch>/.
ARCH_INCLUDE="/usr/include/$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"
ARCH_LIB="/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"

AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
cmake -S "$CMAKE_DIR" -B "$BUILD_DIR" \
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
    -DJPEG_LIBRARY="$ARCH_LIB/libjpeg.so"

echo "[*] Building with $JOBS cores..."
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
cmake --build "$BUILD_DIR" --parallel "$JOBS"

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
# Preserve active symlink chains for every iccDEV library used by tool binaries.
deploy_shared_lib_root() {
    local src="$1"
    local root="$1"
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
}

mapfile -t ICC_SHARED_ROOTS < <(
    find "$BUILD_DIR" -mindepth 2 -maxdepth 2 \( -type f -o -type l \) -name 'libIcc*.so' | sort
)
if [[ ${#ICC_SHARED_ROOTS[@]} -eq 0 ]]; then
    echo "[FAIL] No iccDEV shared libraries found under $BUILD_DIR"
    exit 1
fi

rm -f "$BIN_DIR"/libIcc*.so*
for lib_root in "${ICC_SHARED_ROOTS[@]}"; do
    deploy_shared_lib_root "$lib_root"
done

echo ""
echo "Shared libraries:"
find "$BIN_DIR" -maxdepth 1 -name 'lib*.so' -printf '  %s  %p\n' 2>/dev/null

echo ""
echo "[OK] $DEPLOYED AFL-instrumented tools deployed to afl/bin/"
