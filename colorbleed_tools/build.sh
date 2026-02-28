#!/bin/bash
#
# ColorBleed Tools Build — Vanilla iccDEV + Sandboxed Unsafe Tools
#
# Clones vanilla upstream iccDEV (NO security patches), builds static
# libraries with ASan+UBSan+coverage, then compiles the sandboxed
# iccToXml_unsafe and iccFromXml_unsafe tools.
#
# The tools use fork/exec isolation: each profile operation runs in a
# child process with resource limits. Crashes in the unpatched library
# are caught and reported as security findings, not tool failures.
#
# Usage:  ./build.sh          # build everything
#         ./build.sh clean    # remove build artifacts and start fresh
#
# Requirements: clang/clang++ 14+ (or g++), cmake 3.15+, libxml2-dev,
#               libtiff-dev, zlib1g-dev, liblzma-dev, pkg-config
#
# Copyright (c) 2021-2026 David H Hoyt LLC

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
ICCDEV_DIR="$REPO_ROOT/iccDEV"
BUILD_DIR="$ICCDEV_DIR/Build"
NPROC="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

CXX="${CXX:-clang++}"
CC="${CC:-clang}"

# Full instrumentation: ASan + UBSan + coverage, recoverable mode
# -fsanitize-recover=address allows ASan to log errors and continue
COMMON_CFLAGS="-g -O1 -fno-omit-frame-pointer"
SANITIZER_FLAGS="-fsanitize=address,undefined -fsanitize-recover=address,undefined"
COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
CFLAGS_LIB="$COMMON_CFLAGS $SANITIZER_FLAGS $COVERAGE_FLAGS"
CXXFLAGS_TOOL="$COMMON_CFLAGS $SANITIZER_FLAGS $COVERAGE_FLAGS -std=gnu++17 -Wall -frtti"

INCLUDE_FLAGS="-I$ICCDEV_DIR/IccProfLib -I$ICCDEV_DIR/IccXML/IccLibXML"
INCLUDE_FLAGS="$INCLUDE_FLAGS $(pkg-config --cflags libxml-2.0 2>/dev/null || echo '-I/usr/include/libxml2')"

LIB_PROF="$BUILD_DIR/IccProfLib/libIccProfLib2-static.a"
LIB_XML="$BUILD_DIR/IccXML/libIccXML2-static.a"
LINK_LIBS="-lxml2 -lz -llzma -lm -lpthread"

TARGETS=(iccToXml_unsafe iccFromXml_unsafe)

banner() {
  echo ""
  echo "════════════════════════════════════════"
  echo "  $1"
  echo "════════════════════════════════════════"
}

# --- Clean mode ---
if [ "${1:-}" = "clean" ]; then
  banner "Cleaning build artifacts"
  rm -f "$REPO_ROOT/iccToXml_unsafe" "$REPO_ROOT/iccFromXml_unsafe"
  rm -rf "$ICCDEV_DIR"
  echo "[OK] Clean complete"
  exit 0
fi

# --- Pre-flight ---
for tool in "$CXX" cmake pkg-config; do
  if ! command -v "$tool" &>/dev/null; then
    echo "[FAIL] ERROR: $tool not found. Install it and retry."
    exit 1
  fi
done

banner "ColorBleed Tools Build"
echo "Compiler:  $($CXX --version | head -1)"
echo "CMake:     $(cmake --version | head -1)"
echo "Cores:     $NPROC"
echo ""

# --- Step 1: Clone iccDEV if needed ---
banner "Step 1: iccDEV source"
if [ -d "$ICCDEV_DIR/.git" ]; then
  echo "Using existing checkout: $(cd "$ICCDEV_DIR" && git rev-parse --short HEAD)"
else
  echo "Cloning iccDEV..."
  rm -rf "$ICCDEV_DIR"
  git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git "$ICCDEV_DIR"
fi
echo "Commit: $(cd "$ICCDEV_DIR" && git rev-parse --short HEAD)"

# --- Step 2: Vanilla upstream (NO patches) ---
banner "Step 2: Vanilla upstream — no CFL patches applied"
echo "ColorBleed tools deliberately use unpatched iccDEV to detect crashes."
echo "Fork/exec sandboxing in the tool wrappers catches library crashes."

# Strip stray U+FE0F (emoji variation selector) from upstream source
SIGUTILS="$ICCDEV_DIR/IccProfLib/IccSignatureUtils.h"
if grep -qP '\xef\xb8\x8f' "$SIGUTILS" 2>/dev/null; then
  sed -i 's/\xef\xb8\x8f//g' "$SIGUTILS"
  echo "[OK] Stripped stray U+FE0F from IccSignatureUtils.h"
else
  echo "[INFO] IccSignatureUtils.h already clean"
fi

# --- Step 3: Patch wxWidgets and LTO out ---
banner "Step 3: Patch wxWidgets & LTO"
CMAKELISTS="$ICCDEV_DIR/Build/Cmake/CMakeLists.txt"
if grep -q 'find_package(wxWidgets' "$CMAKELISTS" 2>/dev/null; then
  sed -i 's/find_package(wxWidgets/#find_package(wxWidgets/' "$CMAKELISTS"
  sed -i 's/if(wxWidgets_FOUND)/if(FALSE AND wxWidgets_FOUND)/' "$CMAKELISTS"
  sed -i '/wx_/ s/^/#/' "$CMAKELISTS" 2>/dev/null || true
  echo "Patched out wxWidgets"
else
  echo "wxWidgets already patched"
fi
if grep -q 'set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)' "$CMAKELISTS" 2>/dev/null; then
  sed -i 's/set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)/#set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)/' "$CMAKELISTS"
  echo "Patched out LTO"
else
  echo "LTO already patched"
fi

# --- Step 4: Build static libraries ---
banner "Step 4: Build IccProfLib2-static + IccXML2-static"
mkdir -p "$BUILD_DIR"

# Clear cmake cache to prevent stale configs
rm -rf "$BUILD_DIR/CMakeCache.txt" "$BUILD_DIR/CMakeFiles"

cd "$BUILD_DIR"
cmake Cmake/ \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="$CFLAGS_LIB" \
  -DCMAKE_CXX_FLAGS="$CFLAGS_LIB -frtti" \
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
  -DENABLE_STATIC_LIBS=ON \
  -DENABLE_SHARED_LIBS=ON \
  -DENABLE_TOOLS=OFF \
  -Wno-dev 2>&1 | tail -5

make -j"$NPROC" IccProfLib2-static IccXML2-static 2>&1 | tail -3

echo ""
echo "Libraries:"
ls -lh "$LIB_PROF" "$LIB_XML"

# Verify instrumentation
ASAN_SYM=$( nm "$LIB_PROF" | grep -c '__asan' || true )
UBSAN_SYM=$( nm "$LIB_PROF" | grep -c '__ubsan' || true )
COV_SYM=$(  nm "$LIB_PROF" | grep -c '__profc_\|__llvm_prf' || true )
echo ""
echo "Instrumentation (IccProfLib2-static):"
echo "  ASan symbols:     $ASAN_SYM"
echo "  UBSan symbols:    $UBSAN_SYM"
echo "  Coverage symbols: $COV_SYM"

if [ "$ASAN_SYM" -eq 0 ] || [ "$UBSAN_SYM" -eq 0 ] || [ "$COV_SYM" -eq 0 ]; then
  echo "[FAIL] ERROR: Missing instrumentation — aborting"
  exit 1
fi

# --- Step 5: Build tools ---
banner "Step 5: Build ColorBleed tools"
cd "$REPO_ROOT"

for target in "${TARGETS[@]}"; do
  src="${target}.cpp"
  src_upper="$(echo "${target}" | sed 's/icc/Icc/' | sed 's/_u/U/')"
  # Map target name to source file
  case "$target" in
    iccToXml_unsafe)  src="IccToXml_unsafe.cpp" ;;
    iccFromXml_unsafe) src="IccFromXml_unsafe.cpp" ;;
  esac

  if [ ! -f "$src" ]; then
    echo "  [SKIP] $target ($src not found)"
    continue
  fi

  echo "Building $target..."
  $CXX $CXXFLAGS_TOOL $INCLUDE_FLAGS "$src" \
    "$LIB_PROF" "$LIB_XML" \
    $LINK_LIBS \
    -o "$target"
  chmod +x "$target"
  echo "  [OK] $target ($(ls -lh "$target" | awk '{print $5}'))"
done

# --- Summary ---
banner "Build Summary"
echo "Tools:"
ls -lh "${TARGETS[@]}" 2>/dev/null || echo "  (none built)"
echo ""
echo "SHA256 fingerprints:"
sha256sum "${TARGETS[@]}" 2>/dev/null || shasum -a 256 "${TARGETS[@]}" 2>/dev/null
echo ""
echo "Profraw: set LLVM_PROFILE_FILE to control coverage output"
echo "  Example:  LLVM_PROFILE_FILE=/tmp/colorbleed-%m.profraw ASAN_OPTIONS=detect_leaks=0 ./iccToXml_unsafe in.icc out.xml"
echo "  Merge:    llvm-profdata merge -sparse /tmp/colorbleed-*.profraw -o colorbleed.profdata"
echo "  Report:   llvm-cov report -object ./iccToXml_unsafe -object ./iccFromXml_unsafe -instr-profile=colorbleed.profdata"
echo ""
echo "ColorBleed Tooling: Unsafe Load & Store for ICC Profiles"
echo "Copyright (c) 2021-2026 David H Hoyt LLC"
echo ""
echo "[OK] Build complete"
