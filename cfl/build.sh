#!/bin/bash -eu
#
# CFL Local Build — Debug + ASan + UBSan + Instrumentation + Coverage
#
# Clones iccDEV, builds static libraries, then compiles all fuzzers
# with full sanitizer instrumentation and Clang source-based coverage.
#
# Usage:  ./build.sh          # build all fuzzers
#         ./build.sh clean    # remove build artifacts and start fresh
#
# Requirements: clang/clang++ 14+, cmake 3.15+, libxml2-dev, libtiff-dev, zlib,
#               libclang-rt-<ver>-dev (provides ASan/UBSan runtime)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ICCDEV_DIR="$SCRIPT_DIR/iccDEV"
BUILD_DIR="$ICCDEV_DIR/Build"
OUTPUT_DIR="$SCRIPT_DIR/bin"
NPROC="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

CC="${CC:-clang}"
CXX="${CXX:-clang++}"

# Sanitizer + debug + instrumentation + coverage flags
COMMON_CFLAGS="-g -O1 -fno-omit-frame-pointer"
SANITIZER_FLAGS="-fsanitize=address,undefined"
FUZZER_FLAGS="-fsanitize=fuzzer,address,undefined"
COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"

CFLAGS_LIB="$COMMON_CFLAGS $SANITIZER_FLAGS $COVERAGE_FLAGS"
CXXFLAGS_FUZZER="$COMMON_CFLAGS $FUZZER_FLAGS $COVERAGE_FLAGS -frtti"

INCLUDE_FLAGS="-I$ICCDEV_DIR/IccProfLib -I$ICCDEV_DIR/IccXML/IccLibXML"
INCLUDE_FLAGS="$INCLUDE_FLAGS -I$ICCDEV_DIR/Tools/CmdLine/IccCommon"
INCLUDE_FLAGS="$INCLUDE_FLAGS -I$ICCDEV_DIR/Tools/CmdLine/IccApplyProfiles"
INCLUDE_FLAGS="$INCLUDE_FLAGS $(pkg-config --cflags libxml-2.0 2>/dev/null || echo '-I/usr/include/libxml2')"

LIB_PROF="$BUILD_DIR/IccProfLib/libIccProfLib2-static.a"
LIB_XML="$BUILD_DIR/IccXML/libIccXML2-static.a"

# Core fuzzers (IccProfLib only)
CORE_FUZZERS=(
  icc_profile_fuzzer
  icc_calculator_fuzzer
  icc_v5dspobs_fuzzer
  icc_multitag_fuzzer
  icc_roundtrip_fuzzer
  icc_dump_fuzzer
  icc_io_fuzzer
  icc_link_fuzzer
  icc_spectral_fuzzer
  icc_apply_fuzzer
  icc_applynamedcmm_fuzzer
  icc_applyprofiles_fuzzer
  icc_deep_dump_fuzzer
)

# XML fuzzers (IccProfLib + IccXML + libxml2)
XML_FUZZERS=(
  icc_fromxml_fuzzer
  icc_toxml_fuzzer
)

# TIFF fuzzers (IccProfLib + TiffImg.o + libtiff)
TIFF_FUZZERS=(
  icc_specsep_fuzzer
  icc_tiffdump_fuzzer
)

TIFFIMG_SRC="$ICCDEV_DIR/Tools/CmdLine/IccApplyProfiles/TiffImg.cpp"
TIFFIMG_OBJ="$SCRIPT_DIR/.build_tmp/TiffImg.o"
TIFF_CFLAGS="$(pkg-config --cflags libtiff-4 2>/dev/null || true)"
TIFF_LIBS="$(pkg-config --libs libtiff-4 2>/dev/null || echo '-ltiff')"

banner() { echo ""; echo "════════════════════════════════════════"; echo "  $1"; echo "════════════════════════════════════════"; }

# --- Clean mode ---
if [ "${1:-}" = "clean" ]; then
  banner "Cleaning build artifacts"
  rm -rf "$OUTPUT_DIR" "$ICCDEV_DIR" "$SCRIPT_DIR/.build_tmp"
  echo "✅ Clean complete"
  exit 0
fi

# --- Pre-flight: verify toolchain ---
for tool in "$CC" "$CXX" cmake pkg-config; do
  if ! command -v "$tool" &>/dev/null; then
    echo "❌ ERROR: $tool not found. Install it and retry."
    exit 1
  fi
done

# Verify ASan/UBSan runtime is available (libclang-rt-*-dev)
ASAN_TEST=$(mktemp /tmp/asan_test.XXXXXX.cpp)
echo 'int main(){}' > "$ASAN_TEST"
if ! $CXX -fsanitize=address,undefined "$ASAN_TEST" -o /dev/null 2>/dev/null; then
  rm -f "$ASAN_TEST"
  CLANG_VER=$($CXX --version | grep -oP '\d+' | head -1)
  echo "❌ ERROR: Clang sanitizer runtime not found."
  echo ""
  echo "   The ASan/UBSan runtime library is required but missing."
  echo "   On Ubuntu/Debian, install it with:"
  echo ""
  echo "     sudo apt install libclang-rt-${CLANG_VER}-dev"
  echo ""
  echo "   This provides libclang_rt.asan, libclang_rt.ubsan, and fuzzer runtimes."
  exit 1
fi
rm -f "$ASAN_TEST"

banner "CFL Fuzzer Build — Full Instrumentation"
echo "Compiler:  $($CXX --version | head -1)"
echo "CMake:     $(cmake --version | head -1)"
echo "Cores:     $NPROC"
echo "Output:    $OUTPUT_DIR"
echo ""
echo "Flags:"
echo "  Library:  $CFLAGS_LIB"
echo "  Fuzzer:   $CXXFLAGS_FUZZER"
echo "  Coverage: $COVERAGE_FLAGS"

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

# --- Step 2: Patch wxWidgets out ---
banner "Step 2: Patch wxWidgets"
CMAKELISTS="$ICCDEV_DIR/Build/Cmake/CMakeLists.txt"
if grep -q 'find_package(wxWidgets' "$CMAKELISTS" 2>/dev/null; then
  sed -i 's/find_package(wxWidgets/#find_package(wxWidgets/' "$CMAKELISTS"
  sed -i 's/if(wxWidgets_FOUND)/if(FALSE AND wxWidgets_FOUND)/' "$CMAKELISTS"
  sed -i '/wx_/ s/^/#/' "$CMAKELISTS" 2>/dev/null || true
  echo "Patched out wxWidgets"
else
  echo "Already patched (or not present)"
fi

# --- Step 3: Build static libraries ---
banner "Step 3: Build IccProfLib2-static + IccXML2-static"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake Cmake/ \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS_LIB" \
  -DCMAKE_CXX_FLAGS="$CFLAGS_LIB -frtti" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_STATIC_LIBS=ON \
  -DENABLE_SHARED_LIBS=ON \
  -DENABLE_TOOLS=OFF \
  -DENABLE_FUZZING=ON \
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
  echo "❌ ERROR: Missing instrumentation — aborting"
  exit 1
fi

# --- Step 4: Build fuzzers ---
banner "Step 4: Build fuzzers"
mkdir -p "$OUTPUT_DIR"
cd "$SCRIPT_DIR"

BUILT=0
FAILED=0
SKIPPED=0

build_fuzzer() {
  local name="$1"
  shift
  local extra_libs=("$@")

  if [ ! -f "$SCRIPT_DIR/${name}.cpp" ]; then
    echo "  SKIP $name (no source)"
    SKIPPED=$((SKIPPED + 1))
    return
  fi

  if $CXX $CXXFLAGS_FUZZER $INCLUDE_FLAGS \
    "$SCRIPT_DIR/${name}.cpp" \
    "$LIB_PROF" \
    "${extra_libs[@]}" \
    -o "$OUTPUT_DIR/$name" 2>&1; then
    SIZE=$(ls -lh "$OUTPUT_DIR/$name" | awk '{print $5}')
    echo "  ✅ $name ($SIZE)"
    BUILT=$((BUILT + 1))
  else
    echo "  ❌ $name FAILED"
    FAILED=$((FAILED + 1))
  fi
}

echo "Core fuzzers (12):"
for f in "${CORE_FUZZERS[@]}"; do
  if [ "$f" = "icc_deep_dump_fuzzer" ]; then
    build_fuzzer "$f" "-Wl,--allow-multiple-definition"
  else
    build_fuzzer "$f"
  fi
done

echo ""
echo "XML fuzzers (2):"
for f in "${XML_FUZZERS[@]}"; do
  build_fuzzer "$f" "$LIB_XML" -lxml2 -lz
done

echo ""
echo "TIFF fuzzers (2):"
if [ -f "$TIFFIMG_SRC" ]; then
  mkdir -p "$(dirname "$TIFFIMG_OBJ")"
  echo "  Compiling TiffImg.o..."
  $CXX $CXXFLAGS_FUZZER $INCLUDE_FLAGS $TIFF_CFLAGS \
    -I"$(dirname "$TIFFIMG_SRC")" \
    -c "$TIFFIMG_SRC" -o "$TIFFIMG_OBJ" 2>&1
  for f in "${TIFF_FUZZERS[@]}"; do
    build_fuzzer "$f" "$TIFFIMG_OBJ" $TIFF_LIBS
  done
  rm -rf "$SCRIPT_DIR/.build_tmp"
else
  echo "  SKIP (TiffImg.cpp not found)"
  SKIPPED=$((SKIPPED + 2))
fi

# --- Summary ---
banner "Build Summary"
TOTAL=$((BUILT + FAILED + SKIPPED))
echo "  Built:   $BUILT / $TOTAL"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo ""

if [ "$BUILT" -gt 0 ]; then
  echo "Binaries:"
  ls -lh "$OUTPUT_DIR"/
  echo ""
  echo "SHA256 fingerprints:"
  sha256sum "$OUTPUT_DIR"/icc_* 2>/dev/null || shasum -a 256 "$OUTPUT_DIR"/icc_* 2>/dev/null
fi

if [ "$FAILED" -gt 0 ]; then
  echo ""
  echo "❌ $FAILED fuzzer(s) failed to build"
  exit 1
fi

echo ""
echo "✅ All $BUILT fuzzers built successfully"
