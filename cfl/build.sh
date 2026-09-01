#!/bin/bash -eu
#
# CFL Local Build - instrumented LibFuzzer or TSAN corpus replay
#
# Clones iccDEV, builds static libraries, then compiles all fuzzers.
#
# Usage:  ./build.sh                         # build all fuzzers against upstream master
#         ./build.sh clean                   # remove build artifacts and start fresh
#         ./build.sh --sanitizer thread
#
# Requirements: clang-22/clang++-22, cmake 3.15+, libxml2-dev, libtiff-dev,
#               zlib, libclang-rt-22-dev (provides ASan/UBSan runtime)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ICCDEV_DIR="${CFL_ICCDEV_DIR:-$SCRIPT_DIR/iccDEV}"
BUILD_DIR="$ICCDEV_DIR/Build"
OUTPUT_DIR="$SCRIPT_DIR/bin"
PROFRAW_DIR="$SCRIPT_DIR/profraw"
PATCH_DIR="$SCRIPT_DIR/patches"
NPROC="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

CC="${CC:-clang-22}"
CXX="${CXX:-clang++-22}"
WITH_PATCHES="${CFL_WITH_PATCHES:-0}"
REFRESH_ICCDEV="${CFL_REFRESH_ICCDEV:-0}"
KEEP_ICCDEV="${CFL_KEEP_ICCDEV:-0}"
ICCDEV_REF="${CFL_ICCDEV_REF:-master}"
SANITIZER_MODE="${CFL_SANITIZER:-address}"
DEFAULT_ICCDEV_DIR="$SCRIPT_DIR/iccDEV"

# Sanitizer + debug + instrumentation + coverage flags
COMMON_CFLAGS="-g3 -O0 -fno-omit-frame-pointer -Wall -Wextra -Wpedantic -Werror"
COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
SANITIZER_FLAGS=""
FUZZER_FLAGS=""
ENABLE_FUZZING_VALUE="ON"

configure_sanitizer() {
  COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
  ENABLE_FUZZING_VALUE="ON"
  case "$SANITIZER_MODE" in
    address)
      OUTPUT_DIR="$SCRIPT_DIR/bin"
      SANITIZER_FLAGS="-fsanitize=address,undefined,integer,float-divide-by-zero,float-cast-overflow -fsanitize=fuzzer-no-link"
      FUZZER_FLAGS="-fsanitize=fuzzer,address,undefined,integer,float-divide-by-zero,float-cast-overflow"
      ;;
    thread)
      OUTPUT_DIR="$SCRIPT_DIR/bin-tsan"
      SANITIZER_FLAGS="-fsanitize=thread"
      FUZZER_FLAGS="-fsanitize=thread"
      COVERAGE_FLAGS=""
      ENABLE_FUZZING_VALUE="OFF"
      ;;
    *)
      echo "[FAIL] ERROR: unsupported sanitizer '$SANITIZER_MODE' (use address or thread)" >&2
      exit 1
      ;;
  esac
  CFLAGS_LIB="$COMMON_CFLAGS $SANITIZER_FLAGS $COVERAGE_FLAGS"
  CXXFLAGS_FUZZER="$COMMON_CFLAGS $FUZZER_FLAGS $COVERAGE_FLAGS -std=c++17 -frtti"
}

INCLUDE_FLAGS="-I$ICCDEV_DIR/IccProfLib -I$ICCDEV_DIR/IccXML/IccLibXML"
INCLUDE_FLAGS="$INCLUDE_FLAGS -I$ICCDEV_DIR/Tools/CmdLine"
INCLUDE_FLAGS="$INCLUDE_FLAGS -I$ICCDEV_DIR/Tools/CmdLine/IccCommon"
INCLUDE_FLAGS="$INCLUDE_FLAGS -I$ICCDEV_DIR/Tools/CmdLine/IccApplyProfiles"
INCLUDE_FLAGS="$INCLUDE_FLAGS -I$ICCDEV_DIR/Tools/CmdLine/IccPawgReport"
INCLUDE_FLAGS="$INCLUDE_FLAGS -I$ICCDEV_DIR/Tools/CmdLine/IccProfilePlot"
INCLUDE_FLAGS="$INCLUDE_FLAGS -I$ICCDEV_DIR/IccConnect/IccLibConnect"
INCLUDE_FLAGS="$INCLUDE_FLAGS -I$ICCDEV_DIR/IccJSON/IccLibJSON"
INCLUDE_FLAGS="$INCLUDE_FLAGS -I$BUILD_DIR/IccConnect -I$BUILD_DIR/IccJSON"
INCLUDE_FLAGS="$INCLUDE_FLAGS $(pkg-config --cflags libxml-2.0 2>/dev/null || echo '-I/usr/include/libxml2')"

# Upstream cmake may set CMAKE_DEBUG_POSTFIX="d" for Debug builds.
LIB_PROF="$BUILD_DIR/IccProfLib/libIccProfLib2-static.a"
LIB_XML="$BUILD_DIR/IccXML/libIccXML2-static.a"
LIB_CONNECT="$BUILD_DIR/IccConnect/libIccConnect2-static.a"
LIB_JSON="$BUILD_DIR/IccJSON/libIccJSON2-static.a"
[ ! -f "$LIB_PROF" ] && LIB_PROF="$BUILD_DIR/IccProfLib/libIccProfLib2-staticd.a"
[ ! -f "$LIB_XML" ] && LIB_XML="$BUILD_DIR/IccXML/libIccXML2-staticd.a"
[ ! -f "$LIB_CONNECT" ] && LIB_CONNECT="$BUILD_DIR/IccConnect/libIccConnect2-staticd.a"
[ ! -f "$LIB_JSON" ] && LIB_JSON="$BUILD_DIR/IccJSON/libIccJSON2-staticd.a"

# Core fuzzers (IccProfLib only), mapped to upstream iccDEV tools.
CORE_FUZZERS=(
  icc_proflib_fuzzer
  icc_v5dspobs_fuzzer
  icc_roundtrip_fuzzer
  icc_dump_fuzzer
  icc_link_fuzzer
  icc_fromcube_fuzzer
)

# IccConnect library fuzzers.
CONNECT_FUZZERS=(
  icc_applynamedcmm_fuzzer
  icc_applysearch_fuzzer
  icc_applysearch_weight_fuzzer
  icc_connect_fuzzer
)

# IccJSON library fuzzers.
JSON_FUZZERS=(
  icc_fromjson_fuzzer
  icc_tojson_fuzzer
)

# XML fuzzers (IccProfLib + IccXML + libxml2)
XML_FUZZERS=(
  icc_fromxml_fuzzer
  icc_toxml_fuzzer
)

# TIFF fuzzers (IccProfLib + TiffImg.o + libtiff)
TIFF_FUZZERS=(
  icc_applyprofiles_fuzzer
  icc_applyprofiles_row_fuzzer
  icc_specsep_fuzzer
  icc_tiffdump_fuzzer
)

# Media/report fuzzers for ICC-bearing image/report tool surfaces.
JPEG_FUZZERS=(
  icc_jpegdump_fuzzer
)

PNG_FUZZERS=(
  icc_pngdump_fuzzer
)

REPORT_FUZZERS=(
  icc_pawgreport_fuzzer
)

# Data-first profile visualization API fuzzer.
PROFILE_VISUALIZE_FUZZERS=(
  icc_profilevisualize_fuzzer
)

TIFFIMG_SRC="$ICCDEV_DIR/Tools/CmdLine/IccApplyProfiles/TiffImg.cpp"
TIFFIMG_OBJ="$SCRIPT_DIR/.build_tmp/TiffImg.o"
TIFF_CFLAGS="$(pkg-config --cflags libtiff-4 2>/dev/null || true)"
TIFF_LIBS="$(pkg-config --libs libtiff-4 2>/dev/null || echo '-ltiff')"
PNG_CFLAGS="$(pkg-config --cflags libpng 2>/dev/null || true)"
PNG_LIBS="$(pkg-config --libs libpng 2>/dev/null || echo '-lpng')"
ZLIB_LIBS="$(pkg-config --libs zlib 2>/dev/null || echo '-lz')"
PAWG_SRC="$ICCDEV_DIR/Tools/CmdLine/IccPawgReport/PawgReport.cpp"
PAWG_OBJ="$SCRIPT_DIR/.build_tmp/PawgReport.o"
ICC_VIZ_MODEL_SRC="$ICCDEV_DIR/Tools/CmdLine/IccProfilePlot/IccVizModel.cpp"
ICC_VIZ_MODEL_OBJ="$SCRIPT_DIR/.build_viz_tmp/IccVizModel.o"
INCLUDE_FLAGS="$INCLUDE_FLAGS $PNG_CFLAGS"

banner() {
  echo ""
  echo "========================================"
  echo "  $1"
  echo "========================================"
}

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \?//'
  echo ""
  echo "Options:"
  echo "  clean             remove build artifacts and nested iccDEV checkout"
  echo "  --with-patches    apply local patches from cfl/patches"
  echo "  --branch REF      clone/fetch the named iccDEV branch or tag (default: master)"
  echo "  --ref REF         alias for --branch"
  echo "  --keep-iccdev     preserve current cfl/iccDEV source edits"
  echo "  --sanitizer MODE  address (default) or thread; thread writes bin-tsan/"
  echo "  --refresh-iccdev  fetch the selected iccDEV ref and reset the nested checkout"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    clean)
      CLEAN=1
      shift
      ;;
    --with-patches)
      WITH_PATCHES=1
      shift
      ;;
    --branch|--ref)
      if [[ $# -lt 2 || "$2" == --* ]]; then
        echo "[FAIL] ERROR: $1 requires an iccDEV branch or tag"
        exit 1
      fi
      ICCDEV_REF="$2"
      shift 2
      ;;
    --keep-iccdev)
      KEEP_ICCDEV=1
      shift
      ;;
    --sanitizer)
      if [[ $# -lt 2 || "$2" == --* ]]; then
        echo "[FAIL] ERROR: --sanitizer requires address or thread"
        exit 1
      fi
      SANITIZER_MODE="$2"
      shift 2
      ;;
    --refresh-iccdev)
      REFRESH_ICCDEV=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[FAIL] ERROR: unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

configure_sanitizer

if [[ "$REFRESH_ICCDEV" = "1" && "$KEEP_ICCDEV" = "1" ]]; then
  echo "[FAIL] ERROR: --refresh-iccdev and --keep-iccdev are mutually exclusive"
  exit 1
fi

if [[ "$ICCDEV_DIR" != "$DEFAULT_ICCDEV_DIR" && "$REFRESH_ICCDEV" = "1" ]]; then
  echo "[FAIL] ERROR: refusing --refresh-iccdev for external CFL_ICCDEV_DIR" >&2
  exit 1
fi

if [[ -z "$ICCDEV_REF" ]]; then
  echo "[FAIL] ERROR: iccDEV branch/ref must not be empty"
  exit 1
fi

if [[ "$WITH_PATCHES" != "0" && "$WITH_PATCHES" != "1" ]]; then
  echo "[FAIL] ERROR: CFL_WITH_PATCHES must be 0 or 1"
  exit 1
fi

if [ "${CLEAN:-0}" = "1" ]; then
  banner "Cleaning build artifacts"
  rm -rf "$SCRIPT_DIR/bin" "$SCRIPT_DIR/bin-tsan" "$SCRIPT_DIR/.build_tmp" \
    "$SCRIPT_DIR/.build_viz_tmp"
  if [[ "$ICCDEV_DIR" == "$DEFAULT_ICCDEV_DIR" ]]; then
    rm -rf "$ICCDEV_DIR"
  else
    echo "Preserving external CFL_ICCDEV_DIR: $ICCDEV_DIR"
  fi
  echo "[OK] Clean complete"
  exit 0
fi

for tool in "$CC" "$CXX" cmake pkg-config; do
  if ! command -v "$tool" &>/dev/null; then
    echo "[FAIL] ERROR: $tool not found. Install it and retry."
    exit 1
  fi
done

# Verify the selected sanitizer runtime is available.
ASAN_TEST=$(mktemp /tmp/asan_test.XXXXXX.cpp)
trap 'rm -f "$ASAN_TEST"' EXIT
echo 'int main(){}' > "$ASAN_TEST"
if [[ "$SANITIZER_MODE" == "thread" ]]; then
  RUNTIME_FLAGS="-fsanitize=thread"
else
  RUNTIME_FLAGS="-fsanitize=address,undefined"
fi
if ! $CXX $RUNTIME_FLAGS "$ASAN_TEST" -o /dev/null 2>/dev/null; then
  CLANG_VER=$($CXX --version | grep -oP '\d+' | head -1)
  echo "[FAIL] ERROR: Clang sanitizer runtime not found."
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
trap - EXIT

banner "CFL Fuzzer Build - $SANITIZER_MODE instrumentation"
echo "Compiler:  $($CXX --version | head -1)"
echo "CMake:     $(cmake --version | head -1)"
echo "Cores:     $NPROC"
echo "Output:    $OUTPUT_DIR"
echo "iccDEV ref: $ICCDEV_REF"
echo "Sanitizer: $SANITIZER_MODE"
echo ""
echo "Flags:"
echo "  Library:  $CFLAGS_LIB"
echo "  Fuzzer:   $CXXFLAGS_FUZZER"
echo "  Coverage: $COVERAGE_FLAGS"

banner "Step 1: iccDEV source"
if git -C "$ICCDEV_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [ "$REFRESH_ICCDEV" = "1" ]; then
    echo "Refreshing existing checkout from origin/$ICCDEV_REF"
    git -C "$ICCDEV_DIR" fetch --depth 1 origin "$ICCDEV_REF"
    git -C "$ICCDEV_DIR" checkout -B "$ICCDEV_REF" FETCH_HEAD
    git -C "$ICCDEV_DIR" reset --hard FETCH_HEAD
    git -C "$ICCDEV_DIR" clean -fd
  else
    echo "Using existing checkout: $(cd "$ICCDEV_DIR" && git rev-parse --short HEAD)"
  fi
else
  if [[ "$ICCDEV_DIR" != "$DEFAULT_ICCDEV_DIR" ]]; then
    echo "[FAIL] ERROR: external CFL_ICCDEV_DIR is not a Git worktree: $ICCDEV_DIR" >&2
    exit 1
  fi
  echo "Cloning iccDEV ref: $ICCDEV_REF"
  rm -rf "$ICCDEV_DIR"
  git clone --branch "$ICCDEV_REF" --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git "$ICCDEV_DIR"
fi
echo "Branch: $(cd "$ICCDEV_DIR" && git rev-parse --abbrev-ref HEAD)"
echo "Commit: $(cd "$ICCDEV_DIR" && git rev-parse --short HEAD)"

if [ "$KEEP_ICCDEV" = "1" ]; then
  echo "Preserving current cfl/iccDEV source edits"
else
  (cd "$ICCDEV_DIR" && git checkout -- . 2>/dev/null)
fi

if [ "$WITH_PATCHES" = "1" ]; then
  shopt -s nullglob
  cfl_patches=("$PATCH_DIR"/*.patch)
  shopt -u nullglob
  for patch_path in "${cfl_patches[@]}"; do
    patch_name="$(basename "$patch_path")"
    if git -C "$ICCDEV_DIR" apply --check "$patch_path"; then
      git -C "$ICCDEV_DIR" apply "$patch_path"
      echo "[OK] Applied: $patch_name"
    elif git -C "$ICCDEV_DIR" apply --reverse --check "$patch_path" >/dev/null 2>&1; then
      echo "[OK] Already applied: $patch_name"
    else
      echo "[FAIL] Patch does not apply: $patch_name"
      exit 1
    fi
  done
else
  echo "Patch application disabled"
fi

banner "Step 2: Build IccProfLib2-static + IccXML2-static"
mkdir -p "$BUILD_DIR"
rm -rf "$BUILD_DIR/CMakeCache.txt" "$BUILD_DIR/CMakeFiles"
cd "$BUILD_DIR"
rm -f IccProfLib/libIccProfLib2-static*.a IccXML/libIccXML2-static*.a \
  IccConnect/libIccConnect2-static*.a IccJSON/libIccJSON2-static*.a

cmake -S "$ICCDEV_DIR/Build/Cmake" -B "$BUILD_DIR" \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS_LIB" \
  -DCMAKE_CXX_FLAGS="$CFLAGS_LIB -std=c++17 -frtti" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_STATIC_LIBS=ON \
  -DENABLE_SHARED_LIBS=ON \
  -DENABLE_ICCJSON=ON \
  -DENABLE_TOOLS=OFF \
  -DENABLE_FUZZING="$ENABLE_FUZZING_VALUE" \
  -Wno-dev 2>&1 | tail -5

make -j"$NPROC" IccProfLib2-static IccXML2-static IccConnect2-static IccJSON2-static 2>&1 | tail -3

LIB_PROF="$BUILD_DIR/IccProfLib/libIccProfLib2-staticd.a"
LIB_XML="$BUILD_DIR/IccXML/libIccXML2-staticd.a"
LIB_CONNECT="$BUILD_DIR/IccConnect/libIccConnect2-staticd.a"
LIB_JSON="$BUILD_DIR/IccJSON/libIccJSON2-staticd.a"
[ ! -f "$LIB_PROF" ] && LIB_PROF="$BUILD_DIR/IccProfLib/libIccProfLib2-static.a"
[ ! -f "$LIB_XML" ] && LIB_XML="$BUILD_DIR/IccXML/libIccXML2-static.a"
[ ! -f "$LIB_CONNECT" ] && LIB_CONNECT="$BUILD_DIR/IccConnect/libIccConnect2-static.a"
[ ! -f "$LIB_JSON" ] && LIB_JSON="$BUILD_DIR/IccJSON/libIccJSON2-static.a"

echo ""
echo "Libraries:"
ls -lh "$LIB_PROF" "$LIB_XML" "$LIB_CONNECT" "$LIB_JSON"

ASAN_SYM=$(nm "$LIB_PROF" | grep -c '__asan' || true)
UBSAN_SYM=$(nm "$LIB_PROF" | grep -c '__ubsan' || true)
COV_SYM=$(nm "$LIB_PROF" | grep -c '__profc_\|__llvm_prf' || true)
XML_COV_SYM=$(nm "$LIB_XML" | grep -c '__profc_\|__llvm_prf' || true)
CONNECT_COV_SYM=$(nm "$LIB_CONNECT" | grep -c '__profc_\|__llvm_prf' || true)
JSON_COV_SYM=$(nm "$LIB_JSON" | grep -c '__profc_\|__llvm_prf' || true)
echo ""
echo "Instrumentation:"
echo "  ASan symbols:     $ASAN_SYM"
echo "  UBSan symbols:    $UBSAN_SYM"
echo "  Coverage symbols: $COV_SYM"
echo "  IccXML cov:       $XML_COV_SYM"
echo "  IccConnect cov:   $CONNECT_COV_SYM"
echo "  IccJSON cov:      $JSON_COV_SYM"
TSAN_SYM=$(nm "$LIB_PROF" | grep -c '__tsan' || true)
echo "  TSan symbols:     $TSAN_SYM"

if { [[ "$SANITIZER_MODE" == "address" ]] && \
     { [ "$ASAN_SYM" -eq 0 ] || [ "$UBSAN_SYM" -eq 0 ] || \
       [ "$COV_SYM" -eq 0 ] || [ "$XML_COV_SYM" -eq 0 ] || \
       [ "$CONNECT_COV_SYM" -eq 0 ] || [ "$JSON_COV_SYM" -eq 0 ]; }; } || \
   { [[ "$SANITIZER_MODE" == "thread" ]] && [ "$TSAN_SYM" -eq 0 ]; }; then
  echo "[FAIL] ERROR: Missing instrumentation - aborting"
  exit 1
fi

banner "Step 4: Build fuzzers"
mkdir -p "$OUTPUT_DIR" "$PROFRAW_DIR"
cd "$SCRIPT_DIR"

BUILD_RESULTS=$(mktemp)

build_fuzzer() {
  local name="$1"
  shift
  local extra_libs=("$@")

  if [ ! -f "$SCRIPT_DIR/${name}.cpp" ]; then
    echo "  SKIP $name (no source)"
    echo "SKIP" >> "$BUILD_RESULTS"
    return
  fi

  local CXXFLAGS_THIS="$COMMON_CFLAGS $FUZZER_FLAGS $COVERAGE_FLAGS -std=c++17 -frtti"
  local extra_sources=()
  local target_defines=()
  if [[ "$SANITIZER_MODE" == "thread" ]]; then
    extra_sources+=("$SCRIPT_DIR/tsan_corpus_runner.cpp")
    case "$name" in
      icc_applysearch_fuzzer|icc_applysearch_weight_fuzzer)
        target_defines+=("-DCFL_APPLYSEARCH_THREADED=1")
        ;;
    esac
  fi

  # shellcheck disable=SC2086
  if $CXX $CXXFLAGS_THIS $INCLUDE_FLAGS \
    "${target_defines[@]}" \
    "$SCRIPT_DIR/${name}.cpp" \
    "${extra_sources[@]}" \
    -Wl,--whole-archive "$LIB_PROF" -Wl,--no-whole-archive \
    "${extra_libs[@]}" \
    $ZLIB_LIBS \
    -o "$OUTPUT_DIR/$name" 2>&1; then
    SIZE=$(du -h "$OUTPUT_DIR/$name" | cut -f1)
    echo "  [OK] $name ($SIZE)"
    echo "OK" >> "$BUILD_RESULTS"
  else
    echo "  [FAIL] $name FAILED"
    echo "FAIL" >> "$BUILD_RESULTS"
  fi
}

echo "Core fuzzers - parallel build with $NPROC cores:"
for f in "${CORE_FUZZERS[@]}"; do
  build_fuzzer "$f" &
done
wait

echo ""
echo "IccConnect fuzzers:"
for f in "${CONNECT_FUZZERS[@]}"; do
  build_fuzzer "$f" -Wl,--whole-archive "$LIB_CONNECT" -Wl,--no-whole-archive &
done
wait

echo ""
echo "IccJSON fuzzers:"
for f in "${JSON_FUZZERS[@]}"; do
  build_fuzzer "$f" -Wl,--whole-archive "$LIB_JSON" -Wl,--no-whole-archive &
done
wait

echo ""
echo "XML fuzzers:"
for f in "${XML_FUZZERS[@]}"; do
  build_fuzzer "$f" "$LIB_XML" -lxml2 -lz &
done
wait

echo ""
echo "TIFF fuzzers:"
if [ -f "$TIFFIMG_SRC" ]; then
  mkdir -p "$(dirname "$TIFFIMG_OBJ")"
  echo "  Compiling TiffImg.o..."
  # shellcheck disable=SC2086
  $CXX $CXXFLAGS_FUZZER $INCLUDE_FLAGS $TIFF_CFLAGS \
    -I"$(dirname "$TIFFIMG_SRC")" \
    -c "$TIFFIMG_SRC" -o "$TIFFIMG_OBJ" 2>&1
  for f in "${TIFF_FUZZERS[@]}"; do
    # shellcheck disable=SC2086
    case "$f" in
      icc_applyprofiles_fuzzer|icc_applyprofiles_row_fuzzer)
        build_fuzzer "$f" "$TIFFIMG_OBJ" -Wl,--whole-archive "$LIB_CONNECT" -Wl,--no-whole-archive $TIFF_LIBS &
        ;;
      *)
        build_fuzzer "$f" "$TIFFIMG_OBJ" $TIFF_LIBS &
        ;;
    esac
  done
  wait
  rm -rf "$SCRIPT_DIR/.build_tmp"
else
  echo "  SKIP (TiffImg.cpp not found)"
  echo "SKIP" >> "$BUILD_RESULTS"
  echo "SKIP" >> "$BUILD_RESULTS"
fi

echo ""
echo "JPEG fuzzers:"
for f in "${JPEG_FUZZERS[@]}"; do
  build_fuzzer "$f" &
done
wait

echo ""
echo "PNG fuzzers:"
for f in "${PNG_FUZZERS[@]}"; do
  # shellcheck disable=SC2086
  build_fuzzer "$f" $PNG_LIBS &
done
wait

echo ""
echo "PAWG report fuzzers:"
if [ -f "$PAWG_SRC" ]; then
  mkdir -p "$(dirname "$PAWG_OBJ")"
  echo "  Compiling PawgReport.o..."
  # shellcheck disable=SC2086
  $CXX $CXXFLAGS_FUZZER $INCLUDE_FLAGS \
    -c "$PAWG_SRC" -o "$PAWG_OBJ" 2>&1
  for f in "${REPORT_FUZZERS[@]}"; do
    build_fuzzer "$f" "$PAWG_OBJ" &
  done
  wait
else
  echo "  SKIP (PawgReport.cpp not found)"
  echo "SKIP" >> "$BUILD_RESULTS"
fi

echo ""
echo "Profile visualization fuzzers:"
if [ -f "$ICC_VIZ_MODEL_SRC" ]; then
  mkdir -p "$(dirname "$ICC_VIZ_MODEL_OBJ")"
  echo "  Compiling IccVizModel.o..."
  # Compile the public model separately so the harness proves that the header
  # and implementation remain consumable across translation units.
  # shellcheck disable=SC2086
  $CXX $CXXFLAGS_FUZZER $INCLUDE_FLAGS \
    -c "$ICC_VIZ_MODEL_SRC" -o "$ICC_VIZ_MODEL_OBJ" 2>&1
  for f in "${PROFILE_VISUALIZE_FUZZERS[@]}"; do
    build_fuzzer "$f" "$ICC_VIZ_MODEL_OBJ" &
  done
  wait
  rm -rf "$SCRIPT_DIR/.build_viz_tmp"
else
  echo "  SKIP (IccVizModel.cpp not found)"
  echo "SKIP" >> "$BUILD_RESULTS"
fi

echo ""
echo "JSON config fuzzer:"
CFGCOMMON_DIR="$ICCDEV_DIR/IccConnect/IccLibConnect"
CFG_BUILD_TMP="$SCRIPT_DIR/.build_cfg_tmp"
mkdir -p "$CFG_BUILD_TMP"
if [ -f "$CFGCOMMON_DIR/IccCmmConfig.cpp" ] && [ -f "$CFGCOMMON_DIR/IccJsonUtil.cpp" ]; then
  echo "  Compiling IccCmmConfig.o + IccJsonUtil.o..."
  # shellcheck disable=SC2086
  $CXX $CXXFLAGS_FUZZER $INCLUDE_FLAGS \
    -c "$CFGCOMMON_DIR/IccCmmConfig.cpp" -o "$CFG_BUILD_TMP/IccCmmConfig.o" 2>&1
  # shellcheck disable=SC2086
  $CXX $CXXFLAGS_FUZZER $INCLUDE_FLAGS \
    -c "$CFGCOMMON_DIR/IccJsonUtil.cpp" -o "$CFG_BUILD_TMP/IccJsonUtil.o" 2>&1
  build_fuzzer "icc_cfg_fuzzer" "$CFG_BUILD_TMP/IccCmmConfig.o" "$CFG_BUILD_TMP/IccJsonUtil.o"
  rm -rf "$CFG_BUILD_TMP"
else
  echo "  SKIP (IccCmmConfig.cpp not found)"
  echo "SKIP" >> "$BUILD_RESULTS"
fi

banner "Build Summary"
BUILT=$(grep -c '^OK$' "$BUILD_RESULTS" || true)
FAILED=$(grep -c '^FAIL$' "$BUILD_RESULTS" || true)
SKIPPED=$(grep -c '^SKIP$' "$BUILD_RESULTS" || true)
BUILT=${BUILT:-0}
FAILED=${FAILED:-0}
SKIPPED=${SKIPPED:-0}
rm -f "$BUILD_RESULTS"
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
  echo ""
  if [[ "$SANITIZER_MODE" == "address" ]]; then
    echo "Profraw: set LLVM_PROFILE_FILE to control output, for example /mnt/fuzz-ssd/profraw/\${fuzzer}_%m_%p.profraw"
    echo "  Merge:  llvm-profdata merge -sparse /mnt/fuzz-ssd/profraw/*.profraw -o merged.profdata"
    echo "  Report: llvm-cov report \$(printf ' -object %s' $OUTPUT_DIR/icc_*) -instr-profile=merged.profdata"
  fi
fi

if [ "$FAILED" -gt 0 ]; then
  echo ""
  echo "[FAIL] fuzzer(s) failed to build"
  exit 1
fi

if [ "$SKIPPED" -gt 0 ]; then
  echo ""
  echo "[FAIL] fuzzer source or dependency missing; skipped targets are not valid for a full CFL build"
  exit 1
fi

if [ "$BUILT" -eq 0 ]; then
  echo ""
  echo "[FAIL] no CFL fuzzers were built"
  exit 1
fi

echo ""
echo "[OK] All $BUILT fuzzers built successfully"
