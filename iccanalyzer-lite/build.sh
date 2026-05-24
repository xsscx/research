#!/bin/bash
# Build iccAnalyzer-lite -- Debug build with maximum instrumentation
# Goal: Find bugs in iccDEV library code via ASAN, UBSAN, coverage, and debug checks
#
# Build profile: DEBUG (not Release)
#   -O0          : No optimization -- preserves all code paths for analysis
#   -g3          : Maximum debug info (includes macro definitions)
#   -DDEBUG      : Enable library-level debug assertions
#   ASAN+UBSAN   : Runtime memory and undefined-behavior detection (RECOVERABLE)
#   Coverage     : clang source-based coverage (LLVM profraw/profdata)
#   -fstack-protector-strong : Stack buffer overflow detection
#
# Recovery architecture:
#   -fsanitize-recover=address,undefined : ASAN/UBSAN continue after findings
#   __asan_default_options()  : allocator_may_return_null=1, halt_on_error=0
#   __ubsan_default_options() : print_stacktrace=1, halt_on_error=0
#   icRealloc override        : 256MB single / 1GB cumulative allocation caps
#   Signal handler            : SIGSEGV/SIGBUS/SIGFPE crash recovery via siglongjmp

set -e

# Build directories
# When iccDEV is in iccanalyzer-lite/iccDEV/ (A/B test pattern)
if [ -d "iccDEV" ]; then
  ICCDEV_BUILD="iccDEV/Build"
  ICCDEV_ROOT="iccDEV"
# When iccDEV is in parent directory (original pattern)
elif [ -d "../iccDEV" ]; then
  ICCDEV_BUILD="../iccDEV/Build"
  ICCDEV_ROOT="../iccDEV"
else
  echo "ERROR: iccDEV not found in current directory or parent directory"
  exit 1
fi

echo "Using iccDEV at: $ICCDEV_ROOT"

if [ -d "$ICCDEV_ROOT/.git" ] && [ -n "$(cd "$ICCDEV_ROOT" && git diff --name-only | grep -v '^Testing/' || true)" ]; then
  echo "ERROR: iccDEV checkout has tracked modifications; refusing no-patch build."
  (cd "$ICCDEV_ROOT" && git diff --name-only | sed 's/^/  /')
  exit 1
fi

# Clean stale coverage data to prevent gcda merge errors after rebuild
find . -name "*.gcda" -delete 2>/dev/null || true

# -- Compiler ----------------------------------------------------------
export CXX="${CXX:-clang++}"
export CC="${CC:-clang}"
NPROC=$(nproc 2>/dev/null || echo 4)

# -- Debug + Sanitizer + Coverage flags --------------------------------
# NO_SANITIZERS=1 disables ASAN/UBSAN (local testing only -- do NOT use in Docker,
# the MCP Docker image MUST have ASAN+UBSAN for security analysis)
if [ "${NO_SANITIZERS:-0}" = "1" ]; then
  SANITIZERS=""
  echo "[INFO] Sanitizers disabled (NO_SANITIZERS=1)"
else
  SANITIZERS="-fsanitize=address,undefined -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow -fsanitize=integer -fsanitize-recover=address,undefined"
fi
DEBUG_FLAGS="-g3 -O0 -DDEBUG -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-common"
HARDENING="-fstack-protector-strong -D_FORTIFY_SOURCE=2"
# NO_COVERAGE=1 disables gcov instrumentation (e.g. Docker containers)
if [ "${NO_COVERAGE:-0}" = "1" ]; then
  COVERAGE=""
  echo "[INFO] Coverage disabled (NO_COVERAGE=1)"
else
  COVERAGE="-fprofile-instr-generate -fcoverage-mapping"
fi
STANDARD="-std=c++17 -DICCANALYZER_LITE -Wall -Wextra -Wno-unused-parameter -Wformat=2 -Wformat-security"
DIAGNOSTICS="-DICC_LOG_SAFE -DICC_TRACE_NAN_ENABLED"

export CXXFLAGS="${SANITIZERS} ${DEBUG_FLAGS} ${HARDENING} ${COVERAGE} ${STANDARD} ${DIAGNOSTICS}"
if [ "${NO_COVERAGE:-0}" = "1" ]; then
  export LDFLAGS="${SANITIZERS}"
else
  export LDFLAGS="${SANITIZERS} -fprofile-instr-generate"
fi

echo "CXXFLAGS: $CXXFLAGS"
echo ""

# Include paths
INCLUDES="-I. -I${ICCDEV_BUILD}/IccProfLib -I${ICCDEV_BUILD}/IccXML -I${ICCDEV_ROOT}/IccProfLib -I${ICCDEV_ROOT}/IccXML/IccLibXML -I/usr/include/libxml2"

# Libraries
find_static_lib() {
  local dir="$1"
  local base="$2"

  for candidate in \
    "${dir}/${base}-static.a" \
    "${dir}/${base}-staticd.a"; do
    if [ -f "$candidate" ]; then
      printf '%s' "$candidate"
      return 0
    fi
  done

  return 1
}

resolve_static_lib() {
  local dir="$1"
  local base="$2"
  local lib=""

  if lib="$(find_static_lib "$dir" "$base")"; then
    printf '%s' "$lib"
    return 0
  fi

  echo "ERROR: required static library not found in $dir for ${base}-static[ d].a" >&2
  exit 1
}

ensure_iccdev_static_libs() {
  local prof_lib=""
  local xml_lib=""

  if prof_lib="$(find_static_lib "${ICCDEV_BUILD}/IccProfLib" "libIccProfLib2")" &&
     xml_lib="$(find_static_lib "${ICCDEV_BUILD}/IccXML" "libIccXML2")"; then
    echo "[INFO] iccDEV static libraries already built:"
    ls -lh "$prof_lib" "$xml_lib"
    return 0
  fi

  if [ ! -d "${ICCDEV_BUILD}/Cmake" ]; then
    echo "ERROR: iccDEV CMake source not found at ${ICCDEV_BUILD}/Cmake" >&2
    exit 1
  fi

  echo "[INFO] Building missing iccDEV static libraries..."
  rm -rf "${ICCDEV_BUILD}/CMakeCache.txt" "${ICCDEV_BUILD}/CMakeFiles"

  local iccdev_c_flags="${SANITIZERS} ${DEBUG_FLAGS} ${HARDENING} ${COVERAGE}"
  local iccdev_cxx_flags="${iccdev_c_flags} ${DIAGNOSTICS} -frtti"

  (
    cd "${ICCDEV_BUILD}"
    CC="${CC}" CXX="${CXX}" cmake Cmake \
      -DCMAKE_C_COMPILER="${CC}" \
      -DCMAKE_CXX_COMPILER="${CXX}" \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="${iccdev_c_flags}" \
      -DCMAKE_CXX_FLAGS="${iccdev_cxx_flags}" \
      -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
      -DENABLE_STATIC_LIBS=ON \
      -DENABLE_SHARED_LIBS=OFF \
      -DENABLE_TOOLS=OFF \
      -DENABLE_TESTS=OFF \
      -DENABLE_WXWIDGETS=OFF \
      -DICC_LOG_SAFE=ON \
      -DICC_TRACE_NAN_ENABLED=ON \
      -Wno-dev
    cmake --build . --target IccProfLib2-static IccXML2-static -j "${NPROC}"
  )

  prof_lib="$(resolve_static_lib "${ICCDEV_BUILD}/IccProfLib" "libIccProfLib2")"
  xml_lib="$(resolve_static_lib "${ICCDEV_BUILD}/IccXML" "libIccXML2")"
  echo "[OK] iccDEV static libraries built:"
  ls -lh "$prof_lib" "$xml_lib"
}

ensure_iccdev_static_libs
LIB_PROF="$(resolve_static_lib "${ICCDEV_BUILD}/IccProfLib" "libIccProfLib2")"
LIB_XML="$(resolve_static_lib "${ICCDEV_BUILD}/IccXML" "libIccXML2")"
LIBS="${LIB_PROF} ${LIB_XML} -lxml2 -ltiff -lpng -ljpeg -lz -llzma -lm -lssl -lcrypto"

# Source files
SOURCES="iccAnalyzer-lite.cpp IccDevSafeOverrides.cpp IccHeuristicResult.cpp IccAnalyzerCapture.cpp IccAnalyzerConfig.cpp IccAnalyzerErrors.cpp IccAnalyzerSecurity.cpp IccAnalyzerPathValidation.cpp IccHeuristicsRawPost.cpp IccHeuristicsCodeQLPatterns.cpp IccHeuristicsExploitGap.cpp IccHeuristicsRegistry.cpp IccHeuristicsLibrary.cpp IccHeuristicsTagValidation.cpp IccHeuristicsDataValidation.cpp IccHeuristicsProfileCompliance.cpp IccHeuristicsIntegrity.cpp IccHeuristicsHeader.cpp IccAnalyzerSignatures.cpp IccAnalyzerValidation.cpp IccAnalyzerComprehensive.cpp IccAnalyzerInspect.cpp IccAnalyzerNinja.cpp IccAnalyzerLUT.cpp IccAnalyzerLUTTextIO.cpp IccAnalyzerLUTVisualization.cpp IccAnalyzerXMLExport.cpp IccAnalyzerCallGraph.cpp IccAnalyzerTagDetails.cpp IccImageAnalyzer.cpp IccAnalyzerJson.cpp IccAnalyzerReport.cpp IccAnalyzerPAWG.cpp IccHeuristicsXmlSafety.cpp IccConformanceHeader.cpp IccConformanceTagTypes.cpp IccConformanceRequired.cpp IccConformanceLUT.cpp IccConformanceV5.cpp IccConformanceSecurity.cpp IccConformanceQuality.cpp"

if [ "${NO_SANITIZERS:-0}" = "1" ] && [ "${NO_COVERAGE:-0}" = "1" ]; then
  echo "Building iccAnalyzer-lite (no sanitizers, no coverage) using $NPROC cores..."
elif [ "${NO_COVERAGE:-0}" = "1" ]; then
  echo "Building iccAnalyzer-lite with ASAN+UBSAN (no coverage) using $NPROC cores..."
else
  echo "Building iccAnalyzer-lite with ASAN+UBSAN+Coverage using $NPROC cores..."
fi

# Compile sources in parallel
for src in $SOURCES; do
  obj="${src%.cpp}.o"
  ${CXX} ${CXXFLAGS} ${INCLUDES} -c $src -o $obj &
done
wait

# Link (--allow-multiple-definition needed for icRealloc OOM-guard override)
echo "Linking..."
${CXX} ${LDFLAGS} -Wl,--allow-multiple-definition *.o ${LIBS} -o iccanalyzer-lite

echo ""
echo "[OK] Build complete"
ls -lh iccanalyzer-lite
file iccanalyzer-lite
if [ "${NO_COVERAGE:-0}" != "1" ]; then
  echo ""
  echo "Coverage: use LLVM_PROFILE_FILE=output_%m_%p.profraw to collect"
  echo "  Merge:  llvm-profdata-18 merge -sparse *.profraw -o merged.profdata"
  echo "  Report: llvm-cov-18 report ./iccanalyzer-lite -instr-profile=merged.profdata"
fi
