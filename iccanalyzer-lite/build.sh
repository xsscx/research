#!/bin/bash
# Build iccAnalyzer-lite — Debug build with maximum instrumentation
# Goal: Find bugs in iccDEV library code via ASAN, UBSAN, coverage, and debug checks
#
# Build profile: DEBUG (not Release)
#   -O0          : No optimization — preserves all code paths for analysis
#   -g3          : Maximum debug info (includes macro definitions)
#   -DDEBUG      : Enable library-level debug assertions
#   ASAN+UBSAN   : Runtime memory and undefined-behavior detection
#   Coverage     : gcov-compatible instrumentation for code profiling
#   -ftrapv      : Trap on signed integer overflow
#   -fstack-protector-strong : Stack buffer overflow detection

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

# Strip stray U+FE0F (emoji variation selector) from upstream source
SIGUTILS="$ICCDEV_ROOT/IccProfLib/IccSignatureUtils.h"
if [ -f "$SIGUTILS" ] && grep -qP '\xef\xb8\x8f' "$SIGUTILS" 2>/dev/null; then
  sed -i 's/\xef\xb8\x8f//g' "$SIGUTILS"
  echo "[OK] Stripped stray U+FE0F from IccSignatureUtils.h"
fi

# Clean stale coverage data to prevent gcda merge errors after rebuild
find . -name "*.gcda" -delete 2>/dev/null || true

# ── Compiler ──────────────────────────────────────────────────────────
export CXX=clang++

# ── Debug + Sanitizer + Coverage flags ────────────────────────────────
SANITIZERS="-fsanitize=address,undefined -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow -fsanitize=integer -fno-sanitize-recover=undefined"
DEBUG_FLAGS="-g3 -O0 -DDEBUG -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-common"
HARDENING="-ftrapv -fstack-protector-strong -D_FORTIFY_SOURCE=0"
# NO_COVERAGE=1 disables gcov instrumentation (e.g. Docker containers)
if [ "${NO_COVERAGE:-0}" = "1" ]; then
  COVERAGE=""
  echo "[INFO] Coverage disabled (NO_COVERAGE=1)"
else
  COVERAGE="-fprofile-arcs -ftest-coverage --coverage"
fi
STANDARD="-std=c++17 -DICCANALYZER_LITE -Wall -Wextra -Wno-unused-parameter"
DIAGNOSTICS="-DICC_LOG_SAFE -DICC_TRACE_NAN_ENABLED"

export CXXFLAGS="${SANITIZERS} ${DEBUG_FLAGS} ${HARDENING} ${COVERAGE} ${STANDARD} ${DIAGNOSTICS}"
if [ "${NO_COVERAGE:-0}" = "1" ]; then
  export LDFLAGS="${SANITIZERS}"
else
  export LDFLAGS="${SANITIZERS} -fprofile-arcs --coverage"
fi

echo "CXXFLAGS: $CXXFLAGS"
echo ""

# Include paths
INCLUDES="-I. -I${ICCDEV_ROOT}/IccProfLib -I${ICCDEV_ROOT}/IccXML/IccLibXML -I/usr/include/libxml2"

# Libraries
GCOV_LIB=""
if [ "${NO_COVERAGE:-0}" != "1" ]; then
  GCOV_LIB="-lgcov"
fi
LIBS="${ICCDEV_BUILD}/IccProfLib/libIccProfLib2-static.a ${ICCDEV_BUILD}/IccXML/libIccXML2-static.a -lxml2 -lz -llzma -lm -lssl -lcrypto ${GCOV_LIB}"

# Source files
SOURCES="iccAnalyzer-lite.cpp IccAnalyzerConfig.cpp IccAnalyzerErrors.cpp IccAnalyzerSecurity.cpp IccAnalyzerSignatures.cpp IccAnalyzerValidation.cpp IccAnalyzerComprehensive.cpp IccAnalyzerInspect.cpp IccAnalyzerNinja.cpp IccAnalyzerLUT.cpp IccAnalyzerXMLExport.cpp IccAnalyzerCallGraph.cpp IccAnalyzerTagDetails.cpp"

NPROC=$(nproc)
if [ "${NO_COVERAGE:-0}" = "1" ]; then
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
  echo "Coverage output: .gcda files written alongside .gcno files at runtime"
  echo "  Library coverage: iccDEV/Build/**/*.gcda"
  echo "  Analyzer coverage: *.gcda (current directory)"
fi
