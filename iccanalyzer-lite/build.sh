#!/bin/bash
# Build iccAnalyzer-lite with ASAN+UBSAN+Coverage instrumentation
# Matches iccDEV Build configuration

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

# Compiler and flags (matching iccDEV)
export CXX=clang++
export CXXFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -fprofile-arcs -ftest-coverage --coverage -std=c++17 -DICCANALYZER_LITE"
export LDFLAGS="-fsanitize=address,undefined -fprofile-arcs --coverage"

# Include paths
INCLUDES="-I. -I${ICCDEV_ROOT}/IccProfLib -I${ICCDEV_ROOT}/IccXML/IccLibXML -I/usr/include/libxml2"

# Libraries
LIBS="${ICCDEV_BUILD}/IccProfLib/libIccProfLib2-static.a ${ICCDEV_BUILD}/IccXML/libIccXML2-static.a -lxml2 -lz -llzma -lm -lssl -lcrypto -lgcov"

# Source files
SOURCES="iccAnalyzer-lite.cpp IccAnalyzerConfig.cpp IccAnalyzerErrors.cpp IccAnalyzerSecurity.cpp IccAnalyzerSignatures.cpp IccAnalyzerValidation.cpp IccAnalyzerComprehensive.cpp IccAnalyzerInspect.cpp IccAnalyzerNinja.cpp IccAnalyzerLUT.cpp IccAnalyzerXMLExport.cpp IccAnalyzerCallGraph.cpp"

NPROC=$(nproc)
echo "Building iccAnalyzer-lite with ASAN+UBSAN+Coverage using $NPROC cores..."

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
