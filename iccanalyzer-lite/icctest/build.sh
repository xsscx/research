#!/bin/bash
# IccTest Library — build.sh
# Convenience build script matching V1 iccanalyzer-lite instrumentation.
#
# Copyright (c) 1994 - 2026 David H Hoyt LLC

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

# ── Find iccDEV ──
if [ -d "${SCRIPT_DIR}/../iccDEV" ]; then
    ICCDEV_ROOT="${SCRIPT_DIR}/../iccDEV"
elif [ -d "${SCRIPT_DIR}/../../iccDEV" ]; then
    ICCDEV_ROOT="${SCRIPT_DIR}/../../iccDEV"
else
    echo "ERROR: Cannot find iccDEV directory"
    exit 1
fi

echo "iccDEV: ${ICCDEV_ROOT}"

# ── Build ──
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

cmake "${SCRIPT_DIR}" \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DICCDEV_ROOT="${ICCDEV_ROOT}" \
    -DENABLE_SANITIZERS=ON \
    -DENABLE_COVERAGE=ON \
    -DBUILD_TESTS=ON

make -j"$(nproc)" VERBOSE=1 2>&1

echo ""
echo "Build complete."
echo "  Library: ${BUILD_DIR}/lib/libIccTest.a"
echo "  Tests:   ${BUILD_DIR}/lib/tests/icctest_unit_tests"
