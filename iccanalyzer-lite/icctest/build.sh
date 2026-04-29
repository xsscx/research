#!/bin/bash
# IccTest Library -- build.sh
# Convenience build script matching V1 iccanalyzer-lite instrumentation.
#
# Copyright (c) 1994 - 2026 David H Hoyt LLC

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
NPROC="$(nproc 2>/dev/null || echo 4)"
CC="${CC:-clang}"
CXX="${CXX:-clang++}"

# -- Find iccDEV --
if [ -d "${SCRIPT_DIR}/../iccDEV" ]; then
    ICCDEV_ROOT="${SCRIPT_DIR}/../iccDEV"
elif [ -d "${SCRIPT_DIR}/../../iccDEV" ]; then
    ICCDEV_ROOT="${SCRIPT_DIR}/../../iccDEV"
else
    echo "ERROR: Cannot find iccDEV directory"
    exit 1
fi

echo "iccDEV: ${ICCDEV_ROOT}"

ICCDEV_BUILD="${ICCDEV_BUILD:-${ICCDEV_ROOT}/Build}"

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

    local sanitizers="-fsanitize=address,undefined -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow -fsanitize=integer -fsanitize-recover=address,undefined"
    local debug_flags="-g3 -O0 -DDEBUG -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-common"
    local hardening="-fstack-protector-strong -D_FORTIFY_SOURCE=2"
    local coverage="-fprofile-instr-generate -fcoverage-mapping"
    local diagnostics="-DICC_LOG_SAFE -DICC_TRACE_NAN_ENABLED"
    local iccdev_c_flags="${sanitizers} ${debug_flags} ${hardening} ${coverage}"
    local iccdev_cxx_flags="${iccdev_c_flags} ${diagnostics} -frtti"

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

# -- Build --
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

cmake "${SCRIPT_DIR}" \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_CXX_COMPILER="${CXX}" \
    -DICCDEV_ROOT="${ICCDEV_ROOT}" \
    -DICCDEV_BUILD="${ICCDEV_BUILD}" \
    -DENABLE_SANITIZERS=ON \
    -DENABLE_COVERAGE=ON \
    -DBUILD_TESTS=ON

cmake --build . -j"${NPROC}" --verbose 2>&1

echo ""
echo "Build complete."
echo "  Library: ${BUILD_DIR}/lib/libIccTest.a"
echo "  Tests:   ${BUILD_DIR}/lib/tests/icctest_unit_tests"
