#!/bin/bash
# local_build.sh — Full local build for iccanalyzer-lite
#
# Bootstraps iccDEV (clone + cmake + make) then calls build.sh.
# CI workflows handle iccDEV separately with 3-layer caching,
# so this script is for local development only.
#
# Usage:
#   ./local_build.sh          # bootstrap iccDEV (if needed) + build analyzer
#   ./local_build.sh clean    # remove iccDEV clone + build artifacts
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt-get install -y clang cmake libxml2-dev libtiff-dev zlib1g-dev \
#     liblzma-dev nlohmann-json3-dev libssl-dev

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ICCDEV_DIR="$SCRIPT_DIR/iccDEV"
LIB_PROF="$ICCDEV_DIR/Build/IccProfLib/libIccProfLib2-static.a"
LIB_XML="$ICCDEV_DIR/Build/IccXML/libIccXML2-static.a"

# --- Clean mode ---
if [ "${1:-}" = "clean" ]; then
    echo "[INFO] Removing iccDEV clone and build artifacts..."
    rm -rf "$ICCDEV_DIR"
    rm -f "$SCRIPT_DIR"/iccanalyzer-lite
    rm -f "$SCRIPT_DIR"/*.o "$SCRIPT_DIR"/*.gcda "$SCRIPT_DIR"/*.gcno
    echo "[OK] Clean complete"
    exit 0
fi

# --- Step 1: Clone iccDEV ---
if [ -d "$ICCDEV_DIR/.git" ]; then
    echo "[INFO] iccDEV already cloned ($(cd "$ICCDEV_DIR" && git rev-parse --short HEAD))"
else
    echo "[INFO] Cloning iccDEV..."
    rm -rf "$ICCDEV_DIR"
    git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git "$ICCDEV_DIR"
fi

# --- Step 2: Build iccDEV static libraries ---
if [ -f "$LIB_PROF" ] && [ -f "$LIB_XML" ]; then
    echo "[INFO] iccDEV libs already built (skip)"
else
    echo "[INFO] Building iccDEV static libraries..."
    cd "$ICCDEV_DIR/Build"
    CXX=clang++ cmake Cmake \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_TOOLS=OFF \
        -DICC_LOG_SAFE=ON \
        -DICC_TRACE_NAN_ENABLED=ON \
        -Wno-dev
    make -j"$(nproc)"
    cd "$SCRIPT_DIR"
    echo "[OK] iccDEV libs built:"
    ls -lh "$LIB_PROF" "$LIB_XML"
fi

# --- Step 3: Build iccanalyzer-lite ---
echo ""
exec "$SCRIPT_DIR/build.sh"
