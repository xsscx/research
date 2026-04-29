#!/bin/bash
# local_build.sh -- Full local build for iccanalyzer-lite
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

if [ -n "$(cd "$ICCDEV_DIR" && git diff --name-only | grep -v '^Testing/' || true)" ]; then
    echo "ERROR: iccDEV checkout has tracked modifications; refusing no-patch build."
    (cd "$ICCDEV_DIR" && git diff --name-only | sed 's/^/  /')
    exit 1
fi

# --- Step 2: Build iccanalyzer-lite ---
# build.sh configures missing iccDEV static libraries with matching flags.
echo ""
exec "$SCRIPT_DIR/build.sh"
