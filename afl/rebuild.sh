#!/bin/bash
# afl/rebuild.sh - Clean rebuild of AFL-instrumented iccDEV
#
# Usage: ./afl/rebuild.sh [build.sh options]
#
# Performs a clean rebuild: removes Build-AFL, reconfigures, and compiles.
# Use after upstream iccDEV sync or when build is corrupted.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ICCDEV_DIR="$REPO_ROOT/afl/iccDEV"
BUILD_DIR="${AFL_BUILD_DIR:-$ICCDEV_DIR/Build-AFL}"

echo "[*] Full AFL rebuild requested"
echo ""

echo "[*] Stopping any AFL fuzzers recorded under AFL output directories..."
"$REPO_ROOT/afl/stop.sh" all

# Clean build directory
if [[ -d "$BUILD_DIR" ]]; then
    echo "[*] Removing $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi

# Delegate to build.sh
exec "$REPO_ROOT/afl/build.sh" "$@"
