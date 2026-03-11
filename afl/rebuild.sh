#!/bin/bash
# afl/rebuild.sh — Clean rebuild of AFL-instrumented iccDEV
#
# Usage: ./afl/rebuild.sh
#
# Performs a clean rebuild: removes Build-AFL, reconfigures, and compiles.
# Use after upstream iccDEV sync or when build is corrupted.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/iccDEV/Build-AFL"

echo "[*] Full AFL rebuild requested"
echo ""

# Stop any running fuzzers first
PIDS=$(pgrep -f "afl-fuzz" 2>/dev/null || true)
if [[ -n "$PIDS" ]]; then
    echo "[!] Active AFL fuzzers detected — stopping first..."
    "$REPO_ROOT/afl/stop.sh"
    sleep 2
fi

# Clean build directory
if [[ -d "$BUILD_DIR" ]]; then
    echo "[*] Removing $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi

# Delegate to build.sh
exec "$REPO_ROOT/afl/build.sh"
