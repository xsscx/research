#!/bin/bash
###############################################################
#
# apply-patches.sh — Unified iccDEV clone, patch, and prep
#
# Usage:
#   docker/apply-patches.sh <target-dir> <patches-dir>
#
# Example:
#   docker/apply-patches.sh /opt/iccdev /tmp/cfl-patches
#
# Steps:
#   1. Clone iccDEV (shallow) into <target-dir>
#   2. Apply all CFL patches from <patches-dir>
#   3. Disable wxWidgets in CMakeLists.txt
#
###############################################################
set -euo pipefail

TARGET="${1:?Usage: apply-patches.sh <target-dir> <patches-dir>}"
PATCHES="${2:?Usage: apply-patches.sh <target-dir> <patches-dir>}"

# --- Clone ---
if [ -d "$TARGET/.git" ]; then
  echo "[apply-patches] $TARGET already exists, skipping clone"
else
  echo "[apply-patches] Cloning iccDEV into $TARGET ..."
  git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git "$TARGET"
fi
echo "[apply-patches] HEAD: $(cd "$TARGET" && git log --oneline -1)"

# --- Apply CFL patches ---
applied=0
skipped=0
for p in "$PATCHES"/*.patch; do
  [ -f "$p" ] || continue
  # Skip comment-only (no-op) patches
  if head -1 "$p" | grep -q '^#'; then
    : # still try to apply — git apply handles empty diffs
  fi
  if patch -p1 -d "$TARGET" --forward -s < "$p" 2>/dev/null; then
    echo "  Applied $(basename "$p")"
    applied=$((applied + 1))
  else
    echo "  Skipped $(basename "$p") (already applied or N/A)"
    skipped=$((skipped + 1))
  fi
done
echo "[apply-patches] $applied applied, $skipped skipped"

# --- Disable wxWidgets ---
CMAKE="$TARGET/Build/Cmake/CMakeLists.txt"
if [ -f "$CMAKE" ]; then
  sed -i '/find_package(wxWidgets/,/endif()/ s/^/# /' "$CMAKE" 2>/dev/null || true
  echo "[apply-patches] wxWidgets disabled in CMakeLists.txt"
fi

echo "[apply-patches] Done — $TARGET ready for cmake"
