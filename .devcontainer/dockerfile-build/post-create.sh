#!/usr/bin/env bash
###############################################################
# post-create.sh — Dockerfile-based dev container setup
#
# The Dockerfile already built iccDEV and generated profiles.
# This script sets up the MCP server venv, symlinks the pre-built
# iccDEV into the workspace, and verifies the environment.
###############################################################
set -euo pipefail

echo "[INFO] Setting up MCP server venv..."
cd "${GITHUB_WORKSPACE:-$PWD}"

if [ -d "mcp-server" ]; then
  cd mcp-server
  python3 -m venv .venv
  .venv/bin/pip install --quiet --upgrade pip
  .venv/bin/pip install --quiet -e .
  cd ..
fi

# Symlink pre-built iccDEV into workspace if not already present
if [ -d "/opt/iccdev" ] && [ ! -d "cfl/iccDEV" ]; then
  mkdir -p cfl
  ln -sf /opt/iccdev cfl/iccDEV
  echo "[OK] Linked /opt/iccdev -> cfl/iccDEV"
fi

# Verify tools are available
TOOL_COUNT=0
for tool in iccFromXml iccToXml iccDumpProfile iccApplyProfiles iccRoundTrip; do
  TOOL_PATH=$(find /opt/iccdev/Build/build/Tools -name "$tool" -type f 2>/dev/null | head -1)
  if [ -n "$TOOL_PATH" ] && [ -x "$TOOL_PATH" ]; then
    TOOL_COUNT=$((TOOL_COUNT + 1))
  fi
done
echo "[OK] Found $TOOL_COUNT/5 iccDEV CLI tools"

# Count generated profiles
PROFILE_COUNT=$(find /opt/iccdev/Testing -name '*.icc' -type f 2>/dev/null | wc -l)
echo "[OK] $PROFILE_COUNT ICC profiles available in /opt/iccdev/Testing/"

echo ""
echo "[OK] Dev container ready (Dockerfile-based, pre-built)"
echo "  MCP server:  cd mcp-server && source .venv/bin/activate && python icc_profile_mcp.py"
echo "  Web UI:      cd mcp-server && source .venv/bin/activate && python web_ui.py"
echo "  Tests:       cd mcp-server && source .venv/bin/activate && python test_mcp.py && python test_web_ui.py"
echo "  iccDEV:      /opt/iccdev (pre-built with ASAN+UBSAN, tools enabled)"
