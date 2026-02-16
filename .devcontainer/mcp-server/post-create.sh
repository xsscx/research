#!/usr/bin/env bash
###############################################################
# post-create.sh — MCP Server Python dev container setup
#
# Installs the MCP server in editable mode with all optional
# dependencies (web UI, dev/test tooling) into a venv.
###############################################################
set -euo pipefail

echo "[INFO] Setting up MCP server..."
cd "${GITHUB_WORKSPACE:-$PWD}/mcp-server"

python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -e ".[dev]"

echo "[INFO] Running tests..."
TEST_OK=true
.venv/bin/python test_mcp.py 2>&1 | tail -3 || TEST_OK=false
.venv/bin/python test_web_ui.py 2>&1 | tail -3 || TEST_OK=false

if [ "$TEST_OK" = true ]; then
  echo "[OK] All tests passed"
else
  echo "[WARN] Some tests failed — analysis binaries may not be built yet"
fi

echo ""
echo "[OK] MCP server dev container ready"
echo "  Activate:    cd mcp-server && source .venv/bin/activate"
echo "  MCP stdio:   python icc_profile_mcp.py"
echo "  Web UI:      python web_ui.py                    # http://localhost:8000"
echo "  Tests:       python test_mcp.py && python test_web_ui.py"
echo ""
echo "  To build analysis binaries (optional):"
echo "    cd ../iccanalyzer-lite && ./build.sh"
echo "    cd ../colorbleed_tools && make setup && make"
