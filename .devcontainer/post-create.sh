#!/usr/bin/env bash
###############################################################
# post-create.sh — Dev container setup
#
# Installs build dependencies, clones iccDEV, sets up the
# MCP server Python venv, and builds analysis tools.
###############################################################
set -euo pipefail

echo "[INFO] Installing build dependencies..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  build-essential cmake pkg-config patch \
  clang-18 llvm-18 llvm-18-tools libclang-rt-18-dev \
  libxml2-dev libtiff-dev libjpeg-dev libpng-dev \
  zlib1g-dev liblzma-dev nlohmann-json3-dev libssl-dev \
  ccache
sudo rm -rf /var/lib/apt/lists/*

echo "[INFO] Setting up MCP server venv..."
cd mcp-server
python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -e .
cd ..

echo "[INFO] Cloning iccDEV..."
if [ ! -d "cfl/iccDEV" ]; then
  git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git cfl/iccDEV
fi

# Strip U+FE0F from upstream source
if [ -f "cfl/iccDEV/IccProfLib/IccSignatureUtils.h" ]; then
  sed -i "s/$(printf '\xef\xb8\x8f')//g" cfl/iccDEV/IccProfLib/IccSignatureUtils.h
fi

# Disable wxWidgets (not needed for CLI tools)
if [ -f "cfl/iccDEV/Build/Cmake/CMakeLists.txt" ]; then
  sed -i '/find_package(wxWidgets/,/endif()/ s/^/# /' cfl/iccDEV/Build/Cmake/CMakeLists.txt
fi

echo "[OK] Dev container ready"
echo "  MCP server:  cd mcp-server && source .venv/bin/activate && python icc_profile_mcp.py"
echo "  Web UI:      cd mcp-server && source .venv/bin/activate && python web_ui.py"
echo "  Tests:       cd mcp-server && source .venv/bin/activate && python test_mcp.py && python test_web_ui.py"
echo "  cmake:       cd cfl/iccDEV/Build && mkdir build && cd build && cmake ../Cmake -DCMAKE_BUILD_TYPE=Debug"
