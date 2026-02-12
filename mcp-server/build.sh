#!/bin/bash
# Build and run the ICC Profile MCP Server
#
# Usage:
#   ./build.sh                      # Build everything (iccDEV + tools + Python venv)
#   ./build.sh build                # Same as above
#   ./build.sh web                  # Start Web UI on 0.0.0.0:8000 (all interfaces)
#   ./build.sh web 8080             # Start Web UI on 0.0.0.0:8080
#   ./build.sh web 8080 192.168.1.5 # Start Web UI on specific IP and port
#   ./build.sh mcp                  # Start MCP server (stdio transport)
#   ./build.sh test                 # Run all tests (195 MCP + 124 Web UI)
#   ./build.sh clean                # Remove build artifacts
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt-get install -y build-essential cmake clang libxml2-dev libtiff-dev \
#     libjpeg-dev libpng-dev zlib1g-dev liblzma-dev nlohmann-json3-dev \
#     libssl-dev python3 python3-venv
#
# Copyright (c) 2026 David H Hoyt LLC

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ANALYZER_DIR="$REPO_ROOT/iccanalyzer-lite"
COLORBLEED_DIR="$REPO_ROOT/colorbleed_tools"
VENV_DIR="$SCRIPT_DIR/.venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Detect clang++ ──────────────────────────────────────────────────
find_clang() {
  if command -v clang++ >/dev/null 2>&1; then
    echo "clang++"
  elif command -v clang++-18 >/dev/null 2>&1; then
    echo "clang++-18"
  elif command -v clang++-17 >/dev/null 2>&1; then
    echo "clang++-17"
  else
    error "clang++ not found. Install with: sudo apt-get install clang"
  fi
}

# ── Build iccDEV libraries ─────────────────────────────────────────
build_iccdev() {
  local iccdev_dir="$ANALYZER_DIR/iccDEV"

  if [ -f "$iccdev_dir/Build/IccProfLib/libIccProfLib2-static.a" ]; then
    info "iccDEV libraries already built (skip)"
    return 0
  fi

  info "Cloning iccDEV..."
  if [ ! -d "$iccdev_dir" ]; then
    git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git "$iccdev_dir"
  fi

  # Patch out wxWidgets (not needed, avoids installing libwxgtk3.2-dev)
  info "Patching wxWidgets out of CMakeLists.txt..."
  sed -i 's/^  find_package(wxWidgets/#  find_package(wxWidgets/' "$iccdev_dir/Build/Cmake/CMakeLists.txt"
  sed -i 's/^      ADD_SUBDIRECTORY(Tools\/wxProfileDump)/#      ADD_SUBDIRECTORY(Tools\/wxProfileDump)/' "$iccdev_dir/Build/Cmake/CMakeLists.txt"
  sed -i 's/^    message(FATAL_ERROR "wxWidgets not found/#    message(FATAL_ERROR "wxWidgets not found/' "$iccdev_dir/Build/Cmake/CMakeLists.txt"

  local CXX
  CXX=$(find_clang)

  info "Building iccDEV with $CXX (ASAN+UBSAN)..."
  cd "$iccdev_dir/Build"
  cmake Cmake \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="${CXX/++/}" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -std=c++17" \
    -DENABLE_TOOLS=OFF \
    -DENABLE_STATIC_LIBS=ON \
    -Wno-dev
  make -j"$(nproc)"
  cd "$SCRIPT_DIR"

  info "iccDEV libraries built"
}

# ── Build iccanalyzer-lite ──────────────────────────────────────────
build_analyzer() {
  if [ -x "$ANALYZER_DIR/iccanalyzer-lite" ]; then
    info "iccanalyzer-lite already built (skip)"
    return 0
  fi

  build_iccdev

  info "Building iccanalyzer-lite..."
  cd "$ANALYZER_DIR"
  ./build.sh
  cd "$SCRIPT_DIR"

  info "iccanalyzer-lite built"
}

# ── Build colorbleed_tools (optional) ──────────────────────────────
build_colorbleed() {
  if [ -x "$COLORBLEED_DIR/iccToXml_unsafe" ]; then
    info "colorbleed_tools already built (skip)"
    return 0
  fi

  if [ ! -d "$COLORBLEED_DIR" ]; then
    warn "colorbleed_tools/ not found (skip — XML conversion will use safe iccToXml)"
    return 0
  fi

  # Symlink iccDEV to avoid a second clone
  if [ ! -d "$COLORBLEED_DIR/iccDEV" ] && [ -d "$ANALYZER_DIR/iccDEV" ]; then
    ln -sf "$ANALYZER_DIR/iccDEV" "$COLORBLEED_DIR/iccDEV"
  fi

  info "Building colorbleed_tools..."
  cd "$COLORBLEED_DIR"
  make CXXFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -std=c++17" \
       LINK_LIBS="-fsanitize=address,undefined -lxml2 -lz -llzma -lm" 2>/dev/null || \
  warn "colorbleed_tools build failed (non-fatal — safe iccToXml still available)"
  cd "$SCRIPT_DIR"
}

# ── Setup Python venv ──────────────────────────────────────────────
setup_venv() {
  if [ -f "$VENV_DIR/bin/activate" ]; then
    info "Python venv already exists (skip)"
    return 0
  fi

  info "Creating Python venv..."
  python3 -m venv "$VENV_DIR"
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
  pip install --quiet -e ".[dev]"

  info "Python venv ready"
}

# ── Activate venv helper ───────────────────────────────────────────
activate_venv() {
  if [ ! -f "$VENV_DIR/bin/activate" ]; then
    setup_venv
  fi
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
}

# ── Commands ───────────────────────────────────────────────────────

cmd_build() {
  info "Building all components..."
  build_iccdev
  build_analyzer
  build_colorbleed
  setup_venv
  echo ""
  info "Build complete. Next steps:"
  echo "  ./build.sh web              # Web UI → http://0.0.0.0:8000 (all interfaces)"
  echo "  ./build.sh web 8080         # Web UI → http://0.0.0.0:8080"
  echo "  ./build.sh web 8080 1.2.3.4 # Web UI on specific IP and port"
  echo "  ./build.sh mcp              # Start MCP server (stdio)"
  echo "  ./build.sh test             # Run test suite"
}

cmd_web() {
  local port="${1:-8000}"
  local host="${2:-0.0.0.0}"
  activate_venv
  info "Starting Web UI → http://$host:$port"
  ASAN_OPTIONS=detect_leaks=0 python "$SCRIPT_DIR/web_ui.py" --host "$host" --port "$port"
}

cmd_mcp() {
  activate_venv
  info "Starting MCP server (stdio transport)..."
  ASAN_OPTIONS=detect_leaks=0 python "$SCRIPT_DIR/icc_profile_mcp.py"
}

cmd_test() {
  activate_venv
  info "Running MCP test suite..."
  ASAN_OPTIONS=detect_leaks=0 python "$SCRIPT_DIR/test_mcp.py" 2>&1 | tee /tmp/mcp-test-output.txt
  local mcp_exit=${PIPESTATUS[0]}

  echo ""
  info "Running Web UI test suite..."
  ASAN_OPTIONS=detect_leaks=0 python "$SCRIPT_DIR/test_web_ui.py" 2>&1 | tee /tmp/webui-test-output.txt
  local webui_exit=${PIPESTATUS[0]}

  echo ""
  if [ "$mcp_exit" -eq 0 ] && [ "$webui_exit" -eq 0 ]; then
    info "All tests passed"
  else
    error "Tests failed (MCP=$mcp_exit, WebUI=$webui_exit)"
  fi
}

cmd_clean() {
  info "Cleaning build artifacts..."
  rm -rf "$VENV_DIR"
  rm -f "$ANALYZER_DIR"/iccanalyzer-lite "$ANALYZER_DIR"/*.o "$ANALYZER_DIR"/*.gcno "$ANALYZER_DIR"/*.gcda
  [ -d "$COLORBLEED_DIR" ] && (cd "$COLORBLEED_DIR" && make clean 2>/dev/null || true)
  info "Clean complete (iccDEV clone preserved — use 'rm -rf iccanalyzer-lite/iccDEV' to remove)"
}

cmd_help() {
  echo "ICC Profile MCP Server — Build & Run"
  echo ""
  echo "Usage: ./build.sh <command> [args]"
  echo ""
  echo "Commands:"
  echo "  build                Build everything (iccDEV + tools + Python venv)"
  echo "  web [port] [host]    Start Web UI (default: 0.0.0.0:8000, all interfaces)"
  echo "  mcp                  Start MCP server (stdio transport for AI assistants)"
  echo "  test                 Run all tests (MCP + Web UI)"
  echo "  clean                Remove build artifacts"
  echo "  help                 Show this help"
  echo ""
  echo "Examples:"
  echo "  ./build.sh                        # Build everything"
  echo "  ./build.sh web                    # Web UI → http://0.0.0.0:8000"
  echo "  ./build.sh web 9000               # Web UI → http://0.0.0.0:9000"
  echo "  ./build.sh web 8080 192.168.1.5   # Web UI on specific IP"
  echo "  ./build.sh web 8080 127.0.0.1     # Web UI on localhost only"
  echo "  ./build.sh mcp                    # MCP stdio server"
  echo "  ./build.sh test                   # Run 319 tests"
}

# ── Main ───────────────────────────────────────────────────────────
case "${1:-build}" in
  build)   cmd_build ;;
  web)     cmd_web "$2" "$3" ;;
  mcp)     cmd_mcp ;;
  test)    cmd_test ;;
  clean)   cmd_clean ;;
  help|-h|--help) cmd_help ;;
  *)       error "Unknown command: $1 (try: ./build.sh help)" ;;
esac
