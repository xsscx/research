#!/bin/bash
#
# ColorBleed Tools Build — Vanilla iccDEV + Sandboxed Unsafe Tools
#
# Clones vanilla upstream iccDEV (NO security patches), builds static
# libraries in three configurations, then compiles the sandboxed
# iccToXml_unsafe and iccFromXml_unsafe tools for each.
#
# Configurations:
#   release    — -O2 -DNDEBUG, no sanitizers, no coverage
#   debug      — -g -O0, no sanitizers, no coverage
#   sanitizer  — -g -O1 ASan+UBSan recoverable + coverage (default)
#
# Usage:  ./build.sh              # build all three configurations
#         ./build.sh sanitizer    # build only sanitizer config
#         ./build.sh release      # build only release config
#         ./build.sh debug        # build only debug config
#         ./build.sh clean        # remove build artifacts
#
# Output:  bin/release/    bin/debug/    bin/sanitizer/
#
# Requirements: clang/clang++ 14+, cmake 3.15+, libxml2-dev,
#               libtiff-dev, zlib1g-dev, liblzma-dev, pkg-config
#
# Copyright (c) 2021-2026 David H Hoyt LLC

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
ICCDEV_DIR="$REPO_ROOT/iccDEV"
NPROC="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
BIN_DIR="$REPO_ROOT/bin"

CXX="${CXX:-clang++}"
CC="${CC:-clang}"

TOOL_SOURCES=(IccToXml_unsafe IccFromXml_unsafe)
TOOL_BINS=(iccToXml_unsafe iccFromXml_unsafe)

INCLUDE_FLAGS="-I$ICCDEV_DIR/IccProfLib -I$ICCDEV_DIR/IccXML/IccLibXML"
INCLUDE_FLAGS="$INCLUDE_FLAGS $(pkg-config --cflags libxml-2.0 2>/dev/null || echo '-I/usr/include/libxml2')"
LINK_LIBS="-lxml2 -lz -llzma -lm -lpthread"

banner() {
  echo ""
  echo "════════════════════════════════════════"
  echo "  $1"
  echo "════════════════════════════════════════"
}

# --- Clean mode ---
if [ "${1:-}" = "clean" ]; then
  banner "Cleaning build artifacts"
  for d in release debug sanitizer; do
    rm -rf "$ICCDEV_DIR/Build-$d" "$BIN_DIR/$d"
  done
  rm -f "$REPO_ROOT/iccToXml_unsafe" "$REPO_ROOT/iccFromXml_unsafe"
  rm -rf "$ICCDEV_DIR" "$BIN_DIR"
  echo "[OK] Clean complete"
  exit 0
fi

# --- Pre-flight ---
for tool in "$CXX" cmake pkg-config; do
  if ! command -v "$tool" &>/dev/null; then
    echo "[FAIL] ERROR: $tool not found. Install it and retry."
    exit 1
  fi
done

banner "ColorBleed Tools Build"
echo "Compiler:  $($CXX --version | head -1)"
echo "CMake:     $(cmake --version | head -1)"
echo "Cores:     $NPROC"

# --- Determine which configs to build ---
CONFIGS_TO_BUILD=()
case "${1:-all}" in
  release|debug|sanitizer)
    CONFIGS_TO_BUILD=("$1") ;;
  all|"")
    CONFIGS_TO_BUILD=(release debug sanitizer) ;;
  *)
    echo "Usage: $0 [release|debug|sanitizer|clean|all]"
    exit 1 ;;
esac
echo "Configs:   ${CONFIGS_TO_BUILD[*]}"

# --- Step 1: Clone iccDEV if needed ---
banner "Step 1: iccDEV source"
if [ -d "$ICCDEV_DIR/.git" ]; then
  echo "Using existing checkout: $(cd "$ICCDEV_DIR" && git rev-parse --short HEAD)"
else
  echo "Cloning iccDEV..."
  rm -rf "$ICCDEV_DIR"
  git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git "$ICCDEV_DIR"
fi
echo "Commit: $(cd "$ICCDEV_DIR" && git rev-parse --short HEAD)"

# --- Step 2: Vanilla upstream (NO patches) ---
banner "Step 2: Vanilla upstream — no CFL patches applied"
echo "ColorBleed tools deliberately use unpatched iccDEV to detect crashes."

# Strip stray U+FE0F (emoji variation selector) from upstream source
SIGUTILS="$ICCDEV_DIR/IccProfLib/IccSignatureUtils.h"
if grep -qP '\xef\xb8\x8f' "$SIGUTILS" 2>/dev/null; then
  sed -i 's/\xef\xb8\x8f//g' "$SIGUTILS"
  echo "[OK] Stripped stray U+FE0F from IccSignatureUtils.h"
else
  echo "[INFO] IccSignatureUtils.h already clean"
fi

# --- Step 3: Patch wxWidgets and LTO out ---
banner "Step 3: Patch wxWidgets & LTO"
CMAKELISTS="$ICCDEV_DIR/Build/Cmake/CMakeLists.txt"
if grep -q 'find_package(wxWidgets' "$CMAKELISTS" 2>/dev/null; then
  sed -i 's/find_package(wxWidgets/#find_package(wxWidgets/' "$CMAKELISTS"
  sed -i 's/if(wxWidgets_FOUND)/if(FALSE AND wxWidgets_FOUND)/' "$CMAKELISTS"
  sed -i '/wx_/ s/^/#/' "$CMAKELISTS" 2>/dev/null || true
  echo "Patched out wxWidgets"
else
  echo "wxWidgets already patched"
fi
if grep -q 'set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)' "$CMAKELISTS" 2>/dev/null; then
  sed -i 's/set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)/#set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)/' "$CMAKELISTS"
  echo "Patched out LTO"
else
  echo "LTO already patched"
fi

# ─────────────────────────────────────────────────────
# Build function: cmake libs + link tools for one config
# ─────────────────────────────────────────────────────
build_config() {
  local config="$1"
  local build_dir="$ICCDEV_DIR/Build-$config"
  local out_dir="$BIN_DIR/$config"
  local cmake_type c_flags cxx_flags tool_flags

  case "$config" in
    release)
      cmake_type="Release"
      c_flags="-O2 -DNDEBUG"
      cxx_flags="$c_flags -frtti"
      tool_flags="-O2 -DNDEBUG -std=gnu++17 -Wall -frtti"
      ;;
    debug)
      cmake_type="Debug"
      c_flags="-g -O0 -fno-omit-frame-pointer"
      cxx_flags="$c_flags -frtti"
      tool_flags="-g -O0 -fno-omit-frame-pointer -std=gnu++17 -Wall -frtti"
      ;;
    sanitizer)
      cmake_type="Debug"
      local san="-fsanitize=address,undefined -fsanitize-recover=address,undefined"
      local cov="-fprofile-instr-generate -fcoverage-mapping"
      c_flags="-g -O1 -fno-omit-frame-pointer $san $cov"
      cxx_flags="$c_flags -frtti"
      tool_flags="-g -O1 -fno-omit-frame-pointer $san $cov -std=gnu++17 -Wall -frtti"
      ;;
  esac

  banner "Building [$config]"
  echo "  Flags: $c_flags"

  # -- cmake + make --
  mkdir -p "$build_dir"
  rm -rf "$build_dir/CMakeCache.txt" "$build_dir/CMakeFiles"

  cd "$build_dir"
  cmake "$ICCDEV_DIR/Build/Cmake/" \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_BUILD_TYPE="$cmake_type" \
    -DCMAKE_C_FLAGS="$c_flags" \
    -DCMAKE_CXX_FLAGS="$cxx_flags" \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
    -DENABLE_STATIC_LIBS=ON \
    -DENABLE_SHARED_LIBS=ON \
    -DENABLE_TOOLS=OFF \
    -Wno-dev 2>&1 | tail -3

  make -j"$NPROC" IccProfLib2-static IccXML2-static 2>&1 | tail -3

  local lib_prof="$build_dir/IccProfLib/libIccProfLib2-static.a"
  local lib_xml="$build_dir/IccXML/libIccXML2-static.a"

  echo ""
  echo "  Libraries:"
  ls -lh "$lib_prof" "$lib_xml" | awk '{print "    "$0}'

  # Verify instrumentation for sanitizer config
  if [ "$config" = "sanitizer" ]; then
    local asan_sym ubsan_sym cov_sym
    asan_sym=$( nm "$lib_prof" | grep -c '__asan' || true )
    ubsan_sym=$( nm "$lib_prof" | grep -c '__ubsan' || true )
    cov_sym=$(  nm "$lib_prof" | grep -c '__profc_\|__llvm_prf' || true )
    echo ""
    echo "  Instrumentation:"
    echo "    ASan:     $asan_sym symbols"
    echo "    UBSan:    $ubsan_sym symbols"
    echo "    Coverage: $cov_sym symbols"

    if [ "$asan_sym" -eq 0 ] || [ "$ubsan_sym" -eq 0 ] || [ "$cov_sym" -eq 0 ]; then
      echo "  [FAIL] Missing instrumentation — aborting"
      exit 1
    fi
  fi

  # -- Link tools --
  mkdir -p "$out_dir"
  cd "$REPO_ROOT"

  for i in "${!TOOL_SOURCES[@]}"; do
    local src="${TOOL_SOURCES[$i]}.cpp"
    local bin="${TOOL_BINS[$i]}"

    if [ ! -f "$src" ]; then
      echo "  [SKIP] $bin ($src not found)"
      continue
    fi

    echo "  Building $bin..."
    $CXX $tool_flags $INCLUDE_FLAGS "$src" \
      "$lib_prof" "$lib_xml" \
      $LINK_LIBS \
      -o "$out_dir/$bin"
    chmod +x "$out_dir/$bin"
    echo "    [OK] $(ls -lh "$out_dir/$bin" | awk '{print $5}') → $out_dir/$bin"
  done

  # Symlink as default if this is the only config being built,
  # or always for sanitizer when building all configs
  local create_symlink=false
  if [ "${#CONFIGS_TO_BUILD[@]}" -eq 1 ]; then
    create_symlink=true
  elif [ "$config" = "sanitizer" ]; then
    create_symlink=true
  fi

  if [ "$create_symlink" = true ]; then
    for bin in "${TOOL_BINS[@]}"; do
      ln -sf "bin/$config/$bin" "$REPO_ROOT/$bin"
    done
    echo "  Symlinked $config → ./iccToXml_unsafe, ./iccFromXml_unsafe"
  fi
}

# ─────────────────────────────────────────────────────
# Build each requested configuration
# ─────────────────────────────────────────────────────
for cfg in "${CONFIGS_TO_BUILD[@]}"; do
  build_config "$cfg"
done

# ─────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────
banner "Build Summary"

for cfg in release debug sanitizer; do
  d="$BIN_DIR/$cfg"
  if [ -d "$d" ]; then
    echo ""
    echo "  [$cfg]"
    ls -lh "$d"/icc* 2>/dev/null | awk '{print "    "$0}'
    sha256sum "$d"/icc* 2>/dev/null | awk '{print "    "$0}'
  fi
done

echo ""
echo "Usage:"
echo "  # Release (fastest, no diagnostics)"
echo "  bin/release/iccToXml_unsafe input.icc output.xml"
echo ""
echo "  # Debug (symbols, assertions, no sanitizers)"
echo "  bin/debug/iccToXml_unsafe input.icc output.xml"
echo ""
echo "  # Sanitizer (ASan+UBSan recoverable + coverage)"
echo "  LLVM_PROFILE_FILE=/tmp/colorbleed-%m.profraw \\"
echo "    bin/sanitizer/iccToXml_unsafe input.icc output.xml"
echo ""
echo "  # Default symlinks point to sanitizer build"
echo "  ./iccToXml_unsafe input.icc output.xml"
echo ""
echo "ColorBleed Tooling: Unsafe Load & Store for ICC Profiles"
echo "Copyright (c) 2021-2026 David H Hoyt LLC"
echo ""
echo "[OK] Build complete"
