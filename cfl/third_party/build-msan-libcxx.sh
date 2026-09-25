#!/usr/bin/env bash
# Build the instrumented C++ standard library required by MemorySanitizer.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/sources"
BUILD_DIR="$SCRIPT_DIR/build-msan-libcxx"
PREFIX="$SCRIPT_DIR/install-msan-libcxx"
LLVM_VERSION="llvmorg-22.1.2"
LLVM_COMMIT="1ab49a973e210e97d61e5db6557180dcb92c3e98"
CC_BIN="${CC:-clang-22}"
CXX_BIN="${CXX:-clang++-22}"
JOBS="${CFL_BUILD_JOBS:-$(nproc 2>/dev/null || echo 4)}"
SOURCE="$SOURCE_DIR/llvm-project"
FUZZER_BUILD_DIR="$BUILD_DIR/libfuzzer"
FUZZER_ARCHIVE="$PREFIX/lib/libclang_rt.fuzzer.a"

for tool in "$CC_BIN" "$CXX_BIN" ar cmake git ninja; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[FAIL] ERROR: $tool is required to build the MSan libc++ runtime" >&2
    exit 1
  fi
done

compiler_major="$($CXX_BIN --version | sed -n '1s/.*version \([0-9][0-9]*\).*/\1/p')"
if [[ "$compiler_major" != "22" ]]; then
  echo "[FAIL] ERROR: the pinned MSan libc++ runtime requires Clang 22; found $($CXX_BIN --version | head -1)" >&2
  exit 1
fi

mkdir -p "$SOURCE_DIR"
if [[ ! -d "$SOURCE/.git" ]]; then
  echo "[*] Fetching llvm-project $LLVM_VERSION runtime sources"
  git clone --depth 1 --filter=blob:none --sparse --branch "$LLVM_VERSION" \
    https://github.com/llvm/llvm-project.git "$SOURCE"
fi
git -C "$SOURCE" sparse-checkout set \
  cmake compiler-rt/lib/fuzzer libc libcxx libcxxabi libunwind llvm/cmake \
  llvm/utils/llvm-lit runtimes

actual_commit="$(git -C "$SOURCE" rev-parse HEAD)"
if [[ "$actual_commit" != "$LLVM_COMMIT" ]]; then
  echo "[FAIL] ERROR: llvm-project source is $actual_commit; expected $LLVM_COMMIT ($LLVM_VERSION)" >&2
  echo "       Remove $SOURCE and rerun to fetch the pinned release." >&2
  exit 1
fi

if [[ ! -f "$PREFIX/lib/libc++.a" || ! -f "$PREFIX/include/c++/v1/__config" ]] ||
   ! grep -a -q '__msan_' "$PREFIX/lib/libc++.a"; then
  echo "[*] Configuring MemorySanitizer-instrumented libc++"
  cmake -G Ninja -S "$SOURCE/runtimes" -B "$BUILD_DIR" \
    -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" \
    -DLLVM_USE_SANITIZER=MemoryWithOrigins \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_C_COMPILER="$CC_BIN" \
    -DCMAKE_CXX_COMPILER="$CXX_BIN" \
    -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBCXX_ENABLE_STATIC=ON \
    -DLIBCXX_INCLUDE_TESTS=OFF \
    -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
    -DLIBCXXABI_ENABLE_SHARED=OFF \
    -DLIBCXXABI_ENABLE_STATIC=ON \
    -DLIBCXXABI_INCLUDE_TESTS=OFF \
    -DLIBCXXABI_USE_LLVM_UNWINDER=OFF \
    -DLIBCXX_STATICALLY_LINK_ABI_IN_STATIC_LIBRARY=ON
  cmake --build "$BUILD_DIR" --parallel "$JOBS" --target cxx cxxabi cxx_experimental
  cmake --install "$BUILD_DIR" --component cxx
  cmake --install "$BUILD_DIR" --component cxxabi
  cmake --install "$BUILD_DIR" --component cxx-headers
  cmake --install "$BUILD_DIR" --component cxxabi-headers
fi

if [[ ! -f "$PREFIX/lib/libc++.a" || ! -f "$PREFIX/include/c++/v1/__config" ]]; then
  echo "[FAIL] ERROR: instrumented libc++ installation is incomplete: $PREFIX" >&2
  exit 1
fi
if ! grep -a -q '__msan_' "$PREFIX/lib/libc++.a"; then
  echo "[FAIL] ERROR: MemorySanitizer instrumentation is missing from $PREFIX/lib/libc++.a" >&2
  exit 1
fi

echo "[OK] MemorySanitizer-instrumented libc++: $PREFIX/lib/libc++.a"

if [[ ! -f "$FUZZER_ARCHIVE" ]] || ! grep -a -q '__msan_' "$FUZZER_ARCHIVE"; then
  fuzzer_source="$SOURCE/compiler-rt/lib/fuzzer"
  fuzzer_sources=(
    FuzzerCrossOver.cpp FuzzerDataFlowTrace.cpp FuzzerDriver.cpp
    FuzzerExtFunctionsDlsym.cpp FuzzerExtFunctionsWeak.cpp
    FuzzerExtFunctionsWindows.cpp FuzzerExtraCounters.cpp
    FuzzerExtraCountersDarwin.cpp FuzzerExtraCountersWindows.cpp FuzzerFork.cpp
    FuzzerIO.cpp FuzzerIOPosix.cpp FuzzerIOWindows.cpp FuzzerLoop.cpp
    FuzzerMain.cpp FuzzerMerge.cpp FuzzerMutate.cpp FuzzerSHA1.cpp
    FuzzerTracePC.cpp FuzzerUtil.cpp FuzzerUtilDarwin.cpp FuzzerUtilFuchsia.cpp
    FuzzerUtilLinux.cpp FuzzerUtilPosix.cpp FuzzerUtilWindows.cpp
  )
  echo "[*] Building MemorySanitizer-instrumented LibFuzzer"
  rm -rf "$FUZZER_BUILD_DIR"
  mkdir -p "$FUZZER_BUILD_DIR" "$PREFIX/lib"
  for source_name in "${fuzzer_sources[@]}"; do
    "$CXX_BIN" -g -O2 -fno-omit-frame-pointer \
      -fsanitize=memory -fsanitize-memory-track-origins=2 \
      -nostdinc++ -isystem "$PREFIX/include/c++/v1" \
      -I"$SOURCE/compiler-rt/include" -I"$fuzzer_source" \
      -c "$fuzzer_source/$source_name" \
      -o "$FUZZER_BUILD_DIR/${source_name%.cpp}.o"
  done
  ar rcs "$FUZZER_ARCHIVE" "$FUZZER_BUILD_DIR"/*.o
fi
if ! grep -a -q '__msan_' "$FUZZER_ARCHIVE"; then
  echo "[FAIL] ERROR: MemorySanitizer instrumentation is missing from $FUZZER_ARCHIVE" >&2
  exit 1
fi
echo "[OK] MemorySanitizer-instrumented LibFuzzer: $FUZZER_ARCHIVE"
