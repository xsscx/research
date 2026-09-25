#!/bin/bash
# Build iccDEV's non-wxWidgets dependencies with AFL and one sanitizer mode.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="${AFL_THIRD_PARTY_SOURCE_DIR:-$ROOT/sources}"
BUILD_DIR="${AFL_THIRD_PARTY_BUILD_DIR:-$ROOT/build}"
PREFIX="${AFL_THIRD_PARTY_PREFIX:-$ROOT/install}"
JOBS="${AFL_THIRD_PARTY_JOBS:-$(nproc)}"
CLEAN=0
unset AFL_THIRD_PARTY_PREFIX AFL_THIRD_PARTY_SOURCE_DIR AFL_THIRD_PARTY_BUILD_DIR AFL_THIRD_PARTY_JOBS

# shellcheck source=versions.sh
source "$ROOT/versions.sh"

if [[ "${1:-}" == "--clean" ]]; then
    CLEAN=1
elif [[ $# -gt 0 ]]; then
    echo "Usage: $0 [--clean]" >&2
    exit 2
fi

CC_BIN="${CC:-clang-21}"
CXX_BIN="${CXX:-clang++-21}"
AR_BIN="${AR:-llvm-ar-21}"
RANLIB_BIN="${RANLIB:-llvm-ranlib-21}"
NM_BIN="${NM:-llvm-nm-21}"
SANITIZER_MODE="${AFL_THIRD_PARTY_SANITIZER:-address}"
unset AFL_THIRD_PARTY_SANITIZER
case "$SANITIZER_MODE" in
    address)
        SANITIZERS="address,undefined,integer,float-divide-by-zero,float-cast-overflow"
        SAN_FLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=$SANITIZERS -fno-sanitize-recover=undefined,integer,float-divide-by-zero,float-cast-overflow -fsanitize-ignorelist=$ROOT/ubsan-ignorelist.txt"
        SAN_SYMBOLS=('__asan_' '__ubsan_handle_')
        ;;
    memory)
        SANITIZERS="memory"
        SAN_FLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=memory -fsanitize-memory-track-origins=2"
        SAN_SYMBOLS=('__msan_')
        ;;
    thread)
        SANITIZERS="thread"
        SAN_FLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=thread"
        SAN_SYMBOLS=('__tsan_')
        ;;
    *)
        echo "[FAIL] Unsupported AFL third-party sanitizer: $SANITIZER_MODE" >&2
        exit 1
        ;;
esac
CXX_SAN_FLAGS="$SAN_FLAGS"
LINK_SAN_FLAGS="-fsanitize=$SANITIZERS"

for tool in "$CC_BIN" "$CXX_BIN" "$AR_BIN" "$RANLIB_BIN" "$NM_BIN" cmake git; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[FAIL] Required third-party build tool not found: $tool" >&2
        exit 1
    fi
done

if [[ "$CLEAN" == "1" ]]; then
    rm -rf "$BUILD_DIR" "$PREFIX"
fi
mkdir -p "$SOURCE_DIR" "$BUILD_DIR" "$PREFIX"

fetch_source() {
    local name="$1"
    local url="$2"
    local version="$3"
    local commit="$4"
    local source="$SOURCE_DIR/$name"

    if [[ ! -d "$source/.git" ]]; then
        echo "[*] Fetching $name $version"
        git clone --depth 1 --branch "$version" "$url" "$source"
    fi

    local actual
    actual="$(git -C "$source" rev-parse HEAD)"
    if [[ "$actual" != "$commit" ]]; then
        echo "[FAIL] $name source is $actual; expected $commit ($version)" >&2
        echo "       Remove $source and rerun to fetch the pinned release." >&2
        exit 1
    fi
}

fetch_llvm_runtimes() {
    local source="$SOURCE_DIR/llvm-project"

    if [[ ! -d "$source/.git" ]]; then
        echo "[*] Fetching llvm-project $LLVM_PROJECT_VERSION runtime sources"
        git clone --depth 1 --filter=blob:none --sparse \
            --branch "$LLVM_PROJECT_VERSION" \
            https://github.com/llvm/llvm-project.git "$source"
        git -C "$source" sparse-checkout set \
            cmake libc libcxx libcxxabi libunwind llvm/cmake \
            llvm/utils/llvm-lit runtimes
    fi

    local actual
    actual="$(git -C "$source" rev-parse HEAD)"
    if [[ "$actual" != "$LLVM_PROJECT_COMMIT" ]]; then
        echo "[FAIL] llvm-project source is $actual; expected $LLVM_PROJECT_COMMIT ($LLVM_PROJECT_VERSION)" >&2
        echo "       Remove $source and rerun to fetch the pinned release." >&2
        exit 1
    fi
}

build_msan_libcxx() {
    local source="$SOURCE_DIR/llvm-project"
    local build="$BUILD_DIR/llvm-runtimes"
    local backend_cc
    local backend_cxx
    local ar_bin
    local ranlib_bin

    backend_cc="$(command -v "${AFL_CC:-clang-21}")"
    backend_cxx="$(command -v "${AFL_CXX:-clang++-21}")"
    ar_bin="$(command -v "$AR_BIN")"
    ranlib_bin="$(command -v "$RANLIB_BIN")"

    echo "[*] Configuring MemorySanitizer-instrumented libc++"
    cmake -G Ninja -S "$source/runtimes" -B "$build" \
        -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" \
        -DLLVM_USE_SANITIZER=MemoryWithOrigins \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_C_COMPILER="$backend_cc" \
        -DCMAKE_CXX_COMPILER="$backend_cxx" \
        -DCMAKE_AR="$ar_bin" \
        -DCMAKE_RANLIB="$ranlib_bin" \
        -DLIBCXX_ENABLE_SHARED=OFF \
        -DLIBCXX_ENABLE_STATIC=ON \
        -DLIBCXX_INCLUDE_TESTS=OFF \
        -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
        -DLIBCXXABI_ENABLE_SHARED=OFF \
        -DLIBCXXABI_ENABLE_STATIC=ON \
        -DLIBCXXABI_INCLUDE_TESTS=OFF \
        -DLIBCXXABI_USE_LLVM_UNWINDER=OFF \
        -DLIBCXX_STATICALLY_LINK_ABI_IN_STATIC_LIBRARY=ON
    cmake --build "$build" --parallel "$JOBS" --target cxx cxxabi cxx_experimental
    cmake --install "$build" --component cxx
    cmake --install "$build" --component cxxabi
    cmake --install "$build" --component cxx-headers
    cmake --install "$build" --component cxxabi-headers

    if [[ ! -f "$PREFIX/lib/libc++.a" ||
          ! -f "$PREFIX/include/c++/v1/__config" ]]; then
        echo "[FAIL] Instrumented libc++ installation is incomplete: $PREFIX" >&2
        exit 1
    fi
    "$NM_BIN" "$PREFIX/lib/libc++.a" > "$build/libc++.symbols"
    if ! grep -q '__msan_' "$build/libc++.symbols"; then
        echo "[FAIL] Missing MemorySanitizer instrumentation in $PREFIX/lib/libc++.a" >&2
        exit 1
    fi
    echo "[OK] MemorySanitizer-instrumented libc++: $PREFIX/lib/libc++.a"
}

configure_build_install() {
    local name="$1"
    shift
    local source="$SOURCE_DIR/$name"
    local build="$BUILD_DIR/$name"
    local cache="$build/CMakeCache.txt"
    local requested_cc
    local requested_cxx
    local cached_cc=""
    local cached_cxx=""
    local cached_prefix=""

    requested_cc="$(command -v "$CC_BIN")"
    requested_cxx="$(command -v "$CXX_BIN")"
    if [[ -f "$cache" ]]; then
        cached_cc="$(sed -n 's/^CMAKE_C_COMPILER:[^=]*=//p' "$cache" | head -n 1)"
        cached_cxx="$(sed -n 's/^CMAKE_CXX_COMPILER:[^=]*=//p' "$cache" | head -n 1)"
        cached_prefix="$(sed -n 's/^CMAKE_INSTALL_PREFIX:[^=]*=//p' "$cache" | head -n 1)"
        if [[ "$cached_prefix" != "$PREFIX" ||
              ( -n "$cached_cc" && "$cached_cc" != "$requested_cc" ) ||
              ( -n "$cached_cxx" && "$cached_cxx" != "$requested_cxx" ) ]]; then
            echo "[*] Resetting stale $name CMake cache"
            rm -rf "$build"
        fi
    fi

    echo "[*] Configuring $name"
    cmake -S "$source" -B "$build" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_PREFIX_PATH="$PREFIX" \
        -DCMAKE_C_COMPILER="$CC_BIN" \
        -DCMAKE_CXX_COMPILER="$CXX_BIN" \
        -DCMAKE_AR="$AR_BIN" \
        -DCMAKE_RANLIB="$RANLIB_BIN" \
        -DCMAKE_NM="$NM_BIN" \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_C_FLAGS="$SAN_FLAGS" \
        -DCMAKE_CXX_FLAGS="$CXX_SAN_FLAGS" \
        -DCMAKE_EXE_LINKER_FLAGS="$LINK_SAN_FLAGS" \
        -DCMAKE_SHARED_LINKER_FLAGS="$LINK_SAN_FLAGS" \
        -DBUILD_SHARED_LIBS=OFF \
        "$@"
    echo "[*] Building $name"
    cmake --build "$build" --parallel "$JOBS"
    cmake --install "$build"
}

fetch_source zlib https://github.com/madler/zlib.git "$ZLIB_VERSION" "$ZLIB_COMMIT"
fetch_source libpng https://github.com/pnggroup/libpng.git "$LIBPNG_VERSION" "$LIBPNG_COMMIT"
fetch_source libjpeg-turbo https://github.com/libjpeg-turbo/libjpeg-turbo.git "$LIBJPEG_TURBO_VERSION" "$LIBJPEG_TURBO_COMMIT"
fetch_source libtiff https://gitlab.com/libtiff/libtiff.git "$LIBTIFF_VERSION" "$LIBTIFF_COMMIT"
fetch_source libxml2 https://gitlab.gnome.org/GNOME/libxml2.git "$LIBXML2_VERSION" "$LIBXML2_COMMIT"
fetch_source nlohmann-json https://github.com/nlohmann/json.git "$NLOHMANN_JSON_VERSION" "$NLOHMANN_JSON_COMMIT"

if [[ "$SANITIZER_MODE" == "memory" ]]; then
    if ! command -v ninja >/dev/null 2>&1; then
        echo "[FAIL] Ninja is required to build the MSan libc++ runtime" >&2
        exit 1
    fi
    fetch_llvm_runtimes
    build_msan_libcxx
    CXX_SAN_FLAGS+=" -stdlib=libc++ -nostdinc++ -isystem $PREFIX/include/c++/v1"
    LINK_SAN_FLAGS+=" -stdlib=libc++ -L$PREFIX/lib"
fi

configure_build_install zlib \
    -DZLIB_BUILD_SHARED=OFF \
    -DZLIB_BUILD_STATIC=ON \
    -DZLIB_BUILD_TESTING=OFF

configure_build_install libjpeg-turbo \
    -DENABLE_SHARED=OFF \
    -DENABLE_STATIC=ON \
    -DWITH_SIMD=OFF \
    -DWITH_TOOLS=OFF \
    -DWITH_TESTS=OFF \
    -DWITH_TURBOJPEG=OFF

configure_build_install libpng \
    -DPNG_SHARED=OFF \
    -DPNG_STATIC=ON \
    -DPNG_TESTS=OFF \
    -DPNG_TOOLS=OFF \
    -DZLIB_ROOT="$PREFIX" \
    -DZLIB_INCLUDE_DIR="$PREFIX/include" \
    -DZLIB_LIBRARY="$PREFIX/lib/libz.a"

configure_build_install libtiff \
    -Dtiff-tools=OFF \
    -Dtiff-tests=OFF \
    -Dtiff-contrib=OFF \
    -Dtiff-docs=OFF \
    -Djpeg=ON \
    -Dzlib=ON \
    -Dlerc=OFF \
    -Dlibdeflate=OFF \
    -Dlzma=OFF \
    -Djbig=OFF \
    -Dwebp=OFF \
    -Dzstd=OFF \
    -DJPEG_INCLUDE_DIR="$PREFIX/include" \
    -DJPEG_LIBRARY="$PREFIX/lib/libjpeg.a" \
    -DZLIB_ROOT="$PREFIX" \
    -DZLIB_INCLUDE_DIR="$PREFIX/include" \
    -DZLIB_LIBRARY="$PREFIX/lib/libz.a"

configure_build_install libxml2 \
    -DLIBXML2_WITH_C14N=OFF \
    -DLIBXML2_WITH_CATALOG=OFF \
    -DLIBXML2_WITH_DEBUG=OFF \
    -DLIBXML2_WITH_FTP=OFF \
    -DLIBXML2_WITH_HTML=OFF \
    -DLIBXML2_WITH_HTTP=OFF \
    -DLIBXML2_WITH_ICONV=OFF \
    -DLIBXML2_WITH_LZMA=OFF \
    -DLIBXML2_WITH_MODULES=OFF \
    -DLIBXML2_WITH_PROGRAMS=OFF \
    -DLIBXML2_WITH_PYTHON=OFF \
    -DLIBXML2_WITH_READER=ON \
    -DLIBXML2_WITH_PATTERN=ON \
    -DLIBXML2_WITH_REGEXPS=ON \
    -DLIBXML2_WITH_RELAXNG=ON \
    -DLIBXML2_WITH_SAX1=ON \
    -DLIBXML2_WITH_SCHEMAS=ON \
    -DLIBXML2_WITH_SCHEMATRON=OFF \
    -DLIBXML2_WITH_TESTS=OFF \
    -DLIBXML2_WITH_THREADS=ON \
    -DLIBXML2_WITH_VALID=OFF \
    -DLIBXML2_WITH_WRITER=ON \
    -DLIBXML2_WITH_XINCLUDE=OFF \
    -DLIBXML2_WITH_XPATH=OFF \
    -DLIBXML2_WITH_XPTR=OFF \
    -DLIBXML2_WITH_ZLIB=OFF

configure_build_install nlohmann-json \
    -DJSON_BuildTests=OFF \
    -DJSON_Install=ON \
    -DJSON_MultipleHeaders=ON

for archive in libz.a libjpeg.a libpng.a libtiff.a libxml2.a; do
    symbol_file="$BUILD_DIR/$archive.symbols"
    "$NM_BIN" "$PREFIX/lib/$archive" > "$symbol_file"
    for sanitizer_symbol in "${SAN_SYMBOLS[@]}"; do
        if ! grep -q "$sanitizer_symbol" "$symbol_file"; then
            echo "[FAIL] Missing $SANITIZER_MODE sanitizer instrumentation in $PREFIX/lib/$archive" >&2
            exit 1
        fi
    done
    if [[ "$CC_BIN" == *afl* ]] && ! grep -q '__afl_' "$symbol_file"; then
        echo "[FAIL] Missing AFL instrumentation in $PREFIX/lib/$archive" >&2
        exit 1
    fi
    echo "[OK] Instrumented archive: $archive"
done

echo ""
echo "[OK] AFL/sanitizer third-party prefix: $PREFIX"
echo "     Sanitizer: $SANITIZER_MODE ($SANITIZERS)"
