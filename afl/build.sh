#!/bin/bash
# afl/build.sh - Build iccDEV with AFL++ and selectable sanitizer instrumentation
#
# Usage: ./afl/build.sh [--clean] [--sanitizer MODE] [--refresh-iccdev]
#
# MODE is address (default), memory, or thread. Each mode uses separate build,
# binary, and third-party dependency directories unless explicitly overridden.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$REPO_ROOT/afl"
AFL_BASE="${AFL_BASE:-$SCRIPT_DIR}"
ICCDEV_DIR="$SCRIPT_DIR/iccDEV"
CMAKE_DIR="$ICCDEV_DIR/Build/Cmake"
THIRD_PARTY_DIR="$SCRIPT_DIR/third_party"
JOBS=$(nproc)
PATCH_DIR="$SCRIPT_DIR/patches"
WITH_PATCHES="${AFL_WITH_PATCHES:-0}"
REFRESH_ICCDEV="${AFL_REFRESH_ICCDEV:-0}"
KEEP_ICCDEV="${AFL_KEEP_ICCDEV:-0}"
ICCDEV_BRANCH="${AFL_ICCDEV_BRANCH:-}"
AFL_CMPLOG_BUILD=0
AFL_LAF_BUILD=0
AFL_CTX_BUILD=0
AFL_NGRAM_SIZE_VAL="${AFL_NGRAM_SIZE:-}"
AFL_LINK_MODE="${AFL_LINK_MODE:-static}"
AFL_UBSAN_IGNORELIST="${AFL_UBSAN_IGNORELIST:-.github/ci/ubsan-ignorelist.txt}"
AFL_REQUIRED_VERSION="5.03a"
CLEAN_THIRD_PARTY=0
SANITIZER_MODE="${AFL_SANITIZER:-address}"

# shellcheck source=afl/sanitizer-env.sh
source "$SCRIPT_DIR/sanitizer-env.sh"

usage() {
    sed -n '2,8p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  --clean           remove Build-AFL before building"
    echo "  --clean-third-party rebuild all AFL-instrumented dependencies"
    echo "  --sanitizer MODE build with address (default), memory, or thread sanitizer"
    echo "  --with-patches    apply local patches from afl/patches"
    echo "  --branch NAME     use iccDEV branch NAME; existing checkout stays local-only"
    echo "  --refresh-iccdev  fetch selected branch or origin/master and reset the nested checkout"
    echo "  --keep-iccdev     preserve current afl/iccDEV source edits"
    echo "  --cmplog          build CMPLOG-instrumented tools"
    echo "  --laf             build with LAF compare splitting"
    echo "  --ctx             build with context-sensitive coverage"
    echo "  --ngram N         build with AFL_LLVM_NGRAM_SIZE=N"
    echo "  --static          link iccDEV libraries statically (default)"
    echo "  --shared          link/deploy iccDEV shared libraries"
    echo ""
    echo "Environment:"
    echo "  AFL_BUILD_DIR     override build directory"
    echo "  AFL_BIN_DIR       override deployed binary directory"
    echo "  AFL_THIRD_PARTY_PREFIX override the dependency install prefix"
    echo "  AFL_SANITIZER     default --sanitizer value"
    echo "  AFL_ICCDEV_BRANCH default --branch value"
    echo "  AFL_CLANG_FAST    override the afl-clang-fast wrapper path"
    echo "  AFL_CLANG_FASTXX  override the afl-clang-fast++ wrapper path"
}

CLEAN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean|clean)
            CLEAN=1
            shift
            ;;
        --clean-third-party)
            CLEAN_THIRD_PARTY=1
            shift
            ;;
        --sanitizer)
            if [[ $# -lt 2 || "$2" == --* ]]; then
                echo "ERROR: --sanitizer requires address, memory, or thread"
                exit 1
            fi
            SANITIZER_MODE="$2"
            shift 2
            ;;
        --with-patches)
            WITH_PATCHES=1
            shift
            ;;
        --branch)
            if [[ $# -lt 2 || "$2" == --* ]]; then
                echo "ERROR: --branch requires a branch name"
                exit 1
            fi
            ICCDEV_BRANCH="$2"
            shift 2
            ;;
        --refresh-iccdev)
            REFRESH_ICCDEV=1
            shift
            ;;
        --keep-iccdev)
            KEEP_ICCDEV=1
            shift
            ;;
        --cmplog)
            AFL_CMPLOG_BUILD=1
            shift
            ;;
        --laf)
            AFL_LAF_BUILD=1
            shift
            ;;
        --ctx)
            AFL_CTX_BUILD=1
            shift
            ;;
        --ngram)
            if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: --ngram requires a numeric size"
                exit 1
            fi
            AFL_NGRAM_SIZE_VAL="$2"
            shift 2
            ;;
        --static)
            AFL_LINK_MODE=static
            shift
            ;;
        --shared)
            AFL_LINK_MODE=shared
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

REQUESTED_SANITIZER_MODE="$SANITIZER_MODE"
if ! SANITIZER_MODE="$(afl_normalize_sanitizer_mode "$REQUESTED_SANITIZER_MODE")"; then
    echo "ERROR: unsupported sanitizer '$REQUESTED_SANITIZER_MODE' (use address, memory, or thread)" >&2
    exit 1
fi

case "$SANITIZER_MODE" in
    address)
        BUILD_SUFFIX=""
        BIN_SUFFIX=""
        THIRD_PARTY_SUFFIX=""
        ;;
    memory)
        BUILD_SUFFIX="-MSan"
        BIN_SUFFIX="-msan"
        THIRD_PARTY_SUFFIX="-msan"
        ;;
    thread)
        BUILD_SUFFIX="-TSan"
        BIN_SUFFIX="-tsan"
        THIRD_PARTY_SUFFIX="-tsan"
        ;;
esac
BUILD_DIR="${AFL_BUILD_DIR:-$ICCDEV_DIR/Build-AFL$BUILD_SUFFIX}"
BIN_DIR="${AFL_BIN_DIR:-$SCRIPT_DIR/bin$BIN_SUFFIX}"
THIRD_PARTY_PREFIX="${AFL_THIRD_PARTY_PREFIX:-$THIRD_PARTY_DIR/install$THIRD_PARTY_SUFFIX}"
THIRD_PARTY_BUILD_DIR="${AFL_THIRD_PARTY_BUILD_DIR:-$THIRD_PARTY_DIR/build$THIRD_PARTY_SUFFIX}"

if [[ "$REFRESH_ICCDEV" = "1" && "$KEEP_ICCDEV" = "1" ]]; then
    echo "ERROR: --refresh-iccdev and --keep-iccdev are mutually exclusive"
    exit 1
fi
if [[ -n "$ICCDEV_BRANCH" && "$ICCDEV_BRANCH" == -* ]]; then
    echo "ERROR: invalid branch name: $ICCDEV_BRANCH"
    exit 1
fi
if [[ "$AFL_CTX_BUILD" = "1" && -n "$AFL_NGRAM_SIZE_VAL" ]]; then
    echo "ERROR: --ctx and --ngram are alternative coverage modes"
    exit 1
fi
if [[ "$AFL_LINK_MODE" != "static" && "$AFL_LINK_MODE" != "shared" ]]; then
    echo "ERROR: AFL_LINK_MODE must be static or shared"
    exit 1
fi
if [[ "$WITH_PATCHES" != "0" && "$WITH_PATCHES" != "1" ]]; then
    echo "ERROR: AFL_WITH_PATCHES must be 0 or 1"
    exit 1
fi

checkout_local_iccdev_branch() {
    local branch="$1"

    if [[ -z "$branch" ]]; then
        return
    fi

    if git -C "$ICCDEV_DIR" show-ref --verify --quiet "refs/heads/$branch"; then
        git -C "$ICCDEV_DIR" checkout "$branch"
    elif git -C "$ICCDEV_DIR" show-ref --verify --quiet "refs/remotes/origin/$branch"; then
        git -C "$ICCDEV_DIR" checkout -B "$branch" "origin/$branch"
    else
        echo "ERROR: branch not found locally: $branch"
        echo "       Use --refresh-iccdev only when remote access is intended."
        exit 1
    fi
}

first_tool() {
    local tool
    for tool in "$@"; do
        if command -v "$tool" >/dev/null 2>&1; then
            command -v "$tool"
            return 0
        fi
    done
    return 1
}

afl_wrappers_compile() {
    local wrapper="$1"
    local wrapperxx="$2"
    local cc_backend="$3"
    local cxx_backend="$4"
    local tmp_root="${AFL_TMP_ROOT:-$AFL_BASE/tmp}"
    local test_dir

    mkdir -p "$tmp_root"
    test_dir="$(mktemp -d "$tmp_root/afl-wrapper-test.XXXXXX")"
    printf 'int main(void) { return 0; }\n' > "$test_dir/test.c"
    printf 'int main(void) { return 0; }\n' > "$test_dir/test.cpp"
    AFL_CC="$cc_backend" AFL_CXX="$cxx_backend" "$wrapper" -c "$test_dir/test.c" -o "$test_dir/test.o" >/dev/null 2>&1 || {
        rm -rf "$test_dir"
        return 1
    }
    AFL_CC="$cc_backend" AFL_CXX="$cxx_backend" "$wrapperxx" -c "$test_dir/test.cpp" -o "$test_dir/testxx.o" >/dev/null 2>&1 || {
        rm -rf "$test_dir"
        return 1
    }
    rm -rf "$test_dir"
    return 0
}

afl_wrapper_has_required_version() {
    local wrapper="$1"
    local banner

    banner="$("$wrapper" -h 2>&1 | head -n 1 || true)"
    [[ "$banner" == *"afl-cc++${AFL_REQUIRED_VERSION}"* ]]
}

select_afl_wrappers() {
    local cc_backend="$1"
    local cxx_backend="$2"
    local wrapper
    local wrapperxx
    local seen=" "
    local candidates=()

    if [[ -n "${AFL_CLANG_FAST:-}" ]]; then
        candidates+=("$AFL_CLANG_FAST")
    fi
    for wrapper in "$HOME"/work/copilot/tools/aflplusplus-llvm21-*/afl-clang-fast \
        "$HOME"/work/copilot/tools/aflplusplus-llvm21/afl-clang-fast; do
        [[ -e "$wrapper" ]] && candidates+=("$wrapper")
    done
    if command -v afl-clang-fast >/dev/null 2>&1; then
        candidates+=("$(command -v afl-clang-fast)")
    fi
    candidates+=("/usr/bin/afl-clang-fast" "/usr/local/bin/afl-clang-fast")

    for wrapper in "${candidates[@]}"; do
        [[ -n "$wrapper" && -x "$wrapper" ]] || continue
        [[ "$seen" != *" $wrapper "* ]] || continue
        seen="${seen}${wrapper} "
        if [[ -n "${AFL_CLANG_FASTXX:-}" ]]; then
            wrapperxx="$AFL_CLANG_FASTXX"
        else
            wrapperxx="${wrapper}++"
        fi
        [[ -x "$wrapperxx" ]] || continue
        if ! afl_wrapper_has_required_version "$wrapper" ||
            ! afl_wrapper_has_required_version "$wrapperxx"; then
            echo "[WARN] Skipping AFL++ wrapper that is not ${AFL_REQUIRED_VERSION}: $wrapper" >&2
            continue
        fi
        if afl_wrappers_compile "$wrapper" "$wrapperxx" "$cc_backend" "$cxx_backend"; then
            AFL_CLANG_FAST_BIN="$wrapper"
            AFL_CLANG_FASTXX_BIN="$wrapperxx"
            return 0
        fi
    done

    return 1
}

select_afl_toolchain() {
    AFL_CC_BACKEND="$(first_tool clang-21 || true)"
    AFL_CXX_BACKEND="$(first_tool clang++-21 || true)"
    if [[ -z "$AFL_CC_BACKEND" || -z "$AFL_CXX_BACKEND" ]]; then
        echo "ERROR: clang-21 and clang++-21 are required for AFL builds" >&2
        return 1
    fi
    AFL_LLVM_AR="$(first_tool llvm-ar-21 || true)"
    AFL_LLVM_RANLIB="$(first_tool llvm-ranlib-21 || true)"
    AFL_LLVM_NM="$(first_tool llvm-nm-21 || true)"
    if [[ -z "$AFL_LLVM_AR" || -z "$AFL_LLVM_RANLIB" || -z "$AFL_LLVM_NM" ]]; then
        echo "ERROR: llvm-ar-21, llvm-ranlib-21, and llvm-nm-21 are required for AFL LTO builds" >&2
        return 1
    fi

    AFL_CLANG_FAST_BIN=""
    AFL_CLANG_FASTXX_BIN=""
    select_afl_wrappers "$AFL_CC_BACKEND" "$AFL_CXX_BACKEND"
}

# Clone iccDEV if not present or incomplete. AFL tests use an isolated
# upstream checkout so the root iccDEV/ source tree stays untouched.
if [ -d "$ICCDEV_DIR/.git" ] && [ -f "$CMAKE_DIR/CMakeLists.txt" ]; then
    echo "[*] Using isolated iccDEV checkout: $(cd "$ICCDEV_DIR" && git rev-parse --short HEAD)"
elif [ ! -f "$CMAKE_DIR/CMakeLists.txt" ]; then
    echo "[*] Cloning iccDEV into afl/iccDEV (unpatched upstream for AFL)..."
    rm -rf "$ICCDEV_DIR"
    if [[ -n "$ICCDEV_BRANCH" ]]; then
        git clone --branch "$ICCDEV_BRANCH" --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git "$ICCDEV_DIR"
    else
        git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git "$ICCDEV_DIR"
    fi
fi

if [[ "$REFRESH_ICCDEV" = "1" ]]; then
    if [[ -n "$ICCDEV_BRANCH" ]]; then
        echo "[*] Refreshing AFL iccDEV checkout from origin/$ICCDEV_BRANCH..."
        git -C "$ICCDEV_DIR" fetch origin "$ICCDEV_BRANCH"
        git -C "$ICCDEV_DIR" checkout -B "$ICCDEV_BRANCH" FETCH_HEAD
        git -C "$ICCDEV_DIR" reset --hard FETCH_HEAD
    else
        echo "[*] Refreshing AFL iccDEV checkout from origin/master..."
        git -C "$ICCDEV_DIR" fetch origin master
        git -C "$ICCDEV_DIR" reset --hard FETCH_HEAD
    fi
    git -C "$ICCDEV_DIR" clean -fd
else
    checkout_local_iccdev_branch "$ICCDEV_BRANCH"
    if [[ "$KEEP_ICCDEV" != "1" ]]; then
        git -C "$ICCDEV_DIR" checkout -- . 2>/dev/null || true
    fi
fi

if [[ "$WITH_PATCHES" = "1" ]]; then
    shopt -s nullglob
    afl_patches=("$PATCH_DIR"/*.patch)
    shopt -u nullglob
    for patch_path in "${afl_patches[@]}"; do
        patch_name="$(basename "$patch_path")"
        if git -C "$ICCDEV_DIR" apply --check "$patch_path"; then
            git -C "$ICCDEV_DIR" apply "$patch_path"
            echo "[OK] Applied: $patch_name"
        elif git -C "$ICCDEV_DIR" apply --reverse --check "$patch_path" >/dev/null 2>&1; then
            echo "[OK] Already applied: $patch_name"
        else
            echo "[FAIL] Patch does not apply: $patch_name"
            exit 1
        fi
    done
else
    echo "[*] Patch application disabled for AFL build"
fi

AFL_CLANG_FAST_BIN=""
AFL_CLANG_FASTXX_BIN=""
if ! select_afl_toolchain; then
    echo "ERROR: no AFL++ ${AFL_REQUIRED_VERSION} afl-clang-fast wrapper can compile with clang-21" >&2
    echo "       Run ./afl/build-afl-runtime.sh or set AFL_CLANG_FAST/AFL_CLANG_FASTXX to AFL++ ${AFL_REQUIRED_VERSION} LLVM 21 wrappers." >&2
    exit 1
fi

echo "[*] Building AFL-instrumented third-party dependencies..."
THIRD_PARTY_ARGS=()
if [[ "$CLEAN_THIRD_PARTY" == "1" ]]; then
    THIRD_PARTY_ARGS+=(--clean)
fi
case "$SANITIZER_MODE" in
    address) AFL_SANITIZER_ENV=(AFL_USE_ASAN=1 AFL_USE_UBSAN=1) ;;
    memory) AFL_SANITIZER_ENV=(AFL_USE_MSAN=1) ;;
    thread) AFL_SANITIZER_ENV=(AFL_USE_TSAN=1) ;;
esac
env \
    -u AFL_CLANG_FAST \
    -u AFL_CLANG_FASTXX \
    AFL_CC="$AFL_CC_BACKEND" \
    AFL_CXX="$AFL_CXX_BACKEND" \
    "${AFL_SANITIZER_ENV[@]}" \
    CC="$AFL_CLANG_FAST_BIN" \
    CXX="$AFL_CLANG_FASTXX_BIN" \
    AR="$AFL_LLVM_AR" \
    RANLIB="$AFL_LLVM_RANLIB" \
    NM="$AFL_LLVM_NM" \
    AFL_THIRD_PARTY_PREFIX="$THIRD_PARTY_PREFIX" \
    AFL_THIRD_PARTY_BUILD_DIR="$THIRD_PARTY_BUILD_DIR" \
    AFL_THIRD_PARTY_SANITIZER="$SANITIZER_MODE" \
    "$THIRD_PARTY_DIR/build.sh" "${THIRD_PARTY_ARGS[@]}"

# Clean build if requested
if [[ "$CLEAN" == "1" ]]; then
    echo "[*] Cleaning Build-AFL directory..."
    rm -rf "$BUILD_DIR"
fi

echo "[*] Configuring iccDEV with AFL++ instrumentation..."
echo "    Compiler: afl-clang-fast++"
case "$SANITIZER_MODE" in
    address) SANITIZER_LABEL="ASAN + UBSAN + integer + float-divide-by-zero + float-cast-overflow" ;;
    memory) SANITIZER_LABEL="MemorySanitizer with origin tracking" ;;
    thread) SANITIZER_LABEL="ThreadSanitizer" ;;
esac
echo "    Sanitizer: $SANITIZER_LABEL"
echo "    Jobs: $JOBS"
echo "    Build dir: $BUILD_DIR"
echo "    Bin dir: $BIN_DIR"
echo "    Link mode: $AFL_LINK_MODE"
echo "    AFL backend: $AFL_CC_BACKEND / $AFL_CXX_BACKEND"
echo "    AFL wrapper: $AFL_CLANG_FAST_BIN / $AFL_CLANG_FASTXX_BIN"
echo "    AFL version: $AFL_REQUIRED_VERSION"
echo "    LLVM binutils: $AFL_LLVM_AR / $AFL_LLVM_RANLIB / $AFL_LLVM_NM"
echo "    Third-party prefix: $THIRD_PARTY_PREFIX"
if [[ -n "$ICCDEV_BRANCH" ]]; then
    echo "    Branch: $ICCDEV_BRANCH"
fi
if [[ "$AFL_CMPLOG_BUILD" = "1" || "$AFL_LAF_BUILD" = "1" || "$AFL_CTX_BUILD" = "1" || -n "$AFL_NGRAM_SIZE_VAL" ]]; then
    echo "    AFL modes: cmplog=$AFL_CMPLOG_BUILD laf=$AFL_LAF_BUILD ctx=$AFL_CTX_BUILD ngram=${AFL_NGRAM_SIZE_VAL:-off}"
fi
UBSAN_IGNORELIST_ARGS=()
if [[ "$SANITIZER_MODE" == "address" && -n "$AFL_UBSAN_IGNORELIST" ]]; then
    if [[ -f "$ICCDEV_DIR/$AFL_UBSAN_IGNORELIST" ]]; then
        UBSAN_IGNORELIST_ARGS=(-DUBSAN_IGNORELIST="$AFL_UBSAN_IGNORELIST")
        echo "    UBSAN ignorelist: $AFL_UBSAN_IGNORELIST"
    else
        echo "    UBSAN ignorelist: not found ($AFL_UBSAN_IGNORELIST)"
    fi
fi

AFL_BUILD_ENV=("${AFL_SANITIZER_ENV[@]}")
AFL_ENABLE_SHARED_LIBS="OFF"
AFL_ENABLE_SANITIZERS="OFF"
AFL_CMAKE_C_FLAGS="-g -O0"
AFL_CMAKE_CXX_FLAGS="-g -O0"
AFL_CMAKE_EXE_LINKER_FLAGS=""
if [[ "$SANITIZER_MODE" == "address" ]]; then
    AFL_ENABLE_SANITIZERS="ON"
elif [[ "$SANITIZER_MODE" == "memory" ]]; then
    AFL_CMAKE_C_FLAGS+=" -fPIE"
    AFL_CMAKE_CXX_FLAGS+=" -fPIE"
    AFL_CMAKE_EXE_LINKER_FLAGS="-pie"
fi
if [[ "$AFL_LINK_MODE" == "shared" ]]; then
    AFL_ENABLE_SHARED_LIBS="ON"
fi
if [[ "$AFL_CMPLOG_BUILD" = "1" ]]; then
    AFL_BUILD_ENV+=(AFL_LLVM_CMPLOG=1)
fi
if [[ "$AFL_LAF_BUILD" = "1" ]]; then
    AFL_BUILD_ENV+=(AFL_LLVM_LAF_ALL=1)
fi
if [[ "$AFL_CTX_BUILD" = "1" ]]; then
    AFL_BUILD_ENV+=(AFL_LLVM_CTX=1)
fi
if [[ -n "$AFL_NGRAM_SIZE_VAL" ]]; then
    AFL_BUILD_ENV+=(AFL_LLVM_NGRAM_SIZE="$AFL_NGRAM_SIZE_VAL")
fi

env -u AFL_BUILD_DIR -u AFL_BIN_DIR AFL_CC="$AFL_CC_BACKEND" AFL_CXX="$AFL_CXX_BACKEND" "${AFL_BUILD_ENV[@]}" cmake -S "$CMAKE_DIR" -B "$BUILD_DIR" \
    -DCMAKE_C_COMPILER="$AFL_CLANG_FAST_BIN" \
    -DCMAKE_CXX_COMPILER="$AFL_CLANG_FASTXX_BIN" \
    -DCMAKE_AR="$AFL_LLVM_AR" \
    -DCMAKE_RANLIB="$AFL_LLVM_RANLIB" \
    -DCMAKE_NM="$AFL_LLVM_NM" \
    -DCMAKE_C_COMPILER_AR="$AFL_LLVM_AR" \
    -DCMAKE_C_COMPILER_RANLIB="$AFL_LLVM_RANLIB" \
    -DCMAKE_CXX_COMPILER_AR="$AFL_LLVM_AR" \
    -DCMAKE_CXX_COMPILER_RANLIB="$AFL_LLVM_RANLIB" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_PREFIX_PATH="$THIRD_PARTY_PREFIX" \
    -DCMAKE_C_FLAGS="$AFL_CMAKE_C_FLAGS" \
    -DCMAKE_CXX_FLAGS="$AFL_CMAKE_CXX_FLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$AFL_CMAKE_EXE_LINKER_FLAGS" \
    -DENABLE_SANITIZERS="$AFL_ENABLE_SANITIZERS" \
    -DSANITIZER_RECOVER=OFF \
    -DENABLE_TOOLS=ON \
    -DENABLE_WXWIDGETS=OFF \
    "${UBSAN_IGNORELIST_ARGS[@]}" \
    -DENABLE_SHARED_LIBS="$AFL_ENABLE_SHARED_LIBS" \
    -DENABLE_STATIC_LIBS=ON \
    -DLibXml2_ROOT="$THIRD_PARTY_PREFIX" \
    -DLIBXML2_INCLUDE_DIR="$THIRD_PARTY_PREFIX/include/libxml2" \
    -DLIBXML2_LIBRARY="$THIRD_PARTY_PREFIX/lib/libxml2.a" \
    -Dnlohmann_json_DIR="$THIRD_PARTY_PREFIX/share/cmake/nlohmann_json" \
    -DTIFF_INCLUDE_DIR="$THIRD_PARTY_PREFIX/include" \
    -DTIFF_LIBRARY:STRING="$THIRD_PARTY_PREFIX/lib/libtiff.a;$THIRD_PARTY_PREFIX/lib/libjpeg.a;$THIRD_PARTY_PREFIX/lib/libz.a" \
    -DZLIB_ROOT="$THIRD_PARTY_PREFIX" \
    -DZLIB_INCLUDE_DIR="$THIRD_PARTY_PREFIX/include" \
    -DZLIB_LIBRARY="$THIRD_PARTY_PREFIX/lib/libz.a" \
    -DPNG_PNG_INCLUDE_DIR="$THIRD_PARTY_PREFIX/include" \
    -DPNG_LIBRARY="$THIRD_PARTY_PREFIX/lib/libpng.a" \
    -DJPEG_INCLUDE_DIR="$THIRD_PARTY_PREFIX/include" \
    -DJPEG_LIBRARY="$THIRD_PARTY_PREFIX/lib/libjpeg.a"

echo "[*] Building with $JOBS cores..."
env -u AFL_BUILD_DIR -u AFL_BIN_DIR AFL_CC="$AFL_CC_BACKEND" AFL_CXX="$AFL_CXX_BACKEND" "${AFL_BUILD_ENV[@]}" cmake --build "$BUILD_DIR" --parallel "$JOBS"

if ! grep -q "^ENABLE_SANITIZERS:BOOL=$AFL_ENABLE_SANITIZERS$" "$BUILD_DIR/CMakeCache.txt"; then
    echo "[FAIL] CMake cache sanitizer setting does not match $SANITIZER_MODE mode"
    exit 1
fi
if [[ "$SANITIZER_MODE" == "address" ]] && ! grep -q '^SANITIZER_RECOVER:BOOL=OFF$' "$BUILD_DIR/CMakeCache.txt"; then
    echo "[FAIL] CMake cache does not enforce fatal sanitizer findings"
    exit 1
fi
if grep -E '^(LIBXML2_LIBRARY|PNG_LIBRARY|TIFF_LIBRARY|JPEG_LIBRARY|ZLIB_LIBRARY):.*=/usr/' "$BUILD_DIR/CMakeCache.txt"; then
    echo "[FAIL] CMake cache selected a system third-party library"
    exit 1
fi
for dependency in libxml2.a libpng.a libtiff.a libjpeg.a libz.a; do
    if [[ ! -f "$THIRD_PARTY_PREFIX/lib/$dependency" ]]; then
        echo "[FAIL] Missing AFL third-party archive: $THIRD_PARTY_PREFIX/lib/$dependency"
        exit 1
    fi
done

echo ""
echo "[OK] AFL-instrumented iccDEV built successfully"
echo ""

# Deploy binaries to afl/bin/.
# CMake directory names use PascalCase, but binary names use camelCase.
echo "[*] Deploying to $BIN_DIR"
mkdir -p "$BIN_DIR"
find "$BIN_DIR" -mindepth 1 ! -name .gitignore -exec rm -rf {} +
DEPLOYED=0
for tool_dir in "$BUILD_DIR"/Tools/*/; do
    while IFS= read -r bin; do
        bin_name=$(basename "$bin")
        if [[ "$bin_name" == "iccDescribeSinkTest" ]]; then
            echo "  [SKIP] $bin_name (CTest helper, not an AFL target)"
            continue
        fi
        cp "$bin" "$BIN_DIR/"
        size=$(du -h "$BIN_DIR/$bin_name" | cut -f1)
        echo "  $size  $BIN_DIR/$bin_name"
        DEPLOYED=$((DEPLOYED + 1))
    done < <(find "$tool_dir" -maxdepth 1 -type f -executable 2>/dev/null)
done
echo "  $DEPLOYED tool binaries deployed"
printf '%s\n' "$SANITIZER_MODE" > "$BIN_DIR/.sanitizer-mode"

# Deploy shared libraries only for shared-link builds. Static builds are the
# default so AFL instrumentation and post-campaign coverage stay in one image.
# Debug builds use a "d" suffix in current iccDEV. Preserve active symlink
# chains for every iccDEV library used by tool binaries.
deploy_shared_lib_root() {
    local src="$1"
    local root="$1"
    local hops=0

    while true; do
        cp -a "$src" "$BIN_DIR/"
        if [[ ! -L "$src" ]]; then
            break
        fi

        local target
        target="$(readlink "$src")"
        if [[ "$target" == /* ]]; then
            src="$target"
        else
            src="$(dirname "$src")/$target"
        fi

        hops=$((hops + 1))
        if [[ "$hops" -gt 16 ]]; then
            echo "[FAIL] Symlink chain too deep for $root"
            exit 1
        fi
    done
}

rm -f "$BIN_DIR"/libIcc*.so*
if [[ "$AFL_LINK_MODE" == "shared" ]]; then
    mapfile -t ICC_SHARED_ROOTS < <(
        find "$BUILD_DIR" -mindepth 2 -maxdepth 2 \( -type f -o -type l \) -name 'libIcc*.so' | sort
    )
    if [[ ${#ICC_SHARED_ROOTS[@]} -eq 0 ]]; then
        echo "[FAIL] No iccDEV shared libraries found under $BUILD_DIR"
        exit 1
    fi

    for lib_root in "${ICC_SHARED_ROOTS[@]}"; do
        deploy_shared_lib_root "$lib_root"
    done

    echo ""
    echo "Shared libraries:"
    find "$BIN_DIR" -maxdepth 1 -name 'lib*.so' -printf '  %s  %p\n' 2>/dev/null
else
    echo ""
    echo "Shared libraries: static link mode, none deployed"
fi

SANITIZER_PROBE="$BIN_DIR/iccDumpProfile"
if [[ ! -x "$SANITIZER_PROBE" ]]; then
    echo "[FAIL] Sanitizer verification binary not found: $SANITIZER_PROBE"
    exit 1
fi

verify_sanitizer_symbol() {
    local label="$1"
    local pattern="$2"

    if ! nm "$SANITIZER_PROBE" 2>/dev/null | grep -E "$pattern" >/dev/null; then
        echo "[FAIL] Missing $label instrumentation in $SANITIZER_PROBE"
        exit 1
    fi
    echo "  [OK] $label"
}

echo ""
echo "Sanitizer instrumentation:"
case "$SANITIZER_MODE" in
    address)
        verify_sanitizer_symbol "AddressSanitizer" '__asan_init'
        verify_sanitizer_symbol "UndefinedBehaviorSanitizer" '__ubsan_handle_(type_mismatch|add_overflow)'
        verify_sanitizer_symbol "IntegerSanitizer" '__ubsan_handle_(implicit_conversion|unsigned_add_overflow|shift_out_of_bounds)'
        verify_sanitizer_symbol "float-divide-by-zero" '__ubsan_handle_divrem_overflow'
        verify_sanitizer_symbol "float-cast-overflow" '__ubsan_handle_float_cast_overflow'
        ;;
    memory) verify_sanitizer_symbol "MemorySanitizer" '__msan_init' ;;
    thread) verify_sanitizer_symbol "ThreadSanitizer" '__tsan_init' ;;
esac

echo ""
echo "[OK] $DEPLOYED AFL-instrumented tools deployed to $BIN_DIR"
