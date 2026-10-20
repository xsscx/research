#!/usr/bin/env bash
# Build the ICC Google FuzzTest harness and its instrumented dependencies.
#
# Usage: ./build.sh [clean] [--mode fuzzing|unit|libfuzzer]
#                   [--refresh-fuzztest] [--refresh-iccdev] [--jobs N]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=fuzztest/versions.sh
source "$SCRIPT_DIR/versions.sh"

FRAMEWORK_DIR="${ICC_FUZZTEST_FRAMEWORK_DIR:-$SCRIPT_DIR/upstream}"
ICCDEV_DIR="${ICC_FUZZTEST_ICCDEV_DIR:-$SCRIPT_DIR/iccDEV}"
MODE="${ICC_FUZZTEST_MODE:-fuzzing}"
JOBS="${ICC_FUZZTEST_JOBS:-32}"
CLEAN=0
REFRESH_FUZZTEST=0
REFRESH_ICCDEV=0

usage() {
    sed -n '2,6p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  clean               remove the selected build directory first"
    echo "  --mode MODE         fuzzing (default), unit, or libfuzzer"
    echo "  --refresh-fuzztest  fetch and check out the pinned FuzzTest revision"
    echo "  --refresh-iccdev    fetch and check out the configured iccDEV revision"
    echo "  --jobs N            parallel build jobs (default: 32)"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        clean|--clean)
            CLEAN=1
            shift
            ;;
        --mode)
            if [[ $# -lt 2 ]]; then
                echo "[FAIL] --mode requires fuzzing, unit, or libfuzzer" >&2
                exit 1
            fi
            MODE="$2"
            shift 2
            ;;
        --refresh-fuzztest)
            REFRESH_FUZZTEST=1
            shift
            ;;
        --refresh-iccdev)
            REFRESH_ICCDEV=1
            shift
            ;;
        --jobs)
            if [[ $# -lt 2 || ! "$2" =~ ^[1-9][0-9]*$ ]]; then
                echo "[FAIL] --jobs requires a positive integer" >&2
                exit 1
            fi
            JOBS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[FAIL] unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

case "$MODE" in
    fuzzing)
        BUILD_DIR="${ICC_FUZZTEST_BUILD_DIR:-$SCRIPT_DIR/build}"
        MODE_OPTIONS=(
            -DFUZZTEST_FUZZING_MODE=ON
            -DFUZZTEST_COMPATIBILITY_MODE=
        )
        ICCDEV_C_FLAGS="-g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -UNDEBUG -fsanitize=address,undefined,integer,float-divide-by-zero,float-cast-overflow -fsanitize-coverage=inline-8bit-counters -fsanitize-coverage=trace-cmp"
        ;;
    unit)
        BUILD_DIR="${ICC_FUZZTEST_BUILD_DIR:-$SCRIPT_DIR/build-unit}"
        MODE_OPTIONS=(
            -DFUZZTEST_FUZZING_MODE=OFF
            -DFUZZTEST_COMPATIBILITY_MODE=
        )
        ICCDEV_C_FLAGS=""
        ;;
    libfuzzer)
        BUILD_DIR="${ICC_FUZZTEST_BUILD_DIR:-$SCRIPT_DIR/build-libfuzzer}"
        MODE_OPTIONS=(
            -DFUZZTEST_FUZZING_MODE=OFF
            -DFUZZTEST_COMPATIBILITY_MODE=libfuzzer
        )
        ICCDEV_C_FLAGS="-g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DFUZZTEST_COMPATIBILITY_MODE -UNDEBUG -fsanitize=fuzzer-no-link,address,undefined,integer,float-divide-by-zero,float-cast-overflow -fsanitize-coverage=inline-8bit-counters -fsanitize-coverage=trace-cmp"
        ;;
    *)
        echo "[FAIL] unsupported mode '$MODE' (use fuzzing, unit, or libfuzzer)" >&2
        exit 1
        ;;
esac

for tool in git cmake ninja clang clang++; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[FAIL] required tool not found: $tool" >&2
        exit 1
    fi
done

ensure_checkout() {
    local name="$1"
    local repository="$2"
    local ref="$3"
    local directory="$4"
    local refresh="$5"
    local resolved_ref="$ref"
    local expected_commit
    local current_commit

    if [[ ! -d "$directory/.git" ]]; then
        if [[ -e "$directory" ]]; then
            echo "[FAIL] $name path exists but is not a Git checkout: $directory" >&2
            exit 1
        fi
        echo "[*] Cloning $name"
        git clone "$repository" "$directory"
        refresh=1
    fi

    if [[ "$refresh" == "1" ]]; then
        if [[ -n "$(git -C "$directory" status --porcelain)" ]]; then
            echo "[FAIL] refusing to refresh dirty $name checkout: $directory" >&2
            exit 1
        fi
        echo "[*] Refreshing $name"
        git -C "$directory" fetch --prune --tags origin
        if git -C "$directory" show-ref --verify --quiet "refs/remotes/origin/$ref"; then
            resolved_ref="origin/$ref"
        fi
        git -C "$directory" checkout --detach "$resolved_ref"
    fi

    if git -C "$directory" show-ref --verify --quiet "refs/remotes/origin/$ref"; then
        resolved_ref="origin/$ref"
    fi
    expected_commit="$(git -C "$directory" rev-parse "${resolved_ref}^{commit}")"
    current_commit="$(git -C "$directory" rev-parse HEAD)"
    if [[ "$current_commit" != "$expected_commit" ]]; then
        echo "[FAIL] $name is at $current_commit, expected $expected_commit ($ref)" >&2
        echo "       Re-run with the matching --refresh option or set an explicit source directory." >&2
        exit 1
    fi
    echo "[OK] $name revision: $current_commit"
}

ensure_checkout "Google FuzzTest" "$GOOGLE_FUZZTEST_REPOSITORY" \
    "$GOOGLE_FUZZTEST_REF" "$FRAMEWORK_DIR" "$REFRESH_FUZZTEST"
ensure_checkout "iccDEV" "$ICCDEV_REPOSITORY" "$ICCDEV_REF" \
    "$ICCDEV_DIR" "$REFRESH_ICCDEV"

if [[ "$CLEAN" == "1" && -d "$BUILD_DIR" ]]; then
    case "$BUILD_DIR" in
        "$SCRIPT_DIR"/build|"$SCRIPT_DIR"/build-unit|"$SCRIPT_DIR"/build-libfuzzer)
            echo "[*] Removing $BUILD_DIR"
            cmake -E remove_directory "$BUILD_DIR"
            ;;
        *)
            echo "[FAIL] refusing to clean unexpected build directory: $BUILD_DIR" >&2
            exit 1
            ;;
    esac
fi

ICCDEV_BUILD_DIR="$BUILD_DIR/iccdev"
ICCDEV_LIBRARY="$ICCDEV_BUILD_DIR/IccProfLib/libIccProfLib2-static.a"

echo "[*] Configuring instrumented iccDEV core library ($MODE)"
CC="${CC:-clang}" CXX="${CXX:-clang++}" cmake \
    -S "$ICCDEV_DIR/Build/Cmake" \
    -B "$ICCDEV_BUILD_DIR" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_FLAGS="$ICCDEV_C_FLAGS" \
    -DCMAKE_CXX_FLAGS="$ICCDEV_C_FLAGS" \
    -DENABLE_TESTS=OFF \
    -DENABLE_TOOLS=OFF \
    -DENABLE_WXWIDGETS=OFF \
    -DENABLE_SHARED_LIBS=OFF \
    -DENABLE_STATIC_LIBS=ON \
    -DENABLE_ICCXML=OFF \
    -DENABLE_ICCJSON=OFF \
    -DENABLE_IMAGE_TOOLS=OFF \
    -DENABLE_CMM_TOOLS=OFF \
    -DENABLE_IIS_TOOLS=OFF

echo "[*] Building instrumented iccDEV core library with $JOBS jobs"
cmake --build "$ICCDEV_BUILD_DIR" --target IccProfLib2-static --parallel "$JOBS"

echo "[*] Configuring ICC FuzzTest ($MODE)"
CC="${CC:-clang}" CXX="${CXX:-clang++}" cmake \
    -S "$SCRIPT_DIR" \
    -B "$BUILD_DIR" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DGOOGLE_FUZZTEST_SOURCE_DIR="$FRAMEWORK_DIR" \
    -DICCDEV_SOURCE_DIR="$ICCDEV_DIR" \
    -DICCDEV_BUILD_DIR="$ICCDEV_BUILD_DIR" \
    -DICCDEV_LIBRARY="$ICCDEV_LIBRARY" \
    -DICC_FUZZTEST_REPO_ROOT="$REPO_ROOT" \
    "${MODE_OPTIONS[@]}"

echo "[*] Building icc_profile_fuzz_test with $JOBS jobs"
cmake --build "$BUILD_DIR" --target icc_profile_fuzz_test --parallel "$JOBS"

echo "[OK] Built $BUILD_DIR/icc_profile_fuzz_test"
