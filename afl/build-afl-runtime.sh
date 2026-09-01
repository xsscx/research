#!/usr/bin/env bash
# Build the pinned AFL++ runtime with a 4 MiB testcase ceiling and LLVM 21.

set -euo pipefail

AFL_COMMIT="45bb74bd3a6591e6853b704c390ab6156c0a3c88"
AFL_MAX_FILE_BYTES=4194304
AFL_REPOSITORY="https://github.com/AFLplusplus/AFLplusplus.git"
AFL_SOURCE_DIR="${AFL_RUNTIME_SOURCE_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/aflplusplus-stable-maxfile4m}"
LLVM_CONFIG_BIN="${LLVM_CONFIG:-llvm-config-21}"
INSTALL_PREFIX="${PREFIX:-/usr/local}"
JOBS="${JOBS:-32}"
export -n AFL_RUNTIME_SOURCE_DIR 2>/dev/null || true

for tool in git make perl "$LLVM_CONFIG_BIN" clang-21 clang++-21 gcc-15; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: Required build tool not found: $tool" >&2
        echo "Install build-essential clang-21 llvm-21-dev llvm-21-tools lld-21" >&2
        echo "libclang-rt-21-dev gcc-15-plugin-dev libpython3-dev zlib1g-dev." >&2
        exit 1
    fi
done

if [[ ! -d "$AFL_SOURCE_DIR/.git" ]]; then
    mkdir -p "$(dirname "$AFL_SOURCE_DIR")"
    git clone --filter=blob:none "$AFL_REPOSITORY" "$AFL_SOURCE_DIR"
fi

git -C "$AFL_SOURCE_DIR" fetch origin "$AFL_COMMIT"
git -C "$AFL_SOURCE_DIR" checkout --detach "$AFL_COMMIT"

config_file="$AFL_SOURCE_DIR/include/config.h"
git -C "$AFL_SOURCE_DIR" restore --source="$AFL_COMMIT" -- include/config.h
perl -pi -e 's/^#define MAX_FILE .*$/#define MAX_FILE (4 * 1024 * 1024L)/' "$config_file"
if ! grep -Fqx '#define MAX_FILE (4 * 1024 * 1024L)' "$config_file"; then
    echo "ERROR: Failed to set AFL++ MAX_FILE to $AFL_MAX_FILE_BYTES in $config_file" >&2
    exit 1
fi

make -C "$AFL_SOURCE_DIR" clean
make -C "$AFL_SOURCE_DIR" -j"$JOBS" source-only \
    LLVM_CONFIG="$LLVM_CONFIG_BIN" NO_NYX=1

install_cmd=(
    make -C "$AFL_SOURCE_DIR" install PREFIX="$INSTALL_PREFIX"
    LLVM_CONFIG="$LLVM_CONFIG_BIN" NO_NYX=1
)
if [[ -w "$INSTALL_PREFIX" ]]; then
    "${install_cmd[@]}"
else
    sudo "${install_cmd[@]}"
fi

afl_fuzz="$INSTALL_PREFIX/bin/afl-fuzz"
afl_cc="$INSTALL_PREFIX/bin/afl-clang-fast"
"$afl_fuzz" --version
if ! { "$afl_fuzz" -hh 2>&1 || true; } | grep -q "default: ${AFL_MAX_FILE_BYTES}"; then
    echo "ERROR: Installed AFL++ does not report a $AFL_MAX_FILE_BYTES-byte testcase ceiling" >&2
    exit 1
fi
if [[ ! -x "$afl_cc" ]]; then
    echo "ERROR: Installed AFL++ compiler wrapper not found: $afl_cc" >&2
    exit 1
fi

echo "Installed AFL++ $AFL_COMMIT with MAX_FILE=$AFL_MAX_FILE_BYTES under $INSTALL_PREFIX."
