#!/usr/bin/env bash
# Build the pinned AFL++ runtime with a configurable large-input ceiling.

set -euo pipefail

AFL_COMMIT="2400206be6fe0d93681c8a5c1535209366602eb1"
AFL_MAX_FILE_BYTES="${AFL_MAX_FILE_BYTES:-67108864}"
AFL_REPOSITORY="https://github.com/AFLplusplus/AFLplusplus.git"
AFL_SOURCE_DIR="${AFL_RUNTIME_SOURCE_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/aflplusplus-stable}"
if [[ -n "${LLVM_CONFIG:-}" ]]; then
    LLVM_CONFIG_BIN="$LLVM_CONFIG"
else
    CLANG_MAJOR="$(clang -dumpversion 2>/dev/null | cut -d. -f1 || true)"
    if [[ "$CLANG_MAJOR" =~ ^[0-9]+$ ]] && command -v "llvm-config-$CLANG_MAJOR" >/dev/null 2>&1; then
        LLVM_CONFIG_BIN="llvm-config-$CLANG_MAJOR"
    else
        LLVM_CONFIG_BIN="llvm-config"
    fi
fi
INSTALL_PREFIX="${PREFIX:-/usr/local}"
JOBS="${JOBS:-32}"
export -n AFL_RUNTIME_SOURCE_DIR 2>/dev/null || true

if [[ ! "$AFL_MAX_FILE_BYTES" =~ ^[0-9]+$ || "$AFL_MAX_FILE_BYTES" -lt 4194304 ]]; then
    echo "ERROR: AFL_MAX_FILE_BYTES must be an integer of at least 4194304" >&2
    exit 1
fi

for tool in git make perl "$LLVM_CONFIG_BIN" clang clang++ gcc-15; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: Required build tool not found: $tool" >&2
        echo "Install build-essential clang llvm-dev llvm-tools lld" >&2
        echo "libclang-rt-dev gcc-15-plugin-dev libpython3-dev zlib1g-dev." >&2
        exit 1
    fi
done

echo "[*] AFL++ LLVM toolchain: $LLVM_CONFIG_BIN ($("$LLVM_CONFIG_BIN" --version))"

if [[ ! -d "$AFL_SOURCE_DIR/.git" ]]; then
    mkdir -p "$(dirname "$AFL_SOURCE_DIR")"
    git clone --filter=blob:none "$AFL_REPOSITORY" "$AFL_SOURCE_DIR"
fi

config_file="$AFL_SOURCE_DIR/include/config.h"
config_backup=""
config_patch=""

restore_config() {
    if [[ -n "$config_backup" && -f "$config_backup" ]]; then
        cp -- "$config_backup" "$config_file"
    fi
    rm -f -- "$config_backup" "$config_patch"
    config_backup=""
    config_patch=""
}

if ! git -C "$AFL_SOURCE_DIR" diff --quiet -- include/config.h ||
    ! git -C "$AFL_SOURCE_DIR" diff --cached --quiet -- include/config.h; then
    config_backup="$(mktemp)"
    config_patch="$(mktemp)"
    cp -- "$config_file" "$config_backup"
    git -C "$AFL_SOURCE_DIR" diff --binary HEAD -- include/config.h >"$config_patch"
    trap restore_config EXIT
    git -C "$AFL_SOURCE_DIR" restore --source=HEAD --staged --worktree -- include/config.h
fi

git -C "$AFL_SOURCE_DIR" fetch origin "$AFL_COMMIT"
git -C "$AFL_SOURCE_DIR" checkout --detach "$AFL_COMMIT"

if [[ -n "$config_patch" ]]; then
    git -C "$AFL_SOURCE_DIR" apply --whitespace=nowarn "$config_patch"
fi
rm -f -- "$config_backup" "$config_patch"
config_backup=""
config_patch=""
trap - EXIT
perl -pi -e "s/^#define MAX_FILE .*\$/#define MAX_FILE (${AFL_MAX_FILE_BYTES}L)/" "$config_file"
if ! grep -Fqx "#define MAX_FILE (${AFL_MAX_FILE_BYTES}L)" "$config_file"; then
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
