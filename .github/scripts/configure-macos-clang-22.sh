#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  printf 'configure-macos-clang-22.sh requires macOS\n' >&2
  exit 64
fi

llvm_prefix="$(brew --prefix llvm@22)"
sdk_root="$(xcrun --sdk macosx --show-sdk-path)"
developer_root="$(xcode-select -p)"
cxx_headers="$sdk_root/usr/include/c++/v1"
toolchain_headers="$developer_root/Toolchains/XcodeDefault.xctoolchain/usr/include"

test -x "$llvm_prefix/bin/clang"
test -x "$llvm_prefix/bin/clang++"
test -d "$cxx_headers"
test -d "$sdk_root/usr/include"
test -d "$toolchain_headers"

export CC="$llvm_prefix/bin/clang"
export CXX="$llvm_prefix/bin/clang++"
export SDKROOT="$sdk_root"
export CFLAGS="--no-default-config -isysroot $sdk_root"
export CXXFLAGS="--no-default-config -isysroot $sdk_root -isystem $cxx_headers -isystem $sdk_root/usr/include -isystem $toolchain_headers"
export LDFLAGS="-isysroot $sdk_root"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    printf 'CC=%s\n' "$CC"
    printf 'CXX=%s\n' "$CXX"
    printf 'SDKROOT=%s\n' "$SDKROOT"
    printf 'CFLAGS=%s\n' "$CFLAGS"
    printf 'CXXFLAGS=%s\n' "$CXXFLAGS"
    printf 'LDFLAGS=%s\n' "$LDFLAGS"
  } >> "$GITHUB_ENV"
fi
