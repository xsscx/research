#!/usr/bin/env bash
# Build the dependency-free ICC profile custom mutator for AFL++.
#
# Usage: ./build-mutator.sh [--output FILE] [--cxx COMPILER]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE="$SCRIPT_DIR/mutators/icc_profile_mutator.cpp"
OUTPUT="${AFL_ICC_MUTATOR_LIBRARY:-$SCRIPT_DIR/mutators/build/icc_profile_mutator.so}"
CXX_BIN="${AFL_MUTATOR_CXX:-clang++}"

usage() {
    sed -n '2,4p' "$0" | sed 's/^# \?//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            [[ $# -ge 2 && -n "$2" ]] || { echo "ERROR: --output requires a file" >&2; exit 1; }
            OUTPUT="$2"
            shift 2
            ;;
        --cxx)
            [[ $# -ge 2 && -n "$2" ]] || { echo "ERROR: --cxx requires a compiler" >&2; exit 1; }
            CXX_BIN="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

command -v "$CXX_BIN" >/dev/null 2>&1 || {
    echo "ERROR: C++ compiler not found: $CXX_BIN" >&2
    exit 127
}
command -v nm >/dev/null 2>&1 || {
    echo "ERROR: nm is required to verify the mutator ABI" >&2
    exit 127
}

output_dir="$(dirname "$OUTPUT")"
mkdir -p "$output_dir"
temp_output="$(mktemp "$output_dir/.icc_profile_mutator.XXXXXX.so")"
trap 'rm -f -- "$temp_output"' EXIT

"$CXX_BIN" \
    -std=c++17 -O2 -g -fPIC -shared \
    -Wall -Wextra -Wpedantic -Werror \
    "$SOURCE" -o "$temp_output"

for symbol in afl_custom_init afl_custom_fuzz afl_custom_deinit; do
    if ! nm -D --defined-only "$temp_output" | awk '{print $3}' | grep -Fxq "$symbol"; then
        echo "ERROR: custom mutator ABI symbol is missing: $symbol" >&2
        exit 1
    fi
done

mv -f -- "$temp_output" "$OUTPUT"
trap - EXIT
echo "[OK] ICC profile custom mutator built: $OUTPUT"
