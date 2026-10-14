#!/usr/bin/env bash
# AFL wrapper for collision-free iccHeifDump extraction fuzzing.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 input.heif /path/to/iccHeifDump" >&2
    exit 2
fi

input_file="$1"
heifdump_bin="$2"

if [[ ! -x "$heifdump_bin" ]]; then
    echo "iccHeifDump not found: $heifdump_bin" >&2
    exit 2
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/afl-heifdump-extract.XXXXXX")"
cleanup() {
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

"$heifdump_bin" "$input_file" "$tmp_dir"
