#!/usr/bin/env bash
# AFL wrapper for iccSpecSepToTiff TIFF-input fuzzing.
#
# iccSpecSepToTiff appends the channel number to argv[4], so AFL cannot pass @@
# directly as the input TIFF. This wrapper stages @@ as spec_1 in a temporary
# directory and runs a one-channel conversion without an optional profile. The
# input's final byte selects output modes so one campaign covers every argv
# shape without consuming five independent AFL workers.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 input.tif" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
SPECSEP_BIN="${ICC_SPECSEP_BIN:-$REPO_ROOT/afl/bin/iccSpecSepToTiff}"

if [[ ! -x "$SPECSEP_BIN" ]]; then
    echo "iccSpecSepToTiff not found: $SPECSEP_BIN" >&2
    exit 2
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/afl-specsep-tiff.XXXXXX")"
cleanup() {
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

cp -- "$1" "$tmp_dir/spec_1"

input_size="$(wc -c < "$1")"
mode="${ICC_SPECSEP_MODE:-auto}"
if [[ "$mode" == "auto" ]]; then
    if [[ "$input_size" -gt 0 ]]; then
        mode="$(od -A n -t u1 -j "$((input_size - 1))" -N 1 "$1")"
        mode="${mode//[[:space:]]/}"
    else
        mode=0
    fi
fi
if [[ ! "$mode" =~ ^[0-9]+$ || "$mode" -gt 15 ]]; then
    echo "ICC_SPECSEP_MODE must be auto or an integer from 0 through 15" >&2
    exit 2
fi

compress="${ICC_SPECSEP_COMPRESS:-$((mode & 1))}"
separate="${ICC_SPECSEP_SEP:-$(((mode >> 1) & 1))}"
tiles="${ICC_SPECSEP_TILES:-$(((mode >> 2) & 1))}"
bigtiff="${ICC_SPECSEP_BIGTIFF:-$(((mode >> 3) & 1))}"
options=()
[[ "$tiles" == "1" ]] && options+=(--tiles 16 16)
[[ "$bigtiff" == "1" ]] && options+=(--bigtiff)

"$SPECSEP_BIN" "${options[@]}" \
    "$tmp_dir/out.tif" \
    "$compress" \
    "$separate" \
    "$tmp_dir/spec_" \
    1 1 1
