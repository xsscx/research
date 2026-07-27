#!/usr/bin/env bash
# AFL wrapper for iccSpecSepToTiff TIFF-input fuzzing.
#
# iccSpecSepToTiff appends the channel number to argv[4], so AFL cannot pass @@
# directly as the input TIFF. This wrapper stages @@ as spec_1 in a temporary
# directory and runs a one-channel conversion without an optional profile.

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

"$SPECSEP_BIN" \
    "$tmp_dir/out.tif" \
    "${ICC_SPECSEP_COMPRESS:-0}" \
    "${ICC_SPECSEP_SEP:-0}" \
    "$tmp_dir/spec_" \
    1 1 1
