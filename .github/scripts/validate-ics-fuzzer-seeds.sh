#!/usr/bin/env bash
# Validate external ICS artifact discovery and format-specific fuzzer routing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ICS_ROOT="${ICS_ROOT:-$REPO_ROOT/ics}"
REPLAY=0

if [[ "${1:-}" == "--replay" ]]; then
  REPLAY=1
elif [[ $# -ne 0 ]]; then
  echo "Usage: $0 [--replay]" >&2
  exit 2
fi

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

[[ -d "$ICS_ROOT/packages" ]] || fail "modern ICS package tree not found: $ICS_ROOT/packages"

scratch_root="$(mktemp -d /tmp/ics-fuzzer-seeds.XXXXXX)"
trap 'rm -rf "$scratch_root"' EXIT

export AFL_ICS_ROOT="$ICS_ROOT"
export CFL_ICS_ROOT="$ICS_ROOT"
export AFL_BASE="$scratch_root/afl"
export BIN_DIR="${BIN_DIR:-$REPO_ROOT/afl/bin}"

# shellcheck source=afl/targets.sh
source "$REPO_ROOT/afl/targets.sh"

expect_afl_route() {
  local target="$1"
  local extension="$2"
  local seed_dir

  afl_configure_target "$target" || fail "AFL target did not configure: $target"
  for seed_dir in "${SEED_DIRS[@]}"; do
    if find "$seed_dir" -maxdepth 1 -type f -name "*.$extension" -print -quit 2>/dev/null |
       grep -q .; then
      [[ "$seed_dir" == "$ICS_ROOT/packages/"* ]] && return 0
    fi
  done
  fail "$target did not discover an ICS .$extension seed directory"
}

expect_afl_route dump icc
expect_afl_route applyprofiles-cfg json
expect_afl_route fromxml xml
expect_afl_route pngdump png
expect_afl_route tiffdump tif

afl_configure_target applyprofiles-hybrid-embedded
[[ "$SEED_DRY_RUN_TIMEOUT" -eq 120 ]] || fail "hybrid embedded seed timeout is not 120 seconds"
[[ "$AFL_TARGET_TIMEOUT" -eq 120000 ]] || fail "hybrid embedded AFL timeout is not 120000 ms"

# shellcheck source=cfl/fuzzers.sh
source "$REPO_ROOT/cfl/fuzzers.sh"

expect_cfl_install() {
  local fuzzer="$1"
  local extension="$2"
  local corpus="$scratch_root/$fuzzer"

  mkdir -p "$corpus"
  cfl_install_curated_seeds "$REPO_ROOT/cfl" "$fuzzer" "$corpus"
  find "$corpus" -maxdepth 1 -type f -name "ics-*-*.$extension" -print -quit |
    grep -q . || fail "$fuzzer did not install an ICS .$extension seed"
}

expect_cfl_install icc_dump_fuzzer icc
expect_cfl_install icc_fromxml_fuzzer xml
expect_cfl_install icc_pngdump_fuzzer png
expect_cfl_install icc_tiffdump_fuzzer tif
expect_cfl_install icc_cfg_fuzzer json

[[ "$(cfl_option_max_len "$REPO_ROOT/cfl" icc_tiffdump_fuzzer)" -eq 0 ]] ||
  fail "TIFF fuzzer still has a fixed input-size ceiling"

cfg_seed="$(find "$scratch_root/icc_cfg_fuzzer" -maxdepth 1 -type f -name 'ics-*-*.json' -print -quit)"
python3 -m json.tool "$cfg_seed" >/dev/null ||
  fail "ICS config seed is not an ordinary JSON document"

if [[ "$REPLAY" -eq 1 ]]; then
  for fuzzer in \
    icc_dump_fuzzer \
    icc_cfg_fuzzer \
    icc_fromxml_fuzzer \
    icc_pngdump_fuzzer \
    icc_tiffdump_fuzzer; do
    binary="${BIN_DIR%/}/$fuzzer"
    corpus="$scratch_root/$fuzzer"
    [[ -x "$binary" ]] || fail "replay binary not found: $binary"
    max_len="$(cfl_effective_max_len "$(cfl_option_max_len "$REPO_ROOT/cfl" "$fuzzer")" "$corpus")"
    ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1 \
    UBSAN_OPTIONS=halt_on_error=1,abort_on_error=1,print_stacktrace=1 \
    LLVM_PROFILE_FILE=/dev/null \
      "$binary" -runs=1 -timeout=120 -rss_limit_mb=6144 \
        -max_len="$max_len" -artifact_prefix="$scratch_root/" "$corpus"
  done
fi

echo "[OK] ICS artifacts route to matching AFL and CFL consumers."
