#!/usr/bin/env bash
# Validate the pure-ICC input and curated-seed contract for ApplyNamedCmm CFL.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CFL_DIR="$REPO_ROOT/cfl"
SEED_DIR="$CFL_DIR/seeds-applynamedcmm"
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

[[ -d "$SEED_DIR" ]] || fail "missing curated seed directory: $SEED_DIR"
mapfile -t seeds < <(find "$SEED_DIR" -maxdepth 1 -type f -name '*.icc' | sort)
[[ ${#seeds[@]} -gt 0 ]] || fail "no curated ICC seeds found"
[[ "$(find "$SEED_DIR" -maxdepth 1 -type f ! -name '*.icc' | wc -l)" -eq 0 ]] ||
  fail "non-ICC files found in the pure-profile seed directory"

for seed in "${seeds[@]}"; do
  file_size="$(stat -c %s "$seed")"
  header_size="$(od -A n -t u4 --endian=big -N 4 "$seed" | tr -d ' ')"
  magic="$(od -A n -t x1 -j 36 -N 4 "$seed" | tr -d ' \n')"
  [[ "$file_size" -eq "$header_size" ]] ||
    fail "$(basename "$seed"): header size $header_size != file size $file_size"
  [[ "$magic" == "61637370" ]] ||
    fail "$(basename "$seed"): missing acsp at byte 36"
done

# shellcheck source=cfl/fuzzers.sh
source "$CFL_DIR/fuzzers.sh"
max_len="$(cfl_option_max_len "$CFL_DIR" icc_applynamedcmm_fuzzer)"
[[ "$max_len" -eq 0 ]] ||
  fail "configured max_len is $max_len; expected corpus-derived sentinel (0)"
tmp_dir="$(mktemp -d /tmp/cfl-applynamedcmm-contract.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/corpus" "$tmp_dir/artifacts"
cfl_install_curated_seeds "$CFL_DIR" icc_applynamedcmm_fuzzer "$tmp_dir/corpus"
installed="$(find "$tmp_dir/corpus" -maxdepth 1 -type f | wc -l)"
[[ "$installed" -eq "${#seeds[@]}" ]] ||
  fail "installed $installed of ${#seeds[@]} curated seeds"
for seed in "${seeds[@]}"; do
  cmp -s "$seed" "$tmp_dir/corpus/$(basename "$seed")" ||
    fail "installed copy differs: $(basename "$seed")"
done

if [[ "$REPLAY" -eq 1 ]]; then
  binary="$CFL_DIR/bin/icc_applynamedcmm_fuzzer"
  large_seed="$REPO_ROOT/test-profiles/CMYK-3DLUTs2.icc"
  [[ -x "$binary" ]] || fail "replay requested but binary is missing"
  [[ -f "$large_seed" ]] || fail "missing large-profile replay fixture"
  [[ "$(stat -c %s "$large_seed")" -gt 1048576 ]] ||
    fail "large-profile replay fixture is missing or no longer above 1 MiB"
  cp "$large_seed" "$tmp_dir/corpus/large-profile.icc"
  effective_max_len="$(cfl_effective_max_len "$max_len" "$tmp_dir/corpus")"
  [[ "$effective_max_len" -eq "$(stat -c %s "$large_seed")" ]] ||
    fail "derived max_len $effective_max_len does not match the largest corpus file"
  ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1,abort_on_error=1,print_stacktrace=1 \
  LLVM_PROFILE_FILE=/dev/null \
    "$binary" -runs=1 -timeout=120 -rss_limit_mb=6144 \
      -max_len="$effective_max_len" \
      -artifact_prefix="$tmp_dir/artifacts/" "$tmp_dir/corpus"
  [[ "$(find "$tmp_dir/artifacts" -maxdepth 1 -type f | wc -l)" -eq 0 ]] ||
    fail "seed replay produced a LibFuzzer artifact"
fi

echo "[OK] ApplyNamedCmm pure-ICC contract passed (${#seeds[@]} curated seeds)"
