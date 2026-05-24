#!/usr/bin/env bash
# Smoke-test the IccConnect/IccJSON CFL harnesses with existing local corpora.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=cfl/fuzzers.sh
source "$SCRIPT_DIR/fuzzers.sh"

RUNS="${RUNS:-16}"
TMP_ROOT="${TMPDIR:-/tmp}/cfl-iccconnect-json-smoke.$$"
TARGETS=(
  icc_connect_fuzzer
  icc_fromjson_fuzzer
  icc_tojson_fuzzer
)

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \?//'
  echo ""
  echo "Usage: $0 [--runs N] [fuzzer ...]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs|-r) RUNS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *) TARGETS=("$@"); break ;;
  esac
done

mkdir -p "$TMP_ROOT/profraw"
trap 'rm -rf "$TMP_ROOT"' EXIT

echo "[*] IccConnect/IccJSON CFL smoke"
echo "    Runs: $RUNS"
echo "    Tmp:  $TMP_ROOT"

copy_seed_subset() {
  local dst="$1"
  shift
  local copied=0
  local src
  local file

  mkdir -p "$dst"
  for src in "$@"; do
    [[ -d "$src" ]] || continue
    while IFS= read -r file; do
      cp -n "$file" "$dst/" 2>/dev/null || true
      copied=$((copied + 1))
      [[ "$copied" -ge 16 ]] && return 0
    done < <(find "$src" -maxdepth 1 -type f | sort)
  done
}

for target in "${TARGETS[@]}"; do
  fuzzer="$(cfl_normalize_fuzzer "$target")"
  bin="$SCRIPT_DIR/bin/$fuzzer"
  if [[ ! -x "$bin" ]]; then
    echo "[FAIL] missing binary: $bin"
    echo "       Run: cd cfl && ./build.sh --refresh-iccdev"
    exit 1
  fi

  corpus="$TMP_ROOT/corpus-$fuzzer"
  case "$fuzzer" in
    icc_connect_fuzzer|icc_tojson_fuzzer)
      copy_seed_subset "$corpus" "$SCRIPT_DIR/../test-profiles"
      ;;
    icc_fromjson_fuzzer)
      copy_seed_subset "$corpus" "$SCRIPT_DIR/corpus-icc_fromjson_fuzzer" \
        "$SCRIPT_DIR/../fuzz/graphics/json" \
        "$SCRIPT_DIR/../docs/Testing/malformed-json"
      ;;
  esac

  dict_args=()
  if dict="$(cfl_resolve_dict "$SCRIPT_DIR" "$fuzzer")"; then
    dict_args=("-dict=$dict")
  fi

  timeout_value="$(cfl_option_timeout "$SCRIPT_DIR" "$fuzzer")"
  echo "[*] $fuzzer"
  FUZZ_TMPDIR="$TMP_ROOT" \
  LLVM_PROFILE_FILE="$TMP_ROOT/profraw/${fuzzer}_%m_%p.profraw" \
  ASAN_OPTIONS="detect_leaks=0,allocator_may_return_null=1" \
  UBSAN_OPTIONS="halt_on_error=0,print_stacktrace=1" \
    "$bin" \
      -runs="$RUNS" \
      -detect_leaks=0 \
      -timeout="$timeout_value" \
      -rss_limit_mb=4096 \
      -use_value_profile=1 \
      -create_missing_dirs=1 \
      "${dict_args[@]}" \
      "$corpus"
done

echo "[OK] IccConnect/IccJSON smoke completed"
