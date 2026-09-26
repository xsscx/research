#!/usr/bin/env bash
# Verify that CFL MSan XML fuzzers have no uninstrumented libxml2 boundary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${CFL_MSAN_BIN_DIR:-$SCRIPT_DIR/bin-msan}"
LIBXML2_ARCHIVE="$SCRIPT_DIR/third_party/install-msan-libxml2/lib/libxml2.a"
FROMXML="$BIN_DIR/icc_fromxml_fuzzer"
TOXML="$BIN_DIR/icc_toxml_fuzzer"

for path in "$LIBXML2_ARCHIVE" "$FROMXML" "$TOXML"; do
  if [[ ! -f "$path" ]]; then
    echo "[FAIL] Missing MSan dependency test input: $path" >&2
    exit 1
  fi
done

if ! grep -a -q '__msan_' "$LIBXML2_ARCHIVE"; then
  echo "[FAIL] libxml2 archive is not MemorySanitizer-instrumented" >&2
  exit 1
fi

for binary in "$FROMXML" "$TOXML"; do
  if ldd "$binary" 2>/dev/null | grep -Eq 'libxml2|libstdc\+\+|libc\+\+'; then
    echo "[FAIL] MSan XML fuzzer loads an uninstrumented shared dependency: $binary" >&2
    ldd "$binary" >&2
    exit 1
  fi
done

artifact="$(mktemp /tmp/icc_fromxml_msan_libxml2.XXXXXX)"
log="$(mktemp /tmp/icc_fromxml_msan_libxml2.XXXXXX.log)"
trap 'rm -f "$artifact" "$log"' EXIT
printf '%s' 'MS4yVG9hfWdBsg==' | base64 --decode > "$artifact"

set +e
MSAN_OPTIONS=halt_on_error=1:abort_on_error=1:symbolize=1:exit_code=86 \
  timeout 30 "$FROMXML" -runs=1 "$artifact" > "$log" 2>&1
replay_exit=$?
set -e

if [[ "$replay_exit" -ne 0 ]] || grep -Eq 'MemorySanitizer|libFuzzer: deadly signal' "$log"; then
  echo "[FAIL] MSan libxml2 regression replay failed with exit $replay_exit" >&2
  cat "$log" >&2
  exit 1
fi

echo "[OK] MSan XML fuzzers use instrumented static libxml2"
echo "[OK] icc_fromxml_fuzzer libxml2-boundary artifact replay exited 0"
