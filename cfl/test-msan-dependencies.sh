#!/usr/bin/env bash
# Verify that CFL MSan fuzzers have no uninstrumented third-party boundary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${CFL_MSAN_BIN_DIR:-$SCRIPT_DIR/bin-msan}"
DEPS_PREFIX="$SCRIPT_DIR/third_party/install-msan-deps"
FROMXML="$BIN_DIR/icc_fromxml_fuzzer"
TOXML="$BIN_DIR/icc_toxml_fuzzer"
APPLYPROFILES_ROW="$BIN_DIR/icc_applyprofiles_row_fuzzer"

for path in "$FROMXML" "$TOXML" "$APPLYPROFILES_ROW"; do
  if [[ ! -f "$path" ]]; then
    echo "[FAIL] Missing MSan dependency test input: $path" >&2
    exit 1
  fi
done

for archive in libxml2.a libz.a libjpeg.a libpng.a libtiff.a; do
  if [[ ! -f "$DEPS_PREFIX/lib/$archive" ]] ||
     ! grep -a -q '__msan_' "$DEPS_PREFIX/lib/$archive"; then
    echo "[FAIL] MSan dependency is missing or uninstrumented: $DEPS_PREFIX/lib/$archive" >&2
    exit 1
  fi
done

shopt -s nullglob
msan_binaries=("$BIN_DIR"/icc_*_fuzzer)
shopt -u nullglob
if [[ ${#msan_binaries[@]} -eq 0 ]]; then
  echo "[FAIL] No MSan fuzzer binaries found in $BIN_DIR" >&2
  exit 1
fi
for binary in "${msan_binaries[@]}"; do
  if ldd "$binary" 2>/dev/null |
     grep -Eq 'libstdc\+\+|libc\+\+|libxml2|libz\.so|libpng|libtiff|libjpeg|libwebp|libzstd|liblzma|libdeflate'; then
    echo "[FAIL] MSan fuzzer loads an uninstrumented shared dependency: $binary" >&2
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

replay_applyprofiles_artifact() {
  local name="$1"
  local encoded="$2"
  local expected_size="$3"
  local expected_sha256="$4"
  local input
  local replay_log
  local replay_status=0
  local actual_size
  local actual_sha256

  input="$(mktemp "/tmp/${name}.XXXXXX")"
  replay_log="$(mktemp "/tmp/${name}.XXXXXX.log")"
  printf '%s' "$encoded" | base64 --decode > "$input"
  actual_size="$(wc -c < "$input")"
  actual_sha256="$(sha256sum "$input" | awk '{print $1}')"
  if [[ "$actual_size" != "$expected_size" ||
        "$actual_sha256" != "$expected_sha256" ]]; then
    echo "[FAIL] $name fixture identity mismatch" >&2
    rm -f "$input" "$replay_log"
    exit 1
  fi

  set +e
  MSAN_OPTIONS=halt_on_error=1:abort_on_error=1:symbolize=1:exit_code=86 \
    timeout 30 "$APPLYPROFILES_ROW" -runs=1 "$input" > "$replay_log" 2>&1
  replay_status=$?
  set -e

  if [[ "$replay_status" -ne 0 ]] ||
     grep -Eq 'MemorySanitizer|libFuzzer: deadly signal' "$replay_log"; then
    echo "[FAIL] $name replay failed with exit $replay_status" >&2
    cat "$replay_log" >&2
    rm -f "$input" "$replay_log"
    exit 1
  fi
  rm -f "$input" "$replay_log"
  echo "[OK] $name replay exited 0 with instrumented image dependencies"
}

replay_applyprofiles_artifact \
  "icc_applyprofiles_issue_2701" \
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAJ8AAAAAAAAAAAAANUNDSQAAAAAAAAAAAAAAAAAAAAAAPQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJ8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///////8AAAAAAAAA////////////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAACOAQAAAA==" \
  205 \
  "8df410008321aab32967c75b5f70a7682a6c8145bfc6542e2ead77dfa6362352"
replay_applyprofiles_artifact \
  "icc_applyprofiles_u2_close" \
  "/w4K+v//////+/v7+/v7+/v7U0dJIPv7+/v7+/v7+/v7+/v7+/v7+/v7+/////////9wc2Qx//////9kbW5k//86/////f////8KCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgr///8=" \
  191 \
  "8269a9a536529294bbbad2c8f7cd9ec064c9767234058e5ca98f244350dd6a63"
