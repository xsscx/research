#!/bin/bash
# Reproduce and patch-check the AFL iccFromXml namedColor2 CountOfDeviceCoords
# sanitizer finding against InternationalColorConsortium/iccDEV.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ICCDEV_REPO="${ICCDEV_REPO:-https://github.com/InternationalColorConsortium/iccDEV.git}"
ICCDEV_REF="${ICCDEV_REF:-ci-afl-cfl}"
WORK_ROOT="${WORK_ROOT:-/tmp/iccdev-afl-fromxml-regression}"
POC_XML="${POC_XML:-$REPO_ROOT/afl/reproducers/fromxml/ub-namedcolor-devicecoords-huge.xml}"
PATCH_FILE="${PATCH_FILE:-$REPO_ROOT/afl/patches/005-fromxml-namedcolor-devicecoords-bounds.patch}"
OUT_ICC="${OUT_ICC:-$WORK_ROOT/out.icc}"
REPORT_FILE="${REPORT_FILE:-$WORK_ROOT/transaction.md}"
ISSUE_URL="${ISSUE_URL:-https://github.com/InternationalColorConsortium/iccDEV/issues/1851}"

CC_BIN="${CC:-clang-18}"
CXX_BIN="${CXX:-clang++-18}"

if [ ! -r "$POC_XML" ]; then
  echo "[FAIL] PoC XML not found: $POC_XML" >&2
  exit 1
fi
if [ ! -r "$PATCH_FILE" ]; then
  echo "[FAIL] AFL patch not found: $PATCH_FILE" >&2
  exit 1
fi
if ! command -v "$CC_BIN" >/dev/null 2>&1 || ! command -v "$CXX_BIN" >/dev/null 2>&1; then
  echo "[FAIL] clang-18 and clang++-18 are required" >&2
  exit 1
fi

begin_section() {
  local title="$1"

  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "::group::$title"
  fi
  echo ""
  echo "============================================================================="
  echo " $title"
  echo "============================================================================="
}

end_section() {
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "::endgroup::"
  fi
}

configure_and_build() {
  local src_dir="$1"
  local build_dir="$2"

  cmake -S "$src_dir/Build/Cmake" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="$CC_BIN" \
    -DCMAKE_CXX_COMPILER="$CXX_BIN" \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined,integer,float-divide-by-zero,float-cast-overflow -fno-omit-frame-pointer -fno-optimize-sibling-calls -O0 -g3" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined,integer,float-divide-by-zero,float-cast-overflow -fno-omit-frame-pointer -fno-optimize-sibling-calls -O0 -g3 -std=c++17" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined,integer,float-divide-by-zero,float-cast-overflow" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined,integer,float-divide-by-zero,float-cast-overflow" \
    -DENABLE_TOOLS=ON \
    -DENABLE_SHARED_LIBS=ON \
    -DENABLE_STATIC_LIBS=ON \
    -Wno-dev >/dev/null

  cmake --build "$build_dir" --target iccFromXml --parallel "$(nproc)"
}

replay_command() {
  local build_dir="$1"
  local tool="$build_dir/Tools/IccFromXml/iccFromXml"

  printf 'LD_LIBRARY_PATH=%s:%s ' "$build_dir/IccProfLib" "$build_dir/IccXML"
  printf 'ASAN_OPTIONS=%s ' "detect_leaks=0:halt_on_error=0:abort_on_error=0:symbolize=1:allocator_may_return_null=1"
  printf 'UBSAN_OPTIONS=%s ' "halt_on_error=0:abort_on_error=0:print_stacktrace=1"
  printf 'timeout 30s %q %q %q\n' "$tool" "$POC_XML" "$OUT_ICC"
}

run_fromxml() {
  local build_dir="$1"
  local log_file="$2"
  local tool="$build_dir/Tools/IccFromXml/iccFromXml"

  if [ ! -x "$tool" ]; then
    echo "[FAIL] iccFromXml not built at $tool" >&2
    exit 1
  fi

  rm -f "$OUT_ICC"
  local rc=0
  LD_LIBRARY_PATH="$build_dir/IccProfLib:$build_dir/IccXML" \
  ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:abort_on_error=0:symbolize=1:allocator_may_return_null=1" \
  UBSAN_OPTIONS="halt_on_error=0:abort_on_error=0:print_stacktrace=1" \
    timeout 30s "$tool" "$POC_XML" "$OUT_ICC" > "$log_file" 2>&1 || rc=$?

  echo "$rc"
}

print_log_excerpt() {
  local label="$1"
  local log_file="$2"

  echo "[EVIDENCE] $label log excerpt:"
  grep -m 20 -E 'runtime error:|SUMMARY: UndefinedBehaviorSanitizer|Unable to Parse' "$log_file" || true
}

write_report() {
  local unpatched_rc="$1"
  local patched_rc="$2"

  {
    echo "### iccFromXml namedColor2 CountOfDeviceCoords transaction"
    echo ""
    echo "| Field | Value |"
    echo "|-------|-------|"
    echo "| iccDEV ref | $ICCDEV_REF |"
    echo "| Upstream issue | $ISSUE_URL |"
    echo "| PoC | $POC_XML |"
    echo "| AFL patch | $PATCH_FILE |"
    echo "| Original CLI shape | iccFromXml id:000003,sig:06,sync:secondary_3,src:001421 foo |"
    echo "| Unpatched exit | $unpatched_rc |"
    echo "| Patched exit | $patched_rc |"
    echo "| Conclusion | Bug patched: unpatched emits IccTagXml.cpp implicit-conversion UBSAN; patched fails closed with no sanitizer finding. |"
    echo ""
    echo "#### Unpatched replay command"
    echo '```bash'
    replay_command "$WORK_ROOT/build-unpatched"
    echo '```'
    echo ""
    echo "#### Unpatched evidence"
    echo '```text'
    grep -m 20 -E 'runtime error:|SUMMARY: UndefinedBehaviorSanitizer|Unable to Parse' "$UNPATCHED_LOG" || true
    echo '```'
    echo ""
    echo "#### Patched replay command"
    echo '```bash'
    replay_command "$WORK_ROOT/build-patched"
    echo '```'
    echo ""
    echo "#### Patched evidence"
    echo '```text'
    grep -m 20 -E 'runtime error:|SUMMARY: UndefinedBehaviorSanitizer|Unable to Parse' "$PATCHED_LOG" || true
    echo '```'
  } > "$REPORT_FILE"
}

rm -rf "$WORK_ROOT"
mkdir -p "$WORK_ROOT"

begin_section "1. Inputs and original command-line reproduction"
echo "[INFO] iccDEV ref: $ICCDEV_REF"
echo "[INFO] Upstream issue: $ISSUE_URL"
echo "[INFO] PoC XML: $POC_XML"
echo "[INFO] AFL patch: $PATCH_FILE"
echo "[INFO] Original CLI shape:"
echo "       iccFromXml id:000003,sig:06,sync:secondary_3,src:001421 foo"
end_section

begin_section "2. Clone raw and patched iccDEV worktrees"
echo "[INFO] Cloning $ICCDEV_REPO ($ICCDEV_REF)"
git clone --depth 1 --branch "$ICCDEV_REF" "$ICCDEV_REPO" "$WORK_ROOT/unpatched" >/dev/null
git clone "$WORK_ROOT/unpatched" "$WORK_ROOT/patched" >/dev/null
echo "[INFO] Unpatched commit: $(git -C "$WORK_ROOT/unpatched" log --oneline -1)"
echo "[INFO] Patched worktree starts from the same commit"
end_section

begin_section "3. Build and replay unpatched iccFromXml"
echo "[INFO] Building unpatched iccFromXml"
configure_and_build "$WORK_ROOT/unpatched" "$WORK_ROOT/build-unpatched"

UNPATCHED_LOG="$WORK_ROOT/unpatched.log"
echo "[COMMAND] Unpatched replay:"
replay_command "$WORK_ROOT/build-unpatched"
UNPATCHED_RC="$(run_fromxml "$WORK_ROOT/build-unpatched" "$UNPATCHED_LOG")"
echo "[INFO] Unpatched replay exit: $UNPATCHED_RC"

if ! grep -q "runtime error: implicit conversion" "$UNPATCHED_LOG"; then
  echo "[FAIL] Unpatched replay did not reproduce the implicit-conversion sanitizer finding" >&2
  sed -n '1,120p' "$UNPATCHED_LOG" >&2
  exit 1
fi
if ! grep -q "IccTagXml.cpp" "$UNPATCHED_LOG"; then
  echo "[FAIL] Unpatched replay did not attribute the finding to IccTagXml.cpp" >&2
  sed -n '1,120p' "$UNPATCHED_LOG" >&2
  exit 1
fi
print_log_excerpt "Unpatched" "$UNPATCHED_LOG"
echo "[OK] Unpatched replay reproduced the IccTagXml.cpp implicit-conversion finding"
end_section

begin_section "4. Apply AFL patch"
echo "[INFO] Applying AFL patch"
git -C "$WORK_ROOT/patched" apply "$PATCH_FILE"
git -C "$WORK_ROOT/patched" diff --stat
end_section

begin_section "5. Build and replay patched iccFromXml"
echo "[INFO] Building patched iccFromXml"
configure_and_build "$WORK_ROOT/patched" "$WORK_ROOT/build-patched"

PATCHED_LOG="$WORK_ROOT/patched.log"
echo "[COMMAND] Patched replay:"
replay_command "$WORK_ROOT/build-patched"
PATCHED_RC="$(run_fromxml "$WORK_ROOT/build-patched" "$PATCHED_LOG")"
echo "[INFO] Patched replay exit: $PATCHED_RC"

if grep -q "runtime error:" "$PATCHED_LOG"; then
  echo "[FAIL] Patched replay still emitted a sanitizer finding" >&2
  sed -n '1,160p' "$PATCHED_LOG" >&2
  exit 1
fi
if ! grep -q "Unable to Parse" "$PATCHED_LOG"; then
  echo "[FAIL] Patched replay did not fail closed on the malformed XML" >&2
  sed -n '1,160p' "$PATCHED_LOG" >&2
  exit 1
fi

print_log_excerpt "Patched" "$PATCHED_LOG"
echo "[OK] Patched replay fails closed without sanitizer findings"
end_section

begin_section "6. Transaction conclusion"
write_report "$UNPATCHED_RC" "$PATCHED_RC"
sed -n '1,160p' "$REPORT_FILE"
echo "[OK] Complete transaction recorded at $REPORT_FILE"
end_section
