#!/usr/bin/env bash
# validate-afl-jpeg-seeds.sh - verify AFL JPEG targets use JPEG+ICC seeds only.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

TARGETS=(jpegdump jpegdump-inject)
EXPECTED_SOURCE="$REPO_ROOT/fuzz/graphics/jpg"
FAILURES=0
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
BIN_DIR="${AFL_BIN_DIR:-$REPO_ROOT/afl/bin}"

source "$REPO_ROOT/afl/targets.sh"

require_tool() {
    local tool="$1"

    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[FAIL] required tool missing: $tool" >&2
        exit 1
    fi
}

fail() {
    echo "[FAIL] $*" >&2
    FAILURES=$((FAILURES + 1))
}

validate_target_config() {
    local target="$1"

    if ! afl_configure_target "$target" >/dev/null; then
        fail "$target: target configuration failed"
        return
    fi

    if [[ "${SEED_REQUIRE_JPEG_ICC:-0}" -ne 1 ]]; then
        fail "$target: SEED_REQUIRE_JPEG_ICC must be 1"
    fi
    if [[ "${SEED_LIMIT:-}" != "200" ]]; then
        fail "$target: SEED_LIMIT must be 200, got ${SEED_LIMIT:-unset}"
    fi
    if [[ "${#SEED_FILES[@]}" -ne 0 ]]; then
        fail "$target: SEED_FILES must be empty for JPEG targets"
    fi
    if [[ "${#SEED_DIRS[@]}" -ne 1 || "${SEED_DIRS[0]}" != "$EXPECTED_SOURCE" ]]; then
        fail "$target: SEED_DIRS must be exactly $EXPECTED_SOURCE"
    fi
    if [[ "${SEED_INCLUDE_REGEX:-}" != '\.([Jj][Pp][Ee]?[Gg])$' ]]; then
        fail "$target: SEED_INCLUDE_REGEX must allow only .jpg/.jpeg"
    fi
    if [[ "${SEED_FILE_TYPE_REGEX:-}" != '^JPEG image data' ]]; then
        fail "$target: SEED_FILE_TYPE_REGEX must require JPEG image data"
    fi
}

validate_raw_icc_rejected() {
    local raw_icc="$REPO_ROOT/test-profiles/sRGB_D65_MAT.icc"

    if [[ ! -f "$raw_icc" ]]; then
        echo "[WARN] raw ICC negative fixture missing: $raw_icc"
        return 0
    fi

    case "$raw_icc" in
        *.jpg|*.jpeg|*.JPG|*.JPEG)
            fail "raw ICC negative fixture unexpectedly matches JPEG extension: $raw_icc"
            ;;
        *)
            echo "[OK] raw ICC negative fixture rejected by JPEG extension policy"
            ;;
    esac
}

validate_seed_file() {
    local seed_file="$1"
    local seed_type
    local icc_size

    case "$seed_file" in
        *.jpg|*.jpeg|*.JPG|*.JPEG) ;;
        *) fail "$seed_file: extension is not .jpg/.jpeg"; return ;;
    esac

    seed_type="$(file -b -- "$seed_file" 2>/dev/null || true)"
    case "$seed_type" in
        JPEG\ image\ data*) ;;
        *) fail "$seed_file: file(1) type is not JPEG: $seed_type"; return ;;
    esac

    icc_size="$(exiftool -b -ICC_Profile "$seed_file" 2>/dev/null | wc -c | tr -d ' ')"
    if [[ "${icc_size:-0}" -le 0 ]]; then
        fail "$seed_file: no extractable embedded ICC profile"
    fi
}

validate_input_dir() {
    local input_dir="$1"
    local count=0
    local seed_file

    [[ -d "$input_dir" ]] || return 0

    while IFS= read -r -d '' seed_file; do
        count=$((count + 1))
        validate_seed_file "$seed_file"
    done < <(find "$input_dir" -maxdepth 1 -type f -print0 2>/dev/null)

    if [[ "$count" -gt 200 ]]; then
        fail "$input_dir: staged seed count exceeds 200: $count"
    fi
    echo "[OK] $input_dir: $count staged seed(s) checked"
}

require_tool file
require_tool exiftool

for target in "${TARGETS[@]}"; do
    validate_target_config "$target"
done

validate_raw_icc_rejected
validate_input_dir "$REPO_ROOT/afl/afl-jpegdump/input"
validate_input_dir "$REPO_ROOT/afl/afl-jpegdump-inject/input"

if [[ "$FAILURES" -ne 0 ]]; then
    echo "[FAIL] AFL JPEG seed validation failed: $FAILURES issue(s)" >&2
    exit 1
fi

echo "[OK] AFL JPEG target seed policy verified"
