#!/usr/bin/env bash
# Validate every registered AFL target configuration without launching fuzzers.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=afl/targets.sh
source "$REPO_ROOT/afl/targets.sh"

LOCAL_AUDIT=0
if [[ "${1:-}" == "--local" ]]; then
    LOCAL_AUDIT=1
elif [[ $# -gt 0 ]]; then
    echo "Usage: $0 [--local]" >&2
    exit 1
fi

scratch_root="$(mktemp -d /tmp/afl-target-contracts-XXXXXX)"
trap 'rm -rf -- "$scratch_root"' EXIT

AFL_BASE="$scratch_root/afl"
BIN_DIR="$REPO_ROOT/afl/bin"
errors=0
declare -A configured_dirs=()

fail() {
    echo "ERROR: $*" >&2
    errors=$((errors + 1))
}

expect_value() {
    local label="$1"
    local actual="$2"
    local expected="$3"

    if [[ "$actual" != "$expected" ]]; then
        fail "$label: expected '$expected', got '$actual'"
    fi
}

for target in "${AFL_TARGETS[@]}"; do
    if ! afl_configure_target "$target"; then
        fail "$target did not configure"
        continue
    fi
    if [[ -z "$BINARY" || -z "$AFL_DIR" || -z "$AFL_WORK_DIR" ]]; then
        fail "$target left a required path empty"
    fi
    if [[ ! "$SEED_MAX_BYTES" =~ ^[0-9]+$ ||
          ! "$SEED_LIMIT" =~ ^[0-9]+$ ||
          ! "$SEED_FIND_MAXDEPTH" =~ ^[0-9]+$ ||
          ! "$SEED_DRY_RUN_TIMEOUT" =~ ^[0-9]+$ ||
          ! "$AFL_TARGET_TIMEOUT" =~ ^[0-9]+$ ]]; then
        fail "$target has a non-numeric seed or timeout policy"
    fi
    if [[ -n "${configured_dirs[$AFL_DIR]:-}" ]]; then
        fail "$target shares AFL_DIR with ${configured_dirs[$AFL_DIR]}: $AFL_DIR"
    else
        configured_dirs[$AFL_DIR]="$target"
    fi
    if [[ "$LOCAL_AUDIT" -eq 1 ]]; then
        existing_seed_dirs=0
        if [[ ! -x "$BINARY" ]]; then
            fail "$target binary is missing or not executable: $BINARY"
        fi
        if ! afl_prepare_target_support_files "$target"; then
            fail "$target support preparation failed"
            continue
        fi
        if [[ -n "$DICT" && ! -f "$DICT" ]]; then
            fail "$target dictionary is missing: $DICT"
        fi
        for configured_path in "${REQUIRED_FILES[@]}" "${SEED_FILES[@]}"; do
            if [[ ! -e "$configured_path" ]]; then
                fail "$target configured file is missing: $configured_path"
            fi
        done
        for configured_path in "${SEED_DIRS[@]}"; do
            if [[ -d "$configured_path" ]]; then
                existing_seed_dirs=$((existing_seed_dirs + 1))
            fi
        done
        if [[ "${#SEED_DIRS[@]}" -gt 0 && "$existing_seed_dirs" -eq 0 ]]; then
            fail "$target has no available configured seed directory"
        fi
    fi
done

AFL_MAX_LENGTH=""
afl_configure_target applyprofiles-hybrid-embedded
expect_value "hybrid embedded seed count" "${#SEED_FILES[@]}" "1"
expect_value "hybrid embedded full-size seed" "${SEED_FILES[0]}" "$HYBRID_MS_TIFF"
expect_value "hybrid embedded seed ceiling" "$SEED_MAX_BYTES" "3145728"
expect_value "hybrid embedded generator ceiling" "$AFL_MAX_LENGTH" "3145728"
expect_value "hybrid embedded dry-run timeout" "$SEED_DRY_RUN_TIMEOUT" "15"
expect_value "hybrid embedded AFL timeout" "$AFL_TARGET_TIMEOUT" "15000"
expect_value "hybrid embedded exit-zero dry run" "$SEED_DRY_RUN_REQUIRE_ZERO_TARGET" "1"

if grep -q 'MS_smCows_64x64' "$REPO_ROOT/afl/targets.sh"; then
    fail "cropped hybrid seed path remains in afl/targets.sh"
fi

if [[ "$errors" -ne 0 ]]; then
    echo "AFL target configuration validation failed with $errors error(s)." >&2
    exit 1
fi

if [[ "$LOCAL_AUDIT" -eq 1 ]]; then
    echo "AFL local target and asset validation passed: ${#AFL_TARGETS[@]} targets."
else
    echo "AFL target configuration validation passed: ${#AFL_TARGETS[@]} targets."
fi
