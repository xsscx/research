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

expect_arg() {
    local target="$1"
    local index="$2"
    local expected="$3"

    expect_value "$target argv[$index]" "${AFL_ARGS[$index]:-}" "$expected"
}

check_apply_argc() {
    local target="$1"
    local expected="$2"

    afl_configure_target "$target"
    expect_value "$target argc" "${#AFL_ARGS[@]}" "$expected"
}

for target in "${AFL_TARGETS[@]}"; do
    if ! afl_configure_target "$target"; then
        fail "$target did not configure"
        continue
    fi
    if [[ -z "$BINARY" || -z "$AFL_DIR" || -z "$AFL_WORK_DIR" ]]; then
        fail "$target left a required path empty"
    fi
    if [[ "$(basename "$BINARY")" == iccApply* ||
          "$(basename "$BINARY")" == "iccBenchApply" ]]; then
        testcase_args=0
        for configured_arg in "${AFL_ARGS[@]}"; do
            if [[ "$configured_arg" == "@@" ]]; then
                testcase_args=$((testcase_args + 1))
            fi
        done
        if [[ "${#AFL_ARGS[@]}" -eq 0 ]]; then
            fail "$target has no argv in $AFL_ICCAPPLY_ARGS_CONFIG"
        elif [[ "$testcase_args" -ne 1 ]]; then
            fail "$target must have exactly one @@ argument in $AFL_ICCAPPLY_ARGS_CONFIG"
        fi
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

check_apply_argc benchapply 7
check_apply_argc applynamedcmm 5
check_apply_argc applynamedcmm-v5-brdf 5
check_apply_argc applynamedcmm-debugcalc 6
check_apply_argc applynamedcmm-cfg 2
check_apply_argc applynamedcmm-hybrid-chain 9
check_apply_argc applynamedcmm-hybrid-pcc 17
check_apply_argc applyprofiles 9
check_apply_argc applyprofiles-fast 9
check_apply_argc applyprofiles-deep 9
check_apply_argc applyprofiles-cfg 4
check_apply_argc applyprofiles-hybrid-embedded 13
check_apply_argc applyprofiles-hybrid-pcc 15
check_apply_argc applyprofiles-row 11
check_apply_argc applysearch 11
check_apply_argc applysearch-noinit 7
check_apply_argc applysearch-cfg 2
check_apply_argc applysearch-fast 11
check_apply_argc applysearch-hybrid-pcc 21
check_apply_argc applysearch-weight-positive 11
check_apply_argc applysearch-weight-positive-fast 11
check_apply_argc applysearch-weight-zero 11
check_apply_argc applysearch-weight-negative 11
check_apply_argc applysearch-weight-nan 11
check_apply_argc applytolink 13
check_apply_argc applytolink-v5 13
check_apply_argc applytolink-cube 11

afl_configure_target benchapply
expect_value "BenchApply binary" "$(basename "$BINARY")" "iccBenchApply"
expect_value "BenchApply argv count" "${#AFL_ARGS[@]}" "7"
expect_value "BenchApply fuzzed profile argument" "${AFL_ARGS[5]}" "@@"
expect_value "BenchApply BPC and luminance intent" "${AFL_ARGS[6]}" "140"
expect_value "BenchApply exit-zero dry run" "$SEED_DRY_RUN_REQUIRE_ZERO_TARGET" "1"

afl_configure_target applynamedcmm-v5-brdf
expect_arg applynamedcmm-v5-brdf 1 "6"
expect_arg applynamedcmm-v5-brdf 2 "1"
expect_arg applynamedcmm-v5-brdf 4 "10063"
expect_value "V5 BRDF seed" "${SEED_FILES[0]}" "$REPO_ROOT/extended-test-profiles/tag-checks/dtob-brdf.icc"

afl_configure_target applynamedcmm-debugcalc
expect_value "debugcalc bootstrap seed" "${SEED_FILES[0]}" "$REPO_ROOT/test-profiles/argbCalc.icc"

afl_configure_target applynamedcmm-hybrid-chain
expect_arg applynamedcmm-hybrid-chain 6 "10103"
expect_value "spectral chain bootstrap seed" "${SEED_FILES[0]}" "$HYBRID_SPEC_D50"

afl_configure_target applyprofiles-deep
expect_arg applyprofiles-deep 2 "2"
expect_arg applyprofiles-deep 3 "1"
expect_arg applyprofiles-deep 4 "0"
expect_arg applyprofiles-deep 5 "1"
expect_arg applyprofiles-deep 6 "1"
expect_arg applyprofiles-deep 8 "12"

afl_configure_target applysearch-noinit
expect_value "no-init bootstrap seed" "${SEED_FILES[0]}" "$REPO_ROOT/test-profiles/sRGB_v4_ICC_preference.icc"

afl_configure_target applysearch-fast
expect_arg applysearch-fast 1 "4"
expect_arg applysearch-fast 2 "0"

for target in applysearch-weight-positive applysearch-weight-zero applysearch-weight-negative applysearch-weight-nan; do
    afl_configure_target "$target"
    expect_arg "$target" 0 "$REPO_ROOT/docs/Testing/test-data/rgb-8bit.txt"
done

afl_configure_target applytolink-v5
expect_value "ApplyToLink V5 bootstrap seed" "${SEED_FILES[0]}" "$REPO_ROOT/test-profiles/sRGB_v4_ICC_preference.icc"

AFL_MAX_LENGTH=""
afl_configure_target applyprofiles-hybrid-embedded
expect_value "hybrid embedded seed count" "${#SEED_FILES[@]}" "1"
expect_value "hybrid embedded full-size seed" "${SEED_FILES[0]}" "$HYBRID_MS_TIFF"
expect_value "hybrid embedded seed ceiling" "$SEED_MAX_BYTES" "3145728"
expect_value "hybrid embedded generator ceiling" "$AFL_MAX_LENGTH" "3145728"
expect_value "hybrid embedded dry-run timeout" "$SEED_DRY_RUN_TIMEOUT" "15"
expect_value "hybrid embedded AFL timeout" "$AFL_TARGET_TIMEOUT" "15000"
expect_value "hybrid embedded exit-zero dry run" "$SEED_DRY_RUN_REQUIRE_ZERO_TARGET" "1"
expect_value "hybrid embedded fast calibration" "$AFL_FAST_CAL_TARGET" "1"
expect_value "hybrid embedded expanded havoc" "$AFL_EXPAND_HAVOC_TARGET" "1"
expect_value "hybrid embedded deterministic skip" "$AFL_SKIP_DETERMINISTIC_TARGET" "1"

for target in applynamedcmm-cfg applyprofiles-cfg applysearch-cfg; do
    afl_configure_target "$target"
    expect_value "$target isolated work flag" "$ISOLATED_WORK_NEEDS_SUPPORT" "1"
    if [[ "$AFL_WORK_DIR" != "$AFL_BASE/work/"*"/root" ]]; then
        fail "$target work directory is not isolated under AFL_BASE/work: $AFL_WORK_DIR"
    fi
    if [[ "$AFL_WORK_DIR" == "$REPO_ROOT" ]]; then
        fail "$target must not run config-controlled outputs from the repository root"
    fi
done

afl_configure_target applyprofiles-hybrid-pcc
expect_value "hybrid PCC seed file count" "${#SEED_FILES[@]}" "1"
expect_value "hybrid PCC compatible seed" "${SEED_FILES[0]}" "$HYBRID_ICC_DIR/MultSpectralRGB.icc"
expect_value "hybrid PCC seed directory count" "${#SEED_DIRS[@]}" "0"
expect_value "hybrid PCC dry-run timeout" "$SEED_DRY_RUN_TIMEOUT" "15"
expect_value "hybrid PCC AFL timeout" "$AFL_TARGET_TIMEOUT" "15000"
if [[ "${AFL_ARGS[1]}" != *"${AFL_TMP_PREFIX}"* ]]; then
    fail "hybrid PCC export config path is not process-specific: ${AFL_ARGS[1]}"
fi

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
