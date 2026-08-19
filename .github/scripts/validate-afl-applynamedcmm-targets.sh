#!/usr/bin/env bash
# Validate the AFL iccApplyNamedCmm target contracts without launching fuzzers.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=afl/targets.sh
source "$REPO_ROOT/afl/targets.sh"

scratch_root="$(mktemp -d /tmp/afl-applynamedcmm-contracts-XXXXXX)"
trap 'rm -rf -- "$scratch_root"' EXIT

AFL_BASE="$scratch_root/afl"
BIN_DIR="$REPO_ROOT/afl/bin"
errors=0

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

expect_arg_count() {
    local target="$1"
    local expected="$2"

    if [[ "${#AFL_ARGS[@]}" -ne "$expected" ]]; then
        fail "$target argv count: expected $expected, got ${#AFL_ARGS[@]}"
    fi
}

expect_arg() {
    local target="$1"
    local index="$2"
    local expected="$3"
    local actual="${AFL_ARGS[$index]:-}"

    expect_value "$target argv[$index]" "$actual" "$expected"
}

expect_common_hybrid_policy() {
    local target="$1"

    expect_value "$target seed ceiling" "$SEED_MAX_BYTES" "1048576"
    expect_value "$target seed dry run" "$SEED_DRY_RUN_TARGET" "1"
    expect_value "$target exit-zero dry run" "$SEED_DRY_RUN_REQUIRE_ZERO_TARGET" "1"
    expect_value "$target upstream seed depth" "$SEED_FIND_MAXDEPTH" "2"
    if [[ ! " ${SEED_DIRS[*]} " =~ [[:space:]]${ICCDEV_TESTING_DIR}[[:space:]] ]]; then
        fail "$target upstream Testing seed root is missing: $ICCDEV_TESTING_DIR"
    fi
    expect_arg "$target" 0 "-exportcfganddata"
    expect_arg "$target" 1 "${AFL_TMP_PREFIX}.json"
}

support_line="$(grep -nF 'afl_prepare_target_support_files ' "$REPO_ROOT/afl/start.sh" | cut -d: -f1)"
required_line="$(grep -nF 'for required_file in ' "$REPO_ROOT/afl/start.sh" | cut -d: -f1)"
if [[ -z "$support_line" || -z "$required_line" || "$support_line" -ge "$required_line" ]]; then
    fail "start.sh must prepare generated support before validating required files"
fi

for required_target in \
    applynamedcmm \
    applynamedcmm-cfg \
    applynamedcmm-hybrid-chain \
    applynamedcmm-hybrid-pcc; do
    matches=0
    for configured_target in "${AFL_TARGETS[@]}"; do
        if [[ "$configured_target" == "$required_target" ]]; then
            matches=$((matches + 1))
        fi
    done
    expect_value "$required_target inventory count" "$matches" "1"
done

afl_configure_target applynamedcmm
expect_arg_count applynamedcmm 5
expect_arg applynamedcmm 0 "$REPO_ROOT/docs/iccDEV/Tools/test-data/test-data-rgb-16bit.txt"
expect_arg applynamedcmm 1 "5"
expect_arg applynamedcmm 2 "1"
expect_arg applynamedcmm 3 "@@"
expect_arg applynamedcmm 4 "1"

afl_configure_target applynamedcmm-cfg
expect_arg_count applynamedcmm-cfg 2
expect_arg applynamedcmm-cfg 0 "-cfg"
expect_arg applynamedcmm-cfg 1 "@@"
expect_value "applynamedcmm-cfg input format" "$AFL_INPUT_FORMAT" "text"
expect_value "applynamedcmm-cfg max length" "$AFL_MAX_LENGTH" "65536"

afl_configure_target applynamedcmm-hybrid-chain
expect_common_hybrid_policy applynamedcmm-hybrid-chain
expect_arg_count applynamedcmm-hybrid-chain 9
expect_arg applynamedcmm-hybrid-chain 2 "$HYBRID_CMYK_DATA"
expect_arg applynamedcmm-hybrid-chain 3 "3"
expect_arg applynamedcmm-hybrid-chain 4 "1"
expect_arg applynamedcmm-hybrid-chain 5 "$HYBRID_CMYK_PROFILE"
expect_arg applynamedcmm-hybrid-chain 6 "10003"
expect_arg applynamedcmm-hybrid-chain 7 "@@"
expect_arg applynamedcmm-hybrid-chain 8 "10"

afl_configure_target applynamedcmm-hybrid-pcc
expect_common_hybrid_policy applynamedcmm-hybrid-pcc
expect_arg_count applynamedcmm-hybrid-pcc 17
expect_arg applynamedcmm-hybrid-pcc 2 "$HYBRID_CMYK_DATA"
expect_arg applynamedcmm-hybrid-pcc 3 "5"
expect_arg applynamedcmm-hybrid-pcc 4 "1"
expect_arg applynamedcmm-hybrid-pcc 5 "-ENV:bkgX"
expect_arg applynamedcmm-hybrid-pcc 6 "0.0985"
expect_arg applynamedcmm-hybrid-pcc 7 "-ENV:bkgY"
expect_arg applynamedcmm-hybrid-pcc 8 "0.159"
expect_arg applynamedcmm-hybrid-pcc 9 "-ENV:bkgZ"
expect_arg applynamedcmm-hybrid-pcc 10 "0.122"
expect_arg applynamedcmm-hybrid-pcc 11 "$HYBRID_CMYK_PROFILE"
expect_arg applynamedcmm-hybrid-pcc 12 "10003"
expect_arg applynamedcmm-hybrid-pcc 13 "-PCC"
expect_arg applynamedcmm-hybrid-pcc 14 "@@"
expect_arg applynamedcmm-hybrid-pcc 15 "$HYBRID_SPEC_D50"
expect_arg applynamedcmm-hybrid-pcc 16 "3"

if [[ "$errors" -ne 0 ]]; then
    echo "ApplyNamedCmm AFL target validation failed with $errors error(s)." >&2
    exit 1
fi

echo "ApplyNamedCmm AFL target validation passed: 4 target contracts."
