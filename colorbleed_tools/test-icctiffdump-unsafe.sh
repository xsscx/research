#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source_icc="${COLORBLEED_TEST_ICC:-$script_dir/iccDEV/Testing/sRGB_v4_ICC_preference.icc}"
no_profile_tiff="${COLORBLEED_NO_PROFILE_TIFF:-$script_dir/../docs/Testing/test-data/rgb-4x4-8bit.tif}"
out_root="${COLORBLEED_TIFF_TEST_OUTDIR:-$(mktemp -d)}"
configs="${COLORBLEED_CONFIGS:-release debug sanitizer}"
timeout_seconds="${COLORBLEED_TIMEOUT_SECONDS:-45}"
failures=0
passes=0

require() {
    local path="$1"
    if [ ! -e "$path" ]; then
        printf '[FAIL] missing required path: %s\n' "$path" >&2
        exit 66
    fi
}

for command_name in cmp jq python3 rg sha256sum timeout; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf '[FAIL] missing required command: %s\n' "$command_name" >&2
        exit 69
    fi
done
require "$source_icc"
require "$no_profile_tiff"

mkdir -p "$out_root/fixtures"
python3 "$script_dir/generate-tiff-regression-fixtures.py" \
    --source-icc "$source_icc" --out-dir "$out_root/fixtures"
printf 'config\tcase\texit_code\tresult\n' >"$out_root/results.tsv"

record() {
    local config="$1"
    local case_name="$2"
    local rc="$3"
    local result="$4"
    printf '%s\t%s\t%s\t%s\n' "$config" "$case_name" "$rc" "$result" \
        >>"$out_root/results.tsv"
    if [ "$result" = PASS ]; then
        passes=$((passes + 1))
    else
        failures=$((failures + 1))
        printf '[FAIL] %s/%s rc=%s\n' "$config" "$case_name" "$rc" >&2
    fi
}

check() {
    local config="$1"
    local case_name="$2"
    local message="$3"
    shift 3
    if ! "$@" >/dev/null; then
        record "$config" "$case_name:$message" - FAIL
    fi
}

run_case() {
    local config="$1"
    local case_name="$2"
    local expected_rc="$3"
    shift 3
    local case_dir="$out_root/$config/$case_name"
    local rc=0
    mkdir -p "$case_dir"
    if env COLORBLEED_STRICT_SANITIZERS=1 timeout "$timeout_seconds" "$@" \
        >"$case_dir/stdout" 2>"$case_dir/stderr"; then
        rc=0
    else
        rc=$?
    fi
    printf '%s' "$rc" >"$case_dir/exit-code"
    if [ "$rc" -eq "$expected_rc" ]; then
        record "$config" "$case_name" "$rc" PASS
    else
        record "$config" "$case_name" "$rc" FAIL
    fi
}

for config in $configs; do
    tool="$script_dir/bin/$config/iccTiffDump_unsafe"
    require "$tool"
    config_dir="$out_root/$config"
    mkdir -p "$config_dir"

    valid_out="$config_dir/valid.icc"
    run_case "$config" valid 0 "$tool" --evidence-json \
        "$out_root/fixtures/valid.tif" "$valid_out"
    check "$config" valid evidence jq -e '.schema == "colorbleed-tiff-evidence/v1" and
        .outcome == "clean" and .tiff.directoriesRead == 1 and
        .tiff.iccDirectories == 1 and .tiff.selectedDirectory == 0 and
        .icc.extracted == true and .icc.opened == true and
        .icc.tagsLoaded == true and .icc.validation == "valid" and
        .sandbox.exitCode == 0 and .sandbox.crashed == false' \
        "$config_dir/valid/stdout"
    check "$config" valid byte-equality cmp -s "$source_icc" "$valid_out"
    check "$config" valid digest test \
        "$(jq -r .icc.sha256 "$config_dir/valid/stdout")" = \
        "$(sha256sum "$source_icc" | awk '{print $1}')"

    run_case "$config" no-profile 0 "$tool" --evidence-json "$no_profile_tiff"
    check "$config" no-profile evidence jq -e \
        '.tiff.iccDirectories == 0 and .icc.extracted == false and
        .icc.sha256 == null and .sandbox.exitCode == 0' \
        "$config_dir/no-profile/stdout"

    run_case "$config" missing-input 66 "$tool" --evidence-json \
        "$out_root/fixtures/does-not-exist.tif"
    check "$config" missing-input evidence jq -e \
        '.outcome == "soft-failure" and .sandbox.exitCode == 66 and
         .tiff.directoriesRead == 0 and .icc.extracted == false' \
        "$config_dir/missing-input/stdout"

    no_profile_out="$config_dir/no-profile.icc"
    run_case "$config" no-profile-export 3 "$tool" --evidence-json \
        "$no_profile_tiff" "$no_profile_out"
    check "$config" no-profile-export no-output test ! -e "$no_profile_out"
    check "$config" no-profile-export evidence jq -e \
        '.outcome == "soft-failure" and .sandbox.exitCode == 3' \
        "$config_dir/no-profile-export/stdout"

    malformed_out="$config_dir/malformed.icc"
    run_case "$config" malformed 4 "$tool" --evidence-json \
        "$out_root/fixtures/malformed.tif" "$malformed_out"
    check "$config" malformed byte-equality cmp -s \
        "$out_root/fixtures/malformed.icc" "$malformed_out"
    check "$config" malformed evidence jq -e \
        '.icc.extracted == true and .icc.opened == false and
         .sandbox.exitCode == 4' "$config_dir/malformed/stdout"

    noncompliant_out="$config_dir/noncompliant.icc"
    run_case "$config" noncompliant 6 "$tool" --evidence-json \
        "$out_root/fixtures/noncompliant.tif" "$noncompliant_out"
    check "$config" noncompliant byte-equality cmp -s \
        "$out_root/fixtures/noncompliant.icc" "$noncompliant_out"
    check "$config" noncompliant evidence jq -e '.icc.extracted == true and
        (.icc.validation == "non-compliant" or .icc.validation == "critical-error") and
        .sandbox.exitCode == 6' "$config_dir/noncompliant/stdout"

    nested_out="$config_dir/nested.icc"
    run_case "$config" nested-depth-512 5 "$tool" --evidence-json \
        "$out_root/fixtures/nested-depth-512.tif" "$nested_out"
    check "$config" nested-depth-512 byte-equality cmp -s \
        "$out_root/fixtures/nested-depth-512.icc" "$nested_out"
    check "$config" nested-depth-512 evidence jq -e \
        '.icc.extracted == true and .icc.opened == true and
        .icc.tagsLoaded == false and .sandbox.exitCode == 5' \
        "$config_dir/nested-depth-512/stdout"

    multiple_out="$config_dir/multiple.icc"
    run_case "$config" multiple-icc 0 "$tool" --evidence-json \
        "$out_root/fixtures/multiple-icc.tif" "$multiple_out"
    check "$config" multiple-icc byte-equality cmp -s "$source_icc" "$multiple_out"
    check "$config" multiple-icc evidence jq -e \
        '.tiff.directoriesRead == 2 and .tiff.iccDirectories == 2 and
         .tiff.selectedDirectory == 0' "$config_dir/multiple-icc/stdout"

    run_case "$config" truncated-chain 8 "$tool" --evidence-json \
        "$out_root/fixtures/truncated-chain.tif" "$config_dir/truncated.icc"
    check "$config" truncated-chain no-output test ! -e "$config_dir/truncated.icc"
    check "$config" truncated-chain evidence jq -e \
        '.sandbox.exitCode == 8 and .tiff.errors > 0 and
         .icc.extracted == false' "$config_dir/truncated-chain/stdout"

    existing_out="$config_dir/existing.icc"
    printf 'sentinel' >"$existing_out"
    run_case "$config" existing-output 7 "$tool" --evidence-json \
        "$out_root/fixtures/valid.tif" "$existing_out"
    check "$config" existing-output unchanged test "$(cat "$existing_out")" = sentinel
    if find "$config_dir" -maxdepth 1 -name '*.tmp-*' -print -quit | rg -q .; then
        record "$config" existing-output:temporary-leak - FAIL
    fi

    run_case "$config" escaped-description 0 "$tool" --verbose \
        "$out_root/fixtures/escaped-description.tif"
    check "$config" escaped-description escaped-text rg -F \
        'bad\n\x1B[31mX!!' "$config_dir/escaped-description/stdout"
    if rg -q "$(printf '\033')" "$config_dir/escaped-description/stdout" \
        "$config_dir/escaped-description/stderr"; then
        record "$config" escaped-description:control-byte - FAIL
    fi

    odd_path="$out_root/fixtures/name_with_"$'\n'"newline-$config.tif"
    cp "$out_root/fixtures/valid.tif" "$odd_path"
    run_case "$config" escaped-path 0 "$tool" --verbose "$odd_path"
    check "$config" escaped-path escaped-text rg -F \
        "name_with_\\nnewline-$config.tif" "$config_dir/escaped-path/stdout"

    oversize_out="$config_dir/oversize.icc"
    run_case "$config" oversize-limit 9 env COLORBLEED_MAX_ICC_BYTES=1024 \
        "$tool" --evidence-json "$out_root/fixtures/valid.tif" "$oversize_out"
    check "$config" oversize-limit no-output test ! -e "$oversize_out"
    check "$config" oversize-limit evidence jq -e \
        '.icc.tooLarge == true and .icc.extracted == false and
        .sandbox.exitCode == 9' "$config_dir/oversize-limit/stdout"

    if rg -n 'runtime error:|ERROR: AddressSanitizer|SUMMARY: UndefinedBehaviorSanitizer|CRASH DETECTED' \
        "$config_dir" >"$config_dir/sanitizer-findings.txt"; then
        record "$config" sanitizer-findings - FAIL
    fi
done

printf 'output_root=%s\n' "$out_root"
printf 'passes=%s failures=%s\n' "$passes" "$failures"
if [ "$failures" -ne 0 ]; then
    exit 1
fi
printf '[OK] iccTiffDump_unsafe regression suite passed\n'
