#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source_icc="${COLORBLEED_JPEG_TEST_ICC:-$script_dir/../test-profiles/Lab_float-IllumA_2deg-Part2.icc}"
out_root="${COLORBLEED_JPEG_TEST_OUTDIR:-$(mktemp -d)}"
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

for command_name in cmp python3 rg timeout; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf '[FAIL] missing required command: %s\n' "$command_name" >&2
        exit 69
    fi
done
require "$source_icc"

mkdir -p "$out_root/fixtures"
python3 "$script_dir/generate-jpeg-icc-regression-fixtures.py" \
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
    tool="$script_dir/bin/$config/iccJpegDump_unsafe"
    require "$tool"
    config_dir="$out_root/$config"
    mkdir -p "$config_dir"

    valid_out="$config_dir/valid.icc"
    run_case "$config" valid 0 "$tool" --strict \
        "$out_root/fixtures/valid-chunks.jpg" "$valid_out"
    check "$config" valid byte-equality cmp -s "$source_icc" "$valid_out"
    check "$config" valid assembly rg -F "ICC assembly: strict sequence order" \
        "$config_dir/valid/stdout"

    recovered_out="$config_dir/recovered.icc"
    run_case "$config" forensic-recovery 10 "$tool" --forensic \
        "$out_root/fixtures/malformed-sequence.jpg" "$recovered_out"
    check "$config" forensic-recovery byte-equality cmp -s \
        "$source_icc" "$recovered_out"
    check "$config" forensic-recovery assembly rg -F \
        "ICC assembly: physical-order forensic recovery" \
        "$config_dir/forensic-recovery/stdout"

    strict_out="$config_dir/strict-reject.icc"
    run_case "$config" strict-reject 8 "$tool" --strict \
        "$out_root/fixtures/malformed-sequence.jpg" "$strict_out"
    check "$config" strict-reject no-output test ! -e "$strict_out"

    no_profile_out="$config_dir/no-profile.icc"
    run_case "$config" no-profile 3 "$tool" --forensic \
        "$out_root/fixtures/no-profile.jpg" "$no_profile_out"
    check "$config" no-profile no-output test ! -e "$no_profile_out"

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
printf '[OK] iccJpegDump_unsafe regression suite passed\n'
