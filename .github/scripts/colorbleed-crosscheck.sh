#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
colorbleed_dir="$repo_root/colorbleed_tools"
source_icc="${1:-$colorbleed_dir/iccDEV/Testing/sRGB_v4_ICC_preference.icc}"
source_tiff="${2:-$colorbleed_dir/test-data/1x1-rgb8--sRGB_v4_ICC_preference.tiff}"
out_root="${3:-$(mktemp -d)}"
configs="${COLORBLEED_CONFIGS:-release debug sanitizer}"
timeout_seconds="${COLORBLEED_TIMEOUT_SECONDS:-45}"
failures=0

require_file() {
    local label="$1"
    local path="$2"

    if [ ! -f "$path" ]; then
        printf '[FAIL] missing %s: %s\n' "$label" "$path" >&2
        exit 66
    fi
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf '[FAIL] required command not found: %s\n' "$1" >&2
        exit 69
    fi
}

run_tool() {
    local config="$1"
    local label="$2"
    shift 2
    local log="$out_root/$config/$label.log"
    local rc=0

    if env COLORBLEED_STRICT_SANITIZERS=1 timeout "$timeout_seconds" "$@" \
        >"$log" 2>&1; then
        rc=0
    else
        rc=$?
        failures=$((failures + 1))
    fi

    printf '%s\t%s\t%s\n' "$config" "$label" "$rc" >>"$out_root/commands.tsv"
    if [ "$rc" -ne 0 ]; then
        printf '[FAIL] %s/%s exited %s; log: %s\n' "$config" "$label" "$rc" "$log" >&2
    fi
}

file_size() {
    stat -c '%s' "$1"
}

byte_diff_count() {
    local left="$1"
    local right="$2"
    local output="$3"

    cmp -l "$left" "$right" >"$output" 2>/dev/null || true
    wc -l <"$output"
}

profile_id() {
    dd if="$1" bs=1 skip=84 count=16 status=none | xxd -p -c 32
}

for command_name in cmp dd jq sha256sum stat timeout wc xxd xmllint; do
    require_command "$command_name"
done
require_file "source ICC profile" "$source_icc"
require_file "source TIFF fixture" "$source_tiff"

mkdir -p "$out_root"
printf 'config\tstep\texit_code\n' >"$out_root/commands.tsv"
printf 'config\tsource_icc_bytes\txml_icc_bytes\txml_icc_delta\txml_icc_byte_diffs\tjson_icc_bytes\tjson_icc_delta\tjson_icc_byte_diffs\txml_c14n_equal\tjson_semantic_equal\ttiff_icc_equal\tsource_profile_id\txml_profile_id\tjson_profile_id\n' >"$out_root/metrics.tsv"

for config in $configs; do
    tools_dir="$colorbleed_dir/bin/$config"
    config_out="$out_root/$config"
    mkdir -p "$config_out"

    for tool in iccToXml_unsafe iccFromXml_unsafe iccToJson_unsafe \
        iccFromJson_unsafe iccTiffDump_unsafe iccDumpAll iccDiagnosticLoad; do
        if [ ! -x "$tools_dir/$tool" ]; then
            printf '[FAIL] missing %s tool: %s\n' "$config" "$tools_dir/$tool" >&2
            exit 69
        fi
    done

    run_tool "$config" icc_to_xml "$tools_dir/iccToXml_unsafe" \
        "$source_icc" "$config_out/source.xml"
    run_tool "$config" xml_to_icc "$tools_dir/iccFromXml_unsafe" \
        "$config_out/source.xml" "$config_out/xml-return.icc" -noid
    run_tool "$config" xml_return_to_xml "$tools_dir/iccToXml_unsafe" \
        "$config_out/xml-return.icc" "$config_out/xml-return.xml"

    run_tool "$config" icc_to_json "$tools_dir/iccToJson_unsafe" \
        "$source_icc" "$config_out/source.json"
    run_tool "$config" json_to_icc "$tools_dir/iccFromJson_unsafe" \
        "$config_out/source.json" "$config_out/json-return.icc" -noid
    run_tool "$config" json_return_to_json "$tools_dir/iccToJson_unsafe" \
        "$config_out/json-return.icc" "$config_out/json-return.json"
    run_tool "$config" json_return_to_xml "$tools_dir/iccToXml_unsafe" \
        "$config_out/json-return.icc" "$config_out/json-return.xml"

    run_tool "$config" dump_xml_return "$tools_dir/iccDumpAll" --diag --read \
        "$config_out/xml-return.icc" ALL
    run_tool "$config" dump_json_return "$tools_dir/iccDumpAll" --diag --read \
        "$config_out/json-return.icc" ALL
    run_tool "$config" validate_xml_return "$tools_dir/iccDumpAll" --diag -v \
        "$config_out/xml-return.icc" ALL
    run_tool "$config" validate_json_return "$tools_dir/iccDumpAll" --diag -v \
        "$config_out/json-return.icc" ALL
    run_tool "$config" diagnose_xml_return "$tools_dir/iccDiagnosticLoad" --all --dump \
        "$config_out/xml-return.icc"
    run_tool "$config" diagnose_json_return "$tools_dir/iccDiagnosticLoad" --all --dump \
        "$config_out/json-return.icc"
    run_tool "$config" tiff_extract "$tools_dir/iccTiffDump_unsafe" \
        "$source_tiff" "$config_out/tiff-extracted.icc"

    xmllint --c14n "$config_out/source.xml" >"$config_out/source.c14n.xml"
    xmllint --c14n "$config_out/xml-return.xml" >"$config_out/xml-return.c14n.xml"
    jq -S . "$config_out/source.json" >"$config_out/source.canonical.json"
    jq -S . "$config_out/json-return.json" >"$config_out/json-return.canonical.json"

    xml_equal=no
    json_equal=no
    tiff_equal=no
    cmp -s "$config_out/source.c14n.xml" "$config_out/xml-return.c14n.xml" && xml_equal=yes
    cmp -s "$config_out/source.canonical.json" "$config_out/json-return.canonical.json" && json_equal=yes
    cmp -s "$source_icc" "$config_out/tiff-extracted.icc" && tiff_equal=yes

    source_size="$(file_size "$source_icc")"
    xml_size="$(file_size "$config_out/xml-return.icc")"
    json_size="$(file_size "$config_out/json-return.icc")"
    xml_diffs="$(byte_diff_count "$source_icc" "$config_out/xml-return.icc" "$config_out/xml-return.cmp")"
    json_diffs="$(byte_diff_count "$source_icc" "$config_out/json-return.icc" "$config_out/json-return.cmp")"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$config" "$source_size" "$xml_size" "$((xml_size - source_size))" "$xml_diffs" \
        "$json_size" "$((json_size - source_size))" "$json_diffs" \
        "$xml_equal" "$json_equal" "$tiff_equal" \
        "$(profile_id "$source_icc")" "$(profile_id "$config_out/xml-return.icc")" \
        "$(profile_id "$config_out/json-return.icc")" >>"$out_root/metrics.tsv"

    if rg -n 'runtime error:|ERROR: AddressSanitizer|SUMMARY: UndefinedBehaviorSanitizer|CRASH DETECTED|wall time limit exceeded' \
        "$config_out"/*.log >"$config_out/sanitizer-findings.txt"; then
        failures=$((failures + 1))
        printf '[FAIL] sanitizer finding in %s; see %s\n' "$config" \
            "$config_out/sanitizer-findings.txt" >&2
    fi
done

reference_config="${configs%% *}"
for config in $configs; do
    [ "$config" = "$reference_config" ] && continue
    for artifact in source.xml xml-return.icc xml-return.xml source.json \
        json-return.icc json-return.json json-return.xml tiff-extracted.icc; do
        if ! cmp -s "$out_root/$reference_config/$artifact" "$out_root/$config/$artifact"; then
            failures=$((failures + 1))
            printf '[FAIL] cross-config delta: %s differs between %s and %s\n' \
                "$artifact" "$reference_config" "$config" >&2
        fi
    done
done

printf 'output_root=%s\n' "$out_root"
printf 'failures=%s\n' "$failures"
cat "$out_root/metrics.tsv"

if [ "$failures" -ne 0 ]; then
    exit 1
fi
