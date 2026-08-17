#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"

if [ -n "${COLORBLEED_TOOLS_DIR:-}" ]; then
  tools_dir="$COLORBLEED_TOOLS_DIR"
elif [ -x "$script_dir/iccToXml_unsafe" ]; then
  tools_dir="$script_dir"
else
  tools_dir="$script_dir/bin/sanitizer"
fi
input_icc="${1:-$script_dir/iccDEV/Testing/sRGB_v4_ICC_preference.icc}"
out_dir="${2:-/tmp/colorbleed-qa-$(date +%s)}"
input_tiff="${3:-$script_dir/test-data/1x1-rgb8--sRGB_v4_ICC_preference.tiff}"
expected_tiff_icc="$script_dir/iccDEV/Testing/sRGB_v4_ICC_preference.icc"

require_file() {
  local label="$1"
  local path="$2"

  if [ ! -f "$path" ]; then
    printf 'ColorBleed QA ERROR: missing %s: %s\n' "$label" "$path" >&2
    exit 66
  fi
}

require_file "input ICC profile" "$input_icc"
require_file "tracked TIFF extraction fixture" "$input_tiff"
require_file "expected embedded ICC profile" "$expected_tiff_icc"

mkdir -p "$out_dir"

scan_findings() {
  local log="$1"
  local out="$2"
  local pattern="runtime error:|ERROR: AddressSanitizer|SUMMARY: UndefinedBehaviorSanitizer|CRASH DETECTED|wall time limit exceeded|ABNORMAL EXIT"

  if command -v rg >/dev/null 2>&1; then
    rg -n "$pattern" "$log" >"$out"
  else
    grep -En "$pattern" "$log" >"$out"
  fi
}

run_tool() {
  local name="$1"
  shift
  local log="$out_dir/$name.log"

  set +e
  timeout 45 "$@" >"$log" 2>&1
  local rc=$?
  set -e

  printf '%-22s rc=%s\n' "$name" "$rc" | tee -a "$out_dir/summary.txt"
  if scan_findings "$log" "$out_dir/$name.findings"; then
    sed "s#^#$name:#" "$out_dir/$name.findings" >> "$out_dir/findings.txt"
  fi

  if [ "$rc" -ne 0 ]; then
    printf 'ColorBleed QA ERROR: %s failed; captured output follows:\n' "$name" >&2
    sed -n '1,120p' "$log" >&2
  fi

  return "$rc"
}

: >"$out_dir/summary.txt"
: >"$out_dir/findings.txt"

run_tool icc_to_xml "$tools_dir/iccToXml_unsafe" "$input_icc" "$out_dir/base.xml"
run_tool xml_to_icc "$tools_dir/iccFromXml_unsafe" "$out_dir/base.xml" "$out_dir/base-roundtrip.icc" -noid
run_tool icc_to_xml_again "$tools_dir/iccToXml_unsafe" "$out_dir/base-roundtrip.icc" "$out_dir/base-roundtrip.xml"
run_tool icc_to_json "$tools_dir/iccToJson_unsafe" "$out_dir/base-roundtrip.icc" "$out_dir/base.json"
run_tool json_to_icc "$tools_dir/iccFromJson_unsafe" "$out_dir/base.json" "$out_dir/base-json.icc" -noid
run_tool json_icc_to_xml "$tools_dir/iccToXml_unsafe" "$out_dir/base-json.icc" "$out_dir/base-json.xml"
run_tool dumpall "$tools_dir/iccDumpAll" --diag --read "$out_dir/base-roundtrip.icc" ALL
run_tool diagnostic "$tools_dir/iccDiagnosticLoad" --all --dump "$out_dir/base-roundtrip.icc"
rm -f "$out_dir/tiff-embedded.icc"
run_tool tiff_dump_extract "$tools_dir/iccTiffDump_unsafe" "$input_tiff" "$out_dir/tiff-embedded.icc"

if ! cmp -s "$out_dir/tiff-embedded.icc" "$expected_tiff_icc"; then
  echo "tiff_dump_extract: embedded ICC is not byte-identical to $expected_tiff_icc" >> "$out_dir/findings.txt"
fi

if [ -s "$out_dir/findings.txt" ]; then
  echo "ColorBleed QA findings:"
  sed -n '1,120p' "$out_dir/findings.txt"
  exit 1
fi

echo "ColorBleed QA clean: $out_dir"
