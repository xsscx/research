#!/usr/bin/env bash
# Validate shared AFL/CFL JSON-config and control-trailer contracts.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
cfl_dir="$repo_root/cfl"
fixture="$repo_root/docs/Testing/json-configs/connect-config-complete.json"
dictionary="$cfl_dir/icc_cfg.dict"
cfg_fuzzer="$cfl_dir/icc_cfg_fuzzer.cpp"
connect_fuzzer="$cfl_dir/icc_connect_fuzzer.cpp"

while IFS= read -r fuzzer; do
    source_file="$cfl_dir/$fuzzer.cpp"
    if [[ ! -s "$source_file" ]]; then
        echo "[FAIL] Missing active CFL source: $source_file" >&2
        exit 1
    fi
    grep -Fq 'Redistribution and use in source and binary forms' "$source_file"
    grep -Fq 'THIS SOFTWARE IS PROVIDED' "$source_file"
done < <(
    # shellcheck source=cfl/fuzzers.sh
    source "$cfl_dir/fuzzers.sh"
    cfl_list_fuzzers
)

python3 -m json.tool "$fixture" >/dev/null
for key in dataFiles imageFiles connect createLink profileSequence searchApply \
    initial pccWeights colorData data; do
    grep -Fq "\"$key\"" "$fixture"
    grep -Fq "\\\"$key\\\"" "$dictionary"
done

for config_type in CIccCfgDataApply CIccCfgImageApply CIccCfgConnectOptions \
    CIccCfgCreateLink CIccCfgProfile CIccCfgProfileSequence CIccCfgPccWeight \
    CIccCfgSearchApply CIccCfgDataEntry CIccCfgColorData; do
    grep -Fq "ExerciseRoundTrip<$config_type>" "$cfg_fuzzer"
done
grep -Fq 'SectionOrRoot(root, "imageFiles")' "$cfg_fuzzer"
grep -Fq 'json::parse(data, data + size' "$cfg_fuzzer"
if grep -Fq 'uint8_t selector = data[0]' "$cfg_fuzzer"; then
    echo "[FAIL] CFL config inputs must remain ordinary JSON documents" >&2
    exit 1
fi

grep -Fq 'ReadBigEndian32(data)' "$connect_fuzzer"
grep -Fq 'size - profile_size >= 4' "$connect_fuzzer"
grep -Fq 'data + profile_size' "$connect_fuzzer"
if grep -Fq 'const size_t profile_size = size - 4' "$connect_fuzzer"; then
    echo "[FAIL] Connect controls must not truncate raw ICC seeds" >&2
    exit 1
fi

grep -Fq 'connect-config-complete.json' "$cfl_dir/fuzzers.sh"
if grep -Fq "printf '\\001'" "$cfl_dir/fuzzers.sh"; then
    echo "[FAIL] CFL config seed installation still prepends a selector" >&2
    exit 1
fi

for target in applynamedcmm-cfg applyprofiles-cfg applysearch-cfg; do
    grep -Fq "$target" "$repo_root/afl/targets.sh"
done
if [[ "$(grep -Fc 'connect-config-complete' "$repo_root/afl/targets.sh")" -lt 3 ]]; then
    echo "[FAIL] Every AFL config lane must admit the complete config seed" >&2
    exit 1
fi

echo "[PASS] AFL/CFL config and control alignment"
