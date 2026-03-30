#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <artifact-dir> <bundle-key> <target-dir>" >&2
    exit 1
fi

artifact_dir=$1
bundle_key=$2
target_dir=$3
archive_path="${artifact_dir}/${bundle_key}.zip"
extract_root="${artifact_dir}/extract-${bundle_key}"
extract_dir="${extract_root}/${bundle_key}"

if [[ ! -f "${archive_path}" ]]; then
    echo "missing vcpkg export archive: ${archive_path}" >&2
    exit 1
fi

rm -rf "${extract_root}" "${target_dir}"
mkdir -p "${extract_root}"
mkdir -p "$(dirname "${target_dir}")"

if command -v unzip >/dev/null 2>&1; then
    unzip -q "${archive_path}" -d "${extract_root}"
elif command -v tar >/dev/null 2>&1; then
    tar -xf "${archive_path}" -C "${extract_root}"
else
    echo "unzip or tar is required to restore ${archive_path}" >&2
    exit 1
fi

if [[ ! -d "${extract_dir}" ]]; then
    echo "missing extracted vcpkg directory: ${extract_dir}" >&2
    exit 1
fi

mv "${extract_dir}" "${target_dir}"
