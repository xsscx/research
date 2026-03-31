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
metadata_path="${artifact_dir}/${bundle_key}.txt"
checksum_path="${artifact_dir}/${bundle_key}.zip.sha256"
extract_root="${artifact_dir}/extract-${bundle_key}"
extract_dir="${extract_root}/${bundle_key}"
expected_dependencies_sha="${bundle_key##*-}"

metadata_value() {
    local key=$1
    local line

    line=$(grep -E "^${key}=" "${metadata_path}" | head -n 1 || true)
    if [[ -z "${line}" ]]; then
        echo "missing ${key} in ${metadata_path}" >&2
        exit 1
    fi

    printf '%s\n' "${line#*=}"
}

sha256_file() {
    local path=$1

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${path}" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${path}" | awk '{print $1}'
    else
        echo "sha256sum or shasum is required to verify ${path}" >&2
        exit 1
    fi
}

for required_file in "${archive_path}" "${metadata_path}" "${checksum_path}"; do
    if [[ ! -f "${required_file}" ]]; then
        echo "missing required vcpkg export file: ${required_file}" >&2
        exit 1
    fi
done

expected_checksum=$(awk 'NR == 1 { print $1 }' "${checksum_path}")
if [[ -z "${expected_checksum}" ]]; then
    echo "missing checksum value in ${checksum_path}" >&2
    exit 1
fi

actual_checksum=$(sha256_file "${archive_path}")
if [[ "${expected_checksum}" != "${actual_checksum}" ]]; then
    echo "checksum mismatch for ${archive_path}" >&2
    exit 1
fi

metadata_bundle=$(metadata_value "bundle")
metadata_archive=$(metadata_value "archive")
metadata_dependencies_sha=$(metadata_value "dependencies_sha")
metadata_restore_path=$(metadata_value "restore_path")

if [[ "${metadata_bundle}" != "${bundle_key}" ]]; then
    echo "bundle mismatch: expected ${bundle_key}, found ${metadata_bundle}" >&2
    exit 1
fi

if [[ "${metadata_archive}" != "$(basename "${archive_path}")" ]]; then
    echo "archive mismatch: expected $(basename "${archive_path}"), found ${metadata_archive}" >&2
    exit 1
fi

if [[ "${metadata_dependencies_sha}" != "${expected_dependencies_sha}" ]]; then
    echo "dependencies hash mismatch for ${bundle_key}" >&2
    exit 1
fi

if [[ "${metadata_restore_path}" != *"backend/vcpkg" ]]; then
    echo "unexpected restore path in metadata: ${metadata_restore_path}" >&2
    exit 1
fi

if [[ "${target_dir}" != *"backend/vcpkg" ]]; then
    echo "unexpected restore target: ${target_dir}" >&2
    exit 1
fi

rm -rf "${extract_root}"
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

for required_entry in ".vcpkg-root" "installed" "scripts"; do
    if [[ ! -e "${extract_dir}/${required_entry}" ]]; then
        echo "missing required vcpkg entry: ${extract_dir}/${required_entry}" >&2
        exit 1
    fi
done

if [[ ! -e "${extract_dir}/vcpkg" && ! -e "${extract_dir}/vcpkg.exe" ]]; then
    echo "missing vcpkg executable under ${extract_dir}" >&2
    exit 1
fi

rm -rf "${target_dir}"
mv "${extract_dir}" "${target_dir}"
rm -rf "${extract_root}"
