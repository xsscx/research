#!/usr/bin/env zsh
#
# Last Updated: 2026-04-03 04:30:00 UTC by Codex
#
# Intent:
#   xxd dump of ICC color profiles with a companion metadata file.
#   Accepts either a single ICC path or a directory to scan recursively.
#

emulate -L zsh
setopt errexit nounset pipefail

usage() {
  cat <<'EOF'
Usage: .github/scripts/icc2txt.zsh [scan-root] [output-dir] [report-path]

Create xxd dumps plus selected ICC metadata files for one file or a tree.

Defaults:
  scan-root   .
  output-dir  ./icc-xxd
  report-path ./consolidated_icc_report.txt
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

scan_root="${1:-.}"
output_dir="${2:-./icc-xxd}"
report_path="${3:-./consolidated_icc_report.txt}"
processed_count=0

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf 'Error: required command not found: %s\n' "$cmd" >&2
    exit 1
  fi
}

current_timestamp() {
  date -u +"%Y-%m-%d_%H-%M-%S"
}

safe_name() {
  printf '%s' "$1" | tr ' ' '_' | tr -c 'A-Za-z0-9._-' '_'
}

hex_slice() {
  local file="$1"
  local skip="$2"
  local count="$3"
  dd if="$file" bs=1 skip="$skip" count="$count" 2>/dev/null \
    | xxd -p -c 256 \
    | tr -d '\n' \
    | tr '[:lower:]' '[:upper:]'
}

log_message() {
  local message="$1"
  local line="[$(current_timestamp)] $message"
  printf '%s\n' "$line" | tee -a "$report_path"
}

process_icc_file() {
  local file="$1"
  local filename safe_filename timestamp output_filename metadata_filename
  local output_path metadata_path file_size tag_count

  filename="$(basename "$file")"
  safe_filename="$(safe_name "$filename")"
  timestamp="$(current_timestamp)"
  output_filename="${safe_filename}-xxd-${timestamp}.txt"
  metadata_filename="${safe_filename}-metadata-${timestamp}.txt"
  output_path="${output_dir}/${output_filename}"
  metadata_path="${output_dir}/${metadata_filename}"
  file_size="$(wc -c < "$file" | tr -d '[:space:]')"
  tag_count="N/A"

  if [[ "$file_size" -ge 132 ]]; then
    tag_count="$(hex_slice "$file" 128 4)"
  fi

  {
    printf 'ICC Profile Metadata for: %s\n' "$filename"
    printf '%s\n' '----------------------------------------'
    printf 'Actual File Size: %s bytes\n' "$file_size"
    printf 'Profile Size (0x00-0x03): %s\n' "$(hex_slice "$file" 0 4)"
    printf 'Preferred CMM (0x04-0x07): %s\n' "$(hex_slice "$file" 4 4)"
    printf 'Profile Version (0x08-0x0B): %s\n' "$(hex_slice "$file" 8 4)"
    printf 'Device Class (0x0C-0x0F): %s\n' "$(hex_slice "$file" 12 4)"
    printf 'Color Space (0x10-0x13): %s\n' "$(hex_slice "$file" 16 4)"
    printf 'PCS (0x14-0x17): %s\n' "$(hex_slice "$file" 20 4)"
    printf 'Magic Bytes (0x24-0x27): %s\n' "$(hex_slice "$file" 36 4)"
    printf 'Profile ID (0x54-0x63): %s\n' "$(hex_slice "$file" 84 16)"
    printf 'Reserved Bytes (0x64-0x7F): %s\n' "$(hex_slice "$file" 100 28)"
    printf 'Tag Count (0x80-0x83): %s\n' "$tag_count"
  } > "$metadata_path"

  xxd -g 1 -c 16 "$file" > "$output_path"

  log_message "Processed metadata: $file -> $metadata_path"
  log_message "Processed xxd dump: $file -> $output_path"
  processed_count=$((processed_count + 1))
}

require_cmd date
require_cmd dd
require_cmd find
require_cmd tee
require_cmd tr
require_cmd wc
require_cmd xxd

if [[ ! -e "$scan_root" ]]; then
  printf 'Error: scan root does not exist: %s\n' "$scan_root" >&2
  exit 1
fi

mkdir -p "$output_dir"
mkdir -p "$(dirname "$report_path")"
printf '%s\n' 'Consolidated ICC Profile Analysis Report' > "$report_path"
printf '%s\n' '----------------------------------------' >> "$report_path"
printf '\n' >> "$report_path"

printf '%s\n' 'Copyright (c) 2024-2026 David H Hoyt LLC | All rights reserved.'
printf '%s\n' 'zsh xxd dump of ICC color profiles'
printf 'Last Updated: %s UTC\n' "$(date -u +"%Y-%m-%d %H:%M:%S")"

log_message "Starting ICC profile xxd analysis"

if [[ -f "$scan_root" ]]; then
  process_icc_file "$scan_root"
else
  while IFS= read -r -d '' icc_file; do
    process_icc_file "$icc_file"
  done < <(
    find "$scan_root" -type f \
      \( -iname '*.icc' -o -iname '*.icm' -o -iname '*.iccp' -o -iname '*.icf' \
      -o -iname '*.profile' -o -iname '*.icd' -o -iname '*.icr' -o -iname '*.icb' \
      -o -iname '*.iic' \) \
      -print0
  )
fi

if [[ "$processed_count" -eq 0 ]]; then
  log_message "No ICC files found under: $scan_root"
else
  log_message "ICC profile xxd analysis completed: $processed_count file(s)"
fi
