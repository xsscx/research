#!/usr/bin/env bash

icc_profile_quarantine_file() {
  if [ -n "${ICC_PROFILE_QUARANTINE_FILE:-}" ] && [ -f "${ICC_PROFILE_QUARANTINE_FILE}" ]; then
    printf '%s\n' "${ICC_PROFILE_QUARANTINE_FILE}"
    return
  fi

  if [ -n "${GITHUB_WORKSPACE:-}" ] && [ -f "${GITHUB_WORKSPACE}/iccanalyzer-lite/tests/profile-resource-quarantine.txt" ]; then
    printf '%s\n' "${GITHUB_WORKSPACE}/iccanalyzer-lite/tests/profile-resource-quarantine.txt"
    return
  fi

  printf '%s\n' "iccanalyzer-lite/tests/profile-resource-quarantine.txt"
}

_icc_profile_relpath() {
  local path="$1"
  local repo_root="${GITHUB_WORKSPACE:-$(pwd)}"

  case "$path" in
    "${repo_root}/"*) printf '%s\n' "${path#${repo_root}/}" ;;
    *) printf '%s\n' "$path" ;;
  esac
}

icc_profile_is_quarantined() {
  local path="$1"
  local quarantine_file="${2:-$(icc_profile_quarantine_file)}"
  local relpath basename pattern line

  if [ ! -f "$quarantine_file" ]; then
    return 1
  fi

  relpath="$(_icc_profile_relpath "$path")"
  basename="$(basename "$path")"

  while IFS= read -r line || [ -n "$line" ]; do
    pattern="${line%%#*}"
    pattern="${pattern#"${pattern%%[![:space:]]*}"}"
    pattern="${pattern%"${pattern##*[![:space:]]}"}"
    [ -n "$pattern" ] || continue

    case "$relpath" in
      $pattern) return 0 ;;
    esac
    case "$basename" in
      $pattern) return 0 ;;
    esac
  done < "$quarantine_file"

  return 1
}

icc_profile_filter_quarantine() {
  local input_file="$1"
  local output_file="$2"
  local quarantine_file="${3:-$(icc_profile_quarantine_file)}"
  local profile

  : > "$output_file"
  while IFS= read -r profile || [ -n "$profile" ]; do
    [ -n "$profile" ] || continue
    if ! icc_profile_is_quarantined "$profile" "$quarantine_file"; then
      printf '%s\n' "$profile" >> "$output_file"
    fi
  done < "$input_file"
}

icc_profile_write_breadcrumb() {
  local output_file="$1"
  local profile="$2"

  printf '%s\n' "$profile" > "$output_file"
}
