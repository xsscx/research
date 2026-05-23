#!/usr/bin/env bash
# Shared CFL fuzzer metadata. Source this file from cfl/*.sh scripts.

CFL_FUZZERS=(
  icc_applynamedcmm_fuzzer
  icc_applyprofiles_fuzzer
  icc_applyprofiles_row_fuzzer
  icc_applysearch_fuzzer
  icc_applysearch_weight_fuzzer
  icc_cfg_fuzzer
  icc_dump_fuzzer
  icc_fromcube_fuzzer
  icc_fromxml_fuzzer
  icc_link_fuzzer
  icc_roundtrip_fuzzer
  icc_specsep_fuzzer
  icc_tiffdump_fuzzer
  icc_toxml_fuzzer
  icc_v5dspobs_fuzzer
)

cfl_list_fuzzers() {
  printf '%s\n' "${CFL_FUZZERS[@]}"
}

cfl_is_fuzzer() {
  local name="$1"
  local fuzzer
  for fuzzer in "${CFL_FUZZERS[@]}"; do
    [[ "$fuzzer" == "$name" ]] && return 0
  done
  return 1
}

cfl_normalize_fuzzer() {
  local name="$1"
  local candidate

  case "$name" in
    namedcmm|applynamedcmm) name="icc_applynamedcmm_fuzzer" ;;
    profiles|applyprofiles) name="icc_applyprofiles_fuzzer" ;;
    profiles-row|applyprofiles-row|rowprofiles|applyprofilesrow) name="icc_applyprofiles_row_fuzzer" ;;
    search|applysearch) name="icc_applysearch_fuzzer" ;;
    search-weight|applysearch-weight|weightsearch|applysearchweight) name="icc_applysearch_weight_fuzzer" ;;
    cfg|config) name="icc_cfg_fuzzer" ;;
    dump) name="icc_dump_fuzzer" ;;
    cube|fromcube) name="icc_fromcube_fuzzer" ;;
    fromxml) name="icc_fromxml_fuzzer" ;;
    link) name="icc_link_fuzzer" ;;
    roundtrip) name="icc_roundtrip_fuzzer" ;;
    specsep) name="icc_specsep_fuzzer" ;;
    tiffdump) name="icc_tiffdump_fuzzer" ;;
    toxml) name="icc_toxml_fuzzer" ;;
    v5|v5dspobs) name="icc_v5dspobs_fuzzer" ;;
  esac

  if cfl_is_fuzzer "$name"; then
    printf '%s\n' "$name"
    return 0
  fi

  candidate="${name%_fuzzer}"
  candidate="${candidate#icc_}"
  candidate="icc_${candidate}_fuzzer"
  if cfl_is_fuzzer "$candidate"; then
    printf '%s\n' "$candidate"
    return 0
  fi

  return 1
}

cfl_resolve_fuzzers() {
  local targets=("$@")
  local target
  local fuzzer

  if [[ ${#targets[@]} -eq 0 || "${targets[0]:-}" == "all" ]]; then
    cfl_list_fuzzers
    return 0
  fi

  for target in "${targets[@]}"; do
    if [[ "$target" == "all" ]]; then
      cfl_list_fuzzers
      continue
    fi

    if ! fuzzer="$(cfl_normalize_fuzzer "$target")"; then
      echo "ERROR: Unknown CFL fuzzer '$target'" >&2
      echo "Available fuzzers:" >&2
      cfl_list_fuzzers >&2
      return 1
    fi
    printf '%s\n' "$fuzzer"
  done | awk '!seen[$0]++'
}

cfl_corpus_dir() {
  local script_dir="$1"
  local fuzzer="$2"
  local candidate

  for candidate in \
    "$script_dir/corpus-$fuzzer" \
    "$script_dir/${fuzzer}_seed_corpus" \
    "$script_dir/consolidated-seed"; do
    if [[ -d "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  printf '%s\n' "$script_dir/corpus-$fuzzer"
}

cfl_resolve_dict() {
  local script_dir="$1"
  local fuzzer="$2"
  local candidate
  local mapped=""

  case "$fuzzer" in
    icc_roundtrip_fuzzer) mapped="icc_core.dict" ;;
    icc_toxml_fuzzer) mapped="icc_xml_consolidated.dict" ;;
  esac

  for candidate in \
    "$script_dir/${fuzzer}.dict" \
    ${mapped:+"$script_dir/$mapped"} \
    "$script_dir/icc_core.dict" \
    "$script_dir/icc.dict"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

cfl_option_timeout() {
  local script_dir="$1"
  local fuzzer="$2"
  local opt_file="$script_dir/${fuzzer}.options"
  local value

  if [[ -f "$opt_file" ]]; then
    value=$(grep -m1 '^timeout' "$opt_file" | sed 's/[^0-9]//g')
    [[ -n "$value" ]] && printf '%s\n' "$value" && return 0
  fi

  printf '30\n'
}

cfl_pid_is_running() {
  local pid_file="$1"
  local fuzzer="$2"
  local pid
  local cmdline

  [[ -f "$pid_file" ]] || return 1
  pid=$(cat "$pid_file" 2>/dev/null || true)
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1

  cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
  [[ "$cmdline" == *"$fuzzer"* ]]
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  cfl_list_fuzzers
fi
