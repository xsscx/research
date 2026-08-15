#!/usr/bin/env bash
# Shared CFL fuzzer metadata. Source this file from cfl/*.sh scripts.

CFL_FUZZERS=(
  icc_applynamedcmm_fuzzer
  icc_applyprofiles_fuzzer
  icc_applyprofiles_row_fuzzer
  icc_applysearch_fuzzer
  icc_applysearch_weight_fuzzer
  icc_connect_fuzzer
  icc_cfg_fuzzer
  icc_dump_fuzzer
  icc_fromcube_fuzzer
  icc_fromjson_fuzzer
  icc_fromxml_fuzzer
  icc_jpegdump_fuzzer
  icc_link_fuzzer
  icc_pawgreport_fuzzer
  icc_pngdump_fuzzer
  icc_profilevisualize_fuzzer
  icc_proflib_fuzzer
  icc_roundtrip_fuzzer
  icc_specsep_fuzzer
  icc_tiffdump_fuzzer
  icc_tojson_fuzzer
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
    connect|iccconnect) name="icc_connect_fuzzer" ;;
    cfg|config) name="icc_cfg_fuzzer" ;;
    dump) name="icc_dump_fuzzer" ;;
    cube|fromcube) name="icc_fromcube_fuzzer" ;;
    json|fromjson) name="icc_fromjson_fuzzer" ;;
    fromxml) name="icc_fromxml_fuzzer" ;;
    jpeg|jpegdump) name="icc_jpegdump_fuzzer" ;;
    link) name="icc_link_fuzzer" ;;
    pawg|pawgreport) name="icc_pawgreport_fuzzer" ;;
    png|pngdump) name="icc_pngdump_fuzzer" ;;
    profilevisualize|profile-visualize|visualize) name="icc_profilevisualize_fuzzer" ;;
    profile|proflib|iccproflib) name="icc_proflib_fuzzer" ;;
    roundtrip) name="icc_roundtrip_fuzzer" ;;
    specsep) name="icc_specsep_fuzzer" ;;
    tiffdump) name="icc_tiffdump_fuzzer" ;;
    tojson) name="icc_tojson_fuzzer" ;;
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

  case "$fuzzer" in
    icc_connect_fuzzer|icc_fromjson_fuzzer|icc_tojson_fuzzer)
      for candidate in \
        "$script_dir/corpus-$fuzzer" \
        "$script_dir/${fuzzer}_seed_corpus"; do
        if [[ -d "$candidate" ]]; then
          printf '%s\n' "$candidate"
          return 0
        fi
      done
      printf '%s\n' "$script_dir/corpus-$fuzzer"
      return 0
      ;;
  esac

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

cfl_curated_seed_dir() {
  local script_dir="$1"
  local fuzzer="$2"

  case "$fuzzer" in
    icc_applynamedcmm_fuzzer)
      printf '%s\n' "$script_dir/seeds-applynamedcmm"
      ;;
    *)
      return 1
      ;;
  esac
}

cfl_install_curated_seeds() {
  local script_dir="$1"
  local fuzzer="$2"
  local corpus_dir="$3"
  local seed_dir
  local target

  if ! seed_dir="$(cfl_curated_seed_dir "$script_dir" "$fuzzer")" ||
     [[ ! -d "$seed_dir" ]]; then
    return 0
  fi

  while IFS= read -r -d '' seed; do
    target="$corpus_dir/$(basename "$seed")"
    cp "$seed" "$target"
  done < <(find "$seed_dir" -maxdepth 1 -type f -print0)
}

cfl_resolve_dict() {
  local script_dir="$1"
  local fuzzer="$2"
  local candidate
  local mapped=""

  case "$fuzzer" in
    icc_connect_fuzzer) mapped="icc_cfg.dict" ;;
    icc_fromjson_fuzzer) mapped="icc_json.dict" ;;
    icc_proflib_fuzzer) mapped="icc_core.dict" ;;
    icc_roundtrip_fuzzer) mapped="icc_core.dict" ;;
    icc_tojson_fuzzer) mapped="icc_core.dict" ;;
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
  cfl_option_value "$1" "$2" timeout 30
}

cfl_option_max_len() {
  cfl_option_value "$1" "$2" max_len 0
}

cfl_effective_max_len() {
  local configured="$1"
  local corpus_dir="$2"
  local largest

  if [[ "$configured" -gt 0 ]]; then
    printf '%s\n' "$configured"
    return 0
  fi

  largest="$(find "$corpus_dir" -maxdepth 1 -type f -printf '%s\n' 2>/dev/null |
    awk '$1 > largest { largest = $1 } END { if (largest) print largest }')"
  printf '%s\n' "${largest:-1048576}"
}

cfl_option_rss_limit() {
  cfl_option_value "$1" "$2" rss_limit_mb 4096
}

cfl_option_value() {
  local script_dir="$1"
  local fuzzer="$2"
  local key="$3"
  local default_value="$4"
  local opt_file="$script_dir/${fuzzer}.options"
  local value

  if [[ -f "$opt_file" ]]; then
    value=$(awk -F= -v key="$key" '
      $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
        value = $2
        sub(/[[:space:]]*#.*/, "", value)
        gsub(/[^0-9]/, "", value)
        if (value != "" && value != "0") {
          print value
          exit
        }
      }
    ' "$opt_file")
    [[ -n "$value" ]] && printf '%s\n' "$value" && return 0
  fi

  printf '%s\n' "$default_value"
}

cfl_asan_options() {
  local fuzzer="$1"
  local options="detect_leaks=0,allocator_may_return_null=1"

  if [[ "$fuzzer" == "icc_link_fuzzer" ]]; then
    options+=",quarantine_size_mb=256"
  fi

  printf '%s\n' "$options"
}

cfl_tool_command() {
  local fuzzer="$1"
  local artifact="${2:-<artifact>}"

  case "$fuzzer" in
    icc_applynamedcmm_fuzzer)
      printf 'iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 %s 1\n' "$artifact"
      ;;
    icc_applyprofiles_fuzzer)
      printf 'iccApplyProfiles test-profiles/tiff-codecs/seed-tiff-none-rgb-8x8.tif /tmp/cfl-applyprofiles-out.tif 3 1 1 1 1 %s 40\n' "$artifact"
      ;;
    icc_applyprofiles_row_fuzzer)
      printf 'iccApplyProfiles -threads 0 test-profiles/tiff-codecs/seed-tiff-none-rgb-8x8.tif /tmp/cfl-applyprofiles-row-out.tif 3 1 1 1 1 %s 40\n' "$artifact"
      ;;
    icc_applysearch_fuzzer)
      printf 'iccApplySearch docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 test-profiles/sRGB_D65_MAT.icc 1 %s 1 -INIT 1 test-profiles/sRGB_D65_MAT.icc 1\n' "$artifact"
      ;;
    icc_applysearch_weight_fuzzer)
      printf 'iccApplySearch docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 test-profiles/sRGB_D65_MAT.icc 1 test-profiles/sRGB_D65_MAT.icc 1 -INIT 1 %s 1\n' "$artifact"
      ;;
    icc_connect_fuzzer)
      printf 'iccApplyProfiles -cfg %s\n' "$artifact"
      ;;
    icc_cfg_fuzzer)
      printf 'iccApplyProfiles -cfg %s\n' "$artifact"
      ;;
    icc_dump_fuzzer)
      printf 'iccDumpProfile -v 100 %s ALL\n' "$artifact"
      ;;
    icc_fromcube_fuzzer)
      printf 'iccFromCube %s /tmp/cfl-fromcube-out.icc\n' "$artifact"
      ;;
    icc_fromjson_fuzzer)
      printf 'iccFromJson %s /tmp/cfl-fromjson-out.icc\n' "$artifact"
      ;;
    icc_fromxml_fuzzer)
      printf 'iccFromXml %s /tmp/cfl-fromxml-out.icc [-noid|-v=SampleIccRELAX.rng]\n' "$artifact"
      ;;
    icc_jpegdump_fuzzer)
      printf 'iccJpegDump %s /tmp/cfl-jpegdump.icc\n' "$artifact"
      ;;
    icc_link_fuzzer)
      printf 'iccApplyToLink /tmp/cfl-link-out.icc 0 2 1 CFL 0.0 1.0 0 0 %s 40 test-profiles/sRGB_D65_MAT.icc 40\n' "$artifact"
      ;;
    icc_pawgreport_fuzzer)
      printf 'iccPawgReport --json %s\n' "$artifact"
      ;;
    icc_pngdump_fuzzer)
      printf 'iccPngDump %s /tmp/cfl-pngdump.icc\n' "$artifact"
      ;;
    icc_profilevisualize_fuzzer)
      printf 'iccProfileVisualize %s\n' "$artifact"
      ;;
    icc_proflib_fuzzer)
      printf 'ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1 cfl/bin/icc_proflib_fuzzer -runs=1 %s\n' "$artifact"
      ;;
    icc_roundtrip_fuzzer)
      printf 'iccRoundTrip %s /tmp/cfl-roundtrip-out.icc\n' "$artifact"
      ;;
    icc_specsep_fuzzer)
      printf 'iccSpecSepToTiff %s _A2B0 /tmp/cfl-specsep 8 0\n' "$artifact"
      ;;
    icc_tiffdump_fuzzer)
      printf 'iccTiffDump %s /tmp/cfl-tiffdump.icc\n' "$artifact"
      ;;
    icc_tojson_fuzzer)
      printf 'iccToJson %s /tmp/cfl-tojson-out.json\n' "$artifact"
      ;;
    icc_toxml_fuzzer)
      printf 'iccToXml %s /tmp/cfl-toxml-out.xml\n' "$artifact"
      ;;
    icc_v5dspobs_fuzzer)
      printf 'iccV5DspObsToV4Dsp %s test-profiles/XYZ_float-D65_2deg-Part1.icc /tmp/cfl-v5dspobs-out.icc\n' "$artifact"
      ;;
    *)
      printf 'ERROR: no tool command mapping for %s\n' "$fuzzer" >&2
      return 1
      ;;
  esac
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
