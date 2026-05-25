#!/usr/bin/env bash
# unbundle-fuzzer-input.sh - Extract derived files from CFL inputs.
#
# Supported layouts:
#   single-file tools  raw input copied as profile.icc, input.xml, input.json,
#                      input.cube, or input.tiff as appropriate
#   v5dspobs          [display.icc declared size][observer.icc]
#   link              [profile1 declared size][profile2][4B control]
#   applysearch       [profile1 declared size][profile2][4B control]
#   applysearch-weight same layout; weight bits apply only when PCC is enabled
#   applyprofiles     [75% profile][25% control/pixel seed]
#   applyprofiles-row [75% profile][25% control/pixel seed], forced row-apply harness
#   specsep           [2B control][N TIFF chunks][optional ICC tail]
#
# The extracted files are triage aids. They are not maintainer-facing proof by
# themselves. A bisect report still requires a one-line iccDEV command-line
# reproducer that crashes or otherwise produces a maintainer-actionable finding.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

usage() {
  cat <<EOF
Usage: $(basename "$0") <fuzzer_name> <crash_file> [tool_root]

Fuzzer names are normalized with cfl/fuzzers.sh aliases when available.
Examples: dump, toxml, fromxml, tojson, fromjson, cfg, connect, link,
          applynamedcmm, applyprofiles, applyprofiles-row, applysearch,
          applysearch-weight, roundtrip, specsep, tiffdump, fromcube, v5dspobs.

Output directory: ./tmp/icc_<normalized_fuzzer>/

Notes:
  Generated files are triage aids. Fuzzer-only control.bin files are not
  standalone maintainer inputs. Verify any printed CLI candidate end-to-end
  before using it in a maintainer report.
EOF
  exit 1
}

[ $# -lt 2 ] && usage

FUZZER_INPUT="$1"
CRASH_FILE="$2"
TOOL_ROOT="${3:-}"

if [ ! -f "$CRASH_FILE" ]; then
  echo "ERROR: crash file not found: $CRASH_FILE" >&2
  exit 1
fi

if [ -f "$REPO_ROOT/cfl/fuzzers.sh" ]; then
  # shellcheck source=/dev/null
  source "$REPO_ROOT/cfl/fuzzers.sh"
fi

if declare -F cfl_normalize_fuzzer >/dev/null; then
  FUZZER="$(cfl_normalize_fuzzer "$FUZZER_INPUT" 2>/dev/null || true)"
else
  FUZZER=""
fi

if [ -z "$FUZZER" ]; then
  case "$FUZZER_INPUT" in
    icc_applynamedcmm_fuzzer|applynamedcmm|namedcmm) FUZZER="icc_applynamedcmm_fuzzer" ;;
    icc_applyprofiles_fuzzer|applyprofiles|profiles) FUZZER="icc_applyprofiles_fuzzer" ;;
    icc_applyprofiles_row_fuzzer|applyprofiles-row|profiles-row|rowprofiles|applyprofilesrow) FUZZER="icc_applyprofiles_row_fuzzer" ;;
    icc_applysearch_fuzzer|applysearch|search) FUZZER="icc_applysearch_fuzzer" ;;
    icc_applysearch_weight_fuzzer|applysearch-weight|search-weight|weightsearch|applysearchweight) FUZZER="icc_applysearch_weight_fuzzer" ;;
    icc_connect_fuzzer|connect|iccconnect) FUZZER="icc_connect_fuzzer" ;;
    icc_cfg_fuzzer|cfg|config) FUZZER="icc_cfg_fuzzer" ;;
    icc_dump_fuzzer|dump) FUZZER="icc_dump_fuzzer" ;;
    icc_fromcube_fuzzer|fromcube|cube) FUZZER="icc_fromcube_fuzzer" ;;
    icc_fromjson_fuzzer|fromjson|json) FUZZER="icc_fromjson_fuzzer" ;;
    icc_fromxml_fuzzer|fromxml) FUZZER="icc_fromxml_fuzzer" ;;
    icc_link_fuzzer|link) FUZZER="icc_link_fuzzer" ;;
    icc_roundtrip_fuzzer|roundtrip) FUZZER="icc_roundtrip_fuzzer" ;;
    icc_specsep_fuzzer|specsep) FUZZER="icc_specsep_fuzzer" ;;
    icc_tiffdump_fuzzer|tiffdump) FUZZER="icc_tiffdump_fuzzer" ;;
    icc_tojson_fuzzer|tojson) FUZZER="icc_tojson_fuzzer" ;;
    icc_toxml_fuzzer|toxml) FUZZER="icc_toxml_fuzzer" ;;
    icc_v5dspobs_fuzzer|v5dspobs|v5) FUZZER="icc_v5dspobs_fuzzer" ;;
    *)
      echo "ERROR: unsupported fuzzer: $FUZZER_INPUT" >&2
      usage
      ;;
  esac
fi

FILE_SIZE=$(stat -c%s "$CRASH_FILE" 2>/dev/null || stat -f%z "$CRASH_FILE" 2>/dev/null)
OUT_NAME="${FUZZER#icc_}"
OUT_DIR="./tmp/icc_${OUT_NAME}"
mkdir -p "$OUT_DIR"

if [ -z "$TOOL_ROOT" ]; then
  for candidate in \
    "$REPO_ROOT/iccDEV/Build/Tools" \
    "$REPO_ROOT/cfl/iccDEV/Build/Tools" \
    "$REPO_ROOT/iccanalyzer-lite/iccDEV/Build/Tools"; do
    if [ -d "$candidate" ]; then
      TOOL_ROOT="$candidate"
      break
    fi
  done
fi

echo "CFL fuzzer input unbundler"
echo "Fuzzer:     $FUZZER"
echo "Input:      $CRASH_FILE"
echo "File size:  $FILE_SIZE bytes"
echo "Output dir: $OUT_DIR"
if [ -n "$TOOL_ROOT" ] && [ -d "$TOOL_ROOT" ]; then
  echo "Tool root:  $TOOL_ROOT"
else
  echo "Tool root:  (not found; extraction only)"
fi
echo ""

read_be32() {
  local file="$1" offset="$2"
  od -A n -t u1 -j "$offset" -N 4 "$file" |
    awk '{printf "%d", ($1*16777216)+($2*65536)+($3*256)+$4}'
}

check_icc_magic() {
  local file="$1" label="$2"
  local magic
  magic=$(od -A n -t x1 -j 36 -N 4 "$file" 2>/dev/null | tr -d ' ')
  if [ "$magic" = "61637370" ]; then
    echo "  [OK] $label: ICC magic acsp"
  else
    echo "  [WARN] $label: magic 0x${magic:-missing}, expected 0x61637370"
  fi
}

icc_header_summary() {
  local file="$1" label="$2"
  local size version class colorspace
  if [ ! -f "$file" ] || [ "$(stat -c%s "$file" 2>/dev/null || echo 0)" -lt 40 ]; then
    echo "  [WARN] $label: too small for ICC header"
    return
  fi
  size=$(read_be32 "$file" 0)
  version=$(od -A n -t x1 -j 8 -N 4 "$file" | tr -d ' ')
  class=$(od -A n -t c -j 12 -N 4 "$file" | tr -d ' ')
  colorspace=$(od -A n -t c -j 16 -N 4 "$file" | tr -d ' ')
  echo "  $label: declared_size=$size version=0x${version} class='${class}' colorSpace='${colorspace}'"
}

json_bool() {
  if [ "$1" -ne 0 ]; then
    printf "true"
  else
    printf "false"
  fi
}

generate_applyprofiles_tiff() {
  local profile_file="$1" control_file="$2" source_tiff="$3" repro_json="$4"
  local output_tiff="$5" width="$6" height="$7" bps="$8" photo="$9" samples="${10}"
  local dst_compress="${11}" dst_planar="${12}" dst_embed="${13}" threads="${14}"
  local intent_name="${15}" interp_name="${16}" use_bpc="${17}" use_luminance="${18}"
  local use_v5sub="${19}" use_d2bx="${20}"

  python3 - "$profile_file" "$control_file" "$source_tiff" "$repro_json" \
    "$output_tiff" "$width" "$height" "$bps" "$photo" "$samples" \
    "$dst_compress" "$dst_planar" "$dst_embed" "$threads" "$intent_name" \
    "$interp_name" "$use_bpc" "$use_luminance" "$use_v5sub" "$use_d2bx" <<'PY'
import json
import struct
import sys
from pathlib import Path

(
    profile_path,
    control_path,
    source_tiff_path,
    repro_json_path,
    output_tiff_path,
    width,
    height,
    bps,
    photo,
    samples,
    dst_compress,
    dst_planar,
    dst_embed,
    threads,
    intent_name,
    interp_name,
    use_bpc,
    use_luminance,
    use_v5sub,
    use_d2bx,
) = sys.argv[1:]

profile = Path(profile_path).read_bytes()
control = Path(control_path).read_bytes()
width = int(width)
height = int(height)
bps = int(bps)
photo = int(photo)
samples = int(samples)
bytes_per_sample = bps // 8
bytes_per_line = width * samples * bytes_per_sample
pixel_bytes = bytearray(bytes_per_line * height)

for row in range(height):
    seed_off = 4 + row * bytes_per_line
    chunk = control[seed_off:seed_off + bytes_per_line]
    start = row * bytes_per_line
    pixel_bytes[start:start + len(chunk)] = chunk


def tiff_entry(tag, typ, count, value):
    if typ == 3 and count == 1:
        return struct.pack("<HHI", tag, typ, count) + struct.pack("<H", value) + b"\0\0"
    if typ == 4 and count == 1:
        return struct.pack("<HHII", tag, typ, count, value)
    return struct.pack("<HHII", tag, typ, count, value)


external = bytearray()
entries = []


def add_external(data, alignment=2):
    while (ifd_end + len(external)) % alignment:
        external.append(0)
    offset = ifd_end + len(external)
    external.extend(data)
    return offset


entry_specs = [
    (256, 4, 1, width),
    (257, 4, 1, height),
    (259, 3, 1, 1),
    (262, 3, 1, photo),
    (277, 3, 1, samples),
    (278, 4, 1, height),
    (279, 4, 1, len(pixel_bytes)),
    (284, 3, 1, 1),
    (296, 3, 1, 2),
]
if bps == 32:
    entry_specs.append((339, 3, 1, 3))
else:
    entry_specs.append((339, 3, 1, 1))
entry_specs.append((34675, 7, len(profile), None))
entry_specs.append((273, 4, 1, None))
entry_specs.append((282, 5, 1, None))
entry_specs.append((283, 5, 1, None))
entry_specs.append((258, 3, samples, None if samples > 1 else bps))
entry_specs.sort(key=lambda item: item[0])

ifd_end = 8 + 2 + len(entry_specs) * 12 + 4
bits_offset = add_external(struct.pack("<" + ("H" * samples), *([bps] * samples))) if samples > 1 else None
xres_offset = add_external(struct.pack("<II", 72, 1), 4)
yres_offset = add_external(struct.pack("<II", 72, 1), 4)
profile_offset = add_external(profile, 2)
pixel_offset = add_external(pixel_bytes, 2)

for tag, typ, count, value in entry_specs:
    if tag == 258 and samples > 1:
        value = bits_offset
    elif tag == 273:
        value = pixel_offset
    elif tag == 282:
        value = xres_offset
    elif tag == 283:
        value = yres_offset
    elif tag == 34675:
        value = profile_offset
    entries.append(tiff_entry(tag, typ, count, value))

source_tiff = Path(source_tiff_path)
with source_tiff.open("wb") as f:
    f.write(b"II")
    f.write(struct.pack("<HI", 42, 8))
    f.write(struct.pack("<H", len(entries)))
    for entry in entries:
        f.write(entry)
    f.write(struct.pack("<I", 0))
    f.write(external)

repro = {
    "imageFiles": {
        "srcImageFile": str(source_tiff.resolve()),
        "dstImageFile": str(Path(output_tiff_path).resolve()),
        "dstEncoding": "sameAsSource",
        "dstCompression": dst_compress == "1",
        "dstPlanar": dst_planar == "1",
        "dstEmbedIcc": dst_embed == "1",
    },
    "connect": {
        "threads": int(threads),
    },
    "profileSequence": [
        {
            "iccFile": None,
            "intent": intent_name,
            "transform": "default",
            "useD2BxB2Dx": use_d2bx == "1",
            "adjustPcsLuminance": use_luminance == "1",
            "useBPC": use_bpc == "1",
            "useV5SubProfile": use_v5sub == "1",
            "interpolation": interp_name,
        }
    ],
}
Path(repro_json_path).write_text(json.dumps(repro, indent=2) + "\n", encoding="ascii")
PY
}

run_tool() {
  local tool_path="$1"
  shift
  local exit_code=0
  local asan_log
  local tool_name
  tool_name=$(basename "$tool_path")
  asan_log="$OUT_DIR/${tool_name}.asan.log"

  echo ""
  echo "Running $tool_name"
  printf 'Command: %q' "$tool_path"
  printf ' %q' "$@"
  echo ""

  {
    set +e
    ASAN_OPTIONS=print_scariness=1:detect_leaks=0:halt_on_error=1:abort_on_error=1 \
    UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    LLVM_PROFILE_FILE=/dev/null \
      timeout 30 "$tool_path" "$@" >"$asan_log" 2>&1
    exit_code=$?
    set -e
  } 2>/dev/null
  cat "$asan_log"

  if [ "$exit_code" -eq 0 ]; then
    echo "Result: EXIT 0 (success)"
  elif [ "$exit_code" -eq 124 ]; then
    echo "Result: TIMEOUT (30s)"
  elif [ "$exit_code" -ge 128 ]; then
    echo "Result: CRASH (exit $exit_code, signal $((exit_code - 128)))"
  else
    echo "Result: SOFT FAILURE (exit $exit_code)"
  fi
  echo "ASAN log: $asan_log"
  return "$exit_code"
}

extract_range() {
  local skip="$1" count="$2" out="$3"
  dd if="$CRASH_FILE" of="$out" bs=1 skip="$skip" count="$count" status=none
}

tool_bin() {
  local dir="$1" bin="$2"
  printf '%s/%s/%s' "$TOOL_ROOT" "$dir" "$bin"
}

read_sig() {
  local file="$1" offset="$2"
  dd if="$file" bs=1 skip="$offset" count=4 status=none 2>/dev/null | tr '\000' ' '
}

encoding_name() {
  case "$1" in
    1) printf 'icEncodePercent' ;;
    2) printf 'icEncodeUnitFloat' ;;
    3) printf 'icEncodeFloat' ;;
    4) printf 'icEncode8Bit' ;;
    5) printf 'icEncode16Bit' ;;
    6) printf 'icEncode16BitV2' ;;
    *) printf 'icEncodeValue' ;;
  esac
}

intent_name() {
  case "$1" in
    0) printf 'perceptual' ;;
    1) printf 'relative' ;;
    2) printf 'saturation' ;;
    *) printf 'absolute' ;;
  esac
}

interp_name() {
  if [ "$1" -eq 0 ]; then
    printf 'linear'
  else
    printf 'tetrahedral'
  fi
}

icc_space_samples() {
  case "$1" in
    "GRAY"|"1CLR") printf '1' ;;
    "2CLR") printf '2' ;;
    "RGB "|"XYZ "|"Lab "|"3CLR") printf '3' ;;
    "CMYK"|"4CLR") printf '4' ;;
    "5CLR") printf '5' ;;
    "6CLR") printf '6' ;;
    "7CLR") printf '7' ;;
    "8CLR") printf '8' ;;
    "9CLR") printf '9' ;;
    "ACLR") printf '10' ;;
    "BCLR") printf '11' ;;
    "CCLR") printf '12' ;;
    "DCLR") printf '13' ;;
    "ECLR") printf '14' ;;
    "FCLR") printf '15' ;;
    *) printf '3' ;;
  esac
}

copy_raw() {
  local out="$1" label="$2"
  cp "$CRASH_FILE" "$OUT_DIR/$out"
  echo "Format: single-file $label input"
  echo "Extracted $out=$FILE_SIZE bytes"
}

copy_icc_profile() {
  copy_raw "profile.icc" "ICC profile"
  check_icc_magic "$OUT_DIR/profile.icc" "Profile"
  icc_header_summary "$OUT_DIR/profile.icc" "Profile"
}

write_legacy_data() {
  local out="$1" sig="$2" enc="$3" mode="$4" seed="${5:-128}"
  local samples
  samples=$(icc_space_samples "$sig")
  {
    printf "'%s'  ; Data Format\n" "$sig"
    printf "%s  ; Encoding\n\n" "$(encoding_name "$enc")"
    awk -v samples="$samples" -v mode="$mode" -v seed="$seed" '
      function value(i, line) {
        if (mode == 1) return 0.0;
        if (mode == 2) return 1.0;
        if (mode == 3) return samples > 1 ? (i - 1) / (samples - 1) : 0.5;
        if (mode == 4) return ((seed + (i - 1) * 37) % 256) / 255.0;
        if (mode == 5) return ((seed + (i - 1) * 73 + 128) % 256) / 255.0;
        return 0.5;
      }
      BEGIN {
        for (line = 0; line < 2; line++) {
          for (i = 1; i <= samples; i++) {
            v = value(i, line);
            if (mode == 5 && line == 0)
              v = ((seed + (i - 1) * 37) % 256) / 255.0;
            printf "%s%.8f", i == 1 ? "" : " ", v;
          }
          printf "\n";
        }
      }'
  } > "$out"
}

run_if_available() {
  local tool="$1"
  shift
  if [ -n "$TOOL_ROOT" ] && [ -x "$tool" ]; then
    run_tool "$tool" "$@" || true
  else
    echo "Tool not run; $(basename "$tool") not found under tool root."
  fi
}

unbundle_v5dspobs() {
  echo "Format: [display.icc declared size][observer.icc]"
  if [ "$FILE_SIZE" -lt 256 ]; then
    echo "ERROR: file too small for two ICC headers" >&2
    return 1
  fi

  local dsp_size obs_size
  dsp_size=$(read_be32 "$CRASH_FILE" 0)
  if [ "$dsp_size" -lt 128 ] || [ "$dsp_size" -gt $((FILE_SIZE - 128)) ]; then
    echo "ERROR: display declared size out of range: $dsp_size" >&2
    return 1
  fi
  obs_size=$((FILE_SIZE - dsp_size))

  extract_range 0 "$dsp_size" "$OUT_DIR/profile_display.icc"
  extract_range "$dsp_size" "$obs_size" "$OUT_DIR/profile_observer.icc"

  echo "Extracted display=$dsp_size bytes observer=$obs_size bytes"
  check_icc_magic "$OUT_DIR/profile_display.icc" "Display"
  check_icc_magic "$OUT_DIR/profile_observer.icc" "Observer"
  icc_header_summary "$OUT_DIR/profile_display.icc" "Display"
  icc_header_summary "$OUT_DIR/profile_observer.icc" "Observer"

  local tool="$TOOL_ROOT/IccV5DspObsToV4Dsp/iccV5DspObsToV4Dsp"
  if [ -n "$TOOL_ROOT" ] && [ -x "$tool" ]; then
    run_tool "$tool" \
      "$OUT_DIR/profile_display.icc" \
      "$OUT_DIR/profile_observer.icc" \
      "$OUT_DIR/output.icc" || true
  else
    echo "Manual CLI candidate:"
    echo "  iccV5DspObsToV4Dsp $OUT_DIR/profile_display.icc $OUT_DIR/profile_observer.icc $OUT_DIR/output.icc"
  fi
}

unbundle_link() {
  echo "Format: [profile1 declared size][profile2][4-byte trailing control]"
  if [ "$FILE_SIZE" -lt 260 ]; then
    echo "ERROR: file too small for two ICC headers plus control" >&2
    return 1
  fi

  local data_size profile1_size profile2_size
  data_size=$((FILE_SIZE - 4))
  profile1_size=$(read_be32 "$CRASH_FILE" 0)
  if [ "$profile1_size" -lt 128 ] || [ "$profile1_size" -gt $((data_size - 128)) ]; then
    echo "ERROR: profile1 declared size out of range: $profile1_size" >&2
    return 1
  fi
  profile2_size=$((data_size - profile1_size))

  extract_range 0 "$profile1_size" "$OUT_DIR/profile_1.icc"
  extract_range "$profile1_size" "$profile2_size" "$OUT_DIR/profile_2.icc"
  extract_range "$data_size" 4 "$OUT_DIR/control.bin"

  local ctrl0 ctrl1 ctrl2 ctrl3 intent interp first_transform use_d2bx use_bpc use_luminance use_subprofile
  read -r ctrl0 ctrl1 ctrl2 ctrl3 < <(od -A n -t u1 -j "$data_size" -N 4 "$CRASH_FILE")
  intent=$((ctrl3 % 4))
  interp=$(( (ctrl2 & 1) ? 0 : 1 ))
  first_transform=$((ctrl0 & 1))
  use_d2bx=$(( (ctrl0 & 2) ? 0 : 1 ))
  use_bpc=$(( (ctrl0 & 4) ? 1 : 0 ))
  use_luminance=$(( (ctrl0 & 8) ? 1 : 0 ))
  use_subprofile=$(( (ctrl0 & 16) ? 1 : 0 ))

  echo "Extracted profile1=$profile1_size bytes profile2=$profile2_size bytes control=4 bytes"
  echo "Control: intent=$intent interp=$interp first_transform=$first_transform use_d2bx=$use_d2bx bpc=$use_bpc luminance=$use_luminance subprofile=$use_subprofile"
  check_icc_magic "$OUT_DIR/profile_1.icc" "Profile 1"
  check_icc_magic "$OUT_DIR/profile_2.icc" "Profile 2"
  icc_header_summary "$OUT_DIR/profile_1.icc" "Profile 1"
  icc_header_summary "$OUT_DIR/profile_2.icc" "Profile 2"

  echo "Manual CLI candidate (verify before using in maintainer reports):"
  echo "  iccApplyToLink $OUT_DIR/output.icc 0 2 0 fuzz-link 0 1 $first_transform $interp $OUT_DIR/profile_1.icc $intent $OUT_DIR/profile_2.icc $intent"
}

unbundle_applysearch() {
  local weighted="$1"
  echo "Format: [profile1 declared size][profile2][4-byte trailing control]"
  if [ "$FILE_SIZE" -lt 264 ]; then
    echo "ERROR: file too small for two ICC headers plus control" >&2
    return 1
  fi

  local data_size profile1_size profile2_size
  data_size=$((FILE_SIZE - 4))
  profile1_size=$(read_be32 "$CRASH_FILE" 0)
  if [ "$profile1_size" -lt 132 ] || [ "$profile1_size" -gt $((data_size - 132)) ]; then
    echo "ERROR: profile1 declared size out of range: $profile1_size" >&2
    return 1
  fi
  profile2_size=$((data_size - profile1_size))

  extract_range 0 "$profile1_size" "$OUT_DIR/profile_1.icc"
  extract_range "$profile1_size" "$profile2_size" "$OUT_DIR/profile_2.icc"
  extract_range "$data_size" 4 "$OUT_DIR/control.bin"

  local ctrl0=0 ctrl1=0 ctrl2=0 ctrl3=0 intent1 intent2 interp use_bounds use_pcc pixel_seed
  local interp_arg interp_label weight_case pcc_weight pcc_weight_label sig data_file tool
  read -r ctrl0 ctrl1 ctrl2 ctrl3 < <(od -A n -t u1 -j "$data_size" -N 4 "$CRASH_FILE")
  intent1=$((ctrl0 % 4))
  intent2=$((ctrl1 % 4))
  if [ $((ctrl2 & 1)) -ne 0 ]; then
    interp_arg=0
  else
    interp_arg=1
  fi
  interp_label=$(interp_name "$interp_arg")
  use_bounds=$(( (ctrl2 & 2) ? 1 : 0 ))
  use_pcc=$(( (ctrl2 & 4) ? 1 : 0 ))
  pixel_seed=$ctrl3
  pcc_weight="1.0"
  if [ "$weighted" -eq 1 ]; then
    weight_case=$(((ctrl2 >> 3) % 6))
    case "$weight_case" in
      0) pcc_weight="1.0" ;;
      1) pcc_weight="0.0" ;;
      2) pcc_weight="-1.0" ;;
      3) pcc_weight="0.5" ;;
      4) pcc_weight="2.0" ;;
      *) pcc_weight="nan" ;;
    esac
  fi
  if [ "$use_pcc" -ne 0 ]; then
    pcc_weight_label="$pcc_weight"
  elif [ "$weighted" -eq 1 ]; then
    pcc_weight_label="inactive(control=$pcc_weight)"
  else
    pcc_weight_label="inactive"
  fi

  echo "Extracted profile1=$profile1_size bytes profile2=$profile2_size bytes control=4 bytes"
  echo "Control: intent1=$intent1 intent2=$intent2 interp=$interp_arg ($interp_label) use_bounds=$use_bounds use_pcc=$use_pcc pixel_seed=$pixel_seed pcc_weight=$pcc_weight_label"
  check_icc_magic "$OUT_DIR/profile_1.icc" "Profile 1"
  check_icc_magic "$OUT_DIR/profile_2.icc" "Profile 2"
  icc_header_summary "$OUT_DIR/profile_1.icc" "Profile 1"
  icc_header_summary "$OUT_DIR/profile_2.icc" "Profile 2"

  sig=$(read_sig "$OUT_DIR/profile_1.icc" 16)
  data_file="$OUT_DIR/search-data.txt"
  write_legacy_data "$data_file" "$sig" 3 5 "$pixel_seed"
  echo "  [OK] Search data: $data_file"

  echo "CLI reproduction candidate:"
  if [ "$use_pcc" -ne 0 ]; then
    echo "  iccApplySearch $data_file 3 $interp_arg $OUT_DIR/profile_1.icc $intent1 $OUT_DIR/profile_2.icc $intent2 -INIT $intent2 $OUT_DIR/profile_1.icc $pcc_weight"
  else
    echo "  iccApplySearch $data_file 3 $interp_arg $OUT_DIR/profile_1.icc $intent1 $OUT_DIR/profile_2.icc $intent2 -INIT $intent2"
    if [ "$weighted" -eq 1 ]; then
      echo "  note: applysearch-weight control disables PCC; omitting weight args matches the harness."
    fi
  fi
  if [ "$weighted" -eq 1 ]; then
    echo "Exact fuzzer replay:"
    echo "  cfl/bin/icc_applysearch_weight_fuzzer $CRASH_FILE -runs=1"
  fi

  tool="$(tool_bin IccApplySearch iccApplySearch)"
  if [ "$use_pcc" -ne 0 ]; then
    run_if_available "$tool" "$data_file" 3 "$interp_arg" "$OUT_DIR/profile_1.icc" "$intent1" "$OUT_DIR/profile_2.icc" "$intent2" -INIT "$intent2" "$OUT_DIR/profile_1.icc" "$pcc_weight"
  else
    run_if_available "$tool" "$data_file" 3 "$interp_arg" "$OUT_DIR/profile_1.icc" "$intent1" "$OUT_DIR/profile_2.icc" "$intent2" -INIT "$intent2"
  fi
}

unbundle_applyprofiles() {
  local force_row="$1"
  echo "Format: [75% ICC profile][25% control/pixel seed]"
  if [ "$FILE_SIZE" -lt 256 ]; then
    echo "ERROR: file too small for applyprofiles layout" >&2
    return 1
  fi

  local profile_size control_size
  profile_size=$(((FILE_SIZE * 3) / 4))
  control_size=$((FILE_SIZE - profile_size))

  extract_range 0 "$profile_size" "$OUT_DIR/profile.icc"
  extract_range "$profile_size" "$control_size" "$OUT_DIR/control.bin"

  echo "Extracted profile=$profile_size bytes control=$control_size bytes"
  check_icc_magic "$OUT_DIR/profile.icc" "Profile"
  icc_header_summary "$OUT_DIR/profile.icc" "Profile"

  local b0=0 b1=0 b2=0 b3=0 b4=0 intent interp dst_compress dst_planar threads
  local use_bpc use_luminance use_v5sub dst_embed use_d2bx bps_sel photo_sel bps
  local img_w img_h samples photo photo_name intent_name interp_name
  if [ "$control_size" -gt 0 ]; then
    read -r b0 b1 b2 b3 b4 < <(od -A n -t u1 -j "$profile_size" -N 5 "$CRASH_FILE")
  fi
  intent=$((b0 % 4))
  interp=$(( (b1 & 1) ? 0 : 1 ))
  use_bpc=$(( (b2 & 1) ? 1 : 0 ))
  use_luminance=$(( (b2 & 2) ? 1 : 0 ))
  use_v5sub=$(( (b2 & 4) ? 1 : 0 ))
  dst_embed=$(( (b2 & 8) ? 1 : 0 ))
  bps_sel=$(((b2 >> 4) & 3))
  photo_sel=$(((b2 >> 6) & 3))
  use_d2bx=$(( (b3 & 1) ? 1 : 0 ))
  img_w=$((((b3 >> 1) & 3) + 1))
  img_h=$((((b3 >> 3) & 3) + 1))
  dst_compress=$(( (b4 & 2) ? 1 : 0 ))
  dst_planar=$(( (b4 & 4) ? 1 : 0 ))
  if [ "$force_row" -eq 1 ] || [ $((b4 & 1)) -ne 0 ]; then
    threads=0
  else
    threads=1
  fi

  case "$bps_sel" in
    1) bps=16 ;;
    2) bps=32 ;;
    *) bps=8 ;;
  esac
  case "$photo_sel" in
    0) photo=2; photo_name="RGB"; samples=3 ;;
    1) photo=8; photo_name="CIELAB"; samples=3 ;;
    2) photo=1; photo_name="MINISBLACK"; samples=1 ;;
    *) photo=0; photo_name="MINISWHITE"; samples=1 ;;
  esac
  case "$intent" in
    0) intent_name="perceptual" ;;
    1) intent_name="relative" ;;
    2) intent_name="saturation" ;;
    *) intent_name="absolute" ;;
  esac
  if [ "$interp" -eq 0 ]; then
    interp_name="linear"
  else
    interp_name="tetrahedral"
  fi

  cat > "$OUT_DIR/control.txt" <<EOF
Fuzzer: $FUZZER
Original input: $CRASH_FILE
Layout: [75% ICC profile][25% control/pixel seed]

Generated files:
  profile.icc   raw ICC profile chunk; also embedded in source.tiff
  source.tiff   generated TIFF source image for iccApplyProfiles
  repro.json    JSON config matching the harness control flags
  control.bin   exact raw control/pixel seed bytes; not a standalone input
  control.txt   this decoded summary

Decoded control:
  intent=$intent ($intent_name)
  interpolation=$interp ($interp_name)
  flags=$b2
  image_byte=$b3
  option_flags=$b4
  use_bpc=$(json_bool "$use_bpc")
  adjust_pcs_luminance=$(json_bool "$use_luminance")
  use_v5_subprofile=$(json_bool "$use_v5sub")
  use_d2bx_b2dx=$(json_bool "$use_d2bx")
  dst_embed_icc=$(json_bool "$dst_embed")
  dst_compression=$(json_bool "$dst_compress")
  dst_planar=$(json_bool "$dst_planar")
  threads=$threads
  source_width=$img_w
  source_height=$img_h
  source_bits_per_sample=$bps
  source_photometric=$photo_name
  source_samples_per_pixel=$samples
EOF

  echo "Control: intent=$intent ($intent_name) interp=$interp ($interp_name) flags=$b2 image_byte=$b3 option_flags=$b4"
  echo "         ${img_w}x${img_h} ${bps}-bit $photo_name samples=$samples threads=$threads dst_compress=$dst_compress dst_planar=$dst_planar dst_embed_icc=$dst_embed"

  local source_tiff="$OUT_DIR/source.tiff"
  local output_tiff="$OUT_DIR/output.tiff"
  local repro_json="$OUT_DIR/repro.json"
  if command -v python3 >/dev/null; then
    if generate_applyprofiles_tiff "$OUT_DIR/profile.icc" "$OUT_DIR/control.bin" \
        "$source_tiff" "$repro_json" "$output_tiff" "$img_w" "$img_h" "$bps" \
        "$photo" "$samples" "$dst_compress" "$dst_planar" "$dst_embed" "$threads" \
        "$intent_name" "$interp_name" "$use_bpc" "$use_luminance" "$use_v5sub" "$use_d2bx"; then
      echo "  [OK] Source TIFF: $source_tiff"
      echo "  [OK] Repro config: $repro_json"
    else
      echo "  [WARN] Failed to generate source TIFF/config from control bytes" >&2
      return 1
    fi
  else
    echo "  [WARN] python3 not found; cannot generate source.tiff or repro.json" >&2
    return 1
  fi

  echo "CLI reproduction candidate:"
  echo "  iccApplyProfiles -cfg $repro_json"

  local tool="$TOOL_ROOT/IccApplyProfiles/iccApplyProfiles"
  if [ -n "$TOOL_ROOT" ] && [ -x "$tool" ]; then
    run_tool "$tool" -cfg "$repro_json" || true
  else
    echo "Tool not run; iccApplyProfiles not found under tool root."
  fi
}

unbundle_specsep() {
  echo "Format: [2-byte control][N equal TIFF chunks][optional ICC tail]"
  if [ "$FILE_SIZE" -lt 10 ]; then
    echo "ERROR: file too small for specsep layout" >&2
    return 1
  fi

  local ctrl0=0 ctrl1=0 n_files compress sep has_icc payload_size icc_size chunk_size
  local payload_offset=2 icc_path="" i blob_len skip out prefix tool
  read -r ctrl0 ctrl1 < <(od -A n -t u1 -N 2 "$CRASH_FILE")
  n_files=$(((ctrl0 % 8) + 1))
  compress=$(( (ctrl1 & 1) ? 1 : 0 ))
  sep=$(( (ctrl1 & 2) ? 1 : 0 ))
  has_icc=$(( (ctrl1 & 4) ? 1 : 0 ))
  payload_size=$((FILE_SIZE - 2))

  if [ "$has_icc" -ne 0 ]; then
    icc_size=$((payload_size / 4))
    if [ "$icc_size" -lt 16 ]; then
      icc_size=16
    fi
    if [ "$icc_size" -gt $((256 * 1024)) ]; then
      icc_size=$((256 * 1024))
    fi
    if [ "$icc_size" -ge $((payload_size - 8)) ]; then
      has_icc=0
      icc_size=0
    else
      payload_size=$((payload_size - icc_size))
      icc_path="$OUT_DIR/profile.icc"
      extract_range $((payload_offset + payload_size)) "$icc_size" "$icc_path"
    fi
  else
    icc_size=0
  fi

  chunk_size=$((payload_size / n_files))
  if [ "$chunk_size" -lt 8 ]; then
    echo "ERROR: TIFF chunk size too small: $chunk_size" >&2
    return 1
  fi

  prefix="$OUT_DIR/spec_"
  for ((i = 0; i < n_files; i++)); do
    skip=$((payload_offset + i * chunk_size))
    if [ "$i" -eq $((n_files - 1)) ]; then
      blob_len=$((payload_size - i * chunk_size))
    else
      blob_len=$chunk_size
    fi
    out="${prefix}${i}"
    extract_range "$skip" "$blob_len" "$out"
  done

  echo "Extracted tiff_chunks=$n_files chunk_size=$chunk_size compress=$compress sep=$sep has_icc=$has_icc icc_size=$icc_size"
  if [ "$has_icc" -ne 0 ]; then
    check_icc_magic "$icc_path" "Embedded profile"
    icc_header_summary "$icc_path" "Embedded profile"
  fi
  echo "CLI reproduction candidate:"
  if [ "$has_icc" -ne 0 ]; then
    echo "  iccSpecSepToTiff $OUT_DIR/output.tiff $compress $sep $prefix 0 $((n_files - 1)) 1 $icc_path"
  else
    echo "  iccSpecSepToTiff $OUT_DIR/output.tiff $compress $sep $prefix 0 $((n_files - 1)) 1"
  fi

  tool="$(tool_bin IccSpecSepToTiff iccSpecSepToTiff)"
  if [ "$has_icc" -ne 0 ]; then
    run_if_available "$tool" "$OUT_DIR/output.tiff" "$compress" "$sep" "$prefix" 0 "$((n_files - 1))" 1 "$icc_path"
  else
    run_if_available "$tool" "$OUT_DIR/output.tiff" "$compress" "$sep" "$prefix" 0 "$((n_files - 1))" 1
  fi
}

unbundle_applynamedcmm() {
  copy_icc_profile
  if [ "$FILE_SIZE" -lt 105 ]; then
    echo "ERROR: file too small for ApplyNamedCmm control bytes" >&2
    return 1
  fi

  local ctrl_xform ctrl_flags ctrl_intent ctrl_enc ctrl_pixel n_type intent interp_arg
  local src_enc dst_enc pixel_mode use_bpc use_luminance use_d2bx use_v5sub packed sig data_file tool
  read -r ctrl_xform ctrl_flags ctrl_intent ctrl_enc ctrl_pixel < <(od -A n -t u1 -j 100 -N 5 "$CRASH_FILE")
  n_type=$((ctrl_xform % 10))
  intent=$((ctrl_intent & 3))
  if [ $((ctrl_intent & 16)) -ne 0 ]; then
    interp_arg=1
  else
    interp_arg=0
  fi
  src_enc=$((ctrl_enc % 7))
  dst_enc=$(((ctrl_enc >> 4) % 7))
  pixel_mode=$((ctrl_pixel & 3))
  use_bpc=$(( (ctrl_flags & 1) ? 1 : 0 ))
  use_luminance=$(( (ctrl_flags & 2) ? 1 : 0 ))
  use_d2bx=$(( (ctrl_flags & 4) ? 0 : 1 ))
  use_v5sub=$(( (ctrl_flags & 8) ? 1 : 0 ))
  packed=$((n_type * 10 + intent))
  if [ "$use_luminance" -ne 0 ]; then
    packed=$((packed + 1000))
  fi
  if [ "$use_v5sub" -ne 0 ]; then
    packed=$((packed + 10000))
  fi
  if [ "$use_bpc" -ne 0 ] && [ "$n_type" -ne 4 ]; then
    echo "  [WARN] BPC flag is set outside packed nType=4; CLI candidate is nearest-effort."
  fi
  if [ "$use_d2bx" -eq 0 ] && [ "$n_type" -ne 1 ]; then
    echo "  [WARN] useD2Bx=false flag is set outside packed nType=1; CLI candidate is nearest-effort."
  fi

  sig=$(read_sig "$OUT_DIR/profile.icc" 16)
  data_file="$OUT_DIR/named-data.txt"
  write_legacy_data "$data_file" "$sig" "$src_enc" "$pixel_mode" 128

  echo "Control: n_type=$n_type intent=$intent interpolation=$interp_arg ($(interp_name "$interp_arg")) src_encoding=$src_enc dst_encoding=$dst_enc pixel_mode=$pixel_mode bpc=$use_bpc luminance=$use_luminance use_d2bx=$use_d2bx v5sub=$use_v5sub packed_intent=$packed"
  echo "  [OK] Named CMM data: $data_file"
  echo "CLI reproduction candidate:"
  echo "  iccApplyNamedCmm $data_file $dst_enc $interp_arg $OUT_DIR/profile.icc $packed"

  tool="$(tool_bin IccApplyNamedCmm iccApplyNamedCmm)"
  run_if_available "$tool" "$data_file" "$dst_enc" "$interp_arg" "$OUT_DIR/profile.icc" "$packed"
}

unbundle_connect() {
  echo "Format: [ICC profile][4-byte trailing control]"
  if [ "$FILE_SIZE" -lt 136 ]; then
    echo "ERROR: file too small for connect layout" >&2
    return 1
  fi

  local profile_size ctrl0=0 ctrl1=0 ctrl2=0 ctrl3=0 use_embedded try_named try_threaded threads
  profile_size=$((FILE_SIZE - 4))
  extract_range 0 "$profile_size" "$OUT_DIR/profile.icc"
  extract_range "$profile_size" 4 "$OUT_DIR/control.bin"
  read -r ctrl0 ctrl1 ctrl2 ctrl3 < <(od -A n -t u1 -j "$profile_size" -N 4 "$CRASH_FILE")
  use_embedded=$(( (ctrl0 & 1) ? 1 : 0 ))
  try_named=$(( (ctrl0 & 2) ? 1 : 0 ))
  try_threaded=$(( (ctrl0 & 4) ? 1 : 0 ))
  if [ "$try_threaded" -ne 0 ] && [ "$profile_size" -le $((64 * 1024)) ]; then
    threads=$(( ((ctrl1 >> 1) & 1) + 1 ))
  else
    threads=1
  fi

  echo "Extracted profile=$profile_size bytes control=4 bytes"
  echo "Control: use_embedded=$use_embedded try_named=$try_named try_threaded=$try_threaded threads=$threads apply_seed=$ctrl3 profile_flags=$ctrl2"
  check_icc_magic "$OUT_DIR/profile.icc" "Profile"
  icc_header_summary "$OUT_DIR/profile.icc" "Profile"
  echo "No exact iccDEV CLI equivalent; replay with cfl/bin/icc_connect_fuzzer for this library-level target."
}

unbundle_cfg() {
  echo "Format: [1-byte selector][JSON payload]"
  if [ "$FILE_SIZE" -lt 2 ]; then
    echo "ERROR: file too small for cfg layout" >&2
    return 1
  fi

  local selector payload_size dispatch
  selector=$(od -A n -t u1 -N 1 "$CRASH_FILE" | awk '{print $1}')
  payload_size=$((FILE_SIZE - 1))
  extract_range 0 1 "$OUT_DIR/selector.bin"
  extract_range 1 "$payload_size" "$OUT_DIR/input.json"
  case $((selector % 10)) in
    0) dispatch="CIccCfgDataApply" ;;
    1) dispatch="CIccCfgImageApply" ;;
    2) dispatch="CIccCfgSearchApply" ;;
    3) dispatch="CIccCfgProfile" ;;
    4) dispatch="CIccCfgProfileSequence" ;;
    5) dispatch="CIccCfgPccWeight" ;;
    6) dispatch="CIccCfgCreateLink" ;;
    7) dispatch="CIccCfgColorData" ;;
    8) dispatch="CIccCfgDataEntry" ;;
    *) dispatch="full config sections" ;;
  esac
  echo "Extracted selector=$selector dispatch='$dispatch' json_payload=$payload_size bytes"
  echo "No exact iccDEV CLI equivalent; replay with cfl/bin/icc_cfg_fuzzer for this parser dispatch target."
}

unbundle_single_icc_tool() {
  local tool_dir="$1" tool_name="$2"
  shift 2
  copy_icc_profile
  echo "CLI reproduction candidate:"
  printf '  %s %s' "$tool_name" "$OUT_DIR/profile.icc"
  printf ' %s' "$@"
  echo ""
  run_if_available "$(tool_bin "$tool_dir" "$tool_name")" "$OUT_DIR/profile.icc" "$@"
}

unbundle_dump() {
  copy_icc_profile
  local verb_byte=0 mode_byte=0 verboseness use_validate tool
  if [ "$FILE_SIZE" -ge 1 ]; then
    verb_byte=$(od -A n -t u1 -j $((FILE_SIZE - 1)) -N 1 "$CRASH_FILE" | awk '{print $1}')
  fi
  if [ "$FILE_SIZE" -ge 2 ]; then
    mode_byte=$(od -A n -t u1 -j $((FILE_SIZE - 2)) -N 1 "$CRASH_FILE" | awk '{print $1}')
  fi
  verboseness=$(((verb_byte % 100) + 1))
  use_validate=$((mode_byte & 1))
  echo "Control: verboseness=$verboseness use_validate=$use_validate"
  echo "CLI reproduction candidate:"
  if [ "$use_validate" -ne 0 ]; then
    echo "  iccDumpProfile -v $verboseness $OUT_DIR/profile.icc ALL"
  else
    echo "  iccDumpProfile $verboseness $OUT_DIR/profile.icc ALL"
  fi
  tool="$(tool_bin IccDumpProfile iccDumpProfile)"
  if [ "$use_validate" -ne 0 ]; then
    run_if_available "$tool" -v "$verboseness" "$OUT_DIR/profile.icc" ALL
  else
    run_if_available "$tool" "$verboseness" "$OUT_DIR/profile.icc" ALL
  fi
}

unbundle_roundtrip() {
  copy_icc_profile
  local intent=0 use_mpe=0 tool
  if [ "$FILE_SIZE" -ge 1 ]; then
    intent=$(od -A n -t u1 -j $((FILE_SIZE - 1)) -N 1 "$CRASH_FILE" | awk '{print $1 % 4}')
  fi
  if [ "$FILE_SIZE" -ge 2 ]; then
    use_mpe=$(od -A n -t u1 -j $((FILE_SIZE - 2)) -N 1 "$CRASH_FILE" | awk '{print $1 % 2}')
  fi
  echo "Control: intent=$intent use_mpe=$use_mpe"
  echo "CLI reproduction candidate:"
  echo "  iccRoundTrip $OUT_DIR/profile.icc $intent $use_mpe"
  tool="$(tool_bin IccRoundTrip iccRoundTrip)"
  run_if_available "$tool" "$OUT_DIR/profile.icc" "$intent" "$use_mpe"
}

unbundle_fromxml() {
  copy_raw "input.xml" "XML"
  echo "CLI reproduction candidate:"
  echo "  iccFromXml $OUT_DIR/input.xml $OUT_DIR/output.icc"
  run_if_available "$(tool_bin IccFromXml iccFromXml)" "$OUT_DIR/input.xml" "$OUT_DIR/output.icc"
}

unbundle_fromjson() {
  copy_raw "input.json" "JSON"
  echo "CLI reproduction candidate:"
  echo "  iccFromJson $OUT_DIR/input.json $OUT_DIR/output.icc"
  run_if_available "$(tool_bin IccFromJson iccFromJson)" "$OUT_DIR/input.json" "$OUT_DIR/output.icc"
}

unbundle_fromcube() {
  copy_raw "input.cube" "CUBE"
  echo "CLI reproduction candidate:"
  echo "  iccFromCube $OUT_DIR/input.cube $OUT_DIR/output.icc"
  run_if_available "$(tool_bin IccFromCube iccFromCube)" "$OUT_DIR/input.cube" "$OUT_DIR/output.icc"
}

unbundle_tiffdump() {
  copy_raw "input.tiff" "TIFF"
  echo "CLI reproduction candidate:"
  echo "  iccTiffDump $OUT_DIR/input.tiff $OUT_DIR/extracted.icc"
  run_if_available "$(tool_bin IccTiffDump iccTiffDump)" "$OUT_DIR/input.tiff" "$OUT_DIR/extracted.icc"
}

case "$FUZZER" in
  icc_applynamedcmm_fuzzer)
    unbundle_applynamedcmm
    ;;
  icc_v5dspobs_fuzzer)
    unbundle_v5dspobs
    ;;
  icc_link_fuzzer)
    unbundle_link
    ;;
  icc_applyprofiles_fuzzer)
    unbundle_applyprofiles 0
    ;;
  icc_applyprofiles_row_fuzzer)
    unbundle_applyprofiles 1
    ;;
  icc_applysearch_fuzzer)
    unbundle_applysearch 0
    ;;
  icc_applysearch_weight_fuzzer)
    unbundle_applysearch 1
    ;;
  icc_connect_fuzzer)
    unbundle_connect
    ;;
  icc_cfg_fuzzer)
    unbundle_cfg
    ;;
  icc_dump_fuzzer)
    unbundle_dump
    ;;
  icc_fromcube_fuzzer)
    unbundle_fromcube
    ;;
  icc_fromjson_fuzzer)
    unbundle_fromjson
    ;;
  icc_fromxml_fuzzer)
    unbundle_fromxml
    ;;
  icc_roundtrip_fuzzer)
    unbundle_roundtrip
    ;;
  icc_specsep_fuzzer)
    unbundle_specsep
    ;;
  icc_tiffdump_fuzzer)
    unbundle_tiffdump
    ;;
  icc_tojson_fuzzer)
    unbundle_single_icc_tool IccToJson iccToJson "$OUT_DIR/output.json"
    ;;
  icc_toxml_fuzzer)
    unbundle_single_icc_tool IccToXml iccToXml "$OUT_DIR/output.xml"
    ;;
esac

echo ""
echo "Done - files in $OUT_DIR/"
