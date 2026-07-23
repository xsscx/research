#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccApplyToLink.sh - iccApplyToLink envelope tests
# Usage: ./test-iccApplyToLink.sh [--asan] [--quick]
# Note: LUT generation with gridpoints>=17 can take 10-30s
source "$(dirname "$0")/iccdev-test-common.sh"

APPLYLINK="$TOOLS/IccApplyToLink/iccApplyToLink"
echo "=== iccApplyToLink ==="

collect_marked_inputs() {
  local output_var="$1"
  shift
  local dir
  local f
  local -a found=()

  for dir in "$@"; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' f; do
      found+=("$f")
    done < <(find "$dir" -type f ! -name '*.cmd' -print0 2>/dev/null | sort -z)
  done

  eval "$output_var"'=("${found[@]}")'
}

split_path_list() {
  local output_var="$1"
  local path_list="$2"
  local old_ifs="$IFS"
  local -a parts=()

  IFS=:
  read -r -a parts <<< "$path_list"
  IFS="$old_ifs"

  eval "$output_var"'=("${parts[@]}")'
}

if [ "$QUICK_MODE" -eq 0 ]; then
  # Device Link (type=0) with varying LUT sizes
  run_test "link-01" "DeviceLink sRGB->sRGB LUT=9 v4" \
    "$APPLYLINK" "$OUTDIR/link_srgb_9.icc" 0 9 0 "sRGB-link" 0.0 1.0 0 0 "$SRGB" 1

  run_test "link-02" "DeviceLink sRGB->sRGB LUT=17 v5" \
    "$APPLYLINK" "$OUTDIR/link_srgb_17.icc" 0 17 1 "sRGB-link-v5" 0.0 1.0 0 0 "$SRGB" 1

  run_test "link-03" "DeviceLink sRGB->sRGB LUT=33" \
    "$APPLYLINK" "$OUTDIR/link_srgb_33.icc" 0 33 0 "sRGB-link-33" 0.0 1.0 0 0 "$SRGB" 1

  # .cube output (type=1)
  run_test "link-04" ".cube output sRGB LUT=9 precision=6" \
    "$APPLYLINK" "$OUTDIR/link_srgb.cube" 1 9 6 "sRGB-cube" 0.0 1.0 0 0 "$SRGB" 1

  # Tetrahedral interpolation
  run_test "link-05" "DeviceLink sRGB tetrahedral LUT=9" \
    "$APPLYLINK" "$OUTDIR/link_srgb_tet.icc" 0 9 0 "sRGB-tet" 0.0 1.0 0 1 "$SRGB" 1

  # Destination transform (first_transform=1)
  run_test "link-06" "DeviceLink first_transform=1 (dest)" \
    "$APPLYLINK" "$OUTDIR/link_srgb_dest.icc" 0 9 0 "sRGB-dest" 0.0 1.0 1 0 "$SRGB" 1

  # Two-profile chain
  run_test "link-07" "DeviceLink sRGB->DisplayP3 chain" \
    "$APPLYLINK" "$OUTDIR/link_srgb_p3.icc" 0 17 0 "sRGB-to-P3" 0.0 1.0 0 0 "$SRGB" 1 "$DISPLAY_P3" 1
else
  # Quick mode: smaller LUTs only
  run_test "link-01" "DeviceLink sRGB->sRGB LUT=5 (quick)" \
    "$APPLYLINK" "$OUTDIR/link_srgb_5.icc" 0 5 0 "sRGB-link-q" 0.0 1.0 0 0 "$SRGB" 1

  run_test "link-04" ".cube output sRGB LUT=5 (quick)" \
    "$APPLYLINK" "$OUTDIR/link_srgb_q.cube" 1 5 4 "sRGB-cube-q" 0.0 1.0 0 0 "$SRGB" 1
fi

MARKED_DEVICE_DIRS=()
MARKED_CUBE_DIRS=()
if [ -n "${ICCDEV_APPLYTOLINK_AFL_DIRS:-}" ]; then
  split_path_list MARKED_DEVICE_DIRS "$ICCDEV_APPLYTOLINK_AFL_DIRS"
else
  MARKED_DEVICE_DIRS=(
    "$REPO_ROOT/afl/marked/applytolink"
  )
fi

if [ -n "${ICCDEV_APPLYTOLINK_CUBE_AFL_DIRS:-}" ]; then
  split_path_list MARKED_CUBE_DIRS "$ICCDEV_APPLYTOLINK_CUBE_AFL_DIRS"
else
  MARKED_CUBE_DIRS=(
    "$REPO_ROOT/afl/marked/applytolink-cube"
  )
fi

MARKED_DEVICE_INPUTS=()
MARKED_CUBE_INPUTS=()
collect_marked_inputs MARKED_DEVICE_INPUTS "${MARKED_DEVICE_DIRS[@]}"
collect_marked_inputs MARKED_CUBE_INPUTS "${MARKED_CUBE_DIRS[@]}"

for marked_input in "${MARKED_DEVICE_INPUTS[@]}"; do
  marked_base="$(basename "$marked_input" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-36)"
  run_test "link-afl-${marked_base}" "AFL marked DeviceLink: ${marked_base}" \
    "$APPLYLINK" "$OUTDIR/afl_${marked_base}.icc" 0 2 1 "AFL-marked" 0.0 1.0 0 0 "$marked_input" 40
done

for marked_input in "${MARKED_CUBE_INPUTS[@]}"; do
  marked_base="$(basename "$marked_input" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-36)"
  run_test "link-afl-cube-${marked_base}" "AFL marked cube: ${marked_base}" \
    "$APPLYLINK" "$OUTDIR/afl_${marked_base}.cube" 1 2 4 "AFL-marked-cube" 0.0 1.0 0 0 "$marked_input" 13
done

print_summary "iccApplyToLink"
exit "$FAIL"
