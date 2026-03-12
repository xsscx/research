#!/bin/bash
# test-iccV5DspObsToV4Dsp.sh — iccV5DspObsToV4Dsp envelope tests
# Usage: ./test-iccV5DspObsToV4Dsp.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

V5DSP="$TOOLS/IccV5DspObsToV4Dsp/iccV5DspObsToV4Dsp"
echo "=== iccV5DspObsToV4Dsp ==="

# V5 display profiles
V5_PROFILES=()
for icc in "$REPO_ROOT"/test-profiles/*Display*.icc \
           "$REPO_ROOT"/test-profiles/LCD*.icc \
           "$REPO_ROOT"/test-profiles/*LCDDisplay*.icc; do
  [ -f "$icc" ] && V5_PROFILES+=("$icc")
done

# Observer profiles (from extended test profiles or test-profiles)
OBS_PROFILES=()
for obs in "$REPO_ROOT"/test-profiles/*observer*.icc \
           "$REPO_ROOT"/extended-test-profiles/*observer*.icc \
           "$REPO_ROOT"/test-profiles/*Observer*.icc \
           "$REPO_ROOT"/extended-test-profiles/*Observer*.icc; do
  [ -f "$obs" ] && OBS_PROFILES+=("$obs")
done

COUNT=0
if [ "${#V5_PROFILES[@]}" -gt 0 ]; then
  for v5_icc in "${V5_PROFILES[@]}"; do
    v5base=$(basename "$v5_icc" .icc | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-20)

    # With observer profile (if available)
    if [ "${#OBS_PROFILES[@]}" -gt 0 ]; then
      for obs_icc in "${OBS_PROFILES[@]}"; do
        obsbase=$(basename "$obs_icc" .icc | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-20)
        run_test "v5-${v5base}-${obsbase}" "V5: $v5base obs=$obsbase" \
          "$V5DSP" "$v5_icc" "$obs_icc" "$OUTDIR/v5_${v5base}_${obsbase}.icc"
        COUNT=$((COUNT + 1))
        [ "$QUICK_MODE" -eq 1 ] && [ "$COUNT" -ge 5 ] && break 2
      done
    else
      # Without observer (2-arg form)
      run_test "v5-${v5base}" "V5: $v5base (no observer)" \
        "$V5DSP" "$v5_icc" "$OUTDIR/v5_${v5base}.icc"
      COUNT=$((COUNT + 1))
      [ "$QUICK_MODE" -eq 1 ] && [ "$COUNT" -ge 5 ] && break
    fi
  done
fi

# Fallback: test with sRGB as input (may fail — not a v5 profile)
if [ "$COUNT" -eq 0 ]; then
  run_test "v5-srgb-fallback" "V5: sRGB (may fail, not v5)" \
    "$V5DSP" "$SRGB" "$OUTDIR/v5_srgb.icc"
fi

print_summary "iccV5DspObsToV4Dsp"
exit $FAIL
