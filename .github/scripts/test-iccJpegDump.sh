#!/bin/bash
# test-iccJpegDump.sh — iccJpegDump envelope tests
# Usage: ./test-iccJpegDump.sh [--asan] [--quick]
# Note: exit=1 is NORMAL when JPEG has no embedded ICC profile — tool limitation
source "$(dirname "$0")/iccdev-test-common.sh"

JPEGDUMP="$TOOLS/IccJpegDump/iccJpegDump"
echo "=== iccJpegDump ==="

# CVE JPEG
if [ -f "$JPG_CVE" ]; then
  run_test "jd-01" "CVE JPEG with ICC" "$JPEGDUMP" "$JPG_CVE"
fi

# Named JPEGs in fuzz corpus (parallel)
CVE_JPGS=()
for jpg_file in "$REPO_ROOT"/fuzz/graphics/jpg/CVE-*.jpg \
                "$REPO_ROOT"/fuzz/graphics/jpg/cve-*.jpg; do
  [ -f "$jpg_file" ] && CVE_JPGS+=("$jpg_file")
done
if [ "${#CVE_JPGS[@]}" -gt 0 ]; then
  run_batch_parallel "jd-cve" "CVE JPEG" "$JPEGDUMP" -- "${CVE_JPGS[@]}"
fi

# macOS generated JPEGs (parallel)
GEN_JPGS=()
for jpg_file in "$REPO_ROOT"/fuzz/xnuimagegenerator/jpg/*.jpg; do
  [ -f "$jpg_file" ] && GEN_JPGS+=("$jpg_file")
done
if [ "${#GEN_JPGS[@]}" -gt 0 ]; then
  run_batch_parallel "jd-gen" "Generated JPEG" "$JPEGDUMP" -- "${GEN_JPGS[@]}"
fi

# Batch fuzz JPEGs (parallel, random sample)
FUZZ_JPG_DIR="$REPO_ROOT/fuzz/graphics/jpg"
if [ -d "$FUZZ_JPG_DIR" ]; then
  MAX_BATCH=10
  [ "$QUICK_MODE" -eq 1 ] && MAX_BATCH=3
  FUZZ_JPGS=()
  while IFS= read -r f; do FUZZ_JPGS+=("$f"); done < <(find "$FUZZ_JPG_DIR" -maxdepth 1 \( -name '*.jpg' -o -name '*.jpeg' \) 2>/dev/null | shuf -n "$MAX_BATCH")
  if [ "${#FUZZ_JPGS[@]}" -gt 0 ]; then
    run_batch_parallel "jd-fuzz" "Fuzz JPEG" "$JPEGDUMP" -- "${FUZZ_JPGS[@]}"
  fi
fi

print_summary "iccJpegDump"
exit $FAIL
