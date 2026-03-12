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

# Named JPEGs in fuzz corpus
for jpg_file in "$REPO_ROOT"/fuzz/graphics/jpg/CVE-*.jpg \
                "$REPO_ROOT"/fuzz/graphics/jpg/cve-*.jpg; do
  if [ -f "$jpg_file" ]; then
    base=$(basename "$jpg_file" .jpg | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    run_test "jd-cve-$base" "CVE JPEG: $base" "$JPEGDUMP" "$jpg_file"
  fi
done

# macOS generated JPEGs
for jpg_file in "$REPO_ROOT"/fuzz/xnuimagegenerator/jpg/*.jpg; do
  if [ -f "$jpg_file" ]; then
    base=$(basename "$jpg_file" .jpg | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-30)
    run_test "jd-gen-$base" "Generated JPEG: $base" "$JPEGDUMP" "$jpg_file"
  fi
done

# Batch fuzz JPEGs (random sample)
FUZZ_JPG_DIR="$REPO_ROOT/fuzz/graphics/jpg"
if [ -d "$FUZZ_JPG_DIR" ]; then
  MAX_BATCH=10
  [ "$QUICK_MODE" -eq 1 ] && MAX_BATCH=3
  for jpg_file in $(find "$FUZZ_JPG_DIR" -maxdepth 1 -name '*.jpg' -o -name '*.jpeg' 2>/dev/null | shuf -n "$MAX_BATCH"); do
    base=$(basename "$jpg_file" | sed 's/\.[^.]*$//' | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    run_test "jd-fuzz-$base" "Fuzz JPEG: $base" "$JPEGDUMP" "$jpg_file"
  done
fi

print_summary "iccJpegDump"
exit $FAIL
