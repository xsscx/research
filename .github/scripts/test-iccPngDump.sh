#!/bin/bash
# test-iccPngDump.sh — iccPngDump envelope tests
# Usage: ./test-iccPngDump.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

PNGDUMP="$TOOLS/IccPngDump/iccPngDump"
echo "=== iccPngDump ==="

# CVE PNG
if [ -f "$PNG_CVE" ]; then
  run_test "pd-01" "CVE PNG with ICC" "$PNGDUMP" "$PNG_CVE"
fi

# Named PNGs in fuzz corpus
for png_file in "$REPO_ROOT"/fuzz/graphics/png/CVE-*.png \
                "$REPO_ROOT"/fuzz/graphics/png/cve-*.png; do
  if [ -f "$png_file" ]; then
    base=$(basename "$png_file" .png | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    run_test "pd-cve-$base" "CVE PNG: $base" "$PNGDUMP" "$png_file"
  fi
done

# macOS generated PNGs
for png_file in "$REPO_ROOT"/fuzz/xnuimagegenerator/png/*.png; do
  if [ -f "$png_file" ]; then
    base=$(basename "$png_file" .png | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-30)
    run_test "pd-gen-$base" "Generated PNG: $base" "$PNGDUMP" "$png_file"
  fi
done

# Batch fuzz PNGs (random sample)
FUZZ_PNG_DIR="$REPO_ROOT/fuzz/graphics/png"
if [ -d "$FUZZ_PNG_DIR" ]; then
  MAX_BATCH=10
  [ "$QUICK_MODE" -eq 1 ] && MAX_BATCH=3
  for png_file in $(find "$FUZZ_PNG_DIR" -maxdepth 1 -name '*.png' 2>/dev/null | shuf -n "$MAX_BATCH"); do
    base=$(basename "$png_file" .png | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    run_test "pd-fuzz-$base" "Fuzz PNG: $base" "$PNGDUMP" "$png_file"
  done
fi

print_summary "iccPngDump"
exit $FAIL
