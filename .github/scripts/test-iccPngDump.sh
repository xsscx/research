#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccPngDump.sh — iccPngDump envelope tests
# Usage: ./test-iccPngDump.sh [--asan] [--quick]
source "$(dirname "$0")/iccdev-test-common.sh"

PNGDUMP="$TOOLS/IccPngDump/iccPngDump"
echo "=== iccPngDump ==="

# CVE PNG
if [ -f "$PNG_CVE" ]; then
  run_test "pd-01" "CVE PNG with ICC" "$PNGDUMP" "$PNG_CVE"
fi

# Seed images directory PNGs (parallel — works in both research and iccDEV)
SEED_PNGS=()
for png_file in "$TP_IMG"/*.png; do
  [ -f "$png_file" ] && SEED_PNGS+=("$png_file")
done
if [ "${#SEED_PNGS[@]}" -gt 0 ]; then
  run_batch_parallel "pd-seed" "Seed PNG" "$PNGDUMP" -- "${SEED_PNGS[@]}"
fi

# Named PNGs in fuzz corpus (parallel)
CVE_PNGS=()
for png_file in "$REPO_ROOT"/fuzz/graphics/png/CVE-*.png \
                "$REPO_ROOT"/fuzz/graphics/png/cve-*.png; do
  [ -f "$png_file" ] && CVE_PNGS+=("$png_file")
done
if [ "${#CVE_PNGS[@]}" -gt 0 ]; then
  run_batch_parallel "pd-cve" "CVE PNG" "$PNGDUMP" -- "${CVE_PNGS[@]}"
fi

# macOS generated PNGs (parallel)
GEN_PNGS=()
for png_file in "$REPO_ROOT"/fuzz/xnuimagegenerator/png/*.png; do
  [ -f "$png_file" ] && GEN_PNGS+=("$png_file")
done
if [ "${#GEN_PNGS[@]}" -gt 0 ]; then
  run_batch_parallel "pd-gen" "Generated PNG" "$PNGDUMP" -- "${GEN_PNGS[@]}"
fi

# Batch fuzz PNGs (parallel, random sample)
FUZZ_PNG_DIR="$REPO_ROOT/fuzz/graphics/png"
if [ -d "$FUZZ_PNG_DIR" ]; then
  MAX_BATCH=10
  [ "$QUICK_MODE" -eq 1 ] && MAX_BATCH=3
  FUZZ_PNGS=()
  while IFS= read -r f; do FUZZ_PNGS+=("$f"); done < <(find "$FUZZ_PNG_DIR" -maxdepth 1 -name '*.png' 2>/dev/null | shuf -n "$MAX_BATCH")
  if [ "${#FUZZ_PNGS[@]}" -gt 0 ]; then
    run_batch_parallel "pd-fuzz" "Fuzz PNG" "$PNGDUMP" -- "${FUZZ_PNGS[@]}"
  fi
fi

print_summary "iccPngDump"
exit "$FAIL"
