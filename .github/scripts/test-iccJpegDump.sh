#!/bin/bash
# shellcheck source=iccdev-test-common.sh
# test-iccJpegDump.sh — iccJpegDump envelope tests
# Usage: ./test-iccJpegDump.sh [--asan] [--quick]
# iccJpegDump requires: <input.jpg> <output.icc> (extraction mode)
source "$(dirname "$0")/iccdev-test-common.sh"

JPEGDUMP="$TOOLS/IccJpegDump/iccJpegDump"
echo "=== iccJpegDump ==="

# Create temp dir for extracted ICC outputs
JPEG_TMPDIR="$OUTDIR/jpeg-icc-out"
mkdir -p "$JPEG_TMPDIR"

# Helper: run iccJpegDump in extraction mode (input.jpg → tmp output.icc)
run_jpeg_test() {
  local test_id="$1" description="$2" jpg_file="$3"
  local out_icc="$JPEG_TMPDIR/${test_id}.icc"
  run_test "$test_id" "$description" "$JPEGDUMP" "$jpg_file" "$out_icc"
}

# Helper: batch parallel extraction (writes wrapper script per file)
run_jpeg_batch_parallel() {
  local id_prefix="$1" desc_prefix="$2"
  shift 2
  local -a files=("$@")

  if [ "${#files[@]}" -eq 0 ]; then return 0; fi

  local pids=() test_ids=() idx=0
  local max_jobs="$NCPU"

  for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    idx=$((idx + 1))
    local base
    base=$(basename "$f" | sed 's/\.[^.]*$//' | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    local test_id="${id_prefix}-${base}"
    local logfile="$OUTDIR/${test_id}.log"
    local out_icc="$JPEG_TMPDIR/${test_id}.icc"
    local desc
    desc="$(_safe_desc "${desc_prefix}: $(basename "$f" | cut -c1-50)")"

    (
      local ec=0
      timeout 60 "$JPEGDUMP" "$f" "$out_icc" > "$logfile" 2>&1 || ec=$?
      _classify_result "$test_id" "$desc" "$ec" "$logfile"
    ) &
    pids+=($!)
    test_ids+=("$test_id")

    if [ "${#pids[@]}" -ge "$max_jobs" ]; then
      wait "${pids[0]}" 2>/dev/null || true
      pids=("${pids[@]:1}")
    fi
  done

  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  # Collect results
  for tid in "${test_ids[@]}"; do
    local rf="$_PARALLEL_DIR/$tid.result"
    if [ -f "$rf" ]; then
      local status exit_code has_asan has_ubsan description note sanitizer_note
      IFS=$'\t' read -r status exit_code has_asan has_ubsan description note sanitizer_note < "$rf"
      TOTAL=$((TOTAL + 1))
      if [ "$status" = "PASS" ]; then
        PASS=$((PASS + 1))
      else
        FAIL=$((FAIL + 1))
      fi
      [ "$has_asan" -eq 1 ] && ASAN_FINDINGS=$((ASAN_FINDINGS + 1))
      [ "$has_ubsan" -eq 1 ] && UBSAN_FINDINGS=$((UBSAN_FINDINGS + 1))
      printf "  [%-7s] %-55s exit=%-3d%s%s\n" "$status" "$description" "$exit_code" "$note" "$sanitizer_note"
    fi
  done
}

# CVE JPEG
if [ -f "$JPG_CVE" ]; then
  run_jpeg_test "jd-01" "CVE JPEG with ICC" "$JPG_CVE"
fi

# Seed images directory JPEGs
SEED_JPGS=()
for jpg_file in "$TP_IMG"/*.jpg "$TP_IMG"/*.jpeg; do
  [ -f "$jpg_file" ] && SEED_JPGS+=("$jpg_file")
done
if [ "${#SEED_JPGS[@]}" -gt 0 ]; then
  run_jpeg_batch_parallel "jd-seed" "Seed JPEG" "${SEED_JPGS[@]}"
fi

# Named JPEGs in fuzz corpus
CVE_JPGS=()
for jpg_file in "$FUZZ_JPG_DIR"/CVE-*.jpg \
                "$FUZZ_JPG_DIR"/cve-*.jpg; do
  [ -f "$jpg_file" ] && CVE_JPGS+=("$jpg_file")
done
if [ "${#CVE_JPGS[@]}" -gt 0 ]; then
  run_jpeg_batch_parallel "jd-cve" "CVE JPEG" "${CVE_JPGS[@]}"
fi

# macOS generated JPEGs
GEN_JPGS=()
for jpg_file in "$MACOS_SPECTRAL"/../../../jpg/*.jpg; do
  [ -f "$jpg_file" ] && GEN_JPGS+=("$jpg_file")
done
if [ -d "$REPO_ROOT/fuzz/xnuimagegenerator/jpg" ]; then
  for jpg_file in "$REPO_ROOT"/fuzz/xnuimagegenerator/jpg/*.jpg; do
    [ -f "$jpg_file" ] && GEN_JPGS+=("$jpg_file")
  done
fi
if [ "${#GEN_JPGS[@]}" -gt 0 ]; then
  run_jpeg_batch_parallel "jd-gen" "Generated JPEG" "${GEN_JPGS[@]}"
fi

# Batch fuzz JPEGs (random sample)
if [ -d "$FUZZ_JPG_DIR" ]; then
  MAX_BATCH=10
  [ "$QUICK_MODE" -eq 1 ] && MAX_BATCH=3
  FUZZ_JPGS=()
  while IFS= read -r f; do FUZZ_JPGS+=("$f"); done < <(find "$FUZZ_JPG_DIR" -maxdepth 1 \( -name '*.jpg' -o -name '*.jpeg' \) 2>/dev/null | shuf -n "$MAX_BATCH")
  if [ "${#FUZZ_JPGS[@]}" -gt 0 ]; then
    run_jpeg_batch_parallel "jd-fuzz" "Fuzz JPEG" "${FUZZ_JPGS[@]}"
  fi
fi

print_summary "iccJpegDump"
exit "$FAIL"
