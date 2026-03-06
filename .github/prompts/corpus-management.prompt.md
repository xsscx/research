# Corpus Management — SSD/Ramdisk Lifecycle

Manage fuzzing corpus across storage tiers: permanent (cfl/corpus-*/), ramdisk (/tmp/fuzz-ramdisk), and external SSD (/mnt/g/fuzz-ssd).

## Prerequisites
- Fuzzers built: `ls cfl/bin/icc_*_fuzzer | wc -l` should return 19
- LLVM tools: `llvm-profdata-18`, `llvm-cov-18`
- For SSD: mounted at /mnt/g with `sudo mount -o defaults,noatime /dev/sde /mnt/g`

## The 19 Fuzzers
```
icc_apply_fuzzer  icc_applynamedcmm_fuzzer  icc_applyprofiles_fuzzer
icc_calculator_fuzzer  icc_deep_dump_fuzzer  icc_dump_fuzzer
icc_fromcube_fuzzer  icc_fromxml_fuzzer  icc_io_fuzzer
icc_link_fuzzer  icc_multitag_fuzzer  icc_profile_fuzzer
icc_roundtrip_fuzzer  icc_specsep_fuzzer  icc_spectral_b_fuzzer
icc_spectral_fuzzer  icc_tiffdump_fuzzer  icc_toxml_fuzzer
icc_v5dspobs_fuzzer
```

## Storage Setup

### Option A: tmpfs Ramdisk (8GB, short runs)
```bash
.github/scripts/ramdisk-seed.sh --mount
```

### Option B: External SSD (1TB, extended fuzzing)
```bash
sudo mount -o defaults,noatime /dev/sde /mnt/g
.github/scripts/ramdisk-seed.sh --ramdisk /mnt/g/fuzz-ssd
```

## Fuzzing

```bash
# All 19 fuzzers on ramdisk (default)
cd cfl && ./fuzz-local.sh

# All 19 fuzzers on SSD
cd cfl && ./fuzz-local.sh -r /mnt/g/fuzz-ssd

# Single fuzzer smoke test (60s)
ASAN_OPTIONS=detect_leaks=0 \
LLVM_PROFILE_FILE="/path/profraw/icc_profile_fuzzer_%m_%p.profraw" \
  cfl/bin/icc_profile_fuzzer -max_total_time=60 -detect_leaks=0 \
  -timeout=30 -rss_limit_mb=4096 -use_value_profile=1 -max_len=5242880 \
  -dict=cfl/icc_profile_fuzzer.dict \
  /path/corpus-icc_profile_fuzzer/
```

### Special fuzzer flags
- **icc_link_fuzzer**: `ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256`
- **Coverage profraw**: `LLVM_PROFILE_FILE=${STORAGE}/profraw/${fuzzer_name}_%m_%p.profraw`
- **Suppress profraw**: `LLVM_PROFILE_FILE=/dev/null`

## End-of-Session: Coverage + Migration

### Step 1: Generate Coverage Report
```bash
# Merge profraw files
llvm-profdata-18 merge -sparse /path/profraw/*.profraw -o /path/merged.profdata

# Generate text + HTML report
OBJS=$(printf ' -object %s' cfl/bin/icc_*_fuzzer)
llvm-cov-18 report $OBJS -instr-profile=/path/merged.profdata
llvm-cov-18 show $OBJS -instr-profile=/path/merged.profdata \
  --format=html --output-dir=coverage-report/html

# Or use the helper script
.github/scripts/generate-coverage-report.sh /path/merged.profdata coverage-report/ cfl/bin/icc_*_fuzzer
```

### Step 2: Migrate Corpus to Permanent Storage
Use parallel rsync (8 jobs max) — NOT LibFuzzer merge for large migrations:
```bash
SSD="/mnt/g/fuzz-ssd"  # or /tmp/fuzz-ramdisk
DEST="cfl"

FUZZERS=(icc_apply_fuzzer icc_applynamedcmm_fuzzer icc_applyprofiles_fuzzer
  icc_calculator_fuzzer icc_deep_dump_fuzzer icc_dump_fuzzer
  icc_fromcube_fuzzer icc_fromxml_fuzzer icc_io_fuzzer
  icc_link_fuzzer icc_multitag_fuzzer icc_profile_fuzzer
  icc_roundtrip_fuzzer icc_specsep_fuzzer icc_spectral_b_fuzzer
  icc_spectral_fuzzer icc_tiffdump_fuzzer icc_toxml_fuzzer
  icc_v5dspobs_fuzzer)

for fuzzer in "${FUZZERS[@]}"; do
  rsync -a --ignore-existing "$SSD/corpus-${fuzzer}/" "$DEST/corpus-${fuzzer}/" &
  while [ $(jobs -r | wc -l) -ge 8 ]; do sleep 1; done
done
wait
```

### Step 3: Optional Corpus Dedup (deferred, per-fuzzer)
LibFuzzer merge deduplicates but is slow. Run 4-6 at a time max:
```bash
.github/scripts/ramdisk-merge.sh --ramdisk /path --jobs 4
```
Or individual:
```bash
mkdir -p /tmp/merged-output
cfl/bin/icc_profile_fuzzer -merge=1 /tmp/merged-output cfl/corpus-icc_profile_fuzzer/
# Then replace: rm -rf cfl/corpus-icc_profile_fuzzer && mv /tmp/merged-output cfl/corpus-icc_profile_fuzzer
```

### Step 4: Unmount
```bash
sudo umount /mnt/g
```

## Corpus Status Check
```bash
echo "=== Corpus Status ==="
total=0
for d in cfl/corpus-*/; do
  name=$(basename "$d" | sed 's/^corpus-//')
  count=$(ls "$d" 2>/dev/null | wc -l)
  sz=$(du -sh "$d" 2>/dev/null | cut -f1)
  total=$((total + count))
  printf "%-40s %6d files  %s\n" "$name" "$count" "$sz"
done
echo "Total: $total files"
```

## Coverage Baseline (March 2026)
| Metric | Value |
|--------|-------|
| Functions | 63.23% |
| Lines | 61.15% |
| Branches | 58.47% |
| Instantiations | 62.99% |

## Lessons Learned
- **Profraw naming**: Use `${fuzzer_name}_%m_%p.profraw` (not `%m.profraw`). `%m` is a numeric module hash, NOT the binary name.
- **Parallel merge limit**: >8 concurrent LibFuzzer merges cause empty output due to I/O contention. Use 4-6 max.
- **Direct rsync vs merge**: For end-of-session migration, rsync is faster and safer. Dedup can be done later.
- **Roundtrip fuzzer**: Very slow (Read→Write→Read per input). Allow 120s+ timeout for merge.
- **Link fuzzer**: Needs quarantine_size_mb=256 (2 profiles per input = 2x ASAN memory).
