# Corpus Management — SSD/Ramdisk Lifecycle

Manage fuzzing corpus across storage tiers: permanent (cfl/corpus-*/), ramdisk (/tmp/fuzz-ramdisk), and external SSD (/mnt/g/fuzz-ssd).

## Prerequisites
- Fuzzers built: `ls cfl/bin/icc_*_fuzzer | wc -l` should return 11
- LLVM tools: `llvm-profdata-18`, `llvm-cov-18`
- For SSD: mounted at /mnt/g with `sudo mount -o defaults,noatime /dev/sde /mnt/g`

## The 11 Fuzzers
```
icc_applynamedcmm_fuzzer  icc_applyprofiles_fuzzer  icc_dump_fuzzer
icc_fromcube_fuzzer  icc_fromxml_fuzzer  icc_link_fuzzer
icc_roundtrip_fuzzer  icc_specsep_fuzzer  icc_tiffdump_fuzzer
icc_toxml_fuzzer  icc_v5dspobs_fuzzer
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
# All 12 fuzzers on ramdisk (default)
cd cfl && ./fuzz-local.sh

# All 12 fuzzers on SSD
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

### Step 1: Clear Stale Profraw
After rebuilding fuzzers, old profraw files are invalidated (binary hash mismatch).
Always clear before collecting new coverage:
```bash
# Clear all profraw and stale merged.profdata
find /mnt/g/fuzz-ssd /tmp/fuzz-ramdisk . -name '*.profraw' -type f -delete
rm -f /mnt/g/fuzz-ssd/merged.profdata /tmp/fuzz-ramdisk/merged.profdata
```

### Step 2: Generate Coverage Report (if profraw is fresh)
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

### Step 2b: Compare Against Upstream Tools (optional fidelity check)
```bash
# Run ASAN-instrumented upstream tools (iccDEV/Build-ASAN/) against test corpus
mkdir -p /tmp/tool-cov && rm -f /tmp/tool-cov/*.profraw
for f in test-profiles/*.icc fuzz/graphics/icc/*.icc; do
  LLVM_PROFILE_FILE=/tmp/tool-cov/dump_%m.profraw \
  LD_LIBRARY_PATH=iccDEV/Build-ASAN/IccProfLib:iccDEV/Build-ASAN/IccXML \
    timeout 5 iccDEV/Build-ASAN/Tools/IccDumpProfile/iccDumpProfile "$f" >/dev/null 2>&1
done

# Compare functions: extract LCOV FNDA lines → sort → comm
llvm-cov-18 export <tool> -instr-profile=<tool.profdata> -format=lcov | \
  grep 'FNDA:[1-9]' | sed 's/FNDA:[0-9]*,//' | sort > tool-funcs.txt
llvm-cov-18 export <fuzzer> -instr-profile=<fuzzer.profdata> -format=lcov | \
  grep 'FNDA:[1-9]' | sed 's/FNDA:[0-9]*,//' | sort > fuzzer-funcs.txt
comm -23 tool-funcs.txt fuzzer-funcs.txt  # Functions in tool but NOT fuzzer
```

### Step 3: Preserve SSD Artifacts
Copy crash/oom/timeout/slow-unit files BEFORE cleaning:
```bash
SSD="/mnt/g/fuzz-ssd"
rsync -a --ignore-existing $SSD/crash-* ./ 2>/dev/null
rsync -a --ignore-existing $SSD/oom-* ./ 2>/dev/null
rsync -a --ignore-existing $SSD/timeout-* ./test-profiles/cwe-400/ 2>/dev/null
rsync -a --ignore-existing $SSD/slow-unit-* ./ 2>/dev/null
rsync -a --ignore-existing $SSD/findings/ cfl/findings/ 2>/dev/null
```

### Step 4: Parallel Corpus Merge (SSD/Ramdisk → Local)
Use 10 concurrent rsyncs with --ignore-existing (NOT LibFuzzer merge for bulk migration):
```bash
SSD="/mnt/g/fuzz-ssd"  # or /tmp/fuzz-ramdisk
DEST="cfl"
MAX_JOBS=10

FUZZERS=(icc_apply_fuzzer icc_applynamedcmm_fuzzer icc_applyprofiles_fuzzer
  icc_calculator_fuzzer icc_deep_dump_fuzzer icc_dump_fuzzer
  icc_fromcube_fuzzer icc_fromxml_fuzzer icc_io_fuzzer
  icc_link_fuzzer icc_multitag_fuzzer icc_profile_fuzzer
  icc_spectral_fuzzer icc_tiffdump_fuzzer icc_toxml_fuzzer
  icc_v5dspobs_fuzzer)

for fuzzer in "${FUZZERS[@]}"; do
  rsync -a --ignore-existing "$SSD/corpus-${fuzzer}/" "$DEST/corpus-${fuzzer}/" &
  while [ $(jobs -r | wc -l) -ge $MAX_JOBS ]; do sleep 1; done
done
wait
```

### Step 5: Verify Merge Completeness
Compare file counts per fuzzer — local MUST be >= source for every fuzzer:
```bash
for fuzzer in "${FUZZERS[@]}"; do
  ssd=$(find "$SSD/corpus-${fuzzer}/" -maxdepth 1 -type f | wc -l)
  local=$(find "$DEST/corpus-${fuzzer}/" -maxdepth 1 -type f | wc -l)
  if [ "$local" -ge "$ssd" ]; then
    echo "✓ $fuzzer: $local >= $ssd"
  else
    echo "✗ $fuzzer: MISSING $((ssd - local)) files!"
  fi
done
```

### Step 6: Clean SSD and Unmount
Only after verification passes:
```bash
rm -rf /mnt/g/fuzz-ssd/corpus-* /mnt/g/fuzz-ssd/bin /mnt/g/fuzz-ssd/dict \
       /mnt/g/fuzz-ssd/seed /mnt/g/fuzz-ssd/profraw /mnt/g/fuzz-ssd/logs \
       /mnt/g/fuzz-ssd/cons-* /mnt/g/fuzz-ssd/findings /mnt/g/fuzz-ssd/coverage-report
rm -f /mnt/g/fuzz-ssd/crash-* /mnt/g/fuzz-ssd/oom-* /mnt/g/fuzz-ssd/timeout-* \
      /mnt/g/fuzz-ssd/slow-unit-* /mnt/g/fuzz-ssd/fuzz_*
sudo umount /mnt/g  # optional — leave mounted for next session
```

### Step 7: Corpus Dedup via Tournament Bracket Merge

LibFuzzer `-merge=1` is **single-threaded per process**. For large corpora (1K+ files),
use a tournament bracket merge to saturate all CPU cores:

```bash
# For small corpora (<500 files): launch all 11 in parallel, 1 per fuzzer
export ASAN_OPTIONS=detect_leaks=0
export LLVM_PROFILE_FILE=/dev/null
for name in applynamedcmm applyprofiles dump fromcube fromxml link roundtrip specsep tiffdump toxml v5dspobs; do
  mkdir -p /tmp/merge-work/${name}-merged
  taskset -c $((RANDOM % $(nproc))) \
    cfl/bin/icc_${name}_fuzzer -merge=1 -timeout=10 -rss_limit_mb=2048 \
    /tmp/merge-work/${name}-merged cfl/corpus-icc_${name}_fuzzer/ &
done
wait
# Swap: rm -rf cfl/corpus-icc_${name}_fuzzer && mv /tmp/merge-work/${name}-merged cfl/corpus-icc_${name}_fuzzer

# For large corpora (1K+ files): tournament bracket on 32 cores
# 1. Split corpus into 32 chunks (round-robin)
# 2. Merge each chunk on its own core (32 parallel processes)
# 3. Pair results: 16 merges → 8 → 4 → 2 → 1 final
# Each round keeps all cores busy. 9103 files → 481 in ~2 min (vs ~30 min single-threaded).
#
# Example for roundtrip fuzzer:
NCPU=32
for i in $(seq 0 $((NCPU-1))); do mkdir -p /tmp/chunks/chunk-$i /tmp/chunks/merged-$i; done
find cfl/corpus-icc_roundtrip_fuzzer -maxdepth 1 -type f | awk '{print NR-1, $0}' | \
  while read idx f; do ln -f "$f" "/tmp/chunks/chunk-$((idx % NCPU))/"; done
# Phase 2: 32 parallel chunk merges
for i in $(seq 0 $((NCPU-1))); do
  taskset -c $i cfl/bin/icc_roundtrip_fuzzer -merge=1 -timeout=10 -rss_limit_mb=1024 \
    /tmp/chunks/merged-$i /tmp/chunks/chunk-$i > /tmp/chunks/log-$i.txt 2>&1 &
done; wait
# Phases 3-5: tournament bracket (pair 16→8→4→2→1)
# Each round: merge pairs of previous round's outputs in parallel
```

**CRITICAL**: NEVER run merges sequentially. All batch operations MUST use all
available CPU cores. See "Parallel Processing" in Lessons Learned below.

**Binary-to-corpus mapping**: Only 11 corpora have matching binaries.
`corpus-xml` is a named XML seed staging area for `icc_fromxml_fuzzer` — it
contains 48 descriptive-named XML files (CVE PoCs, crash reproductions) that
are also copied into `corpus-icc_fromxml_fuzzer/`. Keep both directories.
8 legacy corpus dirs (icc_apply, icc_calculator, icc_deep_dump, icc_io,
icc_multitag, icc_profile, icc_spectral, icc_spectral_b) were orphaned
staging areas — now deleted.

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

## Corpus Baseline (March 12 2026, post-tournament-merge minimization)

11 active fuzzers with matching binaries:

| Fuzzer | Minimized Files | Pre-Merge | Reduction |
|--------|----------------|-----------|-----------|
| icc_toxml_fuzzer | 513 | 9,104 | 95% |
| icc_dump_fuzzer | 501 | 9,112 | 95% |
| icc_roundtrip_fuzzer | 481 | 9,103 | 95% |
| icc_fromcube_fuzzer | 160 | 278 | 43% |
| icc_tiffdump_fuzzer | 55 | 365 | 85% |
| icc_fromxml_fuzzer | 101 | 53 | +48 from corpus-xml |
| icc_specsep_fuzzer | 45 | 357 | 88% |
| icc_applynamedcmm_fuzzer | 17 | 46 | 64% |
| icc_applyprofiles_fuzzer | 14 | 16 | 13% |
| icc_v5dspobs_fuzzer | 11 | 15 | 27% |
| icc_link_fuzzer | 5 | 9 | 45% |
| **Total (active)** | **1,903** | **27,458** | **93%** |

8 orphaned corpus dirs (no matching binary — legacy/staging, DELETED):
icc_apply, icc_calculator, icc_deep_dump, icc_io, icc_multitag,
icc_profile, icc_spectral, icc_spectral_b

`corpus-xml` (48 files) is a named XML seed staging area for `icc_fromxml_fuzzer`.
Contains descriptive-named CVE PoCs, crash reproductions, and spec-valid XML profiles.
Contents are also copied into `corpus-icc_fromxml_fuzzer/`. Keep both directories.

## Coverage Baseline (March 2026)
| Metric | Value |
|--------|-------|
| Functions | 63.23% |
| Lines | 61.15% |
| Branches | 58.47% |
| Instantiations | 62.99% |

## Lessons Learned
- **Profraw staleness**: After rebuilding fuzzers, ALL old profraw is invalid (binary hash mismatch). Clear before collecting new coverage.
- **Profraw naming**: Use `${fuzzer_name}_%m_%p.profraw` (not `%m.profraw`). `%m` is a numeric module hash, NOT the binary name.
- **Parallel processing (MANDATORY)**: ALL batch operations MUST use all available CPU cores (32). NEVER run sequential for-loops for fuzzer/corpus operations. Use `taskset -c N`, background jobs (`&`) + `wait`, or tournament bracket merging. Single-process execution is unacceptable.
- **Tournament bracket merge**: LibFuzzer `-merge=1` is single-threaded per process. For large corpora: split into N chunks (N=nproc), merge each on its own core, then pair results 16→8→4→2→1. Keeps all cores busy. 9103 files minimized to 481 in ~2 min vs ~30 min single-threaded.
- **Binary-to-corpus mapping**: Only 12 fuzzers have binaries. 8 orphaned corpus dirs deleted. `corpus-xml` (48 named XML seeds) kept as staging area for `icc_fromxml_fuzzer`.
- **Parallel rsync**: 10 concurrent rsyncs handles large file sets fast. Safe with `--ignore-existing`.
- **Verification**: Always compare per-fuzzer file counts (local >= source) BEFORE cleaning the source storage.
- **Artifact preservation**: Copy crash/oom/timeout/slow-unit from storage to repo BEFORE cleanup.
- **Roundtrip fuzzer**: Very slow (Read→Write→Read per input). Allow 120s+ timeout for merge.
- **Link fuzzer**: Needs quarantine_size_mb=256 (2 profiles per input = 2x ASAN memory).
- **Storage policy**: External SSD disconnected. Use local cfl/ directory + /tmp/fuzz-ramdisk (tmpfs) only.

## See Also
- [fuzzer-optimization.prompt.md](fuzzer-optimization.prompt.md) — Coverage improvement strategies
- [improve-fuzzer-coverage.prompt.md](improve-fuzzer-coverage.prompt.md) — Coverage gap analysis
- [fuzz-corpus-analysis.prompt.md](fuzz-corpus-analysis.prompt.md) — Corpus inventory and audit
- [cooperative-development.prompt.md](cooperative-development.prompt.md) — Multi-agent coordination
