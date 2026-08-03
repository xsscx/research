---
name: corpus-management
description: >
  Manage fuzzing corpus lifecycle: SSD/scratch setup, fuzzer execution,
  coverage collection, corpus merge and dedup, and artifact preservation.
allowed-tools:
  - bash
  - read
  - write
  - grep
  - glob
---

# Corpus Management

## Overview

Manage fuzzing corpus across permanent (`cfl/corpus-*/`) and scratch/SSD
storage. Covers setup, fuzzing, coverage, merge, dedup, and cleanup.

## Workflow

### 1. Setup Scratch Storage

```bash
# Optional SSD/scratch root for corpus pruning or long runs.
SCRATCH=/mnt/fuzz-ssd
mkdir -p "$SCRATCH"/logs "$SCRATCH"/profraw
for d in cfl/corpus-*; do rsync -a --ignore-existing "$d/" "$SCRATCH/$(basename "$d")/"; done

# Status check
for d in cfl/corpus-*/; do
  name=$(basename "$d" | sed 's/^corpus-//'); count=$(ls "$d" 2>/dev/null | wc -l)
  printf "%-40s %6d files\n" "$name" "$count"
done
```

### 2. Run Fuzzers

```bash
# All fuzzers (sequential, prevents OOM)
cd cfl && ./fuzz-local.sh

# Single fuzzer smoke test (60s)
ASAN_OPTIONS=detect_leaks=0 LLVM_PROFILE_FILE=/dev/null \
  cfl/bin/icc_dump_fuzzer -max_total_time=60 -timeout=30 \
  -rss_limit_mb=4096 cfl/corpus-icc_dump_fuzzer/
```

Special flags: `icc_link_fuzzer` needs `quarantine_size_mb=256`.

### 3. Collect Coverage

```bash
# Clear stale profraw (invalidated by rebuild)
find . /mnt/fuzz-ssd -name '*.profraw' -type f -delete

# Merge and report
llvm-profdata-18 merge -sparse /path/profraw/*.profraw -o merged.profdata
OBJS=$(printf ' -object %s' cfl/bin/icc_*_fuzzer)
llvm-cov-18 report $OBJS -instr-profile=merged.profdata
```

### 4. Preserve Artifacts

Copy crash/oom/timeout files BEFORE cleaning storage:
```bash
rsync -a --ignore-existing cfl/runs/*/artifacts/crash-* ./ 2>/dev/null
rsync -a --ignore-existing cfl/runs/*/artifacts/timeout-* ./test-profiles/cwe-400/ 2>/dev/null
```

### 5. Corpus Merge (Tournament Bracket)

LibFuzzer `-merge=1` is single-threaded. For large corpora, use parallel merge:

```bash
# Small corpora (<500 files): 11 parallel merges
ASAN_OPTIONS=detect_leaks=0 LLVM_PROFILE_FILE=/dev/null
for name in applynamedcmm applyprofiles dump fromcube fromxml link roundtrip specsep tiffdump toxml v5dspobs; do
  mkdir -p /tmp/merge/${name}
  taskset -c $((RANDOM % $(nproc))) \
    cfl/bin/icc_${name}_fuzzer -merge=1 -timeout=10 -rss_limit_mb=2048 \
    /tmp/merge/${name} cfl/corpus-icc_${name}_fuzzer/ &
done
wait
```

For 1K+ file corpora, use tournament bracket (split into N=nproc chunks,
merge each on its own core, pair results 16->8->4->2->1).

### 6. Verify and Swap

Compare file counts (local must be >= source) before swapping directories.

## Key Rules

- After rebuilding fuzzers, ALL old profraw is invalid (binary hash mismatch)
- Use `${fuzzer_name}_%m_%p.profraw` naming (not just `%m.profraw`)
- ALL batch operations MUST use all available CPU cores
- Use existing `.github/scripts/corpus-merge.sh` -- do NOT create custom scripts
- Only corpus dirs matching `cfl/fuzzers.sh` are runnable; `corpus-xml` is a staging area
- AFL `jpegdump` and `jpegdump-inject` seed only up to 200 `.jpg`/`.jpeg` files
  from `fuzz/graphics/jpg` with extractable embedded ICC profiles; never seed
  those lanes with raw `.icc` files.
- On repeated correction or wrap-up requests, skip broad corpus sweeps. Make
  the named fix, run the narrow seed validator or seed-only check, then commit
  and push if requested.

## References

- `.github/prompts/fuzzer-optimization.prompt.md` -- Coverage strategies
- `.github/instructions/cfl.instructions.md` -- Fuzzer details
