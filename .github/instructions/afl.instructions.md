# AFL++ Instructions — Tool-Level Fuzzing

## Overview

The `afl/` directory provides AFL++ fuzzing infrastructure targeting the **unpatched upstream
iccDEV CLI tools** directly — no harness, no wrapper. This tests the real tool binary with
ASAN+UBSAN instrumentation, complementing the CFL LibFuzzer harnesses in `cfl/`.

**Key difference from CFL**: CFL fuzzers (`cfl/`) apply 20 security patches to iccDEV before
building. AFL fuzzers (`afl/`) use the upstream code as-is, catching bugs the patches haven't
addressed yet.

## Build

```bash
# Build all 14 AFL-instrumented tools + shared libs → afl/bin/
./afl/build.sh

# Verify
ls afl/bin/icc* | wc -l    # → 14+ binaries
ls afl/bin/lib*.so          # → libIccProfLib2.so, libIccXML2.so
```

**Compiler**: `afl-clang-fast++` (AFL++ 4.40c)
**Sanitizers**: ASAN + UBSAN (`AFL_USE_ASAN=1 AFL_USE_UBSAN=1`)
**Optimization**: `-O0 -g` (debug, no optimization for better coverage)

## Targets (9)

| Target | Binary | Input Format | AFL Command Suffix |
|--------|--------|-------------|-------------------|
| `dump` | iccDumpProfile | ICC binary | `@@ ALL` |
| `toxml` | iccToXml | ICC binary | `@@ /dev/null` |
| `fromxml` | iccFromXml | ICC XML | `@@ /dev/null` |
| `roundtrip` | iccRoundTrip | ICC binary | `@@` |
| `tiffdump` | iccTiffDump | TIFF image | `@@` |
| `jpegdump` | iccJpegDump | JPEG image | `@@` |
| `pngdump` | iccPngDump | PNG image | `@@` |
| `fromcube` | iccFromCube | .cube LUT text | `@@ /dev/null` |
| `search` | iccApplySearch | ICC binary | `search-data.txt 0 0 @@ 1 @@ 1` |

## Commands

```bash
# Start a fuzzer (interactive TUI)
./afl/start.sh <target>

# Parallel fuzzing (1 main + N-1 secondary)
./afl/start.sh <target> --parallel 4

# Monitor
./afl/status.sh              # all targets
./afl/status.sh <target>     # specific target

# Stop
./afl/stop.sh <target>       # specific target
./afl/stop.sh                # all targets

# Triage crashes against unpatched upstream
./afl/triage.sh <target>

# Clean rebuild
./afl/rebuild.sh
```

## Smoke Test (60 seconds, headless)

```bash
AFL_NO_UI=1 AFL_MAP_SIZE=131072 AFL_SKIP_CPUFREQ=1 \
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
LD_LIBRARY_PATH=afl/bin \
ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=0 \
  afl-fuzz -i afl/afl-dump/input -o /tmp/afl-smoke-dump \
  -m none -t 5000 -V 60 \
  -- afl/bin/iccDumpProfile @@ ALL
```

## Directory Structure

```
afl/
├── build.sh          # Build AFL-instrumented iccDEV
├── start.sh          # Start fuzzer (main orchestrator)
├── stop.sh           # Stop fuzzer (SIGINT → SIGKILL)
├── status.sh         # Real-time status monitor
├── triage.sh         # Crash triage against upstream
├── rebuild.sh        # Full clean rebuild
├── harvest.sh        # Download CI artifacts + deduplicate
├── bin/              # Instrumented binaries + shared libs
└── afl-<target>/     # Per-target working directories
    ├── input/        # Seed corpus
    └── output/       # AFL output (queue/, crashes/, hangs/)
```

## Seed Corpus Sources

| Target | Primary Seeds |
|--------|--------------|
| dump, toxml, roundtrip, search | `test-profiles/` (363 profiles) |
| fromxml | `fuzz/xml/icc/`, `cfl/corpus-icc_fromxml_fuzzer/` |
| tiffdump | `mangled-images/`, `fuzz/graphics/tif/` |
| jpegdump | `fuzz/graphics/jpg/` |
| pngdump | `fuzz/graphics/png/` |
| fromcube | `cfl/icc_fromcube_fuzzer_seed_corpus/` (12 .cube files) |

Seeds are auto-sampled to 200 files max on first run. Subsequent runs auto-resume from
`output/default/fuzzer_stats`.

## Dictionaries

All dictionaries are shared from `cfl/`:
- `cfl/icc_dump_fuzzer.dict` (154 KB)
- `cfl/icc_toxml_fuzzer.dict` (99 KB)
- `cfl/icc_fromxml_fuzzer.dict` (24 KB)
- `cfl/icc_roundtrip_fuzzer.dict` (39 KB)
- `cfl/icc_tiffdump_fuzzer.dict` (157 KB)
- `cfl/icc.dict` (2.9 KB — generic, used for jpegdump/pngdump)
- `cfl/icc_fromcube_fuzzer.dict` (34 KB)
- `cfl/icc_applysearch_fuzzer.dict` (2.8 KB)

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `AFL_MAP_SIZE` | `131072` | Shared memory map (128 KB) |
| `AFL_TIMEOUT` | `5000` | Per-execution timeout (ms) |
| `AFL_SKIP_CPUFREQ` | `1` | Skip CPU freq scaling warnings |
| `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES` | `1` | Suppress crash handler warnings |
| `LD_LIBRARY_PATH` | `afl/bin/` | Load instrumented shared libs |
| `ASAN_OPTIONS` | `detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=0` | ASAN tuning |

## Crash Triage

AFL crashes land in `afl/afl-<target>/output/default/crashes/`. To triage:

```bash
# 1. Run crash against unpatched upstream tool
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <crash-file> ALL

# 2. If upstream crashes → real bug → report upstream + create CFL patch
# 3. If upstream doesn't crash → AFL-only alignment issue

# Automated triage for all crashes in a target
./afl/triage.sh dump
```

## Core Pattern Requirement

AFL++ requires the kernel core pattern to be `core`:
```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
```

## Conventions

- AFL output directories are gitignored (`afl/afl-*/output*/`)
- Crash files with commas in names are gitignored (Windows path issues)
- `afl-cmin` minimized seeds go in `afl/afl-*/cmin/` (also gitignored)
- Commit prefix: `[afl]` for AFL-specific changes

## Corpus Minimization

**CRITICAL**: The Python `afl-cmin` (default) deadlocks or OOMs with ASAN-instrumented
binaries. It spawns N parallel workers (default: `nproc`), each forking an ASAN binary
that uses 4-6× base memory. On a 16GB VM, 16 workers × 500MB = 8GB → OOM killer.

**Use `afl-cmin.bash` (shell version) instead**:
```bash
AFL_PATH=/usr/local/bin AFL_MAP_SIZE=131072 \
LD_LIBRARY_PATH=afl/bin \
ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=0 \
  afl-cmin.bash -i afl/afl-dump/input -o /tmp/afl-dump-cmin \
  -m none -t 5000 \
  -- afl/bin/iccDumpProfile @@ ALL
```

The shell version runs sequentially (safe for ASAN) and typically achieves 51-76% reduction.
Results from March 2026 minimization:

| Target | Before | After | Reduction |
|--------|--------|-------|-----------|
| dump | 3,649 | 1,406 | 61% |
| fromxml | 4,159 | 1,081 | 74% |
| roundtrip | 3,290 | 1,042 | 68% |
| tiffdump | 1,307 | 641 | 51% |
| toxml | 4,819 | 1,178 | 76% |
