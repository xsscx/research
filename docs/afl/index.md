# AFL++ Fuzzing Pipeline

## Overview

AFL++ (American Fuzzy Lop++) fuzzes the **upstream iccDEV tools directly** — no custom
harness, no wrapper. The actual tool binary is the fuzzing target, providing absolute
fidelity to real-world behavior.

**Version**: AFL++ 4.36a (built from source, installed to `/usr/local/bin/`)

**Instrumentation**: `afl-clang-fast++` with ASAN + UBSAN (`AFL_USE_ASAN=1 AFL_USE_UBSAN=1`)

### CFL vs AFL — Complementary Approaches

| Aspect | CFL (LibFuzzer) | AFL++ |
|--------|----------------|-------|
| **Target** | Custom harnesses wrapping library functions | Actual upstream tool binaries |
| **Fidelity** | Harness may diverge from tool behavior | 100% — the real binary |
| **Speed** | In-process, very fast | Fork-based, slower per-exec |
| **Coverage** | Deep library internals (Read/Write/Apply) | End-to-end tool paths (main→exit) |
| **Crash triage** | Needs reproduction against upstream tool | Crash IS from upstream tool |
| **Patches** | 17 CFL patches applied to library | Same iccDEV cfl branch (patches included) |

Both approaches find bugs the other misses. CFL excels at deep library coverage;
AFL++ excels at tool-specific argument parsing, error paths, and output generation.

## Directory Layout

```
afl/
├── build.sh           # Build iccDEV with AFL++ instrumentation
├── start.sh           # Start fuzzing a target (single or parallel)
├── stop.sh            # Stop fuzzing gracefully
├── status.sh          # Show fuzzer stats (all or specific target)
├── triage.sh          # Triage crashes against unpatched upstream
├── harvest.sh         # Download CI artifacts, deduplicate, seed
├── rebuild.sh         # Full clean + rebuild cycle
├── bin/               # 14 AFL-instrumented binaries + shared libs
└── afl-{target}/      # Per-target working directories
    ├── input/         #   Seed corpus (copied on first run)
    └── output/        #   AFL output (queue/, crashes/, hangs/)
```

## Quick Start

```bash
# 1. Build (one-time, or after upstream sync / patch changes)
./afl/build.sh

# 2. Start fuzzing
./afl/start.sh dump                 # single instance
./afl/start.sh toxml --parallel 4   # 4 parallel instances

# 3. Monitor
./afl/status.sh                     # all targets
./afl/status.sh dump                # specific target

# 4. Stop
./afl/stop.sh dump

# 5. Triage crashes
./afl/triage.sh dump

# 6. Harvest CI artifacts
./afl/harvest.sh --seed-local
```

## Targets

### Active (8 single-file-input tools)

| Target | Binary | Input | Seed Source |
|--------|--------|-------|-------------|
| `dump` | iccDumpProfile | ICC binary | test-profiles/, fuzz/graphics/icc/ |
| `toxml` | iccToXml | ICC binary | test-profiles/, fuzz/graphics/icc/ |
| `fromxml` | iccFromXml | ICC XML | fuzz/xml/icc/ |
| `roundtrip` | iccRoundTrip | ICC binary | test-profiles/, fuzz/graphics/icc/ |
| `tiffdump` | iccTiffDump | TIFF image | fuzz/graphics/tif/ |
| `jpegdump` | iccJpegDump | JPEG image | fuzz/graphics/jpg/ |
| `pngdump` | iccPngDump | PNG image | fuzz/graphics/png/ |
| `fromcube` | iccFromCube | .cube text | cfl/ corpus |

### Not Yet Wired (multi-arg tools)

| Binary | Reason | Notes |
|--------|--------|-------|
| iccApplyProfiles | TIFF + N profiles | Needs custom AFL harness |
| iccApplyNamedCmm | Profiles + color args | Needs custom AFL harness |
| iccApplyToLink | Multiple profiles | Needs custom AFL harness |
| iccV5DspObsToV4Dsp | 2 profiles + output | Needs custom AFL harness |
| iccSpecSepToTiff | TIFF + format + profiles | Needs custom AFL harness |
| iccApplySearch | Directory of profiles | Not suitable for AFL |

## Script Reference

### build.sh

Builds iccDEV with `afl-clang-fast++` (ASAN+UBSAN) and deploys 14 instrumented
binaries + shared libraries to `afl/bin/`.

```bash
./afl/build.sh           # incremental build
./afl/build.sh --clean   # clean rebuild (removes Build-AFL/)
```

Build directory: `iccDEV/Build-AFL/`

### start.sh

Starts AFL++ fuzzing for a target. Seeds the input corpus on first run from
test-profiles/ and fuzz/ directories. Uses the matching CFL dictionary for
guided mutation.

```bash
./afl/start.sh <target> [--parallel N]
```

AFL runs in the background. Output goes to `afl/afl-{target}/output/`.

**Parallel fuzzing**: `--parallel 4` launches 1 master + 3 secondary instances.
Each secondary shares the corpus queue for maximum coverage.

### stop.sh

Gracefully stops AFL instances for a target.

```bash
./afl/stop.sh <target>   # stop specific target
./afl/stop.sh all        # stop all targets
```

### status.sh

Displays AFL stats: execs/sec, paths found, crashes, hangs, coverage bitmap.

```bash
./afl/status.sh          # all running targets
./afl/status.sh dump     # specific target
```

### triage.sh

Runs each crash/hang artifact through the **unpatched** upstream iccDEV tool
(`iccDEV/Build/Tools/`) with ASAN+UBSAN to classify findings:

- **Real upstream bug**: ASAN/UBSAN fires → file upstream issue
- **AFL artifact**: Tool handles gracefully → discard

```bash
./afl/triage.sh dump
```

### harvest.sh

Downloads AFL++ CI artifacts, deduplicates, and optionally seeds local corpora.

```bash
./afl/harvest.sh                        # download latest, report
./afl/harvest.sh --seed-local           # download + inject into cfl/corpus + AFL seeds
./afl/harvest.sh --run-id 12345         # specific CI run
./afl/harvest.sh --list                 # list available artifacts
./afl/harvest.sh --report-only          # report on existing harvest
```

### rebuild.sh

Full rebuild cycle — cleans Build-AFL/ and rebuilds from scratch.

```bash
./afl/rebuild.sh
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AFL_BASE` | `afl/` | Base path for working directories |
| `AFL_TIMEOUT` | `5000` | Per-execution timeout in milliseconds |
| `AFL_MAP_SIZE` | `131072` | Shared memory map size (128K) |

## Build Chain

```
iccDEV/ source (cfl branch, 17 CFL patches applied)
    │
    ├── Build/          Debug+ASAN+UBSAN (unpatched upstream reference)
    ├── Build-AFL/      AFL++ instrumented (ASAN+UBSAN, cfl branch)
    │       │
    │       └── afl/bin/    14 deployed binaries + shared libs
    │
    └── (cfl/iccDEV/)   CFL LibFuzzer builds (separate checkout)
```

**Important**: `iccDEV/Build/` is the unpatched upstream reference used by
`triage.sh` for crash classification. `iccDEV/Build-AFL/` is built from the
cfl branch with all 17 patches. When triage shows a crash only in Build-AFL
but not Build, it's a patch-related difference — not an upstream bug.

## Crash Workflow

```
AFL++ finds crash
    │
    ├─→ afl/afl-{target}/output/default/crashes/
    │
    ├─→ triage.sh classifies against upstream Build/ (unpatched)
    │       │
    │       ├── ASAN/UBSAN in upstream → file iccDEV issue
    │       │                            create CFL patch if fixable
    │       │
    │       └── upstream handles it    → AFL artifact, discard
    │
    └─→ harvest.sh collects for cross-seeding
            │
            ├── New ICC crashes → cfl/corpus-* + fuzz/graphics/icc/
            └── New TIFF crashes → fuzz/graphics/tif/
```

## Relationship to Other Components

| Component | Relationship |
|-----------|-------------|
| `cfl/` | LibFuzzer harnesses — complementary to AFL++ |
| `iccDEV/Build/` | Unpatched upstream — triage reference |
| `iccDEV/Build-AFL/` | AFL-instrumented build directory |
| `fuzz/` | Seed corpus source + crash artifact destination |
| `test-profiles/` | ICC profile seeds for dump/toxml/roundtrip |
| `.github/workflows/` | CI runs AFL++ campaigns (when configured) |

## Individual Fuzzer Startup Commands

Prerequisites:
```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
export AFL_BASE=/home/h02332/po/research
cd $AFL_BASE
```

Common environment (set once per shell session):
```bash
export LD_LIBRARY_PATH=$AFL_BASE/afl/bin
export ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=0
export AFL_MAP_SIZE=131072
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
```

> **Note**: Use `-i -` to resume from existing output. For first runs, use
> `-i afl/afl-<target>/input` instead.

### 1. iccDumpProfile — Profile Describe/Validate

```bash
afl-fuzz -i - -o afl/afl-dump/output \
  -x cfl/icc_dump_fuzzer.dict -m none -t 5000 \
  -- $AFL_BASE/afl/bin/iccDumpProfile @@ ALL
```

### 2. iccToXml — ICC→XML serialization

```bash
afl-fuzz -i - -o afl/afl-toxml/output \
  -x cfl/icc_toxml_fuzzer.dict -m none -t 5000 \
  -- $AFL_BASE/afl/bin/iccToXml @@ /dev/null
```

### 3. iccFromXml — XML→ICC parsing

```bash
afl-fuzz -i - -o afl/afl-fromxml/output \
  -x cfl/icc_fromxml_fuzzer.dict -m none -t 5000 \
  -- $AFL_BASE/afl/bin/iccFromXml @@ /dev/null
```

### 4. iccRoundTrip — Round-trip transforms

```bash
afl-fuzz -i - -o afl/afl-rt/output \
  -x cfl/icc_roundtrip_fuzzer.dict -m none -t 5000 \
  -- $AFL_BASE/afl/bin/iccRoundTrip @@
```

### 5. iccTiffDump — TIFF tag reading + ICC extraction

```bash
afl-fuzz -i - -o afl/afl-tiffdump/output \
  -x cfl/icc_tiffdump_fuzzer.dict -m none -t 5000 \
  -- $AFL_BASE/afl/bin/iccTiffDump @@
```

### 6. iccJpegDump — JPEG APP2 ICC extraction

```bash
afl-fuzz -i - -o afl/afl-jpegdump/output \
  -x cfl/icc.dict -m none -t 5000 \
  -- $AFL_BASE/afl/bin/iccJpegDump @@
```

### 7. iccPngDump — PNG iCCP chunk ICC extraction

```bash
afl-fuzz -i - -o afl/afl-pngdump/output \
  -x cfl/icc.dict -m none -t 5000 \
  -- $AFL_BASE/afl/bin/iccPngDump @@
```

### 8. iccFromCube — .cube LUT text parsing

```bash
afl-fuzz -i - -o afl/afl-fromcube/output \
  -x cfl/icc_fromcube_fuzzer.dict -m none -t 5000 \
  -- $AFL_BASE/afl/bin/iccFromCube @@ /dev/null
```

### 9. iccApplySearch — CMM search/optimization

```bash
afl-fuzz -i - -o afl/afl-search/output \
  -x cfl/icc_applysearch_fuzzer.dict -m none -t 5000 \
  -- $AFL_BASE/afl/bin/iccApplySearch \
     afl/afl-search/search-data.txt 0 0 @@ 1 @@ 1
```

### Quick Smoke Test (60 seconds, headless)

```bash
AFL_NO_UI=1 afl-fuzz -i afl/afl-dump/input -o /tmp/afl-smoke \
  -x cfl/icc_dump_fuzzer.dict -m none -t 5000 -V 60 \
  -- $AFL_BASE/afl/bin/iccDumpProfile @@ ALL
```

### Parallel Fuzzing

```bash
# Main instance
afl-fuzz -M main0 -i - -o afl/afl-dump/output \
  -x cfl/icc_dump_fuzzer.dict -m none -t 5000 \
  -- $AFL_BASE/afl/bin/iccDumpProfile @@ ALL

# Secondary instances (share queue with main)
afl-fuzz -S sec1 -i - -o afl/afl-dump/output \
  -x cfl/icc_dump_fuzzer.dict -m none -t 5000 \
  -- $AFL_BASE/afl/bin/iccDumpProfile @@ ALL
```

### First Run Seed Sources

| Target | First-run `-i` path |
|--------|---------------------|
| dump, toxml, roundtrip | `afl/afl-dump/input` (auto-sampled from test-profiles/) |
| fromxml | `afl/afl-fromxml/input` (XML seeds) |
| tiffdump | `afl/afl-tiffdump/input` or `fuzz/graphics/tif/` |
| jpegdump | `fuzz/graphics/jpg/` |
| pngdump | `fuzz/graphics/png/` |
| fromcube | `afl/afl-fromcube/input` |
| search | `afl/afl-search/input` |
