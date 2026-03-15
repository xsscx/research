# AFL++ Fuzzing — iccDEV Tool-Level Testing

## Overview

AFL++ fuzzes the **actual iccDEV CLI tools** (no harness wrapper) with ASAN+UBSAN
instrumentation. This complements the CFL LibFuzzer harnesses which test library
internals. AFL tests end-to-end tool behavior: argument parsing, file I/O, output
generation, and error handling.

**AFL++ version**: 4.36a+ (uses `afl-clang-fast++`)
**Instrumentation**: ASAN + UBSAN (`AFL_USE_ASAN=1 AFL_USE_UBSAN=1`)
**Build optimization**: `-O0 -g` (debug, no optimization)

## Build

```bash
# From research repo root:
./afl/build.sh

# Produces 14 instrumented binaries + shared libs → afl/bin/
ls afl/bin/icc* | wc -l    # → 14
ls afl/bin/lib*.so          # → libIccProfLib2.so, libIccXML2.so
```

## Prerequisites

```bash
# Core pattern (required — AFL needs direct crash notification)
echo core | sudo tee /proc/sys/kernel/core_pattern

# Environment setup
export AFL_BASE=/path/to/research    # e.g., ~/po/research
export LD_LIBRARY_PATH=$AFL_BASE/afl/bin
export ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=0
export AFL_MAP_SIZE=131072
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
cd $AFL_BASE
```

> **CRITICAL**: `LD_LIBRARY_PATH=afl/bin` is mandatory. Without it, the binary
> can't find `libIccProfLib2.so.2` / `libIccXML2.so.2` and the fork server
> handshake fails immediately.

## Targets (9 Active)

| # | Target | Binary | Input Format | Command Suffix |
|---|--------|--------|-------------|----------------|
| 1 | dump | iccDumpProfile | ICC binary | `@@ ALL` |
| 2 | toxml | iccToXml | ICC binary | `@@ /dev/null` |
| 3 | fromxml | iccFromXml | ICC XML | `@@ /dev/null` |
| 4 | roundtrip | iccRoundTrip | ICC binary | `@@` |
| 5 | tiffdump | iccTiffDump | TIFF image | `@@` |
| 6 | jpegdump | iccJpegDump | JPEG image | `@@` |
| 7 | pngdump | iccPngDump | PNG image | `@@` |
| 8 | fromcube | iccFromCube | .cube text | `@@ /dev/null` |
| 9 | search | iccApplySearch | ICC binary | `search-data.txt 0 0 @@ 1 @@ 1` |

## Individual Startup Commands

Use `-i -` to resume from existing output. For first runs, use
`-i afl/afl-<target>/input` instead.

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

## Quick Smoke Test (60 seconds, headless)

```bash
AFL_NO_UI=1 afl-fuzz -i afl/afl-dump/input -o /tmp/afl-smoke \
  -x cfl/icc_dump_fuzzer.dict -m none -t 5000 -V 60 \
  -- $AFL_BASE/afl/bin/iccDumpProfile @@ ALL
```

## Parallel Fuzzing

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

## First Run Seed Sources

| Target | First-run `-i` path |
|--------|---------------------|
| dump, toxml, roundtrip | `afl/afl-dump/input` (auto-sampled from test-profiles/) |
| fromxml | `afl/afl-fromxml/input` (XML seeds) |
| tiffdump | `afl/afl-tiffdump/input` or `fuzz/graphics/tif/` |
| jpegdump | `fuzz/graphics/jpg/` |
| pngdump | `fuzz/graphics/png/` |
| fromcube | `afl/afl-fromcube/input` |
| search | `afl/afl-search/input` |

## Dictionaries

All dictionaries are shared from `cfl/`:

| Target | Dictionary | Size |
|--------|-----------|------|
| dump | `cfl/icc_dump_fuzzer.dict` | 154 KB |
| toxml | `cfl/icc_toxml_fuzzer.dict` | 99 KB |
| fromxml | `cfl/icc_fromxml_fuzzer.dict` | 24 KB |
| roundtrip | `cfl/icc_roundtrip_fuzzer.dict` | 39 KB |
| tiffdump | `cfl/icc_tiffdump_fuzzer.dict` | 157 KB |
| jpegdump, pngdump | `cfl/icc.dict` | 2.9 KB |
| fromcube | `cfl/icc_fromcube_fuzzer.dict` | 34 KB |
| search | `cfl/icc_applysearch_fuzzer.dict` | 2.8 KB |

## Crash Triage

```bash
# Automated triage against unpatched upstream
./afl/triage.sh <target>

# Manual single-crash triage
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <crash-file> ALL
```

If upstream crashes → real bug → file issue + create CFL patch.
If upstream handles it → AFL-only artifact → discard.

## Troubleshooting

### Fork server handshake failed

**Cause**: Missing `LD_LIBRARY_PATH`. The binary can't find shared libs and exits
before AFL's fork server handshake completes.

**Fix**: `export LD_LIBRARY_PATH=$AFL_BASE/afl/bin`

### Core pattern warning

**Fix**: `echo core | sudo tee /proc/sys/kernel/core_pattern`

### Test case too big warnings

Non-fatal. AFL truncates inputs > 1MB by default. Add `-G 5242880` to raise the
limit to 5MB if needed for large XML profiles.

## See Also

- `docs/afl/index.md` — Full AFL++ pipeline documentation
- `.github/instructions/afl.instructions.md` — Agent instructions
- `afl/start.sh` — Automated startup script (handles all env vars)
