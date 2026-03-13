# AFL++ Fuzzing Pipeline — iccDEV Upstream Tools

AFL++ fuzzing infrastructure for the **upstream iccDEV tools directly** — absolute
fidelity by definition (no harness, no wrapper, the actual binary).

## Quick Start

```bash
# 1. Build AFL-instrumented iccDEV (one-time, or after upstream sync)
./afl/build.sh

# 2. Start fuzzing (single instance)
./afl/start.sh dump
./afl/start.sh toxml
./afl/start.sh tiffdump

# 3. Start fuzzing (4 parallel instances)
./afl/start.sh dump --parallel 4

# 4. Check status
./afl/status.sh

# 5. Stop fuzzing
./afl/stop.sh dump

# 6. Triage crashes
./afl/triage.sh dump
```

## Architecture

```
afl/
├── README.md          # This file
├── build.sh           # Build iccDEV with AFL++ instrumentation (ASAN+UBSAN)
├── start.sh           # Start AFL fuzzer for a target tool
├── stop.sh            # Stop AFL fuzzer gracefully
├── status.sh          # Show fuzzer stats (all or specific)
├── triage.sh          # Triage crashes/hangs against unpatched upstream
├── rebuild.sh         # Full rebuild cycle (clean + build)
├── harvest.sh         # Harvest crash/hang artifacts
├── bin/               # AFL-instrumented binaries + shared libraries
└── afl-{target}/      # Per-target working directories
    ├── input/         # Seed corpus
    └── output/        # AFL output (queue, crashes, hangs)
```

## Supported Targets

### Single-File Input (ready to fuzz)

| Target | Binary | Input Format | Seed Source | Notes |
|--------|--------|-------------|-------------|-------|
| `dump` | iccDumpProfile | ICC binary | test-profiles/, fuzz/graphics/icc/ | Broadest coverage — all Describe() paths |
| `toxml` | iccToXml | ICC binary | test-profiles/, fuzz/graphics/icc/ | XML serialization — covers 25 XML advisories |
| `fromxml` | iccFromXml | ICC XML | fuzz/xml/icc/ | XML→ICC parsing |
| `roundtrip` | iccRoundTrip | ICC binary | test-profiles/, fuzz/graphics/icc/ | AToB/BToA CMM Apply pipeline |
| `tiffdump` | iccTiffDump | TIFF image | fuzz/graphics/tif/ | TIFF→ICC extraction |
| `jpegdump` | iccJpegDump | JPEG image | fuzz/graphics/jpg/ | JPEG→ICC extraction |
| `pngdump` | iccPngDump | PNG image | fuzz/graphics/png/ | PNG→ICC extraction |
| `fromcube` | iccFromCube | .cube text | cfl/ corpus | CVE-2026-27691 (patched) |

### Complex-Arg Tools (deployed but not yet wired as targets)

| Binary | Why complex | Workaround |
|--------|-------------|------------|
| iccApplyProfiles | Needs TIFF + N profiles | Custom AFL harness or afl-multiarg |
| iccApplyNamedCmm | Needs profiles + color args | Custom AFL harness |
| iccApplyToLink | Needs multiple profiles | Custom AFL harness |
| iccV5DspObsToV4Dsp | Needs 2 profiles + output | Custom AFL harness |
| iccSpecSepToTiff | Needs TIFF + format string + profiles | Custom AFL harness |
| iccApplySearch | Needs directory of profiles | Not suitable for AFL |

## Storage Layout

```
afl/afl-{target}/
├── input/          # Seed corpus (copied on first run)
├── output/         # AFL output (queue, crashes, hangs)
│   └── default/    # Single-instance output
└── {target}.dict   # Dictionary file
```

## Build Details

- Compiler: `afl-clang-fast++` (AFL++ 4.09c)
- Sanitizers: ASAN + UBSAN (`AFL_USE_ASAN=1 AFL_USE_UBSAN=1`)
- Build dir: `iccDEV/Build-AFL/`
- Libraries: `afl/bin/libIccProfLib2.so`, `afl/bin/libIccXML2.so`
- 14 tools built, 8 wired as AFL targets

## Adding a New Target

1. Add a `case` block in `start.sh` with binary path and argument template
2. Add a `case` block in `triage.sh` with upstream binary path
3. Add to the `TARGETS` array in `status.sh`
4. Create seed corpus or point to existing seeds
5. Create/copy a dictionary file
6. Add to the targets table above
7. Test: `./afl/start.sh {target}` then `./afl/status.sh`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AFL_BASE` | `afl/` | Base path for AFL working directories |
| `AFL_TIMEOUT` | `5000` | Per-exec timeout in ms |
| `AFL_MAP_SIZE` | `131072` | Shared memory map size |

## CVE Coverage

| CVE | Tool | Status | Description |
|-----|------|--------|-------------|
| CVE-2026-27691 | iccFromCube | Patched (43ae18d) | SIO in parse3DTable(), CWE-190/681 |
