# CFL — ClusterFuzzLite / LibFuzzer Harnesses for iccDEV

Last Updated: 2026-03-05 15:00:00 UTC

Security fuzzing toolkit for [DemoIccMAX](https://github.com/InternationalColorConsortium/DemoIccMAX) (iccDEV).
19 LibFuzzer harnesses, 57 active security patches, 18,800+ corpus files, and automated ramdisk workflows.

## Quick Start

```bash
# Build (clones iccDEV, applies 57 patches, compiles 19 fuzzers)
./build.sh

# Smoke test (60 seconds on tmpfs ramdisk)
sudo ./ramdisk-fuzz.sh 60

# Extended fuzzing on pre-mounted storage
./fuzz-local.sh -t 14400 -w 4
```

## Fuzzers (19)

| Fuzzer | LOC | Corpus | iccDEV Tool | API Scope |
|--------|-----|--------|-------------|-----------|
| `icc_dump_fuzzer` | 175 | 1,804 | IccDumpProfile | `OpenIccProfile`, `Describe`, `Validate` |
| `icc_deep_dump_fuzzer` | 1,029 | 307 | IccDumpProfile | Deep tag inspection, `FindTag`, `Describe` |
| `icc_profile_fuzzer` | 138 | 1,172 | IccDumpProfile | `CIccProfile::Read`, header/tag validation |
| `icc_calculator_fuzzer` | 131 | 1,100 | IccDumpProfile | `CIccMpeCalculator`, calc element ops |
| `icc_multitag_fuzzer` | 115 | 618 | IccDumpProfile | Multi-tag iteration, `FindTag` enumeration |
| `icc_io_fuzzer` | 107 | 438 | IccRoundTrip | `CIccProfile::Read`/`Write`, `CIccMemIO` |
| `icc_roundtrip_fuzzer` | 187 | 643 | IccRoundTrip | Read→Write→Read, `EvaluateProfile` |
| `icc_apply_fuzzer` | 132 | 1,450 | IccApplyProfiles | `CIccCmm::AddXform`, `Begin`, `Apply` |
| `icc_applyprofiles_fuzzer` | 163 | 1,592 | IccApplyProfiles | Multi-profile `CIccCmm` pipeline |
| `icc_applynamedcmm_fuzzer` | 359 | 468 | IccApplyNamedCmm | `CIccNamedColorCmm` all Apply variants |
| `icc_link_fuzzer` | 186 | 998 | IccApplyToLink | 2-profile `CIccCmm` link (2× ASAN memory) |
| `icc_spectral_fuzzer` | 172 | 307 | IccV5DspObsToV4Dsp | MPE: `Begin`, `GetNewApply`, `Apply` |
| `icc_spectral_b_fuzzer` | 252 | 1,900 | IccV5DspObsToV4Dsp | Extended spectral MPE pipeline |
| `icc_v5dspobs_fuzzer` | 822 | 741 | IccV5DspObsToV4Dsp | v5 display observer conversion |
| `icc_fromxml_fuzzer` | 167 | 1,693 | XML tools | `CIccProfileXml::LoadXml` |
| `icc_toxml_fuzzer` | 86 | 1,177 | XML tools | `CIccProfile::Read` → `ToXml` |
| `icc_fromcube_fuzzer` | 502 | 338 | IccFromCube | CUBE LUT import pipeline |
| `icc_specsep_fuzzer` | 276 | 1,144 | IccSpecSepToTiff | `CTiffImg` spectral separation |
| `icc_tiffdump_fuzzer` | 223 | 953 | IccTiffDump | `CTiffImg`, `OpenIccProfile`, `FindTag` |

**Total:** 5,222 LOC · 18,843 corpus files · 62,512 dictionary entries

## Patch Kit (57 active patches)

Security patches applied to iccDEV before building. See [`patches/README.md`](patches/README.md) for full details.

| Category | Count | Examples |
|----------|-------|---------|
| OOM allocation caps | 12 | 16MB CLUT, 128MB SetSize, 16MB SparseMatrix |
| Heap-buffer-overflow | 14 | CLUT interp OOB, ApplySequence, pushXYZConvert, icFixXml |
| UBSAN fixes | 10 | Float→int overflow, invalid-enum-load, NaN casts |
| Stack overflow | 4 | Recursion depth caps (100-level), Read8 underflow |
| Memory leaks | 6 | Read() failure paths, ParseTag, CheckPCSConnections |
| Null-deref guards | 3 | NDLut Apply, ParseTag, ToneMapFunc |
| XML parsing limits | 2 | Tag/string caps, mluc/Dict/ProfileSeqId bounds |
| Upstream-adopted (dropped) | 15 | PRs #622, #630-#639 (upstream sync 2026-03-05) |

**Active patches: 56** (70 original − 14 NO-OPs dropped during upstream sync)

## Build

```bash
./build.sh          # full build (clone + patch + compile)
./build.sh clean    # clean rebuild from scratch
```

**Requirements:** clang/clang++ 14+, cmake 3.15+, libxml2-dev, libtiff-dev, zlib, libclang-rt-dev

**What `build.sh` does:**
1. Clones `iccDEV` (or reuses existing checkout)
2. Resets to clean state (`git checkout .`)
3. Applies all 57 patches from `patches/`
4. Builds static libraries (`IccProfLib2-static.a`, `IccXML2-static.a`)
5. Compiles 19 fuzzers with ASAN + UBSAN + coverage instrumentation
6. Outputs binaries to `bin/`

**Instrumentation flags:**
- `-fsanitize=fuzzer,address,undefined`
- `-fprofile-instr-generate -fcoverage-mapping`
- `-g -O1 -fno-omit-frame-pointer`

## Fuzzing Workflows

### Automated Ramdisk (tmpfs)

```bash
# Mount tmpfs, seed corpus, run all fuzzers, sync back, unmount
sudo ./ramdisk-fuzz.sh              # 300s per fuzzer (default)
sudo ./ramdisk-fuzz.sh 60           # 60s per fuzzer (smoke test)
sudo ./ramdisk-fuzz.sh 120 icc_profile_fuzzer icc_io_fuzzer  # specific fuzzers
```

### Local Fuzzing (pre-mounted storage)

```bash
# Requires ramdisk already mounted and seeded
./fuzz-local.sh                     # all 19 fuzzers, 4 workers, 4h each
./fuzz-local.sh -t 3600 icc_dump_fuzzer  # single fuzzer, 1h
./fuzz-local.sh -w 8 -t 600        # 8 workers, 10 min each
./fuzz-local.sh -r /mnt/g/fuzz-ssd  # external SSD storage
```

### Storage Management Scripts

Located in `.github/scripts/`:

| Script | Purpose |
|--------|---------|
| `ramdisk-seed.sh` | Seed corpus from `cfl/corpus-*` to ramdisk/SSD |
| `ramdisk-merge.sh` | LibFuzzer `-merge=1` dedup across all corpora |
| `ramdisk-sync-to-disk.sh` | Sync minimized corpus back to `cfl/corpus-*` |
| `ramdisk-clean.sh` | Remove stale directories (dry-run default) |
| `ramdisk-teardown.sh` | Orchestrate sync → clean → unmount |
| `ramdisk-status.sh` | Report storage state and corpus sizes |
| `ramdisk-cheatsheet.sh` | Copy-paste one-liners for common operations |
| `merge-profdata.sh` | Merge `.profraw` files into `.profdata` |
| `generate-coverage-report.sh` | Generate LCOV/HTML coverage reports |
| `seed-corpus-setup.sh` | Initial corpus seeding from test profiles |
| `seed-pipeline.sh` | Automated seed generation pipeline |
| `test-seed-corpus.sh` | Validate seed corpus readiness |
| `analyze-profile.sh` | Run iccanalyzer-lite 3-phase analysis |
| `batch-test-external.sh` | Batch-test external ICC profiles |
| `sanitize-sed.sh` | Sanitize output for CI display |

### External SSD Fuzzing

```bash
# Mount 1TB SSD
sudo mount -o defaults,noatime /dev/sde /mnt/g

# Seed from disk corpus
.github/scripts/ramdisk-seed.sh --ramdisk /mnt/g/fuzz-ssd

# Run (all scripts accept --ramdisk PATH)
./fuzz-local.sh -r /mnt/g/fuzz-ssd

# Merge + sync back
.github/scripts/ramdisk-merge.sh --ramdisk /mnt/g/fuzz-ssd
.github/scripts/ramdisk-sync-to-disk.sh --ramdisk /mnt/g/fuzz-ssd
```

### Coverage Collection

```bash
# During fuzzing: set per-fuzzer profraw path (includes fuzzer name for identification)
LLVM_PROFILE_FILE=/tmp/fuzz-ramdisk/profraw/icc_profile_fuzzer_%m_%p.profraw \
  /tmp/fuzz-ramdisk/bin/icc_profile_fuzzer ...

# Suppress profraw (for merge ops — avoids 1GB+ stray files)
LLVM_PROFILE_FILE=/dev/null

# Merge profraw → profdata → HTML coverage report
.github/scripts/merge-profdata.sh /tmp/fuzz-ramdisk/profraw
.github/scripts/generate-coverage-report.sh \
  /tmp/fuzz-ramdisk/merged.profdata /tmp/fuzz-ramdisk/coverage-report
```

## Special Fuzzer Notes

| Fuzzer | Special Requirements |
|--------|---------------------|
| `icc_link_fuzzer` | `ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256` (2 profiles per input = 2× ASAN memory) |
| `icc_fromxml_fuzzer` | XML input (not binary ICC); uses `corpus-xml/` seed |
| `icc_fromcube_fuzzer` | CUBE LUT text input (not binary ICC) |
| `icc_deep_dump_fuzzer` | Largest fuzzer (1,029 LOC); deep tag-by-tag inspection |
| `icc_v5dspobs_fuzzer` | v5 spectral profiles only; 822 LOC |

## Directory Structure

```
cfl/
├── bin/                      # Compiled fuzzer binaries (19)
├── corpus-icc_*_fuzzer/      # Per-fuzzer seed corpora (19 dirs)
├── corpus/                   # Shared ICC profiles
├── corpus-xml/               # XML seed corpus for fromxml fuzzer
├── patches/                  # 71 security patches (57 active, 14 NO-OP) + README.md
│   ├── 001-*.patch ... 070-*.patch
│   └── README.md             # Full patch documentation
├── icc_*_fuzzer.cpp           # Fuzzer source files (19)
├── icc_*_fuzzer.dict          # Per-fuzzer dictionaries (19)
├── icc_*_fuzzer.options       # LibFuzzer options files
├── icc_*_fuzzer_seed_corpus/  # Minimal seed corpora
├── findings/                  # Crash/OOM/timeout artifacts
├── iccDEV/                   # DemoIccMAX source (git clone)
├── build.sh                  # Build script (clone + patch + compile)
├── fuzz-local.sh             # Local fuzzing driver
├── ramdisk-fuzz.sh           # Automated ramdisk fuzzing
├── fuzz_utils.h              # Shared fuzzer utilities
├── CMakeLists.txt            # CMake build for iccDEV libraries
├── project.yaml              # ClusterFuzzLite project config
├── Dockerfile                # CFL Docker image
└── codeql-queries/           # Custom CodeQL security queries
```

## Findings

Fuzzing artifacts are stored in:
- `cfl/oom-*` — Out-of-memory reproducers (192 files)
- `cfl/crash-*` — Crash reproducers
- `cfl/findings/` — Organized findings with triage notes

## CodeQL

Custom CodeQL queries in `codeql-queries/` target ICC-specific vulnerability patterns:
- Injection attacks on ICC profile data
- XML external entity (XXE) attacks
- Uncapped allocation patterns
- Unterminated string operations

Config: `codeql-config.yml`

## Related Components

| Component | Path | Description |
|-----------|------|-------------|
| iccanalyzer-lite | `iccanalyzer-lite/` | 102-heuristic security analyzer (v3.3.0) |
| colorbleed_tools | `colorbleed_tools/` | Unsafe ICC↔XML converters for mutation testing |
| MCP Server | `mcp-server/` | ICC Profile MCP server (22 tools) |
| CI Workflows | `.github/workflows/` | CodeQL, coverage, Docker build, MCP tests |
| Prompts | `.github/prompts/` | AI analysis prompt templates |
| Test Profiles | `test-profiles/` | 324 ICC profiles for validation |
