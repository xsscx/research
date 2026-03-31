# CFL — ClusterFuzzLite / LibFuzzer Harnesses for iccDEV

Last Updated: 2026-03-28 18:50:00 UTC

Security fuzzing toolkit for [iccDEV](https://github.com/InternationalColorConsortium/iccDEV) (formerly DemoIccMAX).
13 LibFuzzer harnesses, 44 active security patches, 93 retired patches, and automated ramdisk workflows.

Upstream: iccDEV v2.3.1.5 (commit e62525a)

## Quick Start

```bash
# Build (clones iccDEV, applies 44 patches, compiles 13 fuzzers)
./build.sh

# Smoke test (60 seconds on tmpfs ramdisk)
sudo ./ramdisk-fuzz.sh 60

# Extended fuzzing on pre-mounted storage
./fuzz-local.sh -t 14400 -w 4
```

## Fuzzers (13)

| # | Fuzzer | iccDEV Tool | API Scope |
|---|--------|-------------|-----------|
| 1 | `icc_applynamedcmm_fuzzer` | IccApplyNamedCmm | `CIccNamedColorCmm` all Apply variants |
| 2 | `icc_applyprofiles_fuzzer` | IccApplyProfiles | Multi-profile `CIccCmm` pipeline |
| 3 | `icc_applysearch_fuzzer` | IccApplySearch | `CIccCmmSearch` optimization |
| 4 | `icc_cfg_fuzzer` | JSON config tools | `IccCmmConfig` JSON parsing |
| 5 | `icc_dump_fuzzer` | IccDumpProfile | `OpenIccProfile`, `Describe`, `Validate` |
| 6 | `icc_fromcube_fuzzer` | IccFromCube | CUBE LUT import pipeline |
| 7 | `icc_fromxml_fuzzer` | IccFromXml | `CIccProfileXml::LoadXml` |
| 8 | `icc_link_fuzzer` | IccApplyToLink | 2-profile `CIccCmm` link (2x ASAN memory) |
| 9 | `icc_roundtrip_fuzzer` | IccRoundTrip | Read/Write/Read, `EvaluateProfile` |
| 10 | `icc_specsep_fuzzer` | IccSpecSepToTiff | `CTiffImg` spectral separation |
| 11 | `icc_tiffdump_fuzzer` | IccTiffDump | `CTiffImg`, `OpenIccProfile`, `FindTag` |
| 12 | `icc_toxml_fuzzer` | IccToXml | `CIccProfile::Read` then `ToXml` |
| 13 | `icc_v5dspobs_fuzzer` | IccV5DspObsToV4Dsp | v5 display observer conversion |

## Patch Kit (44 active, 93 retired)

Security patches applied to iccDEV before building. Retired patches are in `patches-retired/` — accepted upstream in v2.3.1.5/v2.3.1.6 or superseded by LibFuzzer runtime limits.

### Active Patches (44)

| # | Patch | CWE | Files |
|---|-------|-----|-------|
| 004 | ToneMapFunc Read parameter count | CWE-122 | IccMpeBasic.cpp |
| 005 | CalculatorFunc Read enum UBSAN | CWE-681 | IccMpeCalc.cpp |
| 006 | SpectralMatrix Describe iteration bounds | CWE-122 | IccMpeSpectral.cpp |
| 007 | TagArray Read overflow guard | CWE-190 | IccTagComposite.cpp |
| 008 | TagCurve Apply NaN-to-unsigned | CWE-681 | IccTagLut.cpp |
| 009 | EnvVar Exec enum UBSAN | CWE-681 | IccMpeCalc.cpp |
| 014 | SequenceNeedTempReset recursion depth | CWE-674 | IccMpeCalc.cpp |
| 017 | GetEnvSig parse enum UBSAN | CWE-681 | IccMpeCalc.cpp, IccMpeCalc.h |
| 019 | PCC getReflectanceObserver null guard | CWE-476 | IccPcc.cpp |
| 021 | SingleSampledCurve OOM size validation | CWE-400 | IccMpeBasic.cpp |
| 022 | Calc Trunc/Floor/Ceil/Round/Mod int overflow | CWE-681 | IccMpeCalc.cpp |
| 023 | Sampled curve NaN-to-unsigned cast | CWE-681 | IccMpeBasic.cpp |
| 025 | CLUT InterpNd null Apply guard | CWE-476 | IccTagLut.cpp |
| 028 | MatrixMath SetRange NaN guard | CWE-681 | IccMatrixMath.cpp |
| 029 | TagArray operator= loop var | CWE-824 | IccTagComposite.cpp |
| 040 | fromIt8 CMYK missing push_back | CWE-787 | IccCmmConfig.cpp |
| 041 | fromIt8 LAB/XYZ val(4) OOB | CWE-125 | IccCmmConfig.cpp |
| 042 | ParseNumbers 'n' vs '\n' typo | CWE-20 | IccCmmConfig.cpp |
| 043 | Tool toJson is_object vs is_array | CWE-697 | iccApplyNamedCmm.cpp, iccApplySearch.cpp |
| 044 | NDLut Apply missing interp dispatch | CWE-476 | IccCmm.cpp |
| 046 | PCS step src matrix delete[] | CWE-762 | IccCmm.cpp |
| 047 | pushXYZNormalize null PCC guard | CWE-476 | IccCmm.cpp |
| 050 | FormulaCurve Describe param bounds | CWE-125 | IccMpeBasic.cpp |
| 051 | ParametricCurve Describe param bounds | CWE-125 | IccTagLut.cpp |
| 052 | fromIt8 wrong index variable | CWE-125 | IccCmmConfig.cpp |
| 053 | FormulaCurve Describe format specifiers | CWE-134 | IccMpeBasic.cpp |
| 054 | ParametricCurve Describe format specifiers | CWE-134 | IccTagLut.cpp |
| 055 | fromIt8 signed-unsigned mismatch | CWE-681 | IccCmmConfig.cpp |
| 056 | Spectral Describe null pointer guards | CWE-476 | IccMpeSpectral.cpp |
| 057 | SearchApply uninitialized members | CWE-908 | IccCmmConfig.cpp |
| 059 | TagCurve Begin nMaxIndex UBSAN | CWE-681 | IccTagLut.h |
| 061 | icF16toF unsigned underflow | CWE-191 | IccUtil.cpp |
| 062 | icGetSig implicit char conversion | CWE-681 | IccUtil.cpp |
| 063 | Bounds check unsigned overflow | CWE-190 | IccProfile.cpp, IccTagMPE.cpp, IccMpeCalc.cpp |
| 064 | Segmented curve subtraction underflow | CWE-191 | IccMpeBasic.cpp |
| 067 | icIsS15Fixed16NumberNear float overflow | CWE-681 | IccUtil.cpp |
| 068 | MpeCurveSet operator= self-assignment | CWE-824 | IccMpeBasic.cpp |
| 069 | operator= self-assignment guards | CWE-824 | Multiple files |
| 070 | Missing member copies operator=/copy-ctor | CWE-665 | Multiple files |
| 072 | printf format + unused fn | CWE-134 | Multiple files |
| 073 | IccProfileXml implicit fallthrough | CWE-484 | IccProfileXml.cpp |
| 075 | IccCmmConfig uninit + format fixes | CWE-908 | IccCmmConfig.cpp |
| 077 | CAM CalcCoefficients div-by-zero guard | CWE-369 | IccCAM.cpp |
| 078 | AddXform cenc UAF guard | CWE-416 | IccCmm.cpp |

### Upstream Status

| Patch | Status | Reference |
|-------|--------|-----------|
| CFL-004 | **PoC-validated** — ASAN HBO at IccMpeBasic.cpp:3988, SCARINESS=17 | `test-profiles/CIccToneMapFunc-Describe-heap-oob-IccMpeBasic_cpp.icc` |
| CFL-077 | **PoC-validated** — UBSAN div-by-zero at IccCAM.cpp:266,283 | [PR #754](https://github.com/InternationalColorConsortium/iccDEV/pull/754) (open, Merge Ready) |
| CFL-078 | **PoC-validated** — HUAF at IccCmm.cpp:10564 via cenc profile ownership | [Issue #763](https://github.com/InternationalColorConsortium/iccDEV/issues/763) (open) |

### Retired Patches (93 in `patches-retired/`)

Patches accepted upstream in iccDEV v2.3.1.5/v2.3.1.6, or superseded by LibFuzzer runtime limits (`-timeout=30 -rss_limit_mb=4096`).

| # | Reason | Upstream Reference |
|---|--------|--------------------|
| 001 | Accepted upstream | v2.3.1.5 |
| 002 | Accepted upstream v2.3.1.6 | GBD triangles overflow |
| 003 | Accepted upstream | PRs #680, #693 |
| 010-013, 015-016, 018 | Accepted upstream | pre-v2.3.1.5 |
| 019-old | Accepted upstream (partial) | PR #691 |
| 020, 024, 026-027 | Accepted upstream | PRs #683, #694, #692 |
| 034, 037, 039 | Accepted upstream | commit c2ea9da |
| 036 | Accepted upstream v2.3.1.6 | linkGridSize toJson |
| 065 | Accepted upstream v2.3.1.6 | IccTagLut nEnd underflow |
| 076 | Accepted upstream v2.3.1.6 | GBD signed channel type confusion |
| 074-083 (old series) | Superseded by LibFuzzer runtime limits | CWE-400 timeout/OOM patterns |

See `patches-retired/` for the complete archive.

## Build

```bash
./build.sh          # full build (clone + patch + compile)
./build.sh clean    # clean rebuild from scratch
```

**Requirements:** clang/clang++ 14+, cmake 3.15+, libxml2-dev, libtiff-dev, zlib, libclang-rt-dev

**What `build.sh` does:**
1. Clones `iccDEV` (or reuses existing checkout)
2. Resets to clean state (`git checkout .`)
3. Applies all 44 patches from `patches/`
4. Builds static libraries (`IccProfLib2-static.a`, `IccXML2-static.a`)
5. Compiles 13 fuzzers with ASAN + UBSAN + coverage instrumentation
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
./fuzz-local.sh                     # all 13 fuzzers, 4 workers, 4h each
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
| `icc_link_fuzzer` | `ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256` (2 profiles per input = 2x ASAN memory) |
| `icc_fromxml_fuzzer` | XML input (not binary ICC); uses `corpus-xml/` seed |
| `icc_fromcube_fuzzer` | CUBE LUT text input (not binary ICC) |
| `icc_cfg_fuzzer` | JSON config input; uses malformed JSON test configs |
| `icc_v5dspobs_fuzzer` | v5 spectral profiles; multi-profile bundled input format |

## Directory Structure

```
cfl/
├── bin/                      # Compiled fuzzer binaries (13)
├── corpus-icc_*_fuzzer/      # Per-fuzzer seed corpora (11 active dirs)
├── corpus/                   # Shared ICC profiles
├── corpus-xml/               # XML seed corpus for fromxml fuzzer
├── patches/                  # 44 active security patches
│   ├── 004-*.patch ... 078-*.patch
│   └── README.md             # Full patch documentation
├── patches-retired/          # 93 retired patches (accepted upstream or superseded)
├── icc_*_fuzzer.cpp          # Fuzzer source files (13)
├── icc_*_fuzzer.dict         # Per-fuzzer dictionaries
├── icc_*_fuzzer.options      # LibFuzzer options files
├── icc_*_fuzzer_seed_corpus/ # Minimal seed corpora
├── findings/                 # Crash/OOM/timeout artifacts
├── iccDEV/                   # iccDEV source (git clone, patched at build time)
├── build.sh                  # Build script (clone + patch + compile)
├── fuzz-local.sh             # Local fuzzing driver
├── ramdisk-fuzz.sh           # Automated ramdisk fuzzing
├── fuzz_utils.h              # Shared fuzzer utilities
├── CflSafeDescribe.h         # SafeDescribe wrapper for Describe-calling fuzzers
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
| iccanalyzer-lite | `iccanalyzer-lite/` | 173-heuristic security analyzer with ASAN/UBSAN |
| colorbleed_tools | `colorbleed_tools/` | Unsafe ICC/XML converters for mutation testing |
| MCP Server | `mcp-server/` | ICC Profile MCP server (24 tools) |
| AFL++ | `afl/` | Tool-level AFL++ fuzzing (14 instrumented iccDEV tools) |
| CI Workflows | `.github/workflows/` | CodeQL, coverage, Docker build, MCP tests |
| Prompts | `.github/prompts/` | AI analysis prompt templates |
| Test Profiles | `test-profiles/` | ICC profiles for validation |
| xnuimagetools | [github.com/xsscx/xnuimagetools](https://github.com/xsscx/xnuimagetools) | Multi-platform image generation + VideoToolbox fuzzer |
| xnuimagefuzzer | [github.com/xsscx/xnuimagefuzzer](https://github.com/xsscx/xnuimagefuzzer) | iOS/macOS image fuzzer (15 bitmap contexts, 22 formats) |
