---
applyTo: "cfl/**"
---

# CFL (ClusterFuzzLite) -- Path-Specific Instructions

## What This Is

13 LibFuzzer harnesses (~2,800 LOC, C/C++) targeting the iccDEV ICC profile library.
Each fuzzer has a custom-built dictionary, seed corpus, and ASAN+UBSAN instrumentation.

## Build

```bash
cd cfl && ./build.sh   # clones iccDEV if missing, applies patches, builds 13 fuzzers
```

- **First run**: clones iccDEV into `cfl/iccDEV/`
- **Subsequent runs**: reuses existing checkout (does NOT auto-update)
- Applies targeted patches from `cfl/patches/`
- Compiler: clang++ 18 with `-fsanitize=address,undefined,fuzzer`
- Binaries: `cfl/bin/icc_*_fuzzer` (13 total)

## Upstream Sync

```bash
cd cfl/iccDEV && git fetch origin && git reset --hard origin/master && git clean -fd
cd .. && ./build.sh   # re-applies patches and rebuilds
```

**CRITICAL**: After sync, delete `Build/` to avoid stale cmake cache retaining
wrong sanitizer flags. Verify ASAN: `nm cfl/bin/icc_dump_fuzzer | grep -c __asan` (must be > 0).

## The 13 Fuzzers

| # | Binary | Primary Target |
|---|--------|----------------|
| 1 | icc_applynamedcmm_fuzzer | Named color CMM |
| 2 | icc_applyprofiles_fuzzer | Multi-profile transforms |
| 3 | icc_dump_fuzzer | CIccProfile::Describe() |
| 4 | icc_fromcube_fuzzer | .cube LUT parsing |
| 5 | icc_fromxml_fuzzer | CIccProfile::LoadXml() |
| 6 | icc_link_fuzzer | Profile linking |
| 7 | icc_roundtrip_fuzzer | Round-trip transforms |
| 8 | icc_specsep_fuzzer | Spectral separation |
| 9 | icc_tiffdump_fuzzer | TIFF tag reading |
| 10 | icc_toxml_fuzzer | CIccProfile::SaveXml() |
| 11 | icc_v5dspobs_fuzzer | v5 DspObs->v4 conversion |
| 12 | icc_applysearch_fuzzer | CIccCmmSearch optimization |
| 13 | icc_cfg_fuzzer | JSON config parsing |

## Patch System

62 legacy patches retired March 2026 (preserved in `cfl/patches-retired/`).
Current approach: minimal targeted patches for verified upstream bugs only.
Timeouts/OOMs handled by LibFuzzer `-timeout=30 -rss_limit_mb=4096`.

### Active Patches (41 files, CFL-001 through CFL-080)

| Patch | Bug Summary | CWE | Primary File |
|-------|------------|-----|-------------|
| 001 | icAnsiToUtf8 null termination HBO | CWE-125/170 | IccTagBasic.cpp, IccUtilXml.cpp |
| 002 | GamutBoundary triangles overflow | CWE-190 | IccTagLut.cpp |
| 005 | CalculatorFunc Read enum UBSAN | CWE-681 | IccMpeCalc.cpp |
| 006 | SpectralMatrix Describe bounds HBO | CWE-122 | IccMpeSpectral.cpp |

| 008 | TagCurve Apply NaN-to-unsigned | CWE-681 | IccTagLut.cpp |
| 009 | EnvVar Exec enum UBSAN | CWE-681 | IccMpeCalc.cpp |
| 014 | SequenceNeedTempReset recursion | CWE-674 | IccMpeCalc.cpp |
| 017 | GetEnvSig parse enum UBSAN | CWE-681 | IccMpeCalc.cpp |
| 019 | PCC getReflectanceObserver null | CWE-476 | IccPcc.cpp |
| 021 | SingleSampledCurve OOM size | CWE-400 | IccMpeBasic.cpp |
| 022 | Calc Trunc/Floor/Ceil int overflow | CWE-681 | IccMpeCalc.cpp |
| 023 | Sampled curve NaN-to-unsigned | CWE-681 | IccMpeBasic.cpp |
| 025 | CLUT InterpNd null Apply guard | CWE-476 | IccTagLut.cpp |
| 028 | MatrixMath SetRange NaN guard | CWE-681 | IccMatrixMath.cpp |

| 030 | FixedNum GetValues SBO | CWE-121 | IccTagBasic.cpp |
| 031 | loadJsonFrom ftell overflow | CWE-190/252 | IccJsonUtil.cpp |
| 032 | icXformInterp enum range | CWE-20/681 | IccCmmConfig.cpp |
| 033 | PccWeight fromJson field swap | CWE-843 | IccCmmConfig.cpp |
| 034 | SearchApply interpolation key | CWE-345 | IccCmmConfig.cpp |
| 035 | ApplyCmmSearch m_nApply OOB | CWE-122 | IccCmmSearch.cpp |
| 036-039 | CreateLink/Profile/Search toJson | CWE-345/561 | IccCmmConfig.cpp |
| 040-041 | fromIt8 CMYK/LAB bugs | CWE-787/125 | IccCmmConfig.cpp |
| 043 | Tool toJson is_object vs is_array | CWE-697 | iccApplyNamedCmm.cpp |
| 044-048 | NDLut/AddXform/PCS/DumpLut guards | CWE-476/762/122 | IccCmm.cpp, IccTagLut.cpp |
| 049-054 | MBB/FormulaCurve/ParametricCurve | CWE-125/134 | IccTagLut.cpp, IccMpeBasic.cpp |
| 056-059 | Spectral null/uninitialized/UBSAN | CWE-476/908/681 | IccMpeSpectral.cpp, IccIO.cpp |
| 060 | icGetSigStr overflow | CWE-190 | IccUtil.cpp |
| 064-067 | Segmented curve/bitmask underflow | CWE-191/681 | Multiple files |
| 076 | GBD signed channel type confusion | CWE-681 | IccTagLut.h |
| 078 | AddXform cenc UAF guard | CWE-416 | IccCmm.cpp |
| 080 | IccUtilXml MCSNeedsSubset UBSAN | CWE-681 | IccUtilXml.cpp |

For per-patch PoC details, ASAN traces, and reproduction commands,
see `docs/analysis/ICCANALYZER_CFL_PATCH_COVERAGE_MATRIX.md`.

### Retired Patches (accepted upstream)

003, 004, 007, 010-013, 015-016, 018, 019-old, 020, 024, 026-027, 029, 034, 037, 039,
042, 055, 061, 062, 063, 072, 073, 077.

### Adding a New Patch

1. Reproduce with upstream `iccDEV/Build/Tools/` (ASAN-instrumented)
2. Identify root cause from ASAN stack frames #2-#3
3. Fix in `cfl/iccDEV/`, generate: `cd cfl/iccDEV && git diff > ../patches/NNN-name.patch`
4. Reset: `cd cfl/iccDEV && git checkout -- .`
5. Rebuild: `cd cfl && ./build.sh` -- verify "Applied: NNN-name.patch"
6. Test PoC with patched fuzzer -- verify exit 0, 0 ASAN
7. File upstream issue per `.github/prompts/upstream-issue-filing.prompt.md` (#795 format)

**Upstream issue format**: Zero prose. Vuln block (6 lines), Build, Repro, Bad, Patch.
One bug per issue. Cut shadow byte legend unless UAF/double-free.

### Build Troubleshooting

**Patch conflicts**: `build.sh` runs `git checkout -- .` before applying.
Patches targeting the same file MUST apply in order (context dependency).
Key multi-patch files: `IccMpeCalc.cpp` (6 patches), `IccTagLut.cpp` (8 patches).

**Stale cmake cache**: After upstream sync, `rm -rf cfl/iccDEV/Build` before rebuild.

## SafeDescribe Pattern

6 fuzzers that call `Describe()` use `SafeDescribe()` from `CflSafeDescribe.h`.
Runs `Validate()` first -- if tag has `icValidateCriticalError`, skips `Describe()`
to avoid crashes from partially-loaded state.

Affected: dump, deep_dump, profile, calculator, spectral, tiffdump fuzzers.

## Fuzzing

```bash
cd cfl && ./ramdisk-fuzz.sh                  # mount + seed + run all 13
cd cfl && ./fuzz-local.sh -r /mnt/g/fuzz-ssd # external SSD
.github/scripts/ramdisk-merge.sh             # merge corpus
.github/scripts/merge-profdata.sh            # coverage
```

### Key Runtime Settings

- `ASAN_OPTIONS=detect_leaks=0` (always)
- `icc_link_fuzzer`: add `quarantine_size_mb=256` (2x ASAN memory)
- `LLVM_PROFILE_FILE=/dev/null` during fuzzing (suppress profraw)
- `Begin()` return check: `CIccMpeCurveSet::Begin()` can return false -- callers MUST check

### Multi-Profile Input Formats

| Fuzzer | Format |
|--------|--------|
| v5dspobs | `[4B BE size][display.icc][observer.icc]` |
| link | `[50% profile1][50% profile2][4B control]` |
| applyprofiles | `[75% profile][25% control (intent, interp, W*H, pixels)]` |
| applynamedcmm | `[4B control header][ICC data]` |
| specsep | `[1B nFiles][14B TIFF meta][TIFF+ICC data]` |

Unbundle: `.github/scripts/unbundle-fuzzer-input.sh <fuzzer> <crash_file>`

## Corpus Management

- Seed corpus: `cfl/corpus-<fuzzer_name>/` (committed)
- Runtime corpus: `$RAMDISK/corpus-<fuzzer_name>/` (in-memory)
- Only 11 corpus dirs have matching binaries for minimization
- `corpus-xml` is a named XML seed staging area for `icc_fromxml_fuzzer`

### Tournament Bracket Merge

For corpora >500 files, split into 32 chunks, merge each on its own core,
then tournament-pair outputs 16->8->4->2->1. Result: 9103->481 in ~2 min.

## Coverage

| Metric | Baseline |
|--------|----------|
| Functions | 63.23% |
| Lines | 61.15% |
| Branches | 58.47% |

92.6% of 54 upstream security fix PRs covered by CFL fuzzers.

## Dictionary Files

One dict per fuzzer: `cfl/icc_<name>_fuzzer.dict` (or `cfl/icc_<name>.dict`).
All entries use `\xHH` hex escapes (NOT raw binary). LibFuzzer rejects raw control chars.
TIFF dict: 4215 entries combining TIFF 6.0 tags + ICC sigs + corpus tokens.

## Adding a New Fuzzer

1. Create `cfl/icc_newfuzzer_fuzzer.cpp` with `LLVMFuzzerTestOneInput()`
2. Create dictionary: `cfl/icc_newfuzzer.dict`
3. Create seed corpus: `cfl/corpus-icc_newfuzzer_fuzzer/`
4. Add to `cfl/CMakeLists.txt`
5. Update fuzzer count across documentation
6. Rebuild: `cd cfl && ./build.sh`
