---
applyTo: "cfl/**"
---

# CFL (Crash-Free LibFuzzer) — Path-Specific Instructions

## What This Is

11 LibFuzzer harnesses (~2,500 LOC, C/C++) targeting the iccDEV ICC profile library.
Each fuzzer has a custom-built dictionary, seed corpus, and ASAN+UBSAN instrumentation.

## Build

```bash
cd cfl && ./build.sh   # clones iccDEV if missing, applies patches, builds 11 fuzzers
```

- **First run**: clones `github.com/InternationalColorConsortium/iccDEV.git` into `cfl/iccDEV/`
- **Subsequent runs**: reuses existing `cfl/iccDEV/` checkout — does NOT auto-update
- Applies targeted patches from `cfl/patches/` (new findings only — see Patch System below)
- Compiler: clang++ 18 with `-fsanitize=address,undefined,fuzzer`
- Binaries: `cfl/bin/icc_*_fuzzer` (11 total)

## Upstream Sync

When upstream iccDEV changes:
```bash
cd cfl/iccDEV && git fetch origin && git reset --hard origin/master && git clean -fd
cd .. && ./build.sh   # re-applies patches and rebuilds
```

Current upstream: commit **1ffa7a8** / v2.3.1.5 (2026-03-08)

## The 11 Fuzzers

| # | Fuzzer Binary | Primary Target |
|---|--------------|----------------|
| 1 | icc_profile_fuzzer | CIccProfile::Read() |
| 2 | icc_toxml_fuzzer | CIccProfile::SaveXml() |
| 3 | icc_fromxml_fuzzer | CIccProfile::LoadXml() |
| 4 | icc_dump_fuzzer | CIccProfile::Describe() |
| 5 | icc_deep_dump_fuzzer | Full tag enumeration |
| 6 | icc_io_fuzzer | Byte-level I/O |
| 7 | icc_apply_fuzzer | CIccCmm::Apply() |
| 8 | icc_applyprofiles_fuzzer | Multi-profile transforms |
| 9 | icc_applynamedcmm_fuzzer | Named color CMM |
| 10 | icc_calculator_fuzzer | MPE Calculator |
| 11 | icc_link_fuzzer | Profile linking |
| 12 | icc_fromcube_fuzzer | .cube LUT parsing |
| 13 | icc_multitag_fuzzer | Multi-tag load |
| 14 | icc_spectral_fuzzer | Spectral PCS |
| 15 | icc_specsep_fuzzer | Spectral separation |
| 16 | icc_v5dspobs_fuzzer | v5 DspObs→v4 conversion |
| 17 | icc_tiffdump_fuzzer | TIFF tag reading |
| 18 | icc_roundtrip_fuzzer | Round-trip transforms |

## Patch System (Post-Retirement Architecture)

### History
62 legacy CFL patches (CFL-001 through CFL-083, with gaps) were retired in March 2026
after repeated multi-hour rework cycles caused by context conflicts, false success
claims, and upstream sync overhead. Retired patches are preserved in `cfl/patches-retired/`
for historical reference.

### Current Approach
- **Minimal targeted patches** in `cfl/patches/` — only for verified upstream bugs
- Timeouts and OOMs handled by LibFuzzer's built-in `-timeout=30 -rss_limit_mb=4096`
- Real crashes become upstream bug reports
- build.sh applies patches with 3-state detection: applied, already-applied, FAIL

### Active Patches

| # | Patch | Bug | CWE | Files Modified |
|---|-------|-----|-----|----------------|
| 001 | icAnsiToUtf8 null termination | HBO via strlen on unterminated 32-byte name | CWE-125/CWE-170 | IccTagBasic.cpp, IccUtilXml.cpp |
| 002 | GamutBoundary triangles overflow | Signed int overflow: m_NumberOfTriangles*3 | CWE-190 | IccTagLut.cpp |
| 003 | TagArray alloc-dealloc mismatch | new[] in copy ctor, free() in Cleanup() | CWE-762 | IccTagComposite.cpp |
| 004 | ToneMapFunc Read parameter count | HBO via Describe() accessing m_params[0..2] with only 1 allocated | CWE-122 | IccMpeBasic.cpp |
| 005 | CalculatorFunc Read enum UBSAN | Enum out-of-range in calculator op read | CWE-681 | IccMpeCalc.cpp |
| 006 | SpectralMatrix Describe iteration bounds | HBO via Describe() iterating m_nOutputChannels rows | CWE-122 | IccMpeSpectral.cpp |
| 007 | TagArray Read overflow guard | Integer overflow in TagArray element count | CWE-190 | IccTagComposite.cpp |
| 008 | TagCurve Apply NaN-to-unsigned | NaN bypasses [0,1] clamp, cast to unsigned is UB | CWE-681 | IccTagLut.cpp |
| 009 | EnvVar Exec enum UBSAN | Enum out-of-range in CIccOpDefEnvVar::Exec() | CWE-681 | IccMpeCalc.cpp |
| 010 | CheckUnderflowOverflow recursion | Unbounded recursion depth 50 + 200K ops budget | CWE-674 | IccMpeCalc.cpp |
| 011 | SpecSepToTiff unique_ptr array | unique_ptr\<T\> with new T[] uses delete not delete[] | CWE-762 | iccSpecSepToTiff.cpp |
| 012 | NDLut InterpND null ApplyCLUT | NULL CIccApplyCLUT deref in CIccXformNDLut::Apply() | CWE-476 | IccCmm.cpp |
| 013 | TagArray Cleanup uninit guard | Uninit m_TagVals/m_nSize in copy ctor + leaked pTag on Read fail | CWE-908/CWE-416/CWE-401 | IccTagComposite.cpp |

- File: `cfl/patches/NNN-descriptive-name.patch`
- Numbering: zero-padded 3-digit, sequential (next: **014**)
- Format: unified diff (`git diff`) against `cfl/iccDEV/`
- **iccanalyzer-lite does NOT use CFL patches** — it links unpatched upstream iccDEV
  and handles all user-controllable inputs via its own defensive programming

### Adding a New Patch

1. Reproduce the bug with upstream `iccDEV/Build/Tools/` (ASAN-instrumented)
2. Identify root cause — read ASAN stack frames #2-#3
3. Apply fix in `cfl/iccDEV/`, generate with `cd cfl/iccDEV && git diff > ../patches/NNN-name.patch`
4. Reset: `cd cfl/iccDEV && git checkout -- .`
5. Rebuild: `cd cfl && ./build.sh` — verify "Applied: NNN-name.patch"
6. Test PoC with patched fuzzer — verify exit 0, 0 ASAN
7. Report upstream at `github.com/InternationalColorConsortium/iccDEV/issues`

### CFL-001: icAnsiToUtf8 Heap-Buffer-Overflow

- **PoC**: `hbo-icAnsiToUtf8-clrt-multitag-IccUtilXml_cpp-Line394.icc`
- **ASAN trace**: `strlen` → `icAnsiToUtf8()` (IccUtilXml.cpp:394) → `CIccTagXmlColorantTable::ToXml()` (IccTagXml.cpp:1883)
- **Root cause**: `icColorantTableEntry.name` is a fixed 32-byte `icInt8Number` array.
  `CIccTagColorantTable::Read()` reads exactly 32 bytes but does NOT enforce null
  termination. When `ToXml()` passes this to `icAnsiToUtf8()`, the non-WIN32 path
  does `buf = szSrc` which calls `strlen()`, reading past the 32-byte buffer.
- **Fix 1**: Force `name[31] = '\0'` after `Read8()` in `IccTagBasic.cpp`
- **Fix 2**: Defense-in-depth `strnlen(szSrc, 256)` in `icAnsiToUtf8()`/`icUtf8ToAnsi()`
- **Affected tools**: iccToXml, icc_toxml_fuzzer, icc_dump_fuzzer, icc_deep_dump_fuzzer
- **iccanalyzer-lite counterpart**: H144 (XML String Termination Precheck) detects this pattern

### CFL-003: CIccTagArray alloc-dealloc-mismatch (CWE-762)

- **PoC 1**: `crash-5d55e28af84613a7a72c0688193085664e7d0a36` (1463 bytes, multi-profile)
- **PoC 2**: `test-profiles/cfl-003-roundtrip-segv-tary.icc` (5851 bytes, mntr/RGB, PCS='XCLR')
  — Triggers SEGV at 0xbebebebebebebebe via BPC path; 3/3 reproducible with upstream iccRoundTrip
- **ASAN trace**: `alloc-dealloc-mismatch (operator new[] vs free)` at IccTagComposite.cpp:1523,
  or SEGV at 0xbebebebebebebebe (ASAN freed memory marker) at IccTagComposite.cpp:1511
- **Root cause**: `CIccTagArray` copy constructor (line 1037) and `operator=` (line 1074)
  allocate `m_TagVals` with `new IccTagPtr[]`, but `Cleanup()` (line 1523) frees with
  `free()`. The `SetSize()` path uses `calloc()`/`icRealloc()`, which matches `free()`.
  Mixed allocation strategies cause undefined behavior on copy/assign paths.
- **Fix**: Replace `new IccTagPtr[n]` with `calloc(n, sizeof(IccTagPtr))` in both
  copy constructor and `operator=` to match the `free()` in `Cleanup()`.
- **Affected tools**: Any tool calling `AddXform(CIccProfile&)` by reference with a
  profile containing CIccTagArray tags. The reference overload at `IccCmm.cpp:8517`
  triggers `new CIccProfile(Profile)` → copy constructor → `CIccTagArray::NewCopy()`.
  `EvaluateProfile()` at `IccEval.cpp:104,115,120` uses this path (3× per profile).
  Also triggered via BPC: `CIccApplyBPC::pixelXfm()` → `CIccProfile copy` → same mismatch.
- **Upstream reproduction (PoC 1 — alloc-dealloc-mismatch)**:
  ```bash
  ASAN_OPTIONS=halt_on_error=1,detect_leaks=0,alloc_dealloc_mismatch=1 \
  LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
    iccDEV/Build/Tools/IccRoundTrip/iccRoundTrip test-profiles/17ChanPart1.icc
  ```
- **Upstream reproduction (PoC 2 — SEGV)**:
  ```bash
  ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
    iccDEV/Build/Tools/IccRoundTrip/iccRoundTrip test-profiles/cfl-003-roundtrip-segv-tary.icc
  ```
  Profile requirement: class `scnr`/`mntr`/`prtr`/`spac` AND contains `tary` tag.
  `17ChanPart1.icc` (scnr, 17-channel) triggers via EvaluateProfile→AddXform.
  `cfl-003-roundtrip-segv-tary.icc` (mntr/RGB, invalid PCS) triggers via BPC→pixelXfm→copy.
- **Call chain (PoC 1)**: `iccRoundTrip::main()` → `EvaluateProfile(path)` →
  `EvaluateProfile(CIccProfile*)` → `CIccCmm::AddXform(CIccProfile&)` →
  `new CIccProfile(Profile)` → `CIccTagArray::CIccTagArray(const&)` (new[]) →
  AddXform fails → `delete pProfile` → `CIccProfile::Cleanup()` →
  `CIccTagArray::Cleanup()` → `free(m_TagVals)` (mismatch)
- **Call chain (PoC 2)**: `iccRoundTrip::main()` → `EvaluateProfile` →
  `CIccCmm::AddXform` → `CIccXformMatrixTRC::Begin()` → `CIccXform::Begin()` →
  `CIccApplyBPC::CalcFactors()` → `calcSrcBlackPoint()` → `pixelXfm()` →
  `CIccProfile::CIccProfile(const&)` → `CIccTagArray::NewCopy()` → copy ctor SEGV

### CFL-004: CIccToneMapFunc Heap-Buffer-Overflow (CWE-122)

- **PoC**: `crash-6ec5f76cd5d6c934c111eb59bc81ea44362ca3ee` (2368 bytes, BT.2100 HLG Narrow)
- **ASAN trace**: `CIccToneMapFunc::Describe()` at IccMpeBasic.cpp:3984 — accesses
  `m_params[0]`, `m_params[1]`, `m_params[2]` but only 1 float allocated
- **Root cause**: `CIccToneMapFunc::Read()` computes `m_nParameters = (size - headerSize) / sizeof(icFloatNumber)`
  from file-controlled size without validating against `NumArgs()`. When the file provides
  only 1 parameter but the function type expects 3, `Describe()` reads past the allocation.
- **Fix**: After computing `m_nParameters`, validate `m_nParameters >= NumArgs()`. If
  insufficient, set `m_params = NULL; m_nParameters = 0; return false;`
- **Upstream reproduction**: `iccDumpProfile <file> ALL` triggers DumpTagCore → Describe
- **Fuzzer alignment fix**: All 6 Describe-calling fuzzers now use `SafeDescribe()`
  from `CflSafeDescribe.h` which validates tag state before calling `Describe()`

### CFL-008: CIccTagCurve::Apply NaN→unsigned UBSAN (CWE-681)

- **UBSAN trace**: `IccTagLut.cpp:584:43: runtime error: -nan is outside the range of
  representable values of type 'unsigned int'`
- **Root cause**: `CIccTagCurve::Apply()` clamps input `v` with `if(v<0.0)` / `else if(v>1.0)`.
  IEEE 754 NaN fails BOTH comparisons (NaN is not less than, greater than, or equal to
  anything). Line 584 then casts `NaN * m_nMaxIndex` to `icUInt32Number` — undefined behavior.
- **Fix**: `if(v<0.0 || std::isnan(v)) v = 0.0;` — `<cmath>` already included at line 78
- **Sister function**: `ClutUnitClip()` at IccTagLut.cpp:1623 ALREADY has
  `if (std::isnan(v)) return 0;` — proving NaN occurrence was known in this code area.
  CFL-008 applies the identical pattern to the unprotected `Apply()` function.
- **Upstream reproduction**: NOT reproducible through upstream CLI tools. The upstream
  tool's input validation (data file parsing, profile validation) prevents the conditions
  that produce NaN. 500+ corpus files tested through `iccApplyNamedCmm` and `iccRoundTrip`
  with UBSAN enabled — zero triggers. The NaN originates from fuzzer mutation paths
  that bypass tool-level input validation.
- **Classification**: Defensive hardening — the code has a genuine bug (NaN bypass of
  clamp checks), but upstream tools never exercise the vulnerable path. Any third-party
  consumer of `CIccTagCurve::Apply()` with attacker-controlled profile data could hit this.
- **Related**: `RGBClip()` at IccCmm.cpp:5380-5388 has the SAME NaN bypass bug
  (potential future patch)

## Fuzzer Alignment — SafeDescribe Pattern

All fuzzers that call `CIccTag::Describe()` use `SafeDescribe()` from `CflSafeDescribe.h`.
This wrapper runs `Validate()` first — if the tag has `icValidateCriticalError`, it
skips `Describe()` to avoid crashes from partially-loaded internal state.

**Affected fuzzers** (6 of 18):
- `icc_dump_fuzzer.cpp` — tag iteration Describe
- `icc_deep_dump_fuzzer.cpp` — tags, curves, MPE elements, structs, dicts
- `icc_profile_fuzzer.cpp` — tag iteration + FindTag Describe
- `icc_calculator_fuzzer.cpp` — LUT/MPE Describe
- `icc_spectral_fuzzer.cpp` — spectral tags, MPE, all tags
- `icc_tiffdump_fuzzer.cpp` — embedded ICC tag Describe

**Why this matters**: Fuzzers call `Describe()` unconditionally on every loaded tag.
Upstream tools only call `Describe()` in specific modes (e.g., `iccDumpProfile ALL`).
When `Read()` partially populates internal state, `Describe()` reads out of bounds.
`SafeDescribe()` catches this by running `Validate()` first.

## Fuzzing — Ramdisk Workflow

```bash
# Mount ramdisk, seed corpus, run all 11 fuzzers
cd cfl && ./ramdisk-fuzz.sh

# Or use external SSD
cd cfl && ./fuzz-local.sh -r /mnt/g/fuzz-ssd

# After fuzzing: merge, sync, coverage
.github/scripts/ramdisk-merge.sh
.github/scripts/ramdisk-sync-to-disk.sh
.github/scripts/merge-profdata.sh
.github/scripts/generate-coverage-report.sh
```

## Special Fuzzer Notes

- **icc_link_fuzzer**: Needs `ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256`
  (2 profiles per input = 2× ASAN memory)
- **Ownership caveat**: `CIccCmm::AddXform(CIccProfile*)` transfers ownership.
  On `icCmmStatBadXform`, profile is already freed — do NOT delete.
  On other errors, caller must delete (not consumed).
- **Coverage**: `LLVM_PROFILE_FILE=$RAMDISK/profraw/${fuzzer_name}_%m_%p.profraw`
  (include fuzzer name; `%m` alone produces numeric hashes)
- **Suppress profraw during fuzzing**: `LLVM_PROFILE_FILE=/dev/null`
- **Begin() return check**: `CIccTagMultiProcessElement::Begin()` and
  `CIccMpeCurveSet::Begin()` can return false when sub-curves have invalid state
  (e.g., `m_nCount < 2`). Callers MUST check the return value — `Apply()` will
  NULL-deref `m_pSamples` otherwise (CWE-476).
- **Timeout triage**: ALWAYS test timeout artifacts with **unpatched** upstream
  tools at `iccDEV/Build/Tools/` first. If upstream also hangs → report upstream.
  If upstream handles it → fuzzer alignment issue.
- **Timeout/OOM handling**: LibFuzzer's `-timeout=30 -rss_limit_mb=4096` handles
  CWE-400 patterns at the process level. No library patches needed.

## Multi-Profile Fuzzer Input Formats

| Fuzzer | Input Format | Tool |
|--------|-------------|------|
| icc_v5dspobs_fuzzer | `[4B BE size][display.icc][observer.icc]` | IccV5DspObsToV4Dsp |
| icc_link_fuzzer | `[50% profile1][50% profile2][4B trailing control]` | IccApplyToLink |
| icc_applyprofiles_fuzzer | `[75% profile][25% control (intent, interp, W×H, pixels)]` | IccApplyProfiles |
| icc_applynamedcmm_fuzzer | `[4B control header][ICC profile data]` | IccApplyNamedCmm |
| icc_specsep_fuzzer | `[1B nFiles][14B TIFF meta][TIFF+ICC data]` | IccSpecSepToTiff |

To unbundle crash files from multi-profile fuzzers:
```bash
.github/scripts/unbundle-fuzzer-input.sh <fuzzer> <crash_file> [tool_root]
# e.g.: .github/scripts/unbundle-fuzzer-input.sh v5dspobs crash-8f8b...
```

## Corpus Management

- Seed corpus: `cfl/corpus-<fuzzer_name>/` (committed to repo)
- Runtime corpus: `$RAMDISK/corpus-<fuzzer_name>/` (in-memory during fuzzing)
- Merge minimizes runtime corpus back to seed: `ramdisk-merge.sh`
- Sync copies minimized corpus to disk: `ramdisk-sync-to-disk.sh`

## Coverage Baseline

| Metric | Value |
|--------|-------|
| Functions | 63.23% |
| Lines | 61.15% |
| Branches | 58.47% |
| Instantiations | 62.99% |

## Fuzzer-to-Tool Fidelity (March 2026)

Measured using ASAN-instrumented upstream tools at `iccDEV/Build-ASAN/Tools/`:

```bash
# Build ASAN upstream tools (one-time)
cd iccDEV && mkdir -p Build-ASAN && cd Build-ASAN
cmake ../Build/Cmake -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON -DENABLE_COVERAGE=ON
make -j32
```

| Fuzzer | iccDEV Tool | Fidelity | Method |
|--------|-------------|----------|--------|
| icc_fromcube_fuzzer | IccFromCube | **100%** | LCOV function diff (only `main` differs) |
| icc_dump_fuzzer | IccDumpProfile | **>100%** | Fuzzer 27.65% lines vs tool 1.88% (custom icRealloc) |
| icc_deep_dump_fuzzer | IccDumpProfile | >100% | Full tag enumeration exceeds tool |
| icc_roundtrip_fuzzer | IccRoundTrip | ~95% | |
| icc_specsep_fuzzer | IccSpecSepToTiff | ~85% | |
| icc_applynamedcmm_fuzzer | IccApplyNamedCmm | ~75% | |
| icc_link_fuzzer | IccApplyToLink | ~65% | |

For per-fuzzer optimization details (input formats, coverage gaps, seed strategies,
dead code), see `.github/prompts/fuzzer-optimization.prompt.md`.

## Upstream Fix Coverage (54 PRs Audited, March 2026)

92.6% of 54 upstream security fix PRs are covered by CFL fuzzers. Targeted seed
profiles were added for the 4 weak areas:

| PR | Bug | Seed Profiles | Target Fuzzers |
|----|-----|---------------|----------------|
| #632 | SBO CIccPcsXform::pushXYZConvert | `seed-pcsxform-lab-*.icc` | apply, link, profile |
| #630 | SO CreateStruct recursion | `seed-nested-struct-deep.xml` | fromxml |
| #616 | HUAF CIccCmm::AddXform | `seed-ownership-*.icc` | link |
| #657 | UB CIccProfileSharedPtr | `seed-pcsxform-display-lab.icc` | apply, link, v5dspobs |

Seed profiles are in `cfl/corpus-<fuzzer>/seed-*.icc` and `seed-*.xml`.
These exercise: Lab/XYZ PCS conversion, deviceLink class, abstract profiles,
CMYK→RGB channel mismatch, nested tag structures, and ownership edge cases.

## Dictionary Files

Each fuzzer has a `.dict` file in `cfl/`. Key conventions:
- One dict per fuzzer: `cfl/icc_<name>_fuzzer.dict` (or `cfl/icc_<name>.dict`)
- TIFF fuzzer uses consolidated `cfl/icc_tiffdump_fuzzer.dict` (4215 entries)
  combining hand-curated TIFF 6.0 tags + ICC sigs + auto-extracted corpus tokens
- All entries must use `\xHH` hex escapes (NOT raw binary bytes)
- LibFuzzer rejects dicts with raw control characters in quoted strings

## Fuzzer Coverage Optimization Patterns

When a fuzzer plateaus on coverage, apply these techniques in order:

1. **2-phase architecture** — Phase 1: lightweight in-memory parse (cheap, broad).
   Phase 2: deep file-based analysis (expensive, targeted). Skip Phase 2 on
   malformed input to increase throughput.

2. **OOM guards** — Add size/offset validation before tag iteration:
   - Skip profiles where `profileSize < 1024`
   - Skip tags where `tSize > 256KB` or `tSize > profileSize`
   - MPE amplification guard: `tSize * 1024 > profileSize` catches small tags
     that expand exponentially (CWE-789)
   - Offset bounds: `tOffset > profileSize || tOffset + tSize > profileSize`

3. **Dictionary consolidation** — Merge hand-curated format-specific tokens with
   auto-extracted corpus tokens. Deduplicate. Fix hex escapes.

4. **Seed corpus diversity** — Add profiles exercising under-covered code paths:
   high-dimensional (6+ channels), MPE calculator elements, spectral PCS,
   named colors with large palettes, deeply nested tag structures.

## Adding a New Fuzzer

1. Create `cfl/icc_newfuzzer_fuzzer.cpp` — must include `extern "C" int LLVMFuzzerTestOneInput(...)`
2. Create dictionary: `cfl/icc_newfuzzer.dict`
3. Create seed corpus: `cfl/corpus-icc_newfuzzer_fuzzer/`
4. Add to `cfl/CMakeLists.txt`
5. Update fuzzer count (19→20) across documentation
6. Rebuild: `cd cfl && ./build.sh`
