---
applyTo: "cfl/**"
---

# CFL (Crash-Free LibFuzzer) — Path-Specific Instructions

## What This Is

18 LibFuzzer harnesses (4,537 LOC, C/C++) targeting the iccDEV ICC profile library.
Each fuzzer has a custom-built dictionary, seed corpus, and OOM-protection patches
applied at build time.

## Build

```bash
cd cfl && ./build.sh   # clones iccDEV if missing, applies patches, builds 18 fuzzers
```

- **First run**: clones `github.com/InternationalColorConsortium/iccDEV.git` into `cfl/iccDEV/`
- **Subsequent runs**: reuses existing `cfl/iccDEV/` checkout — does NOT auto-update
- Applies 61 patches from `cfl/patches/` (all active, 0 NO-OPs remaining)
- Compiler: clang++ 18 with `-fsanitize=address,undefined,fuzzer`
- Binaries: `cfl/bin/icc_*_fuzzer` (18 total)

## Upstream Sync

When upstream iccDEV changes:
```bash
cd cfl/iccDEV && git fetch origin && git reset --hard origin/master
cd .. && ./build.sh   # re-applies all patches and rebuilds
```

Then run patch reconciliation to identify NO-OPs:
```bash
# Check each patch against updated source
for p in patches/*.patch; do
  patch --dry-run -p1 -d iccDEV < "$p" 2>&1 | grep -q "FAILED\|reversed" && echo "NO-OP: $p"
done
```

Current upstream: commit **1ffa7a8** / v2.3.1.5 (2026-03-08)

## The 18 Fuzzers

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

## Patch Conventions

- File: `cfl/patches/NNN-descriptive-name.patch`
- Numbering: zero-padded 3-digit, sequential (next: **083**)
- Format: unified diff against `cfl/iccDEV/`
- 61 patch files total (21 patch numbers deleted — upstreamed or superseded)
- Deleted NO-OPs: 006, 023, 027-029, 032, 039-041, 043, 045, 047, 048, 055-056, 058, 062, 064, 066, 070, 072
  (upstreamed via PRs #648-#657, or superseded by later patches)
- NO-OP patches still in directory: **none** — all remaining patches are active
- Patches MUST be idempotent — `build.sh` applies them with `patch -p1 --forward`
- build.sh now distinguishes "already applied" from "FAILED" — no silent failures
- Latest active: CFL-082 (CTiffImg strip buffer bounds check)
- CFL-077 through CFL-081 (CWE-400 upstream patterns) — patch files exist and ARE applied by build.sh:
  - CFL-077: ResponseCurveStruct nMeasurements cap (100K per channel)
  - CFL-078: NamedColor2 Describe() iteration cap (10K entries)
  - CFL-079: ApplySequence() runtime depth limit (16) — NOW WORKING (regenerated)
  - CFL-080: XYZ Describe() output cap (1MB) — NOW WORKING (regenerated)
  - CFL-081: DescribeSequence() recursion depth limit (32) — NOW WORKING (regenerated)
  - CFL-080: XYZ/Chromaticity/ColorantTable Describe() output cap (1MB)
  - CFL-081: DescribeSequence() recursion depth limit (32)
- **iccanalyzer-lite does NOT use CFL patches** — it links unpatched upstream iccDEV
  and handles all user-controllable inputs via its own defensive programming

### CFL-082: CTiffImg Strip Buffer Bounds Check

- **File**: `Tools/CmdLine/IccApplyProfiles/TiffImg.cpp`
- **Bug**: `Open()` allocates `m_pStripBuf` sized by `TIFFStripSize()` (TIFF
  StripByteCounts), but `ReadLine()` accesses `nRowOffset * m_nBytesPerLine`
  without bounds check. Malformed TIFF with small StripByteCounts → heap-BOF.
- **Fix**: After malloc in `Open()`, validate `m_nStripSize >= m_nRowsPerStrip * m_nBytesPerLine`
  (contig) or `m_nStripSize >= m_nRowsPerStrip * m_nBytesPerStripLine` (separate).
- **CWE**: CWE-122 (Heap Buffer Overflow), CWE-125 (Out-of-bounds Read)
- **Crash**: `crash-3c9fd44b5e25285f5fc22b0941447dd86f55d9c5`
- **Repro**: `LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles crash-3c9fd44b5e25285f5fc22b0941447dd86f55d9c5 /tmp/out.tif 0 0 0 0 1 test-profiles/Rec2020rgbSpectral.icc 1`
- **Affected tools**: iccApplyProfiles, iccSpecSepToTiff, icc_tiffdump_fuzzer, icc_specsep_fuzzer
- **iccanalyzer-lite counterpart**: H139 (TIFF Strip Geometry Validation) detects the same CFL-082 bug pattern via defensive heuristic analysis without patching the library.

## Fuzzing — Ramdisk Workflow

```bash
# Mount ramdisk, seed corpus, run all 18 fuzzers
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
  NULL-deref `m_pSamples` otherwise (CWE-476). Patched in CFL-072.
- **Timeout triage**: ALWAYS test timeout artifacts with **unpatched** upstream
  tools at `iccDEV/Build/Tools/` first. If upstream also hangs → upstream bug.
  If upstream handles it → fuzzer alignment issue. NEVER use `cfl/iccDEV/` for this.
- **CWE-400 timeout fixes**:
  - CFL-074: `CheckUnderflowOverflow()` — added 100K ops budget + depth 16 (was 100)
  - CFL-075: `EvaluateProfile()` — capped nGran^ndim iterations to 100K

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
