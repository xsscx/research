---
applyTo: "cfl/**"
---

# CFL (Crash-Free LibFuzzer) — Path-Specific Instructions

## What This Is

19 LibFuzzer harnesses (4,537 LOC, C/C++) targeting the iccDEV ICC profile library.
Each fuzzer has a custom-built dictionary, seed corpus, and OOM-protection patches
applied at build time.

## Build

```bash
cd cfl && ./build.sh   # clones iccDEV if missing, applies patches, builds 19 fuzzers
```

- **First run**: clones `github.com/InternationalColorConsortium/DemoIccMAX.git` into `cfl/iccDEV/`
- **Subsequent runs**: reuses existing `cfl/iccDEV/` checkout — does NOT auto-update
- Applies 57 active patches (001-071, with 14 NO-OP gaps) from `cfl/patches/`
- Compiler: clang++ 18 with `-fsanitize=address,undefined,fuzzer`
- Binaries: `cfl/bin/icc_*_fuzzer` (19 total)

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

Current upstream: commit **b5ade94** (2026-03-06)

## The 19 Fuzzers

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
| 13 | icc_multi_fuzzer | Multi-profile load |
| 14 | icc_spectral_fuzzer | Spectral PCS |
| 15 | icc_specsep_fuzzer | Spectral separation |
| 16 | icc_v5_fuzzer | v5 profile paths |
| 17 | icc_tiff_fuzzer | TIFF tag reading |
| 18 | icc_rt_fuzzer | Round-trip transforms |
| 19 | icc_spectraltiff_fuzzer | Spectral TIFF |

## Patch Conventions

- File: `cfl/patches/NNN-descriptive-name.patch`
- Numbering: zero-padded 3-digit, sequential (next: **073**)
- Format: unified diff against `cfl/iccDEV/`
- 14 known NO-OP patches: 023, 027-029, 032, 039-041, 045, 055-056, 058, 062, 066
  (upstreamed or made irrelevant by code changes)
- Patches MUST be idempotent — `build.sh` applies them with `patch -p1 --forward`
- Latest: 072 (v5dspobs Begin() return check — CWE-476 NULL deref)

## Fuzzing — Ramdisk Workflow

```bash
# Mount ramdisk, seed corpus, run all 19 fuzzers
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

| Fuzzer | iccDEV Tool | Fidelity |
|--------|-------------|----------|
| icc_link_fuzzer | IccApplyToLink | ~65% |
| icc_applynamedcmm_fuzzer | IccApplyNamedCmm | ~75% |
| icc_specsep_fuzzer | IccSpecSepToTiff | ~85% |
| icc_roundtrip_fuzzer | IccRoundTrip | ~95% |
| icc_deep_dump_fuzzer | IccDumpProfile | >100% |

For per-fuzzer optimization details (input formats, coverage gaps, seed strategies,
dead code), see `.github/prompts/fuzzer-optimization.prompt.md`.

## Adding a New Fuzzer

1. Create `cfl/icc_newfuzzer_fuzzer.cpp` — must include `extern "C" int LLVMFuzzerTestOneInput(...)`
2. Create dictionary: `cfl/icc_newfuzzer.dict`
3. Create seed corpus: `cfl/corpus-icc_newfuzzer_fuzzer/`
4. Add to `cfl/CMakeLists.txt`
5. Update fuzzer count (19→20) across documentation
6. Rebuild: `cd cfl && ./build.sh`
