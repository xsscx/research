# ICC Profile Library — Code Coverage Report

**Date**: 2026-03-05  
**Fuzzers**: All 19 instrumented fuzzers (extended corpus on 1TB SSD)  
**Corpus**: 213,909 inputs across 19 fuzzers (active fuzzing, pre-merge)  
**Patches Applied**: 001–067 (10 no-ops)  
**Profdata**: `/mnt/g/fuzz-ssd/merged.profdata` (43 profraw files merged)  

## Summary

| Metric | Value | Previous (Feb 25) | Delta |
|--------|-------|-------------------|-------|
| **Region Coverage** | **61.06%** | 45.65% | +15.41 |
| **Function Coverage** | **59.81%** | 47.60% | +12.21 |
| **Line Coverage** | **59.01%** | 42.15% | +16.86 |
| **Branch Coverage** | **56.76%** | 39.48% | +17.28 |
| **Total Lines** | 49,972 | 46,552 | +3,420 |
| **Lines Covered** | 29,487 | 19,623 | +9,864 |
| **Total Branches** | 25,418 | 23,474 | +1,944 |
| **Branches Covered** | 14,427 | 9,267 | +5,160 |

## Per-File Coverage (IccProfLib — top 20 by line coverage)

| File | Line Cover | Functions | Func Cover | Branches | Branch Cover |
|------|-----------|-----------|------------|----------|-------------|
| IccMD5.cpp | 99.20% | 6 | 100.00% | 12 | 91.67% |
| IccSignatureUtils.h | 94.74% | 6 | 83.33% | 110 | 90.91% |
| IccTagFactory.cpp | 92.21% | 14 | 85.71% | 162 | 96.30% |
| IccCAM.cpp | 89.52% | 29 | 93.10% | 64 | 62.50% |
| IccMpeCalc.cpp | 87.37% | 155 | 91.61% | 2,262 | 83.91% |
| IccMpeFactory.cpp | 84.93% | 8 | 75.00% | 86 | 90.70% |
| IccArrayFactory.cpp | 82.42% | 10 | 80.00% | 34 | 82.35% |
| IccStructFactory.cpp | 76.24% | 10 | 80.00% | 44 | 79.55% |
| IccTagMPE.cpp | 78.11% | 47 | 82.98% | 456 | 71.71% |
| IccTagXmlFactory.cpp | 76.92% | 5 | 100.00% | 104 | 85.58% |
| IccUtil.cpp | 76.94% | 109 | 77.98% | 1,034 | 76.89% |
| IccProfile.cpp | 75.25% | 60 | 63.33% | 1,682 | 78.24% |
| IccTagLut.cpp | 67.87% | 130 | 74.62% | 1,678 | 66.98% |
| IccSolve.cpp | 70.59% | 8 | 62.50% | 10 | 80.00% |
| IccIO.cpp | 67.38% | 56 | 78.57% | 254 | 57.87% |
| IccTagDict.cpp | 62.26% | 46 | 39.13% | 288 | 62.50% |
| IccTagComposite.cpp | 63.83% | 47 | 70.21% | 376 | 58.78% |
| IccEncoding.cpp | 58.78% | 10 | 80.00% | 142 | 48.59% |
| IccTagBasic.cpp | 60.81% | 348 | 70.40% | 2,838 | 53.45% |
| IccXformFactory.cpp | 71.21% | 6 | 66.67% | 30 | 70.00% |

## Per-File Coverage (IccXML)

| File | Lines | Line Cover | Branches | Branch Cover |
|------|-------|-----------|----------|-------------|
| IccProfileXml.cpp | 683 | 88.29% | 400 | 84.25% |
| IccUtilXml.cpp | 1,067 | 65.04% | 626 | 57.19% |
| IccMpeXml.cpp | 2,793 | 55.39% | 1,196 | 56.52% |
| IccTagXml.cpp | 4,088 | 46.55% | 1,780 | 43.09% |

## Per-File Coverage (Tools)

| File | Lines | Line Cover | Branches | Branch Cover |
|------|-------|-----------|----------|-------------|
| TiffImg.cpp | 303 | 61.06% | 136 | 47.06% |

## Corpus Statistics (Active — Pre-Merge)

| Fuzzer | Corpus Size |
|--------|------------|
| icc_apply_fuzzer | 11,845 |
| icc_applynamedcmm_fuzzer | 16,700 |
| icc_applyprofiles_fuzzer | 15,554 |
| icc_calculator_fuzzer | 8,695 |
| icc_deep_dump_fuzzer | 10,763 |
| icc_dump_fuzzer | 7,576 |
| icc_fromcube_fuzzer | 3,627 |
| icc_fromxml_fuzzer | 13,481 |
| icc_io_fuzzer | 4,972 |
| icc_link_fuzzer | 7,111 |
| icc_multitag_fuzzer | 2,264 |
| icc_profile_fuzzer | 7,075 |
| icc_roundtrip_fuzzer | 5,032 |
| icc_specsep_fuzzer | 18,939 |
| icc_spectral_b_fuzzer | 18,580 |
| icc_spectral_fuzzer | 3,697 |
| icc_tiffdump_fuzzer | 36,629 |
| icc_toxml_fuzzer | 13,649 |
| icc_v5dspobs_fuzzer | 7,720 |
| **Total** | **213,909** |

## Coverage Improvement History

| Metric | Feb 25 (18 fuzzers, 931 merged) | Mar 5 (19 fuzzers, 213K active) | Delta |
|--------|--------------------------------|--------------------------------|-------|
| Line Coverage | 42.15% | **59.01%** | +16.86 |
| Branch Coverage | 39.48% | **56.76%** | +17.28 |
| Function Coverage | 47.60% | **59.81%** | +12.21 |
| Region Coverage | 45.65% | **61.06%** | +15.41 |

Key improvements driven by:
- Extended fuzzing on 1TB SSD (vs 8GB ramdisk)
- 19 fuzzers (added `icc_spectral_b_fuzzer`)
- 67 patches (vs 32) enabling deeper exploration without OOM/crash
- 52 targeted CMM seeds (`seeds-link-pairs/`, `seeds-applyprofiles/`, `seeds-applynamedcmm/`)
- Coverage-driven dictionary additions (TIFF, spectral, cube, XML tokens)

## Top Covered Files (>70% line coverage)

| File | Line Coverage | Key Paths Exercised |
|------|-------------|-------------------|
| IccMD5.cpp | 99.20% | Hash computation (profile ID) |
| IccSignatureUtils.h | 94.74% | Signature string conversion + IsSpaceSpectralPCS |
| IccTagFactory.cpp | 92.21% | Tag creation/dispatch (50+ tag types) |
| IccCAM.cpp | 89.52% | Color Appearance Model transforms |
| IccProfileXml.cpp | 88.29% | XML profile serialization/deserialization |
| IccMpeCalc.cpp | 87.37% | Calculator element (primary attack surface) |
| IccMpeFactory.cpp | 84.93% | MPE element factory dispatch |
| IccArrayFactory.cpp | 82.42% | Array type factory |
| IccTagMPE.cpp | 78.11% | Multi-Processing Element tags |
| IccUtil.cpp | 76.94% | Core utility functions |
| IccStructFactory.cpp | 76.24% | Struct type factory |
| IccProfile.cpp | 75.25% | Profile read/write/validate core |
| IccXformFactory.cpp | 71.21% | Transform factory dispatch |
| IccSolve.cpp | 70.59% | Matrix solver / least squares |

## Coverage Gaps — Priority Targets

| File | Line Cover | Missed Lines | Gap Analysis | Target Fuzzers |
|------|-----------|-------------|-------------|----------------|
| IccCmm.cpp | 36.62% | 4,063 | CMM pipeline — needs profile PAIRS via link/apply fuzzers | link, apply, applyprofiles |
| IccTagXml.cpp | 46.55% | 2,185 | XML tag parsing — 50+ tag type paths | toxml, fromxml |
| IccMpeSpectral.cpp | 31.80% | 828 | Spectral processing — needs v5 spectral profiles | spectral, spectral_b, v5dspobs |
| IccPcc.cpp | 16.53% | 197 | Profile Connection Conditions — needs differing viewing conditions | spectral, v5dspobs |
| IccMatrixMath.cpp | 39.89% | 110 | Matrix math — needs matrix-TRC profile pairs | link, apply |
| IccSparseMatrix.cpp | 26.81% | 314 | Sparse matrix ops — needs sparse matrix element profiles | deep_dump, profile |
| IccTagEmbedIcc.cpp | 30.95% | 174 | Embedded ICC profiles — needs nested profile inputs | deep_dump, profile |
| IccApplyBPC.cpp | 30.09% | 237 | Black Point Compensation — needs BPC-enabled profile pairs | link, applyprofiles |
| IccEnvVar.cpp | 32.56% | 29 | Environment variables — needs env-var-aware profiles | profile |
| IccCmmSearch.cpp | 0.00% | 275 | CMM search API — no fuzzer exercises this code | NONE |
| IccEval.cpp | 0.00% | 95 | Profile evaluation — needs new paired-evaluation fuzzer | NONE |
| IccPrmg.cpp | 0.00% | 140 | Profile Reference Medium Gamut — needs PRMG profiles | NONE |

## Findings Summary

| Category | Count |
|----------|-------|
| **Security patches** | 67 (patches 001–067, 10 no-ops) |
| **Corpus inputs** | 213,909 (active, pre-merge) |
| **Fuzzers** | 19 |
| **iccanalyzer-lite heuristics** | 102 (H1–H102, v3.3.0) |
| **CodeQL alerts (our code)** | 0 |
| **CodeQL alerts (iccDEV upstream)** | 4 |

## Notes

- Coverage generated from extended fuzzing on 1TB SSD at `/mnt/g/fuzz-ssd/`
- 43 profraw files merged with `llvm-profdata-18 merge -sparse`
- IccMpeCalc.cpp (calculator element) at 87.37% — primary attack surface, 11+ patches applied
- IccCmm.cpp at 36.62% — largest gap (4,063 missed lines), requires profile PAIRS for CMM pipeline
- 52 targeted CMM seeds created in `cfl/seeds-link-pairs/`, `seeds-applyprofiles/`, `seeds-applynamedcmm/`
- `ramdisk-seed.sh` Source 3 auto-seeds CMM fuzzers from these directories
- H95-H102 heuristics target coverage-gap APIs: IccSparseMatrix, IccTagEmbedIcc, IccTagProfSeqId, IccMpeSpectral
- UBSAN: 18 unsigned-to-char fixes applied in iccanalyzer-lite; 27 remaining hits are in iccDEV upstream
- SignatureToFourCC() now trims trailing spaces from 4-byte ICC signatures for clean display
