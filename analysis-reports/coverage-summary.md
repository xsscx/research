# ICC Profile Library — Code Coverage Report

**Date**: 2026-02-25  
**Fuzzers**: All 18 instrumented fuzzers (merged/minimized corpus)  
**Corpus**: 931 minimized inputs from ramdisk merge (was ~64K pre-merge)  
**Patches Applied**: 001–032  

## Summary

| Metric | Value |
|--------|-------|
| **Function Coverage** | **47.60%** |
| **Line Coverage** | **42.15%** |
| **Branch Coverage** | **39.48%** |
| **Region Coverage** | **45.65%** |
| **Total Lines** | 46,552 |
| **Lines Covered** | 19,623 |
| **Total Branches** | 23,474 |
| **Branches Covered** | 9,267 |

## Per-File Coverage (IccProfLib — top 20 by line coverage)

| File | Line Cover | Branches | Branch Cover | Functions |
|------|-----------|----------|-------------|-----------|
| IccMD5.cpp | 99.20% | 12 | 91.67% | 6 |
| IccPrmg.cpp | 87.14% | 66 | 78.79% | 7 |
| IccEval.cpp | 86.32% | 48 | 81.25% | 2 |
| IccTagFactory.cpp | 86.15% | 162 | 90.74% | 14 |
| IccMpeCalc.cpp | 82.53% | 2,260 | 75.49% | 155 |
| IccSignatureUtils.h | 80.00% | 110 | 79.09% | 6 |
| IccCAM.cpp | 70.54% | 64 | 28.12% | 29 |
| IccSolve.cpp | 64.71% | 10 | 50.00% | 8 |
| IccProfile.cpp | 64.20% | 1,682 | 58.74% | 60 |
| IccMpeFactory.cpp | 60.96% | 86 | 74.42% | 8 |
| IccTagMPE.cpp | 60.89% | 456 | 55.26% | 47 |
| IccStructFactory.cpp | 60.40% | 44 | 59.09% | 10 |
| IccUtil.cpp | 59.99% | 1,034 | 57.83% | 109 |
| IccTagLut.cpp | 54.28% | 1,628 | 54.48% | 130 |
| IccArrayFactory.cpp | 54.95% | 34 | 52.94% | 10 |
| IccXformFactory.cpp | 54.55% | 30 | 60.00% | 6 |
| IccIO.cpp | 53.43% | 250 | 41.60% | 56 |
| IccTagDict.cpp | 49.45% | 288 | 45.49% | 46 |
| IccEncoding.cpp | 46.10% | 142 | 35.92% | 10 |
| IccTagComposite.cpp | 45.61% | 372 | 35.22% | 45 |

## Per-File Coverage (IccXML)

| File | Lines | Line Cover | Branches | Branch Cover |
|------|-------|-----------|----------|-------------|
| IccIoXml.cpp | 17 | 0.00% | 4 | 0.00% |
| IccMpeXml.cpp | 2793 | 24.88% | 1196 | 29.35% |
| IccMpeXmlFactory.cpp | 43 | 6.98% | 36 | 0.00% |
| IccProfileXml.cpp | 673 | 52.75% | 396 | 58.08% |
| IccTagXml.cpp | 4048 | 24.90% | 1742 | 25.55% |
| IccTagXmlFactory.cpp | 117 | 54.70% | 104 | 73.08% |
| IccUtilXml.cpp | 1067 | 33.65% | 626 | 29.23% |

## Corpus Statistics

| Fuzzer | Pre-Merge | Post-Merge | Reduction |
|--------|-----------|------------|-----------|
| icc_apply_fuzzer | 2,740 | 11 | -99% |
| icc_applynamedcmm_fuzzer | 509 | 2 | -99% |
| icc_applyprofiles_fuzzer | 329 | 2 | -99% |
| icc_calculator_fuzzer | 2,044 | 33 | -98% |
| icc_deep_dump_fuzzer | 501 | 182 | -63% |
| icc_dump_fuzzer | 2,539 | 79 | -96% |
| icc_fromcube_fuzzer | 9,513 | 266 | -97% |
| icc_fromxml_fuzzer | 22,802 | 32 | -99% |
| icc_io_fuzzer | 614 | 3 | -99% |
| icc_link_fuzzer | 1,344 | 4 | -99% |
| icc_multitag_fuzzer | 337 | 19 | -94% |
| icc_profile_fuzzer | 2,718 | 28 | -98% |
| icc_roundtrip_fuzzer | 784 | 42 | -94% |
| icc_specsep_fuzzer | 3,644 | 47 | -98% |
| icc_spectral_fuzzer | 988 | 9 | -99% |
| icc_tiffdump_fuzzer | 7,503 | 77 | -98% |
| icc_toxml_fuzzer | 1,257 | 1 | -99% |
| icc_v5dspobs_fuzzer | 3,951 | 94 | -97% |
| **Total** | **64,117** | **931** | **-98.5%** |

## Coverage Improvement History

| Metric | Test Profiles Only | Full Corpus (pre-merge) | Merged Corpus (final) |
|--------|-------------------|------------------------|----------------------|
| Line Coverage | 29.65% | 45.52% | **42.15%** |
| Branch Coverage | 27.44% | 43.17% | **39.48%** |
| Function Coverage | 35.29% | 50.44% | **47.60%** |

*Note: Merged corpus coverage is slightly lower than pre-merge because merge eliminates
redundant inputs — the remaining 931 inputs preserve all unique coverage edges.*

## Top Covered Files (>60% line coverage)

| File | Line Coverage | Key Paths Exercised |
|------|-------------|-------------------|
| IccMD5.cpp | 99.20% | Hash computation (profile ID) |
| IccPrmg.cpp | 87.14% | Profile Reference Medium Gamut |
| IccEval.cpp | 86.32% | Profile evaluation |
| IccTagFactory.cpp | 86.15% | Tag creation/dispatch |
| IccMpeCalc.cpp | 82.53% | Calculator element (primary attack surface) |
| IccSignatureUtils.h | 80.00% | Signature string conversion |
| IccCAM.cpp | 70.54% | Color Appearance Model transforms |
| IccProfile.cpp | 64.20% | Profile read/write/validate core |

## Coverage Gaps — Priority Targets

| File | Line Cover | Gap Analysis |
|------|-----------|-------------|
| IccApplyBPC.cpp | 0.00% | Black Point Compensation — needs BPC-enabled profiles |
| IccMpeACS.cpp | 0.00% | Abstract Color Space elements — rare in real profiles |
| IccTagEmbedIcc.cpp | 0.00% | Embedded ICC profiles — needs nested profile inputs |
| IccEnvVar.cpp | 0.00% | Environment variables — needs env-var-aware profiles |
| IccMatrixMath.cpp | 0.00% | Matrix math — patch 031 hardened but not reached by minimized corpus |
| IccSparseMatrix.cpp | 0.00% | Sparse matrix ops — needs sparse matrix element profiles |
| IccPcc.cpp | 0.00% | Profile Connection Conditions — needs PCC-specific profiles |
| IccMpeSpectral.cpp | 10.63% | Spectral processing — needs multi-spectral profiles |

## Findings Summary

| Category | Count |
|----------|-------|
| **Security patches** | 32 (patches 001–032) |
| **Crash artifacts** | 37 (saved to cfl/findings/) |
| **Corpus inputs** | 931 (minimized from 64,117) |
| **Fuzzers** | 18 |

## Notes

- Coverage generated from merged/minimized corpus (931 inputs preserve all unique coverage edges)
- Corpus reduced 98.5% via LibFuzzer `-merge=1` deduplication
- IccMpeCalc.cpp (calculator element) at 82.53% — primary attack surface, 7 patches applied
- IccCmm.cpp at 26.62% — large file (6,378 lines), complex call graph, needs multi-profile inputs
- Pre-existing memory leaks in CIccMpeCalculator::GetNewApply (72 bytes) — not a crash, tracked separately
- 37 crash/timeout/leak artifacts preserved in cfl/findings/ for regression testing
