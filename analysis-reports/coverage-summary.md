# ICC Profile Library — Code Coverage Report

**Date**: 2026-02-25  
**Fuzzers**: All 18 instrumented fuzzers (full ramdisk corpus)  
**Corpus**: ~31,500 evolved inputs from `/tmp/fuzz-ramdisk/corpus-*`  
**Patches Applied**: 001–029  

## Summary

| Metric | Value |
|--------|-------|
| **Region Coverage** | **48.98%** |
| **Function Coverage** | **50.44%** |
| **Line Coverage** | **45.52%** |
| **Branch Coverage** | **43.17%** |
| **Total Lines** | 46,530 |
| **Lines Covered** | 21,179 |
| **Total Branches** | 23,444 |
| **Branches Covered** | 10,121 |

## Per-File Coverage (IccProfLib — sorted by line coverage)

| File | Lines | Line Cover | Branches | Branch Cover | Functions | Func Cover |
|------|-------|-----------|----------|-------------|-----------|-----------|
| IccMD5.cpp | 125 | 99.20% | 12 | 91.67% | — | 100.00% |
| IccTagFactory.cpp | 231 | 90.04% | 162 | 93.21% | — | 85.71% |
| IccPrmg.cpp | 140 | 87.14% | 66 | 78.79% | — | 100.00% |
| IccEval.cpp | 95 | 86.32% | 48 | 81.25% | — | 100.00% |
| IccMpeCalc.cpp | 3480 | 85.11% | 2254 | 80.30% | — | 90.97% |
| IccCAM.cpp | 353 | 73.37% | 64 | 32.81% | — | 89.66% |
| IccStructFactory.cpp | 101 | 66.34% | 44 | 68.18% | — | 80.00% |
| IccProfile.cpp | 2388 | 66.12% | 1682 | 61.41% | — | 65.00% |
| IccTagMPE.cpp | 964 | 65.77% | 456 | 59.43% | — | 82.98% |
| IccUtil.cpp | 1817 | 64.72% | 1034 | 62.57% | — | 72.48% |
| IccSolve.cpp | 34 | 64.71% | 10 | 50.00% | — | 62.50% |
| IccMpeFactory.cpp | 146 | 62.33% | 86 | 75.58% | — | 75.00% |
| IccTagLut.cpp | 3349 | 57.66% | 1628 | 57.80% | — | 74.62% |
| IccArrayFactory.cpp | 91 | 54.95% | 34 | 52.94% | — | 60.00% |
| IccXformFactory.cpp | 66 | 54.55% | 30 | 60.00% | — | 66.67% |
| IccIO.cpp | 554 | 53.79% | 250 | 43.60% | — | 62.50% |
| IccEncoding.cpp | 410 | 51.95% | 142 | 41.55% | — | 80.00% |
| IccTagBasic.cpp | 5932 | 50.17% | 2834 | 39.59% | — | 62.93% |
| IccTagDict.cpp | 732 | 49.59% | 288 | 45.83% | — | 43.48% |
| IccTagComposite.cpp | 809 | 47.47% | 372 | 37.37% | — | 66.67% |
| IccMpeBasic.cpp | 3669 | 45.68% | 1870 | 40.96% | — | 65.27% |
| IccStructBasic.cpp | 268 | 32.84% | 102 | 19.61% | — | 43.33% |
| IccCmm.cpp | 6378 | 27.67% | 3568 | 21.80% | — | 37.78% |
| IccTagProfSeqId.cpp | 235 | 27.23% | 80 | 20.00% | — | 28.57% |
| IccArrayBasic.cpp | 373 | 23.59% | 150 | 15.33% | — | 30.43% |
| IccMpeSpectral.cpp | 1214 | 22.16% | 612 | 17.16% | — | 35.71% |
| IccMatrixMath.cpp | 174 | 20.69% | 76 | 19.74% | — | 38.46% |
| IccConvertUTF.cpp | 605 | 16.53% | 428 | 18.69% | — | 26.67% |
| IccSparseMatrix.cpp | 429 | 12.82% | 210 | 6.67% | — | 31.25% |
| IccPcc.cpp | 236 | 12.71% | 94 | 9.57% | — | 5.56% |
| IccTagEmbedIcc.cpp | 252 | 0.00% | 102 | 0.00% | — | 0.00% |
| IccMpeACS.cpp | 157 | 0.00% | 74 | 0.00% | — | 0.00% |
| IccEnvVar.cpp | 43 | 0.00% | 6 | 0.00% | — | 0.00% |
| IccApplyBPC.cpp | 339 | 0.00% | 176 | 0.00% | — | 0.00% |

## Per-File Coverage (IccXML)

| File | Lines | Line Cover | Branches | Branch Cover |
|------|-------|-----------|----------|-------------|
| IccIoXml.cpp | 17 | 0.00% | 4 | 0.00% |
| IccMpeXml.cpp | 2793 | 28.64% | 1196 | 33.53% |
| IccMpeXmlFactory.cpp | 43 | 6.98% | 36 | 0.00% |
| IccProfileXml.cpp | 673 | 55.72% | 396 | 61.62% |
| IccTagXml.cpp | 4048 | 26.06% | 1742 | 28.24% |
| IccTagXmlFactory.cpp | 117 | 54.70% | 104 | 73.08% |
| IccUtilXml.cpp | 1067 | 36.27% | 626 | 37.06% |

## Coverage Improvement vs Single-Pass

| Metric | Test Profiles Only | Full Corpus (ramdisk) | Δ |
|--------|-------------------|----------------------|---|
| Line Coverage | 29.65% | **45.52%** | +15.87pp |
| Branch Coverage | 27.44% | **43.17%** | +15.73pp |
| Function Coverage | 35.29% | **50.44%** | +15.15pp |

## Top Covered Files (>70% line coverage)

| File | Line Coverage | Key Paths Exercised |
|------|-------------|-------------------|
| IccMD5.cpp | 99.20% | Hash computation (profile ID) |
| IccTagFactory.cpp | 90.04% | Tag creation/dispatch |
| IccPrmg.cpp | 87.14% | Profile Reference Medium Gamut |
| IccEval.cpp | 86.32% | Profile evaluation |
| IccMpeCalc.cpp | 85.11% | Calculator element (primary attack surface) |
| IccSignatureUtils.h | 80.00% | Signature string conversion |

## Coverage Gaps — Priority Targets

| File | Line Cover | Gap Analysis |
|------|-----------|-------------|
| IccApplyBPC.cpp | 0.00% | Black Point Compensation — needs BPC-enabled profiles |
| IccMpeACS.cpp | 0.00% | Abstract Color Space elements — rare in real profiles |
| IccTagEmbedIcc.cpp | 0.00% | Embedded ICC profiles — needs nested profile inputs |
| IccEnvVar.cpp | 0.00% | Environment variables — needs env-var-aware profiles |
| IccPcc.cpp | 12.71% | Profile Connection Conditions — needs PCC-specific profiles |
| IccConvertUTF.cpp | 16.53% | UTF conversion — partially reached via XML paths |
| IccSparseMatrix.cpp | 12.82% | Sparse matrix ops — needs sparse matrix element profiles |

## Notes

- Coverage generated from all 18 fuzzer corpora evolved during active fuzzing sessions
- Exit code 1 on some fuzzers is due to pre-existing memory leaks (LeakSanitizer), not crashes
- XML library coverage improved significantly (0% → 28-55%) with fromxml/toxml corpus inputs
- IccMpeCalc.cpp (calculator element) reached 85% — this is the primary attack surface where most crashes have been found
- IccTagBasic.cpp jumped from 22% to 50% — patches 027/028 fixed bugs in previously-uncovered paths
