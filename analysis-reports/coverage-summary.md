# ICC Profile Library — Code Coverage Report

**Date**: 2026-02-25  
**Fuzzers**: 12 of 18 instrumented fuzzers + iccDEV command-line tools  
**Inputs**: test-profiles/, extended-test-profiles/, crash artifacts, corpus samples  
**Patches Applied**: 001–029  

## Summary

| **TOTAL** | 31186 | 21340 | **31.57%** | 3148 | 2037 | **35.29%** | 46223 | 32518 | **29.65%** | 23314 | 16917 | **27.44%** |

| Metric | Value |
|--------|-------|
| Region Coverage | **31.57%** |
| Function Coverage | **35.29%** |
| Line Coverage | **29.65%** |
| Branch Coverage | **27.44%** |

## Per-File Coverage (IccProfLib)

| File | Regions | Region Cover | Functions | Func Cover | Lines | Line Cover | Branches | Branch Cover |
|------|---------|-------------|-----------|-----------|-------|-----------|----------|-------------|
| IccXformFactory.cpp | 31 | 51.61% | 6 | 66.67% | 66 | 54.55% | 30 | 60.00% |
| IccUtil.cpp | 1023 | 52.39% | 109 | 66.97% | 1817 | 51.02% | 1034 | 50.68% |
| IccTagProfSeqId.cpp | 130 | 0.00% | 21 | 0.00% | 235 | 0.00% | 80 | 0.00% |
| IccTagMPE.cpp | 555 | 66.67% | 47 | 82.98% | 964 | 58.09% | 456 | 53.29% |
| IccTagLut.cpp | 2110 | 56.64% | 130 | 66.92% | 3349 | 48.58% | 1628 | 46.13% |
| IccTagFactory.cpp | 143 | 50.35% | 14 | 57.14% | 231 | 53.68% | 162 | 66.05% |
| IccTagEmbedIcc.cpp | 144 | 0.00% | 11 | 0.00% | 252 | 0.00% | 102 | 0.00% |
| IccTagDict.cpp | 418 | 5.98% | 46 | 8.70% | 732 | 4.51% | 288 | 3.82% |
| IccTagComposite.cpp | 544 | 39.34% | 45 | 55.56% | 809 | 39.31% | 372 | 30.65% |
| IccTagBasic.cpp | 3901 | 23.25% | 348 | 34.20% | 5932 | 22.20% | 2834 | 16.30% |
| IccStructFactory.cpp | 57 | 38.60% | 10 | 60.00% | 101 | 41.58% | 44 | 38.64% |
| IccStructBasic.cpp | 156 | 19.23% | 30 | 23.33% | 268 | 20.90% | 102 | 13.73% |
| IccSparseMatrix.cpp | 262 | 0.00% | 16 | 0.00% | 429 | 0.00% | 210 | 0.00% |
| IccSolve.cpp | 21 | 42.86% | 8 | 37.50% | 34 | 38.24% | 10 | 30.00% |
| IccProfile.cpp | 1772 | 54.68% | 60 | 56.67% | 2388 | 49.83% | 1682 | 46.08% |
| IccPrmg.cpp | 92 | 89.13% | 7 | 100.00% | 140 | 87.14% | 66 | 77.27% |
| IccPcc.cpp | 143 | 11.19% | 18 | 5.56% | 236 | 12.71% | 94 | 9.57% |
| IccMpeSpectral.cpp | 797 | 23.34% | 42 | 30.95% | 1214 | 20.35% | 612 | 16.50% |
| IccMpeFactory.cpp | 63 | 63.49% | 8 | 75.00% | 146 | 62.33% | 86 | 75.58% |
| IccMpeCalc.cpp | 2616 | 69.11% | 155 | 80.00% | 3480 | 71.35% | 2254 | 64.11% |
| IccMpeBasic.cpp | 2477 | 44.61% | 167 | 61.08% | 3669 | 40.20% | 1870 | 35.29% |
| IccMpeACS.cpp | 107 | 0.00% | 15 | 0.00% | 157 | 0.00% | 74 | 0.00% |
| IccMatrixMath.cpp | 124 | 23.39% | 13 | 38.46% | 174 | 20.69% | 76 | 19.74% |
| IccMD5.cpp | 215 | 99.53% | 6 | 100.00% | 125 | 99.20% | 12 | 91.67% |
| IccIO.cpp | 402 | 51.00% | 56 | 60.71% | 554 | 51.26% | 250 | 39.60% |
| IccEval.cpp | 67 | 80.60% | 2 | 100.00% | 95 | 77.89% | 48 | 68.75% |
| IccEnvVar.cpp | 17 | 0.00% | 8 | 0.00% | 43 | 0.00% | 6 | 0.00% |
| IccEncoding.cpp | 198 | 60.61% | 10 | 80.00% | 410 | 51.95% | 142 | 40.85% |
| IccConvertUTF.cpp | 592 | 0.00% | 15 | 0.00% | 605 | 0.00% | 428 | 0.00% |
| IccCmm.cpp | 4534 | 26.44% | 270 | 36.30% | 6378 | 24.80% | 3568 | 19.25% |
| IccCAM.cpp | 114 | 50.00% | 29 | 89.66% | 353 | 72.52% | 64 | 31.25% |
| IccArrayFactory.cpp | 52 | 42.31% | 10 | 60.00% | 91 | 46.15% | 34 | 35.29% |
| IccArrayBasic.cpp | 204 | 4.90% | 23 | 13.04% | 373 | 5.63% | 150 | 2.67% |
| IccApplyBPC.cpp | 210 | 0.00% | 11 | 0.00% | 339 | 0.00% | 176 | 0.00% |

## Key Findings

### High Coverage (>60% line coverage)
Files with strong fuzzer coverage indicate well-exercised code paths.

### Low Coverage (<20% line coverage)
Files with low coverage represent areas where fuzzers are not reaching — potential targets for new fuzzer harnesses or seed corpus improvements.

### Zero Coverage
Files with 0% coverage are either dead code, rarely-used features, or require specific input formats not yet covered by the fuzzer corpus.

## Coverage Gaps — Priority Targets

1. **IccConvertUTF.cpp** (0%) — UTF conversion routines, may need string-focused fuzzing
2. **IccSparseMatrix.cpp** (0%) — Sparse matrix operations, needs matrix-element profiles
3. **IccTagProfSeqId.cpp** (0%) — Profile sequence ID tags, needs specific tag types
4. **IccMpeACS.cpp** (0%) — ACS (Abstract Color Space) elements
5. **IccTagEmbedIcc.cpp** (0%) — Embedded ICC profiles, needs nested profile inputs
6. **IccXML/** (mostly 0%) — XML serialization paths need XML input corpus

## Notes

- Coverage was generated from a single-pass run of test profiles and crash artifacts
- Extended fuzzing sessions would show higher coverage as the corpus grows
- The XML library paths show near-zero coverage because the XML fuzzers need XML input, not ICC binary input
- Leak reports (LeakSanitizer) are suppressed with `-detect_leaks=0` during coverage runs
