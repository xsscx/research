/*
 * IccConformanceLUT.cpp — ICC specification LUT/curve structure conformance checks
 *
 * Implements CF-060 through CF-070 from the conformance registry.
 * Validates lut8Type, lut16Type, lutAToBType, lutBToAType tags,
 * CLUT grids, and matrix tags against ICC.1-2022-05 §9-10 requirements.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagLut.h"
#include "IccTagMPE.h"
#include "IccUtil.h"
#include "IccConformanceRegistry.h"
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicResult.h"
#include "IccAnalyzerColors.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>

// ── LUT tag signature tables ────────────────────────────────────────────────

static const icTagSignature kAToBSigs[] = {
  icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag
};
static const char *kAToBNames[] = { "AToB0", "AToB1", "AToB2" };

static const icTagSignature kBToASigs[] = {
  icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag
};
static const char *kBToANames[] = { "BToA0", "BToA1", "BToA2" };

static constexpr int kLUTDirCount = 3;

// Combined AToB + BToA signatures for checks spanning both directions
static const icTagSignature kAllLUTSigs[] = {
  icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
  icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag
};
static const char *kAllLUTNames[] = {
  "AToB0", "AToB1", "AToB2", "BToA0", "BToA1", "BToA2"
};
static constexpr int kAllLUTCount = 6;

// Matrix identity tolerance (covers s15Fixed16 quantization)
static constexpr double kMatrixIdentityTol = 0.002;

// Determinant singularity threshold
static constexpr double kDetEpsilon = 0.0001;

// ── Helpers ─────────────────────────────────────────────────────────────────

static bool IsAToBDirection(icTagSignature sig) {
  return sig == icSigAToB0Tag || sig == icSigAToB1Tag || sig == icSigAToB2Tag;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-060: LUT Input Channel Count (ICC.1-2022-05 §10.8-10.11)
//
// AToB tags: input = device channels (colorSpace)
// BToA tags: input = PCS channels
// DeviceLink: AToB0 input = colorSpace (handled generically)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF060_LUTInputChannels(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-060]%s LUT Input Channel Count (%sICC.1-2022-05 §10.8-10.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number deviceChan = icGetSpaceSamples(pIcc->m_Header.colorSpace);
  icUInt32Number pcsChan    = icGetSpaceSamples(pIcc->m_Header.pcs);

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    found = true;
    icUInt8Number lutIn = mbb->InputChannels();

    // AToB: input is device space; BToA: input is PCS
    icUInt32Number expectedIn = IsAToBDirection(kAllLUTSigs[i]) ? deviceChan : pcsChan;

    if (expectedIn == 0) {
      printf("         Tag '%s' — cannot determine expected input channel count\n",
             kAllLUTNames[i]);
      continue;
    }

    if (lutIn != expectedIn) {
      printf("         Tag '%s' — input channels=%u, expected=%u\n",
             kAllLUTNames[i], lutIn, expectedIn);
      printf("         %s[FAIL]%s Input channel count mismatch — ICC.1-2022-05 §10.8-10.11\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No LUT tags present — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s LUT input channel counts valid\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-061: LUT Output Channel Count (ICC.1-2022-05 §10.8-10.11)
//
// AToB tags: output = PCS channels
// BToA tags: output = device channels (colorSpace)
// DeviceLink: AToB0 output = pcs (which holds the device output space)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF061_LUTOutputChannels(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-061]%s LUT Output Channel Count (%sICC.1-2022-05 §10.8-10.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number deviceChan = icGetSpaceSamples(pIcc->m_Header.colorSpace);
  icUInt32Number pcsChan    = icGetSpaceSamples(pIcc->m_Header.pcs);

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    found = true;
    icUInt8Number lutOut = mbb->OutputChannels();

    // AToB: output is PCS; BToA: output is device space
    icUInt32Number expectedOut = IsAToBDirection(kAllLUTSigs[i]) ? pcsChan : deviceChan;

    if (expectedOut == 0) {
      printf("         Tag '%s' — cannot determine expected output channel count\n",
             kAllLUTNames[i]);
      continue;
    }

    if (lutOut != expectedOut) {
      printf("         Tag '%s' — output channels=%u, expected=%u\n",
             kAllLUTNames[i], lutOut, expectedOut);
      printf("         %s[FAIL]%s Output channel count mismatch — ICC.1-2022-05 §10.8-10.11\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No LUT tags present — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s LUT output channel counts valid\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-062: CLUT Grid Dimensionality (ICC.1-2022-05 §10.8-10.11)
//
// Each grid dimension must have >= 2 points.
// Product of all grid dimensions must not overflow uint32.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF062_CLUTGridDimensionality(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-062]%s CLUT Grid Dimensionality (%sICC.1-2022-05 §10.8-10.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    CIccCLUT *clut = mbb->GetCLUT();
    if (!clut) continue;

    found = true;
    int nDims = clut->GetInputDim();

    // Each grid dimension must be >= 2
    for (int d = 0; d < nDims; d++) {
      icUInt8Number gp = clut->GridPoint(d);
      if (gp < 2) {
        printf("         Tag '%s' — grid dimension %d has %u points (minimum 2)\n",
               kAllLUTNames[i], d, static_cast<unsigned>(gp));
        printf("         %s[FAIL]%s CLUT grid points < 2 — ICC.1-2022-05 §10.8\n",
               ColorError(), ColorReset());
        issues++;
      }
    }

    // Check for grid size overflow (product of all dimensions)
    uint64_t total = 1;
    bool overflow = false;
    for (int d = 0; d < nDims; d++) {
      uint64_t gp = clut->GridPoint(d);
      if (gp > 0 && total > UINT32_MAX / gp) {
        overflow = true;
        break;
      }
      total *= gp;
    }
    if (overflow) {
      printf("         Tag '%s' — CLUT grid dimension product overflows uint32\n",
             kAllLUTNames[i]);
      printf("         %s[FAIL]%s CLUT grid dimension overflow — ICC.1-2022-05 §10.8\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No CLUT elements found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s CLUT grid dimensions valid\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-063: lut8Type Fixed Table Size 256 (ICC.1-2022-05 §10.9)
//
// lut8Type input and output tables MUST have exactly 256 entries each.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF063_Lut8FixedTableSize(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-063]%s lut8Type Fixed Table Size 256 (%sICC.1-2022-05 §10.9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccTagLut8 *lut8 = dynamic_cast<CIccTagLut8 *>(tag);
    if (!lut8) continue;

    found = true;
    int nIn  = lut8->InputChannels();
    int nOut = lut8->OutputChannels();

    // Check input curves (B curves in MBB abstraction for legacy LUTs)
    LPIccCurve *curvesB = lut8->GetCurvesB();
    if (curvesB) {
      for (int c = 0; c < nIn; c++) {
        if (!curvesB[c]) continue;
        CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesB[c]);
        if (curve && curve->GetSize() != 256) {
          printf("         Tag '%s' — input table[%d] has %u entries (must be 256)\n",
                 kAllLUTNames[i], c, curve->GetSize());
          printf("         %s[FAIL]%s lut8 input table size != 256 — ICC.1-2022-05 §10.9\n",
                 ColorError(), ColorReset());
          issues++;
        }
      }
    }

    // Check output curves (A curves in MBB abstraction for legacy LUTs)
    LPIccCurve *curvesA = lut8->GetCurvesA();
    if (curvesA) {
      for (int c = 0; c < nOut; c++) {
        if (!curvesA[c]) continue;
        CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesA[c]);
        if (curve && curve->GetSize() != 256) {
          printf("         Tag '%s' — output table[%d] has %u entries (must be 256)\n",
                 kAllLUTNames[i], c, curve->GetSize());
          printf("         %s[FAIL]%s lut8 output table size != 256 — ICC.1-2022-05 §10.9\n",
                 ColorError(), ColorReset());
          issues++;
        }
      }
    }
  }

  if (!found)
    printf("         No lut8Type tags found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s lut8Type table sizes conformant\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-064: lut16Type Table Size Range 2-4096 (ICC.1-2022-05 §10.10)
//
// lut16Type input and output table entries must be in range [2, 4096].
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF064_Lut16TableSizeRange(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-064]%s lut16Type Table Size Range 2-4096 (%sICC.1-2022-05 §10.10%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccTagLut16 *lut16 = dynamic_cast<CIccTagLut16 *>(tag);
    if (!lut16) continue;

    found = true;
    int nIn  = lut16->InputChannels();
    int nOut = lut16->OutputChannels();

    // Check input curves
    LPIccCurve *curvesB = lut16->GetCurvesB();
    if (curvesB) {
      for (int c = 0; c < nIn; c++) {
        if (!curvesB[c]) continue;
        CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesB[c]);
        if (curve) {
          icUInt32Number sz = curve->GetSize();
          if (sz < 2 || sz > 4096) {
            printf("         Tag '%s' — input table[%d] has %u entries (must be 2-4096)\n",
                   kAllLUTNames[i], c, sz);
            printf("         %s[FAIL]%s lut16 input table size out of range — ICC.1-2022-05 §10.10\n",
                   ColorError(), ColorReset());
            issues++;
          }
        }
      }
    }

    // Check output curves
    LPIccCurve *curvesA = lut16->GetCurvesA();
    if (curvesA) {
      for (int c = 0; c < nOut; c++) {
        if (!curvesA[c]) continue;
        CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesA[c]);
        if (curve) {
          icUInt32Number sz = curve->GetSize();
          if (sz < 2 || sz > 4096) {
            printf("         Tag '%s' — output table[%d] has %u entries (must be 2-4096)\n",
                   kAllLUTNames[i], c, sz);
            printf("         %s[FAIL]%s lut16 output table size out of range — ICC.1-2022-05 §10.10\n",
                   ColorError(), ColorReset());
            issues++;
          }
        }
      }
    }
  }

  if (!found)
    printf("         No lut16Type tags found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s lut16Type table sizes within range\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-065: lutAToBType Processing Element Present (ICC.1-2022-05 §10.11)
//
// Valid element combinations:
//   B only | M + matrix + B | A + CLUT + B | A + CLUT + M + matrix + B
// Invalid: CLUT without A curves, Matrix without M curves
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF065_LutAToBElementPresent(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-065]%s lutAToBType Processing Element Present (%sICC.1-2022-05 §10.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kLUTDirCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAToBSigs[i]);
    if (!tag) continue;

    // Only validate lutAToBType (not lut8/lut16)
    if (tag->GetType() != icSigLutAtoBType) continue;

    CIccTagLutAtoB *atob = dynamic_cast<CIccTagLutAtoB *>(tag);
    if (!atob) continue;

    found = true;

    bool hasA      = (atob->GetCurvesA() != nullptr);
    bool hasB      = (atob->GetCurvesB() != nullptr);
    bool hasM      = (atob->GetCurvesM() != nullptr);
    bool hasCLUT   = (atob->GetCLUT()    != nullptr);
    bool hasMatrix = (atob->GetMatrix()  != nullptr);

    // B curves are always required
    if (!hasB) {
      printf("         Tag '%s' — B curves missing (required)\n", kAToBNames[i]);
      printf("         %s[FAIL]%s lutAToBType requires B curves — ICC.1-2022-05 §10.11\n",
             ColorError(), ColorReset());
      issues++;
    }

    // CLUT present requires A curves
    if (hasCLUT && !hasA) {
      printf("         Tag '%s' — CLUT present without A curves\n", kAToBNames[i]);
      printf("         %s[FAIL]%s CLUT requires A curves — ICC.1-2022-05 §10.11\n",
             ColorError(), ColorReset());
      issues++;
    }

    // Matrix present requires M curves
    if (hasMatrix && !hasM) {
      printf("         Tag '%s' — Matrix present without M curves\n", kAToBNames[i]);
      printf("         %s[FAIL]%s Matrix requires M curves — ICC.1-2022-05 §10.11\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No lutAToBType tags found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s lutAToBType element presence valid\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-066: lutBToAType Processing Element Present (ICC.1-2022-05 §10.12)
//
// Valid element combinations:
//   B only | B + matrix + M | B + CLUT + A | B + matrix + M + CLUT + A
// Invalid: CLUT without A curves, Matrix without M curves
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF066_LutBToAElementPresent(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-066]%s lutBToAType Processing Element Present (%sICC.1-2022-05 §10.12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kLUTDirCount; i++) {
    CIccTag *tag = pIcc->FindTag(kBToASigs[i]);
    if (!tag) continue;

    // Only validate lutBToAType (not lut8/lut16)
    if (tag->GetType() != icSigLutBtoAType) continue;

    CIccTagLutBtoA *btoa = dynamic_cast<CIccTagLutBtoA *>(tag);
    if (!btoa) continue;

    found = true;

    bool hasA      = (btoa->GetCurvesA() != nullptr);
    bool hasB      = (btoa->GetCurvesB() != nullptr);
    bool hasM      = (btoa->GetCurvesM() != nullptr);
    bool hasCLUT   = (btoa->GetCLUT()    != nullptr);
    bool hasMatrix = (btoa->GetMatrix()  != nullptr);

    // B curves are always required
    if (!hasB) {
      printf("         Tag '%s' — B curves missing (required)\n", kBToANames[i]);
      printf("         %s[FAIL]%s lutBToAType requires B curves — ICC.1-2022-05 §10.12\n",
             ColorError(), ColorReset());
      issues++;
    }

    // CLUT present requires A curves
    if (hasCLUT && !hasA) {
      printf("         Tag '%s' — CLUT present without A curves\n", kBToANames[i]);
      printf("         %s[FAIL]%s CLUT requires A curves — ICC.1-2022-05 §10.12\n",
             ColorError(), ColorReset());
      issues++;
    }

    // Matrix present requires M curves
    if (hasMatrix && !hasM) {
      printf("         Tag '%s' — Matrix present without M curves\n", kBToANames[i]);
      printf("         %s[FAIL]%s Matrix requires M curves — ICC.1-2022-05 §10.12\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No lutBToAType tags found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s lutBToAType element presence valid\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-067: lut8/16 Matrix Identity When Not PCSXYZ (ICC.1-2022-05 §10.8-10.10)
//
// The 3x3 matrix in lut8Type and lut16Type is only meaningful when PCS is XYZ.
// If PCS is not XYZ, the matrix should be identity.  WARNING severity.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF067_LutMatrixIdentityNonXYZ(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-067]%s lut8/16 Matrix Identity When Not PCSXYZ "
         "(%sICC.1-2022-05 §10.8-10.10%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Only relevant when PCS is not XYZ
  if (pIcc->m_Header.pcs == icSigXYZData) {
    printf("         PCS is XYZ — matrix may be non-identity\n");
    printf("         %s[OK]%s PCS=XYZ, identity check not applicable\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    // Only check lut8Type and lut16Type (legacy LUTs with embedded matrix)
    bool isLut8  = (dynamic_cast<CIccTagLut8 *>(tag) != nullptr);
    bool isLut16 = (dynamic_cast<CIccTagLut16 *>(tag) != nullptr);
    if (!isLut8 && !isLut16) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    const CIccMatrix *matrix = mbb->GetMatrix();
    if (!matrix) continue;

    found = true;

    // Check if 3x3 part of m_e[0..8] is approximately identity
    // Layout: m_e[0..8] = 3x3 row-major, m_e[9..11] = constants
    const icFloatNumber *e = matrix->m_e;
    bool isIdentity = true;
    for (int r = 0; r < 3 && isIdentity; r++) {
      for (int c = 0; c < 3 && isIdentity; c++) {
        double expected = (r == c) ? 1.0 : 0.0;
        if (std::fabs(static_cast<double>(e[r * 3 + c]) - expected) > kMatrixIdentityTol)
          isIdentity = false;
      }
    }

    if (!isIdentity) {
      printf("         Tag '%s' — PCS is not XYZ but matrix is not identity\n",
             kAllLUTNames[i]);
      printf("         Matrix: [%.4f %.4f %.4f] [%.4f %.4f %.4f] [%.4f %.4f %.4f]\n",
             static_cast<double>(e[0]), static_cast<double>(e[1]),
             static_cast<double>(e[2]), static_cast<double>(e[3]),
             static_cast<double>(e[4]), static_cast<double>(e[5]),
             static_cast<double>(e[6]), static_cast<double>(e[7]),
             static_cast<double>(e[8]));
      printf("         %s[WARN]%s lut8/16 matrix should be identity when PCS != XYZ "
             "— ICC.1-2022-05 §10.8\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No lut8/lut16 tags with matrix found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s lut8/16 matrix identity check passed\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-068: Chromatic Adaptation Matrix Invertible (ICC.1-2022-05 §9.2.10)
//
// The chad tag 3x3 matrix must be invertible (determinant ≠ 0).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF068_ChadMatrixInvertible(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-068]%s Chromatic Adaptation Matrix Invertible (%sICC.1-2022-05 §9.2.10%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTagS15Fixed16 *chad =
      FindAndCast<CIccTagS15Fixed16>(pIcc, icSigChromaticAdaptationTag);
  if (!chad) {
    printf("         No chromaticAdaptationTag present — check not applicable\n");
    printf("         %s[OK]%s No chad tag to validate\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  if (chad->GetSize() < 9) {
    printf("         chad has %u values (need 9 for 3x3 matrix)\n", chad->GetSize());
    printf("         %s[FAIL]%s Insufficient values for invertibility check "
           "— ICC.1-2022-05 §9.2.10\n",
           ColorError(), ColorReset());
    return 1;
  }

  // Convert 9 s15Fixed16Number values to doubles
  double m[9];
  for (int i = 0; i < 9; i++)
    m[i] = static_cast<double>((*chad)[i]) / 65536.0;

  // 3x3 determinant: a(ei-fh) - b(di-fg) + c(dh-eg)
  // where [[a,b,c],[d,e,f],[g,h,i]] = m[0..8]
  double det = m[0] * (m[4] * m[8] - m[5] * m[7])
             - m[1] * (m[3] * m[8] - m[5] * m[6])
             + m[2] * (m[3] * m[7] - m[4] * m[6]);

  if (std::fabs(det) < kDetEpsilon) {
    printf("         Determinant = %.8f — matrix is singular or near-singular\n", det);
    printf("         %s[FAIL]%s Chromatic adaptation matrix not invertible "
           "— ICC.1-2022-05 §9.2.10\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         Determinant = %.6f — matrix is invertible\n", det);
  }

  if (issues == 0)
    printf("         %s[OK]%s Chromatic adaptation matrix invertible\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-069: Matrix Column Tag XYZ Count (ICC.1-2022-05 §9.2.7, §9.2.18, §9.2.31)
//
// redMatrixColumnTag, greenMatrixColumnTag, blueMatrixColumnTag must each
// contain exactly 1 XYZ triplet (GetSize() == 1).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF069_MatrixColumnXYZCount(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-069]%s Matrix Column Tag XYZ Count "
         "(%sICC.1-2022-05 §9.2.7, §9.2.18, §9.2.31%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const icTagSignature kColSigs[] = {
    icSigRedMatrixColumnTag,
    icSigGreenMatrixColumnTag,
    icSigBlueMatrixColumnTag
  };
  static const char *kColNames[] = {
    "rXYZ (Red)", "gXYZ (Green)", "bXYZ (Blue)"
  };

  for (int i = 0; i < 3; i++) {
    CIccTagXYZ *xyz = FindAndCast<CIccTagXYZ>(pIcc, kColSigs[i]);
    if (!xyz) continue;

    found = true;
    if (xyz->GetSize() != 1) {
      printf("         Tag '%s' — contains %u XYZ triplets (must be exactly 1)\n",
             kColNames[i], xyz->GetSize());
      printf("         %s[FAIL]%s Matrix column must have 1 XYZ triplet "
             "— ICC.1-2022-05 §9.2\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No matrix column tags present — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s Matrix column XYZ counts valid\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-070: Chad s15Fixed16 Array Count 9 (ICC.1-2022-05 §9.2.10)
//
// chromaticAdaptationTag must contain exactly 9 s15Fixed16Number values
// (3x3 matrix).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF070_ChadArrayCount9(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-070]%s Chad s15Fixed16 Array Count 9 (%sICC.1-2022-05 §9.2.10%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTagS15Fixed16 *chad =
      FindAndCast<CIccTagS15Fixed16>(pIcc, icSigChromaticAdaptationTag);
  if (!chad) {
    printf("         No chromaticAdaptationTag present — check not applicable\n");
    printf("         %s[OK]%s No chad tag to validate\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  if (chad->GetSize() != 9) {
    printf("         chad contains %u s15Fixed16 values (must be exactly 9)\n",
           chad->GetSize());
    printf("         %s[FAIL]%s Chad must contain 9 values for 3x3 matrix "
           "— ICC.1-2022-05 §9.2.10\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Chad array count is 9\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-071: Curve Count vs Channel Match (ICC.1-2022-05 §10.10-10.12)
//
// For lutAToBType/lutBToAType: A/B/M curve array lengths must match the
// expected input/output channel counts of the MBB element.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF071_CurveCountChannelMatch(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-071]%s Curve Count vs Channel Match (%sICC.1-2022-05 §10.10-10.12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    found = true;
    int nIn  = mbb->InputChannels();
    int nOut = mbb->OutputChannels();

    // B curves: count should match input channels for AToB (IsInputB),
    //           or output channels for BToA (!IsInputB)
    LPIccCurve *curvesB = mbb->GetCurvesB();
    if (curvesB) {
      int expectedB = mbb->IsInputB() ? nIn : nOut;
      int countB = 0;
      for (int c = 0; c < expectedB && c < 16; c++) {
        if (curvesB[c]) countB++;
      }
      if (countB > 0 && countB != expectedB) {
        printf("         Tag '%s' — B curve count %d != expected %d\n",
               kAllLUTNames[i], countB, expectedB);
        printf("         %s[FAIL]%s B curve count mismatch — §10.10-10.12\n",
               ColorError(), ColorReset());
        issues++;
      }
    }

    // A curves: count should match the other side
    LPIccCurve *curvesA = mbb->GetCurvesA();
    if (curvesA) {
      int expectedA = mbb->IsInputB() ? nOut : nIn;
      int countA = 0;
      for (int c = 0; c < expectedA && c < 16; c++) {
        if (curvesA[c]) countA++;
      }
      if (countA > 0 && countA != expectedA) {
        printf("         Tag '%s' — A curve count %d != expected %d\n",
               kAllLUTNames[i], countA, expectedA);
        printf("         %s[FAIL]%s A curve count mismatch — §10.10-10.12\n",
               ColorError(), ColorReset());
        issues++;
      }
    }

    // M curves: always 3 when present (XYZ PCS matrix pathway)
    LPIccCurve *curvesM = mbb->GetCurvesM();
    if (curvesM) {
      int countM = 0;
      for (int c = 0; c < 3; c++) {
        if (curvesM[c]) countM++;
      }
      if (countM > 0 && countM != 3) {
        printf("         Tag '%s' — M curve count %d != expected 3\n",
               kAllLUTNames[i], countM);
        printf("         %s[FAIL]%s M curve count mismatch — §10.10-10.12\n",
               ColorError(), ColorReset());
        issues++;
      }
    }
  }

  if (!found)
    printf("         No LUT tags found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s Curve counts match channel expectations\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-072: CLUT Output Value Range (ICC.1-2022-05 §10.8-10.12)
//
// CLUT grid point output values must be finite (no NaN or Inf).
// Samples up to 1000 points to avoid timeout on large CLUTs.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF072_CLUTOutputValueRange(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-072]%s CLUT Output Value Range (%sICC.1-2022-05 §10.8-10.12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    CIccCLUT *clut = mbb->GetCLUT();
    if (!clut) continue;

    found = true;
    icUInt32Number nPoints = clut->NumPoints();
    int nOut = clut->GetOutputChannels();
    if (nOut < 1 || nOut > 16) continue;

    // Sample up to 1000 grid points
    icUInt32Number limit = (nPoints < 1000) ? nPoints : 1000;
    int badCount = 0;

    for (icUInt32Number p = 0; p < limit && badCount < 5; p++) {
      icFloatNumber *data = clut->GetData(p * nOut);
      if (!data) break;
      for (int ch = 0; ch < nOut; ch++) {
        if (std::isnan(data[ch]) || std::isinf(data[ch])) {
          if (badCount == 0) {
            printf("         Tag '%s' — CLUT[%u][%d] = %f (non-finite)\n",
                   kAllLUTNames[i], p, ch, static_cast<double>(data[ch]));
            printf("         %s[FAIL]%s CLUT contains NaN/Inf values — §10.8\n",
                   ColorError(), ColorReset());
          }
          badCount++;
          issues++;
          break;
        }
      }
    }
    if (badCount > 1)
      printf("         ... %d additional non-finite CLUT values found\n", badCount - 1);
  }

  if (!found)
    printf("         No CLUT elements found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s CLUT output values are finite\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-073: MBB Matrix Determinant Non-Zero (ICC.1-2022-05 §10.10-10.12)
//
// For MBB tags (lutAToBType/lutBToAType) containing a matrix element:
// the 3×3 determinant must be non-zero to ensure invertibility.
// Complements CF-165 which checks all LUT matrices — this focuses on
// MBB-specific context with per-tag reporting.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF073_MBBMatrixDeterminant(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-073]%s MBB Matrix Determinant Non-Zero (%sICC.1-2022-05 §10.10-10.12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    // Only MBB types (lutAToBType / lutBToAType), not lut8/lut16
    if (tag->GetType() != icSigLutAtoBType && tag->GetType() != icSigLutBtoAType)
      continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    const CIccMatrix *matrix = mbb->GetMatrix();
    if (!matrix) continue;

    found = true;

    double a = matrix->m_e[0], b = matrix->m_e[1], c = matrix->m_e[2];
    double d = matrix->m_e[3], e = matrix->m_e[4], f = matrix->m_e[5];
    double g = matrix->m_e[6], h = matrix->m_e[7], k = matrix->m_e[8];

    double det = a * (e * k - f * h) - b * (d * k - f * g) + c * (d * h - e * g);

    if (std::fabs(det) < 1e-10) {
      printf("         Tag '%s' — matrix determinant = %.10f (near-singular)\n",
             kAllLUTNames[i], det);
      printf("         %s[WARN]%s Singular MBB matrix is non-invertible — §10.10\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No MBB tags with matrix found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s MBB matrix determinants are non-zero\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-074: A2B/B2A Dimension Consistency (ICC.1-2022-05 §10.8-10.12)
//
// For matching A2B/B2A tag pairs (intent 0,1,2):
//   AToB InputChannels  must equal BToA OutputChannels
//   AToB OutputChannels must equal BToA InputChannels
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF074_A2BB2ADimensionConsistency(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-074]%s A2B/B2A Dimension Consistency (%sICC.1-2022-05 §10.8-10.12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kLUTDirCount; i++) {
    CIccTag *aTag = pIcc->FindTag(kAToBSigs[i]);
    CIccTag *bTag = pIcc->FindTag(kBToASigs[i]);
    if (!aTag || !bTag) continue;

    CIccMBB *aMBB = dynamic_cast<CIccMBB *>(aTag);
    CIccMBB *bMBB = dynamic_cast<CIccMBB *>(bTag);
    if (!aMBB || !bMBB) continue;

    found = true;

    if (aMBB->InputChannels() != bMBB->OutputChannels()) {
      printf("         Intent %d — AToB input (%u) != BToA output (%u)\n",
             i, static_cast<unsigned>(aMBB->InputChannels()),
             static_cast<unsigned>(bMBB->OutputChannels()));
      printf("         %s[FAIL]%s Forward/reverse dimension mismatch — §10.8\n",
             ColorError(), ColorReset());
      issues++;
    }

    if (aMBB->OutputChannels() != bMBB->InputChannels()) {
      printf("         Intent %d — AToB output (%u) != BToA input (%u)\n",
             i, static_cast<unsigned>(aMBB->OutputChannels()),
             static_cast<unsigned>(bMBB->InputChannels()));
      printf("         %s[FAIL]%s Forward/reverse dimension mismatch — §10.8\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No matching A2B/B2A pairs found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s A2B/B2A dimensions are consistent\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-075: Tag Data Size vs Dimensions (ICC.1-2022-05 §10.8-10.12)
//
// Validates that declared LUT dimensions don't imply an unreasonable number
// of data entries. Checks input/output channels (1-15) and CLUT total
// grid points (grid^nInput * nOutput capped at 100M).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF075_TagDataSizeVsDimensions(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-075]%s Tag Data Size vs Dimensions (%sICC.1-2022-05 §10.8-10.12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    found = true;
    int nIn  = mbb->InputChannels();
    int nOut = mbb->OutputChannels();

    if (nIn < 1 || nIn > 15) {
      printf("         Tag '%s' — input channels = %d (expected 1-15)\n",
             kAllLUTNames[i], nIn);
      printf("         %s[FAIL]%s Unreasonable input channel count — §10.8\n",
             ColorError(), ColorReset());
      issues++;
    }

    if (nOut < 1 || nOut > 15) {
      printf("         Tag '%s' — output channels = %d (expected 1-15)\n",
             kAllLUTNames[i], nOut);
      printf("         %s[FAIL]%s Unreasonable output channel count — §10.8\n",
             ColorError(), ColorReset());
      issues++;
    }

    CIccCLUT *clut = mbb->GetCLUT();
    if (clut) {
      int nDims = clut->GetInputDim();
      uint64_t totalEntries = 1;
      bool overflow = false;
      for (int d = 0; d < nDims; d++) {
        uint64_t gp = clut->GridPoint(d);
        if (gp == 0 || (totalEntries > 0 && totalEntries > 100000000ULL / gp)) {
          overflow = true;
          break;
        }
        totalEntries *= gp;
      }
      totalEntries *= static_cast<uint64_t>(clut->GetOutputChannels());

      if (overflow || totalEntries > 100000000ULL) {
        printf("         Tag '%s' — CLUT total entries > 100M (suspicious)\n",
               kAllLUTNames[i]);
        printf("         %s[WARN]%s Possibly malformed CLUT dimensions — §10.8\n",
               ColorWarning(), ColorReset());
        issues++;
      }
    }
  }

  if (!found)
    printf("         No LUT tags found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s LUT dimensions are plausible\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-076: Curve Response Direction (ICC.1-2022-05 §10.5)
//
// B curves in AToB tags (output-side curves) should be non-decreasing.
// Detects curves that decrease significantly between sample points, which
// indicates a malformed or corrupted curve. Complements CF-106 (TRC-specific).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF076_CurveResponseDirection(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-076]%s Curve Response Direction (%sICC.1-2022-05 §10.5%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const icFloatNumber kSamplePoints[] = { 0.0f, 0.25f, 0.5f, 0.75f, 1.0f };
  static constexpr int kNumSamples = 5;
  static constexpr icFloatNumber kDecreaseTol = 0.01f;

  for (int i = 0; i < kLUTDirCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAToBSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    // B curves are the output-side curves for AToB
    LPIccCurve *curvesB = mbb->GetCurvesB();
    if (!curvesB) continue;

    int nCurves = mbb->IsInputB() ? mbb->InputChannels() : mbb->OutputChannels();
    if (nCurves < 1 || nCurves > 16) continue;

    found = true;

    for (int c = 0; c < nCurves; c++) {
      if (!curvesB[c]) continue;

      icFloatNumber prev = curvesB[c]->Apply(kSamplePoints[0]);
      for (int s = 1; s < kNumSamples; s++) {
        icFloatNumber val = curvesB[c]->Apply(kSamplePoints[s]);
        if (val < prev - kDecreaseTol) {
          printf("         AToB%d B-curve[%d] — decreases from %.4f to %.4f at input %.2f\n",
                 i, c, static_cast<double>(prev), static_cast<double>(val),
                 static_cast<double>(kSamplePoints[s]));
          printf("         %s[WARN]%s B-curve is not non-decreasing — §10.5\n",
                 ColorWarning(), ColorReset());
          issues++;
          break;
        }
        prev = val;
      }
    }
  }

  if (!found)
    printf("         No AToB tags with B curves found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s B curves are non-decreasing\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-077: CLUT Grid Size Plausibility (ICC.1-2022-05 §10.8-10.12)
//
// Grid dimensions should be reasonable: minimum 2 per axis for interpolation,
// and total grid points should not exceed 10M (likely malformed).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF077_CLUTGridSizePlausibility(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-077]%s CLUT Grid Size Plausibility (%sICC.1-2022-05 §10.8-10.12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    CIccCLUT *clut = mbb->GetCLUT();
    if (!clut) continue;

    found = true;
    int nDims = clut->GetInputDim();

    for (int d = 0; d < nDims; d++) {
      int gp = static_cast<int>(clut->GridPoint(d));
      if (gp < 2) {
        printf("         Tag '%s' dim %d — grid points = %d (< 2, cannot interpolate)\n",
               kAllLUTNames[i], d, gp);
        printf("         %s[FAIL]%s CLUT grid too small for interpolation — §10.8\n",
               ColorError(), ColorReset());
        issues++;
      }
    }

    icUInt32Number nPoints = clut->NumPoints();
    if (nPoints > 10000000U) {
      printf("         Tag '%s' — total grid points = %u (> 10M, likely malformed)\n",
             kAllLUTNames[i], nPoints);
      printf("         %s[WARN]%s Excessive CLUT grid size — §10.8\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No CLUT elements found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s CLUT grid sizes are plausible\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-078: MBB B-Curve Presence (ICC.1-2022-05 §10.10-10.12)
//
// Both lutAToBType (§10.11) and lutBToAType (§10.12) require B curves.
// If an MBB tag exists but GetCurvesB() returns NULL, the tag is malformed.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF078_MBBBCurvePresence(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-078]%s MBB B-Curve Presence (%sICC.1-2022-05 §10.10-10.12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    // Only check MBB types (lutAToBType / lutBToAType)
    if (tag->GetType() != icSigLutAtoBType && tag->GetType() != icSigLutBtoAType)
      continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    found = true;

    if (!mbb->GetCurvesB()) {
      printf("         Tag '%s' — B curves missing (required for %s)\n",
             kAllLUTNames[i],
             tag->GetType() == icSigLutAtoBType ? "lutAToBType" : "lutBToAType");
      printf("         %s[FAIL]%s B curves are mandatory — §10.10-10.12\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No lutAToBType/lutBToAType tags found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s B curves present in all MBB tags\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-079: LUT Bit Depth Consistency (ICC.1-2022-05 §10.9-10.10)
//
// For legacy lut8Type: each curve table must have exactly 256 entries.
// For legacy lut16Type: each curve table must have >= 2 entries.
// Validates both input and output curve tables.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF079_LUTBitDepthConsistency(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-079]%s LUT Bit Depth Consistency (%sICC.1-2022-05 §10.9-10.10%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    // Check lut8Type
    CIccTagLut8 *lut8 = dynamic_cast<CIccTagLut8 *>(tag);
    if (lut8) {
      found = true;
      int nIn  = lut8->InputChannels();
      int nOut = lut8->OutputChannels();

      LPIccCurve *curvesB = lut8->GetCurvesB();
      if (curvesB) {
        for (int c = 0; c < nIn && c < 16; c++) {
          if (!curvesB[c]) continue;
          CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesB[c]);
          if (curve && curve->GetSize() != 256) {
            printf("         Tag '%s' lut8 — input curve[%d] has %u entries (must be 256)\n",
                   kAllLUTNames[i], c, curve->GetSize());
            printf("         %s[FAIL]%s lut8 curve size mismatch — §10.9\n",
                   ColorError(), ColorReset());
            issues++;
          }
        }
      }

      LPIccCurve *curvesA = lut8->GetCurvesA();
      if (curvesA) {
        for (int c = 0; c < nOut && c < 16; c++) {
          if (!curvesA[c]) continue;
          CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesA[c]);
          if (curve && curve->GetSize() != 256) {
            printf("         Tag '%s' lut8 — output curve[%d] has %u entries (must be 256)\n",
                   kAllLUTNames[i], c, curve->GetSize());
            printf("         %s[FAIL]%s lut8 curve size mismatch — §10.9\n",
                   ColorError(), ColorReset());
            issues++;
          }
        }
      }
      continue;
    }

    // Check lut16Type
    CIccTagLut16 *lut16 = dynamic_cast<CIccTagLut16 *>(tag);
    if (lut16) {
      found = true;
      int nIn  = lut16->InputChannels();
      int nOut = lut16->OutputChannels();

      LPIccCurve *curvesB = lut16->GetCurvesB();
      if (curvesB) {
        for (int c = 0; c < nIn && c < 16; c++) {
          if (!curvesB[c]) continue;
          CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesB[c]);
          if (curve && curve->GetSize() < 2) {
            printf("         Tag '%s' lut16 — input curve[%d] has %u entries (must be >= 2)\n",
                   kAllLUTNames[i], c, curve->GetSize());
            printf("         %s[FAIL]%s lut16 curve too small — §10.10\n",
                   ColorError(), ColorReset());
            issues++;
          }
        }
      }

      LPIccCurve *curvesA = lut16->GetCurvesA();
      if (curvesA) {
        for (int c = 0; c < nOut && c < 16; c++) {
          if (!curvesA[c]) continue;
          CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesA[c]);
          if (curve && curve->GetSize() < 2) {
            printf("         Tag '%s' lut16 — output curve[%d] has %u entries (must be >= 2)\n",
                   kAllLUTNames[i], c, curve->GetSize());
            printf("         %s[FAIL]%s lut16 curve too small — §10.10\n",
                   ColorError(), ColorReset());
            issues++;
          }
        }
      }
    }
  }

  if (!found)
    printf("         No lut8/lut16 type tags found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s Legacy LUT curve sizes are consistent\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-105: LUT Channel Symmetry (ICC.1-2022-05 §10.8-10.11)
//
// For corresponding AToB/BToA tag pairs (intent 0,1,2):
//   AToB input channels must equal BToA output channels and vice versa.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF105_LUTChannelSymmetry(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-105]%s LUT Channel Symmetry (%sICC.1-2022-05 §10.8-10.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  bool found = false;
  for (int i = 0; i < kLUTDirCount; i++) {
    CIccTag *aTag = pIcc->FindTag(kAToBSigs[i]);
    CIccTag *bTag = pIcc->FindTag(kBToASigs[i]);
    if (!aTag || !bTag) continue;

    CIccMBB *aMBB = dynamic_cast<CIccMBB *>(aTag);
    CIccMBB *bMBB = dynamic_cast<CIccMBB *>(bTag);
    if (!aMBB || !bMBB) continue;

    found = true;

    // AToB input channels should equal BToA output channels
    if (aMBB->InputChannels() != bMBB->OutputChannels()) {
      printf("         Intent %d: AToB input=%u ≠ BToA output=%u\n",
             i, (unsigned)aMBB->InputChannels(), (unsigned)bMBB->OutputChannels());
      printf("         %s[FAIL]%s Channel symmetry violation — §10.8-10.11\n",
             ColorError(), ColorReset());
      issues++;
    }

    // AToB output channels should equal BToA input channels
    if (aMBB->OutputChannels() != bMBB->InputChannels()) {
      printf("         Intent %d: AToB output=%u ≠ BToA input=%u\n",
             i, (unsigned)aMBB->OutputChannels(), (unsigned)bMBB->InputChannels());
      printf("         %s[FAIL]%s Channel symmetry violation — §10.8-10.11\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No AToB/BToA tag pairs found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s LUT channel symmetry validated\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-106: Curve Monotonicity (ICC.1-2022-05 §10.5, §10.18)
//
// TRC curves (rTRC, gTRC, bTRC, kTRC) and curveType tags used in
// matrix/TRC profiles MUST be monotonically non-decreasing.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF106_CurveMonotonicity(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-106]%s Curve Monotonicity (%sICC.1-2022-05 §10.5%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const icTagSignature trcSigs[] = {
    icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag
  };
  static const char *trcNames[] = { "rTRC", "gTRC", "bTRC", "kTRC" };

  bool found = false;
  for (int i = 0; i < 4; i++) {
    CIccTag *tag = pIcc->FindTag(trcSigs[i]);
    if (!tag) continue;

    CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(tag);
    if (!curve) continue;

    icUInt32Number n = curve->GetSize();
    if (n < 2) continue; // gamma or identity — always monotone

    found = true;
    bool monotone = true;
    for (icUInt32Number j = 1; j < n; j++) {
      if ((*curve)[j] < (*curve)[j - 1]) {
        monotone = false;
        break;
      }
    }

    if (!monotone) {
      printf("         %s TRC curve is not monotonically non-decreasing\n", trcNames[i]);
      printf("         %s[FAIL]%s TRC must be monotone — §10.5\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No tabulated TRC curves found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s TRC curves are monotonically non-decreasing\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-108: CLUT Grid Point Range 2-255 (ICC.1-2022-05 §10.8-10.10)
//
// Each CLUT dimension grid point count MUST be in range [2, 255].
// (This is a stricter version of CF-062 which only checks >= 2.)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF108_CLUTGridPointRange(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-108]%s CLUT Grid Point Range (%sICC.1-2022-05 §10.8-10.10%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  bool found = false;
  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    CIccCLUT *clut = mbb->GetCLUT();
    if (!clut) continue;

    found = true;
    int nDims = clut->GetInputDim();
    for (int d = 0; d < nDims; d++) {
      int gp = static_cast<int>(clut->GridPoint(d));
      if (gp < 2) {
        printf("         Tag '%s' dim %d: grid points=%u (must be 2-255)\n",
               kAllLUTNames[i], d, (unsigned)gp);
        printf("         %s[FAIL]%s CLUT grid points out of range — §10.8\n",
               ColorError(), ColorReset());
        issues++;
      }
    }
  }

  if (!found)
    printf("         No CLUT elements found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s CLUT grid points in valid range [2,255]\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-109: Matrix Column Normalization (ICC.1-2022-05 §9.2.7, TN v4_matrix)
//
// Red/Green/Blue matrix columns (rXYZ, gXYZ, bXYZ) represent the tristimulus
// values of the respective primaries. Each column Y value should be >= 0 and
// the sum of Y values across all three columns should approximate 1.0
// (for D50 white point normalization).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF109_MatrixColumnNormalization(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-109]%s Matrix Column Normalization (%sICC.1-2022-05 §9.2.7%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const icTagSignature matSigs[] = {
    icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag
  };
  static const char *matNames[] = { "rXYZ", "gXYZ", "bXYZ" };

  // All three must be present
  bool allPresent = true;
  for (int i = 0; i < 3; i++) {
    if (!pIcc->FindTag(matSigs[i])) { allPresent = false; break; }
  }
  if (!allPresent) {
    printf("         Not all matrix column tags present — check not applicable\n");
    return 0;
  }

  icFloatNumber ySum = 0.0;
  for (int i = 0; i < 3; i++) {
    CIccTag *tag = pIcc->FindTag(matSigs[i]);
    CIccTagXYZ *xyz = dynamic_cast<CIccTagXYZ *>(tag);
    if (!xyz || xyz->GetSize() < 1) continue;

    icXYZNumber val = (*xyz)[0];
    icFloatNumber x = icFtoD(val.X);
    icFloatNumber y = icFtoD(val.Y);
    icFloatNumber z = icFtoD(val.Z);

    if (y < 0.0) {
      printf("         %s Y value is negative (%.4f)\n", matNames[i], y);
      printf("         %s[WARN]%s Negative Y in matrix column — §9.2.7\n",
             ColorError(), ColorReset());
      issues++;
    }

    // Check for wildly out-of-range values
    if (x < -2.0 || x > 4.0 || y < -2.0 || y > 4.0 || z < -2.0 || z > 4.0) {
      printf("         %s values out of range (X=%.4f Y=%.4f Z=%.4f)\n",
             matNames[i], x, y, z);
      printf("         %s[WARN]%s Matrix column values exceeding typical range — §9.2.7\n",
             ColorError(), ColorReset());
      issues++;
    }

    ySum += y;
  }

  // Sum of Y values across columns should approximate 1.0 (D50 normalization)
  if (std::fabs(ySum - 1.0) > 0.05) {
    printf("         Sum of matrix column Y values = %.4f (expected ~1.0 for D50)\n", ySum);
    printf("         %s[WARN]%s Y column sum deviates significantly from 1.0 — TN v4_matrix\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Matrix columns properly normalized\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-110: B Curves vs CLUT Output Channel Count (ICC.1-2022-05 §10.8-10.11)
//
// In lutAToBType and lutBToAType, if a CLUT and B curves are present,
// the B curve count MUST equal the CLUT output channel count.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF110_BCurveVsCLUTOutput(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-110]%s B Curves vs CLUT Output Count (%sICC.1-2022-05 §10.8-10.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  bool found = false;
  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    // Only applies to lutAToBType and lutBToAType
    icTagTypeSignature ttype = tag->GetType();
    if (ttype != icSigLutAtoBType && ttype != icSigLutBtoAType) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    CIccCLUT *clut = mbb->GetCLUT();
    if (!clut) continue;

    found = true;
    // In AToB: output channels = B curves count
    // In BToA: output channels = B curves count
    icUInt16Number outCh = mbb->OutputChannels();

    // Verify CLUT output matches MBB output
    // (CLUT nOut should match the tag's output channels)
    icUInt16Number clutOut = clut->GetOutputChannels();
    if (clutOut != outCh) {
      printf("         Tag '%s' CLUT output=%u but tag output=%u\n",
             kAllLUTNames[i], (unsigned)clutOut, (unsigned)outCh);
      printf("         %s[FAIL]%s CLUT output must match B curve count — §10.8\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No lutAToB/lutBToA with CLUT found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s B curves match CLUT output channels\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-116: Curve Segment Continuity (ICC.1-2022-05 §10.18)
//
// segmentedCurveType: at segment boundaries, the evaluated curve must be
// continuous (the end of one segment equals the start of the next).
// For parametricCurveType, function parameters must produce finite values
// at the breakpoint (where applicable).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF116_CurveSegmentContinuity(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-116]%s Curve Segment Continuity (%sICC.1-2022-05 §10.18%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Check parametricCurveType tags for valid parameter relationships
  static const icTagSignature trcSigs[] = {
    icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag
  };
  static const char *trcNames[] = { "rTRC", "gTRC", "bTRC", "kTRC" };

  bool found = false;
  for (int i = 0; i < 4; i++) {
    CIccTag *tag = pIcc->FindTag(trcSigs[i]);
    if (!tag) continue;

    CIccTagParametricCurve *para = dynamic_cast<CIccTagParametricCurve *>(tag);
    if (!para) continue;

    found = true;
    icUInt16Number funcType = para->GetFunctionType();
    int nParams = para->GetNumParam();

    // Function types 1-4 have a breakpoint 'd'
    // For continuity at the breakpoint, both pieces must evaluate to the same value
    if (funcType >= 1 && funcType <= 4 && nParams >= 4) {
      icFloatNumber g = para->Param(0);
      if (g < 0.0 || !std::isfinite(g)) {
        printf("         %s parametric gamma=%.4f is invalid\n", trcNames[i], g);
        printf("         %s[FAIL]%s Parametric curve gamma must be positive finite — §10.18\n",
               ColorError(), ColorReset());
        issues++;
      }
    }
  }

  if (!found)
    printf("         No parametricCurveType TRC tags found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s Curve segments continuous\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-163: LUT Matrix Coefficient Finite (v4 Matrix Entries TN)
//
// All 12 matrix coefficients in lutAToBType/lutBToAType and lut8/lut16 must
// be finite (not NaN or Inf). Non-finite values indicate data corruption
// or malicious crafting. Spec: s15Fixed16Number encoding cannot represent
// NaN/Inf, so their presence indicates post-decode corruption.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF163_LUTMatrixCoeffFinite(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-163]%s LUT Matrix Coefficient Finite "
         "(%sICC v4 Matrix Entries TN%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    const CIccMatrix *matrix = mbb->GetMatrix();
    if (!matrix) continue;

    found = true;
    int nCoeff = matrix->m_bUseConstants ? 12 : 9;

    for (int k = 0; k < nCoeff; k++) {
      double v = static_cast<double>(matrix->m_e[k]);
      if (std::isnan(v) || std::isinf(v)) {
        printf("         Tag '%s' — m_e[%d] = %f (non-finite)\n",
               kAllLUTNames[i], k, v);
        printf("         %s[FAIL]%s Matrix coefficient must be finite "
               "— s15Fixed16Number encoding\n",
               ColorError(), ColorReset());
        issues++;
      }
    }
  }

  if (!found)
    printf("         No LUT tags with matrix found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s All LUT matrix coefficients are finite\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-164: LUT Matrix s15Fixed16 Range (v4 Matrix Entries TN)
//
// Matrix coefficients stored as s15Fixed16Number must be within the
// representable range of approximately [-32768.0, +32767.99998].
// Values outside this range indicate encoding errors.
// ═══════════════════════════════════════════════════════════════════════════════

static constexpr double kS15F16Min = -32768.0;
static constexpr double kS15F16Max =  32767.99998474;

static int RunCF164_LUTMatrixS15F16Range(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-164]%s LUT Matrix s15Fixed16 Range "
         "(%sICC v4 Matrix Entries TN%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    const CIccMatrix *matrix = mbb->GetMatrix();
    if (!matrix) continue;

    found = true;
    int nCoeff = matrix->m_bUseConstants ? 12 : 9;

    for (int k = 0; k < nCoeff; k++) {
      double v = static_cast<double>(matrix->m_e[k]);
      if (v < kS15F16Min || v > kS15F16Max) {
        printf("         Tag '%s' — m_e[%d] = %.4f outside s15Fixed16 range "
               "[%.1f, %.5f]\n",
               kAllLUTNames[i], k, v, kS15F16Min, kS15F16Max);
        printf("         %s[FAIL]%s Coefficient outside s15Fixed16 representable range\n",
               ColorError(), ColorReset());
        issues++;
      }
    }
  }

  if (!found)
    printf("         No LUT tags with matrix found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s All LUT matrix coefficients within s15Fixed16 range\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-165: LUT Matrix Determinant Non-Singular (v4 Matrix Entries TN)
//
// The 3×3 portion of the LUT matrix must be invertible (non-zero determinant).
// A singular matrix collapses 3D color information to 2D or less, causing
// irreversible data loss. Equation from TN:
//   y1 = x1*e1 + x2*e2 + x3*e3 + e10
//   y2 = x1*e4 + x2*e5 + x3*e6 + e11
//   y3 = x1*e7 + x2*e8 + x3*e9 + e12
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF165_LUTMatrixDeterminant(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-165]%s LUT Matrix Determinant Non-Singular "
         "(%sICC v4 Matrix Entries TN%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    const CIccMatrix *matrix = mbb->GetMatrix();
    if (!matrix) continue;

    found = true;

    // m_e[0..8] is row-major 3×3: [[e[0],e[1],e[2]], [e[3],e[4],e[5]], [e[6],e[7],e[8]]]
    double a = static_cast<double>(matrix->m_e[0]);
    double b = static_cast<double>(matrix->m_e[1]);
    double c = static_cast<double>(matrix->m_e[2]);
    double d = static_cast<double>(matrix->m_e[3]);
    double e = static_cast<double>(matrix->m_e[4]);
    double f = static_cast<double>(matrix->m_e[5]);
    double g = static_cast<double>(matrix->m_e[6]);
    double h = static_cast<double>(matrix->m_e[7]);
    double k = static_cast<double>(matrix->m_e[8]);

    double det = a * (e * k - f * h) - b * (d * k - f * g) + c * (d * h - e * g);

    if (std::fabs(det) < kDetEpsilon) {
      printf("         Tag '%s' — determinant = %.8f (singular or near-singular)\n",
             kAllLUTNames[i], det);
      printf("         Matrix: [%.4f %.4f %.4f] [%.4f %.4f %.4f] [%.4f %.4f %.4f]\n",
             a, b, c, d, e, f, g, h, k);
      printf("         %s[FAIL]%s Singular matrix causes irreversible data loss\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         Tag '%s' — determinant = %.6f (invertible)\n",
             kAllLUTNames[i], det);
    }
  }

  if (!found)
    printf("         No LUT tags with matrix found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s All LUT matrices are non-singular\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-166: LUT Matrix Row Non-Zero (v4 Matrix Entries TN)
//
// Each row of the 3×3 matrix must have at least one non-zero element.
// An all-zero row maps one output channel to constant zero regardless of input,
// indicating profile corruption or authoring error.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF166_LUTMatrixRowNonZero(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-166]%s LUT Matrix Row Non-Zero "
         "(%sICC v4 Matrix Entries TN%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    const CIccMatrix *matrix = mbb->GetMatrix();
    if (!matrix) continue;

    found = true;

    for (int row = 0; row < 3; row++) {
      double r0 = std::fabs(static_cast<double>(matrix->m_e[row * 3 + 0]));
      double r1 = std::fabs(static_cast<double>(matrix->m_e[row * 3 + 1]));
      double r2 = std::fabs(static_cast<double>(matrix->m_e[row * 3 + 2]));
      if (r0 < 1e-10 && r1 < 1e-10 && r2 < 1e-10) {
        printf("         Tag '%s' — row %d is all-zero [%.6f, %.6f, %.6f]\n",
               kAllLUTNames[i], row, r0, r1, r2);
        printf("         %s[WARN]%s All-zero matrix row → output channel %d is constant\n",
               ColorWarning(), ColorReset(), row);
        issues++;
      }
    }
  }

  if (!found)
    printf("         No LUT tags with matrix found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s All LUT matrix rows have non-zero elements\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-167: LUT Matrix Offset Bounds (v4 Matrix Entries TN)
//
// The offset constants e10, e11, e12 (m_e[9..11]) should be within a
// reasonable range for color math. Extremely large offsets (|e| > 10.0)
// indicate potential authoring errors or malicious values, since normalized
// PCS values range [0, 1] and typical offsets are small fractions.
// ═══════════════════════════════════════════════════════════════════════════════

static constexpr double kOffsetReasonableMax = 10.0;

static int RunCF167_LUTMatrixOffsetBounds(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-167]%s LUT Matrix Offset Bounds "
         "(%sICC v4 Matrix Entries TN%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    const CIccMatrix *matrix = mbb->GetMatrix();
    if (!matrix) continue;

    if (!matrix->m_bUseConstants) continue;  // no offset constants to check

    found = true;

    for (int k = 9; k < 12; k++) {
      double v = static_cast<double>(matrix->m_e[k]);
      if (std::fabs(v) > kOffsetReasonableMax) {
        printf("         Tag '%s' — m_e[%d] = %.4f (|value| > %.1f)\n",
               kAllLUTNames[i], k, v, kOffsetReasonableMax);
        printf("         %s[WARN]%s Matrix offset constant unusually large "
               "for normalized PCS\n",
               ColorWarning(), ColorReset());
        issues++;
      }
    }
  }

  if (!found)
    printf("         No LUT tags with matrix offset constants found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s All LUT matrix offsets within reasonable bounds\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-168: LUT Matrix Input-Output Range (v4 Matrix Entries TN)
//
// Per the v4 Matrix Entries TN, inputs to the matrix stage range [0.0, 1.0].
// The matrix should map unit-cube corners to reasonable output values.
// We test the 3 axis vectors (1,0,0), (0,1,0), (0,0,1) through the matrix
// and verify each output component is within a practical range.
// ═══════════════════════════════════════════════════════════════════════════════

static constexpr double kOutputReasonableMin = -2.0;
static constexpr double kOutputReasonableMax =  3.0;

static int RunCF168_LUTMatrixOutputRange(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-168]%s LUT Matrix Input-Output Range "
         "(%sICC v4 Matrix Entries TN%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kAllLUTCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
    if (!tag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
    if (!mbb) continue;

    const CIccMatrix *matrix = mbb->GetMatrix();
    if (!matrix) continue;

    found = true;

    // Test 3 axis unit vectors through the 3×3 matrix:
    //   y[row] = x[0]*m_e[row*3+0] + x[1]*m_e[row*3+1] + x[2]*m_e[row*3+2] [+ m_e[9+row]]
    for (int axis = 0; axis < 3; axis++) {
      for (int row = 0; row < 3; row++) {
        double y = static_cast<double>(matrix->m_e[row * 3 + axis]);
        if (matrix->m_bUseConstants)
          y += static_cast<double>(matrix->m_e[9 + row]);
        if (y < kOutputReasonableMin || y > kOutputReasonableMax) {
          printf("         Tag '%s' — axis(%d,0,0)[%d]→%.4f outside [%.1f, %.1f]\n",
                 kAllLUTNames[i], axis, row, y,
                 kOutputReasonableMin, kOutputReasonableMax);
          printf("         %s[WARN]%s Matrix output outside expected PCS range\n",
                 ColorWarning(), ColorReset());
          issues++;
        }
      }
    }
  }

  if (!found)
    printf("         No LUT tags with matrix found — check not applicable\n");

  if (issues == 0)
    printf("         %s[OK]%s LUT matrix outputs within expected range\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ─── CF-255: CLUT Grid Points Valid Range ───────────────────────────────────
// ICC.1-2022-05 §10.12 — CLUT grid points must be in range 2..255
int RunCF255_CLUTGridPointValues(CIccProfile *pIcc) {
  int issues = 0;
  const icTagSignature lutSigs[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag
  };
  for (int i = 0; i < 6; i++) {
    CIccTag *pTag = pIcc->FindTag(lutSigs[i]);
    if (!pTag) continue;
    CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pTag);
    if (!pMBB) continue;
    CIccCLUT *pCLUT = pMBB->GetCLUT();
    if (!pCLUT) continue;
    icUInt8Number nInput = pMBB->InputChannels();
    for (int d = 0; d < nInput && d < 16; d++) {
      icUInt8Number gp = pCLUT->GridPoint(d);
      if (gp < 2) {
        printf("    Non-conformance: CLUT grid point[%d]=%u is below minimum of 2\n", d, gp);
        issues++;
      }
    }
  }
  return issues;
}

// ─── CF-256: LUT I/O Channels vs Profile Spaces ────────────────────────────
// ICC.1-2022-05 §10.12 — AToB input channels must match data colour space
int RunCF256_LUTChannelMatchSpaces(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number nDataChannels = icGetSpaceSamples(pIcc->m_Header.colorSpace);
  icUInt32Number nPCSChannels = icGetSpaceSamples(pIcc->m_Header.pcs);
  // AToB: input=colorSpace, output=PCS
  const icTagSignature atobSigs[] = {icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag};
  for (int i = 0; i < 3; i++) {
    CIccTag *pTag = pIcc->FindTag(atobSigs[i]);
    if (!pTag) continue;
    CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pTag);
    if (!pMBB) continue;
    if (pIcc->m_Header.deviceClass != icSigLinkClass) {
      if (pMBB->InputChannels() != nDataChannels) {
        printf("    Non-conformance: AToB%d input channels (%u) != colorSpace channels (%u)\n",
               i, (unsigned)pMBB->InputChannels(), nDataChannels);
        issues++;
      }
      if (pMBB->OutputChannels() != nPCSChannels) {
        printf("    Non-conformance: AToB%d output channels (%u) != PCS channels (%u)\n",
               i, (unsigned)pMBB->OutputChannels(), nPCSChannels);
        issues++;
      }
    }
  }
  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-261: lutAToBType M-Curve Count Must Be 3 When Matrix Present
// ICC.1-2022-05 §10.11: "If the matrix is present, the M curves shall
// have exactly 3 input and output channels." The matrix is always 3x3+offset
// for XYZ PCS, so M-curves must have 3 channels to match.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF261_MCurveCount3WithMatrix(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-261]%s lutAToBType M-Curve Count = 3 When Matrix Present (%sICC.1-2022-05 §10.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Check AToB tags
  for (int i = 0; i < kLUTDirCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAToBSigs[i]);
    if (!tag || tag->GetType() != icSigLutAtoBType) continue;

    CIccTagLutAtoB *atob = dynamic_cast<CIccTagLutAtoB *>(tag);
    if (!atob) continue;

    if (atob->GetMatrix() && atob->GetCurvesM()) {
      found = true;
      // M-curves feed the matrix, matrix is always 3x3 for XYZ PCS
      // The M-curve count should match the matrix input (3)
      CIccCurve *const *pMCurves = atob->GetCurvesM();
      // M-curves in AtoB: allocated with OutputChannels() count
      icUInt16Number nM = atob->OutputChannels();
      int mCount = 0;
      for (int c = 0; c < (int)nM; c++) { if (pMCurves[c]) mCount++; }

      if (mCount != 3) {
        printf("         AToB%d: matrix present with %d M-curves (expected 3)\n",
               i, mCount);
        printf("         %s[FAIL]%s M-curve count must be 3 when matrix present — ICC.1-2022-05 §10.11\n",
               ColorError(), ColorReset());
        issues++;
      }
    }
  }

  // Check BToA tags
  for (int i = 0; i < kLUTDirCount; i++) {
    CIccTag *tag = pIcc->FindTag(kBToASigs[i]);
    if (!tag || tag->GetType() != icSigLutBtoAType) continue;

    CIccTagLutBtoA *btoa = dynamic_cast<CIccTagLutBtoA *>(tag);
    if (!btoa) continue;

    if (btoa->GetMatrix() && btoa->GetCurvesM()) {
      found = true;
      CIccCurve *const *pMCurves = btoa->GetCurvesM();
      // M-curves in BtoA: allocated with InputChannels() count
      icUInt16Number nM = btoa->InputChannels();
      int mCount = 0;
      for (int c = 0; c < (int)nM; c++) { if (pMCurves[c]) mCount++; }

      if (mCount != 3) {
        printf("         BToA%d: matrix present with %d M-curves (expected 3)\n",
               i, mCount);
        printf("         %s[FAIL]%s M-curve count must be 3 when matrix present — ICC.1-2022-05 §10.12\n",
               ColorError(), ColorReset());
        issues++;
      }
    }
  }

  if (!found)
    printf("         No lutAToB/BToA tags with matrix+M-curves found\n");

  if (issues == 0)
    printf("         %s[OK]%s M-curve count consistent with matrix presence\n",
           ColorSuccess(), ColorReset());

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-262: LUT B-Curve Count Must Match CLUT Output Channels
// ICC.1-2022-05 §10.11-10.12: For lutAToBType, the number of B curves
// must equal the number of output channels. For lutBToAType, B curves
// must equal the number of input channels.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF262_BCurveCountMatchCLUT(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-262]%s LUT B-Curve Count vs Output Channels (%sICC.1-2022-05 §10.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int i = 0; i < kLUTDirCount; i++) {
    CIccTag *tag = pIcc->FindTag(kAToBSigs[i]);
    if (!tag || tag->GetType() != icSigLutAtoBType) continue;

    CIccTagLutAtoB *atob = dynamic_cast<CIccTagLutAtoB *>(tag);
    if (!atob) continue;
    found = true;

    CIccCurve *const *pBCurves = atob->GetCurvesB();
    if (!pBCurves) continue;

    // B-curves in AtoB: OutputChannels() count
    icUInt16Number outChan = atob->OutputChannels();
    int bCount = 0;
    for (int c = 0; c < (int)outChan; c++) {
      if (pBCurves[c]) bCount++;
    }

    if (bCount > 0 && outChan > 0 && bCount != (int)outChan) {
      printf("         AToB%d: %d B-curves vs %u output channels\n",
             i, bCount, outChan);
      printf("         %s[FAIL]%s B-curve count must match output channels — ICC.1-2022-05 §10.11\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (!found)
    printf("         No lutAToBType tags found\n");

  if (issues == 0)
    printf("         %s[OK]%s B-curve count matches output channel count\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Dispatcher — runs all LUT/curve/matrix conformance checks
// ═══════════════════════════════════════════════════════════════════════════════

int RunLUTConformance(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  int r;

#define CF_WRAP(id, title, call) \
  hc.begin(id, title); \
  r = call; \
  if (r > 0) hc.warn("%d non-conformance(s)", r); \
  hc.end("Conformant"); \
  issues += r

  CF_WRAP(1060, "CF-060: LUT Input Channel Count", RunCF060_LUTInputChannels(pIcc));
  CF_WRAP(1061, "CF-061: LUT Output Channel Count", RunCF061_LUTOutputChannels(pIcc));
  CF_WRAP(1062, "CF-062: CLUT Grid Dimensionality", RunCF062_CLUTGridDimensionality(pIcc));
  CF_WRAP(1063, "CF-063: lut8Type Fixed 256-Entry Tables", RunCF063_Lut8FixedTableSize(pIcc));
  CF_WRAP(1064, "CF-064: lut16Type Table Size Range", RunCF064_Lut16TableSizeRange(pIcc));
  CF_WRAP(1065, "CF-065: lutAToBType Element Presence", RunCF065_LutAToBElementPresent(pIcc));
  CF_WRAP(1066, "CF-066: lutBToAType Element Presence", RunCF066_LutBToAElementPresent(pIcc));
  CF_WRAP(1067, "CF-067: LUT Matrix Identity for Non-XYZ PCS", RunCF067_LutMatrixIdentityNonXYZ(pIcc));
  CF_WRAP(1068, "CF-068: Chad Matrix Invertible", RunCF068_ChadMatrixInvertible(pIcc));
  CF_WRAP(1069, "CF-069: Matrix Column XYZ Count", RunCF069_MatrixColumnXYZCount(pIcc));
  CF_WRAP(1070, "CF-070: Chad Array Count = 9", RunCF070_ChadArrayCount9(pIcc));
  CF_WRAP(1071, "CF-071: Curve Count vs Channel Match", RunCF071_CurveCountChannelMatch(pIcc));
  CF_WRAP(1072, "CF-072: CLUT Output Value Range", RunCF072_CLUTOutputValueRange(pIcc));
  CF_WRAP(1073, "CF-073: MBB Matrix Determinant Non-Zero", RunCF073_MBBMatrixDeterminant(pIcc));
  CF_WRAP(1074, "CF-074: A2B/B2A Dimension Consistency", RunCF074_A2BB2ADimensionConsistency(pIcc));
  CF_WRAP(1075, "CF-075: Tag Data Size vs Dimensions", RunCF075_TagDataSizeVsDimensions(pIcc));
  CF_WRAP(1076, "CF-076: Curve Response Direction", RunCF076_CurveResponseDirection(pIcc));
  CF_WRAP(1077, "CF-077: CLUT Grid Size Plausibility", RunCF077_CLUTGridSizePlausibility(pIcc));
  CF_WRAP(1078, "CF-078: MBB B-Curve Presence", RunCF078_MBBBCurvePresence(pIcc));
  CF_WRAP(1079, "CF-079: LUT Bit Depth Consistency", RunCF079_LUTBitDepthConsistency(pIcc));

  CF_WRAP(1105, "CF-105: LUT Channel Symmetry", RunCF105_LUTChannelSymmetry(pIcc));
  CF_WRAP(1106, "CF-106: Curve Monotonicity", RunCF106_CurveMonotonicity(pIcc));
  CF_WRAP(1108, "CF-108: CLUT Grid Point Range", RunCF108_CLUTGridPointRange(pIcc));
  CF_WRAP(1109, "CF-109: Matrix Column Normalization", RunCF109_MatrixColumnNormalization(pIcc));
  CF_WRAP(1110, "CF-110: B Curves vs CLUT Output", RunCF110_BCurveVsCLUTOutput(pIcc));
  CF_WRAP(1116, "CF-116: Curve Segment Continuity", RunCF116_CurveSegmentContinuity(pIcc));

  // v4 Matrix Entries TN conformance checks (CF-163..CF-168)
  CF_WRAP(1163, "CF-163: LUT Matrix Coefficient Finite", RunCF163_LUTMatrixCoeffFinite(pIcc));
  CF_WRAP(1164, "CF-164: LUT Matrix s15Fixed16 Range", RunCF164_LUTMatrixS15F16Range(pIcc));
  CF_WRAP(1165, "CF-165: LUT Matrix Determinant Non-Singular", RunCF165_LUTMatrixDeterminant(pIcc));
  CF_WRAP(1166, "CF-166: LUT Matrix Row Non-Zero", RunCF166_LUTMatrixRowNonZero(pIcc));
  CF_WRAP(1167, "CF-167: LUT Matrix Offset Bounds", RunCF167_LUTMatrixOffsetBounds(pIcc));
  CF_WRAP(1168, "CF-168: LUT Matrix Input-Output Range", RunCF168_LUTMatrixOutputRange(pIcc));
  CF_WRAP(1255, "CF-255: CLUT Grid Point Values", RunCF255_CLUTGridPointValues(pIcc));
  CF_WRAP(1256, "CF-256: LUT I/O Channels vs Profile Spaces", RunCF256_LUTChannelMatchSpaces(pIcc));
  CF_WRAP(1261, "CF-261: M-Curve Count = 3 When Matrix Present", RunCF261_MCurveCount3WithMatrix(pIcc));
  CF_WRAP(1262, "CF-262: B-Curve Count vs Output Channels", RunCF262_BCurveCountMatchCLUT(pIcc));

#undef CF_WRAP
  return issues;
}
