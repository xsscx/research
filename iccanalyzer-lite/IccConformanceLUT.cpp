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

    CIccMatrix *matrix = mbb->GetMatrix();
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
// Dispatcher — runs all LUT/curve/matrix conformance checks
// ═══════════════════════════════════════════════════════════════════════════════

int RunLUTConformance(CIccProfile *pIcc) {
  int issues = 0;
  issues += RunCF060_LUTInputChannels(pIcc);
  issues += RunCF061_LUTOutputChannels(pIcc);
  issues += RunCF062_CLUTGridDimensionality(pIcc);
  issues += RunCF063_Lut8FixedTableSize(pIcc);
  issues += RunCF064_Lut16TableSizeRange(pIcc);
  issues += RunCF065_LutAToBElementPresent(pIcc);
  issues += RunCF066_LutBToAElementPresent(pIcc);
  issues += RunCF067_LutMatrixIdentityNonXYZ(pIcc);
  issues += RunCF068_ChadMatrixInvertible(pIcc);
  issues += RunCF069_MatrixColumnXYZCount(pIcc);
  issues += RunCF070_ChadArrayCount9(pIcc);
  return issues;
}
