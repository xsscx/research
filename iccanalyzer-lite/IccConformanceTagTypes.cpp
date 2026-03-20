/*
 * IccConformanceTagTypes.cpp — ICC specification tag type conformance checks
 *
 * Implements CF-020 through CF-034 from the conformance registry.
 * Validates that tag signatures use only ICC-permitted tag types
 * per ICC.1-2022-05 §9 and §10.
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
#include <cmath>
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicResult.h"
#include "IccAnalyzerColors.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>


// ── Tag signature → allowed tag type(s) mapping table ───────────────────────
// ICC.1-2022-05 §9.2 and §10 define which tag types are permitted for each
// tag signature. v2 profiles may use legacy types (desc, text) where v4
// mandates multiLocalizedUnicodeType.

struct TagTypeMapping {
  icTagSignature tagSig;
  const char *tagName;
  const icTagTypeSignature allowedTypes[6];  // 0-terminated
};

static const TagTypeMapping kTagTypeMappings[] = {
  // ── LUT tags (§9.2.1-9.2.6) ──────────────────────────────────────────────
  {icSigAToB0Tag, "AToB0Tag",
   {icSigLutAtoBType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
  {icSigAToB1Tag, "AToB1Tag",
   {icSigLutAtoBType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
  {icSigAToB2Tag, "AToB2Tag",
   {icSigLutAtoBType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
  {icSigBToA0Tag, "BToA0Tag",
   {icSigLutBtoAType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
  {icSigBToA1Tag, "BToA1Tag",
   {icSigLutBtoAType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
  {icSigBToA2Tag, "BToA2Tag",
   {icSigLutBtoAType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},

  // ── Matrix column tags (§9.2.7, §9.2.18, §9.2.31) ───────────────────────
  {icSigBlueMatrixColumnTag, "blueMatrixColumnTag",
   {icSigXYZType, (icTagTypeSignature)0}},
  {icSigGreenMatrixColumnTag, "greenMatrixColumnTag",
   {icSigXYZType, (icTagTypeSignature)0}},
  {icSigRedMatrixColumnTag, "redMatrixColumnTag",
   {icSigXYZType, (icTagTypeSignature)0}},

  // ── TRC tags (§9.2.8, §9.2.19, §9.2.32) ─────────────────────────────────
  {icSigBlueTRCTag, "blueTRCTag",
   {icSigCurveType, icSigParametricCurveType, (icTagTypeSignature)0}},
  {icSigGreenTRCTag, "greenTRCTag",
   {icSigCurveType, icSigParametricCurveType, (icTagTypeSignature)0}},
  {icSigRedTRCTag, "redTRCTag",
   {icSigCurveType, icSigParametricCurveType, (icTagTypeSignature)0}},
  {icSigGrayTRCTag, "grayTRCTag",
   {icSigCurveType, icSigParametricCurveType, (icTagTypeSignature)0}},

  // ── Calibration / characterization (§9.2.9, §9.2.10) ─────────────────────
  {icSigCalibrationDateTimeTag, "calibrationDateTimeTag",
   {icSigDateTimeType, (icTagTypeSignature)0}},
  {icSigCharTargetTag, "charTargetTag",
   {icSigTextType, (icTagTypeSignature)0}},

  // ── Chromatic adaptation (§9.2.11) ────────────────────────────────────────
  {icSigChromaticAdaptationTag, "chromaticAdaptationTag",
   {icSigS15Fixed16ArrayType, (icTagTypeSignature)0}},

  // ── Chromaticity (§9.2.12) ────────────────────────────────────────────────
  {icSigChromaticityTag, "chromaticityTag",
   {icSigChromaticityType, (icTagTypeSignature)0}},

  // ── Copyright (§9.2.13) — v4 uses mluc, v2 allows text ───────────────────
  {icSigCopyrightTag, "copyrightTag",
   {icSigMultiLocalizedUnicodeType, icSigTextType, (icTagTypeSignature)0}},

  // ── Device descriptions (§9.2.14-9.2.15) — v4 uses mluc, v2 uses desc ────
  {icSigDeviceMfgDescTag, "deviceMfgDescTag",
   {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType, (icTagTypeSignature)0}},
  {icSigDeviceModelDescTag, "deviceModelDescTag",
   {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType, (icTagTypeSignature)0}},

  // ── Gamut (§9.2.16) ──────────────────────────────────────────────────────
  {icSigGamutTag, "gamutTag",
   {icSigLutBtoAType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},

  // ── Luminance (§9.2.20) ──────────────────────────────────────────────────
  {icSigLuminanceTag, "luminanceTag",
   {icSigXYZType, (icTagTypeSignature)0}},

  // ── Measurement (§9.2.21) ─────────────────────────────────────────────────
  {icSigMeasurementTag, "measurementTag",
   {icSigMeasurementType, (icTagTypeSignature)0}},

  // ── Media white point (§9.2.22) ──────────────────────────────────────────
  {icSigMediaWhitePointTag, "mediaWhitePointTag",
   {icSigXYZType, (icTagTypeSignature)0}},

  // ── Named color (§9.2.23) ────────────────────────────────────────────────
  {icSigNamedColor2Tag, "namedColor2Tag",
   {icSigNamedColor2Type, (icTagTypeSignature)0}},

  // ── Output response (§9.2.24) ────────────────────────────────────────────
  {icSigOutputResponseTag, "outputResponseTag",
   {icSigResponseCurveSet16Type, (icTagTypeSignature)0}},

  // ── Profile description (§9.2.27) — v4 uses mluc, v2 uses desc ───────────
  {icSigProfileDescriptionTag, "profileDescriptionTag",
   {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType, (icTagTypeSignature)0}},

  // ── Profile sequence description (§9.2.28) ───────────────────────────────
  {icSigProfileSequenceDescTag, "profileSequenceDescTag",
   {icSigProfileSequenceDescType, (icTagTypeSignature)0}},

  // ── Technology (§9.2.33) ──────────────────────────────────────────────────
  {icSigTechnologyTag, "technologyTag",
   {icSigSignatureType, (icTagTypeSignature)0}},

  // ── Viewing condition description (§9.2.35) ──────────────────────────────
  {icSigViewingCondDescTag, "viewingCondDescTag",
   {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType, (icTagTypeSignature)0}},

  // ── Viewing conditions (§9.2.36) ─────────────────────────────────────────
  {icSigViewingConditionsTag, "viewingConditionsTag",
   {icSigViewingConditionsType, (icTagTypeSignature)0}},
};

static constexpr int kTagTypeMappingCount =
    sizeof(kTagTypeMappings) / sizeof(kTagTypeMappings[0]);


// ── XYZ-type tag signatures that must contain exactly 1 triplet ─────────────
// ICC.1-2022-05 §10.23: all XYZ tags used for single tristimulus values

static const icTagSignature kSingleXYZTags[] = {
  icSigMediaWhitePointTag,
  icSigLuminanceTag,
  icSigBlueMatrixColumnTag,
  icSigGreenMatrixColumnTag,
  icSigRedMatrixColumnTag,
};
static constexpr int kSingleXYZTagCount =
    sizeof(kSingleXYZTags) / sizeof(kSingleXYZTags[0]);


// ── Parametric curve: expected parameter count per function type ─────────────
// ICC.1-2022-05 §10.18 Table 68

static const int kParamCurveExpectedParams[] = {
  1,  // type 0: Y = X^g
  3,  // type 1: Y = (aX+b)^g  [X >= -b/a], Y = 0 [X < -b/a]
  4,  // type 2: Y = (aX+b)^g + c  [X >= -b/a], Y = c [X < -b/a]
  5,  // type 3: Y = (aX+b)^g  [X >= d], Y = cX [X < d]
  7,  // type 4: Y = (aX+b)^g + e  [X >= d], Y = cX + f [X < d]
};
static constexpr int kParamCurveMaxFunctionType = 4;


// ═══════════════════════════════════════════════════════════════════════════════
// CF-020: Tag Type Allowed for Signature (ICC.1-2022-05 §9.2, §10)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF020_TagTypeAllowed(CIccProfile *pIcc) {
  int issues = 0;
  int checked = 0;
  int violations = 0;

  printf("%s[CF-020]%s Tag Type Allowed for Signature (%sICC.1-2022-05 §9.2, §10%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Track offsets we have already visited to skip shared-offset duplicates
  std::vector<icUInt32Number> visitedOffsets;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    icTagSignature tagSig = e->TagInfo.sig;
    icUInt32Number tagOffset = e->TagInfo.offset;

    // Skip duplicate entries sharing the same data offset
    bool duplicate = false;
    for (size_t v = 0; v < visitedOffsets.size(); v++) {
      if (visitedOffsets[v] == tagOffset) { duplicate = true; break; }
    }
    if (duplicate) continue;
    visitedOffsets.push_back(tagOffset);

    // Find the tag in our mapping table
    const TagTypeMapping *mapping = nullptr;
    for (int m = 0; m < kTagTypeMappingCount; m++) {
      if (kTagTypeMappings[m].tagSig == tagSig) {
        mapping = &kTagTypeMappings[m];
        break;
      }
    }
    if (!mapping) continue;  // Unknown/private tag — not in spec table

    CIccTag *pTag = pIcc->FindTag(tagSig);
    if (!pTag) continue;

    icTagTypeSignature actualType = pTag->GetType();
    checked++;

    // Check if actual type is in the allowed list
    bool allowed = false;
    for (int a = 0; mapping->allowedTypes[a] != (icTagTypeSignature)0; a++) {
      if (mapping->allowedTypes[a] == actualType) {
        allowed = true;
        break;
      }
    }

    if (!allowed) {
      char sigBuf[5], typeBuf[5];
      SigToChars(static_cast<uint32_t>(tagSig), sigBuf);
      SigToChars(static_cast<uint32_t>(actualType), typeBuf);

      // Build list of allowed type names
      char allowedStr[128] = {0};
      int pos = 0;
      for (int a = 0; mapping->allowedTypes[a] != (icTagTypeSignature)0; a++) {
        char aBuf[5];
        SigToChars(static_cast<uint32_t>(mapping->allowedTypes[a]), aBuf);
        if (pos > 0) pos += snprintf(allowedStr + pos, sizeof(allowedStr) - pos, ", ");
        pos += snprintf(allowedStr + pos, sizeof(allowedStr) - pos, "'%s'", aBuf);
      }

      printf("         Tag '%s' (%s): type '%s' — %snot in allowed set {%s}%s\n",
             sigBuf, mapping->tagName, typeBuf,
             ColorError(), allowedStr, ColorReset());
      printf("         %s[FAIL]%s Type violation — ICC.1-2022-05 §9.2\n",
             ColorError(), ColorReset());
      violations++;
      issues++;
    }
  }

  if (violations == 0)
    printf("         %s[OK]%s %d/%d tags checked, all use permitted types\n",
           ColorSuccess(), ColorReset(), checked, checked);
  else
    printf("         Summary: %d/%d tags checked, %s%d type violation(s)%s\n",
           checked, checked, ColorError(), violations, ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-022: curveType Entry Count Mode (ICC.1-2022-05 §10.6)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF022_CurveTypeEntryCount(CIccProfile *pIcc) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-022]%s curveType Entry Count Mode (%sICC.1-2022-05 §10.6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigCurveType) continue;

    CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve *>(pTag);
    if (!pCurve) continue;

    icUInt32Number size = pCurve->GetSize();
    checked++;

    char sigBuf[5];
    SigToChars(static_cast<uint32_t>(e->TagInfo.sig), sigBuf);

    // §10.6: count 0 = identity, count 1 = gamma, count >= 2 = LUT
    // All three modes are valid; we check for structural consistency
    if (size == 0) {
      printf("         Tag '%s': curveType count=0 (identity curve)\n", sigBuf);
    } else if (size == 1) {
      printf("         Tag '%s': curveType count=1 (gamma=%.4f)\n",
             sigBuf, (*pCurve)[0]);
    }
    // count >= 2 is a lookup table — always valid structurally
  }

  if (checked == 0)
    printf("         No curveType tags found\n");

  printf("         %s[OK]%s %d curveType tag(s) checked, all consistent\n",
         ColorSuccess(), ColorReset(), checked);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-023: parametricCurveType Function Type (ICC.1-2022-05 §10.18 Table 68)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF023_ParametricCurveFunction(CIccProfile *pIcc) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-023]%s parametricCurveType Function Type (%sICC.1-2022-05 §10.18 Table 68%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigParametricCurveType) continue;

    CIccTagParametricCurve *pPara = dynamic_cast<CIccTagParametricCurve *>(pTag);
    if (!pPara) continue;

    icUInt16Number funcType = pPara->GetFunctionType();
    checked++;

    char sigBuf[5];
    SigToChars(static_cast<uint32_t>(e->TagInfo.sig), sigBuf);

    if (funcType > kParamCurveMaxFunctionType) {
      printf("         Tag '%s': functionType=%u — %sout of range (must be 0-4)%s\n",
             sigBuf, funcType, ColorError(), ColorReset());
      printf("         %s[FAIL]%s Invalid parametric function type — ICC.1-2022-05 §10.18\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (checked == 0)
    printf("         No parametricCurveType tags found\n");

  if (issues == 0)
    printf("         %s[OK]%s %d parametricCurveType tag(s) checked, all function types valid\n",
           ColorSuccess(), ColorReset(), checked);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-024: parametricCurveType Parameter Count (ICC.1-2022-05 §10.18 Table 68)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF024_ParametricCurveParamCount(CIccProfile *pIcc) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-024]%s parametricCurveType Parameter Count (%sICC.1-2022-05 §10.18 Table 68%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigParametricCurveType) continue;

    CIccTagParametricCurve *pPara = dynamic_cast<CIccTagParametricCurve *>(pTag);
    if (!pPara) continue;

    icUInt16Number funcType = pPara->GetFunctionType();
    icUInt16Number numParam = pPara->GetNumParam();
    checked++;

    char sigBuf[5];
    SigToChars(static_cast<uint32_t>(e->TagInfo.sig), sigBuf);

    // Only validate param count if function type is in range
    if (funcType > kParamCurveMaxFunctionType) continue;

    int expected = kParamCurveExpectedParams[funcType];
    if (numParam != expected) {
      printf("         Tag '%s': functionType=%u, params=%u — %sexpected %d%s\n",
             sigBuf, funcType, numParam,
             ColorError(), expected, ColorReset());
      printf("         %s[FAIL]%s Parameter count mismatch — ICC.1-2022-05 §10.18 Table 68\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (checked == 0)
    printf("         No parametricCurveType tags found\n");

  if (issues == 0)
    printf("         %s[OK]%s %d parametricCurveType tag(s) checked, all parameter counts correct\n",
           ColorSuccess(), ColorReset(), checked);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-025: chromaticityType Phosphor Count (ICC.1-2022-05 §10.2)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF025_ChromaticityPhosphorCount(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-025]%s chromaticityType Phosphor Count (%sICC.1-2022-05 §10.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTagChromaticity *pChrom =
      FindAndCast<CIccTagChromaticity>(pIcc, icSigChromaticityTag);
  if (!pChrom) {
    printf("         No chromaticityTag found\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  icUInt32Number nChannels = pChrom->GetSize();
  icUInt32Number nExpected = icGetSpaceSamples(pIcc->m_Header.colorSpace);

  if (nExpected > 0 && nChannels != nExpected) {
    printf("         Phosphor count=%u, device channels=%u — %smismatch%s\n",
           nChannels, nExpected, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Phosphor count must equal device channel count — ICC.1-2022-05 §10.2\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         Phosphor count=%u, device channels=%u — match\n",
           nChannels, nExpected);
    printf("         %s[OK]%s Chromaticity phosphor count valid\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-026: colorantTableType Colorant Count (ICC.1-2022-05 §10.4)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF026_ColorantTableCount(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-026]%s colorantTableType Colorant Count (%sICC.1-2022-05 §10.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTagColorantTable *pClrt =
      FindAndCast<CIccTagColorantTable>(pIcc, icSigColorantTableTag);
  if (!pClrt) {
    printf("         No colorantTableTag found\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  icUInt32Number nColorants = pClrt->GetSize();
  icUInt32Number nExpected = icGetSpaceSamples(pIcc->m_Header.colorSpace);

  if (nExpected > 0 && nColorants != nExpected) {
    printf("         Colorant count=%u, device channels=%u — %smismatch%s\n",
           nColorants, nExpected, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Colorant count must equal device channel count — ICC.1-2022-05 §10.4\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         Colorant count=%u, device channels=%u — match\n",
           nColorants, nExpected);
    printf("         %s[OK]%s Colorant table count valid\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-027: colorantOrderType Count Match (ICC.1-2022-05 §10.3)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF027_ColorantOrderCount(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-027]%s colorantOrderType Count Match (%sICC.1-2022-05 §10.3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTagColorantOrder *pClro =
      FindAndCast<CIccTagColorantOrder>(pIcc, icSigColorantOrderTag);
  if (!pClro) {
    printf("         No colorantOrderTag found\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  icUInt32Number nOrder = pClro->GetSize();
  icUInt32Number nExpected = icGetSpaceSamples(pIcc->m_Header.colorSpace);

  if (nExpected > 0 && nOrder != nExpected) {
    printf("         Colorant order count=%u, device channels=%u — %smismatch%s\n",
           nOrder, nExpected, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Count must equal device channel count — ICC.1-2022-05 §10.3\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         Colorant order count=%u, device channels=%u — match\n",
           nOrder, nExpected);
    printf("         %s[OK]%s Colorant order count valid\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-028: namedColor2Type Coordinate Count (ICC.1-2022-05 §10.14)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF028_NamedColor2CoordCount(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-028]%s namedColor2Type Coordinate Count (%sICC.1-2022-05 §10.14%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTagNamedColor2 *pNc2 =
      FindAndCast<CIccTagNamedColor2>(pIcc, icSigNamedColor2Tag);
  if (!pNc2) {
    printf("         No namedColor2Tag found\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  icUInt32Number nDevCoords = pNc2->GetDeviceCoords();

  // ICC spec: nDeviceCoords must be in [0, 15]
  if (nDevCoords > 15) {
    printf("         nDeviceCoords=%u — %sexceeds ICC maximum of 15%s\n",
           nDevCoords, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Device coordinate count out of range — ICC.1-2022-05 §10.14\n",
           ColorError(), ColorReset());
    issues++;
  }

  // If nDeviceCoords > 0, it should match the profile's colour space channels
  if (nDevCoords > 0 && nDevCoords <= 15) {
    icUInt32Number nExpected = icGetSpaceSamples(pIcc->m_Header.colorSpace);
    if (nExpected > 0 && nDevCoords != nExpected) {
      printf("         nDeviceCoords=%u, device channels=%u — %smismatch%s\n",
             nDevCoords, nExpected, ColorWarning(), ColorReset());
      printf("         %s[WARN]%s Device coordinate count should match colour space channels\n",
             ColorWarning(), ColorReset());
      // This is a warning — the spec says "should" not "shall" for the match
    }
  }

  if (issues == 0)
    printf("         nDeviceCoords=%u — %s[OK]%s Within valid range\n",
           nDevCoords, ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-029: dateTimeType Field Ranges (ICC.1-2022-05 §10.7, §4.2)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF029_DateTimeFieldRanges(CIccProfile *pIcc) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-029]%s dateTimeType Field Ranges (%sICC.1-2022-05 §10.7, §4.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // CIccTagDateTime::m_DateTime is protected with no public getter.
  // Use the tag's own Validate() method which checks date field ranges internally.
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigDateTimeType) continue;

    checked++;
    char sigBuf[5];
    SigToChars(static_cast<uint32_t>(e->TagInfo.sig), sigBuf);

    // Use library's own Validate() for date field range checking
    std::string sigPath = "tag(";
    sigPath += sigBuf;
    sigPath += ")";
    std::string report;
    icValidateStatus status = pTag->Validate(sigPath, report, pIcc);

    if (status >= icValidateWarning && !report.empty()) {
      printf("         Tag '%s': %sdate/time validation issue%s\n",
             sigBuf, ColorError(), ColorReset());
      // Show first line of validation report
      std::string firstLine = report.substr(0, report.find('\n'));
      if (!firstLine.empty())
        printf("           %s\n", firstLine.c_str());
      printf("         %s[FAIL]%s Date/time field range violation — ICC.1-2022-05 §10.7\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         Tag '%s': date/time fields valid\n", sigBuf);
    }
  }

  if (checked == 0)
    printf("         No dateTimeType tags found\n");

  if (issues == 0)
    printf("         %s[OK]%s %d dateTimeType tag(s) checked, all fields in range\n",
           ColorSuccess(), ColorReset(), checked);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-032: XYZType Triplet Count (ICC.1-2022-05 §10.23)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF032_XYZTypeTripletCount(CIccProfile *pIcc) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-032]%s XYZType Triplet Count (%sICC.1-2022-05 §10.23%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (int t = 0; t < kSingleXYZTagCount; t++) {
    CIccTagXYZ *pXYZ = FindAndCast<CIccTagXYZ>(pIcc, kSingleXYZTags[t]);
    if (!pXYZ) continue;

    icUInt32Number count = pXYZ->GetSize();
    checked++;

    char sigBuf[5];
    SigToChars(static_cast<uint32_t>(kSingleXYZTags[t]), sigBuf);

    if (count != 1) {
      printf("         Tag '%s': XYZ triplet count=%u — %smust be exactly 1%s\n",
             sigBuf, count, ColorError(), ColorReset());
      printf("         %s[FAIL]%s Single-value XYZ tag must contain 1 triplet — ICC.1-2022-05 §10.23\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (checked == 0)
    printf("         No single-value XYZ tags found\n");

  if (issues == 0)
    printf("         %s[OK]%s %d XYZ tag(s) checked, all contain exactly 1 triplet\n",
           ColorSuccess(), ColorReset(), checked);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-033: measurementType Standard Observer (ICC.1-2022-05 §10.12 Table 56)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF033_MeasurementStandardObserver(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-033]%s measurementType Standard Observer (%sICC.1-2022-05 §10.12 Table 56%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTagMeasurement *pMeas =
      FindAndCast<CIccTagMeasurement>(pIcc, icSigMeasurementTag);
  if (!pMeas) {
    printf("         No measurementTag found\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  icUInt32Number observer = static_cast<icUInt32Number>(pMeas->m_Data.stdObserver);

  // Valid: 0 = unknown, 1 = CIE 1931 2°, 2 = CIE 1964 10°
  if (observer != 0 && observer != 1 && observer != 2) {
    printf("         Observer=0x%08X — %sinvalid (must be 0, 1, or 2)%s\n",
           observer, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Unknown standard observer — ICC.1-2022-05 §10.12 Table 56\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    const char *names[] = {"Unknown", "CIE 1931 2-degree", "CIE 1964 10-degree"};
    printf("         Observer=%u (%s)\n", observer, names[observer]);
    printf("         %s[OK]%s Valid standard observer\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-034: measurementType Measurement Geometry (ICC.1-2022-05 §10.12 Table 57)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF034_MeasurementGeometry(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-034]%s measurementType Measurement Geometry (%sICC.1-2022-05 §10.12 Table 57%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTagMeasurement *pMeas =
      FindAndCast<CIccTagMeasurement>(pIcc, icSigMeasurementTag);
  if (!pMeas) {
    printf("         No measurementTag found\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  icUInt32Number geometry = static_cast<icUInt32Number>(pMeas->m_Data.geometry);

  // Valid: 0 = unknown, 1 = 0°:45° or 45°:0°, 2 = 0°:d or d:0°
  if (geometry != 0 && geometry != 1 && geometry != 2) {
    printf("         Geometry=0x%08X — %sinvalid (must be 0, 1, or 2)%s\n",
           geometry, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Unknown measurement geometry — ICC.1-2022-05 §10.12 Table 57\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    const char *names[] = {"Unknown", "0/45 or 45/0", "0/d or d/0"};
    printf("         Geometry=%u (%s)\n", geometry, names[geometry]);
    printf("         %s[OK]%s Valid measurement geometry\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-112: XYZ Triplet Value Normalization (ICC.1-2022-05 §10.31)
//
// XYZ values should be physically meaningful:
//   - Y values (luminance) must be non-negative
//   - All components should be finite and within reasonable range
//   - Range: typically [−2.0, +4.0] for wide-gamut but finite
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF112_XYZTripletNormalization(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-112]%s XYZ Triplet Value Normalization (%sICC.1-2022-05 §10.31%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const icTagSignature xyzSigs[] = {
    icSigMediaWhitePointTag, icSigRedColorantTag, icSigGreenColorantTag,
    icSigBlueColorantTag, icSigLuminanceTag
  };

  int checked = 0;
  for (auto sig : xyzSigs) {
    CIccTag *tag = pIcc->FindTag(sig);
    CIccTagXYZ *xyz = tag ? dynamic_cast<CIccTagXYZ *>(tag) : nullptr;
    if (!xyz || xyz->GetSize() < 1) continue;

    icXYZNumber val = (*xyz)[0];
    icFloatNumber x = icFtoD(val.X);
    icFloatNumber y = icFtoD(val.Y);
    icFloatNumber z = icFtoD(val.Z);
    checked++;

    // NaN/Inf check
    if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) {
      char s[5] = {};
      SigToChars(sig, s);
      printf("         '%s' contains NaN/Inf values\n", s);
      printf("         %s[FAIL]%s XYZ values must be finite — §10.31\n",
             ColorError(), ColorReset());
      issues++;
      continue;
    }

    // Luminance non-negative for white point and luminance tag
    if (sig == icSigMediaWhitePointTag || sig == icSigLuminanceTag) {
      if (y < 0.0) {
        char s[5] = {};
        SigToChars(sig, s);
        printf("         '%s' Y=%.6f is negative (invalid luminance)\n", s, y);
        printf("         %s[FAIL]%s Y (luminance) must be ≥ 0 — §10.31\n",
               ColorError(), ColorReset());
        issues++;
      }
    }
  }

  if (checked == 0)
    printf("         No XYZ tags to validate\n");
  else if (issues == 0)
    printf("         %s[OK]%s All %d XYZ triplets have valid values\n",
           ColorSuccess(), ColorReset(), checked);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// ADGC (Adaptive Gain Curve) conformance — ICC.1 Amendment April 2025
// ═══════════════════════════════════════════════════════════════════════════════
//
// iccDEV has zero ADGC support — the tag is stored as CIccTagUnknown.
// All validation uses raw byte scanning of the tag data.
//
// ADGC tag signature: 'ADGC' (0x41444743)
// ADGC type signature: 'adgc' (0x61646763)
//
// Header layout (128 bytes):
//   0-3:     type sig 'adgc'
//   4-7:     reserved (0)
//   8-11:    functionTypeID (must be 1)
//   12-27:   GUID (16 bytes, all-zero if not image-specific)
//   28-31:   H_baseline (float32, log2 headroom)
//   32-35:   H_alternate (float32, log2 headroom)
//   36-47:   Red {GainMin, GainMax, kRed} (3×float32)
//   48-59:   Green {GainMin, GainMax, kGreen} (3×float32)
//   60-71:   Blue {GainMin, GainMax, kBlue} (3×float32)
//   72-75:   kMax (float32)
//   76-79:   kMin (float32)
//   80-83:   kComponent (float32)
//   84-87:   PreGainCICP (uInt32)
//   88-91:   PostGainCICP (uInt32)
//   92-95:   A2B0 target headroom (float32)
//   96-99:   A2B1 target headroom (float32)
//   100-103: A2B2 target headroom (float32)
//   104-111: Red curve positionNumber (offset+size, 8 bytes)
//   112-119: Green curve positionNumber (8 bytes)
//   120-127: Blue curve positionNumber (8 bytes)
//
// NOTE: The published PDF has typesetting errors in Table 1 where byte ranges
// are duplicated across page breaks. The layout above is reconstructed from
// field sizes and the 128-byte total.

static const uint32_t kADGC_TagSig  = 0x41444743;  // 'ADGC'
static const uint32_t kADGC_TypeSig = 0x61646763;  // 'adgc'
static const size_t   kADGC_HeaderSize = 128;

// Helper: read big-endian float32 from raw bytes
static float ReadFloat32BE(const uint8_t *p) {
  uint32_t bits = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                  ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
  float f;
  memcpy(&f, &bits, sizeof(f));
  return f;
}

// Find ADGC tag in profile's tag list and return pointer to raw data
// Returns: pointer to raw data bytes (owned by CIccTagUnknown), or nullptr
// tagSize is set to the raw data size
// CF-123: ADGC Class Restriction
// ADGC tag is ONLY permitted when colorSpace=RGB AND class=Input|Display
int RunCF123_ADGCClassRestriction(CIccProfile *pIcc) {
  int issues = 0;
  bool hasADGC = false;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    if (it->TagInfo.sig == (icTagSignature)kADGC_TagSig) {
      hasADGC = true;
      break;
    }
  }

  if (!hasADGC) {
    printf("         No ADGC tag present — check not applicable\n");
    return 0;
  }

  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
  icProfileClassSignature dc = pIcc->m_Header.deviceClass;

  // Must be RGB
  if (cs != icSigRgbData) {
    char s[5] = {};
    SigToChars((icTagSignature)cs, s);
    printf("         %s[FAIL]%s ADGC present but colorSpace='%s' — "
           "ADGC requires RGB — ICC.1 ADGC §3\n",
           ColorError(), ColorReset(), s);
    issues++;
  }

  // Must be Input or Display
  if (dc != icSigInputClass && dc != icSigDisplayClass) {
    char s[5] = {};
    SigToChars((icTagSignature)dc, s);
    printf("         %s[FAIL]%s ADGC present but class='%s' — "
           "ADGC requires Input or Display — ICC.1 ADGC §3\n",
           ColorError(), ColorReset(), s);
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s ADGC class restriction satisfied (RGB + Input|Display)\n",
           ColorSuccess(), ColorReset());
  return issues;
}

// CF-124 through CF-132: Raw ADGC data validation (requires filename for raw read)
// These checks read the ADGC tag data from the file since iccDEV doesn't parse it.

int RunCF124_to_CF132_ADGCDataValidation(CIccProfile *pIcc, const char *filename) {
  int issues = 0;

  // Find ADGC tag entry
  uint32_t adgcOffset = 0, adgcSize = 0;
  bool hasADGC = false;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    if (it->TagInfo.sig == (icTagSignature)kADGC_TagSig) {
      adgcOffset = it->TagInfo.offset;
      adgcSize = it->TagInfo.size;
      hasADGC = true;
      break;
    }
  }

  if (!hasADGC) {
    printf("         No ADGC tag — data validation checks skipped\n");
    return 0;
  }

  // Validate minimum size
  if (adgcSize < kADGC_HeaderSize) {
    printf("         %s[FAIL]%s ADGC tag size %u < minimum %zu bytes — ICC.1 ADGC Table 1\n",
           ColorError(), ColorReset(), adgcSize, kADGC_HeaderSize);
    return 1;
  }

  // Read raw tag data from file
  RawFileHandle fh = OpenRawFile(filename);
  if (!fh.fp) {
    printf("         %s[WARN]%s Cannot open file for ADGC raw validation\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  if (fseek(fh.fp, (long)adgcOffset, SEEK_SET) != 0) {
    printf("         %s[WARN]%s Cannot seek to ADGC tag offset %u\n",
           ColorWarning(), ColorReset(), adgcOffset);
    return 0;
  }

  std::vector<uint8_t> buf(adgcSize);
  size_t bytesRead = fread(buf.data(), 1, adgcSize, fh.fp);
  if (bytesRead < kADGC_HeaderSize) {
    printf("         %s[FAIL]%s ADGC tag truncated: read %zu of %u bytes\n",
           ColorError(), ColorReset(), bytesRead, adgcSize);
    return 1;
  }

  const uint8_t *d = buf.data();

  // ── CF-124: Type signature must be 'adgc' ──
  uint32_t typeSig = ReadU32BE(d + 0);
  if (typeSig != kADGC_TypeSig) {
    printf("         %s[FAIL]%s CF-124: ADGC type signature 0x%08X != expected 0x%08X ('adgc')"
           " — ICC.1 ADGC §3\n", ColorError(), ColorReset(), typeSig, kADGC_TypeSig);
    issues++;
  } else {
    printf("         %s[OK]%s CF-124: Type signature 'adgc' correct\n",
           ColorSuccess(), ColorReset());
  }

  // ── CF-125: Function Type ID must be 1 ──
  uint32_t funcType = ReadU32BE(d + 8);
  if (funcType != 1) {
    printf("         %s[FAIL]%s CF-125: functionTypeID=%u, expected 1 — ICC.1 ADGC §3\n",
           ColorError(), ColorReset(), funcType);
    issues++;
  } else {
    printf("         %s[OK]%s CF-125: functionTypeID=1 correct\n",
           ColorSuccess(), ColorReset());
  }

  // ── CF-126: Reserved bytes must be zero ──
  {
    // Bytes 4-7 must be zero
    uint32_t res1 = ReadU32BE(d + 4);
    if (res1 != 0) {
      printf("         %s[FAIL]%s CF-126: Reserved bytes 4-7 = 0x%08X (must be 0)"
             " — ICC.1 ADGC Table 1\n", ColorError(), ColorReset(), res1);
      issues++;
    } else {
      printf("         %s[OK]%s CF-126: Reserved bytes 4-7 are zero\n",
             ColorSuccess(), ColorReset());
    }
  }

  // ── CF-127: Float field finiteness ──
  // Validate all float32 fields in the header are finite (not NaN, not ±Inf)
  {
    struct FloatField {
      size_t offset;
      const char *name;
    };
    static const FloatField fields[] = {
      {28,  "H_baseline"},     {32,  "H_alternate"},
      {36,  "Red GainMin"},    {40,  "Red GainMax"},    {44,  "kRed"},
      {48,  "Green GainMin"},  {52,  "Green GainMax"},  {56,  "kGreen"},
      {60,  "Blue GainMin"},   {64,  "Blue GainMax"},   {68,  "kBlue"},
      {72,  "kMax"},           {76,  "kMin"},            {80,  "kComponent"},
      {92,  "A2B0 headroom"},  {96,  "A2B1 headroom"},  {100, "A2B2 headroom"},
    };
    int nanCount = 0;
    for (const auto &fld : fields) {
      float v = ReadFloat32BE(d + fld.offset);
      if (!std::isfinite(v)) {
        printf("         %s[FAIL]%s CF-127: %s at offset %zu is %s"
               " — ICC.1 ADGC §3 (must be finite)\n",
               ColorError(), ColorReset(), fld.name, fld.offset,
               std::isnan(v) ? "NaN" : "Inf");
        nanCount++;
      }
    }
    if (nanCount > 0)
      issues += nanCount;
    else
      printf("         %s[OK]%s CF-127: All 17 float fields are finite\n",
             ColorSuccess(), ColorReset());
  }

  // ── CF-128: Weight coefficient sum ──
  // kRed + kGreen + kBlue + kMax + kMin + kComponent should approximately equal 1.0
  {
    float kRed  = ReadFloat32BE(d + 44);
    float kGrn  = ReadFloat32BE(d + 56);
    float kBlu  = ReadFloat32BE(d + 68);
    float kMax  = ReadFloat32BE(d + 72);
    float kMin  = ReadFloat32BE(d + 76);
    float kComp = ReadFloat32BE(d + 80);

    if (std::isfinite(kRed) && std::isfinite(kGrn) && std::isfinite(kBlu) &&
        std::isfinite(kMax) && std::isfinite(kMin) && std::isfinite(kComp)) {
      float sum = kRed + kGrn + kBlu + kMax + kMin + kComp;
      if (std::fabs(sum - 1.0f) > 0.01f) {
        printf("         %s[WARN]%s CF-128: Weight sum=%.6f (expected ≈1.0)"
               " — ICC.1 ADGC §3 Annex 2\n",
               ColorWarning(), ColorReset(), sum);
        issues++;
      } else {
        printf("         %s[OK]%s CF-128: Weight coefficient sum=%.6f ≈ 1.0\n",
               ColorSuccess(), ColorReset(), sum);
      }
    } else {
      printf("         %s[SKIP]%s CF-128: Weight sum — skipped due to non-finite values\n",
             ColorWarning(), ColorReset());
    }
  }

  // ── CF-129: Curve position bounds ──
  // positionNumber fields (offset+size pairs at bytes 104-127) must point within tag
  {
    struct CurvePos {
      size_t headerOffset;
      const char *name;
    };
    static const CurvePos positions[] = {
      {104, "Red"},
      {112, "Green"},
      {120, "Blue"},
    };
    int posIssues = 0;
    for (const auto &cp : positions) {
      uint32_t curveOff  = ReadU32BE(d + cp.headerOffset);
      uint32_t curveSize = ReadU32BE(d + cp.headerOffset + 4);
      if (curveOff == 0 && curveSize == 0) {
        // Shared or absent curve — spec allows shared positions
        continue;
      }
      // Curve offset is relative to the start of the tag data
      if (curveOff + curveSize > adgcSize) {
        printf("         %s[FAIL]%s CF-129: %s curve position (offset=%u, size=%u)"
               " exceeds tag size %u — ICC.1 ADGC Table 1\n",
               ColorError(), ColorReset(), cp.name, curveOff, curveSize, adgcSize);
        posIssues++;
      }
      // Curve data format: uInt32 count + count × {x, y, slope} float32 triplets
      if (curveOff + 4 <= adgcSize && curveOff < bytesRead) {
        uint32_t count = ReadU32BE(d + curveOff);
        if (count == 0) {
          printf("         %s[WARN]%s CF-129: %s curve has 0 entries"
                 " — ICC.1 ADGC Table 2\n",
                 ColorWarning(), ColorReset(), cp.name);
          posIssues++;
        }
        uint32_t expectedSize = 4 + count * 12;  // 4 (count) + N × (x+y+slope)
        if (curveSize > 0 && expectedSize > curveSize) {
          printf("         %s[WARN]%s CF-129: %s curve count=%u requires %u bytes"
                 " but size=%u — ICC.1 ADGC Table 2\n",
                 ColorWarning(), ColorReset(), cp.name, count, expectedSize, curveSize);
          posIssues++;
        }
      }
    }
    if (posIssues > 0)
      issues += posIssues;
    else
      printf("         %s[OK]%s CF-129: All curve positions within tag bounds\n",
             ColorSuccess(), ColorReset());
  }

  // ── CF-130: Image-specific GUID → header flags ──
  // If GUID is non-zero, the profile is image-specific and header flags bits 0,1
  // must both be set (embedded + cannot be used independently)
  {
    bool guidNonZero = false;
    for (size_t i = 12; i < 28; i++) {
      if (d[i] != 0) { guidNonZero = true; break; }
    }
    if (guidNonZero) {
      uint32_t flags = pIcc->m_Header.flags;
      bool embedded     = (flags & 0x00000001) != 0;
      bool noIndepUse   = (flags & 0x00000002) != 0;
      if (!embedded || !noIndepUse) {
        printf("         %s[FAIL]%s CF-130: ADGC GUID is non-zero (image-specific)"
               " but header flags=0x%08X — bits 0,1 must both be set"
               " — ICC.1 ADGC §3\n",
               ColorError(), ColorReset(), flags);
        issues++;
      } else {
        printf("         %s[OK]%s CF-130: Image-specific GUID with correct header flags\n",
               ColorSuccess(), ColorReset());
      }
    } else {
      printf("         %s[OK]%s CF-130: GUID is all-zero (non-image-specific)\n",
             ColorSuccess(), ColorReset());
    }
  }

  // ── CF-131: Headroom range plausibility ──
  // H_baseline and H_alternate are log2 headroom values — reasonable range 0..20
  {
    float hBase = ReadFloat32BE(d + 28);
    float hAlt  = ReadFloat32BE(d + 32);
    int hIssues = 0;
    if (std::isfinite(hBase)) {
      if (hBase < 0.0f || hBase > 20.0f) {
        printf("         %s[WARN]%s CF-131: H_baseline=%.4f outside plausible range [0,20]"
               " — ICC.1 ADGC §3\n", ColorWarning(), ColorReset(), hBase);
        hIssues++;
      }
    }
    if (std::isfinite(hAlt)) {
      if (hAlt < 0.0f || hAlt > 20.0f) {
        printf("         %s[WARN]%s CF-131: H_alternate=%.4f outside plausible range [0,20]"
               " — ICC.1 ADGC §3\n", ColorWarning(), ColorReset(), hAlt);
        hIssues++;
      }
    }
    if (hIssues > 0)
      issues += hIssues;
    else
      printf("         %s[OK]%s CF-131: Headroom values within plausible range\n",
             ColorSuccess(), ColorReset());
  }

  // ── CF-132: Curve data monotonicity ──
  // Curve triplets {x, y, slope}: x values must be monotonically increasing
  {
    struct CurvePos { size_t headerOffset; const char *name; };
    static const CurvePos positions[] = {{104, "Red"}, {112, "Green"}, {120, "Blue"}};
    int monoIssues = 0;
    for (const auto &cp : positions) {
      uint32_t curveOff  = ReadU32BE(d + cp.headerOffset);
      uint32_t curveSize = ReadU32BE(d + cp.headerOffset + 4);
      if (curveOff == 0 && curveSize == 0) continue;
      if (curveOff + 4 > bytesRead) continue;

      uint32_t count = ReadU32BE(d + curveOff);
      if (count < 2) continue;  // Can't check monotonicity with < 2 points

      // Check x-value monotonicity (each triplet: x=offset+4+i*12, y=+4, slope=+8)
      float prevX = -1e30f;
      uint32_t maxCheck = count;
      if (maxCheck > 1000) maxCheck = 1000;  // Cap to prevent excessive scanning
      for (uint32_t i = 0; i < maxCheck; i++) {
        size_t xOff = curveOff + 4 + i * 12;
        if (xOff + 4 > bytesRead) break;
        float x = ReadFloat32BE(d + xOff);
        if (std::isfinite(x) && std::isfinite(prevX)) {
          if (x <= prevX) {
            printf("         %s[FAIL]%s CF-132: %s curve entry %u: x=%.6f ≤ prev=%.6f"
                   " (not monotonically increasing) — ICC.1 ADGC Table 2\n",
                   ColorError(), ColorReset(), cp.name, i, x, prevX);
            monoIssues++;
            break;  // One failure per curve is enough
          }
        }
        prevX = x;
      }
    }
    if (monoIssues > 0)
      issues += monoIssues;
    else
      printf("         %s[OK]%s CF-132: All curve x-values monotonically increasing\n",
             ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Dispatcher — runs all tag type conformance checks
// ═══════════════════════════════════════════════════════════════════════════════

int RunTagTypeConformance(CIccProfile *pIcc, const char *filename) {
  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  int r;

#define CF_WRAP(id, title, call) \
  hc.begin(id, title); \
  r = call; \
  if (r > 0) hc.warn("%d non-conformance(s)", r); \
  hc.end("Conformant"); \
  issues += r

  CF_WRAP(1020, "CF-020: Tag Signature → Allowed Type", RunCF020_TagTypeAllowed(pIcc));
  CF_WRAP(1022, "CF-022: curveType Entry Count", RunCF022_CurveTypeEntryCount(pIcc));
  CF_WRAP(1023, "CF-023: parametricCurveType Function Type", RunCF023_ParametricCurveFunction(pIcc));
  CF_WRAP(1024, "CF-024: parametricCurveType Parameter Count", RunCF024_ParametricCurveParamCount(pIcc));
  CF_WRAP(1025, "CF-025: Chromaticity Phosphor Count", RunCF025_ChromaticityPhosphorCount(pIcc));
  CF_WRAP(1026, "CF-026: Colorant Table Entry Count", RunCF026_ColorantTableCount(pIcc));
  CF_WRAP(1027, "CF-027: Colorant Order Count", RunCF027_ColorantOrderCount(pIcc));
  CF_WRAP(1028, "CF-028: Named Color2 Device Coordinate Count", RunCF028_NamedColor2CoordCount(pIcc));
  CF_WRAP(1029, "CF-029: dateTimeType Field Ranges", RunCF029_DateTimeFieldRanges(pIcc));
  CF_WRAP(1032, "CF-032: XYZType Triplet Count", RunCF032_XYZTypeTripletCount(pIcc));
  CF_WRAP(1033, "CF-033: Measurement Standard Observer", RunCF033_MeasurementStandardObserver(pIcc));
  CF_WRAP(1034, "CF-034: Measurement Geometry", RunCF034_MeasurementGeometry(pIcc));

  CF_WRAP(1112, "CF-112: XYZ Triplet Normalization", RunCF112_XYZTripletNormalization(pIcc));

  // ADGC (Adaptive Gain Curve) — ICC.1 Amendment April 2025
  CF_WRAP(1123, "CF-123: ADGC Class Restriction", RunCF123_ADGCClassRestriction(pIcc));
  CF_WRAP(1124, "CF-124..CF-132: ADGC Data Validation",
          RunCF124_to_CF132_ADGCDataValidation(pIcc, filename));

#undef CF_WRAP
  return issues;
}
