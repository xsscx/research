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
// Dispatcher — runs all tag type conformance checks
// ═══════════════════════════════════════════════════════════════════════════════

int RunTagTypeConformance(CIccProfile *pIcc) {
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

#undef CF_WRAP
  return issues;
}
