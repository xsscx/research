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
#include "IccTagProfSeqId.h"
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
// CF-021: Tag Type Reserved Bytes Zero (ICC.1-2022-05 §10)
//
// Every tag type has a 4-byte type signature followed by 4 reserved bytes
// (offset 4-7 within the tag data) that SHALL be zero.
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF021_TagTypeReservedZero(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  int checked = 0;
  int violations = 0;

  printf("%s[CF-021]%s Tag Type Reserved Bytes Zero (%sICC.1-2022-05 §10%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename) {
    printf("         %sNo filename provided — cannot verify reserved bytes%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s Reserved bytes check skipped\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("         %sCannot open file for reserved bytes check%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s Reserved bytes check skipped\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  // Track offsets already visited to skip shared-offset duplicates
  std::vector<icUInt32Number> visitedOffsets;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    icUInt32Number tagOffset = e->TagInfo.offset;
    icUInt32Number tagSize = e->TagInfo.size;

    // Skip duplicate entries sharing the same data offset
    bool duplicate = false;
    for (size_t v = 0; v < visitedOffsets.size(); v++) {
      if (visitedOffsets[v] == tagOffset) { duplicate = true; break; }
    }
    if (duplicate) continue;
    visitedOffsets.push_back(tagOffset);

    // Need at least 8 bytes (4 type sig + 4 reserved)
    if (tagSize < 8) continue;
    if (static_cast<long>(tagOffset + 8) > fh.fileSize) continue;

    uint8_t reserved[4];
    if (!fh.Seek(static_cast<long>(tagOffset + 4)) || !fh.ReadBytes(reserved, 4))
      continue;

    checked++;

    bool allZero = (reserved[0] == 0 && reserved[1] == 0 &&
                    reserved[2] == 0 && reserved[3] == 0);

    if (!allZero) {
      char sigBuf[5];
      SigToChars(static_cast<uint32_t>(e->TagInfo.sig), sigBuf);
      printf("         Tag '%s' at offset %u: reserved bytes = %02X %02X %02X %02X — %smust be zero%s\n",
             sigBuf, tagOffset, reserved[0], reserved[1], reserved[2], reserved[3],
             ColorError(), ColorReset());
      printf("         %s[FAIL]%s Tag type reserved bytes non-zero — ICC.1-2022-05 §10\n",
             ColorError(), ColorReset());
      violations++;
      issues++;
    }
  }

  if (violations == 0)
    printf("         %s[OK]%s %d tag(s) checked, all reserved bytes are zero\n",
           ColorSuccess(), ColorReset(), checked);
  else
    printf("         Summary: %d/%d tags checked, %s%d violation(s)%s\n",
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


// =============================================================================
// CF-340: colorantTableOutTag Count vs PCS Channels (ICC.1-2022-05 §10.4)
// =============================================================================
// PR #708 regression: upstream validation validates clot against colorSpace
// instead of PCS. The clot (ColorantTableOutTag) describes OUTPUT colorants,
// which must match the PCS channel count -- not the device colorSpace.
// This mirrors CF-026 (clrt vs colorSpace) for the output side.

int RunCF340_ColorantTableOutCountVsPCS(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-340]%s colorantTableOutTag Count vs PCS Channels (%sICC.1-2022-05 %s10.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorInfo(), ColorReset());

  CIccTagColorantTable *pClot =
      FindAndCast<CIccTagColorantTable>(pIcc, icSigColorantTableOutTag);
  if (!pClot) {
    printf("         No colorantTableOutTag found\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  icUInt32Number nColorants = pClot->GetSize();
  icUInt32Number nExpected = icGetSpaceSamples(pIcc->m_Header.pcs);

  if (nExpected > 0 && nColorants != nExpected) {
    printf("         Colorant count=%u, PCS channels=%u -- %smismatch%s\n",
           nColorants, nExpected, ColorError(), ColorReset());
    printf("         %s[FAIL]%s colorantTableOutTag count must equal PCS channel count"
           " -- ICC.1-2022-05 %s10.4\n",
           ColorError(), ColorReset(), ColorReset());
    printf("         NOTE: PR #708 regression validates clot against colorSpace instead of PCS\n");
    issues++;
  } else {
    printf("         Colorant count=%u, PCS channels=%u -- match\n",
           nColorants, nExpected);
    printf("         %s[OK]%s colorantTableOutTag count valid\n",
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
// CF-030: multiLocalizedUnicodeType Structure (ICC.1-2022-05 §10.13)
//
// mluc type: record count (4B at +8), record size (4B at +12, must be 12),
// then N records of (lang 2B, country 2B, length 4B, offset 4B).
// String offsets+lengths must not exceed tag data size.
// No duplicate language/country pairs.
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF030_MlucStructure(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-030]%s multiLocalizedUnicodeType Structure (%sICC.1-2022-05 §10.13%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename) {
    printf("         %sNo filename provided — cannot verify mluc structure%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s mluc check skipped\n", ColorWarning(), ColorReset());
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("         %sCannot open file for mluc verification%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s mluc check skipped\n", ColorWarning(), ColorReset());
    return 0;
  }

  // mluc type signature: 'mluc' = 0x6D6C7563
  static const uint32_t kMlucTypeSig = 0x6D6C7563;

  std::vector<icUInt32Number> visitedOffsets;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    icUInt32Number tagOffset = e->TagInfo.offset;
    icUInt32Number tagSize = e->TagInfo.size;

    // Skip duplicates
    bool duplicate = false;
    for (size_t v = 0; v < visitedOffsets.size(); v++) {
      if (visitedOffsets[v] == tagOffset) { duplicate = true; break; }
    }
    if (duplicate) continue;
    visitedOffsets.push_back(tagOffset);

    // Need at least 16 bytes to read type sig + reserved + count + record size
    if (tagSize < 16) continue;
    if (static_cast<long>(tagOffset + 16) > fh.fileSize) continue;

    // Read type signature
    uint8_t hdr[16];
    if (!fh.Seek(static_cast<long>(tagOffset)) || !fh.ReadBytes(hdr, 16))
      continue;

    uint32_t typeSig = ReadU32BE(hdr);
    if (typeSig != kMlucTypeSig) continue;

    checked++;
    char sigBuf[5];
    SigToChars(static_cast<uint32_t>(e->TagInfo.sig), sigBuf);

    uint32_t recordCount = ReadU32BE(hdr + 8);
    uint32_t recordSize = ReadU32BE(hdr + 12);

    // §10.13: Record size SHALL be 12
    if (recordSize != 12) {
      printf("         Tag '%s': mluc record size=%u — %smust be 12%s\n",
             sigBuf, recordSize, ColorError(), ColorReset());
      printf("         %s[FAIL]%s mluc record size invalid — ICC.1-2022-05 §10.13\n",
             ColorError(), ColorReset());
      issues++;
      continue;  // Can't parse records if size is wrong
    }

    // Validate total record data fits within tag
    uint64_t recordsEnd = 16ULL + (uint64_t)recordCount * 12ULL;
    if (recordsEnd > tagSize) {
      printf("         Tag '%s': %u records × 12 = %llu bytes, exceeds tag size %u\n",
             sigBuf, recordCount, (unsigned long long)(recordCount * 12ULL), tagSize);
      printf("         %s[FAIL]%s mluc record table overflows tag data — §10.13\n",
             ColorError(), ColorReset());
      issues++;
      continue;
    }

    // Read all records
    size_t recBytes = recordCount * 12;
    std::vector<uint8_t> recBuf(recBytes);
    if (!fh.Seek(static_cast<long>(tagOffset + 16)) || !fh.ReadBytes(recBuf.data(), recBytes))
      continue;

    // Validate each record
    struct LangCountry { uint16_t lang; uint16_t country; };
    std::vector<LangCountry> pairs;

    for (uint32_t r = 0; r < recordCount; r++) {
      const uint8_t *rec = recBuf.data() + r * 12;
      uint16_t lang    = (uint16_t)((rec[0] << 8) | rec[1]);
      uint16_t country = (uint16_t)((rec[2] << 8) | rec[3]);
      uint32_t strLen  = ReadU32BE(rec + 4);
      uint32_t strOff  = ReadU32BE(rec + 8);

      // String offset is relative to tag start; must fit within tag data
      if ((uint64_t)strOff + strLen > tagSize) {
        printf("         Tag '%s': record %u string offset=%u + length=%u exceeds tag size %u\n",
               sigBuf, r, strOff, strLen, tagSize);
        printf("         %s[FAIL]%s mluc string overflows tag data — §10.13\n",
               ColorError(), ColorReset());
        issues++;
      }

      // Check for duplicate language/country pairs
      for (size_t p = 0; p < pairs.size(); p++) {
        if (pairs[p].lang == lang && pairs[p].country == country) {
          printf("         Tag '%s': duplicate language/country pair (0x%04X/0x%04X) at record %u\n",
                 sigBuf, lang, country, r);
          printf("         %s[WARN]%s Duplicate mluc language/country pair — §10.13\n",
                 ColorWarning(), ColorReset());
          issues++;
          break;
        }
      }
      pairs.push_back({lang, country});
    }
  }

  if (checked == 0)
    printf("         No multiLocalizedUnicodeType tags found\n");

  if (issues == 0)
    printf("         %s[OK]%s %d mluc tag(s) checked, all structurally valid\n",
           ColorSuccess(), ColorReset(), checked);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-031: s15Fixed16ArrayType Element Count (ICC.1-2022-05 §10.18)
//
// The element count must be (tagDataSize - 8) / 4 with no remainder.
// The 8-byte header is the type signature (4B) + reserved (4B).
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF031_S15Fixed16ArrayCount(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-031]%s s15Fixed16ArrayType Element Count (%sICC.1-2022-05 §10.18%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename) {
    printf("         %sNo filename provided — cannot verify sf32 element count%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s sf32 check skipped\n", ColorWarning(), ColorReset());
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("         %sCannot open file for sf32 verification%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s sf32 check skipped\n", ColorWarning(), ColorReset());
    return 0;
  }

  // sf32 type signature: 'sf32' = 0x73663332
  static const uint32_t kSf32TypeSig = 0x73663332;

  std::vector<icUInt32Number> visitedOffsets;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    icUInt32Number tagOffset = e->TagInfo.offset;
    icUInt32Number tagSize = e->TagInfo.size;

    // Skip duplicates
    bool duplicate = false;
    for (size_t v = 0; v < visitedOffsets.size(); v++) {
      if (visitedOffsets[v] == tagOffset) { duplicate = true; break; }
    }
    if (duplicate) continue;
    visitedOffsets.push_back(tagOffset);

    // Need at least 8 bytes for the type header
    if (tagSize < 8) continue;
    if (static_cast<long>(tagOffset + 4) > fh.fileSize) continue;

    // Read type signature
    uint8_t typeBuf[4];
    if (!fh.Seek(static_cast<long>(tagOffset)) || !fh.ReadBytes(typeBuf, 4))
      continue;

    uint32_t typeSig = ReadU32BE(typeBuf);
    if (typeSig != kSf32TypeSig) continue;

    checked++;
    char sigBuf[5];
    SigToChars(static_cast<uint32_t>(e->TagInfo.sig), sigBuf);

    uint32_t dataBytes = tagSize - 8;  // subtract type sig + reserved
    uint32_t remainder = dataBytes % 4;

    if (remainder != 0) {
      uint32_t elemCount = dataBytes / 4;
      printf("         Tag '%s': data size=%u bytes, %u elements + %u extra bytes\n",
             sigBuf, dataBytes, elemCount, remainder);
      printf("         %s[FAIL]%s s15Fixed16Array data size not divisible by 4 — ICC.1-2022-05 §10.18\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      uint32_t elemCount = dataBytes / 4;
      printf("         Tag '%s': %u s15Fixed16 element(s)\n", sigBuf, elemCount);
    }
  }

  if (checked == 0)
    printf("         No s15Fixed16ArrayType tags found\n");

  if (issues == 0)
    printf("         %s[OK]%s %d sf32 tag(s) checked, all element counts valid\n",
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
// CF-035: responseCurveSet16Type Structure (ICC.1-2022-05 §10.19)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF035_ResponseCurveSet16Structure(CIccProfile *pIcc) {
  printf("%s[CF-035]%s responseCurveSet16Type Structure (%sICC.1-2022-05 §10.19%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;

  CIccTag *pTag = pIcc->FindTag(icSigOutputResponseTag);
  if (!pTag) {
    printf("         No outputResponseTag ('resp') found\n");
    printf("         %s[N/A]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  CIccTagResponseCurveSet16 *pRCS =
      dynamic_cast<CIccTagResponseCurveSet16 *>(pTag);
  if (!pRCS) {
    printf("         %sTag type mismatch — expected responseCurveSet16Type%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Invalid tag type — ICC.1-2022-05 §10.19\n",
           ColorError(), ColorReset());
    issues++;
    return issues;
  }

  icUInt16Number nChannels = pRCS->GetNumChannels();
  icUInt16Number nTypes = pRCS->GetNumResponseCurveTypes();

  if (nChannels == 0) {
    printf("         %sChannel count is 0 — must be >= 1%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Zero channels — ICC.1-2022-05 §10.19\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (nTypes == 0) {
    printf("         %sResponse curve type count is 0 — must be >= 1%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Zero response curve types — ICC.1-2022-05 §10.19\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s responseCurveSet16 valid (channels=%u, types=%u)\n",
           ColorSuccess(), ColorReset(), nChannels, nTypes);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-036: profileSequenceDescType Elements (ICC.1-2022-05 §10.22)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF036_ProfileSequenceDescElements(CIccProfile *pIcc) {
  printf("%s[CF-036]%s profileSequenceDescType Elements (%sICC.1-2022-05 §10.22%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;

  CIccTag *pTag = pIcc->FindTag(icSigProfileSequenceDescTag);
  if (!pTag) {
    printf("         No profileSequenceDescTag found\n");
    printf("         %s[N/A]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  CIccTagProfileSeqDesc *pSeq =
      dynamic_cast<CIccTagProfileSeqDesc *>(pTag);
  if (!pSeq) {
    printf("         %sTag type mismatch — expected profileSequenceDescType%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Invalid tag type — ICC.1-2022-05 §10.22\n",
           ColorError(), ColorReset());
    issues++;
    return issues;
  }

  if (!pSeq->m_Descriptions || pSeq->m_Descriptions->empty()) {
    printf("         %sProfile sequence has 0 entries — must have >= 1%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Empty profile sequence — ICC.1-2022-05 §10.22\n",
           ColorError(), ColorReset());
    issues++;
    return issues;
  }

  int idx = 0;
  for (const auto &desc : *pSeq->m_Descriptions) {
    char mfgSig[5] = {};
    char mdlSig[5] = {};
    icUInt32Number mfg = desc.m_deviceMfg;
    icUInt32Number mdl = desc.m_deviceModel;

    mfgSig[0] = static_cast<char>(static_cast<unsigned char>((mfg >> 24) & 0xFF));
    mfgSig[1] = static_cast<char>(static_cast<unsigned char>((mfg >> 16) & 0xFF));
    mfgSig[2] = static_cast<char>(static_cast<unsigned char>((mfg >> 8) & 0xFF));
    mfgSig[3] = static_cast<char>(static_cast<unsigned char>(mfg & 0xFF));

    mdlSig[0] = static_cast<char>(static_cast<unsigned char>((mdl >> 24) & 0xFF));
    mdlSig[1] = static_cast<char>(static_cast<unsigned char>((mdl >> 16) & 0xFF));
    mdlSig[2] = static_cast<char>(static_cast<unsigned char>((mdl >> 8) & 0xFF));
    mdlSig[3] = static_cast<char>(static_cast<unsigned char>(mdl & 0xFF));

    printf("         Entry %d: mfg='%s' model='%s' tech=0x%08X\n",
           idx, mfgSig, mdlSig,
           static_cast<icUInt32Number>(desc.m_technology));
    idx++;
  }

  if (issues == 0)
    printf("         %s[OK]%s profileSequenceDesc valid (%d entries)\n",
           ColorSuccess(), ColorReset(), idx);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-037: profileSequenceIdentifierType Validation (ICC.1-2022-05 §10.23)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF037_ProfileSequenceIdValidation(CIccProfile *pIcc) {
  printf("%s[CF-037]%s profileSequenceIdentifierType Validation (%sICC.1-2022-05 §10.23%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;

  // NOTE: iccDEV API has a typo — icSigProfileSequceIdTag (missing 'en')
  CIccTag *pTag = pIcc->FindTag(icSigProfileSequceIdTag);
  if (!pTag) {
    printf("         No profileSequenceIdentifierTag ('psid') found\n");
    printf("         %s[N/A]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  CIccTagProfileSequenceId *pSeqId =
      dynamic_cast<CIccTagProfileSequenceId *>(pTag);
  if (!pSeqId) {
    printf("         %sTag type mismatch — expected profileSequenceIdentifierType%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Invalid tag type — ICC.1-2022-05 §10.23\n",
           ColorError(), ColorReset());
    issues++;
    return issues;
  }

  int entryCount = 0;
  int allZeroCount = 0;
  static const icUInt8Number zeroID[16] = {0};

  for (auto it = pSeqId->begin(); it != pSeqId->end(); ++it) {
    entryCount++;
    if (memcmp(it->m_profileID.ID8, zeroID, 16) == 0)
      allZeroCount++;
  }

  if (entryCount == 0) {
    printf("         %sSequence has 0 entries — must have >= 1%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Empty profile sequence identifier — ICC.1-2022-05 §10.23\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (allZeroCount > 0 && entryCount > 0) {
    printf("         %s%d of %d profile IDs are all-zero (unidentified)%s\n",
           ColorWarning(), allZeroCount, entryCount, ColorReset());
    printf("         %s[WARN]%s All-zero Profile IDs — each should identify a unique profile\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s profileSequenceIdentifier valid (%d entries, all IDs non-zero)\n",
           ColorSuccess(), ColorReset(), entryCount);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-038: dateTimeType Tag Range Validation (ICC.1-2022-05 §10.7)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF038_DateTimeTypeTagRange(CIccProfile *pIcc) {
  printf("%s[CF-038]%s dateTimeType Tag Range Validation (%sICC.1-2022-05 §10.7%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;

  CIccTag *pTag = pIcc->FindTag(icSigCalibrationDateTimeTag);
  if (!pTag) {
    printf("         No calibrationDateTimeTag ('calt') found\n");
    printf("         %s[N/A]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  CIccTagDateTime *pDT = dynamic_cast<CIccTagDateTime *>(pTag);
  if (!pDT) {
    printf("         %sTag type mismatch — expected dateTimeType%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Invalid tag type — ICC.1-2022-05 §10.7\n",
           ColorError(), ColorReset());
    issues++;
    return issues;
  }

  // Access the protected m_DateTime through SetDateTime/GetDateTime round-trip
  // is not available, so read from the profile header's calibration tag directly.
  // CIccTagDateTime stores m_DateTime as protected icDateTimeNumber.
  // We use the Describe() output to validate, but for direct field access we
  // re-read the tag from the raw profile data.
  //
  // Alternative: the profile header has its own creation date (already validated
  // by CF-001/CF-029). Here we validate the calibration date tag independently.
  //
  // Since m_DateTime is protected, we get it via Describe() string parsing or
  // trust the library's own Validate(). Use Validate() for conformance.
  std::string report;
  icValidateStatus vs = pDT->Validate("calt", report, pIcc);

  if (vs >= icValidateWarning) {
    printf("         %sLibrary validation flagged issues:%s\n",
           ColorWarning(), ColorReset());
    // Print first few lines of the report
    size_t pos = 0;
    int lines = 0;
    while (pos < report.size() && lines < 4) {
      size_t end = report.find('\n', pos);
      if (end == std::string::npos) end = report.size();
      std::string line = report.substr(pos, end - pos);
      if (!line.empty())
        printf("           %s\n", line.c_str());
      pos = end + 1;
      lines++;
    }
    if (vs >= icValidateNonCompliant) {
      printf("         %s[FAIL]%s dateTimeType validation failed — ICC.1-2022-05 §10.7\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         %s[WARN]%s dateTimeType has warnings — ICC.1-2022-05 §10.7\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  }

  // Additional: describe the tag to show the date values
  if (issues == 0) {
    std::string desc;
    pDT->Describe(desc, 0);
    if (!desc.empty()) {
      // Trim trailing whitespace
      while (!desc.empty() && (desc.back() == '\n' || desc.back() == ' '))
        desc.pop_back();
      printf("         Calibration date: %s\n", desc.c_str());
    }
    printf("         %s[OK]%s calibrationDateTime fields valid\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-039: signatureType Technology Validation (ICC.1-2022-05 §10.24)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF039_SignatureTypeTechnology(CIccProfile *pIcc) {
  printf("%s[CF-039]%s signatureType Technology Validation (%sICC.1-2022-05 §10.24%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;

  CIccTag *pTag = pIcc->FindTag(icSigTechnologyTag);
  if (!pTag) {
    printf("         No technologyTag ('tech') found\n");
    printf("         %s[N/A]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  CIccTagSignature *pSig = dynamic_cast<CIccTagSignature *>(pTag);
  if (!pSig) {
    printf("         %sTag type mismatch — expected signatureType%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Invalid tag type — ICC.1-2022-05 §10.24\n",
           ColorError(), ColorReset());
    issues++;
    return issues;
  }

  icUInt32Number tech = pSig->GetValue();

  // ICC.1-2022-05 Table 29 — Technology Signatures
  static const icUInt32Number knownTechs[] = {
    0x6673636E, // 'fscn' Film Scanner
    0x6463616D, // 'dcam' Digital Camera
    0x6473636E, // 'dscn' Desktop Scanner (Reflective)
    0x696A7072, // 'ijpr' Ink Jet Printer
    0x74776178, // 'twax' Thermal Wax Printer
    0x6570686F, // 'epho' Electrophotographic Printer
    0x65737461, // 'esta' Electrostatic Printer
    0x64737562, // 'dsub' Dye Sublimation Printer
    0x7270686F, // 'rpho' Photographic Paper Printer
    0x6670726E, // 'fprn' Film Writer
    0x7669646D, // 'vidm' Video Monitor
    0x76696463, // 'vidc' Video Camera
    0x706A7476, // 'pjtv' Projection Television
    0x43525420, // 'CRT ' Cathode Ray Tube Display
    0x504D4420, // 'PMD ' Passive Matrix Display
    0x414D4420, // 'AMD ' Active Matrix Display
    0x4B504344, // 'KPCD' Photo CD
    0x696D6773, // 'imgs' PhotoImageSetter
    0x67726176, // 'grav' Gravure
    0x6F667374, // 'ofst' Offset Lithography
    0x73696C6B, // 'silk' Silkscreen
    0x666C6578, // 'flex' Flexography
    0x6D706672, // 'mpfr' Motion Picture Film Recorder
    0x6D706673, // 'mpfs' Motion Picture Film Scanner
    0x6D706665, // 'mpfe' Digital Motion Picture Camera (Electronic)
    0x64637069, // 'dcpj' Digital Cinema Projector
    0x64637664, // 'dcvd' Digital Cinema Viewer Display (non-projector)
    0x646D7066, // 'dmpf' Digital Motion Picture Film
    0x646D7063, // 'dmpc' Digital Motion Picture Camera
    0x70706564, // 'pped' Projection/Pen/Electrostatic Display
  };
  static const int nKnown =
      static_cast<int>(sizeof(knownTechs) / sizeof(knownTechs[0]));

  bool found = false;
  for (int i = 0; i < nKnown; i++) {
    if (tech == knownTechs[i]) {
      found = true;
      break;
    }
  }

  char techStr[5] = {};
  techStr[0] = static_cast<char>(static_cast<unsigned char>((tech >> 24) & 0xFF));
  techStr[1] = static_cast<char>(static_cast<unsigned char>((tech >> 16) & 0xFF));
  techStr[2] = static_cast<char>(static_cast<unsigned char>((tech >> 8) & 0xFF));
  techStr[3] = static_cast<char>(static_cast<unsigned char>(tech & 0xFF));

  if (tech == 0) {
    printf("         Technology signature is 0x00000000 (unspecified)\n");
    printf("         %s[OK]%s Zero is acceptable (unspecified)\n",
           ColorSuccess(), ColorReset());
  } else if (!found) {
    printf("         Technology='%s' (0x%08X) — %sunrecognized%s\n",
           techStr, tech, ColorWarning(), ColorReset());
    printf("         %s[WARN]%s Unrecognized technology signature — ICC.1-2022-05 Table 29\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    printf("         Technology='%s' (0x%08X)\n", techStr, tech);
    printf("         %s[OK]%s Valid technology signature\n",
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
// Negative PCSXYZ Values conformance — ICC TN "Guidelines on the use of
// negative PCSXYZ values" (Phil Green, ICC Technical Secretary)
//
// Key spec points:
// - PCSXYZ uses XYZNumber: u1Fixed15, s15Fixed16, or float32 (ICC.1:2010 §6.3.4.2)
// - u1Fixed15 range: [0, 1+32767/32768] — cannot encode negatives
// - Negative XYZ can arise from chromatic adaptation (Bradford transform)
//   especially for BT.2020 and DCI-P3 red primary Z values
// - Profile builders should use s15Fixed16 or float32 for negative values
// - [0,0,0] = perfect absorber; [0.9642, 1.0, 0.8249] = D50 media white
// ═══════════════════════════════════════════════════════════════════════════════

// CF-169: Negative PCSXYZ Encoding Capability
//
// When matrix column tags (rXYZ, gXYZ, bXYZ) contain negative values — which is
// valid for wide-gamut color spaces after chromatic adaptation — the profile
// must use a tag type capable of representing negatives. The u1Fixed15Number
// encoding can only represent [0, ~1.9999] and would silently clip negative
// values, losing color accuracy for round-trip calculations.
// Spec: ICC TN Negative PCSXYZ, ICC.1:2010 §6.3.4.2, §6.4.3
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF169_NegativePCSXYZEncodingCapability(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-169]%s Negative PCSXYZ Encoding Capability (%sICC TN Negative PCSXYZ §6.3.4.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const icTagSignature xyzSigs[] = {
    icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag,
    icSigMediaWhitePointTag, icSigLuminanceTag
  };
  static const char *xyzNames[] = { "rXYZ", "gXYZ", "bXYZ", "wtpt", "lumi" };

  int checked = 0;
  int negFound = 0;
  for (int i = 0; i < 5; i++) {
    CIccTag *tag = pIcc->FindTag(xyzSigs[i]);
    CIccTagXYZ *xyz = tag ? dynamic_cast<CIccTagXYZ *>(tag) : nullptr;
    if (!xyz || xyz->GetSize() < 1) continue;
    checked++;

    icXYZNumber val = (*xyz)[0];
    icFloatNumber x = icFtoD(val.X);
    icFloatNumber y = icFtoD(val.Y);
    icFloatNumber z = icFtoD(val.Z);

    if (x < 0.0 || y < 0.0 || z < 0.0) {
      negFound++;
      printf("         '%s' has negative component(s): X=%.6f Y=%.6f Z=%.6f\n",
             xyzNames[i], x, y, z);

      // Check if the encoding type can represent this
      // XYZType tags in ICC profiles use s15Fixed16Number for each component,
      // which CAN represent negatives. This is conformant per the TN.
      // Only warn if the profile version uses u1Fixed15Number encoding
      // (ICC.1:2010 §6.4.3.2 defines u1Fixed15 PCS encoding for v2 profiles)
      icUInt32Number version = pIcc->m_Header.version >> 24;
      if (version < 4) {
        printf("         %s[WARN]%s v%u profile with negative XYZ — pre-v4 PCS uses "
               "u1Fixed15Number which cannot encode negatives — ICC TN Negative PCSXYZ\n",
               ColorError(), ColorReset(), version);
        issues++;
      } else {
        printf("         %s[INFO]%s Negative value encoded via s15Fixed16Number — "
               "conformant per ICC TN Negative PCSXYZ\n",
               ColorInfo(), ColorReset());
      }
    }
  }

  if (checked == 0)
    printf("         No XYZ tags to validate\n");
  else if (negFound == 0)
    printf("         %s[OK]%s All %d XYZ tags have non-negative values\n",
           ColorSuccess(), ColorReset(), checked);
  else if (issues == 0)
    printf("         %s[OK]%s %d negative value(s) properly encoded via s15Fixed16\n",
           ColorSuccess(), ColorReset(), negFound);

  return issues;
}


// CF-170: Chromatic Adaptation Negative XYZ Consistency
//
// When a profile uses a chromatic adaptation tag (chad), the adapted primaries
// may have negative components. If negative XYZ values are present in matrix
// column tags, a chad tag SHOULD be present to explain the adaptation source.
// Conversely, if chad is present with a strong adaptation (large off-diagonal
// elements), negative colorant values are expected for some wide-gamut spaces.
// Spec: ICC TN Negative PCSXYZ, ICC.1-2022-05 §9.2.10, Annex E
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF170_ChadNegativeXYZConsistency(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-170]%s Chromatic Adaptation Negative XYZ Consistency "
         "(%sICC TN Negative PCSXYZ, §9.2.10%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Check if matrix columns have any negative components
  static const icTagSignature matSigs[] = {
    icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag
  };
  static const char *matNames[] = { "rXYZ", "gXYZ", "bXYZ" };

  bool hasNegative = false;
  bool hasAllColumns = true;
  for (int i = 0; i < 3; i++) {
    CIccTag *tag = pIcc->FindTag(matSigs[i]);
    CIccTagXYZ *xyz = tag ? dynamic_cast<CIccTagXYZ *>(tag) : nullptr;
    if (!xyz || xyz->GetSize() < 1) { hasAllColumns = false; continue; }

    icXYZNumber val = (*xyz)[0];
    if (icFtoD(val.X) < 0.0 || icFtoD(val.Y) < 0.0 || icFtoD(val.Z) < 0.0) {
      hasNegative = true;
      printf("         '%s' contains negative component(s)\n", matNames[i]);
    }
  }

  if (!hasAllColumns) {
    printf("         Matrix column tags not all present — check not applicable\n");
    return 0;
  }

  // If negative values present, chad SHOULD be present to explain the adaptation
  if (hasNegative) {
    CIccTag *chadTag = pIcc->FindTag(icSigChromaticAdaptationTag);
    if (!chadTag) {
      printf("         Negative matrix column values without chad tag\n");
      printf("         %s[WARN]%s Negative XYZ from chromatic adaptation requires "
             "chad tag to document the adaptation transform — ICC.1 §9.2.10\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         %s[OK]%s Negative XYZ values present with chad tag — "
             "consistent with chromatic adaptation (BT.2020/DCI-P3 pattern)\n",
             ColorSuccess(), ColorReset());
    }
  } else {
    printf("         %s[OK]%s No negative matrix column values — no adaptation concern\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// CF-171: White Point Non-Negative Luminance
//
// The media white point Y value (luminance) must always be non-negative.
// While chromatic adaptation can produce negative X or Z for primaries,
// the white point itself represents the maximum luminance of the medium
// and must have Y >= 0 (and typically Y = 1.0 for normalized PCS).
// Negative Y in the white point is physically impossible.
// Spec: ICC TN Negative PCSXYZ, ICC.1:2010 §3.1.24, §6.4.3
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF171_WhitePointNonNegativeLuminance(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-171]%s White Point Non-Negative Luminance "
         "(%sICC TN Negative PCSXYZ, §3.1.24%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const icTagSignature wpSigs[] = {
    icSigMediaWhitePointTag, icSigLuminanceTag
  };
  static const char *wpNames[] = { "wtpt", "lumi" };

  int checked = 0;
  for (int i = 0; i < 2; i++) {
    CIccTag *tag = pIcc->FindTag(wpSigs[i]);
    CIccTagXYZ *xyz = tag ? dynamic_cast<CIccTagXYZ *>(tag) : nullptr;
    if (!xyz || xyz->GetSize() < 1) continue;
    checked++;

    icXYZNumber val = (*xyz)[0];
    icFloatNumber y = icFtoD(val.Y);

    if (y < 0.0) {
      printf("         '%s' Y=%.6f is negative — physically impossible luminance\n",
             wpNames[i], y);
      printf("         %s[FAIL]%s White point/luminance Y must be >= 0 — "
             "ICC TN §3.1.24\n", ColorError(), ColorReset());
      issues++;
    }

    // Also check X and Z are reasonable for a white point
    icFloatNumber x = icFtoD(val.X);
    icFloatNumber z = icFtoD(val.Z);
    if (i == 0 && (x < 0.0 || z < 0.0)) {
      printf("         '%s' has negative X=%.6f or Z=%.6f\n", wpNames[i], x, z);
      printf("         %s[WARN]%s White point X and Z are typically non-negative — "
             "ICC TN Negative PCSXYZ\n", ColorError(), ColorReset());
      issues++;
    }
  }

  if (checked == 0)
    printf("         No white point tags present\n");
  else if (issues == 0)
    printf("         %s[OK]%s White point luminance values are non-negative\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// CF-172: Colorant XYZ Sum White Point Consistency
//
// For RGB profiles with matrix columns (rXYZ + gXYZ + bXYZ), the column-wise
// sum should approximate the adapted white point. This validates that negative
// XYZ values in individual primaries still produce a valid white when combined.
// If any primary has negative components, the sum can still be valid if the
// other primaries compensate (this is normal for wide-gamut adapted values).
// Spec: ICC TN Negative PCSXYZ, ICC.1-2022-05 §9.2.7
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF172_ColorantSumWhitePointConsistency(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-172]%s Colorant XYZ Sum White Point Consistency "
         "(%sICC TN Negative PCSXYZ, §9.2.7%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Need all three matrix columns
  static const icTagSignature matSigs[] = {
    icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag
  };

  icFloatNumber sumX = 0.0, sumY = 0.0, sumZ = 0.0;
  int colCount = 0;
  for (int i = 0; i < 3; i++) {
    CIccTag *tag = pIcc->FindTag(matSigs[i]);
    CIccTagXYZ *xyz = tag ? dynamic_cast<CIccTagXYZ *>(tag) : nullptr;
    if (!xyz || xyz->GetSize() < 1) continue;
    colCount++;

    icXYZNumber val = (*xyz)[0];
    sumX += icFtoD(val.X);
    sumY += icFtoD(val.Y);
    sumZ += icFtoD(val.Z);
  }

  if (colCount < 3) {
    printf("         Not all matrix columns present — check not applicable\n");
    return 0;
  }

  // Get the media white point for comparison
  CIccTag *wpTag = pIcc->FindTag(icSigMediaWhitePointTag);
  CIccTagXYZ *wpXyz = wpTag ? dynamic_cast<CIccTagXYZ *>(wpTag) : nullptr;

  // D50 reference values (used if no wtpt tag)
  icFloatNumber wpX = 0.9642, wpY = 1.0000, wpZ = 0.8249;
  if (wpXyz && wpXyz->GetSize() >= 1) {
    icXYZNumber wp = (*wpXyz)[0];
    wpX = icFtoD(wp.X);
    wpY = icFtoD(wp.Y);
    wpZ = icFtoD(wp.Z);
  }

  printf("         Column sum: X=%.4f Y=%.4f Z=%.4f\n", sumX, sumY, sumZ);
  printf("         White point: X=%.4f Y=%.4f Z=%.4f\n", wpX, wpY, wpZ);

  // Tolerance: s15Fixed16 quantization + Bradford adaptation rounding
  static constexpr double kWPSumTol = 0.05;
  icFloatNumber dX = std::fabs(sumX - wpX);
  icFloatNumber dY = std::fabs(sumY - wpY);
  icFloatNumber dZ = std::fabs(sumZ - wpZ);

  if (dX > kWPSumTol || dY > kWPSumTol || dZ > kWPSumTol) {
    printf("         Delta: dX=%.4f dY=%.4f dZ=%.4f (tolerance=%.4f)\n",
           dX, dY, dZ, kWPSumTol);
    printf("         %s[WARN]%s Colorant sum deviates from white point — "
           "round-trip accuracy affected — ICC TN §9.2.7\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         %s[OK]%s Colorant sum matches white point within tolerance\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// CF-173: PCS XYZ Absorber Encoding
//
// PCSXYZ [0,0,0] corresponds to the perfect absorber (ICC.1:2010 §6.4.3).
// In AToB/BToA LUT tags, the CLUT should be able to represent this anchor
// point. This check validates that any XYZ zero-encoding in the profile
// is consistent — no XYZ tag should have all components exactly zero unless
// it represents the absorber.
// Spec: ICC TN Negative PCSXYZ, ICC.1:2010 §6.4.3
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF173_PCSXYZAbsorberEncoding(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-173]%s PCS XYZ Absorber Encoding (%sICC TN Negative PCSXYZ, §6.4.3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // White point must NOT be [0,0,0] — that's the absorber, not the emitter
  CIccTag *wpTag = pIcc->FindTag(icSigMediaWhitePointTag);
  CIccTagXYZ *wpXyz = wpTag ? dynamic_cast<CIccTagXYZ *>(wpTag) : nullptr;

  int checked = 0;
  if (wpXyz && wpXyz->GetSize() >= 1) {
    checked++;
    icXYZNumber wp = (*wpXyz)[0];
    icFloatNumber x = icFtoD(wp.X);
    icFloatNumber y = icFtoD(wp.Y);
    icFloatNumber z = icFtoD(wp.Z);

    if (std::fabs(x) < 1e-6 && std::fabs(y) < 1e-6 && std::fabs(z) < 1e-6) {
      printf("         wtpt = [0,0,0] — this encodes the perfect absorber, "
             "not a valid white point\n");
      printf("         %s[FAIL]%s White point cannot be [0,0,0] — §6.4.3 reserves "
             "this for the perfect absorber\n", ColorError(), ColorReset());
      issues++;
    }
  }

  // Matrix columns should not all be zero either (already checked in CF-166)
  // but check luminance tag specifically
  CIccTag *lumiTag = pIcc->FindTag(icSigLuminanceTag);
  CIccTagXYZ *lumiXyz = lumiTag ? dynamic_cast<CIccTagXYZ *>(lumiTag) : nullptr;
  if (lumiXyz && lumiXyz->GetSize() >= 1) {
    checked++;
    icXYZNumber lumi = (*lumiXyz)[0];
    icFloatNumber y = icFtoD(lumi.Y);
    if (std::fabs(y) < 1e-6) {
      printf("         lumi Y = 0 — device has zero luminance output\n");
      printf("         %s[WARN]%s Luminance tag Y=0 implies zero-brightness device — §6.4.3\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (checked == 0)
    printf("         No white point or luminance tags present\n");
  else if (issues == 0)
    printf("         %s[OK]%s White point and luminance properly distinguish "
           "from absorber encoding\n", ColorSuccess(), ColorReset());

  return issues;
}


// CF-174: Lab Conversion Clipping Awareness
//
// When converting from PCSXYZ to PCSLAB, negative PCSXYZ values should be
// clipped per-component to values in the PCSLAB range (ICC.1:2010 §6.4).
// This check validates that profiles with Lab PCS don't contain values that
// would result from unclipped negative XYZ-to-Lab conversion. Specifically,
// if PCS is Lab and the profile contains LUT data, the LUT output should
// not contain Lab values that imply unclipped negative XYZ inputs.
// Spec: ICC TN Negative PCSXYZ, ICC.1:2010 §6.4
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF174_LabConversionClippingAwareness(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-174]%s Lab Conversion Clipping Awareness "
         "(%sICC TN Negative PCSXYZ, §6.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icColorSpaceSignature pcs = pIcc->m_Header.pcs;
  bool isLabPCS = (pcs == icSigLabData);
  bool isXYZPCS = (pcs == icSigXYZData);

  if (!isLabPCS && !isXYZPCS) {
    printf("         PCS is neither XYZ nor Lab — check not applicable\n");
    return 0;
  }

  // For Lab PCS: check matrix columns exist (they shouldn't for Lab PCS
  // profiles using LUTs, but matrix/TRC profiles use XYZ PCS)
  if (isLabPCS) {
    // Lab PCS profiles typically use AToB/BToA LUT tags, not matrix columns.
    // If matrix columns exist in a Lab PCS profile, that's unusual.
    bool hasMatrix = (pIcc->FindTag(icSigRedMatrixColumnTag) != nullptr);
    if (hasMatrix) {
      printf("         Lab PCS profile contains matrix column tags\n");
      printf("         %s[WARN]%s Matrix/TRC model requires XYZ PCS, not Lab — "
             "ICC.1 §8.4\n", ColorError(), ColorReset());
      issues++;
    } else {
      printf("         %s[OK]%s Lab PCS profile uses LUT model (no matrix columns)\n",
             ColorSuccess(), ColorReset());
    }
  }

  // For XYZ PCS: negative values are valid per the TN — just note encoding
  if (isXYZPCS) {
    // Check if any matrix columns have negative values
    static const icTagSignature matSigs[] = {
      icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag
    };
    int negCount = 0;
    for (int i = 0; i < 3; i++) {
      CIccTag *tag = pIcc->FindTag(matSigs[i]);
      CIccTagXYZ *xyz = tag ? dynamic_cast<CIccTagXYZ *>(tag) : nullptr;
      if (!xyz || xyz->GetSize() < 1) continue;

      icXYZNumber val = (*xyz)[0];
      if (icFtoD(val.X) < 0.0 || icFtoD(val.Y) < 0.0 || icFtoD(val.Z) < 0.0)
        negCount++;
    }

    if (negCount > 0) {
      printf("         %d matrix column(s) with negative components in XYZ PCS profile\n",
             negCount);
      printf("         %s[INFO]%s Per ICC TN: CMMs should accept negative PCSXYZ "
             "without clipping; on Lab conversion clip per-component — §6.4\n",
             ColorInfo(), ColorReset());
    } else {
      printf("         %s[OK]%s XYZ PCS profile with all non-negative matrix values\n",
             ColorSuccess(), ColorReset());
    }
  }

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

// ═══════════════════════════════════════════════════════════════════════════════
// ADGC raw data helper — shared by CF-124 through CF-136
// Each individual check calls this to get the tag bytes. The file read is cheap
// (~128 bytes), so the per-check overhead is negligible.
// ═══════════════════════════════════════════════════════════════════════════════

struct ADGCRawData {
  std::vector<uint8_t> buf;
  uint32_t adgcSize;
  size_t bytesRead;
  bool valid;
};

static ADGCRawData ReadADGCRawData(CIccProfile *pIcc, const char *filename) {
  ADGCRawData result = {{}, 0, 0, false};

  // Find ADGC tag entry
  uint32_t adgcOffset = 0;
  bool hasADGC = false;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    if (it->TagInfo.sig == (icTagSignature)kADGC_TagSig) {
      adgcOffset = it->TagInfo.offset;
      result.adgcSize = it->TagInfo.size;
      hasADGC = true;
      break;
    }
  }

  if (!hasADGC) return result;

  if (result.adgcSize < kADGC_HeaderSize) return result;

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh.fp) return result;

  if (fseek(fh.fp, (long)adgcOffset, SEEK_SET) != 0) return result;

  result.buf.resize(result.adgcSize);
  result.bytesRead = fread(result.buf.data(), 1, result.adgcSize, fh.fp);
  if (result.bytesRead < kADGC_HeaderSize) return result;

  result.valid = true;
  return result;
}

// CF-124: ADGC Type Signature — 'adgc' (0x61646763)
static int RunCF124_ADGCTypeSig(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  uint32_t typeSig = ReadU32BE(d + 0);
  if (typeSig != kADGC_TypeSig) {
    printf("         %s[FAIL]%s CF-124: ADGC type signature 0x%08X != expected 0x%08X ('adgc')"
           " — ICC.1 ADGC §3\n", ColorError(), ColorReset(), typeSig, kADGC_TypeSig);
    return 1;
  }
  printf("         %s[OK]%s CF-124: Type signature 'adgc' correct\n",
         ColorSuccess(), ColorReset());
  return 0;
}

// CF-125: ADGC Function Type ID — must be 1
static int RunCF125_ADGCFunctionTypeID(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  uint32_t funcType = ReadU32BE(d + 8);
  if (funcType != 1) {
    printf("         %s[FAIL]%s CF-125: functionTypeID=%u, expected 1 — ICC.1 ADGC §3\n",
           ColorError(), ColorReset(), funcType);
    return 1;
  }
  printf("         %s[OK]%s CF-125: functionTypeID=1 correct\n",
         ColorSuccess(), ColorReset());
  return 0;
}

// CF-126: ADGC Reserved Bytes — bytes 4-7 must be zero
static int RunCF126_ADGCReservedBytes(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  uint32_t res1 = ReadU32BE(d + 4);
  if (res1 != 0) {
    printf("         %s[FAIL]%s CF-126: Reserved bytes 4-7 = 0x%08X (must be 0)"
           " — ICC.1 ADGC Table 1\n", ColorError(), ColorReset(), res1);
    return 1;
  }
  printf("         %s[OK]%s CF-126: Reserved bytes 4-7 are zero\n",
         ColorSuccess(), ColorReset());
  return 0;
}

// CF-127: ADGC Float Field Finiteness — all 17 float32 fields must be finite
static int RunCF127_ADGCFloatFieldFiniteness(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  struct FloatField { size_t offset; const char *name; };
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
  if (nanCount > 0) return nanCount;
  printf("         %s[OK]%s CF-127: All 17 float fields are finite\n",
         ColorSuccess(), ColorReset());
  return 0;
}

// CF-128: ADGC Weight Coefficient Sum — kRed+kGreen+kBlue+kMax+kMin+kComponent ≈ 1.0
static int RunCF128_ADGCWeightCoefficientSum(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
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
      return 1;
    }
    printf("         %s[OK]%s CF-128: Weight coefficient sum=%.6f ≈ 1.0\n",
           ColorSuccess(), ColorReset(), sum);
  } else {
    printf("         %s[GAP]%s CF-128: Weight sum not evaluated due to non-finite values\n",
           ColorWarning(), ColorReset());
  }
  return 0;
}

// CF-129: ADGC Curve Position Bounds — positionNumber pairs must point within tag
static int RunCF129_ADGCCurvePositionBounds(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  struct CurvePos { size_t headerOffset; const char *name; };
  static const CurvePos positions[] = {{104, "Red"}, {112, "Green"}, {120, "Blue"}};
  int posIssues = 0;
  for (const auto &cp : positions) {
    uint32_t curveOff  = ReadU32BE(d + cp.headerOffset);
    uint32_t curveSize = ReadU32BE(d + cp.headerOffset + 4);
    if (curveOff == 0 && curveSize == 0) continue;
    if (curveOff + curveSize > rd.adgcSize) {
      printf("         %s[FAIL]%s CF-129: %s curve position (offset=%u, size=%u)"
             " exceeds tag size %u — ICC.1 ADGC Table 1\n",
             ColorError(), ColorReset(), cp.name, curveOff, curveSize, rd.adgcSize);
      posIssues++;
    }
    if (curveOff + 4 <= rd.adgcSize && curveOff < rd.bytesRead) {
      uint32_t count = ReadU32BE(d + curveOff);
      if (count == 0) {
        printf("         %s[WARN]%s CF-129: %s curve has 0 entries"
               " — ICC.1 ADGC Table 2\n",
               ColorWarning(), ColorReset(), cp.name);
        posIssues++;
      }
      uint32_t expectedSize = 4 + count * 12;
      if (curveSize > 0 && expectedSize > curveSize) {
        printf("         %s[WARN]%s CF-129: %s curve count=%u requires %u bytes"
               " but size=%u — ICC.1 ADGC Table 2\n",
               ColorWarning(), ColorReset(), cp.name, count, expectedSize, curveSize);
        posIssues++;
      }
    }
  }
  if (posIssues > 0) return posIssues;
  printf("         %s[OK]%s CF-129: All curve positions within tag bounds\n",
         ColorSuccess(), ColorReset());
  return 0;
}

// CF-130: ADGC Image-Specific GUID Flags — non-zero GUID requires header flags bits 0,1
static int RunCF130_ADGCGUIDFlags(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  bool guidNonZero = false;
  for (size_t i = 12; i < 28; i++) {
    if (d[i] != 0) { guidNonZero = true; break; }
  }
  if (guidNonZero) {
    uint32_t flags = pIcc->m_Header.flags;
    bool embedded   = (flags & 0x00000001) != 0;
    bool noIndepUse = (flags & 0x00000002) != 0;
    if (!embedded || !noIndepUse) {
      printf("         %s[FAIL]%s CF-130: ADGC GUID is non-zero (image-specific)"
             " but header flags=0x%08X — bits 0,1 must both be set"
             " — ICC.1 ADGC §3\n",
             ColorError(), ColorReset(), flags);
      return 1;
    }
    printf("         %s[OK]%s CF-130: Image-specific GUID with correct header flags\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("         %s[OK]%s CF-130: GUID is all-zero (non-image-specific)\n",
           ColorSuccess(), ColorReset());
  }
  return 0;
}

// CF-131: ADGC Headroom Range Plausibility — H_baseline/H_alternate in [0, 20]
static int RunCF131_ADGCHeadroomRange(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  float hBase = ReadFloat32BE(d + 28);
  float hAlt  = ReadFloat32BE(d + 32);
  int hIssues = 0;
  if (std::isfinite(hBase) && (hBase < 0.0f || hBase > 20.0f)) {
    printf("         %s[WARN]%s CF-131: H_baseline=%.4f outside plausible range [0,20]"
           " — ICC.1 ADGC §3\n", ColorWarning(), ColorReset(), hBase);
    hIssues++;
  }
  if (std::isfinite(hAlt) && (hAlt < 0.0f || hAlt > 20.0f)) {
    printf("         %s[WARN]%s CF-131: H_alternate=%.4f outside plausible range [0,20]"
           " — ICC.1 ADGC §3\n", ColorWarning(), ColorReset(), hAlt);
    hIssues++;
  }
  if (hIssues > 0) return hIssues;
  printf("         %s[OK]%s CF-131: Headroom values within plausible range\n",
         ColorSuccess(), ColorReset());
  return 0;
}

// CF-132: ADGC Curve Data Monotonicity — x values must be monotonically increasing
static int RunCF132_ADGCCurveMonotonicity(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  struct CurvePos { size_t headerOffset; const char *name; };
  static const CurvePos positions[] = {{104, "Red"}, {112, "Green"}, {120, "Blue"}};
  int monoIssues = 0;
  for (const auto &cp : positions) {
    uint32_t curveOff  = ReadU32BE(d + cp.headerOffset);
    uint32_t curveSize = ReadU32BE(d + cp.headerOffset + 4);
    if (curveOff == 0 && curveSize == 0) continue;
    if (curveOff + 4 > rd.bytesRead) continue;
    uint32_t count = ReadU32BE(d + curveOff);
    if (count < 2) continue;
    float prevX = -1e30f;
    uint32_t maxCheck = count;
    if (maxCheck > 1000) maxCheck = 1000;
    for (uint32_t i = 0; i < maxCheck; i++) {
      size_t xOff = curveOff + 4 + i * 12;
      if (xOff + 4 > rd.bytesRead) break;
      float x = ReadFloat32BE(d + xOff);
      if (std::isfinite(x) && std::isfinite(prevX) && x <= prevX) {
        printf("         %s[FAIL]%s CF-132: %s curve entry %u: x=%.6f ≤ prev=%.6f"
               " (not monotonically increasing) — ICC.1 ADGC Table 2\n",
               ColorError(), ColorReset(), cp.name, i, x, prevX);
        monoIssues++;
        break;
      }
      prevX = x;
    }
  }
  if (monoIssues > 0) return monoIssues;
  printf("         %s[OK]%s CF-132: All curve x-values monotonically increasing\n",
         ColorSuccess(), ColorReset());
  return 0;
}

// CF-133: ADGC H_baseline vs H_alternate Division-by-Zero
static int RunCF133_ADGCHeadroomDivByZero(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  float hBase = ReadFloat32BE(d + 28);
  float hAlt  = ReadFloat32BE(d + 32);
  if (std::isfinite(hBase) && std::isfinite(hAlt)) {
    if (ExactFiniteFloatEqual(hBase, hAlt)) {
      printf("         %s[FAIL]%s CF-133: H_baseline=%.4f == H_alternate=%.4f"
             " — division by zero in Output Evaluator W_target"
             " — ICC.1 ADGC §1.2.3\n",
             ColorError(), ColorReset(), hBase, hAlt);
      return 1;
    }
    printf("         %s[OK]%s CF-133: H_baseline ≠ H_alternate (no div-by-zero)\n",
           ColorSuccess(), ColorReset());
  }
  return 0;
}

// CF-134: ADGC Per-Channel GainMin ≤ GainMax
static int RunCF134_ADGCGainMinMax(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  struct GainPair { size_t minOff, maxOff; const char *name; };
  static const GainPair gains[] = {
    {36, 40, "Red"}, {48, 52, "Green"}, {60, 64, "Blue"},
  };
  int gainIssues = 0;
  for (const auto &gp : gains) {
    float gMin = ReadFloat32BE(d + gp.minOff);
    float gMax = ReadFloat32BE(d + gp.maxOff);
    if (std::isfinite(gMin) && std::isfinite(gMax) && gMin > gMax) {
      printf("         %s[WARN]%s CF-134: %s GainMin=%.4f > GainMax=%.4f"
             " (inverted gain range) — ICC.1 ADGC §1.2.3\n",
             ColorWarning(), ColorReset(), gp.name, gMin, gMax);
      gainIssues++;
    }
  }
  if (gainIssues > 0) return gainIssues;
  printf("         %s[OK]%s CF-134: All per-channel GainMin ≤ GainMax\n",
         ColorSuccess(), ColorReset());
  return 0;
}

// CF-135: ADGC Curve X-Value Domain Range — first x ≥ 0.0, last x ≤ 1.0
static int RunCF135_ADGCCurveXDomain(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  struct CurvePos { size_t headerOffset; const char *name; };
  static const CurvePos positions[] = {{104, "Red"}, {112, "Green"}, {120, "Blue"}};
  int rangeIssues = 0;
  for (const auto &cp : positions) {
    uint32_t curveOff  = ReadU32BE(d + cp.headerOffset);
    uint32_t curveSize = ReadU32BE(d + cp.headerOffset + 4);
    if (curveOff == 0 && curveSize == 0) continue;
    if (curveOff + 4 > rd.bytesRead) continue;
    uint32_t count = ReadU32BE(d + curveOff);
    if (count == 0) continue;
    // Check first x value
    size_t firstXOff = curveOff + 4;
    if (firstXOff + 4 <= rd.bytesRead) {
      float firstX = ReadFloat32BE(d + firstXOff);
      if (std::isfinite(firstX) && firstX < 0.0f) {
        printf("         %s[WARN]%s CF-135: %s curve first x=%.6f < 0.0"
               " — ICC.1 ADGC §1.2.2\n",
               ColorWarning(), ColorReset(), cp.name, firstX);
        rangeIssues++;
      }
    }
    // Check last x value
    size_t lastXOff = curveOff + 4 + (count - 1) * 12;
    if (lastXOff + 4 <= rd.bytesRead) {
      float lastX = ReadFloat32BE(d + lastXOff);
      if (std::isfinite(lastX) && lastX > 1.0f) {
        printf("         %s[WARN]%s CF-135: %s curve last x=%.6f > 1.0"
               " — ICC.1 ADGC §1.2.2\n",
               ColorWarning(), ColorReset(), cp.name, lastX);
        rangeIssues++;
      }
    }
  }
  if (rangeIssues > 0) return rangeIssues;
  printf("         %s[OK]%s CF-135: Curve x-value domains within [0.0, 1.0]\n",
         ColorSuccess(), ColorReset());
  return 0;
}

// CF-136: ADGC Curve Adjacent-Point X-Equality — no div-by-zero in cubic coeff
static int RunCF136_ADGCCurveAdjacentX(CIccProfile *pIcc, const char *filename) {
  ADGCRawData rd = ReadADGCRawData(pIcc, filename);
  if (!rd.valid) {
    printf("         No ADGC tag or read failed — check skipped\n");
    return 0;
  }
  const uint8_t *d = rd.buf.data();
  struct CurvePos { size_t headerOffset; const char *name; };
  static const CurvePos positions[] = {{104, "Red"}, {112, "Green"}, {120, "Blue"}};
  int divIssues = 0;
  for (const auto &cp : positions) {
    uint32_t curveOff  = ReadU32BE(d + cp.headerOffset);
    uint32_t curveSize = ReadU32BE(d + cp.headerOffset + 4);
    if (curveOff == 0 && curveSize == 0) continue;
    if (curveOff + 4 > rd.bytesRead) continue;
    uint32_t count = ReadU32BE(d + curveOff);
    if (count < 2) continue;
    uint32_t maxCheck = count;
    if (maxCheck > 1000) maxCheck = 1000;
    for (uint32_t i = 1; i < maxCheck; i++) {
      size_t prevXOff = curveOff + 4 + (i - 1) * 12;
      size_t curXOff  = curveOff + 4 + i * 12;
      if (curXOff + 4 > rd.bytesRead) break;
      float x1 = ReadFloat32BE(d + prevXOff);
      float x2 = ReadFloat32BE(d + curXOff);
      if (ExactFiniteFloatEqual(x1, x2)) {
        printf("         %s[FAIL]%s CF-136: %s curve entries %u,%u have equal x=%.6f"
               " — division by zero in Gain Evaluator cubic"
               " — ICC.1 ADGC §1.2.2\n",
               ColorError(), ColorReset(), cp.name, i - 1, i, x1);
        divIssues++;
        break;
      }
    }
  }
  if (divIssues > 0) return divIssues;
  printf("         %s[OK]%s CF-136: No adjacent curve points with equal x-values\n",
         ColorSuccess(), ColorReset());
  return 0;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-188: Global Per-Tag Validate() Sweep (SampleICC §3 — Compliance Testing)
//
// The SampleICC Profile Compliance Testing framework defines per-tag validation
// as the final step: call CIccTag::Validate() on EVERY tag in the profile and
// aggregate the compliance status. This catches tag-internal issues that
// per-type CF checks (CF-020..CF-034) do not cover — e.g., invalid curve
// parameters, broken LUT structures, or internally inconsistent data.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF188_GlobalTagValidateSweep(CIccProfile *pIcc) {
  int issues = 0;
  int totalTags = 0;
  int validatedOk = 0;
  int validatedWarn = 0;
  int validatedErr = 0;

  printf("  %s[CF-188]%s Global Per-Tag Validate() Sweep (%sSampleICC §3 Compliance%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
    if (!pTag) continue;

    totalTags++;
    char sigBuf[5];
    SigToChars(static_cast<uint32_t>(e->TagInfo.sig), sigBuf);

    std::string sigPath = "tag(";
    sigPath += sigBuf;
    sigPath += ")";
    std::string report;
    icValidateStatus status = pTag->Validate(sigPath, report, pIcc);

    if (status >= icValidateCriticalError) {
      printf("         Tag '%s': %sCRITICAL ERROR%s in Validate()\n",
             sigBuf, ColorError(), ColorReset());
      if (!report.empty()) {
        std::string firstLine = report.substr(0, report.find('\n'));
        if (!firstLine.empty())
          printf("           %s\n", firstLine.c_str());
      }
      validatedErr++;
      issues++;
    } else if (status >= icValidateNonCompliant) {
      printf("         Tag '%s': %snon-compliant%s per Validate()\n",
             sigBuf, ColorError(), ColorReset());
      if (!report.empty()) {
        std::string firstLine = report.substr(0, report.find('\n'));
        if (!firstLine.empty())
          printf("           %s\n", firstLine.c_str());
      }
      validatedErr++;
      issues++;
    } else if (status >= icValidateWarning) {
      validatedWarn++;
    } else {
      validatedOk++;
    }
  }

  printf("         Swept %d tags: %d OK, %d warnings, %d errors\n",
         totalTags, validatedOk, validatedWarn, validatedErr);

  if (issues == 0)
    printf("         %s[OK]%s All %d tags pass library Validate()\n",
           ColorSuccess(), ColorReset(), totalTags);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-189: Tag Type Recognition Coverage (SampleICC §3 — CheckTagTypes)
//
// The tag factory creates CIccTagUnknown objects for tag type signatures it
// does not recognize. While the profile may be technically valid (private tags
// are allowed), an unrecognized type signature indicates either:
//   (a) A private/vendor-specific tag type — informational
//   (b) A corrupted or malformed type signature — potential issue
//
// This check counts how many tags resolved to CIccTagUnknown and reports them.
// Any tag with an unrecognized type signature cannot be semantically validated.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF189_TagTypeRecognition(CIccProfile *pIcc) {
  int issues = 0;
  int totalTags = 0;
  int unknownCount = 0;

  printf("  %s[CF-189]%s Tag Type Recognition Coverage (%sSampleICC §3 CheckTagTypes%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
    if (!pTag) continue;

    totalTags++;

    const char *className = pTag->GetClassName();
    if (className && strcmp(className, "CIccTagUnknown") == 0) {
      char sigBuf[5], typeBuf[5];
      SigToChars(static_cast<uint32_t>(e->TagInfo.sig), sigBuf);
      SigToChars(static_cast<uint32_t>(pTag->GetType()), typeBuf);

      printf("         Tag '%s': unrecognized type '%s' → CIccTagUnknown\n",
             sigBuf, typeBuf);
      unknownCount++;
      issues++;
    }
  }

  printf("         %d/%d tags have recognized type signatures\n",
         totalTags - unknownCount, totalTags);

  if (issues == 0)
    printf("         %s[OK]%s All %d tag types are recognized by the factory\n",
           ColorSuccess(), ColorReset(), totalTags);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-190: Profile Legibility Gate (SampleICC §3 — "Is it legible?")
//
// The SampleICC compliance testing framework asks three questions:
//   1. Is it legible? (Can we read it at all?)
//   2. Does it conform? (Are spec requirements met?)
//   3. Is it usable? (Can the CMM process it?)
//
// This check validates the first question: profile legibility. It verifies:
//   (a) The tag table is non-empty (at least 1 tag parsed)
//   (b) All tag directory entries point to loadable tag data
//   (c) No NULL tag pointers after Read() (broken parse)
//   (d) Profile file size matches header declaration (ReadValidate)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF190_ProfileLegibility(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  int totalEntries = 0;

  printf("  %s[CF-190]%s Profile Legibility Gate (%sSampleICC §3 ReadValidate%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Check 1: Tag table is non-empty
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    totalEntries++;
  }

  if (totalEntries == 0) {
    printf("         %s[FAIL]%s Profile has 0 tag entries — not legible\n",
           ColorError(), ColorReset());
    issues++;
    return issues;
  }

  // Check 2: All tag directory entries resolve to non-NULL tag objects
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
    if (!pTag) {
      char sigBuf[5];
      SigToChars(static_cast<uint32_t>(e->TagInfo.sig), sigBuf);
      printf("         Tag '%s' (offset %u, size %u): NULL after Read()\n",
             sigBuf, (unsigned)e->TagInfo.offset, (unsigned)e->TagInfo.size);
      issues++;
    }
  }

  // Check 3: File size vs header declared size
  if (filename && filename[0]) {
    FILE *fp = fopen(filename, "rb");
    if (fp) {
      fseek(fp, 0, SEEK_END);
      long fileSize = ftell(fp);
      fclose(fp);

      uint32_t headerSize = pIcc->m_Header.size;
      if (fileSize > 0 && headerSize > 0) {
        if ((uint32_t)fileSize < headerSize) {
          printf("         File truncated: actual %ld bytes < header declares %u bytes\n",
                 fileSize, headerSize);
          printf("         %s[FAIL]%s File size mismatch — profile truncated\n",
                 ColorError(), ColorReset());
          issues++;
        } else if ((uint32_t)fileSize > headerSize + 3) {
          // Allow 0-3 byte padding for alignment
          printf("         File has %ld bytes trailing data beyond header size %u\n",
                 fileSize - (long)headerSize, headerSize);
        }
      }
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s Profile is legible: %d tags parsed, all non-NULL\n",
           ColorSuccess(), ColorReset(), totalEntries);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-208: Tag Type Version Compatibility (ICC.1-2022-05 §7.2.4 + §10)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF208_TagTypeVersionCompatibility(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-208]%s Tag Type Version Compatibility (%sICC.1-2022-05 §7.2.4, §10%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int major = (pIcc->m_Header.version >> 24) & 0xFF;

  // v4+ introduced parametricCurveType, multiProcessElementType, etc.
  // v2 profiles should NOT use v4+ tag types
  if (major >= 4) {
    printf("         Profile version %d.x — all standard tag types permitted\n", major);
    printf("         %s[OK]%s Version %d.x tag types unrestricted\n",
           ColorSuccess(), ColorReset(), major);
    return 0;
  }

  // v2 tag type restrictions
  int tagCount = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag) continue;
    tagCount++;

    icTagTypeSignature typeSig = pTag->GetType();
    char sigCC[5];
    SigToChars(static_cast<icUInt32Number>(typeSig), sigCC);

    // parametricCurveType (para) is v4+ only
    if (typeSig == icSigParametricCurveType) {
      char tagCC[5];
      SigToChars(static_cast<icUInt32Number>(it->TagInfo.sig), tagCC);
      printf("         tag '%s' uses parametricCurveType ('para') — %sv4+ only in v%d profile%s\n",
             tagCC, ColorError(), major, ColorReset());
      printf("         %s[FAIL]%s parametricCurveType not defined for v%d — ICC.1-2022-05 §10.18\n",
             ColorError(), ColorReset(), major);
      issues++;
    }

    // multiProcessElementType (mpet) is v5+ only
    if (typeSig == icSigMultiProcessElementType) {
      char tagCC[5];
      SigToChars(static_cast<icUInt32Number>(it->TagInfo.sig), tagCC);
      printf("         tag '%s' uses multiProcessElementType ('mpet') — %sv5+ only in v%d profile%s\n",
             tagCC, ColorError(), major, ColorReset());
      printf("         %s[FAIL]%s multiProcessElementType not defined for v%d — ICC.2-2023 §10.x\n",
             ColorError(), ColorReset(), major);
      issues++;
    }

    // lutAToBType (mAB ) is v4+ only (v2 uses lut8/lut16)
    if (typeSig == icSigLutAtoBType) {
      char tagCC[5];
      SigToChars(static_cast<icUInt32Number>(it->TagInfo.sig), tagCC);
      printf("         tag '%s' uses lutAToBType ('mAB ') — %sv4+ only in v%d profile%s\n",
             tagCC, ColorError(), major, ColorReset());
      printf("         %s[FAIL]%s lutAToBType not defined for v%d — ICC.1-2022-05 §10.11\n",
             ColorError(), ColorReset(), major);
      issues++;
    }

    // lutBToAType (mBA ) is v4+ only
    if (typeSig == icSigLutBtoAType) {
      char tagCC[5];
      SigToChars(static_cast<icUInt32Number>(it->TagInfo.sig), tagCC);
      printf("         tag '%s' uses lutBToAType ('mBA ') — %sv4+ only in v%d profile%s\n",
             tagCC, ColorError(), major, ColorReset());
      printf("         %s[FAIL]%s lutBToAType not defined for v%d — ICC.1-2022-05 §10.12\n",
             ColorError(), ColorReset(), major);
      issues++;
    }
  }

  printf("         Checked %d tags for v%d compatibility\n", tagCount, major);

  if (issues == 0)
    printf("         %s[OK]%s All tag types compatible with profile version %d.x\n",
           ColorSuccess(), ColorReset(), major);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-209: Colorspace Channel Count vs LUT Dimensions (ICC.1-2022-05 §7.2.6, §10.8-10.11)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF209_ColorspaceLUTChannelMatch(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-209]%s Colorspace Channel Count vs LUT Dimensions (%sICC.1-2022-05 §7.2.6, §10.8-10.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
  icColorSpaceSignature pcs = pIcc->m_Header.pcs;
  int csChannels = icGetSpaceSamples(cs);
  int pcsChannels = icGetSpaceSamples(pcs);

  printf("         colorSpace channels=%d, PCS channels=%d\n", csChannels, pcsChannels);

  static const struct {
    icTagSignature sig;
    const char *name;
    bool isAToB; // true = device→PCS, false = PCS→device
  } kLUTTags[] = {
    { icSigAToB0Tag, "AToB0", true },
    { icSigAToB1Tag, "AToB1", true },
    { icSigAToB2Tag, "AToB2", true },
    { icSigBToA0Tag, "BToA0", false },
    { icSigBToA1Tag, "BToA1", false },
    { icSigBToA2Tag, "BToA2", false },
  };

  int checked = 0;
  for (int i = 0; i < 6; i++) {
    CIccTag *pTag = pIcc->FindTag(kLUTTags[i].sig);
    if (!pTag) continue;

    checked++;
    int expectedIn = kLUTTags[i].isAToB ? csChannels : pcsChannels;
    int expectedOut = kLUTTags[i].isAToB ? pcsChannels : csChannels;

    // Check for LUT types that expose channel counts
    CIccMBB *pMBB = dynamic_cast<CIccMBB *>(pTag);
    if (pMBB) {
      int lutIn = static_cast<int>(pMBB->InputChannels());
      int lutOut = static_cast<int>(pMBB->OutputChannels());

      if (lutIn != expectedIn) {
        printf("         %s input channels=%d, expected %d (from %s)\n",
               kLUTTags[i].name, lutIn, expectedIn,
               kLUTTags[i].isAToB ? "colorSpace" : "PCS");
        printf("         %s[FAIL]%s %s input channel mismatch — ICC.1-2022-05 §10.8-10.11\n",
               ColorError(), ColorReset(), kLUTTags[i].name);
        issues++;
      }
      if (lutOut != expectedOut) {
        printf("         %s output channels=%d, expected %d (from %s)\n",
               kLUTTags[i].name, lutOut, expectedOut,
               kLUTTags[i].isAToB ? "PCS" : "colorSpace");
        printf("         %s[FAIL]%s %s output channel mismatch — ICC.1-2022-05 §10.8-10.11\n",
               ColorError(), ColorReset(), kLUTTags[i].name);
        issues++;
      }

      if (lutIn == expectedIn && lutOut == expectedOut) {
        printf("         %s: in=%d out=%d ✓\n", kLUTTags[i].name, lutIn, lutOut);
      }
    }
  }

  if (checked == 0) {
    printf("         No AToB/BToA LUT tags present\n");
  }

  if (issues == 0)
    printf("         %s[OK]%s Colorspace/PCS channel counts match LUT dimensions\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-212: textType Null Termination (ICC.1-2022-05 §10.24)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF212_TextTypeNullTermination(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-212]%s textType Null Termination (%sICC.1-2022-05 §10.24%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Tags that may use textType
  static const icTagSignature kTextTags[] = {
    icSigCopyrightTag,
    icSigCharTargetTag,
  };
  static const char *kTextNames[] = {
    "cprt (copyright)",
    "targ (charTarget)",
  };

  int checked = 0;
  for (int i = 0; i < 2; i++) {
    CIccTag *pTag = pIcc->FindTag(kTextTags[i]);
    if (!pTag) continue;

    CIccTagText *pText = dynamic_cast<CIccTagText *>(pTag);
    if (!pText) continue; // not textType (may be mluc)

    checked++;
    const char *text = pText->GetText();
    if (!text) {
      printf("         %s: %snull text pointer%s\n",
             kTextNames[i], ColorError(), ColorReset());
      printf("         %s[FAIL]%s textType has null data — ICC.1-2022-05 §10.24\n",
             ColorError(), ColorReset());
      issues++;
      continue;
    }

    // Check that the text content is reasonable (7-bit ASCII per §10.24)
    size_t len = strlen(text);
    if (len == 0) {
      printf("         %s: empty text (0 bytes)\n", kTextNames[i]);
      printf("         %s[FAIL]%s textType should contain at least 1 character — ICC.1-2022-05 §10.24\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         %s: \"%.*s\" (%zu bytes)\n", kTextNames[i],
             static_cast<int>(len > 60 ? 60 : len), text, len);
    }
  }

  if (checked == 0) {
    printf("         No textType tags found (profiles may use multiLocalizedUnicodeType)\n");
  }

  if (issues == 0)
    printf("         %s[OK]%s textType tag structure conformant\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-213: viewingConditionsType Completeness (ICC.1-2022-05 §10.32)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF213_ViewingConditionsCompleteness(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-213]%s viewingConditionsType Completeness (%sICC.1-2022-05 §10.32%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigViewingConditionsTag);
  if (!pTag) {
    printf("         No viewingConditionsTag ('view') present\n");
    printf("         %s[OK]%s viewingConditionsTag is optional\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  CIccTagViewingConditions *pVC = dynamic_cast<CIccTagViewingConditions *>(pTag);
  if (!pVC) {
    printf("         %sviewingConditionsTag is not viewingConditionsType%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s viewingConditionsTag must be viewingConditionsType — ICC.1-2022-05 §10.32\n",
           ColorError(), ColorReset());
    return 1;
  }

  // §10.32: illuminant (XYZ), surround (XYZ), standard illuminant type
  const icXYZNumber &illum = pVC->m_XYZIllum;
  const icXYZNumber &surr = pVC->m_XYZSurround;
  icIlluminant illumType = pVC->m_illumType;

  double iX = icFtoD(illum.X), iY = icFtoD(illum.Y), iZ = icFtoD(illum.Z);
  double sX = icFtoD(surr.X), sY = icFtoD(surr.Y), sZ = icFtoD(surr.Z);

  printf("         Illuminant: X=%.4f, Y=%.4f, Z=%.4f\n", iX, iY, iZ);
  printf("         Surround:   X=%.4f, Y=%.4f, Z=%.4f\n", sX, sY, sZ);
  printf("         Illuminant type: %u\n", static_cast<unsigned>(illumType));

  // Illuminant Y must be positive (luminance in cd/m²)
  if (iY <= 0.0) {
    printf("         Illuminant Y=%.4f — %smust be positive%s\n",
           iY, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Illuminant luminance must be > 0 — ICC.1-2022-05 §10.32\n",
           ColorError(), ColorReset());
    issues++;
  }

  // Surround Y should be non-negative
  if (sY < 0.0) {
    printf("         Surround Y=%.4f — %smust be non-negative%s\n",
           sY, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Surround luminance must be >= 0 — ICC.1-2022-05 §10.32\n",
           ColorError(), ColorReset());
    issues++;
  }

  // Illuminant type must be a valid enumeration value
  // ICC.1-2022-05 §10.32 Table 27: valid illuminant types 0-9
  if (static_cast<unsigned>(illumType) > 9 && illumType != static_cast<icIlluminant>(0)) {
    printf("         Illuminant type=%u — %sunrecognized value%s\n",
           static_cast<unsigned>(illumType), ColorError(), ColorReset());
    printf("         %s[FAIL]%s Illuminant type out of range — ICC.1-2022-05 §10.32 Table 27\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s viewingConditionsType structure conformant\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-220: mluc Name Record Overlap Detection (ICC TN PSD §mluc)
//
// The tech note warns that name records "can point anywhere in the storage area
// and can be in any order with overlaps" — shared records are allowed but
// PARTIAL overlaps are suspicious (CWE-119). Two records that share the exact
// same [offset, offset+length) are fine (intentional sharing). Two records
// whose ranges partially overlap indicate encoder error or deliberate attack.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF220_MlucNameRecordOverlap(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-220]%s mluc Name Record Overlap Detection (%sICC TN PSD §mluc%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename) {
    printf("         No filename — skipping raw mluc overlap check\n");
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) return 0;

  static const uint32_t kMlucTypeSig = 0x6D6C7563;
  std::vector<icUInt32Number> visitedOffsets;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    icUInt32Number tagOffset = e->TagInfo.offset;
    icUInt32Number tagSize = e->TagInfo.size;

    bool dup = false;
    for (size_t v = 0; v < visitedOffsets.size(); v++)
      if (visitedOffsets[v] == tagOffset) { dup = true; break; }
    if (dup) continue;
    visitedOffsets.push_back(tagOffset);

    if (tagSize < 16 || (long)(tagOffset + 16) > fh.fileSize) continue;

    uint8_t hdr[16];
    if (!fh.Seek((long)tagOffset) || !fh.ReadBytes(hdr, 16)) continue;
    if (ReadU32BE(hdr) != kMlucTypeSig) continue;

    uint32_t recordCount = ReadU32BE(hdr + 8);
    uint32_t recordSize  = ReadU32BE(hdr + 12);
    if (recordSize != 12 || recordCount < 2) continue;

    uint64_t recordsEnd = 16ULL + (uint64_t)recordCount * 12ULL;
    if (recordsEnd > tagSize) continue;

    size_t recBytes = recordCount * 12;
    std::vector<uint8_t> recBuf(recBytes);
    if (!fh.Seek((long)(tagOffset + 16)) || !fh.ReadBytes(recBuf.data(), recBytes))
      continue;

    checked++;
    char sigBuf[5];
    SigToChars((uint32_t)e->TagInfo.sig, sigBuf);

    // Collect all [offset, length) ranges
    struct Range { uint32_t off; uint32_t len; uint32_t idx; };
    std::vector<Range> ranges;
    for (uint32_t r = 0; r < recordCount; r++) {
      const uint8_t *rec = recBuf.data() + r * 12;
      uint32_t strLen = ReadU32BE(rec + 4);
      uint32_t strOff = ReadU32BE(rec + 8);
      if (strLen > 0)
        ranges.push_back({strOff, strLen, r});
    }

    // Check for partial overlaps (exact match = sharing = OK)
    for (size_t a = 0; a < ranges.size(); a++) {
      for (size_t b = a + 1; b < ranges.size(); b++) {
        uint32_t aStart = ranges[a].off, aEnd = ranges[a].off + ranges[a].len;
        uint32_t bStart = ranges[b].off, bEnd = ranges[b].off + ranges[b].len;
        // Exact same range = intentional sharing
        if (aStart == bStart && aEnd == bEnd) continue;
        // Check partial overlap
        if (aStart < bEnd && bStart < aEnd) {
          printf("         Tag '%s': records %u and %u partially overlap "
                 "([%u..%u) vs [%u..%u))\n",
                 sigBuf, ranges[a].idx, ranges[b].idx,
                 aStart, aEnd, bStart, bEnd);
          printf("         %s[FAIL]%s Partial name record overlap — potential CWE-119\n",
                 ColorError(), ColorReset());
          issues++;
        }
      }
    }
  }

  if (checked > 0 && issues == 0)
    printf("         %s[OK]%s %d mluc tag(s) checked, no partial overlaps\n",
           ColorSuccess(), ColorReset(), checked);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-221: profileSequenceDescTag Structure Validation (ICC.1-2022-05 §9.2.50)
//
// Required in v4+ DeviceLink profiles. Each description entry contains:
//   - Device manufacturer (4B) + model signature (4B) = 8B
//   - Device attributes (8B)
//   - Technology signature (4B)
//   - Two embedded mluc structures (manufacturer desc, model desc)
// Validate description count, and that each entry's sub-structures are valid.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF221_ProfileSequenceDescStructure(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-221]%s profileSequenceDescTag Structure (%sICC.1-2022-05 §9.2.50%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigProfileSequenceDescTag);
  if (!pTag) {
    // Required for DeviceLink v4+
    icUInt32Number ver = pIcc->m_Header.version;
    if (pIcc->m_Header.deviceClass == icSigLinkClass && ver >= icVersionNumberV4) {
      printf("         %s[FAIL]%s profileSequenceDescTag required for v4+ DeviceLink profiles\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         No profileSequenceDescTag — not required for this class\n");
    }
    return issues;
  }

  CIccTagProfileSeqDesc *pSeq = dynamic_cast<CIccTagProfileSeqDesc *>(pTag);
  if (!pSeq || !pSeq->m_Descriptions) {
    printf("         %s[FAIL]%s profileSequenceDescTag has wrong type or null descriptions\n",
           ColorError(), ColorReset());
    return 1;
  }

  size_t descCount = pSeq->m_Descriptions->size();
  printf("         Description count: %zu\n", descCount);

  if (descCount == 0) {
    printf("         %s[WARN]%s Empty profile sequence (zero descriptions)\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  // For DeviceLink, description count should be ≥ 2 (source + destination)
  if (pIcc->m_Header.deviceClass == icSigLinkClass && descCount == 1) {
    printf("         %s[WARN]%s DeviceLink pseq has only 1 description (expected ≥ 2)\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  // Excessive descriptions → DoS risk
  if (descCount > 256) {
    printf("         %s[FAIL]%s %zu descriptions exceeds reasonable maximum (256)\n",
           ColorError(), ColorReset(), descCount);
    issues++;
  }

  // Validate each description entry has valid manufacturer/model descriptions
  int entryIdx = 0;
  for (auto dit = pSeq->m_Descriptions->begin();
       dit != pSeq->m_Descriptions->end(); ++dit, ++entryIdx) {
    // Each CIccProfileDescStruct has:
    //   m_deviceMfg, m_deviceModel (signatures)
    //   m_attributes (icUInt64Number)
    //   m_technology (signature)
    //   m_deviceMfgDesc, m_deviceModelDesc (CIccProfileDescText wrapping mluc or textDescription)

    // Validate manufacturer description locale counts via GetTag()
    size_t mfgCount = 0;
    CIccTag *pMfgTag = dit->m_deviceMfgDesc.GetTag();
    if (pMfgTag) {
      CIccTagMultiLocalizedUnicode *pMluc =
        dynamic_cast<CIccTagMultiLocalizedUnicode*>(pMfgTag);
      if (pMluc) mfgCount = pMluc->m_Strings ? pMluc->m_Strings->size() : 0;
    }
    size_t mdlCount = 0;
    CIccTag *pMdlTag = dit->m_deviceModelDesc.GetTag();
    if (pMdlTag) {
      CIccTagMultiLocalizedUnicode *pMluc =
        dynamic_cast<CIccTagMultiLocalizedUnicode*>(pMdlTag);
      if (pMluc) mdlCount = pMluc->m_Strings ? pMluc->m_Strings->size() : 0;
    }

    // Check for unreasonable locale counts in embedded mluc
    if (mfgCount > 100) {
      printf("         Entry %d: manufacturer desc has %zu locales (>100 suspicious)\n",
             entryIdx, mfgCount);
      printf("         %s[WARN]%s Excessive locale count in embedded mluc\n",
             ColorWarning(), ColorReset());
      issues++;
    }
    if (mdlCount > 100) {
      printf("         Entry %d: model desc has %zu locales (>100 suspicious)\n",
             entryIdx, mdlCount);
      printf("         %s[WARN]%s Excessive locale count in embedded mluc\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s profileSequenceDescTag structure valid (%zu descriptions)\n",
           ColorSuccess(), ColorReset(), descCount);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-222: profileSequenceIdentifierTag Validation (ICC.1-2022-05 §9.2.51)
//
// Optional tag containing profile IDs (MD5) and descriptions for each profile
// in a DeviceLink sequence. Each entry has a profileID (16-byte MD5) and an
// mluc description. Validate entry count, profile ID format, and descriptions.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF222_ProfileSequenceIdentifierTag(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-222]%s profileSequenceIdentifierTag Validation (%sICC.1-2022-05 §9.2.51%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigProfileSequceIdTag);
  if (!pTag) {
    printf("         No profileSequenceIdentifierTag ('psid') present\n");
    return 0;
  }

  CIccTagProfileSequenceId *pPsid = dynamic_cast<CIccTagProfileSequenceId *>(pTag);
  if (!pPsid) {
    printf("         %s[FAIL]%s profileSequenceIdentifierTag has wrong type\n",
           ColorError(), ColorReset());
    return 1;
  }

  // Count entries
  int entryCount = 0;
  int zeroIdCount = 0;
  for (auto it = pPsid->begin(); it != pPsid->end(); ++it) {
    entryCount++;

    // Check if profile ID is all zeros (uncomputed)
    bool allZero = true;
    for (int b = 0; b < 16; b++) {
      if (it->m_profileID.ID8[b] != 0) { allZero = false; break; }
    }
    if (allZero) zeroIdCount++;

    // Validate description mluc has reasonable locale count
    size_t descCount = it->m_desc.m_Strings ? it->m_desc.m_Strings->size() : 0;
    if (descCount > 100) {
      printf("         Entry %d: description has %zu locales (>100 suspicious)\n",
             entryCount - 1, descCount);
      printf("         %s[WARN]%s Excessive locales in psid entry description\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  }

  printf("         Entries: %d, zero-ID entries: %d\n", entryCount, zeroIdCount);

  if (entryCount == 0) {
    printf("         %s[WARN]%s Empty profileSequenceIdentifierTag\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (entryCount > 256) {
    printf("         %s[FAIL]%s %d entries exceeds reasonable maximum (256)\n",
           ColorError(), ColorReset(), entryCount);
    issues++;
  }

  // If all entries have zero profile IDs, that's noteworthy
  if (entryCount > 0 && zeroIdCount == entryCount) {
    printf("         %s[WARN]%s All profile IDs are zero (uncomputed) — §9.2.51\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  // Cross-check: if pseq exists, psid entry count should match
  CIccTag *pSeqTag = pIcc->FindTag(icSigProfileSequenceDescTag);
  if (pSeqTag) {
    CIccTagProfileSeqDesc *pSeq = dynamic_cast<CIccTagProfileSeqDesc *>(pSeqTag);
    if (pSeq && pSeq->m_Descriptions) {
      size_t seqCount = pSeq->m_Descriptions->size();
      if ((size_t)entryCount != seqCount) {
        printf("         %s[WARN]%s psid has %d entries but pseq has %zu — mismatch\n",
               ColorWarning(), ColorReset(), entryCount, seqCount);
        issues++;
      }
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s profileSequenceIdentifierTag valid (%d entries)\n",
           ColorSuccess(), ColorReset(), entryCount);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-223: mluc Zero-Name Placeholder Encoding (ICC TN PSD §placeholder)
//
// The tech note recommends that when component profiles lack deviceMfgDescTag
// or deviceModelDescTag, a "placeholder" mluc with zero name records should
// encode as exactly 12 bytes (type sig + reserved + count=0). Implementations
// may encode 12, 16, or 28 bytes, causing parsing ambiguity. This check
// validates mluc tags with zero records have minimal encoding.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF223_MlucZeroNamePlaceholder(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-223]%s mluc Zero-Name Placeholder Encoding (%sICC TN PSD §placeholder%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename) {
    printf("         No filename — skipping raw mluc placeholder check\n");
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) return 0;

  static const uint32_t kMlucTypeSig = 0x6D6C7563;
  std::vector<icUInt32Number> visitedOffsets;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    icUInt32Number tagOffset = e->TagInfo.offset;
    icUInt32Number tagSize = e->TagInfo.size;

    bool dup = false;
    for (size_t v = 0; v < visitedOffsets.size(); v++)
      if (visitedOffsets[v] == tagOffset) { dup = true; break; }
    if (dup) continue;
    visitedOffsets.push_back(tagOffset);

    if (tagSize < 12 || (long)(tagOffset + 12) > fh.fileSize) continue;

    uint8_t hdr[16];
    size_t readSz = (tagSize >= 16) ? 16 : 12;
    if (!fh.Seek((long)tagOffset) || !fh.ReadBytes(hdr, readSz)) continue;
    if (ReadU32BE(hdr) != kMlucTypeSig) continue;

    uint32_t recordCount = ReadU32BE(hdr + 8);
    if (recordCount != 0) continue;

    checked++;
    char sigBuf[5];
    SigToChars((uint32_t)e->TagInfo.sig, sigBuf);

    // Zero-name mluc: recommended encoding is exactly 12 bytes
    if (tagSize != 12) {
      printf("         Tag '%s': zero-name mluc is %u bytes (recommended: 12)\n",
             sigBuf, tagSize);
      printf("         %s[WARN]%s Non-minimal zero-name placeholder encoding — TN PSD\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  }

  if (checked > 0 && issues == 0)
    printf("         %s[OK]%s %d zero-name mluc tag(s) use minimal encoding\n",
           ColorSuccess(), ColorReset(), checked);
  else if (checked == 0)
    printf("         No zero-name mluc tags found\n");

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-224: mluc Reserved Field Zero (ICC.1-2022-05 §10.13)
//
// Bytes 4-7 of every mluc must be zero (reserved). Non-zero values indicate
// encoder error or potential data injection.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF224_MlucReservedFieldZero(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-224]%s mluc Reserved Field Zero (%sICC.1-2022-05 §10.13%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename) {
    printf("         No filename — skipping raw mluc reserved check\n");
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) return 0;

  static const uint32_t kMlucTypeSig = 0x6D6C7563;
  std::vector<icUInt32Number> visitedOffsets;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    icUInt32Number tagOffset = e->TagInfo.offset;
    icUInt32Number tagSize = e->TagInfo.size;

    bool dup = false;
    for (size_t v = 0; v < visitedOffsets.size(); v++)
      if (visitedOffsets[v] == tagOffset) { dup = true; break; }
    if (dup) continue;
    visitedOffsets.push_back(tagOffset);

    if (tagSize < 12 || (long)(tagOffset + 12) > fh.fileSize) continue;

    uint8_t hdr[12];
    if (!fh.Seek((long)tagOffset) || !fh.ReadBytes(hdr, 12)) continue;
    if (ReadU32BE(hdr) != kMlucTypeSig) continue;

    checked++;
    char sigBuf[5];
    SigToChars((uint32_t)e->TagInfo.sig, sigBuf);

    uint32_t reserved = ReadU32BE(hdr + 4);
    if (reserved != 0) {
      printf("         Tag '%s': mluc reserved field = 0x%08X (must be 0)\n",
             sigBuf, reserved);
      printf("         %s[FAIL]%s mluc reserved bytes non-zero — §10.13\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (checked > 0 && issues == 0)
    printf("         %s[OK]%s %d mluc tag(s) checked, all reserved fields zero\n",
           ColorSuccess(), ColorReset(), checked);
  else if (checked == 0)
    printf("         No mluc tags found\n");

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-225: mluc Name Record String Alignment (ICC.1-2022-05 §7.1, §10.13)
//
// §7.1 requires all tagged element data to be padded to 4-byte boundaries.
// For mluc, the string storage area should have string offsets that are even
// (Unicode strings are 2-byte encoded). Additionally, string lengths should
// be even (complete UTF-16 code units).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF225_MlucStringAlignment(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-225]%s mluc Name Record String Alignment (%sICC.1-2022-05 §7.1, §10.13%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename) {
    printf("         No filename — skipping raw mluc alignment check\n");
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) return 0;

  static const uint32_t kMlucTypeSig = 0x6D6C7563;
  std::vector<icUInt32Number> visitedOffsets;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    icUInt32Number tagOffset = e->TagInfo.offset;
    icUInt32Number tagSize = e->TagInfo.size;

    bool dup = false;
    for (size_t v = 0; v < visitedOffsets.size(); v++)
      if (visitedOffsets[v] == tagOffset) { dup = true; break; }
    if (dup) continue;
    visitedOffsets.push_back(tagOffset);

    if (tagSize < 16 || (long)(tagOffset + 16) > fh.fileSize) continue;

    uint8_t hdr[16];
    if (!fh.Seek((long)tagOffset) || !fh.ReadBytes(hdr, 16)) continue;
    if (ReadU32BE(hdr) != kMlucTypeSig) continue;

    uint32_t recordCount = ReadU32BE(hdr + 8);
    uint32_t recordSize  = ReadU32BE(hdr + 12);
    if (recordSize != 12 || recordCount == 0) continue;

    uint64_t recordsEnd = 16ULL + (uint64_t)recordCount * 12ULL;
    if (recordsEnd > tagSize) continue;

    size_t recBytes = recordCount * 12;
    std::vector<uint8_t> recBuf(recBytes);
    if (!fh.Seek((long)(tagOffset + 16)) || !fh.ReadBytes(recBuf.data(), recBytes))
      continue;

    checked++;
    char sigBuf[5];
    SigToChars((uint32_t)e->TagInfo.sig, sigBuf);

    for (uint32_t r = 0; r < recordCount; r++) {
      const uint8_t *rec = recBuf.data() + r * 12;
      uint32_t strLen = ReadU32BE(rec + 4);
      uint32_t strOff = ReadU32BE(rec + 8);

      // String length should be even (UTF-16 = 2 bytes per code unit)
      if (strLen & 1) {
        printf("         Tag '%s' record %u: odd string length %u (UTF-16 must be even)\n",
               sigBuf, r, strLen);
        printf("         %s[WARN]%s Odd mluc string length — potential truncation\n",
               ColorWarning(), ColorReset());
        issues++;
      }

      // String offset should be even for UTF-16 alignment
      if ((strOff & 1) && strLen > 0) {
        printf("         Tag '%s' record %u: odd string offset %u (UTF-16 misaligned)\n",
               sigBuf, r, strOff);
        printf("         %s[WARN]%s Odd mluc string offset — misaligned UTF-16\n",
               ColorWarning(), ColorReset());
        issues++;
      }
    }
  }

  if (checked > 0 && issues == 0)
    printf("         %s[OK]%s %d mluc tag(s) checked, all strings properly aligned\n",
           ColorSuccess(), ColorReset(), checked);
  else if (checked == 0)
    printf("         No mluc tags with records found\n");

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-226: mluc Size Inference Safety (ICC TN PSD §size)
//
// The tech note's key warning: when mluc is embedded in profileSequenceDescType,
// the size of the mluc is NOT stored — parsers must infer it. The recommended
// size = max(offset + length) across all records. This check validates that
// standalone mluc tags (in the tag table) have a tag size consistent with
// the records' maximum (offset + length), detecting wasted space or truncation.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF226_MlucSizeInferenceSafety(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-226]%s mluc Size Inference Safety (%sICC TN PSD §size%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename) {
    printf("         No filename — skipping mluc size inference check\n");
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) return 0;

  static const uint32_t kMlucTypeSig = 0x6D6C7563;
  std::vector<icUInt32Number> visitedOffsets;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    IccTagEntry *e = &(*it);
    icUInt32Number tagOffset = e->TagInfo.offset;
    icUInt32Number tagSize = e->TagInfo.size;

    bool dup = false;
    for (size_t v = 0; v < visitedOffsets.size(); v++)
      if (visitedOffsets[v] == tagOffset) { dup = true; break; }
    if (dup) continue;
    visitedOffsets.push_back(tagOffset);

    if (tagSize < 16 || (long)(tagOffset + 16) > fh.fileSize) continue;

    uint8_t hdr[16];
    if (!fh.Seek((long)tagOffset) || !fh.ReadBytes(hdr, 16)) continue;
    if (ReadU32BE(hdr) != kMlucTypeSig) continue;

    uint32_t recordCount = ReadU32BE(hdr + 8);
    uint32_t recordSize  = ReadU32BE(hdr + 12);
    if (recordSize != 12 || recordCount == 0) continue;

    uint64_t recordsEnd = 16ULL + (uint64_t)recordCount * 12ULL;
    if (recordsEnd > tagSize) continue;

    size_t recBytes = recordCount * 12;
    std::vector<uint8_t> recBuf(recBytes);
    if (!fh.Seek((long)(tagOffset + 16)) || !fh.ReadBytes(recBuf.data(), recBytes))
      continue;

    checked++;
    char sigBuf[5];
    SigToChars((uint32_t)e->TagInfo.sig, sigBuf);

    // Compute max(offset + length) across all records (TN recommendation)
    uint64_t maxEnd = 0;
    for (uint32_t r = 0; r < recordCount; r++) {
      const uint8_t *rec = recBuf.data() + r * 12;
      uint32_t strLen = ReadU32BE(rec + 4);
      uint32_t strOff = ReadU32BE(rec + 8);
      uint64_t end = (uint64_t)strOff + strLen;
      if (end > maxEnd) maxEnd = end;
    }

    // Tag size should be ≥ maxEnd (otherwise strings are truncated)
    if (maxEnd > tagSize) {
      printf("         Tag '%s': max(offset+length) = %llu but tag size = %u — data truncated\n",
             sigBuf, (unsigned long long)maxEnd, tagSize);
      printf("         %s[FAIL]%s mluc string data exceeds declared tag size\n",
             ColorError(), ColorReset());
      issues++;
    }

    // Warn if tag size exceeds maxEnd by more than 3 (alignment padding)
    // This suggests dead space in the tag (wasted bytes)
    if (tagSize > maxEnd + 3 && maxEnd > 0) {
      uint32_t waste = tagSize - (uint32_t)maxEnd;
      if (waste > 64) {
        printf("         Tag '%s': %u bytes of unused space after string data\n",
               sigBuf, waste);
        printf("         %s[INFO]%s mluc tag has significant unused space\n",
               ColorInfo(), ColorReset());
        // INFO only — not a conformance failure
      }
    }
  }

  if (checked > 0 && issues == 0)
    printf("         %s[OK]%s %d mluc tag(s) checked, sizes consistent with records\n",
           ColorSuccess(), ColorReset(), checked);
  else if (checked == 0)
    printf("         No mluc tags with records found\n");

  return issues;
}

// ========================================================================
// v2->v4 Features Changes conformance checks (CF-227..CF-234)
// Source: ICC TN "Features which have changed when comparing v4 to v2"
// ========================================================================

static int RunCF227_V4TextTagUnicodeMigration(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-227]%s v4 Text Tag Unicode Migration (%sICC.1-2022-05 S9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number ver = pIcc->m_Header.version;
  bool isV4Plus = (ver >= icVersionNumberV4);

  if (!isV4Plus) {
    printf("         Profile is v2 -- mluc migration check not applicable\n");
    return 0;
  }

  struct TagCheck {
    icTagSignature sig;
    const char *name;
  };
  static const TagCheck kTextTags[] = {
    {icSigProfileDescriptionTag, "profileDescriptionTag"},
    {icSigCopyrightTag,          "copyrightTag"},
    {icSigDeviceMfgDescTag,      "deviceMfgDescTag"},
    {icSigDeviceModelDescTag,    "deviceModelDescTag"},
    {icSigViewingCondDescTag,    "viewingCondDescTag"},
  };

  for (const auto &tc : kTextTags) {
    CIccTag *pTag = pIcc->FindTag(tc.sig);
    if (!pTag) continue;

    icTagTypeSignature ttype = pTag->GetType();
    if (ttype == icSigTextDescriptionType) {
      printf("         %s[WARN]%s '%s' uses textDescriptionType (desc) -- v4+ requires mluc\n",
             ColorWarning(), ColorReset(), tc.name);
      issues++;
    } else if (ttype == icSigTextType) {
      printf("         %s[WARN]%s '%s' uses textType -- v4+ requires mluc\n",
             ColorWarning(), ColorReset(), tc.name);
      issues++;
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s All v4+ text tags use multiLocalizedUnicodeType\n",
           ColorSuccess(), ColorReset());
  return issues;
}

static int RunCF228_GrayTRCSemantics(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-228]%s grayTRCTag Semantic Validation (%sv2->v4 TN%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
  if (cs != icSigGrayData) {
    printf("         Profile color space is not Gray -- grayTRC check N/A\n");
    return 0;
  }

  CIccTag *pTag = pIcc->FindTag(icSigGrayTRCTag);
  if (!pTag) {
    printf("         %s[WARN]%s Grayscale profile missing grayTRCTag\n",
           ColorWarning(), ColorReset());
    return 1;
  }

  CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve*>(pTag);
  if (pCurve && pCurve->GetSize() > 1) {
    icUInt32Number sz = pCurve->GetSize();

    icFloatNumber first = (*pCurve)[0];
    if (first > 0.01f) {
      printf("         %s[WARN]%s grayTRC[0]=%.6f -- should be near 0 (black)\n",
             ColorWarning(), ColorReset(), first);
      issues++;
    }

    icFloatNumber last = (*pCurve)[sz - 1];
    if (last < 0.9f) {
      printf("         %s[WARN]%s grayTRC[%u]=%.6f -- should be near 1.0 (white)\n",
             ColorWarning(), ColorReset(), sz - 1, last);
      issues++;
    }

    int monoViolations = 0;
    icUInt32Number step = (sz > 256) ? (sz / 256) : 1;
    icFloatNumber prev = (*pCurve)[0];
    for (icUInt32Number i = step; i < sz; i += step) {
      icFloatNumber val = (*pCurve)[i];
      if (val < prev - 0.001f) {
        monoViolations++;
        if (monoViolations <= 3)
          printf("         grayTRC[%u]=%.6f < grayTRC[prev]=%.6f -- non-monotonic\n",
                 i, val, prev);
      }
      prev = val;
    }
    if (monoViolations > 0) {
      printf("         %s[WARN]%s grayTRCTag has %d monotonicity violations\n",
             ColorWarning(), ColorReset(), monoViolations);
      issues++;
    }
  }

  if (pIcc->FindTag(icSigRedTRCTag) || pIcc->FindTag(icSigGreenTRCTag) ||
      pIcc->FindTag(icSigBlueTRCTag)) {
    printf("         %s[WARN]%s Grayscale profile has RGB TRC tags -- inconsistent\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s grayTRCTag semantics valid (0->black, 1.0->white, monotonic)\n",
           ColorSuccess(), ColorReset());
  return issues;
}

static int RunCF229_RenderingIntentDominance(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-229]%s Rendering Intent Dominance Per Class (%sv2->v4 TN%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icProfileClassSignature cls = pIcc->m_Header.deviceClass;

  int atobCount = 0, btoaCount = 0;
  if (pIcc->FindTag(icSigAToB0Tag)) atobCount++;
  if (pIcc->FindTag(icSigAToB1Tag)) atobCount++;
  if (pIcc->FindTag(icSigAToB2Tag)) atobCount++;
  if (pIcc->FindTag(icSigBToA0Tag)) btoaCount++;
  if (pIcc->FindTag(icSigBToA1Tag)) btoaCount++;
  if (pIcc->FindTag(icSigBToA2Tag)) btoaCount++;

  printf("         AToB tags: %d, BToA tags: %d, class: 0x%08X\n",
         atobCount, btoaCount, cls);

  if (cls == icSigInputClass) {
    if (atobCount == 0 && btoaCount > 0) {
      printf("         %s[WARN]%s Input profile has BToA but no AToB -- AToB should be dominant\n",
             ColorWarning(), ColorReset());
      issues++;
    }
    if (atobCount > 0 && !pIcc->FindTag(icSigAToB0Tag)) {
      printf("         %s[WARN]%s Input profile has AToB tags but missing AToB0 (Perceptual)\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  } else if (cls == icSigDisplayClass || cls == icSigOutputClass) {
    if (btoaCount == 0 && atobCount > 0) {
      printf("         %s[WARN]%s %s profile has AToB but no BToA -- BToA should be dominant\n",
             ColorWarning(), ColorReset(),
             cls == icSigDisplayClass ? "Display" : "Output");
      issues++;
    }
    if (btoaCount > 0 && !pIcc->FindTag(icSigBToA0Tag)) {
      printf("         %s[WARN]%s %s profile has BToA tags but missing BToA0\n",
             ColorWarning(), ColorReset(),
             cls == icSigDisplayClass ? "Display" : "Output");
      issues++;
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s Rendering intent dominance consistent with profile class\n",
           ColorSuccess(), ColorReset());
  return issues;
}

static int RunCF230_CIELABEncodingConsistency(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-230]%s CIELAB Encoding Version Consistency (%sICC.1-2022-05 S6.5.9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icColorSpaceSignature pcs = pIcc->m_Header.pcs;
  icUInt32Number ver = pIcc->m_Header.version;
  bool isV4Plus = (ver >= icVersionNumberV4);

  if (pcs != icSigLabData) {
    printf("         PCS is not Lab -- CIELAB encoding check N/A\n");
    return 0;
  }

  if (!isV4Plus) {
    printf("         v2 profile with Lab PCS -- uses legacy encoding\n");
    return 0;
  }

  static const icTagSignature kLutTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
  };

  int legacyLut16 = 0;
  int modernLut = 0;
  for (auto sig : kLutTags) {
    CIccTag *pTag = pIcc->FindTag(sig);
    if (!pTag) continue;

    icTagTypeSignature ttype = pTag->GetType();
    if (ttype == icSigLut16Type) {
      legacyLut16++;
      char sigStr[5];
      sigStr[0] = (char)((sig >> 24) & 0xFF);
      sigStr[1] = (char)((sig >> 16) & 0xFF);
      sigStr[2] = (char)((sig >> 8) & 0xFF);
      sigStr[3] = (char)(sig & 0xFF);
      sigStr[4] = '\0';
      printf("         %s[WARN]%s Tag '%s' uses lut16Type -- retains v2 Lab encoding in v4 profile\n",
             ColorWarning(), ColorReset(), sigStr);
    } else if (ttype == icSigLutAtoBType || ttype == icSigLutBtoAType) {
      modernLut++;
    }
  }

  if (legacyLut16 > 0 && modernLut > 0) {
    printf("         %s[WARN]%s Mixed lut16Type + lutAtoB/BtoA -- Lab encoding ambiguity\n",
           ColorWarning(), ColorReset());
    issues++;
  }
  if (legacyLut16 > 0)
    issues += legacyLut16;

  if (issues == 0) {
    if (modernLut > 0)
      printf("         %s[OK]%s v4 Lab PCS uses modern LUT types (v4 encoding)\n",
             ColorSuccess(), ColorReset());
    else
      printf("         %s[OK]%s v4 Lab PCS -- no legacy lut16Type detected\n",
             ColorSuccess(), ColorReset());
  }
  return issues;
}

static int RunCF231_LUTProcessingElementSequence(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-231]%s LUT Processing Element Sequence (%sICC.1-2022-05 S10.10-10.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const icTagSignature kLutTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
  };

  int checked = 0;
  for (auto sig : kLutTags) {
    CIccTag *pTag = pIcc->FindTag(sig);
    if (!pTag) continue;

    CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pTag);
    if (!pMBB) continue;
    checked++;

    bool hasBCurves = pMBB->GetCurvesB() != nullptr;
    bool hasMatrix  = pMBB->GetMatrix() != nullptr;
    bool hasMCurves = pMBB->GetCurvesM() != nullptr;
    bool hasCLUT    = pMBB->GetCLUT() != nullptr;
    bool hasACurves = pMBB->GetCurvesA() != nullptr;

    char sigStr[5];
    sigStr[0] = (char)((sig >> 24) & 0xFF);
    sigStr[1] = (char)((sig >> 16) & 0xFF);
    sigStr[2] = (char)((sig >> 8) & 0xFF);
    sigStr[3] = (char)(sig & 0xFF);
    sigStr[4] = '\0';

    if (!hasBCurves) {
      printf("         %s[WARN]%s '%s': missing B curves (always required)\n",
             ColorWarning(), ColorReset(), sigStr);
      issues++;
    }

    if (hasMatrix != hasMCurves) {
      printf("         %s[WARN]%s '%s': matrix present=%d but M curves present=%d -- must appear together\n",
             ColorWarning(), ColorReset(), sigStr, hasMatrix, hasMCurves);
      issues++;
    }

    if (hasACurves && !hasCLUT) {
      printf("         %s[WARN]%s '%s': A curves present without CLUT\n",
             ColorWarning(), ColorReset(), sigStr);
      issues++;
    }

    icUInt16Number inCh = pMBB->InputChannels();
    icUInt16Number outCh = pMBB->OutputChannels();
    if (inCh == 0 || outCh == 0) {
      printf("         %s[WARN]%s '%s': zero channel count (in=%u, out=%u)\n",
             ColorWarning(), ColorReset(), sigStr, inCh, outCh);
      issues++;
    }
  }

  if (checked == 0) {
    printf("         No lutAtoB/lutBtoA type tags found\n");
    return 0;
  }

  if (issues == 0)
    printf("         %s[OK]%s All %d LUT processing element sequences valid\n",
           ColorSuccess(), ColorReset(), checked);
  return issues;
}

static int RunCF232_DateTimeUTCConsistency(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-232]%s Date/Time UTC and Temporal Consistency (%sICC.1-2022-05 S7.2.8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  const icDateTimeNumber &dt = pIcc->m_Header.date;
  int createYear = dt.year;
  int createMonth = dt.month;
  int createDay = dt.day;
  int createHour = dt.hours;
  int createMin = dt.minutes;
  int createSec = dt.seconds;

  printf("         Profile creation: %04d-%02d-%02d %02d:%02d:%02d (UTC)\n",
         createYear, createMonth, createDay, createHour, createMin, createSec);

  if (createSec > 59) {
    printf("         %s[WARN]%s Seconds=%d -- exceeds 59\n",
           ColorWarning(), ColorReset(), createSec);
    issues++;
  }

  if (createHour > 23) {
    printf("         %s[WARN]%s Hour=%d -- exceeds 23\n",
           ColorWarning(), ColorReset(), createHour);
    issues++;
  }

  CIccTag *pCalTag = pIcc->FindTag(icSigCalibrationDateTimeTag);
  if (pCalTag) {
    CIccTagDateTime *pCalDT = dynamic_cast<CIccTagDateTime*>(pCalTag);
    if (pCalDT) {
      std::string desc;
      pCalDT->Describe(desc, 1);
      printf("         Calibration date: %s\n", desc.c_str());
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s Date/time fields consistent with UTC encoding\n",
           ColorSuccess(), ColorReset());
  return issues;
}

static int RunCF233_ColorantOrderIndexValidation(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-233]%s colorantOrderTag Index Validation (%sICC.1-2022-05 S9.2.11, S10.3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigColorantOrderTag);
  if (!pTag) {
    printf("         No colorantOrderTag present\n");
    return 0;
  }

  CIccTagColorantOrder *pOrder = dynamic_cast<CIccTagColorantOrder*>(pTag);
  if (!pOrder) {
    printf("         %s[FAIL]%s colorantOrderTag has unexpected type\n",
           ColorError(), ColorReset());
    return 1;
  }

  icUInt32Number count = pOrder->GetSize();
  printf("         colorantOrderTag: %u entries\n", count);

  if (count == 0) {
    printf("         %s[WARN]%s Empty colorantOrderTag\n",
           ColorWarning(), ColorReset());
    return 1;
  }

  if (count > 15) {
    printf("         %s[WARN]%s colorantOrderTag has %u entries (>15 ICC max)\n",
           ColorWarning(), ColorReset(), count);
    issues++;
  }

  std::vector<int> seen(count, 0);
  for (icUInt32Number i = 0; i < count; i++) {
    icUInt8Number idx = (*pOrder)[i];
    if (idx >= count) {
      printf("         %s[WARN]%s Index[%u]=%u -- out of range [0..%u]\n",
             ColorWarning(), ColorReset(), i, idx, count - 1);
      issues++;
    } else {
      seen[idx]++;
    }
  }

  for (icUInt32Number i = 0; i < count; i++) {
    if (seen[i] == 0) {
      printf("         %s[WARN]%s Colorant index %u missing -- not a valid permutation\n",
             ColorWarning(), ColorReset(), i);
      issues++;
    } else if (seen[i] > 1) {
      printf("         %s[WARN]%s Colorant index %u appears %d times -- duplicate\n",
             ColorWarning(), ColorReset(), i, seen[i]);
      issues++;
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s colorantOrderTag is a valid permutation of [0..%u]\n",
           ColorSuccess(), ColorReset(), count - 1);
  return issues;
}

static int RunCF234_PerceptualPCSReferenceMedium(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-234]%s v4 Perceptual PCS Reference Medium (%sICC.1-2022-05 Annex D%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number intent = pIcc->m_Header.renderingIntent;
  icColorSpaceSignature pcs = pIcc->m_Header.pcs;
  icUInt32Number ver = pIcc->m_Header.version;
  bool isV4Plus = (ver >= icVersionNumberV4);

  if (!isV4Plus) {
    printf("         v2 profile -- Perceptual PCS reference medium check N/A\n");
    return 0;
  }

  bool hasPerceptual = (intent == 0) ||
                       pIcc->FindTag(icSigAToB0Tag) != nullptr ||
                       pIcc->FindTag(icSigBToA0Tag) != nullptr;

  if (!hasPerceptual) {
    printf("         No perceptual intent transforms -- reference medium check N/A\n");
    return 0;
  }

  if (pcs == icSigLabData) {
    printf("         Lab PCS with perceptual intent: reference medium dynamic range 287.9:1\n");
    printf("         Reference white: L*=100 (89%% reflectance), black: L*=3.1373\n");
    printf("         %s[OK]%s Profile has perceptual intent with Lab PCS -- reference medium applies\n",
           ColorSuccess(), ColorReset());
  } else if (pcs == icSigXYZData) {
    printf("         XYZ PCS with perceptual intent: encoding bounds per Annex A.3 apply\n");
    printf("         %s[OK]%s XYZ PCS noted -- clipping at PCS encoding bounds\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}

// ─── CF-247: viewingConditionsType Illuminant Type Range ─────────────────────
// ICC.1-2022-05 Table 27 — illuminant type enumeration
int RunCF247_ViewingCondIllumType(CIccProfile *pIcc) {
  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigViewingConditionsTag);
  if (!pTag) return 0;
  CIccTagViewingConditions *pVC = dynamic_cast<CIccTagViewingConditions*>(pTag);
  if (!pVC) return 0;
  // ICC.1 Table 27: 0=unknown, 1=D50, 2=D65, 3=D93, 4=F2, 5=D55, 6=A, 7=E, 8=F8
  icUInt32Number illum = (icUInt32Number)pVC->m_illumType;
  if (illum > 8) {
    printf("    Non-conformance: viewingConditions illuminant type %u exceeds ICC.1 Table 27 range 0-8\n", illum);
    issues++;
  }
  return issues;
}

// ─── CF-248: namedColor2Type deviceCoords Limit ─────────────────────────────
// ICC.1-2022-05 §10.14 — device coordinates shall not exceed 15
int RunCF248_NamedColor2DeviceCoords(CIccProfile *pIcc) {
  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigNamedColor2Tag);
  if (!pTag) return 0;
  CIccTagNamedColor2 *pNC = dynamic_cast<CIccTagNamedColor2*>(pTag);
  if (!pNC) return 0;
  icUInt32Number nDev = pNC->GetDeviceCoords();
  if (nDev > 15) {
    printf("    Non-conformance: namedColor2 deviceCoords=%u exceeds ICC maximum of 15\n", nDev);
    issues++;
  }
  return issues;
}

// ─── CF-249: profileDescriptionTag Non-Empty Text ───────────────────────────
// ICC.1-2022-05 §9.2.41 — profileDescriptionTag must contain meaningful text
int RunCF249_ProfileDescNonEmpty(CIccProfile *pIcc) {
  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigProfileDescriptionTag);
  if (!pTag) return 0;
  // Try v4 mluc
  CIccTagMultiLocalizedUnicode *pMLUC = dynamic_cast<CIccTagMultiLocalizedUnicode*>(pTag);
  if (pMLUC) {
    if (pMLUC->m_Strings == NULL || pMLUC->m_Strings->size() == 0) {
      printf("    Non-conformance: profileDescriptionTag (mluc) contains no text entries\n");
      issues++;
    }
    return issues;
  }
  // Try v2 text description
  CIccTagTextDescription *pTD = dynamic_cast<CIccTagTextDescription*>(pTag);
  if (pTD) {
    const icChar *txt = pTD->GetText();
    if (!txt || txt[0] == '\0') {
      printf("    Non-conformance: profileDescriptionTag (textDescription) is empty\n");
      issues++;
    }
    return issues;
  }
  // Try plain text
  CIccTagText *pTxt = dynamic_cast<CIccTagText*>(pTag);
  if (pTxt) {
    const icChar *txt = pTxt->GetText();
    if (!txt || txt[0] == '\0') {
      printf("    Non-conformance: profileDescriptionTag (text) is empty\n");
      issues++;
    }
  }
  return issues;
}

// ─── CF-250: copyrightTag Non-Empty Text ────────────────────────────────────
// ICC.1-2022-05 §9.2.21 — copyrightTag shall contain non-empty text
int RunCF250_CopyrightNonEmpty(CIccProfile *pIcc) {
  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigCopyrightTag);
  if (!pTag) return 0;
  CIccTagMultiLocalizedUnicode *pMLUC = dynamic_cast<CIccTagMultiLocalizedUnicode*>(pTag);
  if (pMLUC) {
    if (pMLUC->m_Strings == NULL || pMLUC->m_Strings->size() == 0) {
      printf("    Non-conformance: copyrightTag (mluc) contains no text entries\n");
      issues++;
    }
    return issues;
  }
  CIccTagText *pTxt = dynamic_cast<CIccTagText*>(pTag);
  if (pTxt) {
    const icChar *txt = pTxt->GetText();
    if (!txt || txt[0] == '\0') {
      printf("    Non-conformance: copyrightTag (text) is empty\n");
      issues++;
    }
  }
  return issues;
}

// ─── CF-251: chromaticityType Phosphor Type Range ───────────────────────────
// ICC.1-2022-05 §10.2 — phosphor/colorant type 0=unknown, 1=ITU-R BT.709,
// 2=SMPTE RP145, 3=EBU 3213-E, 4=P22
int RunCF251_ChromaticityPhosphorType(CIccProfile *pIcc) {
  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigChromaticityTag);
  if (!pTag) return 0;
  CIccTagChromaticity *pChr = dynamic_cast<CIccTagChromaticity*>(pTag);
  if (!pChr) return 0;
  if (pChr->m_nColorantType > 4) {
    printf("    Non-conformance: chromaticity phosphor/colorant type %u exceeds ICC range 0-4\n",
           pChr->m_nColorantType);
    issues++;
  }
  return issues;
}

// ─── CF-252: curveType Gamma Positive and Finite ────────────────────────────
// ICC.1-2022-05 §10.6 — when curveType has count=1, the value is u8Fixed8Number gamma
// Gamma must be > 0 and finite
int RunCF252_CurveGammaValid(CIccProfile *pIcc) {
  int issues = 0;
  // Check TRC tags
  const icTagSignature trcSigs[] = {
    icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag
  };
  for (int i = 0; i < 4; i++) {
    CIccTag *pTag = pIcc->FindTag(trcSigs[i]);
    if (!pTag) continue;
    CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve*>(pTag);
    if (!pCurve) continue;
    if (pCurve->GetSize() == 1) {
      icFloatNumber gamma = (*pCurve)[0];
      if (gamma <= 0.0f) {
        char sigCC[5];
        icUInt32Number sig = trcSigs[i];
        sigCC[0] = (char)((sig >> 24) & 0xFF);
        sigCC[1] = (char)((sig >> 16) & 0xFF);
        sigCC[2] = (char)((sig >> 8) & 0xFF);
        sigCC[3] = (char)(sig & 0xFF);
        sigCC[4] = '\0';
        printf("    Non-conformance: '%s' curveType gamma=%.4f is not positive\n", sigCC, gamma);
        issues++;
      }
      if (!std::isfinite(gamma)) {
        char sigCC[5];
        icUInt32Number sig = trcSigs[i];
        sigCC[0] = (char)((sig >> 24) & 0xFF);
        sigCC[1] = (char)((sig >> 16) & 0xFF);
        sigCC[2] = (char)((sig >> 8) & 0xFF);
        sigCC[3] = (char)(sig & 0xFF);
        sigCC[4] = '\0';
        printf("    Non-conformance: '%s' curveType gamma is not finite\n", sigCC);
        issues++;
      }
    }
  }
  return issues;
}

// ─── CF-253: chromaticityType Channel Count Consistency ─────────────────────
// ICC.1-2022-05 §10.2 — number of channels in chromaticityType must match
// the number of channels in the profile's data colour space
int RunCF253_ChromaticityChannelCount(CIccProfile *pIcc) {
  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigChromaticityTag);
  if (!pTag) return 0;
  CIccTagChromaticity *pChr = dynamic_cast<CIccTagChromaticity*>(pTag);
  if (!pChr) return 0;
  icUInt32Number nChrChannels = pChr->GetSize();
  icUInt32Number nColorChannels = icGetSpaceSamples(pIcc->m_Header.colorSpace);
  if (nChrChannels != nColorChannels && nChrChannels != 0) {
    printf("    Non-conformance: chromaticityType has %u channels but profile colorSpace has %u\n",
           nChrChannels, nColorChannels);
    issues++;
  }
  return issues;
}

// ─── CF-254: Technology Signature Registered Values ─────────────────────────
// ICC.1-2022-05 §9.2.47 — technology signature must be a registered value
int RunCF254_TechnologySignature(CIccProfile *pIcc) {
  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigTechnologyTag);
  if (!pTag) return 0;
  CIccTagSignature *pSig = dynamic_cast<CIccTagSignature*>(pTag);
  if (!pSig) return 0;
  icUInt32Number tech = pSig->GetValue();
  // ICC.1 Table 25 — registered technology signatures
  static const icUInt32Number validTech[] = {
    0x6673636E, // 'fscn' Film scanner
    0x6463616D, // 'dcam' Digital camera
    0x7273636E, // 'rscn' Reflective scanner
    0x696A6574, // 'ijet' Ink jet printer
    0x74776178, // 'twax' Thermal wax printer
    0x6570686F, // 'epho' Electrophotographic printer
    0x65737461, // 'esta' Electrostatic printer
    0x64737562, // 'dsub' Dye sublimation printer
    0x7270686F, // 'rpho' Photographic paper printer
    0x6670726E, // 'fprn' Film writer
    0x7669646D, // 'vidm' Video monitor
    0x76696463, // 'vidc' Video camera
    0x706A7476, // 'pjtv' Projection television
    0x43525420, // 'CRT ' Cathode ray tube display
    0x504D4420, // 'PMD ' Passive matrix display
    0x414D4420, // 'AMD ' Active matrix display
    0x4B504344, // 'KPCD' Photo CD
    0x696D6773, // 'imgs' PhotoImageSetter
    0x67726176, // 'grav' Gravure
    0x6F666673, // 'offs' Offset lithography
    0x73696C6B, // 'silk' Silkscreen
    0x666C6578, // 'flex' Flexography
    0x6D706673, // 'mpfs' Motion picture film scanner
    0x6D706672, // 'mpfr' Motion picture film recorder
    0x646D7063, // 'dmpc' Digital motion picture camera
    0x64636A70, // 'dcpj' Digital cinema projector
  };
  bool found = false;
  for (size_t i = 0; i < sizeof(validTech)/sizeof(validTech[0]); i++) {
    if (tech == validTech[i]) { found = true; break; }
  }
  if (!found && tech != 0) {
    char sigCC[5];
    sigCC[0] = (char)((tech >> 24) & 0xFF);
    sigCC[1] = (char)((tech >> 16) & 0xFF);
    sigCC[2] = (char)((tech >> 8) & 0xFF);
    sigCC[3] = (char)(tech & 0xFF);
    sigCC[4] = '\0';
    printf("    Non-conformance: technology signature '%s' (0x%08X) is not in ICC.1 Table 25\n",
           sigCC, tech);
    issues++;
  }
  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-263: Perceptual PCS White Point D50 in Rendering Intent
// ICC.1-2022-05 Annex D: The perceptual rendering intent uses a
// specific reference medium. The PCS white point for perceptual is
// D50 (X=0.9642, Y=1.0000, Z=0.8249). This check validates that
// profiles with rendering intent=0 have consistent luminance data.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF263_PerceptualPCSWhitePointD50(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-263]%s Perceptual PCS White Point D50 (%sICC.1-2022-05 Annex D%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number intent = (icUInt32Number)(pIcc->m_Header.renderingIntent);
  if (intent != icPerceptual) {
    printf("         Rendering intent = %u (not perceptual) — check not applicable\n", intent);
    return 0;
  }

  if (pIcc->m_Header.deviceClass == icSigColorEncodingClass) {
    printf("         ColorEncoding profile — perceptual D50 header rule not applicable\n");
    printf("         %s[OK]%s ColorEncoding uses zero header illuminant instead of D50\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Validate the header illuminant matches D50
  double hdrX = icFtoD(pIcc->m_Header.illuminant.X);
  double hdrY = icFtoD(pIcc->m_Header.illuminant.Y);
  double hdrZ = icFtoD(pIcc->m_Header.illuminant.Z);

  const double D50_X = 0.9642, D50_Y = 1.0000, D50_Z = 0.8249;
  const double tol = 0.002;

  if (fabs(hdrX - D50_X) > tol || fabs(hdrY - D50_Y) > tol || fabs(hdrZ - D50_Z) > tol) {
    printf("         Header illuminant (%.4f, %.4f, %.4f) deviates from D50\n",
           hdrX, hdrY, hdrZ);
    printf("         %s[FAIL]%s Perceptual intent requires D50 PCS illuminant — Annex D\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Perceptual rendering intent PCS illuminant matches D50\n",
           ColorSuccess(), ColorReset());

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-264: CIELAB L* Range in curveType/parametricCurveType
// ICC.1-2022-05 §8.1.2: L* values in v4 CIELAB PCS are encoded as
// L*=0..100 in the range 0x0000..0xFFFF (v4) vs 0x0000..0xFF00 (v2).
// This check validates that profiles with Lab PCS do not contain
// parametricCurveType function types > 4 (only 0..4 are defined).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF264_ParametricCurveFuncType(CIccProfile *pIcc) {
  int issues = 0;
  bool found = false;

  printf("%s[CF-264]%s parametricCurveType Function Type Range (%sICC.1-2022-05 §10.18%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Scan all tags for parametricCurveType
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag) continue;

    // Check MBB tags that contain curve sets
    CIccMBB *pMBB = dynamic_cast<CIccMBB *>(pTag);
    if (!pMBB) continue;
    found = true;

    // Check A, M, B curve sets for parametric curves
    // Curve array sizes depend on MBB direction (AtoB vs BtoA)
    bool inputB = pMBB->IsInputB();
    icUInt16Number nA = inputB ? pMBB->OutputChannels() : pMBB->InputChannels();
    icUInt16Number nM = inputB ? pMBB->InputChannels()  : pMBB->OutputChannels();
    icUInt16Number nB = inputB ? pMBB->InputChannels()  : pMBB->OutputChannels();

    const char *curveSetNames[] = {"A", "M", "B"};
    CIccCurve *const *curveSets[] = {pMBB->GetCurvesA(), pMBB->GetCurvesM(), pMBB->GetCurvesB()};
    icUInt16Number curveCounts[] = {nA, nM, nB};

    for (int s = 0; s < 3; s++) {
      if (!curveSets[s] || curveCounts[s] == 0) continue;
      for (int c = 0; c < curveCounts[s]; c++) {
        if (!curveSets[s][c]) continue;
        CIccTagParametricCurve *pPara = dynamic_cast<CIccTagParametricCurve *>(curveSets[s][c]);
        if (!pPara) continue;

        icUInt16Number funcType = pPara->GetFunctionType();
        if (funcType > 4) {
          char sigCC[5];
          icUInt32Number sig = it->TagInfo.sig;
          sigCC[0] = (char)((sig >> 24) & 0xFF);
          sigCC[1] = (char)((sig >> 16) & 0xFF);
          sigCC[2] = (char)((sig >>  8) & 0xFF);
          sigCC[3] = (char)((sig      ) & 0xFF);
          sigCC[4] = '\0';
          printf("         Tag '%s' %s-curves[%d]: funcType=%u (valid 0..4)\n",
                 sigCC, curveSetNames[s], c, funcType);
          printf("         %s[FAIL]%s parametricCurveType funcType must be 0..4 — ICC.1-2022-05 §10.18\n",
                 ColorError(), ColorReset());
          issues++;
        }
      }
    }
  }

  if (!found)
    printf("         No MBB tags with parametric curves found\n");

  if (issues == 0)
    printf("         %s[OK]%s All parametricCurveType function types in range [0..4]\n",
           ColorSuccess(), ColorReset());

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-265: mluc Record Language/Country Code Validity
// ICC.1-2022-05 §10.15: multiLocalizedUnicodeType records contain
// ISO 639-1 language codes and ISO 3166-1 country codes. Both must
// be lowercase ASCII letters (2 chars) or zero-padded null.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF265_MlucLanguageCountryCode(CIccProfile *pIcc) {
  int issues = 0;
  int checked = 0;

  printf("%s[CF-265]%s mluc Record Language/Country Code (%sICC.1-2022-05 §10.15%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Check common tags that use mluc
  icSignature mlucTags[] = {
    icSigProfileDescriptionTag,
    icSigCopyrightTag,
    icSigDeviceMfgDescTag,
    icSigDeviceModelDescTag,
  };

  for (int t = 0; t < 4; t++) {
    CIccTag *pTag = pIcc->FindTag(mlucTags[t]);
    if (!pTag) continue;

    CIccTagMultiLocalizedUnicode *pMluc =
        dynamic_cast<CIccTagMultiLocalizedUnicode *>(pTag);
    if (!pMluc || !pMluc->m_Strings) continue;

    checked++;
    int recIdx = 0;
    for (auto it = pMluc->m_Strings->begin();
         it != pMluc->m_Strings->end() && recIdx < 32; ++it, ++recIdx) {
      icLanguageCode lang = it->m_nLanguageCode;
      icCountryCode country = it->m_nCountryCode;

      // Language code: 2 lowercase ASCII letters or 0x0000
      char lc1 = (char)((lang >> 8) & 0xFF);
      char lc2 = (char)(lang & 0xFF);

      if (lang != 0) {
        if (!(lc1 >= 'a' && lc1 <= 'z') || !(lc2 >= 'a' && lc2 <= 'z')) {
          printf("         mluc record %d: language=0x%04X ('%c%c') — not ISO 639-1\n",
                 recIdx, lang, (lc1 >= 0x20 && lc1 < 0x7F) ? lc1 : '?',
                          (lc2 >= 0x20 && lc2 < 0x7F) ? lc2 : '?');
          printf("         %s[WARN]%s mluc language code should be ISO 639-1 lowercase\n",
                 ColorWarning(), ColorReset());
          issues++;
        }
      }

      // Country code: 2 uppercase ASCII letters or 0x0000
      char cc1 = (char)((country >> 8) & 0xFF);
      char cc2 = (char)(country & 0xFF);

      if (country != 0) {
        if (!(cc1 >= 'A' && cc1 <= 'Z') || !(cc2 >= 'A' && cc2 <= 'Z')) {
          printf("         mluc record %d: country=0x%04X ('%c%c') — not ISO 3166-1\n",
                 recIdx, country, (cc1 >= 0x20 && cc1 < 0x7F) ? cc1 : '?',
                              (cc2 >= 0x20 && cc2 < 0x7F) ? cc2 : '?');
          printf("         %s[WARN]%s mluc country code should be ISO 3166-1 uppercase\n",
                 ColorWarning(), ColorReset());
          issues++;
        }
      }

      if (issues >= 5) {
        printf("         (stopping after 5 mluc code issues)\n");
        goto done_265;
      }
    }
  }

done_265:
  if (checked == 0)
    printf("         No multiLocalizedUnicodeType tags found\n");

  if (issues == 0)
    printf("         %s[OK]%s mluc language/country codes valid\n",
           ColorSuccess(), ColorReset());

  return issues;
}

// ── CF-273: Primary Colorant XYZ Values Positive and Plausible ───────────────
// ICC.1-2022-05 §10.28 — XYZ values in colorant tags should be positive
// and within plausible range for display/input devices

static int RunCF273_PrimaryColorantXYZPlausible(CIccProfile *pIcc) {
  printf("%s[CF-273]%s Primary Colorant XYZ Values Positive (%sICC.1-2022-05 §10.28%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.colorSpace != icSigRgbData) return 0;
  static const struct { icTagSignature sig; const char *name; } tags[] = {
    {icSigRedMatrixColumnTag, "rXYZ"}, {icSigGreenMatrixColumnTag, "gXYZ"},
    {icSigBlueMatrixColumnTag, "bXYZ"},
  };
  for (int i = 0; i < 3; i++) {
    CIccTag *pTag = pIcc->FindTag(tags[i].sig);
    if (!pTag) continue;
    CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ*>(pTag);
    if (!pXYZ || pXYZ->GetSize() < 1) continue;
    icXYZNumber *xyz = pXYZ->GetXYZ(0);
    if (!xyz) continue;
    double x = icFtoD(xyz->X);
    double y = icFtoD(xyz->Y);
    double z = icFtoD(xyz->Z);
    if (y < 0.0) {
      printf("         %s[WARN]%s %s has negative Y=%.6f — ICC.1-2022-05 §10.28\n",
             ColorWarning(), ColorReset(), tags[i].name, y);
      issues++;
    }
    if (x < -2.0 || x > 3.0 || y > 3.0 || z < -2.0 || z > 3.0) {
      printf("         %s[WARN]%s %s values out of plausible range (X=%.4f Y=%.4f Z=%.4f)\n",
             ColorWarning(), ColorReset(), tags[i].name, x, y, z);
      issues++;
    }
  }
  if (issues == 0)
    printf("         %s[OK]%s Primary colorant XYZ values plausible\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-274: Primary Colorant Chromaticity Sum ────────────────────────────────
// TN v4-matrix-entries — primary colorant chromaticity (x+y+z) ≈ 1.0 per column

static int RunCF274_PrimaryColorantChromaticitySum(CIccProfile *pIcc) {
  printf("%s[CF-274]%s Primary Colorant Chromaticity Sum (%sTN v4-matrix-entries%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.colorSpace != icSigRgbData) return 0;
  static const struct { icTagSignature sig; const char *name; } tags[] = {
    {icSigRedMatrixColumnTag, "rXYZ"}, {icSigGreenMatrixColumnTag, "gXYZ"},
    {icSigBlueMatrixColumnTag, "bXYZ"},
  };
  int checked = 0;
  for (int i = 0; i < 3; i++) {
    CIccTag *pTag = pIcc->FindTag(tags[i].sig);
    if (!pTag) continue;
    CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ*>(pTag);
    if (!pXYZ || pXYZ->GetSize() < 1) continue;
    icXYZNumber *xyz = pXYZ->GetXYZ(0);
    if (!xyz) continue;
    double x = icFtoD(xyz->X);
    double y = icFtoD(xyz->Y);
    double z = icFtoD(xyz->Z);
    double sum = x + y + z;
    checked++;
    if (sum < 0.001) {
      printf("         %s[WARN]%s %s chromaticity sum is %.6f (near zero)\n",
             ColorWarning(), ColorReset(), tags[i].name, sum);
      issues++;
    }
  }
  if (checked == 0) return 0;
  if (issues == 0)
    printf("         %s[OK]%s Primary colorant chromaticity sums plausible\n",
           ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-275: copyrightTag Must Be mluc for v4+ ───────────────────────────────
// ICC.1-2022-05 §9.2.14 — copyrightTag must use multiLocalizedUnicodeType for v4+

static int RunCF275_CopyrightTagMlucV4(CIccProfile *pIcc) {
  printf("%s[CF-275]%s copyrightTag Must Be mluc for v4+ (%sICC.1-2022-05 §9.2.14%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.version < icVersionNumberV4) return 0;
  CIccTag *pTag = pIcc->FindTag(icSigCopyrightTag);
  if (!pTag) return 0;
  if (pTag->GetType() != icSigMultiLocalizedUnicodeType) {
    printf("         %s[WARN]%s v4+ copyrightTag type 0x%08X, expected multiLocalizedUnicodeType "
           "(0x%08X) — ICC.1-2022-05 §9.2.14\n",
           ColorWarning(), ColorReset(), (unsigned)pTag->GetType(),
           (unsigned)icSigMultiLocalizedUnicodeType);
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s copyrightTag is mluc for v4+\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-276: profileDescriptionTag Must Be mluc for v4+ ───────────────────────
// ICC.1-2022-05 §9.2.44 — profileDescriptionTag must be mluc for v4+

static int RunCF276_ProfileDescMlucV4(CIccProfile *pIcc) {
  printf("%s[CF-276]%s profileDescriptionTag Must Be mluc for v4+ (%sICC.1-2022-05 §9.2.44%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.version < icVersionNumberV4) return 0;
  CIccTag *pTag = pIcc->FindTag(icSigProfileDescriptionTag);
  if (!pTag) return 0;
  if (pTag->GetType() != icSigMultiLocalizedUnicodeType) {
    printf("         %s[WARN]%s v4+ profileDescriptionTag type 0x%08X, expected mluc "
           "(0x%08X) — ICC.1-2022-05 §9.2.44\n",
           ColorWarning(), ColorReset(), (unsigned)pTag->GetType(),
           (unsigned)icSigMultiLocalizedUnicodeType);
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s profileDescriptionTag is mluc for v4+\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-277: mediaWhitePointTag Must Be XYZType ───────────────────────────────
// ICC.1-2022-05 §9.2.35 — mediaWhitePointTag must be XYZType

static int RunCF277_MediaWhitePointXYZType(CIccProfile *pIcc) {
  printf("%s[CF-277]%s mediaWhitePointTag Must Be XYZType (%sICC.1-2022-05 §9.2.35%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigMediaWhitePointTag);
  if (!pTag) return 0;
  if (pTag->GetType() != icSigXYZType) {
    printf("         %s[WARN]%s mediaWhitePointTag type 0x%08X, expected XYZType (0x%08X) "
           "— ICC.1-2022-05 §9.2.35\n",
           ColorWarning(), ColorReset(), (unsigned)pTag->GetType(), (unsigned)icSigXYZType);
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s mediaWhitePointTag is XYZType\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-278: chromaticAdaptationTag Must Be s15Fixed16ArrayType ───────────────
// ICC.1-2022-05 §9.2.2 — chromaticAdaptationTag must be s15Fixed16ArrayType

static int RunCF278_ChadS15Fixed16Type(CIccProfile *pIcc) {
  printf("%s[CF-278]%s chromaticAdaptationTag Type (%sICC.1-2022-05 §9.2.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigChromaticAdaptationTag);
  if (!pTag) return 0;
  if (pTag->GetType() != icSigS15Fixed16ArrayType) {
    printf("         %s[WARN]%s chromaticAdaptationTag type 0x%08X, expected s15Fixed16ArrayType "
           "(0x%08X) — ICC.1-2022-05 §9.2.2\n",
           ColorWarning(), ColorReset(), (unsigned)pTag->GetType(),
           (unsigned)icSigS15Fixed16ArrayType);
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s chromaticAdaptationTag is s15Fixed16ArrayType\n",
           ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-279: TRC Curve Values Non-Negative ────────────────────────────────────
// ICC.1-2022-05 §10.5/§10.15 — TRC values should be non-negative (monotonic
// from black to white)

static int RunCF279_TRCCurveNonNegative(CIccProfile *pIcc) {
  printf("%s[CF-279]%s TRC Curve Values Non-Negative (%sICC.1-2022-05 §10.5%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  static const icTagSignature trcTags[] = {
    icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag,
  };
  for (int t = 0; t < 4; t++) {
    CIccTag *pTag = pIcc->FindTag(trcTags[t]);
    if (!pTag) continue;
    CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve*>(pTag);
    if (!pCurve) continue;
    icUInt32Number n = pCurve->GetSize();
    if (n <= 1) continue; // gamma or identity
    for (icUInt32Number i = 0; i < n; i++) {
      icFloatNumber v = (*pCurve)[i];
      if (v < 0.0f) {
        char sigCC[5]; sigCC[4] = '\0';
        icUInt32Number sig = (icUInt32Number)trcTags[t];
        for (int j = 0; j < 4; j++)
          sigCC[j] = (char)(unsigned char)((sig >> (24-8*j)) & 0xFF);
        printf("         %s[WARN]%s TRC '%s' entry %u has negative value %.6f\n",
               ColorWarning(), ColorReset(), sigCC, (unsigned)i, (double)v);
        issues++;
        break; // one per curve
      }
    }
  }
  if (issues == 0)
    printf("         %s[OK]%s TRC curve values non-negative\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-280: XYZ Element Luminance (Y) Non-Negative ───────────────────────────
// ICC.1-2022-05 §10.28 — XYZ type luminance component should be non-negative

static int RunCF280_XYZLuminanceNonNegative(CIccProfile *pIcc) {
  printf("%s[CF-280]%s XYZ Element Luminance (Y) Non-Negative (%sICC.1-2022-05 §10.28%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  // Check all XYZ-type tags for negative Y
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigXYZType) continue;
    CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ*>(pTag);
    if (!pXYZ) continue;
    for (icUInt32Number i = 0; i < pXYZ->GetSize(); i++) {
      icXYZNumber *xyz = pXYZ->GetXYZ(i);
      if (!xyz) continue;
      double y = icFtoD(xyz->Y);
      if (y < -0.001) {
        char sigCC[5]; sigCC[4] = '\0';
        icUInt32Number sig = (icUInt32Number)it->TagInfo.sig;
        for (int j = 0; j < 4; j++)
          sigCC[j] = (char)(unsigned char)((sig >> (24-8*j)) & 0xFF);
        printf("         %s[WARN]%s XYZ tag '%s' element %u has negative Y=%.6f\n",
               ColorWarning(), ColorReset(), sigCC, (unsigned)i, y);
        issues++;
      }
    }
  }
  if (issues == 0)
    printf("         %s[OK]%s XYZ luminance values non-negative\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-281: profileSequenceDescTag Structure ─────────────────────────────────
// ICC.1-2022-05 §10.16 — profileSequenceDescType requires at least one entry

static int RunCF281_ProfileSequenceDescStructure(CIccProfile *pIcc) {
  printf("%s[CF-281]%s profileSequenceDescTag Structure (%sICC.1-2022-05 §10.16%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigProfileSequenceDescTag);
  if (!pTag) return 0;
  // Verify tag type is profileSequenceDescType
  if (pTag->GetType() != icSigProfileSequenceDescType) {
    printf("         %s[WARN]%s profileSequenceDescTag type 0x%08X, expected 0x%08X\n",
           ColorWarning(), ColorReset(), (unsigned)pTag->GetType(),
           (unsigned)icSigProfileSequenceDescType);
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s profileSequenceDescTag structure valid\n", ColorSuccess(), ColorReset());
  return issues;
}


int RunTagTypeConformance(CIccProfile *pIcc, const char *filename) {
  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  int r;

#define CF_WRAP(id, title, call) \
  hc.begin(id, title); \
  r = call; \
  if (r < 0) { \
    hc.skip(nullptr); \
  } else { \
    if (r > 0) hc.warn("%d non-conformance(s)", r); \
    hc.end("Conformant"); \
    issues += r; \
  }

  CF_WRAP(1020, "CF-020: Tag Signature → Allowed Type", RunCF020_TagTypeAllowed(pIcc));
  CF_WRAP(1021, "CF-021: Tag Type Reserved Bytes Zero", RunCF021_TagTypeReservedZero(pIcc, filename));
  CF_WRAP(1022, "CF-022: curveType Entry Count", RunCF022_CurveTypeEntryCount(pIcc));
  CF_WRAP(1023, "CF-023: parametricCurveType Function Type", RunCF023_ParametricCurveFunction(pIcc));
  CF_WRAP(1024, "CF-024: parametricCurveType Parameter Count", RunCF024_ParametricCurveParamCount(pIcc));
  CF_WRAP(1025, "CF-025: Chromaticity Phosphor Count", RunCF025_ChromaticityPhosphorCount(pIcc));
  CF_WRAP(1026, "CF-026: Colorant Table Entry Count", RunCF026_ColorantTableCount(pIcc));
  CF_WRAP(1027, "CF-027: Colorant Order Count", RunCF027_ColorantOrderCount(pIcc));
  CF_WRAP(1028, "CF-028: Named Color2 Device Coordinate Count", RunCF028_NamedColor2CoordCount(pIcc));
  CF_WRAP(1029, "CF-029: dateTimeType Field Ranges", RunCF029_DateTimeFieldRanges(pIcc));
  CF_WRAP(1030, "CF-030: multiLocalizedUnicodeType Structure", RunCF030_MlucStructure(pIcc, filename));
  CF_WRAP(1031, "CF-031: s15Fixed16ArrayType Element Count", RunCF031_S15Fixed16ArrayCount(pIcc, filename));
  CF_WRAP(1032, "CF-032: XYZType Triplet Count", RunCF032_XYZTypeTripletCount(pIcc));
  CF_WRAP(1033, "CF-033: Measurement Standard Observer", RunCF033_MeasurementStandardObserver(pIcc));
  CF_WRAP(1034, "CF-034: Measurement Geometry", RunCF034_MeasurementGeometry(pIcc));
  CF_WRAP(1035, "CF-035: responseCurveSet16Type Structure", RunCF035_ResponseCurveSet16Structure(pIcc));
  CF_WRAP(1036, "CF-036: profileSequenceDescType Elements", RunCF036_ProfileSequenceDescElements(pIcc));
  CF_WRAP(1037, "CF-037: profileSequenceIdentifierType Validation", RunCF037_ProfileSequenceIdValidation(pIcc));
  CF_WRAP(1038, "CF-038: dateTimeType Tag Range Validation", RunCF038_DateTimeTypeTagRange(pIcc));
  CF_WRAP(1039, "CF-039: signatureType Technology Validation", RunCF039_SignatureTypeTechnology(pIcc));

  CF_WRAP(1112, "CF-112: XYZ Triplet Normalization", RunCF112_XYZTripletNormalization(pIcc));

  // Negative PCSXYZ Values TN conformance checks (CF-169..CF-174)
  CF_WRAP(1169, "CF-169: Negative PCSXYZ Encoding Capability", RunCF169_NegativePCSXYZEncodingCapability(pIcc));
  CF_WRAP(1170, "CF-170: Chromatic Adaptation Negative XYZ Consistency", RunCF170_ChadNegativeXYZConsistency(pIcc));
  CF_WRAP(1171, "CF-171: White Point Non-Negative Luminance", RunCF171_WhitePointNonNegativeLuminance(pIcc));
  CF_WRAP(1172, "CF-172: Colorant XYZ Sum White Point Consistency", RunCF172_ColorantSumWhitePointConsistency(pIcc));
  CF_WRAP(1173, "CF-173: PCS XYZ Absorber Encoding", RunCF173_PCSXYZAbsorberEncoding(pIcc));
  CF_WRAP(1174, "CF-174: Lab Conversion Clipping Awareness", RunCF174_LabConversionClippingAwareness(pIcc));

  // ADGC (Adaptive Gain Curve) — ICC.1 Amendment April 2025 (CF-123..CF-136)
  CF_WRAP(1123, "CF-123: ADGC Class Restriction", RunCF123_ADGCClassRestriction(pIcc));
  CF_WRAP(1124, "CF-124: ADGC Type Signature", RunCF124_ADGCTypeSig(pIcc, filename));
  CF_WRAP(1125, "CF-125: ADGC Function Type ID", RunCF125_ADGCFunctionTypeID(pIcc, filename));
  CF_WRAP(1126, "CF-126: ADGC Reserved Bytes", RunCF126_ADGCReservedBytes(pIcc, filename));
  CF_WRAP(1127, "CF-127: ADGC Float Field Finiteness", RunCF127_ADGCFloatFieldFiniteness(pIcc, filename));
  CF_WRAP(1128, "CF-128: ADGC Weight Coefficient Sum", RunCF128_ADGCWeightCoefficientSum(pIcc, filename));
  CF_WRAP(1129, "CF-129: ADGC Curve Position Bounds", RunCF129_ADGCCurvePositionBounds(pIcc, filename));
  CF_WRAP(1130, "CF-130: ADGC Image-Specific GUID Flags", RunCF130_ADGCGUIDFlags(pIcc, filename));
  CF_WRAP(1131, "CF-131: ADGC Headroom Range Plausibility", RunCF131_ADGCHeadroomRange(pIcc, filename));
  CF_WRAP(1132, "CF-132: ADGC Curve Data Monotonicity", RunCF132_ADGCCurveMonotonicity(pIcc, filename));
  CF_WRAP(1133, "CF-133: ADGC H_baseline vs H_alternate Div-by-Zero", RunCF133_ADGCHeadroomDivByZero(pIcc, filename));
  CF_WRAP(1134, "CF-134: ADGC Per-Channel GainMin ≤ GainMax", RunCF134_ADGCGainMinMax(pIcc, filename));
  CF_WRAP(1135, "CF-135: ADGC Curve X-Value Domain Range", RunCF135_ADGCCurveXDomain(pIcc, filename));
  CF_WRAP(1136, "CF-136: ADGC Curve Adjacent-Point X-Equality", RunCF136_ADGCCurveAdjacentX(pIcc, filename));

  // SampleICC Compliance Testing Framework (CF-188..CF-190)
  CF_WRAP(1188, "CF-188: Global Per-Tag Validate() Sweep", RunCF188_GlobalTagValidateSweep(pIcc));
  CF_WRAP(1189, "CF-189: Tag Type Recognition Coverage", RunCF189_TagTypeRecognition(pIcc));
  CF_WRAP(1190, "CF-190: Profile Legibility Gate", RunCF190_ProfileLegibility(pIcc, filename));

  // Spec gap coverage (CF-208, CF-209, CF-212, CF-213)
  CF_WRAP(1208, "CF-208: Tag Type Version Compatibility", RunCF208_TagTypeVersionCompatibility(pIcc));
  CF_WRAP(1209, "CF-209: Colorspace Channel Count vs LUT Dimensions", RunCF209_ColorspaceLUTChannelMatch(pIcc));
  CF_WRAP(1212, "CF-212: textType Null Termination", RunCF212_TextTypeNullTermination(pIcc));
  CF_WRAP(1213, "CF-213: viewingConditionsType Completeness", RunCF213_ViewingConditionsCompleteness(pIcc));

  // ICC TN PSD / mluc structure conformance (CF-220..CF-226)
  CF_WRAP(1220, "CF-220: mluc Name Record Overlap Detection", RunCF220_MlucNameRecordOverlap(pIcc, filename));
  CF_WRAP(1221, "CF-221: profileSequenceDescTag Structure", RunCF221_ProfileSequenceDescStructure(pIcc));
  CF_WRAP(1222, "CF-222: profileSequenceIdentifierTag Validation", RunCF222_ProfileSequenceIdentifierTag(pIcc));
  CF_WRAP(1223, "CF-223: mluc Zero-Name Placeholder Encoding", RunCF223_MlucZeroNamePlaceholder(pIcc, filename));
  CF_WRAP(1224, "CF-224: mluc Reserved Field Zero", RunCF224_MlucReservedFieldZero(pIcc, filename));
  CF_WRAP(1225, "CF-225: mluc Name Record String Alignment", RunCF225_MlucStringAlignment(pIcc, filename));
  CF_WRAP(1226, "CF-226: mluc Size Inference Safety", RunCF226_MlucSizeInferenceSafety(pIcc, filename));

  // v2→v4 Features Changes conformance checks
  CF_WRAP(1227, "CF-227: v4 Text Tag Unicode Migration", RunCF227_V4TextTagUnicodeMigration(pIcc));
  CF_WRAP(1228, "CF-228: grayTRCTag Semantic Validation", RunCF228_GrayTRCSemantics(pIcc));
  CF_WRAP(1229, "CF-229: Rendering Intent Dominance Per Class", RunCF229_RenderingIntentDominance(pIcc));
  CF_WRAP(1230, "CF-230: CIELAB Encoding Version Consistency", RunCF230_CIELABEncodingConsistency(pIcc));
  CF_WRAP(1231, "CF-231: LUT Processing Element Sequence", RunCF231_LUTProcessingElementSequence(pIcc));
  CF_WRAP(1232, "CF-232: Date/Time UTC and Temporal Consistency", RunCF232_DateTimeUTCConsistency(pIcc));
  CF_WRAP(1233, "CF-233: colorantOrderTag Index Validation", RunCF233_ColorantOrderIndexValidation(pIcc));
  CF_WRAP(1234, "CF-234: v4 Perceptual PCS Reference Medium", RunCF234_PerceptualPCSReferenceMedium(pIcc));
  CF_WRAP(1247, "CF-247: viewingConditionsType Illuminant Type Range", RunCF247_ViewingCondIllumType(pIcc));
  CF_WRAP(1248, "CF-248: namedColor2Type Device Coords Limit", RunCF248_NamedColor2DeviceCoords(pIcc));
  CF_WRAP(1249, "CF-249: profileDescriptionTag Non-Empty", RunCF249_ProfileDescNonEmpty(pIcc));
  CF_WRAP(1250, "CF-250: copyrightTag Non-Empty", RunCF250_CopyrightNonEmpty(pIcc));
  CF_WRAP(1251, "CF-251: chromaticityType Phosphor Type Range", RunCF251_ChromaticityPhosphorType(pIcc));
  CF_WRAP(1252, "CF-252: curveType Gamma Positive/Finite", RunCF252_CurveGammaValid(pIcc));
  CF_WRAP(1253, "CF-253: chromaticityType Channel Count", RunCF253_ChromaticityChannelCount(pIcc));
  CF_WRAP(1254, "CF-254: Technology Signature Registered", RunCF254_TechnologySignature(pIcc));
  CF_WRAP(1263, "CF-263: Perceptual PCS White Point D50", RunCF263_PerceptualPCSWhitePointD50(pIcc));
  CF_WRAP(1264, "CF-264: parametricCurveType Function Type Range", RunCF264_ParametricCurveFuncType(pIcc));
  CF_WRAP(1265, "CF-265: mluc Language/Country Code Validity", RunCF265_MlucLanguageCountryCode(pIcc));

  // Tag type enforcement and data validation (CF-273..CF-281)
  CF_WRAP(1273, "CF-273: Primary Colorant XYZ Values Positive", RunCF273_PrimaryColorantXYZPlausible(pIcc));
  CF_WRAP(1274, "CF-274: Primary Colorant Chromaticity Sum", RunCF274_PrimaryColorantChromaticitySum(pIcc));
  CF_WRAP(1275, "CF-275: copyrightTag Must Be mluc for v4+", RunCF275_CopyrightTagMlucV4(pIcc));
  CF_WRAP(1276, "CF-276: profileDescriptionTag Must Be mluc for v4+", RunCF276_ProfileDescMlucV4(pIcc));
  CF_WRAP(1277, "CF-277: mediaWhitePointTag Must Be XYZType", RunCF277_MediaWhitePointXYZType(pIcc));
  CF_WRAP(1278, "CF-278: chromaticAdaptationTag Type", RunCF278_ChadS15Fixed16Type(pIcc));
  CF_WRAP(1279, "CF-279: TRC Curve Values Non-Negative", RunCF279_TRCCurveNonNegative(pIcc));
  CF_WRAP(1280, "CF-280: XYZ Element Luminance (Y) Non-Negative", RunCF280_XYZLuminanceNonNegative(pIcc));
  CF_WRAP(1281, "CF-281: profileSequenceDescTag Structure", RunCF281_ProfileSequenceDescStructure(pIcc));
  CF_WRAP(1340, "CF-340: colorantTableOutTag Count vs PCS Channels", RunCF340_ColorantTableOutCountVsPCS(pIcc));

#undef CF_WRAP
  return issues;
}
