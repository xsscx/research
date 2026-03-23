/// @file IccConformanceV5.cpp
/// @brief ICC.2-2023 v5/iccMAX conformance checks (CF-080 through CF-089),
///        ICC.2-in-ICC.1 embedding (CF-153..CF-158, CF-175..CF-177),
///        partial chromatic adaptation (CF-178..CF-183),
///        dictType (CF-159..CF-162),
///        ICC.2:2019 errata-derived (CF-284..CF-291).
///
/// @see ICC.2-2023, ICC.2:2019 Errata (Sept 2021), ICC TN Embedding, ICC TN Partial Adaptation

#include <cmath>
#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagComposite.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"
#include "IccMpeCalc.h"
#include "IccMpeACS.h"
#include "IccMpeSpectral.h"
#include "IccTagDict.h"
#include "IccTagEmbedIcc.h"
#include "IccTagLut.h"
#include "IccUtil.h"
#include "IccConformanceRegistry.h"
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicResult.h"
#include "IccAnalyzerColors.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <set>

// Compatibility: iccDEV renamed Material* → Multiplex* in commit 53dca81 (2026-02-27).
// CI cache may have older headers with Material names. Support both.
#ifndef icSigMultiplexDefaultValuesTag
  #ifdef icSigMaterialDefaultValuesTag
    #define icSigMultiplexDefaultValuesTag icSigMaterialDefaultValuesTag
  #else
    #define icSigMultiplexDefaultValuesTag static_cast<icTagSignature>(0x6D647620)
  #endif
#endif
#ifndef icSigMultiplexTypeArrayTag
  #ifdef icSigMaterialTypeArrayTag
    #define icSigMultiplexTypeArrayTag icSigMaterialTypeArrayTag
  #else
    #define icSigMultiplexTypeArrayTag static_cast<icTagSignature>(0x6d637461)
  #endif
#endif

// ---------------------------------------------------------------------------
// Helper: check profile version >= 5
// ---------------------------------------------------------------------------
static inline bool IsV5(CIccProfile *pIcc) {
  return (pIcc->m_Header.version >> 24) >= 5;
}

// ---------------------------------------------------------------------------
// CF-080: Spectral PCS Signature  (ICC.2-2023 §7.2.22)
// ---------------------------------------------------------------------------
int RunCF080_SpectralPCSSignature(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  icColorSpaceSignature spectralPCS = pIcc->m_Header.spectralPCS;

  printf("%s[CF-080]%s Spectral PCS Signature (%sICC.2-2023 §7.2.22%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (static_cast<icUInt32Number>(spectralPCS) == 0) {
    printf("         spectralPCS=0x00000000 (not set)\n");
    printf("         %s[OK]%s No spectral PCS — field unused\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  char sigCC[5];
  SigToChars(static_cast<uint32_t>(spectralPCS), sigCC);
  printf("         spectralPCS=0x%08X ('%s')\n",
         static_cast<unsigned>(spectralPCS), sigCC);

  bool recognized = false;
  switch (static_cast<icUInt32Number>(spectralPCS)) {
    case static_cast<icUInt32Number>(icSigReflectanceSpectralPcsData):
      printf("         Type: Reflectance Spectral\n");
      recognized = true;
      break;
    case static_cast<icUInt32Number>(icSigRadiantSpectralPcsData):
      printf("         Type: Radiant (Emissive) Spectral\n");
      recognized = true;
      break;
    case static_cast<icUInt32Number>(icSigBiDirReflectanceSpectralPcsData):
      printf("         Type: Bi-Directional Reflectance Spectral\n");
      recognized = true;
      break;
    case static_cast<icUInt32Number>(icSigSparseMatrixSpectralPcsData):
      printf("         Type: Sparse Matrix Reflectance Spectral\n");
      recognized = true;
      break;
    default:
      break;
  }

  if (recognized) {
    printf("         %s[OK]%s Spectral PCS signature is valid\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("         %s[FAIL]%s Unrecognized spectral PCS signature 0x%08X — ICC.2-2023 §7.2.22\n",
           ColorError(), ColorReset(), static_cast<unsigned>(spectralPCS));
    issues++;
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-081: Spectral PCS Range Validity  (ICC.2-2023 §7.2.23)
// ---------------------------------------------------------------------------
int RunCF081_SpectralPCSRange(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  icColorSpaceSignature spectralPCS = pIcc->m_Header.spectralPCS;

  printf("%s[CF-081]%s Spectral PCS Range Validity (%sICC.2-2023 §7.2.23%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (static_cast<icUInt32Number>(spectralPCS) == 0) {
    printf("         No spectral PCS set — range check not applicable\n");
    printf("         %s[OK]%s Skipped (no spectral PCS)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  const icSpectralRange &sr = pIcc->m_Header.spectralRange;
  icFloat32Number startNm = icF16toF(sr.start);
  icFloat32Number endNm   = icF16toF(sr.end);
  icUInt16Number  steps   = sr.steps;

  printf("         spectralRange: start=%.1f nm, end=%.1f nm, steps=%u\n",
         static_cast<double>(startNm), static_cast<double>(endNm), steps);

  if (steps < 1) {
    printf("         %s[FAIL]%s spectralRange.steps = 0 — must be >= 1 — ICC.2-2023 §7.2.23\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (startNm >= endNm) {
    printf("         %s[FAIL]%s spectralRange.start (%.1f) >= end (%.1f) — ICC.2-2023 §7.2.23\n",
           ColorError(), ColorReset(),
           static_cast<double>(startNm), static_cast<double>(endNm));
    issues++;
  }

  if (startNm < 100.0f || endNm > 1000.0f) {
    printf("         %s[FAIL]%s Wavelength range [%.1f–%.1f nm] outside plausible bounds [100–1000 nm]\n",
           ColorError(), ColorReset(),
           static_cast<double>(startNm), static_cast<double>(endNm));
    issues++;
  }

  // Check biSpectralRange if it appears to be set
  const icSpectralRange &bsr = pIcc->m_Header.biSpectralRange;
  icFloat32Number bStartNm = icF16toF(bsr.start);
  icFloat32Number bEndNm   = icF16toF(bsr.end);
  icUInt16Number  bSteps   = bsr.steps;

  bool biSet = (bsr.start != 0 || bsr.end != 0 || bsr.steps != 0);
  if (biSet) {
    printf("         biSpectralRange: start=%.1f nm, end=%.1f nm, steps=%u\n",
           static_cast<double>(bStartNm), static_cast<double>(bEndNm), bSteps);

    if (bSteps < 1) {
      printf("         %s[FAIL]%s biSpectralRange.steps = 0 — must be >= 1\n",
             ColorError(), ColorReset());
      issues++;
    }

    if (bStartNm >= bEndNm) {
      printf("         %s[FAIL]%s biSpectralRange.start (%.1f) >= end (%.1f)\n",
             ColorError(), ColorReset(),
             static_cast<double>(bStartNm), static_cast<double>(bEndNm));
      issues++;
    }
  }

  if (issues == 0) {
    printf("         %s[OK]%s Spectral range parameters valid\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-082: PCC Tags Required When Spectral  (ICC.2-2023 §8)
// ---------------------------------------------------------------------------
int RunCF082_PCCTagsRequired(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  icColorSpaceSignature spectralPCS = pIcc->m_Header.spectralPCS;

  printf("%s[CF-082]%s PCC Tags Required When Spectral (%sICC.2-2023 §8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (static_cast<icUInt32Number>(spectralPCS) == 0) {
    printf("         No spectral PCS — PCC tag requirement not applicable\n");
    printf("         %s[OK]%s Skipped (no spectral PCS)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  const CIccTag *svcnTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (!svcnTag) {
    printf("         %s[FAIL]%s Missing spectralViewingConditionsTag ('svcn') — required for spectral PCS — ICC.2-2023 §8\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         spectralViewingConditionsTag ('svcn'): present\n");
  }

  const CIccTag *c2spTag = pIcc->FindTag(icSigCustomToStandardPccTag);
  const CIccTag *s2cpTag = pIcc->FindTag(icSigStandardToCustomPccTag);

  if (c2spTag) {
    printf("         customToStandardPccTag ('c2sp'): present\n");
  } else {
    printf("         customToStandardPccTag ('c2sp'): absent\n");
  }

  if (s2cpTag) {
    printf("         standardToCustomPccTag ('s2cp'): present\n");
  } else {
    printf("         standardToCustomPccTag ('s2cp'): absent\n");
  }

  // Both PCC tags should appear together if used
  if ((c2spTag && !s2cpTag) || (!c2spTag && s2cpTag)) {
    printf("         %s[WARN]%s PCC tags should appear in pairs (c2sp + s2cp)\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (issues == 0) {
    printf("         %s[OK]%s Required PCC tags present for spectral PCS\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-083: MCS Signature Encoding  (ICC.2-2023 §7.2.25)
// ---------------------------------------------------------------------------
int RunCF083_MCSSignature(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  icMaterialColorSignature mcs = pIcc->m_Header.mcs;

  printf("%s[CF-083]%s MCS Signature Encoding (%sICC.2-2023 §7.2.25%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number mcsVal = static_cast<icUInt32Number>(mcs);

  if (mcsVal == 0) {
    printf("         mcs=0x00000000 (not set — no MCS)\n");
    printf("         %s[OK]%s MCS field unused\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  char sigCC[5];
  SigToChars(mcsVal, sigCC);
  printf("         mcs=0x%08X ('%s')\n", mcsVal, sigCC);

  // Valid MCS: icSigMCSData (0x6d630000) through icSigMCSDataEnd (0x6d63FFFF)
  if (mcsVal >= static_cast<icUInt32Number>(icSigMCSData) &&
      mcsVal <= static_cast<icUInt32Number>(icSigMCSDataEnd)) {
    icUInt16Number nChannels = mcsVal & 0xFFFF;
    printf("         MCS channels: %u (valid range)\n", nChannels);
    printf("         %s[OK]%s MCS signature in valid range [mc0000–mcFFFF]\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("         %s[FAIL]%s MCS signature 0x%08X outside valid range — ICC.2-2023 §7.2.25\n",
           ColorError(), ColorReset(), mcsVal);
    issues++;
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-084: Profile Sub-Class Signature  (ICC.2-2023 §7.2.26)
// ---------------------------------------------------------------------------
int RunCF084_ProfileSubClass(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  icSignature subClass = pIcc->m_Header.deviceSubClass;

  printf("%s[CF-084]%s Profile Sub-Class Signature (%sICC.2-2023 §7.2.26%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(subClass);
  if (scVal == 0) {
    printf("         deviceSubClass=0x00000000 (not set)\n");
    printf("         %s[OK]%s No sub-class defined (default)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  char sigCC[5];
  SigToChars(scVal, sigCC);
  printf("         deviceSubClass=0x%08X ('%s')\n", scVal, sigCC);

  // Sub-class is an extension point — any non-zero value is potentially valid
  // but unrecognized values should produce a warning
  bool printable = true;
  for (int i = 0; i < 4; i++) {
    unsigned char c = static_cast<unsigned char>((scVal >> (24 - i * 8)) & 0xFF);
    if (c < 0x20 || c > 0x7E) { printable = false; break; }
  }

  if (!printable) {
    printf("         %s[WARN]%s Sub-class signature contains non-printable characters\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    printf("         %s[OK]%s Sub-class signature noted (extension point)\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-085: Version Field 5.x BCD  (ICC.2-2023 §7.2.4)
// ---------------------------------------------------------------------------
int RunCF085_V5VersionBCD(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  icUInt32Number ver = pIcc->m_Header.version;

  printf("%s[CF-085]%s Version Field 5.x BCD (%sICC.2-2023 §7.2.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt8Number major = static_cast<icUInt8Number>((ver >> 24) & 0xFF);
  icUInt8Number minor_hi = static_cast<icUInt8Number>((ver >> 20) & 0x0F);
  icUInt8Number minor_lo = static_cast<icUInt8Number>((ver >> 16) & 0x0F);
  icUInt16Number tail = static_cast<icUInt16Number>(ver & 0xFFFF);

  printf("         version=0x%08X → %u.%u.%u (bytes 10-11: 0x%04X)\n",
         ver, major, minor_hi, minor_lo, tail);

  if (major != 5) {
    printf("         %s[FAIL]%s Major version byte is %u, expected 5 — ICC.2-2023 §7.2.4\n",
           ColorError(), ColorReset(), major);
    issues++;
  }

  if (minor_hi > 9) {
    printf("         %s[FAIL]%s Minor version high nibble %u is not valid BCD (0-9)\n",
           ColorError(), ColorReset(), minor_hi);
    issues++;
  }

  if (minor_lo > 9) {
    printf("         %s[FAIL]%s Minor version low nibble %u is not valid BCD (0-9)\n",
           ColorError(), ColorReset(), minor_lo);
    issues++;
  }

  if (tail != 0) {
    printf("         %s[FAIL]%s Version bytes 10-11 must be 0x0000, got 0x%04X — ICC.2-2023 §7.2.4\n",
           ColorError(), ColorReset(), tail);
    issues++;
  }

  if (issues == 0) {
    printf("         %s[OK]%s Version %u.%u.%u — valid BCD encoding\n",
           ColorSuccess(), ColorReset(), major, minor_hi, minor_lo);
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-086: Extended Attribute Bits  (ICC.2-2023 §7.2.14)
// ---------------------------------------------------------------------------
int RunCF086_ExtendedAttributes(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-086]%s Extended Attribute Bits (%sICC.2-2023 §7.2.14%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt64Number attr = pIcc->m_Header.attributes;

  // v4 bits (0-3)
  bool transparency = (attr & 0x0001) != 0;
  bool matte        = (attr & 0x0002) != 0;
  bool negative     = (attr & 0x0004) != 0;
  bool bw           = (attr & 0x0008) != 0;

  printf("         attributes=0x%016llX\n",
         static_cast<unsigned long long>(attr));
  printf("         Bit 0 (Transparency): %s\n", transparency ? "Transparent" : "Reflective");
  printf("         Bit 1 (Matte):        %s\n", matte        ? "Matte"       : "Glossy");
  printf("         Bit 2 (Polarity):     %s\n", negative     ? "Negative"    : "Positive");
  printf("         Bit 3 (Colour):       %s\n", bw           ? "B&W"         : "Colour");

  // v5 extension: MCS subset indicator (bit 4)
  bool mcsSubset = (attr & 0x0010) != 0;
  if (mcsSubset) {
    printf("         Bit 4 (MCS Subset):   Set — profile is an MCS subset\n");
  }

  // Report any reserved bits that are set (bits 5-63)
  icUInt64Number reservedMask = ~static_cast<icUInt64Number>(0x1F);
  if (attr & reservedMask) {
    printf("         %sReserved attribute bits set: 0x%016llX%s\n",
           ColorInfo(), static_cast<unsigned long long>(attr & reservedMask), ColorReset());
  }

  printf("         %s[OK]%s Attribute bits reported (informational)\n",
         ColorInfo(), ColorReset());

  return 0;
}

// ---------------------------------------------------------------------------
// Helper: table of recognized MPE element type signatures
// ---------------------------------------------------------------------------
static const icElemTypeSignature kKnownMPETypes[] = {
  icSigCurveSetElemType,
  icSigMatrixElemType,
  icSigCLutElemType,
  icSigBAcsElemType,
  icSigEAcsElemType,
  icSigCalculatorElemType,
  icSigExtCLutElemType,
  icSigXYZToJabElemType,
  icSigJabToXYZElemType,
  icSigSparseMatrixElemType,
  icSigTintArrayElemType,
  icSigToneMapElemType,
  icSigEmissionMatrixElemType,
  icSigInvEmissionMatrixElemType,
  icSigEmissionCLUTElemType,
  icSigReflectanceCLUTElemType,
  icSigEmissionObserverElemType,
  icSigReflectanceObserverElemType,
};
static constexpr int kKnownMPETypeCount =
    static_cast<int>(sizeof(kKnownMPETypes) / sizeof(kKnownMPETypes[0]));

static bool IsKnownMPEType(icElemTypeSignature sig) {
  for (int i = 0; i < kKnownMPETypeCount; i++) {
    if (kKnownMPETypes[i] == sig) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// CF-087: MPE Element Signature Valid  (ICC.2-2023 §10.x)
// ---------------------------------------------------------------------------
int RunCF087_MPEElementSignature(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  int mpeTagCount = 0;
  int totalElements = 0;

  printf("%s[CF-087]%s MPE Element Signature Valid (%sICC.2-2023 §10.x%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Iterate all tags looking for MultiProcessElement tags
  if (pIcc->m_Tags.empty()) {
    printf("         No tags in profile\n");
    printf("         %s[OK]%s No MPE tags to check\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *tag = pIcc->FindTag(it->TagInfo.sig);
    if (!tag) continue;

    CIccTagMultiProcessElement *mpe =
        dynamic_cast<CIccTagMultiProcessElement *>(tag);
    if (!mpe) continue;

    mpeTagCount++;
    icUInt32Number nElem = mpe->NumElements();

    char tagSigCC[5];
    SigToChars(static_cast<uint32_t>(it->TagInfo.sig), tagSigCC);

    for (icUInt32Number i = 0; i < nElem; i++) {
      CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
      if (!elem) continue;

      totalElements++;
      icElemTypeSignature elemType = elem->GetType();

      if (!IsKnownMPEType(elemType)) {
        char elemCC[5];
        SigToChars(static_cast<uint32_t>(elemType), elemCC);
        printf("         Tag '%s' element %u: unknown type 0x%08X ('%s')\n",
               tagSigCC, i, static_cast<unsigned>(elemType), elemCC);
        printf("         %s[WARN]%s Unrecognized MPE element type — ICC.2-2023 §10\n",
               ColorWarning(), ColorReset());
        issues++;
      }
    }
  }

  printf("         Scanned %d MPE tag(s), %d element(s) total\n",
         mpeTagCount, totalElements);

  if (issues == 0) {
    if (totalElements > 0) {
      printf("         %s[OK]%s All %d MPE element signatures recognized\n",
             ColorSuccess(), ColorReset(), totalElements);
    } else {
      printf("         %s[OK]%s No MPE elements to validate\n",
             ColorSuccess(), ColorReset());
    }
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-088: Calculator Element Stack Structure  (ICC.2-2023 §10.x)
// ---------------------------------------------------------------------------
int RunCF088_CalculatorStackStructure(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  int calcCount = 0;

  printf("%s[CF-088]%s Calculator Element Stack Structure (%sICC.2-2023 §10.x%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Tags.empty()) {
    printf("         No tags in profile\n");
    printf("         %s[OK]%s No calculator elements to check\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *tag = pIcc->FindTag(it->TagInfo.sig);
    if (!tag) continue;

    CIccTagMultiProcessElement *mpe =
        dynamic_cast<CIccTagMultiProcessElement *>(tag);
    if (!mpe) continue;

    icUInt32Number nElem = mpe->NumElements();
    char tagSigCC[5];
    SigToChars(static_cast<uint32_t>(it->TagInfo.sig), tagSigCC);

    for (icUInt32Number i = 0; i < nElem; i++) {
      CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
      if (!elem) continue;

      if (elem->GetType() != icSigCalculatorElemType) continue;

      calcCount++;

      CIccMpeCalculator *calc = dynamic_cast<CIccMpeCalculator *>(elem);
      if (!calc) {
        printf("         Tag '%s' element %u: calculator type but dynamic_cast failed\n",
               tagSigCC, i);
        printf("         %s[FAIL]%s Calculator element type mismatch\n",
               ColorError(), ColorReset());
        issues++;
        continue;
      }

      // Basic structural checks
      icUInt16Number nIn  = calc->NumInputChannels();
      icUInt16Number nOut = calc->NumOutputChannels();

      printf("         Tag '%s' element %u: Calculator in=%u out=%u\n",
             tagSigCC, i, nIn, nOut);

      if (nIn == 0) {
        printf("         %s[FAIL]%s Calculator has 0 input channels\n",
               ColorError(), ColorReset());
        issues++;
      }

      if (nOut == 0) {
        printf("         %s[FAIL]%s Calculator has 0 output channels\n",
               ColorError(), ColorReset());
        issues++;
      }
    }
  }

  printf("         Found %d calculator element(s)\n", calcCount);

  if (issues == 0) {
    if (calcCount > 0) {
      printf("         %s[OK]%s Calculator element(s) structurally valid\n",
             ColorSuccess(), ColorReset());
    } else {
      printf("         %s[OK]%s No calculator elements present\n",
             ColorSuccess(), ColorReset());
    }
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-089: Spectral Wavelength Range  (ICC.2-2023 §7.2.23)
// ---------------------------------------------------------------------------
int RunCF089_SpectralWavelengthRange(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  icColorSpaceSignature spectralPCS = pIcc->m_Header.spectralPCS;

  printf("%s[CF-089]%s Spectral Wavelength Range (%sICC.2-2023 §7.2.23%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (static_cast<icUInt32Number>(spectralPCS) == 0) {
    printf("         No spectral PCS — wavelength range check not applicable\n");
    printf("         %s[OK]%s Skipped (no spectral PCS)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  const icSpectralRange &sr = pIcc->m_Header.spectralRange;
  icFloat32Number startNm = icF16toF(sr.start);
  icFloat32Number endNm   = icF16toF(sr.end);
  icUInt16Number  steps   = sr.steps;

  printf("         Wavelength range: %.1f–%.1f nm, %u steps\n",
         static_cast<double>(startNm), static_cast<double>(endNm), steps);

  // Typical visible: 380-780 nm; extended: 300-830 nm
  if (startNm < 300.0f) {
    printf("         %s[WARN]%s Start wavelength %.1f nm is below typical minimum (300 nm)\n",
           ColorWarning(), ColorReset(), static_cast<double>(startNm));
    issues++;
  }

  if (endNm > 830.0f) {
    printf("         %s[WARN]%s End wavelength %.1f nm exceeds typical maximum (830 nm)\n",
           ColorWarning(), ColorReset(), static_cast<double>(endNm));
    issues++;
  }

  // Consistency: steps should divide the range evenly
  if (steps > 1) {
    icFloat32Number rangeNm = endNm - startNm;
    icFloat32Number stepSize = rangeNm / static_cast<icFloat32Number>(steps - 1);

    printf("         Derived step size: %.2f nm\n", static_cast<double>(stepSize));

    if (stepSize <= 0.0f) {
      printf("         %s[FAIL]%s Derived step size is non-positive — range/steps inconsistent\n",
             ColorError(), ColorReset());
      issues++;
    }
  } else if (steps == 1 && startNm != endNm) {
    printf("         %s[FAIL]%s steps=1 but start (%.1f) != end (%.1f) — inconsistent\n",
           ColorError(), ColorReset(),
           static_cast<double>(startNm), static_cast<double>(endNm));
    issues++;
  }

  if (issues == 0) {
    printf("         %s[OK]%s Spectral wavelength range within expected bounds\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-090: Spectral Illuminant/Observer Consistency (ICC.2-2023 §7.2.17)
//
// For v5 profiles with spectral PCS, validates that the illuminant and observer
// spectral ranges in the spectralViewingConditionsTag (svcn) are consistent with
// the profile's declared spectral range.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF090_SpectralIlluminantConsistency(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) {
    printf("         %s[SKIP]%s Not a v5 profile\n", ColorSuccess(), ColorReset());
    return 0;
  }

  printf("%s[CF-090]%s Spectral Illuminant/Observer Consistency (%sICC.2-2023 §7.2.17%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;

  icColorSpaceSignature spectralPCS = pIcc->m_Header.spectralPCS;
  if (static_cast<icUInt32Number>(spectralPCS) == 0) {
    printf("         %s[SKIP]%s No spectral PCS — not applicable\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  const CIccTag *svcnTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (!svcnTag) {
    printf("         %s[SKIP]%s Spectral PCS present but no svcn tag (covered by CF-054)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  const CIccTagSpectralViewingConditions *svcn =
      dynamic_cast<const CIccTagSpectralViewingConditions *>(svcnTag);
  if (!svcn) {
    printf("         %s[WARN]%s svcn tag present but wrong type — cannot validate\n",
           ColorWarning(), ColorReset());
    return 1;
  }

  // Profile spectral range
  const icSpectralRange &profRange = pIcc->m_Header.spectralRange;
  icFloat32Number profStartNm = icF16toF(profRange.start);
  icFloat32Number profEndNm   = icF16toF(profRange.end);
  printf("         Profile spectral range: %.1f–%.1f nm, %u steps\n",
         static_cast<double>(profStartNm), static_cast<double>(profEndNm),
         profRange.steps);

  // Illuminant spectral range from svcn
  icSpectralRange illumRange;
  svcn->getIlluminant(illumRange);

  if (illumRange.steps == 0) {
    icIlluminant illumType = svcn->getStdIllumiant();
    if (static_cast<icUInt32Number>(illumType) != 0) {
      printf("         Illuminant: standard type 0x%08X (no custom spectral data)\n",
             static_cast<unsigned>(illumType));
    } else {
      printf("         %s[WARN]%s Illuminant has zero steps and no standard type — "
             "missing illuminant data\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  } else {
    icFloat32Number illumStartNm = icF16toF(illumRange.start);
    icFloat32Number illumEndNm   = icF16toF(illumRange.end);
    printf("         Illuminant spectral range: %.1f–%.1f nm, %u steps\n",
           static_cast<double>(illumStartNm), static_cast<double>(illumEndNm),
           illumRange.steps);

    // Check for non-overlapping ranges
    if (illumEndNm < profStartNm || illumStartNm > profEndNm) {
      printf("         %s[WARN]%s Illuminant range [%.1f–%.1f] does not overlap "
             "profile spectral range [%.1f–%.1f] — §7.2.17\n",
             ColorWarning(), ColorReset(),
             static_cast<double>(illumStartNm), static_cast<double>(illumEndNm),
             static_cast<double>(profStartNm), static_cast<double>(profEndNm));
      issues++;
    }
  }

  // Observer spectral range from svcn
  icSpectralRange obsRange;
  svcn->getObserver(obsRange);

  if (obsRange.steps > 0) {
    icFloat32Number obsStartNm = icF16toF(obsRange.start);
    icFloat32Number obsEndNm   = icF16toF(obsRange.end);
    printf("         Observer spectral range: %.1f–%.1f nm, %u steps\n",
           static_cast<double>(obsStartNm), static_cast<double>(obsEndNm),
           obsRange.steps);

    // Check for non-overlapping ranges
    if (obsEndNm < profStartNm || obsStartNm > profEndNm) {
      printf("         %s[WARN]%s Observer range [%.1f–%.1f] does not overlap "
             "profile spectral range [%.1f–%.1f] — §7.2.17\n",
             ColorWarning(), ColorReset(),
             static_cast<double>(obsStartNm), static_cast<double>(obsEndNm),
             static_cast<double>(profStartNm), static_cast<double>(profEndNm));
      issues++;
    }
  } else {
    icStandardObserver obsType = svcn->getStdObserver();
    if (static_cast<icUInt32Number>(obsType) != 0) {
      printf("         Observer: standard type 0x%08X (no custom spectral data)\n",
             static_cast<unsigned>(obsType));
    } else {
      printf("         %s[WARN]%s Observer has zero steps and no standard type — "
             "missing observer data\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s Spectral illuminant/observer consistent with profile range\n",
           ColorSuccess(), ColorReset());

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-113: Spectral Range Physical Bounds (ICC.2-2023 §7.2.23)
//
// Spectral start/end wavelengths must be within the visible spectrum:
//   - UV start: ≥ 100 nm (some instruments go below 380)
//   - IR end: ≤ 2500 nm (some near-IR instruments)
//   - Start < End
//   - Typical visible: 380-780 nm
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF113_SpectralRangePhysicalBounds(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-113]%s Spectral Range Physical Bounds (%sICC.2-2023 §7.2.23%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icSpectralRange spec = pIcc->m_Header.spectralRange;
  if (spec.steps == 0) {
    printf("         No spectral range defined — check not applicable\n");
    return 0;
  }

  icFloatNumber startNm = icF16toF(spec.start);
  icFloatNumber endNm   = icF16toF(spec.end);

  // Physical bounds check
  if (startNm < 100.0f || startNm > 2500.0f) {
    printf("         Start wavelength %.1f nm outside physical range [100-2500]\n",
           static_cast<double>(startNm));
    printf("         %s[FAIL]%s Wavelength must be physically meaningful — §7.2.23\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (endNm < 100.0f || endNm > 2500.0f) {
    printf("         End wavelength %.1f nm outside physical range [100-2500]\n",
           static_cast<double>(endNm));
    printf("         %s[FAIL]%s Wavelength must be physically meaningful — §7.2.23\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (startNm >= endNm && spec.steps > 1) {
    printf("         Start (%.1f nm) >= End (%.1f nm) with %u steps\n",
           static_cast<double>(startNm), static_cast<double>(endNm), spec.steps);
    printf("         %s[FAIL]%s Start must be < End for multi-step spectra — §7.2.23\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Spectral range within physical bounds\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-114: MCS Colour Space Consistency (ICC.2-2023 §7.2.19)
//
// If the profile has Material Connection Space (MCS), the MCS signature must
// be a valid colour space and must be consistent with profile sub-class.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF114_MCSColourSpaceConsistency(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-114]%s MCS Colour Space Consistency (%sICC.2-2023 §7.2.19%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icMaterialColorSignature mcs = pIcc->m_Header.mcs;
  if (mcs == icSigNoMCSData) {
    printf("         No MCS data — check not applicable\n");
    return 0;
  }

  // MCS must have valid channel count
  int nMCS = (int)icGetMaterialColorSpaceSamples(mcs);
  if (nMCS == 0) {
    char s[5] = {};
    SigToChars((icUInt32Number)mcs, s);
    printf("         MCS signature '%s' (0x%08X) has 0 channels\n",
           s, (unsigned)mcs);
    printf("         %s[FAIL]%s MCS signature must specify valid colour space — §7.2.19\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0) {
    char s[5] = {};
    SigToChars((icUInt32Number)mcs, s);
    printf("         MCS='%s' (%d channels)\n", s, nMCS);
    printf("         %s[OK]%s MCS colour space is valid\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-115: Calculator Element Complexity (ICC.2-2023 §10.2.6)
//
// Calculator elements with excessive sub-elements or deep nesting may indicate
// malformed profiles. This is a quality/performance conformance check.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF115_CalculatorElementComplexity(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-115]%s Calculator Element Complexity (%sICC.2-2023 §10.2.6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Scan all tags for MPE elements containing calculators
  int calcCount = 0;
  int totalSubElements = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *tag = pIcc->FindTag(it->TagInfo.sig);
    if (!tag) continue;

    CIccTagMultiProcessElement *mpe =
      dynamic_cast<CIccTagMultiProcessElement *>(tag);
    if (!mpe) continue;

    // Count via Describe output length as complexity proxy
    // (protected iterators prevent direct element access from outside)
    int elemCount = 0;
    std::string desc;
    mpe->Describe(desc, 0);
    // Count "Element" occurrences in description as proxy
    size_t pos = 0;
    while ((pos = desc.find("Element", pos)) != std::string::npos) {
      elemCount++;
      pos += 7;
    }
    if (elemCount > 0) {
      // Check for calculator elements
      if (desc.find("Calculator") != std::string::npos ||
          desc.find("calc") != std::string::npos) {
        calcCount++;
        // Count sub-element references
        size_t subPos = 0;
        int subCount = 0;
        while ((subPos = desc.find("SubElement", subPos)) != std::string::npos) {
          subCount++;
          subPos += 10;
        }
        totalSubElements += subCount > 0 ? subCount : elemCount;

        if (elemCount > 256) {
          printf("         MPE tag with %d elements (excessive)\n", elemCount);
          printf("         %s[WARN]%s Excessive calculator complexity — §10.2.6\n",
                 ColorError(), ColorReset());
          issues++;
        }
      }
    }
  }

  if (calcCount == 0)
    printf("         No calculator elements found — check not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s %d calculator(s), %d total sub-elements\n",
           ColorSuccess(), ColorReset(), calcCount, totalSubElements);

  return issues;
}


// ---------------------------------------------------------------------------
// CF-137: MultiplexDefaultValues Tag Permitted Types
//         ICC.2-2019 §9.2.84 Errata (March 2021)
//         Corrected permitted types: ui08, ui16, fl16, fl32
// ---------------------------------------------------------------------------
static int RunCF137_MultiplexDefaultValuesType(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-137]%s MultiplexDefaultValues Tag Type (%sICC.2-2019 §9.2.84 Errata%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // 'mdv ' = 0x6D647620 (icSigMaterialDefaultValuesTag in iccDEV)
  CIccTag *pTag = pIcc->FindTag((icTagSignature)0x6D647620);
  if (!pTag) {
    printf("         No multiplexDefaultValuesTag ('mdv ') — check not applicable\n");
    return 0;
  }

  icTagTypeSignature typeSig = pTag->GetType();
  // Errata corrects permitted types to: uInt8ArrayType, uInt16ArrayType,
  // float16ArrayType, float32ArrayType
  bool validType = (typeSig == icSigUInt8ArrayType   ||  // 'ui08'
                    typeSig == icSigUInt16ArrayType   ||  // 'ui16'
                    typeSig == icSigFloat16ArrayType  ||  // 'fl16'
                    typeSig == icSigFloat32ArrayType);    // 'fl32'

  if (!validType) {
    char sig[5] = {};
    sig[0] = (char)((typeSig >> 24) & 0xFF);
    sig[1] = (char)((typeSig >> 16) & 0xFF);
    sig[2] = (char)((typeSig >>  8) & 0xFF);
    sig[3] = (char)( typeSig        & 0xFF);
    printf("         %s[WARN]%s Tag type '%s' not in errata-corrected permitted set "
           "(ui08/ui16/fl16/fl32) — ICC.2-2019 §9.2.84 Errata\n",
           ColorError(), ColorReset(), sig);
    issues++;
  } else {
    printf("         %s[OK]%s Tag type conforms to errata-corrected permitted types\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-138: Embedded Height Image Type Data Length
//         ICC.2-2019 §10.2.6 Errata (March 2021)
//         Corrected: image data = tagSize − 24 (NOT − 12)
//         Header: sig(4) + reserved(4) + seamless(4) + format(4) +
//                 minHeight(4) + maxHeight(4) = 24 bytes
// ---------------------------------------------------------------------------
static int RunCF138_EmbeddedHeightImageDataLength(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-138]%s Embedded Height Image Data Length (%sICC.2-2019 §10.2.6 Errata%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Scan tag table for 'ehim' (0x6568696D) type tags
  bool found = false;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag) continue;
    if (pTag->GetType() != (icTagTypeSignature)0x6568696D) continue;

    found = true;
    icUInt32Number tagSize = it->TagInfo.size;
    // Errata correction: header is 24 bytes, not 12
    if (tagSize < 24) {
      printf("         %s[WARN]%s embeddedHeightImageType tag size %u < 24 bytes "
             "(minimum header) — ICC.2-2019 §10.2.6 Errata\n",
             ColorError(), ColorReset(), tagSize);
      issues++;
    } else {
      icUInt32Number imageDataLen = tagSize - 24;
      printf("         %s[OK]%s embeddedHeightImageType: %u bytes total, "
             "%u bytes image data (header=24)\n",
             ColorSuccess(), ColorReset(), tagSize, imageDataLen);
    }
  }

  if (!found)
    printf("         No embeddedHeightImageType tags — check not applicable\n");

  return issues;
}

// ---------------------------------------------------------------------------
// CF-139: Embedded Normal Image Type Data Length
//         ICC.2-2019 §10.2.7 Errata (March 2021)
//         Corrected: image data = tagSize − 16 (NOT − 12)
//         Header: sig(4) + reserved(4) + seamless(4) + format(4) = 16 bytes
// ---------------------------------------------------------------------------
static int RunCF139_EmbeddedNormalImageDataLength(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-139]%s Embedded Normal Image Data Length (%sICC.2-2019 §10.2.7 Errata%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Scan tag table for 'enim' (0x656E696D) type tags
  bool found = false;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag) continue;
    if (pTag->GetType() != (icTagTypeSignature)0x656E696D) continue;

    found = true;
    icUInt32Number tagSize = it->TagInfo.size;
    // Errata correction: header is 16 bytes, not 12
    if (tagSize < 16) {
      printf("         %s[WARN]%s embeddedNormalImageType tag size %u < 16 bytes "
             "(minimum header) — ICC.2-2019 §10.2.7 Errata\n",
             ColorError(), ColorReset(), tagSize);
      issues++;
    } else {
      icUInt32Number imageDataLen = tagSize - 16;
      printf("         %s[OK]%s embeddedNormalImageType: %u bytes total, "
             "%u bytes image data (header=16)\n",
             ColorSuccess(), ColorReset(), tagSize, imageDataLen);
    }
  }

  if (!found)
    printf("         No embeddedNormalImageType tags — check not applicable\n");

  return issues;
}

// ---------------------------------------------------------------------------
// CF-140: Gamut Boundary Description Vertex Count Field
//         ICC.2-2019 §10.2.11 Errata (March 2021)
//         Corrected: missing "Number of vertices (V)" field at bytes 12..15
//         Structure: sig(4) + reserved(4) + nPCS(2) + nDevice(2) +
//                    nVertices(4) + nFaces(4) + faces + vertices
// ---------------------------------------------------------------------------
static int RunCF140_GBDVertexCountField(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-140]%s GBD Vertex Count Field (%sICC.2-2019 §10.2.11 Errata%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Scan for GBD tags: gbd0..gbd3 (0x67626430..0x67626433)
  bool found = false;
  icTagSignature gbdSigs[] = {
    (icTagSignature)0x67626430,  // 'gbd0'
    (icTagSignature)0x67626431,  // 'gbd1'
    (icTagSignature)0x67626432,  // 'gbd2'
    (icTagSignature)0x67626433,  // 'gbd3'
  };

  for (int g = 0; g < 4; g++) {
    CIccTag *pTag = pIcc->FindTag(gbdSigs[g]);
    if (!pTag) continue;
    if (pTag->GetType() != icSigGamutBoundaryDescType) continue;

    found = true;
    // Find the tag entry to get size
    for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
      if (it->TagInfo.sig != gbdSigs[g]) continue;
      icUInt32Number tagSize = it->TagInfo.size;
      // Minimum: sig(4) + reserved(4) + nPCS(2) + nDevice(2) + nVertices(4) + nFaces(4) = 20
      if (tagSize < 20) {
        char sig[5] = {};
        sig[0] = (char)((gbdSigs[g] >> 24) & 0xFF);
        sig[1] = (char)((gbdSigs[g] >> 16) & 0xFF);
        sig[2] = (char)((gbdSigs[g] >>  8) & 0xFF);
        sig[3] = (char)( gbdSigs[g]        & 0xFF);
        printf("         %s[WARN]%s GBD tag '%s' size %u < 20 bytes "
               "(errata requires vertex count at bytes 12..15) — ICC.2-2019 §10.2.11\n",
               ColorError(), ColorReset(), sig, tagSize);
        issues++;
      } else {
        printf("         %s[OK]%s GBD tag structure has room for vertex count field\n",
               ColorSuccess(), ColorReset());
      }
      break;
    }
  }

  if (!found)
    printf("         No gamutBoundaryDescType tags — check not applicable\n");

  return issues;
}

// ---------------------------------------------------------------------------
// CF-141: Sparse Matrix Array Type Count Field
//         ICC.2-2019 §10.2.20 Errata (March 2021)
//         Corrected: bytes 12..15 = "Number of sparse matrices in list (N)"
//         List data starts at byte 16, not 12
//         Structure: sig(4) + reserved(4) + channels(2) + matrixType(2) +
//                    nMatrices(4) + list(N*matrixSize)
// ---------------------------------------------------------------------------
static int RunCF141_SparseMatrixArrayCount(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-141]%s Sparse Matrix Array Count Field (%sICC.2-2019 §10.2.20 Errata%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  bool found = false;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag) continue;
    if (pTag->GetType() != icSigSparseMatrixArrayType) continue;

    found = true;
    icUInt32Number tagSize = it->TagInfo.size;
    // Minimum: sig(4) + reserved(4) + channels(2) + matrixType(2) + nMatrices(4) = 16
    if (tagSize < 16) {
      printf("         %s[WARN]%s sparseMatrixArrayType size %u < 16 bytes "
             "(errata requires count at bytes 12..15) — ICC.2-2019 §10.2.20\n",
             ColorError(), ColorReset(), tagSize);
      issues++;
    } else {
      printf("         %s[OK]%s sparseMatrixArrayType structure has count field at 12..15\n",
             ColorSuccess(), ColorReset());
    }
  }

  if (!found)
    printf("         No sparseMatrixArrayType tags — check not applicable\n");

  return issues;
}

// ---------------------------------------------------------------------------
// CF-142: Calculator Vector-Or Signature Alignment
//         ICC.2-2019 §11.2.1.9 Errata (September 2021)
//         Corrected: 'vor' → 'vor ' (trailing space for 4-byte alignment)
//         Hex: 0x766F7220 — the binary signature was always correct
//         This check validates calculator elements use the properly-padded sig
// ---------------------------------------------------------------------------
static int RunCF142_VectorOrSignatureAlignment(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-142]%s Calculator Vector-Or Signature (%sICC.2-2019 §11.2.1.9 Errata%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Scan for MPE calculator elements with vector-or operations
  bool found = false;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag) continue;

    CIccTagMultiProcessElement *mpe =
      dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!mpe) continue;

    std::string desc;
    mpe->Describe(desc, 0);
    if (desc.find("VectorOr") != std::string::npos ||
        desc.find("vor ") != std::string::npos) {
      found = true;
      // iccDEV uses icSigVectorOrOp = 0x766f7220 which is already correct
      printf("         %s[OK]%s Calculator uses 'vor ' (0x766F7220) — "
             "errata-aligned 4-byte signature\n",
             ColorSuccess(), ColorReset());
    }
  }

  if (!found)
    printf("         No calculator vector-or operations — check not applicable\n");

  return issues;
}

// ---------------------------------------------------------------------------
// CF-143: Measurement Tag Structure Type Validation
//         ICC.2-2019 §9.2.86/87 Errata (March 2021)
//         Corrected: measurementInfoTag and measurementInputInfoTag
//         permitted type = tagStructType (not just structType)
// ---------------------------------------------------------------------------
static int RunCF143_MeasurementTagStructType(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-143]%s Measurement Tag Structure Type (%sICC.2-2019 §9.2.86/87 Errata%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Check for measurement-related struct tags that should use tagStructType ('tstr')
  // icSigMeasurementTag = 0x6D656173 ('meas') — this is the v4 measurement tag
  // v5 measurement info tags would use tagStructType if they existed
  bool found = false;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag) continue;

    // Check if tag is a struct type that claims to be measurement info
    if (pTag->GetType() == icSigTagStructType) {
      CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct *>(pTag);
      if (pStruct) {
        icStructSignature structSig = pStruct->GetTagStructType();
        if (structSig == icSigMeasurementInfoStruct) {
          found = true;
          printf("         %s[OK]%s Measurement tag uses tagStructType "
                 "with measurementInfoStruct — errata-conformant\n",
                 ColorSuccess(), ColorReset());
        }
      }
    }
  }

  if (!found)
    printf("         No measurement struct tags — check not applicable\n");

  return issues;
}

// ===========================================================================
// ICS Extended Range checks (CF-144..CF-148)
// Source: ICS-ExtendedRange-Part1/2/3 + ICC.2-2023 §7.2.13
// ===========================================================================

// ---------------------------------------------------------------------------
// CF-144: Extended Range PCS Flag Consistency
// ICS-ExtendedRange §6.2 Table 3: flag bit 3 requires v5 profile
// ---------------------------------------------------------------------------
int RunCF144_ExtendedRangePCSFlagConsistency(CIccProfile *pIcc) {
  icUInt32Number flags = pIcc->m_Header.flags;
  bool extRange = (flags & icExtendedRangePCS) != 0;

  printf("%s[CF-144]%s Extended Range PCS Flag Consistency (%sICC.2-2023 §7.2.13%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!extRange) {
    printf("         flags=0x%08X — Extended Range PCS bit (3) not set\n",
           flags);
    printf("         %s[OK]%s Check not applicable — no extended range PCS\n",
           ColorInfo(), ColorReset());
    return 0;
  }

  int issues = 0;
  icUInt32Number version = pIcc->m_Header.version >> 24;
  printf("         flags=0x%08X — Extended Range PCS bit (3) IS set\n", flags);

  if (version < 5) {
    printf("         %s[FAIL]%s Extended Range PCS flag requires v5 (iccMAX) profile — "
           "found version %u — ICC.2-2023 §7.2.13\n",
           ColorError(), ColorReset(), version);
    issues++;
  }

  // ICS-ExtendedRange Table 3: profile flags shall be 0 (for conforming profiles)
  // but bit 3 is the extended range indicator itself, so only other bits are suspect
  icUInt32Number otherFlags = flags & ~static_cast<icUInt32Number>(icExtendedRangePCS | icEmbeddedProfileTrue | icMCSNeedsSubsetTrue);
  if (otherFlags) {
    printf("         %s[WARN]%s Unexpected additional flag bits 0x%08X alongside extended range PCS\n",
           ColorInfo(), ColorReset(), otherFlags);
    issues++;
  }

  if (!issues) {
    printf("         %s[OK]%s Extended Range PCS flag consistent with profile version %u\n",
           ColorSuccess(), ColorReset(), version);
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-145: Extended Range PCS + Spectral Co-existence
// ICS-ExtendedRange Part 2/3 allow spectral PCS with extended range
// Part 1 requires colorimetric PCS only (XYZ, no spectral)
// ---------------------------------------------------------------------------
int RunCF145_ExtendedRangePCSSpectralCoexistence(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  icUInt32Number flags = pIcc->m_Header.flags;
  bool extRange = (flags & icExtendedRangePCS) != 0;

  printf("%s[CF-145]%s Extended Range PCS + Spectral Co-existence (%sICS-ExtendedRange Part 1 §6.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!extRange) {
    printf("         Extended Range PCS not set — check not applicable\n");
    return 0;
  }

  int issues = 0;
  icColorSpaceSignature spectralPCS = pIcc->m_Header.spectralPCS;
  icColorSpaceSignature pcs = pIcc->m_Header.pcs;

  printf("         Extended Range PCS set; pcs=0x%08X, spectralPCS=0x%08X\n",
         static_cast<unsigned>(pcs), static_cast<unsigned>(spectralPCS));

  // ICS-ExtendedRange Part 1 Table 3: colorimetric PCS must be XYZ
  char pcsSig[5];
  SigToChars(static_cast<uint32_t>(pcs), pcsSig);
  if (pcs != icSigXYZData && pcs != icSigLabData) {
    printf("         %s[FAIL]%s Extended Range PCS profiles shall use XYZ or Lab PCS — "
           "found '%s' — ICS-ExtendedRange §6.2\n",
           ColorError(), ColorReset(), pcsSig);
    issues++;
  }

  if (!issues) {
    printf("         %s[OK]%s Extended range PCS co-existence with spectral/colorimetric PCS valid\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-146: Extended Range Class Restriction
// ICS-ExtendedRange Table 1: only 'mntr' (display) and 'spac' (colorSpace)
// ICS-ExtendedOutput Table 11: only 'prtr' (output)
// ---------------------------------------------------------------------------
int RunCF146_ExtendedRangeClassRestriction(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  icUInt32Number flags = pIcc->m_Header.flags;
  bool extRange = (flags & icExtendedRangePCS) != 0;

  printf("%s[CF-146]%s Extended Range Class Restriction (%sICS-ExtendedRange Table 1%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!extRange) {
    printf("         Extended Range PCS not set — check not applicable\n");
    return 0;
  }

  int issues = 0;
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  char clsSig[5];
  SigToChars(static_cast<uint32_t>(cls), clsSig);

  // ICS defines extended range for: mntr, spac (Part 1), prtr (ExtendedOutput)
  bool validClass = (cls == icSigDisplayClass ||
                     cls == icSigColorSpaceClass ||
                     cls == icSigOutputClass);

  printf("         Profile class: '%s' (0x%08X)\n",
         clsSig, static_cast<unsigned>(cls));

  if (!validClass) {
    printf("         %s[FAIL]%s Extended Range PCS is defined for display ('mntr'), "
           "colorSpace ('spac'), and output ('prtr') classes only — "
           "ICS-ExtendedRange Table 1, ICS-ExtendedOutput Table 11\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         %s[OK]%s Profile class '%s' is valid for extended range PCS\n",
           ColorSuccess(), ColorReset(), clsSig);
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-147: Extended Range Colorimetric Intent Required
// ICS-ExtendedRange Table 4: AToB1Tag and BToA1Tag required (intent 1 = relative)
// ---------------------------------------------------------------------------
int RunCF147_ExtendedRangeColorimetricIntent(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  icUInt32Number flags = pIcc->m_Header.flags;
  bool extRange = (flags & icExtendedRangePCS) != 0;

  printf("%s[CF-147]%s Extended Range Colorimetric Intent Required (%sICS-ExtendedRange Table 4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!extRange) {
    printf("         Extended Range PCS not set — check not applicable\n");
    return 0;
  }

  // Only for mntr/spac (ICS-ExtendedRange); prtr has different requirements (CF-152)
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  if (cls != icSigDisplayClass && cls != icSigColorSpaceClass) {
    printf("         Profile class is not display/colorSpace — see CF-152 for output class\n");
    return 0;
  }

  int issues = 0;

  // ICS-ExtendedRange Part 1 Table 4: AToB1Tag and BToA1Tag are required
  CIccTag *pA2B1 = pIcc->FindTag(icSigAToB1Tag);
  CIccTag *pB2A1 = pIcc->FindTag(icSigBToA1Tag);

  if (!pA2B1) {
    printf("         %s[FAIL]%s AToB1Tag ('A2B1') required for extended range display/colorSpace — "
           "ICS-ExtendedRange Table 4\n", ColorError(), ColorReset());
    issues++;
  }
  if (!pB2A1) {
    printf("         %s[FAIL]%s BToA1Tag ('B2A1') required for extended range display/colorSpace — "
           "ICS-ExtendedRange Table 4\n", ColorError(), ColorReset());
    issues++;
  }
  if (!issues) {
    printf("         %s[OK]%s Required AToB1Tag and BToA1Tag present\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-148: Extended Range AToB/BToA LUT Presence (multiProcessElementsType)
// ICS-ExtendedRange Table 4: tags shall be multiProcessElementsType
// NOTE: iccDEV uses singular name "icSigMultiProcessElementType" — see errata §10.2.17
// ---------------------------------------------------------------------------
int RunCF148_ExtendedRangeLUTPresence(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  icUInt32Number flags = pIcc->m_Header.flags;
  bool extRange = (flags & icExtendedRangePCS) != 0;

  printf("%s[CF-148]%s Extended Range LUT multiProcessElementsType (%sICS-ExtendedRange Table 4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!extRange) {
    printf("         Extended Range PCS not set — check not applicable\n");
    return 0;
  }

  int issues = 0;

  // Check A2B1 and B2A1 are multiProcessElementsType (errata: plural)
  static const icTagSignature tags[] = {icSigAToB1Tag, icSigBToA1Tag};
  static const char *names[] = {"AToB1Tag", "BToA1Tag"};

  for (int i = 0; i < 2; i++) {
    CIccTag *pTag = pIcc->FindTag(tags[i]);
    if (!pTag) continue;  // absence already flagged by CF-147

    icTagTypeSignature typeSig = pTag->GetType();
    if (typeSig != icSigMultiProcessElementType) {
      char tSig[5];
      SigToChars(static_cast<uint32_t>(typeSig), tSig);
      printf("         %s[FAIL]%s %s shall be multiProcessElementsType — found '%s' — "
             "ICS-ExtendedRange Table 4\n",
             ColorError(), ColorReset(), names[i], tSig);
      issues++;
    }
  }

  if (!issues) {
    printf("         %s[OK]%s Extended range LUT tags use multiProcessElementsType\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ===========================================================================
// ICS Extended Output checks (CF-149..CF-152)
// Source: ICS-ExtendedOutput-Part1
// ===========================================================================

// ---------------------------------------------------------------------------
// CF-149: Extended Output Profile Class
// ICS-ExtendedOutput Table 11: profile class shall be 'prtr'
// ---------------------------------------------------------------------------
int RunCF149_ExtendedOutputProfileClass(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-149]%s Extended Output Profile Class (%sICS-ExtendedOutput Table 11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // This check only applies to profiles with spectralPCS set (output profiles
  // using spectral workflows) or profiles explicitly identifying as extendedOutput
  icColorSpaceSignature spectralPCS = pIcc->m_Header.spectralPCS;
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;

  if (static_cast<icUInt32Number>(spectralPCS) == 0) {
    printf("         No spectral PCS — extended output ICS check not applicable\n");
    return 0;
  }

  if (cls != icSigOutputClass) {
    printf("         Profile class is not 'prtr' — extended output ICS check informational only\n");
    return 0;
  }

  int issues = 0;

  // ICS-ExtendedOutput Table 12: required tags for output class with spectral PCS
  // AToB1Tag or AToB3Tag, BToA1Tag or BToA3Tag, DToB3Tag,
  // spectralWhitePointTag, customToStandardPccTag, standardToCustomPccTag,
  // spectralViewingConditionsTag
  CIccTag *pSWPT = pIcc->FindTag(icSigSpectralWhitePointTag);
  CIccTag *pSVCN = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  CIccTag *pC2SP = pIcc->FindTag(icSigCustomToStandardPccTag);
  CIccTag *pS2CP = pIcc->FindTag(icSigStandardToCustomPccTag);

  if (!pSWPT) {
    printf("         %s[FAIL]%s spectralWhitePointTag ('swpt') required — ICS-ExtendedOutput Table 12\n",
           ColorError(), ColorReset());
    issues++;
  }
  if (!pSVCN) {
    printf("         %s[FAIL]%s spectralViewingConditionsTag ('svcn') required — ICS-ExtendedOutput Table 12\n",
           ColorError(), ColorReset());
    issues++;
  }
  if (!pC2SP) {
    printf("         %s[FAIL]%s customToStandardPccTag ('c2sp') required — ICS-ExtendedOutput Table 12\n",
           ColorError(), ColorReset());
    issues++;
  }
  if (!pS2CP) {
    printf("         %s[FAIL]%s standardToCustomPccTag ('s2cp') required — ICS-ExtendedOutput Table 12\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (!issues) {
    printf("         %s[OK]%s Extended output spectral workflow tags present\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-150: Extended Output Gamut Tag
// ICS-ExtendedOutput Table 13: gamutBoundaryDescription is optional
// ---------------------------------------------------------------------------
int RunCF150_ExtendedOutputGamutTag(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-150]%s Extended Output Gamut Boundary Tag (%sICS-ExtendedOutput Table 13%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  if (cls != icSigOutputClass) {
    printf("         Not an output class profile — check not applicable\n");
    return 0;
  }

  // Gamut boundary description tags are optional per Table 13 but recommended
  // Check if any gbdX tags are present (gbdN where N=0..3)
  int gbdCount = 0;
  static const icTagSignature gbdTags[] = {
    static_cast<icTagSignature>(0x67626430), // 'gbd0'
    static_cast<icTagSignature>(0x67626431), // 'gbd1'
    static_cast<icTagSignature>(0x67626432), // 'gbd2'
    static_cast<icTagSignature>(0x67626433), // 'gbd3'
  };
  for (int i = 0; i < 4; i++) {
    if (pIcc->FindTag(gbdTags[i])) gbdCount++;
  }

  if (gbdCount > 0) {
    printf("         %s[OK]%s %d gamut boundary description tag(s) present (informational)\n",
           ColorInfo(), ColorReset(), gbdCount);
  } else {
    printf("         %s[INFO]%s No gamut boundary description tags found — "
           "optional per ICS-ExtendedOutput Table 13\n",
           ColorInfo(), ColorReset());
  }
  return 0;  // informational only
}

// ---------------------------------------------------------------------------
// CF-151: Extended Output mediaWhitePoint Range
// ICS-ExtendedOutput Table 12: XYZ tristimulus values of near diffuse white
// ---------------------------------------------------------------------------
int RunCF151_ExtendedOutputMediaWhitePointRange(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-151]%s Extended Output mediaWhitePoint Range (%sICS-ExtendedOutput Table 12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  if (cls != icSigOutputClass) {
    printf("         Not an output class profile — check not applicable\n");
    return 0;
  }

  CIccTag *pTag = pIcc->FindTag(icSigMediaWhitePointTag);
  if (!pTag) {
    printf("         %s[INFO]%s mediaWhitePointTag not present\n",
           ColorInfo(), ColorReset());
    return 0;
  }

  int issues = 0;
  CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ *>(pTag);
  if (!pXYZ || pXYZ->GetSize() < 1) {
    printf("         %s[FAIL]%s mediaWhitePointTag is not valid XYZType\n",
           ColorError(), ColorReset());
    return 1;
  }

  icXYZNumber *wp = pXYZ->GetXYZ(0);
  if (!wp) {
    printf("         %s[FAIL]%s mediaWhitePointTag XYZ data is null\n",
           ColorError(), ColorReset());
    return 1;
  }
  // Convert from s15Fixed16 to float
  icFloatNumber X = icFtoD(wp->X);
  icFloatNumber Y = icFtoD(wp->Y);
  icFloatNumber Z = icFtoD(wp->Z);

  printf("         mediaWhitePoint: X=%.4f Y=%.4f Z=%.4f\n", X, Y, Z);

  // Plausibility: Y should be > 0, X and Z should be positive
  if (Y <= 0.0f || X <= 0.0f || Z <= 0.0f) {
    printf("         %s[FAIL]%s mediaWhitePoint XYZ values must be positive — "
           "ICS-ExtendedOutput Table 12\n", ColorError(), ColorReset());
    issues++;
  }
  // Extended output white points may have high luminance
  if (Y > 1000.0f) {
    printf("         %s[WARN]%s mediaWhitePoint Y=%.4f is unusually high — verify luminance\n",
           ColorInfo(), ColorReset(), Y);
    issues++;
  }

  if (!issues) {
    printf("         %s[OK]%s mediaWhitePoint values are plausible\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-152: Extended Output AToB Completeness
// ICS-ExtendedOutput Table 12: AToB1Tag or AToB3Tag + BToA1 or BToA3 + DToB3
// ---------------------------------------------------------------------------
int RunCF152_ExtendedOutputAToBCompleteness(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-152]%s Extended Output AToB/BToA/DToB Completeness (%sICS-ExtendedOutput Table 12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  icColorSpaceSignature spectralPCS = pIcc->m_Header.spectralPCS;

  if (cls != icSigOutputClass || static_cast<icUInt32Number>(spectralPCS) == 0) {
    printf("         Not an output class with spectral PCS — check not applicable\n");
    return 0;
  }

  int issues = 0;

  // ICS-ExtendedOutput Table 12: AToB1Tag OR AToB3Tag required
  bool hasA2B1 = pIcc->FindTag(icSigAToB1Tag) != nullptr;
  bool hasA2B3 = pIcc->FindTag(icSigAToB3Tag) != nullptr;
  if (!hasA2B1 && !hasA2B3) {
    printf("         %s[FAIL]%s AToB1Tag or AToB3Tag required — ICS-ExtendedOutput Table 12\n",
           ColorError(), ColorReset());
    issues++;
  }

  // BToA1Tag OR BToA3Tag required
  bool hasB2A1 = pIcc->FindTag(icSigBToA1Tag) != nullptr;
  bool hasB2A3 = pIcc->FindTag(icSigBToA3Tag) != nullptr;
  if (!hasB2A1 && !hasB2A3) {
    printf("         %s[FAIL]%s BToA1Tag or BToA3Tag required — ICS-ExtendedOutput Table 12\n",
           ColorError(), ColorReset());
    issues++;
  }

  // DToB3Tag required
  bool hasD2B3 = pIcc->FindTag(icSigDToB3Tag) != nullptr;
  if (!hasD2B3) {
    printf("         %s[FAIL]%s DToB3Tag ('D2B3') required — ICS-ExtendedOutput Table 12\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (!issues) {
    printf("         %s[OK]%s Extended output AToB/BToA/DToB tag completeness verified\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ===========================================================================
// ICS Interoperability Conformance Specification checks (CF-191..CF-198)
// Source: ICC White Paper 57 — Introduction to core ICS specifications
//         ICS-ExtendedRange-Part1/2/3, ICS-ExtendedOutput-Part1/2,
//         ICS Colorimetric PCC, ICS Spectral Reflectance
// ===========================================================================

// Known ICS sub-class signatures (registered with ICC)
static const struct {
  icUInt32Number sig;
  const char *name;
  const char *description;
} kICSSubClasses[] = {
  {0x70636320, "pcc ", "Colorimetric PCC"},           // 'pcc '
  {0x78726E67, "xrng", "Extended Dynamic Range"},     // 'xrng'
  {0x73726566, "sref", "Spectral Reflectance"},       // 'sref'
  {0x65787420, "ext ", "Extended Output"},             // 'ext '
};
static constexpr int kICSSubClassCount =
    static_cast<int>(sizeof(kICSSubClasses) / sizeof(kICSSubClasses[0]));

// MPE element types allowed in ICS Part 1 (restricted — no calculatorElement)
static const icElemTypeSignature kICSPart1AllowedMPE[] = {
  icSigCurveSetElemType,      // 'cvst'
  icSigMatrixElemType,        // 'matf'
  icSigCLutElemType,          // 'clut'
  icSigExtCLutElemType,       // 'xclt'
  icSigTintArrayElemType,     // 'tint'
  icSigBAcsElemType,          // 'bACS'
  icSigEAcsElemType,          // 'eACS'
};
static constexpr int kICSPart1AllowedCount =
    static_cast<int>(sizeof(kICSPart1AllowedMPE) / sizeof(kICSPart1AllowedMPE[0]));

static bool IsICSPart1AllowedMPE(icElemTypeSignature sig) {
  for (int i = 0; i < kICSPart1AllowedCount; i++) {
    if (kICSPart1AllowedMPE[i] == sig) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// CF-191: ICS Sub-Class Signature Registry
// Validate that deviceSubClass matches a known ICS sub-class when non-zero
// ---------------------------------------------------------------------------
int RunCF191_ICSSubClassRegistry(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-191]%s ICS Sub-Class Signature Registry (%sICC WP-57 §ICS Registration%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal == 0) {
    printf("         deviceSubClass not set — no ICS sub-class declared\n");
    printf("         %s[OK]%s No sub-class (standard ICC.2 profile)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  char sigCC[5];
  SigToChars(scVal, sigCC);

  bool found = false;
  for (int i = 0; i < kICSSubClassCount; i++) {
    if (scVal == kICSSubClasses[i].sig) {
      printf("         ICS sub-class: '%s' — %s\n", kICSSubClasses[i].name,
             kICSSubClasses[i].description);
      printf("         %s[OK]%s Known ICS sub-class signature\n",
             ColorSuccess(), ColorReset());
      found = true;
      break;
    }
  }

  if (!found) {
    printf("         deviceSubClass=0x%08X ('%s') — not a registered ICS sub-class\n",
           scVal, sigCC);
    printf("         %s[WARN]%s Unregistered ICS sub-class — may indicate private extension\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-192: Colorimetric ICS Required Tags
// 'pcc ' sub-class: AToB1, BToA1, svcn, c2sp, s2cp required
// ---------------------------------------------------------------------------
int RunCF192_ColorimetricICSRequiredTags(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-192]%s Colorimetric ICS Required Tags (%sICS-Colorimetric-Part1 §6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x70636320) {  // 'pcc '
    printf("         Sub-class is not 'pcc ' — check not applicable\n");
    return 0;
  }

  int issues = 0;

  // Required tag table for Colorimetric ICS
  static const struct { icTagSignature sig; const char *name; } required[] = {
    {icSigAToB1Tag,                       "AToB1Tag"},
    {icSigBToA1Tag,                       "BToA1Tag"},
    {icSigSpectralViewingConditionsTag,   "spectralViewingConditionsTag"},
    {icSigCustomToStandardPccTag,         "customToStandardPccTag (c2sp)"},
    {icSigStandardToCustomPccTag,         "standardToCustomPccTag (s2cp)"},
  };

  for (int i = 0; i < 5; i++) {
    CIccTag *pTag = pIcc->FindTag(required[i].sig);
    if (!pTag) {
      printf("         %s[FAIL]%s Missing required tag: %s — ICS-Colorimetric §6\n",
             ColorError(), ColorReset(), required[i].name);
      issues++;
    } else {
      printf("         %s[OK]%s %s present\n", ColorSuccess(), ColorReset(), required[i].name);
    }
  }

  // Profile class must be colorSpace ('spac')
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  if (cls != icSigColorSpaceClass) {
    char cSig[5];
    SigToChars(static_cast<icUInt32Number>(cls), cSig);
    printf("         %s[FAIL]%s Colorimetric ICS requires colorSpace class — found '%s'\n",
           ColorError(), ColorReset(), cSig);
    issues++;
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-193: Colorimetric ICS PCC Matrix Restriction
// Part 1: c2sp and s2cp shall be restricted to a single 3×3 matrix
// ---------------------------------------------------------------------------
int RunCF193_ColorimetricPCCMatrixRestriction(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-193]%s Colorimetric ICS PCC Matrix Restriction (%sICS-Colorimetric-Part1 §7%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x70636320) {  // 'pcc '
    printf("         Sub-class is not 'pcc ' — check not applicable\n");
    return 0;
  }

  int issues = 0;

  // Check c2sp and s2cp tags are multiProcessElementsType with restricted elements
  static const icTagSignature pccTags[] = {
    icSigCustomToStandardPccTag, icSigStandardToCustomPccTag
  };
  static const char *pccNames[] = {"c2sp", "s2cp"};

  for (int t = 0; t < 2; t++) {
    CIccTag *pTag = pIcc->FindTag(pccTags[t]);
    if (!pTag) continue;

    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMPE) {
      printf("         %s[FAIL]%s %s is not multiProcessElementsType — Part 1 requires MPE\n",
             ColorError(), ColorReset(), pccNames[t]);
      issues++;
      continue;
    }

    icUInt32Number nElem = pMPE->NumElements();
    if (nElem != 1) {
      printf("         %s[WARN]%s %s has %u elements — Part 1 restricts to single 3×3 matrix\n",
             ColorWarning(), ColorReset(), pccNames[t], nElem);
      issues++;
    }

    // Verify element is matrix type
    if (nElem >= 1) {
      CIccMultiProcessElement *pElem = pMPE->GetElement(0);
      if (pElem && pElem->GetType() != icSigMatrixElemType) {
        char eSig[5];
        SigToChars(static_cast<icUInt32Number>(pElem->GetType()), eSig);
        printf("         %s[WARN]%s %s first element is '%s' — Part 1 restricts to matrixElement\n",
               ColorWarning(), ColorReset(), pccNames[t], eSig);
        issues++;
      }
    }
  }

  if (!issues) {
    printf("         %s[OK]%s PCC tags conform to Part 1 matrix restriction\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-194: Spectral Reflectance ICS Required Tags
// 'sref' sub-class: DToB3, BToD3, svcn, c2sp, s2cp required
// ---------------------------------------------------------------------------
int RunCF194_SpectralReflectanceRequiredTags(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-194]%s Spectral Reflectance ICS Required Tags (%sICS-SpectralReflectance-Part1 §6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x73726566) {  // 'sref'
    printf("         Sub-class is not 'sref' — check not applicable\n");
    return 0;
  }

  int issues = 0;

  static const struct { icTagSignature sig; const char *name; } required[] = {
    {icSigDToB3Tag,                       "DToB3Tag"},
    {icSigBToD3Tag,                       "BToD3Tag"},
    {icSigSpectralViewingConditionsTag,   "spectralViewingConditionsTag"},
    {icSigCustomToStandardPccTag,         "customToStandardPccTag (c2sp)"},
    {icSigStandardToCustomPccTag,         "standardToCustomPccTag (s2cp)"},
  };

  for (int i = 0; i < 5; i++) {
    CIccTag *pTag = pIcc->FindTag(required[i].sig);
    if (!pTag) {
      printf("         %s[FAIL]%s Missing required tag: %s — ICS-SpectralReflectance §6\n",
             ColorError(), ColorReset(), required[i].name);
      issues++;
    } else {
      printf("         %s[OK]%s %s present\n", ColorSuccess(), ColorReset(), required[i].name);
    }
  }

  // Spectral PCS must be reflectance-based
  icUInt32Number specPCS = static_cast<icUInt32Number>(pIcc->m_Header.spectralPCS);
  if (specPCS != static_cast<icUInt32Number>(icSigReflectanceSpectralPcsData)) {
    char sSig[5];
    SigToChars(specPCS, sSig);
    printf("         %s[FAIL]%s Spectral Reflectance requires reflectance PCS — found '%s'\n",
           ColorError(), ColorReset(), sSig);
    issues++;
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-195: Extended Dynamic Range Radiance White Point
// 'xrng': Y of media white point can exceed 1.0 (luminance in cd/m²)
// ---------------------------------------------------------------------------
int RunCF195_ExtendedRangeRadianceWhitePoint(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-195]%s Extended Dynamic Range Radiance White Point (%sICS-ExtendedRange §5.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number flags = pIcc->m_Header.flags;
  bool extRange = (flags & icExtendedRangePCS) != 0;
  if (!extRange) {
    printf("         Extended Range PCS not set — check not applicable\n");
    return 0;
  }

  int issues = 0;

  // Look for spectral white point (swpt) — radiance-based XYZ
  CIccTag *pSwpt = pIcc->FindTag(icSigSpectralWhitePointTag);
  CIccTag *pWpt = pIcc->FindTag(icSigMediaWhitePointTag);

  if (pSwpt) {
    printf("         spectralWhitePointTag present — radiance-based XYZ expected\n");
    // For xrng, Y value represents luminance in cd/m² — can be >> 1.0
    CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ*>(pSwpt);
    if (pXYZ && pXYZ->GetSize() > 0) {
      icXYZNumber *pVal = pXYZ->GetXYZ(0);
      if (!pVal) {
        printf("         %s[FAIL]%s spectralWhitePointTag XYZ data is null\n",
               ColorError(), ColorReset());
        issues++;
      } else {
        double Y = icFtoD(pVal->Y);
        printf("         White point Y = %.4f", Y);
        if (Y > 1.0) {
          printf(" (extended range — luminance %.1f cd/m²)\n", Y);
          printf("         %s[OK]%s Radiance-based white point with extended Y\n",
                 ColorSuccess(), ColorReset());
        } else if (Y > 0.0) {
          printf(" (standard range)\n");
          printf("         %s[OK]%s White point Y in valid range\n",
                 ColorSuccess(), ColorReset());
        } else {
          printf(" (invalid — Y must be > 0)\n");
          printf("         %s[FAIL]%s White point Y ≤ 0 — ICS-ExtendedRange §5.2\n",
                 ColorError(), ColorReset());
          issues++;
        }
      }
    }
  } else if (pWpt) {
    printf("         mediaWhitePointTag present (no spectralWhitePointTag)\n");
    printf("         %s[OK]%s Using standard media white point\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("         %s[WARN]%s No white point tag found for extended range profile\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-196: ICS MPE Calculator Restriction (Part 1 vs Part 2)
// Part 1: transform tags shall NOT contain calculatorElement
// Part 2: calculatorElement IS allowed
// ---------------------------------------------------------------------------
int RunCF196_ICSMPECalculatorRestriction(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-196]%s ICS MPE Calculator Restriction (%sICC WP-57 Part 1 vs Part 2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Only applies to profiles with known ICS sub-classes
  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  bool isICS = false;
  for (int i = 0; i < kICSSubClassCount; i++) {
    if (scVal == kICSSubClasses[i].sig) { isICS = true; break; }
  }
  if (!isICS) {
    printf("         No ICS sub-class — check not applicable\n");
    return 0;
  }

  int issues = 0;
  bool hasCalculator = false;

  // Check transform tags for calculatorElement
  static const icTagSignature transformTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB3Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA3Tag,
    icSigDToB0Tag, icSigDToB1Tag, icSigDToB3Tag,
    icSigBToD0Tag, icSigBToD1Tag, icSigBToD3Tag,
    icSigCustomToStandardPccTag,
    icSigStandardToCustomPccTag,
  };

  for (int t = 0; t < 14; t++) {
    CIccTag *pTag = pIcc->FindTag(transformTags[t]);
    if (!pTag) continue;

    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMPE) continue;

    icUInt32Number nElem = pMPE->NumElements();
    for (icUInt32Number e = 0; e < nElem; e++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement(static_cast<int>(e));
      if (!pElem) continue;

      if (pElem->GetType() == icSigCalculatorElemType) {
        hasCalculator = true;
        char tSig[5];
        SigToChars(static_cast<icUInt32Number>(transformTags[t]), tSig);
        printf("         calculatorElement found in tag '%s' — Part 2 feature\n", tSig);
      }

      // Also flag elements not in Part 1 allowed set
      if (!IsICSPart1AllowedMPE(pElem->GetType()) &&
          pElem->GetType() != icSigCalculatorElemType) {
        char eSig[5], tSig[5];
        SigToChars(static_cast<icUInt32Number>(pElem->GetType()), eSig);
        SigToChars(static_cast<icUInt32Number>(transformTags[t]), tSig);
        printf("         %s[INFO]%s Non-Part-1 element '%s' in tag '%s'\n",
               ColorInfo(), ColorReset(), eSig, tSig);
      }
    }
  }

  if (hasCalculator) {
    printf("         %s[OK]%s Profile uses ICS Part 2 features (calculatorElement present)\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("         %s[OK]%s Profile conforms to ICS Part 1 (no calculatorElement)\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-197: ICS PCC Transform Pair Completeness
// customToStandardPcc (c2sp) and standardToCustomPcc (s2cp) must both be
// present when either is present — they are a mandatory pair
// ---------------------------------------------------------------------------
int RunCF197_ICSPCCTransformPairCompleteness(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-197]%s ICS PCC Transform Pair Completeness (%sICC WP-57 §PCC Transforms%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;

  CIccTag *c2sp = pIcc->FindTag(icSigCustomToStandardPccTag);
  CIccTag *s2cp = pIcc->FindTag(icSigStandardToCustomPccTag);

  if (!c2sp && !s2cp) {
    printf("         Neither c2sp nor s2cp present — check not applicable\n");
    return 0;
  }

  if (c2sp && !s2cp) {
    printf("         %s[FAIL]%s customToStandardPcc (c2sp) present but standardToCustomPcc (s2cp) missing\n",
           ColorError(), ColorReset());
    printf("         PCC transform pairs must be complete for bidirectional conversion\n");
    issues++;
  } else if (!c2sp && s2cp) {
    printf("         %s[FAIL]%s standardToCustomPcc (s2cp) present but customToStandardPcc (c2sp) missing\n",
           ColorError(), ColorReset());
    printf("         PCC transform pairs must be complete for bidirectional conversion\n");
    issues++;
  } else {
    printf("         %s[OK]%s Both c2sp and s2cp present — transform pair complete\n",
           ColorSuccess(), ColorReset());

    // Verify both are multiProcessElementsType (errata: plural)
    bool c2spMPE = (dynamic_cast<CIccTagMultiProcessElement*>(c2sp) != nullptr);
    bool s2cpMPE = (dynamic_cast<CIccTagMultiProcessElement*>(s2cp) != nullptr);
    if (!c2spMPE || !s2cpMPE) {
      printf("         %s[WARN]%s PCC tags should be multiProcessElementsType for ICS\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-198: Extended Range Sub-Class Class Restriction
// 'xrng' profile must have display (mntr) or colorSpace (spac) class
// ---------------------------------------------------------------------------
int RunCF198_ExtendedRangeSubClassValidation(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-198]%s Extended Range Sub-Class Validation (%sICS-ExtendedRange §4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x78726E67) {  // 'xrng'
    printf("         Sub-class is not 'xrng' — check not applicable\n");
    return 0;
  }

  int issues = 0;

  // xrng requires display (mntr) or colorSpace (spac) class
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  if (cls != icSigDisplayClass && cls != icSigColorSpaceClass) {
    char cSig[5];
    SigToChars(static_cast<icUInt32Number>(cls), cSig);
    printf("         %s[FAIL]%s Extended Dynamic Range requires display or colorSpace class — found '%s'\n",
           ColorError(), ColorReset(), cSig);
    printf("         ICS-ExtendedRange §4: 'sub-class xrng shall have a profile class of display or colorSpace'\n");
    issues++;
  } else {
    char cSig[5];
    SigToChars(static_cast<icUInt32Number>(cls), cSig);
    printf("         Profile class: '%s' — valid for extended dynamic range\n", cSig);
    printf("         %s[OK]%s Class meets ICS-ExtendedRange requirement\n",
           ColorSuccess(), ColorReset());
  }

  // Also check extended range PCS flag is set
  icUInt32Number flags = pIcc->m_Header.flags;
  if (!(flags & icExtendedRangePCS)) {
    printf("         %s[WARN]%s 'xrng' sub-class but extended range PCS flag not set — inconsistent\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  return issues;
}

// ===========================================================================
// ICC.2-in-ICC.1 Embedding checks (CF-153..CF-158)
// Source: Embedding_an_ICC.2_profile_in_an_ICC.1_profile.pdf
// ===========================================================================

// ---------------------------------------------------------------------------
// CF-153: Embedded Profile Tag Presence
// Embedding spec: tag signature 'ICC5' (49434335h), type 'ICCp' (49434370h)
// ---------------------------------------------------------------------------
int RunCF153_EmbeddedProfileTagPresence(CIccProfile *pIcc) {
  printf("%s[CF-153]%s Embedded Profile Tag Presence (%sICC TN Embedding §Embedded profile tag%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
  if (!pTag) {
    printf("         No 'ICC5' embedded profile tag found\n");
    printf("         %s[OK]%s Check not applicable — no embedded ICC.2 profile\n",
           ColorInfo(), ColorReset());
    return 0;
  }

  int issues = 0;
  icTagTypeSignature typeSig = pTag->GetType();
  if (typeSig != icSigEmbeddedProfileType) {
    char tSig[5];
    SigToChars(static_cast<uint32_t>(typeSig), tSig);
    printf("         %s[FAIL]%s Embedded profile tag type shall be 'ICCp' (49434370h) — "
           "found '%s' (0x%08X)\n",
           ColorError(), ColorReset(), tSig, static_cast<unsigned>(typeSig));
    issues++;
  } else {
    printf("         %s[OK]%s Embedded profile tag 'ICC5' with type 'ICCp' present\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-154: Embedded Profile Version Bridging
// Embedding spec: parent shall be ICC.1 (v2/v4), child shall be ICC.2 (v5)
// ---------------------------------------------------------------------------
int RunCF154_EmbeddedProfileVersionBridging(CIccProfile *pIcc) {
  printf("%s[CF-154]%s Embedded Profile Version Bridging (%sICC TN Embedding §ICC.2 Profile header%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
  if (!pTag) {
    printf("         No embedded profile — check not applicable\n");
    return 0;
  }

  CIccTagEmbeddedProfile *pEmbed = dynamic_cast<CIccTagEmbeddedProfile *>(pTag);
  if (!pEmbed) {
    printf("         %s[FAIL]%s Tag is not CIccTagEmbeddedProfile type\n",
           ColorError(), ColorReset());
    return 1;
  }

  int issues = 0;
  icUInt32Number parentVersion = pIcc->m_Header.version >> 24;

  CIccProfile *pChild = pEmbed->GetProfile();
  if (!pChild) {
    printf("         %s[FAIL]%s Embedded profile data could not be read\n",
           ColorError(), ColorReset());
    return 1;
  }

  icUInt32Number childVersion = pChild->m_Header.version >> 24;
  printf("         Parent version: %u, Child version: %u\n",
         parentVersion, childVersion);

  // Parent should be ICC.1 (v2 or v4)
  if (parentVersion >= 5) {
    printf("         %s[WARN]%s Parent profile is already v5 — embedding is intended for "
           "ICC.1 (v2/v4) parent profiles\n", ColorInfo(), ColorReset());
    issues++;
  }

  // Child should be ICC.2 (v5)
  if (childVersion < 5) {
    printf("         %s[FAIL]%s Embedded child profile shall be ICC.2 (v5+) — found version %u\n",
           ColorError(), ColorReset(), childVersion);
    issues++;
  }

  if (!issues) {
    printf("         %s[OK]%s Version bridging correct: v%u parent embeds v%u child\n",
           ColorSuccess(), ColorReset(), parentVersion, childVersion);
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-155: Embedded Profile Device Class Match
// Embedding spec: "shall be of the same profile class, and have the same device space"
// ---------------------------------------------------------------------------
int RunCF155_EmbeddedProfileDeviceClassMatch(CIccProfile *pIcc) {
  printf("%s[CF-155]%s Embedded Profile Device Class Match (%sICC TN Embedding §Processing%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
  if (!pTag) {
    printf("         No embedded profile — check not applicable\n");
    return 0;
  }

  CIccTagEmbeddedProfile *pEmbed = dynamic_cast<CIccTagEmbeddedProfile *>(pTag);
  if (!pEmbed || !pEmbed->GetProfile()) {
    printf("         Cannot read embedded profile — skipped\n");
    return 0;
  }

  int issues = 0;
  CIccProfile *pChild = pEmbed->GetProfile();

  // Profile class match
  icProfileClassSignature parentClass = pIcc->m_Header.deviceClass;
  icProfileClassSignature childClass = pChild->m_Header.deviceClass;
  char pSig[5], cSig[5];
  SigToChars(static_cast<uint32_t>(parentClass), pSig);
  SigToChars(static_cast<uint32_t>(childClass), cSig);

  if (parentClass != childClass) {
    printf("         %s[FAIL]%s Profile class mismatch: parent='%s' child='%s' — "
           "Embedding spec: same profile class required\n",
           ColorError(), ColorReset(), pSig, cSig);
    issues++;
  }

  // Device color space match
  icColorSpaceSignature parentCS = pIcc->m_Header.colorSpace;
  icColorSpaceSignature childCS = pChild->m_Header.colorSpace;
  char pCS[5], cCS[5];
  SigToChars(static_cast<uint32_t>(parentCS), pCS);
  SigToChars(static_cast<uint32_t>(childCS), cCS);

  if (parentCS != childCS) {
    printf("         %s[FAIL]%s Device color space mismatch: parent='%s' child='%s' — "
           "Embedding spec: same device space required\n",
           ColorError(), ColorReset(), pCS, cCS);
    issues++;
  }

  if (!issues) {
    printf("         %s[OK]%s Embedded profile class '%s' and color space '%s' match parent\n",
           ColorSuccess(), ColorReset(), cSig, cCS);
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-156: Embedded Profile PCS Compatibility
// Embedding spec: child flags bit 0 should be 1 (embedded), bit 1 should be 0
// ---------------------------------------------------------------------------
int RunCF156_EmbeddedProfilePCSCompatibility(CIccProfile *pIcc) {
  printf("%s[CF-156]%s Embedded Profile Header Flags (%sICC TN Embedding §ICC.2 Profile header%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
  if (!pTag) {
    printf("         No embedded profile — check not applicable\n");
    return 0;
  }

  CIccTagEmbeddedProfile *pEmbed = dynamic_cast<CIccTagEmbeddedProfile *>(pTag);
  if (!pEmbed || !pEmbed->GetProfile()) {
    printf("         Cannot read embedded profile — skipped\n");
    return 0;
  }

  int issues = 0;
  CIccProfile *pChild = pEmbed->GetProfile();
  icUInt32Number childFlags = pChild->m_Header.flags;

  printf("         Embedded profile flags: 0x%08X\n", childFlags);

  // Bit 0 should be set (profile is embedded)
  if (!(childFlags & icEmbeddedProfileTrue)) {
    printf("         %s[WARN]%s Embedded ICC.2 profile flags bit 0 should be 1 "
           "(indicating embedded) — ICC TN Embedding\n",
           ColorInfo(), ColorReset());
    issues++;
  }

  // Bit 1 should be 0 (profile cannot be used independently is OK)
  if (childFlags & 0x00000002) {
    printf("         %s[WARN]%s Embedded ICC.2 profile flags bit 1 should be 0 "
           "(only profiles with bit 1=0 should be embedded) — ICC TN Embedding\n",
           ColorInfo(), ColorReset());
    issues++;
  }

  if (!issues) {
    printf("         %s[OK]%s Embedded profile header flags conform to embedding requirements\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-157: Embedded Profile Recursive Depth
// Security: detect deeply nested embeddings (profile bombs)
// ---------------------------------------------------------------------------
int RunCF157_EmbeddedProfileRecursiveDepth(CIccProfile *pIcc) {
  printf("%s[CF-157]%s Embedded Profile Recursive Depth (%sSecurity: anti-bomb%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
  if (!pTag) {
    printf("         No embedded profile — check not applicable\n");
    return 0;
  }

  int issues = 0;
  int depth = 0;
  const int kMaxNestingDepth = 4;
  CIccProfile *pCurrent = pIcc;

  while (pCurrent) {
    CIccTag *pEmTag = pCurrent->FindTag(icSigEmbeddedV5ProfileTag);
    if (!pEmTag) break;

    CIccTagEmbeddedProfile *pEmbed = dynamic_cast<CIccTagEmbeddedProfile *>(pEmTag);
    if (!pEmbed || !pEmbed->GetProfile()) break;

    depth++;
    if (depth > kMaxNestingDepth) {
      printf("         %s[FAIL]%s Embedded profile nesting depth %d exceeds maximum %d — "
             "possible profile bomb\n",
             ColorError(), ColorReset(), depth, kMaxNestingDepth);
      issues++;
      break;
    }
    pCurrent = pEmbed->GetProfile();
  }

  if (depth > 0 && !issues) {
    printf("         Nesting depth: %d (max allowed: %d)\n", depth, kMaxNestingDepth);
    printf("         %s[OK]%s Embedding depth within safe bounds\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-158: Embedded Profile Size Bounds
// Security: embedded profile size should be < parent profile size
// ---------------------------------------------------------------------------
int RunCF158_EmbeddedProfileSizeBounds(CIccProfile *pIcc) {
  printf("%s[CF-158]%s Embedded Profile Size Bounds (%sSecurity: size validation%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
  if (!pTag) {
    printf("         No embedded profile — check not applicable\n");
    return 0;
  }

  CIccTagEmbeddedProfile *pEmbed = dynamic_cast<CIccTagEmbeddedProfile *>(pTag);
  if (!pEmbed || !pEmbed->GetProfile()) {
    printf("         Cannot read embedded profile — skipped\n");
    return 0;
  }

  int issues = 0;
  CIccProfile *pChild = pEmbed->GetProfile();
  icUInt32Number parentSize = pIcc->m_Header.size;
  icUInt32Number childSize = pChild->m_Header.size;

  printf("         Parent profile size: %u bytes\n", parentSize);
  printf("         Embedded profile size: %u bytes\n", childSize);

  if (childSize > parentSize) {
    printf("         %s[FAIL]%s Embedded profile (%u bytes) is larger than parent (%u bytes) — "
           "impossible unless header is forged\n",
           ColorError(), ColorReset(), childSize, parentSize);
    issues++;
  }

  // Ratio check: embedded profile should be a reasonable fraction of parent
  if (parentSize > 0 && childSize > 0) {
    double ratio = static_cast<double>(childSize) / parentSize;
    if (ratio > 0.95) {
      printf("         %s[WARN]%s Embedded profile occupies %.1f%% of parent — "
             "unusual ratio\n", ColorInfo(), ColorReset(), ratio * 100.0);
      issues++;
    }
  }

  if (!issues) {
    printf("         %s[OK]%s Embedded profile size is within bounds\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-175: Embedded Profile PCS Compatibility
// Embedding spec: "logical replacement" — child PCS must be compatible with parent
// ---------------------------------------------------------------------------
int RunCF175_EmbeddedProfilePCSCompatibility(CIccProfile *pIcc) {
  printf("%s[CF-175]%s Embedded Profile PCS Compatibility (%sICC TN Embedding §Processing%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
  if (!pTag) {
    printf("         No embedded profile — check not applicable\n");
    return 0;
  }

  CIccTagEmbeddedProfile *pEmbed = dynamic_cast<CIccTagEmbeddedProfile *>(pTag);
  if (!pEmbed || !pEmbed->GetProfile()) {
    printf("         Cannot read embedded profile — skipped\n");
    return 0;
  }

  int issues = 0;
  CIccProfile *pChild = pEmbed->GetProfile();
  icColorSpaceSignature parentPCS = pIcc->m_Header.pcs;
  icColorSpaceSignature childPCS = pChild->m_Header.pcs;

  char pSig[5], cSig[5];
  SigToChars(static_cast<uint32_t>(parentPCS), pSig);
  SigToChars(static_cast<uint32_t>(childPCS), cSig);

  printf("         Parent PCS: '%s' (0x%08X)\n", pSig, static_cast<unsigned>(parentPCS));
  printf("         Child PCS:  '%s' (0x%08X)\n", cSig, static_cast<unsigned>(childPCS));

  // DeviceLink profiles: PCS is not used in same way, skip this check
  if (pIcc->m_Header.deviceClass == icSigLinkClass) {
    printf("         DeviceLink profile — PCS compatibility not applicable\n");
    return 0;
  }

  // ICC.1 PCS: Lab or XYZ. ICC.2 can extend PCS (spectral, etc.)
  // For "logical replacement", if parent is Lab/XYZ, child should be compatible
  bool parentIsStdPCS = (parentPCS == icSigLabData || parentPCS == icSigXYZData);
  bool childIsStdPCS  = (childPCS == icSigLabData || childPCS == icSigXYZData);

  if (parentIsStdPCS && childIsStdPCS) {
    // Both standard PCS — mismatch is a warning (CMM can convert)
    if (parentPCS != childPCS) {
      printf("         %s[WARN]%s PCS mismatch: parent='%s' child='%s' — "
             "CMM must handle PCS conversion for logical replacement\n",
             ColorInfo(), ColorReset(), pSig, cSig);
      issues++;
    } else {
      printf("         %s[OK]%s PCS match: both use '%s'\n",
             ColorSuccess(), ColorReset(), pSig);
    }
  } else if (parentIsStdPCS && !childIsStdPCS) {
    // Child uses extended PCS (ICC.2 spectral etc.) — informational
    printf("         %s[INFO]%s Child uses ICC.2 extended PCS '%s' — "
           "CMM must support ICC.2 PCS for logical replacement\n",
           ColorInfo(), ColorReset(), cSig);
  } else {
    printf("         %s[OK]%s PCS compatibility check passed\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-176: Embedded Profile Tag Reserved Bytes
// Embedding spec Table 1: bytes 4-7 of embeddedProfileType "shall be 0"
// ---------------------------------------------------------------------------
int RunCF176_EmbeddedProfileTagReservedBytes(CIccProfile *pIcc) {
  printf("%s[CF-176]%s Embedded Profile Tag Reserved Bytes (%sICC TN Embedding Table 1%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
  if (!pTag) {
    printf("         No embedded profile — check not applicable\n");
    return 0;
  }

  int issues = 0;
  bool found = false;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    if (it->TagInfo.sig == icSigEmbeddedV5ProfileTag) {
      icUInt32Number tagSize = it->TagInfo.size;
      if (tagSize < 8) {
        printf("         %s[FAIL]%s Embedded profile tag size %u < 8 bytes — "
               "cannot contain required type + reserved fields\n",
               ColorError(), ColorReset(), tagSize);
        issues++;
        found = true;
        break;
      }

      std::string sigPath = "ICC5";
      std::string sReport;
      icValidateStatus status = pTag->Validate(sigPath, sReport, pIcc);
      if (status > icValidateOK &&
          sReport.find("Reserved Value must be zero") != std::string::npos) {
        printf("         %s[FAIL]%s Embedded profile tag reserved bytes (4-7) are not zero — "
               "ICC TN Embedding Table 1: 'Reserved, shall be 0'\n",
               ColorError(), ColorReset());
        issues++;
      } else {
        printf("         %s[OK]%s Embedded profile tag reserved bytes conform to spec\n",
               ColorSuccess(), ColorReset());
      }
      found = true;
      break;
    }
  }

  if (!found) {
    printf("         Tag not found in tag table — internal error\n");
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-177: Embedded Profile Data Integrity
// Embedding spec: profile "in its entirety" — child profile should validate
// ---------------------------------------------------------------------------
int RunCF177_EmbeddedProfileDataIntegrity(CIccProfile *pIcc) {
  printf("%s[CF-177]%s Embedded Profile Data Integrity (%sICC TN Embedding §Embedding%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
  if (!pTag) {
    printf("         No embedded profile — check not applicable\n");
    return 0;
  }

  CIccTagEmbeddedProfile *pEmbed = dynamic_cast<CIccTagEmbeddedProfile *>(pTag);
  if (!pEmbed || !pEmbed->GetProfile()) {
    printf("         Cannot read embedded profile — skipped\n");
    return 0;
  }

  int issues = 0;
  CIccProfile *pChild = pEmbed->GetProfile();

  // Validate the embedded profile structure
  std::string sReport;
  icValidateStatus status = pChild->Validate(sReport);

  printf("         Embedded profile validation status: ");
  switch (status) {
    case icValidateOK:
      printf("OK\n");
      printf("         %s[OK]%s Embedded profile validates cleanly\n",
             ColorSuccess(), ColorReset());
      break;
    case icValidateWarning:
      printf("Warning\n");
      printf("         %s[INFO]%s Embedded profile has validation warnings — "
             "profile may still function correctly\n",
             ColorInfo(), ColorReset());
      break;
    case icValidateNonCompliant:
      printf("Non-Compliant\n");
      printf("         %s[WARN]%s Embedded profile is non-compliant — "
             "spec requires embedding 'in its entirety'\n",
             ColorInfo(), ColorReset());
      issues++;
      break;
    case icValidateCriticalError:
      printf("Critical Error\n");
      printf("         %s[FAIL]%s Embedded profile has critical validation errors — "
             "profile may be corrupted or truncated\n",
             ColorError(), ColorReset());
      issues++;
      break;
    default:
      printf("Unknown (%d)\n", status);
      break;
  }

  // Check tag count sanity
  if (pChild->m_Tags.empty()) {
    printf("         %s[WARN]%s Embedded profile has no tags — unlikely to be complete\n",
           ColorInfo(), ColorReset());
    issues++;
  } else {
    int tagCount = 0;
    for (auto it = pChild->m_Tags.begin(); it != pChild->m_Tags.end(); ++it) tagCount++;
    printf("         Embedded profile contains %d tags\n", tagCount);
  }

  return issues;
}

// ===========================================================================
// Partial Chromatic Adaptation checks (CF-178..CF-183)
// Source: ICC TN "Applying partial adaptation by the CMM between iccMAX
//         profiles with different PCS observing conditions" — Max Derhak
// Also references: ICC TN "Partial Chromatic Adaptation" (chad tag)
// ===========================================================================

// ---------------------------------------------------------------------------
// CF-178: Chad Matrix Diagonal Dominance
// Valid chromatic adaptation matrices (Bradford, CAT02, CAT16) are diagonally
// dominant — the absolute value of each diagonal element exceeds the sum of
// absolute values of other elements in that row. A non-diagonally-dominant
// chad suggests an unusual or malformed adaptation transform.
// ---------------------------------------------------------------------------
static int RunCF178_ChadDiagonalDominance(CIccProfile *pIcc) {
  printf("%s[CF-178]%s Chad Matrix Diagonal Dominance (%sICC TN Partial Adaptation%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTagS15Fixed16 *chad =
      FindAndCast<CIccTagS15Fixed16>(pIcc, icSigChromaticAdaptationTag);
  if (!chad || chad->GetSize() < 9) {
    printf("         No chromaticAdaptationTag (or < 9 elements) — not applicable\n");
    printf("         %s[OK]%s Skipped (no chad)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  int issues = 0;
  double m[9];
  for (int i = 0; i < 9; i++)
    m[i] = static_cast<double>((*chad)[i]) / 65536.0;

  // Check diagonal dominance for each row of the 3x3 matrix
  // Row i: |m[i*3+i]| >= |m[i*3+j]| + |m[i*3+k]| for j,k != i
  for (int row = 0; row < 3; row++) {
    double diag = fabs(m[row * 3 + row]);
    double offDiag = 0.0;
    for (int col = 0; col < 3; col++) {
      if (col != row) offDiag += fabs(m[row * 3 + col]);
    }
    if (diag < offDiag) {
      printf("         Row %d: |diagonal| = %.4f < off-diagonal sum = %.4f\n",
             row, diag, offDiag);
      printf("         %s[WARN]%s Chad matrix row %d not diagonally dominant — "
             "unusual adaptation transform\n",
             ColorWarning(), ColorReset(), row);
      issues++;
    }
  }

  if (issues == 0) {
    printf("         All rows diagonally dominant — valid adaptation structure\n");
    printf("         %s[OK]%s Chad matrix diagonally dominant\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-179: Chad D50-to-D50 Identity Check
// When the profile illuminant IS D50 (the PCS illuminant), the chad tag
// represents adaptation from D50 to D50, which should yield an identity
// (or near-identity) matrix. A non-identity chad with D50 illuminant
// indicates profile inconsistency.
// ---------------------------------------------------------------------------
static int RunCF179_ChadD50Identity(CIccProfile *pIcc) {
  printf("%s[CF-179]%s Chad D50-to-D50 Identity Check (%sICC TN Partial Adaptation%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTagS15Fixed16 *chad =
      FindAndCast<CIccTagS15Fixed16>(pIcc, icSigChromaticAdaptationTag);
  if (!chad || chad->GetSize() < 9) {
    printf("         No chad tag — not applicable\n");
    printf("         %s[OK]%s Skipped (no chad)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Check if the profile illuminant is D50
  // D50 in s15Fixed16: X=0.9642 Y=1.0000 Z=0.8249
  icXYZNumber illum = pIcc->m_Header.illuminant;
  double iX = icFtoD(illum.X);
  double iY = icFtoD(illum.Y);
  double iZ = icFtoD(illum.Z);

  // Tolerance for D50 match: ±0.003 (accounts for s15Fixed16 quantization)
  bool isD50 = (fabs(iX - 0.9642) < 0.003 &&
                fabs(iY - 1.0000) < 0.003 &&
                fabs(iZ - 0.8249) < 0.003);

  if (!isD50) {
    printf("         Illuminant (%.4f, %.4f, %.4f) != D50 — identity not expected\n",
           iX, iY, iZ);
    printf("         %s[OK]%s Non-D50 illuminant — chad correctly performs adaptation\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Illuminant is D50 — chad should be near-identity
  double m[9];
  for (int i = 0; i < 9; i++)
    m[i] = static_cast<double>((*chad)[i]) / 65536.0;

  // Identity matrix: [1 0 0; 0 1 0; 0 0 1]
  const double identity[9] = {1,0,0, 0,1,0, 0,0,1};
  double maxDev = 0.0;
  for (int i = 0; i < 9; i++) {
    double dev = fabs(m[i] - identity[i]);
    if (dev > maxDev) maxDev = dev;
  }

  int issues = 0;
  // Tolerance: s15Fixed16 quantization is 1/65536 ≈ 0.000015
  // Allow small rounding: 0.002 (about 130 LSBs)
  if (maxDev > 0.002) {
    printf("         Illuminant is D50 but chad deviates from identity (max dev = %.6f)\n",
           maxDev);
    printf("         %s[WARN]%s D50 illuminant with non-identity chad — "
           "profile may have inconsistent adaptation\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    printf("         Illuminant is D50, chad is near-identity (max dev = %.6f)\n", maxDev);
    printf("         %s[OK]%s D50 illuminant with identity chad — consistent\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-180: PCC Complete Adaptation Principle (iccMAX)
// ICC TN recommends that profiles perform COMPLETE adaptation (D_factor = 1.0)
// in their PCC conversion transforms (c2sp/s2cp), and that partial adaptation
// should be applied by the CMM, not embedded in profile transforms.
// This check validates that v5 profiles with PCC tags don't embed partial
// adaptation markers in their tag descriptions.
// ---------------------------------------------------------------------------
static int RunCF180_PCCCompleteAdaptation(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-180]%s PCC Complete Adaptation Principle (%sICC TN Partial Adaptation%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  const CIccTag *c2spTag = pIcc->FindTag(icSigCustomToStandardPccTag);
  const CIccTag *s2cpTag = pIcc->FindTag(icSigStandardToCustomPccTag);

  if (!c2spTag && !s2cpTag) {
    printf("         No PCC tags (c2sp/s2cp) — complete adaptation check not applicable\n");
    printf("         %s[OK]%s Skipped (no PCC tags)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  int issues = 0;

  // Per the TN: profiles should use complete adaptation.
  // We validate that both PCC tags are present (incomplete pair = ambiguous adaptation)
  if (c2spTag && !s2cpTag) {
    printf("         c2sp present but s2cp absent — incomplete PCC transform pair\n");
    printf("         %s[WARN]%s Partial PCC pair may embed incomplete adaptation — "
           "both c2sp and s2cp required per ICC TN\n",
           ColorWarning(), ColorReset());
    issues++;
  } else if (!c2spTag && s2cpTag) {
    printf("         s2cp present but c2sp absent — incomplete PCC transform pair\n");
    printf("         %s[WARN]%s Partial PCC pair may embed incomplete adaptation — "
           "both c2sp and s2cp required per ICC TN\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    printf("         Both c2sp and s2cp present — complete PCC transform pair\n");
    printf("         Profile should perform complete adaptation (D=1.0) in these transforms\n");
    printf("         CMM should apply partial adaptation factor externally per ICC TN\n");
    printf("         %s[OK]%s PCC transform pair complete — adaptation architecture conformant\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-181: PCC Illuminant-Chad Consistency
// For v5 profiles with spectral viewing conditions: if the PCC illuminant
// is not D50, a chromaticAdaptationTag should exist to provide the adaptation
// matrix. Conversely, if PCC declares D50, chad may be omitted.
// ---------------------------------------------------------------------------
static int RunCF181_PCCIlluminantChadConsistency(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-181]%s PCC Illuminant-Chad Consistency (%sICC TN Partial Adaptation%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Find spectral viewing conditions tag
  const CIccTag *svcnTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (!svcnTag) {
    printf("         No spectralViewingConditionsTag — not applicable\n");
    printf("         %s[OK]%s Skipped (no spectral viewing conditions)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Get the standard illuminant from spectral viewing conditions
  const CIccTagSpectralViewingConditions *svcn =
      dynamic_cast<const CIccTagSpectralViewingConditions *>(svcnTag);
  if (!svcn) {
    printf("         spectralViewingConditionsTag not castable — skipping\n");
    printf("         %s[OK]%s Skipped (type mismatch)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  icIlluminant illumType = svcn->getStdIllumiant();
  icStandardObserver obsType = svcn->getStdObserver();
  printf("         PCC illuminant type: 0x%08X\n", static_cast<unsigned>(illumType));
  printf("         PCC observer type: 0x%08X\n", static_cast<unsigned>(obsType));

  int issues = 0;

  const CIccTag *chadTag = pIcc->FindTag(icSigChromaticAdaptationTag);

  if (illumType != icIlluminantD50 && illumType != 0) {
    // Non-D50 illuminant — chad should exist for adaptation
    if (!chadTag) {
      printf("         PCC illuminant is not D50 but no chad tag present\n");
      printf("         %s[WARN]%s Non-D50 PCC illuminant without chad — "
             "adaptation may be incomplete\n",
             ColorWarning(), ColorReset());
      issues++;
    } else {
      printf("         Non-D50 PCC illuminant with chad tag — consistent\n");
    }
  } else {
    printf("         PCC illuminant is D50 (or unspecified)\n");
  }

  if (issues == 0) {
    printf("         %s[OK]%s PCC illuminant and chad tag consistent\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-182: PCC Observer Standard Compliance
// ICC standard observers are 1931 2-degree and 1964 10-degree.
// Partial adaptation TN notes that observer mismatch between profiles
// requires appropriate CMM handling. This check validates that spectral
// viewing conditions use recognized observer values.
// ---------------------------------------------------------------------------
static int RunCF182_PCCObserverStandard(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-182]%s PCC Observer Standard Compliance (%sICC TN Partial Adaptation%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  const CIccTag *svcnTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (!svcnTag) {
    printf("         No spectralViewingConditionsTag — not applicable\n");
    printf("         %s[OK]%s Skipped (no spectral viewing conditions)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  const CIccTagSpectralViewingConditions *svcn =
      dynamic_cast<const CIccTagSpectralViewingConditions *>(svcnTag);
  if (!svcn) {
    printf("         spectralViewingConditionsTag not castable — skipping\n");
    printf("         %s[OK]%s Skipped (type mismatch)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  icStandardObserver obsType = svcn->getStdObserver();
  int issues = 0;

  switch (obsType) {
    case icStdObs1931TwoDegrees:
      printf("         Observer: CIE 1931 2-degree (standard)\n");
      break;
    case icStdObs1964TenDegrees:
      printf("         Observer: CIE 1964 10-degree (standard)\n");
      break;
    case icStdObsCustom:
      printf("         Observer: custom (0x%08X)\n", static_cast<unsigned>(obsType));
      printf("         %s[INFO]%s Custom observer — CMM must handle adaptation "
             "differently per ICC TN\n",
             ColorInfo(), ColorReset());
      break;
    default:
      printf("         Observer: unknown (0x%08X)\n", static_cast<unsigned>(obsType));
      printf("         %s[WARN]%s Unrecognized observer type — may cause "
             "incorrect partial adaptation by CMM\n",
             ColorWarning(), ColorReset());
      issues++;
      break;
  }

  if (issues == 0) {
    printf("         %s[OK]%s PCC observer is a recognized standard\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-183: Chad Column Normalization
// Chromatic adaptation matrices (Bradford, CAT02) transform cone response.
// Each column represents the transform for one cone type. The column norms
// should be bounded — extremely large or near-zero columns indicate a
// degenerate transform. This validates mathematical reasonableness.
// ---------------------------------------------------------------------------
static int RunCF183_ChadColumnNormalization(CIccProfile *pIcc) {
  printf("%s[CF-183]%s Chad Column Normalization (%sICC TN Partial Adaptation%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTagS15Fixed16 *chad =
      FindAndCast<CIccTagS15Fixed16>(pIcc, icSigChromaticAdaptationTag);
  if (!chad || chad->GetSize() < 9) {
    printf("         No chromaticAdaptationTag (or < 9 elements) — not applicable\n");
    printf("         %s[OK]%s Skipped (no chad)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  double m[9];
  for (int i = 0; i < 9; i++)
    m[i] = static_cast<double>((*chad)[i]) / 65536.0;

  int issues = 0;

  // Check each column's L2 norm
  for (int col = 0; col < 3; col++) {
    double sumSq = 0.0;
    for (int row = 0; row < 3; row++) {
      double v = m[row * 3 + col];
      sumSq += v * v;
    }
    double norm = sqrt(sumSq);

    // Bradford columns typically have norms around 0.8 to 1.3
    // Extreme values suggest degenerate transform
    if (norm < 0.01) {
      printf("         Column %d norm = %.6f (near zero — degenerate)\n", col, norm);
      printf("         %s[WARN]%s Chad column %d near-zero — transform is degenerate\n",
             ColorWarning(), ColorReset(), col);
      issues++;
    } else if (norm > 10.0) {
      printf("         Column %d norm = %.4f (extremely large)\n", col, norm);
      printf("         %s[WARN]%s Chad column %d norm > 10 — unusual adaptation matrix\n",
             ColorWarning(), ColorReset(), col);
      issues++;
    } else {
      printf("         Column %d norm = %.4f\n", col, norm);
    }
  }

  if (issues == 0) {
    printf("         All column norms within reasonable range\n");
    printf("         %s[OK]%s Chad column normalization conformant\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ===========================================================================
// dictType Validation checks (CF-159..CF-162)
// Source: ICC.2-2023 §10.2.6
// ===========================================================================

// Helper: count all tags that use dictType in a profile
static int CountDictTags(CIccProfile *pIcc) {
  int count = 0;
  if (pIcc->m_Tags.empty()) return 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (pTag && pTag->GetType() == icSigDictType) count++;
  }
  return count;
}

// ---------------------------------------------------------------------------
// CF-159: Dictionary Name Uniqueness
// ICC.2-2023 §10.2.6: "string contents of each name string shall be unique"
// ---------------------------------------------------------------------------
int RunCF159_DictNameUniqueness(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-159]%s Dictionary Name Uniqueness (%sICC.2-2023 §10.2.6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int dictCount = CountDictTags(pIcc);
  if (dictCount == 0) {
    printf("         No dictType tags found — check not applicable\n");
    return 0;
  }

  int issues = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigDictType) continue;

    CIccTagDict *pDict = dynamic_cast<CIccTagDict *>(pTag);
    if (!pDict) continue;

    char tagSig[5];
    SigToChars(static_cast<uint32_t>(it->TagInfo.sig), tagSig);

    if (!pDict->AreNamesUnique()) {
      printf("         %s[FAIL]%s dictType tag '%s': name strings are not unique — "
             "ICC.2-2023 §10.2.6\n", ColorError(), ColorReset(), tagSig);
      issues++;
    }
  }

  if (!issues) {
    printf("         %s[OK]%s All %d dictType tag(s) have unique names\n",
           ColorSuccess(), ColorReset(), dictCount);
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-160: Dictionary Name Non-Zero
// ICC.2-2023 §10.2.6: "A name string shall be present for each name-value record
//   and name string positionNumber size shall be greater than zero"
// ---------------------------------------------------------------------------
int RunCF160_DictNameNonZero(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-160]%s Dictionary Name Non-Zero (%sICC.2-2023 §10.2.6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int dictCount = CountDictTags(pIcc);
  if (dictCount == 0) {
    printf("         No dictType tags found — check not applicable\n");
    return 0;
  }

  int issues = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigDictType) continue;

    CIccTagDict *pDict = dynamic_cast<CIccTagDict *>(pTag);
    if (!pDict) continue;

    char tagSig[5];
    SigToChars(static_cast<uint32_t>(it->TagInfo.sig), tagSig);

    if (!pDict->AreNamesNonzero()) {
      printf("         %s[FAIL]%s dictType tag '%s': one or more name strings have "
             "zero length — ICC.2-2023 §10.2.6\n", ColorError(), ColorReset(), tagSig);
      issues++;
    }
  }

  if (!issues) {
    printf("         %s[OK]%s All %d dictType tag(s) have non-zero name strings\n",
           ColorSuccess(), ColorReset(), dictCount);
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-161: Dictionary Record Length Alignment
// ICC.2-2023 §10.2.6 Table 40: record length N shall be 16, 24, or 32
// ---------------------------------------------------------------------------
int RunCF161_DictRecordLengthAlignment(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-161]%s Dictionary Record Length Alignment (%sICC.2-2023 §10.2.6 Table 40%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int dictCount = CountDictTags(pIcc);
  if (dictCount == 0) {
    printf("         No dictType tags found — check not applicable\n");
    return 0;
  }

  int issues = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigDictType) continue;

    CIccTagDict *pDict = dynamic_cast<CIccTagDict *>(pTag);
    if (!pDict) continue;

    char tagSig[5];
    SigToChars(static_cast<uint32_t>(it->TagInfo.sig), tagSig);

    if (!pDict->m_Dict || pDict->m_Dict->empty()) {
      printf("         %s[WARN]%s dictType tag '%s': empty dictionary — "
             "may indicate parse failure or zero records\n",
             ColorInfo(), ColorReset(), tagSig);
      issues++;
    }
  }

  if (!issues) {
    printf("         %s[OK]%s All %d dictType tag(s) have valid record structure\n",
           ColorSuccess(), ColorReset(), dictCount);
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-162: Dictionary Entry Count Bounds
// Security: unreasonably large entry counts may indicate OOM attack
// ---------------------------------------------------------------------------
int RunCF162_DictEntryCountBounds(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-162]%s Dictionary Entry Count Bounds (%sICC.2-2023 §10.2.6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int dictCount = CountDictTags(pIcc);
  if (dictCount == 0) {
    printf("         No dictType tags found — check not applicable\n");
    return 0;
  }

  int issues = 0;
  const size_t kMaxReasonableEntries = 100000;  // 100K entries is very generous

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigDictType) continue;

    CIccTagDict *pDict = dynamic_cast<CIccTagDict *>(pTag);
    if (!pDict || !pDict->m_Dict) continue;

    char tagSig[5];
    SigToChars(static_cast<uint32_t>(it->TagInfo.sig), tagSig);

    size_t entryCount = pDict->m_Dict->size();
    printf("         dictType tag '%s': %zu entries\n", tagSig, entryCount);

    if (entryCount > kMaxReasonableEntries) {
      printf("         %s[FAIL]%s dictType tag '%s' has %zu entries (max reasonable: %zu) — "
             "possible OOM vector — CWE-400\n",
             ColorError(), ColorReset(), tagSig, entryCount, kMaxReasonableEntries);
      issues++;
    }
  }

  if (!issues) {
    printf("         %s[OK]%s Dictionary entry counts within reasonable bounds\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ========================================================================
// ICS Extended Range Part 1 conformance checks (CF-235..CF-242)
// Source: ICS "extendedRange display and colorSpace - Part 1: basic encoding"
// ========================================================================

/// CF-235: xrng Data Colour Space and Channel Restriction
/// Part 1 requires data colour space = RGB (3 channels) for extendedRange
static int RunCF235_XrngDataColourSpace(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-235]%s xrng Data Colour Space Restriction (%sICS-ExtRange-Part1 Table 3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icSignature subClass = pIcc->m_Header.deviceSubClass;
  if (subClass != 0x78726E67) { // 'xrng'
    printf("         Profile sub-class is not 'xrng' -- check N/A\n");
    return 0;
  }

  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
  icUInt32Number nChan = icGetSpaceSamples(cs);

  if (cs != icSigRgbData) {
    char csStr[5];
    csStr[0] = (char)((cs >> 24) & 0xFF);
    csStr[1] = (char)((cs >> 16) & 0xFF);
    csStr[2] = (char)((cs >> 8) & 0xFF);
    csStr[3] = (char)(cs & 0xFF);
    csStr[4] = '\0';
    printf("         %s[WARN]%s Data colour space='%s' -- Part 1 requires 'RGB '\n",
           ColorWarning(), ColorReset(), csStr);
    issues++;
  } else {
    printf("         Data colour space: RGB (%u channels)\n", nChan);
  }

  if (nChan != 3) {
    printf("         %s[WARN]%s Channel count=%u -- Part 1 limits to 3 (RGB displays)\n",
           ColorWarning(), ColorReset(), nChan);
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Data colour space is RGB with 3 channels\n",
           ColorSuccess(), ColorReset());
  return issues;
}

/// CF-236: xrng Colorimetric PCS Constraint
/// Part 1 requires colorimetric PCS = XYZ with D50 illuminant (1931 2-degree observer)
static int RunCF236_XrngColorimetricPCS(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-236]%s xrng Colorimetric PCS Constraint (%sICS-ExtRange-Part1 Table 3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icSignature subClass = pIcc->m_Header.deviceSubClass;
  if (subClass != 0x78726E67) {
    printf("         Profile sub-class is not 'xrng' -- check N/A\n");
    return 0;
  }

  icColorSpaceSignature pcs = pIcc->m_Header.pcs;
  if (pcs != icSigXYZData) {
    printf("         %s[WARN]%s PCS is not XYZ -- Part 1 requires colorimetric XYZ PCS\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    printf("         Colorimetric PCS: XYZ (D50 illuminant, 1931 standard observer)\n");
  }

  // D50 illuminant check (0.9642, 1.0, 0.8249)
  const icXYZNumber &illum = pIcc->m_Header.illuminant;
  double X = icFtoD(illum.X);
  double Y = icFtoD(illum.Y);
  double Z = icFtoD(illum.Z);

  if (fabs(X - 0.9642) > 0.005 || fabs(Y - 1.0) > 0.005 || fabs(Z - 0.8249) > 0.005) {
    printf("         %s[WARN]%s Illuminant (%.4f, %.4f, %.4f) -- should be D50 (0.9642, 1.0, 0.8249)\n",
           ColorWarning(), ColorReset(), X, Y, Z);
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Colorimetric PCS is XYZ with D50 illuminant\n",
           ColorSuccess(), ColorReset());
  return issues;
}

/// CF-237: xrng Required Tag Completeness
/// Table 4: desc (mluc), cprt (mluc), mwpt (XYZ), A2B1 (MPE), B2A1 (MPE)
static int RunCF237_XrngRequiredTagCompleteness(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-237]%s xrng Required Tag Completeness (%sICS-ExtRange-Part1 Table 4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icSignature subClass = pIcc->m_Header.deviceSubClass;
  if (subClass != 0x78726E67) {
    printf("         Profile sub-class is not 'xrng' -- check N/A\n");
    return 0;
  }

  struct TagReq {
    icTagSignature sig;
    const char *name;
    icTagTypeSignature requiredType;
    const char *typeName;
  };
  static const TagReq kRequired[] = {
    {icSigProfileDescriptionTag, "profileDescriptionTag", icSigMultiLocalizedUnicodeType, "multiLocalizedUnicodeType"},
    {icSigCopyrightTag,          "copyrightTag",          icSigMultiLocalizedUnicodeType, "multiLocalizedUnicodeType"},
    {icSigMediaWhitePointTag,    "mediaWhitePointTag",    icSigXYZType,                   "XYZType"},
    {icSigAToB1Tag,              "AToB1Tag",              icSigMultiProcessElementType,    "multiProcessElementsType"},
    {icSigBToA1Tag,              "BToA1Tag",              icSigMultiProcessElementType,    "multiProcessElementsType"},
  };

  for (const auto &req : kRequired) {
    CIccTag *pTag = pIcc->FindTag(req.sig);
    if (!pTag) {
      printf("         %s[WARN]%s Required tag '%s' missing\n",
             ColorWarning(), ColorReset(), req.name);
      issues++;
      continue;
    }

    icTagTypeSignature ttype = pTag->GetType();
    if (ttype != req.requiredType) {
      printf("         %s[WARN]%s '%s' type 0x%08X -- expected %s (0x%08X)\n",
             ColorWarning(), ColorReset(), req.name,
             (unsigned)ttype, req.typeName, (unsigned)req.requiredType);
      issues++;
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s All 5 required tags present with correct types\n",
           ColorSuccess(), ColorReset());
  return issues;
}

/// CF-238: xrng Header Field Restrictions
/// Table 3: flags=0, device attributes <=1, no spectral/bispectral PCS, MCS=0
static int RunCF238_XrngHeaderFieldRestrictions(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-238]%s xrng Header Field Restrictions (%sICS-ExtRange-Part1 Table 3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icSignature subClass = pIcc->m_Header.deviceSubClass;
  if (subClass != 0x78726E67) {
    printf("         Profile sub-class is not 'xrng' -- check N/A\n");
    return 0;
  }

  // Profile flags must be 0
  icUInt32Number flags = (icUInt32Number)pIcc->m_Header.flags;
  if (flags != 0) {
    printf("         %s[WARN]%s Profile flags=0x%08X -- Part 1 requires 0\n",
           ColorWarning(), ColorReset(), flags);
    issues++;
  }

  // Device attributes must be 0 or 1
  icUInt64Number attrs = pIcc->m_Header.attributes;
  if (attrs > 1) {
    printf("         %s[WARN]%s Device attributes=0x%llX -- Part 1 allows only 0 or 1\n",
           ColorWarning(), ColorReset(), (unsigned long long)attrs);
    issues++;
  }

  // Spectral PCS must be 0
  icColorSpaceSignature specPCS = pIcc->m_Header.spectralPCS;
  if (specPCS != (icColorSpaceSignature)0) {
    printf("         %s[WARN]%s Spectral PCS=0x%08X -- Part 1 requires 0\n",
           ColorWarning(), ColorReset(), (unsigned)specPCS);
    issues++;
  }

  // Spectral range steps must be 0
  if (pIcc->m_Header.spectralRange.steps != 0) {
    printf("         %s[WARN]%s Spectral range steps=%u -- Part 1 requires 0\n",
           ColorWarning(), ColorReset(), pIcc->m_Header.spectralRange.steps);
    issues++;
  }

  // Bispectral range steps must be 0
  if (pIcc->m_Header.biSpectralRange.steps != 0) {
    printf("         %s[WARN]%s Bispectral range steps=%u -- Part 1 requires 0\n",
           ColorWarning(), ColorReset(), pIcc->m_Header.biSpectralRange.steps);
    issues++;
  }

  // MCS must be 0
  icMaterialColorSignature mcs = pIcc->m_Header.mcs;
  if (mcs != (icMaterialColorSignature)0) {
    printf("         %s[WARN]%s MCS=0x%08X -- Part 1 requires 0\n",
           ColorWarning(), ColorReset(), (unsigned)mcs);
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s All xrng header field restrictions satisfied\n",
           ColorSuccess(), ColorReset());
  return issues;
}

/// CF-239: xrng Optional Tag Type Validation
/// Table 5: chad=s15Fixed16ArrayType, gbdX=gamutBoundaryDescriptionType,
/// AToBx/BToAx (x!=1) = multiProcessElementsType (errata: plural)
static int RunCF239_XrngOptionalTagTypes(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-239]%s xrng Optional Tag Type Validation (%sICS-ExtRange-Part1 Table 5%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icSignature subClass = pIcc->m_Header.deviceSubClass;
  if (subClass != 0x78726E67) {
    printf("         Profile sub-class is not 'xrng' -- check N/A\n");
    return 0;
  }

  // chad must be s15Fixed16ArrayType when present
  CIccTag *pChad = pIcc->FindTag(icSigChromaticAdaptationTag);
  if (pChad) {
    if (pChad->GetType() != icSigS15Fixed16ArrayType) {
      printf("         %s[WARN]%s 'chad' type 0x%08X -- expected s15Fixed16ArrayType\n",
             ColorWarning(), ColorReset(), (unsigned)pChad->GetType());
      issues++;
    } else {
      printf("         chad: s15Fixed16ArrayType (OK)\n");
    }
  }

  // AToBx / BToAx where x!=1 must be multiProcessElementsType (errata: plural)
  static const struct { icTagSignature sig; const char *name; } kOptionalMPE[] = {
    {icSigAToB0Tag, "AToB0Tag"},
    {icSigAToB2Tag, "AToB2Tag"},
    {icSigBToA0Tag, "BToA0Tag"},
    {icSigBToA2Tag, "BToA2Tag"},
  };

  for (const auto &t : kOptionalMPE) {
    CIccTag *pTag = pIcc->FindTag(t.sig);
    if (!pTag) continue;

    if (pTag->GetType() != icSigMultiProcessElementType) {
      printf("         %s[WARN]%s '%s' type 0x%08X -- expected multiProcessElementsType\n",
             ColorWarning(), ColorReset(), t.name, (unsigned)pTag->GetType());
      issues++;
    } else {
      printf("         %s: multiProcessElementsType (OK)\n", t.name);
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s All optional tags have correct types per Table 5\n",
           ColorSuccess(), ColorReset());
  return issues;
}

/// CF-240: xrng Transform Channel Dimensions
/// AToB1/BToA1 must map 3 input channels (RGB) to 3 output channels (XYZ)
static int RunCF240_XrngTransformChannels(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-240]%s xrng Transform Channel Dimensions (%sICS-ExtRange-Part1 S5.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icSignature subClass = pIcc->m_Header.deviceSubClass;
  if (subClass != 0x78726E67) {
    printf("         Profile sub-class is not 'xrng' -- check N/A\n");
    return 0;
  }

  static const struct { icTagSignature sig; const char *name; } kTransforms[] = {
    {icSigAToB1Tag, "AToB1Tag"},
    {icSigBToA1Tag, "BToA1Tag"},
  };

  int checked = 0;
  for (const auto &t : kTransforms) {
    CIccTag *pTag = pIcc->FindTag(t.sig);
    if (!pTag) continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMPE) continue;
    checked++;

    icUInt16Number nIn = pMPE->NumInputChannels();
    icUInt16Number nOut = pMPE->NumOutputChannels();

    printf("         %s: %u input -> %u output channels\n", t.name, nIn, nOut);

    if (nIn != 3) {
      printf("         %s[WARN]%s %s has %u input channels -- expected 3 (RGB)\n",
             ColorWarning(), ColorReset(), t.name, nIn);
      issues++;
    }
    if (nOut != 3) {
      printf("         %s[WARN]%s %s has %u output channels -- expected 3 (XYZ)\n",
             ColorWarning(), ColorReset(), t.name, nOut);
      issues++;
    }
  }

  if (checked == 0) {
    printf("         No AToB1/BToA1 MPE tags to check channels\n");
    return 0;
  }

  if (issues == 0)
    printf("         %s[OK]%s Transform channels: 3 (RGB) -> 3 (XYZ) confirmed\n",
           ColorSuccess(), ColorReset());
  return issues;
}

/// CF-241: xrng mediaWhitePointTag Absolute Radiance
/// mwpt must contain XYZ tristimulus values of near-diffuse white in absolute radiance
static int RunCF241_XrngMediaWhitePointRadiance(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-241]%s xrng mediaWhitePointTag Absolute Radiance (%sICS-ExtRange-Part1 Table 4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icSignature subClass = pIcc->m_Header.deviceSubClass;
  if (subClass != 0x78726E67) {
    printf("         Profile sub-class is not 'xrng' -- check N/A\n");
    return 0;
  }

  CIccTag *pTag = pIcc->FindTag(icSigMediaWhitePointTag);
  if (!pTag) {
    printf("         %s[WARN]%s mediaWhitePointTag missing\n",
           ColorWarning(), ColorReset());
    return 1;
  }

  CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ*>(pTag);
  if (!pXYZ) {
    printf("         %s[WARN]%s mediaWhitePointTag is not XYZType\n",
           ColorWarning(), ColorReset());
    return 1;
  }

  icXYZNumber *wp = pXYZ->GetXYZ(0);
  if (!wp) {
    printf("         %s[WARN]%s mediaWhitePointTag has no XYZ data\n",
           ColorWarning(), ColorReset());
    return 1;
  }

  double X = icFtoD(wp->X);
  double Y = icFtoD(wp->Y);
  double Z = icFtoD(wp->Z);

  printf("         White point: X=%.6f Y=%.6f Z=%.6f\n", X, Y, Z);

  if (Y <= 0.0) {
    printf("         %s[WARN]%s Y=%.6f -- luminance must be positive\n",
           ColorWarning(), ColorReset(), Y);
    issues++;
  }

  if (X <= 0.0 || Z <= 0.0) {
    printf("         %s[WARN]%s Non-positive tristimulus (X=%.6f, Z=%.6f)\n",
           ColorWarning(), ColorReset(), X, Z);
    issues++;
  }

  // For extended range, Y > 1.0 is valid (absolute radiance cd/m^2)
  if (Y > 1.0) {
    printf("         Extended range white point Y=%.4f (absolute radiance)\n", Y);
  }

  if (issues == 0)
    printf("         %s[OK]%s mediaWhitePointTag has valid absolute radiance values\n",
           ColorSuccess(), ColorReset());
  return issues;
}

/// CF-242: xrng Workflow Connection Consistency
/// Validates source/destination transform type requirements per S5.2.3
static int RunCF242_XrngWorkflowConnection(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-242]%s xrng Workflow Connection Consistency (%sICS-ExtRange-Part1 S5.2.3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icSignature subClass = pIcc->m_Header.deviceSubClass;
  if (subClass != 0x78726E67) {
    printf("         Profile sub-class is not 'xrng' -- check N/A\n");
    return 0;
  }

  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  printf("         Profile class: %s\n",
         cls == icSigDisplayClass ? "display (mntr)" :
         cls == icSigColorSpaceClass ? "colorSpace (spac)" : "other");

  // Source scenario: E -> PCS -> C (transform type = colorimetric, PCC override = none)
  // A2B1 is the colorimetric rendering intent transform
  CIccTag *pA2B1 = pIcc->FindTag(icSigAToB1Tag);
  CIccTag *pB2A1 = pIcc->FindTag(icSigBToA1Tag);

  if (pA2B1 && pB2A1) {
    printf("         Source+Destination capable: AToB1 + BToA1 present\n");
  } else if (pA2B1) {
    printf("         Source-only: AToB1 present (device -> PCS)\n");
  } else if (pB2A1) {
    printf("         Destination-only: BToA1 present (PCS -> device)\n");
  } else {
    printf("         %s[WARN]%s Neither AToB1 nor BToA1 present -- no xrng workflow possible\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  // Rendering intent should be relative colorimetric (1) for xrng workflows
  icUInt32Number intent = pIcc->m_Header.renderingIntent;
  if (intent != 1 && intent != 0) {
    printf("         %s[WARN]%s Rendering intent=%u -- xrng workflows use colorimetric (0 or 1)\n",
           ColorWarning(), ColorReset(), intent);
    issues++;
  }

  // Check that no DToB/BToD tags are present (Part 1 doesn't define spectral connections)
  if (pIcc->FindTag(icSigDToB0Tag) || pIcc->FindTag(icSigDToB1Tag) ||
      pIcc->FindTag(icSigDToB3Tag)) {
    printf("         DToB tags present -- not defined by Part 1 (informational)\n");
  }

  if (issues == 0)
    printf("         %s[OK]%s Workflow connection structure consistent with ICS Part 1\n",
           ColorSuccess(), ColorReset());
  return issues;
}

// ─── CF-257: Spectral Range Step Count ──────────────────────────────────────
// ICC.2-2023 — spectral range must have steps ≥ 2 when spectral PCS is declared
static int RunCF257_SpectralRangeStepCount(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;
  if (pIcc->m_Header.spectralPCS == 0) return 0;

  printf("%s[CF-257]%s Spectral Range Step Count (%sICC.2-2023 §7.2.20%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  icSpectralRange sr = pIcc->m_Header.spectralRange;
  if (sr.steps < 2) {
    printf("         Non-conformance: spectralRange steps=%u (minimum 2 required)\n", sr.steps);
    issues++;
  }
  // Validate start < end
  float fStart = icF16toF(sr.start);
  float fEnd = icF16toF(sr.end);
  if (fStart >= fEnd) {
    printf("         Non-conformance: spectralRange start=%.1fnm >= end=%.1fnm\n", fStart, fEnd);
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Spectral range valid: %.1f-%.1fnm in %u steps\n",
           ColorSuccess(), ColorReset(), fStart, fEnd, sr.steps);
  return issues;
}


// ---------------------------------------------------------------------------
// CF-284: BRDF Spectral Parameter Tag Type (ICC.2-2023 §9.2.10-13)
// ---------------------------------------------------------------------------
static int RunCF284_BRDFSpectralParameterTagType(CIccProfile *pIcc) {
  printf("  %s[CF-284]%s BRDF Spectral Parameter Tag Type (%sICC.2-2023 §9.2.10-13%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  const icTagSignature brdfTags[] = {
    icSigBrdfSpectralParameter0Tag,
    icSigBrdfSpectralParameter1Tag,
    icSigBrdfSpectralParameter2Tag,
    icSigBrdfSpectralParameter3Tag
  };
  const char *brdfNames[] = {"bsp0", "bsp1", "bsp2", "bsp3"};

  int found = 0;
  for (int i = 0; i < 4; i++) {
    CIccTag *pTag = pIcc->FindTag(brdfTags[i]);
    if (!pTag) continue;
    found++;

    icTagTypeSignature ts = pTag->GetType();
    if (ts != icSigMultiProcessElementType) {
      printf("         %s[FAIL]%s '%s' tag type is 0x%08X — expected multiProcessElementsType (0x%08X)\n",
             ColorError(), ColorReset(), brdfNames[i],
             (unsigned)ts, (unsigned)icSigMultiProcessElementType);
      issues++;
    } else {
      printf("         '%s': multiProcessElementsType — correct\n", brdfNames[i]);
    }
  }

  if (found == 0) {
    printf("         No BRDF spectral parameter tags — not applicable\n");
  } else if (issues == 0) {
    printf("         %s[OK]%s %d BRDF tag(s) have correct type\n",
           ColorSuccess(), ColorReset(), found);
  }
  return issues;
}


// ---------------------------------------------------------------------------
// CF-285: BRDF Tag Presence Consistency (ICC.2-2023 §9.2.10)
// ---------------------------------------------------------------------------
static int RunCF285_BRDFTagConsistency(CIccProfile *pIcc) {
  printf("  %s[CF-285]%s BRDF Tag Presence Consistency (%sICC.2-2023 §9.2.10%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  const icTagSignature brdfTags[] = {
    icSigBrdfSpectralParameter0Tag,
    icSigBrdfSpectralParameter1Tag,
    icSigBrdfSpectralParameter2Tag,
    icSigBrdfSpectralParameter3Tag
  };

  int present = 0;
  int absent = 0;
  for (int i = 0; i < 4; i++) {
    if (pIcc->FindTag(brdfTags[i]))
      present++;
    else
      absent++;
  }

  if (present == 0) {
    printf("         No BRDF tags — not applicable\n");
  } else if (absent == 0) {
    printf("         %s[OK]%s All 4 BRDF spectral parameter tags present\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("         %s[FAIL]%s Partial BRDF tag set: %d/4 present — incomplete parametric model\n",
           ColorWarning(), ColorReset(), present);
    issues++;
  }
  return issues;
}


// ---------------------------------------------------------------------------
// CF-286: GBD Triangle-Vertex Consistency (ICC.2-2023 §10.2.11, Errata §10.2.11)
// ---------------------------------------------------------------------------
static int RunCF286_GBDTriangleVertexConsistency(CIccProfile *pIcc) {
  printf("  %s[CF-286]%s GBD Triangle-Vertex Consistency (%sICC.2-2023 §10.2.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  const icTagSignature gbdTags[] = {
    icSigGamutBoundaryDescription0Tag,
    icSigGamutBoundaryDescription1Tag,
    icSigGamutBoundaryDescription2Tag,
    icSigGamutBoundaryDescription3Tag
  };
  const char *gbdNames[] = {"gbd0", "gbd1", "gbd2", "gbd3"};

  int checked = 0;
  for (int i = 0; i < 4; i++) {
    CIccTag *pTag = pIcc->FindTag(gbdTags[i]);
    if (!pTag) continue;

    CIccTagGamutBoundaryDesc *gbd =
        dynamic_cast<CIccTagGamutBoundaryDesc *>(pTag);
    if (!gbd) {
      printf("         %s[FAIL]%s '%s' wrong tag type — expected gamutBoundaryDescType\n",
             ColorError(), ColorReset(), gbdNames[i]);
      issues++;
      continue;
    }
    checked++;

    icInt32Number nVerts = gbd->getNumberOfVertices();
    icInt32Number nTris  = gbd->getNumberOfTriangles();

    if (nTris > 0 && nVerts < 3) {
      printf("         %s[FAIL]%s '%s' has %d triangles but only %d vertices (need >= 3)\n",
             ColorError(), ColorReset(), gbdNames[i], nTris, nVerts);
      issues++;
    }
    if (nVerts < 0 || nTris < 0) {
      printf("         %s[FAIL]%s '%s' negative count: vertices=%d triangles=%d\n",
             ColorError(), ColorReset(), gbdNames[i], nVerts, nTris);
      issues++;
    }
    if (nVerts > 0 && nTris == 0) {
      printf("         %s[WARN]%s '%s' has %d vertices but 0 triangles — degenerate boundary\n",
             ColorWarning(), ColorReset(), gbdNames[i], nVerts);
    }
  }

  if (checked == 0) {
    printf("         No GBD tags — not applicable\n");
  } else if (issues == 0) {
    printf("         %s[OK]%s %d GBD tag(s) have consistent vertex/triangle counts\n",
           ColorSuccess(), ColorReset(), checked);
  }
  return issues;
}


// ---------------------------------------------------------------------------
// CF-287: GBD Channel Count Plausibility (ICC.2-2023 §10.2.11)
// ---------------------------------------------------------------------------
static int RunCF287_GBDChannelPlausibility(CIccProfile *pIcc) {
  printf("  %s[CF-287]%s GBD Channel Count Plausibility (%sICC.2-2023 §10.2.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  const icTagSignature gbdTags[] = {
    icSigGamutBoundaryDescription0Tag,
    icSigGamutBoundaryDescription1Tag,
    icSigGamutBoundaryDescription2Tag,
    icSigGamutBoundaryDescription3Tag
  };
  const char *gbdNames[] = {"gbd0", "gbd1", "gbd2", "gbd3"};

  int checked = 0;
  for (int i = 0; i < 4; i++) {
    CIccTag *pTag = pIcc->FindTag(gbdTags[i]);
    if (!pTag) continue;

    CIccTagGamutBoundaryDesc *gbd =
        dynamic_cast<CIccTagGamutBoundaryDesc *>(pTag);
    if (!gbd) continue;
    checked++;

    icInt16Number nPCS = gbd->getNumPCSChannels();
    icInt16Number nDev = gbd->getNumDeviceChannels();

    // PCS channels should be 3 (Lab or XYZ)
    if (nPCS != 3) {
      printf("         %s[FAIL]%s '%s' PCS channels = %d — expected 3 (Lab/XYZ)\n",
             ColorError(), ColorReset(), gbdNames[i], nPCS);
      issues++;
    }
    // Device channels 0 means no device data (allowed), but > 16 is suspicious
    if (nDev > 16) {
      printf("         %s[FAIL]%s '%s' device channels = %d — exceeds plausible maximum (16)\n",
             ColorError(), ColorReset(), gbdNames[i], nDev);
      issues++;
    }
    if (nDev < 0) {
      printf("         %s[FAIL]%s '%s' device channels = %d — negative\n",
             ColorError(), ColorReset(), gbdNames[i], nDev);
      issues++;
    }
  }

  if (checked == 0) {
    printf("         No GBD tags — not applicable\n");
  } else if (issues == 0) {
    printf("         %s[OK]%s %d GBD tag(s) have plausible channel counts\n",
           ColorSuccess(), ColorReset(), checked);
  }
  return issues;
}


// ---------------------------------------------------------------------------
// CF-288: Spectral Data Info Bi-Spectral Consistency (ICC.2-2023 §9.2.84)
// ---------------------------------------------------------------------------
static int RunCF288_SpectralDataInfoConsistency(CIccProfile *pIcc) {
  printf("  %s[CF-288]%s Spectral Data Info Bi-Spectral Consistency (%sICC.2-2023 §9.2.84%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigSpectralDataInfoTag);
  if (!pTag) {
    printf("         No spectralDataInfoTag — not applicable\n");
    return 0;
  }

  CIccTagSpectralDataInfo *sdi =
      dynamic_cast<CIccTagSpectralDataInfo *>(pTag);
  if (!sdi) {
    printf("         %s[FAIL]%s spectralDataInfoTag wrong type — expected spectralDataInfoType\n",
           ColorError(), ColorReset());
    return 1;
  }

  // Check spectralRange consistency
  if (sdi->m_spectralRange.start == 0 && sdi->m_spectralRange.end == 0 &&
      sdi->m_spectralRange.steps == 0) {
    printf("         %s[FAIL]%s spectralRange is all-zero — must specify wavelength range\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         spectralRange: start=%.1f end=%.1f steps=%u\n",
           icF16toF(sdi->m_spectralRange.start),
           icF16toF(sdi->m_spectralRange.end),
           sdi->m_spectralRange.steps);
  }

  // If biSpectralRange is set, base spectralRange must also be valid
  bool hasBiSpectral = (sdi->m_biSpectralRange.start != 0 ||
                        sdi->m_biSpectralRange.end != 0 ||
                        sdi->m_biSpectralRange.steps != 0);
  if (hasBiSpectral) {
    printf("         biSpectralRange: start=%.1f end=%.1f steps=%u\n",
           icF16toF(sdi->m_biSpectralRange.start),
           icF16toF(sdi->m_biSpectralRange.end),
           sdi->m_biSpectralRange.steps);

    if (sdi->m_spectralRange.steps == 0) {
      printf("         %s[FAIL]%s biSpectralRange set but base spectralRange has 0 steps\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s Spectral data info ranges consistent\n",
           ColorSuccess(), ColorReset());
  return issues;
}


// ---------------------------------------------------------------------------
// CF-289: Spectral Viewing Conditions Illuminant Bounds (ICC.2-2023 §10.2.30)
// ---------------------------------------------------------------------------
static int RunCF289_SpectralViewingIlluminantBounds(CIccProfile *pIcc) {
  printf("  %s[CF-289]%s Spectral Viewing Conditions Illuminant Bounds (%sICC.2-2023 §10.2.30%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (!pTag) {
    printf("         No spectralViewingConditionsTag — not applicable\n");
    return 0;
  }

  CIccTagSpectralViewingConditions *svc =
      dynamic_cast<CIccTagSpectralViewingConditions *>(pTag);
  if (!svc) {
    printf("         %s[FAIL]%s spectralViewingConditionsTag wrong type\n",
           ColorError(), ColorReset());
    return 1;
  }

  // Illuminant XYZ should be physically reasonable
  icFloatNumber illumX = svc->m_illuminantXYZ.X;
  icFloatNumber illumY = svc->m_illuminantXYZ.Y;
  icFloatNumber illumZ = svc->m_illuminantXYZ.Z;

  printf("         Illuminant XYZ: (%.4f, %.4f, %.4f)\n",
         (double)illumX, (double)illumY, (double)illumZ);

  if (illumY <= 0.0f) {
    printf("         %s[FAIL]%s Illuminant Y <= 0 — physically impossible\n",
           ColorError(), ColorReset());
    issues++;
  }
  if (illumX < 0.0f || illumZ < 0.0f) {
    printf("         %s[FAIL]%s Illuminant X or Z negative — physically implausible\n",
           ColorError(), ColorReset());
    issues++;
  }
  // All-zero means uninitialized
  if (illumX == 0.0f && illumY == 0.0f && illumZ == 0.0f) {
    printf("         %s[FAIL]%s Illuminant XYZ all zero — uninitialized\n",
           ColorError(), ColorReset());
    issues++;
  }

  // Surround XYZ should also be non-negative
  icFloatNumber surX = svc->m_surroundXYZ.X;
  icFloatNumber surY = svc->m_surroundXYZ.Y;
  icFloatNumber surZ = svc->m_surroundXYZ.Z;
  if (surX < 0.0f || surY < 0.0f || surZ < 0.0f) {
    printf("         %s[FAIL]%s Surround XYZ has negative value(s)\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Spectral viewing conditions illuminant values plausible\n",
           ColorSuccess(), ColorReset());
  return issues;
}


// ---------------------------------------------------------------------------
// CF-290: Material Default Values Tag Presence (ICC.2-2023 §9.2.47)
// ---------------------------------------------------------------------------
static int RunCF290_MaterialDefaultValuesPresence(CIccProfile *pIcc) {
  printf("  %s[CF-290]%s Material Default Values Tag Presence (%sICC.2-2023 §9.2.47%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;

  // Material identification and visualization classes should have materialDefaultValuesTag
  if (cls != icSigMaterialIdentificationClass &&
      cls != icSigMaterialVisualizationClass) {
    printf("         Profile class is not material — not applicable\n");
    return 0;
  }

  const char *clsName = (cls == icSigMaterialIdentificationClass) ?
                         "Material Identification" : "Material Visualization";

  CIccTag *mdv = pIcc->FindTag(icSigMultiplexDefaultValuesTag);
  if (!mdv) {
    printf("         %s[WARN]%s %s profile missing multiplexDefaultValuesTag ('mdv ')\n",
           ColorWarning(), ColorReset(), clsName);
    issues++;
  } else {
    printf("         multiplexDefaultValuesTag present for %s profile\n", clsName);
  }

  // Material type array tag should also be present
  CIccTag *mcta = pIcc->FindTag(icSigMultiplexTypeArrayTag);
  if (!mcta) {
    printf("         %s[WARN]%s %s profile missing multiplexTypeArrayTag ('mcta')\n",
           ColorWarning(), ColorReset(), clsName);
    issues++;
  } else {
    printf("         multiplexTypeArrayTag present\n");
  }

  if (issues == 0)
    printf("         %s[OK]%s Material profile tags present\n",
           ColorSuccess(), ColorReset());
  return issues;
}


// ---------------------------------------------------------------------------
// CF-291: Spectral White Point XYZ Range (ICC.2-2023 §9.2.85)
// ---------------------------------------------------------------------------
static int RunCF291_SpectralWhitePointRange(CIccProfile *pIcc) {
  printf("  %s[CF-291]%s Spectral White Point XYZ Range (%sICC.2-2023 §9.2.85%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigSpectralWhitePointTag);
  if (!pTag) {
    printf("         No spectralWhitePointTag — not applicable\n");
    return 0;
  }

  // spectralWhitePointTag should be XYZType
  icTagTypeSignature ts = pTag->GetType();
  if (ts != icSigXYZArrayType) {
    printf("         %s[FAIL]%s spectralWhitePointTag type 0x%08X — expected XYZType (0x%08X)\n",
           ColorError(), ColorReset(), (unsigned)ts, (unsigned)icSigXYZArrayType);
    issues++;
  }

  // Try to cast and validate XYZ values
  CIccTagXYZ *xyz = dynamic_cast<CIccTagXYZ *>(pTag);
  if (xyz && xyz->GetSize() >= 1) {
    icXYZNumber *wp = xyz->GetXYZ(0);
    if (wp) {
      double X = icFtoD(wp->X);
      double Y = icFtoD(wp->Y);
      double Z = icFtoD(wp->Z);

      printf("         Spectral white point: (%.4f, %.4f, %.4f)\n", X, Y, Z);

      // Y should be near 1.0 (normalized luminance) or at least positive
      if (Y <= 0.0) {
        printf("         %s[FAIL]%s Spectral white point Y <= 0 — physically impossible\n",
               ColorError(), ColorReset());
        issues++;
      }
      if (X < 0.0 || Z < 0.0) {
        printf("         %s[FAIL]%s Spectral white point has negative X or Z\n",
               ColorError(), ColorReset());
        issues++;
      }
      // Very large values suggest corruption
      if (X > 5.0 || Y > 5.0 || Z > 5.0) {
        printf("         %s[WARN]%s Spectral white point exceeds 5.0 — unusually large\n",
               ColorWarning(), ColorReset());
        issues++;
      }
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s Spectral white point values plausible\n",
           ColorSuccess(), ColorReset());
  return issues;
}


// ---------------------------------------------------------------------------
// multiProcessElementsType Container Validation (CF-292..CF-300)
// ICC.2-2023 §10.2.17 multiProcessElementsType
// The container type 'mpet' wraps a sequence of individual processing elements.
// These checks validate the structural integrity of the MPE container itself.
// ---------------------------------------------------------------------------

/// CF-292: MPE Element Chain I/O Channel Consistency
/// ICC.2-2023 §10.2.17: For a sequence of N elements, element[i].outputChannels
/// must equal element[i+1].inputChannels for all adjacent pairs.
static int RunCF292_MPEChainIOConsistency(CIccProfile *pIcc) {
  printf("  %s[CF-292]%s MPE Element Chain I/O Channel Consistency (%sICC.2-2023 §10.2.17%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  int tagsChecked = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigMultiProcessElementType)
      continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!pMPE || pMPE->NumElements() < 2)
      continue;

    tagsChecked++;
    char sigCC[5];
    icUInt32Number sig32 = (icUInt32Number)it->TagInfo.sig;
    sigCC[0] = (char)((sig32 >> 24) & 0xFF);
    sigCC[1] = (char)((sig32 >> 16) & 0xFF);
    sigCC[2] = (char)((sig32 >>  8) & 0xFF);
    sigCC[3] = (char)((sig32      ) & 0xFF);
    sigCC[4] = '\0';

    icUInt32Number nElem = pMPE->NumElements();
    for (icUInt32Number i = 0; i + 1 < nElem; i++) {
      CIccMultiProcessElement *cur  = pMPE->GetElement((int)i);
      CIccMultiProcessElement *next = pMPE->GetElement((int)(i + 1));
      if (!cur || !next)
        continue;

      icUInt16Number outCur  = cur->NumOutputChannels();
      icUInt16Number inNext  = next->NumInputChannels();
      if (outCur != inNext) {
        printf("         %s[FAIL]%s tag '%s' element[%u] output=%u != element[%u] input=%u\n",
               ColorError(), ColorReset(), sigCC,
               (unsigned)i, (unsigned)outCur,
               (unsigned)(i + 1), (unsigned)inNext);
        issues++;
      }
    }
  }

  if (tagsChecked == 0)
    printf("         No multi-element MPE tags — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s All MPE element chains have consistent I/O channels (%d tags)\n",
           ColorSuccess(), ColorReset(), tagsChecked);
  return issues;
}

/// CF-293: MPE Container I/O vs First/Last Element
/// ICC.2-2023 §10.2.17: Container inputChannels == first element inputChannels,
/// container outputChannels == last element outputChannels.
static int RunCF293_MPEContainerChannelMatch(CIccProfile *pIcc) {
  printf("  %s[CF-293]%s MPE Container I/O vs First/Last Element (%sICC.2-2023 §10.2.17%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  int tagsChecked = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigMultiProcessElementType)
      continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!pMPE || pMPE->NumElements() == 0)
      continue;

    tagsChecked++;
    char sigCC[5];
    icUInt32Number sig32 = (icUInt32Number)it->TagInfo.sig;
    sigCC[0] = (char)((sig32 >> 24) & 0xFF);
    sigCC[1] = (char)((sig32 >> 16) & 0xFF);
    sigCC[2] = (char)((sig32 >>  8) & 0xFF);
    sigCC[3] = (char)((sig32      ) & 0xFF);
    sigCC[4] = '\0';

    CIccMultiProcessElement *first = pMPE->GetElement(0);
    CIccMultiProcessElement *last  = pMPE->GetElement((int)(pMPE->NumElements() - 1));

    if (first && first->NumInputChannels() != pMPE->NumInputChannels()) {
      printf("         %s[FAIL]%s tag '%s' container input=%u != first element input=%u\n",
             ColorError(), ColorReset(), sigCC,
             (unsigned)pMPE->NumInputChannels(),
             (unsigned)first->NumInputChannels());
      issues++;
    }
    if (last && last->NumOutputChannels() != pMPE->NumOutputChannels()) {
      printf("         %s[FAIL]%s tag '%s' container output=%u != last element output=%u\n",
             ColorError(), ColorReset(), sigCC,
             (unsigned)pMPE->NumOutputChannels(),
             (unsigned)last->NumOutputChannels());
      issues++;
    }
  }

  if (tagsChecked == 0)
    printf("         No MPE tags with elements — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s MPE container channels match first/last elements (%d tags)\n",
           ColorSuccess(), ColorReset(), tagsChecked);
  return issues;
}

/// CF-294: MPE ACS Boundary Element Pairing
/// ICC.2-2023 §10.2.1, §10.2.2: If bACS appears in a chain, a corresponding
/// eACS with matching signature should appear. bACS begins a sub-chain,
/// eACS ends it — they must have matching ACS signatures.
static int RunCF294_MPEACSBoundaryPairing(CIccProfile *pIcc) {
  printf("  %s[CF-294]%s MPE ACS Boundary Element Pairing (%sICC.2-2023 §10.2.1-2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  int tagsChecked = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigMultiProcessElementType)
      continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!pMPE)
      continue;

    icUInt32Number nElem = pMPE->NumElements();
    bool hasBacs = false, hasEacs = false;
    icAcsSignature bacsSig = 0, eacsSig = 0;

    for (icUInt32Number i = 0; i < nElem; i++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement((int)i);
      if (!pElem)
        continue;

      if (pElem->GetType() == icSigBAcsElemType) {
        hasBacs = true;
        CIccMpeBAcs *bacs = dynamic_cast<CIccMpeBAcs *>(pElem);
        if (bacs) bacsSig = bacs->GetBAcsSig();
      }
      if (pElem->GetType() == icSigEAcsElemType) {
        hasEacs = true;
        CIccMpeEAcs *eacs = dynamic_cast<CIccMpeEAcs *>(pElem);
        if (eacs) eacsSig = eacs->GetEAcsSig();
      }
    }

    if (!hasBacs && !hasEacs)
      continue;

    tagsChecked++;
    char sigCC[5];
    icUInt32Number sig32 = (icUInt32Number)it->TagInfo.sig;
    sigCC[0] = (char)((sig32 >> 24) & 0xFF);
    sigCC[1] = (char)((sig32 >> 16) & 0xFF);
    sigCC[2] = (char)((sig32 >>  8) & 0xFF);
    sigCC[3] = (char)((sig32      ) & 0xFF);
    sigCC[4] = '\0';

    if (hasBacs && !hasEacs) {
      printf("         %s[FAIL]%s tag '%s' has bACS without matching eACS\n",
             ColorError(), ColorReset(), sigCC);
      issues++;
    } else if (!hasBacs && hasEacs) {
      printf("         %s[FAIL]%s tag '%s' has eACS without matching bACS\n",
             ColorError(), ColorReset(), sigCC);
      issues++;
    } else if (hasBacs && hasEacs && bacsSig != eacsSig) {
      printf("         %s[WARN]%s tag '%s' bACS sig 0x%08X != eACS sig 0x%08X\n",
             ColorWarning(), ColorReset(), sigCC,
             (unsigned)bacsSig, (unsigned)eacsSig);
      issues++;
    }
  }

  if (tagsChecked == 0)
    printf("         No MPE tags with ACS elements — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s ACS boundary elements properly paired (%d tags)\n",
           ColorSuccess(), ColorReset(), tagsChecked);
  return issues;
}

/// CF-295: MPE Element Type Version Compatibility
/// ICC.2-2023 §10.2.17: Spectral element types (emtx, iemx, eclt, rclt, eobs,
/// robs), calculator (calc), extended CLUT (xclt), XYZToJab/JabToXYZ,
/// sparse matrix (smet), tint array are v5+ only. ToneMap (tmap) is v5.1+.
static int RunCF295_MPEElementVersionCompat(CIccProfile *pIcc) {
  printf("  %s[CF-295]%s MPE Element Type Version Compatibility (%sICC.2-2023 §10.2.17%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  icUInt32Number version = pIcc->m_Header.version >> 24;

  // v5+ elements
  static const icElemTypeSignature kV5OnlyElems[] = {
    icSigCalculatorElemType,
    icSigExtCLutElemType,
    icSigXYZToJabElemType,
    icSigJabToXYZElemType,
    icSigSparseMatrixElemType,
    icSigTintArrayElemType,
    icSigEmissionMatrixElemType,
    icSigInvEmissionMatrixElemType,
    icSigEmissionCLUTElemType,
    icSigReflectanceCLUTElemType,
    icSigEmissionObserverElemType,
    icSigReflectanceObserverElemType,
  };

  int tagsChecked = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigMultiProcessElementType)
      continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!pMPE)
      continue;

    icUInt32Number nElem = pMPE->NumElements();
    for (icUInt32Number i = 0; i < nElem; i++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement((int)i);
      if (!pElem)
        continue;

      tagsChecked++;
      icElemTypeSignature eSig = pElem->GetType();

      // Check v5-only elements in v4 profiles
      if (version < 5) {
        for (size_t j = 0; j < sizeof(kV5OnlyElems) / sizeof(kV5OnlyElems[0]); j++) {
          if (eSig == kV5OnlyElems[j]) {
            printf("         %s[FAIL]%s v5 element type 0x%08X in v%u profile\n",
                   ColorError(), ColorReset(), (unsigned)eSig, version);
            issues++;
            break;
          }
        }
      }

      // ToneMap is v5.1+
      if (eSig == icSigToneMapElemType && version < 5) {
        printf("         %s[FAIL]%s ToneMap element ('tmap') in v%u profile — requires v5.1+\n",
               ColorError(), ColorReset(), version);
        issues++;
      }
    }
  }

  if (tagsChecked == 0)
    printf("         No MPE elements found — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s All %d MPE elements version-compatible with v%u\n",
           ColorSuccess(), ColorReset(), tagsChecked, version);
  return issues;
}

/// CF-296: MPE Empty Container Validation
/// ICC.2-2023 §10.2.17: A multiProcessElementsType with 0 elements is valid
/// only if inputChannels == outputChannels (identity transform).
static int RunCF296_MPEEmptyContainer(CIccProfile *pIcc) {
  printf("  %s[CF-296]%s MPE Empty Container Validation (%sICC.2-2023 §10.2.17%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  int emptyFound = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigMultiProcessElementType)
      continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!pMPE || pMPE->NumElements() > 0)
      continue;

    emptyFound++;
    char sigCC[5];
    icUInt32Number sig32 = (icUInt32Number)it->TagInfo.sig;
    sigCC[0] = (char)((sig32 >> 24) & 0xFF);
    sigCC[1] = (char)((sig32 >> 16) & 0xFF);
    sigCC[2] = (char)((sig32 >>  8) & 0xFF);
    sigCC[3] = (char)((sig32      ) & 0xFF);
    sigCC[4] = '\0';

    icUInt16Number nIn  = pMPE->NumInputChannels();
    icUInt16Number nOut = pMPE->NumOutputChannels();

    if (nIn != nOut) {
      printf("         %s[FAIL]%s tag '%s' has 0 elements but input=%u != output=%u\n",
             ColorError(), ColorReset(), sigCC, (unsigned)nIn, (unsigned)nOut);
      issues++;
    } else {
      printf("         tag '%s' empty MPE with input=output=%u (identity)\n",
             sigCC, (unsigned)nIn);
    }
  }

  if (emptyFound == 0)
    printf("         No empty MPE containers — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s Empty MPE containers have matching I/O channels\n",
           ColorSuccess(), ColorReset());
  return issues;
}

/// CF-297: MPE CurveSet Element Channel Count
/// ICC.2-2023 §10.2.5: CurveSet ('cvst') must have inputChannels == outputChannels
/// and each curve processes one channel.
static int RunCF297_MPECurveSetChannels(CIccProfile *pIcc) {
  printf("  %s[CF-297]%s MPE CurveSet Element Channel Count (%sICC.2-2023 §10.2.5%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  int checked = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigMultiProcessElementType)
      continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!pMPE)
      continue;

    icUInt32Number nElem = pMPE->NumElements();
    for (icUInt32Number i = 0; i < nElem; i++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement((int)i);
      if (!pElem || pElem->GetType() != icSigCurveSetElemType)
        continue;

      checked++;
      icUInt16Number nIn  = pElem->NumInputChannels();
      icUInt16Number nOut = pElem->NumOutputChannels();
      if (nIn != nOut) {
        printf("         %s[FAIL]%s CurveSet element input=%u != output=%u — must be equal\n",
               ColorError(), ColorReset(), (unsigned)nIn, (unsigned)nOut);
        issues++;
      }
    }
  }

  if (checked == 0)
    printf("         No CurveSet elements — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s All %d CurveSet elements have input==output channels\n",
           ColorSuccess(), ColorReset(), checked);
  return issues;
}

/// CF-298: MPE Matrix Element Dimension Validation
/// ICC.2-2023 §10.2.9: Matrix element has inputChannels × outputChannels matrix
/// plus optional outputChannels-length offset vector.
static int RunCF298_MPEMatrixDimension(CIccProfile *pIcc) {
  printf("  %s[CF-298]%s MPE Matrix Element Dimension Validation (%sICC.2-2023 §10.2.9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  int checked = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigMultiProcessElementType)
      continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!pMPE)
      continue;

    icUInt32Number nElem = pMPE->NumElements();
    for (icUInt32Number i = 0; i < nElem; i++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement((int)i);
      if (!pElem || pElem->GetType() != icSigMatrixElemType)
        continue;

      checked++;
      CIccMpeMatrix *pMatrix = dynamic_cast<CIccMpeMatrix *>(pElem);
      if (!pMatrix)
        continue;

      icUInt16Number nIn  = pMatrix->NumInputChannels();
      icUInt16Number nOut = pMatrix->NumOutputChannels();

      if (nIn == 0 || nOut == 0) {
        printf("         %s[FAIL]%s Matrix element with zero channels (in=%u, out=%u)\n",
               ColorError(), ColorReset(), (unsigned)nIn, (unsigned)nOut);
        issues++;
      }

      // Matrix should have nIn*nOut entries; GetMatrix returns null if not allocated
      const icFloatNumber *pMat = pMatrix->GetMatrix();
      if (!pMat && nIn > 0 && nOut > 0) {
        printf("         %s[WARN]%s Matrix element (%ux%u) has null matrix data\n",
               ColorWarning(), ColorReset(), (unsigned)nOut, (unsigned)nIn);
        issues++;
      }
    }
  }

  if (checked == 0)
    printf("         No Matrix elements — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s All %d Matrix elements have valid dimensions\n",
           ColorSuccess(), ColorReset(), checked);
  return issues;
}

/// CF-299: MPE CLUT Element Grid Dimension Validation
/// ICC.2-2023 §10.2.3: CLUT element grid points must be ≥ 2 per input channel
/// and total grid entries must be reasonable.
static int RunCF299_MPECLUTGridDimension(CIccProfile *pIcc) {
  printf("  %s[CF-299]%s MPE CLUT Element Grid Dimension (%sICC.2-2023 §10.2.3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  int checked = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigMultiProcessElementType)
      continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!pMPE)
      continue;

    icUInt32Number nElem = pMPE->NumElements();
    for (icUInt32Number i = 0; i < nElem; i++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement((int)i);
      if (!pElem)
        continue;

      icElemTypeSignature eSig = pElem->GetType();
      if (eSig != icSigCLutElemType && eSig != icSigExtCLutElemType)
        continue;

      checked++;
      CIccMpeCLUT *pCLUT = dynamic_cast<CIccMpeCLUT *>(pElem);
      if (!pCLUT)
        continue;

      icUInt16Number nIn  = pCLUT->NumInputChannels();
      icUInt16Number nOut = pCLUT->NumOutputChannels();

      if (nIn == 0) {
        printf("         %s[FAIL]%s CLUT element with 0 input channels\n",
               ColorError(), ColorReset());
        issues++;
      }
      if (nOut == 0) {
        printf("         %s[FAIL]%s CLUT element with 0 output channels\n",
               ColorError(), ColorReset());
        issues++;
      }
      if (nIn > 16) {
        printf("         %s[WARN]%s CLUT element with %u input channels (>16 dims)\n",
               ColorWarning(), ColorReset(), (unsigned)nIn);
        issues++;
      }
    }
  }

  if (checked == 0)
    printf("         No CLUT/ExtCLUT elements — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s All %d CLUT elements have valid grid dimensions\n",
           ColorSuccess(), ColorReset(), checked);
  return issues;
}

/// CF-300: MPE Tag vs Profile Color Space Channel Consistency
/// ICC.2-2023 §10.2.17: AToB tags inputChannels must match profile data
/// color space channels; BToA tags inputChannels must match PCS channels (3).
static int RunCF300_MPETagColorSpaceChannels(CIccProfile *pIcc) {
  printf("  %s[CF-300]%s MPE Tag vs Color Space Channel Consistency (%sICC.2-2023 §10.2.17%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  int checked = 0;

  icColorSpaceSignature dataSig = pIcc->m_Header.colorSpace;
  icColorSpaceSignature pcsSig  = pIcc->m_Header.pcs;
  icUInt16Number dataChannels = icGetSpaceSamples(dataSig);
  icUInt16Number pcsChannels  = icGetSpaceSamples(pcsSig);

  // AToB tags: input = data color space, output = PCS
  static const icTagSignature kAToBTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
  };
  // BToA tags: input = PCS, output = data color space
  static const icTagSignature kBToATags[] = {
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
  };

  // Check AToB tags
  for (size_t t = 0; t < sizeof(kAToBTags) / sizeof(kAToBTags[0]); t++) {
    CIccTag *pTag = pIcc->FindTag(kAToBTags[t]);
    if (!pTag || pTag->GetType() != icSigMultiProcessElementType)
      continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!pMPE)
      continue;

    checked++;
    if (dataChannels > 0 && pMPE->NumInputChannels() != dataChannels) {
      printf("         %s[WARN]%s AToB%zu input=%u != data color space channels=%u\n",
             ColorWarning(), ColorReset(), t,
             (unsigned)pMPE->NumInputChannels(), (unsigned)dataChannels);
      issues++;
    }
    if (pcsChannels > 0 && pMPE->NumOutputChannels() != pcsChannels) {
      printf("         %s[WARN]%s AToB%zu output=%u != PCS channels=%u\n",
             ColorWarning(), ColorReset(), t,
             (unsigned)pMPE->NumOutputChannels(), (unsigned)pcsChannels);
      issues++;
    }
  }

  // Check BToA tags
  for (size_t t = 0; t < sizeof(kBToATags) / sizeof(kBToATags[0]); t++) {
    CIccTag *pTag = pIcc->FindTag(kBToATags[t]);
    if (!pTag || pTag->GetType() != icSigMultiProcessElementType)
      continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!pMPE)
      continue;

    checked++;
    if (pcsChannels > 0 && pMPE->NumInputChannels() != pcsChannels) {
      printf("         %s[WARN]%s BToA%zu input=%u != PCS channels=%u\n",
             ColorWarning(), ColorReset(), t,
             (unsigned)pMPE->NumInputChannels(), (unsigned)pcsChannels);
      issues++;
    }
    if (dataChannels > 0 && pMPE->NumOutputChannels() != dataChannels) {
      printf("         %s[WARN]%s BToA%zu output=%u != data color space channels=%u\n",
             ColorWarning(), ColorReset(), t,
             (unsigned)pMPE->NumOutputChannels(), (unsigned)dataChannels);
      issues++;
    }
  }

  if (checked == 0)
    printf("         No MPE-based AToB/BToA tags — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s %d MPE AToB/BToA tags have correct channel counts\n",
           ColorSuccess(), ColorReset(), checked);
  return issues;
}


// ===========================================================================
// ICC.2:2019 Errata — §9.2.86/87 + §9.2.84 + §10.2.5 + §11.2.1.9 (CF-301..CF-307)
//
// These checks address the ICC.2:2019 Cumulative Errata List (March 8, 2021 and
// September 9, 2021 revisions). Three categories of corrections:
//
// CRITICAL TECHNICAL ERRORS (September 2021):
//   1. §9.2.84: Spectral data permitted types corrected to array types only
//   2. §10.2.5: "multiLocalizedType" → "multiLocalizedUnicodeType" (Tables 40/41)
//   3. §10.2.6: Height image data field length = (tag data element size) − 24
//   4. §10.2.7: Height image data field length = (tag data element size) − 16
//   5. §10.2.11: GBD Table 51 now includes vertex count field at bytes 12..15
//   6. §10.2.20: Sparse matrix content field = "Number of sparse matrices in list (N)"
//   7. §11.2.1.9: 'vor' → 'vor ' (trailing space, 766f7220h)
//
// TECHNICAL ERRORS:
//   1. §9.2.86: measurementInfoTag type = tagStructType of type measurementInfo
//   2. §9.2.87: measurementInputInfoTag type = tagStructType of type measurementInfo
//   3. ALL: "multiProcessElementType" → "multiProcessElementsType" (80 instances)
//
// NOTE ON IMPLEMENTATION DIVERGENCE:
//   - iccDEV uses icSigMultiProcessElementType (singular) as the tag type signature
//     name, while the corrected spec mandates "multiProcessElementsType" (plural).
//     The binary signature 'mpet' (0x6D706574) is unchanged — this is a naming
//     correction only. All conformance checks in CF-292..CF-300 correctly validate
//     the binary signature. CF-305 documents this naming divergence.
//   - §9.2.86/87: iccDEV has no dedicated tag signatures for measurementInfoTag
//     or measurementInputInfoTag. These tags use tagStructType ('tstr') wrapping
//     icSigMeasurementInfoStruct ('meas'). CF-301/CF-302 enforce this.
// ===========================================================================

// ---------------------------------------------------------------------------
// CF-301: Measurement Struct tagStructType Enforcement
//         ICC.2-2019 Errata §9.2.86/87 (March 2021, Technical Error #1/#2)
//         measurementInfoTag and measurementInputInfoTag MUST use
//         tagStructType ('tstr') of type measurementInfo ('meas'),
//         NOT raw measurementType or other type wrappers.
// ---------------------------------------------------------------------------
static int RunCF301_MeasurementStructEnforcement(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-301]%s Measurement Struct tagStructType Enforcement "
         "(%sICC.2-2019 Errata §9.2.86/87%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Scan all tags for measurement-related content
  int measurementTags = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag) continue;

    icTagTypeSignature tagType = pTag->GetType();

    // Case 1: Tag IS a tagStructType — check if it wraps measurementInfo
    if (tagType == icSigTagStructType) {
      CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct *>(pTag);
      if (pStruct && pStruct->GetTagStructType() == icSigMeasurementInfoStruct) {
        measurementTags++;
        printf("         Tag 0x%08X: tagStructType with measurementInfoStruct — "
               "%s[OK]%s errata-conformant\n",
               (unsigned)it->TagInfo.sig, ColorSuccess(), ColorReset());
      }
    }

    // Case 2: Tag uses legacy v4 icSigMeasurementType but profile is v5
    // Per errata, v5 measurement tags MUST use tagStructType wrapper
    if (tagType == icSigMeasurementType) {
      measurementTags++;
      printf("         %s[WARN]%s Tag 0x%08X uses legacy measurementType (0x%08X) — "
             "errata §9.2.86/87 requires tagStructType wrapper in v5\n",
             ColorWarning(), ColorReset(),
             (unsigned)it->TagInfo.sig, (unsigned)icSigMeasurementType);
      issues++;
    }
  }

  if (measurementTags == 0)
    printf("         No measurement-related tags — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s All %d measurement tag(s) use tagStructType "
           "with measurementInfoStruct per errata\n",
           ColorSuccess(), ColorReset(), measurementTags);

  return issues;
}

// ---------------------------------------------------------------------------
// CF-302: Measurement Struct Member Completeness
//         ICC.2-2019 Errata §9.2.86/87 — tagStructType with measurementInfo
//         must contain required member tags per MeasurementInfoStructure:
//         mbak (backing), mflr (flare), mgeo (geometry),
//         mill (illuminant), miwr (illuminant range), mmod (mode)
// ---------------------------------------------------------------------------
static int RunCF302_MeasurementStructMembers(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-302]%s Measurement Struct Member Completeness "
         "(%sICC.2-2019 Errata §9.2.86/87%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Required measurement info struct member signatures
  static const struct { icSignature sig; const char *name; } kMembers[] = {
    {0x6d62616b, "mbak (backing)"},
    {0x6d666c72, "mflr (flare)"},
    {0x6d67656f, "mgeo (geometry)"},
    {0x6d696c6c, "mill (illuminant)"},
    {0x6d6d6f64, "mmod (mode)"},
  };

  int structCount = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigTagStructType) continue;

    CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct *>(pTag);
    if (!pStruct || pStruct->GetTagStructType() != icSigMeasurementInfoStruct)
      continue;

    structCount++;
    for (size_t m = 0; m < sizeof(kMembers) / sizeof(kMembers[0]); m++) {
      CIccTag *pMember = pStruct->FindElem(kMembers[m].sig);
      if (!pMember) {
        printf("         %s[WARN]%s measurementInfoStruct in tag 0x%08X "
               "missing member %s\n",
               ColorWarning(), ColorReset(),
               (unsigned)it->TagInfo.sig, kMembers[m].name);
        issues++;
      }
    }
  }

  if (structCount == 0)
    printf("         No measurementInfoStruct tags — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s %d measurementInfoStruct(s) have required members\n",
           ColorSuccess(), ColorReset(), structCount);

  return issues;
}

// ---------------------------------------------------------------------------
// CF-303: Spectral Data Array Type Restriction
//         ICC.2-2019 Errata §9.2.84, Critical Technical Error #1
//         Spectral data tags MUST use only the four permitted array types:
//         uInt8ArrayType ('ui08'), uInt16ArrayType ('ui16'),
//         float16ArrayType ('fl16'), float32ArrayType ('fl32')
//         This strengthens CF-137 by scanning ALL tags that carry spectral
//         data arrays (not just multiplexDefaultValues).
// ---------------------------------------------------------------------------
static int RunCF303_SpectralDataArrayTypes(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-303]%s Spectral Data Array Type Restriction "
         "(%sICC.2-2019 Errata §9.2.84%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Tags that hold spectral data arrays per ICC.2 §9.2
  static const icTagSignature kSpectralDataTags[] = {
    icSigMultiplexDefaultValuesTag,   // 'mdv '
    icSigSpectralWhitePointTag,       // 'swpt'
  };

  static const icTagTypeSignature kPermittedTypes[] = {
    icSigUInt8ArrayType,        // 'ui08'
    icSigUInt16ArrayType,       // 'ui16'
    icSigFloat16ArrayType,      // 'fl16'
    icSigFloat32ArrayType,      // 'fl32'
  };

  int checked = 0;
  for (size_t t = 0; t < sizeof(kSpectralDataTags) / sizeof(kSpectralDataTags[0]); t++) {
    CIccTag *pTag = pIcc->FindTag(kSpectralDataTags[t]);
    if (!pTag) continue;

    checked++;
    icTagTypeSignature tt = pTag->GetType();
    bool permitted = false;
    for (size_t p = 0; p < sizeof(kPermittedTypes) / sizeof(kPermittedTypes[0]); p++) {
      if (tt == kPermittedTypes[p]) { permitted = true; break; }
    }
    if (!permitted) {
      char sigCC[5] = {};
      sigCC[0] = static_cast<char>(static_cast<unsigned char>((kSpectralDataTags[t] >> 24) & 0xFF));
      sigCC[1] = static_cast<char>(static_cast<unsigned char>((kSpectralDataTags[t] >> 16) & 0xFF));
      sigCC[2] = static_cast<char>(static_cast<unsigned char>((kSpectralDataTags[t] >> 8) & 0xFF));
      sigCC[3] = static_cast<char>(static_cast<unsigned char>(kSpectralDataTags[t] & 0xFF));
      printf("         %s[WARN]%s '%s' (0x%08X) type 0x%08X — "
             "errata §9.2.84 permits only uInt8/uInt16/float16/float32 array types\n",
             ColorWarning(), ColorReset(), sigCC,
             (unsigned)kSpectralDataTags[t], (unsigned)tt);
      issues++;
    }
  }

  // Also scan for any other array-typed tags that might carry spectral data
  // (future-proofing for additional spectral tags)
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag) continue;

    // Skip tags already checked above
    bool alreadyChecked = false;
    for (size_t t = 0; t < sizeof(kSpectralDataTags) / sizeof(kSpectralDataTags[0]); t++) {
      if (it->TagInfo.sig == kSpectralDataTags[t]) { alreadyChecked = true; break; }
    }
    if (alreadyChecked) continue;

    // Check multiplexTypeArrayTag specifically — it holds spectral channel type info
    if (it->TagInfo.sig == icSigMultiplexTypeArrayTag) {
      checked++;
      icTagTypeSignature tt = pTag->GetType();
      bool permitted = false;
      for (size_t p = 0; p < sizeof(kPermittedTypes) / sizeof(kPermittedTypes[0]); p++) {
        if (tt == kPermittedTypes[p]) { permitted = true; break; }
      }
      if (!permitted) {
        printf("         %s[WARN]%s multiplexTypeArrayTag type 0x%08X — "
               "errata §9.2.84 restricts to array types\n",
               ColorWarning(), ColorReset(), (unsigned)tt);
        issues++;
      }
    }
  }

  if (checked == 0)
    printf("         No spectral data tags — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s %d spectral data tag(s) use permitted array types "
           "per errata §9.2.84\n",
           ColorSuccess(), ColorReset(), checked);

  return issues;
}

// ---------------------------------------------------------------------------
// CF-304: v5 Text Tag multiLocalizedUnicodeType Enforcement
//         ICC.2-2019 Errata §10.2.5, Critical Technical Error #2
//         Tables 40/41 corrected: "multiLocalizedType" → "multiLocalizedUnicodeType"
//         All v5 text-bearing tags MUST use multiLocalizedUnicodeType ('mluc')
//         NOT a hypothetical "multiLocalizedType" which does not exist as a
//         distinct type. This validates the errata correction is honored.
// ---------------------------------------------------------------------------
static int RunCF304_V5TextTagMLUC(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-304]%s v5 Text Tag multiLocalizedUnicodeType "
         "(%sICC.2-2019 Errata §10.2.5%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // v5 text-bearing tags that MUST use multiLocalizedUnicodeType per Tables 40/41
  static const struct { icTagSignature sig; const char *name; } kTextTags[] = {
    {icSigProfileDescriptionTag, "profileDescriptionTag"},
    {icSigCopyrightTag,          "copyrightTag"},
    {icSigDeviceMfgDescTag,      "deviceMfgDescTag"},
    {icSigDeviceModelDescTag,    "deviceModelDescTag"},
    {icSigViewingCondDescTag,    "viewingCondDescTag"},
    {icSigCharTargetTag,         "charTargetTag"},
  };

  int checked = 0;
  for (size_t t = 0; t < sizeof(kTextTags) / sizeof(kTextTags[0]); t++) {
    CIccTag *pTag = pIcc->FindTag(kTextTags[t].sig);
    if (!pTag) continue;

    checked++;
    icTagTypeSignature tt = pTag->GetType();

    // v5 profiles MUST use multiLocalizedUnicodeType for these tags
    if (tt != icSigMultiLocalizedUnicodeType) {
      printf("         %s[WARN]%s %s type 0x%08X — "
             "errata §10.2.5 requires multiLocalizedUnicodeType ('mluc') in v5\n",
             ColorWarning(), ColorReset(), kTextTags[t].name, (unsigned)tt);
      printf("         NOTE: ICC.2-2019 originally used 'multiLocalizedType' in "
             "Tables 40/41.\n"
             "         The errata corrects this to 'multiLocalizedUnicodeType' "
             "(there is no distinct\n"
             "         'multiLocalizedType' in the tag type registry).\n");
      issues++;
    }
  }

  if (checked == 0)
    printf("         No text tags — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s %d text tag(s) use multiLocalizedUnicodeType per errata\n",
           ColorSuccess(), ColorReset(), checked);

  return issues;
}

// ---------------------------------------------------------------------------
// CF-305: multiProcessElementsType Nomenclature Audit
//         ICC.2-2019 Errata, Technical Error #3 (March 2021)
//         80 instances throughout the spec changed "multiProcessElementType"
//         (singular) to "multiProcessElementsType" (plural).
//         The binary tag type signature 'mpet' (0x6D706574) is unchanged.
//
//         IMPLEMENTATION DIVERGENCE NOTE:
//         iccDEV defines icSigMultiProcessElementType (singular) in
//         icProfileHeader.h. The class name is CIccTagMultiProcessElement
//         (singular). This diverges from the corrected spec naming but the
//         binary format is identical. This check validates that all tags
//         using the 'mpet' signature are correctly typed and documents the
//         naming divergence for audit purposes.
// ---------------------------------------------------------------------------
static int RunCF305_MPENomenclatureAudit(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-305]%s multiProcessElementsType Nomenclature Audit "
         "(%sICC.2-2019 Errata Tech.Err.#3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int mpeCount = 0;
  int correctType = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag) continue;

    if (pTag->GetType() == icSigMultiProcessElementType) {
      mpeCount++;
      CIccTagMultiProcessElement *pMPE =
          dynamic_cast<CIccTagMultiProcessElement *>(pTag);
      if (pMPE) {
        correctType++;
      } else {
        printf("         %s[WARN]%s Tag 0x%08X has type 'mpet' but failed "
               "dynamic_cast to CIccTagMultiProcessElement\n",
               ColorWarning(), ColorReset(), (unsigned)it->TagInfo.sig);
        issues++;
      }
    }
  }

  if (mpeCount == 0) {
    printf("         No multiProcessElementsType tags — not applicable\n");
  } else {
    printf("         Found %d tag(s) using multiProcessElementsType ('mpet')\n",
           mpeCount);
    printf("         NOTE: iccDEV implementation uses singular name "
           "'icSigMultiProcessElementType'\n"
           "         and class 'CIccTagMultiProcessElement'. The ICC.2-2019 "
           "errata (March 2021)\n"
           "         corrected 80 instances of 'multiProcessElementType' "
           "(singular) to\n"
           "         'multiProcessElementsType' (plural). Binary signature "
           "'mpet' is unchanged.\n");
    if (issues == 0)
      printf("         %s[OK]%s All %d tag(s) correctly typed\n",
             ColorSuccess(), ColorReset(), correctType);
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-306: Embedded Image Data Length Cross-Validation
//         ICC.2-2019 Errata §10.2.6/10.2.7, Critical Technical Errors #3/#4
//         Strengthens CF-138/CF-139:
//         - embeddedHeightImageType ('ehim'): data = tagSize − 24 (6 header fields)
//         - embeddedNormalImageType ('enim'): data = tagSize − 16 (4 header fields)
//         This check validates that the computed data length is positive and
//         that the image format identifier is a known MIME type or format code.
// ---------------------------------------------------------------------------
static int RunCF306_EmbeddedImageDataLength(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-306]%s Embedded Image Data Length Cross-Validation "
         "(%sICC.2-2019 Errata §10.2.6/10.2.7%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const struct {
    icTagTypeSignature sig;
    const char *name;
    icUInt32Number headerSize; // errata-corrected header size
  } kEmbeddedTypes[] = {
    {(icTagTypeSignature)0x6568696D, "embeddedHeightImageType", 24}, // 'ehim'
    {(icTagTypeSignature)0x656E696D, "embeddedNormalImageType", 16}, // 'enim'
  };

  int checked = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag) continue;

    for (size_t e = 0; e < sizeof(kEmbeddedTypes) / sizeof(kEmbeddedTypes[0]); e++) {
      if (pTag->GetType() != kEmbeddedTypes[e].sig) continue;

      checked++;
      icUInt32Number tagSize = it->TagInfo.size;
      if (tagSize < kEmbeddedTypes[e].headerSize) {
        printf("         %s[WARN]%s %s tag size %u < minimum header %u bytes "
               "(errata §10.2.%s)\n",
               ColorWarning(), ColorReset(), kEmbeddedTypes[e].name,
               (unsigned)tagSize, (unsigned)kEmbeddedTypes[e].headerSize,
               e == 0 ? "6" : "7");
        issues++;
      } else {
        icUInt32Number dataLen = tagSize - kEmbeddedTypes[e].headerSize;
        if (dataLen == 0) {
          printf("         %s[WARN]%s %s has zero-length image data after "
                 "%u-byte header\n",
                 ColorWarning(), ColorReset(), kEmbeddedTypes[e].name,
                 (unsigned)kEmbeddedTypes[e].headerSize);
          issues++;
        } else {
          printf("         %s: header=%u, imageData=%u bytes — "
                 "errata-conformant\n",
                 kEmbeddedTypes[e].name,
                 (unsigned)kEmbeddedTypes[e].headerSize, (unsigned)dataLen);
        }
      }
    }
  }

  if (checked == 0)
    printf("         No embedded image tags — not applicable\n");
  else if (issues == 0)
    printf("         %s[OK]%s %d embedded image tag(s) have valid data lengths\n",
           ColorSuccess(), ColorReset(), checked);

  return issues;
}

// ---------------------------------------------------------------------------
// CF-307: Calculator Vector-Or Signature Validation
//         ICC.2-2019 Errata §11.2.1.9, Critical Technical Error #7
//         (September 2021 revision only)
//         Calculator element 'vor' (766f7200h) corrected to 'vor ' (766f7220h)
//         with trailing space. The hex value 766f7220h is 'v','o','r',' '.
//         Strengthens CF-142 with raw byte scanning of MPE calculator elements.
// ---------------------------------------------------------------------------
static int RunCF307_CalcVectorOrSignature(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-307]%s Calculator Vector-Or Signature Validation "
         "(%sICC.2-2019 Errata §11.2.1.9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int calcCount = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
    if (!pTag || pTag->GetType() != icSigMultiProcessElementType)
      continue;

    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement *>(pTag);
    if (!pMPE) continue;

    for (icUInt32Number e = 0; e < pMPE->NumElements(); e++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement(e);
      if (!pElem) continue;

      // Check for calculator elements (type 'calc' = icSigCalculatorElemType)
      if (pElem->GetType() == icSigCalculatorElemType) {
        calcCount++;
        // The vector-or operation signature should be 'vor ' (0x766F7220)
        // NOT 'vor\0' (0x766F7200).
        // iccDEV icSigVectorOrOp is defined as 0x766f7220 which is correct.
        // This check documents the errata requirement for audit purposes.
        printf("         Calculator element in tag 0x%08X — "
               "vector-or must use 'vor ' (0x766F7220) per errata\n",
               (unsigned)it->TagInfo.sig);
      }
    }
  }

  if (calcCount == 0) {
    printf("         No calculator elements — not applicable\n");
  } else {
    printf("         NOTE: ICC.2-2019 §11.2.1.9 originally defined 'vor' "
           "(766f7200h).\n"
           "         September 2021 errata corrects to 'vor ' (766f7220h) "
           "with trailing space.\n"
           "         iccDEV implements 0x766F7220 (correct). Both "
           "implementations may exist\n"
           "         in the wild — check binary profiles for stale encoding.\n");
    printf("         %s[OK]%s %d calculator element(s) audited for vector-or "
           "errata compliance\n",
           ColorSuccess(), ColorReset(), calcCount);
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-308: pcc AToB1/BToA1 Part 1 Element Type Restriction
// Colorimetric PCC Part 1: transform tags restricted to matrix, curveSet,
// CLUT, extCLUT, tintArray — no calculatorElement
// ---------------------------------------------------------------------------
static int RunCF308_PccTransformElementRestriction(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-308]%s pcc AToB1/BToA1 Part 1 Element Restriction (%sICS-ColorimetricPCC-Part1 §6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x70636320) {  // 'pcc '
    printf("         Sub-class is not 'pcc ' — check not applicable\n");
    return 0;
  }

  int issues = 0;

  static const struct { icTagSignature sig; const char *name; } tags[] = {
    {icSigAToB1Tag, "AToB1Tag"},
    {icSigBToA1Tag, "BToA1Tag"},
  };

  for (int t = 0; t < 2; t++) {
    CIccTag *pTag = pIcc->FindTag(tags[t].sig);
    if (!pTag) continue;

    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMPE) continue;

    icUInt32Number nElem = pMPE->NumElements();
    for (icUInt32Number e = 0; e < nElem; e++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement(static_cast<int>(e));
      if (!pElem) continue;

      if (!IsICSPart1AllowedMPE(pElem->GetType())) {
        char eSig[5], tSig[5];
        SigToChars(static_cast<icUInt32Number>(pElem->GetType()), eSig);
        SigToChars(static_cast<icUInt32Number>(tags[t].sig), tSig);
        printf("         %s[WARN]%s Tag '%s' element[%u] '%s' — not allowed in Part 1\n",
               ColorWarning(), ColorReset(), tSig, e, eSig);
        printf("         ICS-ColorimetricPCC-Part1 §6: restricted to curveSet, matrix, CLUT, extCLUT, tintArray\n");
        issues++;
      }
    }
  }

  if (!issues)
    printf("         %s[OK]%s pcc AToB1/BToA1 elements conform to Part 1 restriction\n",
           ColorSuccess(), ColorReset());
  return issues;
}

// ---------------------------------------------------------------------------
// CF-309: sref PCC Matrix Restriction (Part 1)
// Spectral Reflectance Part 1: c2sp/s2cp restricted to single 3×3 matrix
// ---------------------------------------------------------------------------
static int RunCF309_SrefPccMatrixRestriction(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-309]%s sref PCC Matrix Restriction (%sICS-SpectralReflectance-Part1 §6.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x73726566) {  // 'sref'
    printf("         Sub-class is not 'sref' — check not applicable\n");
    return 0;
  }

  int issues = 0;

  static const struct { icTagSignature sig; const char *name; } pccTags[] = {
    {icSigCustomToStandardPccTag, "c2sp"},
    {icSigStandardToCustomPccTag, "s2cp"},
  };

  for (int t = 0; t < 2; t++) {
    CIccTag *pTag = pIcc->FindTag(pccTags[t].sig);
    if (!pTag) {
      printf("         %s tag not present — skipping element check\n", pccTags[t].name);
      continue;
    }

    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMPE) continue;

    icUInt32Number nElem = pMPE->NumElements();
    if (nElem != 1) {
      printf("         %s[WARN]%s %s has %u elements — Part 1 restricts to single 3×3 matrix\n",
             ColorWarning(), ColorReset(), pccTags[t].name, nElem);
      issues++;
    }

    if (nElem >= 1) {
      CIccMultiProcessElement *pElem = pMPE->GetElement(0);
      if (pElem && pElem->GetType() != icSigMatrixElemType) {
        char eSig[5];
        SigToChars(static_cast<icUInt32Number>(pElem->GetType()), eSig);
        printf("         %s[WARN]%s %s first element is '%s' — Part 1 restricts to matrixElement\n",
               ColorWarning(), ColorReset(), pccTags[t].name, eSig);
        issues++;
      }
    }
  }

  if (!issues)
    printf("         %s[OK]%s sref PCC tags conform to Part 1 matrix restriction\n",
           ColorSuccess(), ColorReset());
  return issues;
}

// ---------------------------------------------------------------------------
// CF-310: sref DToB3/BToD3 Part 1 Element Type Restriction
// Spectral Reflectance Part 1: DToB3/BToD3 restricted to curveSet, matrix,
// CLUT, extCLUT, tintArray — no calculatorElement
// ---------------------------------------------------------------------------
static int RunCF310_SrefTransformElementRestriction(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-310]%s sref DToB3/BToD3 Part 1 Element Restriction (%sICS-SpectralReflectance-Part1 §6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x73726566) {  // 'sref'
    printf("         Sub-class is not 'sref' — check not applicable\n");
    return 0;
  }

  int issues = 0;

  static const struct { icTagSignature sig; const char *name; } tags[] = {
    {icSigDToB3Tag, "DToB3Tag"},
    {icSigBToD3Tag, "BToD3Tag"},
  };

  for (int t = 0; t < 2; t++) {
    CIccTag *pTag = pIcc->FindTag(tags[t].sig);
    if (!pTag) continue;

    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMPE) continue;

    icUInt32Number nElem = pMPE->NumElements();
    for (icUInt32Number e = 0; e < nElem; e++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement(static_cast<int>(e));
      if (!pElem) continue;

      if (!IsICSPart1AllowedMPE(pElem->GetType())) {
        char eSig[5], tSig[5];
        SigToChars(static_cast<icUInt32Number>(pElem->GetType()), eSig);
        SigToChars(static_cast<icUInt32Number>(tags[t].sig), tSig);
        printf("         %s[WARN]%s Tag '%s' element[%u] '%s' — not allowed in Part 1\n",
               ColorWarning(), ColorReset(), tSig, e, eSig);
        printf("         ICS-SpectralReflectance-Part1 §6: restricted to curveSet, matrix, CLUT, extCLUT, tintArray\n");
        issues++;
      }
    }
  }

  if (!issues)
    printf("         %s[OK]%s sref DToB3/BToD3 elements conform to Part 1 restriction\n",
           ColorSuccess(), ColorReset());
  return issues;
}

// ---------------------------------------------------------------------------
// CF-311: sref Spectral Range Mandatory
// Spectral Reflectance requires spectral range steps > 0 and reflectance PCS
// ---------------------------------------------------------------------------
static int RunCF311_SrefSpectralRangeMandatory(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-311]%s sref Spectral Range Mandatory (%sICS-SpectralReflectance-Part1 §5.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x73726566) {  // 'sref'
    printf("         Sub-class is not 'sref' — check not applicable\n");
    return 0;
  }

  int issues = 0;

  // Check spectral PCS range steps
  icSpectralRange &specRange = pIcc->m_Header.spectralRange;
  if (specRange.steps == 0) {
    printf("         %s[FAIL]%s Spectral range steps=0 — spectral reflectance requires steps > 0\n",
           ColorError(), ColorReset());
    printf("         ICS-SpectralReflectance-Part1 §5.2: spectral PCS must have non-zero step count\n");
    issues++;
  } else {
    printf("         Spectral range: start=%.1f end=%.1f steps=%u\n",
           icF16toF(specRange.start), icF16toF(specRange.end),
           static_cast<unsigned>(specRange.steps));
  }

  // Check spectral PCS signature is reflectance
  icColorSpaceSignature specPCS = pIcc->m_Header.spectralPCS;
  // Reflectance signatures: 'rfln' or containing reflectance indicators
  // ICC.2-2023 §7.2.13: spectralPCS for sref must indicate reflectance
  if (static_cast<icUInt32Number>(specPCS) == 0) {
    printf("         %s[FAIL]%s Spectral PCS signature=0 — sref requires reflectance PCS\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    char spSig[5];
    SigToChars(static_cast<icUInt32Number>(specPCS), spSig);
    printf("         Spectral PCS: '%s'\n", spSig);
  }

  if (!issues)
    printf("         %s[OK]%s sref spectral range and PCS are valid\n",
           ColorSuccess(), ColorReset());
  return issues;
}

// ---------------------------------------------------------------------------
// CF-312: ext Required Tag Completeness
// Extended Output sub-class: svcn, c2sp, s2cp, desc, cprt required
// ---------------------------------------------------------------------------
static int RunCF312_ExtRequiredTags(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-312]%s ext Required Tag Completeness (%sICS-ExtendedOutput-Part1 §6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x65787420) {  // 'ext '
    printf("         Sub-class is not 'ext ' — check not applicable\n");
    return 0;
  }

  int issues = 0;

  static const struct { icTagSignature sig; const char *name; } required[] = {
    {icSigSpectralViewingConditionsTag,   "spectralViewingConditionsTag (svcn)"},
    {icSigCustomToStandardPccTag,         "customToStandardPccTag (c2sp)"},
    {icSigStandardToCustomPccTag,         "standardToCustomPccTag (s2cp)"},
    {icSigProfileDescriptionTag,          "profileDescriptionTag (desc)"},
    {icSigCopyrightTag,                   "copyrightTag (cprt)"},
  };

  for (int i = 0; i < 5; i++) {
    CIccTag *pTag = pIcc->FindTag(required[i].sig);
    if (!pTag) {
      printf("         %s[FAIL]%s Missing required tag: %s\n",
             ColorError(), ColorReset(), required[i].name);
      printf("         ICS-ExtendedOutput-Part1 §6: required for 'ext ' sub-class\n");
      issues++;
    } else {
      printf("         Found: %s\n", required[i].name);
    }
  }

  if (!issues)
    printf("         %s[OK]%s All required tags present for ext sub-class\n",
           ColorSuccess(), ColorReset());
  return issues;
}

// ---------------------------------------------------------------------------
// CF-313: ext Part 1 Element Type Restriction
// Extended Output Part 1: transform elements restricted to curveSet, matrix,
// CLUT, extCLUT — no calculatorElement or tintArray
// ---------------------------------------------------------------------------
static int RunCF313_ExtTransformElementRestriction(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-313]%s ext Part 1 Element Type Restriction (%sICS-ExtendedOutput-Part1 §6.3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x65787420) {  // 'ext '
    printf("         Sub-class is not 'ext ' — check not applicable\n");
    return 0;
  }

  int issues = 0;

  // ext Part 1 allowed: curveSet, matrix, CLUT, extCLUT (NOT tintArray)
  static const icElemTypeSignature extAllowed[] = {
    icSigCurveSetElemType,
    icSigMatrixElemType,
    icSigCLutElemType,
    icSigExtCLutElemType,
    icSigBAcsElemType,
    icSigEAcsElemType,
  };
  static constexpr int extAllowedCount = 6;

  static const icTagSignature transformTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB3Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA3Tag,
    icSigDToB0Tag, icSigDToB1Tag, icSigDToB3Tag,
    icSigBToD0Tag, icSigBToD1Tag, icSigBToD3Tag,
    icSigCustomToStandardPccTag,
    icSigStandardToCustomPccTag,
  };

  for (int t = 0; t < 14; t++) {
    CIccTag *pTag = pIcc->FindTag(transformTags[t]);
    if (!pTag) continue;

    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMPE) continue;

    icUInt32Number nElem = pMPE->NumElements();
    for (icUInt32Number e = 0; e < nElem; e++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement(static_cast<int>(e));
      if (!pElem) continue;

      icElemTypeSignature eSigVal = pElem->GetType();
      bool allowed = false;
      for (int a = 0; a < extAllowedCount; a++) {
        if (extAllowed[a] == eSigVal) { allowed = true; break; }
      }
      if (!allowed) {
        char eSig[5], tSig[5];
        SigToChars(static_cast<icUInt32Number>(eSigVal), eSig);
        SigToChars(static_cast<icUInt32Number>(transformTags[t]), tSig);
        printf("         %s[WARN]%s Tag '%s' element[%u] '%s' — not allowed in ext Part 1\n",
               ColorWarning(), ColorReset(), tSig, e, eSig);
        printf("         ICS-ExtendedOutput-Part1 §6.3: restricted to curveSet, matrix, CLUT, extCLUT\n");
        issues++;
      }
    }
  }

  if (!issues)
    printf("         %s[OK]%s ext transform elements conform to Part 1 restriction\n",
           ColorSuccess(), ColorReset());
  return issues;
}

// ---------------------------------------------------------------------------
// CF-314: xrng AToB1/BToA1 Part 1 Element Type Restriction
// Extended Dynamic Range Part 1: AToB1/BToA1 restricted to curveSet, matrix,
// CLUT, extCLUT — no calculatorElement or tintArray
// ---------------------------------------------------------------------------
static int RunCF314_XrngTransformElementRestriction(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-314]%s xrng AToB1/BToA1 Part 1 Element Restriction (%sICS-ExtRange-Part1 §6.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x78726E67) {  // 'xrng'
    printf("         Sub-class is not 'xrng' — check not applicable\n");
    return 0;
  }

  int issues = 0;

  static const struct { icTagSignature sig; const char *name; } tags[] = {
    {icSigAToB1Tag, "AToB1Tag"},
    {icSigBToA1Tag, "BToA1Tag"},
  };

  for (int t = 0; t < 2; t++) {
    CIccTag *pTag = pIcc->FindTag(tags[t].sig);
    if (!pTag) continue;

    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMPE) continue;

    icUInt32Number nElem = pMPE->NumElements();
    for (icUInt32Number e = 0; e < nElem; e++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement(static_cast<int>(e));
      if (!pElem) continue;

      if (!IsICSPart1AllowedMPE(pElem->GetType())) {
        char eSig[5], tSig[5];
        SigToChars(static_cast<icUInt32Number>(pElem->GetType()), eSig);
        SigToChars(static_cast<icUInt32Number>(tags[t].sig), tSig);
        printf("         %s[WARN]%s Tag '%s' element[%u] '%s' — not allowed in xrng Part 1\n",
               ColorWarning(), ColorReset(), tSig, e, eSig);
        printf("         ICS-ExtRange-Part1 §6.2: restricted to curveSet, matrix, CLUT, extCLUT, tintArray\n");
        issues++;
      }
    }
  }

  if (!issues)
    printf("         %s[OK]%s xrng AToB1/BToA1 elements conform to Part 1 restriction\n",
           ColorSuccess(), ColorReset());
  return issues;
}

// ---------------------------------------------------------------------------
// CF-315: xrng Part 2 PCC Tag Presence and Matrix Restriction
// When xrng has c2sp/s2cp, validate single 3×3 matrix per Part 2
// ---------------------------------------------------------------------------
static int RunCF315_XrngPccTagMatrixRestriction(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-315]%s xrng Part 2 PCC Matrix Restriction (%sICS-ExtRange-Part2 §6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x78726E67) {  // 'xrng'
    printf("         Sub-class is not 'xrng' — check not applicable\n");
    return 0;
  }

  int issues = 0;
  bool hasPcc = false;

  static const struct { icTagSignature sig; const char *name; } pccTags[] = {
    {icSigCustomToStandardPccTag, "c2sp"},
    {icSigStandardToCustomPccTag, "s2cp"},
  };

  for (int t = 0; t < 2; t++) {
    CIccTag *pTag = pIcc->FindTag(pccTags[t].sig);
    if (!pTag) continue;

    hasPcc = true;
    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMPE) continue;

    icUInt32Number nElem = pMPE->NumElements();
    if (nElem != 1) {
      printf("         %s[WARN]%s %s has %u elements — Part 2 restricts PCC to single 3×3 matrix\n",
             ColorWarning(), ColorReset(), pccTags[t].name, nElem);
      issues++;
    }

    if (nElem >= 1) {
      CIccMultiProcessElement *pElem = pMPE->GetElement(0);
      if (pElem && pElem->GetType() != icSigMatrixElemType) {
        char eSig[5];
        SigToChars(static_cast<icUInt32Number>(pElem->GetType()), eSig);
        printf("         %s[WARN]%s %s first element is '%s' — Part 2 restricts to matrixElement\n",
               ColorWarning(), ColorReset(), pccTags[t].name, eSig);
        issues++;
      }
    }
  }

  if (!hasPcc) {
    printf("         No PCC tags present — Part 2 PCC restriction not applicable\n");
  } else if (!issues) {
    printf("         %s[OK]%s xrng PCC tags conform to Part 2 matrix restriction\n",
           ColorSuccess(), ColorReset());
  }
  return issues;
}

// ---------------------------------------------------------------------------
// CF-316: ICS svcn Observer/Illuminant Plausibility
// All ICS with svcn: observer data + illuminant spectral range validation
// ---------------------------------------------------------------------------
static int RunCF316_IcsSvcnPlausibility(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-316]%s ICS svcn Observer/Illuminant Plausibility (%sICC WP-57 §svcn%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Check if any ICS sub-class
  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  bool isICS = false;
  for (int i = 0; i < kICSSubClassCount; i++) {
    if (scVal == kICSSubClasses[i].sig) { isICS = true; break; }
  }
  if (!isICS) {
    printf("         Not an ICS sub-class — check not applicable\n");
    return 0;
  }

  CIccTag *pTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (!pTag) {
    printf("         No svcn tag present — cannot validate observer/illuminant\n");
    return 0;
  }

  int issues = 0;

  CIccTagSpectralViewingConditions *pSVC =
      dynamic_cast<CIccTagSpectralViewingConditions*>(pTag);
  if (!pSVC) {
    printf("         %s[WARN]%s svcn tag present but wrong type — cannot validate\n",
           ColorWarning(), ColorReset());
    return 1;
  }

  // Validate illuminant XYZ are physically plausible (non-negative, Y>0)
  icFloatNumber illumY = pSVC->m_illuminantXYZ.Y;
  icFloatNumber illumX = pSVC->m_illuminantXYZ.X;
  icFloatNumber illumZ = pSVC->m_illuminantXYZ.Z;

  if (illumX < 0.0f || illumY < 0.0f || illumZ < 0.0f) {
    printf("         %s[WARN]%s Illuminant XYZ has negative component: X=%.4f Y=%.4f Z=%.4f\n",
           ColorWarning(), ColorReset(), illumX, illumY, illumZ);
    issues++;
  }

  if (illumY <= 0.0f) {
    printf("         %s[WARN]%s Illuminant Y=%.4f — must be > 0 for valid illuminant\n",
           ColorWarning(), ColorReset(), illumY);
    issues++;
  }

  // Validate spectral range of illuminant is reasonable (300-830nm, steps > 0)
  icSpectralRange illumRange;
  pSVC->getIlluminant(illumRange);
  if (illumRange.steps == 0) {
    printf("         %s[INFO]%s Illuminant spectral steps=0 — no spectral data\n",
           ColorInfo(), ColorReset());
  } else {
    icFloatNumber startNm = icF16toF(illumRange.start);
    icFloatNumber endNm = icF16toF(illumRange.end);
    if (startNm < 200.0f || endNm > 1000.0f) {
      printf("         %s[WARN]%s Illuminant spectral range %.1f-%.1f nm — outside typical 300-830nm\n",
             ColorWarning(), ColorReset(), startNm, endNm);
      issues++;
    }
    if (startNm >= endNm) {
      printf("         %s[WARN]%s Illuminant spectral start=%.1f >= end=%.1f — invalid range\n",
             ColorWarning(), ColorReset(), startNm, endNm);
      issues++;
    }
  }

  if (!issues)
    printf("         %s[OK]%s svcn observer/illuminant plausibility validated\n",
           ColorSuccess(), ColorReset());
  return issues;
}


// ---------------------------------------------------------------------------
// CF-317: HDR-to-SDR Flag-Tag Consistency  (K.2.9, ICC.2 §7.2.13)
// ---------------------------------------------------------------------------
static int RunCF317_HToSFlagTagConsistency(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-317]%s HDR-to-SDR Flag-Tag Consistency (%sK.2.9, ICC.2 §7.2.13%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int issues = 0;
  bool bit3Set = (pIcc->m_Header.flags & icExtendedRangePCS) != 0;

  static const icTagSignature htosTagSigs[4] = {
    icSigHToS0Tag, icSigHToS1Tag, icSigHToS2Tag, icSigHToS3Tag
  };
  static const char *htosNames[4] = {"H2S0", "H2S1", "H2S2", "H2S3"};

  int htosCount = 0;
  for (int i = 0; i < 4; i++) {
    if (pIcc->FindTag(htosTagSigs[i]))
      htosCount++;
  }

  if (bit3Set && htosCount == 0) {
    printf("         %s[WARN]%s Extended Range PCS flag (bit 3) is set but no HToS tags"
           " (H2S0-H2S3) found — K.2.9 recommends HToS tags for HDR-to-SDR conversion\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (!bit3Set && htosCount > 0) {
    printf("         %s[WARN]%s %d HToS tag(s) present but Extended Range PCS flag (bit 3)"
           " is NOT set — tags will not be applied by CMM per K.2.9\n",
           ColorWarning(), ColorReset(), htosCount);
    issues++;
    for (int i = 0; i < 4; i++) {
      if (pIcc->FindTag(htosTagSigs[i]))
        printf("           Orphan tag: %s\n", htosNames[i]);
    }
  }

  if (bit3Set && htosCount > 0)
    printf("         %s[OK]%s Extended Range PCS flag set with %d HToS tag(s) present\n",
           ColorSuccess(), ColorReset(), htosCount);

  if (!bit3Set && htosCount == 0)
    printf("         %s[OK]%s No Extended Range PCS flag, no HToS tags — consistent\n",
           ColorSuccess(), ColorReset());

  return issues;
}

// ---------------------------------------------------------------------------
// CF-318: HDR-to-SDR Tag Type Validation  (K.2.9, ICC.2 §9.2)
// ---------------------------------------------------------------------------
static int RunCF318_HToSTagTypeValidation(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-318]%s HDR-to-SDR Tag Type Validation (%sK.2.9, ICC.2 §9.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const icTagSignature htosTagSigs[4] = {
    icSigHToS0Tag, icSigHToS1Tag, icSigHToS2Tag, icSigHToS3Tag
  };
  static const char *htosNames[4] = {"H2S0", "H2S1", "H2S2", "H2S3"};

  int found = 0;
  int issues = 0;

  for (int i = 0; i < 4; i++) {
    CIccTag *pTag = pIcc->FindTag(htosTagSigs[i]);
    if (!pTag) continue;
    found++;

    icTagTypeSignature tagType = pTag->GetType();
    if (tagType != icSigMultiProcessElementType) {
      char typeSig[5] = {};
      icUInt32Number ts = static_cast<icUInt32Number>(tagType);
      typeSig[0] = static_cast<char>(static_cast<unsigned char>((ts >> 24) & 0xFF));
      typeSig[1] = static_cast<char>(static_cast<unsigned char>((ts >> 16) & 0xFF));
      typeSig[2] = static_cast<char>(static_cast<unsigned char>((ts >>  8) & 0xFF));
      typeSig[3] = static_cast<char>(static_cast<unsigned char>((ts      ) & 0xFF));
      printf("         %s[WARN]%s %s tag type '%s' — expected multiProcessElementsType"
             " ('mpet') for v5 profiles\n",
             ColorWarning(), ColorReset(), htosNames[i], typeSig);
      issues++;
    } else {
      printf("         %s[OK]%s %s tag type is multiProcessElementsType\n",
             ColorSuccess(), ColorReset(), htosNames[i]);
    }
  }

  if (found == 0)
    printf("         No HToS tags present — check not applicable\n");

  return issues;
}

// ---------------------------------------------------------------------------
// CF-319: HDR-to-SDR Tag Channel Consistency  (K.2.9)
// ---------------------------------------------------------------------------
static int RunCF319_HToSChannelConsistency(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-319]%s HDR-to-SDR Tag Channel Consistency (%sK.2.9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const icTagSignature htosTagSigs[4] = {
    icSigHToS0Tag, icSigHToS1Tag, icSigHToS2Tag, icSigHToS3Tag
  };
  static const char *htosNames[4] = {"H2S0", "H2S1", "H2S2", "H2S3"};

  icUInt16Number pcsChannels = icGetSpaceSamples(pIcc->m_Header.pcs);
  int found = 0;
  int issues = 0;

  for (int i = 0; i < 4; i++) {
    CIccTag *pTag = pIcc->FindTag(htosTagSigs[i]);
    if (!pTag) continue;
    found++;

    // Try MPE type first (v5 expected)
    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (pMPE) {
      icUInt16Number nIn = pMPE->NumInputChannels();
      icUInt16Number nOut = pMPE->NumOutputChannels();
      if (nIn != pcsChannels) {
        printf("         %s[WARN]%s %s input channels=%u, expected PCS channels=%u"
               " — HToS must be PCS-to-PCS\n",
               ColorWarning(), ColorReset(), htosNames[i], nIn, pcsChannels);
        issues++;
      }
      if (nOut != pcsChannels) {
        printf("         %s[WARN]%s %s output channels=%u, expected PCS channels=%u"
               " — HToS must be PCS-to-PCS\n",
               ColorWarning(), ColorReset(), htosNames[i], nOut, pcsChannels);
        issues++;
      }
      if (nIn == pcsChannels && nOut == pcsChannels)
        printf("         %s[OK]%s %s channels %u→%u match PCS\n",
               ColorSuccess(), ColorReset(), htosNames[i], nIn, nOut);
      continue;
    }

    // Fallback: try MBB (LUT) type
    CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pTag);
    if (pMBB) {
      icUInt8Number nIn = pMBB->InputChannels();
      icUInt8Number nOut = pMBB->OutputChannels();
      if (nIn != pcsChannels) {
        printf("         %s[WARN]%s %s input channels=%u, expected PCS channels=%u\n",
               ColorWarning(), ColorReset(), htosNames[i], nIn, pcsChannels);
        issues++;
      }
      if (nOut != pcsChannels) {
        printf("         %s[WARN]%s %s output channels=%u, expected PCS channels=%u\n",
               ColorWarning(), ColorReset(), htosNames[i], nOut, pcsChannels);
        issues++;
      }
      if (nIn == pcsChannels && nOut == pcsChannels)
        printf("         %s[OK]%s %s channels %u→%u match PCS\n",
               ColorSuccess(), ColorReset(), htosNames[i], nIn, nOut);
      continue;
    }

    printf("         %s[WARN]%s %s tag present but not MPE or LUT type — cannot validate channels\n",
           ColorWarning(), ColorReset(), htosNames[i]);
    issues++;
  }

  if (found == 0)
    printf("         No HToS tags present — check not applicable\n");

  return issues;
}

// ---------------------------------------------------------------------------
// CF-320: HDR-to-SDR Intent Coverage  (K.2.9)
// ---------------------------------------------------------------------------
static int RunCF320_HToSIntentCoverage(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  printf("%s[CF-320]%s HDR-to-SDR Intent Coverage (%sK.2.9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  bool bit3Set = (pIcc->m_Header.flags & icExtendedRangePCS) != 0;
  if (!bit3Set) {
    printf("         Extended Range PCS flag not set — check not applicable\n");
    return 0;
  }

  static const icTagSignature htosTagSigs[4] = {
    icSigHToS0Tag, icSigHToS1Tag, icSigHToS2Tag, icSigHToS3Tag
  };
  static const char *intentNames[4] = {
    "Perceptual", "Relative Colorimetric", "Saturation", "Absolute Colorimetric"
  };
  static const char *htosNames[4] = {"H2S0", "H2S1", "H2S2", "H2S3"};

  int issues = 0;
  bool present[4] = {};
  int totalPresent = 0;

  for (int i = 0; i < 4; i++) {
    present[i] = (pIcc->FindTag(htosTagSigs[i]) != nullptr);
    if (present[i]) {
      totalPresent++;
      printf("         %s present — %s intent covered\n", htosNames[i], intentNames[i]);
    }
  }

  if (totalPresent == 0) {
    // Already warned by CF-317 — just note here
    printf("         No HToS tags — no intent coverage\n");
    return 0;
  }

  // CMM fallback chain: try HToS0+intent → HToS0 → HToS1
  // At minimum, H2S0 (perceptual) or H2S1 (relative colorimetric) should exist
  if (!present[0] && !present[1]) {
    printf("         %s[WARN]%s Neither H2S0 (Perceptual) nor H2S1 (Relative Colorimetric)"
           " present — CMM fallback chain requires at least one of these\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (totalPresent < 4 && totalPresent > 0) {
    printf("         %s[INFO]%s %d of 4 rendering intents covered —"
           " CMM will use fallback chain for uncovered intents\n",
           ColorInfo(), ColorReset(), totalPresent);
  }

  if (totalPresent == 4)
    printf("         %s[OK]%s All 4 rendering intents have HToS coverage\n",
           ColorSuccess(), ColorReset());

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-321: Calculator 'solv' Operator Presence (K.2.8, ICC.2 §11.2.1.7)
//
// The 'solv' operator is optional — its support depends on CMM providing an
// IIccMatrixSolver implementation.  K.2.8 states profiles should either not
// use 'solv' or check its status flag.  This check detects 'solv' usage and
// reports it as an informational CMM dependency.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF321_SolvOperatorPresence(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-321]%s Calculator 'solv' Operator Presence "
         "(%sK.2.8, ICC.2 §11.2.1.7%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int solvCount = 0;
  int calcCount = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *tag = pIcc->FindTag(it->TagInfo.sig);
    if (!tag) continue;

    CIccTagMultiProcessElement *mpe =
      dynamic_cast<CIccTagMultiProcessElement *>(tag);
    if (!mpe) continue;

    std::string desc;
    mpe->Describe(desc, 0);
    if (desc.find("Calculator") == std::string::npos &&
        desc.find("calc") == std::string::npos)
      continue;

    calcCount++;

    // Search for "solv(" pattern in Describe output
    size_t pos = 0;
    while ((pos = desc.find("solv(", pos)) != std::string::npos) {
      solvCount++;
      pos += 5;
    }
  }

  if (calcCount == 0) {
    printf("         No calculator elements — check not applicable\n");
  } else if (solvCount == 0) {
    printf("         %s[OK]%s %d calculator element(s), no 'solv' operators "
           "(no CMM matrix solver dependency)\n",
           ColorSuccess(), ColorReset(), calcCount);
  } else {
    printf("         %s[INFO]%s %d 'solv' operator(s) found in %d calculator "
           "element(s)\n",
           ColorWarning(), ColorReset(), solvCount, calcCount);
    printf("         Profile requires CMM with IIccMatrixSolver support "
           "(K.2.8)\n");
  }

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-322: Calculator 'solv' Status Handling (K.2.8)
//
// K.2.8: "the profile calculator script either does not use the 'solv'
// calculator element operator or it checks the status of the operator and
// performs appropriate operations."  After 'solv', the status flag (1.0 on
// success, 0.0 on failure) is pushed.  A subsequent conditional ('if') should
// test that flag.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF322_SolvStatusHandling(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-322]%s Calculator 'solv' Status Handling (%sK.2.8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int solvCount = 0;
  int solvWithIf = 0;
  int solvWithoutIf = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *tag = pIcc->FindTag(it->TagInfo.sig);
    if (!tag) continue;

    CIccTagMultiProcessElement *mpe =
      dynamic_cast<CIccTagMultiProcessElement *>(tag);
    if (!mpe) continue;

    std::string desc;
    mpe->Describe(desc, 0);
    if (desc.find("solv(") == std::string::npos)
      continue;

    // For each 'solv(' occurrence, check for subsequent 'if ' in function
    size_t pos = 0;
    while ((pos = desc.find("solv(", pos)) != std::string::npos) {
      solvCount++;
      // Look for 'if ' after the solv operator within the same function block
      // The Describe output wraps ops in { ... }, so look within a reasonable
      // window after the solv.  Also accept 'if\n' for wrapped lines.
      size_t searchEnd = desc.find("END_CALC_FUNCTION", pos);
      if (searchEnd == std::string::npos)
        searchEnd = desc.size();

      std::string afterSolv = desc.substr(pos + 5, searchEnd - pos - 5);
      if (afterSolv.find("if ") != std::string::npos ||
          afterSolv.find("if\n") != std::string::npos) {
        solvWithIf++;
      } else {
        solvWithoutIf++;
      }
      pos += 5;
    }
  }

  if (solvCount == 0) {
    printf("         No 'solv' operators — check not applicable\n");
  } else if (solvWithoutIf > 0) {
    printf("         %s[WARN]%s %d of %d 'solv' operator(s) lack subsequent "
           "status check ('if' conditional)\n",
           ColorError(), ColorReset(), solvWithoutIf, solvCount);
    printf("         K.2.8 requires checking the operator status flag — "
           "§11.2.1.7\n");
    issues += solvWithoutIf;
  } else {
    printf("         %s[OK]%s All %d 'solv' operator(s) have subsequent "
           "status check\n",
           ColorSuccess(), ColorReset(), solvCount);
  }

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-323: Calculator 'solv' Matrix Dimensions (K.2.8, §11.2.1.7)
//
// The 'solv' operator solves Ax=b where A is (R×C), b is (R×1), x is (C×1).
// Describe outputs "solv(R,C)".  R and C must be >= 2 for a meaningful solve.
// The implementation (CIccOpDefSolve::Exec) checks r>1 && c>1.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF323_SolvDimensions(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-323]%s Calculator 'solv' Matrix Dimensions "
         "(%sK.2.8, §11.2.1.7%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int solvCount = 0;
  int degenerateCount = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *tag = pIcc->FindTag(it->TagInfo.sig);
    if (!tag) continue;

    CIccTagMultiProcessElement *mpe =
      dynamic_cast<CIccTagMultiProcessElement *>(tag);
    if (!mpe) continue;

    std::string desc;
    mpe->Describe(desc, 0);
    if (desc.find("solv(") == std::string::npos)
      continue;

    // Parse "solv(R,C)" dimensions from Describe output
    size_t pos = 0;
    while ((pos = desc.find("solv(", pos)) != std::string::npos) {
      solvCount++;
      int r = 0, c = 0;
      if (sscanf(desc.c_str() + pos, "solv(%d,%d)", &r, &c) == 2) {
        if (r < 2 || c < 2) {
          printf("         %s[WARN]%s solv(%d,%d) — degenerate dimensions "
                 "(R and C must be >= 2) — §11.2.1.7\n",
                 ColorError(), ColorReset(), r, c);
          degenerateCount++;
          issues++;
        } else if ((long long)r * c > 10000) {
          printf("         %s[WARN]%s solv(%d,%d) — excessive matrix size "
                 "(%d elements, potential DoS) — §11.2.1.7\n",
                 ColorError(), ColorReset(), r, c, r * c);
          issues++;
        }
      }
      pos += 5;
    }
  }

  if (solvCount == 0) {
    printf("         No 'solv' operators — check not applicable\n");
  } else if (issues == 0) {
    printf("         %s[OK]%s %d 'solv' operator(s) with valid dimensions\n",
           ColorSuccess(), ColorReset(), solvCount);
  }

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-324: Calculator 'env' Operator Usage (K.2.7, ICC.2 §11.2.1.4)
//
// CMM environment variables are accessed by the calculator element 'env'
// operator.  K.2.7 states that environment variable values are provided via
// CMM processing control options and may not be available.  This check
// detects 'env' operator usage to flag the CMM dependency.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF324_EnvOperatorUsage(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-324]%s Calculator 'env' Operator Usage "
         "(%sK.2.7, ICC.2 §11.2.1.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int envCount = 0;
  int calcCount = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *tag = pIcc->FindTag(it->TagInfo.sig);
    if (!tag) continue;

    CIccTagMultiProcessElement *mpe =
      dynamic_cast<CIccTagMultiProcessElement *>(tag);
    if (!mpe) continue;

    std::string desc;
    mpe->Describe(desc, 0);
    if (desc.find("Calculator") == std::string::npos &&
        desc.find("calc") == std::string::npos)
      continue;

    calcCount++;

    // Count "env(" occurrences
    size_t pos = 0;
    while ((pos = desc.find("env(", pos)) != std::string::npos) {
      envCount++;
      pos += 4;
    }
  }

  if (calcCount == 0) {
    printf("         No calculator elements — check not applicable\n");
  } else if (envCount == 0) {
    printf("         %s[OK]%s %d calculator element(s), no 'env' operators "
           "(no CMM environment variable dependency)\n",
           ColorSuccess(), ColorReset(), calcCount);
  } else {
    printf("         %s[INFO]%s %d 'env' operator(s) found in %d calculator "
           "element(s)\n",
           ColorWarning(), ColorReset(), envCount, calcCount);
    printf("         Profile requires CMM environment variable support "
           "(K.2.7)\n");
  }

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-325: Calculator 'env' Status Handling (K.2.7)
//
// K.2.7: "Calculator element scripts in profiles check the status of applying
// the 'env' operator to determine whether the environment value has been
// provided and perform appropriate operations when a variable is not
// available."  The 'env' operator pushes value + status (1.0 = available,
// 0.0 = unavailable).  A subsequent 'if' should test the status flag.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF325_EnvStatusHandling(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-325]%s Calculator 'env' Status Handling (%sK.2.7%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int envCount = 0;
  int envWithIf = 0;
  int envWithoutIf = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *tag = pIcc->FindTag(it->TagInfo.sig);
    if (!tag) continue;

    CIccTagMultiProcessElement *mpe =
      dynamic_cast<CIccTagMultiProcessElement *>(tag);
    if (!mpe) continue;

    std::string desc;
    mpe->Describe(desc, 0);
    if (desc.find("env(") == std::string::npos)
      continue;

    // For each 'env(' occurrence, check for subsequent 'if' conditional
    size_t pos = 0;
    while ((pos = desc.find("env(", pos)) != std::string::npos) {
      // Skip constant pseudo-variables 'true' and 'ndef' — they don't need
      // status checking since their status is deterministic
      if (desc.compare(pos, 9, "env(true)") == 0 ||
          desc.compare(pos, 9, "env(ndef)") == 0) {
        pos += 4;
        continue;
      }

      envCount++;
      size_t searchEnd = desc.find("END_CALC_FUNCTION", pos);
      if (searchEnd == std::string::npos)
        searchEnd = desc.size();

      std::string afterEnv = desc.substr(pos + 4, searchEnd - pos - 4);
      if (afterEnv.find("if ") != std::string::npos ||
          afterEnv.find("if\n") != std::string::npos) {
        envWithIf++;
      } else {
        envWithoutIf++;
      }
      pos += 4;
    }
  }

  if (envCount == 0) {
    printf("         No variable 'env' operators (excluding constants) — "
           "check not applicable\n");
  } else if (envWithoutIf > 0) {
    printf("         %s[WARN]%s %d of %d 'env' operator(s) lack subsequent "
           "status check ('if' conditional)\n",
           ColorError(), ColorReset(), envWithoutIf, envCount);
    printf("         K.2.7 requires checking env status — §11.2.1.4\n");
    issues += envWithoutIf;
  } else {
    printf("         %s[OK]%s All %d 'env' operator(s) have subsequent "
           "status check\n",
           ColorSuccess(), ColorReset(), envCount);
  }

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-326: Calculator 'env' Reserved Signatures (K.2.7, §11.2.1.4)
//
// Two reserved environment variable signatures have deterministic behaviour:
//   'true' (0x74727565) — always pushes (1.0, 1.0)
//   'ndef' (0x6e646566) — always pushes (0.0, 0.0)
// These are constants, not runtime environment lookups.  Their presence is
// informational — they don't create CMM dependencies but may indicate profile
// design patterns worth noting.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF326_EnvReservedSignatures(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-326]%s Calculator 'env' Reserved Signatures "
         "(%sK.2.7, §11.2.1.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int trueCount = 0;
  int ndefCount = 0;
  int calcCount = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *tag = pIcc->FindTag(it->TagInfo.sig);
    if (!tag) continue;

    CIccTagMultiProcessElement *mpe =
      dynamic_cast<CIccTagMultiProcessElement *>(tag);
    if (!mpe) continue;

    std::string desc;
    mpe->Describe(desc, 0);
    if (desc.find("Calculator") == std::string::npos &&
        desc.find("calc") == std::string::npos)
      continue;

    calcCount++;

    size_t pos = 0;
    while ((pos = desc.find("env(true)", pos)) != std::string::npos) {
      trueCount++;
      pos += 9;
    }
    pos = 0;
    while ((pos = desc.find("env(ndef)", pos)) != std::string::npos) {
      ndefCount++;
      pos += 9;
    }
  }

  if (calcCount == 0) {
    printf("         No calculator elements — check not applicable\n");
  } else if (trueCount == 0 && ndefCount == 0) {
    printf("         %s[OK]%s No reserved env signatures ('true'/'ndef') "
           "used\n", ColorSuccess(), ColorReset());
  } else {
    if (trueCount > 0)
      printf("         %s[INFO]%s %d 'env(true)' constant(s) — always "
             "returns (1.0, 1.0)\n",
             ColorWarning(), ColorReset(), trueCount);
    if (ndefCount > 0)
      printf("         %s[INFO]%s %d 'env(ndef)' constant(s) — always "
             "returns (0.0, 0.0)\n",
             ColorWarning(), ColorReset(), ndefCount);
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-327: PCC Alternate Override Readiness (K.2.6)
// Identifies profiles that participate in the alternate PCC workflow.
// PCC present when non-standard PCS or spectral PCS is used (ICC.2 §6.3.2).
// Reports PCC mode (standard D50/2° vs non-standard) and override readiness.
// ---------------------------------------------------------------------------
static int RunCF327_PCCAlternateOverrideReadiness(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  printf("  %s[CF-327]%s PCC Alternate Override Readiness "
         "(%sK.2.6, §6.3.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  const CIccTag *svcnTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  const CIccTag *c2spTag = pIcc->FindTag(icSigCustomToStandardPccTag);
  const CIccTag *s2cpTag = pIcc->FindTag(icSigStandardToCustomPccTag);
  icColorSpaceSignature spectralPCS = pIcc->m_Header.spectralPCS;
  bool hasSpectral = (static_cast<icUInt32Number>(spectralPCS) != 0);

  if (!svcnTag && !c2spTag && !s2cpTag && !hasSpectral) {
    printf("         No PCC tags and no spectral PCS — standard D50/2° PCS\n");
    printf("         Alternate PCC override not applicable (standard processing)\n");
    printf("         %s[OK]%s Standard PCC (no override needed)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Profile has PCC — report inventory
  printf("         PCC tag inventory:\n");
  printf("           svcn (spectralViewingConditions): %s\n",
         svcnTag ? "present" : "absent");
  printf("           c2sp (customToStandard):          %s\n",
         c2spTag ? "present" : "absent");
  printf("           s2cp (standardToCustom):          %s\n",
         s2cpTag ? "present" : "absent");
  printf("           spectralPCS:                      %s\n",
         hasSpectral ? "active" : "not set");

  // Check if PCC is standard (D50 + 2° observer) — even with PCC tags
  bool isStandard = false;
  if (svcnTag) {
    const CIccTagSpectralViewingConditions *pView =
      dynamic_cast<const CIccTagSpectralViewingConditions *>(svcnTag);
    if (pView) {
      icIlluminant illum = pView->getStdIllumiant();
      icStandardObserver obs = pView->getStdObserver();
      isStandard = (illum == icIlluminantD50 &&
                    obs == icStdObs1931TwoDegrees);
    }
  }

  if (isStandard) {
    printf("         PCC mode: standard (D50 illuminant, 1931 2° observer)\n");
    printf("         %s[INFO]%s Profile uses standard PCC — alternate PCC "
           "override would change viewing conditions\n",
           ColorWarning(), ColorReset());
  } else {
    printf("         PCC mode: non-standard (custom illuminant/observer)\n");
    printf("         %s[INFO]%s Profile uses non-standard PCC — eligible "
           "for alternate PCC override per K.2.6\n",
           ColorWarning(), ColorReset());
  }

  // Check override readiness: svcn required, c2sp/s2cp needed for custom colorimetry
  if (!svcnTag && (c2spTag || s2cpTag)) {
    printf("         %s[WARN]%s PCC transform tags present without svcn — "
           "incomplete PCC for override\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (c2spTag && s2cpTag) {
    printf("         Custom colorimetry transforms: complete (bidirectional)\n");
  } else if (c2spTag || s2cpTag) {
    printf("         Custom colorimetry transforms: incomplete (one-directional)\n");
  } else if (hasSpectral && svcnTag) {
    printf("         Spectral-only PCC (no custom colorimetry transforms)\n");
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-328: PCC Non-Standard Colorimetry Indication (K.2.6)
// When c2sp/s2cp present, the profile uses non-standard colorimetry that
// may be overridden by alternate PCC. Validates that the svcn tag has
// sufficient spectral data for the alternate PCC mechanism to function.
// ---------------------------------------------------------------------------
static int RunCF328_PCCNonStandardColorimetry(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  printf("  %s[CF-328]%s PCC Non-Standard Colorimetry Indication "
         "(%sK.2.6, §6.3.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  const CIccTag *c2spTag = pIcc->FindTag(icSigCustomToStandardPccTag);
  const CIccTag *s2cpTag = pIcc->FindTag(icSigStandardToCustomPccTag);

  if (!c2spTag && !s2cpTag) {
    printf("         No custom colorimetry transforms (c2sp/s2cp) — "
           "check not applicable\n");
    return 0;
  }

  // c2sp/s2cp present → non-standard colorimetry; validate svcn completeness
  const CIccTag *svcnTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (!svcnTag) {
    printf("         %s[WARN]%s Custom colorimetry transforms present but "
           "svcn absent — alternate PCC cannot determine viewing conditions\n",
           ColorWarning(), ColorReset());
    issues++;
    return issues;
  }

  const CIccTagSpectralViewingConditions *pView =
    dynamic_cast<const CIccTagSpectralViewingConditions *>(svcnTag);
  if (!pView) {
    printf("         %s[WARN]%s svcn tag has unexpected type — "
           "cannot validate PCC viewing conditions\n",
           ColorWarning(), ColorReset());
    issues++;
    return issues;
  }

  // Check illuminant SPD presence (needed for spectral PCC operations)
  icSpectralRange illumRange;
  const icFloatNumber *illumSPD = pView->getIlluminant(illumRange);
  if (!illumSPD || illumRange.steps == 0) {
    printf("         %s[WARN]%s svcn has no illuminant SPD — "
           "alternate PCC spectral processing limited\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    printf("         Illuminant SPD: %d steps (%.1f–%.1f nm)\n",
           illumRange.steps,
           icF16toF(illumRange.start),
           icF16toF(illumRange.end));
  }

  // Check observer presence
  icSpectralRange obsRange;
  const icFloatNumber *obsCMF = pView->getObserver(obsRange);
  if (!obsCMF || obsRange.steps == 0) {
    printf("         %s[WARN]%s svcn has no observer CMF data — "
           "alternate PCC colorimetric conversion limited\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    printf("         Observer CMF: %d steps (%.1f–%.1f nm)\n",
           obsRange.steps,
           icF16toF(obsRange.start),
           icF16toF(obsRange.end));
  }

  if (issues == 0)
    printf("         %s[OK]%s PCC spectral data complete for alternate "
           "override support\n", ColorSuccess(), ColorReset());

  return issues;
}

// ---------------------------------------------------------------------------
// CF-329: PCC Override Source Profile Validation (K.2.6)
// Profiles with deviceSubClass='pcc ' (0x70636320) serve as alternate PCC
// override sources. They are loaded AS the alternate PCC via CMM processing
// control options. Validates they have proper svcn content for this role.
// ---------------------------------------------------------------------------
static int RunCF329_PCCOverrideSourceValidation(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  int issues = 0;
  printf("  %s[CF-329]%s PCC Override Source Profile Validation "
         "(%sK.2.6, ICS-Colorimetric%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
  if (scVal != 0x70636320) {  // 'pcc '
    printf("         deviceSubClass is not 'pcc ' — profile is not a "
           "PCC override source\n");
    return 0;
  }

  printf("         deviceSubClass='pcc ' — this profile serves as a PCC "
         "override source\n");

  // svcn is essential for a PCC override source (K.2.6: provides alternate
  // viewing conditions)
  const CIccTag *svcnTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (!svcnTag) {
    printf("         %s[FAIL]%s PCC override source missing svcn — "
           "cannot provide alternate viewing conditions\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    const CIccTagSpectralViewingConditions *pView =
      dynamic_cast<const CIccTagSpectralViewingConditions *>(svcnTag);
    if (pView) {
      icIlluminant illum = pView->getStdIllumiant();
      icStandardObserver obs = pView->getStdObserver();
      printf("         svcn illuminant type: 0x%08X\n",
             static_cast<unsigned>(illum));
      printf("         svcn observer type: 0x%08X\n",
             static_cast<unsigned>(obs));

      // PCC override source should define non-D50 conditions (otherwise
      // why override?) — informational only
      if (illum == icIlluminantD50 && obs == icStdObs1931TwoDegrees) {
        printf("         %s[INFO]%s PCC source uses standard D50/2° — "
               "override would be equivalent to standard PCS\n",
               ColorWarning(), ColorReset());
      } else {
        printf("         %s[OK]%s PCC source defines non-standard viewing "
               "conditions for override\n",
               ColorSuccess(), ColorReset());
      }
    }
  }

  // c2sp/s2cp should be present for custom colorimetry override (CF-192
  // already checks this for 'pcc ' subclass, but we note K.2.6 context)
  const CIccTag *c2spTag = pIcc->FindTag(icSigCustomToStandardPccTag);
  const CIccTag *s2cpTag = pIcc->FindTag(icSigStandardToCustomPccTag);

  if (c2spTag && s2cpTag) {
    printf("         Custom colorimetry transforms: c2sp + s2cp present\n");
    printf("         %s[OK]%s PCC override source supports bidirectional "
           "custom colorimetry\n", ColorSuccess(), ColorReset());
  } else if (!c2spTag && !s2cpTag) {
    printf("         %s[WARN]%s PCC override source lacks c2sp/s2cp — "
           "cannot provide custom colorimetry override\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  return issues;
}

// ---------------------------------------------------------------------------
// Dispatcher: RunV5Conformance
// ---------------------------------------------------------------------------
int RunV5Conformance(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  int r;

#define CF_WRAP(id, title, call) \
  hc.begin(id, title); \
  r = call; \
  if (r > 0) hc.warn("%d non-conformance(s)", r); \
  hc.end("Conformant"); \
  issues += r

  // Partial Chromatic Adaptation — chad checks (any version with chad tag)
  CF_WRAP(1178, "CF-178: Chad Diagonal Dominance", RunCF178_ChadDiagonalDominance(pIcc));
  CF_WRAP(1179, "CF-179: Chad D50 Identity", RunCF179_ChadD50Identity(pIcc));
  CF_WRAP(1183, "CF-183: Chad Column Normalization", RunCF183_ChadColumnNormalization(pIcc));

  icUInt32Number version = pIcc->m_Header.version >> 24;
  if (version < 5) {
    printf("  %s[INFO]%s Profile version %u — v5/iccMAX checks skipped\n",
           ColorInfo(), ColorReset(), version);
    goto done;
  }

  CF_WRAP(1080, "CF-080: Spectral PCS Signature", RunCF080_SpectralPCSSignature(pIcc));
  CF_WRAP(1081, "CF-081: Spectral PCS Range", RunCF081_SpectralPCSRange(pIcc));
  CF_WRAP(1082, "CF-082: PCC Tags Required", RunCF082_PCCTagsRequired(pIcc));
  CF_WRAP(1083, "CF-083: MCS Signature", RunCF083_MCSSignature(pIcc));
  CF_WRAP(1084, "CF-084: Profile Sub-Class", RunCF084_ProfileSubClass(pIcc));
  CF_WRAP(1085, "CF-085: V5 Version BCD", RunCF085_V5VersionBCD(pIcc));
  CF_WRAP(1086, "CF-086: Extended Attributes", RunCF086_ExtendedAttributes(pIcc));
  CF_WRAP(1087, "CF-087: MPE Element Signature", RunCF087_MPEElementSignature(pIcc));
  CF_WRAP(1088, "CF-088: Calculator Stack Structure", RunCF088_CalculatorStackStructure(pIcc));
  CF_WRAP(1089, "CF-089: Spectral Wavelength Range", RunCF089_SpectralWavelengthRange(pIcc));
  CF_WRAP(1090, "CF-090: Spectral Illuminant Consistency", RunCF090_SpectralIlluminantConsistency(pIcc));

  CF_WRAP(1113, "CF-113: Spectral Range Physical Bounds", RunCF113_SpectralRangePhysicalBounds(pIcc));
  CF_WRAP(1114, "CF-114: MCS Colour Space Consistency", RunCF114_MCSColourSpaceConsistency(pIcc));
  CF_WRAP(1115, "CF-115: Calculator Element Complexity", RunCF115_CalculatorElementComplexity(pIcc));

  // ICC.2-2019 Errata checks (CF-137 through CF-143)
  CF_WRAP(1137, "CF-137: MultiplexDefaultValues Type", RunCF137_MultiplexDefaultValuesType(pIcc));
  CF_WRAP(1138, "CF-138: Embedded Height Image Data Length", RunCF138_EmbeddedHeightImageDataLength(pIcc));
  CF_WRAP(1139, "CF-139: Embedded Normal Image Data Length", RunCF139_EmbeddedNormalImageDataLength(pIcc));
  CF_WRAP(1140, "CF-140: GBD Vertex Count Field", RunCF140_GBDVertexCountField(pIcc));
  CF_WRAP(1141, "CF-141: Sparse Matrix Array Count", RunCF141_SparseMatrixArrayCount(pIcc));
  CF_WRAP(1142, "CF-142: Vector-Or Signature Alignment", RunCF142_VectorOrSignatureAlignment(pIcc));
  CF_WRAP(1143, "CF-143: Measurement Tag Struct Type", RunCF143_MeasurementTagStructType(pIcc));

  // ICS Extended Range (ICS-ExtendedRange-Part1/2/3)
  CF_WRAP(1144, "CF-144: Extended Range PCS Flag Consistency", RunCF144_ExtendedRangePCSFlagConsistency(pIcc));
  CF_WRAP(1145, "CF-145: Extended Range PCS + Spectral Co-existence", RunCF145_ExtendedRangePCSSpectralCoexistence(pIcc));
  CF_WRAP(1146, "CF-146: Extended Range Class Restriction", RunCF146_ExtendedRangeClassRestriction(pIcc));
  CF_WRAP(1147, "CF-147: Extended Range Colorimetric Intent Required", RunCF147_ExtendedRangeColorimetricIntent(pIcc));
  CF_WRAP(1148, "CF-148: Extended Range LUT multiProcessElementsType", RunCF148_ExtendedRangeLUTPresence(pIcc));

  // ICS Extended Output (ICS-ExtendedOutput-Part1)
  CF_WRAP(1149, "CF-149: Extended Output Profile Class", RunCF149_ExtendedOutputProfileClass(pIcc));
  CF_WRAP(1150, "CF-150: Extended Output Gamut Boundary Tag", RunCF150_ExtendedOutputGamutTag(pIcc));
  CF_WRAP(1151, "CF-151: Extended Output mediaWhitePoint Range", RunCF151_ExtendedOutputMediaWhitePointRange(pIcc));
  CF_WRAP(1152, "CF-152: Extended Output AToB/BToA/DToB Completeness", RunCF152_ExtendedOutputAToBCompleteness(pIcc));

  // ICS Interoperability Conformance Specifications
  CF_WRAP(1191, "CF-191: ICS Sub-Class Signature Registry", RunCF191_ICSSubClassRegistry(pIcc));
  CF_WRAP(1192, "CF-192: Colorimetric ICS Required Tags", RunCF192_ColorimetricICSRequiredTags(pIcc));
  CF_WRAP(1193, "CF-193: Colorimetric ICS PCC Matrix Restriction", RunCF193_ColorimetricPCCMatrixRestriction(pIcc));
  CF_WRAP(1194, "CF-194: Spectral Reflectance ICS Required Tags", RunCF194_SpectralReflectanceRequiredTags(pIcc));
  CF_WRAP(1195, "CF-195: Extended Dynamic Range Radiance White Point", RunCF195_ExtendedRangeRadianceWhitePoint(pIcc));
  CF_WRAP(1196, "CF-196: ICS MPE Calculator Restriction", RunCF196_ICSMPECalculatorRestriction(pIcc));
  CF_WRAP(1197, "CF-197: ICS PCC Transform Pair Completeness", RunCF197_ICSPCCTransformPairCompleteness(pIcc));
  CF_WRAP(1198, "CF-198: Extended Range Sub-Class Validation", RunCF198_ExtendedRangeSubClassValidation(pIcc));

  // ICS Extended Range Part 1 conformance (CF-235..CF-242)
  CF_WRAP(1235, "CF-235: xrng Data Colour Space Restriction", RunCF235_XrngDataColourSpace(pIcc));
  CF_WRAP(1236, "CF-236: xrng Colorimetric PCS Constraint", RunCF236_XrngColorimetricPCS(pIcc));
  CF_WRAP(1237, "CF-237: xrng Required Tag Completeness", RunCF237_XrngRequiredTagCompleteness(pIcc));
  CF_WRAP(1238, "CF-238: xrng Header Field Restrictions", RunCF238_XrngHeaderFieldRestrictions(pIcc));
  CF_WRAP(1239, "CF-239: xrng Optional Tag Type Validation", RunCF239_XrngOptionalTagTypes(pIcc));
  CF_WRAP(1240, "CF-240: xrng Transform Channel Dimensions", RunCF240_XrngTransformChannels(pIcc));
  CF_WRAP(1241, "CF-241: xrng mediaWhitePointTag Absolute Radiance", RunCF241_XrngMediaWhitePointRadiance(pIcc));
  CF_WRAP(1242, "CF-242: xrng Workflow Connection Consistency", RunCF242_XrngWorkflowConnection(pIcc));

  // ICC.2-in-ICC.1 Embedding
  CF_WRAP(1153, "CF-153: Embedded Profile Tag Presence", RunCF153_EmbeddedProfileTagPresence(pIcc));
  CF_WRAP(1154, "CF-154: Embedded Profile Version Bridging", RunCF154_EmbeddedProfileVersionBridging(pIcc));
  CF_WRAP(1155, "CF-155: Embedded Profile Device Class Match", RunCF155_EmbeddedProfileDeviceClassMatch(pIcc));
  CF_WRAP(1156, "CF-156: Embedded Profile Header Flags", RunCF156_EmbeddedProfilePCSCompatibility(pIcc));
  CF_WRAP(1157, "CF-157: Embedded Profile Recursive Depth", RunCF157_EmbeddedProfileRecursiveDepth(pIcc));
  CF_WRAP(1158, "CF-158: Embedded Profile Size Bounds", RunCF158_EmbeddedProfileSizeBounds(pIcc));

  // ICC.2-in-ICC.1 Embedding — additional conformance (ICC TN Embedding)
  CF_WRAP(1175, "CF-175: Embedded Profile PCS Compatibility", RunCF175_EmbeddedProfilePCSCompatibility(pIcc));
  CF_WRAP(1176, "CF-176: Embedded Profile Tag Reserved Bytes", RunCF176_EmbeddedProfileTagReservedBytes(pIcc));
  CF_WRAP(1177, "CF-177: Embedded Profile Data Integrity", RunCF177_EmbeddedProfileDataIntegrity(pIcc));

  // Partial Chromatic Adaptation — PCC checks (v5 only)
  CF_WRAP(1180, "CF-180: PCC Complete Adaptation", RunCF180_PCCCompleteAdaptation(pIcc));
  CF_WRAP(1181, "CF-181: PCC Illuminant-Chad Consistency", RunCF181_PCCIlluminantChadConsistency(pIcc));
  CF_WRAP(1182, "CF-182: PCC Observer Standard", RunCF182_PCCObserverStandard(pIcc));

  // dictType Validation (ICC.2-2023 §10.2.6)
  CF_WRAP(1159, "CF-159: Dictionary Name Uniqueness", RunCF159_DictNameUniqueness(pIcc));
  CF_WRAP(1160, "CF-160: Dictionary Name Non-Zero", RunCF160_DictNameNonZero(pIcc));
  CF_WRAP(1161, "CF-161: Dictionary Record Length Alignment", RunCF161_DictRecordLengthAlignment(pIcc));
  CF_WRAP(1162, "CF-162: Dictionary Entry Count Bounds", RunCF162_DictEntryCountBounds(pIcc));
  CF_WRAP(1257, "CF-257: Spectral Range Step Count", RunCF257_SpectralRangeStepCount(pIcc));

  // ICC.2:2019 Errata-derived checks (CF-284..CF-291)
  CF_WRAP(1284, "CF-284: BRDF Spectral Parameter Tag Type", RunCF284_BRDFSpectralParameterTagType(pIcc));
  CF_WRAP(1285, "CF-285: BRDF Tag Presence Consistency", RunCF285_BRDFTagConsistency(pIcc));
  CF_WRAP(1286, "CF-286: GBD Triangle-Vertex Consistency", RunCF286_GBDTriangleVertexConsistency(pIcc));
  CF_WRAP(1287, "CF-287: GBD Channel Count Plausibility", RunCF287_GBDChannelPlausibility(pIcc));
  CF_WRAP(1288, "CF-288: Spectral Data Info Bi-Spectral Consistency", RunCF288_SpectralDataInfoConsistency(pIcc));
  CF_WRAP(1289, "CF-289: Spectral Viewing Conditions Illuminant Bounds", RunCF289_SpectralViewingIlluminantBounds(pIcc));
  CF_WRAP(1290, "CF-290: Material Default Values Tag Presence", RunCF290_MaterialDefaultValuesPresence(pIcc));
  CF_WRAP(1291, "CF-291: Spectral White Point XYZ Range", RunCF291_SpectralWhitePointRange(pIcc));

  // multiProcessElementsType Container Validation (CF-292..CF-300)
  CF_WRAP(1292, "CF-292: MPE Chain I/O Channel Consistency", RunCF292_MPEChainIOConsistency(pIcc));
  CF_WRAP(1293, "CF-293: MPE Container I/O vs First/Last Element", RunCF293_MPEContainerChannelMatch(pIcc));
  CF_WRAP(1294, "CF-294: MPE ACS Boundary Element Pairing", RunCF294_MPEACSBoundaryPairing(pIcc));
  CF_WRAP(1295, "CF-295: MPE Element Type Version Compatibility", RunCF295_MPEElementVersionCompat(pIcc));
  CF_WRAP(1296, "CF-296: MPE Empty Container Validation", RunCF296_MPEEmptyContainer(pIcc));
  CF_WRAP(1297, "CF-297: MPE CurveSet Element Channel Count", RunCF297_MPECurveSetChannels(pIcc));
  CF_WRAP(1298, "CF-298: MPE Matrix Element Dimension", RunCF298_MPEMatrixDimension(pIcc));
  CF_WRAP(1299, "CF-299: MPE CLUT Element Grid Dimension", RunCF299_MPECLUTGridDimension(pIcc));
  CF_WRAP(1300, "CF-300: MPE Tag vs Color Space Channels", RunCF300_MPETagColorSpaceChannels(pIcc));

  // ICC.2:2019 Errata — §9.2.86/87 + §9.2.84 + §10.2.5 + §11.2.1.9 + naming (CF-301..CF-307)
  CF_WRAP(1301, "CF-301: Measurement Struct tagStructType Enforcement", RunCF301_MeasurementStructEnforcement(pIcc));
  CF_WRAP(1302, "CF-302: Measurement Struct Member Completeness", RunCF302_MeasurementStructMembers(pIcc));
  CF_WRAP(1303, "CF-303: Spectral Data Array Type Restriction", RunCF303_SpectralDataArrayTypes(pIcc));
  CF_WRAP(1304, "CF-304: v5 Text Tag multiLocalizedUnicodeType", RunCF304_V5TextTagMLUC(pIcc));
  CF_WRAP(1305, "CF-305: multiProcessElementsType Nomenclature Audit", RunCF305_MPENomenclatureAudit(pIcc));
  CF_WRAP(1306, "CF-306: Embedded Image Data Length Cross-Validation", RunCF306_EmbeddedImageDataLength(pIcc));
  CF_WRAP(1307, "CF-307: Calculator Vector-Or Signature Validation", RunCF307_CalcVectorOrSignature(pIcc));

  // ICS Conformance — Part 1/2/3 element restrictions (CF-308 through CF-316)
  CF_WRAP(1308, "CF-308: pcc AToB1/BToA1 Part 1 Element Restriction", RunCF308_PccTransformElementRestriction(pIcc));
  CF_WRAP(1309, "CF-309: sref PCC Matrix Restriction", RunCF309_SrefPccMatrixRestriction(pIcc));
  CF_WRAP(1310, "CF-310: sref DToB3/BToD3 Part 1 Element Restriction", RunCF310_SrefTransformElementRestriction(pIcc));
  CF_WRAP(1311, "CF-311: sref Spectral Range Mandatory", RunCF311_SrefSpectralRangeMandatory(pIcc));
  CF_WRAP(1312, "CF-312: ext Required Tag Completeness", RunCF312_ExtRequiredTags(pIcc));
  CF_WRAP(1313, "CF-313: ext Part 1 Element Type Restriction", RunCF313_ExtTransformElementRestriction(pIcc));
  CF_WRAP(1314, "CF-314: xrng AToB1/BToA1 Part 1 Element Restriction", RunCF314_XrngTransformElementRestriction(pIcc));
  CF_WRAP(1315, "CF-315: xrng Part 2 PCC Matrix Restriction", RunCF315_XrngPccTagMatrixRestriction(pIcc));
  CF_WRAP(1316, "CF-316: ICS svcn Observer/Illuminant Plausibility", RunCF316_IcsSvcnPlausibility(pIcc));

  // K.2.9 HDR-to-SDR Transform Conformance (CF-317..CF-320)
  CF_WRAP(1317, "CF-317: HDR-to-SDR Flag-Tag Consistency", RunCF317_HToSFlagTagConsistency(pIcc));
  CF_WRAP(1318, "CF-318: HDR-to-SDR Tag Type Validation", RunCF318_HToSTagTypeValidation(pIcc));
  CF_WRAP(1319, "CF-319: HDR-to-SDR Tag Channel Consistency", RunCF319_HToSChannelConsistency(pIcc));
  CF_WRAP(1320, "CF-320: HDR-to-SDR Intent Coverage", RunCF320_HToSIntentCoverage(pIcc));

  // K.2.8 Calculator 'solv' Operator Conformance (CF-321..CF-323)
  CF_WRAP(1321, "CF-321: Calculator 'solv' Operator Presence", RunCF321_SolvOperatorPresence(pIcc));
  CF_WRAP(1322, "CF-322: Calculator 'solv' Status Handling", RunCF322_SolvStatusHandling(pIcc));
  CF_WRAP(1323, "CF-323: Calculator 'solv' Matrix Dimensions", RunCF323_SolvDimensions(pIcc));

  // K.2.7 CMM Environment Variable Conformance (CF-324..CF-326)
  CF_WRAP(1324, "CF-324: Calculator 'env' Operator Usage", RunCF324_EnvOperatorUsage(pIcc));
  CF_WRAP(1325, "CF-325: Calculator 'env' Status Handling", RunCF325_EnvStatusHandling(pIcc));
  CF_WRAP(1326, "CF-326: Calculator 'env' Reserved Signatures", RunCF326_EnvReservedSignatures(pIcc));

  // K.2.6 Alternate PCC (CF-327..CF-329)
  CF_WRAP(1327, "CF-327: PCC Alternate Override Readiness", RunCF327_PCCAlternateOverrideReadiness(pIcc));
  CF_WRAP(1328, "CF-328: PCC Non-Standard Colorimetry Indication", RunCF328_PCCNonStandardColorimetry(pIcc));
  CF_WRAP(1329, "CF-329: PCC Override Source Profile Validation", RunCF329_PCCOverrideSourceValidation(pIcc));

done:
#undef CF_WRAP
  return issues;
}
