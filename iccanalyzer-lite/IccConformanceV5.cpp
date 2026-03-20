/// @file IccConformanceV5.cpp
/// @brief ICC.2-2023 v5/iccMAX conformance checks (CF-080 through CF-089).
///
/// Validates v5-specific profile features: spectral PCS, MCS, calculator elements,
/// extended attributes, and MPE element signatures. All checks skip profiles with
/// version < 5.
///
/// @see ICC.2-2023 (iccMAX specification)

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"
#include "IccMpeCalc.h"
#include "IccUtil.h"
#include "IccConformanceRegistry.h"
#include "IccHeuristicsHelpers.h"
#include "IccAnalyzerColors.h"
#include <cstdio>
#include <cstdint>
#include <cstring>

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

  CIccTag *svcnTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (!svcnTag) {
    printf("         %s[FAIL]%s Missing spectralViewingConditionsTag ('svcn') — required for spectral PCS — ICC.2-2023 §8\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         spectralViewingConditionsTag ('svcn'): present\n");
  }

  CIccTag *c2spTag = pIcc->FindTag(icSigCustomToStandardPccTag);
  CIccTag *s2cpTag = pIcc->FindTag(icSigStandardToCustomPccTag);

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

// ---------------------------------------------------------------------------
// Dispatcher: RunV5Conformance
// ---------------------------------------------------------------------------
int RunV5Conformance(CIccProfile *pIcc) {
  icUInt32Number version = pIcc->m_Header.version >> 24;
  if (version < 5) {
    printf("  %s[INFO]%s Profile version %u — v5/iccMAX checks skipped\n",
           ColorInfo(), ColorReset(), version);
    return 0;
  }

  int issues = 0;
  issues += RunCF080_SpectralPCSSignature(pIcc);
  issues += RunCF081_SpectralPCSRange(pIcc);
  issues += RunCF082_PCCTagsRequired(pIcc);
  issues += RunCF083_MCSSignature(pIcc);
  issues += RunCF084_ProfileSubClass(pIcc);
  issues += RunCF085_V5VersionBCD(pIcc);
  issues += RunCF086_ExtendedAttributes(pIcc);
  issues += RunCF087_MPEElementSignature(pIcc);
  issues += RunCF088_CalculatorStackStructure(pIcc);
  issues += RunCF089_SpectralWavelengthRange(pIcc);
  return issues;
}
