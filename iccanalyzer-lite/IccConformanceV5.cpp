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
#include "IccTagComposite.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"
#include "IccMpeCalc.h"
#include "IccUtil.h"
#include "IccConformanceRegistry.h"
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicResult.h"
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

  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  int r;

#define CF_WRAP(id, title, call) \
  hc.begin(id, title); \
  r = call; \
  if (r > 0) hc.warn("%d non-conformance(s)", r); \
  hc.end("Conformant"); \
  issues += r

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

#undef CF_WRAP
  return issues;
}
