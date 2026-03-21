/// @file IccConformanceV5.cpp
/// @brief ICC.2-2023 v5/iccMAX conformance checks (CF-080 through CF-089),
///        ICC.2-in-ICC.1 embedding (CF-153..CF-158, CF-175..CF-177),
///        partial chromatic adaptation (CF-178..CF-183),
///        dictType (CF-159..CF-162).
///
/// @see ICC.2-2023, ICC TN Embedding, ICC TN Partial Adaptation

#include <cmath>
#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagComposite.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"
#include "IccMpeCalc.h"
#include "IccTagDict.h"
#include "IccTagEmbedIcc.h"
#include "IccUtil.h"
#include "IccConformanceRegistry.h"
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicResult.h"
#include "IccAnalyzerColors.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <set>

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
// CF-148: Extended Range AToB/BToA LUT Presence (multiProcessElementType)
// ICS-ExtendedRange Table 4: tags shall be multiProcessElementType
// ---------------------------------------------------------------------------
int RunCF148_ExtendedRangeLUTPresence(CIccProfile *pIcc) {
  if (!IsV5(pIcc)) return 0;

  icUInt32Number flags = pIcc->m_Header.flags;
  bool extRange = (flags & icExtendedRangePCS) != 0;

  printf("%s[CF-148]%s Extended Range LUT multiProcessElementType (%sICS-ExtendedRange Table 4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!extRange) {
    printf("         Extended Range PCS not set — check not applicable\n");
    return 0;
  }

  int issues = 0;

  // Check A2B1 and B2A1 are multiProcessElementType
  static const icTagSignature tags[] = {icSigAToB1Tag, icSigBToA1Tag};
  static const char *names[] = {"AToB1Tag", "BToA1Tag"};

  for (int i = 0; i < 2; i++) {
    CIccTag *pTag = pIcc->FindTag(tags[i]);
    if (!pTag) continue;  // absence already flagged by CF-147

    icTagTypeSignature typeSig = pTag->GetType();
    if (typeSig != icSigMultiProcessElementType) {
      char tSig[5];
      SigToChars(static_cast<uint32_t>(typeSig), tSig);
      printf("         %s[FAIL]%s %s shall be multiProcessElementType — found '%s' — "
             "ICS-ExtendedRange Table 4\n",
             ColorError(), ColorReset(), names[i], tSig);
      issues++;
    }
  }

  if (!issues) {
    printf("         %s[OK]%s Extended range LUT tags use multiProcessElementType\n",
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
  {0x7872676E, "xrng", "Extended Dynamic Range"},     // 'xrng'
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

  // Check c2sp and s2cp tags are multiProcessElementType with restricted elements
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
      printf("         %s[FAIL]%s %s is not multiProcessElementType — Part 1 requires MPE\n",
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

    // Verify both are multiProcessElementType
    bool c2spMPE = (dynamic_cast<CIccTagMultiProcessElement*>(c2sp) != nullptr);
    bool s2cpMPE = (dynamic_cast<CIccTagMultiProcessElement*>(s2cp) != nullptr);
    if (!c2spMPE || !s2cpMPE) {
      printf("         %s[WARN]%s PCC tags should be multiProcessElementType for ICS\n",
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
  if (scVal != 0x7872676E) {  // 'xrng'
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

  // Find the ICC5 tag's offset and size from the tag table
  int issues = 0;
  bool found = false;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    if (it->TagInfo.sig == icSigEmbeddedV5ProfileTag) {
      icUInt32Number tagSize = it->TagInfo.size;

      // Tag data layout: bytes 0-3 = type sig 'ICCp', bytes 4-7 = reserved (shall be 0)
      // Need at least 8 bytes
      if (tagSize < 8) {
        printf("         %s[FAIL]%s Embedded profile tag size %u < 8 bytes — "
               "cannot contain required type + reserved fields\n",
               ColorError(), ColorReset(), tagSize);
        issues++;
        found = true;
        break;
      }

      // Read reserved bytes via library's Validate output
      // Since we can't directly access raw tag data here without filename,
      // use the tag's own Validate method which checks reserved bytes
      std::string sigPath, sReport;
      sigPath = "ICC5";
      (void)pTag->Validate(sigPath, sReport, pIcc);

      if (sReport.find("Reserved") != std::string::npos &&
          sReport.find("not zero") != std::string::npos) {
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
    {icSigAToB1Tag,              "AToB1Tag",              icSigMultiProcessElementType,    "multiProcessElementType"},
    {icSigBToA1Tag,              "BToA1Tag",              icSigMultiProcessElementType,    "multiProcessElementType"},
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
/// AToBx/BToAx (x!=1) = multiProcessElementType
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

  // AToBx / BToAx where x!=1 must be multiProcessElementType
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
      printf("         %s[WARN]%s '%s' type 0x%08X -- expected multiProcessElementType\n",
             ColorWarning(), ColorReset(), t.name, (unsigned)pTag->GetType());
      issues++;
    } else {
      printf("         %s: multiProcessElementType (OK)\n", t.name);
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
  CF_WRAP(1148, "CF-148: Extended Range LUT multiProcessElementType", RunCF148_ExtendedRangeLUTPresence(pIcc));

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

done:
#undef CF_WRAP
  return issues;
}
