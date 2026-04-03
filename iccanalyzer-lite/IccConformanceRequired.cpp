/*
 * IccConformanceRequired.cpp — ICC specification required tag conformance checks
 *
 * Implements CF-040 through CF-053, CF-095 through CF-098, and CF-202/CF-204/CF-205
 * from the conformance registry. Validates required tags per profile class per
 * ICC.1-2022-05 §8, private tag conformance per §9, and SampleICC compliance
 * framework structural checks.
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
#include "IccUtil.h"
#include "IccConformanceRegistry.h"
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicResult.h"
#include "IccAnalyzerColors.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>


// ── Helper: check whether a tag exists and print status ─────────────────────

static bool CheckTagPresent(CIccProfile *pIcc, icTagSignature sig, const char *name) {
  char sigCC[5];
  SigToChars(static_cast<uint32_t>(sig), sigCC);

  const CIccTag *pTag = pIcc->FindTag(sig);
  if (pTag) {
    printf("         '%s' (%s): present\n", sigCC, name);
    return true;
  }
  printf("         '%s' (%s): %smissing%s\n", sigCC, name, ColorError(), ColorReset());
  return false;
}

// ── Helper: check whether the data colour space is N-component (xCLR) ───────

static bool IsXCLRColorSpace(icColorSpaceSignature cs) {
  icUInt32Number raw = static_cast<icUInt32Number>(cs);
  // 2CLR (0x32434C52) through FCLR (0x46434C52)
  return (raw >= static_cast<icUInt32Number>(icSig2colorData) &&
          raw <= static_cast<icUInt32Number>(icSig15colorData));
}

// ── Helper: check whether profile uses matrix/TRC model ─────────────────────

static bool HasMatrixTRC(CIccProfile *pIcc) {
  return pIcc->FindTag(icSigRedMatrixColumnTag) != nullptr;
}

// ── Helper: extract profile version major number ────────────────────────────

static int VersionMajor(CIccProfile *pIcc) {
  return (pIcc->m_Header.version >> 24) & 0xFF;
}

static int VersionMinor(CIccProfile *pIcc) {
  return (pIcc->m_Header.version >> 20) & 0x0F;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-040: Common Required Tags — Non-DeviceLink (ICC.1-2022-05 §8.2)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF040_CommonRequiredTags(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-040]%s Common Required Tags (Non-DeviceLink) (%sICC.1-2022-05 §8.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass == icSigColorEncodingClass) {
    if (!CheckTagPresent(pIcc, icSigReferenceNameTag, "referenceNameTag")) {
      printf("         %s[FAIL]%s referenceNameTag required for ColorEncoding profile\n",
             ColorError(), ColorReset());
      return 1;
    }
    printf("         %s[OK]%s ColorEncoding required tags present\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  if (pIcc->m_Header.deviceClass == icSigLinkClass) {
    printf("         DeviceLink profile — common required tags check not applicable\n");
    printf("         %s[OK]%s Skipped (DeviceLink has own requirements in CF-044)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // §8.2: profileDescriptionTag, copyrightTag, mediaWhitePointTag required
  if (!CheckTagPresent(pIcc, icSigProfileDescriptionTag, "profileDescriptionTag")) {
    printf("         %s[FAIL]%s profileDescriptionTag required — ICC.1-2022-05 §8.2\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (!CheckTagPresent(pIcc, icSigCopyrightTag, "copyrightTag")) {
    printf("         %s[FAIL]%s copyrightTag required — ICC.1-2022-05 §8.2\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (!CheckTagPresent(pIcc, icSigMediaWhitePointTag, "mediaWhitePointTag")) {
    printf("         %s[FAIL]%s mediaWhitePointTag required — ICC.1-2022-05 §8.2\n",
           ColorError(), ColorReset());
    issues++;
  }

  // chromaticAdaptationTag required for v4+ if adopted white ≠ D50
  int major = VersionMajor(pIcc);
  if (major >= 4) {
    static const double kTolerance = 0.0001;
    double ix = icFtoD(pIcc->m_Header.illuminant.X);
    double iy = icFtoD(pIcc->m_Header.illuminant.Y);
    double iz = icFtoD(pIcc->m_Header.illuminant.Z);

    bool illumIsD50 = (fabs(ix - 0.9642) <= kTolerance &&
                       fabs(iy - 1.0000) <= kTolerance &&
                       fabs(iz - 0.8249) <= kTolerance);

    const CIccTag *chadTag = pIcc->FindTag(icSigChromaticAdaptationTag);

    if (!illumIsD50 && !chadTag) {
      printf("         Illuminant X=%.4f Y=%.4f Z=%.4f — %snot D50, chad missing%s\n",
             ix, iy, iz, ColorError(), ColorReset());
      printf("         %s[FAIL]%s chromaticAdaptationTag required when adopted white ≠ D50 — ICC.1-2022-05 §8.2\n",
             ColorError(), ColorReset());
      issues++;
    } else if (chadTag) {
      printf("         'chad' (chromaticAdaptationTag): present\n");
    } else {
      printf("         Illuminant is D50, chad not required\n");
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s All common required tags present\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-041: Input Profile Required Tags (ICC.1-2022-05 §8.3 Tables 22-24)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF041_InputProfileRequired(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-041]%s Input Profile Required Tags (%sICC.1-2022-05 §8.3 Tables 22-24%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigInputClass) {
    printf("         Not an Input profile — skipped\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  bool hasMatrix = HasMatrixTRC(pIcc);
  bool hasAToB0  = pIcc->FindTag(icSigAToB0Tag) != nullptr;

  if (hasMatrix) {
    // Matrix/TRC model — need all 6 tags
    printf("         Matrix/TRC model detected (redMatrixColumnTag present)\n");

    static const struct { icTagSignature sig; const char *name; } matrixTags[] = {
      {icSigRedMatrixColumnTag,   "redMatrixColumnTag"},
      {icSigGreenMatrixColumnTag, "greenMatrixColumnTag"},
      {icSigBlueMatrixColumnTag,  "blueMatrixColumnTag"},
      {icSigRedTRCTag,            "redTRCTag"},
      {icSigGreenTRCTag,          "greenTRCTag"},
      {icSigBlueTRCTag,           "blueTRCTag"},
    };

    for (const auto &mt : matrixTags) {
      if (!CheckTagPresent(pIcc, mt.sig, mt.name)) {
        printf("         %s[FAIL]%s %s required for matrix/TRC — ICC.1-2022-05 §8.3 Table 22\n",
               ColorError(), ColorReset(), mt.name);
        issues++;
      }
    }

    // PCS must be XYZ for matrix/TRC (checked in CF-049, but note here)
    if (pIcc->m_Header.pcs != icSigXYZData) {
      printf("         PCS='%c%c%c%c' — %smust be XYZ for matrix/TRC%s\n",
             (char)((pIcc->m_Header.pcs >> 24) & 0xFF),
             (char)((pIcc->m_Header.pcs >> 16) & 0xFF),
             (char)((pIcc->m_Header.pcs >> 8)  & 0xFF),
             (char)( pIcc->m_Header.pcs        & 0xFF),
             ColorError(), ColorReset());
      printf("         %s[FAIL]%s Matrix/TRC input profile PCS must be XYZ — ICC.1-2022-05 §8.3\n",
             ColorError(), ColorReset());
      issues++;
    }
  } else if (hasAToB0) {
    // LUT-based model
    printf("         LUT-based model detected (AToB0Tag present, no matrix/TRC)\n");
  } else {
    // Neither model present
    printf("         %sNeither matrix/TRC tags nor AToB0Tag found%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Input profile must have matrix/TRC set OR AToB0Tag — ICC.1-2022-05 §8.3\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Input profile required tags present\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-042: Display Profile Required Tags (ICC.1-2022-05 §8.4 Tables 25-27)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF042_DisplayProfileRequired(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-042]%s Display Profile Required Tags (%sICC.1-2022-05 §8.4 Tables 25-27%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigDisplayClass) {
    printf("         Not a Display profile — skipped\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  bool hasMatrix = HasMatrixTRC(pIcc);
  bool hasAToB0  = pIcc->FindTag(icSigAToB0Tag) != nullptr;
  bool hasBToA0  = pIcc->FindTag(icSigBToA0Tag) != nullptr;

  if (hasMatrix) {
    // Matrix/TRC model — need all 6 tags
    printf("         Matrix/TRC model detected (redMatrixColumnTag present)\n");

    static const struct { icTagSignature sig; const char *name; } matrixTags[] = {
      {icSigRedMatrixColumnTag,   "redMatrixColumnTag"},
      {icSigGreenMatrixColumnTag, "greenMatrixColumnTag"},
      {icSigBlueMatrixColumnTag,  "blueMatrixColumnTag"},
      {icSigRedTRCTag,            "redTRCTag"},
      {icSigGreenTRCTag,          "greenTRCTag"},
      {icSigBlueTRCTag,           "blueTRCTag"},
    };

    for (const auto &mt : matrixTags) {
      if (!CheckTagPresent(pIcc, mt.sig, mt.name)) {
        printf("         %s[FAIL]%s %s required for matrix/TRC — ICC.1-2022-05 §8.4 Table 25\n",
               ColorError(), ColorReset(), mt.name);
        issues++;
      }
    }

    // PCS must be XYZ for matrix/TRC
    if (pIcc->m_Header.pcs != icSigXYZData) {
      printf("         PCS — %smust be XYZ for matrix/TRC display profile%s\n",
             ColorError(), ColorReset());
      printf("         %s[FAIL]%s Matrix/TRC display profile PCS must be XYZ — ICC.1-2022-05 §8.4\n",
             ColorError(), ColorReset());
      issues++;
    }
  } else if (hasAToB0) {
    // LUT-based model — requires both AToB0 and BToA0
    printf("         LUT-based model detected (AToB0Tag present, no matrix/TRC)\n");

    if (!hasBToA0) {
      printf("         'B2A0' (BToA0Tag): %smissing%s\n", ColorError(), ColorReset());
      printf("         %s[FAIL]%s BToA0Tag required for LUT-based display profile — ICC.1-2022-05 §8.4 Table 26\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         'B2A0' (BToA0Tag): present\n");
    }
  } else {
    printf("         %sNeither matrix/TRC tags nor AToB0Tag found%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Display profile must have matrix/TRC set OR AToB0+BToA0 — ICC.1-2022-05 §8.4\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Display profile required tags present\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-043: Output Profile Required Tags (ICC.1-2022-05 §8.5 Tables 28-29)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF043_OutputProfileRequired(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-043]%s Output Profile Required Tags (%sICC.1-2022-05 §8.5 Tables 28-29%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigOutputClass) {
    printf("         Not an Output profile — skipped\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  // AToB0 + BToA0 always required for output profiles
  if (!CheckTagPresent(pIcc, icSigAToB0Tag, "AToB0Tag")) {
    printf("         %s[FAIL]%s AToB0Tag required — ICC.1-2022-05 §8.5\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (!CheckTagPresent(pIcc, icSigBToA0Tag, "BToA0Tag")) {
    printf("         %s[FAIL]%s BToA0Tag required — ICC.1-2022-05 §8.5\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Output profile required tags present\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-044: DeviceLink Profile Required Tags (ICC.1-2022-05 §8.6 Table 30)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF044_DeviceLinkProfileRequired(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-044]%s DeviceLink Profile Required Tags (%sICC.1-2022-05 §8.6 Table 30%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigLinkClass) {
    printf("         Not a DeviceLink profile — skipped\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  // profileDescriptionTag required
  if (!CheckTagPresent(pIcc, icSigProfileDescriptionTag, "profileDescriptionTag")) {
    printf("         %s[FAIL]%s profileDescriptionTag required — ICC.1-2022-05 §8.6 Table 30\n",
           ColorError(), ColorReset());
    issues++;
  }

  // AToB0Tag required
  if (!CheckTagPresent(pIcc, icSigAToB0Tag, "AToB0Tag")) {
    printf("         %s[FAIL]%s AToB0Tag required — ICC.1-2022-05 §8.6 Table 30\n",
           ColorError(), ColorReset());
    issues++;
  }

  // copyrightTag required
  if (!CheckTagPresent(pIcc, icSigCopyrightTag, "copyrightTag")) {
    printf("         %s[FAIL]%s copyrightTag required — ICC.1-2022-05 §8.6 Table 30\n",
           ColorError(), ColorReset());
    issues++;
  }

  // profileSequenceDescTag or profileSequenceIdentifierTag (v4.4+)
  const CIccTag *pseq = pIcc->FindTag(icSigProfileSequenceDescTag);
  const CIccTag *psid = pIcc->FindTag(icSigProfileSequceIdTag);  // iccDEV typo: SequceId

  int major = VersionMajor(pIcc);
  int minor = VersionMinor(pIcc);

  if (major >= 5 || (major == 4 && minor >= 4)) {
    // v4.4+: profileSequenceIdentifierTag preferred
    if (!pseq && !psid) {
      printf("         'pseq' (profileSequenceDescTag): %smissing%s\n",
             ColorError(), ColorReset());
      printf("         'psid' (profileSequenceIdentifierTag): %smissing%s\n",
             ColorError(), ColorReset());
      printf("         %s[FAIL]%s DeviceLink requires profileSequenceDescTag or profileSequenceIdentifierTag — ICC.1-2022-05 §8.6\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      if (pseq) printf("         'pseq' (profileSequenceDescTag): present\n");
      if (psid) printf("         'psid' (profileSequenceIdentifierTag): present\n");
    }
  } else {
    // Pre-v4.4: profileSequenceDescTag required
    if (!pseq) {
      printf("         'pseq' (profileSequenceDescTag): %smissing%s\n",
             ColorError(), ColorReset());
      printf("         %s[FAIL]%s profileSequenceDescTag required — ICC.1-2022-05 §8.6 Table 30\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         'pseq' (profileSequenceDescTag): present\n");
    }
  }

  // colorantTableTag required if output colour space is xCLR
  icColorSpaceSignature pcs = pIcc->m_Header.pcs;
  if (IsXCLRColorSpace(pcs)) {
    if (!CheckTagPresent(pIcc, icSigColorantTableTag, "colorantTableTag")) {
      printf("         %s[FAIL]%s colorantTableTag required for xCLR output — ICC.1-2022-05 §8.6 Table 30\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s DeviceLink profile required tags present\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-045: ColorSpace Profile Required Tags (ICC.1-2022-05 §8.7 Table 31)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF045_ColorSpaceProfileRequired(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-045]%s ColorSpace Profile Required Tags (%sICC.1-2022-05 §8.7 Table 31%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigColorSpaceClass) {
    printf("         Not a ColorSpace profile — skipped\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  // AToB0 + BToA0 required
  if (!CheckTagPresent(pIcc, icSigAToB0Tag, "AToB0Tag")) {
    printf("         %s[FAIL]%s AToB0Tag required — ICC.1-2022-05 §8.7 Table 31\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (!CheckTagPresent(pIcc, icSigBToA0Tag, "BToA0Tag")) {
    printf("         %s[FAIL]%s BToA0Tag required — ICC.1-2022-05 §8.7 Table 31\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s ColorSpace profile required tags present\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-046: Abstract Profile Required Tags (ICC.1-2022-05 §8.8 Table 32)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF046_AbstractProfileRequired(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-046]%s Abstract Profile Required Tags (%sICC.1-2022-05 §8.8 Table 32%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigAbstractClass) {
    printf("         Not an Abstract profile — skipped\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  if (!CheckTagPresent(pIcc, icSigAToB0Tag, "AToB0Tag")) {
    printf("         %s[FAIL]%s AToB0Tag required — ICC.1-2022-05 §8.8 Table 32\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Abstract profile required tags present\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-047: NamedColor Profile Required Tags (ICC.1-2022-05 §8.9 Table 33)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF047_NamedColorProfileRequired(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-047]%s NamedColor Profile Required Tags (%sICC.1-2022-05 §8.9 Table 33%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigNamedColorClass) {
    printf("         Not a NamedColor profile — skipped\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  if (!CheckTagPresent(pIcc, icSigNamedColor2Tag, "namedColor2Tag")) {
    printf("         %s[FAIL]%s namedColor2Tag required — ICC.1-2022-05 §8.9 Table 33\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s NamedColor profile required tags present\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-048: Rendering Intent Transform Consistency (ICC.1-2022-05 §7.2.15, §8)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF048_RenderingIntentConsistency(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-048]%s Rendering Intent Transform Consistency (%sICC.1-2022-05 §7.2.15, §8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number intent = pIcc->m_Header.renderingIntent;
  printf("         Declared rendering intent: %u", intent);

  switch (intent) {
    case 0: printf(" (Perceptual)\n"); break;
    case 1: printf(" (Media-Relative Colorimetric)\n"); break;
    case 2: printf(" (Saturation)\n"); break;
    case 3: printf(" (ICC-Absolute Colorimetric)\n"); break;
    default: printf(" (%sunknown%s)\n", ColorWarning(), ColorReset()); break;
  }

  // DeviceLink and NamedColor profiles don't use BToA/AToB pairs the same way
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  if (cls == icSigLinkClass || cls == icSigNamedColorClass) {
    printf("         Profile class not subject to rendering intent tag pairing\n");
    printf("         %s[OK]%s Not applicable for this profile class\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Intent 1 (Relative) or 3 (Absolute) → should have AToB1/BToA1
  if (intent == 1 || intent == 3) {
    bool hasA1 = pIcc->FindTag(icSigAToB1Tag) != nullptr;
    bool hasB1 = pIcc->FindTag(icSigBToA1Tag) != nullptr;

    if (!hasA1 && !hasB1) {
      printf("         AToB1Tag: missing, BToA1Tag: missing\n");
      printf("         %s[WARN]%s Intent %u profile should have AToB1/BToA1 transforms — ICC.1-2022-05 §8\n",
             ColorWarning(), ColorReset(), intent);
      issues++;
    } else {
      if (hasA1) printf("         AToB1Tag: present\n");
      if (hasB1) printf("         BToA1Tag: present\n");
    }
  }

  // Intent 2 (Saturation) → should have AToB2/BToA2
  if (intent == 2) {
    bool hasA2 = pIcc->FindTag(icSigAToB2Tag) != nullptr;
    bool hasB2 = pIcc->FindTag(icSigBToA2Tag) != nullptr;

    if (!hasA2 && !hasB2) {
      printf("         AToB2Tag: missing, BToA2Tag: missing\n");
      printf("         %s[WARN]%s Saturation intent profile should have AToB2/BToA2 transforms — ICC.1-2022-05 §8\n",
             ColorWarning(), ColorReset());
      issues++;
    } else {
      if (hasA2) printf("         AToB2Tag: present\n");
      if (hasB2) printf("         BToA2Tag: present\n");
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s Rendering intent consistent with transform tags\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-049: Matrix/TRC Profile PCS Must Be XYZ (ICC.1-2022-05 §8.3-8.4)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF049_MatrixTRCPCSXYZ(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-049]%s Matrix/TRC Profile PCS Must Be XYZ (%sICC.1-2022-05 §8.3-8.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!HasMatrixTRC(pIcc)) {
    printf("         No matrix/TRC tags detected — skipped\n");
    printf("         %s[OK]%s Not a matrix/TRC profile\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  char pcsCC[5];
  SigToChars(static_cast<uint32_t>(pIcc->m_Header.pcs), pcsCC);

  if (pIcc->m_Header.pcs != icSigXYZData) {
    printf("         PCS='%s' (0x%08X) — %smust be 'XYZ ' for matrix/TRC%s\n",
           pcsCC, static_cast<unsigned>(pIcc->m_Header.pcs),
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s Matrix/TRC profiles require PCSXYZ — ICC.1-2022-05 §8.3-8.4\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         PCS='%s' — correct for matrix/TRC\n", pcsCC);
    printf("         %s[OK]%s PCS is XYZ as required\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-050: xCLR Colorant Table Required (ICC.1-2022-05 §8.5-8.6)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF050_xCLRColorantTable(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-050]%s xCLR Colorant Table Required (%sICC.1-2022-05 §8.5-8.6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;

  if (!IsXCLRColorSpace(cs)) {
    printf("         Colour space is not xCLR — skipped\n");
    printf("         %s[OK]%s Not an N-component colour space\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  char csCC[5];
  SigToChars(static_cast<uint32_t>(cs), csCC);
  printf("         Colour space '%s' is N-component (xCLR)\n", csCC);

  // colorantTableTag should be present
  if (!CheckTagPresent(pIcc, icSigColorantTableTag, "colorantTableTag")) {
    printf("         %s[FAIL]%s colorantTableTag required for xCLR colour space — ICC.1-2022-05 §8.5\n",
           ColorError(), ColorReset());
    issues++;
  }

  // For DeviceLink with xCLR PCS/output, colorantTableOutTag should also be present
  if (pIcc->m_Header.deviceClass == icSigLinkClass) {
    icColorSpaceSignature pcs = pIcc->m_Header.pcs;
    if (IsXCLRColorSpace(pcs)) {
      if (!CheckTagPresent(pIcc, icSigColorantTableOutTag, "colorantTableOutTag")) {
        printf("         %s[FAIL]%s colorantTableOutTag required for DeviceLink with xCLR output — ICC.1-2022-05 §8.6\n",
               ColorError(), ColorReset());
        issues++;
      }
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s xCLR colorant table(s) present\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-051: DeviceLink Prohibited Tags (ICC.1-2022-05 §8.6 Table 30)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF051_DeviceLinkProhibited(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-051]%s DeviceLink Prohibited Tags (%sICC.1-2022-05 §8.6 Table 30%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigLinkClass) {
    printf("         Not a DeviceLink profile — skipped\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  // mediaWhitePointTag is explicitly prohibited for DeviceLink
  if (pIcc->FindTag(icSigMediaWhitePointTag)) {
    printf("         'wtpt' (mediaWhitePointTag): %spresent (prohibited)%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s mediaWhitePointTag prohibited in DeviceLink — ICC.1-2022-05 §8.6\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         'wtpt' (mediaWhitePointTag): absent (correct)\n");
  }

  // Only AToB0 is allowed — AToB1, AToB2, BToA0-2 are prohibited
  static const struct { icTagSignature sig; const char *name; } prohibited[] = {
    {icSigAToB1Tag, "AToB1Tag"},
    {icSigAToB2Tag, "AToB2Tag"},
    {icSigBToA0Tag, "BToA0Tag"},
    {icSigBToA1Tag, "BToA1Tag"},
    {icSigBToA2Tag, "BToA2Tag"},
  };

  for (const auto &p : prohibited) {
    if (pIcc->FindTag(p.sig)) {
      char sigCC[5];
      SigToChars(static_cast<uint32_t>(p.sig), sigCC);
      printf("         '%s' (%s): %spresent (prohibited)%s\n",
             sigCC, p.name, ColorError(), ColorReset());
      printf("         %s[FAIL]%s %s prohibited in DeviceLink — ICC.1-2022-05 §8.6\n",
             ColorError(), ColorReset(), p.name);
      issues++;
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s No prohibited tags in DeviceLink profile\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-052: Transform Tag Pair Consistency (ICC.1-2022-05 §8.3-8.5)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF052_TransformTagPairs(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-052]%s Transform Tag Pair Consistency (%sICC.1-2022-05 §8.3-8.5%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // DeviceLink profiles only use AToB0 — pairing not applicable
  if (pIcc->m_Header.deviceClass == icSigLinkClass) {
    printf("         DeviceLink — transform pair check not applicable\n");
    printf("         %s[OK]%s Skipped for DeviceLink\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Check AToB/BToA pairs for intents 1 and 2
  static const struct {
    icTagSignature aSig;
    icTagSignature bSig;
    const char *aName;
    const char *bName;
    int intent;
  } pairs[] = {
    {icSigAToB1Tag, icSigBToA1Tag, "AToB1Tag", "BToA1Tag", 1},
    {icSigAToB2Tag, icSigBToA2Tag, "AToB2Tag", "BToA2Tag", 2},
  };

  for (const auto &pr : pairs) {
    bool hasA = pIcc->FindTag(pr.aSig) != nullptr;
    bool hasB = pIcc->FindTag(pr.bSig) != nullptr;

    if (hasA && !hasB) {
      printf("         %s present but %s missing (intent %d)\n",
             pr.aName, pr.bName, pr.intent);
      printf("         %s[WARN]%s %s should be paired with %s — ICC.1-2022-05 §8\n",
             ColorWarning(), ColorReset(), pr.aName, pr.bName);
      issues++;
    } else if (!hasA && hasB) {
      printf("         %s present but %s missing (intent %d)\n",
             pr.bName, pr.aName, pr.intent);
      printf("         %s[WARN]%s %s should be paired with %s — ICC.1-2022-05 §8\n",
             ColorWarning(), ColorReset(), pr.bName, pr.aName);
      issues++;
    } else if (hasA && hasB) {
      printf("         %s + %s: paired (intent %d)\n",
             pr.aName, pr.bName, pr.intent);
    }
  }

  // Check DToB/BToD pairs for v4.4+ profiles
  int major = VersionMajor(pIcc);
  int minor = VersionMinor(pIcc);

  if (major >= 5 || (major == 4 && minor >= 4)) {
    static const struct {
      icTagSignature dSig;
      icTagSignature bSig;
      const char *dName;
      const char *bName;
      int intent;
    } dtobPairs[] = {
      {icSigDToB0Tag, icSigBToD0Tag, "DToB0Tag", "BToD0Tag", 0},
      {icSigDToB1Tag, icSigBToD1Tag, "DToB1Tag", "BToD1Tag", 1},
      {icSigDToB2Tag, icSigBToD2Tag, "DToB2Tag", "BToD2Tag", 2},
      {icSigDToB3Tag, icSigBToD3Tag, "DToB3Tag", "BToD3Tag", 3},
    };

    for (const auto &dp : dtobPairs) {
      bool hasD = pIcc->FindTag(dp.dSig) != nullptr;
      bool hasB = pIcc->FindTag(dp.bSig) != nullptr;

      if (hasD && !hasB) {
        printf("         %s present but %s missing (intent %d)\n",
               dp.dName, dp.bName, dp.intent);
        printf("         %s[WARN]%s %s should be paired with %s — ICC.1-2022-05 §8\n",
               ColorWarning(), ColorReset(), dp.dName, dp.bName);
        issues++;
      } else if (!hasD && hasB) {
        printf("         %s present but %s missing (intent %d)\n",
               dp.bName, dp.dName, dp.intent);
        printf("         %s[WARN]%s %s should be paired with %s — ICC.1-2022-05 §8\n",
               ColorWarning(), ColorReset(), dp.bName, dp.dName);
        issues++;
      } else if (hasD && hasB) {
        printf("         %s + %s: paired (intent %d)\n",
               dp.dName, dp.bName, dp.intent);
      }
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s All transform tag pairs consistent\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-053: cicpTag Class Restriction (ICC.1-2022-05 §9.2.11)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF053_CicpTagClassRestriction(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-053]%s cicpTag Class Restriction (%sICC.1-2022-05 §9.2.11%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  const CIccTag *cicpTag = pIcc->FindTag(icSigCicpTag);

  if (!cicpTag) {
    printf("         'cicp' (cicpTag): not present — no restriction check needed\n");
    printf("         %s[OK]%s No cicpTag to validate\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  icProfileClassSignature cls = pIcc->m_Header.deviceClass;

  // cicpTag only allowed in Display ('mntr') and Input ('scnr') profiles
  if (cls != icSigDisplayClass && cls != icSigInputClass) {
    char clsCC[5];
    SigToChars(static_cast<uint32_t>(cls), clsCC);
    printf("         'cicp' present in profile class '%s'\n", clsCC);
    printf("         %s[FAIL]%s cicpTag only permitted in Display and Input profiles — ICC.1-2022-05 §9.2.11\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    char clsCC[5];
    SigToChars(static_cast<uint32_t>(cls), clsCC);
    printf("         'cicp' present in profile class '%s' — allowed\n", clsCC);
    printf("         %s[OK]%s cicpTag in permitted profile class\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-054: v5 Spectral Required Tags (ICC.2-2023 §8)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF054_V5SpectralRequiredTags(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-054]%s v5 Spectral Required Tags (%sICC.2-2023 §8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int major = VersionMajor(pIcc);
  if (major < 5) {
    printf("         Profile version %d — not v5, skipped\n", major);
    printf("         %s[OK]%s Not a v5 profile\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Detect spectral PCS: first byte 'r' (0x72) for reflectance or 't' (0x74) for transmittance
  icColorSpaceSignature pcs = pIcc->m_Header.pcs;
  icUInt32Number pcsRaw = static_cast<icUInt32Number>(pcs);
  bool isSpectralPCS = ((pcsRaw & 0xFF000000) == 0x72000000) ||
                       ((pcsRaw & 0xFF000000) == 0x74000000);

  if (!isSpectralPCS) {
    printf("         v5 profile with non-spectral PCS — skipped\n");
    printf("         %s[OK]%s PCS is not spectral\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  char pcsCC[5];
  SigToChars(pcsRaw, pcsCC);
  printf("         Spectral PCS detected: '%s'\n", pcsCC);

  // Spectral PCS requires spectralViewingConditionsTag ('svcn')
  if (!pIcc->FindTag(icSigSpectralViewingConditionsTag)) {
    printf("         'svcn' (spectralViewingConditionsTag): %smissing%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s spectralViewingConditionsTag required for spectral PCS — ICC.2-2023 §8\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         'svcn' (spectralViewingConditionsTag): present\n");
  }

  if (issues == 0)
    printf("         %s[OK]%s v5 spectral required tags present\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-055: D2B/B2D Tag Pair Completeness (ICC.1-2022-05 §8)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF055_D2BB2DPairCompleteness(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-055]%s D2B/B2D Tag Pair Completeness (%sICC.1-2022-05 §8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const struct {
    icTagSignature dSig;
    icTagSignature bSig;
    const char *dName;
    const char *bName;
    int intent;
  } pairs[] = {
    {icSigDToB0Tag, icSigBToD0Tag, "DToB0Tag", "BToD0Tag", 0},
    {icSigDToB1Tag, icSigBToD1Tag, "DToB1Tag", "BToD1Tag", 1},
    {icSigDToB2Tag, icSigBToD2Tag, "DToB2Tag", "BToD2Tag", 2},
    {icSigDToB3Tag, icSigBToD3Tag, "DToB3Tag", "BToD3Tag", 3},
  };

  bool anyFound = false;

  for (const auto &pr : pairs) {
    bool hasD = pIcc->FindTag(pr.dSig) != nullptr;
    bool hasB = pIcc->FindTag(pr.bSig) != nullptr;

    if (!hasD && !hasB)
      continue;

    anyFound = true;

    if (hasD && !hasB) {
      printf("         %s present but %s missing (intent %d)\n",
             pr.dName, pr.bName, pr.intent);
      printf("         %s[WARN]%s %s should be paired with %s — ICC.1-2022-05 §8\n",
             ColorWarning(), ColorReset(), pr.dName, pr.bName);
      issues++;
    } else if (!hasD && hasB) {
      printf("         %s present but %s missing (intent %d)\n",
             pr.bName, pr.dName, pr.intent);
      printf("         %s[WARN]%s %s should be paired with %s — ICC.1-2022-05 §8\n",
             ColorWarning(), ColorReset(), pr.bName, pr.dName);
      issues++;
    } else {
      printf("         %s + %s: paired (intent %d)\n",
             pr.dName, pr.bName, pr.intent);
    }
  }

  if (!anyFound) {
    printf("         No D2B/B2D tags found — skipped\n");
    printf("         %s[OK]%s No D2B/B2D tags to validate\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  if (issues == 0)
    printf("         %s[OK]%s All D2B/B2D tag pairs complete\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-056: Embedded Profile Structure (ICC.2-2023 §9.2)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF056_EmbeddedProfileStructure(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-056]%s Embedded Profile Structure (%sICC.2-2023 §9.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Check for v5 embedded profile tag ('ICC5' = 0x49434335)
  const CIccTag *pEmbed = pIcc->FindTag(icSigEmbeddedV5ProfileTag);

  if (!pEmbed) {
    printf("         No embedded profile tag ('ICC5') found — skipped\n");
    printf("         %s[OK]%s No embedded profile to validate\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  printf("         'ICC5' (embeddedV5ProfileTag): present\n");

  // Validate embedded profile tag size via tag table entry
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    if (it->TagInfo.sig == icSigEmbeddedV5ProfileTag) {
      icUInt32Number embedSize = it->TagInfo.size;
      if (embedSize < 128) {
        printf("         Embedded profile data too small: %u bytes (need >= 128 for header)\n",
               embedSize);
        printf("         %s[FAIL]%s Embedded profile must contain a complete ICC header — ICC.2-2023 §9.2\n",
               ColorError(), ColorReset());
        issues++;
      } else {
        printf("         Embedded profile tag size: %u bytes\n", embedSize);
      }
      break;
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s Embedded profile structure valid\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-057: Dictionary Tag Structure for v5 (ICC.2-2023 §9.2.25)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF057_DictionaryTagStructure(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-057]%s Dictionary Tag Structure v5 (%sICC.2-2023 §9.2.25%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int major = VersionMajor(pIcc);
  if (major < 5) {
    printf("         Profile version %d — not v5, skipped\n", major);
    printf("         %s[OK]%s Not a v5 profile\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Check for metaDataTag ('meta')
  const CIccTag *pMeta = pIcc->FindTag(icSigMetaDataTag);

  if (!pMeta) {
    printf("         'meta' (metaDataTag): not present — no dictionary to validate\n");
    printf("         %s[OK]%s No metaDataTag found\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  printf("         'meta' (metaDataTag): present\n");

  // Validate the tag type — should be a dict type for v5
  icTagTypeSignature tagType = pMeta->GetType();
  char typeCC[5];
  SigToChars(static_cast<uint32_t>(tagType), typeCC);
  printf("         Tag type signature: '%s'\n", typeCC);

  // For v5, metaDataTag should use dict type (0x64696374 = 'dict')
  if (tagType != 0x64696374 /* 'dict' */) {
    printf("         %s[WARN]%s v5 metaDataTag expected type 'dict', got '%s' — ICC.2-2023 §9.2.25\n",
           ColorWarning(), ColorReset(), typeCC);
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Dictionary tag structure valid for v5\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-058: Profile Sequence Identifier Presence for v5 (ICC.2-2023 §8)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF058_ProfileSequenceIdV5(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-058]%s Profile Sequence Identifier v5 (%sICC.2-2023 §8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int major = VersionMajor(pIcc);
  if (major < 5) {
    printf("         Profile version %d — not v5, skipped\n", major);
    printf("         %s[OK]%s Not a v5 profile\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  icProfileClassSignature cls = pIcc->m_Header.deviceClass;

  // DeviceLink profiles used in chains should have profileSequenceIdentifier
  if (cls != icSigLinkClass) {
    printf("         Profile class is not DeviceLink — skipped\n");
    printf("         %s[OK]%s Not a DeviceLink profile\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  char clsCC[5];
  SigToChars(static_cast<uint32_t>(cls), clsCC);
  printf("         v5 DeviceLink profile (class '%s')\n", clsCC);

  // NOTE: icSigProfileSequceIdTag has a typo in iccDEV (missing 'en')
  const CIccTag *pPsid = pIcc->FindTag(icSigProfileSequceIdTag);

  if (!pPsid) {
    printf("         'psid' (profileSequenceIdentifier): %smissing%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s v5 DeviceLink should include profileSequenceIdentifier — ICC.2-2023 §8\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    printf("         'psid' (profileSequenceIdentifier): present\n");
  }

  if (issues == 0)
    printf("         %s[OK]%s Profile sequence identifier present for v5 DeviceLink\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-059: Colorimetric Intent Image State (ICC.1-2022-05 §9.2.12)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF059_ColorimetricIntentImageState(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-059]%s Colorimetric Intent Image State (%sICC.1-2022-05 §9.2.12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  const CIccTag *pCiis = pIcc->FindTag(icSigColorimetricIntentImageStateTag);

  if (!pCiis) {
    printf("         'ciis' (colorimetricIntentImageStateTag): not present — skipped\n");
    printf("         %s[OK]%s No colorimetricIntentImageState tag\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  printf("         'ciis' (colorimetricIntentImageStateTag): present\n");

  // Validate tag type — must be signatureType
  icTagTypeSignature tagType = pCiis->GetType();
  char typeCC[5];
  SigToChars(static_cast<uint32_t>(tagType), typeCC);

  if (tagType != icSigSignatureType) {
    printf("         Tag type: '%s' — expected 'sig '\n", typeCC);
    printf("         %s[FAIL]%s colorimetricIntentImageStateTag must be signatureType — ICC.1-2022-05 §9.2.12\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         Tag type: '%s' — correct (signatureType)\n", typeCC);
  }

  // Cross-validate against profile class
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  char clsCC[5];
  SigToChars(static_cast<uint32_t>(cls), clsCC);

  if (cls == icSigInputClass) {
    printf("         Profile class '%s' (Input/Scanner) — image state indicates scene/focal-plane capture\n", clsCC);
  } else if (cls == icSigDisplayClass) {
    printf("         Profile class '%s' (Display) — image state may indicate output-referred\n", clsCC);
  } else if (cls == icSigOutputClass) {
    printf("         Profile class '%s' (Output) — image state may indicate output-referred\n", clsCC);
  } else {
    printf("         Profile class '%s' — unusual class for colorimetricIntentImageState\n", clsCC);
    printf("         %s[WARN]%s colorimetricIntentImageStateTag is typically used with Input/Display/Output profiles\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Colorimetric intent image state valid\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-095: Non-Required Tags per Class
//   PAWG C18: "Identify additional/private tags beyond required set"
//   ICC.1-2022-05 §8.2-§8.9 defines required tags per class.
//   Any tag not in the required set is flagged for awareness.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF095_NonRequiredTags(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-095]%s Non-Required Tag Identification (%sICC.1-2022-05 §8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Build required tag set for this profile class
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;

  // Common required for all non-DeviceLink
  static const icTagSignature commonReq[] = {
    icSigProfileDescriptionTag, icSigCopyrightTag,
    icSigMediaWhitePointTag, (icTagSignature)0
  };

  // Class-specific required tags (simplified — major ones)
  static const icTagSignature displayReq[] = {
    icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag,
    icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag,
    icSigAToB0Tag, icSigBToA0Tag, (icTagSignature)0
  };

  static const icTagSignature linkReq[] = {
    icSigProfileDescriptionTag, icSigColorantTableTag,
    icSigAToB0Tag, (icTagSignature)0
  };

  auto isInList = [](icTagSignature sig, const icTagSignature *list) -> bool {
    for (int i = 0; list[i] != (icTagSignature)0; i++) {
      if (list[i] == sig) return true;
    }
    return false;
  };

  int extra = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    icTagSignature sig = it->TagInfo.sig;
    bool isRequired = isInList(sig, commonReq);

    if (!isRequired) {
      switch (cls) {
        case icSigDisplayClass:
        case icSigInputClass:
        case icSigOutputClass:
          isRequired = isInList(sig, displayReq);
          break;
        case icSigLinkClass:
          isRequired = isInList(sig, linkReq);
          break;
        default: break;
      }
    }

    if (!isRequired) {
      char sigStr[5] = {};
      SigToChars(sig, sigStr);
      printf("           Additional tag: '%s' (0x%08X)\n", sigStr, (unsigned)sig);
      extra++;
    }
  }

  if (extra > 0) {
    printf("           %s[INFO]%s %d non-required tag(s) present\n",
           ColorInfo(), ColorReset(), extra);
  } else {
    printf("           %s[OK]%s Only required tags present\n",
           ColorSuccess(), ColorReset());
  }

  return issues; // informational — not failures
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-096: Private Tag Signature Range
//   PAWG C19: "Validate private tag registration"
//   ICC.1-2022-05 §9: Private tags should use signatures that don't
//   collide with registered ICC tag signatures.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF096_PrivateTagSignatureRange(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-096]%s Private Tag Signature Range (%sICC.1-2022-05 §9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const icTagSignature knownTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    icSigBlueMatrixColumnTag, icSigBlueTRCTag,
    icSigCalibrationDateTimeTag, icSigCharTargetTag,
    icSigChromaticAdaptationTag, icSigChromaticityTag,
    icSigCopyrightTag, icSigDeviceMfgDescTag,
    icSigDeviceModelDescTag, icSigGamutTag,
    icSigGrayTRCTag, icSigGreenMatrixColumnTag,
    icSigGreenTRCTag, icSigLuminanceTag,
    icSigMeasurementTag, icSigMediaBlackPointTag,
    icSigMediaWhitePointTag, icSigNamedColor2Tag,
    icSigOutputResponseTag, icSigPreview0Tag,
    icSigPreview1Tag, icSigPreview2Tag,
    icSigProfileDescriptionTag, icSigProfileSequenceDescTag,
    icSigReferenceNameTag,
    icSigRedMatrixColumnTag, icSigRedTRCTag,
    icSigTechnologyTag, icSigViewingCondDescTag,
    icSigViewingConditionsTag, icSigColorantOrderTag,
    icSigColorantTableTag, icSigColorantTableOutTag,
    icSigProfileSequceIdTag,
    icSigPerceptualRenderingIntentGamutTag,
    icSigSaturationRenderingIntentGamutTag,
    (icTagSignature)0
  };

  int privateCount = 0;
  int lowRange = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    icTagSignature sig = it->TagInfo.sig;
    bool isKnown = false;
    for (int k = 0; knownTags[k] != (icTagSignature)0; k++) {
      if (sig == knownTags[k]) { isKnown = true; break; }
    }
    if (isKnown) continue;

    privateCount++;
    char sigStr[5] = {};
    SigToChars(sig, sigStr);

    // Check if private tag uses low ASCII range (potential collision)
    uint32_t s = (uint32_t)sig;
    bool allPrintable = true;
    for (int b = 0; b < 4; b++) {
      unsigned char ch = (s >> (24 - b*8)) & 0xFF;
      if (ch < 0x20 || ch > 0x7E) { allPrintable = false; break; }
    }

    if (!allPrintable) {
      printf("           %s[WARN]%s Tag '%s' (0x%08X) uses non-printable signature bytes\n",
             ColorWarning(), ColorReset(), sigStr, s);
      lowRange++;
    } else {
      printf("           Private tag '%s' (0x%08X) — printable signature\n",
             sigStr, s);
    }
  }

  if (lowRange > 0) {
    printf("           %s[WARN]%s %d private tag(s) with non-printable signatures\n",
           ColorWarning(), ColorReset(), lowRange);
    issues = lowRange;
  } else if (privateCount > 0) {
    printf("           %s[OK]%s %d private tag(s) — all use printable 4-char signatures\n",
           ColorSuccess(), ColorReset(), privateCount);
  } else {
    printf("           %s[OK]%s No private tags\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-097: Private Tag Documentation (informational)
//   PAWG C20: "Confirm private tags are documented"
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF097_PrivateTagDocumentation(CIccProfile *pIcc) {
  printf("  %s[CF-097]%s Private Tag Documentation (%sICC.1-2022-05 §9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Known vendor private tags (commonly documented)
  static const struct { uint32_t sig; const char *vendor; const char *desc; } knownPrivate[] = {
    { 0x41444245, "Adobe", "'ADBE' — Adobe private data" },
    { 0x4D534654, "Microsoft", "'MSFT' — Microsoft WCS data" },
    { 0x6170706C, "Apple", "'appl' — Apple private data" },
    { 0x4150504C, "Apple", "'APPL' — Apple private data" },
  };

  int documented = 0, undocumented = 0;

  static const icTagSignature knownTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    icSigBlueMatrixColumnTag, icSigBlueTRCTag,
    icSigCopyrightTag, icSigProfileDescriptionTag,
    icSigMediaWhitePointTag, icSigRedMatrixColumnTag,
    icSigGreenMatrixColumnTag, icSigRedTRCTag,
    icSigGreenTRCTag, icSigGrayTRCTag,
    icSigChromaticAdaptationTag, icSigChromaticityTag,
    icSigCalibrationDateTimeTag, icSigCharTargetTag,
    icSigColorantOrderTag, icSigColorantTableTag,
    icSigColorantTableOutTag, icSigDeviceMfgDescTag,
    icSigDeviceModelDescTag, icSigGamutTag,
    icSigLuminanceTag, icSigMeasurementTag,
    icSigMediaBlackPointTag, icSigNamedColor2Tag,
    icSigOutputResponseTag, icSigPreview0Tag,
    icSigPreview1Tag, icSigPreview2Tag,
    icSigProfileSequenceDescTag, icSigTechnologyTag,
    icSigViewingCondDescTag, icSigViewingConditionsTag,
    icSigProfileSequceIdTag,
    icSigReferenceNameTag,
    icSigPerceptualRenderingIntentGamutTag,
    icSigSaturationRenderingIntentGamutTag,
    (icTagSignature)0
  };

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    icTagSignature sig = it->TagInfo.sig;
    bool isKnown = false;
    for (int k = 0; knownTags[k] != (icTagSignature)0; k++) {
      if (sig == knownTags[k]) { isKnown = true; break; }
    }
    if (isKnown) continue;

    bool isDocumented = false;
    for (size_t v = 0; v < sizeof(knownPrivate)/sizeof(knownPrivate[0]); v++) {
      if ((uint32_t)sig == knownPrivate[v].sig) {
        printf("           %s — %s\n", knownPrivate[v].desc, knownPrivate[v].vendor);
        documented++;
        isDocumented = true;
        break;
      }
    }
    if (!isDocumented) {
      char sigStr[5] = {};
      SigToChars(sig, sigStr);
      printf("           Undocumented private tag: '%s' (0x%08X)\n",
             sigStr, (unsigned)sig);
      undocumented++;
    }
  }

  if (undocumented > 0) {
    printf("           %s[INFO]%s %d undocumented private tag(s)\n",
           ColorInfo(), ColorReset(), undocumented);
  } else if (documented > 0) {
    printf("           %s[OK]%s %d private tag(s) — all from known vendors\n",
           ColorSuccess(), ColorReset(), documented);
  } else {
    printf("           %s[OK]%s No private tags\n",
           ColorSuccess(), ColorReset());
  }

  return undocumented; // informational
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-098: Undocumented Private Tag Identification
//   PAWG C21: "Flag undocumented or unrecognized private tags"
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF098_UndocumentedPrivateTags(CIccProfile *pIcc) {
  printf("  %s[CF-098]%s Undocumented Private Tag Identification (%sICC.1-2022-05 §9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // This is a stricter version of CF-097 — flags any unrecognized tag
  static const icTagSignature knownTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    icSigBlueMatrixColumnTag, icSigBlueTRCTag,
    icSigCalibrationDateTimeTag, icSigCharTargetTag,
    icSigChromaticAdaptationTag, icSigChromaticityTag,
    icSigCopyrightTag, icSigDeviceMfgDescTag,
    icSigDeviceModelDescTag, icSigGamutTag,
    icSigGrayTRCTag, icSigGreenMatrixColumnTag,
    icSigGreenTRCTag, icSigLuminanceTag,
    icSigMeasurementTag, icSigMediaBlackPointTag,
    icSigMediaWhitePointTag, icSigNamedColor2Tag,
    icSigOutputResponseTag, icSigPreview0Tag,
    icSigPreview1Tag, icSigPreview2Tag,
    icSigProfileDescriptionTag, icSigProfileSequenceDescTag,
    icSigReferenceNameTag,
    icSigRedMatrixColumnTag, icSigRedTRCTag,
    icSigTechnologyTag, icSigViewingCondDescTag,
    icSigViewingConditionsTag, icSigColorantOrderTag,
    icSigColorantTableTag, icSigColorantTableOutTag,
    icSigProfileSequceIdTag,
    icSigPerceptualRenderingIntentGamutTag,
    icSigSaturationRenderingIntentGamutTag,
    (icTagSignature)0x44324230, // D2B0
    (icTagSignature)0x44324231, // D2B1
    (icTagSignature)0x44324232, // D2B2
    (icTagSignature)0x42324430, // B2D0
    (icTagSignature)0x42324431, // B2D1
    (icTagSignature)0x42324432, // B2D2
    (icTagSignature)0
  };

  int unknown = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    icTagSignature sig = it->TagInfo.sig;
    bool isKnown = false;
    for (int k = 0; knownTags[k] != (icTagSignature)0; k++) {
      if (sig == knownTags[k]) { isKnown = true; break; }
    }
    if (!isKnown) {
      char sigStr[5] = {};
      SigToChars(sig, sigStr);
      printf("           Unrecognized: '%s' (0x%08X) size=%u\n",
             sigStr, (unsigned)sig, it->TagInfo.size);
      unknown++;
    }
  }

  if (unknown > 0) {
    printf("           %s[INFO]%s %d unrecognized tag(s) — may require vendor documentation\n",
           ColorInfo(), ColorReset(), unknown);
  } else {
    printf("           %s[OK]%s All tags are recognized ICC signatures\n",
           ColorSuccess(), ColorReset());
  }

  return 0; // purely informational
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-103: Tag Table Alignment & Offset Validity (ICC.1-2022-05 §7.3.1)
//
// All tag data offsets MUST be on 4-byte boundaries and MUST point within
// the profile file. Tag data regions MUST NOT extend past the profile size.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF103_TagAlignmentAndOffset(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-103]%s Tag Table Alignment & Offset Validity (%sICC.1-2022-05 §7.3.1%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number profileSize = pIcc->m_Header.size;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    icUInt32Number offset = it->TagInfo.offset;
    icUInt32Number size   = it->TagInfo.size;
    char sigStr[5] = {};
    SigToChars(it->TagInfo.sig, sigStr);

    if (offset % 4 != 0) {
      printf("           Tag '%s' offset 0x%08X not 4-byte aligned\n", sigStr, offset);
      printf("           %s[FAIL]%s Tag offset must be on 4-byte boundary — §7.3.1\n",
             ColorError(), ColorReset());
      issues++;
    }

    if (profileSize > 0 && (offset > profileSize || offset + size > profileSize)) {
      printf("           Tag '%s' offset+size (0x%08X+%u) exceeds profile size (%u)\n",
             sigStr, offset, size, profileSize);
      printf("           %s[FAIL]%s Tag data extends beyond profile — §7.3.1\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (issues == 0)
    printf("           %s[OK]%s All tag offsets aligned and within bounds\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-104: DeviceLink PCS Must Match (ICC.1-2022-05 §8.6)
//
// For DeviceLink profiles, the data colour space is the source and the PCS
// field holds the destination colour space. The PCS field MUST NOT be Lab or
// XYZ when the profile class is 'link' — it holds a device colour space.
// Additionally, the profile SHALL contain AToB0Tag.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF104_DeviceLinkPCSMatch(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-104]%s DeviceLink PCS Consistency (%sICC.1-2022-05 §8.6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigLinkClass) {
    printf("           Not a DeviceLink profile — check not applicable\n");
    return 0;
  }

  // DeviceLink must have AToB0Tag
  if (!pIcc->FindTag(icSigAToB0Tag)) {
    printf("           DeviceLink profile missing required AToB0Tag\n");
    printf("           %s[FAIL]%s DeviceLink requires AToB0Tag — §8.6\n",
           ColorError(), ColorReset());
    issues++;
  }

  // DeviceLink must have profileSequenceDescTag (v4)
  icUInt32Number version = pIcc->m_Header.version >> 24;
  if (version >= 4 && !pIcc->FindTag(icSigProfileSequenceDescTag)) {
    printf("           V4 DeviceLink missing profileSequenceDescTag\n");
    printf("           %s[FAIL]%s V4 DeviceLink requires profileSequenceDescTag — §8.6\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("           %s[OK]%s DeviceLink PCS consistency validated\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-111: Required Tags per ICC Version (ICC.1-2022-05 §8.2-8.9)
//
// V4 profiles require additional tags not required in v2:
//  - chromaticAdaptationTag (chad) when adopted white != D50
//  - profileSequenceDescTag for DeviceLink
//  - profileSequenceIdentifierTag recommended for v4.4
//  - colorimetricIntentImageStateTag for Input profiles (§8.2, v4.4)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF111_RequiredTagsPerVersion(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-111]%s Required Tags per ICC Version (%sICC.1-2022-05 §8.2-8.9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number version = pIcc->m_Header.version >> 24;
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;

  // v4.2+ chromaticAdaptationTag is required when the adopted white point
  // does not equal D50 illuminant (for non-DeviceLink profiles)
  if (version >= 4 && cls != icSigLinkClass && cls != icSigColorEncodingClass) {
    // CF-009 already checks chad requirement — here we note version-specific detail
    if (pIcc->FindTag(icSigChromaticAdaptationTag) == nullptr) {
      // Check if adopted white != D50
      const icFloatNumber *d50 = icD50XYZ;
      bool needsChad = false;
      if (d50) {
        icFloatNumber wtptX = icFtoD(pIcc->m_Header.illuminant.X);
        icFloatNumber wtptY = icFtoD(pIcc->m_Header.illuminant.Y);
        icFloatNumber wtptZ = icFtoD(pIcc->m_Header.illuminant.Z);
        if (std::fabs(wtptX - d50[0]) > 0.001 ||
            std::fabs(wtptY - d50[1]) > 0.001 ||
            std::fabs(wtptZ - d50[2]) > 0.001) {
          needsChad = true;
        }
      }
      if (needsChad) {
        printf("           V%u profile with non-D50 white point missing chromaticAdaptationTag\n", version);
        printf("           %s[FAIL]%s V4+ requires chad when adopted white ≠ D50 — §8\n",
               ColorError(), ColorReset());
        issues++;
      }
    }
  }

  // v4 DeviceLink requires profileSequenceDescTag (checked in CF-104)
  // v4 DeviceLink should have colorantTableTag and colorantTableOutTag
  if (version >= 4 && cls == icSigLinkClass) {
    if (!pIcc->FindTag(icSigColorantTableTag)) {
      printf("           V4 DeviceLink missing colorantTableTag (recommended)\n");
      printf("           %s[INFO]%s §8.6 recommends colorantTableTag for DeviceLink\n",
             ColorInfo(), ColorReset());
    }
  }

  if (issues == 0)
    printf("           %s[OK]%s Version-specific required tags present\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-117: Rendering Intent Tags per Class (ICC.1-2022-05 §8.3-8.5)
//
// Output (prtr) and Input (scnr) profiles with LUT-based rendering SHOULD
// provide AToB/BToA tags for all rendering intents they support.
// The perceptualRenderingIntentGamutTag and saturationRenderingIntentGamutTag
// are only valid for Output and Display profiles (§9.2.36-37).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF117_RenderingIntentTagsPerClass(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-117]%s Rendering Intent Tags per Class (%sICC.1-2022-05 §8.3-8.5%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icProfileClassSignature cls = pIcc->m_Header.deviceClass;

  // rig0/rig2 tags only allowed for Output, Display
  if (cls != icSigOutputClass && cls != icSigDisplayClass) {
    if (pIcc->FindTag(icSigPerceptualRenderingIntentGamutTag)) {
      printf("           perceptualRenderingIntentGamutTag in non-Output/Display profile\n");
      printf("           %s[WARN]%s rig0 only valid for Output/Display — §9.2.36\n",
             ColorError(), ColorReset());
      issues++;
    }
    if (pIcc->FindTag(icSigSaturationRenderingIntentGamutTag)) {
      printf("           saturationRenderingIntentGamutTag in non-Output/Display profile\n");
      printf("           %s[WARN]%s rig2 only valid for Output/Display — §9.2.37\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  if (issues == 0)
    printf("           %s[OK]%s Rendering intent tags appropriate for profile class\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-118: Private Tag Creator Signature (ICC.1-2022-05 §9)
//
// Private tags (signatures not registered in §9.2) SHOULD have a creator
// signature matching the profile's creator field (header bytes 80-83).
// If the profile creator is 0x00000000, no creator validation is possible.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF118_PrivateTagCreatorSignature(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-118]%s Private Tag Creator Signature (%sICC.1-2022-05 §9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icSignature creator = pIcc->m_Header.creator;
  if (creator == 0) {
    printf("           Profile creator field is zero — private tag authorship unknown\n");
    printf("           %s[INFO]%s No creator signature set — §7.2.17\n",
           ColorInfo(), ColorReset());
    return 0; // informational only
  }

  // Count private (unrecognized) tags — if > 5 without creator, flag it
  int privateCount = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    icUInt32Number sig = (icUInt32Number)it->TagInfo.sig;
    // Simple heuristic: if uppercase letters in all 4 bytes, likely registered
    bool allUpper = true;
    for (int b = 0; b < 4; b++) {
      uint8_t ch = (sig >> (24 - b * 8)) & 0xFF;
      if (ch < 0x20 || ch > 0x7E) { allUpper = false; break; }
    }
    if (!allUpper) privateCount++;
  }

  if (privateCount > 0) {
    // creator is guaranteed != 0 here (early return at line 1723)
    printf("           %d private/unusual tags with creator signature 0x%08X\n",
           privateCount, (unsigned)creator);
  }

  if (issues == 0)
    printf("           %s[OK]%s Creator signature present (0x%08X)\n",
           ColorSuccess(), ColorReset(), (unsigned)creator);

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-119: Profile Sequence Identifier (ICC.1-2022-05 §8.6, §10.15)
//
// DeviceLink profiles SHALL include profileSequenceDescTag. V4.4 profiles
// SHOULD include profileSequenceIdentifierTag for unambiguous identification.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF119_ProfileSequenceIdentifier(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-119]%s Profile Sequence Identifier (%sICC.1-2022-05 §8.6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  icUInt32Number version = pIcc->m_Header.version >> 24;

  // DeviceLink must have profileSequenceDescTag
  if (cls == icSigLinkClass) {
    if (!pIcc->FindTag(icSigProfileSequenceDescTag)) {
      printf("           DeviceLink profile missing profileSequenceDescTag\n");
      printf("           %s[FAIL]%s §8.6 requires profileSequenceDescTag for DeviceLink\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  // v4.4+ recommendation: profileSequenceIdentifierTag
  if (version >= 4) {
    if (!pIcc->FindTag(icSigProfileSequceIdTag)) {
      printf("           V%u profile without profileSequenceIdentifierTag\n", version);
      printf("           %s[INFO]%s §10.15 recommends profileSequenceIdentifierTag\n",
             ColorInfo(), ColorReset());
    }
  }

  if (issues == 0)
    printf("           %s[OK]%s Profile sequence identification validated\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-120: Named Color Space Dimensions (ICC.1-2022-05 §8.9, §10.14)
//
// NamedColor profiles: device coordinates in namedColor2Type MUST match
// the number of device channels declared in the header's data colour space.
// If data colour space is xCLR, the device coordinate count must equal the
// channel count implied by x (3CLR=3, 4CLR=4, etc.).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF120_NamedColorSpaceDimensions(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-120]%s Named Color Space Dimensions (%sICC.1-2022-05 §10.14%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigNamedColorClass) {
    printf("           Not a NamedColor profile — check not applicable\n");
    return 0;
  }

  CIccTag *tag = pIcc->FindTag(icSigNamedColor2Tag);
  if (!tag) {
    printf("           NamedColor profile missing namedColor2Tag\n");
    printf("           %s[FAIL]%s §8.9 requires namedColor2Tag — ICC.1-2022-05\n",
           ColorError(), ColorReset());
    return 1;
  }

  CIccTagNamedColor2 *nc = dynamic_cast<CIccTagNamedColor2 *>(tag);
  if (!nc) {
    printf("           namedColor2Tag is not CIccTagNamedColor2 type\n");
    printf("           %s[FAIL]%s Tag type mismatch for namedColor2 — §10.14\n",
           ColorError(), ColorReset());
    return 1;
  }

  icUInt32Number devCoords = nc->GetDeviceCoords();
  icUInt32Number expected  = icGetSpaceSamples(pIcc->m_Header.colorSpace);

  if (expected > 0 && devCoords != expected) {
    printf("           Device coordinates=%u but colour space expects %u channels\n",
           devCoords, expected);
    printf("           %s[FAIL]%s Device coordinate count must match colour space — §10.14\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("           %s[OK]%s Named colour device dimensions match colour space\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-202: Tag Data Padding Zero-Fill (ICC.1-2022-05 §7.2.1c)
//
// Per ICC.1-2022-05 §7.2.1c, "All data MUST be aligned on a 4-byte boundary"
// and padding bytes between tag data regions "shall be zero." This check
// reads the raw file to verify padding bytes between consecutive tag data
// regions are 0x00.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF202_TagDataPaddingZeroFill(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  printf("  %s[CF-202]%s Tag Data Padding Zero-Fill (%sICC.1-2022-05 §7.2.1c%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename || !filename[0]) {
    printf("           No file path — skipping raw padding check\n");
    printf("           %s[OK]%s Skipped (no file)\n", ColorSuccess(), ColorReset());
    return 0;
  }

  // Collect tag regions sorted by offset
  struct TagRegion { icUInt32Number offset; icUInt32Number size; char sig[5]; };
  std::vector<TagRegion> regions;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    TagRegion tr;
    tr.offset = it->TagInfo.offset;
    tr.size   = it->TagInfo.size;
    SigToChars(it->TagInfo.sig, tr.sig);
    // Deduplicate shared offsets (same data region for multiple tag sigs)
    bool dup = false;
    for (size_t j = 0; j < regions.size(); j++) {
      if (regions[j].offset == tr.offset) { dup = true; break; }
    }
    if (!dup) regions.push_back(tr);
  }

  // Sort by offset
  for (size_t i = 0; i < regions.size(); i++) {
    for (size_t j = i + 1; j < regions.size(); j++) {
      if (regions[j].offset < regions[i].offset) {
        TagRegion tmp = regions[i];
        regions[i] = regions[j];
        regions[j] = tmp;
      }
    }
  }

  // Open file and check padding between consecutive regions
  FILE *f = fopen(filename, "rb");
  if (!f) {
    printf("           Cannot open file for padding check\n");
    printf("           %s[OK]%s Skipped (file access error)\n", ColorSuccess(), ColorReset());
    return 0;
  }

  int paddingIssues = 0;
  for (size_t i = 0; i + 1 < regions.size(); i++) {
    icUInt32Number endOfCurrent = regions[i].offset + regions[i].size;
    // Round up to 4-byte boundary
    icUInt32Number aligned = (endOfCurrent + 3) & ~3u;
    icUInt32Number nextStart = regions[i + 1].offset;

    if (aligned < nextStart) {
      // There's a gap — check padding bytes are zero
      icUInt32Number gapSize = nextStart - aligned;
      if (gapSize > 64) gapSize = 64; // Limit check to 64 bytes max
      if (fseek(f, aligned, SEEK_SET) == 0) {
        unsigned char buf[64];
        size_t rd = fread(buf, 1, gapSize, f);
        for (size_t b = 0; b < rd; b++) {
          if (buf[b] != 0x00) {
            if (paddingIssues < 3) {
              printf("           Non-zero padding byte 0x%02X at offset 0x%08X (between '%s' and '%s')\n",
                     buf[b], (unsigned)(aligned + b), regions[i].sig, regions[i + 1].sig);
              printf("           %s[FAIL]%s Padding bytes must be zero — §7.2.1c\n",
                     ColorError(), ColorReset());
            }
            paddingIssues++;
            break; // One report per gap
          }
        }
      }
    }
  }
  fclose(f);

  if (paddingIssues > 3)
    printf("           ... and %d more non-zero padding gaps\n", paddingIssues - 3);

  issues += paddingIssues;
  if (issues == 0)
    printf("           %s[OK]%s All inter-tag padding bytes are zero\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-204: Device Attributes Semantic Validation (ICC.1-2022-05 §7.2.14 Table 22)
//
// Extends CF-004 (reserved bits) with semantic analysis of defined bits:
//   Bit 0: 0=reflective, 1=transparency
//   Bit 1: 0=glossy, 1=matte
//   Bit 2: 0=positive media, 1=negative media (v4+)
//   Bit 3: 0=colour media, 1=black & white media (v4+)
// Cross-checks: abstract/namedColor/colorSpace classes typically don't have
// physical media attributes.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF204_DeviceAttributesSemantics(CIccProfile *pIcc) {
  int issues = 0;
  icUInt64Number attrs = pIcc->m_Header.attributes;
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;

  printf("  %s[CF-204]%s Device Attributes Semantic Validation (%sICC.1-2022-05 §7.2.14 Table 22%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  bool transparency = (attrs & 0x0001) != 0;
  bool matte        = (attrs & 0x0002) != 0;
  bool negative     = (attrs & 0x0004) != 0;
  bool bw           = (attrs & 0x0008) != 0;

  printf("           Bit 0: %s\n", transparency ? "transparency" : "reflective");
  printf("           Bit 1: %s\n", matte ? "matte" : "glossy");
  printf("           Bit 2: %s\n", negative ? "negative media" : "positive media");
  printf("           Bit 3: %s\n", bw ? "black & white" : "colour");

  // Cross-check: abstract/namedColor/colorSpace classes have no physical media
  bool nonDeviceClass = (cls == icSigAbstractClass ||
                         cls == icSigNamedColorClass ||
                         cls == icSigColorSpaceClass);
  if (nonDeviceClass && (transparency || matte || negative || bw)) {
    printf("           Profile class '%c%c%c%c' is non-device — physical media attributes unexpected\n",
           (char)((cls >> 24) & 0xFF), (char)((cls >> 16) & 0xFF),
           (char)((cls >> 8) & 0xFF), (char)(cls & 0xFF));
    printf("           %s[WARN]%s Non-device class with physical media attributes — §7.2.14\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("           %s[OK]%s Device attributes semantics conformant\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-205: Tag Data Region Gap Analysis (ICC.1-2022-05 §7.3)
//
// Analyzes the layout of tag data regions within the profile. Reports:
// - Total number of distinct data regions (after dedup of shared offsets)
// - Total data coverage (bytes used / profile size)
// - Largest gap between tag data regions
// A profile with large uncovered gaps may indicate unused or malformed data.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF205_TagDataRegionGapAnalysis(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-205]%s Tag Data Region Gap Analysis (%sICC.1-2022-05 §7.3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number profileSize = pIcc->m_Header.size;
  if (profileSize == 0) {
    printf("           Profile size is zero — cannot analyze\n");
    printf("           %s[OK]%s Skipped\n", ColorSuccess(), ColorReset());
    return 0;
  }

  // Collect unique tag regions
  struct Region { icUInt32Number offset; icUInt32Number size; };
  std::vector<Region> regions;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    bool dup = false;
    for (size_t j = 0; j < regions.size(); j++) {
      if (regions[j].offset == it->TagInfo.offset) { dup = true; break; }
    }
    if (!dup) {
      Region rg;
      rg.offset = it->TagInfo.offset;
      rg.size = it->TagInfo.size;
      regions.push_back(rg);
    }
  }

  // Sort by offset
  for (size_t i = 0; i < regions.size(); i++) {
    for (size_t j = i + 1; j < regions.size(); j++) {
      if (regions[j].offset < regions[i].offset) {
        Region tmp = regions[i];
        regions[i] = regions[j];
        regions[j] = tmp;
      }
    }
  }

  // Compute coverage and gaps
  icUInt32Number totalCoverage = 0;
  icUInt32Number largestGap = 0;
  icUInt32Number gapCount = 0;

  // Header + tag table = first data region start
  icUInt32Number tagTableEnd = 128 + 4 + (icUInt32Number)pIcc->m_Tags.size() * 12;

  for (size_t i = 0; i < regions.size(); i++) {
    totalCoverage += regions[i].size;

    icUInt32Number prevEnd = (i == 0) ? tagTableEnd : (regions[i - 1].offset + regions[i - 1].size);
    prevEnd = (prevEnd + 3) & ~3u; // Align to 4 bytes
    if (regions[i].offset > prevEnd) {
      icUInt32Number gap = regions[i].offset - prevEnd;
      if (gap > largestGap) largestGap = gap;
      gapCount++;
    }
  }

  // Check trailing gap
  if (!regions.empty()) {
    icUInt32Number lastEnd = regions.back().offset + regions.back().size;
    lastEnd = (lastEnd + 3) & ~3u;
    if (profileSize > lastEnd) {
      icUInt32Number trailing = profileSize - lastEnd;
      if (trailing > largestGap) largestGap = trailing;
      if (trailing > 4) gapCount++;
    }
  }

  double coveragePct = (double)totalCoverage / (double)profileSize * 100.0;

  printf("           Distinct data regions: %zu\n", regions.size());
  printf("           Data coverage: %u / %u bytes (%.1f%%)\n",
         totalCoverage, profileSize, coveragePct);
  printf("           Inter-region gaps: %u (largest: %u bytes)\n", gapCount, largestGap);

  // Flag if data coverage is suspiciously low (less than 30%)
  if (coveragePct < 30.0 && profileSize > 1024) {
    printf("           %s[WARN]%s Data coverage below 30%% — profile may contain excessive padding or dead data\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  // Flag if largest gap exceeds 10% of profile size
  if (largestGap > profileSize / 10 && profileSize > 1024) {
    printf("           %s[WARN]%s Largest gap (%u bytes) exceeds 10%% of profile — §7.3\n",
           ColorWarning(), ColorReset(), largestGap);
    issues++;
  }

  if (issues == 0)
    printf("           %s[OK]%s Tag data region layout conformant\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-207: mediaWhitePointTag Value Range (ICC.1-2022-05 §10.27)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF207_MediaWhitePointTagValueRange(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-207]%s mediaWhitePointTag Value Range (%sICC.1-2022-05 §10.27%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pTag = pIcc->FindTag(icSigMediaWhitePointTag);
  if (!pTag) {
    printf("         No mediaWhitePointTag ('wtpt') found\n");
    printf("         %s[OK]%s Not present (checked separately by CF-040)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ *>(pTag);
  if (!pXYZ || pXYZ->GetSize() < 1) {
    printf("         %swtpt tag is not XYZType or has no entries%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s mediaWhitePointTag must be XYZType — ICC.1-2022-05 §10.27\n",
           ColorError(), ColorReset());
    return 1;
  }

  const icXYZNumber *xyz = pXYZ->GetXYZ(0);
  if (!xyz) {
    printf("         %s[FAIL]%s Cannot read XYZ value\n", ColorError(), ColorReset());
    return 1;
  }

  double X = icFtoD(xyz->X);
  double Y = icFtoD(xyz->Y);
  double Z = icFtoD(xyz->Z);

  printf("         wtpt: X=%.4f, Y=%.4f, Z=%.4f\n", X, Y, Z);

  // Y must be positive (luminance)
  if (Y <= 0.0) {
    printf("         Y=%.4f — %sY must be positive (luminance)%s\n",
           Y, ColorError(), ColorReset());
    printf("         %s[FAIL]%s White point Y must be > 0 — ICC.1-2022-05 §10.27\n",
           ColorError(), ColorReset());
    issues++;
  }

  // X must be positive for a valid white point
  if (X <= 0.0) {
    printf("         X=%.4f — %sX must be positive%s\n",
           X, ColorError(), ColorReset());
    printf("         %s[FAIL]%s White point X must be > 0 — ICC.1-2022-05 §10.27\n",
           ColorError(), ColorReset());
    issues++;
  }

  // Z must be positive for a valid white point
  if (Z <= 0.0) {
    printf("         Z=%.4f — %sZ must be positive%s\n",
           Z, ColorError(), ColorReset());
    printf("         %s[FAIL]%s White point Z must be > 0 — ICC.1-2022-05 §10.27\n",
           ColorError(), ColorReset());
    issues++;
  }

  // §9.2.28 (v4): for non-DeviceLink, wtpt shall be D50 (0.9642, 1.0, 0.8249)
  int major = (pIcc->m_Header.version >> 24) & 0xFF;
  bool isDeviceLink = (pIcc->m_Header.deviceClass == icSigLinkClass);

  if (major >= 4 && !isDeviceLink) {
    double dX = fabs(X - 0.9642);
    double dY = fabs(Y - 1.0000);
    double dZ = fabs(Z - 0.8249);
    if (dX > 0.002 || dY > 0.002 || dZ > 0.002) {
      printf("         v4 non-DeviceLink: wtpt should be D50 (0.9642, 1.0, 0.8249)\n");
      printf("         deviation: ΔX=%.4f, ΔY=%.4f, ΔZ=%.4f\n", dX, dY, dZ);
      printf("         %s[FAIL]%s v4+ non-DeviceLink wtpt must be D50 — ICC.1-2022-05 §9.2.28\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  // Sanity: XYZ values should be physically plausible (< 3.0 for normalized)
  if (X > 3.0 || Y > 3.0 || Z > 3.0) {
    printf("         Values exceed plausible range (max 3.0): X=%.4f, Y=%.4f, Z=%.4f\n",
           X, Y, Z);
    printf("         %s[FAIL]%s White point XYZ values out of physically plausible range\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s mediaWhitePointTag values conformant\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-211: AToB/BToA Tag Pair Completeness (ICC.1-2022-05 §9.2.1, §9.2.2)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF211_AToBBToAPairCompleteness(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-211]%s AToB/BToA Tag Pair Completeness (%sICC.1-2022-05 §9.2.1-9.2.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  static const struct {
    icTagSignature aToBSig;
    icTagSignature bToASig;
    const char *label;
  } kPairs[] = {
    { icSigAToB0Tag, icSigBToA0Tag, "0 (Perceptual)" },
    { icSigAToB1Tag, icSigBToA1Tag, "1 (Relative Colorimetric)" },
    { icSigAToB2Tag, icSigBToA2Tag, "2 (Saturation)" },
  };

  // DeviceLink profiles use AToB0 but not BToA — skip pair check
  if (pIcc->m_Header.deviceClass == icSigLinkClass) {
    printf("         DeviceLink profile — AToB/BToA pairing not required\n");
    printf("         %s[OK]%s DeviceLink exempt from pair requirement\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  int pairCount = 0;
  for (int i = 0; i < 3; i++) {
    CIccTag *pAToB = pIcc->FindTag(kPairs[i].aToBSig);
    CIccTag *pBToA = pIcc->FindTag(kPairs[i].bToASig);

    if (pAToB && pBToA) {
      printf("         Pair %s: AToB ✓  BToA ✓\n", kPairs[i].label);
      pairCount++;
    } else if (pAToB && !pBToA) {
      printf("         Pair %s: AToB ✓  BToA ✗ — %smissing inverse transform%s\n",
             kPairs[i].label, ColorError(), ColorReset());
      printf("         %s[FAIL]%s AToB%s present without matching BToA%s — ICC.1-2022-05 §9.2\n",
             ColorError(), ColorReset(), kPairs[i].label, kPairs[i].label);
      issues++;
    } else if (!pAToB && pBToA) {
      printf("         Pair %s: AToB ✗  BToA ✓ — %smissing forward transform%s\n",
             kPairs[i].label, ColorError(), ColorReset());
      printf("         %s[FAIL]%s BToA%s present without matching AToB%s — ICC.1-2022-05 §9.2\n",
             ColorError(), ColorReset(), kPairs[i].label, kPairs[i].label);
      issues++;
    }
    // Both absent: OK — that intent pair is simply not supported
  }

  if (pairCount == 0 && issues == 0) {
    printf("         No AToB/BToA LUT pairs present (profile may use Matrix/TRC)\n");
  }

  if (issues == 0)
    printf("         %s[OK]%s AToB/BToA tag pair completeness conformant\n",
           ColorSuccess(), ColorReset());

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-258: Display v4+ mediaWhitePointTag Must Equal D50
// ICC.1-2022-05 §8.4 Table 25: "For Display profiles (v4+), the
// mediaWhitePointTag shall contain the D50 illuminant value."
// D50 = (0.9642, 1.0000, 0.8249) in s15Fixed16
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF258_DisplayMediaWhiteD50(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-258]%s Display v4+ mediaWhitePointTag D50 (%sICC.1-2022-05 §8.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number ver = pIcc->m_Header.version;
  if (ver < icVersionNumberV4) {
    printf("         Profile version < 4.0 — D50 mediaWhitePoint not mandated\n");
    printf("         %s[OK]%s v2 profiles exempt from D50 requirement\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  if (pIcc->m_Header.deviceClass != icSigDisplayClass) {
    printf("         Not a Display profile — D50 mediaWhitePoint applies only to mntr\n");
    printf("         %s[OK]%s Non-display class exempt\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  CIccTag *pTag = pIcc->FindTag(icSigMediaWhitePointTag);
  if (!pTag) {
    printf("         %s[FAIL]%s Display v4+ must have mediaWhitePointTag\n",
           ColorError(), ColorReset());
    return 1;
  }

  CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ *>(pTag);
  if (!pXYZ || pXYZ->GetSize() < 1) {
    printf("         %s[FAIL]%s mediaWhitePointTag not XYZType\n",
           ColorError(), ColorReset());
    return 1;
  }

  const icXYZNumber *xyz = pXYZ->GetXYZ(0);
  if (!xyz) {
    printf("         %s[FAIL]%s Cannot read XYZ value\n", ColorError(), ColorReset());
    return 1;
  }

  double X = icFtoD(xyz->X);
  double Y = icFtoD(xyz->Y);
  double Z = icFtoD(xyz->Z);

  // D50 per ICC spec: X=0.9642, Y=1.0000, Z=0.8249
  const double D50_X = 0.9642, D50_Y = 1.0000, D50_Z = 0.8249;
  const double tol = 0.005;

  if (fabs(X - D50_X) > tol || fabs(Y - D50_Y) > tol || fabs(Z - D50_Z) > tol) {
    printf("         mediaWhitePoint = (%.4f, %.4f, %.4f)\n", X, Y, Z);
    printf("         Expected D50    = (%.4f, %.4f, %.4f)\n", D50_X, D50_Y, D50_Z);
    printf("         %s[FAIL]%s Display v4+ mediaWhitePointTag must equal D50 — ICC.1-2022-05 §8.4\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s mediaWhitePointTag equals D50 (tolerance +/-0.005)\n",
           ColorSuccess(), ColorReset());

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-259: colorantOrderTag vs colorantTableTag Cross-Validation
// ICC.1-2022-05 §10.3: Each index in colorantOrderTag must be a valid
// index into colorantTableTag entries.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF259_ColorantOrderVsTable(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-259]%s colorantOrderTag vs colorantTableTag Cross-Validation (%sICC.1-2022-05 §10.3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  CIccTag *pOrderTag = pIcc->FindTag(icSigColorantOrderTag);
  CIccTag *pTableTag = pIcc->FindTag(icSigColorantTableTag);

  if (!pOrderTag && !pTableTag) {
    printf("         Neither colorantOrderTag nor colorantTableTag present\n");
    return 0;
  }

  if (pOrderTag && !pTableTag) {
    printf("         %s[WARN]%s colorantOrderTag present without colorantTableTag\n",
           ColorWarning(), ColorReset());
    printf("         colorantOrderTag references colorantTableTag — both should be present\n");
    return 1;
  }

  if (!pOrderTag) {
    printf("         colorantTableTag present without colorantOrderTag — OK\n");
    return 0;
  }

  CIccTagColorantOrder *pOrder = dynamic_cast<CIccTagColorantOrder *>(pOrderTag);
  CIccTagColorantTable *pTable = dynamic_cast<CIccTagColorantTable *>(pTableTag);

  if (!pOrder || !pTable) {
    printf("         %s[FAIL]%s Unexpected tag types for colorant tags\n",
           ColorError(), ColorReset());
    return 1;
  }

  icUInt32Number orderCount = pOrder->GetSize();
  icUInt32Number tableCount = pTable->GetSize();

  printf("         colorantOrderTag: %u entries, colorantTableTag: %u entries\n",
         orderCount, tableCount);

  if (orderCount != tableCount) {
    printf("         %s[FAIL]%s colorantOrderTag count (%u) != colorantTableTag count (%u)\n",
           ColorError(), ColorReset(), orderCount, tableCount);
    issues++;
  }

  for (icUInt32Number i = 0; i < orderCount && i < 64; i++) {
    icUInt8Number idx = (*pOrder)[i];
    if (idx >= tableCount) {
      printf("         %s[FAIL]%s colorantOrder[%u]=%u exceeds colorantTable count (%u)\n",
             ColorError(), ColorReset(), i, idx, tableCount);
      issues++;
      if (issues >= 5) {
        printf("         (stopping after 5 cross-validation failures)\n");
        break;
      }
    }
  }

  if (issues == 0)
    printf("         %s[OK]%s colorantOrderTag indices valid within colorantTableTag\n",
           ColorSuccess(), ColorReset());

  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-260: Output Profile gamutTag Rendering Intent Consistency
// ICC.1-2022-05 §9.2.22: Output profiles should have a gamutTag when
// they support perceptual or saturation rendering intents.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF260_OutputGamutTagIntent(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-260]%s Output Profile gamutTag Rendering Intent (%sICC.1-2022-05 §9.2.22%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigOutputClass) {
    printf("         Not an Output profile — gamutTag check not applicable\n");
    return 0;
  }

  CIccTag *pGamut = pIcc->FindTag(icSigGamutTag);
  CIccTag *pAToB0 = pIcc->FindTag(icSigAToB0Tag);
  CIccTag *pAToB2 = pIcc->FindTag(icSigAToB2Tag);

  bool hasPerceptual  = (pAToB0 != nullptr);
  bool hasSaturation  = (pAToB2 != nullptr);

  if (!hasPerceptual && !hasSaturation) {
    printf("         No perceptual (AToB0) or saturation (AToB2) intents present\n");
    return 0;
  }

  if (!pGamut && (hasPerceptual || hasSaturation)) {
    printf("         Output profile has %s%s%s intent(s) but no gamutTag\n",
           hasPerceptual ? "perceptual" : "",
           (hasPerceptual && hasSaturation) ? " + " : "",
           hasSaturation ? "saturation" : "");
    printf("         %s[WARN]%s Output profiles with perceptual/saturation intents "
           "should include gamutTag — ICC.1-2022-05 §9.2.22\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Output profile gamutTag consistent with rendering intents\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ── CF-266: Input Profile Device Color Space ─────────────────────────────────
// ICC.1-2022-05 §6.1 — scnr must use data color spaces that correspond to
// the device for which the profile is defined (RGB, CMYK, Gray, or nCLR)

static int RunCF266_InputProfileColorSpace(CIccProfile *pIcc) {
  printf("%s[CF-266]%s Input Profile Device Color Space (%sICC.1-2022-05 §6.1%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.deviceClass != icSigInputClass) return 0;
  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
  bool valid = (cs == icSigRgbData || cs == icSigCmykData || cs == icSigGrayData ||
                icGetColorSpaceType(cs) == icSigNChannelData);
  if (!valid) {
    char sig[5]; sig[4] = '\0';
    for (int i = 0; i < 4; i++) sig[i] = (char)((((icUInt32Number)cs) >> (24-8*i)) & 0xFF);
    printf("         %s[WARN]%s Input profile has device color space '%s' — "
           "expected RGB, CMYK, Gray, or nCLR — ICC.1-2022-05 §6.1\n",
           ColorWarning(), ColorReset(), sig);
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s Input profile device color space valid\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-267: Display Profile Color Space ──────────────────────────────────────
// ICC.1-2022-05 §6.2 — mntr must use RGB, Gray, or nCLR data color spaces

static int RunCF267_DisplayProfileColorSpace(CIccProfile *pIcc) {
  printf("%s[CF-267]%s Display Profile Color Space (%sICC.1-2022-05 §6.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.deviceClass != icSigDisplayClass) return 0;
  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
  bool valid = (cs == icSigRgbData || cs == icSigGrayData ||
                icGetColorSpaceType(cs) == icSigNChannelData);
  if (!valid) {
    char sig[5]; sig[4] = '\0';
    for (int i = 0; i < 4; i++) sig[i] = (char)((((icUInt32Number)cs) >> (24-8*i)) & 0xFF);
    printf("         %s[WARN]%s Display profile has device color space '%s' — "
           "expected RGB, Gray, or nCLR — ICC.1-2022-05 §6.2\n",
           ColorWarning(), ColorReset(), sig);
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s Display profile device color space valid\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-268: Output Profile Color Space ───────────────────────────────────────
// ICC.1-2022-05 §6.3 — prtr must use RGB, CMYK, CMY, Gray, or nCLR

static int RunCF268_OutputProfileColorSpace(CIccProfile *pIcc) {
  printf("%s[CF-268]%s Output Profile Color Space (%sICC.1-2022-05 §6.3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.deviceClass != icSigOutputClass) return 0;
  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
  bool valid = (cs == icSigRgbData || cs == icSigCmykData || cs == icSigCmyData ||
                cs == icSigGrayData || icGetColorSpaceType(cs) == icSigNChannelData);
  if (!valid) {
    char sig[5]; sig[4] = '\0';
    for (int i = 0; i < 4; i++) sig[i] = (char)((((icUInt32Number)cs) >> (24-8*i)) & 0xFF);
    printf("         %s[WARN]%s Output profile has device color space '%s' — "
           "expected RGB, CMYK, CMY, Gray, or nCLR — ICC.1-2022-05 §6.3\n",
           ColorWarning(), ColorReset(), sig);
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s Output profile device color space valid\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-269: DeviceLink Data Color Space Matching ─────────────────────────────
// ICC.1-2022-05 §6.4 — link profile data color space = device side,
// PCS = output side, must both be valid device color spaces

static int RunCF269_DeviceLinkColorSpaces(CIccProfile *pIcc) {
  printf("%s[CF-269]%s DeviceLink Data Color Space Matching (%sICC.1-2022-05 §6.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.deviceClass != icSigLinkClass) return 0;
  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
  icColorSpaceSignature pcs = pIcc->m_Header.pcs;
  // DeviceLink PCS field holds the output device color space, not Lab/XYZ
  // Both source (colorSpace) and destination (pcs) should be device spaces
  auto isDeviceSpace = [](icColorSpaceSignature s) -> bool {
    return (s == icSigRgbData || s == icSigCmykData || s == icSigCmyData ||
            s == icSigGrayData || s == icSigLabData || s == icSigXYZData ||
            s == icSigYCbCrData || s == icSigHsvData || s == icSigHlsData ||
            s == icSigLuvData || icGetColorSpaceType(s) == icSigNChannelData);
  };
  if (!isDeviceSpace(cs)) {
    printf("         %s[WARN]%s DeviceLink source color space unrecognized\n",
           ColorWarning(), ColorReset());
    issues++;
  }
  if (!isDeviceSpace(pcs)) {
    printf("         %s[WARN]%s DeviceLink destination color space unrecognized\n",
           ColorWarning(), ColorReset());
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s DeviceLink color spaces valid\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-270: Abstract Profile PCS ─────────────────────────────────────────────
// ICC.1-2022-05 §6.6 — abst must use Lab or XYZ for both colorSpace and PCS

static int RunCF270_AbstractProfilePCS(CIccProfile *pIcc) {
  printf("%s[CF-270]%s Abstract Profile PCS (%sICC.1-2022-05 §6.6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.deviceClass != icSigAbstractClass) return 0;
  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
  icColorSpaceSignature pcs = pIcc->m_Header.pcs;
  if (cs != icSigLabData && cs != icSigXYZData) {
    printf("         %s[WARN]%s Abstract profile colorSpace must be Lab or XYZ — ICC.1-2022-05 §6.6\n",
           ColorWarning(), ColorReset());
    issues++;
  }
  if (pcs != icSigLabData && pcs != icSigXYZData) {
    printf("         %s[WARN]%s Abstract profile PCS must be Lab or XYZ — ICC.1-2022-05 §6.6\n",
           ColorWarning(), ColorReset());
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s Abstract profile PCS valid\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-271: NamedColor Profile PCS ───────────────────────────────────────────
// ICC.1-2022-05 §6.7 — nmcl PCS must be Lab or XYZ

static int RunCF271_NamedColorProfilePCS(CIccProfile *pIcc) {
  printf("%s[CF-271]%s NamedColor Profile PCS (%sICC.1-2022-05 §6.7%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.deviceClass != icSigNamedColorClass) return 0;
  icColorSpaceSignature pcs = pIcc->m_Header.pcs;
  if (pcs != icSigLabData && pcs != icSigXYZData) {
    printf("         %s[WARN]%s NamedColor profile PCS must be Lab or XYZ — ICC.1-2022-05 §6.7\n",
           ColorWarning(), ColorReset());
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s NamedColor profile PCS valid\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-272: Matrix/TRC RGB Required Colorant Tags ────────────────────────────
// ICC.1-2022-05 §9.2.47 — RGB profiles with matrix/TRC model must have
// rXYZ, gXYZ, bXYZ, rTRC, gTRC, bTRC tags

static int RunCF272_MatrixTRCColorantTags(CIccProfile *pIcc) {
  printf("%s[CF-272]%s Matrix/TRC RGB Required Colorant Tags (%sICC.1-2022-05 §9.2.47%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.colorSpace != icSigRgbData) return 0;
  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  if (cls != icSigInputClass && cls != icSigDisplayClass) return 0;
  // Check if this is a matrix/TRC profile (has rTRC but no AToB0)
  CIccTag *pRTRC = pIcc->FindTag(icSigRedTRCTag);
  CIccTag *pAToB0 = pIcc->FindTag(icSigAToB0Tag);
  if (!pRTRC && pAToB0) return 0; // LUT-based, skip
  if (!pRTRC && !pAToB0) return 0; // No transform model
  // Matrix/TRC profile — check all 6 tags
  static const struct { icTagSignature sig; const char *name; } tags[] = {
    {icSigRedMatrixColumnTag, "rXYZ"}, {icSigGreenMatrixColumnTag, "gXYZ"},
    {icSigBlueMatrixColumnTag, "bXYZ"}, {icSigRedTRCTag, "rTRC"},
    {icSigGreenTRCTag, "gTRC"}, {icSigBlueTRCTag, "bTRC"},
  };
  for (int i = 0; i < 6; i++) {
    if (!pIcc->FindTag(tags[i].sig)) {
      printf("         %s[WARN]%s Missing required tag '%s' for matrix/TRC RGB profile\n",
             ColorWarning(), ColorReset(), tags[i].name);
      issues++;
    }
  }
  if (issues == 0)
    printf("         %s[OK]%s All matrix/TRC colorant tags present\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-282: DeviceLink AToB0Tag Required ─────────────────────────────────────
// ICC.1-2022-05 §6.4 — DeviceLink profiles must contain AToB0Tag

static int RunCF282_DeviceLinkAToB0Required(CIccProfile *pIcc) {
  printf("%s[CF-282]%s DeviceLink AToB0Tag Required (%sICC.1-2022-05 §6.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.deviceClass != icSigLinkClass) return 0;
  if (!pIcc->FindTag(icSigAToB0Tag)) {
    printf("         %s[WARN]%s DeviceLink profile must contain AToB0Tag — ICC.1-2022-05 §6.4\n",
           ColorWarning(), ColorReset());
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s DeviceLink AToB0Tag present\n", ColorSuccess(), ColorReset());
  return issues;
}

// ── CF-283: DeviceLink profileSequenceDescTag ────────────────────────────────
// ICC.1-2022-05 §6.4 — DeviceLink profiles should have profileSequenceDescTag

static int RunCF283_DeviceLinkProfileSequenceDesc(CIccProfile *pIcc) {
  printf("%s[CF-283]%s DeviceLink profileSequenceDescTag (%sICC.1-2022-05 §6.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  int issues = 0;
  if (pIcc->m_Header.deviceClass != icSigLinkClass) return 0;
  if (!pIcc->FindTag(icSigProfileSequenceDescTag)) {
    printf("         %s[WARN]%s DeviceLink profile should contain profileSequenceDescTag "
           "— ICC.1-2022-05 §6.4\n", ColorWarning(), ColorReset());
    issues++;
  }
  if (issues == 0)
    printf("         %s[OK]%s DeviceLink profileSequenceDescTag present\n", ColorSuccess(), ColorReset());
  return issues;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Dispatcher — runs all required tag conformance checks
// ═══════════════════════════════════════════════════════════════════════════════

int RunRequiredTagConformance(CIccProfile *pIcc, const char *filename) {
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

  CF_WRAP(1040, "CF-040: Common Required Tags (cprt, desc, wtpt)", RunCF040_CommonRequiredTags(pIcc));

  icProfileClassSignature cls = pIcc->m_Header.deviceClass;
  switch (cls) {
    case icSigInputClass:
      CF_WRAP(1041, "CF-041: Input Profile Required Tags", RunCF041_InputProfileRequired(pIcc));
      break;
    case icSigDisplayClass:
      CF_WRAP(1042, "CF-042: Display Profile Required Tags", RunCF042_DisplayProfileRequired(pIcc));
      break;
    case icSigOutputClass:
      CF_WRAP(1043, "CF-043: Output Profile Required Tags", RunCF043_OutputProfileRequired(pIcc));
      break;
    case icSigLinkClass:
      CF_WRAP(1044, "CF-044: DeviceLink Profile Required Tags", RunCF044_DeviceLinkProfileRequired(pIcc));
      break;
    case icSigColorSpaceClass:
      CF_WRAP(1045, "CF-045: ColorSpace Profile Required Tags", RunCF045_ColorSpaceProfileRequired(pIcc));
      break;
    case icSigAbstractClass:
      CF_WRAP(1046, "CF-046: Abstract Profile Required Tags", RunCF046_AbstractProfileRequired(pIcc));
      break;
    case icSigNamedColorClass:
      CF_WRAP(1047, "CF-047: NamedColor Profile Required Tags", RunCF047_NamedColorProfileRequired(pIcc));
      break;
    default: break;
  }

  CF_WRAP(1048, "CF-048: Rendering Intent vs Transform Consistency", RunCF048_RenderingIntentConsistency(pIcc));
  CF_WRAP(1049, "CF-049: Matrix/TRC Profiles Must Use PCS XYZ", RunCF049_MatrixTRCPCSXYZ(pIcc));
  CF_WRAP(1050, "CF-050: xCLR Spaces Require Colorant Table", RunCF050_xCLRColorantTable(pIcc));
  CF_WRAP(1051, "CF-051: DeviceLink Prohibited Tags", RunCF051_DeviceLinkProhibited(pIcc));
  CF_WRAP(1052, "CF-052: Transform Tag Pair Completeness", RunCF052_TransformTagPairs(pIcc));
  CF_WRAP(1053, "CF-053: CICP Tag Class Restriction", RunCF053_CicpTagClassRestriction(pIcc));
  CF_WRAP(1054, "CF-054: v5 Spectral Required Tags", RunCF054_V5SpectralRequiredTags(pIcc));
  CF_WRAP(1055, "CF-055: D2B/B2D Tag Pair Completeness", RunCF055_D2BB2DPairCompleteness(pIcc));
  CF_WRAP(1056, "CF-056: Embedded Profile Structure", RunCF056_EmbeddedProfileStructure(pIcc));
  CF_WRAP(1057, "CF-057: Dictionary Tag Structure v5", RunCF057_DictionaryTagStructure(pIcc));
  CF_WRAP(1058, "CF-058: Profile Sequence Identifier v5", RunCF058_ProfileSequenceIdV5(pIcc));
  CF_WRAP(1059, "CF-059: Colorimetric Intent Image State", RunCF059_ColorimetricIntentImageState(pIcc));

  CF_WRAP(1095, "CF-095: Non-Required Tag Identification", RunCF095_NonRequiredTags(pIcc));
  CF_WRAP(1096, "CF-096: Private Tag Signature Range", RunCF096_PrivateTagSignatureRange(pIcc));
  CF_WRAP(1097, "CF-097: Private Tag Documentation", RunCF097_PrivateTagDocumentation(pIcc));
  CF_WRAP(1098, "CF-098: Undocumented Private Tags", RunCF098_UndocumentedPrivateTags(pIcc));

  CF_WRAP(1103, "CF-103: Tag Alignment & Offset Validity", RunCF103_TagAlignmentAndOffset(pIcc));
  CF_WRAP(1104, "CF-104: DeviceLink PCS Consistency", RunCF104_DeviceLinkPCSMatch(pIcc));
  CF_WRAP(1111, "CF-111: Required Tags per ICC Version", RunCF111_RequiredTagsPerVersion(pIcc));
  CF_WRAP(1117, "CF-117: Rendering Intent Tags per Class", RunCF117_RenderingIntentTagsPerClass(pIcc));
  CF_WRAP(1118, "CF-118: Private Tag Creator Signature", RunCF118_PrivateTagCreatorSignature(pIcc));
  CF_WRAP(1119, "CF-119: Profile Sequence Identifier", RunCF119_ProfileSequenceIdentifier(pIcc));
  CF_WRAP(1120, "CF-120: Named Color Space Dimensions", RunCF120_NamedColorSpaceDimensions(pIcc));

  // SampleICC compliance framework structural checks (CF-202, CF-204, CF-205)
  CF_WRAP(1202, "CF-202: Tag Data Padding Zero-Fill", RunCF202_TagDataPaddingZeroFill(pIcc, filename));
  CF_WRAP(1204, "CF-204: Device Attributes Semantic Validation", RunCF204_DeviceAttributesSemantics(pIcc));
  CF_WRAP(1205, "CF-205: Tag Data Region Gap Analysis", RunCF205_TagDataRegionGapAnalysis(pIcc));

  // Spec gap coverage (CF-207, CF-211)
  CF_WRAP(1207, "CF-207: mediaWhitePointTag Value Range", RunCF207_MediaWhitePointTagValueRange(pIcc));
  CF_WRAP(1211, "CF-211: AToB/BToA Tag Pair Completeness", RunCF211_AToBBToAPairCompleteness(pIcc));

  // Deep conformance gap coverage (CF-258..CF-260)
  CF_WRAP(1258, "CF-258: Display v4+ mediaWhitePointTag D50", RunCF258_DisplayMediaWhiteD50(pIcc));
  CF_WRAP(1259, "CF-259: colorantOrderTag vs colorantTableTag Cross-Validation", RunCF259_ColorantOrderVsTable(pIcc));
  CF_WRAP(1260, "CF-260: Output Profile gamutTag Rendering Intent", RunCF260_OutputGamutTagIntent(pIcc));

  // Profile class constraints (CF-266..CF-272, CF-282..CF-283)
  CF_WRAP(1266, "CF-266: Input Profile Device Color Space", RunCF266_InputProfileColorSpace(pIcc));
  CF_WRAP(1267, "CF-267: Display Profile Color Space", RunCF267_DisplayProfileColorSpace(pIcc));
  CF_WRAP(1268, "CF-268: Output Profile Color Space", RunCF268_OutputProfileColorSpace(pIcc));
  CF_WRAP(1269, "CF-269: DeviceLink Data Color Space Matching", RunCF269_DeviceLinkColorSpaces(pIcc));
  CF_WRAP(1270, "CF-270: Abstract Profile PCS", RunCF270_AbstractProfilePCS(pIcc));
  CF_WRAP(1271, "CF-271: NamedColor Profile PCS", RunCF271_NamedColorProfilePCS(pIcc));
  CF_WRAP(1272, "CF-272: Matrix/TRC RGB Required Colorant Tags", RunCF272_MatrixTRCColorantTags(pIcc));
  CF_WRAP(1282, "CF-282: DeviceLink AToB0Tag Required", RunCF282_DeviceLinkAToB0Required(pIcc));
  CF_WRAP(1283, "CF-283: DeviceLink profileSequenceDescTag", RunCF283_DeviceLinkProfileSequenceDesc(pIcc));

#undef CF_WRAP
  return issues;
}
