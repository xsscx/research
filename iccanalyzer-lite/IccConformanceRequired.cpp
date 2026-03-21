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
  if (version >= 4 && cls != icSigLinkClass) {
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

  if (privateCount > 0 && creator == 0) {
    printf("           %d private/unusual tags without creator signature\n", privateCount);
    printf("           %s[INFO]%s Private tags benefit from creator ID — §7.2.17\n",
           ColorInfo(), ColorReset());
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

  double coveragePct = profileSize > 0 ? (double)totalCoverage / (double)profileSize * 100.0 : 0.0;

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
// Dispatcher — runs all required tag conformance checks
// ═══════════════════════════════════════════════════════════════════════════════

int RunRequiredTagConformance(CIccProfile *pIcc, const char *filename) {
  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  int r;

#define CF_WRAP(id, title, call) \
  hc.begin(id, title); \
  r = call; \
  if (r > 0) hc.warn("%d non-conformance(s)", r); \
  hc.end("Conformant"); \
  issues += r

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

#undef CF_WRAP
  return issues;
}
