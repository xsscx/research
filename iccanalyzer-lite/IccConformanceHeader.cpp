/*
 * IccConformanceHeader.cpp — ICC specification header conformance checks
 *
 * Implements CF-001 through CF-015, CF-184..CF-187 from the conformance registry.
 * Validates ICC profile header fields against ICC.1-2022-05 §7.2.
 * CF-184..CF-187: RFC 1321 (MD5) Profile ID conformance per §7.2.18.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagEmbedIcc.h"
#include "IccUtil.h"
#include "IccConformanceRegistry.h"
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicResult.h"
#include "IccAnalyzerColors.h"
#include <openssl/evp.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>

// ── Days-per-month table (non-leap) ─────────────────────────────────────────

static const int kDaysInMonth[13] = {
  0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static bool IsLeapYear(int year) {
  if (year == 0) return false;
  return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

// ── Valid platform signatures (ICC.1-2022-05 §7.2.10 Table 20) ──────────────

static const icUInt32Number kValidPlatforms[] = {
  0,                                           // unspecified
  static_cast<icUInt32Number>(icSigMacintosh),  // 'APPL'
  static_cast<icUInt32Number>(icSigMicrosoft),   // 'MSFT'
  static_cast<icUInt32Number>(icSigSGI),         // 'SGI '
  static_cast<icUInt32Number>(icSigSolaris),     // 'SUNW'
};
static constexpr int kValidPlatformCount = sizeof(kValidPlatforms) / sizeof(kValidPlatforms[0]);

// ── Valid profile class signatures ──────────────────────────────────────────

static const icUInt32Number kV4DeviceClasses[] = {
  static_cast<icUInt32Number>(icSigInputClass),       // 'scnr'
  static_cast<icUInt32Number>(icSigDisplayClass),      // 'mntr'
  static_cast<icUInt32Number>(icSigOutputClass),       // 'prtr'
  static_cast<icUInt32Number>(icSigLinkClass),         // 'link'
  static_cast<icUInt32Number>(icSigColorSpaceClass),   // 'spac'
  static_cast<icUInt32Number>(icSigAbstractClass),     // 'abst'
  static_cast<icUInt32Number>(icSigNamedColorClass),   // 'nmcl'
};
static constexpr int kV4DeviceClassCount = sizeof(kV4DeviceClasses) / sizeof(kV4DeviceClasses[0]);

static const icUInt32Number kV5DeviceClasses[] = {
  static_cast<icUInt32Number>(icSigMaterialVisualizationClass),  // 'mvis'
  static_cast<icUInt32Number>(icSigColorEncodingClass),           // 'cenc'
  static_cast<icUInt32Number>(icSigMaterialLinkClass),            // 'mlnk'
  static_cast<icUInt32Number>(icSigMaterialIdentificationClass),  // 'mid '
};
static constexpr int kV5DeviceClassCount = sizeof(kV5DeviceClasses) / sizeof(kV5DeviceClasses[0]);

// ── Valid colour space signatures (ICC.1-2022-05 §7.2.6 Table 19) ──────────

static const icUInt32Number kValidColorSpaces[] = {
  static_cast<icUInt32Number>(icSigXYZData),    // 'XYZ '
  static_cast<icUInt32Number>(icSigLabData),    // 'Lab '
  static_cast<icUInt32Number>(icSigLuvData),    // 'Luv '
  static_cast<icUInt32Number>(icSigYCbCrData),  // 'YCbr'
  static_cast<icUInt32Number>(icSigYxyData),    // 'Yxy '
  static_cast<icUInt32Number>(icSigRgbData),    // 'RGB '
  static_cast<icUInt32Number>(icSigGrayData),   // 'GRAY'
  static_cast<icUInt32Number>(icSigHsvData),    // 'HSV '
  static_cast<icUInt32Number>(icSigHlsData),    // 'HLS '
  static_cast<icUInt32Number>(icSigCmykData),   // 'CMYK'
  static_cast<icUInt32Number>(icSigCmyData),    // 'CMY '
  static_cast<icUInt32Number>(icSigNamedData),  // named
  // Multi-channel: MCH1 through MCHF (2CLR through FCLR)
  static_cast<icUInt32Number>(icSigMCH1Data),
  static_cast<icUInt32Number>(icSigMCH2Data),
  static_cast<icUInt32Number>(icSigMCH3Data),
  static_cast<icUInt32Number>(icSigMCH4Data),
  static_cast<icUInt32Number>(icSigMCH5Data),
  static_cast<icUInt32Number>(icSigMCH6Data),
  static_cast<icUInt32Number>(icSigMCH7Data),
  static_cast<icUInt32Number>(icSigMCH8Data),
  static_cast<icUInt32Number>(icSigMCH9Data),
  static_cast<icUInt32Number>(icSigMCHAData),
  static_cast<icUInt32Number>(icSigMCHBData),
  static_cast<icUInt32Number>(icSigMCHCData),
  static_cast<icUInt32Number>(icSigMCHDData),
  static_cast<icUInt32Number>(icSigMCHEData),
  static_cast<icUInt32Number>(icSigMCHFData),
};
static constexpr int kValidColorSpaceCount = sizeof(kValidColorSpaces) / sizeof(kValidColorSpaces[0]);

// Check if sig is in the static colour space table or is a v5 N-channel/MCS
static bool IsConformantColorSpace(icUInt32Number sig) {
  for (int i = 0; i < kValidColorSpaceCount; i++) {
    if (sig == kValidColorSpaces[i]) return true;
  }
  // v5/iccMAX N-channel (0x6e63xxxx) and MCS (0x6d63xxxx)
  icUInt32Number csType = icGetColorSpaceType(static_cast<icColorSpaceSignature>(sig));
  icUInt32Number nChan  = icNumColorSpaceChannels(sig);
  if ((csType == static_cast<icUInt32Number>(icSigNChannelData) ||
       csType == static_cast<icUInt32Number>(icSigSrcMCSChannelData)) && nChan > 0)
    return true;
  return false;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-001: Date/Time Month-Day Validity (ICC.1-2022-05 §7.2.8)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF001_DateTimeMonthDay(CIccProfile *pIcc) {
  int issues = 0;
  const icDateTimeNumber &dt = pIcc->m_Header.date;

  printf("%s[CF-001]%s Date/Time Month-Day Validity (%sICC.1-2022-05 §7.2.8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Year 0 is allowed (means unset)
  if (dt.month < 1 || dt.month > 12) {
    printf("         Month=%u — %sout of range (must be 1-12)%s\n",
           dt.month, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Invalid month — ICC.1-2022-05 §7.2.8\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    int maxDay = kDaysInMonth[dt.month];
    if (dt.month == 2 && (dt.year == 0 || IsLeapYear(dt.year)))
      maxDay = 29;

    if (dt.day < 1 || dt.day > static_cast<icUInt16Number>(maxDay)) {
      printf("         Month=%u, Day=%u — %sday out of range (max %d for month %u)%s\n",
             dt.month, dt.day, ColorError(), maxDay, dt.month, ColorReset());
      printf("         %s[FAIL]%s Invalid day for month — ICC.1-2022-05 §7.2.8\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         Month=%u, Day=%u — valid\n", dt.month, dt.day);
    }
  }

  if (dt.hours > 23) {
    printf("         Hours=%u — %sout of range (must be 0-23)%s\n",
           dt.hours, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Invalid hours — ICC.1-2022-05 §7.2.8\n",
           ColorError(), ColorReset());
    issues++;
  }
  if (dt.minutes > 59) {
    printf("         Minutes=%u — %sout of range (must be 0-59)%s\n",
           dt.minutes, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Invalid minutes — ICC.1-2022-05 §7.2.8\n",
           ColorError(), ColorReset());
    issues++;
  }
  if (dt.seconds > 59) {
    printf("         Seconds=%u — %sout of range (must be 0-59)%s\n",
           dt.seconds, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Invalid seconds — ICC.1-2022-05 §7.2.8\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Date fields within range\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-002: Date/Time Leap Year Validation (ICC.1-2022-05 §7.2.8)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF002_DateTimeLeapYear(CIccProfile *pIcc) {
  int issues = 0;
  const icDateTimeNumber &dt = pIcc->m_Header.date;

  printf("%s[CF-002]%s Date/Time Leap Year Validation (%sICC.1-2022-05 §7.2.8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (dt.month != 2) {
    printf("         Month=%u — leap year check not applicable\n", dt.month);
    printf("         %s[OK]%s Not February, skip leap year validation\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Month is February
  if (dt.year == 0) {
    // Year unset — allow day up to 29
    if (dt.day > 29) {
      printf("         Year=0 (unset), Day=%u — %sday > 29 in February%s\n",
             dt.day, ColorError(), ColorReset());
      printf("         %s[FAIL]%s February day exceeds 29 — ICC.1-2022-05 §7.2.8\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         Year=0 (unset), Day=%u — valid (allowing up to 29)\n", dt.day);
      printf("         %s[OK]%s February day valid with unset year\n",
           ColorSuccess(), ColorReset());
    }
  } else if (IsLeapYear(dt.year)) {
    if (dt.day > 29) {
      printf("         Year=%u (leap), Day=%u — %sday > 29%s\n",
             dt.year, dt.day, ColorError(), ColorReset());
      printf("         %s[FAIL]%s February day exceeds 29 in leap year — ICC.1-2022-05 §7.2.8\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         Year=%u (leap), Day=%u — valid\n", dt.year, dt.day);
      printf("         %s[OK]%s February day valid for leap year\n",
             ColorSuccess(), ColorReset());
    }
  } else {
    // Non-leap year
    if (dt.day > 28) {
      printf("         Year=%u (non-leap), Day=%u — %sday > 28%s\n",
             dt.year, dt.day, ColorError(), ColorReset());
      printf("         %s[FAIL]%s February day exceeds 28 in non-leap year — ICC.1-2022-05 §7.2.8\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("         Year=%u (non-leap), Day=%u — valid\n", dt.year, dt.day);
      printf("         %s[OK]%s February day valid for non-leap year\n",
             ColorSuccess(), ColorReset());
    }
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-003: Profile Flags Reserved Bits (ICC.1-2022-05 §7.2.11 Table 21)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF003_ProfileFlagsReserved(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number flags = pIcc->m_Header.flags;

  printf("%s[CF-003]%s Profile Flags Reserved Bits (%sICC.1-2022-05 §7.2.11 Table 21%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number reservedBits = flags & 0xFFF8u;
  if (reservedBits != 0) {
    printf("         flags=0x%08X — %sreserved bits 3-15: non-zero (0x%04X)%s\n",
           flags, ColorError(), reservedBits, ColorReset());
    printf("         %s[FAIL]%s Reserved flag bits must be zero — ICC.1-2022-05 §7.2.11\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         flags=0x%08X — reserved bits 3-15 clear\n", flags);
    printf("         %s[OK]%s Profile flags conformant\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-004: Device Attributes Reserved Bits (ICC.1-2022-05 §7.2.14)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF004_DeviceAttributesReserved(CIccProfile *pIcc) {
  int issues = 0;
  icUInt64Number attrs = pIcc->m_Header.attributes;

  printf("%s[CF-004]%s Device Attributes Reserved Bits (%sICC.1-2022-05 §7.2.14%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Bits 0-3 are defined; bits 4-31 must be zero for v4
  // The upper 32 bits (32-63) are also reserved
  icUInt64Number reservedMask = 0x00000000FFFFFFF0ULL;
  icUInt64Number reservedBits = attrs & reservedMask;

  if (reservedBits != 0) {
    printf("         attributes=0x%016llX — %sreserved bits 4-31: non-zero%s\n",
           static_cast<unsigned long long>(attrs), ColorError(), ColorReset());
    printf("         %s[FAIL]%s Reserved attribute bits must be zero — ICC.1-2022-05 §7.2.14\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         attributes=0x%016llX — reserved bits clear\n",
           static_cast<unsigned long long>(attrs));
    printf("         %s[OK]%s Device attributes conformant\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-005: Rendering Intent Upper Bits Zero (ICC.1-2022-05 §7.2.15)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF005_RenderingIntentUpperBits(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number intent = pIcc->m_Header.renderingIntent;

  printf("%s[CF-005]%s Rendering Intent Upper Bits Zero (%sICC.1-2022-05 §7.2.15%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number upper16 = intent & 0xFFFF0000u;
  icUInt32Number lower16 = intent & 0x0000FFFFu;

  if (upper16 != 0) {
    printf("         renderingIntent=0x%08X — %supper 16 bits non-zero (0x%04X)%s\n",
           intent, ColorError(), upper16 >> 16, ColorReset());
    printf("         %s[FAIL]%s Upper 16 bits must be zero — ICC.1-2022-05 §7.2.15\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (lower16 > 3) {
    printf("         renderingIntent=%u — %sinvalid value (must be 0-3)%s\n",
           lower16, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Rendering intent out of range — ICC.1-2022-05 §7.2.15\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0) {
    static const char *kIntentNames[] = {
      "Perceptual", "Media-Relative Colorimetric",
      "Saturation", "ICC-Absolute Colorimetric"
    };
    printf("         renderingIntent=%u (%s)\n", lower16, kIntentNames[lower16]);
    printf("         %s[OK]%s Rendering intent conformant\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-006: Profile Version BCD Encoding (ICC.1-2022-05 §7.2.4)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF006_VersionBCD(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number version = pIcc->m_Header.version;

  printf("%s[CF-006]%s Profile Version BCD Encoding (%sICC.1-2022-05 §7.2.4%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  int major    = (version >> 24) & 0xFF;
  int minor    = (version >> 20) & 0x0F;
  int bugfix   = (version >> 16) & 0x0F;
  icUInt32Number reserved = version & 0x0000FFFFu;

  printf("         version=0x%08X → v%d.%d.%d.0\n", version, major, minor, bugfix);

  if (reserved != 0) {
    printf("         %sBytes 10-11 non-zero (0x%04X) — must be 0x0000%s\n",
           ColorError(), reserved, ColorReset());
    printf("         %s[FAIL]%s Version reserved bytes must be zero — ICC.1-2022-05 §7.2.4\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (major < 2 || major > 5) {
    printf("         %sMajor version %d not in recognized range (2-5)%s\n",
           ColorWarning(), major, ColorReset());
    printf("         %s[FAIL]%s Unknown major version — ICC.1-2022-05 §7.2.4\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (minor > 9) {
    printf("         %sMinor nibble %d invalid BCD digit (must be 0-9)%s\n",
           ColorError(), minor, ColorReset());
    printf("         %s[FAIL]%s Invalid BCD minor version — ICC.1-2022-05 §7.2.4\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (bugfix > 9) {
    printf("         %sBugfix nibble %d invalid BCD digit (must be 0-9)%s\n",
           ColorError(), bugfix, ColorReset());
    printf("         %s[FAIL]%s Invalid BCD bugfix version — ICC.1-2022-05 §7.2.4\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Version BCD encoding conformant\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-007: Primary Platform Signature (ICC.1-2022-05 §7.2.10 Table 20)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF007_PrimaryPlatform(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number platform = static_cast<icUInt32Number>(pIcc->m_Header.platform);

  printf("%s[CF-007]%s Primary Platform Signature (%sICC.1-2022-05 §7.2.10 Table 20%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  char platCC[5];
  SigToChars(platform, platCC);

  bool found = false;
  for (int i = 0; i < kValidPlatformCount; i++) {
    if (platform == kValidPlatforms[i]) { found = true; break; }
  }

  if (!found) {
    printf("         platform=0x%08X ('%s') — %sunrecognized%s\n",
           platform, platCC, ColorWarning(), ColorReset());
    printf("         %s[WARN]%s Platform not in ICC-defined set — ICC.1-2022-05 §7.2.10\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    const char *name = "unspecified";
    if (platform == static_cast<icUInt32Number>(icSigMacintosh)) name = "Apple (APPL)";
    else if (platform == static_cast<icUInt32Number>(icSigMicrosoft)) name = "Microsoft (MSFT)";
    else if (platform == static_cast<icUInt32Number>(icSigSGI))      name = "SGI (SGI )";
    else if (platform == static_cast<icUInt32Number>(icSigSolaris))   name = "Sun (SUNW)";
    printf("         platform=%s\n", name);
    printf("         %s[OK]%s Platform signature conformant\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-008: PCS Illuminant D50 Precision (ICC.1-2022-05 §7.2.16)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF008_PCSIlluminantD50(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-008]%s PCS Illuminant D50 Precision (%sICC.1-2022-05 §7.2.16%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // D50 reference values in s15Fixed16Number
  // X = 0.9642 → 0x0000F6D6, Y = 1.0000 → 0x00010000, Z = 0.8249 → 0x0000D32D
  static const double kD50_X = 0.9642;
  static const double kD50_Y = 1.0000;
  static const double kD50_Z = 0.8249;
  static const double kTolerance = 0.0001;

  double ix = icFtoD(pIcc->m_Header.illuminant.X);
  double iy = icFtoD(pIcc->m_Header.illuminant.Y);
  double iz = icFtoD(pIcc->m_Header.illuminant.Z);

  printf("         illuminant X=%.4f, Y=%.4f, Z=%.4f\n", ix, iy, iz);
  printf("         expected   X=%.4f, Y=%.4f, Z=%.4f (D50)\n", kD50_X, kD50_Y, kD50_Z);

  if (fabs(ix - kD50_X) > kTolerance) {
    printf("         %sX deviation: %.6f (tolerance %.4f)%s\n",
           ColorError(), fabs(ix - kD50_X), kTolerance, ColorReset());
    printf("         %s[FAIL]%s PCS illuminant X does not match D50 — ICC.1-2022-05 §7.2.16\n",
           ColorError(), ColorReset());
    issues++;
  }
  if (fabs(iy - kD50_Y) > kTolerance) {
    printf("         %sY deviation: %.6f (tolerance %.4f)%s\n",
           ColorError(), fabs(iy - kD50_Y), kTolerance, ColorReset());
    printf("         %s[FAIL]%s PCS illuminant Y does not match D50 — ICC.1-2022-05 §7.2.16\n",
           ColorError(), ColorReset());
    issues++;
  }
  if (fabs(iz - kD50_Z) > kTolerance) {
    printf("         %sZ deviation: %.6f (tolerance %.4f)%s\n",
           ColorError(), fabs(iz - kD50_Z), kTolerance, ColorReset());
    printf("         %s[FAIL]%s PCS illuminant Z does not match D50 — ICC.1-2022-05 §7.2.16\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s PCS illuminant matches D50\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-009: Chromatic Adaptation Tag Requirement (ICC.1-2022-05 §8.2)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF009_ChadTagRequirement(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-009]%s Chromatic Adaptation Tag Requirement (%sICC.1-2022-05 §8.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt32Number version = pIcc->m_Header.version;
  int major = (version >> 24) & 0xFF;
  bool isDeviceLink = (pIcc->m_Header.deviceClass == icSigLinkClass);

  // chad tag is relevant for v4+ non-DeviceLink profiles
  if (major < 4 || isDeviceLink) {
    printf("         Version %d.x %s — chad tag check not applicable\n",
           major, isDeviceLink ? "(DeviceLink)" : "");
    printf("         %s[OK]%s Not required for this profile type\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Check if illuminant deviates from D50
  static const double kTolerance = 0.0001;
  double ix = icFtoD(pIcc->m_Header.illuminant.X);
  double iy = icFtoD(pIcc->m_Header.illuminant.Y);
  double iz = icFtoD(pIcc->m_Header.illuminant.Z);

  bool illumIsD50 = (fabs(ix - 0.9642) <= kTolerance &&
                     fabs(iy - 1.0000) <= kTolerance &&
                     fabs(iz - 0.8249) <= kTolerance);

  const CIccTag *chadTag = pIcc->FindTag(icSigChromaticAdaptationTag);

  if (!illumIsD50 && !chadTag) {
    printf("         Illuminant deviates from D50, chad tag: %smissing%s\n",
           ColorError(), ColorReset());
    printf("         %s[FAIL]%s chad tag required when adopted white != D50 — ICC.1-2022-05 §8.2\n",
           ColorError(), ColorReset());
    issues++;
  } else if (chadTag) {
    printf("         chad tag present\n");
    printf("         %s[OK]%s Chromatic adaptation tag conformant\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("         Illuminant is D50, chad tag not required\n");
    printf("         %s[OK]%s Chromatic adaptation tag conformant\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-010: Profile Size vs File Size (ICC.1-2022-05 §7.2.2)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF010_ProfileSizeVsFileSize(CIccProfile *pIcc, const char *filename) {
  int issues = 0;

  printf("%s[CF-010]%s Profile Size vs File Size (%sICC.1-2022-05 §7.2.2%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename) {
    printf("         %sNo filename provided — cannot verify file size%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s File size check skipped\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("         %sCannot open file for size verification%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s File size check skipped\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  icUInt32Number headerSize = pIcc->m_Header.size;
  long actualSize = fh.fileSize;

  printf("         Header size: %u bytes, File size: %ld bytes\n",
         headerSize, actualSize);

  // Allow trailing padding up to 4-byte boundary
  long paddedHeader = static_cast<long>((headerSize + 3u) & ~3u);

  if (static_cast<long>(headerSize) != actualSize && paddedHeader != actualSize) {
    printf("         %sSize mismatch: header=%u, file=%ld%s\n",
           ColorError(), headerSize, actualSize, ColorReset());
    printf("         %s[FAIL]%s Profile size must match file size — ICC.1-2022-05 §7.2.2\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         %s[OK]%s Profile size matches file size\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-011: Profile ID MD5 Verification (ICC.1-2022-05 §7.2.18, RFC 1321)
//
// The Profile ID is the MD5 hash of the entire profile with bytes
// 44-47 (flags), 64-67 (rendering intent), and 84-99 (profile ID) zeroed.
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF011_ProfileIDMD5(CIccProfile *pIcc, const char *filename) {
  int issues = 0;

  printf("%s[CF-011]%s Profile ID MD5 Verification (%sICC.1-2022-05 §7.2.18%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Check if profile ID is all zeros (not computed)
  const icUInt8Number *profileID = pIcc->m_Header.profileID.ID8;
  bool allZero = true;
  for (int i = 0; i < 16; i++) {
    if (profileID[i] != 0) { allZero = false; break; }
  }

  if (allZero) {
    printf("         Profile ID is all zeros — not computed\n");
    printf("         %s[INFO]%s Profile ID not set — §7.2.18\n",
           ColorInfo(), ColorReset());
    return 0;
  }

  if (!filename) {
    printf("         %sNo filename provided — cannot verify MD5%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s MD5 verification skipped\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("         %sCannot open file for MD5 verification%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s MD5 verification skipped\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  if (fh.fileSize < 128) {
    printf("         %sFile too small for MD5 verification (%ld bytes)%s\n",
           ColorError(), fh.fileSize, ColorReset());
    printf("         %s[FAIL]%s File truncated\n", ColorError(), ColorReset());
    return 1;
  }

  // Read entire profile into memory
  std::vector<uint8_t> data(static_cast<size_t>(fh.fileSize));
  if (!fh.Seek(0) || !fh.ReadBytes(data.data(), data.size())) {
    printf("         %sFailed to read file data%s\n", ColorError(), ColorReset());
    printf("         %s[WARN]%s MD5 verification skipped\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  // Zero the three ranges per §7.2.18 before computing MD5
  // Bytes 44-47 (profile flags)
  for (int i = 44; i <= 47 && i < (int)data.size(); i++) data[i] = 0;
  // Bytes 64-67 (rendering intent)
  for (int i = 64; i <= 67 && i < (int)data.size(); i++) data[i] = 0;
  // Bytes 84-99 (profile ID itself)
  for (int i = 84; i <= 99 && i < (int)data.size(); i++) data[i] = 0;

  // Compute MD5 using OpenSSL EVP
  unsigned char computedMD5[EVP_MAX_MD_SIZE];
  unsigned int md5Len = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    printf("         %sFailed to allocate MD5 context%s\n",
           ColorWarning(), ColorReset());
    printf("         %s[WARN]%s MD5 verification skipped\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  bool ok = (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) == 1) &&
            (EVP_DigestUpdate(ctx, data.data(), data.size()) == 1) &&
            (EVP_DigestFinal_ex(ctx, computedMD5, &md5Len) == 1);
  EVP_MD_CTX_free(ctx);

  if (!ok || md5Len < 16) {
    printf("         %sMD5 computation failed%s\n", ColorWarning(), ColorReset());
    printf("         %s[WARN]%s MD5 verification skipped\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  // Compare computed MD5 with stored profile ID
  if (memcmp(computedMD5, profileID, 16) != 0) {
    char stored[33] = {}, computed[33] = {};
    for (int i = 0; i < 16; i++) {
      snprintf(stored + i * 2, 3, "%02x", profileID[i]);
      snprintf(computed + i * 2, 3, "%02x", computedMD5[i]);
    }
    printf("         Stored:   %s\n", stored);
    printf("         Computed: %s\n", computed);
    printf("         %s[WARN]%s Profile ID MD5 mismatch — ICC.1-2022-05 §7.2.18\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    char hex[33] = {};
    for (int i = 0; i < 16; i++)
      snprintf(hex + i * 2, 3, "%02x", profileID[i]);
    printf("         Profile ID: %s — MD5 verified\n", hex);
    printf("         %s[OK]%s Profile ID matches computed MD5\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-012: Profile Class Signature (ICC.1-2022-05 §7.2.5 Table 18)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF012_ProfileClassSignature(CIccProfile *pIcc) {
  icUInt32Number devClass = static_cast<icUInt32Number>(pIcc->m_Header.deviceClass);

  printf("%s[CF-012]%s Profile Class Signature (%sICC.1-2022-05 §7.2.5 Table 18%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  char classCC[5];
  SigToChars(devClass, classCC);

  // Check v4 classes first
  bool foundV4 = false;
  for (int i = 0; i < kV4DeviceClassCount; i++) {
    if (devClass == kV4DeviceClasses[i]) { foundV4 = true; break; }
  }

  if (foundV4) {
    printf("         deviceClass='%s' (0x%08X)\n", classCC, devClass);
    printf("         %s[OK]%s Valid v4 profile class\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Check v5 extended classes
  bool foundV5 = false;
  for (int i = 0; i < kV5DeviceClassCount; i++) {
    if (devClass == kV5DeviceClasses[i]) { foundV5 = true; break; }
  }

  if (foundV5) {
    int major = (pIcc->m_Header.version >> 24) & 0xFF;
    printf("         deviceClass='%s' (0x%08X) — v5/iccMAX class\n", classCC, devClass);
    if (major < 5) {
      printf("         %sv5 class in v%d profile%s\n",
             ColorWarning(), major, ColorReset());
      printf("         %s[WARN]%s v5 class used in pre-v5 profile — ICC.2-2023 §7.2.5\n",
             ColorWarning(), ColorReset());
      return 1;
    } else {
      printf("         %s[OK]%s Valid v5 profile class\n",
             ColorSuccess(), ColorReset());
    }
    return 0;
  }

  // Unknown class
  printf("         deviceClass='%s' (0x%08X) — %sunknown%s\n",
         classCC, devClass, ColorError(), ColorReset());
  printf("         %s[FAIL]%s Unrecognized profile class signature — ICC.1-2022-05 §7.2.5\n",
         ColorError(), ColorReset());
  return 1;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-013: Data Colour Space Signature (ICC.1-2022-05 §7.2.6 Table 19)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF013_DataColourSpace(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number cs = static_cast<icUInt32Number>(pIcc->m_Header.colorSpace);

  printf("%s[CF-013]%s Data Colour Space Signature (%sICC.1-2022-05 §7.2.6 Table 19%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  char csCC[5];
  SigToChars(cs, csCC);

  if (IsConformantColorSpace(cs)) {
    const char *name = ColorSpaceSignatureToStr(cs);
    printf("         colorSpace='%s' (0x%08X) — %s\n", csCC, cs, name);
    printf("         %s[OK]%s Valid colour space signature\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("         colorSpace='%s' (0x%08X) — %sunrecognized%s\n",
           csCC, cs, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Unknown colour space signature — ICC.1-2022-05 §7.2.6\n",
           ColorError(), ColorReset());
    issues++;
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-014: PCS Field for Non-DeviceLink (ICC.1-2022-05 §7.2.7)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF014_PCSForNonDeviceLink(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number pcs = static_cast<icUInt32Number>(pIcc->m_Header.pcs);
  bool isDeviceLink = (pIcc->m_Header.deviceClass == icSigLinkClass);

  printf("%s[CF-014]%s PCS Field for Non-DeviceLink (%sICC.1-2022-05 §7.2.7%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  char pcsCC[5];
  SigToChars(pcs, pcsCC);

  if (isDeviceLink) {
    // DeviceLink: PCS can be any colour space
    printf("         DeviceLink profile — PCS='%s' (0x%08X)\n", pcsCC, pcs);
    printf("         %s[OK]%s DeviceLink PCS unconstrained\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Non-DeviceLink: PCS must be XYZ or Lab (or spectral for v5)
  bool pcsValid = (pcs == static_cast<icUInt32Number>(icSigXYZData) ||
                   pcs == static_cast<icUInt32Number>(icSigLabData));

  // v5 allows spectral PCS as well
  int major = (pIcc->m_Header.version >> 24) & 0xFF;
  if (major >= 5 && !pcsValid) {
    icUInt32Number csType = icGetColorSpaceType(static_cast<icColorSpaceSignature>(pcs));
    if (csType == static_cast<icUInt32Number>(icSigNChannelData))
      pcsValid = true;
  }

  if (pcsValid) {
    printf("         PCS='%s' (0x%08X)\n", pcsCC, pcs);
    printf("         %s[OK]%s PCS conformant for non-DeviceLink profile\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("         PCS='%s' (0x%08X) — %smust be XYZ or Lab%s\n",
           pcsCC, pcs, ColorError(), ColorReset());
    printf("         %s[FAIL]%s Non-DeviceLink PCS must be PCSXYZ or PCSLab — ICC.1-2022-05 §7.2.7\n",
           ColorError(), ColorReset());
    issues++;
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-015: Reserved Bytes 100-127 Zero (ICC.1-2022-05 §7.2.24)
// ═══════════════════════════════════════════════════════════════════════════════

int RunCF015_ReservedBytesZero(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  (void)pIcc;  // Reserved bytes checked via raw file read

  printf("%s[CF-015]%s Reserved Bytes 100-127 Zero (%sICC.1-2022-05 §7.2.24%s)\n",
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
    printf("         %sCannot open file%s\n", ColorWarning(), ColorReset());
    printf("         %s[WARN]%s Reserved bytes check skipped\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  if (fh.fileSize < 128) {
    printf("         %sFile too small (%ld bytes < 128)%s\n",
           ColorError(), fh.fileSize, ColorReset());
    printf("         %s[FAIL]%s File truncated before reserved bytes — ICC.1-2022-05 §7.2.24\n",
           ColorError(), ColorReset());
    return 1;
  }

  uint8_t reserved[28];
  if (!fh.Seek(100) || !fh.ReadBytes(reserved, 28)) {
    printf("         %sFailed to read bytes 100-127%s\n", ColorError(), ColorReset());
    printf("         %s[FAIL]%s I/O error reading reserved bytes\n",
           ColorError(), ColorReset());
    return 1;
  }

  int nonZeroCount = 0;
  int firstNonZero = -1;
  for (int i = 0; i < 28; i++) {
    if (reserved[i] != 0x00) {
      nonZeroCount++;
      if (firstNonZero < 0) firstNonZero = i;
    }
  }

  if (nonZeroCount > 0) {
    printf("         %s%d non-zero byte(s) in range 100-127 (first at offset %d)%s\n",
           ColorError(), nonZeroCount, 100 + firstNonZero, ColorReset());
    printf("         %s[FAIL]%s Reserved bytes must be zero — ICC.1-2022-05 §7.2.24\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         Bytes 100-127: all zero\n");
    printf("         %s[OK]%s Reserved bytes conformant\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-107: Tag Table Ordering (ICC.1-2022-05 §7.3.1)
//
// The tag table entries SHOULD be in order of increasing offset.
// While not strictly required, the spec recommends this for efficient parsing.
// Duplicate tag signatures MUST NOT occur.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF107_TagTableOrdering(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-107]%s Tag Table Ordering (%sICC.1-2022-05 §7.3.1%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Check for duplicate tag signatures
  std::vector<icTagSignature> sigs;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    for (size_t j = 0; j < sigs.size(); j++) {
      if (sigs[j] == it->TagInfo.sig) {
        char sigStr[5] = {};
        SigToChars(it->TagInfo.sig, sigStr);
        printf("         Duplicate tag signature '%s' (0x%08X)\n",
               sigStr, (unsigned)it->TagInfo.sig);
        printf("         %s[FAIL]%s Duplicate tag signatures prohibited — §7.3.1\n",
               ColorError(), ColorReset());
        issues++;
        break;
      }
    }
    sigs.push_back(it->TagInfo.sig);
  }

  if (issues == 0)
    printf("         %s[OK]%s Tag table has no duplicate signatures\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-121: Illuminant Metadata Consistency (ICC.1-2022-05 §7.2.16)
//
// The PCS illuminant in the header MUST be D50 (X=0.9642, Y=1.0000, Z=0.8249).
// This check validates the illuminant against the mediaWhitePointTag — for
// non-absolute-colorimetric transforms, the wtpt should also represent D50.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF121_IlluminantMetadataConsistency(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-121]%s Illuminant Metadata Consistency (%sICC.1-2022-05 §7.2.16%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Check mediaWhitePointTag value consistency with D50
  CIccTag *wtptTag = pIcc->FindTag(icSigMediaWhitePointTag);
  if (!wtptTag) {
    printf("         No mediaWhitePointTag found — check not applicable\n");
    return 0;
  }

  CIccTagXYZ *wtpt = dynamic_cast<CIccTagXYZ *>(wtptTag);
  if (!wtpt || wtpt->GetSize() < 1) {
    printf("         mediaWhitePointTag is not valid XYZ type\n");
    return 0;
  }

  icXYZNumber val = (*wtpt)[0];
  icFloatNumber y = icFtoD(val.Y);

  // ICC.1-2022-05 §9.2.28: The mediaWhitePointTag for v4 profiles
  // SHALL be D50 (already checked by CF-008 for header illuminant).
  // Here we check the tag value: Y should be ~1.0 for D50-adapted white.
  icUInt32Number version = pIcc->m_Header.version >> 24;
  if (version >= 4) {
    icFloatNumber x = icFtoD(val.X);
    icFloatNumber z = icFtoD(val.Z);

    const icFloatNumber *d50 = icD50XYZ;
    if (d50 && (std::fabs(x - d50[0]) > 0.01 ||
                std::fabs(y - d50[1]) > 0.01 ||
                std::fabs(z - d50[2]) > 0.01)) {
      printf("         V4 mediaWhitePointTag (%.4f, %.4f, %.4f) ≠ D50\n", x, y, z);
      printf("         %s[FAIL]%s V4 wtpt must be D50 — §9.2.28\n",
             ColorError(), ColorReset());
      issues++;
    }
  }

  // For any version: Y value should be positive
  if (y <= 0.0) {
    printf("         mediaWhitePointTag Y=%.4f ≤ 0 — invalid luminance\n", y);
    printf("         %s[FAIL]%s White point Y must be positive — §9.2.28\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Illuminant metadata consistent\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-122: Profile Date/Time Plausibility (ICC.1-2022-05 §7.2.8)
//
// The profile creation date/time SHOULD be a plausible timestamp:
//   - Year in range [1990, 2099] (ICC spec era)
//   - Not a future date (warning, not error)
//   - Not the zero date (indicates unset)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF122_ProfileDateTimePlausibility(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-122]%s Profile Date/Time Plausibility (%sICC.1-2022-05 §7.2.8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icDateTimeNumber dt = pIcc->m_Header.date;

  // Check if entirely zero (unset)
  if (dt.year == 0 && dt.month == 0 && dt.day == 0 &&
      dt.hours == 0 && dt.minutes == 0 && dt.seconds == 0) {
    printf("         Date/time is all zeros — creation date not set\n");
    printf("         %s[INFO]%s Zero date indicates unset — §7.2.8\n",
           ColorInfo(), ColorReset());
    return 0;
  }

  // Year plausibility: ICC spec began in 1994
  if (dt.year < 1990 || dt.year > 2099) {
    printf("         Year %u is outside plausible range [1990-2099]\n", dt.year);
    printf("         %s[WARN]%s Profile date year implausible — §7.2.8\n",
           ColorError(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Profile date/time is plausible\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-184: Profile ID v4+ Presence (ICC.1-2022-05 §7.2.18, RFC 1321)
//
// §7.2.18: "This field, if not zero, shall hold the Profile ID."
// For v4+ profiles the spec recommends computing the Profile ID.
// A zero Profile ID is technically allowed but indicates the ID was not set,
// reducing data integrity assurance.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF184_ProfileIDV4Presence(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-184]%s Profile ID v4+ Presence (%sICC.1-2022-05 §7.2.18, RFC 1321%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  icUInt8Number majorVer = static_cast<icUInt8Number>(pIcc->m_Header.version >> 24);
  printf("         Profile version: %u.x\n", majorVer);

  // v2 profiles: Profile ID was introduced in v4; skip for v2
  if (majorVer < 4) {
    printf("         v2 profile — Profile ID field not defined before v4\n");
    printf("         %s[OK]%s v2 profiles exempt from Profile ID requirement\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Check if Profile ID is all zeros
  const icUInt8Number *pid = pIcc->m_Header.profileID.ID8;
  bool allZero = true;
  for (int i = 0; i < 16; i++) {
    if (pid[i] != 0) { allZero = false; break; }
  }

  if (allZero) {
    printf("         Profile ID is all zeros (not computed)\n");
    printf("         %s[WARN]%s v4+ profile SHOULD have computed Profile ID — §7.2.18\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    char hex[33] = {};
    for (int i = 0; i < 16; i++)
      snprintf(hex + i * 2, 3, "%02x", pid[i]);
    printf("         Profile ID: %s\n", hex);
    printf("         %s[OK]%s v4+ profile has computed Profile ID\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-185: Profile ID Size Consistency (ICC.1-2022-05 §7.2.18, RFC 1321)
//
// The Profile ID is the MD5 hash computed over the entire profile.
// RFC 1321 §3.1 specifies the message length as part of MD5 padding.
// If the header-declared profile size differs from the actual file size,
// the MD5 hash was computed over different data than what the file contains.
// This cross-validates CF-010 (size) and CF-011 (MD5) together.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF185_ProfileIDSizeConsistency(CIccProfile *pIcc, const char *filename) {
  int issues = 0;

  printf("%s[CF-185]%s Profile ID Size Consistency (%sICC.1-2022-05 §7.2.18, RFC 1321 §3.1%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Skip if Profile ID is all zeros
  const icUInt8Number *pid = pIcc->m_Header.profileID.ID8;
  bool allZero = true;
  for (int i = 0; i < 16; i++) {
    if (pid[i] != 0) { allZero = false; break; }
  }
  if (allZero) {
    printf("         Profile ID is zero — size consistency check not applicable\n");
    printf("         %s[OK]%s No Profile ID to validate\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  if (!filename) {
    printf("         %sNo filename — cannot check file size%s\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("         %sCannot open file%s\n", ColorWarning(), ColorReset());
    return 0;
  }

  icUInt32Number headerSize = pIcc->m_Header.size;
  long fileSize = fh.fileSize;

  printf("         Header-declared size: %u bytes\n", headerSize);
  printf("         Actual file size: %ld bytes\n", fileSize);

  // If sizes don't match, the MD5 was computed over different data
  if (headerSize > 0 && static_cast<long>(headerSize) != fileSize) {
    // Allow 4-byte padding tolerance
    long paddedHeader = static_cast<long>((headerSize + 3u) & ~3u);
    if (paddedHeader != fileSize) {
      printf("         Size mismatch: MD5 computed over %u bytes, file is %ld bytes\n",
             headerSize, fileSize);
      printf("         %s[WARN]%s Profile ID MD5 input length inconsistent — §7.2.18 + RFC 1321 §3.1\n",
             ColorWarning(), ColorReset());
      issues++;
    } else {
      printf("         %s[OK]%s Size matches within 4-byte alignment padding\n",
             ColorSuccess(), ColorReset());
    }
  } else {
    printf("         %s[OK]%s Header size matches file size — MD5 input length consistent\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-186: Profile ID Entropy Analysis (RFC 1321, ICC.1-2022-05 §7.2.18)
//
// A valid MD5 hash should have near-uniform byte distribution.
// Detects Profile IDs that are unlikely to be genuine MD5 outputs:
//   - All same byte (e.g., 0xFF repeated) — clearly not MD5
//   - Repeating short pattern (e.g., 0xABCD repeated) — not MD5
//   - Very low unique byte count — statistically implausible for MD5
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF186_ProfileIDEntropy(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-186]%s Profile ID Entropy Analysis (%sRFC 1321, ICC.1-2022-05 §7.2.18%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  const icUInt8Number *pid = pIcc->m_Header.profileID.ID8;

  // Skip if all zeros (not computed)
  bool allZero = true;
  for (int i = 0; i < 16; i++) {
    if (pid[i] != 0) { allZero = false; break; }
  }
  if (allZero) {
    printf("         Profile ID is zero — entropy analysis not applicable\n");
    printf("         %s[OK]%s No Profile ID to analyze\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  // Print the Profile ID
  char hex[33] = {};
  for (int i = 0; i < 16; i++)
    snprintf(hex + i * 2, 3, "%02x", pid[i]);
  printf("         Profile ID: %s\n", hex);

  // Check 1: All same byte (e.g., 0xFFFFFF... or 0x414141...)
  bool allSame = true;
  for (int i = 1; i < 16; i++) {
    if (pid[i] != pid[0]) { allSame = false; break; }
  }
  if (allSame) {
    printf("         All 16 bytes are 0x%02x — not a valid MD5 output\n", pid[0]);
    printf("         %s[WARN]%s Profile ID has constant byte pattern — §7.2.18\n",
           ColorWarning(), ColorReset());
    return 1;
  }

  // Check 2: Short repeating pattern (2-byte or 4-byte repeat)
  bool repeat2 = true;
  for (int i = 2; i < 16; i++) {
    if (pid[i] != pid[i % 2]) { repeat2 = false; break; }
  }
  bool repeat4 = true;
  for (int i = 4; i < 16; i++) {
    if (pid[i] != pid[i % 4]) { repeat4 = false; break; }
  }
  if (repeat2 || repeat4) {
    printf("         Profile ID has short repeating pattern (%d-byte cycle)\n",
           repeat2 ? 2 : 4);
    printf("         %s[WARN]%s Profile ID unlikely to be genuine MD5 — RFC 1321\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  // Check 3: Unique byte count — MD5 of any reasonable input should have
  // high entropy. With 16 bytes, seeing <= 2 unique values is suspicious.
  bool seen[256] = {};
  int uniqueCount = 0;
  for (int i = 0; i < 16; i++) {
    if (!seen[pid[i]]) {
      seen[pid[i]] = true;
      uniqueCount++;
    }
  }
  printf("         Unique byte values: %d/16\n", uniqueCount);
  if (uniqueCount <= 2) {
    printf("         Very low entropy — Profile ID may not be genuine MD5\n");
    printf("         %s[WARN]%s Profile ID entropy implausible — RFC 1321\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Profile ID entropy consistent with MD5 output\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-187: Embedded Profile ProfileID Chain (ICC TN Embedding, §7.2.18, RFC 1321)
//
// When a v4/v5 ICC.1 profile embeds an ICC.2 profile via
// icSigEmbeddedV5ProfileTag, both the outer and inner profiles should
// have valid Profile IDs. An inner profile with a zero ID reduces the
// integrity assurance of the embedding chain.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF187_EmbeddedProfileIDChain(CIccProfile *pIcc) {
  int issues = 0;

  printf("%s[CF-187]%s Embedded Profile ProfileID Chain (%sICC TN Embedding + §7.2.18 + RFC 1321%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Find the embedded profile tag
  CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
  if (!pTag) {
    printf("         No embedded profile tag (ICC5) present\n");
    printf("         %s[OK]%s No embedding chain to validate\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  CIccTagEmbeddedProfile *pEmbed = dynamic_cast<CIccTagEmbeddedProfile*>(pTag);
  if (!pEmbed || !pEmbed->m_pProfile) {
    printf("         Embedded profile tag present but profile not loaded\n");
    printf("         %s[WARN]%s Cannot validate embedded Profile ID\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  CIccProfile *pInner = pEmbed->m_pProfile;
  icUInt8Number innerMajor = static_cast<icUInt8Number>(pInner->m_Header.version >> 24);
  printf("         Embedded profile version: %u.x\n", innerMajor);

  // Check inner profile's Profile ID
  const icUInt8Number *innerPid = pInner->m_Header.profileID.ID8;
  bool innerAllZero = true;
  for (int i = 0; i < 16; i++) {
    if (innerPid[i] != 0) { innerAllZero = false; break; }
  }

  if (innerAllZero && innerMajor >= 4) {
    printf("         Embedded v%u profile has zero Profile ID\n", innerMajor);
    printf("         %s[WARN]%s Embedded v4+ profile SHOULD have computed Profile ID — §7.2.18\n",
           ColorWarning(), ColorReset());
    issues++;
  } else if (!innerAllZero) {
    char hex[33] = {};
    for (int i = 0; i < 16; i++)
      snprintf(hex + i * 2, 3, "%02x", innerPid[i]);
    printf("         Embedded Profile ID: %s\n", hex);
    printf("         %s[OK]%s Embedded profile has computed Profile ID\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("         Embedded v%u profile — Profile ID not required\n", innerMajor);
    printf("         %s[OK]%s Pre-v4 embedded profile exempt\n",
           ColorSuccess(), ColorReset());
  }

  // Also check outer profile's ID for completeness
  const icUInt8Number *outerPid = pIcc->m_Header.profileID.ID8;
  bool outerAllZero = true;
  for (int i = 0; i < 16; i++) {
    if (outerPid[i] != 0) { outerAllZero = false; break; }
  }
  icUInt8Number outerMajor = static_cast<icUInt8Number>(pIcc->m_Header.version >> 24);

  if (outerAllZero && outerMajor >= 4) {
    printf("         Outer v%u profile has zero Profile ID while embedding v%u profile\n",
           outerMajor, innerMajor);
    printf("         %s[WARN]%s Outer profile SHOULD have Profile ID for chain integrity — §7.2.18\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Embedding chain Profile IDs are consistent\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Dispatcher — runs all header conformance checks
// ═══════════════════════════════════════════════════════════════════════════════

int RunHeaderConformance(CIccProfile *pIcc, const char *filename) {
  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  int r;

#define CF_WRAP(id, title, call) \
  hc.begin(id, title); \
  r = call; \
  if (r > 0) hc.warn("%d non-conformance(s)", r); \
  hc.end("Conformant"); \
  issues += r

  CF_WRAP(1001, "CF-001: Date/Time Month-Day Validity", RunCF001_DateTimeMonthDay(pIcc));
  CF_WRAP(1002, "CF-002: Date/Time Leap Year Validation", RunCF002_DateTimeLeapYear(pIcc));
  CF_WRAP(1003, "CF-003: Profile Flags Reserved Bits", RunCF003_ProfileFlagsReserved(pIcc));
  CF_WRAP(1004, "CF-004: Device Attributes Reserved Bits", RunCF004_DeviceAttributesReserved(pIcc));
  CF_WRAP(1005, "CF-005: Rendering Intent Upper Bits Zero", RunCF005_RenderingIntentUpperBits(pIcc));
  CF_WRAP(1006, "CF-006: Version BCD Encoding", RunCF006_VersionBCD(pIcc));
  CF_WRAP(1007, "CF-007: Primary Platform Signature", RunCF007_PrimaryPlatform(pIcc));
  CF_WRAP(1008, "CF-008: PCS Illuminant D50 Values", RunCF008_PCSIlluminantD50(pIcc));
  CF_WRAP(1009, "CF-009: Chromatic Adaptation Tag Requirement", RunCF009_ChadTagRequirement(pIcc));
  CF_WRAP(1010, "CF-010: Profile Size vs File Size", RunCF010_ProfileSizeVsFileSize(pIcc, filename));
  CF_WRAP(1011, "CF-011: Profile ID MD5 Verification", RunCF011_ProfileIDMD5(pIcc, filename));
  CF_WRAP(1012, "CF-012: Profile Class Signature", RunCF012_ProfileClassSignature(pIcc));
  CF_WRAP(1013, "CF-013: Data Colour Space Signature", RunCF013_DataColourSpace(pIcc));
  CF_WRAP(1014, "CF-014: PCS Field for Non-DeviceLink", RunCF014_PCSForNonDeviceLink(pIcc));
  CF_WRAP(1015, "CF-015: Reserved Bytes 100-127 Zero", RunCF015_ReservedBytesZero(pIcc, filename));

  CF_WRAP(1107, "CF-107: Tag Table Ordering", RunCF107_TagTableOrdering(pIcc));
  CF_WRAP(1121, "CF-121: Illuminant Metadata Consistency", RunCF121_IlluminantMetadataConsistency(pIcc));
  CF_WRAP(1122, "CF-122: Profile Date/Time Plausibility", RunCF122_ProfileDateTimePlausibility(pIcc));

  // RFC 1321 / Profile ID conformance (CF-184..CF-187)
  CF_WRAP(1184, "CF-184: Profile ID v4+ Presence", RunCF184_ProfileIDV4Presence(pIcc));
  CF_WRAP(1185, "CF-185: Profile ID Size Consistency", RunCF185_ProfileIDSizeConsistency(pIcc, filename));
  CF_WRAP(1186, "CF-186: Profile ID Entropy Analysis", RunCF186_ProfileIDEntropy(pIcc));
  CF_WRAP(1187, "CF-187: Embedded Profile ProfileID Chain", RunCF187_EmbeddedProfileIDChain(pIcc));

#undef CF_WRAP
  return issues;
}
