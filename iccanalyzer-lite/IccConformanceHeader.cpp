/*
 * IccConformanceHeader.cpp — ICC specification header conformance checks
 *
 * Implements CF-001 through CF-019, CF-184..CF-187, CF-199..CF-201, CF-203
 * CF-214..CF-219 from the conformance registry.
 * Validates ICC profile header fields against ICC.1-2022-05 §7.2.
 * CF-184..CF-187: RFC 1321 (MD5) Profile ID conformance per §7.2.18.
 * CF-199..CF-201: CMM/Manufacturer/Creator signature registration per §7.2.3/12/17.
 * CF-203: Profile flags semantic validation per §7.2.11 Table 21.
 * CF-214..CF-219: Profile embedding conformance per ICC TN Embedding ICC Profiles.
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

  if (pIcc->m_Header.deviceClass == icSigColorEncodingClass) {
    double ix = icFtoD(pIcc->m_Header.illuminant.X);
    double iy = icFtoD(pIcc->m_Header.illuminant.Y);
    double iz = icFtoD(pIcc->m_Header.illuminant.Z);
    printf("         illuminant X=%.4f, Y=%.4f, Z=%.4f\n", ix, iy, iz);
    if (fabs(ix) > 0.0001 || fabs(iy) > 0.0001 || fabs(iz) > 0.0001) {
      printf("         %s[FAIL]%s ColorEncoding profiles must zero header illuminant fields\n",
             ColorError(), ColorReset());
      return 1;
    }
    printf("         %s[OK]%s ColorEncoding header illuminant is zero as required\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

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
  bool isColorEncoding = (pIcc->m_Header.deviceClass == icSigColorEncodingClass);

  // chad tag is relevant for v4+ non-DeviceLink profiles
  if (major < 4 || isDeviceLink || isColorEncoding) {
    printf("         Version %d.x %s — chad tag check not applicable\n",
           major,
           isDeviceLink ? "(DeviceLink)" : (isColorEncoding ? "(ColorEncoding)" : ""));
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
// CF-016: Device Manufacturer Signature (ICC.1-2022-05 §7.2.12)
//
// Bytes 48-51 identify the device manufacturer. Zero is permitted (unspecified).
// If non-zero, all 4 bytes should be printable ASCII (0x20-0x7E).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF016_DeviceManufacturerSignature(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number mfr = pIcc->m_Header.manufacturer;

  printf("%s[CF-016]%s Device Manufacturer Signature (%sICC.1-2022-05 §7.2.12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (mfr == 0) {
    printf("         manufacturer=0x00000000 — not specified (permitted)\n");
    printf("         %s[OK]%s Device manufacturer field conformant\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  bool printable = true;
  for (int i = 0; i < 4; i++) {
    unsigned char byte = (mfr >> (24 - i * 8)) & 0xFF;
    if (byte < 0x20 || byte > 0x7E) { printable = false; break; }
  }

  char sigStr[5] = {};
  SigToChars((icTagSignature)mfr, sigStr);

  if (!printable) {
    printf("         manufacturer=0x%08X — %snon-printable bytes%s\n",
           mfr, ColorWarning(), ColorReset());
    printf("         %s[WARN]%s Device manufacturer contains non-printable ASCII — ICC.1-2022-05 §7.2.12\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    printf("         manufacturer='%s' (0x%08X)\n", sigStr, mfr);
    printf("         %s[OK]%s Device manufacturer field conformant\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-017: Device Model Signature (ICC.1-2022-05 §7.2.13)
//
// Bytes 52-55 identify the device model. Zero is permitted (unspecified).
// If non-zero, all 4 bytes should be printable ASCII (0x20-0x7E).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF017_DeviceModelSignature(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number mdl = pIcc->m_Header.model;

  printf("%s[CF-017]%s Device Model Signature (%sICC.1-2022-05 §7.2.13%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (mdl == 0) {
    printf("         model=0x00000000 — not specified (permitted)\n");
    printf("         %s[OK]%s Device model field conformant\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  bool printable = true;
  for (int i = 0; i < 4; i++) {
    unsigned char byte = (mdl >> (24 - i * 8)) & 0xFF;
    if (byte < 0x20 || byte > 0x7E) { printable = false; break; }
  }

  char sigStr[5] = {};
  SigToChars((icTagSignature)mdl, sigStr);

  if (!printable) {
    printf("         model=0x%08X — %snon-printable bytes%s\n",
           mdl, ColorWarning(), ColorReset());
    printf("         %s[WARN]%s Device model contains non-printable ASCII — ICC.1-2022-05 §7.2.13\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    printf("         model='%s' (0x%08X)\n", sigStr, mdl);
    printf("         %s[OK]%s Device model field conformant\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-018: Device Attributes Semantic Bits (ICC.1-2022-05 §7.2.14 Table 23)
//
// Bits 0-3 have defined semantics (reflective/transparency, glossy/matte,
// positive/negative, colour/b&w). Bits 4-31 are reserved for ICC and must
// be zero. Bits 32-63 are device-specific (no validation).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF018_DeviceAttributesBits(CIccProfile *pIcc) {
  int issues = 0;
  icUInt64Number attrs = pIcc->m_Header.attributes;

  printf("%s[CF-018]%s Device Attributes Semantic Bits (%sICC.1-2022-05 §7.2.14 Table 23%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // Display defined bits 0-3
  printf("         Bit 0 (Media): %s\n",
         (attrs & 0x0001) ? "transparency" : "reflective");
  printf("         Bit 1 (Finish): %s\n",
         (attrs & 0x0002) ? "matte" : "glossy");
  printf("         Bit 2 (Polarity): %s\n",
         (attrs & 0x0004) ? "negative" : "positive");
  printf("         Bit 3 (Colour): %s\n",
         (attrs & 0x0008) ? "black & white" : "colour");

  // Bits 4-31 are reserved for ICC — must be zero
  icUInt32Number reservedBits = static_cast<icUInt32Number>(attrs) & 0xFFFFFFF0u;
  if (reservedBits != 0) {
    printf("         Reserved bits 4-31: 0x%08X — %snon-zero%s\n",
           reservedBits, ColorWarning(), ColorReset());
    printf("         %s[WARN]%s Reserved attribute bits 4-31 must be zero — ICC.1-2022-05 §7.2.14\n",
           ColorWarning(), ColorReset());
    issues++;
  }

  if (issues == 0)
    printf("         %s[OK]%s Device attributes conformant\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-019: Creator Signature (ICC.1-2022-05 §7.2.17)
//
// Bytes 80-83 identify the profile creator. Zero is permitted (unspecified).
// If non-zero, all 4 bytes should be printable ASCII (0x20-0x7E).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF019_CreatorSignature(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number creator = pIcc->m_Header.creator;

  printf("%s[CF-019]%s Creator Signature (%sICC.1-2022-05 §7.2.17%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (creator == 0) {
    printf("         creator=0x00000000 — not specified (permitted)\n");
    printf("         %s[OK]%s Creator signature field conformant\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  bool printable = true;
  for (int i = 0; i < 4; i++) {
    unsigned char byte = (creator >> (24 - i * 8)) & 0xFF;
    if (byte < 0x20 || byte > 0x7E) { printable = false; break; }
  }

  char sigStr[5] = {};
  SigToChars((icTagSignature)creator, sigStr);

  if (!printable) {
    printf("         creator=0x%08X — %snon-printable bytes%s\n",
           creator, ColorWarning(), ColorReset());
    printf("         %s[WARN]%s Creator contains non-printable ASCII — ICC.1-2022-05 §7.2.17\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    printf("         creator='%s' (0x%08X)\n", sigStr, creator);
    printf("         %s[OK]%s Creator signature field conformant\n",
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
// CF-199: CMM Type Signature Registration (ICC.1-2022-05 §7.2.3)
//
// Per §7.2.3 the preferredCMMType field (bytes 4-7) "shall contain the
// signature of the preferred CMM to be used." Zero means no preference.
// Non-zero values should be registered with the ICC. This check validates
// the field against registered CMM signatures.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF199_CMMTypeSignatureRegistration(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number cmm = pIcc->m_Header.cmmId;

  printf("  %s[CF-199]%s CMM Type Signature Registration (%sICC.1-2022-05 §7.2.3%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (cmm == 0) {
    printf("           cmmId=0x00000000 — no preferred CMM (permitted)\n");
    printf("           %s[OK]%s CMM type conformant\n", ColorSuccess(), ColorReset());
    return 0;
  }

  // ICC registered CMM signatures (source: ICC signature registry)
  static const icUInt32Number kRegisteredCMMs[] = {
    0x41444245, // 'ADBE' Adobe
    0x41434D53, // 'ACMS' Agfa
    0x6170706C, // 'appl' Apple
    0x43434D53, // 'CCMS' ColorGear
    0x45464920, // 'EFI ' EFI
    0x46462020, // 'FF  ' Fuji Film
    0x48434D4D, // 'HCMM' Heidelberg
    0x48444D20, // 'HDM ' Heidelberg
    0x4C434D53, // 'LCMS' Little CMS
    0x6C636D73, // 'lcms' Little CMS (v2)
    0x4D534654, // 'MSFT' Microsoft ICM
    0x52494D58, // 'RIMX' Mutoh
    0x53494343, // 'SICC' SampleICC
    0x53475243, // 'SGRC' SI Graphics
    0x54434D4D, // 'TCMM' TOSHIBA
    0x5543434D, // 'UCCM' UC CMM
    0x57435320, // 'WCS ' Microsoft WCS
    0x7A63306C, // 'zc0l' Zoran
    0x44696D43, // 'DimC' DemoIccMAX
    0x48504D32, // 'HPM2' HP
    0x6172676C, // 'argl' ArgyllCMS
    0x4B4F4441, // 'KODA' Kodak
    0x52474D53, // 'RGMS' DeviceLink
    0x6F6E7978, // 'onyx' Onyx
  };
  static const int kNumRegistered = sizeof(kRegisteredCMMs) / sizeof(kRegisteredCMMs[0]);

  bool registered = false;
  for (int i = 0; i < kNumRegistered; i++) {
    if (cmm == kRegisteredCMMs[i]) { registered = true; break; }
  }

  char sigStr[5] = {};
  SigToChars((icTagSignature)cmm, sigStr);

  if (!registered) {
    // Check if bytes are at least printable ASCII
    bool printable = true;
    const unsigned char *b = reinterpret_cast<const unsigned char *>(&cmm);
    for (int i = 0; i < 4; i++) {
      unsigned char byte = (cmm >> (24 - i * 8)) & 0xFF;
      if (byte < 0x20 || byte > 0x7E) { printable = false; break; }
    }
    (void)b;

    if (!printable) {
      printf("           cmmId=0x%08X — %snon-printable bytes, not registered%s\n",
             cmm, ColorError(), ColorReset());
      printf("           %s[FAIL]%s CMM type must be registered or zero — §7.2.3\n",
             ColorError(), ColorReset());
      issues++;
    } else {
      printf("           cmmId='%s' (0x%08X) — not in ICC registry\n", sigStr, cmm);
      printf("           %s[WARN]%s CMM signature not in ICC registered list — §7.2.3\n",
             ColorWarning(), ColorReset());
      issues++;
    }
  } else {
    printf("           cmmId='%s' (0x%08X) — registered ICC CMM\n", sigStr, cmm);
    printf("           %s[OK]%s CMM type conformant\n", ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-200: Device Manufacturer/Model Signature (ICC.1-2022-05 §7.2.12-13)
//
// Per §7.2.12 and §7.2.13, the deviceManufacturer and deviceModel fields
// (bytes 48-51 and 52-55) shall either be zero or contain a registered
// signature. All bytes should be printable ASCII (0x20-0x7E).
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF200_DeviceManufacturerModel(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-200]%s Device Manufacturer/Model Signature (%sICC.1-2022-05 §7.2.12-13%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  struct { const char *name; icUInt32Number val; const char *section; } fields[] = {
    {"manufacturer", pIcc->m_Header.manufacturer, "§7.2.12"},
    {"model",        pIcc->m_Header.model,        "§7.2.13"},
  };

  for (int f = 0; f < 2; f++) {
    icUInt32Number v = fields[f].val;
    if (v == 0) {
      printf("           %s=0x00000000 — not specified (permitted)\n", fields[f].name);
      continue;
    }

    bool printable = true;
    for (int i = 0; i < 4; i++) {
      unsigned char byte = (v >> (24 - i * 8)) & 0xFF;
      if (byte < 0x20 || byte > 0x7E) { printable = false; break; }
    }

    char sigStr[5] = {};
    SigToChars((icTagSignature)v, sigStr);

    if (!printable) {
      printf("           %s=0x%08X — %snon-printable bytes%s\n",
             fields[f].name, v, ColorError(), ColorReset());
      printf("           %s[FAIL]%s Device %s must be printable ASCII 4CC or zero — %s\n",
             ColorError(), ColorReset(), fields[f].name, fields[f].section);
      issues++;
    } else {
      printf("           %s='%s' (0x%08X)\n", fields[f].name, sigStr, v);
    }
  }

  if (issues == 0)
    printf("           %s[OK]%s Device manufacturer/model conformant\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-201: Profile Creator Signature (ICC.1-2022-05 §7.2.17)
//
// Per §7.2.17, the profileCreator field (bytes 80-83) shall either be zero
// or contain a registered ICC member signature. All bytes should be
// printable ASCII.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF201_ProfileCreatorSignature(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number creator = pIcc->m_Header.creator;

  printf("  %s[CF-201]%s Profile Creator Signature (%sICC.1-2022-05 §7.2.17%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (creator == 0) {
    printf("           creator=0x00000000 — not specified (permitted)\n");
    printf("           %s[OK]%s Profile creator conformant\n", ColorSuccess(), ColorReset());
    return 0;
  }

  bool printable = true;
  for (int i = 0; i < 4; i++) {
    unsigned char byte = (creator >> (24 - i * 8)) & 0xFF;
    if (byte < 0x20 || byte > 0x7E) { printable = false; break; }
  }

  char sigStr[5] = {};
  SigToChars((icTagSignature)creator, sigStr);

  if (!printable) {
    printf("           creator=0x%08X — %snon-printable bytes%s\n",
           creator, ColorError(), ColorReset());
    printf("           %s[FAIL]%s Profile creator must be printable ASCII 4CC or zero — §7.2.17\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("           creator='%s' (0x%08X)\n", sigStr, creator);
    printf("           %s[OK]%s Profile creator conformant\n", ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-203: Profile Flags Semantic Validation (ICC.1-2022-05 §7.2.11 Table 21)
//
// Extends CF-003 (reserved bits) with semantic validation of the defined
// flag bits:
//   Bit 0: 0=not embedded, 1=embedded in file (§7.2.11)
//   Bit 1: 0=profile CAN be used independently, 1=CANNOT be used independently
//   Bit 2: MCS subset (v5 only, 0=not MCS subset)
// Semantic rule: if bit 0=0 (not embedded), bit 1 should be 0 (independent).
// A non-embedded profile that cannot be used independently is contradictory.
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF203_ProfileFlagsSemantics(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number flags = pIcc->m_Header.flags;
  icUInt32Number version = pIcc->m_Header.version;

  printf("  %s[CF-203]%s Profile Flags Semantic Validation (%sICC.1-2022-05 §7.2.11 Table 21%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  bool embedded    = (flags & 0x0001) != 0;
  bool dependent   = (flags & 0x0002) != 0;
  bool mcsSubset   = (flags & 0x0004) != 0;

  printf("           Bit 0 (Embedded): %s\n", embedded ? "embedded in file" : "not embedded");
  printf("           Bit 1 (Independent): %s\n", dependent ? "cannot be used independently" : "can be used independently");

  // Semantic check: non-embedded + dependent is contradictory
  if (!embedded && dependent) {
    printf("           %s[FAIL]%s Non-embedded profile marked as cannot-be-used-independently — contradictory — §7.2.11\n",
           ColorError(), ColorReset());
    issues++;
  }

  // Bit 2 (MCS subset) is v5-only
  if (mcsSubset && version < icVersionNumberV5) {
    printf("           Bit 2 (MCS Subset): set but profile version < 5.0\n");
    printf("           %s[FAIL]%s MCS subset flag (bit 2) is only defined for v5+ — §7.2.11\n",
           ColorError(), ColorReset());
    issues++;
  } else if (mcsSubset) {
    printf("           Bit 2 (MCS Subset): MCS subset profile\n");
  }

  if (issues == 0)
    printf("           %s[OK]%s Profile flags semantics conformant\n",
           ColorSuccess(), ColorReset());

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-206: Profile File Signature 'acsp' (ICC.1-2022-05 §7.2.9)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF206_ProfileFileSignature(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number magic = pIcc->m_Header.magic;

  printf("%s[CF-206]%s Profile File Signature 'acsp' (%sICC.1-2022-05 §7.2.9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // ICC.1-2022-05 §7.2.9: bytes 36-39 must be 'acsp' (0x61637370)
  if (magic != icMagicNumber) {
    char buf[5];
    SigToChars(magic, buf);
    printf("         magic=0x%08X ('%s') — %sexpected 'acsp' (0x%08X)%s\n",
           magic, buf, ColorError(), static_cast<unsigned>(icMagicNumber), ColorReset());
    printf("         %s[FAIL]%s Profile file signature must be 'acsp' — ICC.1-2022-05 §7.2.9\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         magic=0x%08X ('acsp')\n", magic);
    printf("         %s[OK]%s Profile file signature conformant\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-210: DeviceLink PCS Space Validation (ICC.1-2022-05 §8.6)
// ═══════════════════════════════════════════════════════════════════════════════

static int RunCF210_DeviceLinkPCSSpace(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number pcs = static_cast<icUInt32Number>(pIcc->m_Header.pcs);
  icUInt32Number cs = static_cast<icUInt32Number>(pIcc->m_Header.colorSpace);

  printf("%s[CF-210]%s DeviceLink PCS Space Validation (%sICC.1-2022-05 §8.6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (pIcc->m_Header.deviceClass != icSigLinkClass) {
    printf("         Not a DeviceLink profile — skipping\n");
    printf("         %s[OK]%s Not applicable\n", ColorSuccess(), ColorReset());
    return 0;
  }

  // §8.6: DeviceLink PCS shall be the same as the colorSpace of the second
  // profile in the sequence. It must be a valid device colour space.
  // The PCS for DeviceLink is actually the output colour space.
  char pcsCC[5], csCC[5];
  SigToChars(pcs, pcsCC);
  SigToChars(cs, csCC);

  printf("         DeviceLink: colorSpace='%s', PCS='%s'\n", csCC, pcsCC);

  // PCS should be a valid device colour space (not Lab or XYZ for v2/v4)
  // For v5, spectral PCS is allowed
  int major = (pIcc->m_Header.version >> 24) & 0xFF;
  bool isAbstractPCS = (pcs == static_cast<icUInt32Number>(icSigXYZData) ||
                        pcs == static_cast<icUInt32Number>(icSigLabData));

  if (isAbstractPCS && major < 5) {
    // DeviceLink PCS being XYZ/Lab means it connects to PCS directly
    // This is valid but unusual — ICC.1 §8.6 allows it
    printf("         DeviceLink PCS='%s' (connects through PCS space)\n", pcsCC);
  }

  // Validate PCS is a recognized colour space signature
  bool recognizedCS = false;
  icUInt32Number csType = icGetColorSpaceType(static_cast<icColorSpaceSignature>(pcs));
  if (pcs == static_cast<icUInt32Number>(icSigXYZData) ||
      pcs == static_cast<icUInt32Number>(icSigLabData) ||
      pcs == static_cast<icUInt32Number>(icSigRgbData) ||
      pcs == static_cast<icUInt32Number>(icSigCmykData) ||
      pcs == static_cast<icUInt32Number>(icSigGrayData) ||
      csType == static_cast<icUInt32Number>(icSigNChannelData) ||
      (pcs >= 0x32434C52u /* '2CLR' */ && pcs <= 0x46434C52u /* 'FCLR' */)) {
    recognizedCS = true;
  }

  if (!recognizedCS) {
    printf("         PCS='%s' (0x%08X) — %sunrecognized colour space%s\n",
           pcsCC, pcs, ColorError(), ColorReset());
    printf("         %s[FAIL]%s DeviceLink PCS must be a valid colour space — ICC.1-2022-05 §8.6\n",
           ColorError(), ColorReset());
    issues++;
  } else {
    printf("         %s[OK]%s DeviceLink PCS is a recognized colour space\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ═══════════════════════════════════════════════════════════════════════════════
// ICC TN "Embedding ICC Profiles" — Conformance Checks CF-214..CF-219
// ═══════════════════════════════════════════════════════════════════════════════

// CF-214: Embedded Profile Class Suitability
// ICC TN Embedding: Profiles are embedded to indicate the colour space of the
// media object. DeviceLink profiles describe device-to-device transforms, not
// colour space definitions. If the embedded flag (§7.2.11 bit 0) is set,
// a DeviceLink class is atypical (only valid in specific contexts like PDF
// OutputIntent). Abstract and NamedColor classes are valid but unusual.
static int RunCF214_EmbeddedProfileClassSuitability(CIccProfile *pIcc) {
  int issues = 0;
  icUInt64Number flags64 = pIcc->m_Header.flags;
  icUInt32Number flags = static_cast<icUInt32Number>(flags64 & 0xFFFFFFFF);
  bool embedded = (flags & 0x00000001) != 0;

  printf("  %s[CF-214]%s Embedded Profile Class Suitability (%sICC TN Embedding §Table 1%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!embedded) {
    printf("         Embedded flag not set — profile not marked for embedding\n");
    printf("         %s[OK]%s Not applicable (not an embedded profile)\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  icProfileClassSignature devClass = pIcc->m_Header.deviceClass;

  if (devClass == icSigLinkClass) {
    printf("         Embedded flag set on DeviceLink class profile\n");
    printf("         DeviceLink profiles describe device-to-device transforms, not colour spaces\n");
    printf("         Embedding a DeviceLink is atypical — only valid in PDF OutputIntent context\n");
    printf("         %s[WARN]%s DeviceLink with embedded flag is unusual — ICC TN Embedding\n",
           ColorWarning(), ColorReset());
    issues++;
  } else if (devClass == icSigAbstractClass) {
    printf("         Embedded flag set on Abstract class profile — unusual but valid\n");
    printf("         %s[OK]%s Abstract profile embedding is uncommon but permitted\n",
           ColorSuccess(), ColorReset());
  } else if (devClass == icSigNamedColorClass) {
    printf("         Embedded flag set on NamedColor class profile — unusual but valid\n");
    printf("         %s[OK]%s NamedColor profile embedding is uncommon but permitted\n",
           ColorSuccess(), ColorReset());
  } else {
    char cc[5];
    SigToChars(static_cast<icTagSignature>(devClass), cc);
    printf("         Embedded flag set on '%s' class profile — standard embedding use case\n", cc);
    printf("         %s[OK]%s Profile class '%s' is appropriate for embedding\n",
           ColorSuccess(), ColorReset(), cc);
  }

  return issues;
}


// CF-215: JPEG APP2 Embedding Size Limit
// ICC TN Embedding §JFIF: JPEG APP2 markers use 1-byte sequence numbering
// (max 255 chunks). Each APP2 segment has max data length 65,533 bytes, minus
// 14 bytes overhead ("ICC_PROFILE\0" + seq_no + total). Max embeddable size:
// 255 × (65,533 - 14) = 255 × 65,519 = 16,707,345 bytes.
static int RunCF215_JPEGEmbeddingSizeLimit(CIccProfile *pIcc) {
  int issues = 0;
  static const icUInt32Number kJPEGMaxEmbedSize = 16707345u;
  icUInt32Number profileSize = pIcc->m_Header.size;

  printf("  %s[CF-215]%s JPEG APP2 Embedding Size Limit (%sICC TN Embedding §JFIF%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  printf("         Profile size: %u bytes (JPEG limit: %u bytes)\n",
         profileSize, kJPEGMaxEmbedSize);

  if (profileSize > kJPEGMaxEmbedSize) {
    printf("         Profile exceeds JPEG APP2 embedding limit (255 × 65,519 bytes)\n");
    printf("         This profile cannot be embedded in JPEG/JFIF images\n");
    printf("         %s[WARN]%s Profile too large for JPEG embedding — ICC TN Embedding §JFIF\n",
           ColorWarning(), ColorReset());
    issues++;
  } else {
    unsigned chunks = (profileSize + 65518) / 65519;
    printf("         Would require %u APP2 segment(s) for JPEG embedding\n", chunks);
    printf("         %s[OK]%s Profile fits within JPEG APP2 embedding limit\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// CF-216: JP2 Restricted ICC Compliance
// ICC TN Embedding §JPEG2000: JP2 (ISO 15444-1) restricts embedded profiles to
// Input class conforming to ICC.1:1998-09 (v2 only, Restricted ICC method).
// Monochrome and RGB data only.
static int RunCF216_JP2RestrictedICCCompliance(CIccProfile *pIcc) {
  int issues = 0;
  int major = (pIcc->m_Header.version >> 24) & 0xFF;
  icProfileClassSignature devClass = pIcc->m_Header.deviceClass;
  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;

  printf("  %s[CF-216]%s JP2 Restricted ICC Compliance (%sISO 15444-1 Annex I%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  bool jp2Compatible = true;

  // JP2 restricts to Input class
  if (devClass != icSigInputClass) {
    char cc[5];
    SigToChars(static_cast<icTagSignature>(devClass), cc);
    printf("         Class '%s' — JP2 requires Input ('scnr') class\n", cc);
    jp2Compatible = false;
  }

  // JP2 restricts to v2 (ICC.1:1998-09)
  if (major > 2) {
    printf("         Version %d.x — JP2 requires ICC v2 (ICC.1:1998-09)\n", major);
    jp2Compatible = false;
  }

  // JP2 restricts to monochrome and RGB
  if (cs != icSigGrayData && cs != icSigRgbData) {
    char cc[5];
    SigToChars(static_cast<icTagSignature>(cs), cc);
    printf("         Color space '%s' — JP2 supports only Gray/RGB\n", cc);
    jp2Compatible = false;
  }

  if (!jp2Compatible) {
    printf("         %s[INFO]%s Profile not compatible with JP2 Restricted ICC method\n",
           ColorInfo(), ColorReset());
    // Info-level — not a hard failure, just container incompatibility
  } else {
    printf("         %s[OK]%s Profile compatible with JP2 Restricted ICC method\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// CF-217: JPX Any ICC Method Compliance
// ICC TN Embedding §JPEG2000: JPX (ISO 15444-2 Annex M) allows Input and Display
// class profiles only. Furthermore, profiles must be Matrix/TRC based — LUT-based
// profiles are excluded from the Any ICC method.
static int RunCF217_JPXAnyICCMethodCompliance(CIccProfile *pIcc) {
  int issues = 0;
  icProfileClassSignature devClass = pIcc->m_Header.deviceClass;

  printf("  %s[CF-217]%s JPX Any ICC Method Compliance (%sISO 15444-2 Annex M%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  bool jpxCompatible = true;

  // JPX allows only Input and Display class
  if (devClass != icSigInputClass && devClass != icSigDisplayClass) {
    char cc[5];
    SigToChars(static_cast<icTagSignature>(devClass), cc);
    printf("         Class '%s' — JPX Any ICC requires Input ('scnr') or Display ('mntr')\n", cc);
    jpxCompatible = false;
  }

  // JPX requires Matrix/TRC — no LUT-based profiles
  bool hasMatrixTRC = (pIcc->FindTag(icSigRedMatrixColumnTag) != nullptr &&
                       pIcc->FindTag(icSigGreenMatrixColumnTag) != nullptr &&
                       pIcc->FindTag(icSigBlueMatrixColumnTag) != nullptr &&
                       pIcc->FindTag(icSigRedTRCTag) != nullptr &&
                       pIcc->FindTag(icSigGreenTRCTag) != nullptr &&
                       pIcc->FindTag(icSigBlueTRCTag) != nullptr);
  bool hasLUT = (pIcc->FindTag(icSigAToB0Tag) != nullptr);

  if (hasLUT && !hasMatrixTRC) {
    printf("         LUT-based profile (AToB0Tag present, no Matrix/TRC tags)\n");
    printf("         JPX Any ICC method requires Matrix/TRC profiles only\n");
    jpxCompatible = false;
  } else if (!hasMatrixTRC && pIcc->m_Header.colorSpace != icSigGrayData) {
    printf("         No Matrix/TRC tags found — JPX requires Matrix/TRC structure\n");
    jpxCompatible = false;
  }

  if (!jpxCompatible) {
    printf("         %s[INFO]%s Profile not compatible with JPX Any ICC method\n",
           ColorInfo(), ColorReset());
  } else {
    printf("         %s[OK]%s Profile compatible with JPX Any ICC method\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// CF-218: HEIF Restricted ICC Compatibility
// ICC TN Embedding §HEIF: HEIF uses ColourInformationBox (ISO/IEC 14496-12).
// Type code 'colr' stores a v4 profile. Type code 'ricc' defines a restricted
// profile: monochrome or 3-component matrix/TRC only. LUT-based profiles are
// not permitted under 'ricc'.
static int RunCF218_HEIFRestrictedICCCompatibility(CIccProfile *pIcc) {
  int issues = 0;
  icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
  int major = (pIcc->m_Header.version >> 24) & 0xFF;

  printf("  %s[CF-218]%s HEIF Restricted ICC Compatibility (%sISO/IEC 14496-12%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  // HEIF 'colr' supports v4 profiles
  bool heifColrOK = (major <= 4);

  // HEIF 'ricc' restricted: monochrome or 3-component matrix/TRC
  bool isMono = (cs == icSigGrayData);
  bool is3Channel = (cs == icSigRgbData);

  bool hasMatrixTRC = false;
  if (is3Channel) {
    hasMatrixTRC = (pIcc->FindTag(icSigRedMatrixColumnTag) != nullptr &&
                    pIcc->FindTag(icSigGreenMatrixColumnTag) != nullptr &&
                    pIcc->FindTag(icSigBlueMatrixColumnTag) != nullptr &&
                    pIcc->FindTag(icSigRedTRCTag) != nullptr &&
                    pIcc->FindTag(icSigGreenTRCTag) != nullptr &&
                    pIcc->FindTag(icSigBlueTRCTag) != nullptr);
  }

  bool heifRiccOK = (isMono || (is3Channel && hasMatrixTRC));

  if (heifColrOK) {
    printf("         HEIF 'colr' compatible (v%d profile, ≤ v4)\n", major);
  } else {
    printf("         HEIF 'colr' incompatible (v%d profile, requires ≤ v4)\n", major);
  }

  if (heifRiccOK) {
    printf("         HEIF 'ricc' compatible (%s)\n",
           isMono ? "monochrome" : "3-component Matrix/TRC");
  } else {
    char cc[5];
    SigToChars(static_cast<icTagSignature>(cs), cc);
    printf("         HEIF 'ricc' incompatible (color space '%s'%s)\n",
           cc, (is3Channel && !hasMatrixTRC) ? ", no Matrix/TRC" : "");
  }

  if (!heifColrOK && !heifRiccOK) {
    printf("         %s[INFO]%s Profile not compatible with any HEIF embedding method\n",
           ColorInfo(), ColorReset());
  } else {
    printf("         %s[OK]%s Profile compatible with HEIF embedding\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// CF-219: Container Format Version Matrix
// ICC TN Embedding §Table 1: Cross-reference profile version against known
// container format embedding support. Reports which formats can embed this profile.
static int RunCF219_ContainerFormatVersionMatrix(CIccProfile *pIcc) {
  int issues = 0;
  int major = (pIcc->m_Header.version >> 24) & 0xFF;
  icProfileClassSignature devClass = pIcc->m_Header.deviceClass;

  printf("  %s[CF-219]%s Container Format Version Matrix (%sICC TN Embedding §Table 1%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());
  printf("         Profile version: %d.x, class: %c%c%c%c\n",
         major,
         (char)((devClass >> 24) & 0xFF), (char)((devClass >> 16) & 0xFF),
         (char)((devClass >> 8) & 0xFF), (char)(devClass & 0xFF));

  // Count compatible formats from Table 1
  int compatCount = 0;

  // Formats supporting v2 and v4: AVIF, DNG, EPS, HEIF, HEVC, JPEG, JPEG-XL,
  //   OpenXPS, PDF, PDF/X, TIFF, TIFF-EP, WebP, CSS, MIME
  if (major <= 4) {
    compatCount += 15;
  }

  // JP2: v2 only, Input class only
  if (major <= 2 && devClass == icSigInputClass) {
    compatCount++;
    printf("         JP2 (ISO 15444-1): compatible (v2 Input)\n");
  }

  // JPX: v2 and v4, Input/Display only, Matrix/TRC only
  if (major <= 4 && (devClass == icSigInputClass || devClass == icSigDisplayClass)) {
    compatCount++;
    printf("         JPX (ISO 15444-2): compatible (v%d %s)\n",
           major, devClass == icSigInputClass ? "Input" : "Display");
  }

  // PNG: officially v2, current practice v4
  if (major <= 2) {
    compatCount++;
    printf("         PNG (ISO 15948): compatible (v2, per specification)\n");
  } else if (major <= 4) {
    printf("         PNG: v4 widely supported in practice (spec says v2)\n");
  }

  // No formats support v5
  if (major >= 5) {
    printf("         No media formats currently support ICC v5 embedding\n");
    printf("         Consider embedding v5 inside a v4 wrapper (ICC TN 04-2018)\n");
    printf("         %s[INFO]%s v5 profile — no standard container format support\n",
           ColorInfo(), ColorReset());
  } else {
    printf("         Compatible with %d+ media formats (of 18 surveyed)\n", compatCount);
    printf("         %s[OK]%s Profile version has broad container format support\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}


// ─── CF-243: dateTimeNumber Field Range Validation ──────────────────────────
// ICC.1-2022-05 §4.2 — month 1-12, day 1-31, hours 0-23, minutes 0-59, seconds 0-59
int RunCF243_DateTimeFieldRange(CIccProfile *pIcc) {
  int issues = 0;
  const icDateTimeNumber &dt = pIcc->m_Header.date;
  if (dt.month < 1 || dt.month > 12) {
    printf("    Non-conformance: month=%u out of range 1-12\n", dt.month);
    issues++;
  }
  if (dt.day < 1 || dt.day > 31) {
    printf("    Non-conformance: day=%u out of range 1-31\n", dt.day);
    issues++;
  }
  if (dt.hours > 23) {
    printf("    Non-conformance: hours=%u exceeds 23\n", dt.hours);
    issues++;
  }
  if (dt.minutes > 59) {
    printf("    Non-conformance: minutes=%u exceeds 59\n", dt.minutes);
    issues++;
  }
  if (dt.seconds > 59) {
    printf("    Non-conformance: seconds=%u exceeds 59\n", dt.seconds);
    issues++;
  }
  return issues;
}

// ─── CF-244: Profile Creation Date Plausibility ─────────────────────────────
// ICC profiles didn't exist before 1990; dates far in the future are suspicious
int RunCF244_DatePlausibility(CIccProfile *pIcc) {
  int issues = 0;
  icUInt16Number year = pIcc->m_Header.date.year;
  if (year != 0 && year < 1990) {
    printf("    Non-conformance: creation year %u predates ICC specification (1990)\n", year);
    issues++;
  }
  if (year > 2100) {
    printf("    Non-conformance: creation year %u implausibly far in the future\n", year);
    issues++;
  }
  return issues;
}

// ─── CF-245: Profile Size Multiple of 4 ────────────────────────────────────
// ICC.1-2022-05 §7.2.2 — profile data shall be padded to 4-byte boundary
int RunCF245_ProfileSizeAlignment(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number sz = pIcc->m_Header.size;
  if (sz % 4 != 0) {
    printf("    Non-conformance: profile size %u is not a multiple of 4 bytes\n", sz);
    issues++;
  }
  return issues;
}

// ─── CF-246: Rendering Intent Range ─────────────────────────────────────────
// ICC.1-2022-05 §7.2.15 — rendering intent must be 0-3
int RunCF246_RenderingIntentRange(CIccProfile *pIcc) {
  int issues = 0;
  icUInt32Number intent = pIcc->m_Header.renderingIntent;
  if (intent > 3) {
    printf("    Non-conformance: rendering intent %u exceeds valid range 0-3\n", intent);
    issues++;
  }
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
  if (r < 0) { \
    hc.skip(nullptr); \
  } else { \
    if (r > 0) hc.warn("%d non-conformance(s)", r); \
    hc.end("Conformant"); \
    issues += r; \
  }

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
  CF_WRAP(1016, "CF-016: Device Manufacturer Signature", RunCF016_DeviceManufacturerSignature(pIcc));
  CF_WRAP(1017, "CF-017: Device Model Signature", RunCF017_DeviceModelSignature(pIcc));
  CF_WRAP(1018, "CF-018: Device Attributes Semantic Bits", RunCF018_DeviceAttributesBits(pIcc));
  CF_WRAP(1019, "CF-019: Creator Signature", RunCF019_CreatorSignature(pIcc));

  CF_WRAP(1107, "CF-107: Tag Table Ordering", RunCF107_TagTableOrdering(pIcc));
  CF_WRAP(1121, "CF-121: Illuminant Metadata Consistency", RunCF121_IlluminantMetadataConsistency(pIcc));
  CF_WRAP(1122, "CF-122: Profile Date/Time Plausibility", RunCF122_ProfileDateTimePlausibility(pIcc));

  // RFC 1321 / Profile ID conformance (CF-184..CF-187)
  CF_WRAP(1184, "CF-184: Profile ID v4+ Presence", RunCF184_ProfileIDV4Presence(pIcc));
  CF_WRAP(1185, "CF-185: Profile ID Size Consistency", RunCF185_ProfileIDSizeConsistency(pIcc, filename));
  CF_WRAP(1186, "CF-186: Profile ID Entropy Analysis", RunCF186_ProfileIDEntropy(pIcc));
  CF_WRAP(1187, "CF-187: Embedded Profile ProfileID Chain", RunCF187_EmbeddedProfileIDChain(pIcc));

  // SampleICC compliance framework header checks (CF-199..CF-201, CF-203)
  CF_WRAP(1199, "CF-199: CMM Type Signature Registration", RunCF199_CMMTypeSignatureRegistration(pIcc));
  CF_WRAP(1200, "CF-200: Device Manufacturer/Model Signature", RunCF200_DeviceManufacturerModel(pIcc));
  CF_WRAP(1201, "CF-201: Profile Creator Signature", RunCF201_ProfileCreatorSignature(pIcc));
  CF_WRAP(1203, "CF-203: Profile Flags Semantic Validation", RunCF203_ProfileFlagsSemantics(pIcc));

  // Spec gap coverage (CF-206, CF-210)
  CF_WRAP(1206, "CF-206: Profile File Signature 'acsp'", RunCF206_ProfileFileSignature(pIcc));
  CF_WRAP(1210, "CF-210: DeviceLink PCS Space Validation", RunCF210_DeviceLinkPCSSpace(pIcc));

  // ICC TN Embedding conformance (CF-214..CF-219)
  CF_WRAP(1214, "CF-214: Embedded Profile Class Suitability", RunCF214_EmbeddedProfileClassSuitability(pIcc));
  CF_WRAP(1215, "CF-215: JPEG APP2 Embedding Size Limit", RunCF215_JPEGEmbeddingSizeLimit(pIcc));
  CF_WRAP(1216, "CF-216: JP2 Restricted ICC Compliance", RunCF216_JP2RestrictedICCCompliance(pIcc));
  CF_WRAP(1217, "CF-217: JPX Any ICC Method Compliance", RunCF217_JPXAnyICCMethodCompliance(pIcc));
  CF_WRAP(1218, "CF-218: HEIF Restricted ICC Compatibility", RunCF218_HEIFRestrictedICCCompatibility(pIcc));
  CF_WRAP(1219, "CF-219: Container Format Version Matrix", RunCF219_ContainerFormatVersionMatrix(pIcc));
  CF_WRAP(1243, "CF-243: dateTimeNumber Field Range", RunCF243_DateTimeFieldRange(pIcc));
  CF_WRAP(1244, "CF-244: Profile Creation Date Plausibility", RunCF244_DatePlausibility(pIcc));
  CF_WRAP(1245, "CF-245: Profile Size Multiple of 4", RunCF245_ProfileSizeAlignment(pIcc));
  CF_WRAP(1246, "CF-246: Rendering Intent Range", RunCF246_RenderingIntentRange(pIcc));

#undef CF_WRAP
  return issues;
}
