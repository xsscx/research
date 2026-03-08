/*
 * IccHeuristicsHeader.cpp — Header validation heuristics (H1-H8, H15-H17)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Extracted from IccAnalyzerSecurity.cpp as part of codebase modernization.
 * Each function validates one header field against ICC.1-2022-05 / ICC.2-2023.
 */

#include "IccHeuristicsHeader.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerSignatures.h"
#include "IccAnalyzerColors.h"
#include "IccDefs.h"
#include "IccProfile.h"
#include "IccUtil.h"
#include "IccUtil.h"
#include <cstdio>
#include <cstring>
#include <cmath>

int RunHeuristic_H1_ProfileSize(const icHeader &header, size_t actualFileSize) {
  int heuristicCount = 0;

// 1. Profile Size Heuristic (ICC.1-2022-05 §7.2.2)
icUInt32Number profileSize = header.size;
printf("[H1] Profile Size: %u bytes (0x%08X)", profileSize, profileSize);
if (actualFileSize > 0) {
  printf("  [actual file: %zu bytes]", actualFileSize);
}
printf("\n");
if (profileSize == 0) {
  printf("     %s[WARN]  HEURISTIC: Profile size is ZERO — ICC.1-2022-05 §7.2.2%s\n", ColorCritical(), ColorReset());
  printf("     %sRisk: Invalid header, possible corruption%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
} else if (profileSize > (1u << 30)) {
  printf("     %s[WARN]  HEURISTIC: Profile size > 1 GiB (possible memory exhaustion)%s\n", ColorWarning(), ColorReset());
  printf("     %sRisk: Resource exhaustion attack%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
} else {
  printf("     %s[OK] Size within normal range%s\n", ColorSuccess(), ColorReset());
}
// Truncation: header claims larger than actual file — tags will read OOB
if (actualFileSize > 0 && profileSize > 0 && profileSize > actualFileSize) {
  printf("     %s[WARN]  HEURISTIC: Profile TRUNCATED — header claims %u bytes but file is only %zu bytes%s\n",
         ColorCritical(), profileSize, actualFileSize, ColorReset());
  printf("     %sRisk: Tags referencing past EOF will cause heap-buffer-overflow reads%s\n",
         ColorCritical(), ColorReset());
  heuristicCount++;
}
// Appended data: file is larger than declared profile size
if (actualFileSize > 0 && profileSize > 0 && actualFileSize > (uint64_t)profileSize + 3) {
  size_t extraBytes = actualFileSize - (size_t)profileSize;
  printf("     %s[WARN]  HEURISTIC: %zu EXTRA BYTES appended past declared profile end%s\n",
         ColorCritical(), extraBytes, ColorReset());
  printf("     %sRisk: Data hiding / smuggling — parsers may ignore appended payload%s\n",
         ColorWarning(), ColorReset());
  printf("     %sNote: Some parsers observed in the wild read past declared size%s\n",
         ColorWarning(), ColorReset());
  heuristicCount++;
}
// Size inflation: header claims much larger than actual file (extreme)
if (actualFileSize > 0 && profileSize > 0 &&
    profileSize > actualFileSize * 16 && profileSize > (128u << 20)) {
  printf("     %s[WARN]  HEURISTIC: Extreme inflation — header claims %u bytes but file is %zu bytes (%.0fx)%s\n",
         ColorCritical(), profileSize, actualFileSize,
         (double)profileSize / actualFileSize, ColorReset());
  printf("     %sRisk: OOM via tag-internal allocations sized from inflated header%s\n",
         ColorWarning(), ColorReset());
  heuristicCount++;
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H2_MagicBytes(const icHeader &header) {
  int heuristicCount = 0;

// 2. Magic Bytes Validation (ICC.1-2022-05 §7.2.9)
const icUInt8Number expectedMagic[4] = {'a', 'c', 's', 'p'};
const icUInt8Number *actualMagic = (icUInt8Number *)&header.magic;
printf("[H2] Magic Bytes (offset 0x24): ");
for (int i = 0; i < 4; i++) {
  printf("%02X ", actualMagic[i]);
}
printf("(");
for (int i = 0; i < 4; i++) {
  printf("%c", actualMagic[i] >= 32 && actualMagic[i] <= 126 ? actualMagic[i] : '.');
}
printf(")\n");

if (memcmp(actualMagic, expectedMagic, 4) != 0) {
  printf("     %s[WARN]  HEURISTIC: Invalid magic bytes (expected \"acsp\" — ICC.1-2022-05 §7.2.9)%s\n", ColorCritical(), ColorReset());
  printf("     %sRisk: Not a valid ICC profile, possible format confusion attack%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
} else {
  printf("     %s[OK] Valid ICC magic signature%s\n", ColorSuccess(), ColorReset());
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H3_ColorSpaceSignature(const icHeader &header) {
  int heuristicCount = 0;

// 3. ColorSpace Signature Validation (ICC.1-2022-05 §7.2.6, Table 22)
icUInt32Number colorSpace = header.colorSpace;
char csFourCC[5];
SignatureToFourCC(colorSpace, csFourCC);
printf("[H3] Data ColorSpace: 0x%08X (%s)\n", colorSpace, csFourCC);

if (IsValidColorSpaceSignature((icColorSpaceSignature)colorSpace)) {
  CIccInfo info;
  printf("     %s[OK] Valid colorSpace: %s%s\n", ColorSuccess(),
         info.GetColorSpaceSigName((icColorSpaceSignature)colorSpace), ColorReset());
} else {
  // Use DescribeColorSpaceSignature for raw byte decomposition
  IccColorSpaceDescription csDesc = DescribeColorSpaceSignature(colorSpace);
  if (colorSpace == 0x00000000 || colorSpace == 0xFFFFFFFF || colorSpace == 0x20202020) {
    printf("     %s[WARN]  HEURISTIC: Invalid/null colorSpace signature%s\n", ColorCritical(), ColorReset());
    printf("     %sRisk: Enum confusion, undefined behavior%s\n", ColorWarning(), ColorReset());
  } else if (HasNonPrintableSignature(colorSpace)) {
    printf("     %s[WARN]  HEURISTIC: ColorSpace contains non-printable characters%s\n", ColorCritical(), ColorReset());
    printf("     %sRisk: Binary signature exploitation%s\n", ColorWarning(), ColorReset());
  } else {
    printf("     %s[WARN]  HEURISTIC: Unknown/invalid colorSpace signature%s\n", ColorWarning(), ColorReset());
    printf("     %sRisk: Parser may not handle unknown values safely%s\n", ColorWarning(), ColorReset());
  }
  printf("     %sName: %s  Bytes: '%s'%s\n", ColorInfo(), csDesc.name, csDesc.bytes, ColorReset());
  heuristicCount++;
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H4_PCSColorSpace(const icHeader &header) {
  int heuristicCount = 0;

// 4. PCS ColorSpace Validation (ICC.1-2022-05 §7.2.7; ICC.2-2023 §7.2.2 for spectral PCS)
icUInt32Number pcs = header.pcs;
char pcsFourCC[5];
SignatureToFourCC(pcs, pcsFourCC);
printf("[H4] PCS ColorSpace: 0x%08X (%s)\n", pcs, pcsFourCC);

if (pcs == icSigLabData || pcs == icSigXYZData) {
  CIccInfo info;
  printf("     %s[OK] Valid PCS: %s%s\n", ColorSuccess(), info.GetColorSpaceSigName((icColorSpaceSignature)pcs), ColorReset());
} else if (IsSpaceSpectralPCS((icColorSpaceSignature)pcs)) {
  printf("     %s[OK] Spectral PCS (ICC v5): 0x%08X%s\n", ColorSuccess(), pcs, ColorReset());
} else {
  IccColorSpaceDescription pcsDesc = DescribeColorSpaceSignature(pcs);
  printf("     %s[WARN]  HEURISTIC: Invalid PCS signature — ICC.1-2022-05 §7.2.7 requires Lab or XYZ; ICC.2-2023 allows spectral%s\n", ColorCritical(), ColorReset());
  printf("     %sRisk: Colorimetric transform failures%s\n", ColorWarning(), ColorReset());
  printf("     %sName: %s  Bytes: '%s'%s\n", ColorInfo(), pcsDesc.name, pcsDesc.bytes, ColorReset());
  heuristicCount++;
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H5_PlatformSignature(const icHeader &header) {
  int heuristicCount = 0;

// 5. Platform Signature Validation (ICC.1-2022-05 §7.2.10, Table 18)
icUInt32Number platform = header.platform;
char pfFourCC[5];
SignatureToFourCC(platform, pfFourCC);
printf("[H5] Platform: 0x%08X (%s)\n", platform, pfFourCC);

bool validPlatform = false;
switch (platform) {
  case icSigMacintosh:
  case icSigMicrosoft:
  case icSigSolaris:
  case icSigSGI:
  case icSigTaligent:
  case 0x00000000:
    validPlatform = true;
    break;
}

if (!validPlatform) {
  printf("     %s[WARN]  HEURISTIC: Unknown platform signature — ICC.1-2022-05 §7.2.10 Table 18%s\n", ColorWarning(), ColorReset());
  printf("     %sRisk: Platform-specific code path exploitation%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
} else {
  printf("     %s[OK] Known platform code%s\n", ColorSuccess(), ColorReset());
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H6_RenderingIntent(const icHeader &header) {
  int heuristicCount = 0;

// 6. Rendering Intent Validation (ICC.1-2022-05 §7.2.15)
// Bytes 64-67: lower 16 bits = intent (0-3), upper 16 bits must be 0
icUInt32Number intent = header.renderingIntent;
printf("[H6] Rendering Intent: %u (0x%08X)\n", intent, intent);

icUInt32Number intentUpper16 = intent >> 16;
icUInt32Number intentLower16 = intent & 0xFFFF;

if (intentUpper16 != 0) {
  printf("     %s[WARN]  HEURISTIC: Upper 16 bits non-zero (0x%04X) — spec requires 0%s\n",
         ColorCritical(), intentUpper16, ColorReset());
  printf("     %sRisk: CWE-20 — non-conformant header, possible exploitation vector%s\n",
         ColorWarning(), ColorReset());
  heuristicCount++;
}
if (intentLower16 > icAbsoluteColorimetric) {
  printf("     %s[WARN]  HEURISTIC: Invalid rendering intent value %u (> 3)%s\n",
         ColorCritical(), intentLower16, ColorReset());
  printf("     %sRisk: Out-of-bounds enum access%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
} else if (intentUpper16 == 0) {
  CIccInfo info;
  printf("     %s[OK] Valid intent: %s%s\n", ColorSuccess(),
         info.GetRenderingIntentName((icRenderingIntent)intentLower16), ColorReset());
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H7_ProfileClass(const icHeader &header) {
  int heuristicCount = 0;

// 7. Profile Class Validation (ICC.1-2022-05 §7.2.5, Table 17)
icUInt32Number devClass = header.deviceClass;
char dcFourCC[5];
SignatureToFourCC(devClass, dcFourCC);
printf("[H7] Profile Class: 0x%08X (%s)\n", devClass, dcFourCC);

CIccInfo info;
const char *className = info.GetProfileClassSigName((icProfileClassSignature)devClass);
if (!className || strlen(className) == 0) {
  printf("     %s[WARN]  HEURISTIC: Unknown profile class — ICC.1-2022-05 §7.2.5 Table 17%s\n", ColorWarning(), ColorReset());
  printf("     %sRisk: Class-specific parsing vulnerabilities%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
} else {
  printf("     %s[OK] Known class: %s%s\n", ColorSuccess(), className, ColorReset());
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H8_IlluminantXYZ(const icHeader &header) {
  int heuristicCount = 0;

// 8. Illuminant XYZ Validation (ICC.1-2022-05 §7.2.16)
// PCS illuminant shall be D50: X=0.9642, Y=1.0000, Z=0.8249
icS15Fixed16Number illumX = header.illuminant.X;
icS15Fixed16Number illumY = header.illuminant.Y;
icS15Fixed16Number illumZ = header.illuminant.Z;

double X = icFtoD(illumX);
double Y = icFtoD(illumY);
double Z = icFtoD(illumZ);

// Diagnostic: trace NaN illuminant values with file/line context
ICC_TRACE_NAN(X, "illuminant.X");
ICC_TRACE_NAN(Y, "illuminant.Y");
ICC_TRACE_NAN(Z, "illuminant.Z");

printf("[H8] Illuminant XYZ: (%.6f, %.6f, %.6f)\n", X, Y, Z);

// ICC spec D50 reference values (s15Fixed16Number encoding)
const double d50X = 0.9642, d50Y = 1.0000, d50Z = 0.8249;
const double d50Tol = 0.002; // s15Fixed16 rounding tolerance

if (std::isnan(X) || std::isnan(Y) || std::isnan(Z) ||
     std::isinf(X) || std::isinf(Y) || std::isinf(Z)) {
  printf("     %s[WARN]  HEURISTIC: NaN or Infinity in illuminant values%s\n", ColorCritical(), ColorReset());
  printf("     %sRisk: NaN propagation in color transforms, potential crash%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
} else if (X < 0.0 || Y < 0.0 || Z < 0.0) {
  printf("     %s[WARN]  HEURISTIC: Negative illuminant values (non-physical)%s\n", ColorCritical(), ColorReset());
  printf("     %sRisk: Undefined behavior in color calculations%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
} else if (fabs(X - d50X) > d50Tol || fabs(Y - d50Y) > d50Tol || fabs(Z - d50Z) > d50Tol) {
  printf("     %s[WARN]  HEURISTIC: PCS illuminant is NOT D50 (spec: %.4f, %.4f, %.4f)%s\n",
         ColorWarning(), d50X, d50Y, d50Z, ColorReset());
  printf("     %sRisk: Non-conformant header — ICC.1-2022-05 §7.2.16 requires D50%s\n",
         ColorWarning(), ColorReset());
  heuristicCount++;
} else if (X > 5.0 || Y > 5.0 || Z > 5.0) {
  printf("     %s[WARN]  HEURISTIC: Illuminant values > 5.0 (suspicious)%s\n", ColorWarning(), ColorReset());
  printf("     %sRisk: Floating-point overflow in transforms%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
} else {
  printf("     %s[OK] PCS illuminant matches D50 (within s15Fixed16 tolerance)%s\n", ColorSuccess(), ColorReset());
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H15_DateValidation(const icHeader &header) {
  int heuristicCount = 0;

// 15. Date Field Validation (ICC.1-2022-05 §4.2 dateTimeNumber)
printf("[H15] Date Validation (§4.2 dateTimeNumber): %u-%02u-%02u %02u:%02u:%02u\n",
       header.date.year, header.date.month, header.date.day,
       header.date.hours, header.date.minutes, header.date.seconds);
{
  bool dateValid = true;
  if (header.date.month > 12 || header.date.month == 0) {
    printf("      %s[WARN]  HEURISTIC: Invalid month: %u%s\n", ColorCritical(), header.date.month, ColorReset());
    dateValid = false;
  }
  if (header.date.day > 31 || header.date.day == 0) {
    printf("      %s[WARN]  HEURISTIC: Invalid day: %u%s\n", ColorCritical(), header.date.day, ColorReset());
    dateValid = false;
  }
  if (header.date.hours > 23) {
    printf("      %s[WARN]  HEURISTIC: Invalid hours: %u%s\n", ColorCritical(), header.date.hours, ColorReset());
    dateValid = false;
  }
  if (header.date.minutes > 59) {
    printf("      %s[WARN]  HEURISTIC: Invalid minutes: %u%s\n", ColorCritical(), header.date.minutes, ColorReset());
    dateValid = false;
  }
  if (header.date.seconds > 59) {
    printf("      %s[WARN]  HEURISTIC: Invalid seconds: %u%s\n", ColorCritical(), header.date.seconds, ColorReset());
    dateValid = false;
  }
  if (header.date.year > 2100 || header.date.year < 1900) {
    printf("      %s[WARN]  HEURISTIC: Suspicious year: %u (expected 1900-2100)%s\n",
           ColorWarning(), header.date.year, ColorReset());
    dateValid = false;
  }
  if (!dateValid) {
    printf("      %sRisk: Malformed date may indicate crafted/corrupted profile%s\n", ColorWarning(), ColorReset());
    heuristicCount++;
  } else {
    printf("      %s[OK] Date values within valid ranges%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H16_SignaturePatterns(const icHeader &header) {
  int heuristicCount = 0;

// 16. Suspicious Signature Patterns (repeat-byte, null)
printf("[H16] Signature Pattern Analysis\n");
{
  struct { const char *name; icUInt32Number sig; } sigs[] = {
    {"colorSpace",  header.colorSpace},
    {"pcs",         header.pcs},
    {"platform",    header.platform},
    {"deviceClass", header.deviceClass},
    {"manufacturer",header.manufacturer},
    {"creator",     header.creator},
    {"mcs",         header.mcs},
  };
  int suspiciousCount = 0;
  for (auto &s : sigs) {
    // Diagnostic: check for 0x3F corruption pattern
    ICC_SANITY_CHECK_SIGNATURE(s.sig, s.name);
    // Detect repeat-byte patterns (e.g. 0x8e8e8e8e, 0xabababab)
    uint8_t b0 = (s.sig >> 24) & 0xFF;
    bool repeatByte = (s.sig != 0) &&
                      (b0 == ((s.sig >> 16) & 0xFF)) &&
                      (b0 == ((s.sig >>  8) & 0xFF)) &&
                      (b0 == (s.sig & 0xFF));
    if (repeatByte) {
      printf("      %s[WARN]  %s: 0x%08X repeat-byte pattern (fuzz artifact?)%s\n",
             ColorWarning(), s.name, s.sig, ColorReset());
      suspiciousCount++;
    }
  }
  if (suspiciousCount > 0) {
    printf("      %sRisk: %d repeat-byte signature(s) — likely crafted/fuzzed profile%s\n",
           ColorWarning(), suspiciousCount, ColorReset());
    heuristicCount++;
  } else {
    printf("      %s[OK] No suspicious signature patterns detected%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H17_SpectralRange(const icHeader &header) {
  int heuristicCount = 0;

// 17. Spectral/BiSpectral Range Validation (ICC.2-2023 §7.2.22-23)
printf("[H17] Spectral Range Validation (ICC.2-2023 §7.2.22-23)\n");
{
  float specStart = icF16toF(header.spectralRange.start);
  float specEnd   = icF16toF(header.spectralRange.end);
  uint16_t specSteps = header.spectralRange.steps;
  float biStart = icF16toF(header.biSpectralRange.start);
  float biEnd   = icF16toF(header.biSpectralRange.end);
  uint16_t biSteps = header.biSpectralRange.steps;
  
  // Diagnostic: trace NaN in spectral range conversions
  ICC_TRACE_NAN(specStart, "spectralRange.start");
  ICC_TRACE_NAN(specEnd, "spectralRange.end");
  ICC_TRACE_NAN(biStart, "biSpectralRange.start");
  ICC_TRACE_NAN(biEnd, "biSpectralRange.end");

  bool hasSpectral = (specSteps > 0 || specStart != 0.0f || specEnd != 0.0f);
  bool hasBiSpectral = (biSteps > 0 || biStart != 0.0f || biEnd != 0.0f);
  
  if (hasSpectral) {
    printf("      Spectral: start=%.2fnm end=%.2fnm steps=%u\n", specStart, specEnd, specSteps);
    if (specSteps > 10000) {
      printf("      %s[WARN]  HEURISTIC: Excessive spectral steps: %u%s\n",
             ColorWarning(), specSteps, ColorReset());
      heuristicCount++;
    }
    if (specEnd < specStart && specEnd != 0.0f) {
      printf("      %s[WARN]  HEURISTIC: Spectral end < start (%.2f < %.2f)%s\n",
             ColorWarning(), specEnd, specStart, ColorReset());
      heuristicCount++;
    }
  }
  if (hasBiSpectral) {
    printf("      BiSpectral: start=%.2fnm end=%.2fnm steps=%u\n", biStart, biEnd, biSteps);
    if (biSteps > 10000) {
      printf("      %s[WARN]  HEURISTIC: Excessive bispectral steps: %u%s\n",
             ColorWarning(), biSteps, ColorReset());
      heuristicCount++;
    }
  }
  if (!hasSpectral && !hasBiSpectral) {
    printf("      %s[OK] No spectral data (standard profile)%s\n", ColorSuccess(), ColorReset());
  }

  // MCS (Material Connection Space) enum validation — ICC.2-2023 §7.2.24
  // iccDEV #323: invalid icMaterialColorSignature values cause UBSAN
  // "load of value N, which is not a valid value for type"
  // Valid MCS: 0 (none) or 0x6d630000–0x6d63FFFF ('mc' prefix)
  icUInt32Number mcs = header.mcs;
  if (mcs != 0) {
    icUInt32Number mcsPrefix = mcs & 0xFFFF0000;
    if (mcsPrefix != 0x6d630000) {
      printf("      %s[WARN]  MCS field 0x%08X: not a valid icMaterialColorSignature%s\n",
             ColorCritical(), mcs, ColorReset());
      printf("       %sCWE-843: Invalid enum value → UB in AddXform() (iccDEV #323)%s\n",
             ColorCritical(), ColorReset());
      heuristicCount++;
    } else {
      icUInt32Number mcsChannels = mcs & 0x0000FFFF;
      printf("      MCS: 0x%08X (%u channels)\n", mcs, mcsChannels);
      if (mcsChannels == 0 || mcsChannels > 32) {
        printf("      %s[WARN]  MCS channel count %u outside reasonable range (1-32)%s\n",
               ColorWarning(), mcsChannels, ColorReset());
        heuristicCount++;
      }
    }
  }

  // deviceSubClass validation — ICC.2-2023 §7.2.25
  // Non-zero deviceSubClass should match known device class patterns
  icUInt32Number subClass = header.deviceSubClass;
  if (subClass != 0) {
    printf("      DeviceSubClass: 0x%08X\n", subClass);
  }
}
printf("\n");

  return heuristicCount;
}

// ================================================================
// RunHeaderHeuristics — dispatcher for H1-H8, H15-H17
// ================================================================
int RunHeaderHeuristics(const icHeader &header, size_t actualFileSize)
{
  int heuristicCount = 0;

  heuristicCount += RunHeuristic_H1_ProfileSize(header, actualFileSize);
  heuristicCount += RunHeuristic_H2_MagicBytes(header);
  heuristicCount += RunHeuristic_H3_ColorSpaceSignature(header);
  heuristicCount += RunHeuristic_H4_PCSColorSpace(header);
  heuristicCount += RunHeuristic_H5_PlatformSignature(header);
  heuristicCount += RunHeuristic_H6_RenderingIntent(header);
  heuristicCount += RunHeuristic_H7_ProfileClass(header);
  heuristicCount += RunHeuristic_H8_IlluminantXYZ(header);
  heuristicCount += RunHeuristic_H15_DateValidation(header);
  heuristicCount += RunHeuristic_H16_SignaturePatterns(header);
  heuristicCount += RunHeuristic_H17_SpectralRange(header);

  return heuristicCount;
}
