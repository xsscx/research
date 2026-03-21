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
#include "IccHeuristicsHelpers.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerSignatures.h"
#include "IccAnalyzerColors.h"
#include "IccDefs.h"
#include "IccProfile.h"
#include "IccUtil.h"
#include "IccUtil.h"
#include "IccHeuristicResult.h"
#include <cstdio>
#include <cstring>
#include <cmath>

int RunHeuristic_H1_ProfileSize(const icHeader &header, size_t actualFileSize) {
  auto &hc = HeuristicCollector::instance();

// 1. Profile Size Heuristic (ICC.1-2022-05 §7.2.2)
icUInt32Number profileSize = header.size;
char title[256];
int tlen = snprintf(title, sizeof(title), "Profile Size: %u bytes (0x%08X)", profileSize, profileSize);
if (actualFileSize > 0 && tlen > 0 && tlen < (int)sizeof(title)) {
  snprintf(title + tlen, sizeof(title) - tlen, "  [actual file: %zu bytes]", actualFileSize);
}
hc.begin(1, title);
if (profileSize == 0) {
  hc.warn("HEURISTIC: Profile size is ZERO — ICC.1-2022-05 §7.2.2");
  hc.info("Risk: Invalid header, possible corruption");
} else if (profileSize > (1u << 30)) {
  hc.warn("HEURISTIC: Profile size > 1 GiB (possible memory exhaustion)");
  hc.info("Risk: Resource exhaustion attack");
}
// Truncation: header claims larger than actual file — tags will read OOB
if (actualFileSize > 0 && profileSize > 0 && profileSize > actualFileSize) {
  hc.warn("HEURISTIC: Profile TRUNCATED — header claims %u bytes but file is only %zu bytes",
         profileSize, actualFileSize);
  hc.info("Risk: Tags referencing past EOF will cause heap-buffer-overflow reads");
  double truncPct = 100.0 * (1.0 - (double)actualFileSize / (double)profileSize);
  hc.info("Truncation: %.1f%% of declared data missing (%zu bytes absent)",
         truncPct, (size_t)(profileSize - actualFileSize));
}
// Appended data: file is larger than declared profile size
if (actualFileSize > 0 && profileSize > 0 && actualFileSize > (uint64_t)profileSize + 3) {
  size_t extraBytes = actualFileSize - (size_t)profileSize;
  hc.warn("HEURISTIC: %zu EXTRA BYTES appended past declared profile end", extraBytes);
  hc.info("Risk: Data hiding / smuggling — parsers may ignore appended payload");
  hc.info("Note: Some parsers observed in the wild read past declared size");
}
// Size inflation: header claims much larger than actual file (extreme)
if (actualFileSize > 0 && profileSize > 0 &&
    profileSize > actualFileSize * 16 && profileSize > (128u << 20)) {
  hc.warn("HEURISTIC: Extreme inflation — header claims %u bytes but file is %zu bytes (%.0fx)",
         profileSize, actualFileSize,
         (double)profileSize / actualFileSize);
  hc.info("Risk: OOM via tag-internal allocations sized from inflated header");
}

  return hc.end("Size within normal range");
}

int RunHeuristic_H2_MagicBytes(const icHeader &header) {
  auto &hc = HeuristicCollector::instance();

// 2. Magic Bytes Validation (ICC.1-2022-05 §7.2.9)
const icUInt8Number expectedMagic[4] = {'a', 'c', 's', 'p'};
const icUInt8Number *actualMagic = (icUInt8Number *)&header.magic;
char title[128];
int tlen = snprintf(title, sizeof(title), "Magic Bytes (offset 0x24): ");
for (int i = 0; i < 4 && tlen < (int)sizeof(title) - 4; i++) {
  tlen += snprintf(title + tlen, sizeof(title) - tlen, "%02X ", actualMagic[i]);
}
if (tlen < (int)sizeof(title) - 1)
  tlen += snprintf(title + tlen, sizeof(title) - tlen, "(");
for (int i = 0; i < 4 && tlen < (int)sizeof(title) - 2; i++) {
  tlen += snprintf(title + tlen, sizeof(title) - tlen, "%c",
                   actualMagic[i] >= 32 && actualMagic[i] <= 126 ? actualMagic[i] : '.');
}
if (tlen < (int)sizeof(title) - 1)
  snprintf(title + tlen, sizeof(title) - tlen, ")");
hc.begin(2, title);

if (memcmp(actualMagic, expectedMagic, 4) != 0) {
  hc.warn("HEURISTIC: Invalid magic bytes (expected \"acsp\" — ICC.1-2022-05 §7.2.9)");
  hc.info("Risk: Not a valid ICC profile, possible format confusion attack");
}

  return hc.end("Valid ICC magic signature");
}

int RunHeuristic_H3_ColorSpaceSignature(const icHeader &header) {
  auto &hc = HeuristicCollector::instance();

// 3. ColorSpace Signature Validation (ICC.1-2022-05 §7.2.6, Table 22)
icUInt32Number colorSpace = header.colorSpace;
char csFourCC[5];
SignatureToFourCC(colorSpace, csFourCC);
char title[128];
snprintf(title, sizeof(title), "Data ColorSpace: 0x%08X (%s)", colorSpace, csFourCC);
hc.begin(3, title);

if (IsValidColorSpaceSignature((icColorSpaceSignature)colorSpace)) {
  CIccInfo info;
  char okMsg[128];
  snprintf(okMsg, sizeof(okMsg), "Valid colorSpace: %s",
           info.GetColorSpaceSigName((icColorSpaceSignature)colorSpace));
  return hc.end(okMsg);
} else {
  // Use DescribeColorSpaceSignature for raw byte decomposition
  IccColorSpaceDescription csDesc = DescribeColorSpaceSignature(colorSpace);
  if (colorSpace == 0x00000000 || colorSpace == 0xFFFFFFFF || colorSpace == 0x20202020) {
    hc.warn("HEURISTIC: Invalid/null colorSpace signature");
    hc.info("Risk: Enum confusion, undefined behavior");
  } else if (HasNonPrintableSignature(colorSpace)) {
    hc.warn("HEURISTIC: ColorSpace contains non-printable characters");
    hc.info("Risk: Binary signature exploitation");
  } else {
    hc.warn("HEURISTIC: Unknown/invalid colorSpace signature");
    hc.info("Risk: Parser may not handle unknown values safely");
  }
  hc.info("Name: %s  Bytes: '%s'", csDesc.name, csDesc.bytes);
}

  return hc.end("Valid colorSpace");
}

int RunHeuristic_H4_PCSColorSpace(const icHeader &header) {
  auto &hc = HeuristicCollector::instance();

// 4. PCS ColorSpace Validation (ICC.1-2022-05 §7.2.7; ICC.2-2023 §7.2.2 for spectral PCS)
icUInt32Number pcs = header.pcs;
char pcsFourCC[5];
SignatureToFourCC(pcs, pcsFourCC);
char title[128];
snprintf(title, sizeof(title), "PCS ColorSpace: 0x%08X (%s)", pcs, pcsFourCC);
hc.begin(4, title);

if (pcs == icSigLabData || pcs == icSigXYZData) {
  CIccInfo info;
  char okMsg[128];
  snprintf(okMsg, sizeof(okMsg), "Valid PCS: %s", info.GetColorSpaceSigName((icColorSpaceSignature)pcs));
  return hc.end(okMsg);
} else if (IsSpaceSpectralPCS((icColorSpaceSignature)pcs)) {
  char okMsg[128];
  snprintf(okMsg, sizeof(okMsg), "Spectral PCS (ICC v5): 0x%08X", pcs);
  return hc.end(okMsg);
} else {
  IccColorSpaceDescription pcsDesc = DescribeColorSpaceSignature(pcs);
  hc.warn("HEURISTIC: Invalid PCS signature — ICC.1-2022-05 §7.2.7 requires Lab or XYZ; ICC.2-2023 allows spectral");
  hc.info("Risk: Colorimetric transform failures");
  hc.info("Name: %s  Bytes: '%s'", pcsDesc.name, pcsDesc.bytes);
}

  return hc.end("Valid PCS");
}

int RunHeuristic_H5_PlatformSignature(const icHeader &header) {
  auto &hc = HeuristicCollector::instance();

// 5. Platform, CMM, Manufacturer, Creator Signature Validation
// ICC.1-2022-05 §7.2.10 (Platform), §7.2.3 (CMM), §7.2.12 (Manufacturer), §7.2.17 (Creator)
// PAWS: "Platform, Creator, Manufacturer and CMM fields correspond to registered signatures or are zero"
icUInt32Number platform = header.platform;
char pfFourCC[5];
SignatureToFourCC(platform, pfFourCC);
hc.begin(5, "Platform / CMM / Manufacturer / Creator Validation");
hc.info("Platform: 0x%08X (%s)", platform, pfFourCC);

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
  hc.warn("HEURISTIC: Unknown platform signature — ICC.1-2022-05 §7.2.10 Table 18");
  hc.info("Risk: Platform-specific code path exploitation");
} else {
  hc.info("[OK] Known platform code");
}

// CMM Type Signature (ICC.1-2022-05 §7.2.3, bytes 4-7)
icUInt32Number cmm = header.cmmId;
char cmmFourCC[5];
SignatureToFourCC(cmm, cmmFourCC);
hc.info("CMM: 0x%08X (%s)", cmm, cmmFourCC);

bool validCmm = false;
switch (cmm) {
  case icSigAdobe:           // 'ADBE'
  case icSigAgfa:            // 'ACMS'
  case icSigApple:           // 'appl'
  case icSigColorGear:       // 'CCMS'
  case icSigColorGearLite:   // 'UCCM'
  case icSigColorGearC:      // 'UCMS'
  case icSigEFI:             // 'EFI '
  case icSigExactScan:       // 'EXAC'
  case icSigFujiFilm:        // 'FF  '
  case icSigHarlequinRIP:    // 'HCMM'
  case icSigArgyllCMS:       // 'argl'
  case icSigLogoSync:        // 'LgoS'
  case icSigHeidelberg:      // 'HDM '
  case icSigLinoColor:       // 'Lino'
  case icSigMonaco:          // 'mnco'
  case icSigLittleCMS:       // 'lcms'
  case icSigKodak:           // 'KCMS'
  case icSigKonicaMinolta:   // 'MCML'
  case icSigMicrosoftCMM:    // 'MSFT'
  case icSigWindowsCMS:      // 'WCS '
  case icSigMutoh:           // 'SIGN'
  case icSigOnyxGraphics:    // 'ONYX'
  case icSigRefIccMAX:       // 'RIMX'
  case icSigDemoIccMAX:      // 'DIMX'
  case icSigIccDEV:          // 'ICCD'
  case icSigRolfGierling:    // 'RGMS'
  case icSigSampleICC:       // 'SICC'
  case icSigToshiba:         // 'TCMM'
  case icSigTheImagingFactory: // '32BT'
  case icSigVivo:            // 'VIVO'
  case icSigWareToGo:        // 'WTG '
  case icSigZoran:           // 'zc00'
  case 0x00000000:           // unset
    validCmm = true;
    break;
}

if (!validCmm) {
  hc.warn("HEURISTIC: Unregistered CMM signature — ICC.1-2022-05 §7.2.3");
} else {
  hc.info("[OK] CMM signature registered or zero");
}

// Device Manufacturer (ICC.1-2022-05 §7.2.12, bytes 48-51)
icUInt32Number mfg = header.manufacturer;
char mfgFourCC[5];
SignatureToFourCC(mfg, mfgFourCC);
hc.info("Manufacturer: 0x%08X (%s)", mfg, mfgFourCC);

// ICC spec §7.2.12: "shall" match ICC signature registry or be zero
// We flag unregistered non-zero values as INFO (many valid profiles use vendor sigs)
if (mfg != 0x00000000) {
  // Check for printable ASCII — registered sigs are always printable 4-byte ASCII
  bool printable = true;
  for (int i = 0; i < 4; i++) {
    unsigned char c = static_cast<unsigned char>((mfg >> (24 - i * 8)) & 0xFF);
    if (c < 0x20 || c > 0x7E) { printable = false; break; }
  }
  if (!printable) {
    hc.warn("HEURISTIC: Manufacturer contains non-printable bytes — ICC.1-2022-05 §7.2.12");
  } else {
    hc.info("[OK] Manufacturer signature is printable ASCII");
  }
} else {
  hc.info("[OK] Manufacturer is zero (unspecified)");
}

// Profile Creator (ICC.1-2022-05 §7.2.17, bytes 80-83)
icUInt32Number creator = header.creator;
char crFourCC[5];
SignatureToFourCC(creator, crFourCC);
hc.info("Creator: 0x%08X (%s)", creator, crFourCC);

if (creator != 0x00000000) {
  bool printable = true;
  for (int i = 0; i < 4; i++) {
    unsigned char c = static_cast<unsigned char>((creator >> (24 - i * 8)) & 0xFF);
    if (c < 0x20 || c > 0x7E) { printable = false; break; }
  }
  if (!printable) {
    hc.warn("HEURISTIC: Creator contains non-printable bytes — ICC.1-2022-05 §7.2.17");
  } else {
    hc.info("[OK] Creator signature is printable ASCII");
  }
} else {
  hc.info("[OK] Creator is zero (unspecified)");
}

  return hc.end("All platform/CMM/manufacturer/creator signatures valid");
}

int RunHeuristic_H6_RenderingIntent(const icHeader &header) {
  auto &hc = HeuristicCollector::instance();

// 6. Rendering Intent Validation (ICC.1-2022-05 §7.2.15)
// Bytes 64-67: lower 16 bits = intent (0-3), upper 16 bits must be 0
icUInt32Number intent = header.renderingIntent;
char title[128];
snprintf(title, sizeof(title), "Rendering Intent: %u (0x%08X)", intent, intent);
hc.begin(6, title);

icUInt32Number intentUpper16 = intent >> 16;
icUInt32Number intentLower16 = intent & 0xFFFF;

if (intentUpper16 != 0) {
  hc.warn("HEURISTIC: Upper 16 bits non-zero (0x%04X) — spec requires 0",
         intentUpper16);
  hc.info("Risk: CWE-20: non-conformant header, possible exploitation vector");
}
if (intentLower16 > icAbsoluteColorimetric) {
  hc.warn("HEURISTIC: Invalid rendering intent value %u (> 3)",
         intentLower16);
  hc.info("Risk: Out-of-bounds enum access");
} else if (intentUpper16 == 0) {
  CIccInfo info;
  char okMsg[128];
  snprintf(okMsg, sizeof(okMsg), "Valid intent: %s",
           info.GetRenderingIntentName((icRenderingIntent)intentLower16));
  return hc.end(okMsg);
}

  return hc.end("Valid rendering intent");
}

int RunHeuristic_H7_ProfileClass(const icHeader &header) {
  auto &hc = HeuristicCollector::instance();

// 7. Profile Class Validation (ICC.1-2022-05 §7.2.5, Table 17)
icUInt32Number devClass = header.deviceClass;
char dcFourCC[5];
SignatureToFourCC(devClass, dcFourCC);
char title[128];
snprintf(title, sizeof(title), "Profile Class: 0x%08X (%s)", devClass, dcFourCC);
hc.begin(7, title);

CIccInfo info;
const char *className = info.GetProfileClassSigName((icProfileClassSignature)devClass);
if (!className || strlen(className) == 0) {
  hc.warn("HEURISTIC: Unknown profile class — ICC.1-2022-05 §7.2.5 Table 17");
  hc.info("Risk: Class-specific parsing vulnerabilities");
} else {
  char okMsg[128];
  snprintf(okMsg, sizeof(okMsg), "Known class: %s", className);
  return hc.end(okMsg);
}

  return hc.end("Known profile class");
}

int RunHeuristic_H8_IlluminantXYZ(const icHeader &header) {
  auto &hc = HeuristicCollector::instance();

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

char title[128];
snprintf(title, sizeof(title), "Illuminant XYZ: (%.6f, %.6f, %.6f)", X, Y, Z);
hc.begin(8, title);

// ICC spec D50 reference values (s15Fixed16Number encoding)
const double d50X = 0.9642, d50Y = 1.0000, d50Z = 0.8249;
const double d50Tol = 0.002; // s15Fixed16 rounding tolerance

if (std::isnan(X) || std::isnan(Y) || std::isnan(Z) ||
     std::isinf(X) || std::isinf(Y) || std::isinf(Z)) {
  hc.warn("HEURISTIC: NaN or Infinity in illuminant values");
  hc.info("Risk: NaN propagation in color transforms, potential crash");
} else if (X < 0.0 || Y < 0.0 || Z < 0.0) {
  hc.warn("HEURISTIC: Negative illuminant values (non-physical)");
  hc.info("Risk: Undefined behavior in color calculations");
} else if (fabs(X - d50X) > d50Tol || fabs(Y - d50Y) > d50Tol || fabs(Z - d50Z) > d50Tol) {
  hc.warn("HEURISTIC: PCS illuminant is NOT D50 (spec: %.4f, %.4f, %.4f)",
         d50X, d50Y, d50Z);
  hc.info("Risk: Non-conformant header — ICC.1-2022-05 §7.2.16 requires D50");
} else if (X > 5.0 || Y > 5.0 || Z > 5.0) {
  hc.warn("HEURISTIC: Illuminant values > 5.0 (suspicious)");
  hc.info("Risk: Floating-point overflow in transforms");
}

  return hc.end("PCS illuminant matches D50 (within s15Fixed16 tolerance)");
}

int RunHeuristic_H15_DateValidation(const icHeader &header) {
  auto &hc = HeuristicCollector::instance();

// 15. Date Field Validation (ICC.1-2022-05 §4.2 dateTimeNumber)
char title[128];
snprintf(title, sizeof(title), "Date Validation (§4.2 dateTimeNumber): %u-%02u-%02u %02u:%02u:%02u",
         header.date.year, header.date.month, header.date.day,
         header.date.hours, header.date.minutes, header.date.seconds);
hc.begin(15, title);
{
  bool dateValid = true;
  if (header.date.month > 12 || header.date.month == 0) {
    hc.warn("HEURISTIC: Invalid month: %u", header.date.month);
    dateValid = false;
  }
  if (header.date.day > 31 || header.date.day == 0) {
    hc.warn("HEURISTIC: Invalid day: %u", header.date.day);
    dateValid = false;
  }
  if (header.date.hours > 23) {
    hc.warn("HEURISTIC: Invalid hours: %u", header.date.hours);
    dateValid = false;
  }
  if (header.date.minutes > 59) {
    hc.warn("HEURISTIC: Invalid minutes: %u", header.date.minutes);
    dateValid = false;
  }
  if (header.date.seconds > 59) {
    hc.warn("HEURISTIC: Invalid seconds: %u", header.date.seconds);
    dateValid = false;
  }
  if (header.date.year > 2100 || header.date.year < 1900) {
    hc.warn("HEURISTIC: Suspicious year: %u (expected 1900-2100)",
           header.date.year);
    dateValid = false;
  }
  if (!dateValid) {
    hc.info("Risk: Malformed date may indicate crafted/corrupted profile");
  }
}

  return hc.end("Date values within valid ranges");
}

int RunHeuristic_H16_SignaturePatterns(const icHeader &header) {
  auto &hc = HeuristicCollector::instance();

// 16. Suspicious Signature Patterns (repeat-byte, null)
hc.begin(16, "Signature Pattern Analysis");
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
      hc.info("%s: 0x%08X repeat-byte pattern (fuzz artifact?)", s.name, s.sig);
      suspiciousCount++;
    }
  }
  if (suspiciousCount > 0) {
    hc.warn("HEURISTIC: %d repeat-byte signature(s) — likely crafted/fuzzed profile", suspiciousCount);
  }
}

  return hc.end("No suspicious signature patterns detected");
}

int RunHeuristic_H17_SpectralRange(const icHeader &header) {
  auto &hc = HeuristicCollector::instance();

// 17. Spectral/BiSpectral Range Validation (ICC.2-2023 §7.2.22-23)
hc.begin(17, "Spectral Range Validation (ICC.2-2023 §7.2.22-23)");
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
    hc.info("Spectral: start=%.2fnm end=%.2fnm steps=%u", specStart, specEnd, specSteps);
    if (specSteps > 10000) {
      hc.warn("HEURISTIC: Excessive spectral steps: %u", specSteps);
    }
    if (specEnd < specStart && specEnd != 0.0f) {
      hc.warn("HEURISTIC: Spectral end < start (%.2f < %.2f)", specEnd, specStart);
    }
    // CFL-028 pattern: steps==1 causes division by zero in SetRange() (CWE-369/CWE-681)
    if (specSteps == 1) {
      hc.warn("HEURISTIC: Spectral steps=1 causes division by zero in rangeMap/SetRange — CWE-369");
      hc.cweNote("CWE-369: Divide By Zero / CWE-681: NaN-to-integer cast");
    }
    // Degenerate range: start==end with any steps causes 0/0=NaN scale factor
    if (specSteps > 0 && (specEnd - specStart) < 0.001f && (specStart - specEnd) < 0.001f) {
      hc.warn("HEURISTIC: Spectral start==end (%.2fnm) with steps=%u — degenerate range causes NaN scale — CWE-681",
             specStart, specSteps);
      hc.cweNote("CWE-681: Incorrect Conversion between Numeric Types");
    }
  }
  if (hasBiSpectral) {
    hc.info("BiSpectral: start=%.2fnm end=%.2fnm steps=%u", biStart, biEnd, biSteps);
    if (biSteps > 10000) {
      hc.warn("HEURISTIC: Excessive bispectral steps: %u", biSteps);
    }
    if (biSteps == 1) {
      hc.warn("HEURISTIC: BiSpectral steps=1 causes division by zero in rangeMap/SetRange — CWE-369");
    }
    if (biSteps > 0 && (biEnd - biStart) < 0.001f && (biStart - biEnd) < 0.001f) {
      hc.warn("HEURISTIC: BiSpectral start==end (%.2fnm) — degenerate range causes NaN scale — CWE-681",
             biStart);
    }
  }
  // MCS (Material Connection Space) enum validation — ICC.2-2023 §7.2.24
  // iccDEV #323: invalid icMaterialColorSignature values cause UBSAN
  // "load of value N, which is not a valid value for type"
  // Valid MCS: 0 (none) or 0x6d630000–0x6d63FFFF ('mc' prefix)
  icUInt32Number mcs = header.mcs;
  if (mcs != 0) {
    icUInt32Number mcsPrefix = mcs & 0xFFFF0000;
    if (mcsPrefix != 0x6d630000) {
      hc.warn("HEURISTIC: MCS field 0x%08X: not a valid icMaterialColorSignature", mcs);
      hc.cweNote("CWE-843: Invalid enum value — UB in AddXform() (iccDEV #323)");
    } else {
      icUInt32Number mcsChannels = mcs & 0x0000FFFF;
      hc.info("MCS: 0x%08X (%u channels)", mcs, mcsChannels);
      if (mcsChannels == 0 || mcsChannels > 32) {
        hc.warn("HEURISTIC: MCS channel count %u outside reasonable range (1-32)", mcsChannels);
      }
    }
  }

  // deviceSubClass validation — ICC.2-2023 §7.2.25
  // Non-zero deviceSubClass should match known device class patterns
  icUInt32Number subClass = header.deviceSubClass;
  if (subClass != 0) {
    hc.info("DeviceSubClass: 0x%08X", subClass);
  }
}

  return hc.end("No spectral range issues detected");
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
