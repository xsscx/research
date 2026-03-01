/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * This software and associated documentation files (the "Software") are the
 * exclusive intellectual property of David H Hoyt LLC.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "David H Hoyt LLC" must not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID H HOYT LLC "AS IS" AND ANY EXPRESSED
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL DAVID H HOYT LLC BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Contact: https://hoyt.net
 */

#include "IccAnalyzerCommon.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerSignatures.h"

#include "IccAnalyzerSafeArithmetic.h"
#include "IccAnalyzerColors.h"
#include "IccTagBasic.h"
#include "IccTagComposite.h"
#include "IccProfile.h"
#include "IccMpeBasic.h"
#include "IccMpeCalc.h"
#include "IccTagMPE.h"
#include <cmath>

//==============================================================================
// Heuristic Security Analysis
//==============================================================================

int HeuristicAnalyze(const char *filename, const char *fingerprint_db)
{
  printf("\n");
  printf("=========================================================================\n");
  printf("|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |\n");
  printf("=========================================================================\n");
  printf("\nFile: %s\n\n", filename);
  
  int heuristicCount = 0;
  
  // PHASE 0: Fingerprint Database Check (if available)
#if ICCANALYZER_ENABLE_FINGERPRINT
  if (fingerprint_db != nullptr) {
    printf("=======================================================================\n");
    printf("FINGERPRINT DATABASE CHECK (V2.1)\n");
    printf("=======================================================================\n\n");
    
    std::string vuln_type, known_as;
    float confidence = 0.0f;
    RiskLevel risk = RiskLevel::UNKNOWN;
    
    int fp_result = CheckFingerprintQuiet(filename, fingerprint_db, vuln_type, known_as, confidence, risk);
    
    if (fp_result == 2) {
      // EXACT MATCH - Known malicious
      printf("[CRITICAL] EXACT MATCH TO KNOWN MALICIOUS PROFILE\n\n");
      printf("  Vulnerability Type: %s\n", vuln_type.c_str());
      printf("  Known As: %s\n", known_as.c_str());
      printf("  Confidence: %.0f%% (exact SHA256 match)\n", confidence);
      printf("  Risk Level: %s\n", RiskLevelToString(risk).c_str());
      
      // Display risk-specific warnings
      if (risk == RiskLevel::CRITICAL || risk == RiskLevel::HIGH) {
        printf("  [WARN]  EXPLOITABLE VULNERABILITY DETECTED\n\n");
        printf("  [WARN]  This profile matches a known exploit/POC in the fingerprint database.\n");
        printf("  [WARN]  DO NOT use this profile in production systems.\n");
        printf("  [WARN]  Recommended action: QUARANTINE IMMEDIATELY and analyze for threat intelligence.\n\n");
        heuristicCount += 10; // Critical severity
      } else if (risk == RiskLevel::MEDIUM) {
        printf("  [WARN]  POTENTIALLY EXPLOITABLE ISSUE\n\n");
        printf("  [WARN]  This profile contains known security issues.\n");
        printf("  [WARN]  Use with caution in controlled environments only.\n\n");
        heuristicCount += 7; // High severity
      } else {
        printf("  [INFO] LOW SEVERITY ISSUE\n\n");
        printf("  [INFO] This profile contains known issues but is unlikely exploitable.\n");
        printf("  [INFO] Review recommended before deployment.\n\n");
        heuristicCount += 3; // Low severity
      }
    } else if (fp_result == 1) {
      // PARTIAL MATCH - Suspicious similarity
      printf("[WARN]  WARNING: PARTIAL MATCH TO KNOWN MALICIOUS PROFILE\n\n");
      printf("  Vulnerability Type: %s\n", vuln_type.c_str());
      printf("  Similar To: %s\n", known_as.c_str());
      printf("  Confidence: %.0f%% (structural/header similarity)\n", confidence);
      printf("  Risk Level: %s\n", RiskLevelToString(risk).c_str());
      
      // Risk-aware warnings for partial matches
      if (risk == RiskLevel::CRITICAL || risk == RiskLevel::HIGH) {
        printf("  [WARN]  SIMILAR TO HIGH-RISK PROFILE\n\n");
        printf("  [WARN]  This profile shares structural similarities with known exploits.\n");
        printf("  [WARN]  Possible variant or mutated version of known vulnerability.\n");
        printf("  [WARN]  Recommended action: Additional scrutiny required.\n\n");
        heuristicCount += 5; // Medium-high severity
      } else {
        printf("  [INFO] SIMILAR TO KNOWN ISSUE\n\n");
        printf("  [INFO] This profile may be a variant of a known issue.\n");
        printf("  [INFO] Recommended action: Manual review suggested.\n\n");
        heuristicCount += 2;
      }
    } else {
      printf("[OK] No match to known malicious profiles in database\n");
      printf("  Database: %s\n", fingerprint_db);
      printf("  Status: Profile appears novel (not previously seen)\n");
      printf("  Note: Novel doesn't mean safe - continue with heuristic analysis\n\n");
    }
  }
#else
  // Lite version: fingerprint database disabled
  if (fingerprint_db != nullptr) {
    printf("Note: Fingerprint database checking is disabled in lite version\n");
    printf("      For full fingerprint analysis, use regular iccAnalyzer\n\n");
  }
#endif
  
  CIccFileIO io;
  if (!io.Open(filename, "rb")) {
    printf("[ERROR] Cannot open file: %s\n", filename);
    return -1;
  }

  // Get actual file size for inflation detection
  struct stat fileStat;
  size_t actualFileSize = 0;
  if (stat(filename, &fileStat) == 0) {
    actualFileSize = fileStat.st_size;
  }
  
  icHeader header;
  // Read header with proper byte-swapping (ICC is big-endian)
  if (!io.Read32(&header.size) ||
      !io.Read32(&header.cmmId) ||
      !io.Read32(&header.version) ||
      !io.Read32(&header.deviceClass) ||
      !io.Read32(&header.colorSpace) ||
      !io.Read32(&header.pcs) ||
      !io.Read16(&header.date.year) ||
      !io.Read16(&header.date.month) ||
      !io.Read16(&header.date.day) ||
      !io.Read16(&header.date.hours) ||
      !io.Read16(&header.date.minutes) ||
      !io.Read16(&header.date.seconds) ||
      io.Read8(&header.magic, sizeof(header.magic)) != sizeof(header.magic) ||
      !io.Read32(&header.platform) ||
      !io.Read32(&header.flags) ||
      !io.Read32(&header.manufacturer) ||
      !io.Read32(&header.model) ||
      !io.Read64(&header.attributes) ||
      !io.Read32(&header.renderingIntent) ||
      !io.Read32(&header.illuminant.X) ||
      !io.Read32(&header.illuminant.Y) ||
      !io.Read32(&header.illuminant.Z) ||
      !io.Read32(&header.creator) ||
      io.Read8(&header.profileID, sizeof(header.profileID)) != sizeof(header.profileID) ||
      !io.Read32(&header.spectralPCS) ||
      !io.Read16(&header.spectralRange.start) ||
      !io.Read16(&header.spectralRange.end) ||
      !io.Read16(&header.spectralRange.steps) ||
      !io.Read16(&header.biSpectralRange.start) ||
      !io.Read16(&header.biSpectralRange.end) ||
      !io.Read16(&header.biSpectralRange.steps) ||
      !io.Read32(&header.mcs) ||
      !io.Read32(&header.deviceSubClass) ||
      io.Read8(&header.reserved[0], sizeof(header.reserved)) != sizeof(header.reserved)) {
    printf("[ERROR] Cannot read ICC header (file too small or corrupted)\n");
    io.Close();
    return -1;
  }
  
  printf("=======================================================================\n");
  printf("%sHEADER VALIDATION HEURISTICS%s\n", ColorHeader(), ColorReset());
  printf("=======================================================================\n\n");
  
  // 1. Profile Size Heuristic
  icUInt32Number profileSize = header.size;
  printf("[H1] Profile Size: %u bytes (0x%08X)", profileSize, profileSize);
  if (actualFileSize > 0) {
    printf("  [actual file: %zu bytes]", actualFileSize);
  }
  printf("\n");
  if (profileSize == 0) {
    printf("     %s[WARN]  HEURISTIC: Profile size is ZERO%s\n", ColorCritical(), ColorReset());
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
  
  // 2. Magic Bytes Validation
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
    printf("     %s[WARN]  HEURISTIC: Invalid magic bytes (expected \"acsp\")%s\n", ColorCritical(), ColorReset());
    printf("     %sRisk: Not a valid ICC profile, possible format confusion attack%s\n", ColorWarning(), ColorReset());
    heuristicCount++;
  } else {
    printf("     %s[OK] Valid ICC magic signature%s\n", ColorSuccess(), ColorReset());
  }
  printf("\n");
  
  // 3. ColorSpace Signature Validation (using IccSignatureUtils)
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
  
  // 4. PCS ColorSpace Validation (with ICC v5 spectral PCS support)
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
    printf("     %s[WARN]  HEURISTIC: Invalid PCS signature (must be Lab, XYZ, or spectral)%s\n", ColorCritical(), ColorReset());
    printf("     %sRisk: Colorimetric transform failures%s\n", ColorWarning(), ColorReset());
    printf("     %sName: %s  Bytes: '%s'%s\n", ColorInfo(), pcsDesc.name, pcsDesc.bytes, ColorReset());
    heuristicCount++;
  }
  printf("\n");
  
  // 5. Platform Signature Validation
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
    printf("     %s[WARN]  HEURISTIC: Unknown platform signature%s\n", ColorWarning(), ColorReset());
    printf("     %sRisk: Platform-specific code path exploitation%s\n", ColorWarning(), ColorReset());
    heuristicCount++;
  } else {
    printf("     %s[OK] Known platform code%s\n", ColorSuccess(), ColorReset());
  }
  printf("\n");
  
  // 6. Rendering Intent Validation
  icUInt32Number intent = header.renderingIntent;
  printf("[H6] Rendering Intent: %u (0x%08X)\n", intent, intent);
  
  if (intent > icAbsoluteColorimetric) {
    printf("     %s[WARN]  HEURISTIC: Invalid rendering intent (> 3)%s\n", ColorCritical(), ColorReset());
    printf("     %sRisk: Out-of-bounds enum access%s\n", ColorWarning(), ColorReset());
    heuristicCount++;
  } else {
    CIccInfo info;
    printf("     %s[OK] Valid intent: %s%s\n", ColorSuccess(), info.GetRenderingIntentName((icRenderingIntent)intent), ColorReset());
  }
  printf("\n");
  
  // 7. Profile Class Validation
  icUInt32Number devClass = header.deviceClass;
  char dcFourCC[5];
  SignatureToFourCC(devClass, dcFourCC);
  printf("[H7] Profile Class: 0x%08X (%s)\n", devClass, dcFourCC);
  
  CIccInfo info;
  const char *className = info.GetProfileClassSigName((icProfileClassSignature)devClass);
  if (!className || strlen(className) == 0) {
    printf("     %s[WARN]  HEURISTIC: Unknown profile class signature%s\n", ColorWarning(), ColorReset());
    printf("     %sRisk: Class-specific parsing vulnerabilities%s\n", ColorWarning(), ColorReset());
    heuristicCount++;
  } else {
    printf("     %s[OK] Known class: %s%s\n", ColorSuccess(), className, ColorReset());
  }
  printf("\n");
  
  // 8. Illuminant XYZ Validation
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
  
  if (X < 0.0 || Y < 0.0 || Z < 0.0) {
    printf("     %s[WARN]  HEURISTIC: Negative illuminant values (non-physical)%s\n", ColorCritical(), ColorReset());
    printf("     %sRisk: Undefined behavior in color calculations%s\n", ColorWarning(), ColorReset());
    heuristicCount++;
  } else if (std::isnan(X) || std::isnan(Y) || std::isnan(Z) ||
             std::isinf(X) || std::isinf(Y) || std::isinf(Z)) {
    printf("     %s[WARN]  HEURISTIC: NaN or Infinity in illuminant values%s\n", ColorCritical(), ColorReset());
    printf("     %sRisk: NaN propagation in color transforms, potential crash%s\n", ColorWarning(), ColorReset());
    heuristicCount++;
  } else if (X > 5.0 || Y > 5.0 || Z > 5.0) {
    printf("     %s[WARN]  HEURISTIC: Illuminant values > 5.0 (suspicious)%s\n", ColorWarning(), ColorReset());
    printf("     %sRisk: Floating-point overflow in transforms%s\n", ColorWarning(), ColorReset());
    heuristicCount++;
  } else {
    printf("     %s[OK] Illuminant values within physical range%s\n", ColorSuccess(), ColorReset());
  }
  printf("\n");
  
  // 15. Date Field Validation
  printf("[H15] Date Validation: %u-%02u-%02u %02u:%02u:%02u\n",
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
  
  // 17. Spectral/BiSpectral Range Validation
  printf("[H17] Spectral Range Validation\n");
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
  }
  printf("\n");

  io.Close();
  
  // Now open profile with IccProfLib for tag-level analysis
  CIccProfile *pIcc = OpenIccProfile(filename);
  if (!pIcc) {
    printf("=======================================================================\n");
    printf("[WARN]  Profile failed to load - skipping tag-level heuristics\n");
    printf("   Use -n (ninja mode) for raw analysis of malformed profiles\n");
    printf("=======================================================================\n\n");
  } else {
    printf("=======================================================================\n");
    printf("TAG-LEVEL HEURISTICS\n");
    printf("=======================================================================\n\n");
    
    // 9. Text Tag Presence
    icTagSignature textTags[] = {
      icSigProfileDescriptionTag,
      icSigCopyrightTag,
      icSigDeviceMfgDescTag,
      icSigDeviceModelDescTag
    };
    
    const char *textTagNames[] = {
      "Description",
      "Copyright",
      "Manufacturer",
      "Device Model"
    };
    
    printf("[H9] Critical Text Tags:\n");
    int missingCount = 0;
    for (size_t i = 0; i < sizeof(textTags)/sizeof(textTags[0]); i++) {
      CIccTag *pTag = pIcc->FindTag(textTags[i]);
      if (pTag) {
        printf("     %s: Present [OK]\n", textTagNames[i]);
      } else {
        printf("     %s: Missing\n", textTagNames[i]);
        missingCount++;
      }
    }
    if (missingCount > 2) {
      printf("     %s[WARN]  HEURISTIC: Multiple required text tags missing%s\n", ColorWarning(), ColorReset());
      printf("       %sRisk: Incomplete/malformed profile%s\n", ColorWarning(), ColorReset());
      heuristicCount++;
    }
    printf("\n");
    
    // 10. Tag Count Validation
    int tagCount = pIcc->m_Tags.size();
    
    printf("[H10] Tag Count: %d\n", tagCount);
    if (tagCount == 0) {
      printf("      %s[WARN]  HEURISTIC: Zero tags (invalid profile)%s\n", ColorCritical(), ColorReset());
      printf("       %sRisk: Parser confusion, empty profile attack%s\n", ColorWarning(), ColorReset());
      heuristicCount++;
    } else if (tagCount > 200) {
      printf("      %s[WARN]  HEURISTIC: Excessive tag count (>200)%s\n", ColorWarning(), ColorReset());
      printf("       %sRisk: Resource exhaustion%s\n", ColorWarning(), ColorReset());
      heuristicCount++;
    } else {
      printf("      %s[OK] Tag count within normal range%s\n", ColorSuccess(), ColorReset());
    }
    printf("\n");
    
    // 11. CLUT Size Limit Check (Resource Exhaustion) — walk actual LUT tags
    printf("[H11] CLUT Entry Limit Check\n");
    printf("      Max safe CLUT entries per tag: %llu (16M)\n",
           (unsigned long long)ICCANALYZER_MAX_CLUT_ENTRIES);
    
    {
      static const icTagSignature clutSigs[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
      };
      int clutCount = 0;
      for (size_t li = 0; li < sizeof(clutSigs)/sizeof(clutSigs[0]); li++) {
        CIccTag *pLTag = pIcc->FindTag(clutSigs[li]);
        if (!pLTag) continue;
        CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pLTag);
        if (!pMBB) continue;
        CIccCLUT *pCLUT = pMBB->GetCLUT();
        if (!pCLUT) continue;
        clutCount++;
        icUInt8Number nIn = pMBB->InputChannels();
        uint64_t entries = 1;
        bool overflow = false;
        for (int ch = 0; ch < nIn && ch < 16; ch++) {
          if (!SafeMul64(&entries, entries, pCLUT->GridPoint(ch))) { overflow = true; break; }
        }
        if (!overflow) SafeMul64(&entries, entries, pCLUT->GetOutputChannels());
        if (overflow || entries > ICCANALYZER_MAX_CLUT_ENTRIES) {
          char sig4[5];
          SignatureToFourCC(static_cast<icUInt32Number>(clutSigs[li]), sig4);
          printf("      %s[WARN] CLUT in '%s': %llu entries (limit %llu)%s\n",
                 ColorWarning(), sig4, (unsigned long long)entries,
                 (unsigned long long)ICCANALYZER_MAX_CLUT_ENTRIES, ColorReset());
          heuristicCount++;
        }
      }
      if (clutCount == 0) {
        printf("      %s[OK] No CLUT tags to check%s\n", ColorSuccess(), ColorReset());
      } else {
        printf("      Inspected %d CLUT tag(s)\n", clutCount);
      }
    }
    printf("\n");
    
    // 12. MPE Element Chain Depth — walk actual MPE tags
    printf("[H12] MPE Chain Depth Check\n");
    printf("      Max MPE elements per chain: %u\n", ICCANALYZER_MAX_MPE_ELEMENTS);
    
    {
      static const icTagSignature mpeSigs[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
        icSigDToB0Tag, icSigDToB1Tag,
        icSigBToD0Tag, icSigBToD1Tag,
      };
      int mpeCount = 0;
      for (size_t mi = 0; mi < sizeof(mpeSigs)/sizeof(mpeSigs[0]); mi++) {
        CIccTag *pMTag = pIcc->FindTag(mpeSigs[mi]);
        if (!pMTag) continue;
        CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement*>(pMTag);
        if (!pMPE) continue;
        mpeCount++;
        icUInt32Number nElem = pMPE->NumElements();
        if (nElem > ICCANALYZER_MAX_MPE_ELEMENTS) {
          char sig4[5];
          SignatureToFourCC(static_cast<icUInt32Number>(mpeSigs[mi]), sig4);
          printf("      %s[WARN] MPE '%s' has %u elements (limit %u)%s\n",
                 ColorWarning(), sig4, nElem, ICCANALYZER_MAX_MPE_ELEMENTS, ColorReset());
          heuristicCount++;
        }
      }
      if (mpeCount == 0) {
        printf("      %s[OK] No MPE tags to check%s\n", ColorSuccess(), ColorReset());
      } else {
        printf("      Inspected %d MPE tag(s)\n", mpeCount);
      }
    }
    printf("\n");
    
    // 13. Per-Tag Size Check — inspect actual tag sizes
    printf("[H13] Per-Tag Size Check\n");
    printf("      Max tag size: %llu MB (%llu bytes)\n",
           (unsigned long long)(ICCANALYZER_MAX_TAG_SIZE >> 20),
           (unsigned long long)ICCANALYZER_MAX_TAG_SIZE);
    
    {
      int oversizedCount = 0;
      TagEntryList::iterator tit;
      for (tit = pIcc->m_Tags.begin(); tit != pIcc->m_Tags.end(); tit++) {
        IccTagEntry *e = &(*tit);
        if (e->TagInfo.size > ICCANALYZER_MAX_TAG_SIZE) {
          char sig4[5];
          SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), sig4);
          printf("      %s[WARN] Tag '%s' size=%u bytes (%.1f MB) exceeds limit%s\n",
                 ColorWarning(), sig4, e->TagInfo.size,
                 e->TagInfo.size / (1024.0 * 1024.0), ColorReset());
          oversizedCount++;
        }
      }
      if (oversizedCount > 0) {
        printf("      %s[WARN] %d tag(s) exceed size limit%s\n",
               ColorCritical(), oversizedCount, ColorReset());
        heuristicCount++;
      } else {
        printf("      %s[OK] All %d tags within size limits%s\n",
               ColorSuccess(), tagCount, ColorReset());
      }
    }
    printf("\n");

    
    // 14. TagArrayType Detection (CRITICAL - Heap-Use-After-Free)
    // Based on fuzzer findings 2026-01-30: TagArray can appear under ANY signature
    printf("[H14] TagArrayType Detection (UAF Risk)\n");
    printf("      Checking for TagArrayType (0x74617279 = 'tary')\n");
    printf("      Note: Tag signature ≠ tag type - must check tag DATA\n");
    
    // Re-read file for raw tag type validation
    FILE *fp = fopen(filename, "rb");
    if (fp) {
      // Get file size
      fseek(fp, 0, SEEK_END);
      size_t fileSize = ftell(fp);
      fseek(fp, 0, SEEK_SET);
      
      if (fileSize >= 132) {
        icUInt8Number rawHdr[132];
        if (fread(rawHdr, 1, 132, fp) == 132) {
          icUInt32Number tagTableCount = (static_cast<icUInt32Number>(rawHdr[128])<<24) | (static_cast<icUInt32Number>(rawHdr[129])<<16) | 
                                          (static_cast<icUInt32Number>(rawHdr[130])<<8) | rawHdr[131];
          
          bool foundTagArray = false;
          icUInt32Number tagArrayCount = 0;
          
          // Read each tag entry and check its TYPE (not just signature)
          for (icUInt32Number i = 0; i < tagTableCount && i < 256; i++) {
            size_t entryPos = 132 + i*12;
            if (entryPos + 12 > fileSize) break;
            
            icUInt8Number entry[12];
            fseek(fp, entryPos, SEEK_SET);
            if (fread(entry, 1, 12, fp) != 12) break;
            
            icUInt32Number tagSig = (static_cast<icUInt32Number>(entry[0])<<24) | (static_cast<icUInt32Number>(entry[1])<<16) | (static_cast<icUInt32Number>(entry[2])<<8) | entry[3];
            icUInt32Number tagOffset = (static_cast<icUInt32Number>(entry[4])<<24) | (static_cast<icUInt32Number>(entry[5])<<16) | (static_cast<icUInt32Number>(entry[6])<<8) | entry[7];
            icUInt32Number tagSize = (static_cast<icUInt32Number>(entry[8])<<24) | (static_cast<icUInt32Number>(entry[9])<<16) | (static_cast<icUInt32Number>(entry[10])<<8) | entry[11];
            
            // Validate tag is within file bounds (overflow-safe check)
            if (tagOffset >= 128 && tagSize >= 4 && tagSize <= fileSize && tagOffset <= fileSize - tagSize) {
              icUInt8Number tagData[4];
              fseek(fp, tagOffset, SEEK_SET);
              if (fread(tagData, 1, 4, fp) == 4) {
                icUInt32Number tagType = (static_cast<icUInt32Number>(tagData[0])<<24) | (static_cast<icUInt32Number>(tagData[1])<<16) | 
                                         (static_cast<icUInt32Number>(tagData[2])<<8) | tagData[3];
                
                // Check for TagArrayType (0x74617279 = 'tary')
                if (tagType == 0x74617279) {
                  foundTagArray = true;
                  tagArrayCount++;
                  
                  char sigStr[5], typeStr[5];
                  sigStr[0] = (tagSig>>24)&0xff; sigStr[1] = (tagSig>>16)&0xff;
                  sigStr[2] = (tagSig>>8)&0xff; sigStr[3] = tagSig&0xff; sigStr[4] = '\0';
                  typeStr[0] = (tagType>>24)&0xff; typeStr[1] = (tagType>>16)&0xff;
                  typeStr[2] = (tagType>>8)&0xff; typeStr[3] = tagType&0xff; typeStr[4] = '\0';
                  
                  printf("      [WARN]  CRITICAL: TagArrayType found!\n");
                  printf("       Tag %u: signature='%s' (0x%08X), type='%s' (0x%08X)\n",
                         i, sigStr, tagSig, typeStr, tagType);
                }
              }
            }
          }
          
          if (foundTagArray) {
            printf("      %s[CRITICAL] HEURISTIC: %u TagArrayType tag(s) detected%s\n", ColorCritical(), tagArrayCount, ColorReset());
            printf("       %sRisk: CRITICAL - Heap-use-after-free in CIccTagArray::Cleanup()%s\n", ColorCritical(), ColorReset());
            printf("       %sLocation: IccProfLib/IccTagComposite.cpp:1514%s\n", ColorInfo(), ColorReset());
            printf("       %sImpact: Code execution, memory corruption%s\n", ColorCritical(), ColorReset());
            printf("       %sRecommendation: REJECT profile, potential exploit attempt%s\n", ColorCritical(), ColorReset());
            heuristicCount++;
          } else {
            printf("      %s[OK] No TagArrayType tags detected%s\n", ColorSuccess(), ColorReset());
          }
        }
      }
      fclose(fp);
    } else {
      printf("      %s[WARN]  Cannot re-open file for tag type validation%s\n", ColorWarning(), ColorReset());
    }
    printf("\n");
    
    // 18. Technology Signature Validation
    printf("[H18] Technology Signature Validation\n");
    {
      CIccTag *pTechTag = pIcc->FindTag(icSigTechnologyTag);
      if (pTechTag) {
        CIccTagSignature *pSigTag = dynamic_cast<CIccTagSignature*>(pTechTag);
        if (pSigTag) {
          icTechnologySignature techSig = static_cast<icTechnologySignature>(pSigTag->GetValue());
          if (IsValidTechnologySignature(techSig)) {
            CIccInfo techInfo;
            printf("      %s[OK] Valid technology: %s%s\n", ColorSuccess(),
                   techInfo.GetTechnologySigName(techSig), ColorReset());
          } else {
            printf("      %s[WARN]  HEURISTIC: Unknown technology signature: 0x%08X%s\n",
                   ColorWarning(), static_cast<unsigned>(techSig), ColorReset());
            printf("       %sRisk: Non-standard technology, possible parser issue%s\n",
                   ColorWarning(), ColorReset());
            heuristicCount++;
          }
        } else {
          printf("      %s[WARN]  Technology tag has unexpected type%s\n", ColorWarning(), ColorReset());
          heuristicCount++;
        }
      } else {
        printf("      %sINFO: No technology tag present%s\n", ColorInfo(), ColorReset());
      }
    }
    printf("\n");

    // 19. Tag Overlap Detection
    printf("[H19] Tag Offset/Size Overlap Detection\n");
    {
      struct TagRange { icUInt32Number sig; icUInt32Number offset; icUInt32Number size; };
      std::vector<TagRange> ranges;
      TagEntryList::iterator it;
      for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
        IccTagEntry *e = &(*it);
        ranges.push_back({static_cast<icUInt32Number>(e->TagInfo.sig), e->TagInfo.offset, e->TagInfo.size});
      }
      int overlapCount = 0;
      for (size_t a = 0; a < ranges.size(); a++) {
        for (size_t b = a+1; b < ranges.size(); b++) {
          if (ranges[a].offset == ranges[b].offset && ranges[a].size == ranges[b].size)
            continue; // Shared tag data (allowed by spec)
          uint64_t aEnd = (uint64_t)ranges[a].offset + ranges[a].size;
          uint64_t bEnd = (uint64_t)ranges[b].offset + ranges[b].size;
          if (ranges[a].offset < bEnd && ranges[b].offset < aEnd &&
              ranges[a].offset != ranges[b].offset) {
            char s1[5], s2[5];
            SignatureToFourCC(ranges[a].sig, s1);
            SignatureToFourCC(ranges[b].sig, s2);
            printf("      %s[WARN]  Tags '%s' and '%s' overlap: [%u+%u] vs [%u+%u]%s\n",
                   ColorCritical(), s1, s2,
                   ranges[a].offset, ranges[a].size,
                   ranges[b].offset, ranges[b].size, ColorReset());
            overlapCount++;
          }
        }
      }
      if (overlapCount > 0) {
        printf("      %sRisk: %d tag overlap(s) — possible data corruption or exploitation%s\n",
               ColorCritical(), overlapCount, ColorReset());
        heuristicCount++;
      } else {
        printf("      %s[OK] No tag overlaps detected%s\n", ColorSuccess(), ColorReset());
      }
    }
    printf("\n");

    // 20. Tag Type Signature Validation
    printf("[H20] Tag Type Signature Validation\n");
    {
      int invalidTypeCount = 0;
      FILE *fp = fopen(filename, "rb");
      if (fp) {
        TagEntryList::iterator it;
        for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
          IccTagEntry *e = &(*it);
          icUInt32Number tagOffset = e->TagInfo.offset;
          icUInt32Number tagSize = e->TagInfo.size;
          if (tagSize < 8) continue; // Too small for type+reserved

          icUInt8Number typeBuf[4] = {0};
          if (fseek(fp, tagOffset, SEEK_SET) == 0 &&
              fread(typeBuf, 1, 4, fp) == 4) {
            bool allPrintable = true;
            bool allZero = true;
            for (int b = 0; b < 4; b++) {
              if (typeBuf[b] != 0) allZero = false;
              if (typeBuf[b] < 0x20 || typeBuf[b] > 0x7E) allPrintable = false;
            }

            char sigFCC[5];
            SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), sigFCC);

            if (allZero) {
              printf("      %s[WARN]  Tag '%s' has null type signature (0x00000000)%s\n",
                     ColorWarning(), sigFCC, ColorReset());
              printf("       %sRisk: Corrupted tag data — parser may misinterpret%s\n",
                     ColorWarning(), ColorReset());
              invalidTypeCount++;
            } else if (!allPrintable) {
              printf("      %s[WARN]  Tag '%s' has non-ASCII type: 0x%02X%02X%02X%02X%s\n",
                     ColorWarning(), sigFCC,
                     typeBuf[0], typeBuf[1], typeBuf[2], typeBuf[3], ColorReset());
              printf("       %sRisk: Malformed type bytes — possible type confusion%s\n",
                     ColorWarning(), ColorReset());
              invalidTypeCount++;
            }
          }
        }
        fclose(fp);
      }
      if (invalidTypeCount > 0) {
        heuristicCount += invalidTypeCount;
      } else {
        printf("      %s[OK] All tag type signatures are valid ASCII%s\n", ColorSuccess(), ColorReset());
      }
    }
    printf("\n");

    // 21. tagStruct Member Inspection
    printf("[H21] tagStruct Member Inspection\n");
    {
      int structIssues = 0;
      bool foundStruct = false;
      TagEntryList::iterator it;
      for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
        IccTagEntry *e = &(*it);
        CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
        if (!pTag) continue;

        CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct*>(pTag);
        if (!pStruct) continue;
        foundStruct = true;

        char sigFCC[5];
        SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), sigFCC);
        icStructSignature structType = pStruct->GetTagStructType();
        char structFCC[5];
        SignatureToFourCC(static_cast<icUInt32Number>(structType), structFCC);

        TagEntryList *pElems = pStruct->GetElemList();
        int memberCount = 0;
        if (pElems) {
          memberCount = (int)pElems->size();
        }

        printf("      Tag '%s' is tagStruct (type='%s', %d members)\n",
               sigFCC, structFCC, memberCount);

        if (memberCount > 100) {
          printf("      %s[WARN]  Excessive member count: %d (limit 100)%s\n",
                 ColorCritical(), memberCount, ColorReset());
          printf("       %sRisk: Resource exhaustion via struct expansion%s\n",
                 ColorCritical(), ColorReset());
          structIssues++;
        }

        if (pElems) {
          TagEntryList::iterator eit;
          for (eit = pElems->begin(); eit != pElems->end(); eit++) {
            IccTagEntry *me = &(*eit);
            char mFCC[5];
            SignatureToFourCC(static_cast<icUInt32Number>(me->TagInfo.sig), mFCC);

            CIccTag *mTag = pStruct->FindElem(me->TagInfo.sig);
            if (mTag) {
              icTagTypeSignature mType = mTag->GetType();
              char mtFCC[5];
              SignatureToFourCC(static_cast<icUInt32Number>(mType), mtFCC);
              printf("        Member '%s': type='%s' size=%u",
                     mFCC, mtFCC, me->TagInfo.size);

              if (mTag->IsNumArrayType()) {
                CIccTagNumArray *pNum = dynamic_cast<CIccTagNumArray*>(mTag);
                if (pNum) {
                  printf(" values=%u", pNum->GetNumValues());
                }
              }
              printf("\n");

              // Check member type signature for non-printable bytes
              icUInt32Number mTypeVal = static_cast<icUInt32Number>(mType);
              icUInt8Number tb[4];
              tb[0] = (mTypeVal >> 24) & 0xFF;
              tb[1] = (mTypeVal >> 16) & 0xFF;
              tb[2] = (mTypeVal >> 8) & 0xFF;
              tb[3] = mTypeVal & 0xFF;
              bool mAllPrint = true;
              bool mAllZero = (mTypeVal == 0);
              for (int b = 0; b < 4; b++) {
                if (tb[b] < 0x20 || tb[b] > 0x7E) mAllPrint = false;
              }
              if (mAllZero) {
                printf("        %s[WARN]  Member '%s' has null type (0x00000000)%s\n",
                       ColorWarning(), mFCC, ColorReset());
                structIssues++;
              } else if (!mAllPrint) {
                printf("        %s[WARN]  Member '%s' has non-ASCII type: 0x%08X%s\n",
                       ColorWarning(), mFCC, mTypeVal, ColorReset());
                structIssues++;
              }
            } else {
              printf("        Member '%s': size=%u %s[UNREADABLE]%s\n",
                     mFCC, me->TagInfo.size, ColorWarning(), ColorReset());
              structIssues++;
            }
          }
        }
      }
      if (!foundStruct) {
        printf("      %s[OK] No tagStruct tags present%s\n", ColorSuccess(), ColorReset());
      } else if (structIssues > 0) {
        heuristicCount += structIssues;
      } else {
        printf("      %s[OK] tagStruct members appear well-formed%s\n", ColorSuccess(), ColorReset());
      }
    }
    printf("\n");

    // 22. NumArray Scalar Expectation Validation (cept-specific)
    printf("[H22] NumArray Scalar Expectation (cept struct)\n");
    {
      int scalarIssues = 0;
      CIccTag *pCeptTag = pIcc->FindTag(icSigColorEncodingParamsTag);
      CIccTagStruct *pCept = pCeptTag ? dynamic_cast<CIccTagStruct*>(pCeptTag) : nullptr;

      if (!pCept) {
        printf("      %s[OK] No cept (ColorEncodingParams) tag — check not applicable%s\n",
               ColorSuccess(), ColorReset());
      } else {
        // Members consumed as scalars by GetElemNumberValue() in IccEncoding.cpp
        struct ScalarMember {
          icSignature sig;
          const char *name;
        };
        const ScalarMember scalarMembers[] = {
          { icSigCeptWhitePointLuminanceMbr,           "wlum (WhitePointLuminance)" },
          { icSigCeptAmbientWhitePointLuminanceMbr,    "awlm (AmbientWPLuminance)" },
          { icSigCeptViewingSurroundMbr,               "srnd (ViewingSurround)" },
          { icSigCeptMediumWhitePointLuminanceMbr,     "mwpl (MediumWPLuminance)" },
        };

        for (size_t s = 0; s < sizeof(scalarMembers)/sizeof(scalarMembers[0]); s++) {
          CIccTag *mTag = pCept->FindElem(scalarMembers[s].sig);
          if (!mTag) continue;
          if (!mTag->IsNumArrayType()) continue;

          CIccTagNumArray *pNum = dynamic_cast<CIccTagNumArray*>(mTag);
          if (!pNum) continue;

          icUInt32Number numVals = pNum->GetNumValues();
          if (numVals > 1) {
            printf("      %s[HIGH]  %s has %u values (expected 1 scalar)%s\n",
                   ColorCritical(), scalarMembers[s].name, numVals, ColorReset());
            printf("       %sRisk: Stack buffer overflow in GetElemNumberValue → GetValues%s\n",
                   ColorCritical(), ColorReset());
            printf("       %s(SCARINESS: 51 — 4-byte-write-stack-buffer-overflow, CFL patch 027)%s\n",
                   ColorCritical(), ColorReset());
            scalarIssues++;
          } else {
            printf("      [OK] %s: %u value (scalar)\n", scalarMembers[s].name, numVals);
          }
        }
      }
      if (scalarIssues > 0) {
        heuristicCount += scalarIssues;
      }
    }
    printf("\n");

    // 23. NumArray Value Range Validation
    printf("[H23] NumArray Value Range Validation\n");
    {
      int rangeIssues = 0;
      TagEntryList::iterator it;
      for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
        IccTagEntry *e = &(*it);
        CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
        if (!pTag || !pTag->IsNumArrayType()) continue;

        CIccTagNumArray *pNum = dynamic_cast<CIccTagNumArray*>(pTag);
        if (!pNum) continue;

        icUInt32Number numVals = pNum->GetNumValues();
        if (numVals == 0 || numVals > 1048576) {
          char sigFCC[5];
          SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), sigFCC);
          if (numVals == 0) {
            printf("      %s[WARN]  Tag '%s': empty NumArray (0 values)%s\n",
                   ColorWarning(), sigFCC, ColorReset());
          } else {
            printf("      %s[WARN]  Tag '%s': excessive NumArray (%u values)%s\n",
                   ColorCritical(), sigFCC, numVals, ColorReset());
          }
          rangeIssues++;
          continue;
        }

        // Allocate full numVals buffer — unpatched GetValues loops over m_nSize
        icUInt32Number sampleSize = (numVals < 64) ? numVals : 64;
        icFloatNumber *vals = new(std::nothrow) icFloatNumber[numVals];
        if (!vals) continue;

        if (pNum->GetValues(vals, 0, numVals)) {
          int nanCount = 0, infCount = 0;
          for (icUInt32Number v = 0; v < sampleSize; v++) {
            if (std::isnan(vals[v])) nanCount++;
            if (std::isinf(vals[v])) infCount++;
          }
          if (nanCount > 0 || infCount > 0) {
            char sigFCC[5];
            SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), sigFCC);
            if (nanCount > 0) {
              printf("      %s[WARN]  Tag '%s': %d NaN value(s) in NumArray%s\n",
                     ColorCritical(), sigFCC, nanCount, ColorReset());
            }
            if (infCount > 0) {
              printf("      %s[WARN]  Tag '%s': %d Inf value(s) in NumArray%s\n",
                     ColorCritical(), sigFCC, infCount, ColorReset());
            }
            printf("       %sRisk: Floating-point exceptions, division-by-zero%s\n",
                   ColorWarning(), ColorReset());
            rangeIssues++;
          }
        }
        delete[] vals;
      }

      // Also check NumArrays inside tagStruct members
      for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
        IccTagEntry *e = &(*it);
        CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
        if (!pTag) continue;
        CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct*>(pTag);
        if (!pStruct) continue;

        TagEntryList *pElems = pStruct->GetElemList();
        if (!pElems) continue;

        char parentFCC[5];
        SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), parentFCC);

        TagEntryList::iterator eit;
        for (eit = pElems->begin(); eit != pElems->end(); eit++) {
          IccTagEntry *me = &(*eit);
          CIccTag *mTag = pStruct->FindElem(me->TagInfo.sig);
          if (!mTag || !mTag->IsNumArrayType()) continue;

          CIccTagNumArray *pNum = dynamic_cast<CIccTagNumArray*>(mTag);
          if (!pNum) continue;

          icUInt32Number numVals = pNum->GetNumValues();
          if (numVals == 0 || numVals > 1048576) continue; // Already flagged or skip

          icUInt32Number sampleSize = (numVals < 64) ? numVals : 64;
          icFloatNumber *vals = new(std::nothrow) icFloatNumber[numVals];
          if (!vals) continue;

          if (pNum->GetValues(vals, 0, numVals)) {
            int nanCount = 0, infCount = 0;
            for (icUInt32Number v = 0; v < sampleSize; v++) {
              if (std::isnan(vals[v])) nanCount++;
              if (std::isinf(vals[v])) infCount++;
            }
            if (nanCount > 0 || infCount > 0) {
              char mFCC[5];
              SignatureToFourCC(static_cast<icUInt32Number>(me->TagInfo.sig), mFCC);
              printf("      %s[WARN]  Struct '%s' member '%s': ", ColorCritical(), parentFCC, mFCC);
              if (nanCount > 0) printf("%d NaN ", nanCount);
              if (infCount > 0) printf("%d Inf ", infCount);
              printf("value(s)%s\n", ColorReset());
              rangeIssues++;
            }
          }
          delete[] vals;
        }
      }

      if (rangeIssues > 0) {
        heuristicCount += rangeIssues;
      } else {
        printf("      %s[OK] All NumArray values within normal ranges%s\n", ColorSuccess(), ColorReset());
      }
    }
    printf("\n");

    // 24. tagStruct/tagArray Nesting Depth Check
    printf("[H24] tagStruct/tagArray Nesting Depth\n");
    {
      int nestIssues = 0;
      const int MAX_SAFE_DEPTH = 4;

      // Lambda-like depth walk using iterative approach with stack
      struct DepthEntry { CIccTag *tag; int depth; };
      std::vector<DepthEntry> stack;

      TagEntryList::iterator it;
      for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
        IccTagEntry *e = &(*it);
        CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
        if (!pTag) continue;
        stack.push_back({pTag, 0});
      }

      int maxDepth = 0;
      while (!stack.empty()) {
        DepthEntry cur = stack.back();
        stack.pop_back();

        if (cur.depth > maxDepth) maxDepth = cur.depth;

        if (cur.depth > MAX_SAFE_DEPTH) {
          printf("      %s[WARN]  Nesting depth %d exceeds safe limit (%d)%s\n",
                 ColorCritical(), cur.depth, MAX_SAFE_DEPTH, ColorReset());
          printf("       %sRisk: Stack overflow via recursive Read/Describe (CFL patch 061)%s\n",
                 ColorCritical(), ColorReset());
          nestIssues++;
          continue; // Don't descend further
        }

        CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct*>(cur.tag);
        if (pStruct) {
          TagEntryList *pElems = pStruct->GetElemList();
          if (pElems) {
            TagEntryList::iterator eit;
            for (eit = pElems->begin(); eit != pElems->end(); eit++) {
              CIccTag *mTag = pStruct->FindElem((*eit).TagInfo.sig);
              if (mTag) {
                stack.push_back({mTag, cur.depth + 1});
              }
            }
          }
        }

        CIccTagArray *pArr = dynamic_cast<CIccTagArray*>(cur.tag);
        if (pArr) {
          icUInt32Number arrSize = pArr->GetSize();
          // Limit iteration to prevent runaway
          icUInt32Number checkLimit = (arrSize < 64) ? arrSize : 64;
          for (icUInt32Number idx = 0; idx < checkLimit; idx++) {
            CIccTag *aTag = pArr->GetIndex(idx);
            if (aTag) {
              stack.push_back({aTag, cur.depth + 1});
            }
          }
        }
      }

      if (nestIssues > 0) {
        heuristicCount += nestIssues;
      } else {
        printf("      %s[OK] Max nesting depth: %d (safe limit: %d)%s\n",
               ColorSuccess(), maxDepth, MAX_SAFE_DEPTH, ColorReset());
      }
    }
    printf("\n");

    // 25. Tag Offset/Size OOB Detection (raw file bytes)
    printf("[H25] Tag Offset/Size Out-of-Bounds Detection\n");
    {
      FILE *fp25 = fopen(filename, "rb");
      if (fp25) {
        fseek(fp25, 0, SEEK_END);
        size_t realSize = ftell(fp25);
        fseek(fp25, 0, SEEK_SET);
        
        int oobCount = 0;
        if (realSize >= 132) {
          icUInt8Number hdr25[132];
          if (fread(hdr25, 1, 132, fp25) == 132) {
            icUInt32Number hdrProfileSize = (static_cast<icUInt32Number>(hdr25[0])<<24) | (static_cast<icUInt32Number>(hdr25[1])<<16) |
                                            (static_cast<icUInt32Number>(hdr25[2])<<8) | hdr25[3];
            icUInt32Number tc = (static_cast<icUInt32Number>(hdr25[128])<<24) | (static_cast<icUInt32Number>(hdr25[129])<<16) |
                                (static_cast<icUInt32Number>(hdr25[130])<<8) | hdr25[131];
            size_t bound = (realSize < hdrProfileSize) ? realSize : hdrProfileSize;
            
            for (icUInt32Number i = 0; i < tc && i < 256; i++) {
              size_t ePos = 132 + i * 12;
              if (ePos + 12 > realSize) break;
              
              icUInt8Number e25[12];
              fseek(fp25, ePos, SEEK_SET);
              if (fread(e25, 1, 12, fp25) != 12) break;
              
              icUInt32Number tSig = (static_cast<icUInt32Number>(e25[0])<<24) | (static_cast<icUInt32Number>(e25[1])<<16) |
                                    (static_cast<icUInt32Number>(e25[2])<<8) | e25[3];
              icUInt32Number tOff = (static_cast<icUInt32Number>(e25[4])<<24) | (static_cast<icUInt32Number>(e25[5])<<16) |
                                    (static_cast<icUInt32Number>(e25[6])<<8) | e25[7];
              icUInt32Number tSz  = (static_cast<icUInt32Number>(e25[8])<<24) | (static_cast<icUInt32Number>(e25[9])<<16) |
                                    (static_cast<icUInt32Number>(e25[10])<<8) | e25[11];
              
              uint64_t tagEnd = (uint64_t)tOff + tSz;
              char sig25[5];
              sig25[0] = (tSig>>24)&0xff; sig25[1] = (tSig>>16)&0xff;
              sig25[2] = (tSig>>8)&0xff;  sig25[3] = tSig&0xff; sig25[4] = '\0';
              
              if (tOff >= bound) {
                printf("      %s[WARN]  Tag '%s' offset 0x%X beyond file/profile bounds (%zu bytes)%s\n",
                       ColorCritical(), sig25, tOff, bound, ColorReset());
                oobCount++;
              } else if (tagEnd > bound) {
                printf("      %s[WARN]  Tag '%s' [offset=0x%X, size=%u] extends %llu bytes past bounds (%zu)%s\n",
                       ColorCritical(), sig25, tOff, tSz,
                       (unsigned long long)(tagEnd - bound), bound, ColorReset());
                oobCount++;
              }
            }
          }
        }
        fclose(fp25);
        
        if (oobCount > 0) {
          printf("      %s%d tag(s) reference data beyond file/profile bounds%s\n",
                 ColorCritical(), oobCount, ColorReset());
          printf("      %sRisk: Heap-buffer-overflow when loading OOB tags%s\n",
                 ColorCritical(), ColorReset());
          heuristicCount++;
        } else {
          printf("      %s[OK] All tag offsets/sizes within bounds%s\n", ColorSuccess(), ColorReset());
        }
      }
    }
    printf("\n");

    // 26. NamedColor2 String Validation (raw scan — checks tag TYPE, not signature)
    printf("[H26] NamedColor2 String Validation\n");
    {
      FILE *fp26 = fopen(filename, "rb");
      if (fp26) {
          fseek(fp26, 0, SEEK_END);
          size_t fs26 = ftell(fp26);
          fseek(fp26, 0, SEEK_SET);
          
          int nc2Issues = 0;
          if (fs26 >= 132) {
            icUInt8Number hdr26[132];
            if (fread(hdr26, 1, 132, fp26) == 132) {
              icUInt32Number tc26 = (static_cast<icUInt32Number>(hdr26[128])<<24) | (static_cast<icUInt32Number>(hdr26[129])<<16) |
                                    (static_cast<icUInt32Number>(hdr26[130])<<8) | hdr26[131];
              
              for (icUInt32Number i = 0; i < tc26 && i < 256; i++) {
                size_t ePos = 132 + i * 12;
                if (ePos + 12 > fs26) break;
                
                icUInt8Number e26[12];
                fseek(fp26, ePos, SEEK_SET);
                if (fread(e26, 1, 12, fp26) != 12) break;
                
                icUInt32Number tOff26 = (static_cast<icUInt32Number>(e26[4])<<24) | (static_cast<icUInt32Number>(e26[5])<<16) |
                                        (static_cast<icUInt32Number>(e26[6])<<8) | e26[7];
                icUInt32Number tSz26  = (static_cast<icUInt32Number>(e26[8])<<24) | (static_cast<icUInt32Number>(e26[9])<<16) |
                                        (static_cast<icUInt32Number>(e26[10])<<8) | e26[11];
                
                // Read first 4 bytes of tag data to check type
                if (tOff26 + 4 > fs26 || tSz26 < 84) continue;
                icUInt8Number typeCheck[4];
                fseek(fp26, tOff26, SEEK_SET);
                if (fread(typeCheck, 1, 4, fp26) != 4) continue;
                icUInt32Number tagType26 = (static_cast<icUInt32Number>(typeCheck[0])<<24) | (static_cast<icUInt32Number>(typeCheck[1])<<16) |
                                           (static_cast<icUInt32Number>(typeCheck[2])<<8) | typeCheck[3];
                if (tagType26 != 0x6E636C32) continue;  // Not 'ncl2' type
                if (tOff26 + 84 > fs26) continue;
                
                // NamedColor2: type(4)+reserved(4)+vendorFlags(4)+count(4)+nDevCoords(4)+prefix(32)+suffix(32)
                icUInt8Number prefix[32], suffix[32];
                fseek(fp26, tOff26 + 20, SEEK_SET);
                if (fread(prefix, 1, 32, fp26) != 32) continue;
                if (fread(suffix, 1, 32, fp26) != 32) continue;
                
                // Count XML-expandable chars: ' " & < > expand to 4-6 chars in icFixXml
                auto countXmlExpand = [](const icUInt8Number *buf, int len) -> int {
                  int ct = 0;
                  for (int j = 0; j < len && buf[j] != 0; j++) {
                    if (buf[j] == '\'' || buf[j] == '"' || buf[j] == '&' ||
                        buf[j] == '<'  || buf[j] == '>')
                      ct++;
                  }
                  return ct;
                };
                
                int prefixLen = 0, suffixLen = 0;
                for (int j = 0; j < 32 && prefix[j]; j++) prefixLen++;
                for (int j = 0; j < 32 && suffix[j]; j++) suffixLen++;
                
                int prefixExpand = countXmlExpand(prefix, 32);
                int suffixExpand = countXmlExpand(suffix, 32);
                
                // icFixXml destination is char[256]. Expandable chars grow up to 6x (&apos; etc.)
                int prefixExpanded = prefixLen + prefixExpand * 5;
                int suffixExpanded = suffixLen + suffixExpand * 5;
                
                if (prefixExpanded > 255) {
                  printf("      %s[HIGH] Prefix (%d bytes, %d XML-expandable) overflows icFixXml buffer (expanded: %d > 255)%s\n",
                         ColorCritical(), prefixLen, prefixExpand, prefixExpanded, ColorReset());
                  printf("       %sRisk: Stack-buffer-overflow in icFixXml() (SCARINESS:55 class)%s\n",
                         ColorCritical(), ColorReset());
                  nc2Issues++;
                } else if (prefixExpand > 0 && prefixLen > 20) {
                  printf("      %s[WARN]  Prefix has %d XML-expandable chars in %d-byte string (expanded: %d)%s\n",
                         ColorWarning(), prefixExpand, prefixLen, prefixExpanded, ColorReset());
                  nc2Issues++;
                }
                
                if (suffixExpanded > 255) {
                  printf("      %s[HIGH] Suffix (%d bytes, %d XML-expandable) overflows icFixXml buffer (expanded: %d > 255)%s\n",
                         ColorCritical(), suffixLen, suffixExpand, suffixExpanded, ColorReset());
                  printf("       %sRisk: Stack-buffer-overflow in icFixXml() (SCARINESS:55 class)%s\n",
                         ColorCritical(), ColorReset());
                  nc2Issues++;
                } else if (suffixExpand > 0 && suffixLen > 20) {
                  printf("      %s[WARN]  Suffix has %d XML-expandable chars in %d-byte string (expanded: %d)%s\n",
                         ColorWarning(), suffixExpand, suffixLen, suffixExpanded, ColorReset());
                  nc2Issues++;
                }
                
                // Check for non-null-terminated strings
                bool prefixUnterminated = true, suffixUnterminated = true;
                for (int j = 0; j < 32; j++) { if (prefix[j] == 0) { prefixUnterminated = false; break; } }
                for (int j = 0; j < 32; j++) { if (suffix[j] == 0) { suffixUnterminated = false; break; } }
                
                if (prefixUnterminated) {
                  printf("      %s[WARN]  Prefix not null-terminated (all 32 bytes non-zero)%s\n",
                         ColorCritical(), ColorReset());
                  printf("       %sRisk: strlen overflow, icFixXml reads past buffer boundary%s\n",
                         ColorCritical(), ColorReset());
                  nc2Issues++;
                }
                if (suffixUnterminated) {
                  printf("      %s[WARN]  Suffix not null-terminated (all 32 bytes non-zero)%s\n",
                         ColorCritical(), ColorReset());
                  printf("       %sRisk: strlen overflow, icFixXml reads past buffer boundary%s\n",
                         ColorCritical(), ColorReset());
                  nc2Issues++;
                }
              }
            }
          }
          fclose(fp26);
          
          if (nc2Issues > 0) {
            heuristicCount += nc2Issues;
          } else {
            printf("      %s[OK] No NamedColor2 tags with risky strings%s\n", ColorSuccess(), ColorReset());
          }
        }
      }
    printf("\n");

    // 27. MPE Matrix Output Channel Validation
    printf("[H27] MPE Matrix Output Channel Validation\n");
    {
      int matrixIssues = 0;
      icUInt32Number mpeSigs[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
        icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
        icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag
      };
      for (auto sig : mpeSigs) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;
        CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
        if (!pMpe) continue;
        
        icUInt32Number numElements = pMpe->NumElements();
        
        int elemIdx = 0;
        for (icUInt32Number ei = 0; ei < numElements && elemIdx < 64; ei++, elemIdx++) {
          CIccMultiProcessElement *pElem = pMpe->GetElement(ei);
          if (!pElem) continue;
          
          // Check for matrix elements with 0 output channels
          CIccMpeMatrix *pMatrix = dynamic_cast<CIccMpeMatrix*>(pElem);
          if (pMatrix) {
            icUInt16Number numOut = pMatrix->NumOutputChannels();
            icUInt16Number numIn = pMatrix->NumInputChannels();
            
            char sigStr27[5];
            SignatureToFourCC(sig, sigStr27);
            
            if (numOut == 0 || numIn == 0) {
              printf("      %s[WARN]  Tag '%s' elem %d: Matrix %ux%u — zero dimension%s\n",
                     ColorCritical(), sigStr27, elemIdx, numIn, numOut, ColorReset());
              printf("       %sRisk: Division by zero or null-pointer in matrix operations%s\n",
                     ColorCritical(), ColorReset());
              matrixIssues++;
            } else if (numOut < 3) {
              printf("      %s[WARN]  Tag '%s' elem %d: Matrix has %u output channels (XYZ needs 3)%s\n",
                     ColorWarning(), sigStr27, elemIdx, numOut, ColorReset());
              printf("       %sRisk: HBO in pushXYZConvert accessing pOffset[0..2] on %u-channel matrix%s\n",
                     ColorCritical(), numOut, ColorReset());
              matrixIssues++;
            }
          }
          
          // Check calculator elements for sub-element count
          CIccMpeCalculator *pCalc = dynamic_cast<CIccMpeCalculator*>(pElem);
          if (pCalc) {
            icUInt16Number calcOut = pCalc->NumOutputChannels();
            icUInt16Number calcIn = pCalc->NumInputChannels();
            
            char sigStr27c[5];
            SignatureToFourCC(sig, sigStr27c);
            
            if (calcOut == 0 || calcIn == 0) {
              printf("      %s[WARN]  Tag '%s' elem %d: Calculator %ux%u — zero dimension%s\n",
                     ColorCritical(), sigStr27c, elemIdx, calcIn, calcOut, ColorReset());
              matrixIssues++;
            }
          }
        }
      }
      
      if (matrixIssues > 0) {
        heuristicCount += matrixIssues;
      } else {
        printf("      %s[OK] All MPE matrix/calculator dimensions valid%s\n", ColorSuccess(), ColorReset());
      }
    }
    printf("\n");

    delete pIcc;
  }
  
  // Summary
  printf("=======================================================================\n");
  printf("%sHEURISTIC SUMMARY%s\n", ColorHeader(), ColorReset());
  printf("=======================================================================\n\n");
  
  if (heuristicCount == 0) {
    printf("%s[OK] NO HEURISTIC WARNINGS DETECTED%s\n", ColorSuccess(), ColorReset());
    printf("  Profile appears well-formed with no obvious security concerns.\n");
  } else {
    printf("%s[WARN]  %d HEURISTIC WARNING(S) DETECTED%s\n\n", ColorCritical(), heuristicCount, ColorReset());
    printf("  This profile exhibits patterns associated with:\n");
    printf("  %s- Malformed/corrupted data%s\n", ColorWarning(), ColorReset());
    printf("  %s- Resource exhaustion attempts%s\n", ColorWarning(), ColorReset());
    printf("  %s- Enum confusion vulnerabilities%s\n", ColorWarning(), ColorReset());
    printf("  %s- Parser exploitation attempts%s\n", ColorWarning(), ColorReset());
    printf("\n");
    printf("  %sRecommendations:%s\n", ColorInfo(), ColorReset());
    printf("  • Validate profile with official ICC tools\n");
    printf("  • Use -n (ninja mode) for detailed byte-level analysis\n");
    printf("  • Do NOT use in production color workflows\n");
    printf("  • Consider as potential security test case\n");
  }
  
  printf("\n");
  return heuristicCount;
}

// ============================================================================
// Phase 14: Security Validation Implementation
// ============================================================================

#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <cstring>
#include <algorithm>

namespace IccAnalyzerSecurity {

// Maximum allowed path length (security limit)
constexpr size_t MAX_PATH_LENGTH = 4096;

// Maximum allowed binary database size (100 MB uncompressed)
constexpr size_t MAX_BINARY_DB_UNCOMPRESSED_SIZE = 100ULL * 1024 * 1024;

// Maximum allowed Bloom filter size (1 MB)
constexpr size_t MAX_BLOOM_FILTER_SIZE = 1024 * 1024;

bool IsSymlink(const std::string& path) {
  struct stat path_stat;
  if (lstat(path.c_str(), &path_stat) != 0) {
    return false; // Path doesn't exist or error
  }
  return S_ISLNK(path_stat.st_mode);
}

bool ContainsPathTraversal(const std::string& path) {
  // Check for ../ or /..\\ patterns
  if (path.find("../") != std::string::npos ||
      path.find("..\\") != std::string::npos ||
      path.find("/..") != std::string::npos ||
      path.find("\\..") != std::string::npos) {
    return true;
  }
  
  // Check for path starting with ../
  if (path.rfind("../", 0) == 0 || path.rfind("..\\", 0) == 0) {
    return true;
  }
  
  return false;
}

bool SanitizePath(const std::string& path, std::string& sanitized) {
  char resolved[PATH_MAX];
  if (realpath(path.c_str(), resolved) == nullptr) {
    return false; // Path doesn't exist or can't be resolved
  }
  sanitized = std::string(resolved);
  return true;
}

bool IsWithinBoundary(const std::string& path, const std::string& base_dir) {
  std::string sanitized_path, sanitized_base;
  
  if (!SanitizePath(path, sanitized_path)) {
    return false; // Can't resolve path
  }
  
  if (!SanitizePath(base_dir, sanitized_base)) {
    return false; // Can't resolve base directory
  }
  
  // Check if path starts with base_dir
  return sanitized_path.rfind(sanitized_base, 0) == 0;
}

PathValidationResult ValidateFilePath(
  const std::string& path,
  PathValidationMode mode,
  bool require_exists,
  const std::vector<std::string>& allowed_extensions
) {
  // Check for empty path
  if (path.empty()) {
    return PathValidationResult::INVALID_EMPTY;
  }
  
  // Check for null bytes (security risk)
  if (path.find('\0') != std::string::npos) {
    return PathValidationResult::INVALID_NULL_BYTE;
  }
  
  // Check path length
  if (path.length() > MAX_PATH_LENGTH) {
    return PathValidationResult::INVALID_TOO_LONG;
  }
  
  // In strict mode, check for special characters
  if (mode == PathValidationMode::STRICT) {
    for (char c : path) {
      if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
        return PathValidationResult::INVALID_SPECIAL_CHAR; // Control characters
      }
    }
  }
  
  // Check for path traversal
  if (mode == PathValidationMode::STRICT && ContainsPathTraversal(path)) {
    return PathValidationResult::INVALID_TRAVERSAL;
  }
  
  // Check if file exists (if required)
  struct stat path_stat;
  bool exists = (stat(path.c_str(), &path_stat) == 0);
  
  if (require_exists && !exists) {
    return PathValidationResult::INVALID_NONEXISTENT;
  }
  
  if (exists) {
    // Check if it's a symlink (security risk)
    if (mode == PathValidationMode::STRICT && IsSymlink(path)) {
      return PathValidationResult::INVALID_SYMLINK;
    }
    
    // Check if it's a regular file
    if (!S_ISREG(path_stat.st_mode)) {
      return PathValidationResult::INVALID_NOT_REGULAR_FILE;
    }
  }
  
  // Check file extension whitelist
  if (!allowed_extensions.empty()) {
    bool found = false;
    for (const auto& ext : allowed_extensions) {
      if (path.length() >= ext.length() &&
          path.compare(path.length() - ext.length(), ext.length(), ext) == 0) {
        found = true;
        break;
      }
    }
    if (!found) {
      return PathValidationResult::INVALID_EXTENSION;
    }
  }
  
  return PathValidationResult::VALID;
}

PathValidationResult ValidateDirectoryPath(
  const std::string& path,
  PathValidationMode mode,
  bool require_exists
) {
  // Check for empty path
  if (path.empty()) {
    return PathValidationResult::INVALID_EMPTY;
  }
  
  // Check for null bytes
  if (path.find('\0') != std::string::npos) {
    return PathValidationResult::INVALID_NULL_BYTE;
  }
  
  // Check path length
  if (path.length() > MAX_PATH_LENGTH) {
    return PathValidationResult::INVALID_TOO_LONG;
  }
  
  // Check for path traversal
  if (mode == PathValidationMode::STRICT && ContainsPathTraversal(path)) {
    return PathValidationResult::INVALID_TRAVERSAL;
  }
  
  // Check if directory exists (if required)
  struct stat path_stat;
  bool exists = (stat(path.c_str(), &path_stat) == 0);
  
  if (require_exists && !exists) {
    return PathValidationResult::INVALID_NONEXISTENT;
  }
  
  if (exists) {
    // Check if it's a symlink
    if (mode == PathValidationMode::STRICT && IsSymlink(path)) {
      return PathValidationResult::INVALID_SYMLINK;
    }
    
    // Check if it's a directory
    if (!S_ISDIR(path_stat.st_mode)) {
      return PathValidationResult::INVALID_NOT_DIRECTORY;
    }
  }
  
  return PathValidationResult::VALID;
}

std::string GetValidationErrorMessage(PathValidationResult result, const std::string& path) {
  switch (result) {
    case PathValidationResult::VALID:
      return "Path is valid";
    case PathValidationResult::INVALID_EMPTY:
      return "Path is empty";
    case PathValidationResult::INVALID_TOO_LONG:
      return "Path exceeds maximum length (" + std::to_string(MAX_PATH_LENGTH) + " characters)";
    case PathValidationResult::INVALID_TRAVERSAL:
      return "Path contains traversal sequence (../) - SECURITY RISK DETECTED";
    case PathValidationResult::INVALID_ABSOLUTE:
      return "Absolute paths not allowed in this context";
    case PathValidationResult::INVALID_SYMLINK:
      return "Symlink detected: " + path + " - SECURITY RISK (use real path)";
    case PathValidationResult::INVALID_EXTENSION:
      return "File extension not allowed: " + path;
    case PathValidationResult::INVALID_SPECIAL_CHAR:
      return "Path contains special/control characters - SECURITY RISK";
    case PathValidationResult::INVALID_NULL_BYTE:
      return "Path contains null bytes - SECURITY RISK DETECTED";
    case PathValidationResult::INVALID_NONEXISTENT:
      return "Path does not exist: " + path;
    case PathValidationResult::INVALID_NOT_REGULAR_FILE:
      return "Not a regular file (may be device, socket, or directory): " + path;
    case PathValidationResult::INVALID_NOT_DIRECTORY:
      return "Not a directory: " + path;
    default:
      return "Unknown validation error";
  }
}

bool ValidateBinaryDatabaseFormat(
  const uint8_t* data,
  size_t size,
  std::string& error_message
) {
  // Minimum size check (header = 8 bytes magic + 4 version + 4 flags)
  if (size < 16) {
    error_message = "Binary database too small (minimum 16 bytes)";
    return false;
  }
  
  // Validate magic header (exact match "ICCDB001")
  const char expected_magic[9] = "ICCDB001";
  if (memcmp(data, expected_magic, 8) != 0) {
    error_message = "Invalid magic header (expected 'ICCDB001')";
    return false;
  }
  
  // Read version (bytes 8-11, little-endian) — use memcpy for alignment safety
  uint32_t version;
  memcpy(&version, data + 8, sizeof(version));
  
  // Validate version range (0x00000001 - 0x00000003)
  if (version < 0x00000001 || version > 0x00000003) {
    error_message = "Unknown database version: 0x" + 
                    std::to_string(version) + 
                    " (expected 0x01-0x03)";
    return false;
  }
  
  // Read flags (bytes 12-15, little-endian) — parsed for future validation
  uint32_t flags;
  memcpy(&flags, data + 12, sizeof(flags));
  (void)flags;
  
  // If version >= 2, check uncompressed size
  if (version >= 2) {
    if (size < 20) {
      error_message = "Binary database V2/V3 too small (minimum 20 bytes)";
      return false;
    }
    
    uint32_t uncompressed_size;
    memcpy(&uncompressed_size, data + 16, sizeof(uncompressed_size));
    
    // Validate uncompressed size (prevent OOM attacks)
    if (uncompressed_size > MAX_BINARY_DB_UNCOMPRESSED_SIZE) {
      error_message = "Uncompressed size exceeds limit (" + 
                      std::to_string(uncompressed_size) + 
                      " > " + 
                      std::to_string(MAX_BINARY_DB_UNCOMPRESSED_SIZE) + 
                      ") - POSSIBLE OOM ATTACK";
      return false;
    }
  }
  
  // If version >= 3, check Bloom filter size
  if (version >= 3) {
    if (size < 24) {
      error_message = "Binary database V3 too small (minimum 24 bytes)";
      return false;
    }
    
    uint32_t bloom_size;
    memcpy(&bloom_size, data + 20, sizeof(bloom_size));
    
    // Validate Bloom filter size (prevent absurd allocations)
    if (bloom_size > MAX_BLOOM_FILTER_SIZE) {
      error_message = "Bloom filter size exceeds limit (" + 
                      std::to_string(bloom_size) + 
                      " > " + 
                      std::to_string(MAX_BLOOM_FILTER_SIZE) + 
                      ") - POSSIBLE OOM ATTACK";
      return false;
    }
    
    // Check that total size is sufficient for header + Bloom filter
    size_t min_required_size = 24 + bloom_size;
    if (size < min_required_size) {
      error_message = "Binary database truncated (expected " + 
                      std::to_string(min_required_size) + 
                      " bytes, got " + 
                      std::to_string(size) + 
                      ")";
      return false;
    }
  }
  
  // All checks passed
  return true;
}

} // namespace IccAnalyzerSecurity

// ── Output sanitization (CodeQL icc/injection-attacks) ──────────────

std::string SanitizeForLog(const std::string& input) {
  std::string out;
  out.reserve(input.size());
  for (unsigned char c : input) {
    if (c == '\n' || c == '\r' || c == '\0' || c == '\x1b') continue;
    if (c < 0x20 && c != '\t') continue;
    out.push_back(static_cast<char>(c));
  }
  return out;
}

std::string SanitizeForLog(const char* input) {
  if (!input) return "(null)";
  return SanitizeForLog(std::string(input));
}

std::string SanitizeForDOT(const std::string& input) {
  std::string out;
  out.reserve(input.size());
  for (char c : input) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '<':  out += "\\<";  break;
      case '>':  out += "\\>";  break;
      case '\n': out += "\\n";  break;
      case '\r': break;
      case '\0': break;
      default:   out.push_back(c); break;
    }
  }
  return out;
}
