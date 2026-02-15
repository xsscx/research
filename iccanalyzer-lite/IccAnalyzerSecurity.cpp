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
      printf("🚨 CRITICAL ALERT: EXACT MATCH TO KNOWN MALICIOUS PROFILE\n\n");
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
        printf("  ℹ️  LOW SEVERITY ISSUE\n\n");
        printf("  ℹ️  This profile contains known issues but is unlikely exploitable.\n");
        printf("  ℹ️  Review recommended before deployment.\n\n");
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
        printf("  ℹ️  SIMILAR TO KNOWN ISSUE\n\n");
        printf("  ℹ️  This profile may be a variant of a known issue.\n");
        printf("  ℹ️  Recommended action: Manual review suggested.\n\n");
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
  // Size inflation: header claims much larger than actual file
  if (actualFileSize > 0 && profileSize > 0 &&
      profileSize > actualFileSize * 16 && profileSize > (128u << 20)) {
    printf("     %s[WARN]  HEURISTIC: Header claims %u bytes but file is %zu bytes (%.0fx inflation)%s\n",
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
    
    // 11. CLUT Size Limit Check (Resource Exhaustion)
    printf("[H11] CLUT Entry Limit Check\n");
    printf("      Max safe CLUT entries per tag: %llu (16M)\n",
           (unsigned long long)ICCANALYZER_MAX_CLUT_ENTRIES);
    
    // Theoretical maximum based on tag count
    uint64_t max_clut_theoretical;
    if (!SafeMul64(&max_clut_theoretical, tagCount, ICCANALYZER_MAX_CLUT_ENTRIES)) {
      printf("      %s[WARN]  HEURISTIC: Overflow calculating total CLUT capacity%s\n", ColorCritical(), ColorReset());
      printf("       %sRisk: Tag count × CLUT limit exceeds 64-bit integer%s\n", ColorWarning(), ColorReset());
      heuristicCount++;
    } else if (tagCount > 10) {
      printf("      %sINFO: Profile has %d tags%s\n", ColorInfo(), tagCount, ColorReset());
      printf("      Theoretical max CLUT: %llu entries (%llu per tag)\n",
             (unsigned long long)max_clut_theoretical,
             (unsigned long long)ICCANALYZER_MAX_CLUT_ENTRIES);
    } else {
      printf("      %s[OK] Low tag count reduces CLUT exhaustion risk%s\n", ColorSuccess(), ColorReset());
    }
    printf("\n");
    
    // 12. MPE Element Chain Depth Limit
    printf("[H12] MPE Chain Depth Limit\n");
    printf("      Max MPE elements per chain: %u\n", ICCANALYZER_MAX_MPE_ELEMENTS);
    printf("      Note: Full MPE analysis requires tag-level parsing\n");
    printf("      %s[OK] Limit defined (%u elements max)%s\n", ColorSuccess(), ICCANALYZER_MAX_MPE_ELEMENTS, ColorReset());
    printf("\n");
    
    // 13. Per-Tag Size Limit Check
    printf("[H13] Per-Tag Size Limit\n");
    printf("      Max tag size: %llu MB (%llu bytes)\n",
           (unsigned long long)(ICCANALYZER_MAX_TAG_SIZE >> 20),
           (unsigned long long)ICCANALYZER_MAX_TAG_SIZE);
    
    // Calculate theoretical maximum profile size
    uint64_t max_profile_theoretical;
    if (!SafeMul64(&max_profile_theoretical, tagCount, ICCANALYZER_MAX_TAG_SIZE)) {
      printf("      %s[WARN]  HEURISTIC: Overflow calculating max profile size%s\n", ColorCritical(), ColorReset());
      printf("       %sRisk: Tag count × tag size exceeds addressable memory%s\n", ColorWarning(), ColorReset());
      heuristicCount++;
    } else if (max_profile_theoretical > ICCANALYZER_MAX_PROFILE_SIZE) {
      printf("      %s[WARN]  WARNING: Theoretical max (%llu bytes) > profile limit (%llu)%s\n",
             ColorWarning(),
             (unsigned long long)max_profile_theoretical,
             (unsigned long long)ICCANALYZER_MAX_PROFILE_SIZE,
             ColorReset());
      printf("       Tag count: %d, Max per tag: %llu bytes\n",
             tagCount, (unsigned long long)ICCANALYZER_MAX_TAG_SIZE);
      heuristicCount++;
    } else {
      printf("      [OK] Theoretical max within limits: %llu bytes\n",
             (unsigned long long)max_profile_theoretical);
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
            printf("      %s🚨 HEURISTIC: %u TagArrayType tag(s) detected%s\n", ColorCritical(), tagArrayCount, ColorReset());
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
          icTechnologySignature techSig = (icTechnologySignature)pSigTag->GetValue();
          if (IsValidTechnologySignature(techSig)) {
            CIccInfo techInfo;
            printf("      %s[OK] Valid technology: %s%s\n", ColorSuccess(),
                   techInfo.GetTechnologySigName(techSig), ColorReset());
          } else {
            printf("      %s[WARN]  HEURISTIC: Unknown technology signature: 0x%08X%s\n",
                   ColorWarning(), (unsigned)techSig, ColorReset());
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
        ranges.push_back({(icUInt32Number)e->TagInfo.sig, e->TagInfo.offset, e->TagInfo.size});
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
  
  // Read version (bytes 8-11, little-endian)
  uint32_t version = *reinterpret_cast<const uint32_t*>(data + 8);
  
  // Validate version range (0x00000001 - 0x00000003)
  if (version < 0x00000001 || version > 0x00000003) {
    error_message = "Unknown database version: 0x" + 
                    std::to_string(version) + 
                    " (expected 0x01-0x03)";
    return false;
  }
  
  // Read flags (bytes 12-15, little-endian) — parsed for future validation
  uint32_t flags = *reinterpret_cast<const uint32_t*>(data + 12);
  (void)flags;
  
  // If version >= 2, check uncompressed size
  if (version >= 2) {
    if (size < 20) {
      error_message = "Binary database V2/V3 too small (minimum 20 bytes)";
      return false;
    }
    
    uint32_t uncompressed_size = *reinterpret_cast<const uint32_t*>(data + 16);
    
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
    
    uint32_t bloom_size = *reinterpret_cast<const uint32_t*>(data + 20);
    
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
