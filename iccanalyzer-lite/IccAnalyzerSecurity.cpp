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
  
  // Read raw tag count from offset 128 (4 bytes big-endian) for early gating
  bool skipLibraryPhase = false;
  icUInt32Number rawTagCount = 0;
  {
    icUInt8Number tcBytes[4] = {};
    io.Seek(128, icSeekSet);
    if (io.Read8(tcBytes, 4) == 4) {
      rawTagCount = (static_cast<icUInt32Number>(tcBytes[0])<<24) |
                    (static_cast<icUInt32Number>(tcBytes[1])<<16) |
                    (static_cast<icUInt32Number>(tcBytes[2])<<8) | tcBytes[3];
    }
    if (rawTagCount > 1000) {
      skipLibraryPhase = true;
      printf("=======================================================================\n");
      printf("[PREFLIGHT] Tag count = %u (>1000) — profile is severely malformed\n", rawTagCount);
      printf("            Library-API heuristics will be skipped to avoid crash/hang\n");
      printf("=======================================================================\n\n");
    }
  }
  
  static constexpr int kCriticalHeuristicThreshold = 5;

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
  
  // Gate: skip library-API phase if profile is too malformed.
  // Raw-file heuristics (H1-H8, H15-H17, H25-H32) are safe (they read bytes directly).
  // Library-API heuristics (H9-H14, H18-H24) call into unpatched iccDEV which can
  // infinite-recurse, stack-overflow, or OOM on severely malformed profiles.
  if (skipLibraryPhase || heuristicCount >= kCriticalHeuristicThreshold) {
    printf("=======================================================================\n");
    printf("[SKIP] Profile too malformed for library analysis (%d warnings, %u tags)\n",
           heuristicCount, rawTagCount);
    printf("       Library-API heuristics skipped to avoid crash/hang\n");
    printf("       Use -n (ninja mode) for byte-level raw analysis\n");
    printf("=======================================================================\n\n");
  } else {
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
    // CVE refs: CVE-2026-21490, CVE-2026-21494 (LUT8/LUT16 OOM via extreme CLUT dimensions)
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
    // CVE refs: CVE-2026-21677 (UAF in CIccTagArray::Cleanup)
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
      FILE *fp20 = fopen(filename, "rb");
      if (fp20) {
        TagEntryList::iterator it;
        for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
          IccTagEntry *e = &(*it);
          icUInt32Number tagOffset = e->TagInfo.offset;
          icUInt32Number tagSize = e->TagInfo.size;
          if (tagSize < 8) continue; // Too small for type+reserved

          icUInt8Number typeBuf[4] = {0};
          if (fseek(fp20, tagOffset, SEEK_SET) == 0 &&
              fread(typeBuf, 1, 4, fp20) == 4) {
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
        fclose(fp20);
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
    // CVE refs: CVE-2026-25583 (HBO in CIccFileIO::Read8), CVE-2026-24852 (tag offset overflow)
    printf("[H25] Tag Offset/Size Out-of-Bounds Detection\n");
    {
      FILE *fp25 = fopen(filename, "rb");
      if (fp25) {
        fseek(fp25, 0, SEEK_END);
        long realSize_l = ftell(fp25);
        if (realSize_l < 0) { fclose(fp25); fp25 = NULL; }
        size_t realSize = (fp25) ? (size_t)realSize_l : 0;
        if (fp25) fseek(fp25, 0, SEEK_SET);
        
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
        if (fp25) fclose(fp25);
        
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
    // CVE refs: CVE-2026-21488 (non-null-terminated strings), CVE-2026-24852 (text overflow)
    printf("[H26] NamedColor2 String Validation\n");
    {
      FILE *fp26 = fopen(filename, "rb");
      if (fp26) {
          fseek(fp26, 0, SEEK_END);
          long fs26_l = ftell(fp26);
          if (fs26_l < 0) { fclose(fp26); fp26 = NULL; }
          size_t fs26 = (fp26) ? (size_t)fs26_l : 0;
          if (fp26) fseek(fp26, 0, SEEK_SET);
          
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
          if (fp26) fclose(fp26);
          
          if (nc2Issues > 0) {
            heuristicCount += nc2Issues;
          } else {
            printf("      %s[OK] No NamedColor2 tags with risky strings%s\n", ColorSuccess(), ColorReset());
          }
        }
      }
    printf("\n");

    // 27. MPE Matrix Output Channel Validation
    // CVE refs: CVE-2026-25634 (memcpy-param-overlap), CVE-2026-22047 (CalcOp element bounds)
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

    // 28. LUT Dimension Validation (raw file bytes)
    // CVE refs: CVE-2026-21490, CVE-2026-21494, GHSA-x9hr-pxxc-h38p (OOM via extreme nInput^nGrid)
    // LUT8 type='mft1', LUT16 type='mft2': nInput/nOutput/nGrid parsed from raw bytes
    printf("[H28] LUT Dimension Validation (OOM Risk)\n");
    {
      FILE *fp28 = fopen(filename, "rb");
      if (fp28) {
        fseek(fp28, 0, SEEK_END);
        long fs28_l = ftell(fp28);
        if (fs28_l < 0) { fclose(fp28); fp28 = NULL; }
        size_t fs28 = (fp28) ? (size_t)fs28_l : 0;
        if (fp28) fseek(fp28, 0, SEEK_SET);

        int lutIssues = 0;
        if (fs28 >= 132) {
          icUInt8Number hdr28[132];
          if (fread(hdr28, 1, 132, fp28) == 132) {
            icUInt32Number tc28 = (static_cast<icUInt32Number>(hdr28[128])<<24) | (static_cast<icUInt32Number>(hdr28[129])<<16) |
                                  (static_cast<icUInt32Number>(hdr28[130])<<8) | hdr28[131];

            for (icUInt32Number i = 0; i < tc28 && i < 256; i++) {
              size_t ePos = 132 + i * 12;
              if (ePos + 12 > fs28) break;

              icUInt8Number e28[12];
              fseek(fp28, ePos, SEEK_SET);
              if (fread(e28, 1, 12, fp28) != 12) break;

              icUInt32Number tOff28 = (static_cast<icUInt32Number>(e28[4])<<24) | (static_cast<icUInt32Number>(e28[5])<<16) |
                                      (static_cast<icUInt32Number>(e28[6])<<8) | e28[7];
              icUInt32Number tSz28  = (static_cast<icUInt32Number>(e28[8])<<24) | (static_cast<icUInt32Number>(e28[9])<<16) |
                                      (static_cast<icUInt32Number>(e28[10])<<8) | e28[11];

              // Need at least type(4) + reserved(4) + nInput(1) + nOutput(1) + nGrid(1) = 11 bytes
              if (tOff28 + 11 > fs28 || tSz28 < 11) continue;
              icUInt8Number lutHdr[11];
              fseek(fp28, tOff28, SEEK_SET);
              if (fread(lutHdr, 1, 11, fp28) != 11) continue;

              icUInt32Number lutType = (static_cast<icUInt32Number>(lutHdr[0])<<24) | (static_cast<icUInt32Number>(lutHdr[1])<<16) |
                                       (static_cast<icUInt32Number>(lutHdr[2])<<8) | lutHdr[3];

              // Check for LUT8 (0x6D667431='mft1') or LUT16 (0x6D667432='mft2')
              if (lutType != 0x6D667431 && lutType != 0x6D667432) continue;

              icUInt8Number nInput28  = lutHdr[8];
              icUInt8Number nOutput28 = lutHdr[9];
              icUInt8Number nGrid28   = lutHdr[10];

              char sig28[5];
              sig28[0] = (e28[0]); sig28[1] = (e28[1]);
              sig28[2] = (e28[2]); sig28[3] = (e28[3]); sig28[4] = '\0';

              // Spec max: nInput ≤ 16, nOutput ≤ 16
              if (nInput28 > 16 || nOutput28 > 16) {
                printf("      %s[WARN]  Tag '%s' (%s): nInput=%u nOutput=%u exceeds spec max (16)%s\n",
                       ColorCritical(), sig28, (lutType == 0x6D667431) ? "LUT8" : "LUT16",
                       nInput28, nOutput28, ColorReset());
                printf("       %sRisk: Buffer overflow in grid point arrays (max 16 channels)%s\n",
                       ColorCritical(), ColorReset());
                lutIssues++;
                continue;
              }

              // Compute CLUT point count: nGrid^nInput * nOutput
              uint64_t points = 1;
              bool overflow28 = false;
              for (int ch = 0; ch < nInput28; ch++) {
                uint64_t prev = points;
                points *= nGrid28;
                if (nGrid28 > 0 && points / nGrid28 != prev) { overflow28 = true; break; }
              }
              if (!overflow28) {
                uint64_t prev = points;
                points *= nOutput28;
                if (nOutput28 > 0 && points / nOutput28 != prev) overflow28 = true;
              }

              // 16M entries × 4 bytes = 64MB — generous limit
              const uint64_t MAX_LUT_POINTS = 16ULL * 1024 * 1024;
              if (overflow28 || points > MAX_LUT_POINTS) {
                printf("      %s[WARN]  Tag '%s' (%s): nInput=%u nOutput=%u nGrid=%u → %s CLUT points%s\n",
                       ColorCritical(), sig28, (lutType == 0x6D667431) ? "LUT8" : "LUT16",
                       nInput28, nOutput28, nGrid28,
                       overflow28 ? "OVERFLOW" : std::to_string(points).c_str(),
                       ColorReset());
                printf("       %sRisk: OOM — allocation of %s bytes in CIccCLUT::Init()%s\n",
                       ColorCritical(),
                       overflow28 ? ">2^64" : std::to_string(points * 4).c_str(),
                       ColorReset());
                lutIssues++;
              } else if (nInput28 > 0 && nGrid28 > 0) {
                printf("      [OK] Tag '%s' (%s): %ux%ux%u → %llu points\n",
                       sig28, (lutType == 0x6D667431) ? "LUT8" : "LUT16",
                       nInput28, nOutput28, nGrid28, (unsigned long long)points);
              }
            }
          }
        }
        if (fp28) fclose(fp28);

        if (lutIssues > 0) {
          heuristicCount += lutIssues;
        } else {
          printf("      %s[OK] All LUT dimensions within safe limits%s\n", ColorSuccess(), ColorReset());
        }
      }
    }
    printf("\n");

    // 29. ColorantTable String Validation (raw file bytes)
    // CVE refs: GHSA-4wqv-pvm8-5h27 (OOB read via unterminated colorant name[32])
    // CVE-2026-27692 (HBO in TextDescription from unterminated strings)
    printf("[H29] ColorantTable String Validation\n");
    {
      FILE *fp29 = fopen(filename, "rb");
      if (fp29) {
        fseek(fp29, 0, SEEK_END);
        long fs29_l = ftell(fp29);
        if (fs29_l < 0) { fclose(fp29); fp29 = NULL; }
        size_t fs29 = (fp29) ? (size_t)fs29_l : 0;
        if (fp29) fseek(fp29, 0, SEEK_SET);

        int clrtIssues = 0;
        if (fs29 >= 132) {
          icUInt8Number hdr29[132];
          if (fread(hdr29, 1, 132, fp29) == 132) {
            icUInt32Number tc29 = (static_cast<icUInt32Number>(hdr29[128])<<24) | (static_cast<icUInt32Number>(hdr29[129])<<16) |
                                  (static_cast<icUInt32Number>(hdr29[130])<<8) | hdr29[131];

            for (icUInt32Number i = 0; i < tc29 && i < 256; i++) {
              size_t ePos = 132 + i * 12;
              if (ePos + 12 > fs29) break;

              icUInt8Number e29[12];
              fseek(fp29, ePos, SEEK_SET);
              if (fread(e29, 1, 12, fp29) != 12) break;

              icUInt32Number tOff29 = (static_cast<icUInt32Number>(e29[4])<<24) | (static_cast<icUInt32Number>(e29[5])<<16) |
                                      (static_cast<icUInt32Number>(e29[6])<<8) | e29[7];
              icUInt32Number tSz29  = (static_cast<icUInt32Number>(e29[8])<<24) | (static_cast<icUInt32Number>(e29[9])<<16) |
                                      (static_cast<icUInt32Number>(e29[10])<<8) | e29[11];

              // Read type signature
              if (tOff29 + 12 > fs29 || tSz29 < 12) continue;
              icUInt8Number typeCheck29[12];
              fseek(fp29, tOff29, SEEK_SET);
              if (fread(typeCheck29, 1, 12, fp29) != 12) continue;

              icUInt32Number tagType29 = (static_cast<icUInt32Number>(typeCheck29[0])<<24) | (static_cast<icUInt32Number>(typeCheck29[1])<<16) |
                                          (static_cast<icUInt32Number>(typeCheck29[2])<<8) | typeCheck29[3];

              // 'clrt' = 0x636C7274
              if (tagType29 != 0x636C7274) continue;

              // ColorantTable layout: type(4)+reserved(4)+count(4) then count × entry(38)
              // Each entry: name[32] + data[6]
              icUInt32Number colorantCount = (static_cast<icUInt32Number>(typeCheck29[8])<<24) | (static_cast<icUInt32Number>(typeCheck29[9])<<16) |
                                              (static_cast<icUInt32Number>(typeCheck29[10])<<8) | typeCheck29[11];

              if (colorantCount > 256) {
                printf("      %s[WARN]  ColorantTable: count=%u (>256) — excessive allocation risk%s\n",
                       ColorCritical(), colorantCount, ColorReset());
                clrtIssues++;
                continue;
              }

              // Check each colorant name for null termination
              for (icUInt32Number ci = 0; ci < colorantCount && ci < 256; ci++) {
                size_t namePos = tOff29 + 12 + ci * 38;
                if (namePos + 32 > fs29) break;

                icUInt8Number name29[32];
                fseek(fp29, namePos, SEEK_SET);
                if (fread(name29, 1, 32, fp29) != 32) break;

                bool hasNull = false;
                for (int j = 0; j < 32; j++) {
                  if (name29[j] == 0) { hasNull = true; break; }
                }
                if (!hasNull) {
                  printf("      %s[WARN]  Colorant[%u] name not null-terminated (all 32 bytes non-zero)%s\n",
                         ColorCritical(), ci, ColorReset());
                  printf("       %sRisk: strlen overflow in ToXml → heap-buffer-overflow read%s\n",
                         ColorCritical(), ColorReset());
                  clrtIssues++;
                }
              }
            }
          }
        }
        if (fp29) fclose(fp29);

        if (clrtIssues > 0) {
          heuristicCount += clrtIssues;
        } else {
          printf("      %s[OK] No ColorantTable string issues detected%s\n", ColorSuccess(), ColorReset());
        }
      }
    }
    printf("\n");

    // 30. GamutBoundaryDesc Allocation Validation (raw file bytes)
    // CVE refs: GHSA-rc3h-95ph-j363 (OOM via unvalidated triangle count in 'gbd ' tags)
    printf("[H30] GamutBoundaryDesc Allocation Validation\n");
    {
      FILE *fp30 = fopen(filename, "rb");
      if (fp30) {
        fseek(fp30, 0, SEEK_END);
        long fs30_l = ftell(fp30);
        if (fs30_l < 0) { fclose(fp30); fp30 = NULL; }
        size_t fs30 = (fp30) ? (size_t)fs30_l : 0;
        if (fp30) fseek(fp30, 0, SEEK_SET);

        int gbdIssues = 0;
        if (fs30 >= 132) {
          icUInt8Number hdr30[132];
          if (fread(hdr30, 1, 132, fp30) == 132) {
            icUInt32Number tc30 = (static_cast<icUInt32Number>(hdr30[128])<<24) | (static_cast<icUInt32Number>(hdr30[129])<<16) |
                                  (static_cast<icUInt32Number>(hdr30[130])<<8) | hdr30[131];

            for (icUInt32Number i = 0; i < tc30 && i < 256; i++) {
              size_t ePos = 132 + i * 12;
              if (ePos + 12 > fs30) break;

              icUInt8Number e30[12];
              fseek(fp30, ePos, SEEK_SET);
              if (fread(e30, 1, 12, fp30) != 12) break;

              icUInt32Number tOff30 = (static_cast<icUInt32Number>(e30[4])<<24) | (static_cast<icUInt32Number>(e30[5])<<16) |
                                      (static_cast<icUInt32Number>(e30[6])<<8) | e30[7];
              icUInt32Number tSz30  = (static_cast<icUInt32Number>(e30[8])<<24) | (static_cast<icUInt32Number>(e30[9])<<16) |
                                      (static_cast<icUInt32Number>(e30[10])<<8) | e30[11];

              // 'gbd ' type header: type(4)+reserved(4)+reserved(4)+nVertices(4)+nTriangles(4)+nPCSCh(2)+nDevCh(2) = 24 bytes
              if (tOff30 + 24 > fs30 || tSz30 < 24) continue;
              icUInt8Number gbdHdr[24];
              fseek(fp30, tOff30, SEEK_SET);
              if (fread(gbdHdr, 1, 24, fp30) != 24) continue;

              icUInt32Number gbdType = (static_cast<icUInt32Number>(gbdHdr[0])<<24) | (static_cast<icUInt32Number>(gbdHdr[1])<<16) |
                                       (static_cast<icUInt32Number>(gbdHdr[2])<<8) | gbdHdr[3];

              // 'gbd ' = 0x67626420
              if (gbdType != 0x67626420) continue;

              icUInt32Number nVerts = (static_cast<icUInt32Number>(gbdHdr[12])<<24) | (static_cast<icUInt32Number>(gbdHdr[13])<<16) |
                                      (static_cast<icUInt32Number>(gbdHdr[14])<<8) | gbdHdr[15];
              icUInt32Number nTris  = (static_cast<icUInt32Number>(gbdHdr[16])<<24) | (static_cast<icUInt32Number>(gbdHdr[17])<<16) |
                                      (static_cast<icUInt32Number>(gbdHdr[18])<<8) | gbdHdr[19];
              icUInt16Number nPCSCh = (static_cast<icUInt16Number>(gbdHdr[20])<<8) | gbdHdr[21];
              icUInt16Number nDevCh = (static_cast<icUInt16Number>(gbdHdr[22])<<8) | gbdHdr[23];

              // Triangle allocation: nTriangles × 12 bytes
              uint64_t triAlloc = (uint64_t)nTris * 12;
              // Vertex arrays: nVertices × (3*4 + nPCSCh*4 + nDevCh*4)
              uint64_t vertAlloc = (uint64_t)nVerts * (12 + (uint64_t)nPCSCh * 4 + (uint64_t)nDevCh * 4);
              uint64_t totalAlloc = triAlloc + vertAlloc + 24;

              char sig30[5];
              sig30[0] = e30[0]; sig30[1] = e30[1]; sig30[2] = e30[2]; sig30[3] = e30[3]; sig30[4] = '\0';

              // Check: allocation exceeds tag size (OOM risk)
              if (totalAlloc > (uint64_t)tSz30 * 4) {
                printf("      %s[WARN]  Tag '%s' (gbd): %u vertices, %u triangles, PCS=%u Dev=%u%s\n",
                       ColorCritical(), sig30, nVerts, nTris, nPCSCh, nDevCh, ColorReset());
                printf("       %sAllocation: %llu bytes vs tag size %u bytes%s\n",
                       ColorCritical(), (unsigned long long)totalAlloc, tSz30, ColorReset());
                printf("       %sRisk: OOM in CIccTagGamutBoundaryDesc::Read()%s\n",
                       ColorCritical(), ColorReset());
                gbdIssues++;
              }

              // Check: negative channel counts (icUInt16Number interpreted as signed)
              if (nPCSCh > 3 || nDevCh > 15) {
                printf("      %s[WARN]  Tag '%s' (gbd): PCS channels=%u, Device channels=%u — out of range%s\n",
                       ColorWarning(), sig30, nPCSCh, nDevCh, ColorReset());
                printf("       %sRisk: Signed/unsigned confusion in allocation size%s\n",
                       ColorCritical(), ColorReset());
                gbdIssues++;
              }
            }
          }
        }
        if (fp30) fclose(fp30);

        if (gbdIssues > 0) {
          heuristicCount += gbdIssues;
        } else {
          printf("      %s[OK] No GamutBoundaryDesc allocation issues%s\n", ColorSuccess(), ColorReset());
        }
      }
    }
    printf("\n");

    // 31. MPE Channel Count Validation
    // CVE refs: CVE-2026-25634 (memcpy-param-overlap from large m_nInputChannels)
    // CVE-2026-25584 (SBO in CIccTagFloatNum::GetValues)
    // CVE-2026-25585 (OOB in CIccXform3DLut::Apply)
    printf("[H31] MPE Channel Count Validation\n");
    {
      int channelIssues = 0;
      icUInt32Number mpeSigs31[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
        icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
        icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag
      };
      for (auto sig31 : mpeSigs31) {
        CIccTag *pTag31 = pIcc->FindTag(sig31);
        if (!pTag31) continue;
        CIccTagMultiProcessElement *pMpe31 = dynamic_cast<CIccTagMultiProcessElement*>(pTag31);
        if (!pMpe31) continue;

        icUInt16Number mpeIn  = pMpe31->NumInputChannels();
        icUInt16Number mpeOut = pMpe31->NumOutputChannels();

        char sigStr31[5];
        SignatureToFourCC(sig31, sigStr31);

        // MPE with extreme channel counts → memcpy overlap on stack buffers
        if (mpeIn > 32 || mpeOut > 32) {
          printf("      %s[WARN]  Tag '%s': MPE channels in=%u out=%u (>32)%s\n",
                 ColorCritical(), sigStr31, mpeIn, mpeOut, ColorReset());
          printf("       %sRisk: memcpy-param-overlap in Apply(), stack buffer overflow%s\n",
                 ColorCritical(), ColorReset());
          channelIssues++;
        }

        // Check individual elements for channel mismatches
        icUInt32Number nElems31 = pMpe31->NumElements();
        for (icUInt32Number ei = 0; ei < nElems31 && ei < 64; ei++) {
          CIccMultiProcessElement *pElem31 = pMpe31->GetElement(ei);
          if (!pElem31) continue;

          icUInt16Number elemIn  = pElem31->NumInputChannels();
          icUInt16Number elemOut = pElem31->NumOutputChannels();

          if (elemIn > 64 || elemOut > 64) {
            printf("      %s[WARN]  Tag '%s' elem %u: channels in=%u out=%u (extreme)%s\n",
                   ColorCritical(), sigStr31, ei, elemIn, elemOut, ColorReset());
            printf("       %sRisk: Stack buffer overflow in element Apply()%s\n",
                   ColorCritical(), ColorReset());
            channelIssues++;
          }
        }
      }

      if (channelIssues > 0) {
        heuristicCount += channelIssues;
      } else {
        printf("      %s[OK] All MPE channel counts within safe limits%s\n", ColorSuccess(), ColorReset());
      }
    }
    printf("\n");

    // 32. Tag Data Type Confusion Detection (raw file bytes)
    // CVE refs: GHSA-2pjj-3c98-qp37 (type confusion in ToXmlCurve)
    // GHSA-xqq3-g894-w2h5 (HBO in IccTagXml from type confusion)
    // Checks that tag type signatures are valid printable ICC 4CC codes
    printf("[H32] Tag Data Type Confusion Detection\n");
    {
      FILE *fp32 = fopen(filename, "rb");
      if (fp32) {
        fseek(fp32, 0, SEEK_END);
        long fs32_l = ftell(fp32);
        if (fs32_l < 0) { fclose(fp32); fp32 = NULL; }
        size_t fs32 = (fp32) ? (size_t)fs32_l : 0;
        if (fp32) fseek(fp32, 0, SEEK_SET);

        int typeConfusionCount = 0;
        if (fs32 >= 132) {
          icUInt8Number hdr32[132];
          if (fread(hdr32, 1, 132, fp32) == 132) {
            icUInt32Number tc32 = (static_cast<icUInt32Number>(hdr32[128])<<24) | (static_cast<icUInt32Number>(hdr32[129])<<16) |
                                  (static_cast<icUInt32Number>(hdr32[130])<<8) | hdr32[131];

            // Known valid ICC tag type signatures
            static const icUInt32Number knownTypes[] = {
              0x63757276, // 'curv' - curveType
              0x70617261, // 'para' - parametricCurveType
              0x6D667431, // 'mft1' - lut8Type
              0x6D667432, // 'mft2' - lut16Type
              0x6D414220, // 'mAB ' - lutAtoBType
              0x6D424120, // 'mBA ' - lutBtoAType
              0x6D706574, // 'mpet' - multiProcessElementsType
              0x58595A20, // 'XYZ ' - XYZType
              0x74657874, // 'text' - textType
              0x64657363, // 'desc' - textDescriptionType
              0x6D6C7563, // 'mluc' - multiLocalizedUnicodeType
              0x73663332, // 'sf32' - s15Fixed16ArrayType
              0x75663332, // 'uf32' - u16Fixed16ArrayType
              0x73696720, // 'sig ' - signatureType
              0x64617461, // 'data' - dataType
              0x6474696D, // 'dtim' - dateTimeType
              0x76696577, // 'view' - viewingConditionsType
              0x6D656173, // 'meas' - measurementType
              0x6E636C32, // 'ncl2' - namedColor2Type
              0x636C7274, // 'clrt' - colorantTableType
              0x636C726F, // 'clro' - colorantOrderType
              0x63727064, // 'crpd' - crdInfoType
              0x75693038, // 'ui08' - uInt8ArrayType
              0x75693136, // 'ui16' - uInt16ArrayType
              0x75693332, // 'ui32' - uInt32ArrayType
              0x75693634, // 'ui64' - uInt64ArrayType
              0x666C3136, // 'fl16' - float16ArrayType
              0x666C3332, // 'fl32' - float32ArrayType
              0x666C3634, // 'fl64' - float64ArrayType
              0x67626420, // 'gbd ' - gamutBoundaryDescType
              0x63696370, // 'cicp' - cicpType
              0x73706563, // 'spec' - spectralDataInfoType
              0x736D6174, // 'smat' - sparseMatrixArrayType
              0x74617279, // 'tary' - tagArrayType
              0x74737472, // 'tstr' - tagStructType
              0x7A757466, // 'zutf' - zipUtf8Type
              0x7A786D6C, // 'zxml' - zipXmlType
              0x75746638, // 'utf8' - utf8Type
              0x64696374, // 'dict' - dictType
              0x656D6274, // 'embt' - embeddedHeightImageType / embeddedNormalImageType
              0x636F6C52, // 'colR' - colorEncodingParamsStructType
              0x636F6C53, // 'colS' - colorSpaceTypeTagType
              0x7376636E, // 'svcn' - spectralViewingConditionsType
              0x7364696E, // 'sdin' - spectralDataInfoType
              0x736D7769, // 'smwi' - spectralMediaWhiteType
            };
            const int numKnownTypes = sizeof(knownTypes) / sizeof(knownTypes[0]);

            for (icUInt32Number i = 0; i < tc32 && i < 256; i++) {
              size_t ePos = 132 + i * 12;
              if (ePos + 12 > fs32) break;

              icUInt8Number e32[12];
              fseek(fp32, ePos, SEEK_SET);
              if (fread(e32, 1, 12, fp32) != 12) break;

              icUInt32Number tSig32 = (static_cast<icUInt32Number>(e32[0])<<24) | (static_cast<icUInt32Number>(e32[1])<<16) |
                                      (static_cast<icUInt32Number>(e32[2])<<8) | e32[3];
              icUInt32Number tOff32 = (static_cast<icUInt32Number>(e32[4])<<24) | (static_cast<icUInt32Number>(e32[5])<<16) |
                                      (static_cast<icUInt32Number>(e32[6])<<8) | e32[7];
              icUInt32Number tSz32  = (static_cast<icUInt32Number>(e32[8])<<24) | (static_cast<icUInt32Number>(e32[9])<<16) |
                                      (static_cast<icUInt32Number>(e32[10])<<8) | e32[11];

              if (tOff32 + 4 > fs32 || tSz32 < 4) continue;
              icUInt8Number typeData32[4];
              fseek(fp32, tOff32, SEEK_SET);
              if (fread(typeData32, 1, 4, fp32) != 4) continue;

              icUInt32Number dataType32 = (static_cast<icUInt32Number>(typeData32[0])<<24) | (static_cast<icUInt32Number>(typeData32[1])<<16) |
                                           (static_cast<icUInt32Number>(typeData32[2])<<8) | typeData32[3];

              // Already caught by H20 (non-printable type bytes)
              // Here we check if the type is a known ICC type signature
              bool isKnown = false;
              for (int k = 0; k < numKnownTypes; k++) {
                if (dataType32 == knownTypes[k]) { isKnown = true; break; }
              }

              if (!isKnown) {
                // Check if all 4 bytes are printable ASCII (might be a valid extension type)
                bool allPrintable = true;
                for (int b = 0; b < 4; b++) {
                  if (typeData32[b] < 0x20 || typeData32[b] > 0x7E) { allPrintable = false; break; }
                }

                if (!allPrintable) {
                  // Already caught by H20, skip to avoid duplicate
                  continue;
                }

                char sigStr32[5], typeStr32[5];
                sigStr32[0] = (tSig32>>24)&0xff; sigStr32[1] = (tSig32>>16)&0xff;
                sigStr32[2] = (tSig32>>8)&0xff; sigStr32[3] = tSig32&0xff; sigStr32[4] = '\0';
                typeStr32[0] = (dataType32>>24)&0xff; typeStr32[1] = (dataType32>>16)&0xff;
                typeStr32[2] = (dataType32>>8)&0xff; typeStr32[3] = dataType32&0xff; typeStr32[4] = '\0';

                printf("      %s[WARN]  Tag '%s': unknown type signature '%s' (0x%08X)%s\n",
                       ColorWarning(), sigStr32, typeStr32, dataType32, ColorReset());
                printf("       %sRisk: Type confusion → wrong parser invoked → memory corruption%s\n",
                       ColorCritical(), ColorReset());
                typeConfusionCount++;
              }
            }
          }
        }
        if (fp32) fclose(fp32);

        if (typeConfusionCount > 0) {
          heuristicCount += typeConfusionCount;
        } else {
          printf("      %s[OK] All tag type signatures are known ICC types%s\n", ColorSuccess(), ColorReset());
        }
      }
    }
    printf("\n");

    delete pIcc;
  }
  } // end of critical-threshold gate

  // =========================================================================
  // Raw-file heuristics H33-H36 (safe on all inputs — no library API calls)
  // Derived from ICC profile structural analysis and fuzzer coverage gaps:
  // OOB sub-element offsets, integer overflow via 32-bit truncation in bounds checks.
  // =========================================================================

  // 33. mBA/mAB Sub-Element Offset Validation (raw file bytes)
  // Detects OOB M/CLUT/A curve offsets within mBA/mAB tags that cause reads past
  // mmap boundary. Parsers following B→M→CLUT→A offsets without bounds checking
  // against tag size are vulnerable to SIGBUS/SIGSEGV.
  printf("[H33] mBA/mAB Sub-Element Offset Validation\n");
  {
    FILE *fp33 = fopen(filename, "rb");
    if (fp33) {
      fseek(fp33, 0, SEEK_END);
      long fs33_l = ftell(fp33);
      if (fs33_l < 0) { fclose(fp33); fp33 = NULL; }
      size_t fs33 = (fp33) ? (size_t)fs33_l : 0;
      if (fp33) fseek(fp33, 0, SEEK_SET);

      int mbaOobCount = 0;
      if (fs33 >= 132) {
        icUInt8Number hdr33[132];
        if (fread(hdr33, 1, 132, fp33) == 132) {
          icUInt32Number tc33 = (static_cast<icUInt32Number>(hdr33[128])<<24) | (static_cast<icUInt32Number>(hdr33[129])<<16) |
                                (static_cast<icUInt32Number>(hdr33[130])<<8) | hdr33[131];

          for (icUInt32Number i = 0; i < tc33 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs33) break;

            icUInt8Number e33[12];
            fseek(fp33, ePos, SEEK_SET);
            if (fread(e33, 1, 12, fp33) != 12) break;

            icUInt32Number tSig33 = (static_cast<icUInt32Number>(e33[0])<<24) | (static_cast<icUInt32Number>(e33[1])<<16) |
                                    (static_cast<icUInt32Number>(e33[2])<<8) | e33[3];
            icUInt32Number tOff33 = (static_cast<icUInt32Number>(e33[4])<<24) | (static_cast<icUInt32Number>(e33[5])<<16) |
                                    (static_cast<icUInt32Number>(e33[6])<<8) | e33[7];
            icUInt32Number tSz33  = (static_cast<icUInt32Number>(e33[8])<<24) | (static_cast<icUInt32Number>(e33[9])<<16) |
                                    (static_cast<icUInt32Number>(e33[10])<<8) | e33[11];

            // Read tag type signature at the tag data offset
            if (tOff33 + 32 > fs33 || tSz33 < 32) continue;
            icUInt8Number tagData33[32];
            fseek(fp33, tOff33, SEEK_SET);
            if (fread(tagData33, 1, 32, fp33) != 32) continue;

            icUInt32Number tagType33 = (static_cast<icUInt32Number>(tagData33[0])<<24) | (static_cast<icUInt32Number>(tagData33[1])<<16) |
                                       (static_cast<icUInt32Number>(tagData33[2])<<8) | tagData33[3];

            // Check for mAB (0x6D414220) or mBA (0x6D424120)
            if (tagType33 != 0x6D414220 && tagType33 != 0x6D424120) continue;

            char sig33[5];
            sig33[0] = (tSig33>>24)&0xff; sig33[1] = (tSig33>>16)&0xff;
            sig33[2] = (tSig33>>8)&0xff;  sig33[3] = tSig33&0xff; sig33[4] = '\0';
            const char *typeName33 = (tagType33 == 0x6D414220) ? "mAB" : "mBA";

            // mBA/mAB internal structure (offsets from tag start):
            // +0: type sig (4), +4: reserved (4), +8: nInput(1)+nOutput(1)+pad(2)
            // +12: B offset (4), +16: matrix offset (4), +20: M offset (4)
            // +24: CLUT offset (4), +28: A offset (4)
            struct { const char *name; size_t pos; } subElems[] = {
              {"B_curves", 12}, {"Matrix", 16}, {"M_curves", 20}, {"CLUT", 24}, {"A_curves", 28}
            };

            for (int se = 0; se < 5; se++) {
              size_t p = subElems[se].pos;
              icUInt32Number subOff = (static_cast<icUInt32Number>(tagData33[p])<<24) | (static_cast<icUInt32Number>(tagData33[p+1])<<16) |
                                      (static_cast<icUInt32Number>(tagData33[p+2])<<8) | tagData33[p+3];
              if (subOff == 0) continue; // not present

              if (subOff > tSz33) {
                printf("      %s[WARN]  Tag '%s' (%s): %s offset 0x%08X exceeds tag size %u%s\n",
                       ColorCritical(), sig33, typeName33, subElems[se].name, subOff, tSz33, ColorReset());
                if (subOff >= 0xFFFF0000) {
                  printf("       %sCRITICAL: Offset near uint32 max — OOB read/write past mmap boundary%s\n",
                         ColorCritical(), ColorReset());
                }
                mbaOobCount++;
              }
            }
          }
        }
      }
      if (fp33) fclose(fp33);

      if (mbaOobCount > 0) {
        printf("      %s%d mBA/mAB sub-element offset(s) reference data beyond tag bounds%s\n",
               ColorCritical(), mbaOobCount, ColorReset());
        printf("      %sRisk: OOB read past mmap boundary → SIGBUS/SIGSEGV on ICC parsers%s\n",
               ColorCritical(), ColorReset());
        heuristicCount += mbaOobCount;
      } else {
        printf("      %s[OK] All mBA/mAB sub-element offsets within tag bounds%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 34. 32-bit Integer Overflow in Sub-Element Offset Bounds Checks
  // Common ICC parser pattern: offset + element_size computed in 32-bit arithmetic.
  // When CLUT offset ≥ 0xFFFFFFEC, the add wraps: 0xFFFFFFFF + 0x14 = 0x13 (truncated)
  // which passes the bounds check, leading to OOB access.
  printf("[H34] 32-bit Integer Overflow in Sub-Element Bounds\n");
  {
    FILE *fp34 = fopen(filename, "rb");
    if (fp34) {
      fseek(fp34, 0, SEEK_END);
      long fs34_l = ftell(fp34);
      if (fs34_l < 0) { fclose(fp34); fp34 = NULL; }
      size_t fs34 = (fp34) ? (size_t)fs34_l : 0;
      if (fp34) fseek(fp34, 0, SEEK_SET);

      int overflowCount = 0;
      if (fs34 >= 132) {
        icUInt8Number hdr34[132];
        if (fread(hdr34, 1, 132, fp34) == 132) {
          icUInt32Number tc34 = (static_cast<icUInt32Number>(hdr34[128])<<24) | (static_cast<icUInt32Number>(hdr34[129])<<16) |
                                (static_cast<icUInt32Number>(hdr34[130])<<8) | hdr34[131];

          for (icUInt32Number i = 0; i < tc34 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs34) break;

            icUInt8Number e34[12];
            fseek(fp34, ePos, SEEK_SET);
            if (fread(e34, 1, 12, fp34) != 12) break;

            icUInt32Number tOff34 = (static_cast<icUInt32Number>(e34[4])<<24) | (static_cast<icUInt32Number>(e34[5])<<16) |
                                    (static_cast<icUInt32Number>(e34[6])<<8) | e34[7];
            icUInt32Number tSz34  = (static_cast<icUInt32Number>(e34[8])<<24) | (static_cast<icUInt32Number>(e34[9])<<16) |
                                    (static_cast<icUInt32Number>(e34[10])<<8) | e34[11];

            if (tOff34 + 32 > fs34 || tSz34 < 32) continue;
            icUInt8Number tagData34[32];
            fseek(fp34, tOff34, SEEK_SET);
            if (fread(tagData34, 1, 32, fp34) != 32) continue;

            icUInt32Number tagType34 = (static_cast<icUInt32Number>(tagData34[0])<<24) | (static_cast<icUInt32Number>(tagData34[1])<<16) |
                                       (static_cast<icUInt32Number>(tagData34[2])<<8) | tagData34[3];

            if (tagType34 != 0x6D414220 && tagType34 != 0x6D424120) continue;

            icUInt32Number tSig34 = (static_cast<icUInt32Number>(e34[0])<<24) | (static_cast<icUInt32Number>(e34[1])<<16) |
                                    (static_cast<icUInt32Number>(e34[2])<<8) | e34[3];
            char sig34[5];
            sig34[0] = (tSig34>>24)&0xff; sig34[1] = (tSig34>>16)&0xff;
            sig34[2] = (tSig34>>8)&0xff;  sig34[3] = tSig34&0xff; sig34[4] = '\0';

            // Check sub-element offsets at +20 (M), +24 (CLUT), +28 (A)
            // These are the offsets parsers add small constants to for header traversal
            static const uint32_t addConstants[] = {0x14, 0x30, 0x0C};
            static const char *subNames34[] = {"M_curves", "CLUT", "A_curves"};
            static const size_t subPos34[] = {20, 24, 28};

            for (int se = 0; se < 3; se++) {
              size_t p = subPos34[se];
              icUInt32Number subOff = (static_cast<icUInt32Number>(tagData34[p])<<24) | (static_cast<icUInt32Number>(tagData34[p+1])<<16) |
                                      (static_cast<icUInt32Number>(tagData34[p+2])<<8) | tagData34[p+3];
              if (subOff == 0) continue;

              // Check if offset + any common addend overflows 32 bits
              for (int ac = 0; ac < 3; ac++) {
                uint64_t sum64 = (uint64_t)subOff + addConstants[ac];
                uint32_t sum32 = (uint32_t)(subOff + addConstants[ac]);
                if (sum64 != sum32) {
                  printf("      %s[WARN]  Tag '%s': %s offset 0x%08X + 0x%X = 0x%08X (truncated from 0x%llX)%s\n",
                         ColorCritical(), sig34, subNames34[se], subOff, addConstants[ac],
                         sum32, (unsigned long long)sum64, ColorReset());
                  printf("       %sCRITICAL: 32-bit truncation bypasses bounds check → OOB access%s\n",
                         ColorCritical(), ColorReset());
                  overflowCount++;
                  break; // one overflow per sub-element is enough
                }
              }
            }
          }
        }
      }
      if (fp34) fclose(fp34);

      if (overflowCount > 0) {
        printf("      %s%d sub-element offset(s) trigger 32-bit integer overflow%s\n",
               ColorCritical(), overflowCount, ColorReset());
        printf("      %sRisk: Bounds check bypass via uint32 truncation (common ICC parser vulnerability)%s\n",
               ColorCritical(), ColorReset());
        heuristicCount += overflowCount;
      } else {
        printf("      %s[OK] No 32-bit integer overflow in sub-element offsets%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 35. Suspicious Fill Pattern Detection in mBA/mAB B-Curve Data
  // All-0xFF fill in B-curve data (bytes 32+) creates parseable curve structures that
  // the parser processes without error, then follows OOB M/CLUT/A offsets into unmapped memory.
  // Changing fill to 0x00 or 0x41 causes "Data overruns tag length" early exit.
  printf("[H35] Suspicious Fill Pattern in mBA/mAB Data\n");
  {
    FILE *fp35 = fopen(filename, "rb");
    if (fp35) {
      fseek(fp35, 0, SEEK_END);
      long fs35_l = ftell(fp35);
      if (fs35_l < 0) { fclose(fp35); fp35 = NULL; }
      size_t fs35 = (fp35) ? (size_t)fs35_l : 0;
      if (fp35) fseek(fp35, 0, SEEK_SET);

      int fillCount = 0;
      if (fs35 >= 132) {
        icUInt8Number hdr35[132];
        if (fread(hdr35, 1, 132, fp35) == 132) {
          icUInt32Number tc35 = (static_cast<icUInt32Number>(hdr35[128])<<24) | (static_cast<icUInt32Number>(hdr35[129])<<16) |
                                (static_cast<icUInt32Number>(hdr35[130])<<8) | hdr35[131];

          for (icUInt32Number i = 0; i < tc35 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs35) break;

            icUInt8Number e35[12];
            fseek(fp35, ePos, SEEK_SET);
            if (fread(e35, 1, 12, fp35) != 12) break;

            icUInt32Number tSig35 = (static_cast<icUInt32Number>(e35[0])<<24) | (static_cast<icUInt32Number>(e35[1])<<16) |
                                    (static_cast<icUInt32Number>(e35[2])<<8) | e35[3];
            icUInt32Number tOff35 = (static_cast<icUInt32Number>(e35[4])<<24) | (static_cast<icUInt32Number>(e35[5])<<16) |
                                    (static_cast<icUInt32Number>(e35[6])<<8) | e35[7];
            icUInt32Number tSz35  = (static_cast<icUInt32Number>(e35[8])<<24) | (static_cast<icUInt32Number>(e35[9])<<16) |
                                    (static_cast<icUInt32Number>(e35[10])<<8) | e35[11];

            if (tOff35 + 32 > fs35 || tSz35 < 48) continue; // need at least 32-byte header + 16 data bytes
            icUInt8Number typeCheck[4];
            fseek(fp35, tOff35, SEEK_SET);
            if (fread(typeCheck, 1, 4, fp35) != 4) continue;

            icUInt32Number tagType35 = (static_cast<icUInt32Number>(typeCheck[0])<<24) | (static_cast<icUInt32Number>(typeCheck[1])<<16) |
                                       (static_cast<icUInt32Number>(typeCheck[2])<<8) | typeCheck[3];
            if (tagType35 != 0x6D414220 && tagType35 != 0x6D424120) continue;

            // Read B-curve data region (bytes 32+ within the tag, up to 256 bytes)
            size_t dataStart = tOff35 + 32;
            size_t dataLen = tSz35 - 32;
            if (dataLen > 256) dataLen = 256;
            if (dataStart + dataLen > fs35) dataLen = fs35 - dataStart;
            if (dataLen < 16) continue;

            icUInt8Number bData[256];
            fseek(fp35, dataStart, SEEK_SET);
            if (fread(bData, 1, dataLen, fp35) != dataLen) continue;

            // Check for runs of identical bytes ≥ 16
            int runLen = 1;
            for (size_t b = 1; b < dataLen; b++) {
              if (bData[b] == bData[b-1]) {
                runLen++;
              } else {
                if (runLen >= 16) {
                  char sig35[5];
                  sig35[0] = (tSig35>>24)&0xff; sig35[1] = (tSig35>>16)&0xff;
                  sig35[2] = (tSig35>>8)&0xff;  sig35[3] = tSig35&0xff; sig35[4] = '\0';
                  printf("      %s[WARN]  Tag '%s': %d-byte run of 0x%02X at B-curve data+%zu%s\n",
                         ColorWarning(), sig35, runLen, bData[b-1], b - runLen, ColorReset());
                  if (bData[b-1] == 0xFF) {
                    printf("       %s0xFF fill creates parseable curve structure → enables OOB offset traversal%s\n",
                           ColorCritical(), ColorReset());
                  }
                  fillCount++;
                }
                runLen = 1;
              }
            }
            // Check final run
            if (runLen >= 16) {
              char sig35[5];
              sig35[0] = (tSig35>>24)&0xff; sig35[1] = (tSig35>>16)&0xff;
              sig35[2] = (tSig35>>8)&0xff;  sig35[3] = tSig35&0xff; sig35[4] = '\0';
              printf("      %s[WARN]  Tag '%s': %d-byte run of 0x%02X at B-curve data+%zu%s\n",
                     ColorWarning(), sig35, runLen, bData[dataLen-1], dataLen - runLen, ColorReset());
              if (bData[dataLen-1] == 0xFF) {
                printf("       %s0xFF fill creates parseable curve structure → enables OOB offset traversal%s\n",
                       ColorCritical(), ColorReset());
              }
              fillCount++;
            }
          }
        }
      }
      if (fp35) fclose(fp35);

      if (fillCount > 0) {
        printf("      %s%d suspicious fill pattern(s) in mBA/mAB B-curve data%s\n",
               ColorWarning(), fillCount, ColorReset());
        heuristicCount += fillCount;
      } else {
        printf("      %s[OK] No suspicious fill patterns in mBA/mAB data%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 36. LUT Tag Pair Completeness
  // Check A2B↔B2A and D2B↔B2D pairing. Unpaired LUT tags may indicate crafted
  // profiles targeting only one transform direction.
  printf("[H36] LUT Tag Pair Completeness\n");
  {
    FILE *fp36 = fopen(filename, "rb");
    if (fp36) {
      fseek(fp36, 0, SEEK_END);
      long fs36_l = ftell(fp36);
      if (fs36_l < 0) { fclose(fp36); fp36 = NULL; }
      size_t fs36 = (fp36) ? (size_t)fs36_l : 0;
      if (fp36) fseek(fp36, 0, SEEK_SET);

      int pairIssues = 0;
      if (fs36 >= 132) {
        icUInt8Number hdr36[132];
        if (fread(hdr36, 1, 132, fp36) == 132) {
          icUInt32Number tc36 = (static_cast<icUInt32Number>(hdr36[128])<<24) | (static_cast<icUInt32Number>(hdr36[129])<<16) |
                                (static_cast<icUInt32Number>(hdr36[130])<<8) | hdr36[131];

          // Collect all tag signatures
          bool hasA2B[4] = {false}, hasB2A[4] = {false};
          bool hasD2B[4] = {false}, hasB2D[4] = {false};

          for (icUInt32Number i = 0; i < tc36 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs36) break;

            icUInt8Number e36[12];
            fseek(fp36, ePos, SEEK_SET);
            if (fread(e36, 1, 12, fp36) != 12) break;

            icUInt32Number tSig36 = (static_cast<icUInt32Number>(e36[0])<<24) | (static_cast<icUInt32Number>(e36[1])<<16) |
                                    (static_cast<icUInt32Number>(e36[2])<<8) | e36[3];

            // A2B0-A2B3: 0x41324230 - 0x41324233
            // B2A0-B2A3: 0x42324130 - 0x42324133
            // D2B0-D2B3: 0x44324230 - 0x44324233
            // B2D0-B2D3: 0x42324430 - 0x42324433
            if (tSig36 >= 0x41324230 && tSig36 <= 0x41324233) hasA2B[tSig36 - 0x41324230] = true;
            if (tSig36 >= 0x42324130 && tSig36 <= 0x42324133) hasB2A[tSig36 - 0x42324130] = true;
            if (tSig36 >= 0x44324230 && tSig36 <= 0x44324233) hasD2B[tSig36 - 0x44324230] = true;
            if (tSig36 >= 0x42324430 && tSig36 <= 0x42324433) hasB2D[tSig36 - 0x42324430] = true;
          }

          // Check pairing
          for (int idx = 0; idx < 4; idx++) {
            if (hasA2B[idx] && !hasB2A[idx]) {
              printf("      %s[INFO]  A2B%d present but B2A%d missing — forward-only LUT%s\n",
                     ColorInfo(), idx, idx, ColorReset());
              pairIssues++;
            }
            if (hasB2A[idx] && !hasA2B[idx]) {
              printf("      %s[INFO]  B2A%d present but A2B%d missing — reverse-only LUT%s\n",
                     ColorInfo(), idx, idx, ColorReset());
              pairIssues++;
            }
            if (hasD2B[idx] && !hasB2D[idx]) {
              printf("      %s[INFO]  D2B%d present but B2D%d missing — forward-only device LUT%s\n",
                     ColorInfo(), idx, idx, ColorReset());
              pairIssues++;
            }
            if (hasB2D[idx] && !hasD2B[idx]) {
              printf("      %s[INFO]  B2D%d present but D2B%d missing — reverse-only device LUT%s\n",
                     ColorInfo(), idx, idx, ColorReset());
              pairIssues++;
            }
          }
        }
      }
      if (fp36) fclose(fp36);

      if (pairIssues > 0) {
        printf("      %s%d unpaired LUT tag(s) — may indicate crafted profile%s\n",
               ColorInfo(), pairIssues, ColorReset());
        // Informational only — do not increment heuristicCount for missing pairs
      } else {
        printf("      %s[OK] All LUT tags properly paired%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 37. Calculator Element Complexity Validation (raw file bytes)
  // Calculator elements (0x63616C63 'calc') are Turing-complete: if/sel opcodes enable
  // arbitrary branching, tget/tput/tsav access stack memory. #1 UBSAN source in fuzzing.
  // CVE refs: CVE-2026-22047, calcOverMem/calcUnderStack test profiles
  printf("[H37] Calculator Element Complexity Validation\n");
  {
    FILE *fp37 = fopen(filename, "rb");
    if (fp37) {
      fseek(fp37, 0, SEEK_END);
      long fs37_l = ftell(fp37);
      if (fs37_l < 0) { fclose(fp37); fp37 = NULL; }
      size_t fs37 = (fp37) ? (size_t)fs37_l : 0;
      if (fp37) fseek(fp37, 0, SEEK_SET);

      int calcIssues = 0;
      if (fs37 >= 132) {
        icUInt8Number hdr37[132];
        if (fread(hdr37, 1, 132, fp37) == 132) {
          icUInt32Number tc37 = (static_cast<icUInt32Number>(hdr37[128])<<24) | (static_cast<icUInt32Number>(hdr37[129])<<16) |
                                (static_cast<icUInt32Number>(hdr37[130])<<8) | hdr37[131];

          for (icUInt32Number i = 0; i < tc37 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs37) break;

            icUInt8Number e37[12];
            fseek(fp37, ePos, SEEK_SET);
            if (fread(e37, 1, 12, fp37) != 12) break;

            icUInt32Number tSig37 = (static_cast<icUInt32Number>(e37[0])<<24) | (static_cast<icUInt32Number>(e37[1])<<16) |
                                    (static_cast<icUInt32Number>(e37[2])<<8) | e37[3];
            icUInt32Number tOff37 = (static_cast<icUInt32Number>(e37[4])<<24) | (static_cast<icUInt32Number>(e37[5])<<16) |
                                    (static_cast<icUInt32Number>(e37[6])<<8) | e37[7];
            icUInt32Number tSz37  = (static_cast<icUInt32Number>(e37[8])<<24) | (static_cast<icUInt32Number>(e37[9])<<16) |
                                    (static_cast<icUInt32Number>(e37[10])<<8) | e37[11];

            if (tOff37 + 4 > fs37 || tSz37 < 4) continue;

            // Check if tag contains mpet type
            icUInt8Number typeCheck37[4];
            fseek(fp37, tOff37, SEEK_SET);
            if (fread(typeCheck37, 1, 4, fp37) != 4) continue;
            icUInt32Number tagType37 = (static_cast<icUInt32Number>(typeCheck37[0])<<24) | (static_cast<icUInt32Number>(typeCheck37[1])<<16) |
                                       (static_cast<icUInt32Number>(typeCheck37[2])<<8) | typeCheck37[3];
            // mpet = 0x6D706574
            if (tagType37 != 0x6D706574) continue;

            // Scan tag data for 'calc' sub-element signatures (0x63616C63)
            // and count occurrences + check for extreme indices
            size_t scanLen = (tSz37 < 4096) ? tSz37 : 4096;
            if (tOff37 + scanLen > fs37) scanLen = fs37 - tOff37;
            if (scanLen < 8) continue;

            icUInt8Number *scanBuf = new icUInt8Number[scanLen];
            fseek(fp37, tOff37, SEEK_SET);
            if (fread(scanBuf, 1, scanLen, fp37) != scanLen) { delete[] scanBuf; continue; }

            char sig37[5];
            sig37[0] = (tSig37>>24)&0xff; sig37[1] = (tSig37>>16)&0xff;
            sig37[2] = (tSig37>>8)&0xff;  sig37[3] = tSig37&0xff; sig37[4] = '\0';

            int calcCount = 0;
            int ifSelCount = 0;
            for (size_t b = 0; b + 3 < scanLen; b++) {
              icUInt32Number w = (static_cast<icUInt32Number>(scanBuf[b])<<24) | (static_cast<icUInt32Number>(scanBuf[b+1])<<16) |
                                 (static_cast<icUInt32Number>(scanBuf[b+2])<<8) | scanBuf[b+3];
              if (w == 0x63616C63) calcCount++; // 'calc'
              if (w == 0x69660000 || w == 0x73656C00) ifSelCount++; // 'if\0\0' or 'sel\0' patterns
            }

            if (calcCount > 100) {
              printf("      %s[WARN]  Tag '%s': %d calculator sub-elements (limit 100)%s\n",
                     ColorCritical(), sig37, calcCount, ColorReset());
              printf("       %sRisk: Stack exhaustion / OOM via calculator element recursion%s\n",
                     ColorCritical(), ColorReset());
              calcIssues++;
            }

            // Check for zero-length MPE (tag size < 16 means no elements)
            if (tSz37 >= 8 && tSz37 < 16) {
              printf("      %s[WARN]  Tag '%s': MPE tag size %u too small for any elements%s\n",
                     ColorWarning(), sig37, tSz37, ColorReset());
              printf("       %sRisk: Crash on empty element list traversal%s\n",
                     ColorCritical(), ColorReset());
              calcIssues++;
            }

            // Check for extreme sub-element count in mpet header
            // mpet: type(4) + reserved(4) + nInput(2) + nOutput(2) + nElements(4) = 16 bytes
            if (scanLen >= 16) {
              icUInt32Number nElems = (static_cast<icUInt32Number>(scanBuf[12])<<24) | (static_cast<icUInt32Number>(scanBuf[13])<<16) |
                                      (static_cast<icUInt32Number>(scanBuf[14])<<8) | scanBuf[15];
              if (nElems > 256) {
                printf("      %s[WARN]  Tag '%s': MPE has %u elements (limit 256)%s\n",
                       ColorCritical(), sig37, nElems, ColorReset());
                printf("       %sRisk: DoS via excessive element processing%s\n",
                       ColorCritical(), ColorReset());
                calcIssues++;
              }
            }

            delete[] scanBuf;
          }
        }
      }
      if (fp37) fclose(fp37);

      if (calcIssues > 0) {
        heuristicCount += calcIssues;
      } else {
        printf("      %s[OK] No calculator complexity issues%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 38. Curve Degenerate Value Detection (raw file bytes)
  // TRC curves with all-zero, all-max, or NaN values cause undefined behavior
  // in color math. Applies to curv (0x63757276) and para (0x70617261) tags.
  printf("[H38] Curve Degenerate Value Detection\n");
  {
    FILE *fp38 = fopen(filename, "rb");
    if (fp38) {
      fseek(fp38, 0, SEEK_END);
      long fs38_l = ftell(fp38);
      if (fs38_l < 0) { fclose(fp38); fp38 = NULL; }
      size_t fs38 = (fp38) ? (size_t)fs38_l : 0;
      if (fp38) fseek(fp38, 0, SEEK_SET);

      int curveIssues = 0;
      if (fs38 >= 132) {
        icUInt8Number hdr38[132];
        if (fread(hdr38, 1, 132, fp38) == 132) {
          icUInt32Number tc38 = (static_cast<icUInt32Number>(hdr38[128])<<24) | (static_cast<icUInt32Number>(hdr38[129])<<16) |
                                (static_cast<icUInt32Number>(hdr38[130])<<8) | hdr38[131];

          for (icUInt32Number i = 0; i < tc38 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs38) break;

            icUInt8Number e38[12];
            fseek(fp38, ePos, SEEK_SET);
            if (fread(e38, 1, 12, fp38) != 12) break;

            icUInt32Number tSig38 = (static_cast<icUInt32Number>(e38[0])<<24) | (static_cast<icUInt32Number>(e38[1])<<16) |
                                    (static_cast<icUInt32Number>(e38[2])<<8) | e38[3];
            icUInt32Number tOff38 = (static_cast<icUInt32Number>(e38[4])<<24) | (static_cast<icUInt32Number>(e38[5])<<16) |
                                    (static_cast<icUInt32Number>(e38[6])<<8) | e38[7];
            icUInt32Number tSz38  = (static_cast<icUInt32Number>(e38[8])<<24) | (static_cast<icUInt32Number>(e38[9])<<16) |
                                    (static_cast<icUInt32Number>(e38[10])<<8) | e38[11];

            if (tOff38 + 12 > fs38 || tSz38 < 12) continue;
            icUInt8Number curveHdr[12];
            fseek(fp38, tOff38, SEEK_SET);
            if (fread(curveHdr, 1, 12, fp38) != 12) continue;

            icUInt32Number curveType = (static_cast<icUInt32Number>(curveHdr[0])<<24) | (static_cast<icUInt32Number>(curveHdr[1])<<16) |
                                       (static_cast<icUInt32Number>(curveHdr[2])<<8) | curveHdr[3];

            char sig38[5];
            sig38[0] = (tSig38>>24)&0xff; sig38[1] = (tSig38>>16)&0xff;
            sig38[2] = (tSig38>>8)&0xff;  sig38[3] = tSig38&0xff; sig38[4] = '\0';

            if (curveType == 0x63757276) { // 'curv'
              // curv: type(4) + reserved(4) + count(4) + entries(2*count)
              icUInt32Number count = (static_cast<icUInt32Number>(curveHdr[8])<<24) | (static_cast<icUInt32Number>(curveHdr[9])<<16) |
                                     (static_cast<icUInt32Number>(curveHdr[10])<<8) | curveHdr[11];
              if (count > 1 && count <= 65535) {
                size_t dataStart = tOff38 + 12;
                size_t dataLen = count * 2;
                if (dataLen > 512) dataLen = 512; // sample first 256 entries
                if (dataStart + dataLen > fs38) continue;

                icUInt8Number *cData = new icUInt8Number[dataLen];
                fseek(fp38, dataStart, SEEK_SET);
                if (fread(cData, 1, dataLen, fp38) == dataLen) {
                  bool allZero = true, allMax = true;
                  for (size_t b = 0; b < dataLen; b += 2) {
                    uint16_t val = (static_cast<uint16_t>(cData[b]) << 8) | cData[b+1];
                    if (val != 0) allZero = false;
                    if (val != 0xFFFF) allMax = false;
                  }
                  if (allZero) {
                    printf("      %s[WARN]  Tag '%s' (curv): all %u entries are zero — degenerate TRC%s\n",
                           ColorCritical(), sig38, count, ColorReset());
                    printf("       %sRisk: All color channels collapse to black — division by zero in inverse%s\n",
                           ColorCritical(), ColorReset());
                    curveIssues++;
                  }
                  if (allMax) {
                    printf("      %s[WARN]  Tag '%s' (curv): all %u entries are 0xFFFF — saturated TRC%s\n",
                           ColorWarning(), sig38, count, ColorReset());
                    curveIssues++;
                  }
                }
                delete[] cData;
              }
            } else if (curveType == 0x70617261) { // 'para'
              // para: type(4) + reserved(4) + funcType(2) + reserved(2) + params...
              // funcType 0: Y = X^g  (1 param: g)
              // funcType 1-4: increasingly complex (a,b,c,d,e,f params)
              if (tSz38 >= 16) {
                icUInt8Number paraHdr[4];
                fseek(fp38, tOff38 + 8, SEEK_SET);
                if (fread(paraHdr, 1, 4, fp38) == 4) {
                  uint16_t funcType = (static_cast<uint16_t>(paraHdr[0]) << 8) | paraHdr[1];
                  if (funcType > 4) {
                    printf("      %s[WARN]  Tag '%s' (para): funcType %u > 4 (invalid)%s\n",
                           ColorCritical(), sig38, funcType, ColorReset());
                    printf("       %sRisk: Parser reads uninitialized coefficients%s\n",
                           ColorCritical(), ColorReset());
                    curveIssues++;
                  }
                  // Check first param (gamma) for zero — causes pow(x, 0) flattening
                  if (tSz38 >= 16 && tOff38 + 16 <= fs38) {
                    icUInt8Number gamma38[4];
                    fseek(fp38, tOff38 + 12, SEEK_SET);
                    if (fread(gamma38, 1, 4, fp38) == 4) {
                      int32_t gammaFixed = (static_cast<int32_t>(gamma38[0])<<24) | (gamma38[1]<<16) |
                                            (gamma38[2]<<8) | gamma38[3];
                      if (gammaFixed == 0) {
                        printf("      %s[WARN]  Tag '%s' (para): gamma = 0 (s15Fixed16) — degenerate%s\n",
                               ColorWarning(), sig38, ColorReset());
                        curveIssues++;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      if (fp38) fclose(fp38);

      if (curveIssues > 0) {
        heuristicCount += curveIssues;
      } else {
        printf("      %s[OK] No degenerate curve values detected%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 39. Shared Tag Data Aliasing Detection (raw file bytes)
  // Multiple tag entries pointing to the same offset+size is ICC-legal (shared data).
  // However, shared mutable types (mBA/mAB/calc/tary) can cause UAF.
  printf("[H39] Shared Tag Data Aliasing Detection\n");
  {
    FILE *fp39 = fopen(filename, "rb");
    if (fp39) {
      fseek(fp39, 0, SEEK_END);
      long fs39_l = ftell(fp39);
      if (fs39_l < 0) { fclose(fp39); fp39 = NULL; }
      size_t fs39 = (fp39) ? (size_t)fs39_l : 0;
      if (fp39) fseek(fp39, 0, SEEK_SET);

      int aliasIssues = 0;
      if (fs39 >= 132) {
        icUInt8Number hdr39[132];
        if (fread(hdr39, 1, 132, fp39) == 132) {
          icUInt32Number tc39 = (static_cast<icUInt32Number>(hdr39[128])<<24) | (static_cast<icUInt32Number>(hdr39[129])<<16) |
                                (static_cast<icUInt32Number>(hdr39[130])<<8) | hdr39[131];
          if (tc39 > 256) tc39 = 256;

          struct TagEntry39 { icUInt32Number sig; icUInt32Number off; icUInt32Number sz; };
          std::vector<TagEntry39> tags39;

          for (icUInt32Number i = 0; i < tc39; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs39) break;
            icUInt8Number e39[12];
            fseek(fp39, ePos, SEEK_SET);
            if (fread(e39, 1, 12, fp39) != 12) break;
            TagEntry39 te;
            te.sig = (static_cast<icUInt32Number>(e39[0])<<24) | (static_cast<icUInt32Number>(e39[1])<<16) | (static_cast<icUInt32Number>(e39[2])<<8) | e39[3];
            te.off = (static_cast<icUInt32Number>(e39[4])<<24) | (static_cast<icUInt32Number>(e39[5])<<16) | (static_cast<icUInt32Number>(e39[6])<<8) | e39[7];
            te.sz  = (static_cast<icUInt32Number>(e39[8])<<24) | (static_cast<icUInt32Number>(e39[9])<<16) | (static_cast<icUInt32Number>(e39[10])<<8) | e39[11];
            tags39.push_back(te);
          }

          int sharedCount = 0;
          for (size_t a = 0; a < tags39.size(); a++) {
            for (size_t b = a+1; b < tags39.size(); b++) {
              if (tags39[a].off == tags39[b].off && tags39[a].sz == tags39[b].sz && tags39[a].sig != tags39[b].sig) {
                char s1[5], s2[5];
                s1[0] = (tags39[a].sig>>24)&0xff; s1[1] = (tags39[a].sig>>16)&0xff; s1[2] = (tags39[a].sig>>8)&0xff; s1[3] = tags39[a].sig&0xff; s1[4] = '\0';
                s2[0] = (tags39[b].sig>>24)&0xff; s2[1] = (tags39[b].sig>>16)&0xff; s2[2] = (tags39[b].sig>>8)&0xff; s2[3] = tags39[b].sig&0xff; s2[4] = '\0';

                sharedCount++;
                if (sharedCount <= 5) {
                  printf("      [INFO]  Tags '%s' and '%s' share data at offset 0x%X (%u bytes)\n",
                         s1, s2, tags39[a].off, tags39[a].sz);
                }

                // Check if shared type is mutable (mBA, mAB, calc, tary — higher UAF risk)
                if (tags39[a].off + 4 <= fs39) {
                  icUInt8Number sharedType[4];
                  fseek(fp39, tags39[a].off, SEEK_SET);
                  if (fread(sharedType, 1, 4, fp39) == 4) {
                    icUInt32Number st = (static_cast<icUInt32Number>(sharedType[0])<<24) | (static_cast<icUInt32Number>(sharedType[1])<<16) |
                                        (static_cast<icUInt32Number>(sharedType[2])<<8) | sharedType[3];
                    if (st == 0x6D424120 || st == 0x6D414220 || st == 0x6D706574 || st == 0x74617279) {
                      printf("      %s[WARN]  Shared data is mutable type (0x%08X) — UAF risk%s\n",
                             ColorCritical(), st, ColorReset());
                      aliasIssues++;
                    }
                  }
                }
              }
            }
          }

          if (sharedCount > 5) {
            printf("      ... and %d more shared tag pair(s)\n", sharedCount - 5);
          }
          if (sharedCount > 0 && aliasIssues == 0) {
            printf("      %s[OK] %d shared tag pair(s) — all immutable types (safe)%s\n",
                   ColorSuccess(), sharedCount, ColorReset());
          }
        }
      }
      if (fp39) fclose(fp39);

      if (aliasIssues > 0) {
        heuristicCount += aliasIssues;
      } else if (aliasIssues == 0) {
        printf("      %s[OK] No risky shared tag data aliasing%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 40. Tag Alignment & Padding Validation (raw file bytes)
  // ICC spec requires tag data offsets to be 4-byte aligned. Misalignment causes
  // SIGBUS on strict-alignment platforms (arm64). Non-zero padding can leak data.
  printf("[H40] Tag Alignment & Padding Validation\n");
  {
    FILE *fp40 = fopen(filename, "rb");
    if (fp40) {
      fseek(fp40, 0, SEEK_END);
      long fs40_l = ftell(fp40);
      if (fs40_l < 0) { fclose(fp40); fp40 = NULL; }
      size_t fs40 = (fp40) ? (size_t)fs40_l : 0;
      if (fp40) fseek(fp40, 0, SEEK_SET);

      int alignIssues = 0;
      if (fs40 >= 132) {
        icUInt8Number hdr40[132];
        if (fread(hdr40, 1, 132, fp40) == 132) {
          icUInt32Number tc40 = (static_cast<icUInt32Number>(hdr40[128])<<24) | (static_cast<icUInt32Number>(hdr40[129])<<16) |
                                (static_cast<icUInt32Number>(hdr40[130])<<8) | hdr40[131];
          if (tc40 > 256) tc40 = 256;

          int misaligned = 0;
          int nonZeroPad = 0;

          for (icUInt32Number i = 0; i < tc40; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs40) break;
            icUInt8Number e40[12];
            fseek(fp40, ePos, SEEK_SET);
            if (fread(e40, 1, 12, fp40) != 12) break;

            icUInt32Number tOff40 = (static_cast<icUInt32Number>(e40[4])<<24) | (static_cast<icUInt32Number>(e40[5])<<16) |
                                    (static_cast<icUInt32Number>(e40[6])<<8) | e40[7];
            icUInt32Number tSz40  = (static_cast<icUInt32Number>(e40[8])<<24) | (static_cast<icUInt32Number>(e40[9])<<16) |
                                    (static_cast<icUInt32Number>(e40[10])<<8) | e40[11];

            // Check 4-byte alignment
            if (tOff40 % 4 != 0) {
              if (misaligned < 3) {
                char sig40[5];
                sig40[0] = e40[0]; sig40[1] = e40[1]; sig40[2] = e40[2]; sig40[3] = e40[3]; sig40[4] = '\0';
                printf("      %s[WARN]  Tag '%s' offset 0x%X not 4-byte aligned%s\n",
                       ColorWarning(), sig40, tOff40, ColorReset());
              }
              misaligned++;
            }

            // Check padding bytes after tag data (up to next 4-byte boundary)
            size_t tagEnd = (size_t)tOff40 + tSz40;
            size_t padEnd = (tagEnd + 3) & ~3UL;
            if (padEnd > tagEnd && padEnd <= fs40) {
              size_t padLen = padEnd - tagEnd;
              icUInt8Number padBuf[4];
              fseek(fp40, tagEnd, SEEK_SET);
              size_t toRead = (padLen < 4) ? padLen : 4;
              if (fread(padBuf, 1, toRead, fp40) == toRead) {
                for (size_t p = 0; p < toRead; p++) {
                  if (padBuf[p] != 0x00) {
                    nonZeroPad++;
                    break;
                  }
                }
              }
            }
          }

          if (misaligned > 3) {
            printf("      ... and %d more misaligned tag(s)\n", misaligned - 3);
          }
          if (misaligned > 0) {
            printf("      %s%d tag(s) with non-aligned offsets%s\n", ColorWarning(), misaligned, ColorReset());
            printf("      %sRisk: SIGBUS on strict-alignment platforms (arm64)%s\n",
                   ColorWarning(), ColorReset());
            alignIssues += misaligned;
          }
          if (nonZeroPad > 0) {
            printf("      %s[WARN]  %d tag(s) have non-zero padding bytes%s\n",
                   ColorWarning(), nonZeroPad, ColorReset());
            printf("      %sRisk: Potential data leakage in padding%s\n", ColorInfo(), ColorReset());
            alignIssues++;
          }
        }
      }
      if (fp40) fclose(fp40);

      if (alignIssues > 0) {
        heuristicCount++;
      } else {
        printf("      %s[OK] All tags properly aligned with zero padding%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 41. Version/Type Consistency Check (raw file bytes)
  // Flag v5-only types/tags in v2/v4 profiles (type confusion risk) and
  // deprecated v2-only types in v4+ profiles.
  printf("[H41] Version/Type Consistency Check\n");
  {
    FILE *fp41 = fopen(filename, "rb");
    if (fp41) {
      fseek(fp41, 0, SEEK_END);
      long fs41_l = ftell(fp41);
      if (fs41_l < 0) { fclose(fp41); fp41 = NULL; }
      size_t fs41 = (fp41) ? (size_t)fs41_l : 0;
      if (fp41) fseek(fp41, 0, SEEK_SET);

      int versionIssues = 0;
      if (fs41 >= 132) {
        icUInt8Number hdr41[132];
        if (fread(hdr41, 1, 132, fp41) == 132) {
          // Profile version: byte 8 = major, byte 9 = minor.sub
          uint8_t verMajor = hdr41[8];
          uint8_t verMinor = hdr41[9];
          printf("      Profile version: %u.%u.%u\n", verMajor, (verMinor >> 4), (verMinor & 0x0F));

          icUInt32Number tc41 = (static_cast<icUInt32Number>(hdr41[128])<<24) | (static_cast<icUInt32Number>(hdr41[129])<<16) |
                                (static_cast<icUInt32Number>(hdr41[130])<<8) | hdr41[131];
          if (tc41 > 256) tc41 = 256;

          // v5-only type signatures
          static const icUInt32Number v5OnlyTypes[] = {
            0x736D6174, // 'smat' sparseMatrixArrayType
            0x7A757466, // 'zutf' zipUtf8Type
            0x7A786D6C, // 'zxml' zipXmlType
            0x63696370, // 'cicp' cicpType
            0x75746638, // 'utf8' utf8Type
            0x666C3136, // 'fl16' float16ArrayType
            0x666C3332, // 'fl32' float32ArrayType
            0x666C3634, // 'fl64' float64ArrayType
            0x62726466, // 'brdf' brdfType
          };
          // v5-only tag signatures
          static const icUInt32Number v5OnlyTags[] = {
            0x7364696E, // 'sdin' spectralDataInfo
            0x73777074, // 'swpt' spectralWhitePoint
            0x7376636E, // 'svcn' spectralViewingConditions
            0x656F6273, // 'eobs' emissionObserver
            0x726F6273, // 'robs' reflectanceObserver
          };

          for (icUInt32Number i = 0; i < tc41; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs41) break;
            icUInt8Number e41[12];
            fseek(fp41, ePos, SEEK_SET);
            if (fread(e41, 1, 12, fp41) != 12) break;

            icUInt32Number tSig41 = (static_cast<icUInt32Number>(e41[0])<<24) | (static_cast<icUInt32Number>(e41[1])<<16) |
                                    (static_cast<icUInt32Number>(e41[2])<<8) | e41[3];
            icUInt32Number tOff41 = (static_cast<icUInt32Number>(e41[4])<<24) | (static_cast<icUInt32Number>(e41[5])<<16) |
                                    (static_cast<icUInt32Number>(e41[6])<<8) | e41[7];

            char sig41[5];
            sig41[0] = (tSig41>>24)&0xff; sig41[1] = (tSig41>>16)&0xff;
            sig41[2] = (tSig41>>8)&0xff;  sig41[3] = tSig41&0xff; sig41[4] = '\0';

            // Check tag signature against v5-only list
            if (verMajor < 5) {
              for (int k = 0; k < (int)(sizeof(v5OnlyTags)/sizeof(v5OnlyTags[0])); k++) {
                if (tSig41 == v5OnlyTags[k]) {
                  printf("      %s[WARN]  v5-only tag '%s' in v%u profile%s\n",
                         ColorWarning(), sig41, verMajor, ColorReset());
                  versionIssues++;
                  break;
                }
              }
            }

            // Check tag data type against v5-only list
            if (verMajor < 5 && tOff41 + 4 <= fs41) {
              icUInt8Number typeBytes41[4];
              fseek(fp41, tOff41, SEEK_SET);
              if (fread(typeBytes41, 1, 4, fp41) == 4) {
                icUInt32Number dataType41 = (static_cast<icUInt32Number>(typeBytes41[0])<<24) | (static_cast<icUInt32Number>(typeBytes41[1])<<16) |
                                             (static_cast<icUInt32Number>(typeBytes41[2])<<8) | typeBytes41[3];
                for (int k = 0; k < (int)(sizeof(v5OnlyTypes)/sizeof(v5OnlyTypes[0])); k++) {
                  if (dataType41 == v5OnlyTypes[k]) {
                    char typeStr41[5];
                    typeStr41[0] = (dataType41>>24)&0xff; typeStr41[1] = (dataType41>>16)&0xff;
                    typeStr41[2] = (dataType41>>8)&0xff;  typeStr41[3] = dataType41&0xff; typeStr41[4] = '\0';
                    printf("      %s[WARN]  Tag '%s' uses v5-only type '%s' in v%u profile%s\n",
                           ColorWarning(), sig41, typeStr41, verMajor, ColorReset());
                    printf("       %sRisk: Type confusion — v4 parser may misinterpret v5 data%s\n",
                           ColorCritical(), ColorReset());
                    versionIssues++;
                    break;
                  }
                }
              }
            }
          }
        }
      }
      if (fp41) fclose(fp41);

      if (versionIssues > 0) {
        printf("      %s%d version/type inconsistency(ies) detected%s\n",
               ColorWarning(), versionIssues, ColorReset());
        heuristicCount += versionIssues;
      } else {
        printf("      %s[OK] All tags/types consistent with declared version%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 42. Matrix Singularity Detection (raw file bytes)
  // Read rXYZ, gXYZ, bXYZ tags (s15Fixed16 × 3 each) and compute 3×3 determinant.
  // Near-zero determinant → division by zero in color transforms.
  printf("[H42] Matrix Singularity Detection\n");
  {
    FILE *fp42 = fopen(filename, "rb");
    if (fp42) {
      fseek(fp42, 0, SEEK_END);
      long fs42_l = ftell(fp42);
      if (fs42_l < 0) { fclose(fp42); fp42 = NULL; }
      size_t fs42 = (fp42) ? (size_t)fs42_l : 0;
      if (fp42) fseek(fp42, 0, SEEK_SET);

      int matrixIssues = 0;
      if (fs42 >= 132) {
        icUInt8Number hdr42[132];
        if (fread(hdr42, 1, 132, fp42) == 132) {
          icUInt32Number tc42 = (static_cast<icUInt32Number>(hdr42[128])<<24) | (static_cast<icUInt32Number>(hdr42[129])<<16) |
                                (static_cast<icUInt32Number>(hdr42[130])<<8) | hdr42[131];
          if (tc42 > 256) tc42 = 256;

          // Find rXYZ (0x7258595A), gXYZ (0x6758595A), bXYZ (0x6258595A)
          static const icUInt32Number xyzSigs[] = {0x7258595A, 0x6758595A, 0x6258595A};
          double mat[3][3] = {{0}};
          int found = 0;

          for (int col = 0; col < 3; col++) {
            for (icUInt32Number i = 0; i < tc42; i++) {
              size_t ePos = 132 + i * 12;
              if (ePos + 12 > fs42) break;
              icUInt8Number e42[12];
              fseek(fp42, ePos, SEEK_SET);
              if (fread(e42, 1, 12, fp42) != 12) break;

              icUInt32Number tSig42 = (static_cast<icUInt32Number>(e42[0])<<24) | (static_cast<icUInt32Number>(e42[1])<<16) |
                                      (static_cast<icUInt32Number>(e42[2])<<8) | e42[3];
              if (tSig42 != xyzSigs[col]) continue;

              icUInt32Number tOff42 = (static_cast<icUInt32Number>(e42[4])<<24) | (static_cast<icUInt32Number>(e42[5])<<16) |
                                      (static_cast<icUInt32Number>(e42[6])<<8) | e42[7];
              // XYZ type: type(4) + reserved(4) + X(4) + Y(4) + Z(4) = 20 bytes
              if (tOff42 + 20 > fs42) break;
              icUInt8Number xyzData[12];
              fseek(fp42, tOff42 + 8, SEEK_SET);
              if (fread(xyzData, 1, 12, fp42) != 12) break;

              for (int row = 0; row < 3; row++) {
                int32_t fixed = (static_cast<int32_t>(xyzData[row*4])<<24) | (xyzData[row*4+1]<<16) |
                                 (xyzData[row*4+2]<<8) | xyzData[row*4+3];
                mat[row][col] = fixed / 65536.0;
              }
              found++;
              break;
            }
          }

          if (found == 3) {
            // Compute determinant: det = a(ei-fh) - b(di-fg) + c(dh-eg)
            double det = mat[0][0] * (mat[1][1]*mat[2][2] - mat[1][2]*mat[2][1])
                       - mat[0][1] * (mat[1][0]*mat[2][2] - mat[1][2]*mat[2][0])
                       + mat[0][2] * (mat[1][0]*mat[2][1] - mat[1][1]*mat[2][0]);

            printf("      Matrix determinant: %.8f\n", det);

            if (det == 0.0 || (det > -1e-7 && det < 1e-7)) {
              printf("      %s[WARN]  Near-singular matrix (det ≈ 0) — non-invertible%s\n",
                     ColorCritical(), ColorReset());
              printf("       %sRisk: Division by zero in inverse color transforms%s\n",
                     ColorCritical(), ColorReset());
              matrixIssues++;
            } else if (det < 0) {
              printf("      %s[WARN]  Negative determinant (%.6f) — inverted color space%s\n",
                     ColorWarning(), det, ColorReset());
              matrixIssues++;
            }
          } else {
            printf("      [INFO]  rXYZ/gXYZ/bXYZ tags not all present (%d/3 found)\n", found);
          }
        }
      }
      if (fp42) fclose(fp42);

      if (matrixIssues > 0) {
        heuristicCount += matrixIssues;
      } else {
        printf("      %s[OK] Color matrix is well-conditioned%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 43. Spectral/BRDF Tag Structural Validation (raw file bytes)
  // ICC v5/iccMAX adds 24+ BRDF signatures and spectral tags. Check for
  // structural presence and pairing issues.
  printf("[H43] Spectral/BRDF Tag Structural Validation\n");
  {
    FILE *fp43 = fopen(filename, "rb");
    if (fp43) {
      fseek(fp43, 0, SEEK_END);
      long fs43_l = ftell(fp43);
      if (fs43_l < 0) { fclose(fp43); fp43 = NULL; }
      size_t fs43 = (fp43) ? (size_t)fs43_l : 0;
      if (fp43) fseek(fp43, 0, SEEK_SET);

      int spectralIssues = 0;
      if (fs43 >= 132) {
        icUInt8Number hdr43[132];
        if (fread(hdr43, 1, 132, fp43) == 132) {
          icUInt32Number tc43 = (static_cast<icUInt32Number>(hdr43[128])<<24) | (static_cast<icUInt32Number>(hdr43[129])<<16) |
                                (static_cast<icUInt32Number>(hdr43[130])<<8) | hdr43[131];
          if (tc43 > 256) tc43 = 256;

          bool hasSdin = false, hasSwpt = false, hasSvcn = false;
          bool hasEobs = false, hasRobs = false;
          int brdfCount = 0;

          for (icUInt32Number i = 0; i < tc43; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs43) break;
            icUInt8Number e43[12];
            fseek(fp43, ePos, SEEK_SET);
            if (fread(e43, 1, 12, fp43) != 12) break;

            icUInt32Number tSig43 = (static_cast<icUInt32Number>(e43[0])<<24) | (static_cast<icUInt32Number>(e43[1])<<16) |
                                    (static_cast<icUInt32Number>(e43[2])<<8) | e43[3];
            icUInt32Number tOff43 = (static_cast<icUInt32Number>(e43[4])<<24) | (static_cast<icUInt32Number>(e43[5])<<16) |
                                    (static_cast<icUInt32Number>(e43[6])<<8) | e43[7];
            icUInt32Number tSz43  = (static_cast<icUInt32Number>(e43[8])<<24) | (static_cast<icUInt32Number>(e43[9])<<16) |
                                    (static_cast<icUInt32Number>(e43[10])<<8) | e43[11];

            if (tSig43 == 0x7364696E) hasSdin = true; // 'sdin'
            if (tSig43 == 0x73777074) hasSwpt = true; // 'swpt'
            if (tSig43 == 0x7376636E) hasSvcn = true; // 'svcn'
            if (tSig43 == 0x656F6273) hasEobs = true; // 'eobs'
            if (tSig43 == 0x726F6273) hasRobs = true; // 'robs'

            // Count BRDF tags (bAB, bDB, bMB, bMS, bcp, bsp, BPh)
            char s43[5];
            s43[0] = (tSig43>>24)&0xff; s43[1] = (tSig43>>16)&0xff;
            s43[2] = (tSig43>>8)&0xff;  s43[3] = tSig43&0xff; s43[4] = '\0';
            if ((s43[0] == 'b' && (s43[1] == 'A' || s43[1] == 'D' || s43[1] == 'M' || s43[1] == 'c' || s43[1] == 's')) ||
                (s43[0] == 'B' && s43[1] == 'P')) {
              brdfCount++;
              // Check for zero-size BRDF tag
              if (tSz43 < 8) {
                printf("      %s[WARN]  BRDF tag '%s' has size %u < 8 (too small for any data)%s\n",
                       ColorWarning(), s43, tSz43, ColorReset());
                spectralIssues++;
              }
            }

            // Validate sdin structure: spectralDataInfo must have valid wavelength data
            if (tSig43 == 0x7364696E && tOff43 + 20 <= fs43 && tSz43 >= 20) {
              icUInt8Number sdinData[12];
              fseek(fp43, tOff43 + 8, SEEK_SET);
              if (fread(sdinData, 1, 12, fp43) == 12) {
                // Spectral range: start(4), end(4), steps(2)
                int32_t specStart = (static_cast<int32_t>(sdinData[0])<<24) | (sdinData[1]<<16) | (sdinData[2]<<8) | sdinData[3];
                int32_t specEnd   = (static_cast<int32_t>(sdinData[4])<<24) | (sdinData[5]<<16) | (sdinData[6]<<8) | sdinData[7];
                uint16_t specSteps = (static_cast<uint16_t>(sdinData[8])<<8) | sdinData[9];
                double startNm = specStart / 65536.0;
                double endNm   = specEnd / 65536.0;
                if (endNm < startNm) {
                  printf("      %s[WARN]  sdin: spectral end (%.1f nm) < start (%.1f nm)%s\n",
                         ColorCritical(), endNm, startNm, ColorReset());
                  spectralIssues++;
                }
                if (specSteps == 0 || specSteps > 1000) {
                  printf("      %s[WARN]  sdin: spectral steps = %u (expected 1-1000)%s\n",
                         ColorWarning(), specSteps, ColorReset());
                  spectralIssues++;
                }
              }
            }
          }

          // Report BRDF presence
          if (brdfCount > 0) {
            printf("      [INFO]  %d BRDF tag(s) present\n", brdfCount);
          }

          // Check spectral tag consistency
          if (hasSdin && !hasSwpt) {
            printf("      %s[WARN]  sdin present but swpt (spectral white) missing%s\n",
                   ColorWarning(), ColorReset());
            spectralIssues++;
          }
          if (hasEobs && !hasRobs && hasSdin) {
            printf("      [INFO]  eobs present without robs — emission-only profile\n");
          }
        }
      }
      if (fp43) fclose(fp43);

      if (spectralIssues > 0) {
        heuristicCount += spectralIssues;
      } else {
        printf("      %s[OK] Spectral/BRDF tags structurally valid%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 44. Embedded Image Validation (raw file bytes, ICC v5)
  // v5 embeddedHeightImageType / embeddedNormalImageType (embt = 0x656D6274)
  // can contain PNG or TIFF data. Check magic bytes and size.
  printf("[H44] Embedded Image Validation\n");
  {
    FILE *fp44 = fopen(filename, "rb");
    if (fp44) {
      fseek(fp44, 0, SEEK_END);
      long fs44_l = ftell(fp44);
      if (fs44_l < 0) { fclose(fp44); fp44 = NULL; }
      size_t fs44 = (fp44) ? (size_t)fs44_l : 0;
      if (fp44) fseek(fp44, 0, SEEK_SET);

      int embedIssues = 0;
      if (fs44 >= 132) {
        icUInt8Number hdr44[132];
        if (fread(hdr44, 1, 132, fp44) == 132) {
          icUInt32Number tc44 = (static_cast<icUInt32Number>(hdr44[128])<<24) | (static_cast<icUInt32Number>(hdr44[129])<<16) |
                                (static_cast<icUInt32Number>(hdr44[130])<<8) | hdr44[131];
          if (tc44 > 256) tc44 = 256;

          int embedFound = 0;
          for (icUInt32Number i = 0; i < tc44; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs44) break;
            icUInt8Number e44[12];
            fseek(fp44, ePos, SEEK_SET);
            if (fread(e44, 1, 12, fp44) != 12) break;

            icUInt32Number tOff44 = (static_cast<icUInt32Number>(e44[4])<<24) | (static_cast<icUInt32Number>(e44[5])<<16) |
                                    (static_cast<icUInt32Number>(e44[6])<<8) | e44[7];
            icUInt32Number tSz44  = (static_cast<icUInt32Number>(e44[8])<<24) | (static_cast<icUInt32Number>(e44[9])<<16) |
                                    (static_cast<icUInt32Number>(e44[10])<<8) | e44[11];

            if (tOff44 + 4 > fs44 || tSz44 < 12) continue;
            icUInt8Number typeBytes44[4];
            fseek(fp44, tOff44, SEEK_SET);
            if (fread(typeBytes44, 1, 4, fp44) != 4) continue;

            icUInt32Number tagType44 = (static_cast<icUInt32Number>(typeBytes44[0])<<24) | (static_cast<icUInt32Number>(typeBytes44[1])<<16) |
                                       (static_cast<icUInt32Number>(typeBytes44[2])<<8) | typeBytes44[3];
            if (tagType44 != 0x656D6274) continue; // 'embt'

            embedFound++;
            char sig44[5];
            sig44[0] = e44[0]; sig44[1] = e44[1]; sig44[2] = e44[2]; sig44[3] = e44[3]; sig44[4] = '\0';

            // Size check: > 10MB is suspicious
            if (tSz44 > 10 * 1024 * 1024) {
              printf("      %s[WARN]  Tag '%s' (embt): embedded image %u bytes (>10MB)%s\n",
                     ColorWarning(), sig44, tSz44, ColorReset());
              printf("       %sRisk: Resource exhaustion via large embedded image%s\n",
                     ColorWarning(), ColorReset());
              embedIssues++;
            }

            // Check embedded image magic (skip type(4) + reserved(4) + flags(4) = offset 12)
            if (tOff44 + 16 <= fs44) {
              icUInt8Number imgMagic[4];
              fseek(fp44, tOff44 + 12, SEEK_SET);
              if (fread(imgMagic, 1, 4, fp44) == 4) {
                bool validPNG = (imgMagic[0] == 0x89 && imgMagic[1] == 0x50 &&
                                 imgMagic[2] == 0x4E && imgMagic[3] == 0x47);
                bool validTIFF_LE = (imgMagic[0] == 0x49 && imgMagic[1] == 0x49 &&
                                      imgMagic[2] == 0x2A && imgMagic[3] == 0x00);
                bool validTIFF_BE = (imgMagic[0] == 0x4D && imgMagic[1] == 0x4D &&
                                      imgMagic[2] == 0x00 && imgMagic[3] == 0x2A);
                if (!validPNG && !validTIFF_LE && !validTIFF_BE) {
                  printf("      %s[WARN]  Tag '%s' (embt): invalid image magic 0x%02X%02X%02X%02X%s\n",
                         ColorWarning(), sig44, imgMagic[0], imgMagic[1], imgMagic[2], imgMagic[3], ColorReset());
                  printf("       %sExpected PNG (89504E47) or TIFF (49492A00/4D4D002A)%s\n",
                         ColorInfo(), ColorReset());
                  embedIssues++;
                }
              }
            }
          }

          if (embedFound > 0) {
            printf("      [INFO]  %d embedded image tag(s) found\n", embedFound);
          }
        }
      }
      if (fp44) fclose(fp44);

      if (embedIssues > 0) {
        heuristicCount += embedIssues;
      } else {
        printf("      %s[OK] Embedded images valid (or none present)%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 45. Sparse Matrix Bounds Validation (raw file bytes, ICC v5)
  // smat (0x736D6174) tags specify rows × cols for sparse matrix data.
  // Extreme dimensions cause OOM. CFL patch 044.
  printf("[H45] Sparse Matrix Bounds Validation\n");
  {
    FILE *fp45 = fopen(filename, "rb");
    if (fp45) {
      fseek(fp45, 0, SEEK_END);
      long fs45_l = ftell(fp45);
      if (fs45_l < 0) { fclose(fp45); fp45 = NULL; }
      size_t fs45 = (fp45) ? (size_t)fs45_l : 0;
      if (fp45) fseek(fp45, 0, SEEK_SET);

      int sparseIssues = 0;
      if (fs45 >= 132) {
        icUInt8Number hdr45[132];
        if (fread(hdr45, 1, 132, fp45) == 132) {
          icUInt32Number tc45 = (static_cast<icUInt32Number>(hdr45[128])<<24) | (static_cast<icUInt32Number>(hdr45[129])<<16) |
                                (static_cast<icUInt32Number>(hdr45[130])<<8) | hdr45[131];
          if (tc45 > 256) tc45 = 256;

          for (icUInt32Number i = 0; i < tc45; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs45) break;
            icUInt8Number e45[12];
            fseek(fp45, ePos, SEEK_SET);
            if (fread(e45, 1, 12, fp45) != 12) break;

            icUInt32Number tOff45 = (static_cast<icUInt32Number>(e45[4])<<24) | (static_cast<icUInt32Number>(e45[5])<<16) |
                                    (static_cast<icUInt32Number>(e45[6])<<8) | e45[7];
            icUInt32Number tSz45  = (static_cast<icUInt32Number>(e45[8])<<24) | (static_cast<icUInt32Number>(e45[9])<<16) |
                                    (static_cast<icUInt32Number>(e45[10])<<8) | e45[11];

            if (tOff45 + 4 > fs45 || tSz45 < 16) continue;
            icUInt8Number typeBytes45[4];
            fseek(fp45, tOff45, SEEK_SET);
            if (fread(typeBytes45, 1, 4, fp45) != 4) continue;

            icUInt32Number tagType45 = (static_cast<icUInt32Number>(typeBytes45[0])<<24) | (static_cast<icUInt32Number>(typeBytes45[1])<<16) |
                                       (static_cast<icUInt32Number>(typeBytes45[2])<<8) | typeBytes45[3];
            if (tagType45 != 0x736D6174) continue; // 'smat'

            char sig45[5];
            sig45[0] = e45[0]; sig45[1] = e45[1]; sig45[2] = e45[2]; sig45[3] = e45[3]; sig45[4] = '\0';

            // smat: type(4) + reserved(4) + nChannels(2) + encoding(2) + ...
            // Read channel count and encoding
            if (tOff45 + 12 <= fs45) {
              icUInt8Number smatHdr[4];
              fseek(fp45, tOff45 + 8, SEEK_SET);
              if (fread(smatHdr, 1, 4, fp45) == 4) {
                uint16_t nChannels = (static_cast<uint16_t>(smatHdr[0])<<8) | smatHdr[1];
                uint16_t encoding  = (static_cast<uint16_t>(smatHdr[2])<<8) | smatHdr[3];

                if (nChannels == 0) {
                  printf("      %s[WARN]  Tag '%s' (smat): zero channels%s\n",
                         ColorCritical(), sig45, ColorReset());
                  sparseIssues++;
                }

                // Estimated matrix size: nChannels² entries
                uint64_t estEntries = (uint64_t)nChannels * nChannels;
                const uint64_t MAX_SPARSE_ENTRIES = 16ULL * 1024 * 1024;
                if (estEntries > MAX_SPARSE_ENTRIES) {
                  printf("      %s[WARN]  Tag '%s' (smat): %u channels → %llu potential entries (limit %llu)%s\n",
                         ColorCritical(), sig45, nChannels,
                         (unsigned long long)estEntries, (unsigned long long)MAX_SPARSE_ENTRIES, ColorReset());
                  printf("       %sRisk: OOM via sparse matrix allocation (CFL patch 044)%s\n",
                         ColorCritical(), ColorReset());
                  sparseIssues++;
                } else if (nChannels > 0) {
                  printf("      [INFO]  Tag '%s' (smat): %u channels, encoding %u\n",
                         sig45, nChannels, encoding);
                }
              }
            }
          }
        }
      }
      if (fp45) fclose(fp45);

      if (sparseIssues > 0) {
        heuristicCount += sparseIssues;
      } else {
        printf("      %s[OK] Sparse matrix bounds valid (or none present)%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // =========================================================================
  // Raw-file heuristics H46-H54 (CWE-driven gap analysis from 77 CVEs)
  // All use raw file I/O — no library API calls.
  // =========================================================================

  // 46. TextDescription Unicode Length Validation (raw file bytes)
  // desc tag: type(4) + reserved(4) + ASCII_count(4) + ASCII_data(ASCII_count) +
  //           unicode_lang(4) + unicode_count(4) + unicode_data(unicode_count*2) + ...
  // CVE-2026-21491: Unicode buffer overflow in CIccTagTextDescription
  // CVE-2026-21488: OOB read + improper null termination
  // CWE-122, CWE-170, CWE-130
  printf("[H46] TextDescription Unicode Length Validation\n");
  {
    FILE *fp46 = fopen(filename, "rb");
    if (fp46) {
      fseek(fp46, 0, SEEK_END);
      long fs46_l = ftell(fp46);
      if (fs46_l < 0) { fclose(fp46); fp46 = NULL; }
      size_t fs46 = (fp46) ? (size_t)fs46_l : 0;

      int descIssues = 0;
      if (fp46 && fs46 >= 132) {
        // Read tag count
        icUInt8Number tc46[4];
        fseek(fp46, 128, SEEK_SET);
        if (fread(tc46, 1, 4, fp46) == 4) {
          uint32_t tagCount46 = ((uint32_t)tc46[0]<<24)|((uint32_t)tc46[1]<<16)|
                                ((uint32_t)tc46[2]<<8)|tc46[3];
          if (tagCount46 > 1000) tagCount46 = 1000;

          for (uint32_t t = 0; t < tagCount46 && fp46; t++) {
            icUInt8Number tagEntry[12];
            fseek(fp46, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fp46) != 12) break;

            uint32_t tSig = ((uint32_t)tagEntry[0]<<24)|((uint32_t)tagEntry[1]<<16)|
                            ((uint32_t)tagEntry[2]<<8)|tagEntry[3];
            uint32_t tOff = ((uint32_t)tagEntry[4]<<24)|((uint32_t)tagEntry[5]<<16)|
                            ((uint32_t)tagEntry[6]<<8)|tagEntry[7];
            uint32_t tSz  = ((uint32_t)tagEntry[8]<<24)|((uint32_t)tagEntry[9]<<16)|
                            ((uint32_t)tagEntry[10]<<8)|tagEntry[11];

            // desc type = 0x64657363
            if (tOff + 12 > fs46 || tSz < 12) continue;

            icUInt8Number typeSig[4];
            fseek(fp46, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fp46) != 4) continue;
            uint32_t typeVal = ((uint32_t)typeSig[0]<<24)|((uint32_t)typeSig[1]<<16)|
                               ((uint32_t)typeSig[2]<<8)|typeSig[3];
            if (typeVal != 0x64657363) continue; // not 'desc' type

            // Read ASCII count (offset +8)
            icUInt8Number ascBuf[4];
            fseek(fp46, tOff + 8, SEEK_SET);
            if (fread(ascBuf, 1, 4, fp46) != 4) continue;
            uint32_t asciiCount = ((uint32_t)ascBuf[0]<<24)|((uint32_t)ascBuf[1]<<16)|
                                  ((uint32_t)ascBuf[2]<<8)|ascBuf[3];

            // Unicode section starts at tOff + 12 + asciiCount
            uint64_t unicodeStart = (uint64_t)tOff + 12 + asciiCount;
            if (unicodeStart + 8 > fs46 || unicodeStart + 8 > (uint64_t)tOff + tSz) continue;

            icUInt8Number uniBuf[8];
            fseek(fp46, (long)unicodeStart, SEEK_SET);
            if (fread(uniBuf, 1, 8, fp46) != 8) continue;

            uint32_t unicodeLang = ((uint32_t)uniBuf[0]<<24)|((uint32_t)uniBuf[1]<<16)|
                                   ((uint32_t)uniBuf[2]<<8)|uniBuf[3];
            uint32_t unicodeCount = ((uint32_t)uniBuf[4]<<24)|((uint32_t)uniBuf[5]<<16)|
                                    ((uint32_t)uniBuf[6]<<8)|uniBuf[7];

            // Validate: unicode data = unicodeCount * 2 bytes
            uint64_t unicodeDataEnd = unicodeStart + 8 + (uint64_t)unicodeCount * 2;
            char sig46[5]; SignatureToFourCC(tSig, sig46);

            if (unicodeCount > 0 && unicodeDataEnd > (uint64_t)tOff + tSz) {
              printf("      %s[WARN]  Tag '%s' (desc): unicode count %u × 2 = %llu bytes exceeds tag bounds%s\n",
                     ColorCritical(), sig46, unicodeCount,
                     (unsigned long long)(unicodeCount * 2), ColorReset());
              printf("       %sCWE-122/CWE-170: Heap buffer overflow via unicode length (CVE-2026-21491 pattern)%s\n",
                     ColorCritical(), ColorReset());
              descIssues++;
            }

            // Check ASCII count vs tag size too
            if (asciiCount > tSz - 12) {
              printf("      %s[WARN]  Tag '%s' (desc): ASCII count %u exceeds available tag data%s\n",
                     ColorCritical(), sig46, asciiCount, ColorReset());
              descIssues++;
            }
          }
        }
      }
      if (fp46) fclose(fp46);

      if (descIssues > 0) {
        heuristicCount += descIssues;
      } else {
        printf("      %s[OK] TextDescription unicode lengths valid (or no desc tags)%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 47. NamedColor2 Size Overflow Detection (raw file bytes)
  // ncl2 tag: type(4) + reserved(4) + vendorFlag(4) + count(4) + nDeviceCoords(4) +
  //           prefix(32) + suffix(32) = 84-byte header
  //           Each entry: name(32) + PCS(6) + deviceCoords(nDeviceCoords*2)
  // CVE-2026-24406: HBO in CIccTagNamedColor2::SetSize() (CVSS 8.8)
  // CWE-122, CWE-190, CWE-787
  printf("[H47] NamedColor2 Size Overflow Detection\n");
  {
    FILE *fp47 = fopen(filename, "rb");
    if (fp47) {
      fseek(fp47, 0, SEEK_END);
      long fs47_l = ftell(fp47);
      if (fs47_l < 0) { fclose(fp47); fp47 = NULL; }
      size_t fs47 = (fp47) ? (size_t)fs47_l : 0;

      int ncl2Issues = 0;
      if (fp47 && fs47 >= 132) {
        icUInt8Number tc47[4];
        fseek(fp47, 128, SEEK_SET);
        if (fread(tc47, 1, 4, fp47) == 4) {
          uint32_t tagCount47 = ((uint32_t)tc47[0]<<24)|((uint32_t)tc47[1]<<16)|
                                ((uint32_t)tc47[2]<<8)|tc47[3];
          if (tagCount47 > 1000) tagCount47 = 1000;

          for (uint32_t t = 0; t < tagCount47 && fp47; t++) {
            icUInt8Number tagEntry[12];
            fseek(fp47, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fp47) != 12) break;

            uint32_t tSig = ((uint32_t)tagEntry[0]<<24)|((uint32_t)tagEntry[1]<<16)|
                            ((uint32_t)tagEntry[2]<<8)|tagEntry[3];
            uint32_t tOff = ((uint32_t)tagEntry[4]<<24)|((uint32_t)tagEntry[5]<<16)|
                            ((uint32_t)tagEntry[6]<<8)|tagEntry[7];
            uint32_t tSz  = ((uint32_t)tagEntry[8]<<24)|((uint32_t)tagEntry[9]<<16)|
                            ((uint32_t)tagEntry[10]<<8)|tagEntry[11];

            if (tOff + 84 > fs47 || tSz < 84) continue;

            // Read type signature
            icUInt8Number typeSig[4];
            fseek(fp47, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fp47) != 4) continue;
            uint32_t typeVal = ((uint32_t)typeSig[0]<<24)|((uint32_t)typeSig[1]<<16)|
                               ((uint32_t)typeSig[2]<<8)|typeSig[3];
            if (typeVal != 0x6E636C32) continue; // not 'ncl2' type

            // Read count and nDeviceCoords
            icUInt8Number ncl2Hdr[8];
            fseek(fp47, tOff + 16, SEEK_SET); // skip type(4)+reserved(4)+vendorFlag(4)+count starts at +16
            // Actually: type(4)+reserved(4)+vendorFlag(4) = 12, count at +12, nDeviceCoords at +16
            fseek(fp47, tOff + 12, SEEK_SET);
            if (fread(ncl2Hdr, 1, 8, fp47) != 8) continue;

            uint32_t ncl2Count = ((uint32_t)ncl2Hdr[0]<<24)|((uint32_t)ncl2Hdr[1]<<16)|
                                 ((uint32_t)ncl2Hdr[2]<<8)|ncl2Hdr[3];
            uint32_t nDevCoords = ((uint32_t)ncl2Hdr[4]<<24)|((uint32_t)ncl2Hdr[5]<<16)|
                                  ((uint32_t)ncl2Hdr[6]<<8)|ncl2Hdr[7];

            char sig47[5]; SignatureToFourCC(tSig, sig47);

            // Each entry: rootName(32) + PCS_coords(6) + deviceCoords(nDevCoords*2)
            uint64_t entrySize = 32 + 6 + (uint64_t)nDevCoords * 2;
            uint64_t totalData = (uint64_t)ncl2Count * entrySize;
            uint64_t headerSize = 84; // type(4)+reserved(4)+vendorFlag(4)+count(4)+nDevCoords(4)+prefix(32)+suffix(32)
            uint64_t neededSize = headerSize + totalData;

            if (ncl2Count > 0 && entrySize > 0 && totalData / entrySize != ncl2Count) {
              printf("      %s[WARN]  Tag '%s' (ncl2): count %u × entry_size %llu overflows uint64%s\n",
                     ColorCritical(), sig47, ncl2Count, (unsigned long long)entrySize, ColorReset());
              printf("       %sCRITICAL: CWE-190 integer overflow → HBO (CVE-2026-24406 pattern)%s\n",
                     ColorCritical(), ColorReset());
              ncl2Issues++;
            } else if (neededSize > tSz) {
              printf("      %s[WARN]  Tag '%s' (ncl2): %u entries × %llu bytes = %llu, but tag is only %u bytes%s\n",
                     ColorCritical(), sig47, ncl2Count, (unsigned long long)entrySize,
                     (unsigned long long)neededSize, tSz, ColorReset());
              printf("       %sCWE-122: Heap buffer overflow via NamedColor2 size mismatch%s\n",
                     ColorCritical(), ColorReset());
              ncl2Issues++;
            }

            if (nDevCoords > 100) {
              printf("      %s[WARN]  Tag '%s' (ncl2): nDeviceCoords = %u (suspicious, >100)%s\n",
                     ColorCritical(), sig47, nDevCoords, ColorReset());
              ncl2Issues++;
            }
          }
        }
      }
      if (fp47) fclose(fp47);

      if (ncl2Issues > 0) {
        heuristicCount += ncl2Issues;
      } else {
        printf("      %s[OK] NamedColor2 sizes valid (or no ncl2 tags)%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 48. CLUT Grid Dimension Product Overflow (raw file bytes)
  // mAB/mBA (mft2): type(4)+reserved(4)+nInput(1)+nOutput(1)+pad(2)+offsets... CLUT grid at CLUT_offset
  // mft1 (lut8): type(4)+reserved(4)+nInput(1)+nOutput(1)+gridPoints(1)+pad(1)+matrix(36)+...
  // mft2 (lut16): type(4)+reserved(4)+nInput(1)+nOutput(1)+gridPoints(1)+pad(1)+matrix(36)+...
  // Grid product = gridPoints^nInput × nOutput — must not overflow
  // CVE-2026-22255: HBO in CIccCLUT::Init() (CVSS 8.8)
  // CVE-2026-21677: UB in CIccCLUT::Init() (CVSS 8.8)
  // CWE-131, CWE-190, CWE-400
  printf("[H48] CLUT Grid Dimension Product Overflow\n");
  {
    FILE *fp48 = fopen(filename, "rb");
    if (fp48) {
      fseek(fp48, 0, SEEK_END);
      long fs48_l = ftell(fp48);
      if (fs48_l < 0) { fclose(fp48); fp48 = NULL; }
      size_t fs48 = (fp48) ? (size_t)fs48_l : 0;

      int clutOvfIssues = 0;
      if (fp48 && fs48 >= 132) {
        icUInt8Number tc48[4];
        fseek(fp48, 128, SEEK_SET);
        if (fread(tc48, 1, 4, fp48) == 4) {
          uint32_t tagCount48 = ((uint32_t)tc48[0]<<24)|((uint32_t)tc48[1]<<16)|
                                ((uint32_t)tc48[2]<<8)|tc48[3];
          if (tagCount48 > 1000) tagCount48 = 1000;

          for (uint32_t t = 0; t < tagCount48 && fp48; t++) {
            icUInt8Number tagEntry[12];
            fseek(fp48, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fp48) != 12) break;

            uint32_t tSig = ((uint32_t)tagEntry[0]<<24)|((uint32_t)tagEntry[1]<<16)|
                            ((uint32_t)tagEntry[2]<<8)|tagEntry[3];
            uint32_t tOff = ((uint32_t)tagEntry[4]<<24)|((uint32_t)tagEntry[5]<<16)|
                            ((uint32_t)tagEntry[6]<<8)|tagEntry[7];
            uint32_t tSz  = ((uint32_t)tagEntry[8]<<24)|((uint32_t)tagEntry[9]<<16)|
                            ((uint32_t)tagEntry[10]<<8)|tagEntry[11];

            if (tOff + 12 > fs48 || tSz < 12) continue;

            icUInt8Number typeSig[4];
            fseek(fp48, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fp48) != 4) continue;
            uint32_t typeVal = ((uint32_t)typeSig[0]<<24)|((uint32_t)typeSig[1]<<16)|
                               ((uint32_t)typeSig[2]<<8)|typeSig[3];

            char sig48[5]; SignatureToFourCC(tSig, sig48);

            // lut8 (0x6D667431) and lut16 (0x6D667432): uniform grid
            if (typeVal == 0x6D667431 || typeVal == 0x6D667432) {
              if (tOff + 12 > fs48) continue;
              icUInt8Number lutHdr[4];
              fseek(fp48, tOff + 8, SEEK_SET);
              if (fread(lutHdr, 1, 4, fp48) != 4) continue;

              uint8_t nInput = lutHdr[0];
              uint8_t nOutput = lutHdr[1];
              uint8_t gridPts = lutHdr[2];

              if (nInput > 0 && gridPts > 0 && nOutput > 0) {
                // Product = gridPts^nInput × nOutput
                uint64_t product = 1;
                bool overflow = false;
                for (int d = 0; d < nInput; d++) {
                  product *= gridPts;
                  if (product > 256ULL * 1024 * 1024) { overflow = true; break; }
                }
                if (!overflow) product *= nOutput;
                if (product > 256ULL * 1024 * 1024) overflow = true;

                if (overflow) {
                  printf("      %s[WARN]  Tag '%s' (%s): grid %u^%u × %u output = overflow%s\n",
                         ColorCritical(), sig48,
                         (typeVal == 0x6D667431) ? "lut8" : "lut16",
                         gridPts, nInput, nOutput, ColorReset());
                  printf("       %sCRITICAL: CWE-131/CWE-190 CLUT allocation overflow (CVE-2026-22255 pattern)%s\n",
                         ColorCritical(), ColorReset());
                  clutOvfIssues++;
                }
              }
            }

            // mAB (0x6D414220) / mBA (0x6D424120): per-dimension grid points in CLUT sub-element
            if (typeVal == 0x6D414220 || typeVal == 0x6D424120) {
              if (tOff + 32 > fs48) continue;
              icUInt8Number mbaHdr[24];
              fseek(fp48, tOff + 8, SEEK_SET);
              if (fread(mbaHdr, 1, 24, fp48) != 24) continue;

              uint8_t nInput = mbaHdr[0];
              uint8_t nOutput = mbaHdr[1];
              // CLUT offset is at +20 in the header (bytes 12-15 relative to mbaHdr start)
              uint32_t clutOff = ((uint32_t)mbaHdr[12]<<24)|((uint32_t)mbaHdr[13]<<16)|
                                 ((uint32_t)mbaHdr[14]<<8)|mbaHdr[15];

              if (clutOff > 0 && clutOff < tSz && tOff + clutOff + 16 <= fs48 && nInput <= 16) {
                // CLUT sub-element: 16 bytes of grid dimensions (1 per input channel)
                icUInt8Number gridDims[16];
                fseek(fp48, tOff + clutOff, SEEK_SET);
                if (fread(gridDims, 1, 16, fp48) == 16) {
                  uint64_t product = 1;
                  bool overflow = false;
                  bool hasZeroDim = false;
                  for (int d = 0; d < nInput; d++) {
                    if (gridDims[d] == 0) { hasZeroDim = true; break; }
                    product *= gridDims[d];
                    if (product > 256ULL * 1024 * 1024) { overflow = true; break; }
                  }
                  if (!overflow && !hasZeroDim && nOutput > 0) {
                    product *= nOutput;
                    if (product > 256ULL * 1024 * 1024) overflow = true;
                  }

                  if (overflow) {
                    printf("      %s[WARN]  Tag '%s' (%s): CLUT grid product overflows (>256M entries)%s\n",
                           ColorCritical(), sig48,
                           (typeVal == 0x6D414220) ? "mAB" : "mBA", ColorReset());
                    printf("       %sCRITICAL: CWE-131/CWE-190 CLUT allocation overflow (CVE-2026-22255 pattern)%s\n",
                           ColorCritical(), ColorReset());
                    clutOvfIssues++;
                  }
                  // hasZeroDim is checked in H54
                }
              }
            }
          }
        }
      }
      if (fp48) fclose(fp48);

      if (clutOvfIssues > 0) {
        heuristicCount += clutOvfIssues;
      } else {
        printf("      %s[OK] CLUT grid dimension products within bounds%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 49. Float/s15Fixed16 NaN/Inf Detection (raw file bytes)
  // Scan XYZ (0x58595A20), sf32 (0x73663332), fl32 (0x666C3332) tag data
  // for IEEE 754 NaN (exponent=0xFF, mantissa≠0) and Inf (exponent=0xFF, mantissa=0)
  // CVE-2026-21681: UB runtime error: nan is outside the range (CVSS 7.1)
  // CWE-758, CWE-682
  printf("[H49] Float/s15Fixed16 NaN/Inf Detection\n");
  {
    FILE *fp49 = fopen(filename, "rb");
    if (fp49) {
      fseek(fp49, 0, SEEK_END);
      long fs49_l = ftell(fp49);
      if (fs49_l < 0) { fclose(fp49); fp49 = NULL; }
      size_t fs49 = (fp49) ? (size_t)fs49_l : 0;

      int nanInfIssues = 0;
      if (fp49 && fs49 >= 132) {
        icUInt8Number tc49[4];
        fseek(fp49, 128, SEEK_SET);
        if (fread(tc49, 1, 4, fp49) == 4) {
          uint32_t tagCount49 = ((uint32_t)tc49[0]<<24)|((uint32_t)tc49[1]<<16)|
                                ((uint32_t)tc49[2]<<8)|tc49[3];
          if (tagCount49 > 1000) tagCount49 = 1000;

          for (uint32_t t = 0; t < tagCount49 && fp49; t++) {
            icUInt8Number tagEntry[12];
            fseek(fp49, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fp49) != 12) break;

            uint32_t tSig = ((uint32_t)tagEntry[0]<<24)|((uint32_t)tagEntry[1]<<16)|
                            ((uint32_t)tagEntry[2]<<8)|tagEntry[3];
            uint32_t tOff = ((uint32_t)tagEntry[4]<<24)|((uint32_t)tagEntry[5]<<16)|
                            ((uint32_t)tagEntry[6]<<8)|tagEntry[7];
            uint32_t tSz  = ((uint32_t)tagEntry[8]<<24)|((uint32_t)tagEntry[9]<<16)|
                            ((uint32_t)tagEntry[10]<<8)|tagEntry[11];

            if (tOff + 8 > fs49 || tSz < 8) continue;

            icUInt8Number typeSig[4];
            fseek(fp49, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fp49) != 4) continue;
            uint32_t typeVal = ((uint32_t)typeSig[0]<<24)|((uint32_t)typeSig[1]<<16)|
                               ((uint32_t)typeSig[2]<<8)|typeSig[3];

            // fl32 (0x666C3332): IEEE 754 float array
            // sf32 (0x73663332): s15Fixed16 array (check for 0x7FFFFFFF/0x80000000 extremes)
            // XYZ (0x58595A20): 3 × s15Fixed16 values
            bool isFloat = (typeVal == 0x666C3332);
            bool isSf32  = (typeVal == 0x73663332);
            bool isXYZ   = (typeVal == 0x58595A20);
            if (!isFloat && !isSf32 && !isXYZ) continue;

            char sig49[5]; SignatureToFourCC(tSig, sig49);

            // Scan data portion (after type + reserved = 8 bytes)
            size_t dataStart = tOff + 8;
            size_t dataEnd = (size_t)tOff + tSz;
            if (dataEnd > fs49) dataEnd = fs49;
            size_t maxScan = 4096; // limit scan to first 4KB of data
            if (dataEnd - dataStart > maxScan) dataEnd = dataStart + maxScan;

            fseek(fp49, dataStart, SEEK_SET);
            for (size_t pos = dataStart; pos + 4 <= dataEnd; pos += 4) {
              icUInt8Number val4[4];
              if (fread(val4, 1, 4, fp49) != 4) break;

              if (isFloat) {
                // IEEE 754: exponent bits [30:23]
                uint8_t exponent = ((val4[0] & 0x7F) << 1) | ((val4[1] >> 7) & 0x01);
                uint32_t mantissa = (((uint32_t)val4[1] & 0x7F) << 16) |
                                    ((uint32_t)val4[2] << 8) | val4[3];
                if (exponent == 0xFF) {
                  const char *kind = (mantissa == 0) ? "Inf" : "NaN";
                  printf("      %s[WARN]  Tag '%s' (fl32): %s detected at offset +%zu%s\n",
                         ColorCritical(), sig49, kind, pos - tOff, ColorReset());
                  printf("       %sCWE-758: Undefined behavior when converting %s to integer (CVE-2026-21681)%s\n",
                         ColorCritical(), kind, ColorReset());
                  nanInfIssues++;
                  break; // one warning per tag is enough
                }
              } else {
                // s15Fixed16: check for extreme sentinel values
                uint32_t fixVal = ((uint32_t)val4[0]<<24)|((uint32_t)val4[1]<<16)|
                                  ((uint32_t)val4[2]<<8)|val4[3];
                if (fixVal == 0x7FFFFFFF || fixVal == 0x80000000) {
                  printf("      %s[WARN]  Tag '%s': s15Fixed16 extreme value 0x%08X at offset +%zu%s\n",
                         ColorCritical(), sig49, fixVal, pos - tOff, ColorReset());
                  printf("       %sCWE-758: Potential undefined behavior in fixed-point conversion%s\n",
                         ColorCritical(), ColorReset());
                  nanInfIssues++;
                  break;
                }
              }
            }
          }
        }
      }
      if (fp49) fclose(fp49);

      if (nanInfIssues > 0) {
        heuristicCount += nanInfIssues;
      } else {
        printf("      %s[OK] No NaN/Inf/extreme values in float/fixed-point tags%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 50. Profile Size Zero / Zero-Size Tag Detection (raw file bytes)
  // CVE-2026-21507: Infinite loop in CalcProfileID() when profile size = 0 (CVSS 7.5)
  // Also: any tag with size = 0 may cause div-by-zero or infinite loops in parsers
  // CWE-835, CWE-369
  printf("[H50] Zero-Size Profile/Tag Detection (Infinite Loop)\n");
  {
    FILE *fp50 = fopen(filename, "rb");
    if (fp50) {
      fseek(fp50, 0, SEEK_END);
      long fs50_l = ftell(fp50);
      if (fs50_l < 0) { fclose(fp50); fp50 = NULL; }
      size_t fs50 = (fp50) ? (size_t)fs50_l : 0;

      int zeroIssues = 0;
      if (fp50 && fs50 >= 132) {
        // Check profile size field (bytes 0-3)
        icUInt8Number psz[4];
        fseek(fp50, 0, SEEK_SET);
        if (fread(psz, 1, 4, fp50) == 4) {
          uint32_t profileSize = ((uint32_t)psz[0]<<24)|((uint32_t)psz[1]<<16)|
                                 ((uint32_t)psz[2]<<8)|psz[3];
          if (profileSize == 0) {
            printf("      %s[WARN]  Profile size field = 0%s\n", ColorCritical(), ColorReset());
            printf("       %sCRITICAL: CWE-835 infinite loop in CalcProfileID() (CVE-2026-21507)%s\n",
                   ColorCritical(), ColorReset());
            zeroIssues++;
          }
        }

        // Check for zero-size tags
        icUInt8Number tc50[4];
        fseek(fp50, 128, SEEK_SET);
        if (fread(tc50, 1, 4, fp50) == 4) {
          uint32_t tagCount50 = ((uint32_t)tc50[0]<<24)|((uint32_t)tc50[1]<<16)|
                                ((uint32_t)tc50[2]<<8)|tc50[3];
          if (tagCount50 > 1000) tagCount50 = 1000;

          int zeroSizeTags = 0;
          for (uint32_t t = 0; t < tagCount50 && fp50; t++) {
            icUInt8Number tagEntry[12];
            fseek(fp50, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fp50) != 12) break;

            uint32_t tSig = ((uint32_t)tagEntry[0]<<24)|((uint32_t)tagEntry[1]<<16)|
                            ((uint32_t)tagEntry[2]<<8)|tagEntry[3];
            uint32_t tSz  = ((uint32_t)tagEntry[8]<<24)|((uint32_t)tagEntry[9]<<16)|
                            ((uint32_t)tagEntry[10]<<8)|tagEntry[11];

            if (tSz == 0) {
              char sig50[5]; SignatureToFourCC(tSig, sig50);
              printf("      %s[WARN]  Tag '%s': size = 0 (may cause infinite loop or div-by-zero)%s\n",
                     ColorCritical(), sig50, ColorReset());
              zeroSizeTags++;
            }
          }
          if (zeroSizeTags > 0) {
            zeroIssues += zeroSizeTags;
          }
        }
      }
      if (fp50) fclose(fp50);

      if (zeroIssues > 0) {
        heuristicCount += zeroIssues;
      } else {
        printf("      %s[OK] No zero-size profile or tags detected%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 51. LUT I/O Channel Count Consistency (raw file bytes)
  // lut8 (mft1) and lut16 (mft2): inputChan at +8, outputChan at +9
  // These must match the profile's colorSpace (input) and PCS (output) channel counts.
  // Off-by-one in these causes HBO during Validate().
  // CVE-2026-21490: HBO in CIccTagLut16::Validate() (off-by-one)
  // CVE-2026-21494: HBO in CIccTagLut8::Validate() (off-by-one)
  // CWE-193, CWE-122
  printf("[H51] LUT I/O Channel Count Consistency\n");
  {
    FILE *fp51 = fopen(filename, "rb");
    if (fp51) {
      fseek(fp51, 0, SEEK_END);
      long fs51_l = ftell(fp51);
      if (fs51_l < 0) { fclose(fp51); fp51 = NULL; }
      size_t fs51 = (fp51) ? (size_t)fs51_l : 0;

      int lutChanIssues = 0;
      if (fp51 && fs51 >= 132) {
        icUInt8Number tc51[4];
        fseek(fp51, 128, SEEK_SET);
        if (fread(tc51, 1, 4, fp51) == 4) {
          uint32_t tagCount51 = ((uint32_t)tc51[0]<<24)|((uint32_t)tc51[1]<<16)|
                                ((uint32_t)tc51[2]<<8)|tc51[3];
          if (tagCount51 > 1000) tagCount51 = 1000;

          for (uint32_t t = 0; t < tagCount51 && fp51; t++) {
            icUInt8Number tagEntry[12];
            fseek(fp51, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fp51) != 12) break;

            uint32_t tSig = ((uint32_t)tagEntry[0]<<24)|((uint32_t)tagEntry[1]<<16)|
                            ((uint32_t)tagEntry[2]<<8)|tagEntry[3];
            uint32_t tOff = ((uint32_t)tagEntry[4]<<24)|((uint32_t)tagEntry[5]<<16)|
                            ((uint32_t)tagEntry[6]<<8)|tagEntry[7];
            uint32_t tSz  = ((uint32_t)tagEntry[8]<<24)|((uint32_t)tagEntry[9]<<16)|
                            ((uint32_t)tagEntry[10]<<8)|tagEntry[11];

            if (tOff + 12 > fs51 || tSz < 12) continue;

            icUInt8Number typeSig[4];
            fseek(fp51, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fp51) != 4) continue;
            uint32_t typeVal = ((uint32_t)typeSig[0]<<24)|((uint32_t)typeSig[1]<<16)|
                               ((uint32_t)typeSig[2]<<8)|typeSig[3];

            // mft1 (lut8) or mft2 (lut16) or mAB or mBA
            bool isLut8  = (typeVal == 0x6D667431);
            bool isLut16 = (typeVal == 0x6D667432);
            bool isMab   = (typeVal == 0x6D414220 || typeVal == 0x6D424120);
            if (!isLut8 && !isLut16 && !isMab) continue;

            icUInt8Number chanHdr[2];
            fseek(fp51, tOff + 8, SEEK_SET);
            if (fread(chanHdr, 1, 2, fp51) != 2) continue;

            uint8_t nInput = chanHdr[0];
            uint8_t nOutput = chanHdr[1];
            char sig51[5]; SignatureToFourCC(tSig, sig51);

            // Sanity limits: ICC spec allows max 16 input channels, 16 output
            if (nInput == 0 || nOutput == 0) {
              printf("      %s[WARN]  Tag '%s': %s has zero %s channels%s\n",
                     ColorCritical(), sig51,
                     isLut8 ? "lut8" : isLut16 ? "lut16" : "mAB/mBA",
                     (nInput == 0) ? "input" : "output", ColorReset());
              printf("       %sCWE-193: Off-by-one/zero channel count → HBO in Validate() (CVE-2026-21490)%s\n",
                     ColorCritical(), ColorReset());
              lutChanIssues++;
            } else if (nInput > 16 || nOutput > 16) {
              printf("      %s[WARN]  Tag '%s': %s has %u input, %u output channels (max 16)%s\n",
                     ColorCritical(), sig51,
                     isLut8 ? "lut8" : isLut16 ? "lut16" : "mAB/mBA",
                     nInput, nOutput, ColorReset());
              printf("       %sCWE-122: Excessive channel count → potential buffer overflow%s\n",
                     ColorCritical(), ColorReset());
              lutChanIssues++;
            }
          }
        }
      }
      if (fp51) fclose(fp51);

      if (lutChanIssues > 0) {
        heuristicCount += lutChanIssues;
      } else {
        printf("      %s[OK] LUT I/O channel counts within valid range%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 52. Integer Underflow in Tag Size Subtraction (raw file bytes)
  // Tags have minimum header sizes: desc=12, curv=12, text=8, XYZ=20, mluc=16, ncl2=84
  // When tag_size < minimum_header, subtraction (tag_size - header) wraps negative as uint
  // CVE-2026-21489: OOB Read + Integer Underflow
  // CWE-191, CWE-125
  printf("[H52] Integer Underflow in Tag Size Subtraction\n");
  {
    FILE *fp52 = fopen(filename, "rb");
    if (fp52) {
      fseek(fp52, 0, SEEK_END);
      long fs52_l = ftell(fp52);
      if (fs52_l < 0) { fclose(fp52); fp52 = NULL; }
      size_t fs52 = (fp52) ? (size_t)fs52_l : 0;

      int underflowIssues = 0;
      if (fp52 && fs52 >= 132) {
        icUInt8Number tc52[4];
        fseek(fp52, 128, SEEK_SET);
        if (fread(tc52, 1, 4, fp52) == 4) {
          uint32_t tagCount52 = ((uint32_t)tc52[0]<<24)|((uint32_t)tc52[1]<<16)|
                                ((uint32_t)tc52[2]<<8)|tc52[3];
          if (tagCount52 > 1000) tagCount52 = 1000;

          for (uint32_t t = 0; t < tagCount52 && fp52; t++) {
            icUInt8Number tagEntry[12];
            fseek(fp52, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fp52) != 12) break;

            uint32_t tSig = ((uint32_t)tagEntry[0]<<24)|((uint32_t)tagEntry[1]<<16)|
                            ((uint32_t)tagEntry[2]<<8)|tagEntry[3];
            uint32_t tOff = ((uint32_t)tagEntry[4]<<24)|((uint32_t)tagEntry[5]<<16)|
                            ((uint32_t)tagEntry[6]<<8)|tagEntry[7];
            uint32_t tSz  = ((uint32_t)tagEntry[8]<<24)|((uint32_t)tagEntry[9]<<16)|
                            ((uint32_t)tagEntry[10]<<8)|tagEntry[11];

            if (tOff + 4 > fs52 || tSz < 4) continue;

            icUInt8Number typeSig[4];
            fseek(fp52, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fp52) != 4) continue;
            uint32_t typeVal = ((uint32_t)typeSig[0]<<24)|((uint32_t)typeSig[1]<<16)|
                               ((uint32_t)typeSig[2]<<8)|typeSig[3];

            // Minimum sizes by type
            uint32_t minSize = 8; // default: type(4) + reserved(4)
            if (typeVal == 0x64657363) minSize = 12;      // desc: +count(4)
            else if (typeVal == 0x63757276) minSize = 12;  // curv: +count(4)
            else if (typeVal == 0x58595A20) minSize = 20;  // XYZ: +X(4)+Y(4)+Z(4)
            else if (typeVal == 0x6D6C7563) minSize = 16;  // mluc: +count(4)+recSize(4)
            else if (typeVal == 0x6E636C32) minSize = 84;  // ncl2: full header
            else if (typeVal == 0x6D667431) minSize = 48;  // lut8: header+matrix
            else if (typeVal == 0x6D667432) minSize = 52;  // lut16: header+matrix+in/outTableEntries
            else if (typeVal == 0x6D414220 || typeVal == 0x6D424120) minSize = 32; // mAB/mBA
            else if (typeVal == 0x70617261) minSize = 12;  // para: +funcType(2)+reserved(2)
            else if (typeVal == 0x73663332) minSize = 12;  // sf32: at least one value
            else if (typeVal == 0x666C3332) minSize = 12;  // fl32: at least one value

            if (tSz > 0 && tSz < minSize) {
              char sig52[5]; SignatureToFourCC(tSig, sig52);
              char type52[5]; SignatureToFourCC(typeVal, type52);
              printf("      %s[WARN]  Tag '%s' (type '%s'): size %u < minimum %u bytes%s\n",
                     ColorCritical(), sig52, type52, tSz, minSize, ColorReset());
              printf("       %sCWE-191: size - header underflows → OOB read (CVE-2026-21489 pattern)%s\n",
                     ColorCritical(), ColorReset());
              underflowIssues++;
            }
          }
        }
      }
      if (fp52) fclose(fp52);

      if (underflowIssues > 0) {
        heuristicCount += underflowIssues;
      } else {
        printf("      %s[OK] All tag sizes meet minimum requirements%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 53. Embedded Profile Recursion Detection (raw file bytes)
  // Scan profile data for 'acsp' magic (0x61637370) at offset 36 within embedded data,
  // indicating nested ICC profiles that could trigger recursive parsing → stack overflow/UAF
  // CWE-674, CWE-416
  printf("[H53] Embedded Profile Recursion Detection\n");
  {
    FILE *fp53 = fopen(filename, "rb");
    if (fp53) {
      fseek(fp53, 0, SEEK_END);
      long fs53_l = ftell(fp53);
      if (fs53_l < 0) { fclose(fp53); fp53 = NULL; }
      size_t fs53 = (fp53) ? (size_t)fs53_l : 0;

      int recursionIssues = 0;
      if (fp53 && fs53 >= 132) {
        // The main profile has 'acsp' at offset 36. Search for additional 'acsp' signatures
        // at positions > 128 (inside tag data) that could indicate embedded profiles.
        // Look for the pattern: at position P, bytes P-36..P form a plausible profile header
        // Simpler: just scan for 0x61637370 at any 4-byte-aligned position after the tag table
        icUInt8Number tc53[4];
        fseek(fp53, 128, SEEK_SET);
        if (fread(tc53, 1, 4, fp53) == 4) {
          uint32_t tagCount53 = ((uint32_t)tc53[0]<<24)|((uint32_t)tc53[1]<<16)|
                                ((uint32_t)tc53[2]<<8)|tc53[3];
          if (tagCount53 > 1000) tagCount53 = 1000;
          size_t tagTableEnd = 132 + tagCount53 * 12;

          // Scan tag data area for 'acsp' magic
          size_t scanLimit = fs53;
          if (scanLimit > 1024 * 1024) scanLimit = 1024 * 1024; // limit to first 1MB
          int embeddedCount = 0;

          fseek(fp53, tagTableEnd, SEEK_SET);
          for (size_t pos = tagTableEnd; pos + 40 <= scanLimit; pos += 4) {
            icUInt8Number scanBuf[40];
            fseek(fp53, pos, SEEK_SET);
            if (fread(scanBuf, 1, 40, fp53) != 40) break;

            // Check for 'acsp' at byte 36 of a potential embedded profile header
            uint32_t magic = ((uint32_t)scanBuf[36]<<24)|((uint32_t)scanBuf[37]<<16)|
                             ((uint32_t)scanBuf[38]<<8)|scanBuf[39];
            if (magic == 0x61637370) {
              // Verify it looks like a profile (has plausible size field)
              uint32_t embSize = ((uint32_t)scanBuf[0]<<24)|((uint32_t)scanBuf[1]<<16)|
                                 ((uint32_t)scanBuf[2]<<8)|scanBuf[3];
              if (embSize >= 128 && embSize <= 64 * 1024 * 1024) {
                embeddedCount++;
                if (embeddedCount <= 3) {
                  printf("      %s[WARN]  Embedded ICC profile detected at offset %zu (size %u)%s\n",
                         ColorCritical(), pos, embSize, ColorReset());
                }
              }
            }
          }
          if (embeddedCount > 0) {
            printf("       %sCWE-674: %d embedded profile(s) — recursive parsing risk (UAF/stack overflow)%s\n",
                   ColorCritical(), embeddedCount, ColorReset());
            recursionIssues += embeddedCount;
          }
        }
      }
      if (fp53) fclose(fp53);

      if (recursionIssues > 0) {
        heuristicCount += recursionIssues;
      } else {
        printf("      %s[OK] No embedded profiles detected%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  // 54. Division-by-Zero Trigger Detection (raw file bytes)
  // Check for structural values that cause division by zero in parsers:
  // - CLUT grid dimension = 0 in any channel (mAB/mBA/lut8/lut16)
  // - Spectral step = 0 (partially covered in H43, reinforced here)
  // - curv with count = 1 (identity) is valid, but count field itself = 0 with data is suspicious
  // CVE-2026-21495: Division by Zero in iccDEV TIFF Image Reader
  // CWE-369
  printf("[H54] Division-by-Zero Trigger Detection\n");
  {
    FILE *fp54 = fopen(filename, "rb");
    if (fp54) {
      fseek(fp54, 0, SEEK_END);
      long fs54_l = ftell(fp54);
      if (fs54_l < 0) { fclose(fp54); fp54 = NULL; }
      size_t fs54 = (fp54) ? (size_t)fs54_l : 0;

      int divZeroIssues = 0;
      if (fp54 && fs54 >= 132) {
        icUInt8Number tc54[4];
        fseek(fp54, 128, SEEK_SET);
        if (fread(tc54, 1, 4, fp54) == 4) {
          uint32_t tagCount54 = ((uint32_t)tc54[0]<<24)|((uint32_t)tc54[1]<<16)|
                                ((uint32_t)tc54[2]<<8)|tc54[3];
          if (tagCount54 > 1000) tagCount54 = 1000;

          for (uint32_t t = 0; t < tagCount54 && fp54; t++) {
            icUInt8Number tagEntry[12];
            fseek(fp54, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fp54) != 12) break;

            uint32_t tSig = ((uint32_t)tagEntry[0]<<24)|((uint32_t)tagEntry[1]<<16)|
                            ((uint32_t)tagEntry[2]<<8)|tagEntry[3];
            uint32_t tOff = ((uint32_t)tagEntry[4]<<24)|((uint32_t)tagEntry[5]<<16)|
                            ((uint32_t)tagEntry[6]<<8)|tagEntry[7];
            uint32_t tSz  = ((uint32_t)tagEntry[8]<<24)|((uint32_t)tagEntry[9]<<16)|
                            ((uint32_t)tagEntry[10]<<8)|tagEntry[11];

            if (tOff + 12 > fs54 || tSz < 12) continue;

            icUInt8Number typeSig[4];
            fseek(fp54, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fp54) != 4) continue;
            uint32_t typeVal = ((uint32_t)typeSig[0]<<24)|((uint32_t)typeSig[1]<<16)|
                               ((uint32_t)typeSig[2]<<8)|typeSig[3];

            char sig54[5]; SignatureToFourCC(tSig, sig54);

            // lut8/lut16: gridPoints at +10 must be > 0
            if (typeVal == 0x6D667431 || typeVal == 0x6D667432) {
              icUInt8Number lutInfo[4];
              fseek(fp54, tOff + 8, SEEK_SET);
              if (fread(lutInfo, 1, 4, fp54) == 4) {
                uint8_t gridPts = lutInfo[2];
                if (gridPts == 0 && lutInfo[0] > 0) {
                  printf("      %s[WARN]  Tag '%s' (%s): gridPoints = 0 with %u input channels%s\n",
                         ColorCritical(), sig54,
                         (typeVal == 0x6D667431) ? "lut8" : "lut16",
                         lutInfo[0], ColorReset());
                  printf("       %sCWE-369: Division by zero in CLUT interpolation%s\n",
                         ColorCritical(), ColorReset());
                  divZeroIssues++;
                }
              }
            }

            // mAB/mBA: CLUT sub-element grid dimensions
            if (typeVal == 0x6D414220 || typeVal == 0x6D424120) {
              if (tOff + 32 > fs54) continue;
              icUInt8Number mbaInfo[24];
              fseek(fp54, tOff + 8, SEEK_SET);
              if (fread(mbaInfo, 1, 24, fp54) != 24) continue;

              uint8_t nInput = mbaInfo[0];
              uint32_t clutOff = ((uint32_t)mbaInfo[12]<<24)|((uint32_t)mbaInfo[13]<<16)|
                                 ((uint32_t)mbaInfo[14]<<8)|mbaInfo[15];

              if (clutOff > 0 && clutOff < tSz && tOff + clutOff + 16 <= fs54 && nInput > 0 && nInput <= 16) {
                icUInt8Number gridDims[16];
                fseek(fp54, tOff + clutOff, SEEK_SET);
                if (fread(gridDims, 1, 16, fp54) == 16) {
                  for (int d = 0; d < nInput; d++) {
                    if (gridDims[d] == 0) {
                      printf("      %s[WARN]  Tag '%s' (%s): CLUT grid dimension[%d] = 0%s\n",
                             ColorCritical(), sig54,
                             (typeVal == 0x6D414220) ? "mAB" : "mBA",
                             d, ColorReset());
                      printf("       %sCWE-369: Division by zero in CLUT interpolation%s\n",
                             ColorCritical(), ColorReset());
                      divZeroIssues++;
                      break;
                    }
                  }
                }
              }
            }
          }
        }
      }
      if (fp54) fclose(fp54);

      if (divZeroIssues > 0) {
        heuristicCount += divZeroIssues;
      } else {
        printf("      %s[OK] No division-by-zero triggers detected%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

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
    printf("  %s- Type confusion / buffer overflow patterns%s\n", ColorWarning(), ColorReset());
    printf("\n");
    printf("  %s- Sub-element offset OOB (mBA/mAB SIGBUS pattern)%s\n", ColorWarning(), ColorReset());
    printf("  %s- 32-bit integer overflow in bounds checks%s\n", ColorWarning(), ColorReset());
    printf("  %s- Suspicious fill patterns enabling OOB traversal%s\n", ColorWarning(), ColorReset());
    printf("\n");
    printf("  %sCVE Coverage: 54 heuristics covering patterns from 77+ iccDEV/RefIccMAX CVEs%s\n", ColorInfo(), ColorReset());
    printf("  %sKey CVE categories: HBO, OOB, OOM, UAF, SBO, type confusion, integer overflow%s\n", ColorInfo(), ColorReset());
    printf("  %sH33-H36: mBA/mAB structural analysis (OOB offsets, integer overflow, fill patterns)%s\n", ColorInfo(), ColorReset());
    printf("  %sH37-H45: CFL fuzzer dictionary analysis (calc, curves, v5, BRDF, sparse matrix)%s\n", ColorInfo(), ColorReset());
    printf("  %sH46-H54: CWE-driven gap analysis (unicode HBO, ncl2 overflow, CLUT grid, NaN/Inf, recursion)%s\n", ColorInfo(), ColorReset());
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
