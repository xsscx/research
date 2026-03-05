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
#include "IccAnalyzerHeuristicTypes.h"
#include "IccHeuristicsRawPost.h"
#include "IccHeuristicsLibrary.h"

#include "IccAnalyzerSafeArithmetic.h"
#include "IccAnalyzerColors.h"
#include "IccTagBasic.h"
#include "IccTagComposite.h"
#include "IccTagDict.h"
#include "IccProfile.h"
#include "IccMpeBasic.h"
#include "IccMpeCalc.h"
#include "IccTagMPE.h"
#include "IccTagLut.h"
#include <cmath>
#include <map>
#include <set>
#include <vector>

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
  bool libraryAnalyzed = false;
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
  
  // kCriticalHeuristicThreshold defined in IccAnalyzerHeuristicTypes.h

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
  // Appended data: file is larger than declared profile size
  if (actualFileSize > 0 && profileSize > 0 && actualFileSize > profileSize + 3) {
    size_t extraBytes = actualFileSize - profileSize;
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
    libraryAnalyzed = true;
    printf("=======================================================================\n");
    printf("TAG-LEVEL HEURISTICS\n");
    printf("=======================================================================\n\n");
    
    // Library-API heuristics (H9-H32, H56-H86)
    // Extracted to IccHeuristicsLibrary.cpp
    heuristicCount += RunLibraryAPIHeuristics(pIcc, filename);

    delete pIcc;
  }
  } // end of critical-threshold gate

  // Raw-file fallback engine (H10, H13, H25, H28, H32 when library fails)
  // Extracted to IccHeuristicsRawPost.cpp
  heuristicCount += RunRawFallbackHeuristics(filename, libraryAnalyzed);
  // Post-library raw-file heuristics (H33-H55, H57, H59, H68-H69)
  // Extracted to IccHeuristicsRawPost.cpp
  heuristicCount += RunRawPostLibraryHeuristics(filename);

  // Summary
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
    printf("  %sCVE Coverage: 86 heuristics covering patterns from 77+ iccDEV/RefIccMAX CVEs%s\n", ColorInfo(), ColorReset());
    printf("  %sKey CVE categories: HBO, OOB, OOM, UAF, SBO, type confusion, integer overflow%s\n", ColorInfo(), ColorReset());
    printf("  %sH33-H36: mBA/mAB structural analysis (OOB offsets, integer overflow, fill patterns)%s\n", ColorInfo(), ColorReset());
    printf("  %sH37-H45: CFL fuzzer dictionary analysis (calc, curves, v5, BRDF, sparse matrix)%s\n", ColorInfo(), ColorReset());
    printf("  %sH46-H54: CWE-driven gap analysis (unicode HBO, ncl2 overflow, CLUT grid, NaN/Inf, recursion)%s\n", ColorInfo(), ColorReset());
    printf("  %sH55-H60: UTF-16, calc depth, embedded profiles, spectral, dict%s\n", ColorInfo(), ColorReset());
    printf("  %sH61-H70: Viewing conditions, mluc bombs, LUT channels, NamedColor2, chromaticity,%s\n", ColorInfo(), ColorReset());
    printf("  %s         NumArray NaN/Inf, ResponseCurveSet, GBD overflow, Profile ID, measurement%s\n", ColorInfo(), ColorReset());
    printf("  %sH71-H78: ColorantTable null-term, SparseMatrix, nesting depth, type confusion,%s\n", ColorInfo(), ColorReset());
    printf("  %s         small tags, data flags, calculator sub-elements, CLUT grid overflow%s\n", ColorInfo(), ColorReset());
    printf("  %sH79-H86: LoadTag overflow, UAF shared pointers, MPE channel consistency,%s\n", ColorInfo(), ColorReset());
    printf("  %s         I/O bit-shift overflow, float array SBO, 3D LUT OOB, memcpy overlap, mluc HBO%s\n", ColorInfo(), ColorReset());
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

// Path validation, sanitization, and binary database format utilities
// are now in IccAnalyzerPathValidation.cpp
