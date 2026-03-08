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
#include "IccHeuristicsHeader.h"

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
#include <array>

//==============================================================================
// External File Metadata Helper
//==============================================================================

// Run an external command and capture first N lines of output.
// Returns empty string if command not found or fails.
// Validates filename to prevent command injection.
static std::string RunExternalTool(const char *tool, const char *args,
                                   const char *filename, int maxLines = 20) {
  // Reject filenames with shell metacharacters
  if (strpbrk(filename, ";|&$`\\\"'{}()!<>") != nullptr) {
    return "";
  }

  // Build command with timeout and stderr capture
  char cmd[4096];
  int n = snprintf(cmd, sizeof(cmd), "timeout 10 %s %s '%s' 2>&1",
                   tool, args, filename);
  if (n < 0 || static_cast<size_t>(n) >= sizeof(cmd)) return "";

  FILE *fp = popen(cmd, "r");
  if (!fp) return "";

  std::string result;
  char line[1024];
  int lineCount = 0;
  while (fgets(line, sizeof(line), fp) && lineCount < maxLines) {
    result += "      ";
    result += line;
    lineCount++;
  }
  pclose(fp);
  return result;
}

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
  
  // PHASE 0.5: External File Metadata (when tools available)
  printf("=======================================================================\n");
  printf("%sEXTERNAL FILE METADATA%s\n", ColorHeader(), ColorReset());
  printf("=======================================================================\n\n");

  // file(1) — magic-based type identification
  {
    std::string out = RunExternalTool("file", "-b", filename, 3);
    if (!out.empty()) {
      printf("  [file]\n%s\n", out.c_str());
    }
  }

  // exiftool — structured metadata extraction
  {
    std::string out = RunExternalTool("exiftool", "", filename, 30);
    if (!out.empty()) {
      printf("  [exiftool]\n%s\n", out.c_str());
    }
  }

  // tiffinfo — TIFF IFD structure (only for TIFF-wrapped profiles)
  {
    // Check for TIFF magic at file start (II\x2a or MM\x00\x2a)
    icUInt8Number tiffMagic[4] = {};
    io.Seek(0, icSeekSet);
    if (io.Read8(tiffMagic, 4) == 4) {
      bool isTiff = (tiffMagic[0] == 'I' && tiffMagic[1] == 'I' && tiffMagic[2] == 0x2a) ||
                    (tiffMagic[0] == 'M' && tiffMagic[1] == 'M' && tiffMagic[3] == 0x2a);
      if (isTiff) {
        std::string out = RunExternalTool("tiffinfo", "", filename, 30);
        if (!out.empty()) {
          printf("  [tiffinfo]\n%s\n", out.c_str());
        }
      }
    }
    io.Seek(0, icSeekSet); // Reset file position
  }

  // identify (ImageMagick) — image structure analysis
  {
    std::string out = RunExternalTool("identify", "-verbose", filename, 40);
    if (!out.empty()) {
      printf("  [identify]\n%s\n", out.c_str());
    }
  }

  // xxd — hex dump of first 128 bytes (ICC header)
  {
    std::string out = RunExternalTool("xxd", "-l 128", filename, 10);
    if (!out.empty()) {
      printf("  [xxd -l 128]\n%s\n", out.c_str());
    }
  }

  // SHA-256 of the file
  {
    std::string out = RunExternalTool("sha256sum", "", filename, 1);
    if (!out.empty()) {
      printf("  [sha256sum]\n%s\n", out.c_str());
    }
  }

  // Reset file position for header analysis
  io.Seek(0, icSeekSet);
  io.Read32(&header.size);
  io.Seek(0, icSeekSet);
  // Re-read full header
  io.Read32(&header.size);
  io.Read32(&header.cmmId);
  io.Read32(&header.version);
  io.Read32(&header.deviceClass);
  io.Read32(&header.colorSpace);
  io.Read32(&header.pcs);
  io.Read16(&header.date.year);
  io.Read16(&header.date.month);
  io.Read16(&header.date.day);
  io.Read16(&header.date.hours);
  io.Read16(&header.date.minutes);
  io.Read16(&header.date.seconds);
  io.Read8(&header.magic, sizeof(header.magic));
  io.Read32(&header.platform);
  io.Read32(&header.flags);
  io.Read32(&header.manufacturer);
  io.Read32(&header.model);
  io.Read64(&header.attributes);
  io.Read32(&header.renderingIntent);
  io.Read32(&header.illuminant.X);
  io.Read32(&header.illuminant.Y);
  io.Read32(&header.illuminant.Z);
  io.Read32(&header.creator);
  io.Read8(&header.profileID, sizeof(header.profileID));
  io.Read32(&header.spectralPCS);
  io.Read16(&header.spectralRange.start);
  io.Read16(&header.spectralRange.end);
  io.Read16(&header.spectralRange.steps);
  io.Read16(&header.biSpectralRange.start);
  io.Read16(&header.biSpectralRange.end);
  io.Read16(&header.biSpectralRange.steps);
  io.Read32(&header.mcs);
  io.Read32(&header.deviceSubClass);
  io.Read8(&header.reserved[0], sizeof(header.reserved));

  printf("=======================================================================\n");
  printf("%sHEADER VALIDATION HEURISTICS%s\n", ColorHeader(), ColorReset());
  printf("=======================================================================\n\n");

  heuristicCount += RunHeaderHeuristics(header, actualFileSize);

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
    
    // Library-API heuristics (H9-H32, H56-H86, H95-H106)
    // Extracted to IccHeuristicsLibrary.cpp
    heuristicCount += RunLibraryAPIHeuristics(pIcc, filename);

    // H103-H106: Coverage-gap heuristics (PCC, PRMG, Matrix-TRC, EnvVar)
    heuristicCount += RunHeuristic_H103_PCC(pIcc);
    heuristicCount += RunHeuristic_H104_PRMG(pIcc, filename);
    heuristicCount += RunHeuristic_H105_MatrixTRC(pIcc);
    heuristicCount += RunHeuristic_H106_EnvVar(pIcc);

    // H107-H115: Feedback-driven heuristics (channel cross-check, private tags,
    // shellcode, class validation, reserved bytes, wtpt, round-trip, TRC, targ)
    heuristicCount += RunHeuristic_H107_ChannelCrossCheck(pIcc);
    heuristicCount += RunHeuristic_H108_PrivateTags(pIcc);
    heuristicCount += RunHeuristic_H109_ShellcodePatterns(filename);
    heuristicCount += RunHeuristic_H110_ClassTagValidation(pIcc);
    heuristicCount += RunHeuristic_H111_ReservedBytes(filename);
    heuristicCount += RunHeuristic_H112_WtptValidation(pIcc);
    heuristicCount += RunHeuristic_H113_RoundTripFidelity(pIcc);
    heuristicCount += RunHeuristic_H114_CurveSmoothness(pIcc);
    heuristicCount += RunHeuristic_H115_CharacterizationData(pIcc);

    // H116-H127: ICC Technical Secretary / Profile Assessment WG feedback
    // Conformance, quality metrics, and enhanced private tag analysis
    heuristicCount += RunHeuristic_H116_CprtDescEncoding(pIcc);
    heuristicCount += RunHeuristic_H117_TagTypeAllowed(pIcc);
    heuristicCount += RunHeuristic_H118_CalcCostEstimate(pIcc);
    heuristicCount += RunHeuristic_H119_RoundTripDeltaE(pIcc);
    heuristicCount += RunHeuristic_H120_CurveInvertibility(pIcc);
    heuristicCount += RunHeuristic_H121_CharDataRoundTrip(pIcc);
    heuristicCount += RunHeuristic_H122_TagEncoding(pIcc);
    heuristicCount += RunHeuristic_H123_NonRequiredTags(pIcc);
    heuristicCount += RunHeuristic_H124_VersionTags(pIcc);
    heuristicCount += RunHeuristic_H125_TransformSmoothness(pIcc);
    heuristicCount += RunHeuristic_H126_PrivateTagMalware(pIcc, filename);
    heuristicCount += RunHeuristic_H127_PrivateTagRegistry(pIcc);

    // H128-H132: ICC.1-2022-05 spec compliance heuristics
    heuristicCount += RunHeuristic_H128_VersionBCD(filename);
    heuristicCount += RunHeuristic_H129_PCSIlluminantD50(filename);
    heuristicCount += RunHeuristic_H130_TagAlignment(filename);
    heuristicCount += RunHeuristic_H131_ProfileIdMD5(filename);
    heuristicCount += RunHeuristic_H132_ChadDeterminant(pIcc);

    // H133-H135: ICC.1-2022-05 additional spec compliance
    heuristicCount += RunHeuristic_H133_FlagsReservedBits(filename);
    heuristicCount += RunHeuristic_H134_TagTypeReservedBytes(pIcc, filename);
    heuristicCount += RunHeuristic_H135_DuplicateTagSignatures(filename);

    // H136-H138: CWE-400 systemic patterns (CFL-074 through CFL-076 findings)
    // NOTE: H136 uses raw file I/O only — moved to always-run phase below.
    // H137/H138 require pIcc and stay in library phase.
    heuristicCount += RunHeuristic_H137_HighDimensionalGridComplexity(pIcc);
    heuristicCount += RunHeuristic_H138_CalculatorBranchingDepth(pIcc);

    delete pIcc;
  }
  } // end of critical-threshold gate

  // Raw-file fallback engine (H10, H13, H25, H28, H32 when library fails)
  // Extracted to IccHeuristicsRawPost.cpp
  heuristicCount += RunRawFallbackHeuristics(filename, libraryAnalyzed);
  // Post-library raw-file heuristics (H33-H55, H57, H59, H68-H69)
  // Extracted to IccHeuristicsRawPost.cpp
  heuristicCount += RunRawPostLibraryHeuristics(filename);

  // H136: CWE-400 ResponseCurve measurement count — raw file scan, ALWAYS runs.
  // This is intentionally outside the library phase because the most dangerous
  // profiles (those that crash the library) are too malformed for library loading.
  // Validation-time safety must not depend on runtime library success.
  heuristicCount += RunHeuristic_H136_ResponseCurveMeasurementCount(filename);

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
    printf("  %sCVE Coverage: 141 heuristics (H1-H138 ICC profile + H139-H141 TIFF image) covering patterns from 48 CVEs across 77 iccDEV security advisories (39 heuristics with CVE cross-references)%s\n", ColorInfo(), ColorReset());
    printf("  %sSpec conformance: ICC.1-2022-05, ICC.2-2023 — heuristics cite §section references%s\n", ColorInfo(), ColorReset());
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
    printf("  %sH87-H94: TRC curve anomalies, chromatic adaptation matrix, profile sequence,%s\n", ColorInfo(), ColorReset());
    printf("  %s         preview channels, colorant order, spectral viewing, flags, matrix colorants%s\n", ColorInfo(), ColorReset());
    printf("  %sH95-H102: Sparse matrix bounds, embedded profile recursion, profile sequence ID,%s\n", ColorInfo(), ColorReset());
    printf("  %s          spectral MPE elements, embedded images, sequence desc, MPE chain, tag sizes%s\n", ColorInfo(), ColorReset());
    printf("  %sH103-H106: PCC viewing conditions, PRMG gamut evaluation, matrix-TRC validation,%s\n", ColorInfo(), ColorReset());
    printf("  %s           environment variable tags, spectral range validation%s\n", ColorInfo(), ColorReset());
    printf("  %sH107-H115: LUT/colorspace channel cross-check, private tag scan, shellcode patterns,%s\n", ColorInfo(), ColorReset());
    printf("  %s           class-required tags, reserved bytes, wtpt validation, round-trip fidelity,%s\n", ColorInfo(), ColorReset());
    printf("  %s           TRC monotonicity, characterization data%s\n", ColorInfo(), ColorReset());
    printf("  %sH116-H127: ICC Technical Secretary feedback — cprt/desc encoding, tag-type validation,%s\n", ColorInfo(), ColorReset());
    printf("  %s           computation cost, ΔE round-trip, curve invertibility, characterization RT,%s\n", ColorInfo(), ColorReset());
    printf("  %s           deep encoding, non-required tags, version-tag, smoothness, malware scan, registry%s\n", ColorInfo(), ColorReset());
    printf("  %sH128-H132: ICC.1-2022-05 spec compliance — version BCD, PCS D50, tag alignment,%s\n", ColorInfo(), ColorReset());
    printf("  %s           Profile ID MD5, chromaticAdaptation matrix (§7.2.4, §7.2.16, §7.3.1, §7.2.18, Annex G)%s\n", ColorInfo(), ColorReset());
    printf("  %sH133-H135: ICC.1-2022-05 additional — flags reserved bits (§7.2.11), tag type reserved%s\n", ColorInfo(), ColorReset());
    printf("  %s           bytes (§10.1), duplicate tag signatures (§7.3.1)%s\n", ColorInfo(), ColorReset());
    printf("  %sH136-H138: CWE-400 systemic — ResponseCurve measurement counts, high-dimensional%s\n", ColorInfo(), ColorReset());
    printf("  %s           grid complexity, calculator branching depth (CFL-074/075/076 findings)%s\n", ColorInfo(), ColorReset());
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
