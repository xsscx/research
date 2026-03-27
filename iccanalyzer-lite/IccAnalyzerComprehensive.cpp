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
#include "IccAnalyzerComprehensive.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerValidation.h"
#include "IccAnalyzerSignatures.h"
#include <new>
#include <cstdio>
#include <cstring>
#include "IccAnalyzerInspect.h"
#include "IccAnalyzerColors.h"
#include "IccAnalyzerTagDetails.h"
#include "IccConformanceHeader.h"
#include "IccConformanceTagTypes.h"
#include "IccConformanceRequired.h"
#include "IccConformanceLUT.h"
#include "IccConformanceV5.h"
#include "IccConformanceSecurity.h"
#include "IccConformanceQuality.h"
#include "IccHeuristicResult.h"
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicsRawPost.h"
#include "IccHeuristicsCodeQLPatterns.h"
#include "IccHeuristicsDataValidation.h"

//==============================================================================
// Pre-loading raw scan: detect tag data patterns that cause UBSAN in the
// upstream iccDEV library during Read(). iccanalyzer-lite links the UNPATCHED
// upstream library, so the only defense is to detect these BEFORE calling
// CIccProfile::Read() / ValidateIccProfile().
//
// Returns true if the profile contains patterns that will trigger undefined
// behavior in the upstream library's tag Read() methods.
//==============================================================================
static bool HasLibraryUBPatterns(const char *filename) {
  if (!filename) return false;

  if (IsLibraryUBDefenseEnabled() &&
      DetectH96EmbeddedProfileConstructorUB(filename)) {
    printf("\n%s[DEFENSE] Embedded ICC5 tag with ICCp type will hit "
           "CIccEmbedIO constructor UB (IccIO.cpp:569) — skipping library phase%s\n",
           ColorCritical(), ColorReset());
    return true;
  }

  if (IsLibraryUBDefenseEnabled() &&
      DetectH174HalfFloatReadPathUB(filename)) {
    printf("\n%s[DEFENSE] Non-zero half-float values below 1.0 will hit "
           "icF16toF() unsigned-wrap UBSAN (IccUtil.cpp:665/677) — "
           "skipping library phase%s\n",
           ColorCritical(), ColorReset());
    return true;
  }

  if (IsLibraryUBDefenseEnabled() &&
      DetectH101MPEElementOffsetSizeOverflow(filename)) {
    printf("\n%s[DEFENSE] Malformed mpet element offset/size pair will wrap "
           "CIccTagMultiProcessElement::Read() (IccTagMPE.cpp:1042) — "
           "skipping library phase%s\n",
           ColorCritical(), ColorReset());
    return true;
  }

  if (IsLibraryUBDefenseEnabled() &&
      DetectH152CurveElementOOMSize(filename)) {
    printf("\n%s[DEFENSE] Oversized sampled-curve element count would drive "
           "upstream sampled-curve allocation/underflow paths — skipping "
           "library phase%s\n",
           ColorCritical(), ColorReset());
    return true;
  }

  FILE *fp = fopen(filename, "rb");
  if (!fp) return false;

  // Read enough of the header to get the tag table
  uint8_t hdr[132];
  if (fread(hdr, 1, 132, fp) < 132) { fclose(fp); return false; }

  // Verify ICC magic at offset 36
  if (hdr[36] != 'a' || hdr[37] != 'c' || hdr[38] != 's' || hdr[39] != 'p') {
    fclose(fp);
    return false;
  }

  uint32_t tagCount = ReadU32BE(&hdr[128]);
  if (tagCount > 1000) { fclose(fp); return false; }

  bool dangerous = false;

  for (uint32_t i = 0; i < tagCount && !dangerous; i++) {
    uint8_t tagEntry[12];
    if (fread(tagEntry, 1, 12, fp) < 12) break;

    uint32_t tOff = ReadU32BE(&tagEntry[4]);
    uint32_t tSz  = ReadU32BE(&tagEntry[8]);

    // Read the type signature from the tag data
    long savedPos = ftell(fp);
    if (savedPos < 0) break;

    uint8_t typeHdr[20];
    if (tOff + 20 > tOff && tSz >= 20) { // overflow-safe check
      if (fseek(fp, static_cast<long>(tOff), SEEK_SET) == 0) {
        if (fread(typeHdr, 1, 20, fp) == 20) {
          uint32_t typeSig = ReadU32BE(typeHdr);

          // GamutBoundaryDesc ('gbd ' = 0x67626420):
          // Layout: [type:4][reserved:4][nPCSCh:2][nDevCh:2][nVertices:4][nTriangles:4]
          // UBSAN: m_NumberOfTriangles*3 signed overflow at IccTagLut.cpp:5730
          if (typeSig == 0x67626420) {
            int32_t nTriangles;
            memcpy(&nTriangles, &typeHdr[16], 4);
            // Convert from big-endian
            nTriangles = static_cast<int32_t>(ReadU32BE(&typeHdr[16]));
            if (nTriangles > 0 &&
                static_cast<uint32_t>(nTriangles) > static_cast<uint32_t>(0x7FFFFFFF / 3)) {
              printf("\n%s[DEFENSE] GamutBoundaryDesc nTriangles=%d would overflow "
                     "nTriangles*3 (signed int32) in upstream library Read() "
                     "— skipping library phase (CWE-190)%s\n",
                     ColorCritical(), nTriangles, ColorReset());
              dangerous = true;
            }
          }
        }
      }
    }
    if (fseek(fp, savedPos, SEEK_SET) != 0) break;
  }

  fclose(fp);
  return dangerous;
}

// Emit raw preflight fingerprints that explain known upstream integer-sanitizer
// sites before the library phase runs. This keeps conformance-mode output
// aligned with the actual byte pattern that reaches the library code path.
static int EmitConformancePreflightFingerprints(const char *filename) {
  RawProfileContext ctx = OpenRawProfileContext(filename);
  if (!ctx.valid) {
    return 0;
  }

  auto &hc = HeuristicCollector::instance();
  bool prevCollecting = hc.collecting();
  hc.setCollecting(false);
  int preflightIssues = 0;
  preflightIssues += RunHeuristic_H173_SigConversionShiftOverflow(ctx);
  preflightIssues += RunHeuristic_H174_HalfFloatConversionUnsignedUnderflow(ctx);
  hc.setCollecting(prevCollecting);
  if (DetectH101MPEElementOffsetSizeOverflow(filename)) {
    preflightIssues += RunHeuristic_H101_MPESubElementChannelContinuityRaw(filename);
  }
  if (DetectH152CurveElementOOMSize(filename)) {
    preflightIssues += RunHeuristic_H152_CurveElementOOMSizeValidation(ctx);
  }
  return preflightIssues;
}

//==============================================================================
// Comprehensive Analysis - All Modes Combined
//
// legacy=false (default): ICC Specification Conformance Audit
//   Phase 1: ICC specification conformance (CIccProfile::Validate)
//   Phase 2: Round-trip validation (encode/decode fidelity)
//   Phase 3: Signature and structure verification
//   Phase 4: Profile structure dump (header, tag table)
//   Phase 5: Deep tag content analysis (LUT, curve, MPE, named color)
//
// legacy=true: Full analysis including backward-looking vulnerability heuristics
//   Phase 1: Security heuristic checks (171 CVE/GHSA pattern detectors)
//   Phase 2: Round-trip validation
//   Phase 3: ICC specification conformance (CIccProfile::Validate)
//   Phase 4: Signature and structure verification
//   Phase 5: Profile structure dump
//   Phase 6: Deep tag content analysis
//
// Returns: total number of issues detected across all phases (0 = clean profile).
//==============================================================================

int ComprehensiveAnalyze(const char *filename, const char *fingerprint_db,
                         bool legacy)
{
  printf("\n");
  printf("=======================================================================\n");
  if (legacy) {
    printf("  %sICC PROFILE COMPREHENSIVE ANALYSIS (LEGACY + CONFORMANCE)%s\n",
           ColorHeader(), ColorReset());
  } else {
    printf("  %sICC PROFILE CONFORMANCE AUDIT%s\n",
           ColorHeader(), ColorReset());
  }
  printf("=======================================================================\n");
  printf("\n%sFile:%s %s\n\n", ColorInfo(), ColorReset(), filename);
  
  int totalIssues = 0;
  int phaseNum = 1;
  
  // Legacy mode Phase 1: Security Heuristics (CVE/GHSA pattern detectors)
  if (legacy) {
    printf("=======================================================================\n");
    printf("%sPHASE %d: SECURITY HEURISTIC ANALYSIS (LEGACY)%s\n",
           ColorHeader(), phaseNum, ColorReset());
    printf("=======================================================================\n\n");
    
    int heuristicCount = HeuristicAnalyze(filename, fingerprint_db);
    if (heuristicCount > 0) {
      totalIssues += heuristicCount;
    }
    phaseNum++;
  }
  
  // Conformance Phase: ICC specification validation via CIccProfile::ReadValidate()
  if (IsProfileTruncated(filename)) {
    // Distinguish empty/unreadable files from truncated-but-analyzable profiles.
    // Files < 128 bytes cannot hold an ICC header — report error without analysis.
    FILE *fpCheck = fopen(filename, "rb");
    long fileSizeCheck = 0;
    if (fpCheck) {
      fseek(fpCheck, 0, SEEK_END);
      fileSizeCheck = ftell(fpCheck);
      fclose(fpCheck);
    }
    if (fileSizeCheck < 128) {
      printf("\n%s[ERROR] Cannot read ICC header (file too small or corrupted)%s\n",
             ColorCritical(), ColorReset());
      printf("\n%s[NOT RUN] Library-phase conformance validation skipped — profile truncated%s\n",
             ColorCritical(), ColorReset());
      return -1;
    }

    printf("\n%s[CRITICAL] Profile TRUNCATED — header claims more bytes than file contains (CWE-125/CWE-131)%s\n",
           ColorCritical(), ColorReset());
    printf("       %sLibrary-phase conformance skipped (unsafe on truncated data)%s\n",
           ColorInfo(), ColorReset());
    printf("       %sRunning raw-byte security heuristics (H1-H178)...%s\n\n",
           ColorInfo(), ColorReset());
    totalIssues++;

    // Run the full raw-byte heuristic engine — header checks, raw tag analysis,
    // CodeQL-driven patterns, exploit gap analysis all work on truncated profiles.
    // Only library-API heuristics (CIccProfile*-dependent) are skipped internally
    // via the skipLibraryPhase gate in HeuristicAnalyze/RunSecurityHeuristics.
    // Guard: legacy mode already ran HeuristicAnalyze above — don't run twice.
    if (!legacy) {
      int heuristicCount = HeuristicAnalyze(filename, fingerprint_db);
      if (heuristicCount > 0) {
        totalIssues += heuristicCount;
      }
    }

    printf("\n%s[NOT RUN] Library-phase conformance validation skipped — profile truncated%s\n",
           ColorCritical(), ColorReset());
    return totalIssues;
  }

  if (!legacy) {
    totalIssues += EmitConformancePreflightFingerprints(filename);
  }

  // Pre-loading defense: detect tag data patterns that trigger undefined behavior
  // in the upstream iccDEV library during Read(). Must run BEFORE any library call.
  bool skipLibrary = HasLibraryUBPatterns(filename);
  bool skipLibraryValidation = false;
  if (!skipLibrary &&
      IsLibraryUBDefenseEnabled() &&
      DetectH174HalfFloatConversionUB(filename)) {
    skipLibraryValidation = true;
    printf("%s[DEFENSE] H174 half-float fingerprint reaches upstream validation "
           "paths — skipping Validate() phase but continuing with safe deep "
           "conformance checks%s\n",
           ColorCritical(), ColorReset());
  }
  if (skipLibrary) {
    totalIssues += RunCF115_CalculatorElementComplexityRaw(filename);
    printf("%s[NOT RUN] Library-phase conformance not run — profile triggers upstream "
           "undefined behavior (CWE-190)%s\n",
           ColorCritical(), ColorReset());
    printf("       %sRaw-phase heuristics (H1-H178) still ran in legacy mode%s\n",
           ColorInfo(), ColorReset());
    totalIssues++;
    return totalIssues;
  }

  printf("=======================================================================\n");
  printf("%sPHASE %d: ICC SPECIFICATION CONFORMANCE%s\n",
         ColorHeader(), phaseNum, ColorReset());
  printf("=======================================================================\n\n");
  
  if (skipLibraryValidation) {
    printf("%s[NOT RUN] Library validation not run — half-float fields would hit "
           "upstream icF16toF UB during Validate()%s\n",
           ColorCritical(), ColorReset());
    printf("       %sDeep conformance checks will continue using analyzer-owned "
           "safe conversions%s\n",
           ColorInfo(), ColorReset());
    totalIssues++;
  } else {
    int validateIssues = RunIccLibraryValidation(filename);
    if (validateIssues > 0) {
      totalIssues += validateIssues;
    }
  }
  phaseNum++;
  
  // Deep Conformance Phase: specification checks beyond library validation
  // Requires a loaded CIccProfile — load early and reuse for later phases
  CIccFileIO ioConf;
  CIccProfile *pIcc = nullptr;
  if (ioConf.Open(filename, "rb")) {
    pIcc = new (std::nothrow) CIccProfile;
    if (pIcc && pIcc->Read(&ioConf)) {
      ioConf.Close();
      
      printf("\n");
      printf("=======================================================================\n");
      printf("%sPHASE %d: DEEP CONFORMANCE CHECKS (ICC.1/ICC.2)%s\n",
             ColorHeader(), phaseNum, ColorReset());
      printf("=======================================================================\n\n");
      
      int cfIssues = 0;
      
      printf("%s--- Header Conformance (CF-001..CF-015, CF-184..CF-187, CF-199..CF-201, CF-203, CF-206, CF-210, CF-214..CF-219) ---%s\n\n",
             ColorInfo(), ColorReset());
      cfIssues += RunHeaderConformance(pIcc, filename);
      
      printf("\n%s--- Tag Type Conformance (CF-020..CF-034, CF-169..CF-174, CF-188..CF-190, CF-208, CF-209, CF-212, CF-213, CF-220..CF-234, CF-247..CF-254, CF-263..CF-265, CF-273..CF-281) ---%s\n\n",
             ColorInfo(), ColorReset());
      cfIssues += RunTagTypeConformance(pIcc, filename);
      
      printf("\n%s--- Required Tag Conformance (CF-040..CF-053, CF-202, CF-204..CF-205, CF-207, CF-211, CF-258..CF-260, CF-266..CF-272, CF-282..CF-283) ---%s\n\n",
             ColorInfo(), ColorReset());
      cfIssues += RunRequiredTagConformance(pIcc, filename);
      
      printf("\n%s--- LUT/Matrix Conformance (CF-060..CF-070, CF-163..CF-168, CF-255..CF-256, CF-261..CF-262) ---%s\n\n",
             ColorInfo(), ColorReset());
      cfIssues += RunLUTConformance(pIcc);
      
      printf("\n%s--- v5/iccMAX Conformance (CF-080..CF-090, CF-113..CF-115, CF-137..CF-162, CF-175..CF-198, CF-235..CF-242, CF-257, CF-284..CF-316) ---%s\n\n",
             ColorInfo(), ColorReset());
      cfIssues += RunV5Conformance(pIcc);
      
      printf("\n%s--- Security Conformance (CF-091..CF-094) ---%s\n\n",
             ColorInfo(), ColorReset());
      cfIssues += RunSecurityConformance(pIcc, filename);
      
      printf("\n%s--- Private Tag Conformance (CF-095..CF-098) ---%s\n\n",
             ColorInfo(), ColorReset());
      // CF-095..CF-098 run inside RunRequiredTagConformance() above
      
      printf("\n%s--- Quality Conformance (CF-099..CF-102) ---%s\n\n",
             ColorInfo(), ColorReset());
      cfIssues += RunQualityConformance(pIcc);
      
      printf("\n%sDeep Conformance Summary:%s %d issue(s)\n",
             ColorInfo(), ColorReset(), cfIssues);
      totalIssues += cfIssues;
    } else {
      if (pIcc) { delete pIcc; pIcc = nullptr; }
      ioConf.Close();
      printf("\n%s[NOT RUN] Deep conformance checks not run — profile failed to load%s\n",
             ColorWarning(), ColorReset());
    }
  }
  phaseNum++;
  
  // Round-trip tag validation
  printf("\n");
  printf("=======================================================================\n");
  printf("%sPHASE %d: ROUND-TRIP TAG VALIDATION%s\n",
         ColorHeader(), phaseNum, ColorReset());
  printf("=======================================================================\n\n");
  
  int rtResult = RoundTripAnalyze(filename);
  if (rtResult != 0) {
    printf("%sResult: NOT round-trip capable%s\n", ColorCritical(), ColorReset());
    totalIssues++;
  } else {
    printf("%sResult: Round-trip capable [OK]%s\n", ColorSuccess(), ColorReset());
  }
  phaseNum++;

  // Remaining phases need a loaded profile for signature/structure/tag analysis
  // Reuse pIcc from conformance phase if available; otherwise load fresh
  if (!pIcc) {
    CIccFileIO io;
    if (!io.Open(filename, "rb")) {
      printf("%s[ERROR] Cannot open file for signature analysis%s\n", ColorCritical(), ColorReset());
      return totalIssues > 0 ? totalIssues : -1;
    }
    
    pIcc = new (std::nothrow) CIccProfile;
    if (!pIcc) {
      printf("%s[ERROR] Memory allocation failed%s\n", ColorCritical(), ColorReset());
      io.Close();
      return totalIssues > 0 ? totalIssues : -1;
    }
    if (!pIcc->Read(&io)) {
      printf("%s[ERROR] Profile failed to load - skipping remaining phases%s\n", ColorCritical(), ColorReset());
      printf("        %sUse -n (ninja mode) for raw analysis of malformed profiles%s\n", ColorInfo(), ColorReset());
      delete pIcc;
      io.Close();
      return totalIssues > 0 ? totalIssues : -1;
    }
    io.Close();
  }

  printf("\n");
  printf("=======================================================================\n");
  printf("%sPHASE %d: SIGNATURE ANALYSIS%s\n", ColorHeader(), phaseNum, ColorReset());
  printf("=======================================================================\n\n");
  
  AnalyzeSignatures(pIcc);
  phaseNum++;
  
  printf("\n");
  printf("=======================================================================\n");
  printf("%sPHASE %d: PROFILE STRUCTURE DUMP%s\n", ColorHeader(), phaseNum, ColorReset());
  printf("=======================================================================\n\n");
  
  CIccFileIO io2;
  if (io2.Open(filename, "rb")) {
    printf("%s=== ICC Profile Header ===%s\n", ColorInfo(), ColorReset());
    DumpProfileHeader(pIcc, &io2);
    printf("\n%s=== Tag Table ===%s\n", ColorInfo(), ColorReset());
    DumpTagTable(pIcc, &io2);
    io2.Close();
  }
  phaseNum++;
  
  printf("\n");
  printf("=======================================================================\n");
  printf("%sPHASE %d: TAG CONTENT ANALYSIS%s\n", ColorHeader(), phaseNum, ColorReset());
  printf("=======================================================================\n\n");
  
  int tagIssues = TagDetailAnalyze(pIcc, filename);
  if (tagIssues > 0) {
    totalIssues += tagIssues;
  }
  
  delete pIcc;
  
  printf("\n");
  printf("=======================================================================\n");
  if (legacy) {
    printf("%sCOMPREHENSIVE ANALYSIS SUMMARY%s\n", ColorHeader(), ColorReset());
  } else {
    printf("%sCONFORMANCE AUDIT SUMMARY%s\n", ColorHeader(), ColorReset());
  }
  printf("=======================================================================\n\n");
  
  printf("%sFile:%s %s\n", ColorInfo(), ColorReset(), filename);
  printf("%sMode:%s %s\n", ColorInfo(), ColorReset(),
         legacy ? "Legacy (conformance + vulnerability heuristics)"
                : "Conformance (ICC specification audit)");
  printf("%sTotal Issues Detected:%s %s%d%s\n", ColorInfo(), ColorReset(), 
         totalIssues > 0 ? ColorWarning() : ColorSuccess(), totalIssues, ColorReset());
  
  if (totalIssues == 0) {
    printf("\n%s[OK] ANALYSIS COMPLETE - No issues detected%s\n", ColorSuccess(), ColorReset());
    if (legacy) {
      printf("  Profile appears well-formed and free of known vulnerability patterns.\n");
    } else {
      printf("  Profile conforms to ICC specification.\n");
    }
  } else {
    printf("\n%s[WARN] ANALYSIS COMPLETE - %d issue(s) detected%s\n", ColorCritical(), totalIssues, ColorReset());
    if (legacy) {
      printf("  %sReview detailed output above for security concerns.%s\n", ColorWarning(), ColorReset());
    } else {
      printf("  %sReview conformance findings above. Use --legacy for vulnerability analysis.%s\n",
             ColorWarning(), ColorReset());
    }
  }
  
  printf("\n");
  return totalIssues;
}
