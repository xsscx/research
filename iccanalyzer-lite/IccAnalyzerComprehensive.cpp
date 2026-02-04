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
#include "IccAnalyzerInspect.h"
#include "IccAnalyzerColors.h"

//==============================================================================
// Comprehensive Analysis - All Modes Combined
//==============================================================================

int ComprehensiveAnalyze(const char *filename, const char *fingerprint_db)
{
  printf("\n");
  printf("=======================================================================\n");
  printf("  %sICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)%s\n", ColorHeader(), ColorReset());
  printf("=======================================================================\n");
  printf("\n%sFile:%s %s\n\n", ColorInfo(), ColorReset(), filename);
  
  int totalIssues = 0;
  
  // Phase 1: Security Heuristics (with fingerprint check if DB provided)
  printf("=======================================================================\n");
  printf("%sPHASE 1: SECURITY HEURISTIC ANALYSIS%s\n", ColorHeader(), ColorReset());
  printf("=======================================================================\n\n");
  
  int heuristicCount = HeuristicAnalyze(filename, fingerprint_db);
  if (heuristicCount > 0) {
    totalIssues += heuristicCount;
  }
  
  printf("\n");
  printf("=======================================================================\n");
  printf("%sPHASE 2: ROUND-TRIP TAG VALIDATION%s\n", ColorHeader(), ColorReset());
  printf("=======================================================================\n\n");
  
  int rtResult = RoundTripAnalyze(filename);
  if (rtResult != 0) {
    printf("%sResult: NOT round-trip capable%s\n", ColorCritical(), ColorReset());
    totalIssues++;
  } else {
    printf("%sResult: Round-trip capable [OK]%s\n", ColorSuccess(), ColorReset());
  }
  
  printf("\n");
  printf("=======================================================================\n");
  printf("%sPHASE 3: SIGNATURE ANALYSIS%s\n", ColorHeader(), ColorReset());
  printf("=======================================================================\n\n");
  
  CIccFileIO io;
  if (!io.Open(filename, "rb")) {
    printf("%s[ERROR] Cannot open file for signature analysis%s\n", ColorCritical(), ColorReset());
    return -1;
  }
  
  CIccProfile *pIcc = new CIccProfile;
  if (pIcc->Read(&io)) {
    AnalyzeSignatures(pIcc);
    delete pIcc;
  } else {
    printf("%s[ERROR] Profile failed to load - skipping signature analysis%s\n", ColorCritical(), ColorReset());
    printf("        %sUse -n (ninja mode) for raw analysis of malformed profiles%s\n", ColorInfo(), ColorReset());
    delete pIcc;
  }
  io.Close();
  
  printf("\n");
  printf("=======================================================================\n");
  printf("%sPHASE 4: PROFILE STRUCTURE DUMP%s\n", ColorHeader(), ColorReset());
  printf("=======================================================================\n\n");
  
  if (!io.Open(filename, "rb")) {
    printf("%s[ERROR] Cannot reopen file for dump%s\n", ColorCritical(), ColorReset());
    return -1;
  }
  
  pIcc = new CIccProfile;
  if (pIcc->Read(&io)) {
    printf("%s=== ICC Profile Header ===%s\n", ColorInfo(), ColorReset());
    DumpProfileHeader(pIcc, &io);
    printf("\n%s=== Tag Table ===%s\n", ColorInfo(), ColorReset());
    DumpTagTable(pIcc, &io);
    delete pIcc;
  } else {
    printf("%s[ERROR] Profile failed to load for structure dump%s\n", ColorCritical(), ColorReset());
    delete pIcc;
  }
  io.Close();
  
  printf("\n");
  printf("=======================================================================\n");
  printf("%sCOMPREHENSIVE ANALYSIS SUMMARY%s\n", ColorHeader(), ColorReset());
  printf("=======================================================================\n\n");
  
  printf("%sFile:%s %s\n", ColorInfo(), ColorReset(), filename);
  printf("%sTotal Issues Detected:%s %s%d%s\n", ColorInfo(), ColorReset(), 
         totalIssues > 0 ? ColorWarning() : ColorSuccess(), totalIssues, ColorReset());
  
  if (totalIssues == 0) {
    printf("\n%s[OK] ANALYSIS COMPLETE - No critical issues detected%s\n", ColorSuccess(), ColorReset());
    printf("  Profile appears well-formed.\n");
  } else {
    printf("\n%s[WARN] ANALYSIS COMPLETE - %d issue(s) detected%s\n", ColorCritical(), totalIssues, ColorReset());
    printf("  %sReview detailed output above for security concerns.%s\n", ColorWarning(), ColorReset());
  }
  
  printf("\n");
  return totalIssues;
}
