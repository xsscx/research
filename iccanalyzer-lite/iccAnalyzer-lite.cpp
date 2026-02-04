/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC * LITE VERSION - Fingerprint database features disabled
 */

#include "IccAnalyzerCommon.h"
#include "IccAnalyzerInspect.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerSignatures.h"
#include "IccAnalyzerValidation.h"
#include "IccAnalyzerLUT.h"
#include "IccAnalyzerNinja.h"
#include "IccAnalyzerComprehensive.h"
#include "IccAnalyzerCallGraph.h"
#include "IccAnalyzerConfig.h"
#include "IccAnalyzerErrors.h"

#include <cstdio>
#include <cstring>

void PrintUsage() {
  printf("iccAnalyzer-lite v2.9.0 - Static Build (No Database Features)\n\n");
  printf("Usage: iccAnalyzer-lite [OPTIONS] <profile.icc>\n\n");
  
  printf("Analysis Modes:\n");
  printf("  -h <file.icc>              Security heuristics analysis\n");
  printf("  -r <file.icc>              Round-trip accuracy test\n");
  printf("  -a <file.icc>              Comprehensive analysis (all modes)\n");
  printf("  -n <file.icc>              Ninja mode (minimal output)\n");
  printf("  -nf <file.icc>             Ninja mode (full dump, no truncation)\n");
  
  printf("\nExtraction:\n");
  printf("  -x <file.icc> <basename>   Extract LUT tables\n");
  
  printf("\nNote: This is the LITE version - fingerprint database features disabled\n");
  printf("      For full version with all features, use regular iccAnalyzer\n");
}

int main(int argc, char **argv) {
  if (argc < 2) {
    PrintUsage();
    return 1;
  }

  const char *mode = argv[1];
  
  // Heuristics mode (pass NULL for fingerprint_db in lite version)
  if (strcmp(mode, "-h") == 0 && argc >= 3) {
    return HeuristicAnalyze(argv[2], nullptr);
  }
  
  // Round-trip mode
  if (strcmp(mode, "-r") == 0 && argc >= 3) {
    return RoundTripAnalyze(argv[2]);
  }
  
  // Comprehensive mode (pass NULL for fingerprint_db in lite version)
  if (strcmp(mode, "-a") == 0 && argc >= 3) {
    return ComprehensiveAnalyze(argv[2], nullptr);
  }
  
  // Ninja mode
  if (strcmp(mode, "-n") == 0 && argc >= 3) {
    return NinjaModeAnalyze(argv[2], false);
  }
  
  // Ninja mode (full dump)
  if (strcmp(mode, "-nf") == 0 && argc >= 3) {
    return NinjaModeAnalyze(argv[2], true);
  }
  
  // Extract LUT
  if (strcmp(mode, "-x") == 0 && argc >= 4) {
    return ExtractLutData(argv[2], argv[3]);
  }
  
  // Version
  if (strcmp(mode, "--version") == 0 || strcmp(mode, "-version") == 0) {
    printf("=======================================================================\n");
    printf("|                     iccAnalyzer-lite v2.9.0                         |\n");
    printf("|                                                                     |\n");
    printf("|             Copyright (c) 2021-2026 David H Hoyt LLC               |\n");
    printf("|                         hoyt.net                                    |\n");
    printf("=======================================================================\n");
    printf("\nBuild: Static (no external dependencies)\n");
    printf("Database features: DISABLED (lite version)\n");
    return 0;
  }
  
  // Help
  if (strcmp(mode, "--help") == 0 || strcmp(mode, "-help") == 0) {
    PrintUsage();
    return 0;
  }
  
  fprintf(stderr, "ERROR: Unknown option: %s\n\n", mode);
  PrintUsage();
  return 1;
}
