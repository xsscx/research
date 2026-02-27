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
#include "IccAnalyzerXMLExport.h"
#include "IccAnalyzerHeuristics.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <sys/stat.h>

// Resolve and validate a user-supplied file path.
// Returns resolved path or nullptr on error.
static const char *ValidateProfilePath(const char *path) {
  static char resolved[PATH_MAX];
  if (!path || !path[0]) return nullptr;
  if (!realpath(path, resolved)) return nullptr;
  struct stat st;
  if (stat(resolved, &st) != 0 || !S_ISREG(st.st_mode)) return nullptr;
  return resolved;
}

// ─── OOM protection: icRealloc override ───
// iccDEV library routes all tag data allocations through icRealloc()
// (IccUtil.cpp:112). Malicious profiles can trigger 4GB+ allocations via
// CIccTagXYZ::SetSize, CIccTagData::SetSize, CIccMpeTintArray::Read, etc.
// By providing our own definition, the linker picks this over the library's
// version, capping single allocations at 256MB.
static constexpr size_t kMaxSingleAlloc = 256 * 1024 * 1024; // 256 MB

void* icRealloc(void *ptr, size_t size) {
  if (size == 0) {
    free(ptr);
    return nullptr;
  }
  if (size > kMaxSingleAlloc) {
    fprintf(stderr, "[OOM-guard] icRealloc(%p, %zu) rejected (%.1fMB > %zuMB limit)\n",
            ptr, size, (double)size / (1024.0*1024.0),
            kMaxSingleAlloc / (1024*1024));
    free(ptr);  // free(NULL) is safe per C standard
    return nullptr;
  }
  void *nptr = realloc(ptr, size);
  // realloc guarantees: on failure, original ptr is NOT freed (C11 §7.22.3.5)
  if (!nptr) free(ptr);
  return nptr;
}

// ─── ASAN options ───
// When analyzing malicious profiles, library may request huge allocations.
// allocator_may_return_null=1 makes ASAN return NULL instead of aborting.
extern "C" const char *__asan_default_options() {
  return "allocator_may_return_null=1:detect_leaks=0";
}

void PrintUsage() {
  printf("iccAnalyzer-lite v2.9.1 - Static Build (No Database Features)\n\n");
  printf("Usage: iccAnalyzer-lite [OPTIONS] <profile.icc>\n\n");
  
  printf("Analysis Modes:\n");
  printf("  -h <file.icc>              Security heuristics analysis\n");
  printf("  -r <file.icc>              Round-trip accuracy test\n");
  printf("  -a <file.icc>              Comprehensive analysis (all modes)\n");
  printf("  -n <file.icc>              Ninja mode (minimal output)\n");
  printf("  -nf <file.icc>             Ninja mode (full dump, no truncation)\n");
  
  printf("\nExtraction:\n");
  printf("  -x <file.icc> <basename>   Extract LUT tables\n");
  printf("  -xml <file.icc> <out.xml>  Export heuristics report as XML + XSLT\n");
  
  printf("\nExit Codes:\n");
  printf("  0  Clean    - Profile analyzed, no issues detected\n");
  printf("  1  Finding  - Security heuristic warnings or validation failures\n");
  printf("  2  Error    - I/O error (file not found, profile read failure)\n");
  printf("  3  Usage    - Bad arguments or unknown option\n");
  
  printf("\nNote: This is the LITE version - fingerprint database features disabled\n");
  printf("      For full version with all features, use regular iccAnalyzer\n");
}

// Normalize raw analysis return values to deterministic exit codes.
// Raw: -1 = I/O error, 0 = clean, >0 = findings (count or flag)
static int NormalizeExit(int raw) {
  if (raw < 0)  return ICC_EXIT_ERROR;
  if (raw == 0) return ICC_EXIT_CLEAN;
  return ICC_EXIT_FINDING;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    PrintUsage();
    return ICC_EXIT_USAGE;
  }

  const char *mode = argv[1];
  
  // Validate profile path for modes that accept one
  const char *profilePath = nullptr;
  if (argc >= 3 && strcmp(mode, "--version") != 0 && strcmp(mode, "-version") != 0) {
    profilePath = ValidateProfilePath(argv[2]);
    if (!profilePath) {
      fprintf(stderr, "[ERR] Invalid or inaccessible path: %s\n", argv[2]);
      return ICC_EXIT_USAGE;
    }
  }
  
  // Heuristics mode (pass NULL for fingerprint_db in lite version)
  if (strcmp(mode, "-h") == 0 && argc >= 3) {
    return NormalizeExit(HeuristicAnalyze(profilePath, nullptr));
  }
  
  // Round-trip mode
  if (strcmp(mode, "-r") == 0 && argc >= 3) {
    return NormalizeExit(RoundTripAnalyze(profilePath));
  }
  
  // Comprehensive mode (pass NULL for fingerprint_db in lite version)
  if (strcmp(mode, "-a") == 0 && argc >= 3) {
    return NormalizeExit(ComprehensiveAnalyze(profilePath, nullptr));
  }
  
  // Ninja mode
  if (strcmp(mode, "-n") == 0 && argc >= 3) {
    return NormalizeExit(NinjaModeAnalyze(profilePath, false));
  }
  
  // Ninja mode (full dump)
  if (strcmp(mode, "-nf") == 0 && argc >= 3) {
    return NormalizeExit(NinjaModeAnalyze(profilePath, true));
  }
  
  // Extract LUT
  if (strcmp(mode, "-x") == 0 && argc >= 4) {
    return NormalizeExit(ExtractLutData(profilePath, argv[3]));
  }
  
  // XML report export
  if (strcmp(mode, "-xml") == 0 && argc >= 4) {
    const char *outXml = argv[3];
    // Run heuristic analysis to collect findings
    HeuristicReport report;
    int result = HeuristicAnalyze(profilePath, nullptr);

    // Populate report summary from exit code
    HeuristicFinding f;
    f.check_name = "Heuristic Analysis";
    f.status = (result == 0) ? "PASS" : "FAIL";
    f.severity = (result == 0) ? "LOW" : "HIGH";
    f.message = (result == 0) ? "No security issues detected"
                              : "Security heuristic findings detected";
    report.findings.push_back(f);
    report.totalChecks = 1;
    report.passedChecks = (result == 0) ? 1 : 0;
    report.failedChecks = (result == 0) ? 0 : 1;

    if (IccAnalyzerXMLExport::ExportHeuristicsToXML(outXml, profilePath, &report)) {
      printf("\n[OK] XML report written to: %s\n", outXml);
      printf("[OK] XSLT stylesheet written alongside XML\n");
      printf("[OK] Open the XML file in a browser to view the styled report\n");
      return ICC_EXIT_CLEAN;
    } else {
      fprintf(stderr, "[ERR] Failed to write XML report to: %s\n", outXml);
      return ICC_EXIT_ERROR;
    }
  }
  
  // Version
  if (strcmp(mode, "--version") == 0 || strcmp(mode, "-version") == 0) {
    printf("=======================================================================\n");
    printf("|                     iccAnalyzer-lite v2.9.1                         |\n");
    printf("|                                                                     |\n");
    printf("|             Copyright (c) 2021-2026 David H Hoyt LLC               |\n");
    printf("|                         hoyt.net                                    |\n");
    printf("=======================================================================\n");
    printf("\nBuild: Static (no external dependencies)\n");
    printf("Database features: DISABLED (lite version)\n");
    return ICC_EXIT_CLEAN;
  }
  
  // Help
  if (strcmp(mode, "--help") == 0 || strcmp(mode, "-help") == 0) {
    PrintUsage();
    return ICC_EXIT_CLEAN;
  }
  
  fprintf(stderr, "ERROR: Unknown option: %s\n\n", SanitizeForLog(mode).c_str());
  PrintUsage();
  return ICC_EXIT_USAGE;
}
