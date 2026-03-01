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
#include <csignal>
#include <csetjmp>
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
// version, capping single allocations at 256MB and cumulative at 1GB.
static constexpr size_t kMaxSingleAlloc = 256 * 1024 * 1024;  // 256 MB
static constexpr size_t kMaxTotalAlloc  = 1ULL << 30;          // 1 GB cumulative

// Track cumulative allocation to prevent death-by-a-thousand-cuts OOM
static thread_local size_t g_total_alloc = 0;

void* icRealloc(void *ptr, size_t size) {
  if (size == 0) {
    free(ptr);
    return nullptr;
  }
  if (size > kMaxSingleAlloc) {
    fprintf(stderr, "[OOM-guard] icRealloc(%p, %zu) rejected (%.1fMB > %zuMB limit)\n",
            ptr, size, (double)size / (1024.0*1024.0),
            kMaxSingleAlloc / (1024*1024));
    // Do NOT free(ptr) — caller may still reference the old buffer
    return nullptr;
  }
  if (g_total_alloc + size > kMaxTotalAlloc) {
    fprintf(stderr, "[OOM-guard] icRealloc cumulative limit exceeded "
            "(total=%.1fMB + %.1fMB > %zuMB)\n",
            (double)g_total_alloc / (1024.0*1024.0),
            (double)size / (1024.0*1024.0),
            kMaxTotalAlloc / (1024*1024));
    return nullptr;
  }
  void *nptr = realloc(ptr, size);
  if (nptr) g_total_alloc += size;
  // realloc guarantees: on failure, original ptr is NOT freed (C11 §7.22.3.5)
  // Callers must handle NULL return and still have access to original ptr.
  return nptr;
}

// Reset cumulative allocator state between analysis runs or after recovery.
void ResetAllocGuard() {
  g_total_alloc = 0;
}

// ─── Sanitizer options ───
// allocator_may_return_null=1: ASAN returns NULL instead of aborting on OOM
// halt_on_error=0: ASAN continues after finding (recoverable mode)
// handle_segv/sigbus/sigfpe=0: let OUR signal handler run, not ASAN's
//   (ASAN's handler aborts; ours recovers via siglongjmp)
extern "C" const char *__asan_default_options() {
  return "allocator_may_return_null=1:detect_leaks=0:halt_on_error=0"
         ":handle_segv=0:handle_sigbus=0:handle_sigfpe=0:handle_abort=0";
}

// print_stacktrace=1: show where UB occurred
// halt_on_error=0: continue after UB (recoverable mode)
extern "C" const char *__ubsan_default_options() {
  return "print_stacktrace=1:halt_on_error=0";
}

// ─── Crash recovery ───
// When the unpatched iccDEV library hits a CVE (SIGSEGV, SIGBUS, SIGFPE),
// we recover and report partial results instead of dying silently.
static sigjmp_buf g_recovery_jmp;
static volatile sig_atomic_t g_recovery_active = 0;
static volatile sig_atomic_t g_crash_signal = 0;

static const char *SignalName(int sig) {
  switch (sig) {
    case SIGSEGV: return "SIGSEGV (segmentation fault)";
    case SIGBUS:  return "SIGBUS (bus error)";
    case SIGFPE:  return "SIGFPE (floating-point exception)";
    case SIGALRM: return "SIGALRM (analysis timeout)";
    case SIGABRT: return "SIGABRT (abort)";
    default:      return "unknown signal";
  }
}

static void CrashRecoveryHandler(int sig) {
  if (g_recovery_active) {
    g_crash_signal = sig;
    siglongjmp(g_recovery_jmp, sig);
  }
  // Recovery not active — restore default handler and re-raise
  signal(sig, SIG_DFL);
  raise(sig);
}

static void InstallCrashRecovery() {
  // 256KB alternate stack — ASAN needs space for error reporting in signal context
  static char alt_stack[262144];
  stack_t ss = {};
  ss.ss_sp = alt_stack;
  ss.ss_size = sizeof(alt_stack);
  ss.ss_flags = 0;
  sigaltstack(&ss, nullptr);

  struct sigaction sa = {};
  sa.sa_handler = CrashRecoveryHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_NODEFER | SA_ONSTACK;
  sigaction(SIGSEGV, &sa, nullptr);
  sigaction(SIGBUS,  &sa, nullptr);
  sigaction(SIGFPE,  &sa, nullptr);
  sigaction(SIGABRT, &sa, nullptr);

  // SIGALRM for analysis timeout — uses default flags (no SA_ONSTACK needed)
  struct sigaction sa_alrm = {};
  sa_alrm.sa_handler = CrashRecoveryHandler;
  sigemptyset(&sa_alrm.sa_mask);
  sa_alrm.sa_flags = SA_NODEFER;
  sigaction(SIGALRM, &sa_alrm, nullptr);
}

// Normalize raw analysis return values to deterministic exit codes.
// Raw: -1 = I/O error, 0 = clean, >0 = findings (count or flag)
static int NormalizeExit(int raw) {
  if (raw < 0)  return ICC_EXIT_ERROR;
  if (raw == 0) return ICC_EXIT_CLEAN;
  return ICC_EXIT_FINDING;
}

// Run an analysis function with crash recovery. If the library crashes
// or hangs, print a diagnostic and return ICC_EXIT_FINDING instead of dying.
static constexpr unsigned kAnalysisTimeoutSec = 15;

template<typename Fn>
static int RecoverableRun(const char *label, Fn fn) {
  g_recovery_active = 1;
  alarm(kAnalysisTimeoutSec);  // watchdog: recover if analysis hangs
  int sig = sigsetjmp(g_recovery_jmp, 1);
  if (sig != 0) {
    alarm(0);  // cancel watchdog
    g_recovery_active = 0;
    fprintf(stderr, "\n╔══════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║  [RECOVERY] Library crashed: %s\n", SignalName(sig));
    fprintf(stderr, "║  During: %s\n", label);
    fprintf(stderr, "║  Partial results above may be incomplete\n");
    fprintf(stderr, "╚══════════════════════════════════════════════════════╝\n");
    ResetAllocGuard();
    return ICC_EXIT_FINDING;
  }
  int result = fn();
  alarm(0);  // cancel watchdog on success
  g_recovery_active = 0;
  return NormalizeExit(result);
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

int main(int argc, char **argv) {
  InstallCrashRecovery();

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
    return RecoverableRun("heuristic analysis", [&]{ return HeuristicAnalyze(profilePath, nullptr); });
  }
  
  // Round-trip mode
  if (strcmp(mode, "-r") == 0 && argc >= 3) {
    return RecoverableRun("round-trip analysis", [&]{ return RoundTripAnalyze(profilePath); });
  }
  
  // Comprehensive mode (pass NULL for fingerprint_db in lite version)
  if (strcmp(mode, "-a") == 0 && argc >= 3) {
    return RecoverableRun("comprehensive analysis", [&]{ return ComprehensiveAnalyze(profilePath, nullptr); });
  }
  
  // Ninja mode
  if (strcmp(mode, "-n") == 0 && argc >= 3) {
    return RecoverableRun("ninja analysis", [&]{ return NinjaModeAnalyze(profilePath, false); });
  }
  
  // Ninja mode (full dump)
  if (strcmp(mode, "-nf") == 0 && argc >= 3) {
    return RecoverableRun("ninja analysis (full)", [&]{ return NinjaModeAnalyze(profilePath, true); });
  }
  
  // Extract LUT
  if (strcmp(mode, "-x") == 0 && argc >= 4) {
    auto lutPathResult = IccAnalyzerSecurity::ValidateFilePath(
        argv[3], IccAnalyzerSecurity::PathValidationMode::STRICT,
        false, {});
    if (lutPathResult != IccAnalyzerSecurity::PathValidationResult::VALID) {
      fprintf(stderr, "[ERR] Invalid output path: %s\n",
              IccAnalyzerSecurity::GetValidationErrorMessage(lutPathResult, argv[3]).c_str());
      return ICC_EXIT_ERROR;
    }
    return RecoverableRun("LUT extraction", [&]{ return ExtractLutData(profilePath, argv[3]); });
  }
  
  // XML report export
  if (strcmp(mode, "-xml") == 0 && argc >= 4) {
    const char *outXml = argv[3];
    auto xmlPathResult = IccAnalyzerSecurity::ValidateFilePath(
        outXml, IccAnalyzerSecurity::PathValidationMode::STRICT,
        false, {".xml"});
    if (xmlPathResult != IccAnalyzerSecurity::PathValidationResult::VALID) {
      fprintf(stderr, "[ERR] Invalid output path: %s\n",
              IccAnalyzerSecurity::GetValidationErrorMessage(xmlPathResult, outXml).c_str());
      return ICC_EXIT_ERROR;
    }
    // Run heuristic analysis with crash recovery
    HeuristicReport report;
    g_recovery_active = 1;
    int sig = sigsetjmp(g_recovery_jmp, 1);
    int result;
    if (sig != 0) {
      g_recovery_active = 0;
      fprintf(stderr, "\n[RECOVERY] Library crashed (%s) during XML export analysis\n",
              SignalName(sig));
      result = -1;
      ResetAllocGuard();
    } else {
      result = HeuristicAnalyze(profilePath, nullptr);
      g_recovery_active = 0;
    }

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
