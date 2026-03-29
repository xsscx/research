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
#include "IccImageAnalyzer.h"
#include "IccAnalyzerJson.h"
#include "IccAnalyzerReport.h"
#include "IccAnalyzerPAWG.h"
#include "IccAnalyzerLUTVisualization.h"
#include "IccHeuristicsRegistry.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <csignal>
#include <csetjmp>
#include <sys/stat.h>
#include <libgen.h>

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
  printf(ICCANALYZER_VERSION_FULL " - ICC Profile Conformance Auditor\n\n");
  printf("Usage: iccAnalyzer-lite [OPTIONS] [--legacy] <file>\n\n");

  printf("Conformance Modes (default — ICC specification auditing):\n");
  printf("  -a <file>                  Conformance audit (auto-detects TIFF/PNG/JPEG/ICC)\n");
  printf("  -pawg <file>               ICC PAWG assessment report (31-item checklist)\n");
  printf("  --json <file>              Conformance results as structured JSON\n");
  printf("  --report <file>            Conformance report (severity-sorted)\n");
  printf("  -xml <file.icc> <out.xml>  Conformance report as XML + XSLT\n");
  printf("  --registry                 Emit heuristic database as JSON (source of truth)\n");

  printf("\nLegacy Mode (backward-looking vulnerability analysis):\n");
  printf("  --legacy                   Add 171-heuristic CVE/GHSA pattern analysis\n");
  printf("  -h <file.icc>              Security heuristics only (always legacy)\n");
  printf("  Examples:\n");
  printf("    -a --legacy <file>       Full conformance + vulnerability analysis\n");
  printf("    --json --legacy <file>   JSON with heuristic findings included\n");

  printf("\nStructure & Inspection:\n");
  printf("  -r <file.icc>              Round-trip accuracy test\n");
  printf("  -img <file>                Image analysis (TIFF/PNG/JPEG with ICC extraction)\n");
  printf("  -n <file.icc>              Ninja mode (minimal output)\n");
  printf("  -nf <file.icc>             Ninja mode (full dump, no truncation)\n");
  printf("  -dump <file.icc>           Full profile dump (DumpAll: header, tags, v5 summary)\n");
  printf("  -cg <crash.log> [out.png]  Call graph from ASAN/UBSAN log\n");
  printf("  -luts <file.icc> [base]    LUT visualization (SVG curves + TIFF 3D CLUTs)\n");

  printf("\nLUT I/O:\n");
  printf("  -x <file.icc> <basename>   Extract LUT tables (binary CLUT)\n");
  printf("  -xt <file.icc> <basename>  Extract LUT tables as editable text (TSV)\n");
  printf("  -i <file.icc> <clut.bin> <output.icc>   Inject binary CLUT (lut8/16)\n");
  printf("  -im <file.icc> <clut.bin> <output.icc>  Inject binary CLUT (MPE)\n");
  printf("  -it <file.icc> <text.txt> <output.icc> [tag]  Import edited text LUT\n");
  printf("  -cube <file.icc> <output.cube> [tag]    Export 3D CLUT as .cube\n");
  printf("  -from-cube <file.cube> <output.icc>     Create ICC profile from .cube\n");

  printf("\nImage Analysis (-a auto-detect, or -img explicit):\n");
  printf("  TIFF: Extract embedded ICC (tag 34675), report metadata, scan injections\n");
  printf("  PNG:  Extract ICC from iCCP chunk\n");
  printf("  JPEG: Extract ICC from APP2 marker\n");

  printf("\nExit Codes:\n");
  printf("  0  Clean    - Profile analyzed, no issues detected\n");
  printf("  1  Finding  - Conformance issues or heuristic warnings detected\n");
  printf("  2  Error    - I/O error (file not found, profile read failure)\n");
  printf("  3  Usage    - Bad arguments or unknown option\n");

  printf("\nNote: Default mode is conformance auditing (ICC spec validation).\n");
  printf("      Use --legacy to include backward-looking vulnerability heuristics.\n");
}

int main(int argc, char **argv) {
  InstallCrashRecovery();

  if (argc < 2) {
    PrintUsage();
    return ICC_EXIT_USAGE;
  }

  // Scan for --legacy modifier flag and strip it from effective argv.
  // --legacy re-enables the 171-heuristic vulnerability analysis (disabled by
  // default in conformance-first mode). Can appear anywhere in argv.
  bool legacyMode = false;
  static char *effectiveArgv[128];
  int effectiveArgc = 0;
  for (int i = 0; i < argc && effectiveArgc < 127; i++) {
    if (strcmp(argv[i], "--legacy") == 0) {
      legacyMode = true;
    } else {
      effectiveArgv[effectiveArgc++] = argv[i];
    }
  }
  effectiveArgv[effectiveArgc] = nullptr;
  argc = effectiveArgc;
  argv = effectiveArgv;

  if (argc < 2) {
    PrintUsage();
    return ICC_EXIT_USAGE;
  }

  const char *mode = argv[1];

  // Validate profile path for modes that accept one (skip -cg which takes log files)
  const char *profilePath = nullptr;
  if (argc >= 3 && strcmp(mode, "--version") != 0 && strcmp(mode, "-version") != 0
      && strcmp(mode, "--registry") != 0 && strcmp(mode, "-cg") != 0) {
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

  // JSON output mode
  if (strcmp(mode, "--json") == 0 && argc >= 3) {
    return RecoverableRun("JSON analysis", [&]{ return RunWithJsonOutput(profilePath, nullptr, legacyMode); });
  }

  // Report output mode (severity-sorted professional report)
  if (strcmp(mode, "--report") == 0 && argc >= 3) {
    return RecoverableRun("report analysis", [&]{ return RunWithReportOutput(profilePath, nullptr, legacyMode); });
  }

  // PAWG assessment report (ICC Profile Assessment Working Group checklist)
  if (strcmp(mode, "-pawg") == 0 && argc >= 3) {
    return RecoverableRun("PAWG assessment", [&]{ return RunWithPAWGOutput(profilePath, nullptr); });
  }

  // Comprehensive mode (pass NULL for fingerprint_db in lite version)
  if (strcmp(mode, "-a") == 0 && argc >= 3) {
    // Auto-detect: if file is an image (TIFF/PNG/JPEG), use image analyzer
    ImageFormat fmt = DetectFileFormat(profilePath);
    if (fmt == ImageFormat::TIFF_LE || fmt == ImageFormat::TIFF_BE ||
        fmt == ImageFormat::BIGTIFF_LE || fmt == ImageFormat::BIGTIFF_BE) {
      return RecoverableRun("TIFF image analysis", [&]{ return AnalyzeTiffImage(profilePath, nullptr); });
    }
    if (fmt == ImageFormat::PNG) {
      return RecoverableRun("PNG image analysis", [&]{ return AnalyzePngImage(profilePath, nullptr); });
    }
    if (fmt == ImageFormat::JPEG) {
      return RecoverableRun("JPEG image analysis", [&]{ return AnalyzeJpegImage(profilePath, nullptr); });
    }
    return RecoverableRun("comprehensive analysis", [&]{ return ComprehensiveAnalyze(profilePath, nullptr, legacyMode); });
  }

  // Image analysis mode (explicit — any image format)
  if (strcmp(mode, "-img") == 0 && argc >= 3) {
    return RecoverableRun("image analysis", [&]{ return AnalyzeImageFile(profilePath, nullptr); });
  }

  // Ninja mode
  if (strcmp(mode, "-n") == 0 && argc >= 3) {
    return RecoverableRun("ninja analysis", [&]{ return NinjaModeAnalyze(profilePath, false); });
  }

  // Ninja mode (full dump)
  if (strcmp(mode, "-nf") == 0 && argc >= 3) {
    return RecoverableRun("ninja analysis (full)", [&]{ return NinjaModeAnalyze(profilePath, true); });
  }

  // Call graph mode (ASAN/UBSAN log analysis — no ICC profile needed)
  if (strcmp(mode, "-cg") == 0) {
    return RecoverableRun("call graph analysis", [&]{ return RunCallGraphMode(argc, argv); });
  }

  // LUT visualization mode (SVG 1D curves + TIFF 3D CLUTs)
  if (strcmp(mode, "-luts") == 0 && argc >= 3) {
    const char *outBase = (argc >= 4) ? argv[3] : nullptr;
    return RecoverableRun("LUT visualization", [&]{ return ProcessLutVisualization(profilePath, outBase); });
  }

  // DumpAll mode (full profile dump: header, tags, v5 summary, MPE chains)
  if (strcmp(mode, "-dump") == 0 && argc >= 3) {
    return RecoverableRun("profile dump", [&]{ return DumpAllAnalysis(profilePath, 100); });
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

  // Extract LUT as editable text (TSV)
  if (strcmp(mode, "-xt") == 0 && argc >= 4) {
    // argv[3] is a filename prefix, not a single file — validate parent dir exists
    const char *baseName = argv[3];
    if (!baseName || baseName[0] == '\0' || strlen(baseName) > 4000) {
      fprintf(stderr, "[ERR] Invalid output prefix\n");
      return ICC_EXIT_ERROR;
    }
    return RecoverableRun("LUT text extraction", [&]{ return ExtractLutText(profilePath, baseName); });
  }

  // Inject binary CLUT (lut8/lut16)
  if (strcmp(mode, "-i") == 0 && argc >= 5) {
    return RecoverableRun("CLUT injection", [&]{ return InjectLutData(argc, argv); });
  }

  // Inject binary CLUT (MPE)
  if (strcmp(mode, "-im") == 0 && argc >= 5) {
    return RecoverableRun("MPE CLUT injection", [&]{ return InjectMpeLutData(argc, argv); });
  }

  // Import edited text LUT into profile
  if (strcmp(mode, "-it") == 0 && argc >= 5) {
    const char *textFile = argv[3];
    const char *outFile = argv[4];
    const char *tagSig = (argc >= 6) ? argv[5] : nullptr;
    return RecoverableRun("text LUT import", [&]{
      return ImportTextLutData(profilePath, outFile, textFile, tagSig);
    });
  }

  // Export .cube from ICC profile
  if (strcmp(mode, "-cube") == 0 && argc >= 4) {
    const char *tagSig = argv[3];
    const char *cubeOut = (argc >= 5) ? argv[4] : nullptr;
    if (!cubeOut) {
      fprintf(stderr, "Usage: %s -cube <profile> <tag> <output.cube>\n", argv[0]);
      return 3;
    }
    return RecoverableRun("cube export", [&]{
      return ExportCubeFromProfile(profilePath, tagSig, cubeOut);
    });
  }

  // Import .cube into ICC DeviceLink profile
  if (strcmp(mode, "-from-cube") == 0 && argc >= 4) {
    const char *cubeIn = argv[2];
    const char *outFile = argv[3];
    return RecoverableRun("cube import", [&]{
      return ImportCubeToProfile(cubeIn, outFile);
    });
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
    // Resolve output path via realpath on parent directory
    char xmlPathCopy[PATH_MAX];
    strncpy(xmlPathCopy, outXml, PATH_MAX - 1);
    xmlPathCopy[PATH_MAX - 1] = '\0';
    char *xmlDir = dirname(xmlPathCopy);
    char resolvedXmlDir[PATH_MAX];
    if (!realpath(xmlDir, resolvedXmlDir)) {
      fprintf(stderr, "[ERR] Cannot resolve output directory: %s\n", xmlDir);
      return ICC_EXIT_ERROR;
    }
    char xmlPathCopy2[PATH_MAX];
    strncpy(xmlPathCopy2, outXml, PATH_MAX - 1);
    xmlPathCopy2[PATH_MAX - 1] = '\0';
    char resolvedXml[PATH_MAX];
    int xmlN = snprintf(resolvedXml, PATH_MAX, "%s/%s", resolvedXmlDir, basename(xmlPathCopy2));
    if (xmlN < 0 || xmlN >= PATH_MAX) {
      fprintf(stderr, "[ERR] XML output path too long (truncated)\n");
      return ICC_EXIT_ERROR;
    }
    outXml = resolvedXml;
    return RecoverableRun("XML export", [&]{ return IccAnalyzerXMLExport::RunWithXMLOutput(profilePath, outXml, nullptr, legacyMode); });
  }

  // Registry dump — emit heuristic database as JSON (source of truth for all counts)
  if (strcmp(mode, "--registry") == 0) {
    RegistryStats stats = ComputeRegistryStats();
    printf("{\n");
    printf("  \"version\": \"%s\",\n", ICCANALYZER_VERSION_FULL);
    printf("  \"totalHeuristics\": %d,\n", stats.totalHeuristics);
    printf("  \"heuristicsWithCVE\": %d,\n", stats.heuristicsWithCVE);
    printf("  \"uniqueCVEs\": %d,\n", stats.uniqueCVEs);
    printf("  \"uniqueGHSAs\": %d,\n", stats.uniqueGHSAs);
    printf("  \"severity\": {\n");
    printf("    \"CRITICAL\": %d,\n", stats.severity[0]);
    printf("    \"HIGH\": %d,\n", stats.severity[1]);
    printf("    \"MEDIUM\": %d,\n", stats.severity[2]);
    printf("    \"LOW\": %d,\n", stats.severity[3]);
    printf("    \"INFO\": %d\n", stats.severity[4]);
    printf("  },\n");
    printf("  \"heuristics\": [\n");
    for (size_t i = 0; i < kHeuristicRegistrySize; i++) {
      const auto &h = kHeuristicRegistry[i];
      printf("    {\"id\": %d, \"name\": \"%s\", \"specRef\": %s%s%s, "
             "\"cwe\": \"%s\", \"cveRefs\": %s%s%s, \"phase\": \"%s\", \"severity\": \"%s\"}%s\n",
             h.id, h.name,
             h.specRef ? "\"" : "", h.specRef ? h.specRef : "null", h.specRef ? "\"" : "",
             h.primaryCWE,
             h.cveRefs ? "\"" : "", h.cveRefs ? h.cveRefs : "null", h.cveRefs ? "\"" : "",
             PhaseToString(h.phase),
             SeverityToString(h.severity),
             (i + 1 < kHeuristicRegistrySize) ? "," : "");
    }
    printf("  ]\n");
    printf("}\n");
    return ICC_EXIT_CLEAN;
  }

  // Version
  if (strcmp(mode, "--version") == 0 || strcmp(mode, "-version") == 0) {
    printf("=======================================================================\n");
    printf("|                     %-47s |\n", ICCANALYZER_VERSION_FULL);
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
