/*
 * IccAnalyzerPAWG.cpp — ICC Profile Assessment Working Group report output
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Runs ComprehensiveAnalyze() with HeuristicCollector in quiet mode, then reads
 * structured results directly to build a report organized per the ICC PAWG
 * checklist:
 *
 *   SECURITY (13 items)
 *   CONFORMANCE (14 items)
 *   QUALITY (4 items)
 *
 * Each PAWG item maps to one or more ICC conformance checks (CF-*). The item
 * verdict is PASS when every mapped check is [OK], WARN when at least one
 * is [WARN], and FAIL when at least one is non-conformant. When every mapped
 * check skips, PAWG distinguishes:
 *   N/A     - genuinely not applicable to this profile shape/class
 *   GAP     - current coverage/applicability gap
 *   NOT RUN - runtime/execution failure prevented evaluation
 *
 * Reference: ICC Profile Assessment Working Group — Goals for profile assessment
 */

#include "IccAnalyzerPAWG.h"
#include "IccAnalyzerCommon.h"
#include "IccAnalyzerHash.h"
#include "IccAnalyzerComprehensive.h"
#include "PawgSpecReferences.h"
#include "IccHeuristicsRegistry.h"
#include "IccConformanceRegistry.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "IccHeuristicResult.h"

// ── Heuristic result from captured output ────────────────────────────────────

struct PAWGHeuristicResult {
  int id;
  std::string name;
  std::string status;   // "ok", "warn", "critical"
  std::string detail;
};

// ── PAWG checklist item ──────────────────────────────────────────────────────

enum class PAWGVerdict {
  PASS = 0,
  WARN = 1,
  FAIL = 2,
  NOT_APPLICABLE = 3,
  GAP = 4,
  NOT_RUN = 5
};

struct PAWGItem {
  const char *id;           // e.g. "S1", "C14", "Q28"
  const char *title;        // PAWG checklist text
  const int  *checks;       // NULL-terminated list of conformance check IDs (1001+)
  int         checkCount;   // number of mapped checks
  PAWGVerdict allSkippedVerdict;
  PAWGVerdict verdict;
  std::vector<std::string> detailLines;
};

// ── Conformance check mappings (CF-* IDs = CF number + 1000) ─────────────────
// Security items: mapped to ICC spec conformance checks where applicable.
// When every mapped check skips, items default to either N/A or GAP.

static const int kS1[]  = { 1060, 1061, 0 };                    // LUT channel counts
static const int kS2[]  = { 1010, 1006, 1012, 1013, 0 };        // header encoding
static const int kS3[]  = { 1007, 0 };                          // platform signature
static const int kS4[]  = { 1008, 0 };                          // D50 illuminant
static const int kS5[]  = { 1014, 0 };                          // PCS field
static const int kS6[]  = { 1020, 1103, 1107, 0 };               // tag alignment + ordering
static const int kS7[]  = { 1040, 0 };                          // tag table
static const int kS8[]  = { 1091, 0 };                          // malware scan
static const int kS9[]  = { 1010, 0 };                          // EOF/size
static const int kS10[] = { 1088, 1062, 0 };                    // calculator elements
static const int kS11[] = { 1092, 0 };                          // private tag presence
static const int kS12[] = { 1093, 0 };                          // private tag content scan
static const int kS13[] = { 1094, 0 };                          // NOP/shellcode pattern scan

// Conformance items: mapped to ICC spec conformance checks.
static const int kC14[] = { 1020, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1032, 1033, 1034, 1112, 0 };
static const int kC15[] = { 1040, 0 };                          // cprt/desc in common required
static const int kC16[] = { 1020, 0 };                          // allowed tag types
static const int kC17[] = { 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1104, 1111, 0 };
static const int kC18[] = { 1095, 0 };                          // non-required tags
static const int kC19[] = { 1096, 0 };                          // private tag registration
static const int kC20[] = { 1097, 0 };                          // private tag documentation
static const int kC21[] = { 1098, 0 };                          // undocumented private tags
static const int kC22[] = { 1012, 1013, 0 };                    // class/colour space
static const int kC23[] = { 1001, 1002, 1003, 1004, 1005, 1006, 1008, 1009, 1014, 1015, 1121, 1122, 0 };
static const int kC24[] = { 1048, 1053, 0 };                    // tags vs version
static const int kC25[] = { 1008, 0 };                          // wtpt D50
static const int kC26[] = { 1015, 0 };                          // reserved bytes
static const int kC27[] = { 1020, 1103, 0 };                     // 4-byte boundaries

// Quality items default to GAP when every mapped check skips, unless a skip
// reason clearly indicates true not-applicable semantics for the profile.
static const int kQ28[] = { 1099, 0 };                          // round-trip CIEDE2000
static const int kQ29[] = { 1100, 1106, 0 };                     // curve invertibility + monotonicity
static const int kQ30[] = { 1101, 0 };                          // transform smoothness
static const int kQ31[] = { 1102, 0 };                          // characterization round-trip

// ── Build the PAWG checklist ─────────────────────────────────────────────────

#define PAWG_ITEM(code, text, arr, skipVerdict) \
  { code, text, arr, (int)(sizeof(arr)/sizeof(arr[0]) - 1), skipVerdict, PAWGVerdict::NOT_RUN, {} }

static PAWGItem BuildSecurityItems[] = {
  PAWG_ITEM("S1",  "Do channel counts in tags match the data colour space?", kS1, PAWGVerdict::GAP),
  PAWG_ITEM("S2",  "Is header 128 bytes and correctly encoded?", kS2, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("S3",  "Do Platform, Creator, Manufacturer and CMM fields correspond to registered signatures or are zero?", kS3, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("S4",  "Does illuminant correspond to D50?", kS4, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("S5",  "Is PCS Lab or XYZ (unless DeviceLink profile)?", kS5, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("S6",  "Are tags correctly aligned - offset and length correspond to tag table, no overlapping tags or gaps between tags - and correctly encoded?", kS6, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("S7",  "Is the tag table correctly encoded?", kS7, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("S8",  "Is the profile free of known malware signatures?", kS8, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("S9",  "Does EOF follow last tag (including four-byte boundary), with no additional bytes before or after?", kS9, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("S10", "[iccMAX profiles only] Are excessive calculator elements avoided (if possible provide an estimate of computation cost)", kS10, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("S11", "Are private tags absent?", kS11, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("S12", "If present, are private tags free of malware?", kS12, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("S13", "If present, are private tags free of exploitable non-operation (NOP) instructions?", kS13, PAWGVerdict::NOT_APPLICABLE),
};

static PAWGItem BuildConformanceItems[] = {
  PAWG_ITEM("C1",  "Are tag types correctly encoded (signature, structure, data types, ranges, encoded values)?", kC14, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C2",  "Are cprt and desc tags encoded as Unicode or text according to specification version?", kC15, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C3",  "Do tags only use tag types allowed for the tag?", kC16, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C4",  "Are all required tags for profile class present?", kC17, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C5",  "Is the profile free of additional tags not required for profile class (other than allowed optional tags); if present are they flagged as private tags?", kC18, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C6",  "If present, do private tags have a registered signature?", kC19, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C7",  "If present, is documentation for private tags available through the tag registry?", kC20, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C8",  "Are any undocumented private tags identified?", kC21, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C9",  "Is the profile class consistent with the data colour space?", kC22, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C10", "Does the header content conform with the specification?", kC23, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C11", "Do the tags present correspond to the profile version?", kC24, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C12", "Is the white point correctly encoded (D50 for v4 display; or valid value for other profile classes)?", kC25, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C13", "Are reserved bytes zero?", kC26, PAWGVerdict::NOT_APPLICABLE),
  PAWG_ITEM("C14", "Do tags start and end on four-byte boundaries?", kC27, PAWGVerdict::NOT_APPLICABLE),
};

static PAWGItem BuildQualityItems[] = {
  PAWG_ITEM("Q1",  "First and second round trip average and maximum differences in CIEDE2000", kQ28, PAWGVerdict::GAP),
  PAWG_ITEM("Q2",  "Curve round trip differences in CIEDE2000 (i.e. can be inverted)", kQ29, PAWGVerdict::GAP),
  PAWG_ITEM("Q3",  "Smoothness metric values of overall transform", kQ30, PAWGVerdict::GAP),
  PAWG_ITEM("Q4",  "Round trip average and maximum differences of profile output in CIEDE2000 (if characterization data is present)", kQ31, PAWGVerdict::GAP),
};

#undef PAWG_ITEM

static long PAWGGetFileSize(const char *path) {
  struct stat st;
  if (stat(path, &st) != 0) return -1;
  return st.st_size;
}

// ── Print helpers ────────────────────────────────────────────────────────────

static void PAWGRule(int width) {
  for (int i = 0; i < width; i++) printf("-");
  printf("\n");
}

static void PAWGBanner(const char *title, int width) {
  int titleLen = (int)strlen(title);
  int pad = (width - titleLen - 4) / 2;
  if (pad < 0) pad = 0;
  for (int i = 0; i < pad; i++) printf("=");
  printf("[ %s ]", title);
  int remaining = width - pad - titleLen - 4;
  for (int i = 0; i < remaining; i++) printf("=");
  printf("\n");
}

static const char *VerdictIcon(PAWGVerdict v) {
  switch (v) {
    case PAWGVerdict::PASS:    return "[OK]  ";
    case PAWGVerdict::WARN:    return "[WARN]";
    case PAWGVerdict::FAIL:    return "[FAIL]";
    case PAWGVerdict::NOT_APPLICABLE: return "[N/A] ";
    case PAWGVerdict::GAP:     return "[GAP] ";
    case PAWGVerdict::NOT_RUN: return "[ -- ]";
  }
  return "[??]  ";
}

static PAWGVerdict UpgradeVerdict(PAWGVerdict current, PAWGVerdict candidate) {
  if (candidate == PAWGVerdict::NOT_RUN) return current;
  if (current == PAWGVerdict::NOT_RUN) return candidate;
  return (int)candidate > (int)current ? candidate : current;
}

static std::string TrimCopy(const std::string &text) {
  size_t begin = text.find_first_not_of(" \t");
  if (begin == std::string::npos) return std::string();
  size_t end = text.find_last_not_of(" \t");
  return text.substr(begin, end - begin + 1);
}

static bool ExtractExplicitCoverageVerdict(const std::string &detail,
                                           PAWGVerdict &verdict,
                                           std::string &matchedLine) {
  std::istringstream iss(detail);
  std::string line;
  while (std::getline(iss, line)) {
    std::string trimmed = TrimCopy(line);
    if (trimmed.rfind("NOT RUN:", 0) == 0) {
      verdict = PAWGVerdict::NOT_RUN;
      matchedLine = trimmed;
      return true;
    }
    if (trimmed.rfind("N/A:", 0) == 0) {
      verdict = PAWGVerdict::NOT_APPLICABLE;
      matchedLine = trimmed;
      return true;
    }
    if (trimmed.rfind("GAP:", 0) == 0) {
      verdict = PAWGVerdict::GAP;
      matchedLine = trimmed;
      return true;
    }
  }
  return false;
}

static bool IsRuntimeSkipDetail(const std::string &detail) {
  return detail.find("Library failed to load") != std::string::npos ||
         detail.find("not loaded") != std::string::npos ||
         detail.find("read failed") != std::string::npos ||
         detail.find("failed to load") != std::string::npos ||
         detail.find("unsafe") != std::string::npos;
}

static bool IsExplicitNotApplicableDetail(const std::string &detail) {
  return detail.find("not applicable") != std::string::npos ||
         detail.find("N/A") != std::string::npos ||
         detail.find("exempt") != std::string::npos ||
         detail.find("No charTargetTag present") != std::string::npos ||
         detail.find("No characterization data") != std::string::npos;
}

static PAWGVerdict ClassifySkippedDetail(const std::string &detail,
                                         PAWGVerdict defaultVerdict) {
  if (IsRuntimeSkipDetail(detail)) return PAWGVerdict::NOT_RUN;
  if (IsExplicitNotApplicableDetail(detail)) return PAWGVerdict::NOT_APPLICABLE;
  return defaultVerdict;
}

static PAWGVerdict MergeSkippedVerdict(PAWGVerdict current,
                                       PAWGVerdict candidate) {
  if (current == PAWGVerdict::NOT_RUN || candidate == PAWGVerdict::NOT_RUN)
    return PAWGVerdict::NOT_RUN;
  if (current == PAWGVerdict::GAP || candidate == PAWGVerdict::GAP)
    return PAWGVerdict::GAP;
  if (current == PAWGVerdict::NOT_APPLICABLE ||
      candidate == PAWGVerdict::NOT_APPLICABLE)
    return PAWGVerdict::NOT_APPLICABLE;
  return candidate;
}

static void AppendSkippedCheckDetail(PAWGItem &item,
                                     int cid,
                                     const std::string &detail,
                                     PAWGVerdict verdict) {
  char cfLabel[16];
  snprintf(cfLabel, sizeof(cfLabel), "CF-%03d", cid - 1000);

  std::string line = cfLabel;
  line += ": ";
  line += detail.empty() ? "check skipped" : detail;
  switch (verdict) {
    case PAWGVerdict::NOT_APPLICABLE:
      line += " [N/A]";
      break;
    case PAWGVerdict::GAP:
      line += " [GAP]";
      break;
    case PAWGVerdict::NOT_RUN:
      line += " [ -- ]";
      break;
    default:
      break;
  }
  item.detailLines.push_back(line);
}

struct PAWGTotals {
  int pass = 0;
  int warn = 0;
  int fail = 0;
  int notApplicable = 0;
  int gap = 0;
  int notRun = 0;
};

static void CountVerdict(PAWGTotals &totals, PAWGVerdict verdict) {
  switch (verdict) {
    case PAWGVerdict::PASS: ++totals.pass; break;
    case PAWGVerdict::WARN: ++totals.warn; break;
    case PAWGVerdict::FAIL: ++totals.fail; break;
    case PAWGVerdict::NOT_APPLICABLE: ++totals.notApplicable; break;
    case PAWGVerdict::GAP: ++totals.gap; break;
    case PAWGVerdict::NOT_RUN: ++totals.notRun; break;
  }
}

// ── Score a PAWG item against collected heuristic results ────────────────────

static void ScorePAWGItem(PAWGItem &item,
                          const std::map<int, PAWGHeuristicResult> &results) {
  item.verdict = PAWGVerdict::NOT_RUN;
  item.detailLines.clear();

  bool anyFound = false;
  bool anyEvaluated = false;
  PAWGVerdict worst = PAWGVerdict::PASS;
  std::vector<std::pair<int, std::string>> skippedChecks;
  std::vector<std::pair<int, std::pair<PAWGVerdict, std::string>>> coverageChecks;

  for (int i = 0; i < item.checkCount; i++) {
    int cid = item.checks[i];
    auto it = results.find(cid);
    if (it == results.end()) continue;

    anyFound = true;
    const auto &r = it->second;

    if (r.status == "skip") {
      skippedChecks.push_back(std::make_pair(cid, r.detail));
      continue;
    }

    PAWGVerdict explicitVerdict = PAWGVerdict::PASS;
    std::string explicitDetail;
    if (r.status == "ok" &&
        ExtractExplicitCoverageVerdict(r.detail, explicitVerdict, explicitDetail)) {
      coverageChecks.push_back(
          std::make_pair(cid, std::make_pair(explicitVerdict, explicitDetail)));
      continue;
    }
    anyEvaluated = true;

    PAWGVerdict hv = PAWGVerdict::PASS;
    if (r.status == "critical") hv = PAWGVerdict::FAIL;
    else if (r.status == "warn")  hv = PAWGVerdict::WARN;

    worst = UpgradeVerdict(worst, hv);

    // Collect detail from non-conformant checks only
    if (hv != PAWGVerdict::PASS && !r.detail.empty()) {
      const char *statusTag = (r.status == "critical") ? " [FAIL]" :
                              (r.status == "warn")     ? " [WARN]" : "";
      char cfLabel[16];
      snprintf(cfLabel, sizeof(cfLabel), "CF-%03d", cid - 1000);
      std::istringstream ds(r.detail);
      std::string dl;
      while (std::getline(ds, dl)) {
        size_t first = dl.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        std::string trimmed = dl.substr(first);
        if (trimmed.find("[H") == 0 || trimmed.find("[CF") == 0) continue;
        if (trimmed.find("[OK]") != std::string::npos) continue;
        if (trimmed.find("=====") != std::string::npos) continue;
        item.detailLines.push_back(std::string(cfLabel) + ": " + trimmed + statusTag);
      }
    }
  }

  if (!anyFound) {
    item.verdict = PAWGVerdict::NOT_RUN;
    item.detailLines.push_back("No mapped conformance checks were executed [ -- ]");
    return;
  }

  if (!anyEvaluated) {
    PAWGVerdict skippedVerdict = PAWGVerdict::NOT_APPLICABLE;
    for (const auto &entry : coverageChecks) {
      skippedVerdict = MergeSkippedVerdict(skippedVerdict, entry.second.first);
    }
    for (const auto &entry : skippedChecks) {
      skippedVerdict = MergeSkippedVerdict(
          skippedVerdict,
          ClassifySkippedDetail(entry.second, item.allSkippedVerdict));
    }
    item.verdict = skippedVerdict;
    for (const auto &entry : coverageChecks) {
      AppendSkippedCheckDetail(item, entry.first, entry.second.second,
                               entry.second.first);
    }
    for (const auto &entry : skippedChecks) {
      AppendSkippedCheckDetail(item, entry.first, entry.second, skippedVerdict);
    }
    return;
  }

  item.verdict = worst;
}

// ── Print one section of PAWG items ──────────────────────────────────────────

static void PrintPAWGSection(const char *sectionTitle,
                             PAWGItem *items, int count,
                             PAWGTotals &totals) {
  const int W = 78;
  printf("\n");
  PAWGBanner(sectionTitle, W);
  printf("\n");

  for (int i = 0; i < count; i++) {
    const auto &item = items[i];
    printf("  %s  %-4s  %s\n", VerdictIcon(item.verdict), item.id, item.title);

    // Print mapped conformance checks on next line
    if (item.checkCount > 0) {
      printf("          Checks: ");
      for (int j = 0; j < item.checkCount; j++) {
        if (j > 0) printf(", ");
        printf("CF-%03d", item.checks[j] - 1000);
      }
      printf("\n");
    } else {
      printf("          Checks: (none mapped)\n");
    }

    if (!item.detailLines.empty()) {
      for (const auto &dl : item.detailLines) {
        if (!dl.empty()) printf("          %s\n", dl.c_str());
      }
    }
    printf("\n");

    CountVerdict(totals, item.verdict);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  RunWithPAWGOutput — Main entry point
// ══════════════════════════════════════════════════════════════════════════════

int RunWithPAWGOutput(const char *profilePath, const char *fingerprint_db) {
  // ── Step 1: Run analysis with HeuristicCollector in quiet mode ────────────
  auto &hc = HeuristicCollector::instance();
  hc.reset();
  hc.setCollecting(true);
  hc.setQuiet(true);

  // Redirect stdout to /dev/null for phase banner printf calls
  int savedStdout = dup(STDOUT_FILENO);
  int devNull = open("/dev/null", O_WRONLY);
  if (devNull >= 0) {
    dup2(devNull, STDOUT_FILENO);
    close(devNull);
  }

  int exitCode = ComprehensiveAnalyze(profilePath, fingerprint_db, false);

  fflush(stdout);
  if (savedStdout >= 0) {
    dup2(savedStdout, STDOUT_FILENO);
    close(savedStdout);
  }
  hc.setQuiet(false);

  // ── Step 2: Build results map from HeuristicCollector ─────────────────────
  std::map<int, PAWGHeuristicResult> results;

  for (const auto &hf : hc.results()) {
    PAWGHeuristicResult r;
    r.id = hf.id;
    r.name = hf.title;
    r.status = hf.status;
    // Join detail lines
    for (size_t i = 0; i < hf.details.size(); ++i) {
      if (i > 0) r.detail += "\n";
      r.detail += hf.details[i];
    }
    results[hf.id] = std::move(r);
  }

  // ── Step 3: Score every PAWG item ─────────────────────────────────────────
  const int nSecurity    = sizeof(BuildSecurityItems)    / sizeof(BuildSecurityItems[0]);
  const int nConformance = sizeof(BuildConformanceItems) / sizeof(BuildConformanceItems[0]);
  const int nQuality     = sizeof(BuildQualityItems)     / sizeof(BuildQualityItems[0]);

  for (int i = 0; i < nSecurity;    i++) ScorePAWGItem(BuildSecurityItems[i],    results);
  for (int i = 0; i < nConformance; i++) ScorePAWGItem(BuildConformanceItems[i], results);
  for (int i = 0; i < nQuality;     i++) ScorePAWGItem(BuildQualityItems[i],     results);

  // ── Step 4: Emit the report ───────────────────────────────────────────────
  const int W = 78;
  std::string sha256 = ComputeFileSHA256(profilePath);
  long fileSize = PAWGGetFileSize(profilePath);
  const std::vector<std::string> specReferences =
      iccanalyzer::pawg::listSpecReferencePaths(profilePath);
  time_t now = time(nullptr);
  char timeBuf[64];
  struct tm utc_buf;
  struct tm *utc = gmtime_r(&now, &utc_buf);
  strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S UTC", utc);

  // ── Header ────────────────────────────────────────────────────────────────
  printf("\n");
  for (int i = 0; i < W; i++) printf("=");
  printf("\n");
  PAWGBanner("ICC PROFILE ASSESSMENT REPORT (PAWG)", W);
  for (int i = 0; i < W; i++) printf("=");
  printf("\n\n");

  printf("  Reference:  ICC Profile Assessment Working Group\n");
  printf("              Goals for profile assessment\n");
  printf("  ICC Profile Assessment Working Group Checklist Reference: %s\n",
         iccanalyzer::pawg::kChecklistUrl);
  printf("  ICC Specification References:\n");
  for (const auto &ref : specReferences) {
    printf("    %s\n", ref.c_str());
  }
  printf("  Tool:       %s\n", ICCANALYZER_VERSION_FULL);
  printf("  Date:       %s\n", timeBuf);
  printf("  Build:      ASAN+UBSAN+Coverage | Clang 18\n");
  printf("\n");
  PAWGRule(W);
  printf("  File:       %s\n", profilePath);
  printf("  SHA-256:    %s\n", sha256.c_str());
  printf("  Size:       %ld bytes\n", fileSize);
  PAWGRule(W);
  printf("\n");

  // ── Sections ──────────────────────────────────────────────────────────────
  PAWGTotals totals;

  PrintPAWGSection("SECURITY", BuildSecurityItems, nSecurity,
                   totals);

  PrintPAWGSection("CONFORMANCE", BuildConformanceItems, nConformance,
                   totals);

  PrintPAWGSection("QUALITY", BuildQualityItems, nQuality,
                   totals);

  // ── Summary ───────────────────────────────────────────────────────────────
  int totalItems = nSecurity + nConformance + nQuality;

  printf("\n");
  PAWGBanner("ASSESSMENT SUMMARY", W);
  printf("\n");
  printf("  Total checklist items:  %d\n", totalItems);
  printf("  PASS:                   %d\n", totals.pass);
  printf("  WARN:                   %d\n", totals.warn);
  printf("  FAIL:                   %d\n", totals.fail);
  if (totals.notApplicable > 0)
    printf("  N/A:                    %d\n", totals.notApplicable);
  if (totals.gap > 0)
    printf("  GAP:                    %d\n", totals.gap);
  if (totals.notRun > 0)
    printf("  NOT RUN:                %d\n", totals.notRun);
  printf("\n");

  // Overall verdict
  const char *overall;
  if (totals.fail > 0)
    overall = "FAIL - Profile does not meet ICC PAWG assessment criteria";
  else if (totals.warn > 0)
    overall = "CONDITIONAL PASS - Warnings detected, review recommended";
  else if ((totals.pass + totals.notApplicable) == totalItems &&
           totals.gap == 0 && totals.notRun == 0)
    overall = "PASS - Profile meets all ICC PAWG assessment criteria";
  else if (totals.gap > 0 || totals.notRun > 0)
    overall = "INCOMPLETE - Some checklist items are not yet covered or could not be evaluated";
  else
    overall = "PASS - Profile meets all ICC PAWG assessment criteria";

  printf("  Overall:   %s\n", overall);
  printf("\n");

  // ── Conformance check coverage table ──────────────────────────────────────
  printf("\n");
  PAWGBanner("CONFORMANCE CHECK COVERAGE", W);
  printf("\n");
  size_t evaluatedConformance = 0;
  for (const auto &entry : results) {
    if (entry.first >= 1001 && entry.first < 2000) {
      ++evaluatedConformance;
    }
  }

  // Count unique conformance checks mapped by PAWG items
  std::set<int> mappedChecks;
  for (int i = 0; i < nSecurity;    i++)
    for (int j = 0; j < BuildSecurityItems[i].checkCount; j++)
      mappedChecks.insert(BuildSecurityItems[i].checks[j]);
  for (int i = 0; i < nConformance; i++)
    for (int j = 0; j < BuildConformanceItems[i].checkCount; j++)
      mappedChecks.insert(BuildConformanceItems[i].checks[j]);
  for (int i = 0; i < nQuality;     i++)
    for (int j = 0; j < BuildQualityItems[i].checkCount; j++)
      mappedChecks.insert(BuildQualityItems[i].checks[j]);

  ConformanceRegistryStats cfStats = ComputeConformanceRegistryStats();
  printf("  Checks evaluated:       %zu / %d\n",
         evaluatedConformance, cfStats.totalChecks);
  printf("  Checks mapped:          %zu (across %d PAWG items)\n",
         mappedChecks.size(), totalItems);
  printf("  Registry total:         %d conformance checks\n", cfStats.totalChecks);
  printf("  Spec coverage:          %d checks with ICC spec refs\n",
         cfStats.checksWithSpecRef);
  printf("\n");

  // ── Spec references ───────────────────────────────────────────────────────
  printf("\n");
  PAWGBanner("SPECIFICATION REFERENCES", W);
  printf("\n");
  for (const auto &ref : specReferences) {
    printf("  %s\n", ref.c_str());
  }
  printf("\n");

  // ── Footer ────────────────────────────────────────────────────────────────
  for (int i = 0; i < W; i++) printf("=");
  printf("\n");
  printf("  Report generated by %s\n", ICCANALYZER_VERSION_FULL);
  printf("  ICC PAWG checklist: 31 items (%d Security + %d Conformance + %d Quality)\n",
         nSecurity, nConformance, nQuality);
  for (int i = 0; i < W; i++) printf("=");
  printf("\n\n");

  return exitCode;
}
