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
 * Each PAWG item maps to one or more ICC conformance checks (CF-*).  The item
 * verdict is PASS when every mapped check is [OK], WARN when at least one
 * is [WARN], and FAIL when at least one is non-conformant.
 * Items without conformance check mappings (security-only, quality metrics)
 * receive NOT_RUN verdict.
 *
 * Reference: ICC Profile Assessment Working Group — Goals for profile assessment
 */

#include "IccAnalyzerPAWG.h"
#include "IccAnalyzerCommon.h"
#include "IccAnalyzerHash.h"
#include "IccAnalyzerComprehensive.h"
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

enum class PAWGVerdict { PASS, WARN, FAIL, NOT_RUN };

struct PAWGItem {
  const char *id;           // e.g. "S1", "C14", "Q28"
  const char *title;        // PAWG checklist text
  const int  *checks;       // NULL-terminated list of conformance check IDs (1001+)
  int         checkCount;   // number of mapped checks
  PAWGVerdict verdict;
  std::string detail;       // collected detail from triggered checks
};

// ── Conformance check mappings (CF-* IDs = CF number + 1000) ─────────────────
// Security items: mapped to ICC spec conformance checks where applicable.
// Security-only items (S8, S11, S12, S13) have no ICC spec basis → NOT_RUN.

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

// Quality items: require computational verification (CIEDE2000) → NOT_RUN.
static const int kQ28[] = { 1099, 0 };                          // round-trip CIEDE2000
static const int kQ29[] = { 1100, 1106, 0 };                     // curve invertibility + monotonicity
static const int kQ30[] = { 1101, 0 };                          // transform smoothness
static const int kQ31[] = { 1102, 0 };                          // characterization round-trip

// ── Build the PAWG checklist ─────────────────────────────────────────────────

#define PAWG_ITEM(code, text, arr) { code, text, arr, (int)(sizeof(arr)/sizeof(arr[0]) - 1), PAWGVerdict::NOT_RUN, {} }

static PAWGItem BuildSecurityItems[] = {
  PAWG_ITEM("S1",  "Channel counts in tags match data colour space", kS1),
  PAWG_ITEM("S2",  "Header is 128 bytes and correctly encoded", kS2),
  PAWG_ITEM("S3",  "Platform, Creator, Manufacturer and CMM fields correspond to registered signatures or are zero", kS3),
  PAWG_ITEM("S4",  "Illuminant corresponds to D50", kS4),
  PAWG_ITEM("S5",  "Unless a DeviceLink profile, PCS is Lab or XYZ", kS5),
  PAWG_ITEM("S6",  "Tags correctly aligned - offset and length correspond to tag table, no overlapping tags or gaps between tags - and correctly encoded", kS6),
  PAWG_ITEM("S7",  "Tag table correctly encoded", kS7),
  PAWG_ITEM("S8",  "No known malware signatures present", kS8),
  PAWG_ITEM("S9",  "EOF follows last tag (including four-byte boundary), no additional bytes before or after", kS9),
  PAWG_ITEM("S10", "Excessive calculator elements not present (ideally provide an estimate of computation cost)", kS10),
  PAWG_ITEM("S11", "Private tags ideally not present", kS11),
  PAWG_ITEM("S12", "Private tags do not contain malware", kS12),
  PAWG_ITEM("S13", "Private tags do not contain exploitable non-operation (NOP) instructions", kS13),
};

static PAWGItem BuildConformanceItems[] = {
  PAWG_ITEM("C1",  "Tag types are correctly encoded (signature, structure, data types, ranges, encoded values)", kC14),
  PAWG_ITEM("C2",  "cprt, desc tags encoded as Unicode or text according to specification version", kC15),
  PAWG_ITEM("C3",  "Tags only use tag types allowed for the tag", kC16),
  PAWG_ITEM("C4",  "All required tags for profile class are present", kC17),
  PAWG_ITEM("C5",  "Additional tags not required for profile class (other than allowed optional tags) are not present; or are flagged as private tags", kC18),
  PAWG_ITEM("C6",  "Private tags have a registered signature", kC19),
  PAWG_ITEM("C7",  "Private tag documentation is available through the tag registry", kC20),
  PAWG_ITEM("C8",  "Undocumented private tags are identified", kC21),
  PAWG_ITEM("C9",  "Profile class is consistent with data colour space", kC22),
  PAWG_ITEM("C10", "Header content conforms with specification", kC23),
  PAWG_ITEM("C11", "Tags present correspond to profile version", kC24),
  PAWG_ITEM("C12", "Wtpt correctly encoded - D50 for v4 display; or valid value for other profile classes", kC25),
  PAWG_ITEM("C13", "Reserved bytes are zero", kC26),
  PAWG_ITEM("C14", "Tags start and end on four-byte boundaries", kC27),
};

static PAWGItem BuildQualityItems[] = {
  PAWG_ITEM("Q1",  "First and second round trip average and maximum differences in CIEDE2000", kQ28),
  PAWG_ITEM("Q2",  "Curve round trip differences in CIEDE2000 (i.e. can be inverted)", kQ29),
  PAWG_ITEM("Q3",  "Smoothness metric values of overall transform", kQ30),
  PAWG_ITEM("Q4",  "If characterization data is present, round trip average and maximum differences of profile output in CIEDE2000", kQ31),
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
    case PAWGVerdict::NOT_RUN: return "[ -- ]";
  }
  return "[??]  ";
}

// ── Score a PAWG item against collected heuristic results ────────────────────

static void ScorePAWGItem(PAWGItem &item,
                          const std::map<int, PAWGHeuristicResult> &results) {
  bool anyFound = false;
  PAWGVerdict worst = PAWGVerdict::PASS;

  for (int i = 0; i < item.checkCount; i++) {
    int cid = item.checks[i];
    auto it = results.find(cid);
    if (it == results.end()) continue;

    anyFound = true;
    const auto &r = it->second;

    PAWGVerdict hv = PAWGVerdict::PASS;
    if (r.status == "critical") hv = PAWGVerdict::FAIL;
    else if (r.status == "warn")  hv = PAWGVerdict::WARN;

    if (static_cast<int>(hv) > static_cast<int>(worst))
      worst = hv;

    // Collect detail from non-conformant checks only
    if (hv != PAWGVerdict::PASS && !r.detail.empty()) {
      if (!item.detail.empty()) item.detail += "\n";
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
        if (!item.detail.empty() && item.detail.back() != '\n')
          item.detail += "\n";
        item.detail += "          ";
        item.detail += cfLabel;
        item.detail += ": ";
        item.detail += trimmed;
        item.detail += statusTag;
      }
    }
  }

  item.verdict = anyFound ? worst : PAWGVerdict::NOT_RUN;
}

// ── Print one section of PAWG items ──────────────────────────────────────────

static void PrintPAWGSection(const char *sectionTitle,
                             PAWGItem *items, int count,
                             int &passCount, int &warnCount, int &failCount) {
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

    // Print detail for non-PASS items
    if (item.verdict != PAWGVerdict::PASS &&
        item.verdict != PAWGVerdict::NOT_RUN &&
        !item.detail.empty()) {
      std::istringstream ds(item.detail);
      std::string dl;
      while (std::getline(ds, dl)) {
        if (!dl.empty()) printf("          %s\n", dl.c_str());
      }
    }
    printf("\n");

    switch (item.verdict) {
      case PAWGVerdict::PASS: passCount++; break;
      case PAWGVerdict::WARN: warnCount++; break;
      case PAWGVerdict::FAIL: failCount++; break;
      case PAWGVerdict::NOT_RUN: break;
    }
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
  int passCount = 0, warnCount = 0, failCount = 0;

  PrintPAWGSection("SECURITY", BuildSecurityItems, nSecurity,
                   passCount, warnCount, failCount);

  PrintPAWGSection("CONFORMANCE", BuildConformanceItems, nConformance,
                   passCount, warnCount, failCount);

  PrintPAWGSection("QUALITY", BuildQualityItems, nQuality,
                   passCount, warnCount, failCount);

  // ── Summary ───────────────────────────────────────────────────────────────
  int totalItems = nSecurity + nConformance + nQuality;
  int notRun = totalItems - passCount - warnCount - failCount;

  printf("\n");
  PAWGBanner("ASSESSMENT SUMMARY", W);
  printf("\n");
  printf("  Total checklist items:  %d\n", totalItems);
  printf("  PASS:                   %d\n", passCount);
  printf("  WARN:                   %d\n", warnCount);
  printf("  FAIL:                   %d\n", failCount);
  if (notRun > 0)
    printf("  NOT RUN:                %d\n", notRun);
  printf("\n");

  // Overall verdict
  const char *overall;
  if (failCount > 0)
    overall = "FAIL - Profile does not meet ICC PAWG assessment criteria";
  else if (warnCount > 0)
    overall = "CONDITIONAL PASS - Warnings detected, review recommended";
  else if (passCount == totalItems)
    overall = "PASS - Profile meets all ICC PAWG assessment criteria";
  else
    overall = "INCOMPLETE - Some checks could not be evaluated";

  printf("  Overall:   %s\n", overall);
  printf("\n");

  // ── Conformance check coverage table ──────────────────────────────────────
  printf("\n");
  PAWGBanner("CONFORMANCE CHECK COVERAGE", W);
  printf("\n");
  printf("  Checks evaluated:       %zu / %d\n", results.size(), kTotalHeuristics);

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

  printf("  Checks mapped:          %zu (across %d PAWG items)\n",
         mappedChecks.size(), totalItems);

  ConformanceRegistryStats cfStats = ComputeConformanceRegistryStats();
  printf("  Registry total:         %d conformance checks\n", cfStats.totalChecks);
  printf("  Spec coverage:          %d checks with ICC spec refs\n",
         cfStats.checksWithSpecRef);
  printf("\n");

  // ── Spec references ───────────────────────────────────────────────────────
  printf("\n");
  PAWGBanner("SPECIFICATION REFERENCES", W);
  printf("\n");
  printf("  ICC.1-2022-05   Profile specification v4.4\n");
  printf("  ICC.2-2023      iccMAX profile specification v5\n");
  printf("  RFC 1321        MD5 Message-Digest Algorithm (Profile ID)\n");
  printf("  CIEDE2000       CIE Technical Report 142-2001\n");
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
