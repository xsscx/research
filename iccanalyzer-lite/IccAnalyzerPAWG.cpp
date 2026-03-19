/*
 * IccAnalyzerPAWG.cpp — ICC Profile Assessment Working Group report output
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Captures ComprehensiveAnalyze() stdout, parses [H##] markers, then emits a
 * structured report organized per the ICC PAWG checklist:
 *
 *   SECURITY (13 items)
 *   CONFORMANCE (14 items)
 *   QUALITY (4 items)
 *
 * Each PAWG item maps to one or more iccanalyzer-lite heuristics.  The item
 * verdict is PASS when every mapped heuristic is [OK], WARN when at least one
 * is [WARN], and FAIL when at least one is [CRIT].
 *
 * Reference: ICC Profile Assessment Working Group — Goals for profile assessment
 */

#include "IccAnalyzerPAWG.h"
#include "IccAnalyzerCommon.h"
#include "IccAnalyzerHash.h"
#include "IccAnalyzerComprehensive.h"
#include "IccHeuristicsRegistry.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <map>
#include <regex>
#include <set>
#include <string>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>

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
  const int  *heuristics;   // NULL-terminated list of heuristic IDs
  int         hCount;       // number of mapped heuristics
  PAWGVerdict verdict;
  std::string detail;       // collected detail from triggered heuristics
};

// ── Heuristic-to-PAWG mappings ───────────────────────────────────────────────
// Each PAWG item maps to an array of heuristic IDs (terminated by 0).

static const int kS1[]  = { 3, 31, 63, 107, 164, 0 };
static const int kS2[]  = { 1, 2, 5, 0 };
static const int kS3[]  = { 5, 0 };
static const int kS4[]  = { 8, 129, 0 };
static const int kS5[]  = { 4, 7, 0 };
static const int kS6[]  = { 19, 25, 40, 130, 0 };
static const int kS7[]  = { 10, 20, 122, 135, 0 };
static const int kS8[]  = { 16, 109, 126, 163, 0 };
static const int kS9[]  = { 1, 40, 130, 0 };
static const int kS10[] = { 37, 56, 118, 138, 151, 0 };
static const int kS11[] = { 108, 0 };
static const int kS12[] = { 126, 0 };
static const int kS13[] = { 109, 126, 163, 0 };

static const int kC14[] = { 20, 32, 74, 76, 117, 145, 0 };
static const int kC15[] = { 116, 46, 55, 86, 0 };
static const int kC16[] = { 117, 0 };
static const int kC17[] = { 9, 110, 0 };
static const int kC18[] = { 123, 108, 0 };
static const int kC19[] = { 127, 0 };
static const int kC20[] = { 127, 0 };
static const int kC21[] = { 127, 0 };
static const int kC22[] = { 7, 103, 0 };
static const int kC23[] = { 2, 15, 111, 133, 0 };
static const int kC24[] = { 124, 41, 128, 0 };
static const int kC25[] = { 112, 129, 0 };
static const int kC26[] = { 111, 133, 134, 0 };
static const int kC27[] = { 40, 130, 0 };

static const int kQ28[] = { 113, 119, 0 };
static const int kQ29[] = { 120, 114, 87, 0 };
static const int kQ30[] = { 114, 125, 0 };
static const int kQ31[] = { 115, 113, 119, 0 };

// Count entries in a 0-terminated int array
static int CountArr(const int *a) {
  int n = 0;
  while (a[n] != 0) n++;
  return n;
}

// ── Build the PAWG checklist ─────────────────────────────────────────────────

#define PAWG_ITEM(code, text, arr) { code, text, arr, CountArr(arr), PAWGVerdict::NOT_RUN, {} }

static PAWGItem BuildSecurityItems[] = {
  PAWG_ITEM("S1",  "Channel counts in tags match data colour space", kS1),
  PAWG_ITEM("S2",  "Header is 128 bytes and correctly encoded", kS2),
  PAWG_ITEM("S3",  "Platform, Creator, Manufacturer and CMM fields correspond to registered signatures or are zero", kS3),
  PAWG_ITEM("S4",  "Illuminant corresponds to D50", kS4),
  PAWG_ITEM("S5",  "Unless a DeviceLink profile, PCS is Lab or XYZ", kS5),
  PAWG_ITEM("S6",  "Tags correctly aligned - offset and length correspond to tag table, no overlapping tags or gaps", kS6),
  PAWG_ITEM("S7",  "Tag table correctly encoded", kS7),
  PAWG_ITEM("S8",  "No known malware signatures present", kS8),
  PAWG_ITEM("S9",  "EOF follows last tag (including four-byte boundary), no additional bytes before or after", kS9),
  PAWG_ITEM("S10", "Excessive calculator elements not present (computation cost estimate provided)", kS10),
  PAWG_ITEM("S11", "Private tags ideally not present", kS11),
  PAWG_ITEM("S12", "Private tags do not contain malware", kS12),
  PAWG_ITEM("S13", "Private tags do not contain exploitable NOP instructions", kS13),
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

// ── Strip ANSI escape codes ──────────────────────────────────────────────────

static std::string StripAnsiPAWG(const std::string &s) {
  std::string out;
  out.reserve(s.size());
  size_t i = 0;
  while (i < s.size()) {
    if (s[i] == '\033' && i + 1 < s.size() && s[i + 1] == '[') {
      i += 2;
      while (i < s.size() && s[i] != 'm') i++;
      if (i < s.size()) i++;
    } else {
      out += s[i++];
    }
  }
  return out;
}

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

  for (int i = 0; i < item.hCount; i++) {
    int hid = item.heuristics[i];
    auto it = results.find(hid);
    if (it == results.end()) continue;

    anyFound = true;
    const auto &r = it->second;

    PAWGVerdict hv = PAWGVerdict::PASS;
    if (r.status == "critical") hv = PAWGVerdict::FAIL;
    else if (r.status == "warn")  hv = PAWGVerdict::WARN;

    if (static_cast<int>(hv) > static_cast<int>(worst))
      worst = hv;

    // Collect detail from triggered heuristics only
    if (hv != PAWGVerdict::PASS && !r.detail.empty()) {
      if (!item.detail.empty()) item.detail += "\n";
      // Extract meaningful lines from detail
      std::istringstream ds(r.detail);
      std::string dl;
      while (std::getline(ds, dl)) {
        size_t first = dl.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        std::string trimmed = dl.substr(first);
        if (trimmed.find("[H") == 0) continue;
        if (trimmed.find("[OK]") != std::string::npos) continue;
        if (trimmed.find("=====") != std::string::npos) continue;
        if (!item.detail.empty() && item.detail.back() != '\n')
          item.detail += "\n";
        item.detail += "          H" + std::to_string(hid) + ": " + trimmed;
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

    // Print mapped heuristics on next line
    printf("          Heuristics: ");
    for (int j = 0; j < item.hCount; j++) {
      if (j > 0) printf(", ");
      printf("H%d", item.heuristics[j]);
    }
    printf("\n");

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
  // ── Step 1: Capture stdout from ComprehensiveAnalyze via pipe ─────────────
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    fprintf(stderr, "Failed to create pipe for PAWG capture\n");
    return 2;
  }

  int savedStdout = dup(STDOUT_FILENO);
  dup2(pipefd[1], STDOUT_FILENO);
  close(pipefd[1]);

  int exitCode = ComprehensiveAnalyze(profilePath, fingerprint_db);

  fflush(stdout);
  dup2(savedStdout, STDOUT_FILENO);
  close(savedStdout);

  std::string captured;
  char buf[4096];
  ssize_t nr;
  while ((nr = read(pipefd[0], buf, sizeof(buf))) > 0) {
    captured.append(buf, nr);
  }
  close(pipefd[0]);

  std::string clean = StripAnsiPAWG(captured);

  // ── Step 2: Parse [H##] markers into results map ──────────────────────────
  std::map<int, PAWGHeuristicResult> results;

  std::regex hRegex(R"(\[H(\d+)\]\s+(.+))");
  std::regex warnRegex(R"(\[WARN\])");
  std::regex critRegex(R"(\[CRIT(?:ICAL)?\])");

  std::istringstream stream(clean);
  std::string line;
  int currentH = -1;
  std::string currentTitle;
  std::string currentDetail;
  std::string currentStatus = "ok";

  auto flushResult = [&]() {
    if (currentH > 0) {
      PAWGHeuristicResult r;
      r.id = currentH;
      r.name = currentTitle;
      r.status = currentStatus;
      r.detail = currentDetail;
      results[currentH] = std::move(r);
    }
  };

  while (std::getline(stream, line)) {
    std::smatch m;
    if (std::regex_search(line, m, hRegex)) {
      flushResult();
      currentH = std::stoi(m[1].str());
      currentTitle = m[2].str();
      currentDetail.clear();
      currentStatus = "ok";
    } else if (currentH > 0) {
      if (line.find("HEURISTIC SUMMARY") != std::string::npos ||
          line.find("PHASE 2:") != std::string::npos ||
          line.find("PHASE 3:") != std::string::npos ||
          line.find("========") != std::string::npos) {
        flushResult();
        currentH = -1;
        continue;
      }
      if (std::regex_search(line, critRegex)) currentStatus = "critical";
      else if (std::regex_search(line, warnRegex) && currentStatus != "critical")
        currentStatus = "warn";
      if (!line.empty()) {
        if (!currentDetail.empty()) currentDetail += "\n";
        currentDetail += line;
      }
    }
  }
  flushResult();

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

  // ── Heuristic coverage table ──────────────────────────────────────────────
  printf("\n");
  PAWGBanner("HEURISTIC COVERAGE", W);
  printf("\n");
  printf("  Heuristics evaluated:   %zu / %d\n", results.size(), kTotalHeuristics);

  // Count unique heuristics mapped by PAWG items
  std::set<int> mappedHeuristics;
  for (int i = 0; i < nSecurity;    i++)
    for (int j = 0; j < BuildSecurityItems[i].hCount; j++)
      mappedHeuristics.insert(BuildSecurityItems[i].heuristics[j]);
  for (int i = 0; i < nConformance; i++)
    for (int j = 0; j < BuildConformanceItems[i].hCount; j++)
      mappedHeuristics.insert(BuildConformanceItems[i].heuristics[j]);
  for (int i = 0; i < nQuality;     i++)
    for (int j = 0; j < BuildQualityItems[i].hCount; j++)
      mappedHeuristics.insert(BuildQualityItems[i].heuristics[j]);

  printf("  Heuristics mapped:      %zu (across %d PAWG items)\n",
         mappedHeuristics.size(), totalItems);

  RegistryStats regStats = ComputeRegistryStats();
  printf("  Registry total:         %d heuristics\n", regStats.totalHeuristics);
  printf("  CVE coverage:           %d heuristics with CVE refs (%d unique CVEs)\n",
         regStats.heuristicsWithCVE, regStats.uniqueCVEs);
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
