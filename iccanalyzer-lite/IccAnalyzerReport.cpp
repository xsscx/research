/*
 * IccAnalyzerReport.cpp — Professional severity-sorted report output
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Uses shared CaptureAndParseAnalysis() to capture stdout, parse [H##] markers,
 * then emits a professional report sorted by severity (CRITICAL → HIGH → MEDIUM →
 * LOW → INFO) with banner header, CWE category summary, and CVE cross-references.
 */

#include "IccAnalyzerReport.h"
#include "IccAnalyzerCommon.h"
#include "IccAnalyzerHash.h"
#include "IccAnalyzerCapture.h"
#include "IccHeuristicsRegistry.h"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <sstream>
#include <vector>
#include <sys/stat.h>

// Get file size
static long GetFileSize(const char *path) {
  struct stat st;
  if (stat(path, &st) != 0) return -1;
  return st.st_size;
}

// Print a horizontal rule
static void PrintRule(const char *ch, int width) {
  for (int i = 0; i < width; i++) printf("%s", ch);
  printf("\n");
}

// Print a centered title within a rule
static void PrintBanner(const char *title, int width) {
  int titleLen = (int)strlen(title);
  int pad = (width - titleLen - 2) / 2;
  if (pad < 0) pad = 0;
  for (int i = 0; i < pad; i++) printf("=");
  printf(" %s ", title);
  int remaining = width - pad - titleLen - 2;
  for (int i = 0; i < remaining; i++) printf("=");
  printf("\n");
}

int RunWithReportOutput(const char *profilePath, const char *fingerprint_db,
                        bool legacy) {
  CapturedAnalysis cap = CaptureAndParseAnalysis(profilePath, fingerprint_db, legacy);

  // Collect only findings with warnings/critical (not OK)
  std::vector<const CapturedFinding*> activeFindings;
  for (const auto &f : cap.findings) {
    if (f.status != "ok") activeFindings.push_back(&f);
  }

  // Sort by severity (CRITICAL first, then HIGH, MEDIUM, LOW, INFO)
  std::sort(activeFindings.begin(), activeFindings.end(),
    [](const CapturedFinding *a, const CapturedFinding *b) {
      if (a->severity != b->severity)
        return static_cast<int>(a->severity) < static_cast<int>(b->severity);
      return a->id < b->id;
    });

  // Count by severity
  int sevCounts[5] = {0}; // CRITICAL, HIGH, MEDIUM, LOW, INFO
  for (const auto *f : activeFindings) {
    sevCounts[static_cast<int>(f->severity)]++;
  }

  // Collect CWE categories from findings
  std::map<std::string, int> cweCounts;
  std::set<std::string> cveSet;
  for (const auto *f : activeFindings) {
    if (f->primaryCWE) cweCounts[f->primaryCWE]++;
    if (f->cveRefs) {
      for (const auto &r : ParseCSVRefs(f->cveRefs))
        cveSet.insert(r);
    }
  }

  // Get metadata
  std::string sha256 = ComputeFileSHA256(profilePath);
  long fileSize = GetFileSize(profilePath);
  time_t now = time(nullptr);
  char timeBuf[64];
  struct tm utc_buf;
  struct tm *utc = gmtime_r(&now, &utc_buf);
  strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S UTC", utc);

  const int W = 78;

  // === BANNER ===
  printf("\n");
  PrintRule("=", W);
  if (legacy) {
    PrintBanner("ICC PROFILE SECURITY REPORT (LEGACY)", W);
  } else {
    PrintBanner("ICC PROFILE CONFORMANCE REPORT", W);
  }
  PrintRule("=", W);
  printf("\n");
  printf("  Tool:     %s\n", ICCANALYZER_VERSION_FULL);
  printf("  Date:     %s\n", timeBuf);
  printf("  Build:    ASAN+UBSAN+Coverage | Clang 18\n");
  printf("\n");
  PrintRule("-", W);
  printf("  File:     %s\n", profilePath);
  printf("  SHA-256:  %s\n", sha256.c_str());
  printf("  Size:     %ld bytes\n", fileSize);
  PrintRule("-", W);
  printf("\n");

  // === EXECUTIVE SUMMARY ===
  PrintBanner("EXECUTIVE SUMMARY", W);
  printf("\n");
  printf("  Heuristics Run:  %zu / %d\n", cap.findings.size(), kTotalHeuristics);
  printf("  Findings:        %zu", activeFindings.size());
  if (!activeFindings.empty()) {
    printf(" (");
    bool first = true;
    const char *sevNames[] = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"};
    for (int i = 0; i < 5; i++) {
      if (sevCounts[i] > 0) {
        if (!first) printf(", ");
        printf("%d %s", sevCounts[i], sevNames[i]);
        first = false;
      }
    }
    printf(")");
  }
  printf("\n");
  printf("  Clean:           %d\n", cap.okCount);
  printf("  Exit Code:       %d\n", cap.exitCode);
  printf("\n");

  // === FINDINGS BY SEVERITY ===
  const HeuristicSeverity sevOrder[] = {
    HeuristicSeverity::CRITICAL,
    HeuristicSeverity::HIGH,
    HeuristicSeverity::MEDIUM,
    HeuristicSeverity::LOW,
    HeuristicSeverity::INFO
  };
  const char *sevLabels[] = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"};

  for (int si = 0; si < 5; si++) {
    if (sevCounts[si] == 0) continue;

    printf("\n");
    char sectionTitle[64];
    snprintf(sectionTitle, sizeof(sectionTitle), "%s FINDINGS (%d)", sevLabels[si], sevCounts[si]);
    PrintBanner(sectionTitle, W);
    printf("\n");

    for (const auto *f : activeFindings) {
      if (f->severity != sevOrder[si]) continue;

      printf("  [H%d] %s", f->id, f->name.c_str());
      if (f->primaryCWE) printf(" (%s)", f->primaryCWE);
      printf("\n");

      if (f->specRef)
        printf("        ICC.1-2022-05 %s\n", f->specRef);

      if (f->cveRefs) {
        printf("        CVEs: %s\n", f->cveRefs);
      }

      // Print detail lines (indented, trimmed)
      std::istringstream dstream(f->detail);
      std::string dline;
      while (std::getline(dstream, dline)) {
        size_t first = dline.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        std::string trimmed = dline.substr(first);
        if (trimmed.find("[H") == 0) continue; // skip repeated header
        printf("        %s\n", trimmed.c_str());
      }
      printf("\n");
    }
  }

  // === CWE CATEGORY SUMMARY ===
  if (!cweCounts.empty()) {
    printf("\n");
    PrintBanner("CWE CATEGORY SUMMARY", W);
    printf("\n");

    std::vector<std::pair<std::string, int>> sortedCwe(cweCounts.begin(), cweCounts.end());
    std::sort(sortedCwe.begin(), sortedCwe.end(),
      [](const auto &a, const auto &b) { return a.second > b.second; });

    for (const auto &kv : sortedCwe) {
      printf("  %-12s  %d finding%s\n", kv.first.c_str(), kv.second, kv.second > 1 ? "s" : "");
    }
    printf("\n");
  }

  // === CVE CROSS-REFERENCES ===
  if (!cveSet.empty()) {
    printf("\n");
    PrintBanner("CVE CROSS-REFERENCES", W);
    printf("\n");
    printf("  %zu CVE%s matched from active findings:\n", cveSet.size(), cveSet.size() > 1 ? "s" : "");
    for (const auto &cve : cveSet) {
      printf("    %s\n", cve.c_str());
    }
    printf("\n");
  }

  // === CVE COVERAGE STATISTICS ===
  printf("\n");
  PrintBanner("CVE COVERAGE STATISTICS", W);
  printf("\n");

  RegistryStats regStats = ComputeRegistryStats();
  printf("  Total Heuristics:     %d\n", regStats.totalHeuristics);
  printf("  Heuristics with CVE:  %d\n", regStats.heuristicsWithCVE);
  printf("  Unique CVEs:          %d\n", regStats.uniqueCVEs);
  printf("  Unique GHSAs:         %d\n", regStats.uniqueGHSAs);
  printf("  Advisory Total:       93 iccDEV security advisories\n");
  printf("  Out of Scope:         0 XML parser (covered by H142-H145) + 0 tool-specific (iccFromCube now in scope via H34)\n");

  printf("\n");
  printf("  Severity Distribution:\n");
  printf("    CRITICAL:  %d heuristics\n", regStats.severity[0]);
  printf("    HIGH:      %d heuristics\n", regStats.severity[1]);
  printf("    MEDIUM:    %d heuristics\n", regStats.severity[2]);
  printf("    LOW:       %d heuristics\n", regStats.severity[3]);
  printf("    INFO:      %d heuristics\n", regStats.severity[4]);
  printf("\n");

  // === FOOTER ===
  PrintRule("=", W);
  printf("  Report generated by %s\n", ICCANALYZER_VERSION_FULL);
  printf("  Spec conformance: ICC.1-2022-05, ICC.2-2023\n");
  PrintRule("=", W);
  printf("\n");

  return cap.exitCode;
}
