/*
 * IccAnalyzerReport.cpp — Professional severity-sorted report output
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Captures analysis stdout, parses [H##] markers with [OK]/[WARN]/[CRIT] status,
 * then emits a professional report sorted by severity (CRITICAL → HIGH → MEDIUM →
 * LOW → INFO) with banner header, CWE category summary, and CVE cross-references.
 */

#include "IccAnalyzerReport.h"
#include "IccAnalyzerCommon.h"
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
#include <openssl/evp.h>

struct ReportFinding {
  int id;
  std::string name;
  std::string status;   // "ok", "warn", "critical"
  std::string detail;
  HeuristicSeverity severity;
  const char *cwe;
  const char *specRef;
  const char *cveRefs;
};

// Strip ANSI escape codes
static std::string StripAnsiReport(const std::string &s) {
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

// Compute SHA-256 of a file (no shell commands — safe from injection)
static std::string ComputeSHA256(const char *path) {
  FILE *fp = fopen(path, "rb");
  if (!fp) return "(unavailable)";

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) { fclose(fp); return "(unavailable)"; }

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx); fclose(fp); return "(unavailable)";
  }

  unsigned char buf[8192];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
    EVP_DigestUpdate(ctx, buf, n);
  }
  fclose(fp);

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLen = 0;
  EVP_DigestFinal_ex(ctx, hash, &hashLen);
  EVP_MD_CTX_free(ctx);

  char hex[65] = {};
  for (unsigned int i = 0; i < hashLen && i < 32; i++) {
    snprintf(hex + i * 2, 3, "%02x", hash[i]);
  }
  return std::string(hex);
}

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

int RunWithReportOutput(const char *profilePath, const char *fingerprint_db) {
  // Capture stdout via pipe (same pattern as --json mode)
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    fprintf(stderr, "Failed to create pipe for report capture\n");
    return 2;
  }

  int savedStdout = dup(STDOUT_FILENO);
  dup2(pipefd[1], STDOUT_FILENO);
  close(pipefd[1]);

  int exitCode = ComprehensiveAnalyze(profilePath, fingerprint_db);

  fflush(stdout);
  dup2(savedStdout, STDOUT_FILENO);
  close(savedStdout);

  // Read captured output
  std::string captured;
  char buf[4096];
  ssize_t nr;
  while ((nr = read(pipefd[0], buf, sizeof(buf))) > 0) {
    captured.append(buf, nr);
  }
  close(pipefd[0]);

  std::string clean = StripAnsiReport(captured);

  // Parse [H##] blocks
  std::vector<ReportFinding> findings;
  int okCount = 0, warnCount = 0, critCount = 0;

  std::regex hRegex(R"(\[H(\d+)\]\s+(.+))");
  std::regex warnRegex(R"(\[WARN\])");
  std::regex critRegex(R"(\[CRIT(?:ICAL)?\])");

  std::istringstream stream(clean);
  std::string line;
  int currentH = -1;
  std::string currentTitle;
  std::string currentDetail;
  std::string currentStatus = "ok";

  auto flushFinding = [&]() {
    if (currentH > 0) {
      const HeuristicEntry *entry = LookupHeuristic(currentH);
      ReportFinding f;
      f.id = currentH;
      f.name = entry ? entry->name : currentTitle;
      f.status = currentStatus;
      f.detail = currentDetail;
      f.severity = entry ? entry->severity : HeuristicSeverity::INFO;
      f.cwe = entry ? entry->primaryCWE : nullptr;
      f.specRef = entry ? entry->specRef : nullptr;
      f.cveRefs = entry ? entry->cveRefs : nullptr;

      if (currentStatus == "ok") okCount++;
      else if (currentStatus == "warn") warnCount++;
      else if (currentStatus == "critical") critCount++;

      findings.push_back(f);
    }
  };

  while (std::getline(stream, line)) {
    std::smatch m;
    if (std::regex_search(line, m, hRegex)) {
      flushFinding();
      currentH = std::stoi(m[1].str());
      currentTitle = m[2].str();
      currentDetail.clear();
      currentStatus = "ok";
    } else if (currentH > 0) {
      // Stop collecting detail on section boundaries
      if (line.find("HEURISTIC SUMMARY") != std::string::npos ||
          line.find("PHASE 2:") != std::string::npos ||
          line.find("PHASE 3:") != std::string::npos ||
          line.find("========") != std::string::npos) {
        flushFinding();
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
  flushFinding();

  // Collect only findings with warnings/critical (not OK)
  std::vector<const ReportFinding*> activeFindings;
  for (const auto &f : findings) {
    if (f.status != "ok") activeFindings.push_back(&f);
  }

  // Sort by severity (CRITICAL first, then HIGH, MEDIUM, LOW, INFO)
  std::sort(activeFindings.begin(), activeFindings.end(),
    [](const ReportFinding *a, const ReportFinding *b) {
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
    if (f->cwe) cweCounts[f->cwe]++;
    if (f->cveRefs) {
      std::string refs(f->cveRefs);
      size_t start = 0;
      for (size_t pos = 0; pos <= refs.size(); pos++) {
        if (pos == refs.size() || refs[pos] == ',') {
          if (pos > start) cveSet.insert(refs.substr(start, pos - start));
          start = pos + 1;
        }
      }
    }
  }

  // Get metadata
  std::string sha256 = ComputeSHA256(profilePath);
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
  PrintBanner("ICC PROFILE SECURITY REPORT", W);
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
  printf("  Heuristics Run:  %zu / %d\n", findings.size(), kTotalHeuristics);
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
  printf("  Clean:           %d\n", okCount);
  printf("  Exit Code:       %d\n", exitCode);
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
      if (f->cwe) printf(" (%s)", f->cwe);
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
        // Skip empty lines and redundant header lines
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

    // Sort CWE categories by count (descending)
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

  // All counts derived dynamically from the registry — no hardcoded sync needed
  RegistryStats regStats = ComputeRegistryStats();
  printf("  Total Heuristics:     %d\n", regStats.totalHeuristics);

  printf("  Heuristics with CVE:  %d\n", regStats.heuristicsWithCVE);
  printf("  Unique CVEs:          %d\n", regStats.uniqueCVEs);
  printf("  Unique GHSAs:         %d\n", regStats.uniqueGHSAs);
  printf("  Advisory Total:       93 iccDEV security advisories\n");
  printf("  Out of Scope:         0 XML parser (covered by H142-H145) + 1 tool-specific\n");

  // Severity distribution from registry
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

  return exitCode;
}
