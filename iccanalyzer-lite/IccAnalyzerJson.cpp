/*
 * IccAnalyzerJson.cpp — JSON structured output for iccanalyzer-lite
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Captures analysis stdout, parses [H##] markers and [OK]/[WARN]/[CRIT] status,
 * then emits structured JSON using the HeuristicRegistry for metadata.
 */

#include "IccAnalyzerJson.h"
#include "IccAnalyzerComprehensive.h"
#include "IccHeuristicsRegistry.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>
#include <vector>
#include <regex>
#include <unistd.h>

struct HeuristicJsonResult {
  int id;
  std::string name;
  std::string status;  // "ok", "warn", "critical", "info"
  std::string detail;
};

// Escape a string for JSON output
static std::string JsonEscape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 16);
  for (char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20)
          ; // skip control chars
        else
          out += c;
    }
  }
  return out;
}

// Strip ANSI escape codes from a string
static std::string StripAnsi(const std::string &s) {
  std::string out;
  out.reserve(s.size());
  size_t i = 0;
  while (i < s.size()) {
    if (s[i] == '\033' && i + 1 < s.size() && s[i + 1] == '[') {
      i += 2;
      while (i < s.size() && s[i] != 'm') i++;
      if (i < s.size()) i++; // skip 'm'
    } else {
      out += s[i++];
    }
  }
  return out;
}

int RunWithJsonOutput(const char *profilePath, const char *fingerprint_db) {
  // Capture stdout by redirecting to a pipe
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    fprintf(stderr, "Failed to create pipe for JSON capture\n");
    return 2;
  }

  int savedStdout = dup(STDOUT_FILENO);
  dup2(pipefd[1], STDOUT_FILENO);
  close(pipefd[1]);

  // Run the analysis
  int exitCode = ComprehensiveAnalyze(profilePath, fingerprint_db);

  // Flush and restore stdout
  fflush(stdout);
  dup2(savedStdout, STDOUT_FILENO);
  close(savedStdout);

  // Read captured output
  std::string captured;
  char buf[4096];
  ssize_t n;
  while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
    captured.append(buf, n);
  }
  close(pipefd[0]);

  // Strip ANSI codes for parsing
  std::string clean = StripAnsi(captured);

  // Parse [H##] blocks from the output
  std::vector<HeuristicJsonResult> results;
  int okCount = 0, warnCount = 0, critCount = 0, infoCount = 0;

  std::regex hRegex(R"(\[H(\d+)\]\s+(.+))");
  std::regex okRegex(R"(\[OK\])");
  std::regex warnRegex(R"(\[WARN\])");
  std::regex critRegex(R"(\[CRIT(?:ICAL)?\])");

  std::istringstream stream(clean);
  std::string line;
  int currentH = -1;
  std::string currentTitle;
  std::string currentDetail;
  std::string currentStatus = "ok";

  auto flushHeuristic = [&]() {
    if (currentH > 0) {
      HeuristicJsonResult r;
      r.id = currentH;
      const HeuristicEntry *entry = LookupHeuristic(currentH);
      r.name = entry ? entry->name : currentTitle;
      r.status = currentStatus;
      r.detail = currentDetail;
      results.push_back(r);

      if (currentStatus == "ok") okCount++;
      else if (currentStatus == "warn") warnCount++;
      else if (currentStatus == "critical") critCount++;
      else infoCount++;
    }
  };

  while (std::getline(stream, line)) {
    std::smatch m;
    if (std::regex_search(line, m, hRegex)) {
      flushHeuristic();
      currentH = std::stoi(m[1].str());
      currentTitle = m[2].str();
      currentDetail.clear();
      currentStatus = "ok";
    } else if (currentH > 0) {
      if (std::regex_search(line, critRegex)) currentStatus = "critical";
      else if (std::regex_search(line, warnRegex) && currentStatus != "critical")
        currentStatus = "warn";
      if (!line.empty()) {
        if (!currentDetail.empty()) currentDetail += "\n";
        currentDetail += line;
      }
    }
  }
  flushHeuristic();

  // Count CVE coverage from triggered heuristics
  int cveHeuristicsTriggered = 0;
  int totalCveRefs = 0;
  std::set<std::string> uniqueCves;
  for (const auto &r : results) {
    const HeuristicEntry *entry = LookupHeuristic(r.id);
    if (entry && entry->cveRefs) {
      cveHeuristicsTriggered++;
      std::string refs(entry->cveRefs);
      totalCveRefs++;
      size_t start = 0;
      for (size_t pos = 0; pos <= refs.size(); pos++) {
        if (pos == refs.size() || refs[pos] == ',') {
          if (pos > start)
            uniqueCves.insert(refs.substr(start, pos - start));
          start = pos + 1;
          if (pos < refs.size()) totalCveRefs++;
        }
      }
    }
  }

  // Registry-level stats (source of truth — independent of which heuristics ran)
  RegistryStats regStats = ComputeRegistryStats();

  // Emit JSON to stdout
  printf("{\n");
  printf("  \"file\": \"%s\",\n", JsonEscape(profilePath).c_str());
  printf("  \"exitCode\": %d,\n", exitCode);
  printf("  \"summary\": {\n");
  printf("    \"totalHeuristics\": %d,\n", kTotalHeuristics);
  printf("    \"heuristicsRun\": %zu,\n", results.size());
  printf("    \"ok\": %d,\n", okCount);
  printf("    \"warnings\": %d,\n", warnCount);
  printf("    \"critical\": %d,\n", critCount);
  printf("    \"info\": %d,\n", infoCount);
  printf("    \"cveCoverage\": {\n");
  printf("      \"heuristicsWithCVE\": %d,\n", cveHeuristicsTriggered);
  printf("      \"uniqueCVEs\": %d,\n", (int)uniqueCves.size());
  printf("      \"totalCVEReferences\": %d,\n", totalCveRefs);
  printf("      \"advisoryTotal\": 93,\n");
  printf("      \"outOfScopeXmlCVEs\": 0,\n");
  printf("      \"outOfScopeToolCVEs\": 1\n");
  printf("    },\n");
  printf("    \"registry\": {\n");
  printf("      \"totalHeuristics\": %d,\n", regStats.totalHeuristics);
  printf("      \"heuristicsWithCVE\": %d,\n", regStats.heuristicsWithCVE);
  printf("      \"uniqueCVEs\": %d,\n", regStats.uniqueCVEs);
  printf("      \"uniqueGHSAs\": %d\n", regStats.uniqueGHSAs);
  printf("    }\n");
  printf("  },\n");
  printf("  \"results\": [\n");

  for (size_t i = 0; i < results.size(); i++) {
    const auto &r = results[i];
    const HeuristicEntry *entry = LookupHeuristic(r.id);
    printf("    {\n");
    printf("      \"id\": %d,\n", r.id);
    printf("      \"name\": \"%s\",\n", JsonEscape(r.name).c_str());
    printf("      \"status\": \"%s\",\n", r.status.c_str());
    printf("      \"severity\": \"%s\"", entry ? SeverityToString(entry->severity) : "INFO");
    if (entry && entry->specRef) {
      printf(",\n      \"specRef\": \"ICC.1-2022-05 %s\"", JsonEscape(entry->specRef).c_str());
    }
    if (entry && entry->primaryCWE) {
      printf(",\n      \"cwe\": \"%s\"", JsonEscape(entry->primaryCWE).c_str());
    }
    if (entry && entry->cveRefs) {
      printf(",\n      \"cveRefs\": [");
      std::string refs(entry->cveRefs);
      bool first = true;
      size_t pos = 0;
      while (pos < refs.size()) {
        size_t comma = refs.find(',', pos);
        if (comma == std::string::npos) comma = refs.size();
        if (!first) printf(",");
        printf("\"%s\"", JsonEscape(refs.substr(pos, comma - pos)).c_str());
        first = false;
        pos = comma + 1;
      }
      printf("]");
    }
    if (!r.detail.empty()) {
      printf(",\n      \"detail\": \"%s\"", JsonEscape(r.detail).c_str());
    }
    printf("\n    }%s\n", i + 1 < results.size() ? "," : "");
  }

  printf("  ]\n");
  printf("}\n");

  return exitCode;
}
