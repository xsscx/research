/*
 * IccAnalyzerCapture.cpp — Shared stdout capture and parse implementation
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Consolidates the pipe/dup2/regex capture-and-parse pattern that was
 * triplicated across IccAnalyzerJson.cpp, IccAnalyzerReport.cpp, and
 * IccAnalyzerXMLExport.cpp.
 */

#include "IccAnalyzerCapture.h"
#include "IccAnalyzerComprehensive.h"
#include "IccHeuristicsRegistry.h"

#include <cstdio>
#include <regex>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

std::string StripAnsiCodes(const std::string &s) {
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

std::string JsonEscapeString(const std::string &s) {
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

CapturedAnalysis CaptureAndParseAnalysis(const char *profilePath,
                                          const char *fingerprint_db) {
  CapturedAnalysis result;
  result.exitCode = 2;
  result.okCount = result.warnCount = result.critCount = 0;

  // Capture stdout by redirecting to a pipe
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    fprintf(stderr, "[ERR] pipe() failed for analysis capture\n");
    return result;
  }

  int savedStdout = dup(STDOUT_FILENO);
  dup2(pipefd[1], STDOUT_FILENO);
  close(pipefd[1]);

  result.exitCode = ComprehensiveAnalyze(profilePath, fingerprint_db);

  fflush(stdout);
  dup2(savedStdout, STDOUT_FILENO);
  close(savedStdout);

  // Read captured output
  std::string captured;
  {
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
      captured.append(buf, n);
    close(pipefd[0]);
  }

  // Strip ANSI codes for clean parsing
  std::string clean = StripAnsiCodes(captured);

  // Parse [H##] markers using line-by-line state machine
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
      CapturedFinding f;
      f.id = currentH;
      f.name = entry ? entry->name : currentTitle;
      f.status = currentStatus;
      f.detail = currentDetail;
      f.severity = entry ? entry->severity : HeuristicSeverity::INFO;
      f.primaryCWE = entry ? entry->primaryCWE : nullptr;
      f.specRef = entry ? entry->specRef : nullptr;
      f.cveRefs = entry ? entry->cveRefs : nullptr;

      if (currentStatus == "ok") result.okCount++;
      else if (currentStatus == "warn") result.warnCount++;
      else if (currentStatus == "critical") result.critCount++;

      result.findings.push_back(f);
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
      // Stop collecting detail at section boundaries
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

  return result;
}
