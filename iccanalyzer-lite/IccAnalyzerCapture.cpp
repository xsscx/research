/*
 * IccAnalyzerCapture.cpp — Structured analysis capture implementation
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Phase 5 architecture: runs ComprehensiveAnalyze() with stdout redirected
 * to /dev/null and HeuristicCollector in quiet mode. Reads structured
 * findings directly from HeuristicCollector::instance().results() — no
 * pipe/read/regex parsing needed. Enriches with registry metadata.
 */

#include "IccAnalyzerCapture.h"
#include "IccAnalyzerComprehensive.h"
#include "IccHeuristicResult.h"
#include "IccHeuristicsRegistry.h"

#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

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

  // Phase 5: Use HeuristicCollector quiet mode + stdout redirect to /dev/null.
  // ComprehensiveAnalyze() emits phase banners via printf — redirect those away.
  // HeuristicCollector quiet mode suppresses heuristic printf internally.
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

  result.exitCode = ComprehensiveAnalyze(profilePath, fingerprint_db);

  // Restore stdout and quiet mode
  fflush(stdout);
  if (savedStdout >= 0) {
    dup2(savedStdout, STDOUT_FILENO);
    close(savedStdout);
  }
  hc.setQuiet(false);

  // Read structured findings directly from HeuristicCollector — no regex parsing
  for (const auto &hf : hc.results()) {
    const HeuristicEntry *entry = LookupHeuristic(hf.id);

    CapturedFinding f;
    f.id = hf.id;
    f.name = entry ? entry->name : hf.title;
    f.status = hf.status;
    f.severity = entry ? entry->severity : HeuristicSeverity::INFO;
    f.primaryCWE = entry ? entry->primaryCWE : nullptr;
    f.specRef = entry ? entry->specRef : nullptr;
    f.cveRefs = entry ? entry->cveRefs : nullptr;

    // Join detail lines
    for (size_t i = 0; i < hf.details.size(); ++i) {
      if (i > 0) f.detail += "\n";
      f.detail += hf.details[i];
    }

    if (hf.status == "ok") result.okCount++;
    else if (hf.status == "warn") result.warnCount++;
    else if (hf.status == "critical") result.critCount++;

    result.findings.push_back(f);
  }

  return result;
}
