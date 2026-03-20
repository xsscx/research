/*
 * IccAnalyzerCapture.h — Shared stdout capture and parse infrastructure
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Consolidates the pipe/dup2/regex capture-and-parse pattern that was
 * triplicated across IccAnalyzerJson.cpp, IccAnalyzerReport.cpp, and
 * IccAnalyzerXMLExport.cpp into a single shared implementation.
 *
 * TODO: When all 171 heuristics use HeuristicCollector (Phase 4),
 * replace CaptureAndParseAnalysis() internals with direct read from
 * HeuristicCollector::instance().results() — no pipe/dup2 needed.
 */

#ifndef ICCANALYZERCAPTURE_H
#define ICCANALYZERCAPTURE_H

#include "IccHeuristicsRegistry.h"
#include <string>
#include <vector>

/// A single parsed heuristic finding with registry-enriched metadata.
struct CapturedFinding {
  int id;
  std::string name;
  std::string status;   // "ok", "warn", "critical"
  std::string detail;   // newline-joined detail lines
  HeuristicSeverity severity;
  const char *primaryCWE;
  const char *specRef;
  const char *cveRefs;
};

/// Result of capturing and parsing ComprehensiveAnalyze() output.
struct CapturedAnalysis {
  int exitCode;
  std::vector<CapturedFinding> findings;
  int okCount;
  int warnCount;
  int critCount;
};

/// Capture ComprehensiveAnalyze() stdout via pipe, parse [H##] markers,
/// and return structured findings enriched with registry metadata.
CapturedAnalysis CaptureAndParseAnalysis(const char *profilePath,
                                          const char *fingerprint_db);

/// Strip ANSI escape codes (ESC[...m) from a string.
std::string StripAnsiCodes(const std::string &s);

/// Escape a string for JSON output (quotes, backslashes, control chars).
std::string JsonEscapeString(const std::string &s);

#endif // ICCANALYZERCAPTURE_H
