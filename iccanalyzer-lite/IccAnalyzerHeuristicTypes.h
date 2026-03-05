/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

#ifndef _ICCANALYZERHEURISTICTYPES_H
#define _ICCANALYZERHEURISTICTYPES_H

#include <string>
#include <vector>
#include <cstdint>

// Severity levels for heuristic findings
enum class HeuristicSeverity {
  INFO = 0,
  LOW = 1,
  MEDIUM = 2,
  HIGH = 3,
  CRITICAL = 4
};

// Individual heuristic result
struct HeuristicResult {
  std::string id;         // e.g. "H1", "H25"
  HeuristicSeverity severity;
  std::string message;
  std::string cwe;        // e.g. "CWE-131"
  std::string cve;        // e.g. "CVE-2026-21490"
  bool triggered;

  HeuristicResult() : severity(HeuristicSeverity::INFO), triggered(false) {}
};

// Shared context passed to heuristic groups during analysis
struct HeuristicContext {
  const char *filename;
  const char *fingerprint_db;

  // Cumulative warning counter (drives exit code and library gate)
  int heuristicCount;

  // Pre-library raw tag count (read at offset 128)
  uint32_t rawTagCount;

  // Control flags
  bool skipLibraryPhase;    // true when rawTagCount > 1000
  bool libraryAnalyzed;     // true after successful CIccProfile load

  // File metadata
  size_t actualFileSize;

  HeuristicContext()
    : filename(nullptr), fingerprint_db(nullptr),
      heuristicCount(0), rawTagCount(0),
      skipLibraryPhase(false), libraryAnalyzed(false),
      actualFileSize(0) {}
};

// If heuristicCount reaches this threshold, skip library-API phase
static constexpr int kCriticalHeuristicThreshold = 5;

inline const char* SeverityToString(HeuristicSeverity s) {
  switch (s) {
    case HeuristicSeverity::INFO:     return "INFO";
    case HeuristicSeverity::LOW:      return "LOW";
    case HeuristicSeverity::MEDIUM:   return "MEDIUM";
    case HeuristicSeverity::HIGH:     return "HIGH";
    case HeuristicSeverity::CRITICAL: return "CRITICAL";
    default:                          return "UNKNOWN";
  }
}

#endif // _ICCANALYZERHEURISTICTYPES_H
