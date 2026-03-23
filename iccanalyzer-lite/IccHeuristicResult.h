/*
 * IccHeuristicResult.h — Structured heuristic result tracking
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Provides HeuristicFinding for structured per-heuristic results and
 * HeuristicCollector for dual-mode output (printf backward compat +
 * structured collection). Eliminates the pipe/dup2/regex pattern used
 * in JSON/Report/XML modes by collecting findings at the source.
 */

#ifndef ICCHEURISTICRESULT_H
#define ICCHEURISTICRESULT_H

#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>

/// One heuristic check result — carries ID, status, and detail lines.
struct HeuristicFinding {
  int id;                            // H1-H171+
  std::string title;                 // e.g. "mBA/mAB Sub-Element Offset Validation"
  std::string status;                // "ok", "warn", "critical", "skip"
  std::vector<std::string> details;  // finding/info/skip detail lines
  int findingCount;                  // number of [WARN] or [CRIT] sub-findings

  HeuristicFinding() : id(0), findingCount(0) {}
};

/// Dual-mode heuristic result collector.
///
/// During analysis, each heuristic calls begin()/warn()/ok()/end() on this
/// collector. The collector simultaneously:
///   1. Emits printf() output (exact same format as before, for backward compat)
///   2. Accumulates structured HeuristicFinding objects
///
/// After analysis completes, output modes (JSON/Report/XML) can read the
/// structured results directly instead of re-running analysis through a
/// pipe/dup2/regex capture hack.
///
/// Usage:
///   auto &hc = HeuristicCollector::instance();
///   hc.begin(33, "mBA/mAB Sub-Element Offset Validation");
///   if (problem) hc.warn("Tag '%s': offset 0x%X exceeds size %u", sig, off, sz);
///   return hc.end("All mBA/mAB sub-element offsets within tag bounds");
///
class HeuristicCollector {
public:
  /// Get the singleton instance (safe for single-threaded CLI app).
  static HeuristicCollector &instance();

  /// Start a new heuristic check. Emits "[H##] Title\n".
  void begin(int id, const char *title);

  /// Record a warning finding. Emits "      [WARN]  ...\n" with color.
  /// __attribute__((format)) enables compiler format-string checking.
  void warn(const char *fmt, ...) __attribute__((format(printf, 2, 3)));

  /// Record a CWE/CVE annotation line. Emits "       CWE-...\n" with color.
  void cweNote(const char *fmt, ...) __attribute__((format(printf, 2, 3)));

  /// Record a critical finding (overrides status to "critical").
  void critical(const char *fmt, ...) __attribute__((format(printf, 2, 3)));

  /// Record an info/detail line (not a finding, just additional context).
  void info(const char *fmt, ...) __attribute__((format(printf, 2, 3)));

  /// End the current heuristic.
  /// If no warnings/criticals were added, emits "[OK] okMessage\n".
  /// If okMessage is nullptr, uses a generic "No issues detected".
  /// Always emits a trailing newline.
  /// Returns the finding count for this heuristic.
  int end(const char *okMessage = nullptr);

  /// Skip a heuristic internally while printing an explicit coverage label.
  int skip(const char *reason);

  /// Access all collected results (since last reset).
  const std::vector<HeuristicFinding> &results() const { return m_results; }

  /// Total findings across all collected heuristics.
  int totalFindings() const;

  /// Finding count from the most recently ended heuristic.
  int lastFindingCount() const { return m_lastCount; }

  /// Clear all collected results (call before a new analysis run).
  void reset();

  /// Whether collection is active (true by default).
  /// When disabled, only printf output is emitted (legacy mode).
  bool collecting() const { return m_collecting; }
  void setCollecting(bool on) { m_collecting = on; }

  /// Quiet mode: when true, suppress all printf output (structured output only).
  /// Used by JSON/Report/XML modes to avoid mixing printf with structured output.
  bool quiet() const { return m_quiet; }
  void setQuiet(bool on) { m_quiet = on; }

private:
  HeuristicCollector();

  std::vector<HeuristicFinding> m_results;
  HeuristicFinding m_current;
  bool m_active;      // true between begin() and end()
  bool m_collecting;  // true = accumulate results; false = printf only
  bool m_quiet;       // true = suppress printf; structured collection only
  int m_lastCount;

  // Format a va_list into a std::string
  static std::string vformat(const char *fmt, va_list ap);
};

#endif // ICCHEURISTICRESULT_H
