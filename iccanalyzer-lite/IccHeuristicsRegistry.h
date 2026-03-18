/*
 * IccHeuristicsRegistry.h — Declarations for the heuristic metadata registry
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Type definitions and extern declarations only. The registry array and
 * helper function implementations live in IccHeuristicsRegistry.cpp
 * (compiled once, not duplicated in every translation unit).
 */

#ifndef ICC_HEURISTICS_REGISTRY_H
#define ICC_HEURISTICS_REGISTRY_H

#include <cstddef>

enum class HeuristicPhase {
  HEADER,
  TAG_VALIDATION,
  RAW_POST,
  DATA_VALIDATION,
  PROFILE_COMPLIANCE,
  INTEGRITY,
  IMAGE
};

// Severity classification based on CWE impact and exploitability.
// CRITICAL = memory corruption / code execution (HBO, OOB write, UAF, integer overflow -> alloc)
// HIGH     = denial of service / crash (stack overflow, resource exhaustion, type confusion -> crash)
// MEDIUM   = data integrity / logic errors (incorrect calculation, type flag, size mismatch)
// LOW      = spec compliance / input validation (non-exploitable validation checks)
// INFO     = informational / suspicious patterns (metadata, anomaly indicators)
enum class HeuristicSeverity {
  CRITICAL,
  HIGH,
  MEDIUM,
  LOW,
  INFO
};

struct HeuristicEntry {
  int id;
  const char *name;
  const char *specRef;       // ICC.1-2022-05 section or nullptr
  const char *primaryCWE;    // Primary CWE identifier or nullptr
  const char *cveRefs;       // Comma-separated CVE IDs or nullptr
  HeuristicPhase phase;
  HeuristicSeverity severity;
};

// Registry array and size — defined in IccHeuristicsRegistry.cpp
extern const HeuristicEntry kHeuristicRegistry[];
extern const size_t kHeuristicRegistrySize;
extern const int kTotalHeuristics;

// Helper functions — implemented in IccHeuristicsRegistry.cpp
const char *SeverityToString(HeuristicSeverity s);
const char *PhaseToString(HeuristicPhase p);
const HeuristicEntry *LookupHeuristic(int id);

// Registry statistics computed dynamically from the registry array.
struct RegistryStats {
  int totalHeuristics;
  int heuristicsWithCVE;
  int uniqueCVEs;
  int uniqueGHSAs;
  int severity[5]; // CRITICAL, HIGH, MEDIUM, LOW, INFO
};

RegistryStats ComputeRegistryStats();

#endif
