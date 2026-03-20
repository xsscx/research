/*
 * IccAnalyzerJson.cpp — JSON structured output for iccanalyzer-lite
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Uses shared CaptureAndParseAnalysis() to capture stdout, parse [H##] markers,
 * then emits structured JSON using the HeuristicRegistry for metadata.
 */

#include "IccAnalyzerJson.h"
#include "IccAnalyzerCapture.h"
#include "IccHeuristicsRegistry.h"
#include <cstdio>
#include <set>
#include <string>

int RunWithJsonOutput(const char *profilePath, const char *fingerprint_db) {
  CapturedAnalysis cap = CaptureAndParseAnalysis(profilePath, fingerprint_db);

  // Count CVE coverage from triggered heuristics
  int cveHeuristicsTriggered = 0;
  int totalCveRefs = 0;
  std::set<std::string> uniqueCves;
  for (const auto &f : cap.findings) {
    if (f.cveRefs) {
      cveHeuristicsTriggered++;
      auto refs = ParseCSVRefs(f.cveRefs);
      totalCveRefs += static_cast<int>(refs.size());
      for (const auto &r : refs) uniqueCves.insert(r);
    }
  }

  RegistryStats regStats = ComputeRegistryStats();
  int infoCount = static_cast<int>(cap.findings.size())
                  - cap.okCount - cap.warnCount - cap.critCount;

  // Emit JSON to stdout
  printf("{\n");
  printf("  \"file\": \"%s\",\n", JsonEscapeString(profilePath).c_str());
  printf("  \"exitCode\": %d,\n", cap.exitCode);
  printf("  \"summary\": {\n");
  printf("    \"totalHeuristics\": %d,\n", kTotalHeuristics);
  printf("    \"heuristicsRun\": %zu,\n", cap.findings.size());
  printf("    \"ok\": %d,\n", cap.okCount);
  printf("    \"warnings\": %d,\n", cap.warnCount);
  printf("    \"critical\": %d,\n", cap.critCount);
  printf("    \"info\": %d,\n", infoCount);
  printf("    \"cveCoverage\": {\n");
  printf("      \"heuristicsWithCVE\": %d,\n", cveHeuristicsTriggered);
  printf("      \"uniqueCVEs\": %d,\n", (int)uniqueCves.size());
  printf("      \"totalCVEReferences\": %d,\n", totalCveRefs);
  printf("      \"advisoryTotal\": 93,\n");
  printf("      \"outOfScopeXmlCVEs\": 0,\n");
  printf("      \"outOfScopeToolCVEs\": 0\n");
  printf("    },\n");
  printf("    \"registry\": {\n");
  printf("      \"totalHeuristics\": %d,\n", regStats.totalHeuristics);
  printf("      \"heuristicsWithCVE\": %d,\n", regStats.heuristicsWithCVE);
  printf("      \"uniqueCVEs\": %d,\n", regStats.uniqueCVEs);
  printf("      \"uniqueGHSAs\": %d\n", regStats.uniqueGHSAs);
  printf("    }\n");
  printf("  },\n");
  printf("  \"results\": [\n");

  for (size_t i = 0; i < cap.findings.size(); i++) {
    const auto &f = cap.findings[i];
    printf("    {\n");
    printf("      \"id\": %d,\n", f.id);
    printf("      \"name\": \"%s\",\n", JsonEscapeString(f.name).c_str());
    printf("      \"status\": \"%s\",\n", f.status.c_str());
    printf("      \"severity\": \"%s\"", SeverityToString(f.severity));
    if (f.specRef) {
      printf(",\n      \"specRef\": \"ICC.1-2022-05 %s\"",
             JsonEscapeString(f.specRef).c_str());
    }
    if (f.primaryCWE) {
      printf(",\n      \"cwe\": \"%s\"", JsonEscapeString(f.primaryCWE).c_str());
    }
    if (f.cveRefs) {
      printf(",\n      \"cveRefs\": [");
      auto refs = ParseCSVRefs(f.cveRefs);
      for (size_t ri = 0; ri < refs.size(); ri++) {
        if (ri > 0) printf(",");
        printf("\"%s\"", JsonEscapeString(refs[ri]).c_str());
      }
      printf("]");
    }
    if (!f.detail.empty()) {
      printf(",\n      \"detail\": \"%s\"", JsonEscapeString(f.detail).c_str());
    }
    printf("\n    }%s\n", i + 1 < cap.findings.size() ? "," : "");
  }

  printf("  ]\n");
  printf("}\n");

  return cap.exitCode;
}
