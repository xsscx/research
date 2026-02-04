// Stub header for ICCANALYZER_LITE build  
// Heuristics functionality disabled in lite version
#ifndef _ICCANALYZERHEURISTICS_H
#define _ICCANALYZERHEURISTICS_H

#include <vector>
#include <string>

// Minimal stub structures matching XML export expectations
struct HeuristicFinding {
  std::string check_name;
  std::string status;
  std::string severity;
  std::string message;
  std::string details;
  int lineNumber = 0;
};

struct HeuristicReport {
  std::vector<HeuristicFinding> findings;
  std::string summary;
  int totalChecks = 0;
  int passedChecks = 0;
  int failedChecks = 0;
  int warningChecks = 0;
};

#endif
