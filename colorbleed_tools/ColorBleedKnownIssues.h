/*!
 *  @file ColorBleedKnownIssues.h
 *  @brief Shared known-issue reporting before unsafe iccDEV library calls.
 */

#ifndef COLORBLEED_KNOWN_ISSUES_H
#define COLORBLEED_KNOWN_ISSUES_H

#include <cstdio>
#include <cstddef>

enum class ColorBleedKnownIssueSeverity {
  CLEAN,
  WARNING,
  CRITICAL
};

struct ColorBleedKnownIssueSummary {
  ColorBleedKnownIssueSeverity worst = ColorBleedKnownIssueSeverity::CLEAN;
  size_t count = 0;
  unsigned int profile_size = 0;
  unsigned int tag_count = 0;
};

const char *ColorBleedKnownIssueSeverityName(ColorBleedKnownIssueSeverity severity);

ColorBleedKnownIssueSummary ColorBleedScanKnownIssues(const char *filename);

ColorBleedKnownIssueSummary ColorBleedReportKnownIssues(const char *filename,
                                                        FILE *out,
                                                        bool report_clean);

#endif
