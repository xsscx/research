/*!
 *  @file ColorBleedKnownIssues.cpp
 *  @brief Shared known-issue reporting before unsafe iccDEV library calls.
 */

#include "ColorBleedKnownIssues.h"

#define COLORBLEED_SKIP_XML_PREFLIGHT
#include "ColorBleedPreflight.h"

#include <set>
#include <string>

static ColorBleedKnownIssueSeverity MapPreflightSeverity(PreflightSeverity severity)
{
  if (severity == PreflightSeverity::CRITICAL)
    return ColorBleedKnownIssueSeverity::CRITICAL;
  if (severity == PreflightSeverity::WARNING)
    return ColorBleedKnownIssueSeverity::WARNING;
  return ColorBleedKnownIssueSeverity::CLEAN;
}

const char *ColorBleedKnownIssueSeverityName(ColorBleedKnownIssueSeverity severity)
{
  switch (severity) {
    case ColorBleedKnownIssueSeverity::CRITICAL:
      return "CRITICAL";
    case ColorBleedKnownIssueSeverity::WARNING:
      return "WARNING";
    case ColorBleedKnownIssueSeverity::CLEAN:
    default:
      return "CLEAN";
  }
}

ColorBleedKnownIssueSummary ColorBleedScanKnownIssues(const char *filename)
{
  ColorBleedKnownIssueSummary summary;
  if (!filename) {
    summary.worst = ColorBleedKnownIssueSeverity::CRITICAL;
    summary.count = 1;
    return summary;
  }

  PreflightResult result = PreflightValidateICC(filename);
  summary.worst = MapPreflightSeverity(result.worst);
  summary.count = result.warnings.size();
  summary.profile_size = result.profile_size;
  summary.tag_count = result.tag_count;
  return summary;
}

ColorBleedKnownIssueSummary ColorBleedReportKnownIssues(const char *filename,
                                                        FILE *out,
                                                        bool report_clean)
{
  if (!out)
    out = stderr;

  ColorBleedKnownIssueSummary summary;
  if (!filename) {
    summary.worst = ColorBleedKnownIssueSeverity::CRITICAL;
    summary.count = 1;
    if (report_clean)
      fprintf(out, "[ColorBleed] [KNOWN-ISSUE] H0 CRITICAL: null filename\n");
    fflush(out);
    return summary;
  }

  PreflightResult result = PreflightValidateICC(filename);
  summary.worst = MapPreflightSeverity(result.worst);
  summary.count = result.warnings.size();
  summary.profile_size = result.profile_size;
  summary.tag_count = result.tag_count;

  if (summary.count == 0 && !report_clean)
    return summary;

  fprintf(out, "[ColorBleed] Known issue scan: %s\n", filename ? filename : "(null)");
  if (summary.count == 0) {
    fprintf(out, "[ColorBleed] Known issue scan: CLEAN (%u tags, %u bytes)\n",
            summary.tag_count, summary.profile_size);
    fflush(out);
    return summary;
  }

  std::set<std::string> ids;
  for (const auto& warning : result.warnings) {
    const char *severity = warning.severity == PreflightSeverity::CRITICAL
        ? "CRITICAL"
        : "WARNING";
    ids.insert(warning.heuristic);
    fprintf(out, "[ColorBleed] [KNOWN-ISSUE] %s %s: %s\n",
            warning.heuristic.c_str(), severity, warning.message.c_str());
  }

  std::string id_list;
  for (const auto& id : ids) {
    if (!id_list.empty())
      id_list += ",";
    id_list += id;
  }

  fprintf(out, "[ColorBleed] KNOWN-ISSUES file=%s count=%zu worst=%s ids=%s\n",
          filename ? filename : "(null)",
          summary.count,
          ColorBleedKnownIssueSeverityName(summary.worst),
          id_list.c_str());
  fflush(out);
  return summary;
}
