/*
 * IccTest CLI — OutputFormatter.h
 * Abstract base for output formatters.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 *
 * Formatters live in the CLI, NOT the library. The library returns
 * structured AnalysisResult objects — formatters convert those to
 * human-readable (text, JSON, SARIF, XML, CSV) output.
 */

#ifndef ICCTEST_OUTPUT_FORMATTER_H
#define ICCTEST_OUTPUT_FORMATTER_H

#include <icctest/CheckResult.h>
#include <icctest/CheckRegistry.h>

#include <iosfwd>
#include <string>

namespace icctest {

/// Options that affect formatter behavior.
struct FormatOptions {
    bool useColor   = true;   // Terminal color codes (text only)
    bool verbose    = false;  // Include per-check detail
    bool includeOk  = false;  // Include checks that passed (text only)
    std::string inputFile;    // Original input path (for SARIF/metadata)
};

/// Abstract output formatter.
class OutputFormatter {
public:
    virtual ~OutputFormatter() = default;

    /// Format an analysis result to the given output stream.
    virtual void format(const AnalysisResult& result,
                        const FormatOptions& opts,
                        std::ostream& out) = 0;

    /// Format the check registry as a standalone document.
    virtual void formatRegistry(std::ostream& out) {
        (void)out;
        // Default: not supported
    }

    virtual int recommendedExitCode(const AnalysisResult& result) const {
        return result.hasCritical() ? 1 :
               (result.stats.findingsTotal > 0 ? 1 : 0);
    }
};

} // namespace icctest

#endif // ICCTEST_OUTPUT_FORMATTER_H
