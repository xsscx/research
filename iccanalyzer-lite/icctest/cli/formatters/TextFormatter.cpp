/*
 * IccTest CLI — TextFormatter.cpp
 * Colored terminal output matching V1's display style.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "../src/OutputFormatter.h"

#include <iostream>
#include <cstdio>

namespace icctest {

namespace {

const char* colorForSeverity(Severity sev, bool useColor) {
    if (!useColor) return "";
    switch (sev) {
        case Severity::CRITICAL: return "\033[1;31m";  // Bold red
        case Severity::HIGH:     return "\033[31m";     // Red
        case Severity::MEDIUM:   return "\033[33m";     // Yellow
        case Severity::LOW:      return "\033[36m";     // Cyan
        case Severity::INFO:     return "\033[37m";     // White
    }
    return "";
}

const char* colorReset(bool useColor) {
    return useColor ? "\033[0m" : "";
}

const char* colorSuccess(bool useColor) {
    return useColor ? "\033[32m" : "";
}

const char* colorHeader(bool useColor) {
    return useColor ? "\033[1;34m" : "";
}

} // anon

class TextFormatter final : public OutputFormatter {
public:
    void format(const AnalysisResult& result,
                const FormatOptions& opts,
                std::ostream& out) override
    {
        const bool c = opts.useColor;

        // Banner
        out << colorHeader(c) << "═══════════════════════════════════════════════"
            << "════════════════════════" << colorReset(c) << "\n"
            << colorHeader(c) << "  IccTest v2.0 — ICC Profile Security & "
            << "Conformance Analyzer" << colorReset(c) << "\n"
            << colorHeader(c) << "═══════════════════════════════════════════════"
            << "════════════════════════" << colorReset(c) << "\n";

        // File info
        if (!opts.inputFile.empty()) {
            out << "  File: " << opts.inputFile << "\n";
        }

        // Profile metadata
        out << "  Version: "
            << ((result.metadata.version >> 24) & 0xFF) << "."
            << ((result.metadata.version >> 20) & 0xF) << "."
            << ((result.metadata.version >> 16) & 0xF) << "\n";

        // Render profile class signature
        auto sigStr = [](uint32_t sig) -> std::string {
            char buf[5];
            buf[0] = static_cast<char>((sig >> 24) & 0xFF);
            buf[1] = static_cast<char>((sig >> 16) & 0xFF);
            buf[2] = static_cast<char>((sig >> 8) & 0xFF);
            buf[3] = static_cast<char>(sig & 0xFF);
            buf[4] = '\0';
            return buf;
        };
        out << "  Class: " << sigStr(result.metadata.profileClass) << "\n";
        out << "  Color Space: " << sigStr(result.metadata.colorSpace) << "\n";
        out << "  PCS: " << sigStr(result.metadata.pcs) << "\n\n";

        // Summary
        out << colorHeader(c) << "─── Summary ─────────────────────────────────"
            << "──────────────────────────" << colorReset(c) << "\n";
        const int coverageOnlyChecks = countCoverageOnlyChecks(result);
        out << "  Checks run: " << result.stats.checksRun
            << "  Coverage-only: " << coverageOnlyChecks
            << "  Time: " << (result.stats.totalTime.count() / 1000) << " ms\n";

        // Findings by severity
        const char* sevLabels[] = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
        bool anyFindings = false;
        for (int i = 4; i >= 0; --i) {
            if (result.stats.findingsBySeverity[i] > 0) {
                auto sev = static_cast<Severity>(i);
                out << "  " << colorForSeverity(sev, c) << sevLabels[i]
                    << ": " << result.stats.findingsBySeverity[i]
                    << colorReset(c) << "\n";
                anyFindings = true;
            }
        }
        if (!anyFindings) {
            out << "  " << colorSuccess(c) << "No findings" << colorReset(c) << "\n";
        }
        out << "\n";

        // Findings detail
        if (!result.findings.empty()) {
            out << colorHeader(c) << "─── Findings ────────────────────────────────"
                << "──────────────────────────" << colorReset(c) << "\n";

            for (const auto& f : result.findings) {
                out << "  " << colorForSeverity(f.level, c)
                    << "[" << f.id.str() << "] "
                    << severityName(f.level) << colorReset(c);
                out << "\n";
                out << "    " << f.message << "\n";
                if (!f.detail.empty()) {
                    out << "    " << f.detail << "\n";
                }
                if (!f.cweNote.empty()) {
                    out << "    " << f.cweNote << "\n";
                }
                out << "\n";
            }
        }

        // Footer
        out << colorHeader(c) << "═══════════════════════════════════════════════"
            << "════════════════════════" << colorReset(c) << "\n";
    }
};

// Factory function (used by main.cpp)
std::unique_ptr<OutputFormatter> createTextFormatter() {
    return std::make_unique<TextFormatter>();
}

} // namespace icctest
