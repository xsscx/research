/*
 * IccTest CLI — JsonFormatter.cpp
 * Structured JSON output matching V1's --json schema.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "../src/OutputFormatter.h"

#include <icctest/CheckRegistry.h>

#include <iostream>
#include <sstream>

namespace icctest {

namespace {

// Minimal JSON writer (no external dependency).
// Uses escaped strings for safety against control characters.
std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

} // anon

class JsonFormatter final : public OutputFormatter {
public:
    void format(const AnalysisResult& result,
                const FormatOptions& opts,
                std::ostream& out) override
    {
        out << "{\n";

        // Metadata
        out << "  \"metadata\": {\n";
        out << "    \"version\": \"" << ((result.metadata.version >> 24) & 0xFF) << "."
            << ((result.metadata.version >> 20) & 0xF) << "."
            << ((result.metadata.version >> 16) & 0xF) << "\",\n";

        auto sigStr = [](uint32_t sig) -> std::string {
            char buf[5];
            buf[0] = static_cast<char>((sig >> 24) & 0xFF);
            buf[1] = static_cast<char>((sig >> 16) & 0xFF);
            buf[2] = static_cast<char>((sig >> 8) & 0xFF);
            buf[3] = static_cast<char>(sig & 0xFF);
            buf[4] = '\0';
            return buf;
        };
        out << "    \"profileClass\": \"" << sigStr(result.metadata.profileClass) << "\",\n";
        out << "    \"colorSpace\": \"" << sigStr(result.metadata.colorSpace) << "\",\n";
        out << "    \"pcs\": \"" << sigStr(result.metadata.pcs) << "\",\n";
        out << "    \"flags\": " << result.metadata.flags << ",\n";
        out << "    \"fileSize\": " << result.metadata.fileSize << "\n";
        out << "  },\n";

        // Stats
        out << "  \"stats\": {\n";
        out << "    \"checksRun\": " << result.stats.checksRun << ",\n";
        out << "    \"checksSkipped\": " << result.stats.checksSkipped << ",\n";
        out << "    \"findingsTotal\": " << result.stats.findingsTotal << ",\n";
        out << "    \"totalTimeUs\": " << result.stats.totalTime.count() << ",\n";
        out << "    \"severity\": {\n";
        out << "      \"CRITICAL\": " << result.stats.findingsBySeverity[4] << ",\n";
        out << "      \"HIGH\": " << result.stats.findingsBySeverity[3] << ",\n";
        out << "      \"MEDIUM\": " << result.stats.findingsBySeverity[2] << ",\n";
        out << "      \"LOW\": " << result.stats.findingsBySeverity[1] << ",\n";
        out << "      \"INFO\": " << result.stats.findingsBySeverity[0] << "\n";
        out << "    }\n";
        out << "  },\n";

        // Input file
        if (!opts.inputFile.empty()) {
            out << "  \"inputFile\": \"" << jsonEscape(opts.inputFile) << "\",\n";
        }

        // Findings
        out << "  \"findings\": [\n";
        for (size_t i = 0; i < result.findings.size(); ++i) {
            const auto& f = result.findings[i];
            out << "    {\n";
            out << "      \"id\": \"" << f.id.str() << "\",\n";
            out << "      \"severity\": \"" << severityName(f.level) << "\",\n";
            out << "      \"message\": \"" << jsonEscape(f.message) << "\"";
            if (!f.detail.empty()) {
                out << ",\n      \"detail\": \"" << jsonEscape(f.detail) << "\"";
            }
            if (!f.cweNote.empty()) {
                out << ",\n      \"cwe\": \"" << jsonEscape(f.cweNote) << "\"";
            }
            out << "\n    }";
            if (i + 1 < result.findings.size()) out << ",";
            out << "\n";
        }
        out << "  ]\n";

        out << "}\n";
    }

    void formatRegistry(std::ostream& out) override {
        const auto& reg = CheckRegistry::instance();
        const auto& checks = reg.all();

        out << "{\n";
        out << "  \"totalChecks\": " << checks.size() << ",\n";

        // Count by kind
        int hCount = 0, cfCount = 0;
        for (const auto& c : checks) {
            if (c.id.kind == CheckID::Kind::Heuristic) ++hCount;
            else ++cfCount;
        }
        out << "  \"heuristics\": " << hCount << ",\n";
        out << "  \"conformance\": " << cfCount << ",\n";

        out << "  \"checks\": [\n";
        for (size_t i = 0; i < checks.size(); ++i) {
            const auto& c = checks[i];
            out << "    {\n";
            out << "      \"id\": \"" << c.id.str() << "\",\n";
            out << "      \"name\": \"" << jsonEscape(std::string(c.meta.name)) << "\",\n";
            out << "      \"severity\": \"" << severityName(c.meta.severity) << "\",\n";
            out << "      \"phase\": \"" << phaseName(c.meta.phase) << "\"";
            if (!c.meta.specRef.empty()) {
                out << ",\n      \"specRef\": \"" << jsonEscape(std::string(c.meta.specRef)) << "\"";
            }
            if (!c.meta.primaryCWE.empty()) {
                out << ",\n      \"cwe\": \"" << jsonEscape(std::string(c.meta.primaryCWE)) << "\"";
            }
            out << "\n    }";
            if (i + 1 < checks.size()) out << ",";
            out << "\n";
        }
        out << "  ]\n";
        out << "}\n";
    }
};

// Factory function
std::unique_ptr<OutputFormatter> createJsonFormatter() {
    return std::make_unique<JsonFormatter>();
}

} // namespace icctest
