/*
 * IccTest CLI — SarifFormatter.cpp
 * SARIF 2.1.0 output for CI integration (GitHub Code Scanning).
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 *
 * SARIF (Static Analysis Results Interchange Format) is an OASIS standard
 * for representing results of static analysis tools. GitHub Code Scanning
 * consumes SARIF files to display alerts in the Security tab.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

#include "../src/OutputFormatter.h"

#include <iostream>
#include <sstream>

namespace icctest {

namespace {

std::string sarifEscape(const std::string& s) {
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

const char* sarifLevel(Severity sev) {
    switch (sev) {
        case Severity::CRITICAL: return "error";
        case Severity::HIGH:     return "error";
        case Severity::MEDIUM:   return "warning";
        case Severity::LOW:      return "note";
        case Severity::INFO:     return "note";
    }
    return "note";
}

} // anon

class SarifFormatter final : public OutputFormatter {
public:
    void format(const AnalysisResult& result,
                const FormatOptions& opts,
                std::ostream& out) override
    {
        out << "{\n";
        out << "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json\",\n";
        out << "  \"version\": \"2.1.0\",\n";
        out << "  \"runs\": [{\n";

        // Tool section
        out << "    \"tool\": {\n";
        out << "      \"driver\": {\n";
        out << "        \"name\": \"IccTest\",\n";
        out << "        \"version\": \"2.0.1\",\n";
        out << "        \"informationUri\": \"https://github.com/xsscx/research\",\n";
        out << "        \"rules\": [\n";

        // Emit unique rules from findings
        std::vector<std::string> emittedRules;
        for (const auto& f : result.findings) {
            auto ruleId = f.id.str();
            bool alreadyEmitted = false;
            for (const auto& r : emittedRules) {
                if (r == ruleId) { alreadyEmitted = true; break; }
            }
            if (alreadyEmitted) continue;
            emittedRules.push_back(ruleId);

            if (emittedRules.size() > 1) out << ",\n";
            out << "          {\n";
            out << "            \"id\": \"" << ruleId << "\",\n";
            out << "            \"shortDescription\": {\n";
            out << "              \"text\": \"" << sarifEscape(f.message.substr(0, 200)) << "\"\n";
            out << "            },\n";
            out << "            \"defaultConfiguration\": {\n";
            out << "              \"level\": \"" << sarifLevel(f.level) << "\"\n";
            out << "            }";
            if (!f.cweNote.empty()) {
                out << ",\n            \"relationships\": [{\n";
                out << "              \"target\": {\n";
                out << "                \"id\": \"" << sarifEscape(f.cweNote) << "\",\n";
                out << "                \"toolComponent\": { \"name\": \"CWE\" }\n";
                out << "              },\n";
                out << "              \"kinds\": [\"superset\"]\n";
                out << "            }]";
            }
            out << "\n          }";
        }
        out << "\n        ]\n";
        out << "      }\n";
        out << "    },\n";

        // Results section
        out << "    \"results\": [\n";
        for (size_t i = 0; i < result.findings.size(); ++i) {
            const auto& f = result.findings[i];
            if (i > 0) out << ",\n";
            out << "      {\n";
            out << "        \"ruleId\": \"" << f.id.str() << "\",\n";
            out << "        \"level\": \"" << sarifLevel(f.level) << "\",\n";
            out << "        \"message\": {\n";
            out << "          \"text\": \"" << sarifEscape(f.message) << "\"\n";
            out << "        },\n";
            out << "        \"locations\": [{\n";
            out << "          \"physicalLocation\": {\n";
            out << "            \"artifactLocation\": {\n";
            out << "              \"uri\": \"" << sarifEscape(opts.inputFile) << "\"\n";
            out << "            }\n";
            out << "          }\n";
            out << "        }]\n";
            out << "      }";
        }
        out << "\n    ]\n";

        out << "  }]\n";
        out << "}\n";
    }
};

// Factory function
std::unique_ptr<OutputFormatter> createSarifFormatter() {
    return std::make_unique<SarifFormatter>();
}

} // namespace icctest
