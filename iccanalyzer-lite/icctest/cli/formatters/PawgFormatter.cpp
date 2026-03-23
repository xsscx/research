/*
 * IccTest CLI — PawgFormatter.cpp
 * ICC PAWG checklist formatter aligned with the published assessment page.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "../src/OutputFormatter.h"
#include "../../../PawgSpecReferences.h"

#include <icctest/IccTest.h>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace icctest {

namespace {

enum class PawgVerdict {
    PASS = 0,
    WARN = 1,
    FAIL = 2,
    NOT_APPLICABLE = 3,
    GAP = 4,
    NOT_RUN = 5,
};

struct PawgItemDef {
    const char* id;
    const char* title;
    std::initializer_list<int> checks;
    PawgVerdict allSkippedVerdict;
};

struct PawgItem {
    const char* id;
    const char* title;
    std::vector<int> checks;
    PawgVerdict allSkippedVerdict = PawgVerdict::NOT_APPLICABLE;
    PawgVerdict verdict = PawgVerdict::NOT_RUN;
    std::vector<std::string> detailLines;
};

constexpr std::array<PawgItemDef, 13> kSecurityItems{{
    {"S1", "Channel counts in tags match data colour space", {60, 61}, PawgVerdict::GAP},
    {"S2", "Header is 128 bytes and correctly encoded", {10, 6, 12, 13}, PawgVerdict::NOT_APPLICABLE},
    {"S3", "Platform, Creator, Manufacturer and CMM fields correspond to registered signatures or are zero", {7}, PawgVerdict::NOT_APPLICABLE},
    {"S4", "Illuminant corresponds to D50", {8}, PawgVerdict::NOT_APPLICABLE},
    {"S5", "Unless a DeviceLink profile, PCS is Lab or XYZ", {14}, PawgVerdict::NOT_APPLICABLE},
    {"S6", "Tags correctly aligned - offset and length correspond to tag table, no overlapping tags or gaps between tags - and correctly encoded", {20, 103, 107}, PawgVerdict::NOT_APPLICABLE},
    {"S7", "Tag table correctly encoded", {40}, PawgVerdict::NOT_APPLICABLE},
    {"S8", "No known malware signatures present", {91}, PawgVerdict::NOT_APPLICABLE},
    {"S9", "EOF follows last tag (including four-byte boundary), no additional bytes before or after", {10}, PawgVerdict::NOT_APPLICABLE},
    {"S10", "Excessive calculator elements not present (ideally provide an estimate of computation cost)", {88, 62}, PawgVerdict::NOT_APPLICABLE},
    {"S11", "Private tags ideally not present", {92}, PawgVerdict::NOT_APPLICABLE},
    {"S12", "Private tags do not contain malware", {93}, PawgVerdict::NOT_APPLICABLE},
    {"S13", "Private tags do not contain exploitable non-operation (NOP) instructions", {94}, PawgVerdict::NOT_APPLICABLE},
}};

constexpr std::array<PawgItemDef, 14> kConformanceItems{{
    {"C1", "Tag types are correctly encoded (signature, structure, data types, ranges, encoded values)", {20, 22, 23, 24, 25, 26, 27, 28, 29, 32, 33, 34, 112}, PawgVerdict::NOT_APPLICABLE},
    {"C2", "cprt, desc tags encoded as Unicode or text according to specification version", {40}, PawgVerdict::NOT_APPLICABLE},
    {"C3", "Tags only use tag types allowed for the tag", {20}, PawgVerdict::NOT_APPLICABLE},
    {"C4", "All required tags for profile class are present", {40, 41, 42, 43, 44, 45, 46, 47, 104, 111}, PawgVerdict::NOT_APPLICABLE},
    {"C5", "Additional tags not required for profile class (other than allowed optional tags) are not present; or are flagged as private tags", {95}, PawgVerdict::NOT_APPLICABLE},
    {"C6", "Private tags have a registered signature", {96}, PawgVerdict::NOT_APPLICABLE},
    {"C7", "Private tag documentation is available through the tag registry", {97}, PawgVerdict::NOT_APPLICABLE},
    {"C8", "Undocumented private tags are identified", {98}, PawgVerdict::NOT_APPLICABLE},
    {"C9", "Profile class is consistent with data colour space", {12, 13}, PawgVerdict::NOT_APPLICABLE},
    {"C10", "Header content conforms with specification", {1, 2, 3, 4, 5, 6, 8, 9, 14, 15, 121, 122}, PawgVerdict::NOT_APPLICABLE},
    {"C11", "Tags present correspond to profile version", {48, 53}, PawgVerdict::NOT_APPLICABLE},
    {"C12", "Wtpt correctly encoded - D50 for v4 display; or valid value for other profile classes", {8}, PawgVerdict::NOT_APPLICABLE},
    {"C13", "Reserved bytes are zero", {15}, PawgVerdict::NOT_APPLICABLE},
    {"C14", "Tags start and end on four-byte boundaries", {20, 103}, PawgVerdict::NOT_APPLICABLE},
}};

constexpr std::array<PawgItemDef, 4> kQualityItems{{
    {"Q1", "First and second round trip average and maximum differences in CIEDE2000", {99}, PawgVerdict::GAP},
    {"Q2", "Curve round trip differences in CIEDE2000 (i.e. can be inverted)", {100, 106}, PawgVerdict::GAP},
    {"Q3", "Smoothness metric values of overall transform", {101}, PawgVerdict::GAP},
    {"Q4", "If characterization data is present, round trip average and maximum differences of profile output in CIEDE2000", {102}, PawgVerdict::GAP},
}};

template <size_t N>
std::vector<PawgItem> makeItems(const std::array<PawgItemDef, N>& defs) {
    std::vector<PawgItem> out;
    out.reserve(N);
    for (const auto& def : defs) {
        out.push_back(PawgItem{
            def.id,
            def.title,
            std::vector<int>(def.checks.begin(), def.checks.end()),
            def.allSkippedVerdict,
            PawgVerdict::NOT_RUN,
            {},
        });
    }
    return out;
}

std::string computeFileSha256(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    std::array<char, 8192> buf{};
    while (in.good()) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        std::streamsize got = in.gcount();
        if (got > 0) {
            EVP_DigestUpdate(ctx, buf.data(), static_cast<size_t>(got));
        }
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digestLen) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digestLen; ++i) {
        oss << std::setw(2) << static_cast<unsigned>(digest[i]);
    }
    return oss.str();
}

long fileSizeBytes(const std::string& path) {
    std::error_code ec;
    auto size = std::filesystem::file_size(path, ec);
    if (ec) return -1;
    return static_cast<long>(size);
}

std::string utcNowString() {
    std::time_t now = std::time(nullptr);
    char buf[64];
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &utc);
    return buf;
}

std::string compilerString() {
#if defined(__clang__)
    std::ostringstream oss;
    oss << "Clang " << __clang_major__;
    return oss.str();
#else
    return "Unknown Compiler";
#endif
}

const char* verdictIcon(PawgVerdict verdict) {
    switch (verdict) {
        case PawgVerdict::PASS:    return "[OK]  ";
        case PawgVerdict::WARN:    return "[WARN]";
        case PawgVerdict::FAIL:    return "[FAIL]";
        case PawgVerdict::NOT_APPLICABLE: return "[N/A] ";
        case PawgVerdict::GAP:     return "[GAP] ";
        case PawgVerdict::NOT_RUN: return "[ -- ]";
    }
    return "[??]  ";
}

void pawgBanner(std::ostream& out, std::string_view title, int width) {
    int titleLen = static_cast<int>(title.size());
    int pad = (width - titleLen - 4) / 2;
    if (pad < 0) pad = 0;
    for (int i = 0; i < pad; ++i) out << '=';
    out << "[ " << title << " ]";
    int remaining = width - pad - titleLen - 4;
    for (int i = 0; i < remaining; ++i) out << '=';
    out << '\n';
}

void pawgRule(std::ostream& out, int width) {
    for (int i = 0; i < width; ++i) out << '-';
    out << '\n';
}

PawgVerdict upgradeVerdict(PawgVerdict current, PawgVerdict candidate) {
    if (candidate == PawgVerdict::NOT_RUN) return current;
    if (current == PawgVerdict::NOT_RUN) return candidate;
    return static_cast<int>(candidate) > static_cast<int>(current) ? candidate : current;
}

PawgVerdict verdictForCheck(const PerCheckResult& entry) {
    if (entry.result.status == CheckResult::Status::ERROR) {
        return PawgVerdict::FAIL;
    }
    if (entry.result.status == CheckResult::Status::NEEDS_ISOLATION) {
        return PawgVerdict::WARN;
    }
    if (entry.result.status == CheckResult::Status::FINDINGS) {
        const bool anyCritical = std::any_of(
            entry.result.findings.begin(),
            entry.result.findings.end(),
            [](const Finding& finding) {
                return finding.level == Severity::CRITICAL;
            });
        return anyCritical ? PawgVerdict::FAIL : PawgVerdict::WARN;
    }
    return PawgVerdict::PASS;
}

bool isRuntimeSkipSummary(std::string_view summary) {
    if (summary.empty()) return false;
    return summary.find("Library failed to load") != std::string_view::npos
        || summary.find("not loaded") != std::string_view::npos
        || summary.find("read failed") != std::string_view::npos
        || summary.find("failed to load") != std::string_view::npos
        || summary.find("unsafe") != std::string_view::npos;
}

bool isExplicitNotApplicableSummary(std::string_view summary) {
    if (summary.empty()) return false;
    return summary.find("not applicable") != std::string_view::npos
        || summary.find("N/A") != std::string_view::npos
        || summary.find("exempt") != std::string_view::npos
        || summary.find("No charTargetTag present") != std::string_view::npos
        || summary.find("No characterization data") != std::string_view::npos;
}

PawgVerdict classifySkippedSummary(std::string_view summary, PawgVerdict defaultVerdict) {
    if (isRuntimeSkipSummary(summary)) return PawgVerdict::NOT_RUN;
    if (isExplicitNotApplicableSummary(summary)) return PawgVerdict::NOT_APPLICABLE;
    return defaultVerdict;
}

PawgVerdict mergeSkippedVerdict(PawgVerdict current, PawgVerdict candidate) {
    if (current == PawgVerdict::NOT_RUN || candidate == PawgVerdict::NOT_RUN) {
        return PawgVerdict::NOT_RUN;
    }
    if (current == PawgVerdict::GAP || candidate == PawgVerdict::GAP) {
        return PawgVerdict::GAP;
    }
    if (current == PawgVerdict::NOT_APPLICABLE || candidate == PawgVerdict::NOT_APPLICABLE) {
        return PawgVerdict::NOT_APPLICABLE;
    }
    return candidate;
}

void appendSkippedCheckDetail(PawgItem& item,
                              int cfNumber,
                              std::string_view summary,
                              PawgVerdict verdict) {
    std::ostringstream line;
    line << "CF-" << std::setw(3) << std::setfill('0') << cfNumber << std::setfill(' ');
    if (!summary.empty()) {
        line << ": " << summary;
    } else {
        line << ": check skipped";
    }
    switch (verdict) {
        case PawgVerdict::NOT_APPLICABLE:
            line << " [N/A]";
            break;
        case PawgVerdict::GAP:
            line << " [GAP]";
            break;
        case PawgVerdict::NOT_RUN:
            line << " [ -- ]";
            break;
        default:
            break;
    }
    item.detailLines.push_back(line.str());
}

struct PawgTotals {
    int pass = 0;
    int warn = 0;
    int fail = 0;
    int notApplicable = 0;
    int gap = 0;
    int notRun = 0;
};

void countVerdict(PawgTotals& totals, PawgVerdict verdict) {
    switch (verdict) {
        case PawgVerdict::PASS: ++totals.pass; break;
        case PawgVerdict::WARN: ++totals.warn; break;
        case PawgVerdict::FAIL: ++totals.fail; break;
        case PawgVerdict::NOT_APPLICABLE: ++totals.notApplicable; break;
        case PawgVerdict::GAP: ++totals.gap; break;
        case PawgVerdict::NOT_RUN: ++totals.notRun; break;
    }
}

void scorePawgItems(std::vector<PawgItem>& items, const AnalysisResult& result) {
    std::map<int, const PerCheckResult*> perCheck;
    for (const auto& entry : result.perCheck) {
        if (entry.id.kind != CheckID::Kind::Conformance) continue;
        perCheck.emplace(entry.id.number, &entry);
    }

    for (auto& item : items) {
        bool anySeen = false;
        bool anyEvaluated = false;
        PawgVerdict worst = PawgVerdict::PASS;
        std::vector<std::pair<int, std::string>> skippedChecks;
        for (int cfNumber : item.checks) {
            auto it = perCheck.find(cfNumber);
            if (it == perCheck.end()) continue;
            anySeen = true;

            const auto& entry = *it->second;
            if (entry.result.status == CheckResult::Status::SKIP) {
                skippedChecks.emplace_back(cfNumber, entry.result.summary);
                continue;
            }
            anyEvaluated = true;

            PawgVerdict checkVerdict = verdictForCheck(entry);
            worst = upgradeVerdict(worst, checkVerdict);

            if (checkVerdict == PawgVerdict::PASS) continue;

            std::ostringstream line;
            line << "CF-" << std::setw(3) << std::setfill('0') << cfNumber << std::setfill(' ');
            if (entry.result.status == CheckResult::Status::FINDINGS) {
                line << ": " << entry.result.findings.size() << " non-conformance(s) "
                     << (checkVerdict == PawgVerdict::FAIL ? "[FAIL]" : "[WARN]");
            } else if (!entry.result.summary.empty()) {
                line << ": " << entry.result.summary << ' '
                     << (checkVerdict == PawgVerdict::FAIL ? "[FAIL]" : "[WARN]");
            } else {
                line << ": check could not be fully evaluated "
                     << (checkVerdict == PawgVerdict::FAIL ? "[FAIL]" : "[WARN]");
            }
            item.detailLines.push_back(line.str());
        }

        if (!anySeen) {
            item.verdict = PawgVerdict::NOT_RUN;
            item.detailLines.push_back("No mapped conformance checks were executed [ -- ]");
            continue;
        }
        if (!anyEvaluated) {
            PawgVerdict skippedVerdict = PawgVerdict::NOT_APPLICABLE;
            for (const auto& [cfNumber, summary] : skippedChecks) {
                skippedVerdict = mergeSkippedVerdict(
                    skippedVerdict,
                    classifySkippedSummary(summary, item.allSkippedVerdict));
            }
            item.verdict = skippedVerdict;
            for (const auto& [cfNumber, summary] : skippedChecks) {
                appendSkippedCheckDetail(item, cfNumber, summary, skippedVerdict);
            }
            continue;
        }
        item.verdict = worst;
    }
}

void printPawgSection(std::ostream& out,
                      const char* sectionTitle,
                      const std::vector<PawgItem>& items,
                      PawgTotals& totals) {
    constexpr int kWidth = 78;
    out << '\n';
    pawgBanner(out, sectionTitle, kWidth);
    out << '\n';

    for (const auto& item : items) {
        out << "  " << verdictIcon(item.verdict) << "  "
            << std::left << std::setw(4) << item.id << "  "
            << item.title << '\n';
        out << std::right;

        out << "          Checks: ";
        if (item.checks.empty()) {
            out << "(none mapped)\n";
        } else {
            for (size_t i = 0; i < item.checks.size(); ++i) {
                if (i > 0) out << ", ";
                out << "CF-" << std::setw(3) << std::setfill('0') << item.checks[i];
            }
            out << std::setfill(' ') << '\n';
        }

        for (const auto& detail : item.detailLines) {
            out << "          " << detail << '\n';
        }
        out << '\n';

        countVerdict(totals, item.verdict);
    }
}

std::string overallVerdict(int totalItems, const PawgTotals& totals) {
    if (totals.fail > 0) {
        return "FAIL - Profile does not meet ICC PAWG assessment criteria";
    }
    if (totals.warn > 0) {
        return "CONDITIONAL PASS - Warnings detected, review recommended";
    }
    if ((totals.pass + totals.notApplicable) == totalItems && totals.gap == 0 && totals.notRun == 0) {
        return "PASS - Profile meets all ICC PAWG assessment criteria";
    }
    if (totals.gap > 0 || totals.notRun > 0) {
        return "INCOMPLETE - Some checklist items are not yet covered or could not be evaluated";
    }
    return "PASS - Profile meets all ICC PAWG assessment criteria";
}

size_t countMappedChecks() {
    std::set<int> mapped;
    for (const auto& def : kSecurityItems) {
        mapped.insert(def.checks.begin(), def.checks.end());
    }
    for (const auto& def : kConformanceItems) {
        mapped.insert(def.checks.begin(), def.checks.end());
    }
    for (const auto& def : kQualityItems) {
        mapped.insert(def.checks.begin(), def.checks.end());
    }
    return mapped.size();
}

std::pair<int, int> conformanceRegistryStats() {
    int total = 0;
    int withSpecRef = 0;
    for (const auto& check : CheckRegistry::instance().all()) {
        if (check.id.kind != CheckID::Kind::Conformance) continue;
        ++total;
        if (!check.meta.specRef.empty()) ++withSpecRef;
    }
    return {total, withSpecRef};
}

} // namespace

class PawgFormatter final : public OutputFormatter {
public:
    void format(const AnalysisResult& result,
                const FormatOptions& opts,
                std::ostream& out) override {
        constexpr int kWidth = 78;
        auto securityItems = makeItems(kSecurityItems);
        auto conformanceItems = makeItems(kConformanceItems);
        auto qualityItems = makeItems(kQualityItems);
        const auto specReferences = iccanalyzer::pawg::listSpecReferencePaths(opts.inputFile);

        scorePawgItems(securityItems, result);
        scorePawgItems(conformanceItems, result);
        scorePawgItems(qualityItems, result);

        const std::string sha256 = opts.inputFile.empty() ? "" : computeFileSha256(opts.inputFile);
        const long fileSize = opts.inputFile.empty() ? -1 : fileSizeBytes(opts.inputFile);

        out << '\n';
        for (int i = 0; i < kWidth; ++i) out << '=';
        out << '\n';
        pawgBanner(out, "ICC PROFILE ASSESSMENT REPORT (PAWG)", kWidth);
        for (int i = 0; i < kWidth; ++i) out << '=';
        out << "\n\n";

        out << "  Reference:  ICC Profile Assessment Working Group\n";
        out << "              Goals for profile assessment\n";
        out << "  ICC Profile Assessment Working Group Checklist Reference: "
            << iccanalyzer::pawg::kChecklistUrl << '\n';
        out << "  ICC Specification References:\n";
        for (const auto& ref : specReferences) {
            out << "    " << ref << '\n';
        }
        out << "  Tool:       IccTest v" << IccTestRunner::version() << '\n';
        out << "  Date:       " << utcNowString() << '\n';
        out << "  Build:      ASAN+UBSAN+Coverage | " << compilerString() << '\n';
        out << '\n';
        pawgRule(out, kWidth);
        if (!opts.inputFile.empty()) {
            out << "  File:       " << opts.inputFile << '\n';
        }
        if (!sha256.empty()) {
            out << "  SHA-256:    " << sha256 << '\n';
        }
        if (fileSize >= 0) {
            out << "  Size:       " << fileSize << " bytes\n";
        }
        pawgRule(out, kWidth);
        out << '\n';

        PawgTotals totals;
        printPawgSection(out, "SECURITY", securityItems, totals);
        printPawgSection(out, "CONFORMANCE", conformanceItems, totals);
        printPawgSection(out, "QUALITY", qualityItems, totals);

        const int totalItems = static_cast<int>(securityItems.size() + conformanceItems.size() + qualityItems.size());

        out << '\n';
        pawgBanner(out, "ASSESSMENT SUMMARY", kWidth);
        out << '\n';
        out << "  Total checklist items:  " << totalItems << '\n';
        out << "  PASS:                   " << totals.pass << '\n';
        out << "  WARN:                   " << totals.warn << '\n';
        out << "  FAIL:                   " << totals.fail << '\n';
        if (totals.notApplicable > 0) {
            out << "  N/A:                    " << totals.notApplicable << '\n';
        }
        if (totals.gap > 0) {
            out << "  GAP:                    " << totals.gap << '\n';
        }
        if (totals.notRun > 0) {
            out << "  NOT RUN:                " << totals.notRun << '\n';
        }
        out << '\n';
        out << "  Overall:   " << overallVerdict(totalItems, totals) << '\n';
        out << '\n';

        const auto [registryTotal, checksWithSpecRef] = conformanceRegistryStats();
        size_t evaluatedConformance = 0;
        for (const auto& entry : result.perCheck) {
            if (entry.id.kind == CheckID::Kind::Conformance) ++evaluatedConformance;
        }

        out << '\n';
        pawgBanner(out, "CONFORMANCE CHECK COVERAGE", kWidth);
        out << '\n';
        out << "  Checks evaluated:       " << evaluatedConformance << " / " << registryTotal << '\n';
        out << "  Checks mapped:          " << countMappedChecks() << " (across " << totalItems << " PAWG items)\n";
        out << "  Registry total:         " << registryTotal << " conformance checks\n";
        out << "  Spec coverage:          " << checksWithSpecRef << " checks with ICC spec refs\n";
        out << '\n';

        out << '\n';
        pawgBanner(out, "SPECIFICATION REFERENCES", kWidth);
        out << '\n';
        for (const auto& ref : specReferences) {
            out << "  " << ref << '\n';
        }
        out << '\n';

        for (int i = 0; i < kWidth; ++i) out << '=';
        out << '\n';
        out << "  Report generated by IccTest v" << IccTestRunner::version() << '\n';
        out << "  ICC PAWG checklist: 31 items (13 Security + 14 Conformance + 4 Quality)\n";
        for (int i = 0; i < kWidth; ++i) out << '=';
        out << "\n\n";
    }
};

std::unique_ptr<OutputFormatter> createPawgFormatter() {
    return std::make_unique<PawgFormatter>();
}

} // namespace icctest
