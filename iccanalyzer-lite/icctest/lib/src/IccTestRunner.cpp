/*
 * IccTest Library -- IccTestRunner.cpp
 * Main analysis orchestrator.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/IccTest.h"
#include "icctest/Logger.h"

#include <chrono>

namespace icctest {

static constexpr const char* ICCTEST_VERSION = "2.0.1-alpha";

static bool isRawMlucAlignmentCheck(const RegisteredCheck& check) {
    return check.id.kind == CheckID::Kind::Conformance &&
           check.id.number == 225;
}

static bool canRunWhenLibraryQuarantined(const RegisteredCheck& check) {
    if (isRawMlucAlignmentCheck(check)) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic && check.id.number == 90) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic && check.id.number == 93) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic && check.id.number == 97) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic && check.id.number == 98) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic && check.id.number == 99) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic && check.id.number == 100) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic && check.id.number == 147) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic && check.id.number == 127) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic && check.id.number == 172) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic && check.id.number == 101) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic && check.id.number == 102) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic &&
        check.id.number >= 128 && check.id.number <= 135) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Heuristic &&
        (check.id.number == 123 || check.id.number == 124 ||
         check.id.number == 126)) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Conformance && check.id.number == 115) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Conformance && check.id.number == 140) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Conformance && check.id.number == 286) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Conformance && check.id.number == 287) {
        return true;
    }
    return false;
}

static bool canRunWhenLibraryLoadFails(const RegisteredCheck& check) {
    if (canRunWhenLibraryQuarantined(check)) {
        return true;
    }
    if (check.id.kind == CheckID::Kind::Conformance && check.id.number == 190) {
        return true;
    }
    return false;
}

const char* IccTestRunner::version() {
    return ICCTEST_VERSION;
}

size_t IccTestRunner::checkCount() {
    return CheckRegistry::instance().size();
}

bool IccTestRunner::shouldRun(const RegisteredCheck& check,
                               const AnalysisOptions& opts) const {
    // Phase filter
    if (!opts.phases.empty()) {
        bool phaseMatch = false;
        for (auto p : opts.phases) {
            if (p == check.meta.phase) { phaseMatch = true; break; }
        }
        if (!phaseMatch) return false;
    }

    // Specific check filter
    if (!opts.specificChecks.empty()) {
        bool idMatch = false;
        for (const auto& id : opts.specificChecks) {
            if (id == check.id) { idMatch = true; break; }
        }
        if (!idMatch) return false;
    }

    // Isolation filter
    if (opts.skipIsolation && check.meta.phase == CheckPhase::IMAGE) {
        // IMAGE phase may require fork isolation
        return false;
    }

    return true;
}

AnalysisResult IccTestRunner::analyze(const std::filesystem::path& path,
                                       const AnalysisOptions& opts) const {
    ICCTEST_INFO("Analyzing file: %s", path.c_str());

    auto pv = ProfileView::open(path, opts.skipLibraryOnUB);
    if (!pv) {
        AnalysisResult result{};
        result.findings.push_back(Finding{
            {CheckID::Kind::Heuristic, 0},
            Severity::CRITICAL,
            "Failed to open profile: " + path.string(),
            "", ""
        });
        result.stats.findingsTotal = 1;
        result.stats.findingsBySeverity[static_cast<size_t>(Severity::CRITICAL)] = 1;
        return result;
    }

    return analyze(*pv, opts);
}

AnalysisResult IccTestRunner::analyze(const uint8_t* data, size_t len,
                                       const AnalysisOptions& opts) const {
    ICCTEST_INFO("Analyzing buffer (%zu bytes)", len);

    auto pv = ProfileView::open(data, len, opts.skipLibraryOnUB);
    if (!pv) {
        AnalysisResult result{};
        result.findings.push_back(Finding{
            {CheckID::Kind::Heuristic, 0},
            Severity::CRITICAL,
            "Failed to parse profile from buffer",
            "", ""
        });
        result.stats.findingsTotal = 1;
        result.stats.findingsBySeverity[static_cast<size_t>(Severity::CRITICAL)] = 1;
        return result;
    }

    return analyze(*pv, opts);
}

AnalysisResult IccTestRunner::analyze(const ProfileView& pv,
                                       const AnalysisOptions& opts) const {
    auto startTime = std::chrono::steady_clock::now();

    AnalysisResult result{};
    result.metadata = pv.metadata();

    auto& registry = CheckRegistry::instance();
    registry.sort();

    bool skipLibrary = opts.skipLibraryOnUB && pv.requiresLibraryQuarantine();
    if (skipLibrary) {
        ICCTEST_WARN("UB patterns detected -- skipping library-phase checks");
        // Add info finding about skipped library checks
        result.findings.push_back(Finding{
            {CheckID::Kind::Heuristic, 0},
            Severity::INFO,
            "Library-phase checks skipped due to UB pre-scan findings",
            pv.ubPatternDescriptions().empty() ? ""
                : pv.ubPatternDescriptions()[0],
            ""
        });
    }

    for (const auto& check : registry.all()) {
        // Skip checks that don't match options
        if (!shouldRun(check, opts)) {
            continue;
        }

        // Skip library-phase checks if UB detected
        if (skipLibrary &&
            (check.meta.phase == CheckPhase::LIBRARY ||
             check.meta.phase == CheckPhase::CONFORMANCE) &&
            !canRunWhenLibraryQuarantined(check)) {
            continue;
        }

        if ((check.meta.phase == CheckPhase::LIBRARY ||
             check.meta.phase == CheckPhase::CONFORMANCE) &&
            !pv.libraryLoaded() &&
            !canRunWhenLibraryLoadFails(check)) {
            result.stats.checksRun++;
            auto cr = CheckResult::ok("NOT RUN: Profile failed to load");
            result.perCheck.push_back(PerCheckResult{
                check.id,
                check.meta,
                std::move(cr)
            });
            continue;
        }

        // Run the check
        ICCTEST_TRACE("Running %s", check.id.str().c_str());
        CheckResult cr;
        try {
            cr = check.fn(pv);
        } catch (const std::exception& e) {
            cr = CheckResult::error(
                check.id.str() + " threw: " + e.what());
        } catch (...) {
            cr = CheckResult::error(
                check.id.str() + " threw unknown exception");
        }

        result.stats.checksRun++;

        // Collect findings
        for (auto& f : cr.findings) {
            // Enrich finding with check ID if not already set
            if (f.id.number == 0) f.id = check.id;
            // Apply minimum severity filter
            if (f.level >= opts.minSeverity) {
                result.stats.countFinding(f.level);
                result.findings.push_back(f);
            }
        }

        result.perCheck.push_back(PerCheckResult{
            check.id,
            check.meta,
            std::move(cr)
        });

        // Check max findings limit
        if (opts.maxFindings > 0 &&
            result.stats.findingsTotal >= opts.maxFindings) {
            ICCTEST_INFO("Max findings limit reached (%d)", opts.maxFindings);
            break;
        }
    }

    auto endTime = std::chrono::steady_clock::now();
    result.stats.totalTime = std::chrono::duration_cast<std::chrono::microseconds>(
        endTime - startTime);

    ICCTEST_INFO("Analysis complete: %d checks, %d findings, %lld us",
        result.stats.checksRun, result.stats.findingsTotal,
        (long long)result.stats.totalTime.count());

    return result;
}

} // namespace icctest
