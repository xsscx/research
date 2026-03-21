/*
 * IccTest Library — IccTest.h
 * Public API: IccTestRunner orchestrates check execution.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 *
 * This is the main entry point for consumers of libIccTest.
 * IccTestRunner opens a profile, runs registered checks, and
 * returns a structured AnalysisResult with zero I/O.
 */

#ifndef ICCTEST_ICCTEST_H
#define ICCTEST_ICCTEST_H

#include "CheckResult.h"
#include "CheckRegistry.h"
#include "ProfileView.h"
#include "Logger.h"

#include <filesystem>
#include <optional>
#include <vector>

namespace icctest {

/// Options controlling which checks to run.
struct AnalysisOptions {
    /// Minimum severity to include in results (default: INFO = all).
    Severity minSeverity = Severity::INFO;

    /// Phases to run (empty = all phases).
    std::vector<CheckPhase> phases;

    /// Specific check IDs to run (empty = all checks).
    std::vector<CheckID> specificChecks;

    /// Maximum number of findings before stopping (0 = unlimited).
    int maxFindings = 0;

    /// Skip checks that require fork-based isolation.
    bool skipIsolation = false;

    /// Whether to run UB pre-scan (default: true).
    bool ubPreScan = true;

    /// Whether to skip library-phase checks if UB patterns detected.
    bool skipLibraryOnUB = true;
};

/// Main analysis orchestrator. Stateless — all state is in the result.
class IccTestRunner {
public:
    IccTestRunner() = default;

    /// Analyze a profile from a file path.
    AnalysisResult analyze(const std::filesystem::path& path,
                           const AnalysisOptions& opts = {}) const;

    /// Analyze a profile from a memory buffer.
    AnalysisResult analyze(const uint8_t* data, size_t len,
                           const AnalysisOptions& opts = {}) const;

    /// Analyze a profile that has already been opened.
    AnalysisResult analyze(const ProfileView& pv,
                           const AnalysisOptions& opts = {}) const;

    /// Get the version string of the IccTest library.
    static const char* version();

    /// Get the number of registered checks.
    static size_t checkCount();

private:
    bool shouldRun(const RegisteredCheck& check,
                   const AnalysisOptions& opts) const;
};

} // namespace icctest

#endif // ICCTEST_ICCTEST_H
