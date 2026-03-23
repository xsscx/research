/*
 * IccTest Library — test_check_result.cpp
 * Tests for CheckResult, Finding, AnalysisResult, and related types.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckResult.h"
#include <cstdio>

// From test_main.cpp
extern void test_assert(bool, const char*, const char*, int);
#define ASSERT(cond)      test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_EQ(a, b)   test_assert((a) == (b), #a " == " #b, __FILE__, __LINE__)
#define ASSERT_TRUE(cond)  test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_FALSE(cond) test_assert(!(cond), "!" #cond, __FILE__, __LINE__)

using namespace icctest;

static void test_severity_names() {
    std::printf("  test_severity_names...\n");
    ASSERT_EQ(std::string("INFO"),     severityName(Severity::INFO));
    ASSERT_EQ(std::string("LOW"),      severityName(Severity::LOW));
    ASSERT_EQ(std::string("MEDIUM"),   severityName(Severity::MEDIUM));
    ASSERT_EQ(std::string("HIGH"),     severityName(Severity::HIGH));
    ASSERT_EQ(std::string("CRITICAL"), severityName(Severity::CRITICAL));
}

static void test_phase_names() {
    std::printf("  test_phase_names...\n");
    ASSERT_EQ(std::string("HEADER"),      phaseName(CheckPhase::HEADER));
    ASSERT_EQ(std::string("TAG_TABLE"),   phaseName(CheckPhase::TAG_TABLE));
    ASSERT_EQ(std::string("RAW_SCAN"),    phaseName(CheckPhase::RAW_SCAN));
    ASSERT_EQ(std::string("LIBRARY"),     phaseName(CheckPhase::LIBRARY));
    ASSERT_EQ(std::string("CONFORMANCE"), phaseName(CheckPhase::CONFORMANCE));
    ASSERT_EQ(std::string("IMAGE"),       phaseName(CheckPhase::IMAGE));
}

static void test_check_id() {
    std::printf("  test_check_id...\n");
    CheckID h42 = {CheckID::Kind::Heuristic, 42};
    ASSERT_EQ(std::string("H42"), h42.str());

    CheckID cf317 = {CheckID::Kind::Conformance, 317};
    ASSERT_EQ(std::string("CF-317"), cf317.str());

    // Equality
    CheckID h42b = {CheckID::Kind::Heuristic, 42};
    ASSERT_TRUE(h42 == h42b);
    ASSERT_FALSE(h42 == cf317);

    // Ordering: Heuristic < Conformance
    ASSERT_TRUE(h42 < cf317);
}

static void test_check_result_constructors() {
    std::printf("  test_check_result_constructors...\n");

    auto ok = CheckResult::ok("Everything fine");
    ASSERT_TRUE(ok.isOk());
    ASSERT_EQ(0, ok.issueCount());
    ASSERT_EQ(CheckResult::Status::OK, ok.status);

    auto skip = CheckResult::skip("Not applicable");
    ASSERT_EQ(CheckResult::Status::SKIP, skip.status);
    ASSERT_EQ(0, skip.issueCount());

    auto err = CheckResult::error("Internal error");
    ASSERT_EQ(CheckResult::Status::ERROR, err.status);

    auto iso = CheckResult::needsIsolation("Fork required");
    ASSERT_EQ(CheckResult::Status::NEEDS_ISOLATION, iso.status);
}

static void test_check_result_with_findings() {
    std::printf("  test_check_result_with_findings...\n");

    CheckResult result;
    result.status = CheckResult::Status::FINDINGS;
    result.summary = "3 issues found";
    result.findings.push_back(Finding{
        {CheckID::Kind::Heuristic, 1},
        Severity::HIGH,
        "Bad size field",
        "Size declared as 0",
        "CWE-131"
    });
    result.findings.push_back(Finding{
        {CheckID::Kind::Heuristic, 2},
        Severity::MEDIUM,
        "Version mismatch",
        "", ""
    });
    result.findings.push_back(Finding{
        {CheckID::Kind::Heuristic, 3},
        Severity::CRITICAL,
        "Buffer overflow",
        "Tag exceeds file size",
        "CWE-122"
    });

    ASSERT_FALSE(result.isOk());
    ASSERT_EQ(3, result.issueCount());
}

static void test_run_stats() {
    std::printf("  test_run_stats...\n");
    RunStats stats;
    ASSERT_EQ(0, stats.checksRun);
    ASSERT_EQ(0, stats.findingsTotal);

    stats.countFinding(Severity::HIGH);
    stats.countFinding(Severity::HIGH);
    stats.countFinding(Severity::CRITICAL);

    ASSERT_EQ(3, stats.findingsTotal);
    ASSERT_EQ(2, stats.findingsBySeverity[static_cast<size_t>(Severity::HIGH)]);
    ASSERT_EQ(1, stats.findingsBySeverity[static_cast<size_t>(Severity::CRITICAL)]);
    ASSERT_EQ(0, stats.findingsBySeverity[static_cast<size_t>(Severity::INFO)]);
}

static void test_analysis_result_queries() {
    std::printf("  test_analysis_result_queries...\n");

    AnalysisResult ar;
    ar.findings.push_back(Finding{
        {CheckID::Kind::Heuristic, 1}, Severity::LOW,
        "Minor issue", "", ""});
    ar.findings.push_back(Finding{
        {CheckID::Kind::Heuristic, 2}, Severity::CRITICAL,
        "Buffer overflow", "", "CWE-122: Heap-based buffer overflow"});
    ar.findings.push_back(Finding{
        {CheckID::Kind::Conformance, 42}, Severity::HIGH,
        "Missing required tag", "", "CWE-20: Improper Input Validation"});

    ASSERT_TRUE(ar.hasCritical());

    auto critical = ar.bySeverity(Severity::CRITICAL);
    ASSERT_EQ(1u, critical.size());

    auto highPlus = ar.bySeverity(Severity::HIGH);
    ASSERT_EQ(2u, highPlus.size());  // HIGH + CRITICAL

    auto cwe122 = ar.byCWE("CWE-122");
    ASSERT_EQ(1u, cwe122.size());

    auto cwe20 = ar.byCWE("CWE-20");
    ASSERT_EQ(1u, cwe20.size());
}

static void test_profile_metadata() {
    std::printf("  test_profile_metadata...\n");
    ProfileMetadata md{};
    md.version = 0x04400000;
    md.profileClass = 0x6D6E7472;  // 'mntr'
    md.colorSpace = 0x52474220;    // 'RGB '
    md.fileSize = 4096;
    md.creator = "test";

    ASSERT_EQ(0x04400000u, md.version);
    ASSERT_EQ(0x6D6E7472u, md.profileClass);
    ASSERT_EQ(std::string("test"), md.creator);
}

static void test_coverage_only_count() {
    std::printf("  test_coverage_only_count...\n");

    AnalysisResult ar;
    ar.perCheck.push_back(PerCheckResult{
        {CheckID::Kind::Conformance, 1},
        CheckMeta{"CF-001", "", "", "", "", Severity::LOW, CheckPhase::CONFORMANCE},
        CheckResult::ok("N/A: Not applicable")
    });
    ar.perCheck.push_back(PerCheckResult{
        {CheckID::Kind::Conformance, 2},
        CheckMeta{"CF-002", "", "", "", "", Severity::LOW, CheckPhase::CONFORMANCE},
        CheckResult::ok("GAP: Coverage pending")
    });
    ar.perCheck.push_back(PerCheckResult{
        {CheckID::Kind::Conformance, 3},
        CheckMeta{"CF-003", "", "", "", "", Severity::LOW, CheckPhase::CONFORMANCE},
        CheckResult::ok("NOT RUN: Profile failed to load")
    });
    ar.perCheck.push_back(PerCheckResult{
        {CheckID::Kind::Conformance, 4},
        CheckMeta{"CF-004", "", "", "", "", Severity::LOW, CheckPhase::CONFORMANCE},
        CheckResult::ok("Conformant")
    });

    ASSERT_EQ(3, countCoverageOnlyChecks(ar));
}

void test_check_result() {
    std::printf("test_check_result:\n");
    test_severity_names();
    test_phase_names();
    test_check_id();
    test_check_result_constructors();
    test_check_result_with_findings();
    test_run_stats();
    test_analysis_result_queries();
    test_profile_metadata();
    test_coverage_only_count();
    std::printf("  [OK]\n\n");
}
