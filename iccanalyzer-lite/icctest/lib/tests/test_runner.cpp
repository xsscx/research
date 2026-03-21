/*
 * IccTest Library — test_runner.cpp
 * Tests for IccTestRunner orchestration.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/IccTest.h"
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <set>
#include <vector>

extern void test_assert(bool, const char*, const char*, int);
#define ASSERT(cond)       test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_EQ(a, b)    test_assert((a) == (b), #a " == " #b, __FILE__, __LINE__)
#define ASSERT_TRUE(cond)  test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_FALSE(cond) test_assert(!(cond), "!" #cond, __FILE__, __LINE__)
#define ASSERT_GT(a, b)    test_assert((a) > (b), #a " > " #b, __FILE__, __LINE__)

using namespace icctest;

// Example check: validates magic is 'acsp'
static CheckResult check_magic(const ProfileView& pv) {
    if (pv.header().magic != 0x61637370) {
        CheckResult r;
        r.status = CheckResult::Status::FINDINGS;
        r.summary = "Invalid magic";
        r.findings.push_back(Finding{
            {CheckID::Kind::Heuristic, 1},
            Severity::CRITICAL,
            "Magic is not 'acsp'", "", "CWE-20"});
        return r;
    }
    return CheckResult::ok("Magic valid");
}

// Example check: validates version
static CheckResult check_version(const ProfileView& pv) {
    uint8_t major = (pv.header().version >> 24) & 0xFF;
    if (major < 2 || major > 5) {
        CheckResult r;
        r.status = CheckResult::Status::FINDINGS;
        r.summary = "Unusual version";
        r.findings.push_back(Finding{
            {CheckID::Kind::Heuristic, 2},
            Severity::LOW,
            "Version major byte is outside 2-5 range", "", ""});
        return r;
    }
    return CheckResult::ok("Version OK");
}

static void setup_registry() {
    auto& reg = CheckRegistry::instance();
    reg.clear();

    reg.add(RegisteredCheck{
        {CheckID::Kind::Heuristic, 1},
        CheckMeta{"Magic Validation", "ICC.1 §7.2.9", "ICC.1-2022-05",
                  "CWE-20", "", Severity::CRITICAL, CheckPhase::HEADER},
        check_magic
    });

    reg.add(RegisteredCheck{
        {CheckID::Kind::Heuristic, 2},
        CheckMeta{"Version Validation", "ICC.1 §7.2.4", "ICC.1-2022-05",
                  "", "", Severity::LOW, CheckPhase::HEADER},
        check_version
    });
}

static void test_version_string() {
    std::printf("  test_version_string...\n");
    const char* ver = IccTestRunner::version();
    ASSERT_TRUE(ver != nullptr);
    ASSERT_TRUE(std::strstr(ver, "2.0") != nullptr);
}

static void test_check_count() {
    std::printf("  test_check_count...\n");
    // Do NOT call setup_registry() here — we want the auto-registered checks
    // from static initializers (REGISTER_HEURISTIC macros in check .cpp files).
    auto count = CheckRegistry::instance().size();
    std::printf("    Registered checks: %zu\n", count);
    ASSERT_TRUE(count >= 172u);
}

static void test_analyze_minimal_profile() {
    std::printf("  test_analyze_minimal_profile...\n");
    setup_registry();

    // Create a minimal ICC profile buffer
    std::vector<uint8_t> data(256, 0);
    auto* p = data.data();
    p[0] = 0; p[1] = 0; p[2] = 1; p[3] = 0;  // size=256
    p[8] = 0x04; p[9] = 0x40;                   // v4.4
    p[12] = 'm'; p[13] = 'n'; p[14] = 't'; p[15] = 'r';
    p[16] = 'R'; p[17] = 'G'; p[18] = 'B'; p[19] = ' ';
    p[20] = 'X'; p[21] = 'Y'; p[22] = 'Z'; p[23] = ' ';
    p[36] = 'a'; p[37] = 'c'; p[38] = 's'; p[39] = 'p';
    p[128] = 0; p[129] = 0; p[130] = 0; p[131] = 0;  // 0 tags

    IccTestRunner runner;
    auto result = runner.analyze(
        data.data(), data.size());

    // Both checks should have run
    ASSERT_EQ(2, result.stats.checksRun);
    // Magic is valid → H1 OK, version is v4 → H2 OK
    // (Findings depend on library parse success)
    ASSERT_GT(result.stats.checksRun, 0);
}

static void test_analyze_bad_magic() {
    std::printf("  test_analyze_bad_magic...\n");
    setup_registry();

    // Create profile with wrong magic
    std::vector<uint8_t> data(256, 0);
    auto* p = data.data();
    p[0] = 0; p[1] = 0; p[2] = 1; p[3] = 0;
    p[8] = 0x04; p[9] = 0x40;
    p[12] = 'm'; p[13] = 'n'; p[14] = 't'; p[15] = 'r';
    p[36] = 'B'; p[37] = 'A'; p[38] = 'D'; p[39] = '!';  // Wrong magic

    IccTestRunner runner;
    auto result = runner.analyze(data.data(), data.size());

    // H1 should find the bad magic
    ASSERT_TRUE(result.hasCritical());
    ASSERT_GT(result.stats.findingsTotal, 0);
}

static void test_analyze_nonexistent_file() {
    std::printf("  test_analyze_nonexistent_file...\n");
    setup_registry();

    IccTestRunner runner;
    auto result = runner.analyze(
        std::filesystem::path("/nonexistent.icc"));

    // Should get a CRITICAL finding for file open failure
    ASSERT_TRUE(result.hasCritical());
}

static void test_severity_filter() {
    std::printf("  test_severity_filter...\n");
    setup_registry();

    // Profile with bad magic → CRITICAL finding
    std::vector<uint8_t> data(256, 0);
    auto* p = data.data();
    p[0] = 0; p[1] = 0; p[2] = 1; p[3] = 0;
    p[8] = 0x04; p[9] = 0x40;
    p[12] = 'm'; p[13] = 'n'; p[14] = 't'; p[15] = 'r';
    p[36] = 'X'; p[37] = 'X'; p[38] = 'X'; p[39] = 'X';

    AnalysisOptions opts;
    opts.minSeverity = Severity::CRITICAL;

    IccTestRunner runner;
    auto result = runner.analyze(data.data(), data.size(), opts);

    // Only CRITICAL findings should be in results
    for (const auto& f : result.findings) {
        ASSERT_EQ(Severity::CRITICAL, f.level);
    }
}

static void test_analyze_real_profile() {
    std::printf("  test_analyze_real_profile...\n");
    setup_registry();

    std::filesystem::path testProfile("test-profiles/sRGB_D65_MAT.icc");
    if (!std::filesystem::exists(testProfile))
        testProfile = "../test-profiles/sRGB_D65_MAT.icc";
    if (!std::filesystem::exists(testProfile))
        testProfile = "../../test-profiles/sRGB_D65_MAT.icc";
    if (!std::filesystem::exists(testProfile)) {
        std::printf("    (skipped — no test profile found)\n");
        return;
    }

    IccTestRunner runner;
    auto result = runner.analyze(testProfile);

    ASSERT_EQ(2, result.stats.checksRun);
    // sRGB should pass both magic and version checks
    ASSERT_FALSE(result.hasCritical());
    // sRGB is class 'mntr' (Display) = 0x6D6E7472
    ASSERT_EQ(0x6D6E7472u, result.metadata.profileClass);
    ASSERT_GT(result.metadata.fileSize, 128u);
}

static void test_heuristic_coverage() {
    std::printf("  test_heuristic_coverage...\n");
    // Do NOT call setup_registry() — use auto-registered checks.

    auto& reg = CheckRegistry::instance();
    const auto& all = reg.all();

    // Verify every H-number from 1..172 is registered
    std::set<int> registered;
    for (auto& c : all) {
        if (c.id.kind == CheckID::Kind::Heuristic)
            registered.insert(c.id.number);
    }

    int missing = 0;
    for (int h = 1; h <= 172; h++) {
        if (registered.find(h) == registered.end()) {
            std::printf("    MISSING: H%d\n", h);
            missing++;
        }
    }
    ASSERT_EQ(0, missing);
    std::printf("    All 172 heuristic IDs present\n");
}

void test_runner() {
    std::printf("test_runner:\n");
    test_version_string();
    // Run auto-registration tests FIRST (before setup_registry clears them)
    test_check_count();
    test_heuristic_coverage();
    // Analysis tests use setup_registry() which clears auto-registrations
    test_analyze_minimal_profile();
    test_analyze_bad_magic();
    test_analyze_nonexistent_file();
    test_severity_filter();
    test_analyze_real_profile();
    std::printf("  [OK]\n\n");

    // Clean up registry
    CheckRegistry::instance().clear();
}
