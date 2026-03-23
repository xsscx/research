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

static std::filesystem::path resolve_repo_file(const char* relativePath) {
    std::filesystem::path base = std::filesystem::path(__FILE__).parent_path();
    auto candidate = (base / "../../../" / relativePath).lexically_normal();
    if (std::filesystem::exists(candidate)) return candidate;

    candidate = (std::filesystem::current_path() / relativePath).lexically_normal();
    if (std::filesystem::exists(candidate)) return candidate;

    return {};
}

static const PerCheckResult* find_per_check(const AnalysisResult& result,
                                            CheckID::Kind kind,
                                            int number) {
    for (const auto& entry : result.perCheck) {
        if (entry.id.kind == kind && entry.id.number == number) {
            return &entry;
        }
    }
    return nullptr;
}

static AnalysisResult analyze_corpus_checks(const std::filesystem::path& profilePath,
                                            const std::vector<int>& checks) {
    AnalysisOptions opts;
    opts.phases = {CheckPhase::CONFORMANCE};
    opts.skipLibraryOnUB = false;
    for (int check : checks) {
        opts.specificChecks.push_back({CheckID::Kind::Conformance, check});
    }

    IccTestRunner runner;
    return runner.analyze(profilePath, opts);
}

static AnalysisResult analyze_corpus_heuristics(const std::filesystem::path& profilePath,
                                                const std::vector<int>& checks) {
    AnalysisOptions opts;
    opts.phases = {
        CheckPhase::HEADER,
        CheckPhase::TAG_TABLE,
        CheckPhase::RAW_SCAN,
        CheckPhase::LIBRARY,
    };
    opts.skipLibraryOnUB = false;
    for (int check : checks) {
        opts.specificChecks.push_back({CheckID::Kind::Heuristic, check});
    }

    IccTestRunner runner;
    return runner.analyze(profilePath, opts);
}

static AnalysisResult analyze_image_checks(const std::filesystem::path& imagePath,
                                           const std::vector<int>& checks) {
    AnalysisOptions opts;
    opts.phases = {CheckPhase::IMAGE};
    for (int check : checks) {
        opts.specificChecks.push_back({CheckID::Kind::Heuristic, check});
    }

    IccTestRunner runner;
    return runner.analyze(imagePath, opts);
}

static void expect_conformance_result(const AnalysisResult& result,
                                      int number,
                                      CheckResult::Status status,
                                      int issueCount) {
    const auto* check = find_per_check(result, CheckID::Kind::Conformance, number);
    ASSERT_TRUE(check != nullptr);
    ASSERT_EQ(status, check->result.status);
    ASSERT_EQ(issueCount, check->result.issueCount());
}

static void expect_heuristic_result(const AnalysisResult& result,
                                    int number,
                                    CheckResult::Status status,
                                    int issueCount) {
    const auto* check = find_per_check(result, CheckID::Kind::Heuristic, number);
    ASSERT_TRUE(check != nullptr);
    ASSERT_EQ(status, check->result.status);
    ASSERT_EQ(issueCount, check->result.issueCount());
}

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
    ASSERT_TRUE(count >= 502u);  // 173 heuristics + 329 conformance
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
    ASSERT_EQ(2u, result.perCheck.size());
    ASSERT_EQ(CheckID::Kind::Heuristic, result.perCheck[0].id.kind);
    ASSERT_EQ(1, result.perCheck[0].id.number);
    ASSERT_EQ(std::string("Magic Validation"),
              std::string(result.perCheck[0].meta.name));
    ASSERT_EQ(CheckResult::Status::FINDINGS, result.perCheck[0].result.status);
    ASSERT_EQ(1, result.perCheck[0].result.issueCount());
    ASSERT_EQ(std::string("Magic is not 'acsp'"),
              result.perCheck[0].result.findings[0].message);
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

    // Verify every H-number from 1..173 is registered
    std::set<int> registered;
    for (auto& c : all) {
        if (c.id.kind == CheckID::Kind::Heuristic)
            registered.insert(c.id.number);
    }

    int missing = 0;
    for (int h = 1; h <= 173; h++) {
        if (registered.find(h) == registered.end()) {
            std::printf("    MISSING: H%d\n", h);
            missing++;
        }
    }
    ASSERT_EQ(0, missing);
    std::printf("    All 173 heuristic IDs present\n");
}

static void test_conformance_coverage() {
    std::printf("  test_conformance_coverage...\n");
    // Do NOT call setup_registry() — use auto-registered checks.

    auto& reg = CheckRegistry::instance();
    const auto& all = reg.all();

    // Collect all registered conformance CF numbers
    std::set<int> registered;
    for (auto& c : all) {
        if (c.id.kind == CheckID::Kind::Conformance)
            registered.insert(c.id.number);
    }

    // All 329 CF IDs are registered (CF-001..CF-329, complete range)
    int missing = 0;
    for (int cf = 1; cf <= 329; cf++) {
        if (registered.find(cf) == registered.end()) {
            std::printf("    MISSING: CF-%03d\n", cf);
            missing++;
        }
    }

    std::printf("    Registered conformance checks: %zu\n", registered.size());
    ASSERT_EQ(0, missing);
    std::printf("    All 329 conformance IDs present\n");
}

static void test_conformance_private_tag_documentation_regression() {
    std::printf("  test_conformance_private_tag_documentation_regression...\n");

    auto corpusPath = resolve_repo_file("tests/corpus/private_tags.icc");
    if (corpusPath.empty()) {
        std::printf("    (skipped — private_tags.icc not found)\n");
        return;
    }

    AnalysisOptions opts;
    opts.phases = {CheckPhase::CONFORMANCE};
    opts.specificChecks = {{CheckID::Kind::Conformance, 97}};

    IccTestRunner runner;
    auto result = runner.analyze(corpusPath, opts);

    ASSERT_EQ(1, result.stats.checksRun);
    const auto* cf97 = find_per_check(result, CheckID::Kind::Conformance, 97);
    ASSERT_TRUE(cf97 != nullptr);
    ASSERT_EQ(CheckResult::Status::FINDINGS, cf97->result.status);
    ASSERT_EQ(2, cf97->result.issueCount());
    ASSERT_TRUE(cf97->result.findings[0].message.find("Undocumented private tag") != std::string::npos);
}

static void test_conformance_adgc_regression() {
    std::printf("  test_conformance_adgc_regression...\n");

    auto corpusPath = resolve_repo_file("tests/corpus/cf_adgc_bad_curve_range.icc");
    if (corpusPath.empty()) {
        std::printf("    (skipped — cf_adgc_bad_curve_range.icc not found)\n");
        return;
    }

    AnalysisOptions opts;
    opts.phases = {CheckPhase::CONFORMANCE};
    opts.specificChecks = {
        {CheckID::Kind::Conformance, 128},
        {CheckID::Kind::Conformance, 134},
        {CheckID::Kind::Conformance, 135},
    };

    IccTestRunner runner;
    auto result = runner.analyze(corpusPath, opts);

    ASSERT_EQ(3, result.stats.checksRun);

    const auto* cf128 = find_per_check(result, CheckID::Kind::Conformance, 128);
    const auto* cf134 = find_per_check(result, CheckID::Kind::Conformance, 134);
    const auto* cf135 = find_per_check(result, CheckID::Kind::Conformance, 135);

    ASSERT_TRUE(cf128 != nullptr);
    ASSERT_TRUE(cf134 != nullptr);
    ASSERT_TRUE(cf135 != nullptr);

    ASSERT_EQ(CheckResult::Status::OK, cf128->result.status);
    ASSERT_EQ(CheckResult::Status::OK, cf134->result.status);
    ASSERT_EQ(CheckResult::Status::FINDINGS, cf135->result.status);
    ASSERT_EQ(0, cf128->result.issueCount());
    ASSERT_EQ(0, cf134->result.issueCount());
    ASSERT_EQ(6, cf135->result.issueCount());
    ASSERT_EQ(6, result.stats.findingsTotal);
}

static void test_sampleicc_legibility_regression() {
    std::printf("  test_sampleicc_legibility_regression...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "valid_srgb.icc", {188, 189, 190});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_conformance_result(result, 188, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 189, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 190, CheckResult::Status::OK, 0);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "zero_tags.icc", {190});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 190, CheckResult::Status::FINDINGS, 1);

        const auto* cf190 = find_per_check(result, CheckID::Kind::Conformance, 190);
        ASSERT_TRUE(cf190 != nullptr);
        ASSERT_TRUE(cf190->result.summary.find("Legibility") != std::string::npos);
        ASSERT_TRUE(cf190->result.findings[0].message.find("0 tags") != std::string::npos);
    }
}

static void test_conformance_parity_regressions() {
    std::printf("  test_conformance_parity_regressions...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_mluc_bad_record_size.icc", {30});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 30, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_mluc_zero_name_placeholder.icc", {223});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 223, CheckResult::Status::FINDINGS, 1);

        const auto* cf223 = find_per_check(result, CheckID::Kind::Conformance, 223);
        ASSERT_TRUE(cf223 != nullptr);
        ASSERT_TRUE(cf223->result.findings[0].message.find("12-byte") != std::string::npos);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_reserved_bytes_nonzero_tag.icc", {224});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 224, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "odd_utf16_mluc.icc", {225});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 225, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "valid_srgb.icc", {223, 224, 225, 226});
        ASSERT_EQ(4, result.stats.checksRun);
        expect_conformance_result(result, 223, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 224, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 225, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 226, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_adgc_nan_weights.icc", {123, 128});
        ASSERT_EQ(2, result.stats.checksRun);
        expect_conformance_result(result, 123, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 128, CheckResult::Status::SKIP, 0);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_devicelink_no_atob.icc", {221});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 221, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "calc_trunc_operator.icc", {229});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 229, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf143-meas-valid.icc", {33, 34, 302});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_conformance_result(result, 33, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 34, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 302, CheckResult::Status::FINDINGS, 5);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf137-mdv-invalid-type.icc", {303});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 303, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_htos_bad_type.icc", {319});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 319, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "xyz_out_of_range.icc", {112, 170, 172, 273, 280});
        ASSERT_EQ(5, result.stats.checksRun);
        expect_conformance_result(result, 112, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 170, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 172, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 273, CheckResult::Status::FINDINGS, 2);
        expect_conformance_result(result, 280, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_sf32_bad_size.icc", {278});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 278, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_adgc_cmyk_violation.icc", {123});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 123, CheckResult::Status::FINDINGS, 2);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "named_color2_excessive_coords.icc", {28});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 28, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "wrong_d50_illuminant.icc", {8});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 8, CheckResult::Status::FINDINGS, 3);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "zero_tags.icc", {93});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 93, CheckResult::Status::OK, 0);
    }
}

static void test_embedding_tech_note_regressions() {
    std::printf("  test_embedding_tech_note_regressions...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_checks(
            corpusDir / "cf_embedded_clean.icc",
            {153, 154, 155, 156, 157, 158, 175, 176, 177});
        ASSERT_EQ(9, result.stats.checksRun);
        expect_conformance_result(result, 153, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 154, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 155, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 156, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 157, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 158, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 175, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 176, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 177, CheckResult::Status::OK, 0);

        const auto* cf154 = find_per_check(result, CheckID::Kind::Conformance, 154);
        ASSERT_TRUE(cf154 != nullptr);
        ASSERT_TRUE(cf154->result.findings[0].message.find("already v5") != std::string::npos);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_wrong_type.icc", {153, 154, 157, 158, 187});
        ASSERT_EQ(5, result.stats.checksRun);
        expect_conformance_result(result, 153, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 154, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 157, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 158, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 187, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_child_class_mismatch.icc", {155});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 155, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf_embedded_child_class_mismatch.icc", {96});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 96, CheckResult::Status::FINDINGS, 1);
        const auto* h96 = find_per_check(result, CheckID::Kind::Heuristic, 96);
        ASSERT_TRUE(h96 != nullptr);
        ASSERT_TRUE(h96->result.findings[0].message.find("CIccEmbedIO constructor sentinel UB") != std::string::npos);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf_embedded_wrong_type.icc", {96});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 96, CheckResult::Status::FINDINGS, 1);
        const auto* h96 = find_per_check(result, CheckID::Kind::Heuristic, 96);
        ASSERT_TRUE(h96 != nullptr);
        ASSERT_TRUE(h96->result.findings[0].message.find("wrong runtime type") != std::string::npos);
    }

    {
        AnalysisOptions opts;
        opts.phases = {CheckPhase::RAW_SCAN, CheckPhase::LIBRARY, CheckPhase::CONFORMANCE};
        opts.specificChecks = {
            {CheckID::Kind::Heuristic, 96},
            {CheckID::Kind::Conformance, 155},
        };

        IccTestRunner runner;
        auto result = runner.analyze(corpusDir / "cf_embedded_child_class_mismatch.icc", opts);

        const auto* h96 = find_per_check(result, CheckID::Kind::Heuristic, 96);
        ASSERT_TRUE(h96 != nullptr);
        ASSERT_EQ(CheckResult::Status::FINDINGS, h96->result.status);
        ASSERT_TRUE(h96->result.findings[0].message.find("CIccEmbedIO constructor sentinel UB") != std::string::npos);
        ASSERT_TRUE(find_per_check(result, CheckID::Kind::Conformance, 155) == nullptr);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {173});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 173, CheckResult::Status::FINDINGS, 1);
        const auto* h173 = find_per_check(result, CheckID::Kind::Heuristic, 173);
        ASSERT_TRUE(h173 != nullptr);
        ASSERT_TRUE(h173->result.findings[0].message.find("IccUtil.cpp:1088,1130") != std::string::npos);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_child_flags_bad.icc", {156});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 156, CheckResult::Status::FINDINGS, 2);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_child_pcs_mismatch.icc", {175});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 175, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_reserved_nonzero.icc", {176});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 176, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_devicelink_flagged.icc", {214});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 214, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "valid_srgb.icc", {214, 215, 216, 217, 218, 219});
        ASSERT_EQ(6, result.stats.checksRun);
        expect_conformance_result(result, 214, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 215, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 216, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 217, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 218, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 219, CheckResult::Status::OK, 0);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "v5_spac_basic.icc", {216, 217, 218, 219});
        ASSERT_EQ(4, result.stats.checksRun);
        expect_conformance_result(result, 216, CheckResult::Status::SKIP, 0);
        expect_conformance_result(result, 217, CheckResult::Status::SKIP, 0);
        expect_conformance_result(result, 218, CheckResult::Status::SKIP, 0);
        expect_conformance_result(result, 219, CheckResult::Status::SKIP, 0);
    }
}

static void test_heuristic_parity_regressions() {
    std::printf("  test_heuristic_parity_regressions...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "calc_trunc_operator.icc", {151});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 151, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "reserved_bytes_nonzero.icc", {111, 142});
        ASSERT_EQ(2, result.stats.checksRun);
        expect_heuristic_result(result, 111, CheckResult::Status::FINDINGS, 1);
        expect_heuristic_result(result, 142, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "bad_magic.icc", {111, 142, 164});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_heuristic_result(result, 111, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 142, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 164, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf137-mdv-invalid-type.icc", {15, 153});
        ASSERT_EQ(2, result.stats.checksRun);
        expect_heuristic_result(result, 15, CheckResult::Status::FINDINGS, 3);
        expect_heuristic_result(result, 153, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "named_color2_large_nsize.icc", {154, 155});
        ASSERT_EQ(2, result.stats.checksRun);
        expect_heuristic_result(result, 154, CheckResult::Status::FINDINGS, 1);
        expect_heuristic_result(result, 155, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "just_header.icc", {154, 155, 156, 158, 162, 163});
        ASSERT_EQ(6, result.stats.checksRun);
        expect_heuristic_result(result, 154, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 155, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 156, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 158, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 162, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 163, CheckResult::Status::SKIP, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "invalid_rendering_intent.icc", {158});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 158, CheckResult::Status::OK, 0);
    }
}

static void test_conformance_v5_only_skip_regression() {
    std::printf("  test_conformance_v5_only_skip_regression...\n");

    auto corpusPath = resolve_repo_file("tests/corpus/bad_wtpt.icc");
    if (corpusPath.empty()) {
        std::printf("    (skipped — bad_wtpt.icc not found)\n");
        return;
    }

    auto result = analyze_corpus_checks(corpusPath, {157, 158, 159, 160, 161, 162, 180, 181, 295});
    ASSERT_EQ(9, result.stats.checksRun);
    expect_conformance_result(result, 157, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 158, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 159, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 160, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 161, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 162, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 180, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 181, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 295, CheckResult::Status::SKIP, 0);
}

static void test_conformance_v5_gate_regression() {
    std::printf("  test_conformance_v5_gate_regression...\n");

    auto reservedBytesPath = resolve_repo_file("tests/corpus/reserved_bytes_nonzero.icc");
    if (reservedBytesPath.empty()) {
        std::printf("    (skipped — reserved_bytes_nonzero.icc not found)\n");
        return;
    }

    auto spectralResult = analyze_corpus_checks(reservedBytesPath, {113, 114, 257});
    ASSERT_EQ(3, spectralResult.stats.checksRun);
    expect_conformance_result(spectralResult, 113, CheckResult::Status::SKIP, 0);
    expect_conformance_result(spectralResult, 114, CheckResult::Status::SKIP, 0);
    expect_conformance_result(spectralResult, 257, CheckResult::Status::SKIP, 0);

    auto flagsPath = resolve_repo_file("tests/corpus/flags_reserved_bits.icc");
    if (flagsPath.empty()) {
        std::printf("    (skipped — flags_reserved_bits.icc not found)\n");
        return;
    }

    auto extendedRangeResult = analyze_corpus_checks(flagsPath, {147});
    ASSERT_EQ(1, extendedRangeResult.stats.checksRun);
    expect_conformance_result(extendedRangeResult, 147, CheckResult::Status::SKIP, 0);
}

static void test_conformance_adgc_skip_regression() {
    std::printf("  test_conformance_adgc_skip_regression...\n");

    auto corpusPath = resolve_repo_file("tests/corpus/bad_wtpt.icc");
    if (corpusPath.empty()) {
        std::printf("    (skipped — bad_wtpt.icc not found)\n");
        return;
    }

    auto result = analyze_corpus_checks(corpusPath, {133, 134, 135, 136});
    ASSERT_EQ(4, result.stats.checksRun);
    expect_conformance_result(result, 133, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 134, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 135, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 136, CheckResult::Status::SKIP, 0);

    const auto* cf133 = find_per_check(result, CheckID::Kind::Conformance, 133);
    ASSERT_TRUE(cf133 != nullptr);
    ASSERT_EQ(std::string("No ADGC tag or read failed"), cf133->result.summary);
}

static void test_image_tiff_with_embedded_icc_regression() {
    std::printf("  test_image_tiff_with_embedded_icc_regression...\n");

    auto imagePath = resolve_repo_file("tests/corpus/test_tiff_with_icc.tif");
    if (imagePath.empty()) {
        std::printf("    (skipped — test_tiff_with_icc.tif not found)\n");
        return;
    }

    auto result = analyze_image_checks(imagePath, {139, 140, 141, 149, 150});
    ASSERT_EQ(5, result.stats.checksRun);
    expect_heuristic_result(result, 139, CheckResult::Status::OK, 0);
    expect_heuristic_result(result, 140, CheckResult::Status::OK, 0);
    expect_heuristic_result(result, 141, CheckResult::Status::OK, 0);
    expect_heuristic_result(result, 149, CheckResult::Status::OK, 0);
    expect_heuristic_result(result, 150, CheckResult::Status::OK, 0);

    const auto* h150 = find_per_check(result, CheckID::Kind::Heuristic, 150);
    ASSERT_TRUE(h150 != nullptr);
    ASSERT_EQ(std::string("Strip-based image - tile geometry N/A"), h150->result.summary);
}

static void test_image_truncated_tiff_regression() {
    std::printf("  test_image_truncated_tiff_regression...\n");

    auto imagePath = resolve_repo_file("tests/corpus/corrupt_truncated.tif");
    if (imagePath.empty()) {
        std::printf("    (skipped — corrupt_truncated.tif not found)\n");
        return;
    }

    auto result = analyze_image_checks(imagePath, {139, 140, 141, 149, 150});
    ASSERT_EQ(5, result.stats.checksRun);
    expect_heuristic_result(result, 139, CheckResult::Status::SKIP, 0);
    expect_heuristic_result(result, 140, CheckResult::Status::SKIP, 0);
    expect_heuristic_result(result, 141, CheckResult::Status::SKIP, 0);
    expect_heuristic_result(result, 149, CheckResult::Status::OK, 0);
    expect_heuristic_result(result, 150, CheckResult::Status::SKIP, 0);
}

void test_runner() {
    std::printf("test_runner:\n");
    test_version_string();
    // Run auto-registration tests FIRST (before setup_registry clears them)
    test_check_count();
    test_heuristic_coverage();
    test_conformance_coverage();
    test_conformance_private_tag_documentation_regression();
    test_conformance_adgc_regression();
    test_sampleicc_legibility_regression();
    test_conformance_parity_regressions();
    test_embedding_tech_note_regressions();
    test_conformance_v5_only_skip_regression();
    test_conformance_v5_gate_regression();
    test_conformance_adgc_skip_regression();
    test_heuristic_parity_regressions();
    test_image_tiff_with_embedded_icc_regression();
    test_image_truncated_tiff_regression();
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
