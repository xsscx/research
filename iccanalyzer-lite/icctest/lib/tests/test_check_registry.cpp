/*
 * IccTest Library — test_check_registry.cpp
 * Tests for CheckRegistry and self-registration.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "icctest/ProfileView.h"
#include <cstdio>

extern void test_assert(bool, const char*, const char*, int);
#define ASSERT(cond)       test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_EQ(a, b)    test_assert((a) == (b), #a " == " #b, __FILE__, __LINE__)
#define ASSERT_TRUE(cond)  test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_FALSE(cond) test_assert(!(cond), "!" #cond, __FILE__, __LINE__)
#define ASSERT_GT(a, b)    test_assert((a) > (b), #a " > " #b, __FILE__, __LINE__)

using namespace icctest;

// Example check function for registration test
static CheckResult dummy_header_check(const ProfileView& pv) {
    if (pv.header().magic != 0x61637370) {
        CheckResult r;
        r.status = CheckResult::Status::FINDINGS;
        r.summary = "Bad magic";
        r.findings.push_back(Finding{
            {CheckID::Kind::Heuristic, 999},
            Severity::CRITICAL,
            "Magic is not 'acsp'", "", "CWE-20"});
        return r;
    }
    return CheckResult::ok("Magic valid");
}

static CheckResult dummy_conformance_check(const ProfileView& pv) {
    (void)pv;
    return CheckResult::ok("Conformance OK");
}

static void test_manual_registration() {
    std::printf("  test_manual_registration...\n");
    auto& reg = CheckRegistry::instance();
    reg.clear();

    reg.add(RegisteredCheck{
        {CheckID::Kind::Heuristic, 999},
        CheckMeta{
            "Dummy Header Check",
            "ICC.1 §7.2.9",
            "ICC.1-2022-05",
            "CWE-20", "",
            Severity::CRITICAL,
            CheckPhase::HEADER
        },
        dummy_header_check
    });

    reg.add(RegisteredCheck{
        {CheckID::Kind::Conformance, 999},
        CheckMeta{
            "Dummy Conformance",
            "ICC.1 §7.2",
            "ICC.1-2022-05",
            "", "",
            Severity::MEDIUM,
            CheckPhase::CONFORMANCE
        },
        dummy_conformance_check
    });

    ASSERT_EQ(2u, reg.size());

    auto* found = reg.find({CheckID::Kind::Heuristic, 999});
    ASSERT_TRUE(found != nullptr);
    if (found) {
        ASSERT_EQ(std::string("Dummy Header Check"),
                  std::string(found->meta.name));
    }

    auto* cf = reg.find({CheckID::Kind::Conformance, 999});
    ASSERT_TRUE(cf != nullptr);
}

static void test_phase_lookup() {
    std::printf("  test_phase_lookup...\n");
    auto& reg = CheckRegistry::instance();
    // Uses the checks registered in test_manual_registration

    auto headerChecks = reg.byPhase(CheckPhase::HEADER);
    ASSERT_EQ(1u, headerChecks.size());

    auto conformanceChecks = reg.byPhase(CheckPhase::CONFORMANCE);
    ASSERT_EQ(1u, conformanceChecks.size());

    auto rawChecks = reg.byPhase(CheckPhase::RAW_SCAN);
    ASSERT_EQ(0u, rawChecks.size());
}

static void test_kind_lookup() {
    std::printf("  test_kind_lookup...\n");
    auto& reg = CheckRegistry::instance();

    auto heuristics = reg.byKind(CheckID::Kind::Heuristic);
    ASSERT_EQ(1u, heuristics.size());

    auto conformance = reg.byKind(CheckID::Kind::Conformance);
    ASSERT_EQ(1u, conformance.size());
}

static void test_sort() {
    std::printf("  test_sort...\n");
    auto& reg = CheckRegistry::instance();
    reg.clear();

    // Add in reverse order
    reg.add(RegisteredCheck{
        {CheckID::Kind::Conformance, 42},
        CheckMeta{"CF-042", "", "", "", "", Severity::LOW, CheckPhase::CONFORMANCE},
        dummy_conformance_check
    });
    reg.add(RegisteredCheck{
        {CheckID::Kind::Heuristic, 5},
        CheckMeta{"H5", "", "", "", "", Severity::HIGH, CheckPhase::HEADER},
        dummy_header_check
    });
    reg.add(RegisteredCheck{
        {CheckID::Kind::Heuristic, 1},
        CheckMeta{"H1", "", "", "", "", Severity::HIGH, CheckPhase::HEADER},
        dummy_header_check
    });

    reg.sort();
    const auto& all = reg.all();
    ASSERT_EQ(3u, all.size());
    // Heuristic < Conformance, and within kind by number
    ASSERT_EQ(CheckID::Kind::Heuristic, all[0].id.kind);
    ASSERT_EQ(1, all[0].id.number);
    ASSERT_EQ(CheckID::Kind::Heuristic, all[1].id.kind);
    ASSERT_EQ(5, all[1].id.number);
    ASSERT_EQ(CheckID::Kind::Conformance, all[2].id.kind);
    ASSERT_EQ(42, all[2].id.number);
}

static void test_clear() {
    std::printf("  test_clear...\n");
    auto& reg = CheckRegistry::instance();
    reg.clear();
    ASSERT_EQ(0u, reg.size());
}

void test_check_registry() {
    std::printf("test_check_registry:\n");
    test_manual_registration();
    test_phase_lookup();
    test_kind_lookup();
    test_sort();
    test_clear();
    std::printf("  [OK]\n\n");
}
