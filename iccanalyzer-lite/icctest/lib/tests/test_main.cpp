/*
 * IccTest Library — test_main.cpp
 * Minimal test harness (no external framework dependency).
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

// Simple test infrastructure — no Catch2/gtest dependency
struct TestStats {
    int passed = 0;
    int failed = 0;
    int total  = 0;
};

static TestStats g_stats;

void test_assert(bool condition, const char* expr,
                 const char* file, int line) {
    g_stats.total++;
    if (condition) {
        g_stats.passed++;
    } else {
        g_stats.failed++;
        std::fprintf(stderr, "FAIL: %s:%d: %s\n", file, line, expr);
    }
}

#define ASSERT(cond) test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_EQ(a, b) test_assert((a) == (b), #a " == " #b, __FILE__, __LINE__)
#define ASSERT_NE(a, b) test_assert((a) != (b), #a " != " #b, __FILE__, __LINE__)
#define ASSERT_GT(a, b) test_assert((a) > (b), #a " > " #b, __FILE__, __LINE__)
#define ASSERT_GE(a, b) test_assert((a) >= (b), #a " >= " #b, __FILE__, __LINE__)
#define ASSERT_TRUE(cond) test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_FALSE(cond) test_assert(!(cond), "!" #cond, __FILE__, __LINE__)

// Test functions (defined in other files)
extern void test_check_result();
extern void test_profile_view();
extern void test_check_registry();
extern void test_logger();
extern void test_runner();

int main(int argc, char** argv) {
    std::printf("IccTest Library — Unit Tests v2.0.0\n");
    std::printf("====================================\n\n");

    // test_runner must run FIRST — it tests auto-registered checks from
    // REGISTER_HEURISTIC macros. Other tests call clear() which destroys them.
    test_runner();
    test_check_result();
    test_profile_view();
    test_check_registry();
    test_logger();

    std::printf("\n====================================\n");
    std::printf("Results: %d/%d passed", g_stats.passed, g_stats.total);
    if (g_stats.failed > 0)
        std::printf(", %d FAILED", g_stats.failed);
    std::printf("\n");

    return g_stats.failed > 0 ? 1 : 0;
}
