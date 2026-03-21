/*
 * IccTest Library — test_logger.cpp
 * Tests for Logger and LogSink hierarchy.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/Logger.h"
#include <cstdio>
#include <cstring>

extern void test_assert(bool, const char*, const char*, int);
#define ASSERT(cond)       test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_EQ(a, b)    test_assert((a) == (b), #a " == " #b, __FILE__, __LINE__)
#define ASSERT_TRUE(cond)  test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_FALSE(cond) test_assert(!(cond), "!" #cond, __FILE__, __LINE__)
#define ASSERT_GT(a, b)    test_assert((a) > (b), #a " > " #b, __FILE__, __LINE__)

using namespace icctest;

static void test_memory_sink_capture() {
    std::printf("  test_memory_sink_capture...\n");

    auto sink = std::make_unique<MemorySink>();
    auto* sinkPtr = sink.get();

    auto& logger = Logger::instance();
    logger.setLevel(LogLevel::kDebug);
    logger.setSink(std::move(sink));

    logger.info("Hello %s %d", "world", 42);
    logger.debug("Debug message");
    logger.warn("Warning: %d issues", 3);

    ASSERT_EQ(3u, sinkPtr->entries().size());
    ASSERT_EQ(LogLevel::kInfo, sinkPtr->entries()[0].level);
    ASSERT_TRUE(sinkPtr->entries()[0].message.find("Hello world 42")
                != std::string::npos);
    ASSERT_EQ(LogLevel::kWarn, sinkPtr->entries()[2].level);

    // Reset
    logger.setLevel(LogLevel::kNone);
    logger.setSink(nullptr);
}

static void test_level_filtering() {
    std::printf("  test_level_filtering...\n");

    auto sink = std::make_unique<MemorySink>();
    auto* sinkPtr = sink.get();

    auto& logger = Logger::instance();
    logger.setLevel(LogLevel::kWarn);
    logger.setSink(std::move(sink));

    logger.trace("trace");   // filtered
    logger.debug("debug");   // filtered
    logger.info("info");     // filtered
    logger.warn("warn");     // captured
    logger.error("error");   // captured

    ASSERT_EQ(2u, sinkPtr->entries().size());
    ASSERT_EQ(LogLevel::kWarn, sinkPtr->entries()[0].level);
    ASSERT_EQ(LogLevel::kError, sinkPtr->entries()[1].level);

    // Reset
    logger.setLevel(LogLevel::kNone);
    logger.setSink(nullptr);
}

static void test_none_level() {
    std::printf("  test_none_level...\n");

    auto sink = std::make_unique<MemorySink>();
    auto* sinkPtr = sink.get();

    auto& logger = Logger::instance();
    logger.setLevel(LogLevel::kNone);
    logger.setSink(std::move(sink));

    logger.error("This should not appear");
    ASSERT_EQ(0u, sinkPtr->entries().size());

    logger.setSink(nullptr);
}

static void test_format_string() {
    std::printf("  test_format_string...\n");

    auto sink = std::make_unique<MemorySink>();
    auto* sinkPtr = sink.get();

    auto& logger = Logger::instance();
    logger.setLevel(LogLevel::kTrace);
    logger.setSink(std::move(sink));

    logger.info("int=%d float=%.2f str=%s", 42, 3.14, "test");

    ASSERT_EQ(1u, sinkPtr->entries().size());
    ASSERT_TRUE(sinkPtr->entries()[0].message.find("int=42") != std::string::npos);
    ASSERT_TRUE(sinkPtr->entries()[0].message.find("float=3.14") != std::string::npos);
    ASSERT_TRUE(sinkPtr->entries()[0].message.find("str=test") != std::string::npos);

    logger.setLevel(LogLevel::kNone);
    logger.setSink(nullptr);
}

void test_logger() {
    std::printf("test_logger:\n");
    test_memory_sink_capture();
    test_level_filtering();
    test_none_level();
    test_format_string();
    std::printf("  [OK]\n\n");
}
