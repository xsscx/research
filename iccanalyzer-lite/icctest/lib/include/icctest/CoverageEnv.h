/*
 * IccTest Library - CoverageEnv.h
 * Helpers for isolating gcov output across rebuilds and processes.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#ifndef ICCTEST_COVERAGE_ENV_H
#define ICCTEST_COVERAGE_ENV_H

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>

namespace icctest {

inline void configureUniqueCoverageOutput(const char* bucket) {
#if defined(__clang__)
    if (!bucket || !bucket[0] || std::getenv("GCOV_PREFIX")) {
        return;
    }

    std::filesystem::path prefix = std::filesystem::temp_directory_path();
    prefix /= bucket;
    prefix /= std::to_string(
        static_cast<unsigned long long>(
            std::chrono::steady_clock::now().time_since_epoch().count()));

    std::error_code ec;
    std::filesystem::create_directories(prefix, ec);

    const std::string prefixStr = prefix.string();
    setenv("GCOV_PREFIX", prefixStr.c_str(), 0);
    setenv("GCOV_PREFIX_STRIP", "0", 0);
#else
    (void)bucket;
#endif
}

} // namespace icctest

#endif // ICCTEST_COVERAGE_ENV_H
