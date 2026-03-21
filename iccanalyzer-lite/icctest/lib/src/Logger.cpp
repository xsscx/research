/*
 * IccTest Library — Logger.cpp
 * Structured logging implementation.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/Logger.h"

#include <cstdio>
#include <cstring>

namespace icctest {

// ── StderrSink ──

void StderrSink::write(LogLevel level, const char* msg) {
    static const char* levelNames[] = {
        "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "NONE"
    };
    int idx = static_cast<int>(level);
    if (idx < 0 || idx > 4) idx = 4;
    std::fprintf(stderr, "[icctest:%s] %s\n", levelNames[idx], msg);
}

// ── MemorySink ──

void MemorySink::write(LogLevel level, const char* msg) {
    m_entries.push_back({level, std::string(msg)});
}

// ── Logger ──

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

void Logger::vlog(LogLevel level, const char* fmt, va_list args) {
    if (level < m_level) return;

    char buf[1024];
    std::vsnprintf(buf, sizeof(buf), fmt, args);

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_sink) {
        m_sink->write(level, buf);
    }
}

void Logger::log(LogLevel level, const char* fmt, ...) {
    if (level < m_level) return;
    va_list args;
    va_start(args, fmt);
    vlog(level, fmt, args);
    va_end(args);
}

void Logger::trace(const char* fmt, ...) {
    if (LogLevel::kTrace < m_level) return;
    va_list args;
    va_start(args, fmt);
    vlog(LogLevel::kTrace, fmt, args);
    va_end(args);
}

void Logger::debug(const char* fmt, ...) {
    if (LogLevel::kDebug < m_level) return;
    va_list args;
    va_start(args, fmt);
    vlog(LogLevel::kDebug, fmt, args);
    va_end(args);
}

void Logger::info(const char* fmt, ...) {
    if (LogLevel::kInfo < m_level) return;
    va_list args;
    va_start(args, fmt);
    vlog(LogLevel::kInfo, fmt, args);
    va_end(args);
}

void Logger::warn(const char* fmt, ...) {
    if (LogLevel::kWarn < m_level) return;
    va_list args;
    va_start(args, fmt);
    vlog(LogLevel::kWarn, fmt, args);
    va_end(args);
}

void Logger::error(const char* fmt, ...) {
    if (LogLevel::kError < m_level) return;
    va_list args;
    va_start(args, fmt);
    vlog(LogLevel::kError, fmt, args);
    va_end(args);
}

} // namespace icctest
