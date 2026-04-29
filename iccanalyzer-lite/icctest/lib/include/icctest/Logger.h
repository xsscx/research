/*
 * IccTest Library — Logger.h
 * Structured logging for diagnostics (NOT analysis output).
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 *
 * The Logger is for internal diagnostics: "opening file X", "tag parse failed",
 * "UB pattern detected". It is NOT for check findings (those go into CheckResult).
 * This is the only global singleton in the library — it is optional, and
 * defaults to silent (no output) if no sink is configured.
 */

#ifndef ICCTEST_LOGGER_H
#define ICCTEST_LOGGER_H

#include <cstdarg>
#include <cstdio>
#include <memory>
#include <vector>
#include <string>
#include <mutex>

namespace icctest {

// Values named to avoid collision with common macros (-DDEBUG, windows ERROR)
enum class LogLevel : uint8_t {
    kTrace = 0,
    kDebug = 1,
    kInfo  = 2,
    kWarn  = 3,
    kError = 4,
    kNone  = 5,  // Disables all logging
};

/// Abstract log sink. Implement this to redirect log output.
class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void write(LogLevel level, const char* msg) = 0;
};

/// Writes to stderr. Thread-safe via internal mutex.
class StderrSink : public LogSink {
public:
    void write(LogLevel level, const char* msg) override;
};

/// Collects log messages into a vector (for testing).
class MemorySink : public LogSink {
public:
    struct Entry {
        LogLevel    level;
        std::string message;
    };

    void write(LogLevel level, const char* msg) override;
    const std::vector<Entry>& entries() const { return m_entries; }
    void clear() { m_entries.clear(); }

private:
    std::vector<Entry> m_entries;
};

/// Global logger. Defaults to NONE level (silent).
class Logger {
public:
    static Logger& instance();

    void setLevel(LogLevel lvl) { m_level = lvl; }
    LogLevel getLevel() const { return m_level; }

    void setSink(std::unique_ptr<LogSink> sink) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_sink = std::move(sink);
    }

    /// Log a message at the given level. No-op if below current level.
    void log(LogLevel level, const char* fmt, ...)
        __attribute__((format(printf, 3, 4)));

    // Convenience methods
    void trace(const char* fmt, ...) __attribute__((format(printf, 2, 3)));
    void debug(const char* fmt, ...) __attribute__((format(printf, 2, 3)));
    void info(const char* fmt, ...)  __attribute__((format(printf, 2, 3)));
    void warn(const char* fmt, ...)  __attribute__((format(printf, 2, 3)));
    void error(const char* fmt, ...) __attribute__((format(printf, 2, 3)));

private:
    Logger() = default;
    void vlog(LogLevel level, const char* fmt, va_list args)
        __attribute__((format(printf, 3, 0)));

    LogLevel                   m_level{LogLevel::kNone};
    std::unique_ptr<LogSink>   m_sink;
    std::mutex                 m_mutex;
};

// Shorthand macro that avoids format-string evaluation when level is disabled
#define ICCTEST_LOG(lvl, ...) \
    do { \
        auto& logger_ = ::icctest::Logger::instance(); \
        if (logger_.getLevel() <= (lvl)) \
            logger_.log((lvl), __VA_ARGS__); \
    } while (0)

#define ICCTEST_TRACE(...) ICCTEST_LOG(::icctest::LogLevel::kTrace, __VA_ARGS__)
#define ICCTEST_DEBUG(...) ICCTEST_LOG(::icctest::LogLevel::kDebug, __VA_ARGS__)
#define ICCTEST_INFO(...)  ICCTEST_LOG(::icctest::LogLevel::kInfo,  __VA_ARGS__)
#define ICCTEST_WARN(...)  ICCTEST_LOG(::icctest::LogLevel::kWarn,  __VA_ARGS__)
#define ICCTEST_ERROR(...) ICCTEST_LOG(::icctest::LogLevel::kError, __VA_ARGS__)

} // namespace icctest

#endif // ICCTEST_LOGGER_H
