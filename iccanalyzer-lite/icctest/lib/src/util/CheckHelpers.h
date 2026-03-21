/*
 * IccTest Library — CheckHelpers.h
 * Utility functions for implementing checks.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#ifndef ICCTEST_CHECK_HELPERS_H
#define ICCTEST_CHECK_HELPERS_H

#include "icctest/CheckResult.h"
#include "icctest/ProfileView.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

namespace icctest {

// ── String formatting ──

/// Safe printf-style string formatting (max 2048 chars).
inline std::string sfmt(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
inline std::string sfmt(const char* fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return std::string(fmt);
    return std::string(buf, static_cast<size_t>(n < 2048 ? n : 2047));
}

/// Convert a 4-byte big-endian signature to a printable string.
inline std::string sigStr(uint32_t sig) {
    char buf[5];
    buf[0] = static_cast<char>((sig >> 24) & 0xFF);
    buf[1] = static_cast<char>((sig >> 16) & 0xFF);
    buf[2] = static_cast<char>((sig >>  8) & 0xFF);
    buf[3] = static_cast<char>((sig      ) & 0xFF);
    buf[4] = '\0';
    // Replace non-printable with '?'
    for (int i = 0; i < 4; i++) {
        unsigned char c = static_cast<unsigned char>(buf[i]);
        if (c < 0x20 || c > 0x7E) buf[i] = '?';
    }
    return std::string(buf);
}

// ── Finding construction helpers ──

/// Create a Finding with level + message.
inline Finding makeFinding(Severity level, std::string message) {
    return Finding{{}, level, std::move(message), {}, {}};
}

/// Create a Finding with level + message + CWE note.
inline Finding makeFinding(Severity level, std::string message, std::string cweNote) {
    return Finding{{}, level, std::move(message), {}, std::move(cweNote)};
}

/// Create a Finding with level + message + detail + CWE note.
inline Finding makeFindingFull(Severity level, std::string message,
                                std::string detail, std::string cweNote) {
    return Finding{{}, level, std::move(message), std::move(detail), std::move(cweNote)};
}

// ── Raw byte reading (big-endian) ──

inline uint32_t readU32BE(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
}

inline uint16_t readU16BE(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

inline int32_t readS32BE(const uint8_t* p) {
    return static_cast<int32_t>(readU32BE(p));
}

/// Read s15Fixed16Number as double.
inline double readS15Fixed16(const uint8_t* p) {
    int32_t raw = readS32BE(p);
    return raw / 65536.0;
}

// ── Signature constants ──

constexpr uint32_t kIccMagic = 0x61637370; // 'acsp'

// Profile classes
constexpr uint32_t kClassInput       = 0x73636E72; // 'scnr'
constexpr uint32_t kClassDisplay     = 0x6D6E7472; // 'mntr'
constexpr uint32_t kClassOutput      = 0x70727472; // 'prtr'
constexpr uint32_t kClassLink        = 0x6C696E6B; // 'link'
constexpr uint32_t kClassColorSpace  = 0x73706163; // 'spac'
constexpr uint32_t kClassAbstract    = 0x61627374; // 'abst'
constexpr uint32_t kClassNamedColor  = 0x6E6D636C; // 'nmcl'

// Common tag signatures
constexpr uint32_t kSigDesc   = 0x64657363; // 'desc'
constexpr uint32_t kSigWtpt   = 0x77747074; // 'wtpt'
constexpr uint32_t kSigCprt   = 0x63707274; // 'cprt'
constexpr uint32_t kSigChad   = 0x63686164; // 'chad'
constexpr uint32_t kSigAToB0  = 0x41324230; // 'A2B0'
constexpr uint32_t kSigBToA0  = 0x42324130; // 'B2A0'

// D50 illuminant values (s15Fixed16)
constexpr int32_t kD50X = 0x0000F6D6; //  0.9642
constexpr int32_t kD50Y = 0x00010000; //  1.0000
constexpr int32_t kD50Z = 0x0000D32D; //  0.8249

// ── CheckResult builder ──

/// Helper to build CheckResult with accumulated findings.
class CheckBuilder {
public:
    void warn(std::string message) {
        m_findings.push_back(makeFinding(Severity::MEDIUM, std::move(message)));
    }
    void warn(std::string message, std::string cwe) {
        m_findings.push_back(makeFinding(Severity::MEDIUM, std::move(message), std::move(cwe)));
    }
    void high(std::string message) {
        m_findings.push_back(makeFinding(Severity::HIGH, std::move(message)));
    }
    void high(std::string message, std::string cwe) {
        m_findings.push_back(makeFinding(Severity::HIGH, std::move(message), std::move(cwe)));
    }
    void critical(std::string message) {
        m_findings.push_back(makeFinding(Severity::CRITICAL, std::move(message)));
    }
    void critical(std::string message, std::string cwe) {
        m_findings.push_back(makeFinding(Severity::CRITICAL, std::move(message), std::move(cwe)));
    }
    void info(std::string message) {
        m_findings.push_back(makeFinding(Severity::INFO, std::move(message)));
    }

    CheckResult done(std::string okSummary) {
        if (m_findings.empty()) return CheckResult::ok(std::move(okSummary));
        CheckResult r;
        r.status = CheckResult::Status::FINDINGS;
        r.summary = sfmt("%d issue(s)", static_cast<int>(m_findings.size()));
        r.findings = std::move(m_findings);
        return r;
    }

    bool empty() const { return m_findings.empty(); }
    size_t count() const { return m_findings.size(); }

private:
    std::vector<Finding> m_findings;
};

} // namespace icctest

#endif // ICCTEST_CHECK_HELPERS_H
