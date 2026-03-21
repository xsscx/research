/*
 * IccTest Library — CheckResult.h
 * Core result types for ICC profile analysis checks.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "David H Hoyt LLC" must not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID H HOYT LLC "AS IS" AND ANY EXPRESSED
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL DAVID H HOYT LLC BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef ICCTEST_CHECK_RESULT_H
#define ICCTEST_CHECK_RESULT_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <chrono>
#include <algorithm>

namespace icctest {

/// Severity of a finding, ordered from lowest to highest impact.
enum class Severity : uint8_t {
    INFO     = 0,
    LOW      = 1,
    MEDIUM   = 2,
    HIGH     = 3,
    CRITICAL = 4,
};

/// When a check runs in the analysis pipeline.
enum class CheckPhase : uint8_t {
    HEADER      = 0,  // Raw header bytes (before library parse)
    TAG_TABLE   = 1,  // Raw tag table structure
    RAW_SCAN    = 2,  // Raw byte scanning (no library)
    LIBRARY     = 3,  // Library-assisted validation (CIccProfile API)
    CONFORMANCE = 4,  // ICC spec conformance (CF-* checks)
    IMAGE       = 5,  // Image container analysis (TIFF/PNG/JPEG)
};

/// Identifies a check by kind (Heuristic or Conformance) and number.
struct CheckID {
    enum class Kind : uint8_t { Heuristic, Conformance };
    Kind kind;
    int  number;  // H1-H172+ or CF-001..CF-329+

    /// Render as "H042" or "CF-317".
    std::string str() const {
        if (kind == Kind::Heuristic) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "H%d", number);
            return buf;
        }
        char buf[12];
        std::snprintf(buf, sizeof(buf), "CF-%03d", number);
        return buf;
    }

    bool operator==(const CheckID& o) const {
        return kind == o.kind && number == o.number;
    }
    bool operator<(const CheckID& o) const {
        if (kind != o.kind) return kind < o.kind;
        return number < o.number;
    }
};

/// Static metadata about a check. Stored in the registry, not per-finding.
struct CheckMeta {
    std::string_view name;        // "Profile Size Validation"
    std::string_view specRef;     // "ICC.1-2022-05 §7.2.2"
    std::string_view specDoc;     // "ICC.1-2022-05"
    std::string_view primaryCWE;  // "CWE-131" or empty
    std::string_view cveRefs;     // "CVE-2026-21677,..." or empty
    Severity         severity;
    CheckPhase       phase;
};

/// A single finding from a check execution.
struct Finding {
    CheckID     id;
    Severity    level;     // Per-finding (may differ from check default)
    std::string message;   // Human-readable description
    std::string detail;    // Additional context
    std::string cweNote;   // CWE classification note
};

/// Result of running a single check.
struct CheckResult {
    enum class Status : uint8_t {
        OK,               // Check passed, no issues
        SKIP,             // Check skipped (not applicable)
        FINDINGS,         // Check completed with findings
        NEEDS_ISOLATION,  // Check requires fork-based isolation
        ERROR,            // Check encountered an internal error
    };

    Status               status;
    std::string          summary;
    std::vector<Finding> findings;

    // Convenience constructors
    static CheckResult ok(std::string summary) {
        return {Status::OK, std::move(summary), {}};
    }
    static CheckResult skip(std::string reason) {
        return {Status::SKIP, std::move(reason), {}};
    }
    static CheckResult error(std::string what) {
        return {Status::ERROR, std::move(what), {}};
    }
    static CheckResult needsIsolation(std::string reason) {
        return {Status::NEEDS_ISOLATION, std::move(reason), {}};
    }

    bool isOk() const   { return status == Status::OK; }
    int issueCount() const { return static_cast<int>(findings.size()); }
};

/// Summary metadata extracted from a profile header (always safe — parsed from raw bytes).
struct ProfileMetadata {
    uint32_t version;
    uint32_t profileClass;
    uint32_t colorSpace;
    uint32_t pcs;
    uint32_t flags;
    uint32_t headerSize;    // Declared size in header (bytes 0-3)
    uint64_t fileSize;      // Actual file size on disk
    uint32_t renderingIntent;
    uint32_t manufacturer;
    uint32_t model;
    std::array<uint8_t, 16> profileId;
    std::array<uint8_t, 4>  magic;      // Should be 'acsp'
    std::array<uint8_t, 12> illuminant; // PCS illuminant (D50)
    std::string creator;                // 4-char creator signature as string
};

/// Timing and counting statistics for one analysis run.
struct RunStats {
    std::chrono::microseconds totalTime{0};
    int checksRun     = 0;
    int checksSkipped = 0;
    int findingsTotal = 0;
    std::array<int, 5> findingsBySeverity{};  // [INFO, LOW, MEDIUM, HIGH, CRITICAL]

    void countFinding(Severity sev) {
        findingsTotal++;
        findingsBySeverity[static_cast<size_t>(sev)]++;
    }
};

/// Complete result of analyzing one ICC profile.
struct AnalysisResult {
    ProfileMetadata          metadata;
    std::vector<Finding>     findings;
    RunStats                 stats;
    std::vector<CheckResult> perCheck;  // Individual check results, in run order

    // Query helpers
    std::vector<Finding> bySeverity(Severity minLevel) const {
        std::vector<Finding> out;
        for (auto& f : findings) {
            if (f.level >= minLevel) out.push_back(f);
        }
        return out;
    }

    std::vector<Finding> byCWE(std::string_view cwe) const {
        std::vector<Finding> out;
        for (auto& f : findings) {
            if (f.cweNote.find(cwe) != std::string::npos) out.push_back(f);
        }
        return out;
    }

    std::vector<Finding> byPhase(CheckPhase phase) const {
        // Requires id→phase mapping from registry; left for IccTestRunner
        (void)phase;
        return {};
    }

    bool hasCritical() const {
        return std::any_of(findings.begin(), findings.end(),
            [](const Finding& f) { return f.level == Severity::CRITICAL; });
    }
};

// Severity helpers
inline const char* severityName(Severity s) {
    switch (s) {
        case Severity::INFO:     return "INFO";
        case Severity::LOW:      return "LOW";
        case Severity::MEDIUM:   return "MEDIUM";
        case Severity::HIGH:     return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

inline const char* phaseName(CheckPhase p) {
    switch (p) {
        case CheckPhase::HEADER:      return "HEADER";
        case CheckPhase::TAG_TABLE:   return "TAG_TABLE";
        case CheckPhase::RAW_SCAN:    return "RAW_SCAN";
        case CheckPhase::LIBRARY:     return "LIBRARY";
        case CheckPhase::CONFORMANCE: return "CONFORMANCE";
        case CheckPhase::IMAGE:       return "IMAGE";
    }
    return "UNKNOWN";
}

} // namespace icctest

#endif // ICCTEST_CHECK_RESULT_H
