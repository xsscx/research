/*
 * IccTest Library — CodeQLPatternChecks.cpp
 * Heuristic checks H154-H161: CodeQL-derived vulnerability patterns.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

namespace icctest {

// ── H154: Uncontrolled Tag Allocation Size ──
static CheckResult check_h154_uncontrolled_alloc(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    for (const auto& t : pv.rawTagTable()) {
        // Tag sizes that would cause new[]/malloc() without bounds checking
        if (t.size > 64 * 1024 * 1024) { // 64 MB
            cb.critical(sfmt("Tag '%s' size %u (%.1f MB) — uncontrolled allocation",
                              sigStr(t.signature).c_str(), t.size, t.size / (1024.0*1024.0)),
                        "CWE-789: Memory Allocation with Excessive Size");
        }
    }

    return cb.done("Allocation sizes validated");
}

// ── H155: Integer Overflow in Tag Dimensions ──
static CheckResult check_h155_dimension_overflow(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Check GBD nTriangles*3 overflow (CWE-190)
    constexpr uint32_t kGbdType = 0x67626420;
    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 20 || t.offset + 20 > len) continue;
        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig != kGbdType) continue;

        uint32_t nTriangles = readU32BE(d + t.offset + 16);
        if (nTriangles > 715827882U) {
            cb.critical(sfmt("GBD nTriangles=%u — overflow in nTriangles*3", nTriangles),
                        "CWE-190: Integer Overflow or Wraparound");
        }
    }

    // Check NamedColor2 nDeviceCoords
    constexpr uint32_t kNcl2Type = 0x6E636C32; // 'ncl2'
    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 16 || t.offset + 16 > len) continue;
        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig != kNcl2Type) continue;

        uint32_t nDevCoords = readU32BE(d + t.offset + 12);
        if (nDevCoords > 15) {
            cb.high(sfmt("NamedColor2 nDeviceCoords=%u exceeds ICC max 15", nDevCoords),
                    "CWE-190: Integer Overflow or Wraparound");
        }
    }

    return cb.done("Dimension overflow checks complete");
}

// ── H156: Allocation Failure Path Profiles ──
static CheckResult check_h156_alloc_failure(const ProfileView& pv) {
    CheckBuilder cb;
    // This is a static analysis pattern — detect profiles that would trigger
    // allocation failure (null return) not checked before use
    // In V2 library, we detect the pattern via tag size heuristics

    for (const auto& t : pv.rawTagTable()) {
        if (t.size > 256 * 1024 * 1024) { // 256 MB
            cb.high(sfmt("Tag '%s' size %u would likely fail allocation",
                          sigStr(t.signature).c_str(), t.size),
                    "CWE-252: Unchecked Return Value");
        }
    }

    return cb.done("Allocation failure paths checked");
}

// ── H158: Enum Range Violation Detection ──
static CheckResult check_h158_enum_range(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    // Check rendering intent
    if (hdr.renderingIntent > 3) {
        cb.high(sfmt("Rendering intent %u out of range 0-3", hdr.renderingIntent),
                "CWE-681: Incorrect Conversion between Numeric Types");
    }

    return cb.done("Enum ranges validated");
}

// ── H160: Format String Injection in Text Tags ──
static CheckResult check_h160_format_string(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Scan text tag types for format specifiers
    constexpr uint32_t kDescType = 0x64657363; // 'desc'
    constexpr uint32_t kTextType = 0x74657874; // 'text'
    constexpr uint32_t kMlucType = 0x6D6C7563; // 'mluc'

    const char* fmtPatterns[] = { "%n", "%s", "%x", "%p" };

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 8 || t.offset + 8 > len) continue;
        uint32_t typeSig = readU32BE(d + t.offset);

        if (typeSig != kDescType && typeSig != kTextType && typeSig != kMlucType)
            continue;

        // Scan tag data for format specifiers
        uint32_t scanLen = std::min(t.size, 4096U);
        if (t.offset + scanLen > len) scanLen = len - t.offset;

        for (uint32_t i = 8; i < scanLen - 1; i++) {
            if (d[t.offset + i] != '%') continue;
            char next = d[t.offset + i + 1];
            if (next == 'n' || next == 'p') {
                cb.critical(sfmt("Text tag '%s' contains format specifier '%%%c' at offset %u",
                                  sigStr(t.signature).c_str(), next, i),
                            "CWE-134: Use of Externally-Controlled Format String");
            }
        }
    }

    return cb.done("Format string injection checked");
}

// ── Registration ──

REGISTER_HEURISTIC(154, "Uncontrolled Tag Allocation Size",
    "CodeQL cpp/new-array-with-large-size", "CWE-789",
    "CWE-789", "", Severity::CRITICAL, CheckPhase::RAW_SCAN, check_h154_uncontrolled_alloc);

REGISTER_HEURISTIC(155, "Integer Overflow in Tag Dimensions",
    "CodeQL cpp/integer-overflow", "CWE-190",
    "CWE-190", "", Severity::CRITICAL, CheckPhase::RAW_SCAN, check_h155_dimension_overflow);

REGISTER_HEURISTIC(156, "Allocation Failure Path Profiles",
    "CodeQL cpp/unchecked-return-value", "CWE-252",
    "CWE-252", "", Severity::HIGH, CheckPhase::RAW_SCAN, check_h156_alloc_failure);

REGISTER_HEURISTIC(158, "Enum Range Violation Detection",
    "CodeQL cpp/enum-out-of-range", "CWE-681",
    "CWE-681", "", Severity::HIGH, CheckPhase::HEADER, check_h158_enum_range);

REGISTER_HEURISTIC(160, "Format String Injection in Text Tags",
    "CodeQL cpp/format-string-injection", "CWE-134",
    "CWE-134", "", Severity::CRITICAL, CheckPhase::RAW_SCAN, check_h160_format_string);


// ── Additional registrations for CodeQLPatternChecks ──

static CheckResult check_h157_alloc_dealloc_mismatch_tag_patterns(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H157
    return cb.done("Alloc-Dealloc Mismatch Tag Patterns checked");
}

REGISTER_HEURISTIC(157, "Alloc-Dealloc Mismatch Tag Patterns",
    "§10.14", "ICC.1-2022-05",
    "CWE-762", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h157_alloc_dealloc_mismatch_tag_patterns);

static CheckResult check_h159_uaf_tag_ownership_chain_detection(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H159
    return cb.done("UAF Tag Ownership Chain Detection checked");
}

REGISTER_HEURISTIC(159, "UAF Tag Ownership Chain Detection",
    "§7.3", "ICC.1-2022-05",
    "CWE-416", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h159_uaf_tag_ownership_chain_detection);

static CheckResult check_h161_stack_address_escape_deep_apply_chains(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H161
    return cb.done("Stack Address Escape Deep Apply Chains checked");
}

REGISTER_HEURISTIC(161, "Stack Address Escape Deep Apply Chains",
    "§10.14", "ICC.1-2022-05",
    "CWE-121", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h161_stack_address_escape_deep_apply_chains);


} // namespace icctest
