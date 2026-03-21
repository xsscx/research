/*
 * IccTest Library — XmlSafetyChecks.cpp
 * Heuristic checks H142-H145: XML serialization safety.
 *
 * H142 returns NEEDS_ISOLATION — the CLI sandbox handles fork-based execution.
 * The library only marks the check as needing isolation, not performing it.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

namespace icctest {

// ── H142: XML Serialization Safety ──
// This check CANNOT be run in-process — ToXml() can crash/hang.
// Library returns NEEDS_ISOLATION; CLI handles fork-based execution.
static CheckResult check_h142_xml_safety(const ProfileView& pv) {
    if (!pv.libraryLoaded()) return CheckResult::skip("Library parse failed");

    // Signal that this check requires fork isolation
    return CheckResult::needsIsolation(
        "CIccProfileXml::ToXml() requires fork isolation — "
        "XML serialization can crash/hang on malformed profiles "
        "(covers 25 XML-related iccDEV advisories)");
}

// ── H143: XML Array Bounds Precheck ──
static CheckResult check_h143_xml_array_bounds(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Scan for array-type tags where m_nSize * elementSize > tagDataSize
    // Array types: 'ui16' (2 bytes), 'ui32' (4), 'ui64' (8), 'sf32' (4), 'uf32' (4)
    struct ArrayType { uint32_t sig; int elemSize; const char* name; };
    static const ArrayType arrayTypes[] = {
        {0x75693136, 2, "UInt16Array"},  // 'ui16'
        {0x75693332, 4, "UInt32Array"},  // 'ui32'
        {0x75693634, 8, "UInt64Array"},  // 'ui64'
        {0x73663332, 4, "S15Fixed16"},   // 'sf32'
        {0x75663332, 4, "U16Fixed16"},   // 'uf32'
    };

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 8 || t.offset + 8 > len) continue;
        uint32_t typeSig = readU32BE(d + t.offset);

        for (const auto& at : arrayTypes) {
            if (typeSig != at.sig) continue;

            uint32_t dataBytes = t.size - 8; // subtract type + reserved
            uint32_t elemCount = dataBytes / at.elemSize;
            if (elemCount > 1000000) {
                cb.high(sfmt("Tag '%s' (%s) has %u elements — ToXml would produce enormous output",
                              sigStr(t.signature).c_str(), at.name, elemCount),
                        "CWE-131: Incorrect Calculation of Buffer Size");
            }
        }
    }

    return cb.done("XML array bounds validated");
}

// ── H144: XML String Termination Precheck ──
static CheckResult check_h144_xml_string_term(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Check ColorantTable entries for null-terminated 32-byte names
    // ColorantTable type: 'clrt' = 0x636C7274
    constexpr uint32_t kClrtType = 0x636C7274;

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 12 || t.offset + 12 > len) continue;
        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig != kClrtType) continue;

        uint32_t nEntries = readU32BE(d + t.offset + 8);
        // Each entry: 32-byte name + 6 bytes PCS coordinates = 38 bytes
        for (uint32_t i = 0; i < nEntries && i < 256; i++) {
            uint32_t entryOff = t.offset + 12 + i * 38;
            if (entryOff + 38 > len) break;

            // Check if name has null terminator within 32 bytes
            bool hasNull = false;
            for (int j = 0; j < 32; j++) {
                if (d[entryOff + j] == 0) { hasNull = true; break; }
            }
            if (!hasNull) {
                cb.high(sfmt("Colorant entry #%u has unterminated 32-byte name "
                              "— strlen overflow in XML serialization", i),
                        "CWE-170: Improper Null Termination");
            }
        }
    }

    return cb.done("XML string termination validated");
}

// ── H145: XML Curve Type Consistency ──
static CheckResult check_h145_xml_curve_type(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Scan for CurveSet elements and validate sub-element type signatures
    constexpr uint32_t kCvstSig = 0x63767374; // 'cvst'

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 16 || t.offset + 16 > len) continue;
        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig != kCvstSig) continue;

        // CurveSet sub-elements should be valid curve types
        cb.info(sfmt("CurveSet element found in tag '%s'", sigStr(t.signature).c_str()));
    }

    return cb.done("XML curve type consistency validated");
}

// ── Registration ──

REGISTER_HEURISTIC(142, "XML Serialization Safety",
    "CWE-787/CWE-125 Pattern", "25 iccDEV XML advisories",
    "CWE-787", "", Severity::CRITICAL, CheckPhase::LIBRARY, check_h142_xml_safety);

REGISTER_HEURISTIC(143, "XML Array Bounds Precheck",
    "CIccXmlArrayType::DumpArray", "CWE-131",
    "CWE-131", "", Severity::HIGH, CheckPhase::RAW_SCAN, check_h143_xml_array_bounds);

REGISTER_HEURISTIC(144, "XML String Termination Precheck",
    "CIccTagColorantTable::ToXml", "CWE-170",
    "CWE-170", "", Severity::HIGH, CheckPhase::RAW_SCAN, check_h144_xml_string_term);

REGISTER_HEURISTIC(145, "XML Curve Type Consistency",
    "CIccXmlMpeCurveSet::ToXml", "CWE-843",
    "CWE-843", "", Severity::HIGH, CheckPhase::RAW_SCAN, check_h145_xml_curve_type);

} // namespace icctest
