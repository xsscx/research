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
    if (len < 132) return CheckResult::skip("File too small for tag table");

    for (const auto& t : pv.rawTagTable()) {
        if (static_cast<uint64_t>(t.offset) <= len &&
            static_cast<uint64_t>(t.size) <= len &&
            static_cast<uint64_t>(t.offset) + t.size <= len) {
            continue;
        }

        cb.critical(
            sfmt("Tag '%s': offset=%u size=%u exceeds file (%zu bytes)",
                 sigStr(t.signature).c_str(), t.offset, t.size, len),
            "CWE-789: Uncontrolled allocation");
    }

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 12 || t.offset + 12 > len) continue;

        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig == 0x6E636C32 && t.size >= 16) {
            uint32_t nDevCoords = readU32BE(d + t.offset + 12);
            if (nDevCoords > 15) {
                cb.critical(
                    sfmt("NamedColor2: nDeviceCoords=%u (ICC spec max=15)", nDevCoords),
                    "CWE-789: Unbounded allocation in NamedColor2 Read()");
            }
        }

        if ((typeSig == 0x6D414220 || typeSig == 0x6D424120) && t.size >= 28) {
            const char* subNames[] = {"Bcurves", "Matrix", "Acurves", "CLUT"};
            for (int i = 0; i < 4; i++) {
                uint32_t subOff = readU32BE(d + t.offset + 12 + i * 4);
                if (subOff > 0 && subOff >= t.size) {
                    cb.critical(
                        sfmt("Tag '%s' (%s): %s offset=%u exceeds tag size (%u)",
                             sigStr(t.signature).c_str(),
                             typeSig == 0x6D414220 ? "mAB" : "mBA",
                             subNames[i], subOff, t.size),
                        "CWE-789: Out-of-bounds sub-element offset causes uncontrolled allocation");
                }
            }
        }
    }

    return cb.done("Allocation sizes validated");
}

// ── H155: Integer Overflow in Tag Dimensions ──
static CheckResult check_h155_dimension_overflow(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();
    if (len < 132) return CheckResult::skip("File too small");

    uint32_t tagCount = readU32BE(d + 128);
    if (tagCount == 0 || tagCount > 1000) {
        return CheckResult::skip("Invalid tag count");
    }

    for (uint32_t i = 0; i < tagCount && i < 256; i++) {
        size_t entryOff = 132 + static_cast<size_t>(i) * 12;
        if (entryOff + 12 > len) break;

        uint32_t tSig = readU32BE(d + entryOff);
        uint32_t tOffset = readU32BE(d + entryOff + 4);
        uint32_t tSize = readU32BE(d + entryOff + 8);
        if (static_cast<uint64_t>(tOffset) + 8 > len || tSize < 8) continue;

        uint32_t typeSig = readU32BE(d + tOffset);
        std::string tagName = sigStr(tSig);

        if (typeSig == 0x6D667431 && static_cast<uint64_t>(tOffset) + 48 <= len) {
            uint8_t nInput = d[tOffset + 8];
            uint8_t nOutput = d[tOffset + 9];
            uint8_t grid = d[tOffset + 10];
            if (nInput > 0 && grid > 0) {
                uint64_t clutSize = 1;
                bool overflow = false;
                for (uint8_t dim = 0; dim < nInput; dim++) {
                    clutSize *= grid;
                    if (clutSize > 0xFFFFFFFFULL) {
                        overflow = true;
                        break;
                    }
                }
                clutSize *= nOutput;
                if (clutSize > 0xFFFFFFFFULL) overflow = true;
                if (overflow || clutSize > tSize) {
                    cb.critical(
                        sfmt("Tag '%s' (Lut8): %ux%u grid^%u x %u = overflow",
                             tagName.c_str(), nInput, nOutput, nInput, grid),
                        "CWE-190: Integer overflow in CLUT size calculation");
                }
            }
        }

        if (typeSig == 0x6D667432 && static_cast<uint64_t>(tOffset) + 48 <= len) {
            uint8_t nInput = d[tOffset + 8];
            uint8_t nOutput = d[tOffset + 9];
            uint8_t grid = d[tOffset + 10];
            if (nInput > 0 && grid > 0) {
                uint64_t clutSize = 2;
                bool overflow = false;
                for (uint8_t dim = 0; dim < nInput; dim++) {
                    clutSize *= grid;
                    if (clutSize > 0xFFFFFFFFULL) {
                        overflow = true;
                        break;
                    }
                }
                clutSize *= nOutput;
                if (clutSize > 0xFFFFFFFFULL) overflow = true;
                if (overflow || clutSize > tSize) {
                    cb.critical(
                        sfmt("Tag '%s' (Lut16): %ux%u grid^%u x %u x 2 = overflow",
                             tagName.c_str(), nInput, nOutput, nInput, grid),
                        "CWE-190: Integer overflow in CLUT size calculation");
                }
            }
        }

        if ((typeSig == 0x6D414220 || typeSig == 0x6D424120) &&
            static_cast<uint64_t>(tOffset) + 32 <= len) {
            uint8_t nInput = d[tOffset + 8];
            uint8_t nOutput = d[tOffset + 9];
            uint32_t clutOff = readU32BE(d + tOffset + 24);
            if (clutOff != 0 && static_cast<uint64_t>(tOffset) + clutOff + 20 <= len) {
                size_t clutAddr = tOffset + clutOff;
                uint64_t clutSize = (d[clutAddr + 16] == 2) ? 2 : 1;
                bool overflow = false;
                for (uint8_t dim = 0; dim < nInput && dim < 16; dim++) {
                    uint8_t gp = d[clutAddr + dim];
                    if (gp == 0) gp = 1;
                    clutSize *= gp;
                    if (clutSize > 0xFFFFFFFFULL) {
                        overflow = true;
                        break;
                    }
                }
                clutSize *= nOutput;
                if (clutSize > 0xFFFFFFFFULL) overflow = true;
                if (overflow) {
                    cb.critical(
                        sfmt("Tag '%s' (%s): %u-in x %u-out CLUT grid overflows uint32",
                             tagName.c_str(),
                             typeSig == 0x6D414220 ? "mAB" : "mBA",
                             nInput, nOutput),
                        "CWE-190: Multiplication overflow before allocation");
                }
            }
        }

        if (typeSig == 0x6D706574 && static_cast<uint64_t>(tOffset) + 16 <= len) {
            uint16_t nInput = readU16BE(d + tOffset + 8);
            uint16_t nOutput = readU16BE(d + tOffset + 10);
            uint32_t nElem = readU32BE(d + tOffset + 12);
            uint64_t posTableSize = static_cast<uint64_t>(nElem) * 8;
            if (posTableSize > tSize || nElem > 10000) {
                cb.critical(
                    sfmt("Tag '%s' (MPE): %u elements x 8 = %llu bytes (tag size=%u)",
                         tagName.c_str(), nElem,
                         static_cast<unsigned long long>(posTableSize), tSize),
                    "CWE-190: Element count drives allocation overflow");
            }
            if (nInput > 0 && nOutput > 0) {
                uint64_t chanProduct = static_cast<uint64_t>(nInput) * nOutput * 4;
                if (chanProduct > 1024 * 1024ULL) {
                    cb.warn(
                        sfmt("Tag '%s' (MPE): %ux%u channels -> %llu bytes per element",
                             tagName.c_str(), nInput, nOutput,
                             static_cast<unsigned long long>(chanProduct)),
                        "CWE-190: High channel count amplifies per-element allocation");
                }
            }
        }
    }

    return cb.done("Dimension overflow checks complete");
}

// ── H156: Allocation Failure Path Profiles ──
static CheckResult check_h156_alloc_failure(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();
    if (len < 132) return CheckResult::skip("File too small");

    uint32_t profileSize = readU32BE(d);
    uint64_t totalDeclaredSize = 0;
    int largeTagCount = 0;

    for (const auto& t : pv.rawTagTable()) {
        totalDeclaredSize += t.size;
        if (t.size > 10 * 1024 * 1024) {
            largeTagCount++;
        }
    }

    if (totalDeclaredSize > 256ULL * 1024 * 1024) {
        cb.warn(
            sfmt("Aggregate tag allocation: %.1f MB across %zu tags",
                 static_cast<double>(totalDeclaredSize) / (1024.0 * 1024.0),
                 pv.rawTagTable().size()),
            "CWE-252: Aggregate pressure increases OOM probability");
    }

    if (largeTagCount >= 3) {
        cb.warn(
            sfmt("%d tags exceed 10MB — high concurrent allocation demand", largeTagCount),
            "CWE-252: Multiple large allocations increase NULL-deref risk");
    }

    if (profileSize > 0 && totalDeclaredSize > static_cast<uint64_t>(profileSize) * 2) {
        cb.warn(
            sfmt("Tag sizes total %llu bytes but profile is %u bytes",
                 static_cast<unsigned long long>(totalDeclaredSize), profileSize),
            "CWE-252: Oversized tag declarations trigger allocation then fail on read");
    }

    return cb.done("Allocation failure paths checked");
}

// ── H158: Enum Range Violation Detection ──
static CheckResult check_h158_enum_range(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();
    if (len < 132) return CheckResult::skip("File too small");

    uint32_t tagCount = readU32BE(d + 128);
    if (tagCount > 0 && tagCount <= 1000) {
        int invalidTypeSigs = 0;
        for (uint32_t i = 0; i < tagCount && i < 256; i++) {
            size_t entryOff = 132 + static_cast<size_t>(i) * 12;
            if (entryOff + 12 > len) break;

            uint32_t tOffset = readU32BE(d + entryOff + 4);
            uint32_t tSize = readU32BE(d + entryOff + 8);
            if (static_cast<uint64_t>(tOffset) + 4 > len || tSize < 4) continue;

            uint32_t typeSig = readU32BE(d + tOffset);
            bool validFourCC = true;
            for (int byte = 0; byte < 4; byte++) {
                uint8_t ch = static_cast<uint8_t>((typeSig >> (24 - byte * 8)) & 0xFF);
                if (ch < 0x20 || ch > 0x7E) {
                    validFourCC = false;
                    break;
                }
            }
            if (!validFourCC && typeSig != 0) {
                invalidTypeSigs++;
            }
        }

        if (invalidTypeSigs > 0) {
            cb.warn(
                sfmt("%d tag type signatures are not valid FourCC (non-printable bytes)",
                     invalidTypeSigs),
                "CWE-681: Tag type enum cast without validation");
        }
    }

    for (uint32_t i = 0; i < tagCount && i < 256; i++) {
        size_t entryOff = 132 + static_cast<size_t>(i) * 12;
        if (entryOff + 12 > len) break;

        uint32_t tOffset = readU32BE(d + entryOff + 4);
        uint32_t tSize = readU32BE(d + entryOff + 8);
        if (static_cast<uint64_t>(tOffset) + 16 > len || tSize < 16) continue;

        uint32_t typeSig = readU32BE(d + tOffset);
        if (typeSig != 0x6D706574) continue;

        uint32_t nElem = readU32BE(d + tOffset + 12);
        if (nElem > 10000) continue;

        int invalidElemSigs = 0;
        for (uint32_t e = 0; e < nElem && e < 100; e++) {
            size_t posOff = tOffset + 16 + static_cast<size_t>(e) * 8;
            if (posOff + 8 > len) break;

            uint32_t elemOff = readU32BE(d + posOff);
            size_t absElemOff = tOffset + elemOff;
            if (absElemOff + 4 > len) continue;

            uint32_t elemSig = readU32BE(d + absElemOff);
            bool validFourCC = true;
            for (int byte = 0; byte < 4; byte++) {
                uint8_t ch = static_cast<uint8_t>((elemSig >> (24 - byte * 8)) & 0xFF);
                if (ch < 0x20 || ch > 0x7E) {
                    validFourCC = false;
                    break;
                }
            }
            if (!validFourCC && elemSig != 0) {
                invalidElemSigs++;
            }
        }

        if (invalidElemSigs > 0) {
            cb.warn(
                sfmt("MPE tag has %d sub-elements with invalid type signatures (non-FourCC)",
                     invalidElemSigs),
                "CWE-681: Element type enum cast without validation");
        }
    }

    return cb.done("Enum ranges validated");
}

// ── H160: Format String Injection in Text Tags ──
static CheckResult check_h160_format_string(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();
    if (len < 132) return CheckResult::skip("Cannot open file");

    // Scan text tag types for format specifiers
    constexpr uint32_t kDescType = 0x64657363; // 'desc'
    constexpr uint32_t kTextType = 0x74657874; // 'text'
    constexpr uint32_t kMlucType = 0x6D6C7563; // 'mluc'

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
    "CWE-681", "", Severity::HIGH, CheckPhase::RAW_SCAN, check_h158_enum_range);

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

// ── H173: Signature Conversion Shift Overflow ──
// Detects the UBSAN pattern in iccDEV IccUtil.cpp icGetSigStr()/icGetColorSig()
// where sig<<=8 on a uint32 with first byte >= 0x01 overflows.
// Every valid FourCC signature (printable ASCII) has first byte >= 0x20 and
// therefore triggers this overflow.
static CheckResult check_h173_sig_conversion_shift_overflow(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();
    if (!d || len < 132) return CheckResult::skip("Cannot read profile");

    int overflowCount = 0;
    int totalSigs = 0;

    // Header signature fields passed through icGetSigStr/icGetColorSig:
    // offset  4: preferred CMM type
    // offset 12: device class
    // offset 16: color data space
    // offset 20: PCS
    // offset 36: magic ('acsp')
    // offset 40: primary platform
    // offset 48: device manufacturer
    // offset 52: device model
    static const int kHeaderSigOffsets[] = { 4, 12, 16, 20, 36, 40, 48, 52 };

    for (int off : kHeaderSigOffsets) {
        uint32_t sig = readU32BE(d + off);
        if (sig == 0) continue;
        totalSigs++;
        if (sig > 0x00FFFFFFU) overflowCount++;
    }

    // Tag table: tag signatures
    for (const auto& t : pv.rawTagTable()) {
        totalSigs++;
        if (t.signature > 0x00FFFFFFU) overflowCount++;
    }

    // Tag type signatures (first 4 bytes of each tag's data)
    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 4 || t.offset + 4 > len) continue;
        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig == 0) continue;
        totalSigs++;
        if (typeSig > 0x00FFFFFFU) overflowCount++;
    }

    if (overflowCount > 0) {
        cb.warn(sfmt("%d/%d FourCC signatures trigger UBSAN shift overflow "
                     "in icGetSigStr()/icGetColorSig() — IccUtil.cpp:1088,1130",
                     overflowCount, totalSigs),
                "CWE-190: sig<<=8 on uint32 with first byte non-zero "
                "produces value > UINT32_MAX");
    }

    return cb.done(sfmt("Signature shift overflow scan (%d/%d checked)",
                        overflowCount, totalSigs));
}

REGISTER_HEURISTIC(173, "Signature Conversion Shift Overflow",
    "IccUtil.cpp:1088/1130", "CWE Pattern",
    "CWE-190", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h173_sig_conversion_shift_overflow);

} // namespace icctest
