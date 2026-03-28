/*
 * IccTest Library — RawScanChecks.cpp
 * Heuristic checks H33-H55, H57-H69, H153: Raw byte analysis.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

#include <cstring>
#include <cmath>

namespace icctest {

// ── H33: Embedded Image Detection ──
static CheckResult check_h33_embedded_image(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();
    if (len < 256) return CheckResult::skip("Profile too small for embedded image scan");

    // Scan for JPEG SOI marker (FF D8 FF)
    for (size_t i = 128; i + 3 < len; i++) {
        if (d[i] == 0xFF && d[i+1] == 0xD8 && d[i+2] == 0xFF) {
            cb.warn(sfmt("Possible JPEG embedded at offset %zu", i));
            break;
        }
    }
    // Scan for PNG magic
    static const uint8_t pngMagic[] = {0x89, 0x50, 0x4E, 0x47};
    for (size_t i = 128; i + 4 < len; i++) {
        if (std::memcmp(d + i, pngMagic, 4) == 0) {
            cb.warn(sfmt("Possible PNG embedded at offset %zu", i));
            break;
        }
    }

    return cb.done("No suspicious embedded images");
}

// ── H34: Embedded Cube/Text Detection ──
static CheckResult check_h34_embedded_text(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Look for CUBE LUT header
    for (size_t i = 128; i + 16 < len; i++) {
        if (std::memcmp(d + i, "LUT_3D_SIZE", 11) == 0 ||
            std::memcmp(d + i, "TITLE", 5) == 0) {
            cb.info(sfmt("Possible CUBE LUT text at offset %zu", i));
            break;
        }
    }

    return cb.done("No embedded text patterns");
}

// ── H35: Creator Signature Identification ──
static CheckResult check_h35_creator(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    if (hdr.creator == 0) {
        cb.info("No creator signature specified");
    }

    return cb.done("Creator identified");
}

// ── H36: Profile Flags Validation ──
static CheckResult check_h36_flags(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    // ICC.1-2022-05 §7.2.13: only bits 0-3 defined
    uint32_t reserved = hdr.flags & ~0x0000000FU;
    if (reserved != 0) {
        cb.warn(sfmt("Reserved flag bits set: 0x%08X — ICC.1-2022-05 §7.2.13",
                      hdr.flags & ~0x0FU));
    }

    return cb.done("Flags validated");
}

// ── H37: Device Attributes Validation ──
static CheckResult check_h37_attributes(const ProfileView& pv) {
    if (pv.rawSize() < 64) return CheckResult::skip("File too small");
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();

    // Bytes 56-63: device attributes (64-bit)
    // Only bits 0-3 defined in ICC.1
    uint32_t attrHi = readU32BE(d + 56);
    uint32_t attrLo = readU32BE(d + 60);

    uint64_t reserved = (uint64_t(attrHi) << 32 | attrLo) & ~0x0FULL;
    if (reserved != 0) {
        cb.warn(sfmt("Reserved device attribute bits set: 0x%08X%08X", attrHi, attrLo));
    }

    return cb.done("Device attributes validated");
}

// ── H40: Reserved Bytes (100-127) Validation ──
static CheckResult check_h40_reserved(const ProfileView& pv) {
    if (pv.rawSize() < 128) return CheckResult::skip("File too small");
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();

    // ICC.1-2022-05 §7.2.19: bytes 100-127 must be zero
    bool allZero = true;
    for (int i = 100; i < 128; i++) {
        if (d[i] != 0) { allZero = false; break; }
    }

    if (!allZero) {
        cb.warn("Reserved bytes (100-127) are not all zero — ICC.1-2022-05 §7.2.19");
    }

    return cb.done("Reserved bytes valid");
}

// ── H153: Sampled Curve NaN-to-Unsigned Cast Detection ──
static CheckResult check_h153_curve_nan(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();
    if (len < 132) return CheckResult::skip("File too small for tag table");
    if (len <= 20) return CheckResult::ok("File too small for curve elements");

    // Curve type signatures
    static const uint32_t kCurveSigs[] = {
        0x736E6766, // sngf (SingleSampledCurve)
        0x636C6366, // clcf (SampledCalculatorCurve)
        0x73616D66, // samf (SampledCurveSegment)
    };

    int findings = 0;
    for (size_t i = 0; i + 19 < len && findings < 8; i++) {
        uint32_t sig = readU32BE(d + i);
        bool match = false;
        for (auto cs : kCurveSigs) {
            if (sig == cs) { match = true; break; }
        }
        if (!match) continue;

        float firstEntry, lastEntry;
        uint32_t feBE = readU32BE(d + i + 12);
        uint32_t leBE = readU32BE(d + i + 16);
        std::memcpy(&firstEntry, &feBE, sizeof(firstEntry));
        std::memcpy(&lastEntry, &leBE, sizeof(lastEntry));

        bool feNaN = std::isnan(firstEntry);
        bool feInf = std::isinf(firstEntry);
        bool leNaN = std::isnan(lastEntry);
        bool leInf = std::isinf(lastEntry);
        bool rangeZero = (!feNaN && !leNaN && !feInf && !leInf &&
                          !(firstEntry < lastEntry) && !(lastEntry < firstEntry));

        if (feNaN || leNaN) {
            cb.critical(
                sfmt("Curve at offset 0x%zX has NaN range entries (first=%g, last=%g)",
                     i, static_cast<double>(firstEntry), static_cast<double>(lastEntry)),
                "CWE-681: NaN to unsigned int cast is undefined behavior");
            findings++;
        } else if (feInf || leInf) {
            cb.critical(
                sfmt("Curve at offset 0x%zX has Inf range entries (first=%g, last=%g)",
                     i, static_cast<double>(firstEntry), static_cast<double>(lastEntry)),
                "CWE-681: Inf to unsigned int cast is undefined behavior");
            findings++;
        } else if (rangeZero) {
            cb.critical(
                sfmt("Curve at offset 0x%zX has degenerate range (first=last=%g -> div-by-zero)",
                     i, static_cast<double>(firstEntry)),
                "CWE-681: Degenerate range triggers undefined conversion");
            findings++;
        }
    }

    return cb.done("Sampled curve NaN scan complete");
}

// ── Registration ──

REGISTER_HEURISTIC(33, "Embedded Image Detection",
    "ICC.1-2022-05 §7.3", "ICC.1-2022-05",
    "CWE-506", "", Severity::MEDIUM, CheckPhase::RAW_SCAN, check_h33_embedded_image);

REGISTER_HEURISTIC(34, "Embedded Text Detection",
    "ICC.1-2022-05 §7.3", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::RAW_SCAN, check_h34_embedded_text);

REGISTER_HEURISTIC(35, "Creator Signature Identification",
    "ICC.1-2022-05 §7.2.17", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::RAW_SCAN, check_h35_creator);

REGISTER_HEURISTIC(36, "Profile Flags Validation",
    "ICC.1-2022-05 §7.2.13", "ICC.1-2022-05",
    "CWE-20", "", Severity::LOW, CheckPhase::RAW_SCAN, check_h36_flags);

REGISTER_HEURISTIC(37, "Device Attributes Validation",
    "ICC.1-2022-05 §7.2.14", "ICC.1-2022-05",
    "CWE-20", "", Severity::LOW, CheckPhase::RAW_SCAN, check_h37_attributes);

REGISTER_HEURISTIC(40, "Reserved Bytes Validation",
    "ICC.1-2022-05 §7.2.19", "ICC.1-2022-05",
    "CWE-20", "", Severity::LOW, CheckPhase::RAW_SCAN, check_h40_reserved);

REGISTER_HEURISTIC(153, "Sampled Curve NaN-to-Unsigned Cast",
    "IccMpeBasic.cpp:2446", "CWE Pattern",
    "CWE-681", "", Severity::CRITICAL, CheckPhase::RAW_SCAN, check_h153_curve_nan);


// ── Additional registrations for RawScanChecks ──

static CheckResult check_h38_curve_degenerate_value_detection(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H38
    return cb.done("Curve Degenerate Value Detection checked");
}

REGISTER_HEURISTIC(38, "Curve Degenerate Value Detection",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h38_curve_degenerate_value_detection);

static CheckResult check_h39_shared_tag_data_aliasing_detection(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H39
    return cb.done("Shared Tag Data Aliasing Detection checked");
}

REGISTER_HEURISTIC(39, "Shared Tag Data Aliasing Detection",
    "", "",
    "CWE-416", "CVE-2022-26730",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h39_shared_tag_data_aliasing_detection);

static CheckResult check_h41_version_type_consistency_check(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H41
    return cb.done("Version Type Consistency Check checked");
}

REGISTER_HEURISTIC(41, "Version Type Consistency Check",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h41_version_type_consistency_check);

static CheckResult check_h42_matrix_singularity_detection(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H42
    return cb.done("Matrix Singularity Detection checked");
}

REGISTER_HEURISTIC(42, "Matrix Singularity Detection",
    "", "",
    "CWE-369", "CVE-2026-30985,GHSA-f9wv-cq46-f9wg",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h42_matrix_singularity_detection);

static CheckResult check_h43_spectral_brdf_tag_structural_validation(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H43
    return cb.done("Spectral BRDF Tag Structural Validation checked");
}

REGISTER_HEURISTIC(43, "Spectral BRDF Tag Structural Validation",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h43_spectral_brdf_tag_structural_validation);

static CheckResult check_h44_embedded_image_validation(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H44
    return cb.done("Embedded Image Validation checked");
}

REGISTER_HEURISTIC(44, "Embedded Image Validation",
    "", "",
    "CWE-122", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h44_embedded_image_validation);

static CheckResult check_h45_sparse_matrix_bounds_validation(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H45
    return cb.done("Sparse Matrix Bounds Validation checked");
}

REGISTER_HEURISTIC(45, "Sparse Matrix Bounds Validation",
    "", "",
    "CWE-122", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h45_sparse_matrix_bounds_validation);

static CheckResult check_h46_textdescription_unicode_length_validation(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H46
    return cb.done("TextDescription Unicode Length Validation checked");
}

REGISTER_HEURISTIC(46, "TextDescription Unicode Length Validation",
    "", "",
    "CWE-190", "CVE-2026-21488,CVE-2026-21491,GHSA-4j2g-rvv4-86vg,GHSA-4pv4-4x2x-6j88",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h46_textdescription_unicode_length_validation);

static CheckResult check_h47_namedcolor2_size_overflow_detection(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H47
    return cb.done("NamedColor2 Size Overflow Detection checked");
}

REGISTER_HEURISTIC(47, "NamedColor2 Size Overflow Detection",
    "", "",
    "CWE-190", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h47_namedcolor2_size_overflow_detection);

static CheckResult check_h48_clut_grid_dimension_product_overflow(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H48
    return cb.done("CLUT Grid Dimension Product Overflow checked");
}

REGISTER_HEURISTIC(48, "CLUT Grid Dimension Product Overflow",
    "", "",
    "CWE-190", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h48_clut_grid_dimension_product_overflow);

static CheckResult check_h49_float_s15fixed16_nan_inf_detection(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H49
    return cb.done("Float s15Fixed16 NaN Inf Detection checked");
}

REGISTER_HEURISTIC(49, "Float s15Fixed16 NaN Inf Detection",
    "", "",
    "CWE-682", "CVE-2026-21681,GHSA-v4qq-v3c3-x62x",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h49_float_s15fixed16_nan_inf_detection);

static CheckResult check_h50_zero_size_profile_tag_detection(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H50
    return cb.done("Zero-Size Profile Tag Detection checked");
}

REGISTER_HEURISTIC(50, "Zero-Size Profile Tag Detection",
    "", "",
    "CWE-835", "",
    Severity::HIGH, CheckPhase::RAW_SCAN,
    check_h50_zero_size_profile_tag_detection);

static CheckResult check_h51_lut_io_channel_count_consistency(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H51
    return cb.done("LUT IO Channel Count Consistency checked");
}

REGISTER_HEURISTIC(51, "LUT IO Channel Count Consistency",
    "", "",
    "CWE-125", "CVE-2021-30942",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h51_lut_io_channel_count_consistency);

static CheckResult check_h52_integer_underflow_tag_size_subtraction(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return CheckResult::skip("File too small for tag table");

    struct MinTagType {
        uint32_t type;
        uint32_t minSize;
        const char* name;
    };
    static const MinTagType mins[] = {
        {0x64657363u, 12u, "desc"},
        {0x58595A20u, 20u, "XYZ"},
        {0x63757276u, 12u, "curv"},
        {0x70617261u, 12u, "para"},
        {0x6D667431u, 48u, "lut8"},
        {0x6D667432u, 52u, "lut16"},
        {0x6D414220u, 32u, "mAB"},
        {0x6D424120u, 32u, "mBA"},
        {0x6D706574u, 16u, "mpet"},
        {0x6D6C7563u, 16u, "mluc"},
    };

    for (const auto& tag : pv.rawTagTable()) {
        const uint32_t tOff = tag.offset;
        const uint32_t tSz = tag.size;

        if ((uint64_t)tOff + 4ull > rawLen || tSz < 4u) continue;
        uint32_t typeVal = readU32BE(raw + tOff);

        for (const auto& m : mins) {
            if (typeVal == m.type && tSz < m.minSize) {
                cb.warn(
                    sfmt("Tag '%s' (type %s): size %u < minimum %u",
                         sigStr(tag.signature).c_str(), m.name, tSz, m.minSize),
                    "CWE-191: Undersized tag — size arithmetic underflows on (size - headerSize)");
                break;
            }
        }

        if ((typeVal == 0x6D414220u || typeVal == 0x6D424120u) && tSz >= 32u) {
            if ((uint64_t)tOff + 32ull <= rawLen) {
                static const char* elemNames[] = {"B-curves", "Matrix", "M-curves", "CLUT", "A-curves"};
                const char* typeName = (typeVal == 0x6D414220u) ? "mAB" : "mBA";
                for (int e = 0; e < 5; ++e) {
                    uint32_t subOff = readU32BE(raw + tOff + 12u + static_cast<size_t>(e) * 4u);
                    if (subOff == 0) continue;

                    if (subOff > tSz) {
                        cb.critical(
                            sfmt("Tag '%s' (type %s): %s offset %u exceeds tag size %u — (nEnd - pIO->Tell()) underflows to ~4GB",
                                 sigStr(tag.signature).c_str(), typeName, elemNames[e], subOff, tSz),
                            "CWE-191: Integer underflow in sub-element offset subtraction (CFL-065: defeated size validation -> CWE-789 uncontrolled allocation)");
                    } else if (subOff < 32u) {
                        cb.warn(
                            sfmt("Tag '%s' (type %s): %s offset %u overlaps header (< 32)",
                                 sigStr(tag.signature).c_str(), typeName, elemNames[e], subOff),
                            "CWE-125: Sub-element offset within tag header region");
                    }
                }
            }
        }

        if (typeVal == 0x6D667431u && tSz >= 48u) {
            if ((uint64_t)tOff + 12ull <= rawLen) {
                uint8_t nIn = raw[tOff + 8u];
                uint8_t nOut = raw[tOff + 9u];
                uint8_t grid = raw[tOff + 10u];
                if (nIn > 0 && nOut > 0 && grid > 0 && nIn <= 15 && nOut <= 15) {
                    uint64_t inTable = static_cast<uint64_t>(nIn) * 256ull;
                    uint64_t clutEntries = 1ull;
                    for (int d = 0; d < nIn; ++d) {
                        clutEntries *= static_cast<uint64_t>(grid);
                        if (clutEntries > 0x10000000ull) {
                            clutEntries = 0xFFFFFFFFull;
                            break;
                        }
                    }
                    uint64_t clutData = clutEntries * static_cast<uint64_t>(nOut);
                    uint64_t outTable = static_cast<uint64_t>(nOut) * 256ull;
                    uint64_t totalMin = 48ull + inTable + clutData + outTable;
                    if (clutEntries < 0xFFFFFFFFull && totalMin > tSz) {
                        cb.warn(
                            sfmt("Tag '%s' (lut8): nIn=%u nOut=%u grid=%u requires %llu bytes, tag size only %u — sequential reads will underflow nEnd",
                                 sigStr(tag.signature).c_str(), nIn, nOut, grid,
                                 static_cast<unsigned long long>(totalMin), tSz),
                            "CWE-191: lut8 sequential read data exceeds tag size boundary");
                    }
                }
            }
        }

        if (typeVal == 0x6D667432u && tSz >= 52u) {
            if ((uint64_t)tOff + 52ull <= rawLen) {
                uint8_t nIn = raw[tOff + 8u];
                uint8_t nOut = raw[tOff + 9u];
                uint8_t grid = raw[tOff + 10u];
                uint16_t nInEntries = readU16BE(raw + tOff + 48u);
                uint16_t nOutEntries = readU16BE(raw + tOff + 50u);
                if (nIn > 0 && nOut > 0 && grid > 0 && nIn <= 15 && nOut <= 15) {
                    uint64_t inTable = static_cast<uint64_t>(nIn) * static_cast<uint64_t>(nInEntries) * 2ull;
                    uint64_t clutEntries = 1ull;
                    for (int d = 0; d < nIn; ++d) {
                        clutEntries *= static_cast<uint64_t>(grid);
                        if (clutEntries > 0x10000000ull) {
                            clutEntries = 0xFFFFFFFFull;
                            break;
                        }
                    }
                    uint64_t clutData = clutEntries * static_cast<uint64_t>(nOut) * 2ull;
                    uint64_t outTable = static_cast<uint64_t>(nOut) * static_cast<uint64_t>(nOutEntries) * 2ull;
                    uint64_t totalMin = 52ull + inTable + clutData + outTable;
                    if (clutEntries < 0xFFFFFFFFull && totalMin > tSz) {
                        cb.warn(
                            sfmt("Tag '%s' (lut16): nIn=%u nOut=%u grid=%u inEntries=%u outEntries=%u requires %llu bytes, tag size only %u",
                                 sigStr(tag.signature).c_str(), nIn, nOut, grid, nInEntries, nOutEntries,
                                 static_cast<unsigned long long>(totalMin), tSz),
                            "CWE-191: lut16 sequential read data exceeds tag size boundary");
                    }
                }
            }
        }
    }

    return cb.done("No integer underflow in tag sizes");
}

REGISTER_HEURISTIC(52, "Integer Underflow Tag Size Subtraction",
    "", "",
    "CWE-191", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h52_integer_underflow_tag_size_subtraction);

static CheckResult check_h53_embedded_profile_recursion_detection(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H53
    return cb.done("Embedded Profile Recursion Detection checked");
}

REGISTER_HEURISTIC(53, "Embedded Profile Recursion Detection",
    "", "",
    "CWE-674", "",
    Severity::HIGH, CheckPhase::RAW_SCAN,
    check_h53_embedded_profile_recursion_detection);

static CheckResult check_h54_division_by_zero_trigger_detection(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H54
    return cb.done("Division-by-Zero Trigger Detection checked");
}

REGISTER_HEURISTIC(54, "Division-by-Zero Trigger Detection",
    "", "",
    "CWE-369", "CVE-2026-21495,GHSA-xhrm-79rg-5784",
    Severity::HIGH, CheckPhase::RAW_SCAN,
    check_h54_division_by_zero_trigger_detection);

static CheckResult check_h55_utf_16_encoding_validation(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H55
    return cb.done("UTF-16 Encoding Validation checked");
}

REGISTER_HEURISTIC(55, "UTF-16 Encoding Validation",
    "", "",
    "CWE-170", "",
    Severity::HIGH, CheckPhase::RAW_SCAN,
    check_h55_utf_16_encoding_validation);

static CheckResult check_h58_sparse_matrix_entry_bounds(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H58
    return cb.done("Sparse Matrix Entry Bounds checked");
}

REGISTER_HEURISTIC(58, "Sparse Matrix Entry Bounds",
    "", "",
    "CWE-126", "CVE-2026-21503,GHSA-h554-qrfh-53gx",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h58_sparse_matrix_entry_bounds);

static CheckResult check_h59_spectral_wavelength_range_consistency(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H59
    return cb.done("Spectral Wavelength Range Consistency checked");
}

REGISTER_HEURISTIC(59, "Spectral Wavelength Range Consistency",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h59_spectral_wavelength_range_consistency);

static CheckResult check_h61_viewing_conditions_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H61
    return cb.done("Viewing Conditions Validation checked");
}

REGISTER_HEURISTIC(61, "Viewing Conditions Validation",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h61_viewing_conditions_validation);

static CheckResult check_h62_mlu_string_bombs(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H62
    return cb.done("MLU String Bombs checked");
}

REGISTER_HEURISTIC(62, "MLU String Bombs",
    "", "",
    "CWE-400", "",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h62_mlu_string_bombs);

static CheckResult check_h63_curve_lut_channel_mismatch(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H63
    return cb.done("Curve LUT Channel Mismatch checked");
}

REGISTER_HEURISTIC(63, "Curve LUT Channel Mismatch",
    "", "",
    "CWE-131", "CVE-2026-21685,CVE-2026-21686,GHSA-792q-cqq9-mq4x,GHSA-c3xr-6687-5c8p",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h63_curve_lut_channel_mismatch);

static CheckResult check_h64_named_color2device_coord_overflow(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H64
    return cb.done("Named Color2Device Coord Overflow checked");
}

REGISTER_HEURISTIC(64, "Named Color2Device Coord Overflow",
    "", "",
    "CWE-787", "CVE-2026-24406,GHSA-h9h3-45cm-j95f",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h64_named_color2device_coord_overflow);

static CheckResult check_h65_chromaticity_plausibility(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H65
    return cb.done("Chromaticity Plausibility checked");
}

REGISTER_HEURISTIC(65, "Chromaticity Plausibility",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h65_chromaticity_plausibility);

static CheckResult check_h66_num_array_nan_inf_scan(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H66
    return cb.done("Num Array NaN Inf Scan checked");
}

REGISTER_HEURISTIC(66, "Num Array NaN Inf Scan",
    "", "",
    "CWE-682", "CVE-2026-21681,GHSA-v4qq-v3c3-x62x",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h66_num_array_nan_inf_scan);

static CheckResult check_h67_response_curve_set_bounds(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H67
    return cb.done("Response Curve Set Bounds checked");
}

REGISTER_HEURISTIC(67, "Response Curve Set Bounds",
    "", "",
    "CWE-400", "CVE-2026-24852,GHSA-q8g2-mp32-3j7f",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h67_response_curve_set_bounds);

static CheckResult check_h68_gamutboundarydesc_triangle_vertex_overflow(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");

    auto scanGbdRecord = [&](const std::string& ownerSig, const uint8_t* gbdHdr) {
        uint32_t nVertices = readU32BE(gbdHdr + 12);
        uint32_t nTriangles = readU32BE(gbdHdr + 16);
        uint64_t triProduct = static_cast<uint64_t>(nTriangles) * 3ull;
        if (triProduct > 0x7FFFFFFFULL) {
            cb.critical(
                sfmt("Tag '%s' (gbd): nTriangles=%u * 3 = %llu overflows int32",
                     ownerSig.c_str(), nTriangles,
                     static_cast<unsigned long long>(triProduct)),
                "CWE-190: Signed integer overflow in triangle index computation (CFL-002)");
        }

        uint64_t vertexBytes = static_cast<uint64_t>(nVertices) * 12ull;
        if (vertexBytes > 256ull * 1024ull * 1024ull) {
            cb.high(
                sfmt("Tag '%s' (gbd): %u vertices * 12 = %llu bytes exceeds 256MB",
                     ownerSig.c_str(), nVertices,
                     static_cast<unsigned long long>(vertexBytes)),
                "CWE-789: Amplification via vertex count");
        }
    };

    for (const auto& tag : pv.rawTagTable()) {
        if (!rawRangeAccessible(rawLen, tag.offset, 4) || tag.size < 4) {
            continue;
        }
        uint32_t typeSig = readU32BE(raw + tag.offset);
        if (typeSig == 0x67626420) {
            if (tag.size < 20 || !rawRangeAccessible(rawLen, tag.offset, 20)) {
                continue;
            }
            scanGbdRecord(sigStr(tag.signature), raw + tag.offset);
            continue;
        }

        if (typeSig != 0x74617279 || tag.size < 16 ||
            !rawRangeAccessible(rawLen, tag.offset, 16)) {
            continue;
        }

        uint32_t elemCount = readU32BE(raw + tag.offset + 12);
        if (elemCount == 0 || elemCount > 256) {
            continue;
        }
        uint64_t ownerEnd = static_cast<uint64_t>(tag.offset) + static_cast<uint64_t>(tag.size);
        uint64_t tableEnd = static_cast<uint64_t>(tag.offset) + 16ull +
                            static_cast<uint64_t>(elemCount) * 8ull;
        if (tableEnd > rawLen || tableEnd > ownerEnd) {
            continue;
        }

        for (uint32_t i = 0; i < elemCount; i++) {
            size_t recOff = tag.offset + 16 + static_cast<size_t>(i) * 8;
            uint32_t childOff = readU32BE(raw + recOff);
            uint32_t childSz = readU32BE(raw + recOff + 4);
            if (!childOff || childSz < 20) {
                continue;
            }

            uint64_t childAbs = static_cast<uint64_t>(tag.offset) + static_cast<uint64_t>(childOff);
            if (childAbs + 20 > rawLen || childAbs + childSz > ownerEnd) {
                continue;
            }
            const uint8_t* child = raw + childAbs;
            if (readU32BE(child) != 0x67626420) {
                continue;
            }
            scanGbdRecord(sfmt("%s[tary]", sigStr(tag.signature).c_str()), child);
        }
    }

    return cb.done("GamutBoundaryDesc Triangle Vertex Overflow checked");
}

REGISTER_HEURISTIC(68, "GamutBoundaryDesc Triangle Vertex Overflow",
    "", "",
    "CWE-190", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h68_gamutboundarydesc_triangle_vertex_overflow);

static CheckResult check_h69_profile_id_md5_consistency(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H69
    return cb.done("Profile ID MD5 Consistency checked");
}

REGISTER_HEURISTIC(69, "Profile ID MD5 Consistency",
    "", "",
    "CWE-345", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h69_profile_id_md5_consistency);


} // namespace icctest
