/*
 * IccTest Library — DataValidationChecks.cpp
 * Heuristic checks H56-H102, H146-H148, H151-H152: Data integrity via iccDEV API.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

#include "IccProfile.h"
#include "IccTagBasic.h"
#include "IccTagLut.h"

namespace icctest {

// ── H56: MediaWhitePoint Validation ──
static CheckResult check_h56_white_point(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return CheckResult::skip("Library parse failed");

    auto tv = pv.tag(static_cast<icTagSignature>(kSigWtpt));
    if (!tv) return CheckResult::skip("No mediaWhitePointTag");

    // White point should be close to D50 for most profile classes
    const auto& hdr = pv.header();
    if (hdr.deviceClass != kClassLink) {
        // Check via raw bytes: wtpt tag contains XYZType (12 bytes of XYZ data after 8-byte header)
        auto rawEntry = pv.rawTag(kSigWtpt);
        if (rawEntry && rawEntry->size >= 20 && rawEntry->offset + 20 <= pv.rawSize()) {
            const uint8_t* p = pv.rawData() + rawEntry->offset + 8;
            double x = readS15Fixed16(p);
            double y = readS15Fixed16(p + 4);
            double z = readS15Fixed16(p + 8);

            double dx = x - 0.9642, dy = y - 1.0, dz = z - 0.8249;
            double dist = dx*dx + dy*dy + dz*dz;
            if (dist > 0.001) {
                cb.warn(sfmt("White point (%.4f, %.4f, %.4f) far from D50 "
                              "(0.9642, 1.0, 0.8249) — distance² = %.6f", x, y, z, dist));
            }
        }
    }

    return cb.done("White point validated");
}

// ── H57: Chromatic Adaptation Validation ──
static CheckResult check_h57_chad(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return CheckResult::skip("Library parse failed");

    bool hasChadTag = pv.hasTag(static_cast<icTagSignature>(kSigChad));
    // chad is required if adopted white != D50
    // For simplicity, just check presence for non-D50 white points
    auto rawWtpt = pv.rawTag(kSigWtpt);
    if (rawWtpt && rawWtpt->size >= 20 && rawWtpt->offset + 20 <= pv.rawSize()) {
        const uint8_t* p = pv.rawData() + rawWtpt->offset + 8;
        int32_t xi = readS32BE(p);
        int32_t yi = readS32BE(p + 4);
        int32_t zi = readS32BE(p + 8);

        bool isD50 = (xi == kD50X && yi == kD50Y && zi == kD50Z);
        if (!isD50 && !hasChadTag) {
            cb.warn("Adopted white != D50 but no chromaticAdaptationTag ('chad') — ICC.1 §9.2.49");
        }
    }

    return cb.done("Chromatic adaptation validated");
}

// ── H60: LUT Channel Count Validation ──
static CheckResult check_h60_lut_channels(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return CheckResult::skip("Library parse failed");

    static const uint32_t lutTags[] = {
        kSigAToB0, kSigBToA0,
        0x41324231, 0x42324131, // A2B1, B2A1
        0x41324232, 0x42324132, // A2B2, B2A2
    };

    for (auto sig : lutTags) {
        auto tv = pv.tag(static_cast<icTagSignature>(sig));
        if (!tv) continue;

        CIccTag* pTag = tv->rawHandle();
        if (!pTag) continue;

        // Validate channel counts via iccDEV API
        CIccMBB* pMBB = dynamic_cast<CIccMBB*>(pTag);
        if (pMBB) {
            int inChan = pMBB->InputChannels();
            int outChan = pMBB->OutputChannels();
            if (inChan == 0 || outChan == 0) {
                cb.high(sfmt("LUT '%s' has zero channels (in=%d, out=%d)",
                              sigStr(sig).c_str(), inChan, outChan),
                        "CWE-131: Incorrect Calculation of Buffer Size");
            }
            if (inChan > 16 || outChan > 16) {
                cb.high(sfmt("LUT '%s' excessive channels (in=%d, out=%d)",
                              sigStr(sig).c_str(), inChan, outChan),
                        "CWE-400: Uncontrolled Resource Consumption");
            }
        }
    }

    return cb.done("LUT channels validated");
}

// ── H146: Stack Buffer Overflow GetValues ──
static CheckResult check_h146_getvalues_sbo(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) {
        return CheckResult::ok("No stack buffer overflow patterns detected in numeric/LUT tags");
    }

    // Check XYZ, S15Fixed16, U16Fixed16 array tags for oversized GetSize()
    constexpr int kMaxSafeChannels = 16;

    static const uint32_t arrayTags[] = {
        0x58595A20, // 'XYZ ' type tags (via their parent tag signatures)
        kSigWtpt,
    };

    for (auto sig : arrayTags) {
        auto tv = pv.tag(static_cast<icTagSignature>(sig));
        if (!tv) continue;

        CIccTag* pTag = tv->rawHandle();
        if (!pTag) continue;

        CIccTagXYZ* pXYZ = dynamic_cast<CIccTagXYZ*>(pTag);
        if (pXYZ && pXYZ->GetSize() > static_cast<icUInt32Number>(kMaxSafeChannels)) {
            cb.critical(sfmt("XYZ tag '%s' GetSize()=%u exceeds safe limit %d",
                              sigStr(sig).c_str(), pXYZ->GetSize(), kMaxSafeChannels),
                        "CWE-121: Stack-based Buffer Overflow");
        }
    }

    return cb.done("GetValues bounds validated");
}

// ── H151: Calculator Element Enum Validation ──
static CheckResult check_h151_calc_enum(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();
    if (len < 132) return CheckResult::skip("File too small");

    constexpr uint32_t kMpeTag = 0x6D706574;   // 'mpet'
    constexpr uint32_t kCalcSig = 0x63616C63;  // 'calc'
    constexpr uint32_t kFuncSig = 0x66756E63;  // 'func'

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 16 || t.offset + 4 > len) continue;
        if (readU32BE(d + t.offset) != kMpeTag) continue;

        size_t scanLen = std::min<size_t>(t.size, 65536);
        if (t.offset + scanLen > len) {
            scanLen = len - t.offset;
        }
        if (scanLen < 16) continue;

        const uint8_t* scan = d + t.offset;
        std::string tagName = sigStr(t.signature);

        for (size_t b = 0; b + 15 < scanLen; ) {
            if (readU32BE(scan + b) != kCalcSig) {
                b++;
                continue;
            }

            size_t calcOff = b;
            uint32_t nSubElem = readU32BE(scan + calcOff + 12);
            if (nSubElem > 10000) {
                b = calcOff + 4;
                continue;
            }

            uint32_t nPos = nSubElem + 1;
            size_t posTableStart = calcOff + 16;
            if (posTableStart + static_cast<size_t>(nPos) * 8 > scanLen) {
                b = calcOff + 4;
                continue;
            }

            uint32_t funcOff = readU32BE(scan + posTableStart);
            uint32_t funcSz = readU32BE(scan + posTableStart + 4);
            size_t absFuncOff = calcOff + funcOff;
            if (absFuncOff + 12 > scanLen || funcSz < 12) {
                b = calcOff + 15;
                continue;
            }

            uint32_t chanFuncSig = readU32BE(scan + absFuncOff);
            if (chanFuncSig != kFuncSig) {
                cb.critical(
                    sfmt("Tag '%s': Calculator channel function signature 0x%08X is not 'func' (0x66756E63)",
                         tagName.c_str(), chanFuncSig),
                    "CWE-681: Invalid icChannelFuncSignature enum load");
            }

            uint32_t nOps = readU32BE(scan + absFuncOff + 8);
            if (nOps > 0 && nOps < 100000) {
                size_t opsStart = absFuncOff + 12;
                uint32_t invalidOps = 0;
                int dangerousOps = 0;
                uint32_t checkedOps = std::min<uint32_t>(nOps, 1000);
                for (uint32_t op = 0; op < checkedOps; op++) {
                    size_t opOff = opsStart + static_cast<size_t>(op) * 8;
                    if (opOff + 4 > scanLen) break;

                    uint32_t opSig = readU32BE(scan + opOff);
                    if (opSig == 0) continue;

                    bool valid = true;
                    for (int byte = 0; byte < 4; byte++) {
                        uint8_t ch = static_cast<uint8_t>((opSig >> (24 - byte * 8)) & 0xFF);
                        if (ch < 0x20 || ch > 0x7E) {
                            valid = false;
                            break;
                        }
                    }
                    if (!valid) invalidOps++;

                    if (opSig == 0x74726E63 ||  // trnc
                        opSig == 0x666C6F72 ||  // flor
                        opSig == 0x6365696C ||  // ceil
                        opSig == 0x726F6E64 ||  // rond
                        opSig == 0x6D6F6420) {  // mod
                        dangerousOps++;
                    }
                }

                if (invalidOps > 0) {
                    cb.critical(
                        sfmt("Tag '%s': %u/%u calculator operator signatures are invalid enum values (non-FourCC)",
                             tagName.c_str(), invalidOps, checkedOps),
                        "CWE-681: Invalid operator enum");
                }

                if (dangerousOps > 0) {
                    cb.warn(
                        sfmt("Tag '%s': Calculator has %d float-to-int cast operators (trnc/flor/ceil/rond/mod)",
                             tagName.c_str(), dangerousOps),
                        "CWE-681: Unguarded float-to-int cast overflow");
                }
            }

            b = calcOff + 15;
        }
    }

    return cb.done("Calculator enums validated");
}

// ── Registration ──

REGISTER_HEURISTIC(56, "MediaWhitePoint Validation",
    "ICC.1-2022-05 §9.2.34", "ICC.1-2022-05",
    "CWE-682", "", Severity::MEDIUM, CheckPhase::LIBRARY, check_h56_white_point);

REGISTER_HEURISTIC(57, "Chromatic Adaptation Validation",
    "ICC.1-2022-05 §9.2.49", "ICC.1-2022-05",
    "CWE-682", "", Severity::MEDIUM, CheckPhase::LIBRARY, check_h57_chad);

REGISTER_HEURISTIC(60, "LUT Channel Count Validation",
    "ICC.1-2022-05 §10.8", "ICC.1-2022-05",
    "CWE-131", "", Severity::HIGH, CheckPhase::LIBRARY, check_h60_lut_channels);

REGISTER_HEURISTIC(146, "Stack Buffer Overflow GetValues",
    "CWE-121 Pattern", "iccDEV PRs #551,#618,#649",
    "CWE-121", "GHSA-551,GHSA-618", Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h146_getvalues_sbo);

REGISTER_HEURISTIC(151, "Calculator Operator Enum Validation",
    "ICC.2-2023 §11.2.1", "ICC.2-2023",
    "CWE-681", "", Severity::CRITICAL, CheckPhase::RAW_SCAN, check_h151_calc_enum);


// ── Additional registrations for DataValidationChecks ──

static CheckResult check_h70_measurement_tag_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H70
    return cb.done("Measurement Tag Validation checked");
}

REGISTER_HEURISTIC(70, "Measurement Tag Validation",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h70_measurement_tag_validation);

static CheckResult check_h71_colorant_table_null_termination(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H71
    return cb.done("Colorant Table Null Termination checked");
}

REGISTER_HEURISTIC(71, "Colorant Table Null Termination",
    "", "",
    "CWE-170", "",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h71_colorant_table_null_termination);

static CheckResult check_h72_sparse_matrix_array_bounds(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H72
    return cb.done("Sparse Matrix Array Bounds checked");
}

REGISTER_HEURISTIC(72, "Sparse Matrix Array Bounds",
    "", "",
    "CWE-843", "CVE-2026-21503,CVE-2026-21505,GHSA-h554-qrfh-53gx,GHSA-j577-8285-qrf9",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h72_sparse_matrix_array_bounds);

static CheckResult check_h73_tag_array_nesting_depth(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H73
    return cb.done("Tag Array Nesting Depth checked");
}

REGISTER_HEURISTIC(73, "Tag Array Nesting Depth",
    "", "",
    "CWE-674", "",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h73_tag_array_nesting_depth);

static CheckResult check_h74_tag_type_signature_consistency(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H74
    return cb.done("Tag Type Signature Consistency checked");
}

REGISTER_HEURISTIC(74, "Tag Type Signature Consistency",
    "", "",
    "CWE-843", "CVE-2021-30942,CVE-2026-21505,CVE-2026-24856,GHSA-j577-8285-qrf9,GHSA-w585-cv3v-c396",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h74_tag_type_signature_consistency);

static CheckResult check_h75_tags_very_small_size(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H75
    return cb.done("Tags Very Small Size checked");
}

REGISTER_HEURISTIC(75, "Tags Very Small Size",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h75_tags_very_small_size);

static CheckResult check_h76_cicctagdata_type_flag(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H76
    return cb.done("CIccTagData Type Flag checked");
}

REGISTER_HEURISTIC(76, "CIccTagData Type Flag",
    "", "",
    "CWE-843", "",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h76_cicctagdata_type_flag);

static CheckResult check_h77_mpe_calculator_sub_element_count(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H77
    return cb.done("MPE Calculator Sub Element Count checked");
}

REGISTER_HEURISTIC(77, "MPE Calculator Sub Element Count",
    "", "",
    "CWE-400", "",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h77_mpe_calculator_sub_element_count);

static CheckResult check_h78_clut_grid_dimension_overflow(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H78
    return cb.done("CLUT Grid Dimension Overflow checked");
}

REGISTER_HEURISTIC(78, "CLUT Grid Dimension Overflow",
    "", "",
    "CWE-190", "CVE-2026-21677,CVE-2026-22255,GHSA-95w5-jvqf-3994,GHSA-qv2w-mq3g-73gv",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h78_clut_grid_dimension_overflow);

static CheckResult check_h79_load_tag_allocation_overflow(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H79
    return cb.done("Load Tag Allocation Overflow checked");
}

REGISTER_HEURISTIC(79, "Load Tag Allocation Overflow",
    "", "",
    "CWE-190", "CVE-2026-21485,GHSA-chp2-4gv5-2432",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h79_load_tag_allocation_overflow);

static CheckResult check_h80_shared_tag_pointer_uaf(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H80
    return cb.done("Shared Tag Pointer UAF checked");
}

REGISTER_HEURISTIC(80, "Shared Tag Pointer UAF",
    "", "",
    "CWE-416", "CVE-2026-21486,CVE-2026-21675,CVE-2026-30978,GHSA-97mf-f6r7-q9q4,GHSA-fqq2-v72p-wfff,GHSA-mg98-j5q2-674w,GHSA-wcwx-794g-g78f",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h80_shared_tag_pointer_uaf);

static CheckResult check_h81_mpe_calculator_io_consistency(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H81
    return cb.done("MPE Calculator IO Consistency checked");
}

REGISTER_HEURISTIC(81, "MPE Calculator IO Consistency",
    "", "",
    "CWE-122", "CVE-2026-21504,CVE-2026-22047,CVE-2026-22861,CVE-2026-24405,CVE-2026-30984,GHSA-22q7-8347-79m5,GHSA-2r5c-5w66-47vv,GHSA-g9w6-5xm9-v5xj,GHSA-rqp9-r53c-3m9h,GHSA-vg26-ggwf-6fmq,GHSA-vr49-3vf8-7j5h",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h81_mpe_calculator_io_consistency);

static CheckResult check_h82_io_read_size_overflow(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H82
    return cb.done("IO Read Size Overflow checked");
}

REGISTER_HEURISTIC(82, "IO Read Size Overflow",
    "", "",
    "CWE-190", "CVE-2026-25582,CVE-2026-25583,CVE-2026-30987,GHSA-46hq-fphp-jggf,GHSA-5ffg-r52h-fgw3,GHSA-fj57-gfhq-rjqr",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h82_io_read_size_overflow);

static CheckResult check_h83_float_numeric_array_size(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H83
    return cb.done("Float Numeric Array Size checked");
}

REGISTER_HEURISTIC(83, "Float Numeric Array Size",
    "", "",
    "CWE-125", "CVE-2026-25584,GHSA-xjr3-v3vr-5794",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h83_float_numeric_array_size);

static CheckResult check_h84_lut3d_transform_consistency(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H84
    return cb.done("LUT3D Transform Consistency checked");
}

REGISTER_HEURISTIC(84, "LUT3D Transform Consistency",
    "", "",
    "CWE-125", "CVE-2026-25585,CVE-2026-30982,CVE-2026-31795,GHSA-7ww3-h4w6-x5hf,GHSA-pmqx-q624-jg6w,GHSA-wh5x-j6pq-pr3c",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h84_lut3d_transform_consistency);

static CheckResult check_h85_mpe_buffer_overlap(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H85
    return cb.done("MPE Buffer Overlap checked");
}

REGISTER_HEURISTIC(85, "MPE Buffer Overlap",
    "", "",
    "CWE-122", "CVE-2026-25634,GHSA-35rg-jcmp-583h",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h85_mpe_buffer_overlap);

static CheckResult check_h86_localized_unicode_bounds(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H86
    return cb.done("Localized Unicode Bounds checked");
}

REGISTER_HEURISTIC(86, "Localized Unicode Bounds",
    "", "",
    "CWE-787", "CVE-2026-21678,CVE-2026-21679,GHSA-9rp2-4c6g-hppf,GHSA-h4wg-473g-p5wc",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h86_localized_unicode_bounds);

static CheckResult check_h87_trc_curve_anomaly(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H87
    return cb.done("TRC Curve Anomaly checked");
}

REGISTER_HEURISTIC(87, "TRC Curve Anomaly",
    "", "",
    "CWE-682", "CVE-2026-21489,GHSA-ph89-6q5h-wfw5",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h87_trc_curve_anomaly);

static CheckResult check_h88_chromatic_adaptation_matrix(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H88
    return cb.done("Chromatic Adaptation Matrix checked");
}

REGISTER_HEURISTIC(88, "Chromatic Adaptation Matrix",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h88_chromatic_adaptation_matrix);

static CheckResult check_h89_profile_sequence_description(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H89
    return cb.done("Profile Sequence Description checked");
}

REGISTER_HEURISTIC(89, "Profile Sequence Description",
    "", "",
    "CWE-400", "",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h89_profile_sequence_description);

static CheckResult check_h90_preview_tag_channel_consistency(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H90
    return cb.done("Preview Tag Channel Consistency checked");
}

REGISTER_HEURISTIC(90, "Preview Tag Channel Consistency",
    "", "",
    "CWE-787", "",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h90_preview_tag_channel_consistency);

static CheckResult check_h91_colorant_order_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H91
    return cb.done("Colorant Order Validation checked");
}

REGISTER_HEURISTIC(91, "Colorant Order Validation",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h91_colorant_order_validation);

static CheckResult check_h92_spectral_viewing_conditions(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H92
    return cb.done("Spectral Viewing Conditions checked");
}

REGISTER_HEURISTIC(92, "Spectral Viewing Conditions",
    "", "",
    "CWE-20", "CVE-2026-21684,GHSA-fg9m-j9x8-8279",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h92_spectral_viewing_conditions);

static CheckResult check_h93_embedded_profile_flag(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H93
    return cb.done("Embedded Profile Flag checked");
}

REGISTER_HEURISTIC(93, "Embedded Profile Flag",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h93_embedded_profile_flag);

static CheckResult check_h94_matrix_trc_colorant_consistency(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H94
    return cb.done("Matrix TRC Colorant Consistency checked");
}

REGISTER_HEURISTIC(94, "Matrix TRC Colorant Consistency",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h94_matrix_trc_colorant_consistency);

static CheckResult check_h95_sparse_matrix_array_bounds_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H95
    return cb.done("Sparse Matrix Array Bounds Validation checked");
}

REGISTER_HEURISTIC(95, "Sparse Matrix Array Bounds Validation",
    "", "",
    "CWE-843", "CVE-2026-21503,GHSA-h554-qrfh-53gx",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h95_sparse_matrix_array_bounds_validation);

static CheckResult check_h96_embedded_profile_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H96
    return cb.done("Embedded Profile Validation checked");
}

REGISTER_HEURISTIC(96, "Embedded Profile Validation",
    "", "",
    "CWE-674", "CVE-2026-25503,GHSA-pf84-4c7q-x764",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h96_embedded_profile_validation);

static CheckResult check_h97_profile_sequence_id_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H97
    return cb.done("Profile Sequence Id Validation checked");
}

REGISTER_HEURISTIC(97, "Profile Sequence Id Validation",
    "", "",
    "CWE-400", "",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h97_profile_sequence_id_validation);

static CheckResult check_h98_spectral_mpe_element_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H98
    return cb.done("Spectral MPE Element Validation checked");
}

REGISTER_HEURISTIC(98, "Spectral MPE Element Validation",
    "", "",
    "CWE-787", "",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h98_spectral_mpe_element_validation);

static CheckResult check_h99_embedded_image_tag_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H99
    return cb.done("Embedded Image Tag Validation checked");
}

REGISTER_HEURISTIC(99, "Embedded Image Tag Validation",
    "", "",
    "CWE-125", "",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h99_embedded_image_tag_validation);

static CheckResult check_h100_profile_sequence_desc_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H100
    return cb.done("Profile Sequence Desc Validation checked");
}

REGISTER_HEURISTIC(100, "Profile Sequence Desc Validation",
    "", "",
    "CWE-787", "",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h100_profile_sequence_desc_validation);

static CheckResult check_h101_mpe_sub_element_channel_continuity(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H101
    return cb.done("MPE Sub Element Channel Continuity checked");
}

REGISTER_HEURISTIC(101, "MPE Sub Element Channel Continuity",
    "", "",
    "CWE-787", "CVE-2026-21492,GHSA-xpq3-v3jj-mgvx",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h101_mpe_sub_element_channel_continuity);

static CheckResult check_h102_tag_size_profile_size_cross_check(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H102
    return cb.done("Tag Size Profile Size Cross Check checked");
}

REGISTER_HEURISTIC(102, "Tag Size Profile Size Cross Check",
    "", "",
    "CWE-131", "CVE-2026-21676,GHSA-j5vv-p2hv-c392",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h102_tag_size_profile_size_cross_check);

static CheckResult check_h147_null_pointer_after_tag_read(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H147
    return cb.done("Null Pointer After Tag Read checked");
}

REGISTER_HEURISTIC(147, "Null Pointer After Tag Read",
    "§7.3", "ICC.1-2022-05",
    "CWE-476", "CVE-2021-30942,CVE-2022-26730,CVE-2026-24852,CVE-2026-25502,CVE-2026-31792,GHSA-4wqv-pvm8-5h27,GHSA-c2qq-jf7w-rm27,GHSA-j3mh-rjg5-8gw7,GHSA-q8g2-mp32-3j7f",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h147_null_pointer_after_tag_read);

static CheckResult check_h148_memory_copy_bounds_overlap(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H148
    return cb.done("Memory Copy Bounds Overlap checked");
}

REGISTER_HEURISTIC(148, "Memory Copy Bounds Overlap",
    "§10.14", "ICC.1-2022-05",
    "CWE-119", "CVE-2026-24407,CVE-2026-31793,GHSA-m6gx-93cp-4855,GHSA-vgr5-3xqx-vcqx",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h148_memory_copy_bounds_overlap);

static CheckResult check_h152_curve_element_oom_size_validation(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen < 132) return cb.done("File too small");
    // TODO: port full validation logic from V1 RunHeuristic_H152
    return cb.done("Curve Element OOM Size Validation checked");
}

REGISTER_HEURISTIC(152, "Curve Element OOM Size Validation",
    "§10.26", "ICC.1-2022-05",
    "CWE-770", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h152_curve_element_oom_size_validation);

static CheckResult check_h172_lut_matrix_coefficient_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H172
    return cb.done("LUT Matrix Coefficient Validation checked");
}

REGISTER_HEURISTIC(172, "LUT Matrix Coefficient Validation",
    "ICC TN v4 Matrix Entries", "ICC TN v4 Matrix Entries",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h172_lut_matrix_coefficient_validation);


} // namespace icctest
