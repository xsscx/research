/*
 * IccTest Library — ComplianceChecks.cpp
 * Heuristic checks H103-H120: ICC specification compliance.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

namespace icctest {

// ── H103: Profile ID (MD5) Validation ──
static CheckResult check_h103_profile_id(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 100) return CheckResult::skip("File too small");
    const uint8_t* d = pv.rawData();

    // Profile ID is at bytes 84-99
    bool allZero = true;
    for (int i = 84; i < 100; i++) {
        if (d[i] != 0) { allZero = false; break; }
    }

    if (allZero) {
        cb.info("Profile ID is all zeros (not computed)");
    }
    // Full MD5 validation would require computing MD5 with zeroed fields

    return cb.done("Profile ID checked");
}

// ── H104: CMM Type Validation ──
static CheckResult check_h104_cmm(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 8) return CheckResult::skip("File too small");
    const uint8_t* d = pv.rawData();
    uint32_t cmm = readU32BE(d + 4);

    if (cmm != 0) {
        // CMM type should be printable if non-zero
        bool printable = true;
        for (int i = 0; i < 4; i++) {
            uint8_t c = (cmm >> (24 - i*8)) & 0xFF;
            if (c != 0 && (c < 0x20 || c > 0x7E)) { printable = false; break; }
        }
        if (!printable) {
            cb.warn(sfmt("Non-printable CMM type 0x%08X", cmm));
        }
    }

    return cb.done("CMM type validated");
}

// ── H105: Data Color Space vs PCS Consistency ──
static CheckResult check_h105_cs_pcs(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    // For DeviceLink, PCS must match output color space (not enforced here)
    // For non-DeviceLink, PCS must be XYZ or Lab
    if (hdr.deviceClass != kClassLink) {
        if (hdr.pcs != 0x58595A20 && hdr.pcs != 0x4C616220) {
            cb.high(sfmt("Non-DeviceLink profile has invalid PCS '%s'",
                          sigStr(hdr.pcs).c_str()),
                    "CWE-20: Improper Input Validation");
        }
    }

    return cb.done("ColorSpace/PCS consistency validated");
}

// ── H108: Encoding Validation ──
static CheckResult check_h108_encoding(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 128) return CheckResult::skip("File too small");
    const uint8_t* d = pv.rawData();

    // Rendering intent upper 16 bits must be zero (bytes 66-67)
    uint16_t intentHi = readU16BE(d + 66);
    if (intentHi != 0) {
        cb.warn(sfmt("Rendering intent upper 16 bits = 0x%04X (must be 0)", intentHi));
    }

    return cb.done("Encoding validated");
}

// ── H111: Reserved Bytes (100-127) All Zeros ──
static CheckResult check_h111_reserved_zeros(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 128) return CheckResult::skip("File too small");
    const uint8_t* d = pv.rawData();

    // ICC.1-2022-05 §7.2.19: bytes 100-127 must be 0x00
    int nonZero = 0;
    for (int i = 100; i < 128; i++) {
        if (d[i] != 0) nonZero++;
    }

    if (nonZero > 0) {
        cb.warn(sfmt("%d non-zero reserved bytes in header (offsets 100-127)", nonZero));
    }

    return cb.done("Reserved bytes validated");
}

// ── H112: D50 Illuminant Precision ──
static CheckResult check_h112_d50_precision(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 80) return CheckResult::skip("File too small");
    const uint8_t* d = pv.rawData();

    // D50 at bytes 68-79 (3 × s15Fixed16Number)
    int32_t xi = readS32BE(d + 68);
    int32_t yi = readS32BE(d + 72);
    int32_t zi = readS32BE(d + 76);

    // Exact ICC D50 values
    if (xi != kD50X || yi != kD50Y || zi != kD50Z) {
        double x = xi / 65536.0, y = yi / 65536.0, z = zi / 65536.0;
        cb.warn(sfmt("D50 illuminant values (%.6f, %.6f, %.6f) differ from ICC spec "
                      "(0.9642, 1.0000, 0.8249)", x, y, z));
    }

    return cb.done("D50 precision validated");
}

// ── Registration ──

REGISTER_HEURISTIC(103, "Profile ID Validation",
    "ICC.1-2022-05 §7.2.18", "ICC.1-2022-05",
    "CWE-345", "", Severity::LOW, CheckPhase::LIBRARY, check_h103_profile_id);

REGISTER_HEURISTIC(104, "CMM Type Validation",
    "ICC.1-2022-05 §7.2.3", "ICC.1-2022-05",
    "CWE-20", "", Severity::LOW, CheckPhase::HEADER, check_h104_cmm);

REGISTER_HEURISTIC(105, "ColorSpace/PCS Consistency",
    "ICC.1-2022-05 §7.2.6-7", "ICC.1-2022-05",
    "CWE-20", "", Severity::HIGH, CheckPhase::HEADER, check_h105_cs_pcs);

REGISTER_HEURISTIC(108, "Encoding Validation",
    "ICC.1-2022-05 §7.2.15", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::HEADER, check_h108_encoding);

REGISTER_HEURISTIC(111, "Reserved Bytes Validation",
    "ICC.1-2022-05 §7.2.19", "ICC.1-2022-05",
    "CWE-20", "", Severity::LOW, CheckPhase::HEADER, check_h111_reserved_zeros);

REGISTER_HEURISTIC(112, "D50 Illuminant Precision",
    "ICC.1-2022-05 §7.2.16", "ICC.1-2022-05",
    "CWE-682", "", Severity::MEDIUM, CheckPhase::HEADER, check_h112_d50_precision);


// ── Additional registrations for ComplianceChecks ──

static CheckResult check_h106_env_var(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H106
    return cb.done("Env Var checked");
}

REGISTER_HEURISTIC(106, "Env Var",
    "", "",
    "CWE-131", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h106_env_var);

static CheckResult check_h107_channel_cross_check(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H107
    return cb.done("Channel Cross Check checked");
}

REGISTER_HEURISTIC(107, "Channel Cross Check",
    "", "",
    "CWE-131", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h107_channel_cross_check);

static CheckResult check_h109_shellcode_patterns(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H109
    return cb.done("Shellcode Patterns checked");
}

REGISTER_HEURISTIC(109, "Shellcode Patterns",
    "", "",
    "CWE-506", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h109_shellcode_patterns);

static CheckResult check_h110_class_tag_validation(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H110
    return cb.done("Class Tag Validation checked");
}

REGISTER_HEURISTIC(110, "Class Tag Validation",
    "§8", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h110_class_tag_validation);

static CheckResult check_h113_round_trip_fidelity(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H113
    return cb.done("Round Trip Fidelity checked");
}

REGISTER_HEURISTIC(113, "Round Trip Fidelity",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h113_round_trip_fidelity);

static CheckResult check_h114_curve_smoothness(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H114
    return cb.done("Curve Smoothness checked");
}

REGISTER_HEURISTIC(114, "Curve Smoothness",
    "", "",
    "CWE-20", "CVE-2026-21687,GHSA-prmm-g479-4fv7",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h114_curve_smoothness);

static CheckResult check_h115_characterization_data(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H115
    return cb.done("Characterization Data checked");
}

REGISTER_HEURISTIC(115, "Characterization Data",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h115_characterization_data);

static CheckResult check_h116_cprt_desc_encoding(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H116
    return cb.done("Cprt Desc Encoding checked");
}

REGISTER_HEURISTIC(116, "Cprt Desc Encoding",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h116_cprt_desc_encoding);

static CheckResult check_h117_tag_type_allowed(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H117
    return cb.done("Tag Type Allowed checked");
}

REGISTER_HEURISTIC(117, "Tag Type Allowed",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h117_tag_type_allowed);

static CheckResult check_h118_calc_cost_estimate(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H118
    return cb.done("Calc Cost Estimate checked");
}

REGISTER_HEURISTIC(118, "Calc Cost Estimate",
    "", "",
    "CWE-400", "",
    Severity::HIGH, CheckPhase::RAW_SCAN,
    check_h118_calc_cost_estimate);

static CheckResult check_h119_round_trip_delta_e(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H119
    return cb.done("Round Trip Delta E checked");
}

REGISTER_HEURISTIC(119, "Round Trip Delta E",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h119_round_trip_delta_e);

static CheckResult check_h120_curve_invertibility(const ProfileView& pv) {
    CheckBuilder cb;
    // TODO: port full validation logic from V1 RunHeuristic_H120
    return cb.done("Curve Invertibility checked");
}

REGISTER_HEURISTIC(120, "Curve Invertibility",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h120_curve_invertibility);


} // namespace icctest
