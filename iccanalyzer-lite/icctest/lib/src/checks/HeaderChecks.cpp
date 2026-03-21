/*
 * IccTest Library — HeaderChecks.cpp
 * Heuristic checks H1-H8, H15-H17: Raw header byte validation.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

namespace icctest {

// ── H1: Profile Size Validation ──
static CheckResult check_h1_size(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    if (pv.rawSize() < 128) {
        cb.critical(sfmt("File too small for ICC header (need 128, got %zu)", pv.rawSize()),
                    "CWE-131: Incorrect Calculation of Buffer Size");
        return cb.done("Profile size validated");
    }

    if (hdr.size != pv.rawSize()) {
        cb.high(sfmt("Header size (%u) != file size (%zu) — ICC.1-2022-05 §7.2.2",
                      hdr.size, pv.rawSize()),
                "CWE-131: Incorrect Calculation of Buffer Size");
    }

    if (hdr.size < 128) {
        cb.high(sfmt("Header declares size %u (< 128 minimum)", hdr.size),
                "CWE-131: Incorrect Calculation of Buffer Size");
    }

    if (hdr.size > 100 * 1024 * 1024) {
        cb.warn(sfmt("Profile size %u exceeds 100 MB — potential DoS", hdr.size),
                "CWE-400: Uncontrolled Resource Consumption");
    }

    return cb.done("Profile size validated");
}

// ── H2: Magic Number Validation ──
static CheckResult check_h2_magic(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    if (hdr.magic != kIccMagic) {
        cb.critical(sfmt("Invalid magic 0x%08X (expected 'acsp' = 0x61637370)", hdr.magic),
                    "CWE-345: Insufficient Verification of Data Authenticity");
    }

    return cb.done("Magic number valid");
}

// ── H3: Version Validation ──
static CheckResult check_h3_version(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();
    uint8_t major = (hdr.version >> 24) & 0xFF;
    uint8_t minor_bugfix = (hdr.version >> 16) & 0xFF;
    uint16_t zero_bits = hdr.version & 0xFFFF;

    if (major == 0 || major > 5) {
        cb.high(sfmt("Invalid major version %u (expected 2-5)", major),
                "CWE-20: Improper Input Validation");
    }

    if (zero_bits != 0) {
        cb.warn(sfmt("Version bytes 10-11 = 0x%04X (must be 0x0000) — ICC.1-2022-05 §7.2.4",
                      zero_bits));
    }

    // Check minor nibble validity
    uint8_t minor = (minor_bugfix >> 4) & 0x0F;
    uint8_t bugfix = minor_bugfix & 0x0F;
    if (minor > 9 || bugfix > 9) {
        cb.warn(sfmt("Non-BCD version encoding: minor=%u bugfix=%u", minor, bugfix));
    }

    return cb.done("Version validated");
}

// ── H4: Profile/Device Class Validation ──
static CheckResult check_h4_class(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();
    uint32_t cls = hdr.deviceClass;

    static const uint32_t kValidClasses[] = {
        kClassInput, kClassDisplay, kClassOutput, kClassLink,
        kClassColorSpace, kClassAbstract, kClassNamedColor
    };

    bool valid = false;
    for (auto c : kValidClasses) {
        if (cls == c) { valid = true; break; }
    }

    if (!valid) {
        cb.high(sfmt("Unknown device class '%s' (0x%08X)", sigStr(cls).c_str(), cls),
                "CWE-20: Improper Input Validation");
    }

    return cb.done("Device class valid");
}

// ── H5: Color Space Validation ──
static CheckResult check_h5_colorspace(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();
    uint32_t cs = hdr.colorSpace;

    static const uint32_t kValid[] = {
        0x58595A20, // 'XYZ '
        0x4C616220, // 'Lab '
        0x4C757620, // 'Luv '
        0x59436272, // 'YCbr'
        0x59787920, // 'Yxy '
        0x52474220, // 'RGB '
        0x47524159, // 'GRAY'
        0x48535620, // 'HSV '
        0x484C5320, // 'HLS '
        0x434D594B, // 'CMYK'
        0x434D5920, // 'CMY '
        0x32434C52, // '2CLR'
        0x33434C52, // '3CLR'
        0x34434C52, // '4CLR'
        0x35434C52, // '5CLR'
        0x36434C52, // '6CLR'
        0x37434C52, // '7CLR'
        0x38434C52, // '8CLR'
        0x39434C52, // '9CLR'
        0x41434C52, // 'ACLR'
        0x42434C52, // 'BCLR'
        0x43434C52, // 'CCLR'
        0x44434C52, // 'DCLR'
        0x45434C52, // 'ECLR'
        0x46434C52, // 'FCLR'
    };

    bool valid = false;
    for (auto v : kValid) {
        if (cs == v) { valid = true; break; }
    }

    if (!valid) {
        cb.warn(sfmt("Unrecognized color space '%s' (0x%08X)", sigStr(cs).c_str(), cs));
    }

    return cb.done("Color space validated");
}

// ── H6: PCS Validation ──
static CheckResult check_h6_pcs(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();
    uint32_t cls = hdr.deviceClass;

    // DeviceLink profiles can have any PCS; others must be XYZ or Lab
    if (cls != kClassLink) {
        if (hdr.pcs != 0x58595A20 && hdr.pcs != 0x4C616220) {
            cb.high(sfmt("Invalid PCS '%s' (must be 'XYZ ' or 'Lab ') — ICC.1-2022-05 §7.2.7",
                          sigStr(hdr.pcs).c_str()),
                    "CWE-20: Improper Input Validation");
        }
    }

    return cb.done("PCS validated");
}

// ── H7: Rendering Intent Validation ──
static CheckResult check_h7_intent(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    uint32_t intent = hdr.renderingIntent;
    if (intent > 3) {
        cb.high(sfmt("Invalid rendering intent %u (max 3) — ICC.1-2022-05 §7.2.15", intent),
                "CWE-20: Improper Input Validation");
    }

    return cb.done("Rendering intent valid");
}

// ── H8: PCS Illuminant (D50) Validation ──
static CheckResult check_h8_illuminant(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    if (hdr.illuminantX != kD50X || hdr.illuminantY != kD50Y || hdr.illuminantZ != kD50Z) {
        double x = hdr.illuminantX / 65536.0;
        double y = hdr.illuminantY / 65536.0;
        double z = hdr.illuminantZ / 65536.0;
        cb.warn(sfmt("PCS illuminant (%.4f, %.4f, %.4f) != D50 (0.9642, 1.0, 0.8249) — §7.2.16",
                      x, y, z));
    }

    return cb.done("PCS illuminant valid");
}

// ── H15: Date/Time Validation ──
static CheckResult check_h15_datetime(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    if (hdr.year < 1900 || hdr.year > 2100) {
        cb.warn(sfmt("Suspicious creation year %u", hdr.year));
    }
    if (hdr.month == 0 || hdr.month > 12) {
        cb.warn(sfmt("Invalid creation month %u", hdr.month));
    }
    if (hdr.day == 0 || hdr.day > 31) {
        cb.warn(sfmt("Invalid creation day %u", hdr.day));
    }
    if (hdr.hour > 23) {
        cb.warn(sfmt("Invalid creation hour %u", hdr.hour));
    }
    if (hdr.minute > 59) {
        cb.warn(sfmt("Invalid creation minute %u", hdr.minute));
    }
    if (hdr.second > 59) {
        cb.warn(sfmt("Invalid creation second %u", hdr.second));
    }

    return cb.done("Date/time validated");
}

// ── H16: Platform Validation ──
static CheckResult check_h16_platform(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    static const uint32_t kValid[] = {
        0x4150504C, // 'APPL' (Apple)
        0x4D534654, // 'MSFT' (Microsoft)
        0x53474920, // 'SGI ' (Silicon Graphics)
        0x53554E57, // 'SUNW' (Sun)
        0x00000000, // Unspecified
    };

    bool valid = false;
    for (auto v : kValid) {
        if (hdr.platform == v) { valid = true; break; }
    }

    if (!valid) {
        cb.info(sfmt("Non-standard platform '%s' (0x%08X)", sigStr(hdr.platform).c_str(),
                      hdr.platform));
    }

    return cb.done("Platform validated");
}

// ── H17: Spectral PCS Validation (v5) ──
static CheckResult check_h17_spectral(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    uint8_t major = (hdr.version >> 24) & 0xFF;
    if (major < 5) return CheckResult::skip("Pre-v5 profile — spectral PCS N/A");

    // For v5 profiles, check spectral PCS range fields at bytes 100-107
    if (pv.rawSize() >= 128) {
        const uint8_t* h = pv.rawData();
        uint16_t spectralPCS   = readU16BE(h + 100);
        uint16_t spectralStart = readU16BE(h + 102);
        uint16_t spectralEnd   = readU16BE(h + 104);
        uint16_t spectralSteps = readU16BE(h + 106);

        if (spectralPCS != 0) {
            if (spectralStart == 0 || spectralEnd == 0 || spectralSteps == 0) {
                cb.warn("Spectral PCS declared but wavelength range is zero");
            }
            if (spectralStart >= spectralEnd) {
                cb.warn(sfmt("Spectral range inverted: start=%u >= end=%u",
                              spectralStart, spectralEnd));
            }
        }
    }

    return cb.done("Spectral PCS validated");
}

// ── Registration ──

REGISTER_HEURISTIC(1, "Profile Size Validation",
    "ICC.1-2022-05 §7.2.2", "ICC.1-2022-05",
    "CWE-131", "", Severity::HIGH, CheckPhase::HEADER, check_h1_size);

REGISTER_HEURISTIC(2, "Magic Number Validation",
    "ICC.1-2022-05 §7.2.9", "ICC.1-2022-05",
    "CWE-345", "", Severity::CRITICAL, CheckPhase::HEADER, check_h2_magic);

REGISTER_HEURISTIC(3, "Version Validation",
    "ICC.1-2022-05 §7.2.4", "ICC.1-2022-05",
    "CWE-20", "", Severity::HIGH, CheckPhase::HEADER, check_h3_version);

REGISTER_HEURISTIC(4, "Device Class Validation",
    "ICC.1-2022-05 §7.2.5", "ICC.1-2022-05",
    "CWE-20", "", Severity::HIGH, CheckPhase::HEADER, check_h4_class);

REGISTER_HEURISTIC(5, "Color Space Validation",
    "ICC.1-2022-05 §7.2.6", "ICC.1-2022-05",
    "CWE-20", "", Severity::MEDIUM, CheckPhase::HEADER, check_h5_colorspace);

REGISTER_HEURISTIC(6, "PCS Validation",
    "ICC.1-2022-05 §7.2.7", "ICC.1-2022-05",
    "CWE-20", "", Severity::HIGH, CheckPhase::HEADER, check_h6_pcs);

REGISTER_HEURISTIC(7, "Rendering Intent Validation",
    "ICC.1-2022-05 §7.2.15", "ICC.1-2022-05",
    "CWE-20", "", Severity::HIGH, CheckPhase::HEADER, check_h7_intent);

REGISTER_HEURISTIC(8, "PCS Illuminant D50 Validation",
    "ICC.1-2022-05 §7.2.16", "ICC.1-2022-05",
    "CWE-682", "", Severity::MEDIUM, CheckPhase::HEADER, check_h8_illuminant);

REGISTER_HEURISTIC(15, "Creation Date/Time Validation",
    "ICC.1-2022-05 §7.2.8", "ICC.1-2022-05",
    "CWE-20", "", Severity::LOW, CheckPhase::HEADER, check_h15_datetime);

REGISTER_HEURISTIC(16, "Primary Platform Validation",
    "ICC.1-2022-05 §7.2.10", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::HEADER, check_h16_platform);

REGISTER_HEURISTIC(17, "Spectral PCS Validation",
    "ICC.2-2023 §7.2.X", "ICC.2-2023",
    "CWE-20", "", Severity::MEDIUM, CheckPhase::HEADER, check_h17_spectral);

} // namespace icctest
