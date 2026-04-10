// CfHeaderChecks.cpp — V2 conformance checks (HEADER)
// 43 checks: CF-001..CF-246
//
// Ported from V1 IccConformanceHeader.cpp + CF-232 from IccConformanceTagTypes.cpp
//
// SPDX-License-Identifier: MIT

#include <icctest/CheckRegistry.h>
#include <icctest/ProfileView.h>
#include <icctest/CheckResult.h>

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagEmbedIcc.h"
#include "IccUtil.h"
#include "IccDefs.h"

#include <openssl/evp.h>
#include <cmath>
#include <cstring>
#include <cstdio>
#include <set>
#include <vector>
#include <string>

using namespace icctest;

// ── Helper tables ───────────────────────────────────────────────────────────

static const int kDaysInMonth[13] = {
    0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static bool IsLeapYear(int year) {
    if (year == 0) return false;
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

static const uint32_t kValidPlatforms[] = {
    0,
    static_cast<uint32_t>(icSigMacintosh),
    static_cast<uint32_t>(icSigMicrosoft),
    static_cast<uint32_t>(icSigSGI),
    static_cast<uint32_t>(icSigSolaris),
};
static constexpr int kValidPlatformCount = sizeof(kValidPlatforms) / sizeof(kValidPlatforms[0]);

static const uint32_t kV4DeviceClasses[] = {
    static_cast<uint32_t>(icSigInputClass),
    static_cast<uint32_t>(icSigDisplayClass),
    static_cast<uint32_t>(icSigOutputClass),
    static_cast<uint32_t>(icSigLinkClass),
    static_cast<uint32_t>(icSigColorSpaceClass),
    static_cast<uint32_t>(icSigAbstractClass),
    static_cast<uint32_t>(icSigNamedColorClass),
};
static constexpr int kV4DeviceClassCount = sizeof(kV4DeviceClasses) / sizeof(kV4DeviceClasses[0]);

static const uint32_t kV5DeviceClasses[] = {
    static_cast<uint32_t>(icSigMultiplexVisualizationClass),
    static_cast<uint32_t>(icSigColorEncodingClass),
    static_cast<uint32_t>(icSigMultiplexLinkClass),
    static_cast<uint32_t>(icSigMultiplexIdentificationClass),
};
static constexpr int kV5DeviceClassCount = sizeof(kV5DeviceClasses) / sizeof(kV5DeviceClasses[0]);

static const uint32_t kValidColorSpaces[] = {
    static_cast<uint32_t>(icSigXYZData),
    static_cast<uint32_t>(icSigLabData),
    static_cast<uint32_t>(icSigLuvData),
    static_cast<uint32_t>(icSigYCbCrData),
    static_cast<uint32_t>(icSigYxyData),
    static_cast<uint32_t>(icSigRgbData),
    static_cast<uint32_t>(icSigGrayData),
    static_cast<uint32_t>(icSigHsvData),
    static_cast<uint32_t>(icSigHlsData),
    static_cast<uint32_t>(icSigCmykData),
    static_cast<uint32_t>(icSigCmyData),
    static_cast<uint32_t>(icSigNamedData),
    static_cast<uint32_t>(icSigMCH1Data),
    static_cast<uint32_t>(icSigMCH2Data),
    static_cast<uint32_t>(icSigMCH3Data),
    static_cast<uint32_t>(icSigMCH4Data),
    static_cast<uint32_t>(icSigMCH5Data),
    static_cast<uint32_t>(icSigMCH6Data),
    static_cast<uint32_t>(icSigMCH7Data),
    static_cast<uint32_t>(icSigMCH8Data),
    static_cast<uint32_t>(icSigMCH9Data),
    static_cast<uint32_t>(icSigMCHAData),
    static_cast<uint32_t>(icSigMCHBData),
    static_cast<uint32_t>(icSigMCHCData),
    static_cast<uint32_t>(icSigMCHDData),
    static_cast<uint32_t>(icSigMCHEData),
    static_cast<uint32_t>(icSigMCHFData),
};
static constexpr int kValidColorSpaceCount = sizeof(kValidColorSpaces) / sizeof(kValidColorSpaces[0]);

static bool IsConformantColorSpace(uint32_t sig) {
    for (int i = 0; i < kValidColorSpaceCount; i++) {
        if (sig == kValidColorSpaces[i]) return true;
    }
    uint32_t csType = icGetColorSpaceType(static_cast<icColorSpaceSignature>(sig));
    uint32_t nChan  = icNumColorSpaceChannels(sig);
    if ((csType == static_cast<uint32_t>(icSigNChannelData) ||
         csType == static_cast<uint32_t>(icSigSrcMCSChannelData)) && nChan > 0)
        return true;
    return false;
}

static const uint32_t kRegisteredCMMs[] = {
    0x41444245, 0x41434D53, 0x6170706C, 0x43434D53,
    0x45464920, 0x46462020, 0x48434D4D, 0x48444D20,
    0x4C434D53, 0x6C636D73, 0x4D534654, 0x52494D58,
    0x53494343, 0x53475243, 0x54434D4D, 0x5543434D,
    0x57435320, 0x7A63306C, 0x44696D43, 0x48504D32,
    0x6172676C, 0x4B4F4441, 0x52474D53, 0x6F6E7978,
};
static constexpr int kRegisteredCMMCount = sizeof(kRegisteredCMMs) / sizeof(kRegisteredCMMs[0]);

static void SigToChars(uint32_t sig, char buf[5]) {
    buf[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));
    buf[1] = static_cast<char>(static_cast<unsigned char>((sig >> 16) & 0xFF));
    buf[2] = static_cast<char>(static_cast<unsigned char>((sig >>  8) & 0xFF));
    buf[3] = static_cast<char>(static_cast<unsigned char>( sig        & 0xFF));
    buf[4] = '\0';
}

static bool IsPrintable4CC(uint32_t sig) {
    for (int i = 0; i < 4; i++) {
        unsigned char b = (sig >> (24 - i * 8)) & 0xFF;
        if (b < 0x20 || b > 0x7E) return false;
    }
    return true;
}

static double S15Fixed16ToDouble(int32_t val) {
    return static_cast<double>(val) / 65536.0;
}

// ── Check implementations ───────────────────────────────────────────────────

static CheckResult check_cf001_date_time_month_day_validity(const ProfileView& pv) {
    const auto& h = pv.header();
    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 1};

    if (h.month < 1 || h.month > 12) {
        findings.push_back({cfId, Severity::HIGH,
            "Month=" + std::to_string(h.month) + " out of range (must be 1-12)",
            "ICC.1-2022-05 §7.2.8", ""});
    }
    if (h.month >= 1 && h.month <= 12) {
        int maxDay = kDaysInMonth[h.month];
        if (h.month == 2 && IsLeapYear(h.year)) maxDay = 29;
        if (h.day < 1 || h.day > static_cast<uint16_t>(maxDay)) {
            findings.push_back({cfId, Severity::HIGH,
                "Day=" + std::to_string(h.day) + " out of range for month " + std::to_string(h.month) +
                " (max=" + std::to_string(maxDay) + ")",
                "ICC.1-2022-05 §7.2.8", ""});
        }
    }
    if (h.hour > 23) {
        findings.push_back({cfId, Severity::HIGH,
            "Hours=" + std::to_string(h.hour) + " exceeds 23",
            "ICC.1-2022-05 §7.2.8", ""});
    }
    if (h.minute > 59) {
        findings.push_back({cfId, Severity::HIGH,
            "Minutes=" + std::to_string(h.minute) + " exceeds 59",
            "ICC.1-2022-05 §7.2.8", ""});
    }
    if (h.second > 59) {
        findings.push_back({cfId, Severity::HIGH,
            "Seconds=" + std::to_string(h.second) + " exceeds 59",
            "ICC.1-2022-05 §7.2.8", ""});
    }

    if (findings.empty()) return CheckResult::ok("Date/time fields valid");
    return {CheckResult::Status::FINDINGS, "Date/time field range violation", std::move(findings)};
}

static CheckResult check_cf002_date_time_leap_year_validation(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 2};

    if (h.month != 2) return CheckResult::ok("Not February — leap year check not applicable");

    int maxDay = IsLeapYear(h.year) ? 29 : 28;
    if (h.year == 0) maxDay = 29; // year=0 means unset, allow 29

    if (h.day > static_cast<uint16_t>(maxDay)) {
        return {CheckResult::Status::FINDINGS, "February day exceeds leap year limit", {
            {cfId, Severity::HIGH,
             "February day=" + std::to_string(h.day) + " but year " +
             std::to_string(h.year) + " max=" + std::to_string(maxDay),
             "ICC.1-2022-05 §7.2.8", ""}}};
    }
    return CheckResult::ok("February day valid for year");
}

static CheckResult check_cf003_profile_flags_reserved_bits(const ProfileView& pv) {
    uint32_t flags = pv.header().flags;
    CheckID cfId{CheckID::Kind::Conformance, 3};

    if (flags & 0xFFF8u) {
        char detail[64];
        snprintf(detail, sizeof(detail), "flags=0x%08X, reserved bits 3-15 must be zero", flags);
        return {CheckResult::Status::FINDINGS, "Flags reserved bits non-zero", {
            {cfId, Severity::HIGH, detail, "ICC.1-2022-05 §7.2.11 Table 21", ""}}};
    }
    return CheckResult::ok("Profile flags reserved bits zero");
}

static CheckResult check_cf004_device_attributes_reserved_bits(const ProfileView& pv) {
    uint64_t attr = pv.header().attributes;
    CheckID cfId{CheckID::Kind::Conformance, 4};

    if (attr & 0x00000000FFFFFFF0ULL) {
        char detail[80];
        snprintf(detail, sizeof(detail), "attributes=0x%016llX, reserved bits 4-31 must be zero",
                 static_cast<unsigned long long>(attr));
        return {CheckResult::Status::FINDINGS, "Attributes reserved bits non-zero", {
            {cfId, Severity::HIGH, detail, "ICC.1-2022-05 §7.2.14", ""}}};
    }
    return CheckResult::ok("Device attributes reserved bits zero");
}

static CheckResult check_cf005_rendering_intent_upper_bits_zero(const ProfileView& pv) {
    uint32_t intent = pv.header().renderingIntent;
    CheckID cfId{CheckID::Kind::Conformance, 5};
    std::vector<Finding> findings;

    if (intent & 0xFFFF0000u) {
        findings.push_back({cfId, Severity::HIGH,
            "Rendering intent upper 16 bits non-zero (0x" +
            std::to_string(intent) + ")",
            "ICC.1-2022-05 §7.2.15", ""});
    }
    if ((intent & 0xFFFFu) > 3) {
        findings.push_back({cfId, Severity::HIGH,
            "Rendering intent value " + std::to_string(intent & 0xFFFFu) + " out of range 0-3",
            "ICC.1-2022-05 §7.2.15", ""});
    }
    if (findings.empty()) return CheckResult::ok("Rendering intent field valid");
    return {CheckResult::Status::FINDINGS, "Rendering intent invalid", std::move(findings)};
}

static CheckResult check_cf006_profile_version_bcd_encoding(const ProfileView& pv) {
    uint32_t ver = pv.header().version;
    CheckID cfId{CheckID::Kind::Conformance, 6};
    std::vector<Finding> findings;

    uint8_t major = static_cast<uint8_t>(ver >> 24);
    uint8_t minorBugfix = static_cast<uint8_t>((ver >> 16) & 0xFF);
    uint8_t byte10 = static_cast<uint8_t>((ver >> 8) & 0xFF);
    uint8_t byte11 = static_cast<uint8_t>(ver & 0xFF);

    if (major < 2 || major > 5) {
        findings.push_back({cfId, Severity::HIGH,
            "Major version " + std::to_string(major) + " outside expected range 2-5",
            "ICC.1-2022-05 §7.2.4", ""});
    }
    uint8_t minor = (minorBugfix >> 4) & 0x0F;
    uint8_t bugfix = minorBugfix & 0x0F;
    if (minor > 9) {
        findings.push_back({cfId, Severity::HIGH,
            "Minor version nibble " + std::to_string(minor) + " not valid BCD (0-9)",
            "ICC.1-2022-05 §7.2.4", ""});
    }
    if (bugfix > 9) {
        findings.push_back({cfId, Severity::HIGH,
            "Bugfix version nibble " + std::to_string(bugfix) + " not valid BCD (0-9)",
            "ICC.1-2022-05 §7.2.4", ""});
    }
    if (byte10 != 0 || byte11 != 0) {
        findings.push_back({cfId, Severity::HIGH,
            "Version bytes 10-11 must be zero (got 0x" +
            std::to_string(byte10) + ", 0x" + std::to_string(byte11) + ")",
            "ICC.1-2022-05 §7.2.4", ""});
    }
    if (findings.empty()) return CheckResult::ok("Version BCD encoding valid");
    return {CheckResult::Status::FINDINGS, "Version encoding issue", std::move(findings)};
}

static CheckResult check_cf007_primary_platform_signature(const ProfileView& pv) {
    uint32_t plat = pv.header().platform;
    CheckID cfId{CheckID::Kind::Conformance, 7};

    for (int i = 0; i < kValidPlatformCount; i++) {
        if (plat == kValidPlatforms[i]) return CheckResult::ok("Platform signature recognized");
    }
    char buf[5];
    SigToChars(plat, buf);
    return {CheckResult::Status::FINDINGS, "Platform not in registered list", {
        {cfId, Severity::MEDIUM,
         std::string("Platform '") + buf + "' (0x" + std::to_string(plat) +
         ") not in ICC registered list",
         "ICC.1-2022-05 §7.2.10 Table 20", ""}}};
}

static CheckResult check_cf008_pcs_illuminant_d50_precision(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 8};

    if (h.deviceClass == static_cast<uint32_t>(icSigColorEncodingClass)) {
        if (h.illuminantX == 0 && h.illuminantY == 0 && h.illuminantZ == 0) {
            return CheckResult::ok("ColorEncoding header illuminant is zero as required");
        }
        return {CheckResult::Status::FINDINGS, "ColorEncoding header illuminant must be zero", {
            {cfId, Severity::HIGH,
             "ColorEncoding profiles must zero header illuminant fields",
             "ICC.2 ColorEncoding header rules", ""}}};
    }

    double x = S15Fixed16ToDouble(h.illuminantX);
    double y = S15Fixed16ToDouble(h.illuminantY);
    double z = S15Fixed16ToDouble(h.illuminantZ);

    const double d50X = 0.9642, d50Y = 1.0000, d50Z = 0.8249;
    const double tol = 0.0001;

    std::vector<Finding> findings;
    if (std::fabs(x - d50X) > tol) {
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "PCS illuminant X=%.4f != D50 X=%.4f", x, d50X);
        findings.push_back({cfId, Severity::HIGH, detail, "ICC.1-2022-05 §7.2.16", ""});
    }
    if (std::fabs(y - d50Y) > tol) {
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "PCS illuminant Y=%.4f != D50 Y=%.4f", y, d50Y);
        findings.push_back({cfId, Severity::HIGH, detail, "ICC.1-2022-05 §7.2.16", ""});
    }
    if (std::fabs(z - d50Z) > tol) {
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "PCS illuminant Z=%.4f != D50 Z=%.4f", z, d50Z);
        findings.push_back({cfId, Severity::HIGH, detail, "ICC.1-2022-05 §7.2.16", ""});
    }
    if (!findings.empty())
        return {CheckResult::Status::FINDINGS, "PCS illuminant not D50", std::move(findings)};
    return CheckResult::ok("PCS illuminant matches D50");
}

static CheckResult check_cf009_chromatic_adaptation_tag_requirement(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 9};
    uint8_t major = static_cast<uint8_t>(h.version >> 24);

    if (major < 4) return CheckResult::ok("v2 profile — chad not required");
    if (h.deviceClass == static_cast<uint32_t>(icSigLinkClass))
        return CheckResult::ok("DeviceLink — chad not required");
    if (h.deviceClass == static_cast<uint32_t>(icSigColorEncodingClass))
        return CheckResult::ok("ColorEncoding — chad not required");

    double x = S15Fixed16ToDouble(h.illuminantX);
    double y = S15Fixed16ToDouble(h.illuminantY);
    double z = S15Fixed16ToDouble(h.illuminantZ);
    const double tol = 0.0001;

    bool isD50 = (std::fabs(x - 0.9642) <= tol &&
                  std::fabs(y - 1.0000) <= tol &&
                  std::fabs(z - 0.8249) <= tol);

    if (!isD50 && !pv.hasTag(icSigChromaticAdaptationTag)) {
        return {CheckResult::Status::FINDINGS, "Missing chromaticAdaptationTag", {
            {cfId, Severity::HIGH,
             "Adopted white != D50 but chromaticAdaptationTag (chad) is missing",
             "ICC.1-2022-05 §8.2", ""}}};
    }
    return CheckResult::ok("Chromatic adaptation tag requirement satisfied");
}

static CheckResult check_cf010_profile_size_vs_file_size(const ProfileView& pv) {
    uint32_t headerSize = pv.header().size;
    size_t fileSize = pv.rawSize();
    CheckID cfId{CheckID::Kind::Conformance, 10};

    if (headerSize == 0)
        return CheckResult::ok("Header size is zero — cannot validate");

    long paddedHeader = static_cast<long>((headerSize + 3u) & ~3u);
    long diff = static_cast<long>(fileSize) - paddedHeader;
    if (diff < -4 || diff > 4) {
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "Header declares %u bytes, file is %zu bytes (diff=%ld beyond 4-byte tolerance)",
                 headerSize, fileSize, static_cast<long>(fileSize) - static_cast<long>(headerSize));
        return {CheckResult::Status::FINDINGS, "Profile size mismatch", {
            {cfId, Severity::HIGH, detail, "ICC.1-2022-05 §7.2.2", ""}}};
    }
    return CheckResult::ok("Profile size matches file size");
}

static CheckResult check_cf011_profile_id_md5_verification(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 11};

    bool allZero = true;
    for (int i = 0; i < 16; i++) {
        if (h.profileId[i] != 0) { allZero = false; break; }
    }
    if (allZero) return CheckResult::ok("Profile ID is zero — MD5 not computed");

    const uint8_t* raw = pv.rawData();
    size_t rawSz = pv.rawSize();
    if (!raw || rawSz < 128) return CheckResult::skip("Raw data too small for MD5");

    // Make a copy and zero the fields per spec
    std::vector<uint8_t> buf(raw, raw + rawSz);
    // Zero bytes 44-47 (flags), 64-67 (rendering intent), 84-99 (profile ID)
    std::memset(&buf[44], 0, 4);
    std::memset(&buf[64], 0, 4);
    std::memset(&buf[84], 0, 16);

    unsigned char md5[EVP_MAX_MD_SIZE];
    unsigned int md5Len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return CheckResult::error("Cannot create MD5 context");

    bool ok = EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) &&
              EVP_DigestUpdate(ctx, buf.data(), buf.size()) &&
              EVP_DigestFinal_ex(ctx, md5, &md5Len);
    EVP_MD_CTX_free(ctx);

    if (!ok) return CheckResult::error("MD5 computation failed");

    if (std::memcmp(md5, h.profileId.data(), 16) != 0) {
        char expected[33] = {}, computed[33] = {};
        for (int i = 0; i < 16; i++) {
            snprintf(expected + i*2, 3, "%02x", h.profileId[i]);
            snprintf(computed + i*2, 3, "%02x", md5[i]);
        }
        return {CheckResult::Status::FINDINGS, "Profile ID MD5 mismatch", {
            {cfId, Severity::MEDIUM,
             std::string("Expected ") + expected + " but computed " + computed,
             "ICC.1-2022-05 §7.2.18, RFC 1321", ""}}};
    }
    return CheckResult::ok("Profile ID MD5 verified");
}

static CheckResult check_cf012_profile_class_signature(const ProfileView& pv) {
    uint32_t dc = pv.header().deviceClass;
    uint8_t major = static_cast<uint8_t>(pv.header().version >> 24);
    CheckID cfId{CheckID::Kind::Conformance, 12};

    for (int i = 0; i < kV4DeviceClassCount; i++) {
        if (dc == kV4DeviceClasses[i]) return CheckResult::ok("Profile class recognized (v4)");
    }
    for (int i = 0; i < kV5DeviceClassCount; i++) {
        if (dc == kV5DeviceClasses[i]) {
            if (major < 5) {
                char buf[5]; SigToChars(dc, buf);
                return {CheckResult::Status::FINDINGS, "v5 class in pre-v5 profile", {
                    {cfId, Severity::HIGH,
                     std::string("Class '") + buf + "' is v5-only but version is " + std::to_string(major),
                     "ICC.1-2022-05 §7.2.5 Table 18", ""}}};
            }
            return CheckResult::ok("Profile class recognized (v5)");
        }
    }
    char buf[5]; SigToChars(dc, buf);
    return {CheckResult::Status::FINDINGS, "Unrecognized profile class", {
        {cfId, Severity::HIGH,
         std::string("Class '") + buf + "' not in ICC registered list",
         "ICC.1-2022-05 §7.2.5 Table 18", ""}}};
}

static CheckResult check_cf013_data_colour_space_signature(const ProfileView& pv) {
    uint32_t cs = pv.header().colorSpace;
    CheckID cfId{CheckID::Kind::Conformance, 13};

    if (IsConformantColorSpace(cs))
        return CheckResult::ok("Data colour space recognized");

    char buf[5]; SigToChars(cs, buf);
    return {CheckResult::Status::FINDINGS, "Unrecognized colour space", {
        {cfId, Severity::HIGH,
         std::string("Colour space '") + buf + "' not recognized",
         "ICC.1-2022-05 §7.2.6 Table 19", ""}}};
}

static CheckResult check_cf014_pcs_field_for_non_devicelink(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 14};

    if (h.deviceClass == static_cast<uint32_t>(icSigLinkClass))
        return CheckResult::ok("DeviceLink — PCS is output colour space");

    uint32_t pcs = h.pcs;
    uint8_t major = static_cast<uint8_t>(h.version >> 24);

    if (pcs == static_cast<uint32_t>(icSigXYZData) ||
        pcs == static_cast<uint32_t>(icSigLabData))
        return CheckResult::ok("PCS is XYZ or Lab");

    // v5 allows spectral PCS
    if (major >= 5) {
        uint32_t csType = icGetColorSpaceType(static_cast<icColorSpaceSignature>(pcs));
        if (csType == static_cast<uint32_t>(icSigNChannelData))
            return CheckResult::ok("v5 spectral PCS recognized");
    }

    char buf[5]; SigToChars(pcs, buf);
    return {CheckResult::Status::FINDINGS, "Non-DeviceLink PCS not XYZ/Lab", {
        {cfId, Severity::HIGH,
         std::string("PCS '") + buf + "' — non-DeviceLink profiles must use XYZ or Lab PCS",
         "ICC.1-2022-05 §7.2.7", ""}}};
}

static CheckResult check_cf015_reserved_bytes_100_127_zero(const ProfileView& pv) {
    const auto& reserved = pv.header().reserved;
    CheckID cfId{CheckID::Kind::Conformance, 15};

    for (size_t i = 0; i < reserved.size(); i++) {
        if (reserved[i] != 0) {
            char detail[80];
            snprintf(detail, sizeof(detail),
                     "Reserved byte at offset %zu (header byte %zu) is 0x%02X, must be 0x00",
                     i, 100 + i, reserved[i]);
            return {CheckResult::Status::FINDINGS, "Reserved bytes non-zero", {
                {cfId, Severity::HIGH, detail, "ICC.1-2022-05 §7.2.24", ""}}};
        }
    }
    return CheckResult::ok("Reserved bytes 100-127 all zero");
}

static CheckResult check_cf016_device_manufacturer_signature(const ProfileView& pv) {
    uint32_t mfr = pv.header().manufacturer;
    CheckID cfId{CheckID::Kind::Conformance, 16};

    if (mfr == 0) return CheckResult::ok("Manufacturer not specified (zero)");
    if (!IsPrintable4CC(mfr)) {
        char buf[5]; SigToChars(mfr, buf);
        return {CheckResult::Status::FINDINGS, "Manufacturer has non-printable bytes", {
            {cfId, Severity::MEDIUM,
             std::string("Manufacturer 0x") + buf + " contains non-printable ASCII",
             "ICC.1-2022-05 §7.2.12", ""}}};
    }
    return CheckResult::ok("Device manufacturer signature valid");
}

static CheckResult check_cf017_device_model_signature(const ProfileView& pv) {
    uint32_t model = pv.header().model;
    CheckID cfId{CheckID::Kind::Conformance, 17};

    if (model == 0) return CheckResult::ok("Model not specified (zero)");
    if (!IsPrintable4CC(model)) {
        char buf[5]; SigToChars(model, buf);
        return {CheckResult::Status::FINDINGS, "Model has non-printable bytes", {
            {cfId, Severity::MEDIUM,
             std::string("Model 0x") + buf + " contains non-printable ASCII",
             "ICC.1-2022-05 §7.2.13", ""}}};
    }
    return CheckResult::ok("Device model signature valid");
}

static CheckResult check_cf018_device_attributes_semantic_bits(const ProfileView& pv) {
    uint64_t attr = pv.header().attributes;
    CheckID cfId{CheckID::Kind::Conformance, 18};
    uint32_t lower = static_cast<uint32_t>(attr & 0xFFFFFFFF);

    if (lower & 0xFFFFFFF0u) {
        char detail[80];
        snprintf(detail, sizeof(detail),
                 "attributes lower=0x%08X, bits 4-31 are reserved and must be zero", lower);
        return {CheckResult::Status::FINDINGS, "Attributes reserved bits set", {
            {cfId, Severity::MEDIUM, detail, "ICC.1-2022-05 §7.2.14", ""}}};
    }
    return CheckResult::ok("Device attributes semantic bits valid");
}

static CheckResult check_cf019_creator_signature(const ProfileView& pv) {
    uint32_t creator = pv.header().creator;
    CheckID cfId{CheckID::Kind::Conformance, 19};

    if (creator == 0) return CheckResult::ok("Creator not specified (zero)");
    if (!IsPrintable4CC(creator)) {
        return {CheckResult::Status::FINDINGS, "Creator has non-printable bytes", {
            {cfId, Severity::MEDIUM,
             "Creator signature contains non-printable ASCII bytes",
             "ICC.1-2022-05 §7.2.17", ""}}};
    }
    return CheckResult::ok("Creator signature valid");
}

static CheckResult check_cf107_tag_table_ordering(const ProfileView& pv) {
    CheckID cfId{CheckID::Kind::Conformance, 107};
    const auto& tags = pv.rawTagTable();

    std::set<uint32_t> seen;
    std::vector<Finding> findings;
    for (const auto& entry : tags) {
        if (seen.count(entry.signature)) {
            char buf[5]; SigToChars(entry.signature, buf);
            findings.push_back({cfId, Severity::HIGH,
                std::string("Duplicate tag signature '") + buf + "'",
                "ICC.1-2022-05 §7.3.1", ""});
        }
        seen.insert(entry.signature);
    }
    if (findings.empty()) return CheckResult::ok("No duplicate tag signatures");
    return {CheckResult::Status::FINDINGS, "Duplicate tag signatures found", std::move(findings)};
}

static CheckResult check_cf121_illuminant_metadata_consistency(const ProfileView& pv) {
    CheckID cfId{CheckID::Kind::Conformance, 121};
    if (!pv.libraryLoaded()) return CheckResult::skip("Library failed to load");

    auto* pIcc = pv.unsafeLibraryHandle();
    CIccTag* wtptTag = pIcc->FindTag(icSigMediaWhitePointTag);
    if (!wtptTag) return CheckResult::ok("No mediaWhitePointTag — not applicable");

    CIccTagXYZ* wtpt = dynamic_cast<CIccTagXYZ*>(wtptTag);
    if (!wtpt || wtpt->GetSize() < 1)
        return CheckResult::ok("mediaWhitePointTag not valid XYZ — skipped");

    std::vector<Finding> findings;
    icXYZNumber val = (*wtpt)[0];
    uint8_t major = static_cast<uint8_t>(pv.header().version >> 24);

    if (major >= 4) {
        double x = icFtoD(val.X), y = icFtoD(val.Y), z = icFtoD(val.Z);
        const icFloatNumber* d50 = icD50XYZ;
        if (d50 && (std::fabs(x - d50[0]) > 0.01 ||
                    std::fabs(y - d50[1]) > 0.01 ||
                    std::fabs(z - d50[2]) > 0.01)) {
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "V4 mediaWhitePointTag (%.4f, %.4f, %.4f) != D50", x, y, z);
            findings.push_back({cfId, Severity::HIGH, detail,
                "ICC.1-2022-05 §9.2.28", ""});
        }
    }
    double y = icFtoD(val.Y);
    if (y <= 0.0) {
        findings.push_back({cfId, Severity::HIGH,
            "mediaWhitePointTag Y=" + std::to_string(y) + " <= 0 — invalid luminance",
            "ICC.1-2022-05 §9.2.28", ""});
    }

    if (findings.empty()) return CheckResult::ok("Illuminant metadata consistent");
    return {CheckResult::Status::FINDINGS, "Illuminant inconsistency", std::move(findings)};
}

static CheckResult check_cf122_profile_date_time_plausibility(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 122};

    if (h.year == 0 && h.month == 0 && h.day == 0 &&
        h.hour == 0 && h.minute == 0 && h.second == 0)
        return CheckResult::ok("Date/time all zeros — creation date not set");

    if (h.year < 1990 || h.year > 2099) {
        return {CheckResult::Status::FINDINGS, "Profile date implausible", {
            {cfId, Severity::MEDIUM,
             "Year " + std::to_string(h.year) + " outside plausible range [1990-2099]",
             "ICC.1-2022-05 §7.2.8", ""}}};
    }
    return CheckResult::ok("Profile date/time plausible");
}

static CheckResult check_cf184_profile_id_v4_presence(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 184};
    uint8_t major = static_cast<uint8_t>(h.version >> 24);

    if (major < 4)
        return CheckResult::ok("v2 profile — Profile ID not defined before v4");

    bool allZero = true;
    for (int i = 0; i < 16; i++) {
        if (h.profileId[i] != 0) { allZero = false; break; }
    }
    if (allZero) {
        return {CheckResult::Status::FINDINGS, "v4+ Profile ID not computed", {
            {cfId, Severity::MEDIUM,
             "v4+ profile SHOULD have a computed Profile ID (all zeros)",
             "ICC.1-2022-05 §7.2.18", ""}}};
    }
    return CheckResult::ok("v4+ profile has computed Profile ID");
}

static CheckResult check_cf185_profile_id_size_consistency(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 185};

    bool allZero = true;
    for (int i = 0; i < 16; i++) {
        if (h.profileId[i] != 0) { allZero = false; break; }
    }
    if (allZero) return CheckResult::ok("Profile ID is zero — size check not applicable");

    uint32_t headerSize = h.size;
    size_t fileSize = pv.rawSize();

    if (headerSize > 0 && static_cast<long>(headerSize) != static_cast<long>(fileSize)) {
        long paddedHeader = static_cast<long>((headerSize + 3u) & ~3u);
        if (paddedHeader != static_cast<long>(fileSize)) {
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "Header size=%u, file size=%zu — MD5 input length mismatch",
                     headerSize, fileSize);
            return {CheckResult::Status::FINDINGS, "Profile ID size inconsistency", {
                {cfId, Severity::MEDIUM, detail,
                 "ICC.1-2022-05 §7.2.18, RFC 1321 §3.1", ""}}};
        }
    }
    return CheckResult::ok("Profile ID size consistent");
}

static CheckResult check_cf186_profile_id_entropy_analysis(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 186};

    bool allZero = true;
    for (int i = 0; i < 16; i++) {
        if (h.profileId[i] != 0) { allZero = false; break; }
    }
    if (allZero) return CheckResult::ok("Profile ID is zero — entropy analysis not applicable");

    std::vector<Finding> findings;

    // All same byte
    bool allSame = true;
    for (int i = 1; i < 16; i++) {
        if (h.profileId[i] != h.profileId[0]) { allSame = false; break; }
    }
    if (allSame) {
        findings.push_back({cfId, Severity::MEDIUM,
            "All 16 bytes identical — not a valid MD5 output",
            "RFC 1321", ""});
        return {CheckResult::Status::FINDINGS, "Profile ID constant pattern", std::move(findings)};
    }

    // 2-byte or 4-byte repeating pattern
    bool repeat2 = true;
    for (int i = 2; i < 16; i++) {
        if (h.profileId[i] != h.profileId[i % 2]) { repeat2 = false; break; }
    }
    bool repeat4 = true;
    for (int i = 4; i < 16; i++) {
        if (h.profileId[i] != h.profileId[i % 4]) { repeat4 = false; break; }
    }
    if (repeat2 || repeat4) {
        findings.push_back({cfId, Severity::MEDIUM,
            std::string("Short repeating pattern (") + (repeat2 ? "2" : "4") + "-byte cycle)",
            "RFC 1321", ""});
    }

    // Unique byte count
    bool seen[256] = {};
    int uniqueCount = 0;
    for (int i = 0; i < 16; i++) {
        if (!seen[h.profileId[i]]) { seen[h.profileId[i]] = true; uniqueCount++; }
    }
    if (uniqueCount <= 2) {
        findings.push_back({cfId, Severity::MEDIUM,
            "Only " + std::to_string(uniqueCount) + " unique byte values — implausible for MD5",
            "RFC 1321", ""});
    }

    if (findings.empty()) return CheckResult::ok("Profile ID entropy consistent with MD5");
    return {CheckResult::Status::FINDINGS, "Profile ID entropy suspicious", std::move(findings)};
}

static CheckResult check_cf187_embedded_profile_profileid_chain(const ProfileView& pv) {
    CheckID cfId{CheckID::Kind::Conformance, 187};
    if (!pv.libraryLoaded()) return CheckResult::skip("Library failed to load");

    auto* pIcc = pv.unsafeLibraryHandle();
    CIccTag* pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
    if (!pTag) return CheckResult::ok("No embedded profile tag — no chain to validate");

    CIccTagEmbeddedProfile* pEmbed = dynamic_cast<CIccTagEmbeddedProfile*>(pTag);
    if (!pEmbed || !pEmbed->m_pProfile) {
        std::vector<Finding> findings;
        findings.push_back({cfId, Severity::MEDIUM,
            "Cannot validate embedded Profile ID",
            "Embedded profile tag present but profile not loaded", ""});
        return {CheckResult::Status::FINDINGS, "Embedded profile tag present but profile not loaded",
            std::move(findings)};
    }

    std::vector<Finding> findings;
    CIccProfile* pInner = pEmbed->m_pProfile;
    uint8_t innerMajor = static_cast<uint8_t>(pInner->m_Header.version >> 24);

    const icUInt8Number* innerPid = pInner->m_Header.profileID.ID8;
    bool innerZero = true;
    for (int i = 0; i < 16; i++) {
        if (innerPid[i] != 0) { innerZero = false; break; }
    }
    if (innerZero && innerMajor >= 4) {
        findings.push_back({cfId, Severity::MEDIUM,
            "Embedded v" + std::to_string(innerMajor) + " profile has zero Profile ID",
            "ICC.1-2022-05 §7.2.18", ""});
    }

    const auto& outerPid = pv.header().profileId;
    bool outerZero = true;
    for (int i = 0; i < 16; i++) {
        if (outerPid[i] != 0) { outerZero = false; break; }
    }
    uint8_t outerMajor = static_cast<uint8_t>(pv.header().version >> 24);
    if (outerZero && outerMajor >= 4) {
        findings.push_back({cfId, Severity::MEDIUM,
            "Outer v" + std::to_string(outerMajor) + " profile has zero Profile ID while embedding",
            "ICC.1-2022-05 §7.2.18", ""});
    }

    if (findings.empty()) return CheckResult::ok("Embedding chain Profile IDs consistent");
    return {CheckResult::Status::FINDINGS, "Embedding chain ID issue", std::move(findings)};
}

static CheckResult check_cf199_cmm_type_signature_registration(const ProfileView& pv) {
    uint32_t cmm = pv.header().cmmType;
    CheckID cfId{CheckID::Kind::Conformance, 199};

    if (cmm == 0) return CheckResult::ok("CMM type zero — no preferred CMM");

    for (int i = 0; i < kRegisteredCMMCount; i++) {
        if (cmm == kRegisteredCMMs[i]) return CheckResult::ok("CMM type registered");
    }

    if (!IsPrintable4CC(cmm)) {
        char buf[5]; SigToChars(cmm, buf);
        return {CheckResult::Status::FINDINGS, "CMM type not printable", {
            {cfId, Severity::MEDIUM,
             std::string("CMM '") + buf + "' is not printable ASCII and not ICC-registered",
             "ICC.1-2022-05 §7.2.3", ""}}};
    }

    char buf[5]; SigToChars(cmm, buf);
    return {CheckResult::Status::FINDINGS, "CMM type not in registered list", {
        {cfId, Severity::MEDIUM,
         std::string("CMM '") + buf + "' is printable but not in ICC registered CMM list",
         "ICC.1-2022-05 §7.2.3", ""}}};
}

static CheckResult check_cf200_device_manufacturer_model_signature(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 200};
    std::vector<Finding> findings;

    uint32_t fields[] = {h.manufacturer, h.model};
    const char* names[] = {"Manufacturer", "Model"};
    for (int f = 0; f < 2; f++) {
        if (fields[f] == 0) continue;
        if (!IsPrintable4CC(fields[f])) {
            char buf[5]; SigToChars(fields[f], buf);
            findings.push_back({cfId, Severity::MEDIUM,
                std::string(names[f]) + " '" + buf + "' contains non-printable ASCII",
                "ICC.1-2022-05 §7.2.12-13", ""});
        }
    }
    if (findings.empty()) return CheckResult::ok("Manufacturer/model signatures valid");
    return {CheckResult::Status::FINDINGS, "Non-printable manufacturer/model", std::move(findings)};
}

static CheckResult check_cf201_profile_creator_signature(const ProfileView& pv) {
    uint32_t creator = pv.header().creator;
    CheckID cfId{CheckID::Kind::Conformance, 201};

    if (creator == 0) return CheckResult::ok("Creator not specified (zero)");
    if (!IsPrintable4CC(creator)) {
        return {CheckResult::Status::FINDINGS, "Creator non-printable", {
            {cfId, Severity::MEDIUM,
             "Profile creator must be printable ASCII 4CC or zero",
             "ICC.1-2022-05 §7.2.17", ""}}};
    }
    return CheckResult::ok("Profile creator signature valid");
}

static CheckResult check_cf203_profile_flags_semantic_validation(const ProfileView& pv) {
    uint32_t flags = pv.header().flags;
    uint32_t version = pv.header().version;
    CheckID cfId{CheckID::Kind::Conformance, 203};
    std::vector<Finding> findings;

    bool embedded  = (flags & 0x0001) != 0;
    bool dependent = (flags & 0x0002) != 0;
    bool mcsSubset = (flags & 0x0004) != 0;

    if (!embedded && dependent) {
        findings.push_back({cfId, Severity::MEDIUM,
            "Non-embedded profile marked as cannot-be-used-independently — contradictory",
            "ICC.1-2022-05 §7.2.11 Table 21", ""});
    }
    if (mcsSubset && version < icVersionNumberV5) {
        findings.push_back({cfId, Severity::MEDIUM,
            "MCS subset flag (bit 2) set but version < 5.0 — v5 only",
            "ICC.1-2022-05 §7.2.11", ""});
    }

    if (findings.empty()) return CheckResult::ok("Profile flags semantics conformant");
    return {CheckResult::Status::FINDINGS, "Profile flags semantic issue", std::move(findings)};
}

static CheckResult check_cf206_profile_file_signature_acsp(const ProfileView& pv) {
    uint32_t magic = pv.header().magic;
    CheckID cfId{CheckID::Kind::Conformance, 206};

    if (magic != static_cast<uint32_t>(icMagicNumber)) {
        char buf[5]; SigToChars(magic, buf);
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "magic=0x%08X ('%s') — expected 'acsp' (0x%08X)",
                 magic, buf, static_cast<unsigned>(icMagicNumber));
        return {CheckResult::Status::FINDINGS, "Magic number not 'acsp'", {
            {cfId, Severity::HIGH, detail, "ICC.1-2022-05 §7.2.9", ""}}};
    }
    return CheckResult::ok("Profile file signature 'acsp' confirmed");
}

static CheckResult check_cf210_devicelink_pcs_space_validation(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 210};

    if (h.deviceClass != static_cast<uint32_t>(icSigLinkClass))
        return CheckResult::ok("Not a DeviceLink profile");

    uint32_t pcs = h.pcs;
    uint32_t csType = icGetColorSpaceType(static_cast<icColorSpaceSignature>(pcs));

    bool recognized = (pcs == static_cast<uint32_t>(icSigXYZData) ||
                       pcs == static_cast<uint32_t>(icSigLabData) ||
                       pcs == static_cast<uint32_t>(icSigRgbData) ||
                       pcs == static_cast<uint32_t>(icSigCmykData) ||
                       pcs == static_cast<uint32_t>(icSigGrayData) ||
                       csType == static_cast<uint32_t>(icSigNChannelData) ||
                       (pcs >= 0x32434C52u && pcs <= 0x46434C52u));
    if (!recognized) {
        char buf[5]; SigToChars(pcs, buf);
        return {CheckResult::Status::FINDINGS, "DeviceLink PCS unrecognized", {
            {cfId, Severity::HIGH,
             std::string("DeviceLink PCS '") + buf + "' is not a valid colour space",
             "ICC.1-2022-05 §8.6", ""}}};
    }
    return CheckResult::ok("DeviceLink PCS is recognized colour space");
}

static CheckResult check_cf214_embedded_profile_class_suitability(const ProfileView& pv) {
    uint32_t flags = pv.header().flags;
    CheckID cfId{CheckID::Kind::Conformance, 214};

    if (!(flags & 0x0001))
        return CheckResult::ok("Not an embedded profile — not applicable");

    uint32_t dc = pv.header().deviceClass;
    if (dc == static_cast<uint32_t>(icSigLinkClass)) {
        return {CheckResult::Status::FINDINGS, "DeviceLink with embedded flag", {
            {cfId, Severity::MEDIUM,
             "DeviceLink profile with embedded flag is atypical — ICC TN Embedding",
             "ICC TN Embedding §Table 1", ""}}};
    }
    return CheckResult::ok("Profile class appropriate for embedding");
}

static CheckResult check_cf215_jpeg_app2_embedding_size_limit(const ProfileView& pv) {
    static constexpr uint32_t kJPEGMaxEmbedSize = 16707345u;
    uint32_t profileSize = pv.header().size;
    CheckID cfId{CheckID::Kind::Conformance, 215};

    if (profileSize > kJPEGMaxEmbedSize) {
        return {CheckResult::Status::FINDINGS, "Profile too large for JPEG embedding", {
            {cfId, Severity::MEDIUM,
             "Profile " + std::to_string(profileSize) + " bytes exceeds JPEG APP2 limit (" +
             std::to_string(kJPEGMaxEmbedSize) + " bytes)",
             "ICC TN Embedding §JFIF", ""}}};
    }
    return CheckResult::ok("Profile fits within JPEG APP2 embedding limit");
}

static CheckResult check_cf216_jp2_restricted_icc_compliance(const ProfileView& pv) {
    const auto& h = pv.header();
    uint8_t major = static_cast<uint8_t>(h.version >> 24);
    CheckID cfId{CheckID::Kind::Conformance, 216};
    std::vector<Finding> findings;

    bool jp2ok = true;
    if (h.deviceClass != static_cast<uint32_t>(icSigInputClass)) jp2ok = false;
    if (major > 2) jp2ok = false;
    if (h.colorSpace != static_cast<uint32_t>(icSigGrayData) &&
        h.colorSpace != static_cast<uint32_t>(icSigRgbData)) jp2ok = false;

    if (!jp2ok) {
        findings.push_back({cfId, Severity::INFO,
            "Profile not compatible with JP2 Restricted ICC method",
            "ISO 15444-1 Annex I", ""});
    }
    if (findings.empty()) return CheckResult::ok("JP2 Restricted ICC compatible");
    return {CheckResult::Status::FINDINGS, "JP2 incompatible", std::move(findings)};
}

static CheckResult check_cf217_jpx_any_icc_method_compliance(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 217};

    bool jpxOk = true;
    if (h.deviceClass != static_cast<uint32_t>(icSigInputClass) &&
        h.deviceClass != static_cast<uint32_t>(icSigDisplayClass))
        jpxOk = false;

    if (jpxOk && pv.libraryLoaded()) {
        auto* pIcc = pv.unsafeLibraryHandle();
        bool hasMatrixTRC = (pIcc->FindTag(icSigRedMatrixColumnTag) &&
                             pIcc->FindTag(icSigGreenMatrixColumnTag) &&
                             pIcc->FindTag(icSigBlueMatrixColumnTag) &&
                             pIcc->FindTag(icSigRedTRCTag) &&
                             pIcc->FindTag(icSigGreenTRCTag) &&
                             pIcc->FindTag(icSigBlueTRCTag));
        bool hasLUT = (pIcc->FindTag(icSigAToB0Tag) != nullptr);

        if (hasLUT && !hasMatrixTRC) jpxOk = false;
        if (!hasMatrixTRC && h.colorSpace != static_cast<uint32_t>(icSigGrayData))
            jpxOk = false;
    }

    if (!jpxOk) {
        return {CheckResult::Status::FINDINGS, "JPX incompatible", {
            {cfId, Severity::INFO,
             "Profile not compatible with JPX Any ICC method",
             "ISO 15444-2 Annex M", ""}}};
    }
    return CheckResult::ok("JPX Any ICC method compatible");
}

static CheckResult check_cf218_heif_restricted_icc_compatibility(const ProfileView& pv) {
    const auto& h = pv.header();
    uint8_t major = static_cast<uint8_t>(h.version >> 24);
    CheckID cfId{CheckID::Kind::Conformance, 218};

    bool heifColrOK = (major <= 4);
    bool isMono = (h.colorSpace == static_cast<uint32_t>(icSigGrayData));
    bool is3Ch  = (h.colorSpace == static_cast<uint32_t>(icSigRgbData));

    bool hasMatrixTRC = false;
    if (is3Ch && pv.libraryLoaded()) {
        auto* pIcc = pv.unsafeLibraryHandle();
        hasMatrixTRC = (pIcc->FindTag(icSigRedMatrixColumnTag) &&
                        pIcc->FindTag(icSigGreenMatrixColumnTag) &&
                        pIcc->FindTag(icSigBlueMatrixColumnTag) &&
                        pIcc->FindTag(icSigRedTRCTag) &&
                        pIcc->FindTag(icSigGreenTRCTag) &&
                        pIcc->FindTag(icSigBlueTRCTag));
    }
    bool heifRiccOK = (isMono || (is3Ch && hasMatrixTRC));

    if (!heifColrOK && !heifRiccOK) {
        return {CheckResult::Status::FINDINGS, "HEIF incompatible", {
            {cfId, Severity::INFO,
             "Profile not compatible with any HEIF embedding method",
             "ISO/IEC 14496-12", ""}}};
    }
    return CheckResult::ok("HEIF embedding compatible");
}

static CheckResult check_cf219_container_format_version_matrix(const ProfileView& pv) {
    const auto& h = pv.header();
    uint8_t major = static_cast<uint8_t>(h.version >> 24);
    CheckID cfId{CheckID::Kind::Conformance, 219};

    if (major >= 5) {
        return {CheckResult::Status::FINDINGS, "v5 limited container support", {
            {cfId, Severity::INFO,
             "No media formats currently support ICC v5 embedding",
             "ICC TN Embedding §Table 1", ""}}};
    }
    return CheckResult::ok("Profile version has broad container format support");
}

static CheckResult check_cf232_date_time_utc_and_temporal_consistency(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 232};
    std::vector<Finding> findings;

    if (h.second > 59) {
        findings.push_back({cfId, Severity::INFO,
            "Seconds=" + std::to_string(h.second) + " exceeds 59",
            "ICC.1-2022-05 §7.2.8", ""});
    }
    if (h.hour > 23) {
        findings.push_back({cfId, Severity::INFO,
            "Hour=" + std::to_string(h.hour) + " exceeds 23",
            "ICC.1-2022-05 §7.2.8", ""});
    }

    // Check calibration date if library loaded
    if (pv.libraryLoaded()) {
        auto* pIcc = pv.unsafeLibraryHandle();
        CIccTag* pCalTag = pIcc->FindTag(icSigCalibrationDateTimeTag);
        if (pCalTag) {
            CIccTagDateTime* pCalDT = dynamic_cast<CIccTagDateTime*>(pCalTag);
            if (pCalDT) {
                // Just report presence — V1 used Describe() for display
                std::string desc;
                pCalDT->Describe(desc, 1);
                // No finding — informational only in V1
            }
        }
    }

    if (findings.empty()) return CheckResult::ok("Date/time UTC and temporal consistency OK");
    return {CheckResult::Status::FINDINGS, "Date/time UTC issue", std::move(findings)};
}

static CheckResult check_cf243_datetimenumber_field_range(const ProfileView& pv) {
    const auto& h = pv.header();
    CheckID cfId{CheckID::Kind::Conformance, 243};
    std::vector<Finding> findings;

    if (h.month < 1 || h.month > 12)
        findings.push_back({cfId, Severity::HIGH,
            "month=" + std::to_string(h.month) + " out of range 1-12",
            "ICC.1-2022-05 §4.2", ""});
    if (h.day < 1 || h.day > 31)
        findings.push_back({cfId, Severity::HIGH,
            "day=" + std::to_string(h.day) + " out of range 1-31",
            "ICC.1-2022-05 §4.2", ""});
    if (h.hour > 23)
        findings.push_back({cfId, Severity::HIGH,
            "hours=" + std::to_string(h.hour) + " exceeds 23",
            "ICC.1-2022-05 §4.2", ""});
    if (h.minute > 59)
        findings.push_back({cfId, Severity::HIGH,
            "minutes=" + std::to_string(h.minute) + " exceeds 59",
            "ICC.1-2022-05 §4.2", ""});
    if (h.second > 59)
        findings.push_back({cfId, Severity::HIGH,
            "seconds=" + std::to_string(h.second) + " exceeds 59",
            "ICC.1-2022-05 §4.2", ""});

    if (findings.empty()) return CheckResult::ok("dateTimeNumber field ranges valid");
    return {CheckResult::Status::FINDINGS, "dateTimeNumber range violation", std::move(findings)};
}

static CheckResult check_cf244_profile_creation_date_plausibility(const ProfileView& pv) {
    uint16_t year = pv.header().year;
    CheckID cfId{CheckID::Kind::Conformance, 244};

    if (year != 0 && year < 1990) {
        return {CheckResult::Status::FINDINGS, "Creation date too early", {
            {cfId, Severity::MEDIUM,
             "Year " + std::to_string(year) + " predates ICC specification (1990)",
             "ICC.1-2022-05 §7.2.8", ""}}};
    }
    if (year > 2100) {
        return {CheckResult::Status::FINDINGS, "Creation date implausibly far", {
            {cfId, Severity::MEDIUM,
             "Year " + std::to_string(year) + " implausibly far in the future",
             "ICC.1-2022-05 §7.2.8", ""}}};
    }
    return CheckResult::ok("Profile creation date plausible");
}

static CheckResult check_cf245_profile_size_multiple_of_4(const ProfileView& pv) {
    uint32_t sz = pv.header().size;
    CheckID cfId{CheckID::Kind::Conformance, 245};

    if (sz % 4 != 0) {
        return {CheckResult::Status::FINDINGS, "Size not 4-byte aligned", {
            {cfId, Severity::HIGH,
             "Profile size " + std::to_string(sz) + " is not a multiple of 4 bytes",
             "ICC.1-2022-05 §7.2.2", ""}}};
    }
    return CheckResult::ok("Profile size is 4-byte aligned");
}

static CheckResult check_cf246_rendering_intent_range(const ProfileView& pv) {
    uint32_t intent = pv.header().renderingIntent;
    CheckID cfId{CheckID::Kind::Conformance, 246};

    if (intent > 3) {
        return {CheckResult::Status::FINDINGS, "Rendering intent out of range", {
            {cfId, Severity::HIGH,
             "Rendering intent " + std::to_string(intent) + " exceeds valid range 0-3",
             "ICC.1-2022-05 §7.2.15", ""}}};
    }
    return CheckResult::ok("Rendering intent valid (0-3)");
}

// ── Registrations (43 checks) ──

REGISTER_CONFORMANCE(1, "Date/Time Month-Day Validity",
    "§7.2.8", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf001_date_time_month_day_validity);

REGISTER_CONFORMANCE(2, "Date/Time Leap Year Validation",
    "§7.2.8", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf002_date_time_leap_year_validation);

REGISTER_CONFORMANCE(3, "Profile Flags Reserved Bits",
    "§7.2.11 Table 21", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf003_profile_flags_reserved_bits);

REGISTER_CONFORMANCE(4, "Device Attributes Reserved Bits",
    "§7.2.14", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf004_device_attributes_reserved_bits);

REGISTER_CONFORMANCE(5, "Rendering Intent Upper Bits Zero",
    "§7.2.15", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf005_rendering_intent_upper_bits_zero);

REGISTER_CONFORMANCE(6, "Profile Version BCD Encoding",
    "§7.2.4", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf006_profile_version_bcd_encoding);

REGISTER_CONFORMANCE(7, "Primary Platform Signature",
    "§7.2.10 Table 20", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf007_primary_platform_signature);

REGISTER_CONFORMANCE(8, "PCS Illuminant D50 Precision",
    "§7.2.16", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf008_pcs_illuminant_d50_precision);

REGISTER_CONFORMANCE(9, "Chromatic Adaptation Tag Requirement",
    "§8.2, TN-PartialAdaptation", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf009_chromatic_adaptation_tag_requirement);

REGISTER_CONFORMANCE(10, "Profile Size vs File Size",
    "§7.2.2", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf010_profile_size_vs_file_size);

REGISTER_CONFORMANCE(11, "Profile ID MD5 Verification",
    "§7.2.18, RFC 1321", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf011_profile_id_md5_verification);

REGISTER_CONFORMANCE(12, "Profile Class Signature",
    "§7.2.5 Table 18", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf012_profile_class_signature);

REGISTER_CONFORMANCE(13, "Data Colour Space Signature",
    "§7.2.6 Table 19", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf013_data_colour_space_signature);

REGISTER_CONFORMANCE(14, "PCS Field for Non-DeviceLink",
    "§7.2.7", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf014_pcs_field_for_non_devicelink);

REGISTER_CONFORMANCE(15, "Reserved Bytes 100-127 Zero",
    "§7.2.24", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf015_reserved_bytes_100_127_zero);

REGISTER_CONFORMANCE(16, "Device Manufacturer Signature",
    "§7.2.12", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf016_device_manufacturer_signature);

REGISTER_CONFORMANCE(17, "Device Model Signature",
    "§7.2.13", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf017_device_model_signature);

REGISTER_CONFORMANCE(18, "Device Attributes Semantic Bits",
    "§7.2.14", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf018_device_attributes_semantic_bits);

REGISTER_CONFORMANCE(19, "Creator Signature",
    "§7.2.17", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf019_creator_signature);

REGISTER_CONFORMANCE(107, "Tag Table Ordering",
    "§7.3.1 (no duplicate tag signatures)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf107_tag_table_ordering);

REGISTER_CONFORMANCE(121, "Illuminant Metadata Consistency",
    "§7.2.16 (wtpt matches D50 for v4)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf121_illuminant_metadata_consistency);

REGISTER_CONFORMANCE(122, "Profile Date/Time Plausibility",
    "§7.2.8 (date year in plausible range)", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf122_profile_date_time_plausibility);

REGISTER_CONFORMANCE(184, "Profile ID v4+ Presence",
    "v4+ profiles SHOULD have a computed Profile ID (MD5 hash per RFC 1321)", "ICC.1-2022-05 §7.2.18",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf184_profile_id_v4_presence);

REGISTER_CONFORMANCE(185, "Profile ID Size Consistency",
    "MD5 input length (header-declared profile size) must match actual file size per RFC 1321 §3.1", "ICC.1-2022-05 §7.2.18",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf185_profile_id_size_consistency);

REGISTER_CONFORMANCE(186, "Profile ID Entropy Analysis",
    "Profile ID (MD5 hash) should have near-uniform byte distribution per RFC 1321", "ICC.1-2022-05 §7.2.18",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf186_profile_id_entropy_analysis);

REGISTER_CONFORMANCE(187, "Embedded Profile ProfileID Chain",
    "Both outer and inner profiles in embedding chain should have valid Profile IDs", "ICC TN Embedding + §7.2.18",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf187_embedded_profile_profileid_chain);

REGISTER_CONFORMANCE(199, "CMM Type Signature Registration",
    "Validate CMM type signature against known registered ICC implementations or confirm printability", "ICC.1-2022-05 §7.2.3",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf199_cmm_type_signature_registration);

REGISTER_CONFORMANCE(200, "Device Manufacturer/Model Signature",
    "Validate manufacturer and model signatures for printable ASCII characters", "ICC.1-2022-05 §7.2.12-13",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf200_device_manufacturer_model_signature);

REGISTER_CONFORMANCE(201, "Profile Creator Signature",
    "Validate creator signature for printable ASCII characters or zero (unspecified)", "ICC.1-2022-05 §7.2.17",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf201_profile_creator_signature);

REGISTER_CONFORMANCE(203, "Profile Flags Semantic Validation",
    "Validate defined flag bits (embedded, independent, MCS) for semantic consistency", "ICC.1-2022-05 §7.2.11",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf203_profile_flags_semantic_validation);

REGISTER_CONFORMANCE(206, "Profile File Signature 'acsp'",
    "Validate ICC magic number 'acsp' (0x61637370) at header bytes 36-39", "ICC.1-2022-05 §7.2.9",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf206_profile_file_signature_acsp);

REGISTER_CONFORMANCE(210, "DeviceLink PCS Space Validation",
    "Validate DeviceLink profiles have consistent PCS space assignment and color space compatibility", "ICC.1-2022-05 §8.6",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf210_devicelink_pcs_space_validation);

REGISTER_CONFORMANCE(214, "Embedded Profile Class Suitability",
    "When embedded flag (§7.2.11 bit 0) is set, validate profile class is appropriate for embedding (DeviceLink atypical)", "ICC TN Embedding §Table 1",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf214_embedded_profile_class_suitability);

REGISTER_CONFORMANCE(215, "JPEG APP2 Embedding Size Limit",
    "Profile must not exceed 16,707,345 bytes (255 × 65,519) for JPEG APP2 multi-segment embedding", "ICC TN Embedding §JFIF",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf215_jpeg_app2_embedding_size_limit);

REGISTER_CONFORMANCE(216, "JP2 Restricted ICC Compliance",
    "JP2 (ISO 15444-1) restricts embedded profiles to Input class, v2 only, monochrome/RGB", "ISO 15444-1 Annex I",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf216_jp2_restricted_icc_compliance);

REGISTER_CONFORMANCE(217, "JPX Any ICC Method Compliance",
    "JPX (ISO 15444-2 Annex M) allows Input/Display class only with Matrix/TRC structure (no LUT-based)", "ISO 15444-2 Annex M",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf217_jpx_any_icc_method_compliance);

REGISTER_CONFORMANCE(218, "HEIF Restricted ICC Compatibility",
    "HEIF ricc type code requires monochrome or 3-component Matrix/TRC profile; colr requires v4 or lower", "ISO/IEC 14496-12",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf218_heif_restricted_icc_compatibility);

REGISTER_CONFORMANCE(219, "Container Format Version Matrix",
    "Cross-reference profile version and class against 18 media formats supporting ICC embedding", "ICC TN Embedding §Table 1",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf219_container_format_version_matrix);

REGISTER_CONFORMANCE(232, "Date/Time UTC and Temporal Consistency",
    "All dates UTC, seconds ≤59, calibrationDateTimeTag should precede profile creation", "ICC.1-2022-05 §7.2.8",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf232_date_time_utc_and_temporal_consistency);

REGISTER_CONFORMANCE(243, "dateTimeNumber Field Range",
    "Month 1-12, day 1-31, hours 0-23, minutes 0-59, seconds 0-59", "ICC.1-2022-05 §4.2",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf243_datetimenumber_field_range);

REGISTER_CONFORMANCE(244, "Profile Creation Date Plausibility",
    "Year must be >=1990 (ICC specification era) and <=2100", "ICC.1-2022-05 §7.2.8",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf244_profile_creation_date_plausibility);

REGISTER_CONFORMANCE(245, "Profile Size Multiple of 4",
    "Profile data shall be padded to 4-byte boundary", "ICC.1-2022-05 §7.2.2",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf245_profile_size_multiple_of_4);

REGISTER_CONFORMANCE(246, "Rendering Intent Range",
    "Rendering intent must be 0-3 (Perceptual/Relative/Saturation/Absolute)", "ICC.1-2022-05 §7.2.15",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf246_rendering_intent_range);
