// CfRequiredChecks.cpp — V2 conformance checks (REQUIRED TAGS)
// 51 checks: CF-040..CF-283
//
// Ported from V1 IccConformanceRequired.cpp
//
// SPDX-License-Identifier: MIT

#include <icctest/CheckRegistry.h>
#include <icctest/ProfileView.h>
#include <icctest/CheckResult.h>

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccUtil.h"
#include "IccDefs.h"

#include <cmath>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <vector>
#include <string>
#include <set>

using namespace icctest;

// ── Helpers ─────────────────────────────────────────────────────────────────

static void SigToChars(uint32_t sig, char buf[5]) {
    buf[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));
    buf[1] = static_cast<char>(static_cast<unsigned char>((sig >> 16) & 0xFF));
    buf[2] = static_cast<char>(static_cast<unsigned char>((sig >>  8) & 0xFF));
    buf[3] = static_cast<char>(static_cast<unsigned char>( sig        & 0xFF));
    buf[4] = '\0';
}

static double S15Fixed16ToDouble(int32_t val) {
    return static_cast<double>(val) / 65536.0;
}

static bool IsXCLRColorSpace(uint32_t cs) {
    return (cs >= 0x32434C52u && cs <= 0x46434C52u); // '2CLR'..'FCLR'
}

static bool HasMatrixTRC(const ProfileView& pv) {
    return pv.hasTag(icSigRedMatrixColumnTag);
}

static int VersionMajor(const ProfileView& pv) {
    return (pv.header().version >> 24) & 0xFF;
}

static int VersionMinor(const ProfileView& pv) {
    return (pv.header().version >> 20) & 0x0F;
}

static bool IsPrintable4CC(uint32_t sig) {
    for (int i = 0; i < 4; i++) {
        unsigned char b = (sig >> (24 - i * 8)) & 0xFF;
        if (b < 0x20 || b > 0x7E) return false;
    }
    return true;
}

// ── CF-040: Common Required Tags (Non-DeviceLink) ───────────────────────────

static CheckResult check_cf040_common_required_tags_non_devicelink(const ProfileView& pv) {
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls == icSigLinkClass)
        return CheckResult::skip("DeviceLink — common required tags checked in CF-044");

    std::vector<Finding> findings;
    if (!pv.hasTag(icSigProfileDescriptionTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 40}, Severity::HIGH,
            "Missing profileDescriptionTag (desc)", "ICC.1-2022-05 §8.2 requires desc for non-DeviceLink", ""});
    if (!pv.hasTag(icSigCopyrightTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 40}, Severity::HIGH,
            "Missing copyrightTag (cprt)", "ICC.1-2022-05 §8.2 requires cprt for non-DeviceLink", ""});
    if (!pv.hasTag(icSigMediaWhitePointTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 40}, Severity::HIGH,
            "Missing mediaWhitePointTag (wtpt)", "ICC.1-2022-05 §8.2 requires wtpt for non-DeviceLink", ""});

    // chad required if adopted white != D50
    double iX = S15Fixed16ToDouble(pv.header().illuminantX);
    double iY = S15Fixed16ToDouble(pv.header().illuminantY);
    double iZ = S15Fixed16ToDouble(pv.header().illuminantZ);
    const double D50_X = 0.9642, D50_Y = 1.0000, D50_Z = 0.8249;
    if (std::fabs(iX - D50_X) > 0.0001 || std::fabs(iY - D50_Y) > 0.0001 ||
        std::fabs(iZ - D50_Z) > 0.0001) {
        if (!pv.hasTag(icSigChromaticAdaptationTag))
            findings.push_back({CheckID{CheckID::Kind::Conformance, 40}, Severity::HIGH,
                "Missing chromaticAdaptationTag (chad)",
                "ICC.1-2022-05 §8.2 requires chad when adopted white != D50", ""});
    }
    if (findings.empty())
        return CheckResult::ok("Common required tags present");
    return {CheckResult::Status::FINDINGS, "Missing common required tags", std::move(findings)};
}

// ── CF-041: Input Profile Required Tags ─────────────────────────────────────

static CheckResult check_cf041_input_profile_required_tags(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigInputClass)
        return CheckResult::skip("Not an Input profile");

    std::vector<Finding> findings;
    bool hasMatrix = HasMatrixTRC(pv);
    bool hasAToB0 = pv.hasTag(icSigAToB0Tag);

    if (!hasMatrix && !hasAToB0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 41}, Severity::HIGH,
            "Input profile must have matrix/TRC tags or AToB0Tag",
            "ICC.1-2022-05 §8.3 Tables 22-24", ""});

    if (hasMatrix) {
        static const struct { icTagSignature sig; const char *name; } matTags[] = {
            {icSigRedMatrixColumnTag, "rXYZ"}, {icSigGreenMatrixColumnTag, "gXYZ"},
            {icSigBlueMatrixColumnTag, "bXYZ"}, {icSigRedTRCTag, "rTRC"},
            {icSigGreenTRCTag, "gTRC"}, {icSigBlueTRCTag, "bTRC"},
        };
        for (int i = 0; i < 6; i++) {
            if (!pv.hasTag(matTags[i].sig)) {
                char msg[128];
                std::snprintf(msg, sizeof(msg), "Missing matrix/TRC tag '%s'", matTags[i].name);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 41}, Severity::HIGH,
                    msg, "ICC.1-2022-05 §8.3", ""});
            }
        }
        if (pv.header().pcs != static_cast<uint32_t>(icSigXYZData))
            findings.push_back({CheckID{CheckID::Kind::Conformance, 41}, Severity::HIGH,
                "Matrix/TRC input profile PCS must be XYZ", "ICC.1-2022-05 §8.3", ""});
    }
    if (findings.empty())
        return CheckResult::ok("Input profile required tags present");
    return {CheckResult::Status::FINDINGS, "Input profile missing required tags", std::move(findings)};
}

// ── CF-042: Display Profile Required Tags ───────────────────────────────────

static CheckResult check_cf042_display_profile_required_tags(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigDisplayClass)
        return CheckResult::skip("Not a Display profile");

    std::vector<Finding> findings;
    bool hasMatrix = HasMatrixTRC(pv);
    bool hasAToB0 = pv.hasTag(icSigAToB0Tag);
    bool hasBToA0 = pv.hasTag(icSigBToA0Tag);

    if (!hasMatrix && !hasAToB0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 42}, Severity::HIGH,
            "Display profile must have matrix/TRC tags or AToB0+BToA0",
            "ICC.1-2022-05 §8.4 Tables 25-27", ""});

    if (!hasMatrix && hasAToB0 && !hasBToA0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 42}, Severity::HIGH,
            "Display profile with AToB0 must also have BToA0",
            "ICC.1-2022-05 §8.4", ""});

    if (hasMatrix) {
        static const struct { icTagSignature sig; const char *name; } matTags[] = {
            {icSigRedMatrixColumnTag, "rXYZ"}, {icSigGreenMatrixColumnTag, "gXYZ"},
            {icSigBlueMatrixColumnTag, "bXYZ"}, {icSigRedTRCTag, "rTRC"},
            {icSigGreenTRCTag, "gTRC"}, {icSigBlueTRCTag, "bTRC"},
        };
        for (int i = 0; i < 6; i++) {
            if (!pv.hasTag(matTags[i].sig)) {
                char msg[128];
                std::snprintf(msg, sizeof(msg), "Missing matrix/TRC tag '%s'", matTags[i].name);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 42}, Severity::HIGH,
                    msg, "ICC.1-2022-05 §8.4", ""});
            }
        }
        if (pv.header().pcs != static_cast<uint32_t>(icSigXYZData))
            findings.push_back({CheckID{CheckID::Kind::Conformance, 42}, Severity::HIGH,
                "Matrix/TRC display profile PCS must be XYZ", "ICC.1-2022-05 §8.4", ""});
    }
    if (findings.empty())
        return CheckResult::ok("Display profile required tags present");
    return {CheckResult::Status::FINDINGS, "Display profile missing required tags", std::move(findings)};
}

// ── CF-043: Output Profile Required Tags ────────────────────────────────────

static CheckResult check_cf043_output_profile_required_tags(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigOutputClass)
        return CheckResult::skip("Not an Output profile");

    std::vector<Finding> findings;
    if (!pv.hasTag(icSigAToB0Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 43}, Severity::HIGH,
            "Output profile must have AToB0Tag", "ICC.1-2022-05 §8.5 Tables 28-29", ""});
    if (!pv.hasTag(icSigBToA0Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 43}, Severity::HIGH,
            "Output profile must have BToA0Tag", "ICC.1-2022-05 §8.5 Tables 28-29", ""});
    if (findings.empty())
        return CheckResult::ok("Output profile required tags present");
    return {CheckResult::Status::FINDINGS, "Output profile missing required tags", std::move(findings)};
}

// ── CF-044: DeviceLink Profile Required Tags ────────────────────────────────

static CheckResult check_cf044_devicelink_profile_required_tags(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigLinkClass)
        return CheckResult::skip("Not a DeviceLink profile");

    std::vector<Finding> findings;
    if (!pv.hasTag(icSigProfileDescriptionTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 44}, Severity::HIGH,
            "DeviceLink must have profileDescriptionTag", "ICC.1-2022-05 §8.6 Table 30", ""});
    if (!pv.hasTag(icSigAToB0Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 44}, Severity::HIGH,
            "DeviceLink must have AToB0Tag", "ICC.1-2022-05 §8.6 Table 30", ""});
    if (!pv.hasTag(icSigCopyrightTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 44}, Severity::HIGH,
            "DeviceLink must have copyrightTag", "ICC.1-2022-05 §8.6 Table 30", ""});

    // v4.4+ requires either pseq or psid
    int major = VersionMajor(pv);
    int minor = VersionMinor(pv);
    if (major > 4 || (major == 4 && minor >= 4)) {
        bool hasPseq = pv.hasTag(icSigProfileSequenceDescTag);
        bool hasPsid = pv.hasTag(icSigProfileSequceIdTag);
        if (!hasPseq && !hasPsid)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 44}, Severity::HIGH,
                "DeviceLink v4.4+ must have pseq or psid",
                "ICC.1-2022-05 §8.6 Table 30", ""});
    }

    // colorantTable if xCLR PCS
    uint32_t pcs = pv.header().pcs;
    if (IsXCLRColorSpace(pcs) && !pv.hasTag(icSigColorantTableTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 44}, Severity::HIGH,
            "DeviceLink with xCLR PCS must have colorantTableTag",
            "ICC.1-2022-05 §8.6", ""});

    if (findings.empty())
        return CheckResult::ok("DeviceLink profile required tags present");
    return {CheckResult::Status::FINDINGS, "DeviceLink missing required tags", std::move(findings)};
}

// ── CF-045: ColorSpace Profile Required Tags ────────────────────────────────

static CheckResult check_cf045_colorspace_profile_required_tags(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigColorSpaceClass)
        return CheckResult::skip("Not a ColorSpace profile");

    std::vector<Finding> findings;
    if (!pv.hasTag(icSigAToB0Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 45}, Severity::HIGH,
            "ColorSpace profile must have AToB0Tag", "ICC.1-2022-05 §8.7 Table 31", ""});
    if (!pv.hasTag(icSigBToA0Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 45}, Severity::HIGH,
            "ColorSpace profile must have BToA0Tag", "ICC.1-2022-05 §8.7 Table 31", ""});
    if (findings.empty())
        return CheckResult::ok("ColorSpace profile required tags present");
    return {CheckResult::Status::FINDINGS, "ColorSpace profile missing required tags", std::move(findings)};
}

// ── CF-046: Abstract Profile Required Tags ──────────────────────────────────

static CheckResult check_cf046_abstract_profile_required_tags(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigAbstractClass)
        return CheckResult::skip("Not an Abstract profile");

    std::vector<Finding> findings;
    if (!pv.hasTag(icSigAToB0Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 46}, Severity::HIGH,
            "Abstract profile must have AToB0Tag", "ICC.1-2022-05 §8.8 Table 32", ""});
    if (findings.empty())
        return CheckResult::ok("Abstract profile required tags present");
    return {CheckResult::Status::FINDINGS, "Abstract profile missing required tags", std::move(findings)};
}

// ── CF-047: NamedColor Profile Required Tags ────────────────────────────────

static CheckResult check_cf047_namedcolor_profile_required_tags(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigNamedColorClass)
        return CheckResult::skip("Not a NamedColor profile");

    std::vector<Finding> findings;
    if (!pv.hasTag(icSigNamedColor2Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 47}, Severity::HIGH,
            "NamedColor profile must have namedColor2Tag", "ICC.1-2022-05 §8.9 Table 33", ""});
    if (findings.empty())
        return CheckResult::ok("NamedColor profile required tags present");
    return {CheckResult::Status::FINDINGS, "NamedColor profile missing required tags", std::move(findings)};
}

// ── CF-048: Rendering Intent Transform Consistency ──────────────────────────

static CheckResult check_cf048_rendering_intent_transform_consistency(const ProfileView& pv) {
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls == icSigLinkClass || cls == icSigNamedColorClass)
        return CheckResult::skip("DeviceLink/NamedColor exempt from rendering intent consistency");

    std::vector<Finding> findings;
    uint32_t intent = pv.header().renderingIntent;

    if (intent == 1 || intent == 3) { // Relative or Absolute
        if (pv.hasTag(icSigAToB0Tag) && !pv.hasTag(icSigAToB1Tag))
            findings.push_back({CheckID{CheckID::Kind::Conformance, 48}, Severity::MEDIUM,
                "Profile has AToB0 but missing AToB1 for relative/absolute intent",
                "ICC.1-2022-05 §7.2.15", ""});
        if (pv.hasTag(icSigBToA0Tag) && !pv.hasTag(icSigBToA1Tag))
            findings.push_back({CheckID{CheckID::Kind::Conformance, 48}, Severity::MEDIUM,
                "Profile has BToA0 but missing BToA1 for relative/absolute intent",
                "ICC.1-2022-05 §7.2.15", ""});
    }
    if (intent == 2) { // Saturation
        if (pv.hasTag(icSigAToB0Tag) && !pv.hasTag(icSigAToB2Tag))
            findings.push_back({CheckID{CheckID::Kind::Conformance, 48}, Severity::MEDIUM,
                "Profile has AToB0 but missing AToB2 for saturation intent",
                "ICC.1-2022-05 §7.2.15", ""});
        if (pv.hasTag(icSigBToA0Tag) && !pv.hasTag(icSigBToA2Tag))
            findings.push_back({CheckID{CheckID::Kind::Conformance, 48}, Severity::MEDIUM,
                "Profile has BToA0 but missing BToA2 for saturation intent",
                "ICC.1-2022-05 §7.2.15", ""});
    }
    if (findings.empty())
        return CheckResult::ok("Rendering intent consistent with transform tags");
    return {CheckResult::Status::FINDINGS, "Rendering intent/transform mismatch", std::move(findings)};
}

// ── CF-049: Matrix/TRC Profile PCS Must Be XYZ ──────────────────────────────

static CheckResult check_cf049_matrix_trc_profile_pcs_must_be_xyz(const ProfileView& pv) {
    if (!HasMatrixTRC(pv))
        return CheckResult::skip("Not a matrix/TRC profile");

    if (pv.header().pcs != static_cast<uint32_t>(icSigXYZData))
        return {CheckResult::Status::FINDINGS, "Matrix/TRC PCS not XYZ", {
            {CheckID{CheckID::Kind::Conformance, 49}, Severity::HIGH,
             "Matrix/TRC profiles must use PCS = XYZ", "ICC.1-2022-05 §8.3-8.4", ""}}};
    return CheckResult::ok("Matrix/TRC PCS is XYZ");
}

// ── CF-050: xCLR Colorant Table Required ────────────────────────────────────

static CheckResult check_cf050_xclr_colorant_table_required(const ProfileView& pv) {
    std::vector<Finding> findings;
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    uint32_t cs = pv.header().colorSpace;
    uint32_t pcs = pv.header().pcs;

    if (IsXCLRColorSpace(cs) && !pv.hasTag(icSigColorantTableTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 50}, Severity::HIGH,
            "xCLR device space requires colorantTableTag",
            "ICC.1-2022-05 §8.5-8.6", ""});

    if (cls == icSigLinkClass && IsXCLRColorSpace(pcs)) {
        if (!pv.hasTag(icSigColorantTableOutTag))
            findings.push_back({CheckID{CheckID::Kind::Conformance, 50}, Severity::HIGH,
                "DeviceLink with xCLR PCS requires colorantTableOutTag",
                "ICC.1-2022-05 §8.6", ""});
    }
    if (findings.empty())
        return CheckResult::ok("xCLR colorant table requirements met");
    return {CheckResult::Status::FINDINGS, "Missing xCLR colorant table", std::move(findings)};
}

// ── CF-051: DeviceLink Prohibited Tags ──────────────────────────────────────

static CheckResult check_cf051_devicelink_prohibited_tags(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigLinkClass)
        return CheckResult::skip("Not a DeviceLink profile");

    std::vector<Finding> findings;
    if (pv.hasTag(icSigMediaWhitePointTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 51}, Severity::HIGH,
            "DeviceLink must not contain mediaWhitePointTag", "ICC.1-2022-05 §8.6", ""});

    static const struct { icTagSignature sig; const char *name; } prohibited[] = {
        {icSigAToB1Tag, "AToB1"}, {icSigAToB2Tag, "AToB2"},
        {icSigBToA0Tag, "BToA0"}, {icSigBToA1Tag, "BToA1"}, {icSigBToA2Tag, "BToA2"},
    };
    for (int i = 0; i < 5; i++) {
        if (pv.hasTag(prohibited[i].sig)) {
            char msg[128];
            std::snprintf(msg, sizeof(msg), "DeviceLink must not contain %sTag", prohibited[i].name);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 51}, Severity::HIGH,
                msg, "ICC.1-2022-05 §8.6 Table 30", ""});
        }
    }
    if (findings.empty())
        return CheckResult::ok("DeviceLink has no prohibited tags");
    return {CheckResult::Status::FINDINGS, "DeviceLink contains prohibited tags", std::move(findings)};
}

// ── CF-052: Transform Tag Pair Consistency ──────────────────────────────────

static CheckResult check_cf052_transform_tag_pair_consistency(const ProfileView& pv) {
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls == icSigLinkClass || cls == icSigNamedColorClass)
        return CheckResult::skip("DeviceLink/NamedColor exempt from tag pair check");

    std::vector<Finding> findings;
    struct TagPair { icTagSignature a; icTagSignature b; const char *name; };
    static const TagPair pairs[] = {
        {icSigAToB1Tag, icSigBToA1Tag, "intent 1 (relative)"},
        {icSigAToB2Tag, icSigBToA2Tag, "intent 2 (saturation)"},
    };

    for (int i = 0; i < 2; i++) {
        bool hasA = pv.hasTag(pairs[i].a);
        bool hasB = pv.hasTag(pairs[i].b);
        if (hasA && !hasB) {
            char msg[128];
            std::snprintf(msg, sizeof(msg), "AToB present but BToA missing for %s", pairs[i].name);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 52}, Severity::MEDIUM,
                msg, "ICC.1-2022-05 §8.3-8.5", ""});
        }
        if (!hasA && hasB) {
            char msg[128];
            std::snprintf(msg, sizeof(msg), "BToA present but AToB missing for %s", pairs[i].name);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 52}, Severity::MEDIUM,
                msg, "ICC.1-2022-05 §8.3-8.5", ""});
        }
    }

    // DToB/BToD pairs for v4.4+
    int major = VersionMajor(pv);
    int minor = VersionMinor(pv);
    if (major > 4 || (major == 4 && minor >= 4)) {
        struct DPair { icTagSignature d; icTagSignature b; const char *name; };
        static const DPair dpairs[] = {
            {icSigDToB0Tag, icSigBToD0Tag, "DToB0/BToD0"},
            {icSigDToB1Tag, icSigBToD1Tag, "DToB1/BToD1"},
            {icSigDToB2Tag, icSigBToD2Tag, "DToB2/BToD2"},
            {icSigDToB3Tag, icSigBToD3Tag, "DToB3/BToD3"},
        };
        for (int i = 0; i < 4; i++) {
            bool hasD = pv.hasTag(dpairs[i].d);
            bool hasB = pv.hasTag(dpairs[i].b);
            if (hasD && !hasB) {
                char msg[128];
                std::snprintf(msg, sizeof(msg), "DToB present but BToD missing for %s", dpairs[i].name);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 52}, Severity::MEDIUM,
                    msg, "ICC.1-2022-05 §8", ""});
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("Transform tag pairs consistent");
    return {CheckResult::Status::FINDINGS, "Transform tag pair inconsistency", std::move(findings)};
}

// ── CF-053: cicpTag Class Restriction ───────────────────────────────────────

static CheckResult check_cf053_cicptag_class_restriction(const ProfileView& pv) {
    if (!pv.hasTag(icSigCicpTag))
        return CheckResult::ok("No cicpTag present");

    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls != icSigDisplayClass && cls != icSigInputClass)
        return {CheckResult::Status::FINDINGS, "cicpTag in wrong class", {
            {CheckID{CheckID::Kind::Conformance, 53}, Severity::HIGH,
             "cicpTag only allowed in Display/Input profiles", "ICC.1-2022-05 §9.2.11", ""}}};
    return CheckResult::ok("cicpTag in valid profile class");
}

// ── CF-054: v5 Spectral Required Tags ───────────────────────────────────────

static CheckResult check_cf054_v5_spectral_required_tags(const ProfileView& pv) {
    uint32_t pcs = pv.header().pcs;
    uint8_t pcsFirstByte = (pcs >> 24) & 0xFF;
    if (pcsFirstByte != 0x72 && pcsFirstByte != 0x74)
        return CheckResult::skip("Not a spectral PCS profile");

    if (VersionMajor(pv) < 5)
        return CheckResult::skip("Spectral PCS only defined for v5+");

    std::vector<Finding> findings;
    if (!pv.hasTag(icSigSpectralViewingConditionsTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 54}, Severity::HIGH,
            "v5 spectral profile must have spectralViewingConditionsTag (svcn)",
            "ICC.2-2023 §8", ""});
    if (findings.empty())
        return CheckResult::ok("v5 spectral required tags present");
    return {CheckResult::Status::FINDINGS, "Missing v5 spectral tags", std::move(findings)};
}

// ── CF-055: D2B/B2D Tag Pair Completeness ───────────────────────────────────

static CheckResult check_cf055_d2b_b2d_tag_pair_completeness(const ProfileView& pv) {
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls == icSigLinkClass || cls == icSigNamedColorClass)
        return CheckResult::skip("DeviceLink/NamedColor exempt from D2B/B2D check");

    std::vector<Finding> findings;
    struct Pair { icTagSignature d; icTagSignature b; const char *name; };
    static const Pair pairs[] = {
        {icSigDToB0Tag, icSigBToD0Tag, "intent 0 (perceptual)"},
        {icSigDToB1Tag, icSigBToD1Tag, "intent 1 (relative)"},
        {icSigDToB2Tag, icSigBToD2Tag, "intent 2 (saturation)"},
        {icSigDToB3Tag, icSigBToD3Tag, "intent 3 (absolute)"},
    };

    for (int i = 0; i < 4; i++) {
        bool hasD = pv.hasTag(pairs[i].d);
        bool hasB = pv.hasTag(pairs[i].b);
        if (hasD && !hasB) {
            char msg[128];
            std::snprintf(msg, sizeof(msg), "DToB present but BToD missing for %s", pairs[i].name);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 55}, Severity::MEDIUM,
                msg, "ICC.1-2022-05 §8", ""});
        }
        if (!hasD && hasB) {
            char msg[128];
            std::snprintf(msg, sizeof(msg), "BToD present but DToB missing for %s", pairs[i].name);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 55}, Severity::MEDIUM,
                msg, "ICC.1-2022-05 §8", ""});
        }
    }
    if (findings.empty())
        return CheckResult::ok("D2B/B2D tag pairs complete");
    return {CheckResult::Status::FINDINGS, "D2B/B2D tag pair incomplete", std::move(findings)};
}

// ── CF-056: Embedded Profile Structure ──────────────────────────────────────

static CheckResult check_cf056_embedded_profile_structure(const ProfileView& pv) {
    if (VersionMajor(pv) < 5)
        return CheckResult::skip("Embedded profile checks only for v5+");

    std::vector<Finding> findings;
    for (const auto& entry : pv.rawTagTable()) {
        if (entry.signature == icSigEmbeddedV5ProfileTag) {
            if (entry.size < 128)
                findings.push_back({CheckID{CheckID::Kind::Conformance, 56}, Severity::MEDIUM,
                    "Embedded ICC5 profile tag too small (<128 bytes)",
                    "ICC.2-2023 §9.2", ""});
        }
    }
    if (findings.empty())
        return CheckResult::ok("Embedded profile structure valid");
    return {CheckResult::Status::FINDINGS, "Embedded profile structure issue", std::move(findings)};
}

// ── CF-057: Dictionary Tag Structure v5 ─────────────────────────────────────

static CheckResult check_cf057_dictionary_tag_structure_v5(const ProfileView& pv) {
    if (VersionMajor(pv) < 5)
        return CheckResult::skip("Dictionary tag check only for v5+");

    if (!pv.hasTag(icSigMetaDataTag))
        return CheckResult::ok("No metaDataTag present");

    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library handle unavailable");

    CIccTag *pTag = pIcc->FindTag(icSigMetaDataTag);
    if (!pTag) return CheckResult::ok("No metaDataTag present");

    // dict type = 0x64696374 ('dict')
    if (pTag->GetType() != static_cast<icTagTypeSignature>(0x64696374u))
        return {CheckResult::Status::FINDINGS, "metaDataTag not dict type", {
            {CheckID{CheckID::Kind::Conformance, 57}, Severity::MEDIUM,
             "v5 metaDataTag should be dictionaryType", "ICC.2-2023 §9.2.25", ""}}};

    return CheckResult::ok("Dictionary tag structure valid");
}

// ── CF-058: Profile Sequence Identifier v5 ──────────────────────────────────

static CheckResult check_cf058_profile_sequence_identifier_v5(const ProfileView& pv) {
    if (VersionMajor(pv) < 5)
        return CheckResult::skip("v5 profile sequence check only for v5+");

    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls != icSigLinkClass)
        return CheckResult::skip("Profile sequence identifier check for DeviceLink only");

    // iccDEV has intentional typo: icSigProfileSequceIdTag (missing 'en')
    if (!pv.hasTag(icSigProfileSequceIdTag))
        return {CheckResult::Status::FINDINGS, "v5 DeviceLink missing psid", {
            {CheckID{CheckID::Kind::Conformance, 58}, Severity::MEDIUM,
             "v5 DeviceLink should have profileSequenceIdentifierTag",
             "ICC.2-2023 §8", ""}}};

    return CheckResult::ok("v5 DeviceLink has profileSequenceIdentifierTag");
}

// ── CF-059: Colorimetric Intent Image State ─────────────────────────────────

static CheckResult check_cf059_colorimetric_intent_image_state(const ProfileView& pv) {
    if (!pv.hasTag(icSigColorimetricIntentImageStateTag))
        return CheckResult::ok("No ciis tag present");

    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library handle unavailable");

    CIccTag *pTag = pIcc->FindTag(icSigColorimetricIntentImageStateTag);
    if (!pTag) return CheckResult::ok("No ciis tag present");

    std::vector<Finding> findings;
    if (pTag->GetType() != icSigSignatureType)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 59}, Severity::MEDIUM,
            "ciis tag must be signatureType", "ICC.1-2022-05 §9.2.12", ""});

    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls != icSigInputClass && cls != icSigDisplayClass && cls != icSigOutputClass)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 59}, Severity::MEDIUM,
            "ciis tag unusual in non-device profile class", "ICC.1-2022-05 §9.2.12", ""});

    if (findings.empty())
        return CheckResult::ok("Colorimetric intent image state valid");
    return {CheckResult::Status::FINDINGS, "ciis tag issue", std::move(findings)};
}

// ── CF-095: Non-Required Tag Identification ─────────────────────────────────

static CheckResult check_cf095_non_required_tag_identification(const ProfileView& pv) {
    static const icTagSignature commonReq[] = {
        icSigProfileDescriptionTag, icSigCopyrightTag, icSigMediaWhitePointTag,
        icSigChromaticAdaptationTag,
    };
    static const icTagSignature displayReq[] = {
        icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag,
        icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag,
        icSigAToB0Tag, icSigBToA0Tag,
    };
    static const icTagSignature linkReq[] = {
        icSigProfileDescriptionTag, icSigAToB0Tag, icSigCopyrightTag,
        icSigProfileSequenceDescTag, icSigColorantTableTag,
    };

    auto isInList = [](icTagSignature sig, const icTagSignature *list, int count) -> bool {
        for (int i = 0; i < count; i++)
            if (list[i] == sig) return true;
        return false;
    };

    int nonReqCount = 0;
    for (const auto& entry : pv.rawTagTable()) {
        auto sig = static_cast<icTagSignature>(entry.signature);
        bool required = isInList(sig, commonReq, 4) ||
                        isInList(sig, displayReq, 8) ||
                        isInList(sig, linkReq, 5);
        if (!required) nonReqCount++;
    }

    char summary[128];
    std::snprintf(summary, sizeof(summary), "%d non-required tags identified out of %zu total",
                  nonReqCount, pv.rawTagTable().size());
    return CheckResult::ok(summary);
}

// ── CF-096: Private Tag Signature Range ─────────────────────────────────────

static CheckResult check_cf096_private_tag_signature_range(const ProfileView& pv) {
    std::vector<Finding> findings;

    for (const auto& entry : pv.rawTagTable()) {
        uint32_t sig = entry.signature;
        if (!IsPrintable4CC(sig)) {
            char sigStr[5];
            SigToChars(sig, sigStr);
            char msg[128];
            std::snprintf(msg, sizeof(msg), "Tag signature '%.4s' (0x%08X) contains non-printable bytes",
                          sigStr, sig);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 96}, Severity::MEDIUM,
                msg, "ICC.1-2022-05 §9 private tag signature conventions", ""});
            if (findings.size() >= 5) break;
        }
    }
    if (findings.empty())
        return CheckResult::ok("All tag signatures use printable 4CC");
    return {CheckResult::Status::FINDINGS, "Non-printable tag signatures found", std::move(findings)};
}

// ── CF-097: Private Tag Documentation ───────────────────────────────────────

static CheckResult check_cf097_private_tag_documentation(const ProfileView& pv) {
    // Known vendor prefixes
    static const uint32_t knownVendors[] = {
        0x41444245u, // 'ADBE' (Adobe)
        0x4D534654u, // 'MSFT' (Microsoft)
        0x6170706Cu, // 'appl' (Apple)
        0x4150504Cu, // 'APPL' (Apple)
    };

    int privateCount = 0;
    int knownCount = 0;
    for (const auto& entry : pv.rawTagTable()) {
        uint32_t sig = entry.signature;
        // Rough private tag detection: lowercase first byte or known vendor
        uint8_t firstByte = (sig >> 24) & 0xFF;
        if (firstByte >= 'a' && firstByte <= 'z') {
            privateCount++;
        } else {
            for (int v = 0; v < 4; v++) {
                if (sig == knownVendors[v]) { knownCount++; break; }
            }
        }
    }

    char summary[128];
    std::snprintf(summary, sizeof(summary), "%d private tags, %d from known vendors", privateCount, knownCount);
    return CheckResult::ok(summary);
}

// ── CF-098: Undocumented Private Tags ───────────────────────────────────────

static CheckResult check_cf098_undocumented_private_tags(const ProfileView& pv) {
    // Extended known tag set includes DToB/BToD
    static const icTagSignature knownTags[] = {
        icSigProfileDescriptionTag, icSigCopyrightTag, icSigMediaWhitePointTag,
        icSigChromaticAdaptationTag, icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag,
        icSigBlueMatrixColumnTag, icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag,
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
        icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
        icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag,
        icSigGamutTag, icSigProfileSequenceDescTag, icSigProfileSequceIdTag,
        icSigColorantTableTag, icSigColorantTableOutTag, icSigColorantOrderTag,
        icSigNamedColor2Tag, icSigViewingConditionsTag,
        icSigViewingCondDescTag, icSigLuminanceTag, icSigMeasurementTag,
        icSigTechnologyTag, icSigCicpTag, icSigColorimetricIntentImageStateTag,
        icSigMetaDataTag, icSigMediaBlackPointTag, icSigOutputResponseTag,
        icSigCalibrationDateTimeTag, icSigCharTargetTag, icSigDeviceMfgDescTag,
        icSigDeviceModelDescTag, icSigPreview0Tag, icSigPreview1Tag, icSigPreview2Tag,
        icSigScreeningDescTag, icSigScreeningTag, icSigUcrBgTag,
        icSigSpectralViewingConditionsTag,
    };
    static constexpr int nKnown = sizeof(knownTags) / sizeof(knownTags[0]);

    int undocumented = 0;
    for (const auto& entry : pv.rawTagTable()) {
        auto sig = static_cast<icTagSignature>(entry.signature);
        bool found = false;
        for (int i = 0; i < nKnown; i++) {
            if (knownTags[i] == sig) { found = true; break; }
        }
        if (!found) undocumented++;
    }

    char summary[128];
    std::snprintf(summary, sizeof(summary), "%d undocumented/private tags out of %zu total",
                  undocumented, pv.rawTagTable().size());
    return CheckResult::ok(summary);
}

// ── CF-103: Tag Alignment and Offset ────────────────────────────────────────

static CheckResult check_cf103_tag_alignment_and_offset(const ProfileView& pv) {
    std::vector<Finding> findings;
    uint32_t profileSize = pv.header().size;

    for (const auto& entry : pv.rawTagTable()) {
        if ((entry.offset & 3) != 0) {
            char msg[128];
            char sigStr[5]; SigToChars(entry.signature, sigStr);
            std::snprintf(msg, sizeof(msg), "Tag '%.4s' offset 0x%X not 4-byte aligned", sigStr, entry.offset);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 103}, Severity::HIGH,
                msg, "ICC.1-2022-05 §7.3", ""});
        }
        if (entry.offset + entry.size > profileSize) {
            char msg[128];
            char sigStr[5]; SigToChars(entry.signature, sigStr);
            std::snprintf(msg, sizeof(msg), "Tag '%.4s' extends beyond profile (offset+size=%u > %u)",
                          sigStr, entry.offset + entry.size, profileSize);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 103}, Severity::HIGH,
                msg, "ICC.1-2022-05 §7.3", ""});
        }
        if (findings.size() >= 10) break;
    }
    if (findings.empty())
        return CheckResult::ok("All tags properly aligned and within bounds");
    return {CheckResult::Status::FINDINGS, "Tag alignment/offset issues", std::move(findings)};
}

// ── CF-104: DeviceLink PCS Match ────────────────────────────────────────────

static CheckResult check_cf104_devicelink_pcs_match(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigLinkClass)
        return CheckResult::skip("Not a DeviceLink profile");

    std::vector<Finding> findings;
    if (!pv.hasTag(icSigAToB0Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 104}, Severity::HIGH,
            "DeviceLink must have AToB0Tag", "ICC.1-2022-05 §8.4", ""});

    int major = VersionMajor(pv);
    if (major >= 4 && !pv.hasTag(icSigProfileSequenceDescTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 104}, Severity::MEDIUM,
            "v4+ DeviceLink should have profileSequenceDescTag",
            "ICC.1-2022-05 §8.4", ""});

    if (findings.empty())
        return CheckResult::ok("DeviceLink PCS requirements met");
    return {CheckResult::Status::FINDINGS, "DeviceLink PCS issues", std::move(findings)};
}

// ── CF-111: Required Tags Per Version ───────────────────────────────────────

static CheckResult check_cf111_required_tags_per_version(const ProfileView& pv) {
    std::vector<Finding> findings;
    int major = VersionMajor(pv);
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);

    if (major >= 4 && cls != icSigLinkClass) {
        // chad required for v4+ non-DeviceLink if white point != D50
        double iX = S15Fixed16ToDouble(pv.header().illuminantX);
        double iY = S15Fixed16ToDouble(pv.header().illuminantY);
        double iZ = S15Fixed16ToDouble(pv.header().illuminantZ);
        if (std::fabs(iX - 0.9642) > 0.0001 || std::fabs(iY - 1.0000) > 0.0001 ||
            std::fabs(iZ - 0.8249) > 0.0001) {
            if (!pv.hasTag(icSigChromaticAdaptationTag))
                findings.push_back({CheckID{CheckID::Kind::Conformance, 111}, Severity::HIGH,
                    "v4+ non-DeviceLink with non-D50 white must have chad",
                    "ICC.1-2022-05 §8", ""});
        }
    }

    if (major >= 4 && cls == icSigLinkClass) {
        uint32_t pcs = pv.header().pcs;
        if (IsXCLRColorSpace(pcs) && !pv.hasTag(icSigColorantTableTag))
            findings.push_back({CheckID{CheckID::Kind::Conformance, 111}, Severity::HIGH,
                "v4 DeviceLink with xCLR PCS must have colorantTable",
                "ICC.1-2022-05 §8.6", ""});
    }

    if (findings.empty())
        return CheckResult::ok("Version-specific required tags present");
    return {CheckResult::Status::FINDINGS, "Missing version-specific tags", std::move(findings)};
}

// ── CF-117: Rendering Intent Tags Per Class ─────────────────────────────────

static CheckResult check_cf117_rendering_intent_tags_per_class(const ProfileView& pv) {
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);

    // rig0/rig2 only for Output/Display
    bool hasRig0 = pv.hasTag(icSigPerceptualRenderingIntentGamutTag);
    bool hasRig2 = pv.hasTag(icSigSaturationRenderingIntentGamutTag);

    if ((hasRig0 || hasRig2) && cls != icSigOutputClass && cls != icSigDisplayClass)
        return {CheckResult::Status::FINDINGS, "Gamut tags in wrong class", {
            {CheckID{CheckID::Kind::Conformance, 117}, Severity::MEDIUM,
             "rig0/rig2 gamut tags only valid for Output/Display profiles",
             "ICC.1-2022-05 §8.3-8.5", ""}}};

    return CheckResult::ok("Rendering intent gamut tags in valid class");
}

// ── CF-118: Private Tag Creator Signature ───────────────────────────────────

static CheckResult check_cf118_private_tag_creator_signature(const ProfileView& pv) {
    uint32_t creator = pv.header().creator;
    int privateCount = 0;

    for (const auto& entry : pv.rawTagTable()) {
        uint8_t firstByte = (entry.signature >> 24) & 0xFF;
        if (firstByte >= 'a' && firstByte <= 'z')
            privateCount++;
    }

    if (privateCount > 0 && creator == 0) {
        char msg[128];
        std::snprintf(msg, sizeof(msg), "%d private tags but creator signature is 0x00000000", privateCount);
        return {CheckResult::Status::FINDINGS, "Private tags without creator", {
            {CheckID{CheckID::Kind::Conformance, 118}, Severity::INFO,
             msg, "ICC.1-2022-05 §7.2.12", ""}}};
    }

    char summary[128];
    char creatorStr[5]; SigToChars(creator, creatorStr);
    std::snprintf(summary, sizeof(summary), "Creator '%.4s', %d private tags", creatorStr, privateCount);
    return CheckResult::ok(summary);
}

// ── CF-119: Profile Sequence Identifier ─────────────────────────────────────

static CheckResult check_cf119_profile_sequence_identifier(const ProfileView& pv) {
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);

    if (cls == icSigLinkClass && !pv.hasTag(icSigProfileSequenceDescTag))
        return {CheckResult::Status::FINDINGS, "DeviceLink missing pseq", {
            {CheckID{CheckID::Kind::Conformance, 119}, Severity::INFO,
             "DeviceLink profiles should have profileSequenceDescTag",
             "ICC.1-2022-05 §9.2.33-34", ""}}};

    int major = VersionMajor(pv);
    if (major >= 4 && !pv.hasTag(icSigProfileSequceIdTag)) {
        // psid recommended for v4+
        return {CheckResult::Status::FINDINGS, "v4+ missing psid", {
            {CheckID{CheckID::Kind::Conformance, 119}, Severity::INFO,
             "v4+ profiles should have profileSequenceIdentifierTag for caching",
             "ICC.1-2022-05 §9.2.34", ""}}};
    }

    return CheckResult::ok("Profile sequence identifiers present");
}

// ── CF-120: Named Color Space Dimensions ────────────────────────────────────

static CheckResult check_cf120_named_color_space_dimensions(const ProfileView& pv) {
    if (!pv.hasTag(icSigNamedColor2Tag))
        return CheckResult::skip("No namedColor2Tag present");

    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library handle unavailable");

    CIccTag *pTag = pIcc->FindTag(icSigNamedColor2Tag);
    if (!pTag) return CheckResult::skip("namedColor2Tag not found");

    CIccTagNamedColor2 *pNc = dynamic_cast<CIccTagNamedColor2*>(pTag);
    if (!pNc) return CheckResult::error("namedColor2Tag unexpected type");

    icUInt32Number devCoords = pNc->GetDeviceCoords();
    icUInt32Number spaceSamples = icGetSpaceSamples(
        static_cast<icColorSpaceSignature>(pv.header().colorSpace));

    if (devCoords > 0 && spaceSamples > 0 && devCoords != spaceSamples) {
        char msg[128];
        std::snprintf(msg, sizeof(msg),
            "namedColor2 deviceCoords=%u but colorSpace channels=%u", devCoords, spaceSamples);
        return {CheckResult::Status::FINDINGS, "Named color dimension mismatch", {
            {CheckID{CheckID::Kind::Conformance, 120}, Severity::HIGH,
             msg, "ICC.1-2022-05 §10.14", ""}}};
    }
    return CheckResult::ok("Named color space dimensions consistent");
}

// ── CF-147: Extended Range Colorimetric Intent Required (ICS) ───────────────

static CheckResult check_cf147_extended_range_colorimetric_intent_requi(const ProfileView& pv) {
    // ICS-specific check: extended range display/colorSpace profiles need AToB1+BToA1
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls != icSigDisplayClass && cls != icSigColorSpaceClass)
        return CheckResult::skip("Not Display/ColorSpace — ICS extended range N/A");

    uint32_t flags = pv.header().flags;
    if (!(flags & 0x00000008u)) // icExtendedRangePCS bit
        return CheckResult::skip("Extended range PCS not enabled");

    std::vector<Finding> findings;
    if (!pv.hasTag(icSigAToB1Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 147}, Severity::HIGH,
            "Extended range profile missing AToB1Tag", "ICS-ExtendedRange-Part1 Table 4", ""});
    if (!pv.hasTag(icSigBToA1Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 147}, Severity::HIGH,
            "Extended range profile missing BToA1Tag", "ICS-ExtendedRange-Part1 Table 4", ""});
    if (findings.empty())
        return CheckResult::ok("Extended range colorimetric intent tags present");
    return {CheckResult::Status::FINDINGS, "Missing extended range intent tags", std::move(findings)};
}

// ── CF-149: Extended Output Profile Class (ICS) ─────────────────────────────

static CheckResult check_cf149_extended_output_profile_class(const ProfileView& pv) {
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls != icSigOutputClass)
        return CheckResult::skip("Not Output — ICS extended output N/A");

    uint32_t pcs = pv.header().pcs;
    uint8_t pcsFirstByte = (pcs >> 24) & 0xFF;
    if (pcsFirstByte != 0x72 && pcsFirstByte != 0x74)
        return CheckResult::skip("Not spectral PCS — ICS extended output N/A");

    std::vector<Finding> findings;
    if (!pv.hasTag(icSigSpectralWhitePointTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 149}, Severity::HIGH,
            "Spectral output missing swpt tag", "ICS-ExtendedOutput-Part1 Table 12", ""});
    if (!pv.hasTag(icSigSpectralViewingConditionsTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 149}, Severity::HIGH,
            "Spectral output missing svcn tag", "ICS-ExtendedOutput-Part1 Table 12", ""});
    if (!pv.hasTag(icSigCustomToStandardPccTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 149}, Severity::HIGH,
            "Spectral output missing c2sp tag", "ICS-ExtendedOutput-Part1 Table 12", ""});
    if (!pv.hasTag(icSigStandardToCustomPccTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 149}, Severity::HIGH,
            "Spectral output missing s2cp tag", "ICS-ExtendedOutput-Part1 Table 12", ""});
    if (findings.empty())
        return CheckResult::ok("Extended output profile tags present");
    return {CheckResult::Status::FINDINGS, "Missing extended output tags", std::move(findings)};
}

// ── CF-152: Extended Output AToB/BToA/DToB Completeness (ICS) ───────────────

static CheckResult check_cf152_extended_output_atob_btoa_dtob_completen(const ProfileView& pv) {
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls != icSigOutputClass)
        return CheckResult::skip("Not Output — ICS extended output N/A");

    uint32_t pcs = pv.header().pcs;
    uint8_t pcsFirstByte = (pcs >> 24) & 0xFF;
    if (pcsFirstByte != 0x72 && pcsFirstByte != 0x74)
        return CheckResult::skip("Not spectral PCS — ICS extended output N/A");

    std::vector<Finding> findings;
    static const struct { icTagSignature sig; const char *name; } required[] = {
        {icSigAToB1Tag, "AToB1"}, {icSigAToB3Tag, "AToB3"},
        {icSigBToA1Tag, "BToA1"}, {icSigBToA3Tag, "BToA3"},
        {icSigDToB3Tag, "DToB3"},
    };
    for (int i = 0; i < 5; i++) {
        if (!pv.hasTag(required[i].sig)) {
            char msg[128];
            std::snprintf(msg, sizeof(msg), "Spectral output missing %sTag", required[i].name);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 152}, Severity::HIGH,
                msg, "ICS-ExtendedOutput-Part1 Table 12", ""});
        }
    }
    if (findings.empty())
        return CheckResult::ok("Extended output AToB/BToA/DToB complete");
    return {CheckResult::Status::FINDINGS, "Missing extended output transform tags", std::move(findings)};
}

// ── CF-202: Tag Data Padding Zero-Fill ──────────────────────────────────────

static CheckResult check_cf202_tag_data_padding_zero_fill(const ProfileView& pv) {
    const uint8_t *data = pv.rawData();
    size_t dataSize = pv.rawSize();
    if (!data || dataSize < 132)
        return CheckResult::skip("No raw data available");

    auto tagTable = pv.rawTagTable();
    if (tagTable.empty())
        return CheckResult::ok("No tags to check padding");

    // Build sorted list of tag regions
    struct Region { uint32_t start; uint32_t end; };
    std::vector<Region> regions;
    for (const auto& entry : tagTable) {
        if (entry.offset > 0 && entry.size > 0 && entry.offset + entry.size <= dataSize)
            regions.push_back({entry.offset, entry.offset + entry.size});
    }
    std::sort(regions.begin(), regions.end(), [](const Region& a, const Region& b) {
        return a.start < b.start;
    });

    std::vector<Finding> findings;
    for (size_t i = 0; i + 1 < regions.size() && findings.size() < 3; i++) {
        uint32_t gapStart = regions[i].end;
        uint32_t gapEnd = regions[i + 1].start;
        if (gapStart >= gapEnd) continue;
        uint32_t gapLen = gapEnd - gapStart;
        if (gapLen > 64) gapLen = 64; // cap scan
        for (uint32_t j = 0; j < gapLen; j++) {
            if (gapStart + j < dataSize && data[gapStart + j] != 0) {
                char msg[128];
                std::snprintf(msg, sizeof(msg),
                    "Non-zero padding byte at offset 0x%X (gap between tags)", gapStart + j);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 202}, Severity::MEDIUM,
                    msg, "ICC.1-2022-05 §7.2.1c", ""});
                break;
            }
        }
    }
    if (findings.empty())
        return CheckResult::ok("Tag data padding is zero-filled");
    return {CheckResult::Status::FINDINGS, "Non-zero padding found", std::move(findings)};
}

// ── CF-204: Device Attributes Semantic Validation ───────────────────────────

static CheckResult check_cf204_device_attributes_semantic_validation(const ProfileView& pv) {
    uint64_t attrs = pv.header().attributes;
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);

    std::vector<Finding> findings;

    // Bits 0-3 describe physical media — non-physical classes should be 0
    if (cls == icSigAbstractClass || cls == icSigNamedColorClass || cls == icSigColorSpaceClass) {
        if (attrs & 0x0F) {
            findings.push_back({CheckID{CheckID::Kind::Conformance, 204}, Severity::MEDIUM,
                "Non-physical profile class has media attribute bits set",
                "ICC.1-2022-05 §7.2.14 Table 22", ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok("Device attributes semantically valid");
    return {CheckResult::Status::FINDINGS, "Device attribute semantic issues", std::move(findings)};
}

// ── CF-205: Tag Data Region Gap Analysis ────────────────────────────────────

static CheckResult check_cf205_tag_data_region_gap_analysis(const ProfileView& pv) {
    uint32_t profileSize = pv.header().size;
    if (profileSize < 132)
        return CheckResult::skip("Profile too small for gap analysis");

    auto tagTable = pv.rawTagTable();
    if (tagTable.empty())
        return CheckResult::ok("No tags to analyze");

    // Build sorted unique regions (shared-data tags have same offset)
    struct Region { uint32_t start; uint32_t end; };
    std::vector<Region> regions;
    std::set<uint32_t> seen;
    for (const auto& entry : tagTable) {
        if (seen.count(entry.offset)) continue;
        seen.insert(entry.offset);
        if (entry.offset > 0 && entry.size > 0) {
            uint32_t end = entry.offset + entry.size;
            if (end > profileSize) end = profileSize;
            regions.push_back({entry.offset, end});
        }
    }
    std::sort(regions.begin(), regions.end(), [](const Region& a, const Region& b) {
        return a.start < b.start;
    });

    // Compute coverage
    uint32_t covered = 0;
    for (const auto& r : regions) covered += (r.end - r.start);

    uint32_t dataArea = profileSize - 128; // exclude header
    double coveragePct = dataArea > 0 ? (100.0 * covered / dataArea) : 0;

    std::vector<Finding> findings;
    if (coveragePct < 30.0) {
        char msg[128];
        std::snprintf(msg, sizeof(msg), "Tag data covers only %.1f%% of profile data area", coveragePct);
        findings.push_back({CheckID{CheckID::Kind::Conformance, 205}, Severity::INFO,
            msg, "ICC.1-2022-05 §7.3", ""});
    }

    // Check for large gaps
    for (size_t i = 0; i + 1 < regions.size() && findings.size() < 3; i++) {
        uint32_t gapSize = (regions[i + 1].start > regions[i].end) ?
                           (regions[i + 1].start - regions[i].end) : 0;
        double gapPct = dataArea > 0 ? (100.0 * gapSize / dataArea) : 0;
        if (gapPct > 10.0) {
            char msg[128];
            std::snprintf(msg, sizeof(msg), "Gap of %u bytes (%.1f%%) at offset 0x%X",
                          gapSize, gapPct, regions[i].end);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 205}, Severity::INFO,
                msg, "ICC.1-2022-05 §7.3", ""});
        }
    }
    if (findings.empty()) {
        char summary[128];
        std::snprintf(summary, sizeof(summary), "Tag data coverage %.1f%%", coveragePct);
        return CheckResult::ok(summary);
    }
    return {CheckResult::Status::FINDINGS, "Tag data region gaps detected", std::move(findings)};
}

// ── CF-207: mediaWhitePointTag Value Range ──────────────────────────────────

static CheckResult check_cf207_mediawhitepointtag_value_range(const ProfileView& pv) {
    if (!pv.hasTag(icSigMediaWhitePointTag))
        return CheckResult::skip("No mediaWhitePointTag");

    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library handle unavailable");

    CIccTag *pTag = pIcc->FindTag(icSigMediaWhitePointTag);
    if (!pTag) return CheckResult::skip("mediaWhitePointTag not found");

    CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ*>(pTag);
    if (!pXYZ || pXYZ->GetSize() < 1)
        return {CheckResult::Status::FINDINGS, "wtpt not XYZType", {
            {CheckID{CheckID::Kind::Conformance, 207}, Severity::HIGH,
             "mediaWhitePointTag must be XYZType", "ICC.1-2022-05 §10.27", ""}}};

    const icXYZNumber *xyz = pXYZ->GetXYZ(0);
    if (!xyz) return CheckResult::error("Cannot read XYZ value");

    double X = icFtoD(xyz->X);
    double Y = icFtoD(xyz->Y);
    double Z = icFtoD(xyz->Z);

    std::vector<Finding> findings;
    if (X <= 0 || Y <= 0 || Z <= 0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 207}, Severity::HIGH,
            "mediaWhitePoint XYZ values must be positive",
            "ICC.1-2022-05 §9.2.28", ""});

    if (X > 3.0 || Y > 3.0 || Z > 3.0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 207}, Severity::MEDIUM,
            "mediaWhitePoint XYZ values exceed plausible range (>3.0)",
            "ICC.1-2022-05 §9.2.28", ""});

    // v4+ non-DeviceLink must be D50
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (VersionMajor(pv) >= 4 && cls != icSigLinkClass) {
        const double tol = 0.002;
        if (std::fabs(X - 0.9642) > tol || std::fabs(Y - 1.0000) > tol || std::fabs(Z - 0.8249) > tol) {
            char msg[128];
            std::snprintf(msg, sizeof(msg),
                "v4+ non-DeviceLink wtpt=(%.4f,%.4f,%.4f), expected D50=(0.9642,1.0000,0.8249)", X, Y, Z);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 207}, Severity::HIGH,
                msg, "ICC.1-2022-05 §10.27", ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok("mediaWhitePoint XYZ values valid");
    return {CheckResult::Status::FINDINGS, "mediaWhitePoint value issues", std::move(findings)};
}

// ── CF-211: AToB/BToA Tag Pair Completeness ─────────────────────────────────

static CheckResult check_cf211_atob_btoa_tag_pair_completeness(const ProfileView& pv) {
    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls == icSigLinkClass)
        return CheckResult::skip("DeviceLink exempt from AToB/BToA pair check");

    struct Pair { icTagSignature a; icTagSignature b; const char *name; };
    static const Pair pairs[] = {
        {icSigAToB0Tag, icSigBToA0Tag, "intent 0"},
        {icSigAToB1Tag, icSigBToA1Tag, "intent 1"},
        {icSigAToB2Tag, icSigBToA2Tag, "intent 2"},
    };

    std::vector<Finding> findings;
    for (int i = 0; i < 3; i++) {
        bool hasA = pv.hasTag(pairs[i].a);
        bool hasB = pv.hasTag(pairs[i].b);
        if (hasA && !hasB) {
            char msg[128];
            std::snprintf(msg, sizeof(msg), "AToB%d present but BToA%d missing (%s)", i, i, pairs[i].name);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 211}, Severity::MEDIUM,
                msg, "ICC.1-2022-05 §9.2.1-9.2.2", ""});
        }
    }
    if (findings.empty())
        return CheckResult::ok("AToB/BToA tag pairs complete");
    return {CheckResult::Status::FINDINGS, "AToB/BToA pair incomplete", std::move(findings)};
}

// ── CF-258: Display v4+ mediaWhitePointTag D50 ──────────────────────────────

static CheckResult check_cf258_display_v4_mediawhitepointtag_d50(const ProfileView& pv) {
    if (VersionMajor(pv) < 4)
        return CheckResult::skip("Profile version < 4.0 — D50 wtpt not mandated");

    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigDisplayClass)
        return CheckResult::skip("Not a Display profile");

    if (!pv.hasTag(icSigMediaWhitePointTag))
        return {CheckResult::Status::FINDINGS, "Display v4+ missing wtpt", {
            {CheckID{CheckID::Kind::Conformance, 258}, Severity::HIGH,
             "Display v4+ must have mediaWhitePointTag", "ICC.1-2022-05 §8.4", ""}}};

    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library handle unavailable");

    CIccTag *pTag = pIcc->FindTag(icSigMediaWhitePointTag);
    CIccTagXYZ *pXYZ = pTag ? dynamic_cast<CIccTagXYZ*>(pTag) : nullptr;
    if (!pXYZ || pXYZ->GetSize() < 1)
        return {CheckResult::Status::FINDINGS, "wtpt not XYZType", {
            {CheckID{CheckID::Kind::Conformance, 258}, Severity::HIGH,
             "mediaWhitePointTag must be XYZType", "ICC.1-2022-05 §8.4", ""}}};

    const icXYZNumber *xyz = pXYZ->GetXYZ(0);
    if (!xyz) return CheckResult::error("Cannot read XYZ value");

    double X = icFtoD(xyz->X);
    double Y = icFtoD(xyz->Y);
    double Z = icFtoD(xyz->Z);
    const double tol = 0.005;

    if (std::fabs(X - 0.9642) > tol || std::fabs(Y - 1.0000) > tol || std::fabs(Z - 0.8249) > tol) {
        char msg[128];
        std::snprintf(msg, sizeof(msg),
            "Display v4+ wtpt=(%.4f,%.4f,%.4f), expected D50=(0.9642,1.0000,0.8249)", X, Y, Z);
        return {CheckResult::Status::FINDINGS, "Display wtpt != D50", {
            {CheckID{CheckID::Kind::Conformance, 258}, Severity::HIGH,
             msg, "ICC.1-2022-05 §8.4", ""}}};
    }
    return CheckResult::ok("Display v4+ mediaWhitePointTag equals D50");
}

// ── CF-259: colorantOrderTag vs colorantTableTag Cross-Validation ────────────

static CheckResult check_cf259_colorantordertag_vs_coloranttabletag_cro(const ProfileView& pv) {
    bool hasOrder = pv.hasTag(icSigColorantOrderTag);
    bool hasTable = pv.hasTag(icSigColorantTableTag);

    if (!hasOrder && !hasTable)
        return CheckResult::ok("Neither colorantOrder nor colorantTable present");
    if (hasOrder && !hasTable)
        return {CheckResult::Status::FINDINGS, "Order without table", {
            {CheckID{CheckID::Kind::Conformance, 259}, Severity::HIGH,
             "colorantOrderTag present without colorantTableTag", "ICC.1-2022-05 §10.3", ""}}};
    if (!hasOrder)
        return CheckResult::ok("colorantTable present without colorantOrder — OK");

    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library handle unavailable");

    CIccTagColorantOrder *pOrder = dynamic_cast<CIccTagColorantOrder*>(pIcc->FindTag(icSigColorantOrderTag));
    CIccTagColorantTable *pTable = dynamic_cast<CIccTagColorantTable*>(pIcc->FindTag(icSigColorantTableTag));
    if (!pOrder || !pTable)
        return {CheckResult::Status::FINDINGS, "Unexpected tag types", {
            {CheckID{CheckID::Kind::Conformance, 259}, Severity::HIGH,
             "Unexpected types for colorant tags", "ICC.1-2022-05 §10.3", ""}}};

    icUInt32Number orderCount = pOrder->GetSize();
    icUInt32Number tableCount = pTable->GetSize();

    std::vector<Finding> findings;
    if (orderCount != tableCount) {
        char msg[128];
        std::snprintf(msg, sizeof(msg), "colorantOrder count (%u) != colorantTable count (%u)",
                      orderCount, tableCount);
        findings.push_back({CheckID{CheckID::Kind::Conformance, 259}, Severity::HIGH,
            msg, "ICC.1-2022-05 §10.3", ""});
    }

    for (icUInt32Number i = 0; i < orderCount && i < 64 && findings.size() < 5; i++) {
        icUInt8Number idx = (*pOrder)[i];
        if (idx >= tableCount) {
            char msg[128];
            std::snprintf(msg, sizeof(msg), "colorantOrder[%u]=%u exceeds colorantTable count (%u)",
                          i, idx, tableCount);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 259}, Severity::HIGH,
                msg, "ICC.1-2022-05 §10.3", ""});
        }
    }
    if (findings.empty())
        return CheckResult::ok("colorantOrder indices valid within colorantTable");
    return {CheckResult::Status::FINDINGS, "Colorant cross-validation issues", std::move(findings)};
}

// ── CF-260: Output Profile gamutTag Rendering Intent ────────────────────────

static CheckResult check_cf260_output_profile_gamuttag_rendering_intent(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigOutputClass)
        return CheckResult::skip("Not an Output profile");

    bool hasPerceptual = pv.hasTag(icSigAToB0Tag);
    bool hasSaturation = pv.hasTag(icSigAToB2Tag);
    if (!hasPerceptual && !hasSaturation)
        return CheckResult::ok("No perceptual/saturation intents present");

    if (!pv.hasTag(icSigGamutTag)) {
        std::string intents;
        if (hasPerceptual) intents = "perceptual";
        if (hasSaturation) { if (!intents.empty()) intents += " + "; intents += "saturation"; }
        char msg[200];
        std::snprintf(msg, sizeof(msg),
            "Output profile has %s intent(s) but no gamutTag", intents.c_str());
        return {CheckResult::Status::FINDINGS, "Missing gamutTag", {
            {CheckID{CheckID::Kind::Conformance, 260}, Severity::MEDIUM,
             msg, "ICC.1-2022-05 §9.2.22", ""}}};
    }
    return CheckResult::ok("Output profile gamutTag present for rendering intents");
}

// ── CF-266: Input Profile Device Color Space ────────────────────────────────

static CheckResult check_cf266_input_profile_device_color_space(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigInputClass)
        return CheckResult::skip("Not an Input profile");

    auto cs = static_cast<icColorSpaceSignature>(pv.header().colorSpace);
    bool valid = (cs == icSigRgbData || cs == icSigCmykData || cs == icSigGrayData ||
                  icGetColorSpaceType(cs) == icSigNChannelData);
    if (!valid) {
        char sigStr[5]; SigToChars(pv.header().colorSpace, sigStr);
        char msg[128];
        std::snprintf(msg, sizeof(msg),
            "Input profile device color space '%.4s' — expected RGB, CMYK, Gray, or nCLR", sigStr);
        return {CheckResult::Status::FINDINGS, "Invalid input color space", {
            {CheckID{CheckID::Kind::Conformance, 266}, Severity::HIGH,
             msg, "ICC.1-2022-05 §6.1", ""}}};
    }
    return CheckResult::ok("Input profile device color space valid");
}

// ── CF-267: Display Profile Color Space ─────────────────────────────────────

static CheckResult check_cf267_display_profile_color_space(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigDisplayClass)
        return CheckResult::skip("Not a Display profile");

    auto cs = static_cast<icColorSpaceSignature>(pv.header().colorSpace);
    bool valid = (cs == icSigRgbData || cs == icSigGrayData ||
                  icGetColorSpaceType(cs) == icSigNChannelData);
    if (!valid) {
        char sigStr[5]; SigToChars(pv.header().colorSpace, sigStr);
        char msg[128];
        std::snprintf(msg, sizeof(msg),
            "Display profile device color space '%.4s' — expected RGB, Gray, or nCLR", sigStr);
        return {CheckResult::Status::FINDINGS, "Invalid display color space", {
            {CheckID{CheckID::Kind::Conformance, 267}, Severity::HIGH,
             msg, "ICC.1-2022-05 §6.2", ""}}};
    }
    return CheckResult::ok("Display profile device color space valid");
}

// ── CF-268: Output Profile Color Space ──────────────────────────────────────

static CheckResult check_cf268_output_profile_color_space(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigOutputClass)
        return CheckResult::skip("Not an Output profile");

    auto cs = static_cast<icColorSpaceSignature>(pv.header().colorSpace);
    bool valid = (cs == icSigRgbData || cs == icSigCmykData || cs == icSigCmyData ||
                  cs == icSigGrayData || icGetColorSpaceType(cs) == icSigNChannelData);
    if (!valid) {
        char sigStr[5]; SigToChars(pv.header().colorSpace, sigStr);
        char msg[128];
        std::snprintf(msg, sizeof(msg),
            "Output profile device color space '%.4s' — expected RGB, CMYK, CMY, Gray, or nCLR", sigStr);
        return {CheckResult::Status::FINDINGS, "Invalid output color space", {
            {CheckID{CheckID::Kind::Conformance, 268}, Severity::HIGH,
             msg, "ICC.1-2022-05 §6.3", ""}}};
    }
    return CheckResult::ok("Output profile device color space valid");
}

// ── CF-269: DeviceLink Data Color Space Matching ────────────────────────────

static CheckResult check_cf269_devicelink_data_color_space_matching(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigLinkClass)
        return CheckResult::skip("Not a DeviceLink profile");

    auto isDeviceSpace = [](icColorSpaceSignature s) -> bool {
        return (s == icSigRgbData || s == icSigCmykData || s == icSigCmyData ||
                s == icSigGrayData || s == icSigLabData || s == icSigXYZData ||
                s == icSigYCbCrData || s == icSigHsvData || s == icSigHlsData ||
                s == icSigLuvData || icGetColorSpaceType(s) == icSigNChannelData);
    };

    auto cs  = static_cast<icColorSpaceSignature>(pv.header().colorSpace);
    auto pcs = static_cast<icColorSpaceSignature>(pv.header().pcs);

    std::vector<Finding> findings;
    if (!isDeviceSpace(cs))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 269}, Severity::HIGH,
            "DeviceLink source color space unrecognized", "ICC.1-2022-05 §6.4", ""});
    if (!isDeviceSpace(pcs))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 269}, Severity::HIGH,
            "DeviceLink destination color space unrecognized", "ICC.1-2022-05 §6.4", ""});
    if (findings.empty())
        return CheckResult::ok("DeviceLink color spaces valid");
    return {CheckResult::Status::FINDINGS, "DeviceLink color space issues", std::move(findings)};
}

// ── CF-270: Abstract Profile PCS ────────────────────────────────────────────

static CheckResult check_cf270_abstract_profile_pcs(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigAbstractClass)
        return CheckResult::skip("Not an Abstract profile");

    auto cs  = static_cast<icColorSpaceSignature>(pv.header().colorSpace);
    auto pcs = static_cast<icColorSpaceSignature>(pv.header().pcs);

    std::vector<Finding> findings;
    if (cs != icSigLabData && cs != icSigXYZData)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 270}, Severity::HIGH,
            "Abstract profile colorSpace must be Lab or XYZ", "ICC.1-2022-05 §6.6", ""});
    if (pcs != icSigLabData && pcs != icSigXYZData)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 270}, Severity::HIGH,
            "Abstract profile PCS must be Lab or XYZ", "ICC.1-2022-05 §6.6", ""});
    if (findings.empty())
        return CheckResult::ok("Abstract profile PCS valid");
    return {CheckResult::Status::FINDINGS, "Abstract profile PCS issues", std::move(findings)};
}

// ── CF-271: NamedColor Profile PCS ──────────────────────────────────────────

static CheckResult check_cf271_namedcolor_profile_pcs(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigNamedColorClass)
        return CheckResult::skip("Not a NamedColor profile");

    auto pcs = static_cast<icColorSpaceSignature>(pv.header().pcs);
    if (pcs != icSigLabData && pcs != icSigXYZData)
        return {CheckResult::Status::FINDINGS, "NamedColor PCS invalid", {
            {CheckID{CheckID::Kind::Conformance, 271}, Severity::HIGH,
             "NamedColor profile PCS must be Lab or XYZ", "ICC.1-2022-05 §6.7", ""}}};
    return CheckResult::ok("NamedColor profile PCS valid");
}

// ── CF-272: Matrix/TRC RGB Required Colorant Tags ───────────────────────────

static CheckResult check_cf272_matrix_trc_rgb_required_colorant_tags(const ProfileView& pv) {
    if (pv.header().colorSpace != static_cast<uint32_t>(icSigRgbData))
        return CheckResult::skip("Not RGB color space");

    auto cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    if (cls != icSigInputClass && cls != icSigDisplayClass)
        return CheckResult::skip("Not Input/Display class");

    bool hasRTRC = pv.hasTag(icSigRedTRCTag);
    bool hasAToB0 = pv.hasTag(icSigAToB0Tag);
    if (!hasRTRC && hasAToB0) return CheckResult::skip("LUT-based profile");
    if (!hasRTRC && !hasAToB0) return CheckResult::skip("No transform model");

    static const struct { icTagSignature sig; const char *name; } tags[] = {
        {icSigRedMatrixColumnTag, "rXYZ"}, {icSigGreenMatrixColumnTag, "gXYZ"},
        {icSigBlueMatrixColumnTag, "bXYZ"}, {icSigRedTRCTag, "rTRC"},
        {icSigGreenTRCTag, "gTRC"}, {icSigBlueTRCTag, "bTRC"},
    };

    std::vector<Finding> findings;
    for (int i = 0; i < 6; i++) {
        if (!pv.hasTag(tags[i].sig)) {
            char msg[128];
            std::snprintf(msg, sizeof(msg), "Missing matrix/TRC tag '%s'", tags[i].name);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 272}, Severity::HIGH,
                msg, "ICC.1-2022-05 §9.2.47", ""});
        }
    }
    if (findings.empty())
        return CheckResult::ok("All matrix/TRC colorant tags present");
    return {CheckResult::Status::FINDINGS, "Missing matrix/TRC tags", std::move(findings)};
}

// ── CF-282: DeviceLink AToB0Tag Required ────────────────────────────────────

static CheckResult check_cf282_devicelink_atob0tag_required(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigLinkClass)
        return CheckResult::skip("Not a DeviceLink profile");

    if (!pv.hasTag(icSigAToB0Tag))
        return {CheckResult::Status::FINDINGS, "DeviceLink missing AToB0", {
            {CheckID{CheckID::Kind::Conformance, 282}, Severity::HIGH,
             "DeviceLink profile must contain AToB0Tag", "ICC.1-2022-05 §6.4", ""}}};
    return CheckResult::ok("DeviceLink AToB0Tag present");
}

// ── CF-283: DeviceLink profileSequenceDescTag ───────────────────────────────

static CheckResult check_cf283_devicelink_profilesequencedesctag(const ProfileView& pv) {
    if (static_cast<icProfileClassSignature>(pv.header().deviceClass) != icSigLinkClass)
        return CheckResult::skip("Not a DeviceLink profile");

    if (!pv.hasTag(icSigProfileSequenceDescTag))
        return {CheckResult::Status::FINDINGS, "DeviceLink missing pseq", {
            {CheckID{CheckID::Kind::Conformance, 283}, Severity::MEDIUM,
             "DeviceLink should contain profileSequenceDescTag", "ICC.1-2022-05 §6.4", ""}}};
    return CheckResult::ok("DeviceLink profileSequenceDescTag present");
}

// ── Registrations (51 checks) ──

REGISTER_CONFORMANCE(40, "Common Required Tags (Non-DeviceLink)",
    "§8.2", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf040_common_required_tags_non_devicelink);

REGISTER_CONFORMANCE(41, "Input Profile Required Tags",
    "§8.3 Tables 22-24", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf041_input_profile_required_tags);

REGISTER_CONFORMANCE(42, "Display Profile Required Tags",
    "§8.4 Tables 25-27", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf042_display_profile_required_tags);

REGISTER_CONFORMANCE(43, "Output Profile Required Tags",
    "§8.5 Tables 28-29", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf043_output_profile_required_tags);

REGISTER_CONFORMANCE(44, "DeviceLink Profile Required Tags",
    "§8.6 Table 30", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf044_devicelink_profile_required_tags);

REGISTER_CONFORMANCE(45, "ColorSpace Profile Required Tags",
    "§8.7 Table 31", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf045_colorspace_profile_required_tags);

REGISTER_CONFORMANCE(46, "Abstract Profile Required Tags",
    "§8.8 Table 32", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf046_abstract_profile_required_tags);

REGISTER_CONFORMANCE(47, "NamedColor Profile Required Tags",
    "§8.9 Table 33", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf047_namedcolor_profile_required_tags);

REGISTER_CONFORMANCE(48, "Rendering Intent Transform Consistency",
    "§7.2.15, §8", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf048_rendering_intent_transform_consistency);

REGISTER_CONFORMANCE(49, "Matrix/TRC Profile PCS Must Be XYZ",
    "§8.3-8.4", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf049_matrix_trc_profile_pcs_must_be_xyz);

REGISTER_CONFORMANCE(50, "xCLR Colorant Table Required",
    "§8.5-8.6", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf050_xclr_colorant_table_required);

REGISTER_CONFORMANCE(51, "DeviceLink Prohibited Tags",
    "§8.6 Table 30", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf051_devicelink_prohibited_tags);

REGISTER_CONFORMANCE(52, "Transform Tag Pair Consistency",
    "§8.3-8.5", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf052_transform_tag_pair_consistency);

REGISTER_CONFORMANCE(53, "cicpTag Class Restriction",
    "§9.2.11", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf053_cicptag_class_restriction);

REGISTER_CONFORMANCE(54, "v5 Spectral Required Tags",
    "§8", "ICC.2-2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf054_v5_spectral_required_tags);

REGISTER_CONFORMANCE(55, "D2B/B2D Tag Pair Completeness",
    "§8", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf055_d2b_b2d_tag_pair_completeness);

REGISTER_CONFORMANCE(56, "Embedded Profile Structure",
    "§9.2", "ICC.2-2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf056_embedded_profile_structure);

REGISTER_CONFORMANCE(57, "Dictionary Tag Structure v5",
    "§9.2.25", "ICC.2-2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf057_dictionary_tag_structure_v5);

REGISTER_CONFORMANCE(58, "Profile Sequence Identifier v5",
    "§8", "ICC.2-2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf058_profile_sequence_identifier_v5);

REGISTER_CONFORMANCE(59, "Colorimetric Intent Image State",
    "§9.2.12", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf059_colorimetric_intent_image_state);

REGISTER_CONFORMANCE(95, "Non-Required Tag Identification",
    "§8.2-§8.9 (required tags per class)", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf095_non_required_tag_identification);

REGISTER_CONFORMANCE(96, "Private Tag Signature Range",
    "§9 (private tag signature conventions)", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf096_private_tag_signature_range);

REGISTER_CONFORMANCE(97, "Private Tag Documentation",
    "§9 (vendor documentation)", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf097_private_tag_documentation);

REGISTER_CONFORMANCE(98, "Undocumented Private Tags",
    "§9 (undocumented tag identification)", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf098_undocumented_private_tags);

REGISTER_CONFORMANCE(103, "Tag Alignment and Offset",
    "§7.3 (tag table offset/alignment)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf103_tag_alignment_and_offset);

REGISTER_CONFORMANCE(104, "DeviceLink PCS Match",
    "§8.4 (DeviceLink required tags)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf104_devicelink_pcs_match);

REGISTER_CONFORMANCE(111, "Required Tags Per Version",
    "§8 (v4+ chad requirement for non-D50 adopted white)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf111_required_tags_per_version);

REGISTER_CONFORMANCE(117, "Rendering Intent Tags Per Class",
    "§8.3-8.5 (rig0/rig2 only for Output/Display)", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf117_rendering_intent_tags_per_class);

REGISTER_CONFORMANCE(118, "Private Tag Creator Signature",
    "§7.2.12 (creator signature for private tags)", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf118_private_tag_creator_signature);

REGISTER_CONFORMANCE(119, "Profile Sequence Identifier",
    "§9.2.33-34 (profileSequenceDescTag/Identifier)", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf119_profile_sequence_identifier);

REGISTER_CONFORMANCE(120, "Named Color Space Dimensions",
    "§10.14 (device coords match colour space)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf120_named_color_space_dimensions);

REGISTER_CONFORMANCE(147, "Extended Range Colorimetric Intent Required",
    "AToB1Tag and BToA1Tag required for extended range display/colorSpace profiles", "ICS-ExtendedRange-Part1 Table 4",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf147_extended_range_colorimetric_intent_requi);

REGISTER_CONFORMANCE(149, "Extended Output Profile Class",
    "Output class with spectral PCS requires swpt, svcn, c2sp, s2cp tags", "ICS-ExtendedOutput-Part1 Table 12",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf149_extended_output_profile_class);

REGISTER_CONFORMANCE(152, "Extended Output AToB/BToA/DToB Completeness",
    "Spectral output profiles require AToB1/3, BToA1/3, DToB3 tags", "ICS-ExtendedOutput-Part1 Table 12",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf152_extended_output_atob_btoa_dtob_completen);

REGISTER_CONFORMANCE(202, "Tag Data Padding Zero-Fill",
    "Verify padding bytes between tag data regions are zero per spec requirement", "ICC.1-2022-05 §7.2.1c",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf202_tag_data_padding_zero_fill);

REGISTER_CONFORMANCE(204, "Device Attributes Semantic Validation",
    "Validate device attributes bits (reflective/transparency, glossy/matte, media polarity, colour/BW) and cross-check against profile class", "ICC.1-2022-05 §7.2.14 Table 22",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf204_device_attributes_semantic_validation);

REGISTER_CONFORMANCE(205, "Tag Data Region Gap Analysis",
    "Analyze tag data region layout for coverage efficiency and detect excessive gaps", "ICC.1-2022-05 §7.3",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf205_tag_data_region_gap_analysis);

REGISTER_CONFORMANCE(207, "mediaWhitePointTag Value Range",
    "Validate XYZ values in mediaWhitePointTag are positive and physically plausible; v4+ non-DeviceLink must be D50", "ICC.1-2022-05 §10.27, §9.2.28",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf207_mediawhitepointtag_value_range);

REGISTER_CONFORMANCE(211, "AToB/BToA Tag Pair Completeness",
    "Check that AToB tags have matching BToA counterparts for bidirectional color transforms", "ICC.1-2022-05 §9.2.1-9.2.2",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf211_atob_btoa_tag_pair_completeness);

REGISTER_CONFORMANCE(258, "Display v4+ mediaWhitePointTag D50",
    "Display profiles v4+ must have mediaWhitePointTag equal to D50 illuminant", "ICC.1-2022-05 §8.4",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf258_display_v4_mediawhitepointtag_d50);

REGISTER_CONFORMANCE(259, "colorantOrderTag vs colorantTableTag Cross-Validation",
    "colorantOrderTag indices must reference valid colorantTableTag entries", "ICC.1-2022-05 §10.3",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf259_colorantordertag_vs_coloranttabletag_cro);

REGISTER_CONFORMANCE(260, "Output Profile gamutTag Rendering Intent",
    "Output profiles with perceptual/saturation intents should include gamutTag", "ICC.1-2022-05 §9.2.22",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf260_output_profile_gamuttag_rendering_intent);

REGISTER_CONFORMANCE(266, "Input Profile Device Color Space",
    "Input profiles must use RGB, CMYK, Gray, or nCLR device color space", "ICC.1-2022-05 §6.1",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf266_input_profile_device_color_space);

REGISTER_CONFORMANCE(267, "Display Profile Color Space",
    "Display profiles must use RGB, Gray, or nCLR device color space", "ICC.1-2022-05 §6.2",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf267_display_profile_color_space);

REGISTER_CONFORMANCE(268, "Output Profile Color Space",
    "Output profiles must use RGB, CMYK, CMY, Gray, or nCLR device color space", "ICC.1-2022-05 §6.3",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf268_output_profile_color_space);

REGISTER_CONFORMANCE(269, "DeviceLink Data Color Space Matching",
    "DeviceLink source and destination color spaces must be valid device spaces", "ICC.1-2022-05 §6.4",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf269_devicelink_data_color_space_matching);

REGISTER_CONFORMANCE(270, "Abstract Profile PCS",
    "Abstract profiles must use Lab or XYZ for both colorSpace and PCS", "ICC.1-2022-05 §6.6",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf270_abstract_profile_pcs);

REGISTER_CONFORMANCE(271, "NamedColor Profile PCS",
    "NamedColor profiles must use Lab or XYZ PCS", "ICC.1-2022-05 §6.7",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf271_namedcolor_profile_pcs);

REGISTER_CONFORMANCE(272, "Matrix/TRC RGB Required Colorant Tags",
    "RGB matrix/TRC profiles must have rXYZ, gXYZ, bXYZ, rTRC, gTRC, bTRC tags", "ICC.1-2022-05 §9.2.47",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf272_matrix_trc_rgb_required_colorant_tags);

REGISTER_CONFORMANCE(282, "DeviceLink AToB0Tag Required",
    "DeviceLink profiles must contain AToB0Tag", "ICC.1-2022-05 §6.4",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf282_devicelink_atob0tag_required);

REGISTER_CONFORMANCE(283, "DeviceLink profileSequenceDescTag",
    "DeviceLink profiles should contain profileSequenceDescTag", "ICC.1-2022-05 §6.4",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf283_devicelink_profilesequencedesctag);
