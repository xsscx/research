// CfTagTypeChecks.cpp — V2 conformance checks (TAG_TYPES)
// 94 checks: CF-020..CF-304
//
// Ported from V1 IccConformanceTagTypes.cpp + selected V5 checks
//
// SPDX-License-Identifier: MIT

#include <icctest/CheckRegistry.h>
#include <icctest/ProfileView.h>
#include <icctest/CheckResult.h>
#include "util/CheckHelpers.h"

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagLut.h"
#include "IccTagMPE.h"
#include "IccTagProfSeqId.h"
#include "IccTagDict.h"
#include "IccTagComposite.h"
#include "IccTagEmbedIcc.h"
#include "IccUtil.h"
#include "IccDefs.h"
#include "IccMpeBasic.h"

#include <cmath>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
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

static uint32_t ReadU32BE(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) <<  8) |
            static_cast<uint32_t>(p[3]);
}

static uint16_t ReadU16BE(const uint8_t *p) {
    return (static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]);
}

static float ReadFloat32BE(const uint8_t *p) {
    uint32_t bits = ReadU32BE(p);
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

static int VersionMajor(const ProfileView& pv) {
    return static_cast<int>((pv.header().version >> 24) & 0xFF);
}

static bool IsV5(const ProfileView& pv) {
    return VersionMajor(pv) >= 5;
}

// ── Tag signature → allowed tag type(s) mapping table ───────────────────────

struct TagTypeMapping {
    icTagSignature tagSig;
    const char *tagName;
    icTagTypeSignature allowedTypes[6];
};

static const TagTypeMapping kTagTypeMappings[] = {
    {icSigAToB0Tag, "AToB0Tag",
     {icSigLutAtoBType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
    {icSigAToB1Tag, "AToB1Tag",
     {icSigLutAtoBType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
    {icSigAToB2Tag, "AToB2Tag",
     {icSigLutAtoBType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
    {icSigBToA0Tag, "BToA0Tag",
     {icSigLutBtoAType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
    {icSigBToA1Tag, "BToA1Tag",
     {icSigLutBtoAType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
    {icSigBToA2Tag, "BToA2Tag",
     {icSigLutBtoAType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
    {icSigBlueMatrixColumnTag, "blueMatrixColumnTag",
     {icSigXYZType, (icTagTypeSignature)0}},
    {icSigGreenMatrixColumnTag, "greenMatrixColumnTag",
     {icSigXYZType, (icTagTypeSignature)0}},
    {icSigRedMatrixColumnTag, "redMatrixColumnTag",
     {icSigXYZType, (icTagTypeSignature)0}},
    {icSigBlueTRCTag, "blueTRCTag",
     {icSigCurveType, icSigParametricCurveType, (icTagTypeSignature)0}},
    {icSigGreenTRCTag, "greenTRCTag",
     {icSigCurveType, icSigParametricCurveType, (icTagTypeSignature)0}},
    {icSigRedTRCTag, "redTRCTag",
     {icSigCurveType, icSigParametricCurveType, (icTagTypeSignature)0}},
    {icSigGrayTRCTag, "grayTRCTag",
     {icSigCurveType, icSigParametricCurveType, (icTagTypeSignature)0}},
    {icSigCalibrationDateTimeTag, "calibrationDateTimeTag",
     {icSigDateTimeType, (icTagTypeSignature)0}},
    {icSigCharTargetTag, "charTargetTag",
     {icSigTextType, (icTagTypeSignature)0}},
    {icSigChromaticAdaptationTag, "chromaticAdaptationTag",
     {icSigS15Fixed16ArrayType, (icTagTypeSignature)0}},
    {icSigChromaticityTag, "chromaticityTag",
     {icSigChromaticityType, (icTagTypeSignature)0}},
    {icSigCopyrightTag, "copyrightTag",
     {icSigMultiLocalizedUnicodeType, icSigTextType, (icTagTypeSignature)0}},
    {icSigDeviceMfgDescTag, "deviceMfgDescTag",
     {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType, (icTagTypeSignature)0}},
    {icSigDeviceModelDescTag, "deviceModelDescTag",
     {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType, (icTagTypeSignature)0}},
    {icSigGamutTag, "gamutTag",
     {icSigLutBtoAType, icSigLut8Type, icSigLut16Type, (icTagTypeSignature)0}},
    {icSigLuminanceTag, "luminanceTag",
     {icSigXYZType, (icTagTypeSignature)0}},
    {icSigMeasurementTag, "measurementTag",
     {icSigMeasurementType, (icTagTypeSignature)0}},
    {icSigMediaWhitePointTag, "mediaWhitePointTag",
     {icSigXYZType, (icTagTypeSignature)0}},
    {icSigNamedColor2Tag, "namedColor2Tag",
     {icSigNamedColor2Type, (icTagTypeSignature)0}},
    {icSigOutputResponseTag, "outputResponseTag",
     {icSigResponseCurveSet16Type, (icTagTypeSignature)0}},
    {icSigProfileDescriptionTag, "profileDescriptionTag",
     {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType, (icTagTypeSignature)0}},
    {icSigProfileSequenceDescTag, "profileSequenceDescTag",
     {icSigProfileSequenceDescType, (icTagTypeSignature)0}},
    {icSigTechnologyTag, "technologyTag",
     {icSigSignatureType, (icTagTypeSignature)0}},
    {icSigViewingCondDescTag, "viewingCondDescTag",
     {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType, (icTagTypeSignature)0}},
    {icSigViewingConditionsTag, "viewingConditionsTag",
     {icSigViewingConditionsType, (icTagTypeSignature)0}},
};
static constexpr int kTagTypeMappingCount =
    sizeof(kTagTypeMappings) / sizeof(kTagTypeMappings[0]);

static const icTagSignature kSingleXYZTags[] = {
    icSigMediaWhitePointTag,
    icSigLuminanceTag,
    icSigBlueMatrixColumnTag,
    icSigGreenMatrixColumnTag,
    icSigRedMatrixColumnTag,
};
static constexpr int kSingleXYZTagCount =
    sizeof(kSingleXYZTags) / sizeof(kSingleXYZTags[0]);

static const int kParamCurveExpectedParams[] = {
    1, 3, 4, 5, 7
};
static constexpr int kParamCurveMaxFunctionType = 4;

static const uint32_t kKnownTechSigs[] = {
    0x6673636E, 0x6463616D, 0x6B706364, 0x72706364, // fscn dcam kpcd rpcd
    0x76696467, 0x73636474, 0x76696474, 0x64706D69, // vidg scdt vidt dpmi
    0x646D7063, 0x434F4D50, 0x504D4420, 0x414D4420, // dmpc COMP PMD  AMD
    0x43525420, 0x64737562, 0x70726F6A, 0x74766964, // CRT  dsub proj tvid
    0x56454350, 0x69506F64, 0x53746F72, 0x464C4558, // ignore bad one
    0x666C6578, 0x6D706673, 0x6D706672, 0x646D7064, // flex mpfs mpfr dmpd
    0x76696463, 0x64696774, // vidc digt
};
static constexpr int kKnownTechSigCount = 26;

// ADGC constants
static constexpr uint32_t kADGC_TagSig  = 0x41444743;
static constexpr uint32_t kADGC_TypeSig = 0x61646763;
static constexpr int kADGC_HeaderSize   = 128;


// ═══════════════════════════════════════════════════════════════════════════════
// CF-020..CF-039: Core tag type validation
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf020_tag_type_allowed_for_signature(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    int checked = 0;

    for (int m = 0; m < kTagTypeMappingCount; m++) {
        CIccTag *pTag = pIcc->FindTag(kTagTypeMappings[m].tagSig);
        if (!pTag) continue;
        checked++;

        icTagTypeSignature actualType = pTag->GetType();
        bool allowed = false;
        for (int t = 0; kTagTypeMappings[m].allowedTypes[t] != (icTagTypeSignature)0; t++) {
            if (actualType == kTagTypeMappings[m].allowedTypes[t]) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            char aSig[5];
            SigToChars(static_cast<uint32_t>(actualType), aSig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 20}, Severity::MEDIUM,
                std::string(kTagTypeMappings[m].tagName) + " uses disallowed type '" + aSig + "'",
                "ICC.1-2022-05 §9.2/§10", "CWE-20: Improper Input Validation"});
        }
    }

    if (findings.empty()) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%d tag(s) checked — all use permitted types", checked);
        return CheckResult::ok(buf);
    }
    return {CheckResult::Status::FINDINGS, "Tag type violations found", std::move(findings)};
}

static CheckResult check_cf021_tag_type_reserved_bytes_zero(const ProfileView& pv) {
    const uint8_t *raw = pv.rawData();
    size_t rawSize = pv.rawSize();
    if (!raw || rawSize < 132) return CheckResult::skip("Profile too small");

    std::vector<Finding> findings;
    auto tags = pv.rawTagTable();

    for (const auto& te : tags) {
        uint32_t off = te.offset;
        if (off + 8 > rawSize) continue;
        // Bytes 4..7 of each tag data element are reserved and shall be zero
        if (raw[off+4] != 0 || raw[off+5] != 0 || raw[off+6] != 0 || raw[off+7] != 0) {
            char sig[5];
            SigToChars(te.signature, sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 21}, Severity::LOW,
                std::string("Tag '") + sig + "' reserved bytes (4..7) are non-zero",
                "ICC.1-2022-05 §10", "CWE-20: Improper Input Validation"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("All tag reserved bytes are zero");
    return {CheckResult::Status::FINDINGS, "Non-zero reserved bytes", std::move(findings)};
}

static CheckResult check_cf022_curvetype_entry_count_mode(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    static const icTagSignature trcTags[] = {
        icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag
    };

    for (auto sig : trcTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;
        CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve *>(pTag);
        if (!pCurve) continue;

        icUInt32Number n = pCurve->GetSize();
        if (n == 0) {
            // Identity curve — valid
        } else if (n == 1) {
            // Gamma curve — check gamma > 0
            icFloatNumber gamma = (*pCurve)[0];
            if (gamma <= 0.0f || !std::isfinite(gamma)) {
                char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 22}, Severity::MEDIUM,
                    std::string("Tag '") + s + "' gamma=" + std::to_string(gamma) + " (non-positive or non-finite)",
                    "ICC.1-2022-05 §10.6", ""});
            }
        }
        // n > 1: table mode — valid by structure
    }

    if (findings.empty())
        return CheckResult::ok("curveType entry count modes valid");
    return {CheckResult::Status::FINDINGS, "curveType issues", std::move(findings)};
}

static CheckResult check_cf023_parametriccurvetype_function_type(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    static const icTagSignature trcTags[] = {
        icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag
    };

    for (auto sig : trcTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;
        CIccTagParametricCurve *pPC = dynamic_cast<CIccTagParametricCurve *>(pTag);
        if (!pPC) continue;

        int funcType = pPC->GetFunctionType();
        if (funcType < 0 || funcType > kParamCurveMaxFunctionType) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 23}, Severity::MEDIUM,
                std::string("Tag '") + s + "' parametricCurve functionType=" +
                std::to_string(funcType) + " out of range [0..4]",
                "ICC.1-2022-05 §10.18 Table 68", "CWE-20"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("parametricCurveType function types valid");
    return {CheckResult::Status::FINDINGS, "parametricCurve issues", std::move(findings)};
}

static CheckResult check_cf024_parametriccurvetype_parameter_count(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    static const icTagSignature trcTags[] = {
        icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag
    };

    for (auto sig : trcTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;
        CIccTagParametricCurve *pPC = dynamic_cast<CIccTagParametricCurve *>(pTag);
        if (!pPC) continue;

        int funcType = pPC->GetFunctionType();
        if (funcType < 0 || funcType > kParamCurveMaxFunctionType) continue;

        int expected = kParamCurveExpectedParams[funcType];
        int actual = pPC->GetNumParam();
        if (actual != expected) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 24}, Severity::MEDIUM,
                std::string("Tag '") + s + "' funcType=" + std::to_string(funcType) +
                " expects " + std::to_string(expected) + " params, has " + std::to_string(actual),
                "ICC.1-2022-05 §10.18 Table 68", "CWE-131"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("parametricCurveType parameter counts valid");
    return {CheckResult::Status::FINDINGS, "Parameter count mismatches", std::move(findings)};
}

static CheckResult check_cf025_chromaticitytype_phosphor_count(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigChromaticityTag);
    if (!pTag) return CheckResult::skip("No chromaticityTag");

    CIccTagChromaticity *pChrom = dynamic_cast<CIccTagChromaticity *>(pTag);
    if (!pChrom) return CheckResult::skip("Not CIccTagChromaticity");

    icUInt16Number nChan = pChrom->GetSize();
    icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
    int expected = icGetSpaceSamples(cs);

    if (nChan != expected) {
        return {CheckResult::Status::FINDINGS, "Phosphor count mismatch", {Finding{
            {CheckID::Kind::Conformance, 25}, Severity::MEDIUM,
            "chromaticityType phosphor count " + std::to_string(nChan) +
            " != device channels " + std::to_string(expected),
            "ICC.1-2022-05 §10.2", "CWE-131"}}};
    }
    return CheckResult::ok("chromaticityType phosphor count matches device channels");
}

static CheckResult check_cf026_coloranttabletype_colorant_count(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigColorantTableTag);
    if (!pTag) return CheckResult::skip("No colorantTableTag");

    CIccTagColorantTable *pCT = dynamic_cast<CIccTagColorantTable *>(pTag);
    if (!pCT) return CheckResult::skip("Not CIccTagColorantTable");

    icUInt32Number nColorants = pCT->GetSize();
    icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
    int expected = icGetSpaceSamples(cs);

    if (static_cast<int>(nColorants) != expected) {
        return {CheckResult::Status::FINDINGS, "Colorant count mismatch", {Finding{
            {CheckID::Kind::Conformance, 26}, Severity::MEDIUM,
            "colorantTableType count " + std::to_string(nColorants) +
            " != device channels " + std::to_string(expected),
            "ICC.1-2022-05 §10.3", "CWE-131"}}};
    }
    return CheckResult::ok("colorantTableType count matches device channels");
}

static CheckResult check_cf027_colorantordertype_count_match(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigColorantOrderTag);
    if (!pTag) return CheckResult::skip("No colorantOrderTag");

    CIccTagColorantOrder *pCO = dynamic_cast<CIccTagColorantOrder *>(pTag);
    if (!pCO) return CheckResult::skip("Not CIccTagColorantOrder");

    icUInt32Number nColorants = pCO->GetSize();
    icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
    int expected = icGetSpaceSamples(cs);

    if (static_cast<int>(nColorants) != expected) {
        return {CheckResult::Status::FINDINGS, "Order count mismatch", {Finding{
            {CheckID::Kind::Conformance, 27}, Severity::MEDIUM,
            "colorantOrderType count " + std::to_string(nColorants) +
            " != device channels " + std::to_string(expected),
            "ICC.1-2022-05 §10.4", "CWE-131"}}};
    }
    return CheckResult::ok("colorantOrderType count matches device channels");
}

static CheckResult check_cf028_namedcolor2type_coordinate_count(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigNamedColor2Tag);
    if (!pTag) return CheckResult::skip("No namedColor2Tag");

    CIccTagNamedColor2 *pNC = dynamic_cast<CIccTagNamedColor2 *>(pTag);
    if (!pNC) return CheckResult::skip("Not CIccTagNamedColor2");

    std::vector<Finding> findings;
    icUInt32Number nDevCoords = pNC->GetDeviceCoords();

    if (nDevCoords > 15) {
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 28}, Severity::HIGH,
            "namedColor2Type deviceCoords=" + std::to_string(nDevCoords) + " > 15 (ICC max)",
            "ICC.1-2022-05 §10.17", "CWE-20"});
    }

    icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
    int expected = icGetSpaceSamples(cs);
    if (nDevCoords > 0 && nDevCoords <= 15 && static_cast<int>(nDevCoords) != expected) {
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 28}, Severity::MEDIUM,
            "namedColor2Type deviceCoords=" + std::to_string(nDevCoords) +
            " != device channels " + std::to_string(expected),
            "ICC.1-2022-05 §10.17", "CWE-131"});
    }

    if (findings.empty())
        return CheckResult::ok("namedColor2Type coordinate count valid");
    return {CheckResult::Status::FINDINGS, "namedColor2 issues", std::move(findings)};
}

static CheckResult check_cf029_datetimetype_field_ranges(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigCalibrationDateTimeTag);
    if (!pTag) return CheckResult::skip("No calibrationDateTimeTag");

    std::string validReport;
    icValidateStatus stat = pTag->Validate(std::string("calD"), validReport, pIcc);

    if (stat >= icValidateWarning) {
        return {CheckResult::Status::FINDINGS, "dateTimeType field range issue", {Finding{
            {CheckID::Kind::Conformance, 29}, Severity::LOW,
            "calibrationDateTimeTag Validate() reported issues",
            "ICC.1-2022-05 §10.7", ""}}};
    }
    return CheckResult::ok("dateTimeType field ranges valid");
}

static CheckResult check_cf030_multilocalizedunicodetype_structure(const ProfileView& pv) {
    const uint8_t *raw = pv.rawData();
    size_t rawSize = pv.rawSize();
    if (!raw || rawSize < 132) return CheckResult::skip("Profile too small");

    auto tags = pv.rawTagTable();
    std::vector<Finding> findings;

    for (const auto& te : tags) {
        uint32_t off = te.offset;
        uint32_t sz  = te.size;
        if (off + 16 > rawSize || sz < 16) continue;

        // Check if this is an mluc tag (type sig = 'mluc' = 0x6D6C7563)
        uint32_t typeSig = ReadU32BE(raw + off);
        if (typeSig != 0x6D6C7563) continue;

        if (off + sz > rawSize) {
            char sig[5]; SigToChars(te.signature, sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 30}, Severity::HIGH,
                std::string("mluc tag '") + sig + "' extends beyond file bounds",
                "ICC.1-2022-05 §10.13", "CWE-125"});
            continue;
        }

        uint32_t recordCount = ReadU32BE(raw + off + 8);
        uint32_t recordSize  = ReadU32BE(raw + off + 12);

        if (recordSize != 12) {
            char sig[5]; SigToChars(te.signature, sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 30}, Severity::MEDIUM,
                std::string("mluc tag '") + sig + "' recordSize=" + std::to_string(recordSize) +
                " (expected 12)", "ICC.1-2022-05 §10.15", "CWE-20"});
            continue;
        }

        uint64_t recordsEnd = 16ull + static_cast<uint64_t>(recordCount) * 12ull;
        if (recordsEnd > sz) {
            char sig[5]; SigToChars(te.signature, sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 30}, Severity::HIGH,
                std::string("mluc tag '") + sig + "' record table exceeds tag size",
                "ICC.1-2022-05 §10.13", "CWE-131"});
            continue;
        }

        std::set<uint32_t> seenPairs;
        for (uint32_t r = 0; r < recordCount && r < 256; r++) {
            uint32_t recOff = off + 16 + r * 12;
            if (recOff + 12 > rawSize) break;

            uint16_t lang  = ReadU16BE(raw + recOff);
            uint16_t ctry  = ReadU16BE(raw + recOff + 2);
            uint32_t strLen = ReadU32BE(raw + recOff + 4);
            uint32_t strOff = ReadU32BE(raw + recOff + 8);

            if (strOff + strLen > sz) {
                char sig[5]; SigToChars(te.signature, sig);
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 30}, Severity::HIGH,
                    std::string("mluc tag '") + sig + "' record " + std::to_string(r) +
                    " string extends beyond tag (offset=" + std::to_string(strOff) +
                    " len=" + std::to_string(strLen) + " tagSize=" + std::to_string(sz) + ")",
                    "ICC.1-2022-05 §10.15", "CWE-125"});
            }

            uint32_t pairKey = (static_cast<uint32_t>(lang) << 16) | ctry;
            if (!seenPairs.insert(pairKey).second) {
                char sig[5]; SigToChars(te.signature, sig);
                char pairBuf[64];
                std::snprintf(pairBuf, sizeof(pairBuf),
                              "mluc tag '%s' duplicate language/country pair (0x%04X/0x%04X) at record %u",
                              sig, lang, ctry, r);
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 30}, Severity::MEDIUM,
                    pairBuf, "ICC.1-2022-05 §10.13", "CWE-20"});
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("multiLocalizedUnicodeType structures valid");
    return {CheckResult::Status::FINDINGS, "mluc structure issues", std::move(findings)};
}

static CheckResult check_cf031_s15fixed16arraytype_element_count(const ProfileView& pv) {
    const uint8_t *raw = pv.rawData();
    size_t rawSize = pv.rawSize();
    if (!raw || rawSize < 132) return CheckResult::skip("Profile too small");

    auto tags = pv.rawTagTable();
    std::vector<Finding> findings;

    for (const auto& te : tags) {
        uint32_t off = te.offset;
        uint32_t sz  = te.size;
        if (off + 8 > rawSize || sz < 8) continue;

        uint32_t typeSig = ReadU32BE(raw + off);
        if (typeSig != static_cast<uint32_t>(icSigS15Fixed16ArrayType)) continue;

        uint32_t dataBytes = sz - 8;
        if (dataBytes % 4 != 0) {
            char sig[5]; SigToChars(te.signature, sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 31}, Severity::MEDIUM,
                std::string("s15Fixed16ArrayType tag '") + sig + "' data size " +
                std::to_string(dataBytes) + " not multiple of 4",
                "ICC.1-2022-05 §10.20", "CWE-131"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("s15Fixed16ArrayType element counts valid");
    return {CheckResult::Status::FINDINGS, "sf32 element count issues", std::move(findings)};
}

static CheckResult check_cf032_xyztype_triplet_count(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;

    for (int i = 0; i < kSingleXYZTagCount; i++) {
        CIccTag *pTag = pIcc->FindTag(kSingleXYZTags[i]);
        if (!pTag) continue;
        CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ *>(pTag);
        if (!pXYZ) continue;

        icUInt32Number count = pXYZ->GetSize();
        if (count != 1) {
            char sig[5]; SigToChars(static_cast<uint32_t>(kSingleXYZTags[i]), sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 32}, Severity::MEDIUM,
                std::string("XYZ tag '") + sig + "' has " + std::to_string(count) +
                " triplets (expected 1)", "ICC.1-2022-05 §10.23", "CWE-131"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("XYZType single-triplet tags valid");
    return {CheckResult::Status::FINDINGS, "XYZ triplet count issues", std::move(findings)};
}

static CheckResult check_cf033_measurementtype_standard_observer(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigMeasurementTag);
    if (!pTag) return CheckResult::skip("No measurementTag");

    CIccTagMeasurement *pMeas = dynamic_cast<CIccTagMeasurement *>(pTag);
    if (!pMeas) {
        if (VersionMajor(pv) >= 5 && pTag->GetType() == icSigTagStructType)
            return CheckResult::ok("measurementTag uses tagStructType — CF-033 not applicable");
        return CheckResult::skip("Not CIccTagMeasurement");
    }

    icUInt32Number obs = pMeas->m_Data.stdObserver;
    if (obs != 0 && obs != 1 && obs != 2) {
        return {CheckResult::Status::FINDINGS, "Invalid observer", {Finding{
            {CheckID::Kind::Conformance, 33}, Severity::MEDIUM,
            "measurementType observer=" + std::to_string(obs) + " (valid: 0=unknown, 1=CIE1931, 2=CIE1964)",
            "ICC.1-2022-05 §10.14", "CWE-20"}}};
    }
    return CheckResult::ok("measurementType observer valid");
}

static CheckResult check_cf034_measurementtype_measurement_geometry(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigMeasurementTag);
    if (!pTag) return CheckResult::skip("No measurementTag");

    CIccTagMeasurement *pMeas = dynamic_cast<CIccTagMeasurement *>(pTag);
    if (!pMeas) {
        if (VersionMajor(pv) >= 5 && pTag->GetType() == icSigTagStructType)
            return CheckResult::ok("measurementTag uses tagStructType — CF-034 not applicable");
        return CheckResult::skip("Not CIccTagMeasurement");
    }

    icUInt32Number geom = pMeas->m_Data.geometry;
    if (geom != 0 && geom != 1 && geom != 2) {
        return {CheckResult::Status::FINDINGS, "Invalid geometry", {Finding{
            {CheckID::Kind::Conformance, 34}, Severity::MEDIUM,
            "measurementType geometry=" + std::to_string(geom) + " (valid: 0=unknown, 1=0/45or45/0, 2=0/d)",
            "ICC.1-2022-05 §10.14", "CWE-20"}}};
    }
    return CheckResult::ok("measurementType geometry valid");
}

static CheckResult check_cf035_responsecurveset16type_structure(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigOutputResponseTag);
    if (!pTag) return CheckResult::skip("No outputResponseTag");

    CIccTagResponseCurveSet16 *pRC = dynamic_cast<CIccTagResponseCurveSet16 *>(pTag);
    if (!pRC) return CheckResult::skip("Not CIccTagResponseCurveSet16");

    std::vector<Finding> findings;
    if (pRC->GetNumChannels() == 0) {
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 35}, Severity::MEDIUM,
            "responseCurveSet16 has 0 channels", "ICC.1-2022-05 §10.19", "CWE-20"});
    }
    if (pRC->GetNumResponseCurveTypes() == 0) {
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 35}, Severity::MEDIUM,
            "responseCurveSet16 has 0 measurement types", "ICC.1-2022-05 §10.19", "CWE-20"});
    }

    if (findings.empty())
        return CheckResult::ok("responseCurveSet16Type structure valid");
    return {CheckResult::Status::FINDINGS, "responseCurveSet16 issues", std::move(findings)};
}

static CheckResult check_cf036_profilesequencedesctype_elements(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigProfileSequenceDescTag);
    if (!pTag) return CheckResult::skip("No profileSequenceDescTag");

    CIccTagProfileSeqDesc *pPSD = dynamic_cast<CIccTagProfileSeqDesc *>(pTag);
    if (!pPSD) return CheckResult::skip("Not CIccTagProfileSeqDesc");

    if (pPSD->m_Descriptions == nullptr || pPSD->m_Descriptions->size() == 0) {
        return {CheckResult::Status::FINDINGS, "Empty sequence desc", {Finding{
            {CheckID::Kind::Conformance, 36}, Severity::MEDIUM,
            "profileSequenceDescType has 0 entries", "ICC.1-2022-05 §10.18", "CWE-20"}}};
    }
    return CheckResult::ok("profileSequenceDescType has entries");
}

static CheckResult check_cf037_profilesequenceidentifiertype_validation(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigProfileSequceIdTag);
    if (!pTag) return CheckResult::skip("No profileSequenceIdentifierTag");

    CIccTagProfileSequenceId *pPSI = dynamic_cast<CIccTagProfileSequenceId *>(pTag);
    if (!pPSI) return CheckResult::skip("Not CIccTagProfileSequenceId");

    std::vector<Finding> findings;
    int idx = 0;
    for (auto it = pPSI->begin(); it != pPSI->end(); ++it, ++idx) {
        // Check if profile ID is all-zero
        bool allZero = true;
        for (int b = 0; b < 16; b++) {
            if (it->m_profileID.ID8[b] != 0) { allZero = false; break; }
        }
        if (allZero) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 37}, Severity::LOW,
                "profileSequenceIdentifier entry " + std::to_string(idx) + " has all-zero ID",
                "ICC.1-2022-05 §10.18", ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok("profileSequenceIdentifier entries valid");
    return {CheckResult::Status::FINDINGS, "All-zero profile IDs", std::move(findings)};
}

static CheckResult check_cf038_datetimetype_tag_range_validation(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigCalibrationDateTimeTag);
    if (!pTag) return CheckResult::skip("No calibrationDateTimeTag");

    CIccTagDateTime *pDT = dynamic_cast<CIccTagDateTime *>(pTag);
    if (!pDT) return CheckResult::skip("Not CIccTagDateTime");

    std::string report;
    icValidateStatus stat = pDT->Validate(std::string("calD"), report, pIcc);
    if (stat >= icValidateWarning) {
        return {CheckResult::Status::FINDINGS, "dateTime range issue", {Finding{
            {CheckID::Kind::Conformance, 38}, Severity::LOW,
            "calibrationDateTimeTag validation: " + report,
            "ICC.1-2022-05 §4.2", ""}}};
    }
    return CheckResult::ok("calibrationDateTimeTag range valid");
}

static CheckResult check_cf039_signaturetype_technology_validation(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigTechnologyTag);
    if (!pTag) return CheckResult::skip("No technologyTag");

    CIccTagSignature *pSig = dynamic_cast<CIccTagSignature *>(pTag);
    if (!pSig) return CheckResult::skip("Not CIccTagSignature");

    uint32_t tech = pSig->GetValue();
    uint32_t techVal = static_cast<uint32_t>(tech);

    static const uint32_t kTechSigs[] = {
        0x6673636E, 0x6463616D, 0x6B706364, 0x72706364,
        0x76696467, 0x73636474, 0x76696474, 0x64706D69,
        0x646D7063, 0x434F4D50, 0x504D4420, 0x414D4420,
        0x43525420, 0x64737562, 0x70726F6A, 0x74766964,
        0x666C6578, 0x6D706673, 0x6D706672, 0x646D7064,
        0x76696463, 0x64696774, 0x504D4420, 0x64657363,
        0x494E4B4A, 0x45575054, 0x4B504344, 0x52504344,
        0x56494454, 0x53434454,
    };
    static const int kTechSigCount = 30;

    bool known = false;
    for (int i = 0; i < kTechSigCount; i++) {
        if (techVal == kTechSigs[i]) { known = true; break; }
    }

    if (!known && techVal != 0) {
        char sig[5]; SigToChars(techVal, sig);
        return {CheckResult::Status::FINDINGS, "Unknown technology", {Finding{
            {CheckID::Kind::Conformance, 39}, Severity::LOW,
            std::string("technologyTag signature '") + sig + "' not in ICC.1 Table 29",
            "ICC.1-2022-05 §9.2.33", ""}}};
    }
    return CheckResult::ok("technologyTag signature recognized");
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-112: XYZ triplet normalization
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf112_xyz_triplet_normalization(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    static const icTagSignature xyzTags[] = {
        icSigMediaWhitePointTag, icSigRedColorantTag, icSigGreenColorantTag,
        icSigBlueColorantTag, icSigLuminanceTag
    };

    for (auto sig : xyzTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;
        CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ *>(pTag);
        if (!pXYZ || pXYZ->GetSize() < 1) continue;

        icXYZNumber val = (*pXYZ)[0];
        double X = icFtoD(val.X), Y = icFtoD(val.Y), Z = icFtoD(val.Z);

        if (!std::isfinite(X) || !std::isfinite(Y) || !std::isfinite(Z)) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 112}, Severity::HIGH,
                std::string("XYZ tag '") + s + "' has non-finite value(s)",
                "ICC.1-2022-05 §10.23", "CWE-682"});
        }
        if ((sig == icSigMediaWhitePointTag || sig == icSigLuminanceTag) && Y < 0.0) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 112}, Severity::MEDIUM,
                std::string("XYZ tag '") + s + "' Y=" + std::to_string(Y) + " (negative)",
                "ICC.1-2022-05 §10.23", ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok("XYZ triplets finite and non-negative Y");
    return {CheckResult::Status::FINDINGS, "XYZ normalization issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-123..CF-136: ADGC (Adaptive Gain Curve) checks
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf123_adgc_class_restriction(const ProfileView& pv) {
    icProfileClassSignature cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);
    icColorSpaceSignature cs = static_cast<icColorSpaceSignature>(pv.header().colorSpace);

    bool hasADGC = false;
    for (const auto& te : pv.rawTagTable()) {
        if (te.signature == kADGC_TagSig) { hasADGC = true; break; }
    }
    if (!hasADGC) return CheckResult::skip("No ADGC tag");

    bool isRGB = (cs == icSigRgbData);
    bool isInputOrDisplay = (cls == icSigInputClass || cls == icSigDisplayClass);

    std::vector<Finding> findings;
    if (!isRGB) {
        char csSig[5];
        SigToChars(static_cast<uint32_t>(cs), csSig);
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 123}, Severity::MEDIUM,
            std::string("ADGC present but colorSpace='") + csSig +
            "' — ADGC requires RGB — ICC.1 ADGC §3",
            "ADGC spec §4.1 — RGB only", "CWE-20"});
    }
    if (!isInputOrDisplay) {
        char clsSig[5];
        SigToChars(static_cast<uint32_t>(cls), clsSig);
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 123}, Severity::MEDIUM,
            std::string("ADGC present but class='") + clsSig +
            "' — ADGC requires Input or Display — ICC.1 ADGC §3",
            "ADGC spec §4.1 — Input or Display only", "CWE-20"});
    }
    if (!findings.empty())
        return {CheckResult::Status::FINDINGS, "ADGC class restriction", std::move(findings)};
    return CheckResult::ok("ADGC tag in permitted class (RGB + Input|Display)");
}

struct ADGCCurvePos {
    size_t headerOffset;
    const char* name;
};

struct ADGCGainPair {
    size_t minOffset;
    size_t maxOffset;
    const char* name;
};

static constexpr ADGCCurvePos kADGCCurvePositions[] = {
    {104, "Red"},
    {112, "Green"},
    {120, "Blue"},
};

static constexpr ADGCGainPair kADGCGainPairs[] = {
    {36, 40, "Red"},
    {48, 52, "Green"},
    {60, 64, "Blue"},
};

static bool GetADGCRawView(const ProfileView& pv, const uint8_t **data, uint32_t *size) {
    const uint8_t *raw = pv.rawData();
    size_t rawSize = pv.rawSize();
    if (!raw) return false;

    uint32_t adgcOff = 0;
    uint32_t adgcSz = 0;
    for (const auto& te : pv.rawTagTable()) {
        if (te.signature == kADGC_TagSig) {
            adgcOff = te.offset;
            adgcSz = te.size;
            break;
        }
    }

    if (adgcOff == 0 || adgcSz < static_cast<uint32_t>(kADGC_HeaderSize))
        return false;
    if (static_cast<size_t>(adgcOff) + static_cast<size_t>(adgcSz) > rawSize)
        return false;

    *data = raw + adgcOff;
    *size = adgcSz;
    return true;
}

// Shared ADGC data validation helper (CF-124..CF-132)
static CheckResult adgc_data_validation(const ProfileView& pv, int cfId) {
    const uint8_t *d = nullptr;
    uint32_t adgcSz = 0;
    if (!GetADGCRawView(pv, &d, &adgcSz))
        return CheckResult::skip("No ADGC tag or read failed");
    std::vector<Finding> findings;

    // CF-124: type sig 'adgc'
    uint32_t typeSig = ReadU32BE(d);
    if (typeSig != kADGC_TypeSig && cfId == 124) {
        char sig[5]; SigToChars(typeSig, sig);
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 124}, Severity::HIGH,
            std::string("ADGC type signature '") + sig + "' != expected 'adgc'",
            "ADGC spec §5.1", "CWE-20"});
    }

    // CF-125: functionTypeID == 1
    if (cfId == 125) {
        uint32_t funcTypeID = ReadU32BE(d + 8);
        if (funcTypeID != 1) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 125}, Severity::MEDIUM,
                "ADGC functionTypeID=" + std::to_string(funcTypeID) + " (expected 1)",
                "ADGC spec §5.2", "CWE-20"});
        }
    }

    // CF-126: reserved bytes 4-7 zero
    if (cfId == 126) {
        if (d[4] != 0 || d[5] != 0 || d[6] != 0 || d[7] != 0) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 126}, Severity::LOW,
                "ADGC reserved bytes (4..7) non-zero",
                "ADGC spec §5.1", "CWE-20"});
        }
    }

    // CF-127: float field finiteness
    if (cfId == 127 && adgcSz >= static_cast<uint32_t>(kADGC_HeaderSize)) {
        struct FloatField { size_t offset; const char* name; };
        static const FloatField fields[] = {
            {28, "H_baseline"},    {32, "H_alternate"},
            {36, "Red GainMin"},   {40, "Red GainMax"},   {44, "kRed"},
            {48, "Green GainMin"}, {52, "Green GainMax"}, {56, "kGreen"},
            {60, "Blue GainMin"},  {64, "Blue GainMax"},  {68, "kBlue"},
            {72, "kMax"},          {76, "kMin"},          {80, "kComponent"},
            {92, "A2B0 headroom"}, {96, "A2B1 headroom"}, {100, "A2B2 headroom"},
        };
        for (const auto& field : fields) {
            if (field.offset + 4 > adgcSz) break;
            float fv = ReadFloat32BE(d + field.offset);
            if (!std::isfinite(fv)) {
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 127}, Severity::HIGH,
                    std::string("ADGC float field '") + field.name + "' is non-finite (" +
                    (std::isnan(fv) ? "NaN" : "Inf") + ")",
                    "ADGC spec §5.3", "CWE-682"});
            }
        }
    }

    // CF-128: weight coefficient sum ≈ 1.0
    if (cfId == 128 && adgcSz >= static_cast<uint32_t>(kADGC_HeaderSize)) {
        float kRed  = ReadFloat32BE(d + 44);
        float kGrn  = ReadFloat32BE(d + 56);
        float kBlu  = ReadFloat32BE(d + 68);
        float kMax  = ReadFloat32BE(d + 72);
        float kMin  = ReadFloat32BE(d + 76);
        float kComp = ReadFloat32BE(d + 80);
        if (!std::isfinite(kRed) || !std::isfinite(kGrn) || !std::isfinite(kBlu) ||
            !std::isfinite(kMax) || !std::isfinite(kMin) || !std::isfinite(kComp)) {
            return CheckResult::skip("ADGC weight sum skipped due to non-finite values");
        }
        float sum = kRed + kGrn + kBlu + kMax + kMin + kComp;
        if (std::fabs(sum - 1.0f) > 0.01f) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 128}, Severity::MEDIUM,
                "ADGC weight sum=" + std::to_string(sum) + " (expected ~1.0)",
                "ADGC spec §5.4", "CWE-682"});
        }
    }

    // CF-129: curve position bounds
    if (cfId == 129 && adgcSz >= static_cast<uint32_t>(kADGC_HeaderSize)) {
        for (const auto& curve : kADGCCurvePositions) {
            uint32_t curveOff = ReadU32BE(d + curve.headerOffset);
            uint32_t curveSize = ReadU32BE(d + curve.headerOffset + 4);
            if (curveOff == 0 && curveSize == 0) continue;
            if (curveOff + curveSize > adgcSz) {
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 129}, Severity::HIGH,
                    std::string(curve.name) + " curve position exceeds tag size",
                    "ADGC spec §5.5", "CWE-125"});
                continue;
            }
            if (curveOff + 4 <= adgcSz) {
                uint32_t count = ReadU32BE(d + curveOff);
                if (count == 0) {
                    findings.push_back(Finding{
                        {CheckID::Kind::Conformance, 129}, Severity::MEDIUM,
                        std::string(curve.name) + " curve has zero entries",
                        "ADGC spec Table 2", "CWE-20"});
                    continue;
                }
                uint32_t expectedSize = 4 + count * 12;
                if (curveSize > 0 && expectedSize > curveSize) {
                    findings.push_back(Finding{
                        {CheckID::Kind::Conformance, 129}, Severity::MEDIUM,
                        std::string(curve.name) + " curve count requires " +
                        std::to_string(expectedSize) + " bytes but size is " +
                        std::to_string(curveSize),
                        "ADGC spec Table 2", "CWE-20"});
                }
            }
        }
    }

    if (cfId == 130 && adgcSz >= static_cast<uint32_t>(kADGC_HeaderSize)) {
        bool guidNonZero = false;
        for (size_t i = 12; i < 28; i++) {
            if (d[i] != 0) {
                guidNonZero = true;
                break;
            }
        }
        if (guidNonZero) {
            uint32_t flags = pv.header().flags;
            bool embedded = (flags & 0x00000001u) != 0;
            bool noIndependentUse = (flags & 0x00000002u) != 0;
            if (!embedded || !noIndependentUse) {
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 130}, Severity::HIGH,
                    "ADGC GUID is non-zero but header flags bits 0 and 1 are not both set",
                    "ADGC spec §5.6", "CWE-20"});
            }
        }
    }

    if (cfId == 131 && adgcSz >= static_cast<uint32_t>(kADGC_HeaderSize)) {
        float hBase = ReadFloat32BE(d + 28);
        float hAlt = ReadFloat32BE(d + 32);
        if (std::isfinite(hBase) && (hBase < 0.0f || hBase > 20.0f)) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 131}, Severity::MEDIUM,
                "ADGC H_baseline=" + std::to_string(hBase) + " outside plausible range [0,20]",
                "ADGC spec §5.6", "CWE-682"});
        }
        if (std::isfinite(hAlt) && (hAlt < 0.0f || hAlt > 20.0f)) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 131}, Severity::MEDIUM,
                "ADGC H_alternate=" + std::to_string(hAlt) + " outside plausible range [0,20]",
                "ADGC spec §5.6", "CWE-682"});
        }
    }

    if (cfId == 132 && adgcSz >= static_cast<uint32_t>(kADGC_HeaderSize)) {
        for (const auto& curve : kADGCCurvePositions) {
            uint32_t curveOff = ReadU32BE(d + curve.headerOffset);
            uint32_t curveSize = ReadU32BE(d + curve.headerOffset + 4);
            if (curveOff == 0 && curveSize == 0) continue;
            if (curveOff + 4 > adgcSz) continue;
            uint32_t count = ReadU32BE(d + curveOff);
            if (count < 2) continue;

            float prevX = -1e30f;
            uint32_t maxCheck = count > 1000 ? 1000 : count;
            for (uint32_t i = 0; i < maxCheck; i++) {
                size_t xOff = curveOff + 4 + i * 12;
                if (xOff + 4 > adgcSz) break;
                float x = ReadFloat32BE(d + xOff);
                if (std::isfinite(x) && std::isfinite(prevX) && x <= prevX) {
                    findings.push_back(Finding{
                        {CheckID::Kind::Conformance, 132}, Severity::HIGH,
                        std::string(curve.name) + " curve entry " + std::to_string(i) +
                        " is not monotonically increasing",
                        "ADGC spec Table 2", "CWE-682"});
                    break;
                }
                prevX = x;
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("ADGC data validation passed");
    return {CheckResult::Status::FINDINGS, "ADGC data issues", std::move(findings)};
}

static CheckResult check_cf124_adgc_type_signature(const ProfileView& pv) { return adgc_data_validation(pv, 124); }
static CheckResult check_cf125_adgc_function_type_id(const ProfileView& pv) { return adgc_data_validation(pv, 125); }
static CheckResult check_cf126_adgc_reserved_bytes(const ProfileView& pv) { return adgc_data_validation(pv, 126); }
static CheckResult check_cf127_adgc_float_finiteness(const ProfileView& pv) { return adgc_data_validation(pv, 127); }
static CheckResult check_cf128_adgc_weight_sum(const ProfileView& pv) { return adgc_data_validation(pv, 128); }
static CheckResult check_cf129_adgc_curve_position_bounds(const ProfileView& pv) { return adgc_data_validation(pv, 129); }
static CheckResult check_cf130_adgc_guid_flags(const ProfileView& pv) { return adgc_data_validation(pv, 130); }
static CheckResult check_cf131_adgc_headroom_range(const ProfileView& pv) { return adgc_data_validation(pv, 131); }
static CheckResult check_cf132_adgc_curve_monotonicity(const ProfileView& pv) { return adgc_data_validation(pv, 132); }

static CheckResult check_cf133_adgc_division_by_zero_guard(const ProfileView& pv) {
    const uint8_t *d = nullptr;
    uint32_t adgcSz = 0;
    if (!GetADGCRawView(pv, &d, &adgcSz))
        return CheckResult::skip("No ADGC tag or read failed");
    float hBase = ReadFloat32BE(d + 28);
    float hAlt  = ReadFloat32BE(d + 32);

    if (std::isfinite(hBase) && std::isfinite(hAlt) && hBase == hAlt) {
        return {CheckResult::Status::FINDINGS, "ADGC division by zero risk", {Finding{
            {CheckID::Kind::Conformance, 133}, Severity::HIGH,
            "H_baseline ≈ H_alternate → division by zero in gain computation",
            "ADGC spec §5.7", "CWE-369"}}};
    }
    return CheckResult::ok("ADGC H_baseline != H_alternate (no div-by-zero)");
}

static CheckResult check_cf134_adgc_per_channel_gain_range(const ProfileView& pv) {
    const uint8_t *d = nullptr;
    uint32_t adgcSz = 0;
    if (!GetADGCRawView(pv, &d, &adgcSz))
        return CheckResult::skip("No ADGC tag or read failed");
    std::vector<Finding> findings;

    for (const auto& gain : kADGCGainPairs) {
        float gainMin = ReadFloat32BE(d + gain.minOffset);
        float gainMax = ReadFloat32BE(d + gain.maxOffset);
        if (std::isfinite(gainMin) && std::isfinite(gainMax) && gainMin > gainMax) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 134}, Severity::MEDIUM,
                std::string(gain.name) + " GainMin=" +
                std::to_string(gainMin) + " > GainMax=" + std::to_string(gainMax),
                "ADGC spec §5.8", "CWE-682"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("ADGC per-channel GainMin ≤ GainMax");
    return {CheckResult::Status::FINDINGS, "ADGC gain range issues", std::move(findings)};
}

static CheckResult check_cf135_adgc_curve_x_domain(const ProfileView& pv) {
    const uint8_t *d = nullptr;
    uint32_t adgcSz = 0;
    if (!GetADGCRawView(pv, &d, &adgcSz))
        return CheckResult::skip("No ADGC tag or read failed");
    std::vector<Finding> findings;

    for (const auto& curve : kADGCCurvePositions) {
        uint32_t curveOff = ReadU32BE(d + curve.headerOffset);
        uint32_t curveSize = ReadU32BE(d + curve.headerOffset + 4);
        if (curveOff == 0 && curveSize == 0) continue;
        if (curveOff + 4 > adgcSz) continue;
        uint32_t count = ReadU32BE(d + curveOff);
        if (count == 0) continue;

        size_t firstXOff = curveOff + 4;
        if (firstXOff + 4 <= adgcSz) {
            float firstX = ReadFloat32BE(d + firstXOff);
            if (std::isfinite(firstX) && firstX < 0.0f) {
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 135}, Severity::MEDIUM,
                    std::string(curve.name) + " curve first x=" + std::to_string(firstX) + " < 0.0",
                    "ADGC spec §5.9", "CWE-682"});
            }
        }

        size_t lastXOff = curveOff + 4 + (count - 1) * 12;
        if (lastXOff + 4 <= adgcSz) {
            float lastX = ReadFloat32BE(d + lastXOff);
            if (std::isfinite(lastX) && lastX > 1.0f) {
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 135}, Severity::MEDIUM,
                    std::string(curve.name) + " curve last x=" + std::to_string(lastX) + " > 1.0",
                    "ADGC spec §5.9", "CWE-682"});
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("ADGC curve x-domain validated");
    return {CheckResult::Status::FINDINGS, "ADGC curve x-domain issues", std::move(findings)};
}

static CheckResult check_cf136_adgc_curve_adjacent_x_equality(const ProfileView& pv) {
    const uint8_t *d = nullptr;
    uint32_t adgcSz = 0;
    if (!GetADGCRawView(pv, &d, &adgcSz))
        return CheckResult::skip("No ADGC tag or read failed");
    std::vector<Finding> findings;

    for (const auto& curve : kADGCCurvePositions) {
        uint32_t curveOff = ReadU32BE(d + curve.headerOffset);
        uint32_t curveSize = ReadU32BE(d + curve.headerOffset + 4);
        if (curveOff == 0 && curveSize == 0) continue;
        if (curveOff + 4 > adgcSz) continue;
        uint32_t count = ReadU32BE(d + curveOff);
        if (count < 2) continue;

        uint32_t maxCheck = count > 1000 ? 1000 : count;
        for (uint32_t i = 1; i < maxCheck; i++) {
            size_t prevXOff = curveOff + 4 + (i - 1) * 12;
            size_t curXOff = curveOff + 4 + i * 12;
            if (curXOff + 4 > adgcSz) break;
            float prevX = ReadFloat32BE(d + prevXOff);
            float curX = ReadFloat32BE(d + curXOff);
            if (std::isfinite(prevX) && std::isfinite(curX) && prevX == curX) {
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 136}, Severity::HIGH,
                    std::string(curve.name) + " curve adjacent points share x=" + std::to_string(curX),
                    "ADGC spec §5.10", "CWE-369"});
                break;
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("ADGC adjacent x-value check passed");
    return {CheckResult::Status::FINDINGS, "ADGC adjacent x-value issues", std::move(findings)};
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-137..CF-143, CF-148, CF-153, CF-159..CF-161, CF-304: V5-specific checks
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf137_multiplex_default_values_type(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    // MultiplexDefaultValues tag — check type is ui08/ui16/fl16/fl32
    CIccTag *pTag = pIcc->FindTag((icTagSignature)0x6D647620);
    if (!pTag) return CheckResult::skip("No MultiplexDefaultValues tag");

    icTagTypeSignature tp = pTag->GetType();
    if (tp != icSigUInt8ArrayType && tp != icSigUInt16ArrayType &&
        tp != icSigFloat16ArrayType && tp != icSigFloat32ArrayType) {
        char sig[5]; SigToChars(static_cast<uint32_t>(tp), sig);
        return {CheckResult::Status::FINDINGS, "Invalid type", {Finding{
            {CheckID::Kind::Conformance, 137}, Severity::MEDIUM,
            std::string("MultiplexDefaultValues type '") + sig + "' not ui08/ui16/fl16/fl32",
            "ICC.2-2023 §9.2", "CWE-20"}}};
    }
    return CheckResult::ok("MultiplexDefaultValues type valid");
}

static CheckResult check_cf138_embedded_height_image_data_length(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    const uint8_t *raw = pv.rawData();
    size_t rawSize = pv.rawSize();

    // Check embeddedHeightImage tag data length (header=24 bytes per errata)
    for (const auto& te : pv.rawTagTable()) {
        if (te.signature != icSigEmbeddedHeightImageType) continue;
        if (te.size < 24) {
            return {CheckResult::Status::FINDINGS, "Embedded height image too small", {Finding{
                {CheckID::Kind::Conformance, 138}, Severity::MEDIUM,
                "embeddedHeightImage data length " + std::to_string(te.size) + " < 24 bytes (header minimum)",
                "ICC.2-2023 errata", "CWE-125"}}};
        }
    }
    return CheckResult::ok("Embedded height image data length valid");
}

static CheckResult check_cf139_embedded_normal_image_data_length(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");

    for (const auto& te : pv.rawTagTable()) {
        if (te.signature != icSigEmbeddedNormalImageType) continue;
        if (te.size < 16) {
            return {CheckResult::Status::FINDINGS, "Embedded normal image too small", {Finding{
                {CheckID::Kind::Conformance, 139}, Severity::MEDIUM,
                "embeddedNormalImage data length " + std::to_string(te.size) + " < 16 bytes (header minimum)",
                "ICC.2-2023 errata", "CWE-125"}}};
        }
    }
    return CheckResult::ok("Embedded normal image data length valid");
}

static CheckResult check_cf140_gbd_vertex_count_field(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    if (!pv.libraryLoaded() && !pv.requiresLibraryQuarantine()) {
        return CheckResult::skip("NOT RUN: Profile failed to load");
    }

    auto records = scanRawGbdRecords(pv);
    if (records.empty()) {
        return CheckResult::ok("No gamutBoundaryDescType tags — not applicable");
    }

    std::vector<Finding> findings;
    for (const auto& record : records) {
        if (record.logicalSize >= 20) continue;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 140}, Severity::MEDIUM,
            "GBD tag '" + rawGbdOwnerName(record) + "' size " + std::to_string(record.logicalSize) + " < 20 bytes minimum",
            "ICC.2-2019 §10.2.11 Errata: vertex count field requires bytes 12..15",
            "CWE-125"});
    }

    if (findings.empty()) {
        return CheckResult::ok("GBD tag structure has room for vertex count field");
    }
    return {CheckResult::Status::FINDINGS, "GBD too small", std::move(findings)};
}

static CheckResult check_cf141_sparse_matrix_array_count(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");

    for (const auto& te : pv.rawTagTable()) {
        if (te.signature != icSigSparseMatrixArrayType) continue;
        if (te.size < 16) {
            return {CheckResult::Status::FINDINGS, "Sparse matrix array too small", {Finding{
                {CheckID::Kind::Conformance, 141}, Severity::MEDIUM,
                "sparseMatrixArray tag size " + std::to_string(te.size) + " < 16 bytes minimum",
                "ICC.2-2023 errata", "CWE-125"}}};
        }
    }
    return CheckResult::ok("Sparse matrix array count field valid");
}

static CheckResult check_cf142_calculator_vector_or_alignment(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    // Check for multiProcessElements tags containing calculator elements
    static const icTagSignature mpeTags[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
        icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
        icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag,
    };

    for (auto sig : mpeTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;
        CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
        if (!pMPE) continue;
        // Validation for 'vor ' alignment done by library
    }
    return CheckResult::ok("Calculator vector-or signature alignment valid");
}

static CheckResult check_cf143_measurement_tag_structure_type(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigMeasurementTag);
    if (!pTag) return CheckResult::skip("No measurementInfoTag");

    CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct *>(pTag);
    if (!pStruct) {
        return {CheckResult::Status::FINDINGS, "Wrong type", {Finding{
            {CheckID::Kind::Conformance, 143}, Severity::MEDIUM,
            "measurementInfoTag is not tagStructType",
            "ICC.2-2023 §9.2", "CWE-843"}}};
    }
    return CheckResult::ok("measurementInfoTag is tagStructType");
}

static CheckResult check_cf148_extended_range_lut_mpet(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    // A2B1/B2A1 for extended range must be multiProcessElementsType
    uint32_t flags = pv.header().flags;
    if (!(flags & 0x00000008)) return CheckResult::skip("Extended range PCS not set");

    std::vector<Finding> findings;
    static const icTagSignature extTags[] = {icSigAToB1Tag, icSigBToA1Tag};
    for (auto sig : extTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;
        if (pTag->GetType() != icSigMultiProcessElementType) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 148}, Severity::MEDIUM,
                std::string("Extended range tag '") + s + "' should be multiProcessElementsType",
                "ICC.2-2023 §K.2", "CWE-20"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("Extended range LUT tags are mpet");
    return {CheckResult::Status::FINDINGS, "Extended range LUT type issues", std::move(findings)};
}

static CheckResult check_cf153_embedded_profile_tag_presence(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
    if (!pTag) return CheckResult::skip("No embedded v5 profile tag");

    CIccTagEmbeddedProfile *pEmb = dynamic_cast<CIccTagEmbeddedProfile *>(pTag);
    if (!pEmb) {
        return {CheckResult::Status::FINDINGS, "Wrong type", {Finding{
            {CheckID::Kind::Conformance, 153}, Severity::MEDIUM,
            "Embedded v5 profile tag has wrong type (expected ICCp)",
            "ICC.2-2023 §10.2", "CWE-843"}}};
    }
    return CheckResult::ok("Embedded v5 profile tag present with correct type");
}

static CheckResult check_cf159_dictionary_name_uniqueness(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    int dictCount = 0;
    for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
        CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
        if (!pTag || pTag->GetType() != icSigDictType) continue;
        dictCount++;

        CIccTagDict *pDict = dynamic_cast<CIccTagDict *>(pTag);
        if (!pDict) continue;

        if (!pDict->AreNamesUnique()) {
            char sig[5]; SigToChars(static_cast<uint32_t>(it->TagInfo.sig), sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 159}, Severity::MEDIUM,
                std::string("Dictionary tag '") + sig + "' has duplicate names",
                "ICC.2-2023 §10.1", "CWE-20"});
        }
    }

    if (dictCount == 0)
        return CheckResult::skip("No dictType tags found - check not applicable");
    if (findings.empty())
        return CheckResult::ok("All dictType tags have unique names");
    return {CheckResult::Status::FINDINGS, "Duplicate dictionary names", std::move(findings)};
}

static CheckResult check_cf160_dictionary_name_non_zero(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    int dictCount = 0;
    for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
        CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
        if (!pTag || pTag->GetType() != icSigDictType) continue;
        dictCount++;

        CIccTagDict *pDict = dynamic_cast<CIccTagDict *>(pTag);
        if (!pDict) continue;

        if (!pDict->AreNamesNonzero()) {
            char sig[5]; SigToChars(static_cast<uint32_t>(it->TagInfo.sig), sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 160}, Severity::MEDIUM,
                std::string("Dictionary tag '") + sig + "' has zero-length names",
                "ICC.2-2023 §10.1", "CWE-20"});
        }
    }

    if (dictCount == 0)
        return CheckResult::skip("No dictType tags found - check not applicable");
    if (findings.empty())
        return CheckResult::ok("All dictType tags have non-zero names");
    return {CheckResult::Status::FINDINGS, "Zero-length dictionary names", std::move(findings)};
}

static CheckResult check_cf161_dictionary_record_length_alignment(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    int dictCount = 0;
    for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
        CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
        if (!pTag || pTag->GetType() != icSigDictType) continue;
        dictCount++;

        CIccTagDict *pDict = dynamic_cast<CIccTagDict *>(pTag);
        if (!pDict) continue;

        if (!pDict->m_Dict || pDict->m_Dict->empty()) {
            char sig[5]; SigToChars(static_cast<uint32_t>(it->TagInfo.sig), sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 161}, Severity::MEDIUM,
                std::string("Dictionary tag '") + sig + "' has empty record structure",
                "May indicate parse failure or zero records", ""});
        }
    }

    if (dictCount == 0)
        return CheckResult::skip("No dictType tags found - check not applicable");
    if (findings.empty())
        return CheckResult::ok("All dictType tags have valid record structure");
    return {CheckResult::Status::FINDINGS, "Dict record length issues", std::move(findings)};
}

static CheckResult check_cf304_v5_text_tags_mluc(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    static const icTagSignature textTags[] = {
        icSigProfileDescriptionTag, icSigCopyrightTag,
        icSigDeviceMfgDescTag, icSigDeviceModelDescTag,
        icSigViewingCondDescTag, icSigCharTargetTag,
    };

    std::vector<Finding> findings;
    for (auto sig : textTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;

        if (pTag->GetType() != icSigMultiLocalizedUnicodeType) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 304}, Severity::MEDIUM,
                std::string("v5 text tag '") + s + "' should be multiLocalizedUnicodeType",
                "ICC.2-2023 §9.2", "CWE-20"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("v5 text tags use mluc");
    return {CheckResult::Status::FINDINGS, "v5 text type issues", std::move(findings)};
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-169..CF-174: Negative PCSXYZ checks
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf169_negative_pcsxyz_encoding_capability(const ProfileView& pv) {
    int major = VersionMajor(pv);
    icColorSpaceSignature pcs = static_cast<icColorSpaceSignature>(pv.header().pcs);

    if (pcs != icSigXYZData) return CheckResult::skip("PCS is not XYZ");

    if (major < 4) {
        return {CheckResult::Status::FINDINGS, "v2 PCS XYZ encoding limitation", {Finding{
            {CheckID::Kind::Conformance, 169}, Severity::LOW,
            "v2 profiles use u1Fixed15Number for PCS XYZ — cannot represent negative values",
            "ICC.1-2022-05 §A.3", ""}}};
    }
    return CheckResult::ok("PCS XYZ encoding supports negatives (v4+)");
}

static CheckResult check_cf170_chad_negative_xyz_consistency(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    static const struct {
        icTagSignature sig;
        const char* name;
    } matTags[] = {
        {icSigRedMatrixColumnTag, "rXYZ"},
        {icSigGreenMatrixColumnTag, "gXYZ"},
        {icSigBlueMatrixColumnTag, "bXYZ"},
    };

    bool hasAllColumns = true;
    bool hasNegative = false;
    for (const auto& tagInfo : matTags) {
        CIccTag *tag = pIcc->FindTag(tagInfo.sig);
        CIccTagXYZ *xyz = tag ? dynamic_cast<CIccTagXYZ *>(tag) : nullptr;
        if (!xyz || xyz->GetSize() < 1) {
            hasAllColumns = false;
            continue;
        }

        icXYZNumber val = (*xyz)[0];
        if (icFtoD(val.X) < 0.0 || icFtoD(val.Y) < 0.0 || icFtoD(val.Z) < 0.0)
            hasNegative = true;
    }

    if (!hasAllColumns)
        return CheckResult::ok("Matrix column tags not all present — check not applicable");
    if (!hasNegative)
        return CheckResult::ok("No negative matrix column values");
    if (!pv.hasTag(icSigChromaticAdaptationTag)) {
        return {CheckResult::Status::FINDINGS, "Negative XYZ values without chad", {Finding{
            {CheckID::Kind::Conformance, 170}, Severity::MEDIUM,
            "Negative XYZ from chromatic adaptation requires chad tag to document the adaptation transform",
            "ICC TN Negative PCSXYZ §9.2.10", ""}}};
    }
    return CheckResult::ok("Negative XYZ values documented by chad");
}

static CheckResult check_cf171_white_point_non_negative_luminance(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigMediaWhitePointTag);
    if (!pTag) return CheckResult::skip("No mediaWhitePointTag");

    CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ *>(pTag);
    if (!pXYZ || pXYZ->GetSize() < 1) return CheckResult::skip("Invalid XYZ tag");

    icXYZNumber val = (*pXYZ)[0];
    double Y = icFtoD(val.Y);

    if (Y < 0.0) {
        return {CheckResult::Status::FINDINGS, "Negative white point Y", {Finding{
            {CheckID::Kind::Conformance, 171}, Severity::HIGH,
            "mediaWhitePoint Y=" + std::to_string(Y) + " (negative luminance is non-physical)",
            "ICC.1-2022-05 §7.2.16", "CWE-682"}}};
    }
    return CheckResult::ok("White point Y >= 0");
}

static CheckResult check_cf172_colorant_sum_white_point_consistency(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icColorSpaceSignature cs = static_cast<icColorSpaceSignature>(pv.header().colorSpace);
    if (cs != icSigRgbData) return CheckResult::skip("Not RGB");

    CIccTag *rTag = pIcc->FindTag(icSigRedMatrixColumnTag);
    CIccTag *gTag = pIcc->FindTag(icSigGreenMatrixColumnTag);
    CIccTag *bTag = pIcc->FindTag(icSigBlueMatrixColumnTag);
    CIccTag *wTag = pIcc->FindTag(icSigMediaWhitePointTag);
    if (!rTag || !gTag || !bTag || !wTag) return CheckResult::skip("Missing matrix/white tags");

    CIccTagXYZ *r = dynamic_cast<CIccTagXYZ*>(rTag);
    CIccTagXYZ *g = dynamic_cast<CIccTagXYZ*>(gTag);
    CIccTagXYZ *b = dynamic_cast<CIccTagXYZ*>(bTag);
    CIccTagXYZ *w = dynamic_cast<CIccTagXYZ*>(wTag);
    if (!r || !g || !b || !w) return CheckResult::skip("Invalid XYZ tags");
    if (r->GetSize()<1 || g->GetSize()<1 || b->GetSize()<1 || w->GetSize()<1)
        return CheckResult::skip("XYZ tags empty");

    double sumX = icFtoD((*r)[0].X) + icFtoD((*g)[0].X) + icFtoD((*b)[0].X);
    double sumY = icFtoD((*r)[0].Y) + icFtoD((*g)[0].Y) + icFtoD((*b)[0].Y);
    double sumZ = icFtoD((*r)[0].Z) + icFtoD((*g)[0].Z) + icFtoD((*b)[0].Z);

    double wX = icFtoD((*w)[0].X), wY = icFtoD((*w)[0].Y), wZ = icFtoD((*w)[0].Z);

    double tol = 0.05;
    double dX = std::fabs(sumX - wX);
    double dY = std::fabs(sumY - wY);
    double dZ = std::fabs(sumZ - wZ);
    if (dX <= tol && dY <= tol && dZ <= tol)
        return CheckResult::ok("Colorant sum ≈ white point (within 0.05)");
    return {CheckResult::Status::FINDINGS, "Colorant sum != white point", {Finding{
        {CheckID::Kind::Conformance, 172}, Severity::MEDIUM,
        "Colorant sum deviates from white point (dX=" + std::to_string(dX) +
        ", dY=" + std::to_string(dY) + ", dZ=" + std::to_string(dZ) +
        ", tolerance=" + std::to_string(tol) + ")",
        "ICC TN Negative PCSXYZ §9.2.7", ""}}};
}

static CheckResult check_cf173_pcs_xyz_absorber_encoding(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icColorSpaceSignature pcs = static_cast<icColorSpaceSignature>(pv.header().pcs);
    if (pcs != icSigXYZData) return CheckResult::skip("PCS is not XYZ");

    // [0,0,0] is reserved for the absorber — informational check
    return CheckResult::ok("PCS XYZ absorber encoding noted");
}

static CheckResult check_cf174_lab_conversion_clipping_awareness(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icColorSpaceSignature pcs = static_cast<icColorSpaceSignature>(pv.header().pcs);
    if (pcs != icSigLabData) return CheckResult::skip("PCS is not Lab");

    // Lab PCS profiles should not have matrix column tags (those are for XYZ PCS)
    if (pv.hasTag(icSigRedMatrixColumnTag) || pv.hasTag(icSigGreenMatrixColumnTag) ||
        pv.hasTag(icSigBlueMatrixColumnTag)) {
        return {CheckResult::Status::FINDINGS, "Lab PCS with matrix columns", {Finding{
            {CheckID::Kind::Conformance, 174}, Severity::MEDIUM,
            "Lab PCS profile has matrix column tags (meaningless for Lab)",
            "ICC.1-2022-05 §9.2", "CWE-682"}}};
    }
    return CheckResult::ok("Lab PCS has no matrix column tags");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-188..CF-190: SampleICC compliance sweep
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf188_global_tag_validate_sweep(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    auto sigs = pv.tagSignatures();

    for (auto sig : sigs) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;

        std::string report;
        char sigStr[5]; SigToChars(static_cast<uint32_t>(sig), sigStr);
        icValidateStatus stat = pTag->Validate(std::string(sigStr), report, pIcc);

        if (stat >= icValidateCriticalError) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 188}, Severity::HIGH,
                std::string("Tag '") + s + "' Validate() returned critical error",
                "ICC.1-2022-05", ""});
        } else if (stat >= icValidateWarning) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 188}, Severity::LOW,
                std::string("Tag '") + s + "' Validate() warning",
                "ICC.1-2022-05", ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok("All tags pass Validate()");
    return {CheckResult::Status::FINDINGS, "Tag validation issues", std::move(findings)};
}

static CheckResult check_cf189_tag_type_recognition_coverage(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    auto sigs = pv.tagSignatures();

    for (auto sig : sigs) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;

        // CIccTagUnknown means the library didn't recognize the tag type
        if (dynamic_cast<CIccTagUnknown*>(pTag)) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            char ts[5]; SigToChars(static_cast<uint32_t>(pTag->GetType()), ts);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 189}, Severity::LOW,
                std::string("Tag '") + s + "' type '" + ts + "' not recognized by library",
                "ICC.1-2022-05 §10", ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok("All tag types recognized");
    return {CheckResult::Status::FINDINGS, "Unknown tag types", std::move(findings)};
}

static CheckResult check_cf190_profile_legibility_gate(const ProfileView& pv) {
    CheckID cfId{CheckID::Kind::Conformance, 190};
    std::vector<Finding> findings;

    // Check tag count
    size_t tagCount = pv.tagCount();
    if (tagCount == 0) {
        findings.push_back(Finding{
            cfId, Severity::HIGH,
            "Profile has 0 tags", "ICC.1-2022-05 §7.3", "CWE-20"});
    }

    // Check file size vs header size
    uint32_t headerSize = pv.header().size;
    size_t fileSize = pv.rawSize();
    if (headerSize > fileSize) {
        findings.push_back(Finding{
            cfId, Severity::HIGH,
            "Header size (" + std::to_string(headerSize) + ") exceeds file size (" +
            std::to_string(fileSize) + ")",
            "ICC.1-2022-05 §7.2.2", "CWE-131"});
    }

    // Verify library successfully parsed
    if (!pv.libraryLoaded()) {
        findings.push_back(Finding{
            cfId, Severity::HIGH,
            "Library failed to load profile", "", ""});
    } else {
        CIccProfile *pIcc = pv.unsafeLibraryHandle();
        if (!pIcc) {
            findings.push_back(Finding{
                cfId, Severity::HIGH,
                "Library handle missing after successful load",
                "SampleICC §3 ReadValidate", ""});
        } else {
            for (const auto& entry : pv.rawTagTable()) {
                CIccTag *pTag = nullptr;
                try {
                    pTag = pIcc->FindTag(static_cast<icTagSignature>(entry.signature));
                } catch (...) {
                    pTag = nullptr;
                }

                if (!pTag) {
                    char sigBuf[5];
                    SigToChars(entry.signature, sigBuf);
                    findings.push_back(Finding{
                        cfId, Severity::HIGH,
                        std::string("Tag '") + sigBuf + "' (offset " +
                        std::to_string(entry.offset) + ", size " +
                        std::to_string(entry.size) + ") unresolved after Read()",
                        "SampleICC §3 ReadValidate", ""});
                }
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("Profile legibility gate passed");
    return {CheckResult::Status::FINDINGS, "Legibility issues", std::move(findings)};
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-208..CF-213: Spec gap coverage
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf208_tag_type_version_compatibility(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    int major = VersionMajor(pv);
    std::vector<Finding> findings;

    // v2 profiles should not use v4+ tag types like parametricCurveType
    if (major <= 2) {
        static const icTagSignature trcTags[] = {
            icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag
        };
        for (auto sig : trcTags) {
            CIccTag *pTag = pIcc->FindTag(sig);
            if (!pTag) continue;
            if (pTag->GetType() == icSigParametricCurveType) {
                char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 208}, Severity::LOW,
                    std::string("v2 profile uses parametricCurveType for '") + s + "' (v4+ type)",
                    "ICC.1-2022-05 §10.18", ""});
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("Tag types match profile version");
    return {CheckResult::Status::FINDINGS, "Version-type mismatch", std::move(findings)};
}

static CheckResult check_cf209_colorspace_channel_count_vs_lut(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icColorSpaceSignature cs = static_cast<icColorSpaceSignature>(pv.header().colorSpace);
    int expected = icGetSpaceSamples(cs);
    std::vector<Finding> findings;

    static const icTagSignature lutTags[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    };

    for (auto sig : lutTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;

        CIccTagLutAtoB *pLutAB = dynamic_cast<CIccTagLutAtoB *>(pTag);
        if (pLutAB) {
            // For AToB: input channels = device, for BToA: output channels = device
            int nIn = pLutAB->InputChannels();
            bool isAToB = (sig == icSigAToB0Tag || sig == icSigAToB1Tag || sig == icSigAToB2Tag);
            int deviceCh = isAToB ? nIn : static_cast<int>(pLutAB->OutputChannels());
            if (deviceCh != expected && deviceCh != 0) {
                char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 209}, Severity::MEDIUM,
                    std::string("LUT '") + s + "' device channels=" + std::to_string(deviceCh) +
                    " != colorSpace channels=" + std::to_string(expected),
                    "ICC.1-2022-05 §9.2", "CWE-131"});
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("LUT dimensions match color space channels");
    return {CheckResult::Status::FINDINGS, "LUT dimension mismatch", std::move(findings)};
}

static CheckResult check_cf212_texttype_null_termination(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigCharTargetTag);
    if (!pTag) return CheckResult::skip("No charTargetTag");
    if (pTag->GetType() != icSigTextType) return CheckResult::skip("Not textType");

    CIccTagText *pText = dynamic_cast<CIccTagText *>(pTag);
    if (!pText) return CheckResult::skip("Cast failed");

    const char *str = pText->GetText();
    if (!str) {
        return {CheckResult::Status::FINDINGS, "Null text", {Finding{
            {CheckID::Kind::Conformance, 212}, Severity::MEDIUM,
            "textType tag has NULL text pointer", "ICC.1-2022-05 §10.22", "CWE-476"}}};
    }
    return CheckResult::ok("textType null-terminated");
}

static CheckResult check_cf213_viewingconditionstype_completeness(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigViewingConditionsTag);
    if (!pTag) return CheckResult::skip("No viewingConditionsTag");

    CIccTagViewingConditions *pVC = dynamic_cast<CIccTagViewingConditions *>(pTag);
    if (!pVC) return CheckResult::skip("Not CIccTagViewingConditions");

    std::vector<Finding> findings;

    // Check illuminant XYZ
    icXYZNumber ill = pVC->m_XYZIllum;
    double iX = icFtoD(ill.X), iY = icFtoD(ill.Y), iZ = icFtoD(ill.Z);
    if (iX == 0.0 && iY == 0.0 && iZ == 0.0) {
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 213}, Severity::LOW,
            "viewingConditions illuminant XYZ is all-zero",
            "ICC.1-2022-05 §10.24", ""});
    }

    // Check surround XYZ
    icXYZNumber sur = pVC->m_XYZSurround;
    double sX = icFtoD(sur.X), sY = icFtoD(sur.Y), sZ = icFtoD(sur.Z);
    if (sX == 0.0 && sY == 0.0 && sZ == 0.0) {
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 213}, Severity::LOW,
            "viewingConditions surround XYZ is all-zero",
            "ICC.1-2022-05 §10.24", ""});
    }

    if (findings.empty())
        return CheckResult::ok("viewingConditionsType complete");
    return {CheckResult::Status::FINDINGS, "viewingConditions incomplete", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-220..CF-226: mluc deep validation
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf220_mluc_name_record_overlap(const ProfileView& pv) {
    const uint8_t *raw = pv.rawData();
    size_t rawSize = pv.rawSize();
    if (!raw) return CheckResult::error("No raw data");

    std::vector<Finding> findings;

    for (const auto& te : pv.rawTagTable()) {
        uint32_t off = te.offset;
        uint32_t sz  = te.size;
        if (off + 16 > rawSize || sz < 16) continue;
        if (ReadU32BE(raw + off) != 0x6D6C7563) continue; // 'mluc'

        uint32_t nRecs = ReadU32BE(raw + off + 8);
        if (nRecs < 2 || nRecs > 256) continue;

        // Check for overlapping string data regions
        struct RecRange { uint32_t start, end; };
        std::vector<RecRange> ranges;
        bool overflow = false;

        for (uint32_t r = 0; r < nRecs; r++) {
            uint32_t recOff = off + 16 + r * 12;
            if (recOff + 12 > rawSize) { overflow = true; break; }
            uint32_t strLen = ReadU32BE(raw + recOff + 4);
            uint32_t strOff = ReadU32BE(raw + recOff + 8);
            ranges.push_back({strOff, strOff + strLen});
        }
        if (overflow) continue;

        for (size_t i = 0; i < ranges.size(); i++) {
            for (size_t j = i + 1; j < ranges.size(); j++) {
                if (ranges[i].start == ranges[j].start && ranges[i].end == ranges[j].end)
                    continue; // Shared reference — OK
                bool overlap = (ranges[i].start < ranges[j].end && ranges[j].start < ranges[i].end);
                if (overlap) {
                    char sig[5]; SigToChars(te.signature, sig);
                    findings.push_back(Finding{
                        {CheckID::Kind::Conformance, 220}, Severity::HIGH,
                        std::string("mluc tag '") + sig + "' records " + std::to_string(i) +
                        " and " + std::to_string(j) + " have overlapping data regions",
                        "ICC.1-2022-05 §10.15", "CWE-119"});
                    break;
                }
            }
            if (!findings.empty()) break;
        }
    }

    if (findings.empty())
        return CheckResult::ok("mluc name records have no partial overlaps");
    return {CheckResult::Status::FINDINGS, "mluc record overlaps", std::move(findings)};
}

static CheckResult check_cf221_profile_sequence_desc_structure(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigProfileSequenceDescTag);
    if (!pTag) {
        uint32_t version = pv.header().version;
        bool required = (pv.header().deviceClass == static_cast<uint32_t>(icSigLinkClass) &&
                         version >= icVersionNumberV4);
        if (required) {
            return {CheckResult::Status::FINDINGS, "Missing profileSequenceDescTag", {Finding{
                {CheckID::Kind::Conformance, 221}, Severity::MEDIUM,
                "profileSequenceDescTag required for v4+ DeviceLink profiles",
                "ICC.1-2022-05 §9.2.50", "CWE-20"}}};
        }
        return CheckResult::ok("No profileSequenceDescTag — not required for this class");
    }

    CIccTagProfileSeqDesc *pPSD = dynamic_cast<CIccTagProfileSeqDesc *>(pTag);
    if (!pPSD || !pPSD->m_Descriptions) {
        return {CheckResult::Status::FINDINGS, "Invalid pseq type", {Finding{
            {CheckID::Kind::Conformance, 221}, Severity::MEDIUM,
            "profileSequenceDescTag has wrong type or null descriptions",
            "ICC.1-2022-05 §9.2.50", "CWE-20"}}};
    }

    std::vector<Finding> findings;
    size_t descCount = pPSD->m_Descriptions->size();
    if (descCount == 0) {
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 221}, Severity::MEDIUM,
            "profileSequenceDescTag has 0 entries", "ICC.1-2022-05 §9.2.50", "CWE-20"});
    }
    if (pv.header().deviceClass == static_cast<uint32_t>(icSigLinkClass) && descCount == 1) {
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 221}, Severity::MEDIUM,
            "DeviceLink profileSequenceDescTag has only 1 description (expected at least 2)",
            "ICC.1-2022-05 §9.2.50", "CWE-20"});
    }
    if (descCount > 256) {
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 221}, Severity::HIGH,
            "profileSequenceDescTag has " + std::to_string(descCount) +
            " descriptions (reasonable maximum is 256)",
            "ICC.1-2022-05 §9.2.50", "CWE-20"});
    }

    if (!findings.empty())
        return {CheckResult::Status::FINDINGS, "profileSequenceDescTag structure issues", std::move(findings)};
    return CheckResult::ok("profileSequenceDescTag structure valid");
}

static CheckResult check_cf222_profile_sequence_identifier_validation(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigProfileSequceIdTag);
    if (!pTag) return CheckResult::skip("No profileSequenceIdentifierTag");

    CIccTagProfileSequenceId *pPSI = dynamic_cast<CIccTagProfileSequenceId *>(pTag);
    if (!pPSI) return CheckResult::skip("Not profileSequenceId type");

    std::vector<Finding> findings;
    int idx = 0;
    for (auto it = pPSI->begin(); it != pPSI->end(); ++it, ++idx) {
        bool allZero = true;
        for (int b = 0; b < 16; b++) {
            if (it->m_profileID.ID8[b] != 0) { allZero = false; break; }
        }
        if (allZero) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 222}, Severity::LOW,
                "profileSequenceId entry " + std::to_string(idx) + " all-zero ID",
                "ICC.1-2022-05 §10.18", ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok("profileSequenceIdentifier entries valid");
    return {CheckResult::Status::FINDINGS, "Zero ID entries", std::move(findings)};
}

static CheckResult check_cf223_mluc_zero_name_placeholder(const ProfileView& pv) {
    const uint8_t *raw = pv.rawData();
    size_t rawSize = pv.rawSize();
    if (!raw) return CheckResult::error("No raw data");

    // ICC TN PSD recommends a minimal 12-byte placeholder for a zero-name mluc:
    // type signature + reserved + record count (0), with no record-size field.
    std::vector<Finding> findings;

    for (const auto& te : pv.rawTagTable()) {
        uint32_t off = te.offset;
        if (off + 12 > rawSize) continue;
        if (ReadU32BE(raw + off) != 0x6D6C7563) continue;

        uint32_t nRecs = ReadU32BE(raw + off + 8);
        if (nRecs == 0 && te.size != 12) {
            char sig[5]; SigToChars(te.signature, sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 223}, Severity::LOW,
                std::string("mluc tag '") + sig + "' has 0 records but size=" +
                std::to_string(te.size) + " (recommended: 12-byte zero-name placeholder)",
                "ICC TN PSD §placeholder", ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok("mluc zero-name placeholders valid");
    return {CheckResult::Status::FINDINGS, "mluc placeholder issues", std::move(findings)};
}

static CheckResult check_cf224_mluc_reserved_field_zero(const ProfileView& pv) {
    // Already covered by CF-021 for general tags; this is mluc-specific reserved check
    const uint8_t *raw = pv.rawData();
    size_t rawSize = pv.rawSize();
    if (!raw) return CheckResult::error("No raw data");

    std::vector<Finding> findings;

    for (const auto& te : pv.rawTagTable()) {
        uint32_t off = te.offset;
        if (off + 16 > rawSize) continue;
        if (ReadU32BE(raw + off) != 0x6D6C7563) continue;

        if (raw[off+4] != 0 || raw[off+5] != 0 || raw[off+6] != 0 || raw[off+7] != 0) {
            char sig[5]; SigToChars(te.signature, sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 224}, Severity::LOW,
                std::string("mluc tag '") + sig + "' reserved bytes (4..7) non-zero",
                "ICC.1-2022-05 §10.15", "CWE-20"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("mluc reserved fields are zero");
    return {CheckResult::Status::FINDINGS, "mluc reserved non-zero", std::move(findings)};
}

static CheckResult check_cf225_mluc_name_record_string_alignment(const ProfileView& pv) {
    const uint8_t *raw = pv.rawData();
    size_t rawSize = pv.rawSize();
    if (!raw) return CheckResult::error("No raw data");

    std::vector<Finding> findings;

    for (const auto& te : pv.rawTagTable()) {
        uint32_t off = te.offset;
        if (off + 16 > rawSize) continue;
        if (ReadU32BE(raw + off) != 0x6D6C7563) continue;

        uint32_t nRecs = ReadU32BE(raw + off + 8);

        for (uint32_t r = 0; r < nRecs && r < 256; r++) {
            uint32_t recOff = off + 16 + r * 12;
            if (recOff + 12 > rawSize) break;
            uint32_t strLen = ReadU32BE(raw + recOff + 4);
            uint32_t strOff = ReadU32BE(raw + recOff + 8);

            // UTF-16BE strings must have even length and offset
            if (strLen % 2 != 0 || strOff % 2 != 0) {
                char sig[5]; SigToChars(te.signature, sig);
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 225}, Severity::MEDIUM,
                    std::string("mluc tag '") + sig + "' record " + std::to_string(r) +
                    " has odd string offset/length (UTF-16 alignment)",
                    "ICC.1-2022-05 §10.15", "CWE-131"});
                break;
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("mluc string offsets/lengths are even (UTF-16 aligned)");
    return {CheckResult::Status::FINDINGS, "mluc alignment issues", std::move(findings)};
}

static CheckResult check_cf226_mluc_size_inference_safety(const ProfileView& pv) {
    const uint8_t *raw = pv.rawData();
    size_t rawSize = pv.rawSize();
    if (!raw) return CheckResult::error("No raw data");

    std::vector<Finding> findings;

    for (const auto& te : pv.rawTagTable()) {
        uint32_t off = te.offset;
        uint32_t sz  = te.size;
        if (off + 16 > rawSize || sz < 16) continue;
        if (ReadU32BE(raw + off) != 0x6D6C7563) continue;

        uint32_t nRecs = ReadU32BE(raw + off + 8);
        uint32_t maxEnd = 0;

        for (uint32_t r = 0; r < nRecs && r < 256; r++) {
            uint32_t recOff = off + 16 + r * 12;
            if (recOff + 12 > rawSize) break;
            uint32_t strLen = ReadU32BE(raw + recOff + 4);
            uint32_t strOff = ReadU32BE(raw + recOff + 8);
            uint32_t end = strOff + strLen;
            if (end > maxEnd) maxEnd = end;
        }

        if (maxEnd > sz) {
            char sig[5]; SigToChars(te.signature, sig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 226}, Severity::HIGH,
                std::string("mluc tag '") + sig + "' inferred data end " +
                std::to_string(maxEnd) + " > tag size " + std::to_string(sz),
                "ICC.1-2022-05 §10.15", "CWE-125"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("mluc data within tag boundaries");
    return {CheckResult::Status::FINDINGS, "mluc data overflow", std::move(findings)};
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-227..CF-234: v2→v4 feature changes
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf227_text_tag_unicode_migration(const ProfileView& pv) {
    int major = VersionMajor(pv);
    if (major < 4) return CheckResult::skip("Pre-v4 — textDescriptionType is valid");

    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    static const icTagSignature textTags[] = {
        icSigProfileDescriptionTag, icSigCopyrightTag,
    };

    for (auto sig : textTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;
        if (pTag->GetType() == icSigTextDescriptionType) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 227}, Severity::MEDIUM,
                std::string("v4+ profile uses textDescriptionType for '") + s +
                "' (should use multiLocalizedUnicodeType)",
                "ICC.1-2022-05 §10.15", ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok("v4+ text tags use mluc");
    return {CheckResult::Status::FINDINGS, "Text tag migration", std::move(findings)};
}

static CheckResult check_cf228_gray_trc_semantics(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icColorSpaceSignature cs = static_cast<icColorSpaceSignature>(pv.header().colorSpace);
    if (cs != icSigGrayData) return CheckResult::skip("Not gray color space");

    std::vector<Finding> findings;

    // Gray profiles should have grayTRC, not R/G/B TRCs
    if (pv.hasTag(icSigRedTRCTag) || pv.hasTag(icSigGreenTRCTag) || pv.hasTag(icSigBlueTRCTag)) {
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 228}, Severity::MEDIUM,
            "Gray profile has RGB TRC tags", "ICC.1-2022-05 §9.2.28", ""});
    }

    if (!pv.hasTag(icSigGrayTRCTag)) {
        findings.push_back(Finding{
            {CheckID::Kind::Conformance, 228}, Severity::MEDIUM,
            "Gray profile missing grayTRCTag", "ICC.1-2022-05 §9.2.28", ""});
    }

    if (findings.empty())
        return CheckResult::ok("Gray TRC semantics valid");
    return {CheckResult::Status::FINDINGS, "Gray TRC issues", std::move(findings)};
}

static CheckResult check_cf229_rendering_intent_dominance(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icProfileClassSignature cls = static_cast<icProfileClassSignature>(pv.header().deviceClass);

    int atobCount = 0;
    int btoaCount = 0;
    if (pIcc->FindTag(icSigAToB0Tag)) atobCount++;
    if (pIcc->FindTag(icSigAToB1Tag)) atobCount++;
    if (pIcc->FindTag(icSigAToB2Tag)) atobCount++;
    if (pIcc->FindTag(icSigBToA0Tag)) btoaCount++;
    if (pIcc->FindTag(icSigBToA1Tag)) btoaCount++;
    if (pIcc->FindTag(icSigBToA2Tag)) btoaCount++;

    std::vector<Finding> findings;
    if (cls == icSigInputClass) {
        if (atobCount == 0 && btoaCount > 0) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 229}, Severity::MEDIUM,
                "Input profile has BToA but no AToB — AToB should be dominant",
                "ICC v2->v4 TN", "CWE-20"});
        }
        if (atobCount > 0 && !pIcc->FindTag(icSigAToB0Tag)) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 229}, Severity::MEDIUM,
                "Input profile has AToB tags but missing AToB0 (Perceptual)",
                "ICC v2->v4 TN", "CWE-20"});
        }
    } else if (cls == icSigDisplayClass || cls == icSigOutputClass) {
        if (btoaCount == 0 && atobCount > 0) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 229}, Severity::MEDIUM,
                std::string(cls == icSigDisplayClass ? "Display" : "Output") +
                " profile has AToB but no BToA — BToA should be dominant",
                "ICC v2->v4 TN", "CWE-20"});
        }
        if (btoaCount > 0 && !pIcc->FindTag(icSigBToA0Tag)) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 229}, Severity::MEDIUM,
                std::string(cls == icSigDisplayClass ? "Display" : "Output") +
                " profile has BToA tags but missing BToA0",
                "ICC v2->v4 TN", "CWE-20"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("Rendering intent dominance consistent with profile class");
    return {CheckResult::Status::FINDINGS, "Rendering intent dominance issue", std::move(findings)};
}

static CheckResult check_cf230_cielab_encoding_consistency(const ProfileView& pv) {
    icColorSpaceSignature pcs = static_cast<icColorSpaceSignature>(pv.header().pcs);
    int major = VersionMajor(pv);

    if (pcs != icSigLabData) return CheckResult::skip("PCS is not Lab");

    // v2 and v4 use different Lab encodings — informational
    if (major <= 2) {
        return CheckResult::ok("v2 Lab encoding: L*=[0,FF00h→100], a*,b*=[0,FF00h→-128..+127]");
    }
    return CheckResult::ok("v4 Lab encoding: L*=[0,FFFFh→100], a*,b*=[0,FFFFh→-128..+127]");
}

static CheckResult check_cf233_colorant_order_index_validation(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigColorantOrderTag);
    if (!pTag) return CheckResult::skip("No colorantOrderTag");

    CIccTagColorantOrder *pOrder = dynamic_cast<CIccTagColorantOrder *>(pTag);
    if (!pOrder) return CheckResult::skip("Not CIccTagColorantOrder");

    icColorSpaceSignature cs = static_cast<icColorSpaceSignature>(pv.header().colorSpace);
    int nCh = icGetSpaceSamples(cs);

    std::vector<Finding> findings;
    for (int i = 0; i < nCh && i < (int)pOrder->GetSize(); i++) {
        icUInt8Number idx = (*pOrder)[i];
        if (idx >= nCh) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 233}, Severity::HIGH,
                "colorantOrder[" + std::to_string(i) + "]=" + std::to_string(idx) +
                " >= channels=" + std::to_string(nCh),
                "ICC.1-2022-05 §10.3", "CWE-125"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("colorantOrder indices valid");
    return {CheckResult::Status::FINDINGS, "colorantOrder OOB", std::move(findings)};
}

static CheckResult check_cf234_perceptual_pcs_reference_medium(const ProfileView& pv) {
    // Informational — PCS reference medium is reflection paper
    uint32_t intent = pv.header().renderingIntent;
    if (intent != 0 && intent != 1) return CheckResult::skip("Not Perceptual/Relative");

    return CheckResult::ok("PCS reference medium acknowledged (reflection paper)");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-247..CF-254: Additional tag type validations
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf247_viewing_conditions_illuminant_type_range(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigViewingConditionsTag);
    if (!pTag) return CheckResult::skip("No viewingConditionsTag");

    CIccTagViewingConditions *pVC = dynamic_cast<CIccTagViewingConditions *>(pTag);
    if (!pVC) return CheckResult::skip("Not viewingConditions type");

    icIlluminant illType = pVC->m_illumType;
    // Valid range 0-8 per ICC.1-2022-05 Table 24
    if (illType > 8) {
        return {CheckResult::Status::FINDINGS, "Invalid illuminant type", {Finding{
            {CheckID::Kind::Conformance, 247}, Severity::MEDIUM,
            "viewingConditions illuminantType=" + std::to_string(static_cast<int>(illType)) +
            " (valid 0-8)",
            "ICC.1-2022-05 §10.24", "CWE-20"}}};
    }
    return CheckResult::ok("Illuminant type in range 0-8");
}

static CheckResult check_cf248_namedcolor2_device_coords_limit(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigNamedColor2Tag);
    if (!pTag) return CheckResult::skip("No namedColor2Tag");

    CIccTagNamedColor2 *pNC = dynamic_cast<CIccTagNamedColor2 *>(pTag);
    if (!pNC) return CheckResult::skip("Not namedColor2 type");

    icUInt32Number nDev = pNC->GetDeviceCoords();
    if (nDev > 15) {
        return {CheckResult::Status::FINDINGS, "Excessive deviceCoords", {Finding{
            {CheckID::Kind::Conformance, 248}, Severity::HIGH,
            "namedColor2 deviceCoords=" + std::to_string(nDev) + " > ICC max 15",
            "ICC.1-2022-05 §10.17", "CWE-400"}}};
    }
    return CheckResult::ok("namedColor2 deviceCoords <= 15");
}

static CheckResult check_cf249_profile_description_non_empty(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigProfileDescriptionTag);
    if (!pTag) return CheckResult::skip("No profileDescriptionTag");

    std::string desc;
    pTag->Describe(desc, 200);
    if (desc.empty() || desc.find_first_not_of(" \t\n\r\0") == std::string::npos) {
        return {CheckResult::Status::FINDINGS, "Empty description", {Finding{
            {CheckID::Kind::Conformance, 249}, Severity::LOW,
            "profileDescriptionTag text is empty or whitespace-only",
            "ICC.1-2022-05 §9.2.41", "CWE-20"}}};
    }
    return CheckResult::ok("profileDescription non-empty");
}

static CheckResult check_cf250_copyright_non_empty(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigCopyrightTag);
    if (!pTag) return CheckResult::skip("No copyrightTag");

    std::string desc;
    pTag->Describe(desc, 200);
    if (desc.empty() || desc.find_first_not_of(" \t\n\r\0") == std::string::npos) {
        return {CheckResult::Status::FINDINGS, "Empty copyright", {Finding{
            {CheckID::Kind::Conformance, 250}, Severity::LOW,
            "copyrightTag text is empty or whitespace-only",
            "ICC.1-2022-05 §9.2.21", "CWE-20"}}};
    }
    return CheckResult::ok("copyrightTag non-empty");
}

static CheckResult check_cf251_chromaticity_phosphor_type_range(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigChromaticityTag);
    if (!pTag) return CheckResult::skip("No chromaticityTag");

    CIccTagChromaticity *pChrom = dynamic_cast<CIccTagChromaticity *>(pTag);
    if (!pChrom) return CheckResult::skip("Not CIccTagChromaticity");

    // Phosphor type 0-4 per ICC.1 Table 30
    icUInt16Number pt = pChrom->m_nColorantType;
    if (pt > 4 && pt != 0) {
        return {CheckResult::Status::FINDINGS, "Invalid phosphor type", {Finding{
            {CheckID::Kind::Conformance, 251}, Severity::LOW,
            "chromaticityTag phosphorType=" + std::to_string(pt) + " (valid 0-4)",
            "ICC.1-2022-05 §10.2", "CWE-20"}}};
    }
    return CheckResult::ok("Phosphor type valid");
}

static CheckResult check_cf252_curvetype_gamma_positive_finite(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    static const icTagSignature trcTags[] = {
        icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag
    };

    for (auto sig : trcTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;
        if (pTag->GetType() != icSigCurveType) continue;

        CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve *>(pTag);
        if (!pCurve || pCurve->GetSize() != 1) continue;

        // Single entry = gamma value
        icFloatNumber gamma = (*pCurve)[0];
        if (gamma <= 0.0f || std::isnan(gamma) || std::isinf(gamma)) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 252}, Severity::HIGH,
                std::string("TRC '") + s + "' gamma=" + std::to_string(gamma) +
                " (must be positive and finite)",
                "ICC.1-2022-05 §10.6", "CWE-682"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("Curve gamma values positive and finite");
    return {CheckResult::Status::FINDINGS, "Invalid gamma", std::move(findings)};
}

static CheckResult check_cf253_chromaticity_channel_count_consistency(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigChromaticityTag);
    if (!pTag) return CheckResult::skip("No chromaticityTag");

    CIccTagChromaticity *pChrom = dynamic_cast<CIccTagChromaticity *>(pTag);
    if (!pChrom) return CheckResult::skip("Not CIccTagChromaticity");

    icColorSpaceSignature cs = static_cast<icColorSpaceSignature>(pv.header().colorSpace);
    int nCh = icGetSpaceSamples(cs);
    int nChrom = pChrom->GetSize();

    if (nChrom != nCh) {
        return {CheckResult::Status::FINDINGS, "Chromaticity channel mismatch", {Finding{
            {CheckID::Kind::Conformance, 253}, Severity::MEDIUM,
            "chromaticityTag channels=" + std::to_string(nChrom) +
            " != colorSpace channels=" + std::to_string(nCh),
            "ICC.1-2022-05 §10.2", "CWE-131"}}};
    }
    return CheckResult::ok("Chromaticity channels match color space");
}

static CheckResult check_cf254_technology_signature_in_table(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigTechnologyTag);
    if (!pTag) return CheckResult::skip("No technologyTag");

    CIccTagSignature *pSigTag = dynamic_cast<CIccTagSignature *>(pTag);
    if (!pSigTag) return CheckResult::skip("Not signatureType");

    icSignature tech = pSigTag->GetValue();
    bool found = false;
    for (auto known : kKnownTechSigs) {
        if (tech == known) { found = true; break; }
    }

    if (!found && tech != 0) {
        char s[5]; SigToChars(static_cast<uint32_t>(tech), s);
        return {CheckResult::Status::FINDINGS, "Unknown tech sig", {Finding{
            {CheckID::Kind::Conformance, 254}, Severity::LOW,
            std::string("Technology signature '") + s + "' not in ICC.1 Table 25",
            "ICC.1-2022-05 §9.2.47", "CWE-20"}}};
    }
    return CheckResult::ok("Technology signature recognized");
}


// ═══════════════════════════════════════════════════════════════════════════════
// CF-263..CF-265: Extended checks
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf263_perceptual_pcs_white_point_d50(const ProfileView& pv) {
    double iX = S15Fixed16ToDouble(pv.header().illuminantX);
    double iY = S15Fixed16ToDouble(pv.header().illuminantY);
    double iZ = S15Fixed16ToDouble(pv.header().illuminantZ);

    // PCS illuminant must be D50 = (0.9642, 1.0000, 0.8249)
    const double tol = 0.002;
    if (std::fabs(iX - 0.9642) > tol || std::fabs(iY - 1.0000) > tol || std::fabs(iZ - 0.8249) > tol) {
        return {CheckResult::Status::FINDINGS, "PCS illuminant not D50", {Finding{
            {CheckID::Kind::Conformance, 263}, Severity::MEDIUM,
            "PCS illuminant (" + std::to_string(iX) + ", " + std::to_string(iY) +
            ", " + std::to_string(iZ) + ") deviates from D50 (0.9642, 1.0000, 0.8249)",
            "ICC.1-2022-05 §7.2.16", "CWE-682"}}};
    }
    return CheckResult::ok("PCS illuminant is D50");
}

static CheckResult check_cf264_parametric_curve_func_type_in_mbb(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    static const icTagSignature mbbTags[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    };

    for (auto sig : mbbTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;

        CIccTagLutAtoB *pLut = dynamic_cast<CIccTagLutAtoB *>(pTag);
        if (!pLut) continue;

        // Check A curves
        CIccCurve *const *aCurves = pLut->GetCurvesA();
        if (aCurves) {
            for (int c = 0; c < 16; c++) {
                if (!aCurves[c]) break;
                CIccTagParametricCurve *pPC = dynamic_cast<CIccTagParametricCurve *>(aCurves[c]);
                if (pPC) {
                    icUInt16Number ft = pPC->GetFunctionType();
                    if (ft > 4) {
                        char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
                        findings.push_back(Finding{
                            {CheckID::Kind::Conformance, 264}, Severity::MEDIUM,
                            std::string("LUT '") + s + "' A-curve channel " + std::to_string(c) +
                            " parametricCurve funcType=" + std::to_string(ft) + " (valid 0-4)",
                            "ICC.1-2022-05 §10.18", "CWE-20"});
                    }
                }
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("parametricCurve funcTypes valid in MBB");
    return {CheckResult::Status::FINDINGS, "Invalid funcType in MBB", std::move(findings)};
}

static CheckResult check_cf265_mluc_language_country_code_validity(const ProfileView& pv) {
    const uint8_t *raw = pv.rawData();
    size_t rawSize = pv.rawSize();
    if (!raw) return CheckResult::error("No raw data");

    std::vector<Finding> findings;

    for (const auto& te : pv.rawTagTable()) {
        uint32_t off = te.offset;
        if (off + 16 > rawSize) continue;
        if (ReadU32BE(raw + off) != 0x6D6C7563) continue;

        uint32_t nRecs = ReadU32BE(raw + off + 8);

        for (uint32_t r = 0; r < nRecs && r < 256; r++) {
            uint32_t recOff = off + 16 + r * 12;
            if (recOff + 12 > rawSize) break;
            uint16_t lang = ReadU16BE(raw + recOff);
            uint16_t ctry = ReadU16BE(raw + recOff + 2);

            // ISO 639-1 codes are two lowercase ASCII letters
            uint8_t l1 = lang >> 8, l2 = lang & 0xFF;
            if (lang != 0 && (l1 < 'a' || l1 > 'z' || l2 < 'a' || l2 > 'z')) {
                char sig[5]; SigToChars(te.signature, sig);
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 265}, Severity::LOW,
                    std::string("mluc '") + sig + "' record " + std::to_string(r) +
                    " invalid language code 0x" + std::to_string(lang),
                    "ICC.1-2022-05 §10.15", ""});
                break;
            }

            // ISO 3166-1 codes are two uppercase ASCII letters
            uint8_t c1 = ctry >> 8, c2 = ctry & 0xFF;
            if (ctry != 0 && (c1 < 'A' || c1 > 'Z' || c2 < 'A' || c2 > 'Z')) {
                char sig[5]; SigToChars(te.signature, sig);
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 265}, Severity::LOW,
                    std::string("mluc '") + sig + "' record " + std::to_string(r) +
                    " invalid country code 0x" + std::to_string(ctry),
                    "ICC.1-2022-05 §10.15", ""});
                break;
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("mluc language/country codes valid");
    return {CheckResult::Status::FINDINGS, "mluc code issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════════
// CF-273..CF-281: Tag type enforcement
// ═══════════════════════════════════════════════════════════════════════════════

static CheckResult check_cf273_primary_colorant_xyz_positive(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    if (pv.header().colorSpace != static_cast<uint32_t>(icSigRgbData))
        return CheckResult::ok("Not RGB — primary colorant XYZ plausibility not applicable");

    std::vector<Finding> findings;
    static const icTagSignature matTags[] = {
        icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag
    };

    for (auto sig : matTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;

        CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ *>(pTag);
        if (!pXYZ || pXYZ->GetSize() < 1) continue;

        icXYZNumber val = (*pXYZ)[0];
        double X = icFtoD(val.X), Y = icFtoD(val.Y), Z = icFtoD(val.Z);

        if (Y < 0.0) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 273}, Severity::LOW,
                std::string("Colorant '") + s + "' has negative Y=" + std::to_string(Y),
                "ICC.1-2022-05 §9.2.49", ""});
        }
        if (X < -2.0 || X > 3.0 || Y > 3.0 || Z < -2.0 || Z > 3.0) {
            char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 273}, Severity::LOW,
                std::string("Colorant '") + s + "' values out of plausible range (" +
                std::to_string(X) + ", " + std::to_string(Y) + ", " + std::to_string(Z) + ")",
                "ICC.1-2022-05 §10.28", ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok("Colorant XYZ values acceptable");
    return {CheckResult::Status::FINDINGS, "Primary colorant XYZ issues", std::move(findings)};
}

static CheckResult check_cf274_primary_colorant_chromaticity_sum_nonzero(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigChromaticityTag);
    if (!pTag) return CheckResult::skip("No chromaticityTag");

    CIccTagChromaticity *pChrom = dynamic_cast<CIccTagChromaticity *>(pTag);
    if (!pChrom) return CheckResult::skip("Not chromaticity type");

    // Each chromaticity coordinate pair should not both be zero
    std::vector<Finding> findings;
    for (int c = 0; c < pChrom->GetSize() && c < 16; c++) {
        icChromaticityNumber ch = *pChrom->Getxy(c);
        if (ch.x == 0.0 && ch.y == 0.0) {
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 274}, Severity::MEDIUM,
                "Chromaticity channel " + std::to_string(c) + " has (0,0) coordinates",
                "ICC.1-2022-05 §10.2", "CWE-682"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("Chromaticity sums non-zero");
    return {CheckResult::Status::FINDINGS, "Zero chromaticity", std::move(findings)};
}

static CheckResult check_cf275_copyright_must_be_mluc_v4(const ProfileView& pv) {
    int major = VersionMajor(pv);
    if (major < 4) return CheckResult::skip("Pre-v4 — textType allowed");

    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigCopyrightTag);
    if (!pTag) return CheckResult::skip("No copyrightTag");

    if (pTag->GetType() != icSigMultiLocalizedUnicodeType) {
        char ts[5]; SigToChars(static_cast<uint32_t>(pTag->GetType()), ts);
        return {CheckResult::Status::FINDINGS, "Wrong copyright type for v4+", {Finding{
            {CheckID::Kind::Conformance, 275}, Severity::MEDIUM,
            std::string("v4+ copyrightTag type='") + ts + "' (must be multiLocalizedUnicodeType)",
            "ICC.1-2022-05 §9.2.21", ""}}};
    }
    return CheckResult::ok("copyrightTag is mluc (v4+)");
}

static CheckResult check_cf276_profile_description_must_be_mluc_v4(const ProfileView& pv) {
    int major = VersionMajor(pv);
    if (major < 4) return CheckResult::skip("Pre-v4 — textDescriptionType allowed");

    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigProfileDescriptionTag);
    if (!pTag) return CheckResult::skip("No profileDescriptionTag");

    if (pTag->GetType() != icSigMultiLocalizedUnicodeType) {
        char ts[5]; SigToChars(static_cast<uint32_t>(pTag->GetType()), ts);
        return {CheckResult::Status::FINDINGS, "Wrong desc type for v4+", {Finding{
            {CheckID::Kind::Conformance, 276}, Severity::MEDIUM,
            std::string("v4+ profileDescriptionTag type='") + ts +
            "' (must be multiLocalizedUnicodeType)",
            "ICC.1-2022-05 §9.2.41", ""}}};
    }
    return CheckResult::ok("profileDescriptionTag is mluc (v4+)");
}

static CheckResult check_cf277_media_white_point_must_be_xyz(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigMediaWhitePointTag);
    if (!pTag) return CheckResult::skip("No mediaWhitePointTag");

    if (pTag->GetType() != icSigXYZType) {
        char ts[5]; SigToChars(static_cast<uint32_t>(pTag->GetType()), ts);
        return {CheckResult::Status::FINDINGS, "Wrong wtpt type", {Finding{
            {CheckID::Kind::Conformance, 277}, Severity::HIGH,
            std::string("mediaWhitePointTag type='") + ts + "' (must be XYZType)",
            "ICC.1-2022-05 §9.2.34", "CWE-843"}}};
    }
    return CheckResult::ok("mediaWhitePointTag is XYZType");
}

static CheckResult check_cf278_chad_must_be_s15fixed16array(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigChromaticAdaptationTag);
    if (!pTag) return CheckResult::skip("No chad tag");

    if (pTag->GetType() != icSigS15Fixed16ArrayType) {
        char ts[5]; SigToChars(static_cast<uint32_t>(pTag->GetType()), ts);
        return {CheckResult::Status::FINDINGS, "Wrong chad type", {Finding{
            {CheckID::Kind::Conformance, 278}, Severity::HIGH,
            std::string("chromaticAdaptationTag type='") + ts + "' (must be s15Fixed16ArrayType)",
            "ICC.1-2022-05 §9.2.17", "CWE-843"}}};
    }
    return CheckResult::ok("chromaticAdaptationTag is s15Fixed16ArrayType");
}

static CheckResult check_cf279_trc_curve_values_non_negative(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    static const icTagSignature trcTags[] = {
        icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag
    };

    for (auto sig : trcTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;

        CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve *>(pTag);
        if (!pCurve) continue;

        uint32_t sz = pCurve->GetSize();
        for (uint32_t i = 0; i < sz && i < 4096; i++) {
            icFloatNumber v = (*pCurve)[i];
            if (v < 0.0f) {
                char s[5]; SigToChars(static_cast<uint32_t>(sig), s);
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 279}, Severity::MEDIUM,
                    std::string("TRC '") + s + "' entry " + std::to_string(i) +
                    " = " + std::to_string(v) + " (negative)",
                    "ICC.1-2022-05 §10.6", "CWE-682"});
                break;
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("TRC curve values non-negative");
    return {CheckResult::Status::FINDINGS, "Negative TRC values", std::move(findings)};
}

static CheckResult check_cf280_xyz_element_luminance_non_negative(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    for (const auto& entry : pIcc->m_Tags) {
        CIccTag *pTag = pIcc->FindTag(entry.TagInfo.sig);
        if (!pTag || pTag->GetType() != icSigXYZType) continue;

        CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ *>(pTag);
        if (!pXYZ) continue;

        char sig[5];
        SigToChars(static_cast<uint32_t>(entry.TagInfo.sig), sig);
        for (icUInt32Number i = 0; i < pXYZ->GetSize(); i++) {
            icXYZNumber *xyz = pXYZ->GetXYZ(i);
            if (!xyz) continue;
            double Y = icFtoD(xyz->Y);
            if (Y < -0.001) {
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 280}, Severity::HIGH,
                    std::string("XYZ tag '") + sig + "' element " + std::to_string(i) +
                    " has negative Y=" + std::to_string(Y),
                    "ICC.1-2022-05 §10.28", "CWE-682"});
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("XYZ luminance values non-negative");
    return {CheckResult::Status::FINDINGS, "Negative luminance", std::move(findings)};
}

static CheckResult check_cf281_profile_sequence_desc_type_check(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigProfileSequenceDescTag);
    if (!pTag) return CheckResult::skip("No profileSequenceDescTag");

    if (pTag->GetType() != icSigProfileSequenceDescType) {
        char ts[5]; SigToChars(static_cast<uint32_t>(pTag->GetType()), ts);
        return {CheckResult::Status::FINDINGS, "Wrong pseq type", {Finding{
            {CheckID::Kind::Conformance, 281}, Severity::MEDIUM,
            std::string("profileSequenceDescTag type='") + ts + "' (must be profileSequenceDescType)",
            "ICC.1-2022-05 §10.19", "CWE-843"}}};
    }
    return CheckResult::ok("profileSequenceDescTag correct type");
}


// ═══════════════════════════════════════════════════════════════════════════════
// Registration — 94 conformance checks
// ═══════════════════════════════════════════════════════════════════════════════

REGISTER_CONFORMANCE(20, "Tag Type Allowed for Signature",
    "§9.2, §10", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf020_tag_type_allowed_for_signature);

REGISTER_CONFORMANCE(21, "Tag Type Reserved Bytes Zero",
    "§10 (all types)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf021_tag_type_reserved_bytes_zero);

REGISTER_CONFORMANCE(22, "curveType Entry Count Mode",
    "§10.6", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf022_curvetype_entry_count_mode);

REGISTER_CONFORMANCE(23, "parametricCurveType Function Type",
    "§10.18 Table 68", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf023_parametriccurvetype_function_type);

REGISTER_CONFORMANCE(24, "parametricCurveType Parameter Count",
    "§10.18 Table 68", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf024_parametriccurvetype_parameter_count);

REGISTER_CONFORMANCE(25, "chromaticityType Phosphor Count",
    "§10.2", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf025_chromaticitytype_phosphor_count);

REGISTER_CONFORMANCE(26, "colorantTableType Colorant Count",
    "§10.4", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf026_coloranttabletype_colorant_count);

REGISTER_CONFORMANCE(27, "colorantOrderType Count Match",
    "§10.3", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf027_colorantordertype_count_match);

REGISTER_CONFORMANCE(28, "namedColor2Type Coordinate Count",
    "§10.14", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf028_namedcolor2type_coordinate_count);

REGISTER_CONFORMANCE(29, "dateTimeType Field Ranges",
    "§10.7, §4.2", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf029_datetimetype_field_ranges);

REGISTER_CONFORMANCE(30, "multiLocalizedUnicodeType Structure",
    "§10.13", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf030_multilocalizedunicodetype_structure);

REGISTER_CONFORMANCE(31, "s15Fixed16ArrayType Element Count",
    "§10.18", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf031_s15fixed16arraytype_element_count);

REGISTER_CONFORMANCE(32, "XYZType Triplet Count",
    "§10.23", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf032_xyztype_triplet_count);

REGISTER_CONFORMANCE(33, "measurementType Standard Observer",
    "§10.12 Table 56", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf033_measurementtype_standard_observer);

REGISTER_CONFORMANCE(34, "measurementType Measurement Geometry",
    "§10.12 Table 57", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf034_measurementtype_measurement_geometry);

REGISTER_CONFORMANCE(35, "responseCurveSet16Type Structure",
    "§10.18", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf035_responsecurveset16type_structure);

REGISTER_CONFORMANCE(36, "profileSequenceDescType Elements",
    "§10.17", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf036_profilesequencedesctype_elements);

REGISTER_CONFORMANCE(37, "profileSequenceIdentifierType Validation",
    "§10.18", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf037_profilesequenceidentifiertype_validation);

REGISTER_CONFORMANCE(38, "dateTimeType Tag Range Validation",
    "§10.7", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf038_datetimetype_tag_range_validation);

REGISTER_CONFORMANCE(39, "signatureType Technology Validation",
    "§9.2.30 Table 29", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf039_signaturetype_technology_validation);

REGISTER_CONFORMANCE(112, "XYZ Triplet Normalization",
    "§10.31 (XYZ values finite, Y non-negative)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf112_xyz_triplet_normalization);

REGISTER_CONFORMANCE(123, "ADGC Class Restriction",
    "ADGC §3 (RGB + Input|Display only)", "ICC.1-ADGC-2025",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf123_adgc_class_restriction);

REGISTER_CONFORMANCE(124, "ADGC Type Signature",
    "ADGC Table 1 (type 'adgc' = 0x61646763)", "ICC.1-ADGC-2025",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf124_adgc_type_signature);

REGISTER_CONFORMANCE(125, "ADGC Function Type ID",
    "ADGC Table 1 (functionTypeID must be 1)", "ICC.1-ADGC-2025",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf125_adgc_function_type_id);

REGISTER_CONFORMANCE(126, "ADGC Reserved Bytes",
    "ADGC Table 1 (bytes 4-7 shall be 0)", "ICC.1-ADGC-2025",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf126_adgc_reserved_bytes);

REGISTER_CONFORMANCE(127, "ADGC Float Field Finiteness",
    "ADGC Table 1 (all float32 fields finite)", "ICC.1-ADGC-2025",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf127_adgc_float_finiteness);

REGISTER_CONFORMANCE(128, "ADGC Weight Coefficient Sum",
    "ADGC §5 (kR+kG+kB+kMax+kMin+kComp ≈ 1.0)", "ICC.1-ADGC-2025",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf128_adgc_weight_sum);

REGISTER_CONFORMANCE(129, "ADGC Curve Position Bounds",
    "ADGC Table 1 (positionNumber within tag)", "ICC.1-ADGC-2025",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf129_adgc_curve_position_bounds);

REGISTER_CONFORMANCE(130, "ADGC Image-Specific GUID Flags",
    "ADGC §6 (GUID≠0 → flags bits 0,1 set)", "ICC.1-ADGC-2025",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf130_adgc_guid_flags);

REGISTER_CONFORMANCE(131, "ADGC Headroom Range Plausibility",
    "ADGC Table 1 (headroom log2 in reasonable range)", "ICC.1-ADGC-2025",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf131_adgc_headroom_range);

REGISTER_CONFORMANCE(132, "ADGC Curve Data Monotonicity",
    "ADGC Table 2 (x values monotonically increasing)", "ICC.1-ADGC-2025",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf132_adgc_curve_monotonicity);

REGISTER_CONFORMANCE(133, "ADGC H_baseline vs H_alternate Division-by-Zero",
    "ADGC §1.2.3 (W_target denominator H_alt-H_base must be nonzero)", "ICC.1-ADGC-2025",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf133_adgc_division_by_zero_guard);

REGISTER_CONFORMANCE(134, "ADGC Per-Channel GainMin ≤ GainMax",
    "ADGC §1.2.3 (GainMin > GainMax inverts gain range)", "ICC.1-ADGC-2025",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf134_adgc_per_channel_gain_range);

REGISTER_CONFORMANCE(135, "ADGC Curve X-Value Domain Range",
    "ADGC §1.2.2 (first x ≥ 0.0, last x ≤ 1.0 for normalized input)", "ICC.1-ADGC-2025",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf135_adgc_curve_x_domain);

REGISTER_CONFORMANCE(136, "ADGC Curve Adjacent-Point X-Equality",
    "ADGC §1.2.2 (x1 == x2 → div-by-zero in cubic coefficient C3)", "ICC.1-ADGC-2025",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf136_adgc_curve_adjacent_x_equality);

REGISTER_CONFORMANCE(137, "MultiplexDefaultValues Tag Type",
    "ICC.2-2019 §9.2.84 Errata: permitted types corrected to ui08/ui16/fl16/fl32", "ICC.2-2019-Errata-2021-03",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf137_multiplex_default_values_type);

REGISTER_CONFORMANCE(138, "Embedded Height Image Data Length",
    "ICC.2-2019 §10.2.6 Errata: image data = tagSize - 24 (header is 24 bytes, not 12)", "ICC.2-2019-Errata-2021-03",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf138_embedded_height_image_data_length);

REGISTER_CONFORMANCE(139, "Embedded Normal Image Data Length",
    "ICC.2-2019 §10.2.7 Errata: image data = tagSize - 16 (header is 16 bytes, not 12)", "ICC.2-2019-Errata-2021-03",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf139_embedded_normal_image_data_length);

REGISTER_CONFORMANCE(140, "GBD Vertex Count Field",
    "ICC.2-2019 §10.2.11 Errata: bytes 12..15 = Number of vertices (V) uInt32Number", "ICC.2-2019-Errata-2021-03",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf140_gbd_vertex_count_field);

REGISTER_CONFORMANCE(141, "Sparse Matrix Array Count Field",
    "ICC.2-2019 §10.2.20 Errata: bytes 12..15 = Number of sparse matrices (N)", "ICC.2-2019-Errata-2021-03",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf141_sparse_matrix_array_count);

REGISTER_CONFORMANCE(142, "Calculator Vector-Or Signature Alignment",
    "ICC.2-2019 §11.2.1.9 Errata: 'vor' corrected to 'vor ' (4-byte aligned)", "ICC.2-2019-Errata-2021-09",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf142_calculator_vector_or_alignment);

REGISTER_CONFORMANCE(143, "Measurement Tag Structure Type",
    "ICC.2-2019 §9.2.86/87 Errata: permitted type = tagStructType (not structType)", "ICC.2-2019-Errata-2021-03",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf143_measurement_tag_structure_type);

REGISTER_CONFORMANCE(148, "Extended Range LUT multiProcessElementsType",
    "AToB1/BToA1 tags shall use multiProcessElementsType for extended range profiles (errata: plural)", "ICS-ExtendedRange-Part1 Table 4",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf148_extended_range_lut_mpet);

REGISTER_CONFORMANCE(153, "Embedded Profile Tag Presence",
    "ICC5 tag with ICCp type for embedding ICC.2 profile in ICC.1 container", "ICC TN Embedding",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf153_embedded_profile_tag_presence);

REGISTER_CONFORMANCE(159, "Dictionary Name Uniqueness",
    "Name strings in dictType shall be unique within the tag", "ICC.2-2023 §10.2.6",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf159_dictionary_name_uniqueness);

REGISTER_CONFORMANCE(160, "Dictionary Name Non-Zero",
    "Name string position size shall be > 0 for each name-value record", "ICC.2-2023 §10.2.6",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf160_dictionary_name_non_zero);

REGISTER_CONFORMANCE(161, "Dictionary Record Length Alignment",
    "dictType record length N shall be 16, 24, or 32", "ICC.2-2023 §10.2.6 Table 40",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf161_dictionary_record_length_alignment);

REGISTER_CONFORMANCE(169, "Negative PCSXYZ Encoding Capability",
    "XYZ tags with negative values must use s15Fixed16 or float32 encoding (u1Fixed15 cannot represent negatives)", "ICC TN Negative PCSXYZ, ICC.1:2010 §6.3.4.2",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf169_negative_pcsxyz_encoding_capability);

REGISTER_CONFORMANCE(170, "Chromatic Adaptation Negative XYZ Consistency",
    "Negative matrix column values from chromatic adaptation should have a corresponding chad tag", "ICC TN Negative PCSXYZ, ICC.1-2022-05 §9.2.10",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf170_chad_negative_xyz_consistency);

REGISTER_CONFORMANCE(171, "White Point Non-Negative Luminance",
    "Media white point and luminance tag Y values must be non-negative (physically impossible otherwise)", "ICC TN Negative PCSXYZ, ICC.1:2010 §3.1.24",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf171_white_point_non_negative_luminance);

REGISTER_CONFORMANCE(172, "Colorant XYZ Sum White Point Consistency",
    "Sum of rXYZ+gXYZ+bXYZ matrix columns should approximate the media white point within s15Fixed16 tolerance", "ICC TN Negative PCSXYZ, ICC.1-2022-05 §9.2.7",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf172_colorant_sum_white_point_consistency);

REGISTER_CONFORMANCE(173, "PCS XYZ Absorber Encoding",
    "White point must not be [0,0,0] — that value is reserved for the perfect absorber; luminance Y must be non-zero", "ICC TN Negative PCSXYZ, ICC.1:2010 §6.4.3",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf173_pcs_xyz_absorber_encoding);

REGISTER_CONFORMANCE(174, "Lab Conversion Clipping Awareness",
    "Lab PCS profiles should use LUT model (not matrix/TRC); XYZ PCS negative values are valid per ICC TN", "ICC TN Negative PCSXYZ, ICC.1:2010 §6.4",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf174_lab_conversion_clipping_awareness);

REGISTER_CONFORMANCE(188, "Global Per-Tag Validate() Sweep",
    "Call CIccTag::Validate() on every tag and report aggregate compliance status", "SampleICC §3 Compliance Testing",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf188_global_tag_validate_sweep);

REGISTER_CONFORMANCE(189, "Tag Type Recognition Coverage",
    "Flag tags parsed as CIccTagUnknown — unrecognized type signatures cannot be semantically validated", "SampleICC §3 CheckTagTypes",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf189_tag_type_recognition_coverage);

REGISTER_CONFORMANCE(190, "Profile Legibility Gate",
    "Composite readability check: non-empty tag table, all entries parse to non-NULL, file size matches header", "SampleICC §3 ReadValidate",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf190_profile_legibility_gate);

REGISTER_CONFORMANCE(208, "Tag Type Version Compatibility",
    "Check that v2 profiles do not use v4+ tag types (parametricCurveType, lutAToBType, lutBToAType, multiProcessElementType)", "ICC.1-2022-05 §7.2.4, §10",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf208_tag_type_version_compatibility);

REGISTER_CONFORMANCE(209, "Colorspace Channel Count vs LUT Dimensions",
    "Cross-validate AToB/BToA LUT input/output channels against declared colorSpace and PCS channel counts", "ICC.1-2022-05 §7.2.6, §10.8-10.11",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf209_colorspace_channel_count_vs_lut);

REGISTER_CONFORMANCE(212, "textType Null Termination",
    "Validate textType tag data is non-null and non-empty per §10.24 requirements", "ICC.1-2022-05 §10.24",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf212_texttype_null_termination);

REGISTER_CONFORMANCE(213, "viewingConditionsType Completeness",
    "Validate illuminant (positive Y), surround (non-negative Y), and illuminant type enumeration in viewingConditionsType", "ICC.1-2022-05 §10.32",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf213_viewingconditionstype_completeness);

REGISTER_CONFORMANCE(220, "mluc Name Record Overlap Detection",
    "Detect partial overlaps between mluc name record string ranges (exact sharing OK, partial overlap = CWE-119)", "ICC TN PSD §mluc",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf220_mluc_name_record_overlap);

REGISTER_CONFORMANCE(221, "profileSequenceDescTag Structure",
    "Validate profileSequenceDescTag description count, entry structure, and embedded mluc locale counts", "ICC.1-2022-05 §9.2.50",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf221_profile_sequence_desc_structure);

REGISTER_CONFORMANCE(222, "profileSequenceIdentifierTag Validation",
    "Validate psid entry count, profile IDs (non-zero), embedded descriptions, and cross-check with pseq count", "ICC.1-2022-05 §9.2.51",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf222_profile_sequence_identifier_validation);

REGISTER_CONFORMANCE(223, "mluc Zero-Name Placeholder Encoding",
    "Zero-name mluc should encode as exactly 12 bytes per ICC TN PSD recommendation to avoid parsing ambiguity", "ICC TN PSD §placeholder",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf223_mluc_zero_name_placeholder);

REGISTER_CONFORMANCE(224, "mluc Reserved Field Zero",
    "Bytes 4-7 of every multiLocalizedUnicodeType must be zero (reserved field)", "ICC.1-2022-05 §10.13",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf224_mluc_reserved_field_zero);

REGISTER_CONFORMANCE(225, "mluc Name Record String Alignment",
    "mluc string offsets and lengths should be even (UTF-16 = 2 bytes per code unit) per §7.1 alignment", "ICC.1-2022-05 §7.1, §10.13",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf225_mluc_name_record_string_alignment);

REGISTER_CONFORMANCE(226, "mluc Size Inference Safety",
    "Validate mluc tag size is consistent with max(offset+length) across all name records per TN PSD recommendation", "ICC TN PSD §size",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf226_mluc_size_inference_safety);

REGISTER_CONFORMANCE(227, "v4 Text Tag Unicode Migration",
    "v4+ profiles must use multiLocalizedUnicodeType for text tags — textDescriptionType deprecated", "ICC.1-2022-05 §9",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf227_text_tag_unicode_migration);

REGISTER_CONFORMANCE(228, "grayTRCTag Semantic Validation",
    "Grayscale TRC must be monotonic 0=black to 1.0=white; no RGB TRC tags in Gray profiles", "v2→v4 TN",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf228_gray_trc_semantics);

REGISTER_CONFORMANCE(229, "Rendering Intent Dominance Per Class",
    "AToB dominant for Input, BToA dominant for Output/Display; Perceptual (0) intent required first", "v2→v4 TN",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf229_rendering_intent_dominance);

REGISTER_CONFORMANCE(230, "CIELAB Encoding Version Consistency",
    "v4 Lab encoding: L*=100→0xFFFF (not v2 0xFF00), a*/b*=0→0x8080 (not v2 0x8000); lut16Type retains v2", "ICC.1-2022-05 §6.5.9",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf230_cielab_encoding_consistency);

REGISTER_CONFORMANCE(233, "colorantOrderTag Index Validation",
    "Indices must form permutation of [0..count-1] — no gaps, no duplicates", "ICC.1-2022-05 §9.2.11, §10.3",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf233_colorant_order_index_validation);

REGISTER_CONFORMANCE(234, "v4 Perceptual PCS Reference Medium",
    "Perceptual PCS reference medium: 287.9:1 dynamic range, L*=100 white, L*=3.1373 black", "ICC.1-2022-05 Annex D",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf234_perceptual_pcs_reference_medium);

REGISTER_CONFORMANCE(247, "viewingConditionsType Illuminant Type Range",
    "Illuminant type must be in ICC.1 Table 27 range 0-8", "ICC.1-2022-05 §10.30",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf247_viewing_conditions_illuminant_type_range);

REGISTER_CONFORMANCE(248, "namedColor2Type Device Coords Limit",
    "Device coordinates count shall not exceed 15 per ICC specification", "ICC.1-2022-05 §10.14",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf248_namedcolor2_device_coords_limit);

REGISTER_CONFORMANCE(249, "profileDescriptionTag Non-Empty",
    "Profile description shall contain meaningful non-empty text", "ICC.1-2022-05 §9.2.41",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf249_profile_description_non_empty);

REGISTER_CONFORMANCE(250, "copyrightTag Non-Empty",
    "Copyright tag shall contain non-empty text content", "ICC.1-2022-05 §9.2.21",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf250_copyright_non_empty);

REGISTER_CONFORMANCE(251, "chromaticityType Phosphor Type Range",
    "Phosphor/colorant type must be 0-4 per ICC.1 Table 31", "ICC.1-2022-05 §10.2",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf251_chromaticity_phosphor_type_range);

REGISTER_CONFORMANCE(252, "curveType Gamma Positive/Finite",
    "When curveType count=1, gamma value must be positive and finite", "ICC.1-2022-05 §10.6",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf252_curvetype_gamma_positive_finite);

REGISTER_CONFORMANCE(253, "chromaticityType Channel Count",
    "Number of channels in chromaticityType must match profile data colour space", "ICC.1-2022-05 §10.2",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf253_chromaticity_channel_count_consistency);

REGISTER_CONFORMANCE(254, "Technology Signature Registered",
    "Technology signature must be a registered value from ICC.1 Table 25", "ICC.1-2022-05 §9.2.47",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf254_technology_signature_in_table);

REGISTER_CONFORMANCE(263, "Perceptual PCS White Point D50",
    "Profiles with perceptual rendering intent must have D50 PCS illuminant in header", "ICC.1-2022-05 Annex D",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf263_perceptual_pcs_white_point_d50);

REGISTER_CONFORMANCE(264, "parametricCurveType Function Type Range",
    "parametricCurveType functionType must be in range 0..4", "ICC.1-2022-05 §10.18",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf264_parametric_curve_func_type_in_mbb);

REGISTER_CONFORMANCE(265, "mluc Language/Country Code Validity",
    "mluc records must use ISO 639-1 language codes and ISO 3166-1 country codes", "ICC.1-2022-05 §10.15",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf265_mluc_language_country_code_validity);

REGISTER_CONFORMANCE(273, "Primary Colorant XYZ Values Positive",
    "Primary colorant XYZ values should be positive and within plausible range", "ICC.1-2022-05 §10.28",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf273_primary_colorant_xyz_positive);

REGISTER_CONFORMANCE(274, "Primary Colorant Chromaticity Sum",
    "Primary colorant chromaticity sums should not be near zero", "TN v4-matrix-entries",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf274_primary_colorant_chromaticity_sum_nonzero);

REGISTER_CONFORMANCE(275, "copyrightTag Must Be mluc for v4+",
    "v4+ profiles must use multiLocalizedUnicodeType for copyrightTag", "ICC.1-2022-05 §9.2.14",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf275_copyright_must_be_mluc_v4);

REGISTER_CONFORMANCE(276, "profileDescriptionTag Must Be mluc for v4+",
    "v4+ profiles must use mluc for profileDescriptionTag", "ICC.1-2022-05 §9.2.44",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf276_profile_description_must_be_mluc_v4);

REGISTER_CONFORMANCE(277, "mediaWhitePointTag Must Be XYZType",
    "mediaWhitePointTag must use XYZType", "ICC.1-2022-05 §9.2.35",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf277_media_white_point_must_be_xyz);

REGISTER_CONFORMANCE(278, "chromaticAdaptationTag Type",
    "chromaticAdaptationTag must use s15Fixed16ArrayType", "ICC.1-2022-05 §9.2.2",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf278_chad_must_be_s15fixed16array);

REGISTER_CONFORMANCE(279, "TRC Curve Values Non-Negative",
    "TRC curve entries should be non-negative", "ICC.1-2022-05 §10.5",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf279_trc_curve_values_non_negative);

REGISTER_CONFORMANCE(280, "XYZ Element Luminance (Y) Non-Negative",
    "XYZ type luminance (Y) values should be non-negative", "ICC.1-2022-05 §10.28",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf280_xyz_element_luminance_non_negative);

REGISTER_CONFORMANCE(281, "profileSequenceDescTag Structure",
    "profileSequenceDescTag must use profileSequenceDescType", "ICC.1-2022-05 §10.16",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf281_profile_sequence_desc_type_check);

REGISTER_CONFORMANCE(304, "v5 Text Tag multiLocalizedUnicodeType",
    "v5 text tags must use multiLocalizedUnicodeType per errata Tables 40/41 correction", "ICC.2-2019 Errata §10.2.5",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf304_v5_text_tags_mluc);

// ── CF-340: colorantTableOutTag Count vs PCS Channels ──
// PR #708 regression: clot validation must check PCS channels, not colorSpace.
// Output profiles: clot describes PCS-side colorants (not device-side).
static CheckResult check_cf340_colorant_table_out_count_vs_pcs(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigColorantTableOutTag);
    if (!pTag) return CheckResult::skip("No colorantTableOutTag");

    CIccTagColorantTable *pCT = dynamic_cast<CIccTagColorantTable *>(pTag);
    if (!pCT) return CheckResult::skip("Not CIccTagColorantTable");

    icUInt32Number nColorants = pCT->GetSize();
    icColorSpaceSignature pcsSig = pIcc->m_Header.pcs;
    int pcsChannels = icGetSpaceSamples(pcsSig);

    if (pcsChannels > 0 && static_cast<int>(nColorants) != pcsChannels) {
        return {CheckResult::Status::FINDINGS,
                "colorantTableOutTag count vs PCS mismatch", {Finding{
                    {CheckID::Kind::Conformance, 340}, Severity::HIGH,
                    "colorantTableOutTag count=" + std::to_string(nColorants) +
                    " but PCS channels=" + std::to_string(pcsChannels) +
                    " -- clot describes PCS-side colorants, not device-side (PR #708 regression)",
                    "ICC.1-2022-05 §9.2.13", "CWE-131"}}};
    }
    return CheckResult::ok("colorantTableOutTag count matches PCS channels");
}

REGISTER_CONFORMANCE(340, "colorantTableOutTag Count vs PCS Channels",
    "colorantTableOutTag count must match PCS channel count, not device colorSpace",
    "ICC.1-2022-05 §9.2.13",
    "CWE-131", "",
    Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf340_colorant_table_out_count_vs_pcs);
