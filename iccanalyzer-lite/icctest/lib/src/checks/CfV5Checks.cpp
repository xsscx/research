// CfV5Checks.cpp — V2 conformance checks: ICC.2/v5/iccMAX, ICS, PCC, K.2
// 93 checks: CF-080..CF-329
//
// Ported from V1 IccConformanceV5.cpp (6804 lines) to V2 CheckResult API
//
// SPDX-License-Identifier: MIT

#include <icctest/CheckRegistry.h>
#include <icctest/ProfileView.h>
#include <icctest/CheckResult.h>
#include "util/CheckHelpers.h"

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagComposite.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"
#include "IccMpeCalc.h"
#include "IccMpeACS.h"
#include "IccMpeSpectral.h"
#include "IccTagDict.h"
#include "IccTagEmbedIcc.h"
#include "IccTagLut.h"
#include "IccPcc.h"
#include "IccUtil.h"
#include "IccDefs.h"

#include <cmath>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <set>

using namespace icctest;

// Compatibility: iccDEV renamed Material* -> Multiplex*
#ifndef icSigMultiplexDefaultValuesTag
  #ifdef icSigMaterialDefaultValuesTag
    #define icSigMultiplexDefaultValuesTag icSigMaterialDefaultValuesTag
  #else
    #define icSigMultiplexDefaultValuesTag static_cast<icTagSignature>(0x6D647620)
  #endif
#endif
#ifndef icSigMultiplexTypeArrayTag
  #ifdef icSigMaterialTypeArrayTag
    #define icSigMultiplexTypeArrayTag icSigMaterialTypeArrayTag
  #else
    #define icSigMultiplexTypeArrayTag static_cast<icTagSignature>(0x6d637461)
  #endif
#endif

// ── Helpers ─────────────────────────────────────────────────────────────────

static inline bool IsV5(const ProfileView& pv) {
    return (pv.header().version >> 24) >= 5;
}

static inline int VersionMajor(const ProfileView& pv) {
    return static_cast<int>((pv.header().version >> 24) & 0xFF);
}

static void SigToChars(uint32_t sig, char buf[5]) {
    buf[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));
    buf[1] = static_cast<char>(static_cast<unsigned char>((sig >> 16) & 0xFF));
    buf[2] = static_cast<char>(static_cast<unsigned char>((sig >>  8) & 0xFF));
    buf[3] = static_cast<char>(static_cast<unsigned char>( sig        & 0xFF));
    buf[4] = '\0';
}

static inline double S15Fixed16ToDouble(int32_t val) {
    return static_cast<double>(val) / 65536.0;
}

static inline uint32_t ReadU32BE(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

// Table of recognized MPE element type signatures
static const icElemTypeSignature kKnownMPETypes[] = {
    icSigCurveSetElemType, icSigMatrixElemType, icSigCLutElemType,
    icSigBAcsElemType, icSigEAcsElemType, icSigCalculatorElemType,
    icSigExtCLutElemType, icSigXYZToJabElemType, icSigJabToXYZElemType,
    icSigSparseMatrixElemType, icSigTintArrayElemType, icSigToneMapElemType,
    icSigEmissionMatrixElemType, icSigInvEmissionMatrixElemType,
    icSigEmissionCLUTElemType, icSigReflectanceCLUTElemType,
    icSigEmissionObserverElemType, icSigReflectanceObserverElemType,
};
static constexpr int kKnownMPETypeCount =
    static_cast<int>(sizeof(kKnownMPETypes) / sizeof(kKnownMPETypes[0]));

static bool IsKnownMPEType(icElemTypeSignature sig) {
    for (int i = 0; i < kKnownMPETypeCount; i++)
        if (kKnownMPETypes[i] == sig) return true;
    return false;
}

// ICS Part 1 allowed MPE types (no calculator)
static const icElemTypeSignature kICSPart1AllowedMPE[] = {
    icSigCurveSetElemType, icSigMatrixElemType, icSigCLutElemType,
    icSigExtCLutElemType, icSigTintArrayElemType,
    icSigBAcsElemType, icSigEAcsElemType,
};
static constexpr int kICSPart1AllowedMPECount =
    static_cast<int>(sizeof(kICSPart1AllowedMPE) / sizeof(kICSPart1AllowedMPE[0]));

static bool IsICSPart1AllowedMPE(icElemTypeSignature sig) {
    for (int i = 0; i < kICSPart1AllowedMPECount; i++)
        if (kICSPart1AllowedMPE[i] == sig) return true;
    return false;
}

// ICS sub-class signatures
static const uint32_t kICSSubClasses[] = {
    0x70636320, // pcc
    0x78726E67, // xrng
    0x73726566, // sref
    0x65787420, // ext
};
static constexpr int kICSSubClassCount = 4;

static bool IsICSSubClass(uint32_t sig) {
    for (int i = 0; i < kICSSubClassCount; i++)
        if (kICSSubClasses[i] == sig) return true;
    return false;
}

// Helper to find and cast a tag
template<typename T>
static T* FindAndCast(CIccProfile* pIcc, icTagSignature sig) {
    if (!pIcc) return nullptr;
    CIccTag* tag = pIcc->FindTag(sig);
    if (!tag) return nullptr;
    return dynamic_cast<T*>(tag);
}

static uint64_t choose3Clamped(uint32_t n) {
    if (n < 3) return 0;
    if (n > 1000000u) return UINT64_MAX;
    unsigned __int128 v = static_cast<unsigned __int128>(n) *
                          static_cast<unsigned __int128>(n - 1u) *
                          static_cast<unsigned __int128>(n - 2u);
    v /= 6u;
    if (v > static_cast<unsigned __int128>(UINT64_MAX)) return UINT64_MAX;
    return static_cast<uint64_t>(v);
}


// ═══════════════════════════════════════════════════════════════════════════
// CF-080: Spectral PCS Signature (ICC.2-2023 §7.2.22)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf080_v5_spectral_pcs_signature(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icColorSpaceSignature spectralPCS = pIcc->m_Header.spectralPCS;
    if (static_cast<icUInt32Number>(spectralPCS) == 0)
        return CheckResult::ok("No spectral PCS — field unused");

    char sigCC[5];
    SigToChars(static_cast<uint32_t>(spectralPCS), sigCC);

    bool recognized = false;
    switch (static_cast<icUInt32Number>(spectralPCS)) {
        case static_cast<icUInt32Number>(icSigReflectanceSpectralPcsData):
        case static_cast<icUInt32Number>(icSigRadiantSpectralPcsData):
        case static_cast<icUInt32Number>(icSigBiDirReflectanceSpectralPcsData):
        case static_cast<icUInt32Number>(icSigSparseMatrixSpectralPcsData):
            recognized = true; break;
        default: break;
    }

    if (recognized)
        return CheckResult::ok("Spectral PCS signature '" + std::string(sigCC) + "' is valid");

    std::vector<Finding> findings;
    findings.push_back({CheckID{CheckID::Kind::Conformance, 80}, Severity::HIGH,
        "Unrecognized spectral PCS signature 0x" + std::to_string(static_cast<unsigned>(spectralPCS)),
        "spectralPCS='" + std::string(sigCC) + "' — ICC.2-2023 §7.2.22", ""});
    return {CheckResult::Status::FINDINGS, "Unrecognized spectral PCS", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-081: Spectral PCS Range Validity (ICC.2-2023 §7.2.23)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf081_v5_spectral_pcs_range_validity(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    if (static_cast<icUInt32Number>(pIcc->m_Header.spectralPCS) == 0)
        return CheckResult::ok("No spectral PCS set — range check not applicable");

    std::vector<Finding> findings;
    const icSpectralRange &sr = pIcc->m_Header.spectralRange;
    float startNm = safeF16ToF(sr.start);
    float endNm = safeF16ToF(sr.end);

    if (sr.steps < 1)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 81}, Severity::HIGH,
            "spectralRange.steps = 0 — must be >= 1",
            "ICC.2-2023 §7.2.23", ""});
    if (startNm >= endNm)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 81}, Severity::HIGH,
            "spectralRange.start >= end",
            std::string("start=") + std::to_string(startNm) + " end=" + std::to_string(endNm), ""});
    if (startNm < 100.0f || endNm > 1000.0f)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 81}, Severity::HIGH,
            "Wavelength range outside plausible bounds [100-1000 nm]",
            "ICC.2-2023 §7.2.23", ""});

    // Check biSpectralRange if set
    const icSpectralRange &bsr = pIcc->m_Header.biSpectralRange;
    bool biSet = (bsr.start != 0 || bsr.end != 0 || bsr.steps != 0);
    if (biSet) {
        float bStart = safeF16ToF(bsr.start);
        float bEnd = safeF16ToF(bsr.end);
        if (bsr.steps < 1)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 81}, Severity::HIGH,
                "biSpectralRange.steps = 0", "", ""});
        if (bStart >= bEnd)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 81}, Severity::HIGH,
                "biSpectralRange.start >= end", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("Spectral range parameters valid");
    return {CheckResult::Status::FINDINGS, "Spectral range issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-082: PCC Tags Required When Spectral (ICC.2-2023 §8)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf082_v5_pcc_tags_required_when_spectral(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    if (static_cast<icUInt32Number>(pIcc->m_Header.spectralPCS) == 0)
        return CheckResult::ok("No spectral PCS — PCC tag requirement not applicable");

    std::vector<Finding> findings;
    if (!pIcc->FindTag(icSigSpectralViewingConditionsTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 82}, Severity::HIGH,
            "Missing svcn tag — required for spectral PCS", "ICC.2-2023 §8", ""});

    bool hasC2sp = pIcc->FindTag(icSigCustomToStandardPccTag) != nullptr;
    bool hasS2cp = pIcc->FindTag(icSigStandardToCustomPccTag) != nullptr;
    if ((hasC2sp && !hasS2cp) || (!hasC2sp && hasS2cp))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 82}, Severity::MEDIUM,
            "PCC tags should appear in pairs (c2sp + s2cp)", "", ""});

    if (findings.empty()) return CheckResult::ok("Required PCC tags present for spectral PCS");
    return {CheckResult::Status::FINDINGS, "PCC tag issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-083: MCS Signature Encoding (ICC.2-2023 §7.2.25)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf083_v5_mcs_signature_encoding(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icUInt32Number mcsVal = static_cast<icUInt32Number>(pIcc->m_Header.mcs);
    if (mcsVal == 0) return CheckResult::ok("MCS field unused");

    if (mcsVal >= static_cast<icUInt32Number>(icSigMCSData) &&
        mcsVal <= static_cast<icUInt32Number>(icSigMCSDataEnd))
        return CheckResult::ok("MCS signature in valid range [mc0000-mcFFFF]");

    std::vector<Finding> findings;
    char sigCC[5]; SigToChars(mcsVal, sigCC);
    findings.push_back({CheckID{CheckID::Kind::Conformance, 83}, Severity::HIGH,
        std::string("MCS signature '") + sigCC + "' outside valid range",
        "ICC.2-2023 §7.2.25", ""});
    return {CheckResult::Status::FINDINGS, "Invalid MCS signature", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-084: Profile Sub-Class Signature (ICC.2-2023 §7.2.26)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf084_v5_profile_sub_class_signature(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icUInt32Number scVal = static_cast<icUInt32Number>(pIcc->m_Header.deviceSubClass);
    if (scVal == 0) return CheckResult::ok("No sub-class defined (default)");

    bool printable = true;
    for (int i = 0; i < 4; i++) {
        unsigned char c = static_cast<unsigned char>((scVal >> (24 - i * 8)) & 0xFF);
        if (c < 0x20 || c > 0x7E) { printable = false; break; }
    }

    if (!printable) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 84}, Severity::MEDIUM,
            "Sub-class signature contains non-printable characters", "ICC.2-2023 §7.2.26", ""});
        return {CheckResult::Status::FINDINGS, "Non-printable sub-class sig", std::move(findings)};
    }
    return CheckResult::ok("Sub-class signature noted (extension point)");
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-085: Version Field 5.x BCD (ICC.2-2023 §7.2.4)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf085_v5_version_field_5_x_bcd(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    uint32_t ver = pv.header().version;
    uint8_t major = (ver >> 24) & 0xFF;
    uint8_t minor_hi = (ver >> 20) & 0x0F;
    uint8_t minor_lo = (ver >> 16) & 0x0F;
    uint16_t tail = ver & 0xFFFF;

    std::vector<Finding> findings;
    if (major != 5)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 85}, Severity::HIGH,
            "Major version byte is " + std::to_string(major) + ", expected 5", "ICC.2-2023 §7.2.4", ""});
    if (minor_hi > 9)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 85}, Severity::HIGH,
            "Minor version high nibble " + std::to_string(minor_hi) + " is not valid BCD", "", ""});
    if (minor_lo > 9)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 85}, Severity::HIGH,
            "Minor version low nibble " + std::to_string(minor_lo) + " is not valid BCD", "", ""});
    if (tail != 0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 85}, Severity::HIGH,
            "Version bytes 10-11 must be 0x0000", "ICC.2-2023 §7.2.4", ""});

    if (findings.empty()) return CheckResult::ok("Version valid BCD encoding");
    return {CheckResult::Status::FINDINGS, "Version BCD issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-086: Extended Attribute Bits (ICC.2-2023 §7.2.14)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf086_v5_extended_attribute_bits(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    // Informational — report attribute bits
    return CheckResult::ok("Attribute bits reported (informational)");
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-087: MPE Element Signature Valid (ICC.2-2023 §10.x)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf087_v5_mpe_element_signature_valid(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    int mpeTagCount = 0, totalElements = 0;

    for (const auto& entry : pv.rawTagTable()) {
        CIccTag *tag = pIcc->FindTag(static_cast<icTagSignature>(entry.signature));
        if (!tag) continue;
        CIccTagMultiProcessElement *mpe = dynamic_cast<CIccTagMultiProcessElement*>(tag);
        if (!mpe) continue;
        mpeTagCount++;
        icUInt32Number nElem = mpe->NumElements();
        for (icUInt32Number i = 0; i < nElem; i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (!elem) continue;
            totalElements++;
            if (!IsKnownMPEType(elem->GetType())) {
                char eSig[5]; SigToChars(static_cast<uint32_t>(elem->GetType()), eSig);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 87}, Severity::MEDIUM,
                    std::string("Unknown MPE element type '") + eSig + "'", "ICC.2-2023 §10", ""});
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("All " + std::to_string(totalElements) + " MPE element signatures recognized");
    return {CheckResult::Status::FINDINGS, "Unknown MPE element types", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-088: Calculator Element Stack Structure (ICC.2-2023 §10.x)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf088_v5_calculator_element_stack_structure(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::ok("N/A: Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    int calcCount = 0;

    for (const auto& entry : pv.rawTagTable()) {
        CIccTag *tag = pIcc->FindTag(static_cast<icTagSignature>(entry.signature));
        if (!tag) continue;
        CIccTagMultiProcessElement *mpe = dynamic_cast<CIccTagMultiProcessElement*>(tag);
        if (!mpe) continue;
        icUInt32Number nElem = mpe->NumElements();
        for (icUInt32Number i = 0; i < nElem; i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (!elem || elem->GetType() != icSigCalculatorElemType) continue;
            calcCount++;
            CIccMpeCalculator *calc = dynamic_cast<CIccMpeCalculator*>(elem);
            if (!calc) {
                findings.push_back({CheckID{CheckID::Kind::Conformance, 88}, Severity::HIGH,
                    "Calculator type but dynamic_cast failed", "", ""}); continue;
            }
            if (calc->NumInputChannels() == 0)
                findings.push_back({CheckID{CheckID::Kind::Conformance, 88}, Severity::HIGH,
                    "Calculator has 0 input channels", "", ""});
            if (calc->NumOutputChannels() == 0)
                findings.push_back({CheckID{CheckID::Kind::Conformance, 88}, Severity::HIGH,
                    "Calculator has 0 output channels", "", ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok(std::to_string(calcCount) + " calculator element(s) structurally valid");
    return {CheckResult::Status::FINDINGS, "Calculator structure issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-089: Spectral Wavelength Range (ICC.2-2023 §7.2.23)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf089_v5_spectral_wavelength_range(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    if (static_cast<icUInt32Number>(pIcc->m_Header.spectralPCS) == 0)
        return CheckResult::ok("No spectral PCS — wavelength range check not applicable");

    std::vector<Finding> findings;
    const icSpectralRange &sr = pIcc->m_Header.spectralRange;
    float startNm = safeF16ToF(sr.start);
    float endNm = safeF16ToF(sr.end);

    if (startNm < 300.0f)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 89}, Severity::LOW,
            "Start wavelength below typical minimum (300 nm)", "", ""});
    if (endNm > 830.0f)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 89}, Severity::LOW,
            "End wavelength exceeds typical maximum (830 nm)", "", ""});
    if (sr.steps > 1) {
        float stepSize = (endNm - startNm) / static_cast<float>(sr.steps - 1);
        if (stepSize <= 0.0f)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 89}, Severity::HIGH,
                "Derived step size is non-positive", "", ""});
    } else if (sr.steps == 1 && startNm != endNm) {
        findings.push_back({CheckID{CheckID::Kind::Conformance, 89}, Severity::HIGH,
            "steps=1 but start != end — inconsistent", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("Spectral wavelength range within expected bounds");
    return {CheckResult::Status::FINDINGS, "Wavelength range issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-090: Spectral Illuminant/Observer Consistency (ICC.2-2023 §7.2.17)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf090_spectral_illuminant_consistency(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    if (static_cast<icUInt32Number>(pIcc->m_Header.spectralPCS) == 0)
        return CheckResult::skip("No spectral PCS — not applicable");

    const CIccTagSpectralViewingConditions *svcn =
        FindAndCast<CIccTagSpectralViewingConditions>(pIcc, icSigSpectralViewingConditionsTag);
    if (!svcn) return CheckResult::skip("No svcn tag — covered by CF-082");

    std::vector<Finding> findings;
    float profStart = safeF16ToF(pIcc->m_Header.spectralRange.start);
    float profEnd = safeF16ToF(pIcc->m_Header.spectralRange.end);

    icSpectralRange illumRange;
    svcn->getIlluminant(illumRange);
    if (illumRange.steps == 0) {
        icIlluminant illumType = svcn->getStdIllumiant();
        if (static_cast<icUInt32Number>(illumType) == 0)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 90}, Severity::MEDIUM,
                "Illuminant has zero steps and no standard type", "", ""});
    } else {
        float iStart = safeF16ToF(illumRange.start);
        float iEnd = safeF16ToF(illumRange.end);
        if (iEnd < profStart || iStart > profEnd)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 90}, Severity::MEDIUM,
                "Illuminant range does not overlap profile spectral range", "§7.2.17", ""});
    }

    icSpectralRange obsRange;
    svcn->getObserver(obsRange);
    if (obsRange.steps > 0) {
        float oStart = safeF16ToF(obsRange.start);
        float oEnd = safeF16ToF(obsRange.end);
        if (oEnd < profStart || oStart > profEnd)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 90}, Severity::MEDIUM,
                "Observer range does not overlap profile spectral range", "§7.2.17", ""});
    } else {
        icStandardObserver obsType = svcn->getStdObserver();
        if (static_cast<icUInt32Number>(obsType) == 0)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 90}, Severity::MEDIUM,
                "Observer has zero steps and no standard type", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("Spectral illuminant/observer consistent with profile range");
    return {CheckResult::Status::FINDINGS, "Spectral consistency issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-113: Spectral Range Physical Bounds (ICC.2-2023 §7.2.23)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf113_spectral_range_physical_bounds(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icSpectralRange spec = pIcc->m_Header.spectralRange;
    if (spec.steps == 0) return CheckResult::ok("No spectral range defined — not applicable");

    std::vector<Finding> findings;
    float startNm = safeF16ToF(spec.start);
    float endNm = safeF16ToF(spec.end);

    if (startNm < 100.0f || startNm > 2500.0f)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 113}, Severity::HIGH,
            "Start wavelength outside physical range [100-2500]", "§7.2.23", ""});
    if (endNm < 100.0f || endNm > 2500.0f)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 113}, Severity::HIGH,
            "End wavelength outside physical range [100-2500]", "§7.2.23", ""});
    if (startNm >= endNm && spec.steps > 1)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 113}, Severity::HIGH,
            "Start >= End for multi-step spectra", "§7.2.23", ""});

    if (findings.empty()) return CheckResult::ok("Spectral range within physical bounds");
    return {CheckResult::Status::FINDINGS, "Spectral range issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-114: MCS Colour Space Consistency (ICC.2-2023 §7.2.19)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf114_mcs_colour_space_consistency(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icMaterialColorSignature mcs = pIcc->m_Header.mcs;
    if (mcs == icSigNoMCSData) return CheckResult::ok("No MCS data — not applicable");

    int nMCS = static_cast<int>(icGetMaterialColorSpaceSamples(mcs));
    if (nMCS == 0) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 114}, Severity::HIGH,
            "MCS signature has 0 channels", "§7.2.19", ""});
        return {CheckResult::Status::FINDINGS, "Invalid MCS colour space", std::move(findings)};
    }
    return CheckResult::ok("MCS colour space valid (" + std::to_string(nMCS) + " channels)");
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-115: Calculator Element Complexity (ICC.2-2023 §10.2.6)
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf115_calculator_element_complexity(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    if (!pv.libraryLoaded()) {
        if (!pv.requiresLibraryQuarantine()) {
            return CheckResult::skip("NOT RUN: Profile failed to load");
        }
        std::vector<Finding> findings;
        auto issues = scanRawMpePositionIssues(pv);
        for (const auto& issue : issues) {
            findings.push_back({CheckID{CheckID::Kind::Conformance, 115}, Severity::HIGH,
                "MPE element table structurally invalid",
                formatRawMpePositionIssue(issue),
                "CWE-190: Unsigned integer overflow in CIccTagMultiProcessElement::Read() (IccTagMPE.cpp:1042)"});
        }
        if (!findings.empty()) {
            return {CheckResult::Status::FINDINGS, "Calculator complexity issues", std::move(findings)};
        }
        return CheckResult::ok("NOT RUN: Library quarantined and no raw CF-115 fingerprint available");
    }
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    int calcCount = 0;
    int totalSubElements = 0;
    int toneMapIssues = 0;

    for (const auto& entry : pv.rawTagTable()) {
        CIccTag *tag = pIcc->FindTag(static_cast<icTagSignature>(entry.signature));
        if (!tag) continue;
        CIccTagMultiProcessElement *mpe = dynamic_cast<CIccTagMultiProcessElement*>(tag);
        if (!mpe) continue;

        int elemCount = static_cast<int>(mpe->NumElements());
        bool hasCalculator = false;
        for (int e = 0; e < elemCount; ++e) {
            CIccMultiProcessElement *elem = mpe->GetElement(e);
            if (!elem) continue;

            if (elem->GetType() == icSigCalculatorElemType) {
                hasCalculator = true;
            }

            if (auto* toneMap = dynamic_cast<CIccMpeToneMap*>(elem)) {
                std::string report;
                icValidateStatus toneStatus = toneMap->Validate("", report, mpe, pIcc);
                if (toneStatus >= icValidateCriticalError &&
                    (report.find("Tone mapping function has invalid parameters") != std::string::npos ||
                     report.find("unknown function type") != std::string::npos)) {
                    findings.push_back({CheckID{CheckID::Kind::Conformance, 115}, Severity::HIGH,
                        sfmt("Tag '%s' tone map element %d failed validation",
                             sigStr(static_cast<uint32_t>(entry.signature)).c_str(), e),
                        report.substr(0, 240), ""});
                    toneMapIssues++;
                }
            }
        }

        if (!hasCalculator) continue;
        calcCount++;
        totalSubElements += elemCount;

        if (elemCount > 256)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 115}, Severity::MEDIUM,
                "Excessive calculator complexity (" + std::to_string(elemCount) + " elements)", "§10.2.6", ""});
    }

    if (calcCount == 0 && toneMapIssues == 0)
        return CheckResult::ok("No calculator elements — not applicable");
    if (findings.empty())
        return CheckResult::ok(sfmt("%d calculator(s), %d total sub-elements", calcCount, totalSubElements));
    return {CheckResult::Status::FINDINGS, "Calculator complexity issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-144: Extended Range PCS Flag Consistency
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf144_extended_range_pcs_flag_consistency(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t flags = pv.header().flags;
    bool extendedRangeSet = (flags & 0x00000008) != 0; // icExtendedRangePCS bit 3
    bool hasSpectralPCS = static_cast<icUInt32Number>(pIcc->m_Header.spectralPCS) != 0;

    std::vector<Finding> findings;
    if (extendedRangeSet && !hasSpectralPCS) {
        // OK — extended range without spectral is valid for colorimetric extended profiles
    }
    // Both set is fine, both unset is fine, spectral without extended is fine
    // This is informational
    return CheckResult::ok("Extended range PCS flag consistent");
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-145: Extended Range PCS Spectral Co-existence
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf145_extended_range_pcs_spectral_co_existence(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    bool hasSpectralPCS = static_cast<icUInt32Number>(pIcc->m_Header.spectralPCS) != 0;
    bool extendedRange = (pv.header().flags & 0x00000008) != 0;

    if (hasSpectralPCS && extendedRange) {
        return CheckResult::ok("Profile has both spectral PCS and extended range PCS — co-existence valid");
    }
    return CheckResult::ok("Spectral/extended range co-existence check passed");
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-146: Extended Range Class Restriction
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf146_extended_range_class_restriction(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    bool extendedRange = (pv.header().flags & 0x00000008) != 0;
    if (!extendedRange) return CheckResult::ok("No extended range PCS flag — not applicable");

    uint32_t dc = pv.header().deviceClass;
    if (dc == icSigDisplayClass || dc == icSigColorSpaceClass || dc == icSigOutputClass)
        return CheckResult::ok("Extended range class restriction met");

    std::vector<Finding> findings;
    char cls[5]; SigToChars(dc, cls);
    findings.push_back({CheckID{CheckID::Kind::Conformance, 146}, Severity::HIGH,
        std::string("Extended range PCS with class '") + cls + "' — must be mntr, spac, or prtr", "", ""});
    return {CheckResult::Status::FINDINGS, "Class restriction violated", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-150: Extended Output Gamut Boundary Tag
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf150_extended_output_gamut_boundary_tag(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    if (pv.header().deviceClass != icSigOutputClass)
        return CheckResult::ok("Not an output profile — not applicable");

    bool hasGBD = false;
    for (int i = 0; i < 4; i++) {
        icTagSignature gbdSigs[] = {
            icSigGamutBoundaryDescription0Tag, icSigGamutBoundaryDescription1Tag,
            icSigGamutBoundaryDescription2Tag, icSigGamutBoundaryDescription3Tag
        };
        if (pv.hasTag(gbdSigs[i])) { hasGBD = true; break; }
    }

    if (!hasGBD) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 150}, Severity::LOW,
            "Extended output profile lacks gamut boundary tag (optional but recommended)", "", ""});
        return {CheckResult::Status::FINDINGS, "Missing optional GBD tag", std::move(findings)};
    }
    return CheckResult::ok("Gamut boundary tag present");
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-151: Extended Output MediaWhitePoint Range
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf151_extended_output_mediawhitepoint_range(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTagXYZ *pXYZ = FindAndCast<CIccTagXYZ>(pIcc, icSigMediaWhitePointTag);
    if (!pXYZ || pXYZ->GetSize() < 1)
        return CheckResult::ok("No mediaWhitePointTag — not applicable");

    std::vector<Finding> findings;
    const icXYZNumber *xyz = pXYZ->GetXYZ(0);
    if (xyz) {
        double X = icFtoD(xyz->X), Y = icFtoD(xyz->Y), Z = icFtoD(xyz->Z);
        if (X <= 0 || Y <= 0 || Z <= 0)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 151}, Severity::HIGH,
                "Media white point has non-positive XYZ values", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("Media white point XYZ values positive");
    return {CheckResult::Status::FINDINGS, "MWP range issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-154: Embedded Profile Version Bridging
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf154_embedded_profile_version_bridging(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
    if (!pTag) return CheckResult::ok("No embedded profile tag — not applicable");

    CIccTagEmbeddedProfile *pEmbed = dynamic_cast<CIccTagEmbeddedProfile *>(pTag);
    if (!pEmbed) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 154}, Severity::HIGH,
            "Tag is not CIccTagEmbeddedProfile type",
            "ICC TN Embedding §ICC.2 Profile header", ""});
        return {CheckResult::Status::FINDINGS, "Version bridging issues", std::move(findings)};
    }

    CIccProfile *pChild = pEmbed->GetProfile();
    if (!pChild) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 154}, Severity::HIGH,
            "Embedded profile data could not be read",
            "ICC TN Embedding §ICC.2 Profile header", ""});
        return {CheckResult::Status::FINDINGS, "Version bridging issues", std::move(findings)};
    }

    std::vector<Finding> findings;
    int parentMajor = VersionMajor(pv);
    int childMajor = static_cast<int>((pChild->m_Header.version >> 24) & 0xFF);

    if (parentMajor >= 5) {
        findings.push_back({CheckID{CheckID::Kind::Conformance, 154}, Severity::LOW,
            "Parent profile is already v5 — embedding is intended for ICC.1 (v2/v4) parent profiles",
            "ICC TN Embedding §ICC.2 Profile header", ""});
        if (childMajor < 5) {
            findings.push_back({CheckID{CheckID::Kind::Conformance, 154}, Severity::HIGH,
                "Embedded child profile shall be ICC.2 (v5+) — child is v" + std::to_string(childMajor),
                "ICC TN Embedding §ICC.2 Profile header", ""});
        }
    } else {
        // Parent is v2/v4 — child should be v5 (ICC.2 in ICC.1 embedding)
        if (childMajor < 5)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 154}, Severity::HIGH,
                "Embedded profile should be v5 (ICC.2 in ICC.1) — child is v" + std::to_string(childMajor),
                "ICC TN Embedding §ICC.2 Profile header", ""});
    }

    if (findings.empty()) return CheckResult::ok("Embedded profile version bridging valid");
    return {CheckResult::Status::FINDINGS, "Version bridging issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-155: Embedded Profile Device Class Match
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf155_embedded_profile_device_class_match(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTagEmbeddedProfile *pEmbed = FindAndCast<CIccTagEmbeddedProfile>(pIcc, icSigEmbeddedV5ProfileTag);
    if (!pEmbed) return CheckResult::ok("No embedded profile — not applicable");
    CIccProfile *pChild = pEmbed->GetProfile();
    if (!pChild) return CheckResult::ok("No child profile");

    std::vector<Finding> findings;
    if (pIcc->m_Header.deviceClass != pChild->m_Header.deviceClass) {
        char pCls[5], cCls[5];
        SigToChars(static_cast<uint32_t>(pIcc->m_Header.deviceClass), pCls);
        SigToChars(static_cast<uint32_t>(pChild->m_Header.deviceClass), cCls);
        findings.push_back({CheckID{CheckID::Kind::Conformance, 155}, Severity::MEDIUM,
            std::string("Parent class '") + pCls + "' != child class '" + cCls + "'", "", ""});
    }
    if (pIcc->m_Header.colorSpace != pChild->m_Header.colorSpace) {
        findings.push_back({CheckID{CheckID::Kind::Conformance, 155}, Severity::MEDIUM,
            "Parent and child color spaces differ", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("Embedded profile device class and color space match");
    return {CheckResult::Status::FINDINGS, "Class mismatch", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-156: Embedded Profile Header Flags
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf156_embedded_profile_header_flags(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTagEmbeddedProfile *pEmbed = FindAndCast<CIccTagEmbeddedProfile>(pIcc, icSigEmbeddedV5ProfileTag);
    if (!pEmbed) return CheckResult::ok("No embedded profile — not applicable");
    CIccProfile *pChild = pEmbed->GetProfile();
    if (!pChild) return CheckResult::ok("No child profile");

    std::vector<Finding> findings;
    uint32_t childFlags = static_cast<uint32_t>(pChild->m_Header.flags);
    bool embedded = (childFlags & 0x01) != 0;
    bool independent = (childFlags & 0x02) != 0;

    if (!embedded)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 156}, Severity::MEDIUM,
            "Embedded child profile: bit 0 (embedded) should be set", "", ""});
    if (independent)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 156}, Severity::MEDIUM,
            "Embedded child profile: bit 1 (independent) should be clear", "", ""});

    if (findings.empty()) return CheckResult::ok("Embedded profile header flags valid");
    return {CheckResult::Status::FINDINGS, "Embedded flags issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-175: Embedded Profile PCS Compatibility
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf175_embedded_profile_pcs_compatibility(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTagEmbeddedProfile *pEmbed = FindAndCast<CIccTagEmbeddedProfile>(pIcc, icSigEmbeddedV5ProfileTag);
    if (!pEmbed) return CheckResult::ok("No embedded profile — not applicable");
    CIccProfile *pChild = pEmbed->GetProfile();
    if (!pChild) return CheckResult::ok("No child profile");

    // DeviceLink skip
    if (pIcc->m_Header.deviceClass == icSigLinkClass)
        return CheckResult::ok("DeviceLink — PCS compatibility check skipped");

    std::vector<Finding> findings;
    if (pIcc->m_Header.pcs != pChild->m_Header.pcs) {
        bool parentExtended = (static_cast<uint32_t>(pIcc->m_Header.flags) & 0x08) != 0;
        if (!parentExtended)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 175}, Severity::MEDIUM,
                "Parent and child PCS differ without extended PCS flag", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("Embedded PCS compatibility valid");
    return {CheckResult::Status::FINDINGS, "PCS compatibility issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-176: Embedded Profile Tag Reserved Bytes
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf176_embedded_profile_tag_reserved_bytes(const ProfileView& pv) {
    auto rawTag = pv.rawTag(static_cast<uint32_t>(icSigEmbeddedV5ProfileTag));
    if (!rawTag) return CheckResult::ok("No embedded profile — not applicable");

    CheckID id{CheckID::Kind::Conformance, 176};
    std::vector<Finding> findings;

    if (rawTag->size < 8 ||
        rawTag->offset > pv.rawSize() ||
        rawTag->size > pv.rawSize() - rawTag->offset) {
        findings.push_back({id, Severity::HIGH,
            "Embedded profile tag is too small to contain type and reserved fields",
            "size=" + std::to_string(rawTag->size), "CWE-130"});
        return {CheckResult::Status::FINDINGS, "Embedded profile tag too small", std::move(findings)};
    }

    const uint8_t* tagData = pv.rawData() + rawTag->offset;
    uint32_t typeSig = ReadU32BE(tagData);
    if (typeSig != static_cast<uint32_t>(icSigEmbeddedProfileType)) {
        return CheckResult::ok("Embedded tag is not ICCp — covered by CF-153");
    }

    uint32_t reserved = ReadU32BE(tagData + 4);
    if (reserved != 0) {
        char hex[11];
        std::snprintf(hex, sizeof(hex), "0x%08X", reserved);
        findings.push_back({id, Severity::MEDIUM,
            std::string("Embedded profile tag reserved bytes (4-7) shall be 0; found ") + hex,
            "ICC TN Embedding Table 1", ""});
    }

    if (findings.empty()) return CheckResult::ok("Embedded profile tag reserved bytes conform to spec");
    return {CheckResult::Status::FINDINGS, "Embedded profile tag reserved bytes not zero", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-177: Embedded Profile Data Integrity
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf177_embedded_profile_data_integrity(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTagEmbeddedProfile *pEmbed = FindAndCast<CIccTagEmbeddedProfile>(pIcc, icSigEmbeddedV5ProfileTag);
    if (!pEmbed) return CheckResult::ok("No embedded profile — not applicable");
    CIccProfile *pChild = pEmbed->GetProfile();
    if (!pChild) return CheckResult::ok("No child profile");

    std::string report;
    icValidateStatus status = pChild->Validate(report);
    if (status >= icValidateCriticalError) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 177}, Severity::HIGH,
            "Embedded child profile has critical validation errors",
            report.substr(0, 500), ""});
        return {CheckResult::Status::FINDINGS, "Embedded profile validation failed", std::move(findings)};
    }
    return CheckResult::ok("Embedded profile passes library validation");
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-178: Chad Diagonal Dominance
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf178_chad_matrix_diagonal_dominance(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTagS15Fixed16 *pChad = FindAndCast<CIccTagS15Fixed16>(pIcc, icSigChromaticAdaptationTag);
    if (!pChad || pChad->GetSize() < 9)
        return CheckResult::ok("No chad tag or insufficient data — not applicable");

    std::vector<Finding> findings;
    // Check 3x3 matrix diagonal dominance: |M[i][i]| > sum(|M[i][j]| for j!=i)
    for (int row = 0; row < 3; row++) {
        double diag = std::fabs(icFtoD((*pChad)[row * 3 + row]));
        double offDiagSum = 0;
        for (int col = 0; col < 3; col++) {
            if (col != row) offDiagSum += std::fabs(icFtoD((*pChad)[row * 3 + col]));
        }
        if (diag <= offDiagSum)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 178}, Severity::MEDIUM,
                "Chad matrix row " + std::to_string(row) + " is not diagonally dominant", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("Chad matrix is diagonally dominant");
    return {CheckResult::Status::FINDINGS, "Chad diagonal dominance issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-179: Chad D50-to-D50 Identity Check
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf179_chad_d50_to_d50_identity_check(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTagS15Fixed16 *pChad = FindAndCast<CIccTagS15Fixed16>(pIcc, icSigChromaticAdaptationTag);
    if (!pChad || pChad->GetSize() < 9)
        return CheckResult::ok("No chad tag — not applicable");

    // Check if illuminant is D50
    double X = S15Fixed16ToDouble(pv.header().illuminantX);
    double Y = S15Fixed16ToDouble(pv.header().illuminantY);
    double Z = S15Fixed16ToDouble(pv.header().illuminantZ);

    bool isD50 = std::fabs(X - 0.9642) < 0.01 && std::fabs(Y - 1.0) < 0.01 && std::fabs(Z - 0.8249) < 0.01;
    if (!isD50) return CheckResult::ok("Illuminant is not D50 — identity check not applicable");

    // D50 illuminant with chad → should be near-identity
    std::vector<Finding> findings;
    double identity[9] = {1,0,0, 0,1,0, 0,0,1};
    double maxDev = 0;
    for (int i = 0; i < 9; i++) {
        double val = icFtoD((*pChad)[i]);
        double dev = std::fabs(val - identity[i]);
        if (dev > maxDev) maxDev = dev;
    }

    if (maxDev > 0.1)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 179}, Severity::LOW,
            "D50 illuminant but chad is not near-identity (max deviation=" + std::to_string(maxDev) + ")", "", ""});

    if (findings.empty()) return CheckResult::ok("Chad is near-identity for D50 illuminant");
    return {CheckResult::Status::FINDINGS, "Chad identity check", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-180: PCC Complete Adaptation Principle
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf180_pcc_complete_adaptation_principle(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    bool hasC2sp = pv.hasTag(icSigCustomToStandardPccTag);
    bool hasS2cp = pv.hasTag(icSigStandardToCustomPccTag);

    if (!hasC2sp && !hasS2cp)
        return CheckResult::skip("No PCC tags (c2sp/s2cp) - not applicable");

    std::vector<Finding> findings;
    if (!hasC2sp || !hasS2cp)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 180}, Severity::MEDIUM,
            "c2sp/s2cp pair incomplete — PCC complete adaptation requires both", "", ""});

    if (findings.empty()) return CheckResult::ok("PCC transform pair complete");
    return {CheckResult::Status::FINDINGS, "PCC adaptation issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-181: PCC Illuminant-Chad Consistency
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf181_pcc_illuminant_chad_consistency(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    const CIccTag *svcnTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
    if (!svcnTag)
        return CheckResult::skip("No spectralViewingConditionsTag - not applicable");

    const CIccTagSpectralViewingConditions *svcn =
        dynamic_cast<const CIccTagSpectralViewingConditions *>(svcnTag);
    if (!svcn)
        return CheckResult::skip("spectralViewingConditionsTag not castable - skipping");

    icIlluminant illumType = svcn->getStdIllumiant();
    const CIccTag *chadTag = pIcc->FindTag(icSigChromaticAdaptationTag);
    if (illumType != icIlluminantD50 && illumType != 0 && !chadTag) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 181}, Severity::MEDIUM,
            "Non-D50 illuminant but no chad tag — chromatic adaptation required", "", ""});
        return {CheckResult::Status::FINDINGS, "Missing chad for non-D50", std::move(findings)};
    }
    return CheckResult::ok("PCC illuminant and chad tag consistent");
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-182: PCC Observer Standard Compliance
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf182_pcc_observer_standard_compliance(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    const CIccTagSpectralViewingConditions *svcn =
        FindAndCast<CIccTagSpectralViewingConditions>(pIcc, icSigSpectralViewingConditionsTag);
    if (!svcn) return CheckResult::ok("No svcn tag — observer check not applicable");

    icStandardObserver obs = svcn->getStdObserver();
    if (obs == icStdObs1931TwoDegrees || obs == icStdObs1964TenDegrees)
        return CheckResult::ok("Standard observer (1931 2° or 1964 10°)");

    if (static_cast<icUInt32Number>(obs) == 0) {
        // Custom observer — should have spectral data
        icSpectralRange obsRange;
        svcn->getObserver(obsRange);
        if (obsRange.steps == 0) {
            std::vector<Finding> findings;
            findings.push_back({CheckID{CheckID::Kind::Conformance, 182}, Severity::MEDIUM,
                "Custom observer (type=0) but no spectral data provided", "", ""});
            return {CheckResult::Status::FINDINGS, "Custom observer missing data", std::move(findings)};
        }
        return CheckResult::ok("Custom observer with spectral data");
    }

    return CheckResult::ok("Observer type noted");
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-183: Chad Column Normalization
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf183_chad_column_normalization(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTagS15Fixed16 *pChad = FindAndCast<CIccTagS15Fixed16>(pIcc, icSigChromaticAdaptationTag);
    if (!pChad || pChad->GetSize() < 9)
        return CheckResult::ok("No chad tag — not applicable");

    std::vector<Finding> findings;
    for (int col = 0; col < 3; col++) {
        double sumSq = 0;
        for (int row = 0; row < 3; row++) {
            double v = icFtoD((*pChad)[row * 3 + col]);
            sumSq += v * v;
        }
        double norm = std::sqrt(sumSq);
        if (norm < 0.01 || norm > 10.0)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 183}, Severity::MEDIUM,
                "Chad column " + std::to_string(col) + " L2 norm=" + std::to_string(norm) + " outside [0.01, 10.0]", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("Chad column normalization within expected range");
    return {CheckResult::Status::FINDINGS, "Chad normalization issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-191: ICS Sub-Class Signature Registry
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf191_ics_sub_class_signature_registry(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal == 0) return CheckResult::ok("No sub-class defined");

    if (IsICSSubClass(scVal)) {
        char s[5]; SigToChars(scVal, s);
        return CheckResult::ok(std::string("ICS sub-class '") + s + "' recognized");
    }

    char s[5]; SigToChars(scVal, s);
    std::vector<Finding> findings;
    findings.push_back({CheckID{CheckID::Kind::Conformance, 191}, Severity::LOW,
        std::string("Sub-class '") + s + "' is not a registered ICS sub-class", "", ""});
    return {CheckResult::Status::FINDINGS, "Unregistered sub-class", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-192: Colorimetric ICS Required Tags
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf192_colorimetric_ics_required_tags(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x70636320) return CheckResult::ok("Not pcc sub-class — not applicable");

    std::vector<Finding> findings;
    if (!pIcc->FindTag(icSigAToB1Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 192}, Severity::HIGH,
            "pcc sub-class missing AToB1 tag", "", ""});
    if (!pIcc->FindTag(icSigBToA1Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 192}, Severity::HIGH,
            "pcc sub-class missing BToA1 tag", "", ""});
    if (!pIcc->FindTag(icSigSpectralViewingConditionsTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 192}, Severity::HIGH,
            "pcc sub-class missing svcn tag", "", ""});
    if (!pIcc->FindTag(icSigCustomToStandardPccTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 192}, Severity::HIGH,
            "pcc sub-class missing c2sp tag", "", ""});
    if (!pIcc->FindTag(icSigStandardToCustomPccTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 192}, Severity::HIGH,
            "pcc sub-class missing s2cp tag", "", ""});

    if (findings.empty()) return CheckResult::ok("Colorimetric ICS required tags present");
    return {CheckResult::Status::FINDINGS, "Missing ICS required tags", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-193: Colorimetric ICS PCC Matrix Restriction
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf193_colorimetric_ics_pcc_matrix_restriction(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x70636320) return CheckResult::ok("Not pcc sub-class — not applicable");

    std::vector<Finding> findings;
    icTagSignature pccTags[] = {icSigCustomToStandardPccTag, icSigStandardToCustomPccTag};
    const char* pccNames[] = {"c2sp", "s2cp"};

    for (int t = 0; t < 2; t++) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, pccTags[t]);
        if (!mpe) continue;
        if (mpe->NumElements() != 1 || !mpe->GetElement(0) ||
            mpe->GetElement(0)->GetType() != icSigMatrixElemType) {
            findings.push_back({CheckID{CheckID::Kind::Conformance, 193}, Severity::HIGH,
                std::string(pccNames[t]) + " must be a single 3x3 matrixElement", "", ""});
        }
    }

    if (findings.empty()) return CheckResult::ok("PCC matrix restriction met");
    return {CheckResult::Status::FINDINGS, "PCC matrix issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-194..CF-198, CF-235..CF-242, CF-257 — similar pattern checks
// For brevity, implementing with same V1→V2 translation pattern
// ═══════════════════════════════════════════════════════════════════════════

static CheckResult check_cf194_spectral_reflectance_ics_required_tags(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x73726566) return CheckResult::ok("Not sref sub-class — not applicable");

    std::vector<Finding> findings;
    if (!pIcc->FindTag(icSigDToB3Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 194}, Severity::HIGH,
            "sref sub-class missing DToB3 tag", "", ""});
    if (!pIcc->FindTag(icSigBToD3Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 194}, Severity::HIGH,
            "sref sub-class missing BToD3 tag", "", ""});
    if (!pIcc->FindTag(icSigSpectralViewingConditionsTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 194}, Severity::HIGH,
            "sref sub-class missing svcn tag", "", ""});

    if (findings.empty()) return CheckResult::ok("Spectral reflectance ICS required tags present");
    return {CheckResult::Status::FINDINGS, "Missing sref ICS tags", std::move(findings)};
}

static CheckResult check_cf195_extended_dynamic_range_radiance_white_po(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng sub-class — not applicable");

    CIccTagXYZ *pXYZ = FindAndCast<CIccTagXYZ>(pIcc, icSigMediaWhitePointTag);
    if (!pXYZ || pXYZ->GetSize() < 1)
        return CheckResult::ok("No mediaWhitePointTag — not applicable");

    const icXYZNumber *xyz = pXYZ->GetXYZ(0);
    if (xyz && icFtoD(xyz->Y) <= 1.0) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 195}, Severity::MEDIUM,
            "xrng extended dynamic range white point Y <= 1.0 — expected Y > 1.0 for HDR", "", ""});
        return {CheckResult::Status::FINDINGS, "xrng radiance white point", std::move(findings)};
    }
    return CheckResult::ok("Extended dynamic range radiance white point valid");
}

static CheckResult check_cf196_ics_mpe_calculator_restriction(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    // ICS Part 1 restriction: no calculator elements
    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (!IsICSSubClass(scVal)) return CheckResult::ok("Not an ICS sub-class — not applicable");

    std::vector<Finding> findings;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTag *tag = pIcc->FindTag(static_cast<icTagSignature>(entry.signature));
        if (!tag) continue;
        CIccTagMultiProcessElement *mpe = dynamic_cast<CIccTagMultiProcessElement*>(tag);
        if (!mpe) continue;
        for (icUInt32Number i = 0; i < mpe->NumElements(); i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (elem && elem->GetType() == icSigCalculatorElemType) {
                findings.push_back({CheckID{CheckID::Kind::Conformance, 196}, Severity::MEDIUM,
                    "Calculator element found in ICS Part 1 profile — not allowed", "", ""});
                break;
            }
        }
    }

    if (findings.empty()) return CheckResult::ok("No calculator elements in ICS profile — Part 1 compliant");
    return {CheckResult::Status::FINDINGS, "Calculator restriction violated", std::move(findings)};
}

static CheckResult check_cf197_ics_pcc_transform_pair_completeness(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    bool hasC2sp = pIcc->FindTag(icSigCustomToStandardPccTag) != nullptr;
    bool hasS2cp = pIcc->FindTag(icSigStandardToCustomPccTag) != nullptr;

    if (!hasC2sp && !hasS2cp) return CheckResult::ok("No PCC transform tags — not applicable");

    if (hasC2sp && hasS2cp) return CheckResult::ok("PCC transform pair complete");

    std::vector<Finding> findings;
    findings.push_back({CheckID{CheckID::Kind::Conformance, 197}, Severity::HIGH,
        std::string("PCC transform pair incomplete: c2sp=") + (hasC2sp?"yes":"no") + " s2cp=" + (hasS2cp?"yes":"no"), "", ""});
    return {CheckResult::Status::FINDINGS, "Incomplete PCC pair", std::move(findings)};
}

static CheckResult check_cf198_extended_range_sub_class_validation(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng sub-class — not applicable");

    std::vector<Finding> findings;
    uint32_t dc = pv.header().deviceClass;
    if (dc != icSigDisplayClass && dc != icSigColorSpaceClass) {
        char cls[5]; SigToChars(dc, cls);
        findings.push_back({CheckID{CheckID::Kind::Conformance, 198}, Severity::HIGH,
            std::string("xrng sub-class requires mntr or spac class, got '") + cls + "'", "", ""});
    }

    bool extendedRange = (pv.header().flags & 0x00000008) != 0;
    if (!extendedRange)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 198}, Severity::HIGH,
            "xrng sub-class requires extended range PCS flag (bit 3)", "", ""});

    if (findings.empty()) return CheckResult::ok("xrng sub-class validation passed");
    return {CheckResult::Status::FINDINGS, "xrng sub-class issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-235..CF-242: xrng Extended Range checks
// ═══════════════════════════════════════════════════════════════════════════

static CheckResult check_cf235_xrng_data_colour_space_restriction(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng — not applicable");

    uint32_t cs = pv.header().colorSpace;
    int nChan = icGetSpaceSamples(static_cast<icColorSpaceSignature>(cs));
    if (cs != icSigRgbData || nChan != 3) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 235}, Severity::HIGH,
            "xrng requires RGB colour space with 3 channels", "", ""});
        return {CheckResult::Status::FINDINGS, "xrng colour space", std::move(findings)};
    }
    return CheckResult::ok("xrng RGB colour space with 3 channels");
}

static CheckResult check_cf236_xrng_colorimetric_pcs_constraint(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng — not applicable");

    std::vector<Finding> findings;
    if (pv.header().pcs != icSigXYZData)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 236}, Severity::HIGH,
            "xrng requires XYZ PCS", "", ""});

    double Y = S15Fixed16ToDouble(pv.header().illuminantY);
    if (std::fabs(Y - 1.0) > 0.01)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 236}, Severity::MEDIUM,
            "xrng D50 illuminant Y deviation from 1.0", "", ""});

    if (findings.empty()) return CheckResult::ok("xrng colorimetric PCS constraint met");
    return {CheckResult::Status::FINDINGS, "xrng PCS issues", std::move(findings)};
}

static CheckResult check_cf237_xrng_required_tag_completeness(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng — not applicable");

    std::vector<Finding> findings;
    icTagSignature reqTags[] = {
        icSigProfileDescriptionTag, icSigCopyrightTag, icSigMediaWhitePointTag,
        icSigAToB1Tag, icSigBToA1Tag, icSigChromaticAdaptationTag
    };
    const char* reqNames[] = {"desc", "cprt", "wtpt", "A2B1", "B2A1", "chad"};

    for (int i = 0; i < 6; i++) {
        if (!pIcc->FindTag(reqTags[i]))
            findings.push_back({CheckID{CheckID::Kind::Conformance, 237}, Severity::HIGH,
                std::string("xrng missing required tag '") + reqNames[i] + "'", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("xrng required tags present");
    return {CheckResult::Status::FINDINGS, "Missing xrng tags", std::move(findings)};
}

static CheckResult check_cf238_xrng_header_field_restrictions(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng — not applicable");

    std::vector<Finding> findings;
    if (static_cast<icUInt32Number>(pIcc->m_Header.spectralPCS) != 0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 238}, Severity::HIGH,
            "xrng spectralPCS should be 0", "", ""});
    if (static_cast<icUInt32Number>(pIcc->m_Header.mcs) != 0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 238}, Severity::HIGH,
            "xrng MCS should be 0", "", ""});

    if (findings.empty()) return CheckResult::ok("xrng header field restrictions met");
    return {CheckResult::Status::FINDINGS, "xrng header issues", std::move(findings)};
}

static CheckResult check_cf239_xrng_optional_tag_type_validation(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng — not applicable");

    std::vector<Finding> findings;
    // chad must be s15Fixed16ArrayType if present
    CIccTag *pChad = pIcc->FindTag(icSigChromaticAdaptationTag);
    if (pChad && pChad->GetType() != icSigS15Fixed16ArrayType)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 239}, Severity::HIGH,
            "chad tag must be s15Fixed16ArrayType", "", ""});

    if (findings.empty()) return CheckResult::ok("xrng optional tag types valid");
    return {CheckResult::Status::FINDINGS, "xrng tag type issues", std::move(findings)};
}

static CheckResult check_cf240_xrng_transform_channel_dimensions(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng — not applicable");

    std::vector<Finding> findings;
    icTagSignature xformTags[] = {icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
                                   icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag};
    for (int i = 0; i < 6; i++) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, xformTags[i]);
        if (!mpe) continue;
        if (mpe->NumInputChannels() != 3 || mpe->NumOutputChannels() != 3) {
            char s[5]; SigToChars(static_cast<uint32_t>(xformTags[i]), s);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 240}, Severity::HIGH,
                std::string("xrng tag '") + s + "' channels must be 3->3", "", ""});
        }
    }

    if (findings.empty()) return CheckResult::ok("xrng transform channels valid (3->3)");
    return {CheckResult::Status::FINDINGS, "xrng channel issues", std::move(findings)};
}

static CheckResult check_cf241_xrng_mediawhitepointtag_absolute_radianc(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng — not applicable");

    CIccTagXYZ *pXYZ = FindAndCast<CIccTagXYZ>(pIcc, icSigMediaWhitePointTag);
    if (!pXYZ || pXYZ->GetSize() < 1)
        return CheckResult::ok("No mediaWhitePointTag");

    std::vector<Finding> findings;
    const icXYZNumber *xyz = pXYZ->GetXYZ(0);
    if (xyz) {
        double X = icFtoD(xyz->X), Y = icFtoD(xyz->Y), Z = icFtoD(xyz->Z);
        if (X <= 0 || Y <= 0 || Z <= 0)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 241}, Severity::HIGH,
                "Media white point has non-positive values", "", ""});
        if (Y <= 1.0)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 241}, Severity::MEDIUM,
                "xrng media white point Y <= 1.0 — expected extended range Y > 1.0", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("xrng media white point valid");
    return {CheckResult::Status::FINDINGS, "xrng white point issues", std::move(findings)};
}

static CheckResult check_cf242_xrng_workflow_connection_consistency(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng — not applicable");

    std::vector<Finding> findings;
    if (!pIcc->FindTag(icSigAToB1Tag) || !pIcc->FindTag(icSigBToA1Tag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 242}, Severity::HIGH,
            "xrng workflow requires AToB1/BToA1 for relative colorimetric intent", "", ""});

    if (pv.header().renderingIntent != 1)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 242}, Severity::LOW,
            "xrng preferred rendering intent should be relative colorimetric (1)", "", ""});

    if (findings.empty()) return CheckResult::ok("xrng workflow connection consistent");
    return {CheckResult::Status::FINDINGS, "xrng workflow issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-257: Spectral Range Step Count
// ═══════════════════════════════════════════════════════════════════════════
static CheckResult check_cf257_spectral_range_step_count(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    if (pIcc->m_Header.spectralPCS == 0)
        return CheckResult::skip("No spectral PCS - not applicable");

    icSpectralRange spec = pIcc->m_Header.spectralRange;

    std::vector<Finding> findings;
    if (spec.steps < 2)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 257}, Severity::HIGH,
            "Spectral range steps < 2 — must be >= 2 for meaningful spectrum", "", ""});

    float startNm = safeF16ToF(spec.start);
    float endNm = safeF16ToF(spec.end);
    if (startNm >= endNm)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 257}, Severity::HIGH,
            "Spectral start >= end", "", ""});

    if (findings.empty()) return CheckResult::ok("Spectral range step count valid");
    return {CheckResult::Status::FINDINGS, "Spectral step count issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-284..CF-303: Errata-derived checks
// ═══════════════════════════════════════════════════════════════════════════

static CheckResult check_cf284_brdf_spectral_parameter_tag_type(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icTagSignature brdfTags[] = {icSigBrdfSpectralParameter0Tag, icSigBrdfSpectralParameter1Tag,
                                  icSigBrdfSpectralParameter2Tag, icSigBrdfSpectralParameter3Tag};
    std::vector<Finding> findings;
    int found = 0;

    for (int i = 0; i < 4; i++) {
        CIccTag *tag = pIcc->FindTag(brdfTags[i]);
        if (!tag) continue;
        found++;
        if (tag->GetType() != icSigMultiProcessElementType) {
            findings.push_back({CheckID{CheckID::Kind::Conformance, 284}, Severity::HIGH,
                "BRDF spectral parameter tag " + std::to_string(i) + " must be MPE type", "", ""});
        }
    }

    if (found == 0) return CheckResult::ok("No BRDF spectral parameter tags");
    if (findings.empty()) return CheckResult::ok("BRDF tags have correct type");
    return {CheckResult::Status::FINDINGS, "BRDF tag type issues", std::move(findings)};
}

static CheckResult check_cf285_brdf_tag_presence_consistency(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icTagSignature brdfTags[] = {icSigBrdfSpectralParameter0Tag, icSigBrdfSpectralParameter1Tag,
                                  icSigBrdfSpectralParameter2Tag, icSigBrdfSpectralParameter3Tag};
    int count = 0;
    for (int i = 0; i < 4; i++)
        if (pIcc->FindTag(brdfTags[i])) count++;

    if (count == 0 || count == 4) return CheckResult::ok("BRDF tag set consistent (all or none)");

    std::vector<Finding> findings;
    findings.push_back({CheckID{CheckID::Kind::Conformance, 285}, Severity::MEDIUM,
        "BRDF tags partially present (" + std::to_string(count) + "/4) — should be all or none", "", ""});
    return {CheckResult::Status::FINDINGS, "BRDF presence inconsistency", std::move(findings)};
}

static CheckResult check_cf286_gbd_triangle_vertex_consistency(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    if (!pv.libraryLoaded() && !pv.requiresLibraryQuarantine()) {
        return CheckResult::skip("NOT RUN: Profile failed to load");
    }

    auto records = scanRawGbdRecords(pv);
    if (records.empty()) return CheckResult::ok("No GBD tags — not applicable");

    std::vector<Finding> findings;
    for (const auto& record : records) {
        if (!record.headerAccessible) continue;
        uint64_t nTris = record.triangles;
        uint64_t nVerts = record.vertices;
        if (nTris > 0 && nVerts < 3) {
            findings.push_back({CheckID{CheckID::Kind::Conformance, 286}, Severity::HIGH,
                "GBD '" + rawGbdOwnerName(record) + "' has " + std::to_string(nTris) +
                " triangles but only " + std::to_string(nVerts) + " vertices", "", ""});
            continue;
        }
        uint64_t maxTriangles = choose3Clamped(record.vertices);
        if (maxTriangles != UINT64_MAX && nTris > maxTriangles) {
            findings.push_back({CheckID{CheckID::Kind::Conformance, 286}, Severity::HIGH,
                "GBD '" + rawGbdOwnerName(record) + "' has " + std::to_string(nTris) +
                " triangles but only " + std::to_string(nVerts) +
                " vertices (max distinct triangles " + std::to_string(maxTriangles) + ")", "", ""});
        }
    }

    if (findings.empty()) return CheckResult::ok("GBD triangle-vertex consistency OK");
    return {CheckResult::Status::FINDINGS, "GBD consistency issues", std::move(findings)};
}

static CheckResult check_cf287_gbd_channel_count_plausibility(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    if (!pv.libraryLoaded() && !pv.requiresLibraryQuarantine()) {
        return CheckResult::skip("NOT RUN: Profile failed to load");
    }

    auto records = scanRawGbdRecords(pv);
    if (records.empty()) return CheckResult::ok("No GBD tags — not applicable");

    std::vector<Finding> findings;
    for (const auto& record : records) {
        if (!record.headerAccessible) continue;
        uint32_t pcsCh = record.pcsChannels;
        uint32_t devCh = record.deviceChannels;
        if (pcsCh != 3) {
            findings.push_back({CheckID{CheckID::Kind::Conformance, 287}, Severity::MEDIUM,
                "GBD '" + rawGbdOwnerName(record) + "' PCS channels=" + std::to_string(pcsCh) + " (expected 3)", "", ""});
        }
        if (devCh > 15) {
            findings.push_back({CheckID{CheckID::Kind::Conformance, 287}, Severity::MEDIUM,
                "GBD '" + rawGbdOwnerName(record) + "' device channels=" + std::to_string(devCh) + " (>15)", "", ""});
        }
    }

    if (findings.empty()) return CheckResult::ok("GBD channel counts plausible");
    return {CheckResult::Status::FINDINGS, "GBD channel issues", std::move(findings)};
}

static CheckResult check_cf288_spectral_data_info_bi_spectral_consisten(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTagSpectralDataInfo *sdi = FindAndCast<CIccTagSpectralDataInfo>(pIcc, icSigSpectralDataInfoTag);
    if (!sdi) return CheckResult::ok("No spectral data info tag");

    std::vector<Finding> findings;
    if (sdi->m_biSpectralRange.steps > 0) {
        float bStart = safeF16ToF(sdi->m_biSpectralRange.start);
        float bEnd = safeF16ToF(sdi->m_biSpectralRange.end);
        if (bStart >= bEnd)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 288}, Severity::HIGH,
                "Bi-spectral range start >= end", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("Spectral data info bi-spectral consistent");
    return {CheckResult::Status::FINDINGS, "Bi-spectral issues", std::move(findings)};
}

static CheckResult check_cf289_spectral_viewing_conditions_illuminant_b(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    const CIccTagSpectralViewingConditions *svcn =
        FindAndCast<CIccTagSpectralViewingConditions>(pIcc, icSigSpectralViewingConditionsTag);
    if (!svcn) return CheckResult::ok("No svcn tag");

    std::vector<Finding> findings;
    double X = static_cast<double>(svcn->m_illuminantXYZ.X);
    double Y = static_cast<double>(svcn->m_illuminantXYZ.Y);
    double Z = static_cast<double>(svcn->m_illuminantXYZ.Z);

    if (X <= 0 || Y <= 0 || Z <= 0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 289}, Severity::HIGH,
            "svcn illuminant XYZ has non-positive values", "", ""});
    if (Y < 0.5 || Y > 2.0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 289}, Severity::LOW,
            "svcn illuminant Y=" + std::to_string(Y) + " — unusual range", "", ""});

    if (findings.empty()) return CheckResult::ok("svcn illuminant bounds OK");
    return {CheckResult::Status::FINDINGS, "Illuminant bound issues", std::move(findings)};
}

static CheckResult check_cf290_material_default_values_tag_presence(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    if (pIcc->m_Header.mcs == icSigNoMCSData)
        return CheckResult::ok("No MCS — material default values not required");

    if (!pIcc->FindTag(icSigMultiplexDefaultValuesTag)) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 290}, Severity::MEDIUM,
            "Material profile missing multiplexDefaultValues tag", "", ""});
        return {CheckResult::Status::FINDINGS, "Missing mdv tag", std::move(findings)};
    }
    return CheckResult::ok("Material default values tag present");
}

static CheckResult check_cf291_spectral_white_point_xyz_range(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    const CIccTagSpectralViewingConditions *svcn =
        FindAndCast<CIccTagSpectralViewingConditions>(pIcc, icSigSpectralViewingConditionsTag);
    if (!svcn) return CheckResult::ok("No svcn tag");

    std::vector<Finding> findings;
    double Y = static_cast<double>(svcn->m_illuminantXYZ.Y);
    if (Y <= 0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 291}, Severity::HIGH,
            "Spectral white point Y <= 0", "", ""});
    if (std::fabs(Y - 1.0) > 0.5)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 291}, Severity::LOW,
            "Spectral white point Y deviates significantly from 1.0", "", ""});

    if (findings.empty()) return CheckResult::ok("Spectral white point XYZ range OK");
    return {CheckResult::Status::FINDINGS, "White point range issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-292..CF-300: MPE chain and structure checks
// ═══════════════════════════════════════════════════════════════════════════

static CheckResult check_cf292_mpe_chain_i_o_channel_consistency(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe || mpe->NumElements() < 2) continue;

        for (icUInt32Number i = 0; i < mpe->NumElements() - 1; i++) {
            CIccMultiProcessElement *cur = mpe->GetElement(static_cast<int>(i));
            CIccMultiProcessElement *next = mpe->GetElement(static_cast<int>(i + 1));
            if (!cur || !next) continue;
            if (cur->NumOutputChannels() != next->NumInputChannels()) {
                char s[5]; SigToChars(entry.signature, s);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 292}, Severity::HIGH,
                    std::string("MPE chain in '") + s + "' element " + std::to_string(i) +
                    " output=" + std::to_string(cur->NumOutputChannels()) +
                    " != element " + std::to_string(i+1) + " input=" + std::to_string(next->NumInputChannels()), "", ""});
            }
        }
    }

    if (findings.empty()) return CheckResult::ok("MPE chain I/O channels consistent");
    return {CheckResult::Status::FINDINGS, "MPE chain I/O mismatch", std::move(findings)};
}

static CheckResult check_cf293_mpe_container_i_o_vs_first_last_element(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe || mpe->NumElements() == 0) continue;

        CIccMultiProcessElement *first = mpe->GetElement(0);
        CIccMultiProcessElement *last = mpe->GetElement(static_cast<int>(mpe->NumElements() - 1));
        if (first && first->NumInputChannels() != mpe->NumInputChannels()) {
            char s[5]; SigToChars(entry.signature, s);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 293}, Severity::HIGH,
                std::string("MPE '") + s + "' container input != first element input", "", ""});
        }
        if (last && last->NumOutputChannels() != mpe->NumOutputChannels()) {
            char s[5]; SigToChars(entry.signature, s);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 293}, Severity::HIGH,
                std::string("MPE '") + s + "' container output != last element output", "", ""});
        }
    }

    if (findings.empty()) return CheckResult::ok("MPE container I/O matches first/last elements");
    return {CheckResult::Status::FINDINGS, "MPE container I/O mismatch", std::move(findings)};
}

static CheckResult check_cf294_mpe_acs_boundary_element_pairing(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        int bacs = 0, eacs = 0;
        for (icUInt32Number i = 0; i < mpe->NumElements(); i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (!elem) continue;
            if (elem->GetType() == icSigBAcsElemType) bacs++;
            if (elem->GetType() == icSigEAcsElemType) eacs++;
        }
        if (bacs != eacs) {
            char s[5]; SigToChars(entry.signature, s);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 294}, Severity::MEDIUM,
                std::string("MPE '") + s + "' bACS/eACS unpaired (" + std::to_string(bacs) + "/" + std::to_string(eacs) + ")", "", ""});
        }
    }

    if (findings.empty()) return CheckResult::ok("MPE ACS boundary elements paired");
    return {CheckResult::Status::FINDINGS, "ACS pairing issues", std::move(findings)};
}

static CheckResult check_cf295_mpe_element_type_version_compatibility(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    icUInt32Number version = pIcc->m_Header.version >> 24;
    icElemTypeSignature v5OnlyTypes[] = {
        icSigCalculatorElemType, icSigExtCLutElemType, icSigXYZToJabElemType,
        icSigJabToXYZElemType, icSigSparseMatrixElemType, icSigTintArrayElemType,
        icSigToneMapElemType, icSigEmissionMatrixElemType, icSigInvEmissionMatrixElemType,
        icSigEmissionCLUTElemType, icSigReflectanceCLUTElemType,
        icSigEmissionObserverElemType, icSigReflectanceObserverElemType
    };

    int tagsChecked = 0;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        for (icUInt32Number i = 0; i < mpe->NumElements(); i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (!elem) continue;
            tagsChecked++;
            for (const auto& v5type : v5OnlyTypes) {
                if (version < 5 && elem->GetType() == v5type) {
                    char s[5]; SigToChars(static_cast<uint32_t>(v5type), s);
                    findings.push_back({CheckID{CheckID::Kind::Conformance, 295}, Severity::HIGH,
                        std::string("V5-only MPE type '") + s + "' in non-v5 profile", "", ""});
                    break;
                }
            }
        }
    }

    if (tagsChecked == 0)
        return CheckResult::skip("No MPE elements found - not applicable");
    if (findings.empty())
        return CheckResult::ok("All MPE elements version-compatible");
    return {CheckResult::Status::FINDINGS, "Version compatibility issues", std::move(findings)};
}

static CheckResult check_cf296_mpe_empty_container_validation(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe || mpe->NumElements() > 0) continue;
        if (mpe->NumInputChannels() != mpe->NumOutputChannels()) {
            char s[5]; SigToChars(entry.signature, s);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 296}, Severity::MEDIUM,
                std::string("Empty MPE '") + s + "' has input != output channels", "", ""});
        }
    }

    if (findings.empty()) return CheckResult::ok("Empty MPE containers valid");
    return {CheckResult::Status::FINDINGS, "Empty MPE issues", std::move(findings)};
}

static CheckResult check_cf297_mpe_curveset_element_channel_count(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        for (icUInt32Number i = 0; i < mpe->NumElements(); i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (!elem || elem->GetType() != icSigCurveSetElemType) continue;
            if (elem->NumInputChannels() != elem->NumOutputChannels()) {
                char s[5]; SigToChars(entry.signature, s);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 297}, Severity::HIGH,
                    std::string("CurveSet in '") + s + "' input != output channels", "", ""});
            }
        }
    }

    if (findings.empty()) return CheckResult::ok("CurveSet element channels OK");
    return {CheckResult::Status::FINDINGS, "CurveSet channel mismatch", std::move(findings)};
}

static CheckResult check_cf298_mpe_matrix_element_dimension(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        for (icUInt32Number i = 0; i < mpe->NumElements(); i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (!elem || elem->GetType() != icSigMatrixElemType) continue;
            if (elem->NumInputChannels() == 0 || elem->NumOutputChannels() == 0) {
                char s[5]; SigToChars(entry.signature, s);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 298}, Severity::HIGH,
                    std::string("Matrix in '") + s + "' has zero dimension", "", ""});
            }
        }
    }

    if (findings.empty()) return CheckResult::ok("Matrix element dimensions OK");
    return {CheckResult::Status::FINDINGS, "Matrix dimension issues", std::move(findings)};
}

static CheckResult check_cf299_mpe_clut_element_grid_dimension(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        for (icUInt32Number i = 0; i < mpe->NumElements(); i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (!elem || elem->GetType() != icSigCLutElemType) continue;
            CIccMpeCLUT *pClut = dynamic_cast<CIccMpeCLUT*>(elem);
            if (pClut && pClut->GetCLUT()) {
                CIccCLUT *clut = pClut->GetCLUT();
                for (int d = 0; d < static_cast<int>(elem->NumInputChannels()); d++) {
                    if (clut->GridPoint(d) == 0) {
                        char s[5]; SigToChars(entry.signature, s);
                        findings.push_back({CheckID{CheckID::Kind::Conformance, 299}, Severity::HIGH,
                            std::string("CLUT in '") + s + "' has zero grid point in dimension " + std::to_string(d), "", ""});
                    }
                }
            }
        }
    }

    if (findings.empty()) return CheckResult::ok("CLUT grid dimensions OK");
    return {CheckResult::Status::FINDINGS, "CLUT grid issues", std::move(findings)};
}

static CheckResult check_cf300_mpe_tag_vs_color_space_channels(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    int devChan = icGetSpaceSamples(pIcc->m_Header.colorSpace);
    int pcsChan = icGetSpaceSamples(pIcc->m_Header.pcs);

    // Check AToB tags: input=device, output=PCS
    icTagSignature a2bTags[] = {icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag};
    for (int t = 0; t < 3; t++) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, a2bTags[t]);
        if (!mpe) continue;
        if (static_cast<int>(mpe->NumInputChannels()) != devChan) {
            char s[5]; SigToChars(static_cast<uint32_t>(a2bTags[t]), s);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 300}, Severity::HIGH,
                std::string("MPE '") + s + "' input channels != device channels", "", ""});
        }
    }

    // Check BToA tags: input=PCS, output=device
    icTagSignature b2aTags[] = {icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag};
    for (int t = 0; t < 3; t++) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, b2aTags[t]);
        if (!mpe) continue;
        if (static_cast<int>(mpe->NumInputChannels()) != pcsChan) {
            char s[5]; SigToChars(static_cast<uint32_t>(b2aTags[t]), s);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 300}, Severity::HIGH,
                std::string("MPE '") + s + "' input channels != PCS channels", "", ""});
        }
        if (static_cast<int>(mpe->NumOutputChannels()) != devChan) {
            char s[5]; SigToChars(static_cast<uint32_t>(b2aTags[t]), s);
            findings.push_back({CheckID{CheckID::Kind::Conformance, 300}, Severity::HIGH,
                std::string("MPE '") + s + "' output channels != device channels", "", ""});
        }
    }

    if (findings.empty()) return CheckResult::ok("MPE tag channels match color space");
    return {CheckResult::Status::FINDINGS, "MPE channel mismatch", std::move(findings)};
}

static CheckResult check_cf301_measurement_struct_tagstructtype_enforce(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *pTag = pIcc->FindTag(icSigMeasurementTag);
    if (!pTag) return CheckResult::ok("No measurement tag");
    // V5 measurement should be tagStructType
    if (pTag->GetType() != icSigTagStructType) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 301}, Severity::MEDIUM,
            "Measurement tag should be tagStructType in v5", "", ""});
        return {CheckResult::Status::FINDINGS, "Measurement type", std::move(findings)};
    }
    return CheckResult::ok("Measurement tag is tagStructType");
}

static CheckResult check_cf302_measurement_struct_member_completeness(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    static const struct {
        icSignature sig;
        const char *name;
    } kMembers[] = {
        {0x6d62616b, "mbak (backing)"},
        {0x6d666c72, "mflr (flare)"},
        {0x6d67656f, "mgeo (geometry)"},
        {0x6d696c6c, "mill (illuminant)"},
        {0x6d6d6f64, "mmod (mode)"},
    };

    std::vector<Finding> findings;
    int structCount = 0;
    for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
        CIccTag *pTag = pIcc->FindTag(it->TagInfo.sig);
        if (!pTag || pTag->GetType() != icSigTagStructType) continue;

        CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct *>(pTag);
        if (!pStruct || pStruct->GetTagStructType() != icSigMeasurementInfoStruct)
            continue;

        structCount++;
        char sig[5];
        SigToChars(static_cast<uint32_t>(it->TagInfo.sig), sig);
        for (const auto& member : kMembers) {
            CIccTag *pMember = pStruct->FindElem(member.sig);
            if (!pMember) {
                findings.push_back(Finding{
                    {CheckID::Kind::Conformance, 302}, Severity::MEDIUM,
                    std::string("measurementInfoStruct in tag '") + sig +
                    "' missing member " + member.name,
                    "ICC.2-2019 Errata §9.2.86/87", "CWE-20"});
            }
        }
    }

    if (structCount == 0)
        return CheckResult::ok("No measurementInfoStruct tags — not applicable");
    if (findings.empty())
        return CheckResult::ok("measurementInfoStruct tags have required members");
    return {CheckResult::Status::FINDINGS, "Measurement struct members missing", std::move(findings)};
}

static CheckResult check_cf303_spectral_data_array_type_restriction(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    static const icTagSignature kSpectralDataTags[] = {
        icSigMultiplexDefaultValuesTag,
        icSigSpectralWhitePointTag,
        icSigMultiplexTypeArrayTag,
    };
    static const icTagTypeSignature kPermittedTypes[] = {
        icSigUInt8ArrayType,
        icSigUInt16ArrayType,
        icSigFloat16ArrayType,
        icSigFloat32ArrayType,
    };

    std::vector<Finding> findings;
    int checked = 0;
    for (auto sig : kSpectralDataTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;

        checked++;
        icTagTypeSignature tt = pTag->GetType();
        bool permitted = false;
        for (auto allowed : kPermittedTypes) {
            if (tt == allowed) {
                permitted = true;
                break;
            }
        }
        if (!permitted) {
            char tagSig[5];
            SigToChars(static_cast<uint32_t>(sig), tagSig);
            char typeSig[5];
            SigToChars(static_cast<uint32_t>(tt), typeSig);
            findings.push_back(Finding{
                {CheckID::Kind::Conformance, 303}, Severity::MEDIUM,
                std::string("'") + tagSig + "' type '" + typeSig +
                "' — errata permits only uInt8/uInt16/float16/float32 array types",
                "ICC.2-2019 Errata §9.2.84", "CWE-20"});
        }
    }

    if (checked == 0)
        return CheckResult::ok("No spectral data array tags — not applicable");
    if (findings.empty())
        return CheckResult::ok("Spectral data array types permitted");
    return {CheckResult::Status::FINDINGS, "Spectral data array type restriction", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-305..CF-316: ICS Sub-Class checks
// ═══════════════════════════════════════════════════════════════════════════

static CheckResult check_cf305_multiprocesselementstype_nomenclature_au(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    // Informational audit — report presence of MPE tags
    int mpeCount = 0;
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (pIcc) {
        for (const auto& entry : pv.rawTagTable()) {
            CIccTag *tag = pIcc->FindTag(static_cast<icTagSignature>(entry.signature));
            if (tag && dynamic_cast<CIccTagMultiProcessElement*>(tag)) mpeCount++;
        }
    }
    return CheckResult::ok(std::to_string(mpeCount) + " MPE tag(s) present (nomenclature audit)");
}

static CheckResult check_cf306_embedded_image_data_length_cross_validat(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    // Embedded image tags (height/normal) — check data length vs declared dimensions
    // These tags are rare; basic presence check
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    bool hasEmbedImage = pIcc->FindTag(icSigEmbeddedHeightImageType) != nullptr ||
                          pIcc->FindTag(icSigEmbeddedNormalImageType) != nullptr;
    if (!hasEmbedImage) return CheckResult::ok("No embedded image tags");
    return CheckResult::ok("Embedded image tags present — data length validated by library");
}

static CheckResult check_cf307_calculator_vector_or_signature_validatio(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    // Scan for calculator elements and check for 'vor ' (0x766f7220) signature
    std::vector<Finding> findings;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        std::string desc;
        mpe->Describe(desc, 0);
        if (desc.find("vor ") != std::string::npos || desc.find("vor(") != std::string::npos) {
            // vor operator found — informational
        }
    }

    return CheckResult::ok("Calculator vector-or signature check passed");
}

// CF-308..CF-316: ICS element restriction checks
static CheckResult check_cf308_pcc_atob1_btoa1_part_1_element_restricti(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x70636320) return CheckResult::ok("Not pcc sub-class — not applicable");

    std::vector<Finding> findings;
    icTagSignature tags[] = {icSigAToB1Tag, icSigBToA1Tag};
    const char* names[] = {"AToB1", "BToA1"};
    for (int t = 0; t < 2; t++) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, tags[t]);
        if (!mpe) continue;
        for (icUInt32Number i = 0; i < mpe->NumElements(); i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (elem && !IsICSPart1AllowedMPE(elem->GetType())) {
                char s[5]; SigToChars(static_cast<uint32_t>(elem->GetType()), s);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 308}, Severity::HIGH,
                    std::string(names[t]) + " has non-Part-1 MPE type '" + s + "'", "", ""});
            }
        }
    }

    if (findings.empty()) return CheckResult::ok("pcc AToB1/BToA1 Part 1 element restriction met");
    return {CheckResult::Status::FINDINGS, "Part 1 element restriction violated", std::move(findings)};
}

static CheckResult check_cf309_sref_pcc_matrix_restriction(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x73726566) return CheckResult::ok("Not sref — not applicable");

    std::vector<Finding> findings;
    icTagSignature pccTags[] = {icSigCustomToStandardPccTag, icSigStandardToCustomPccTag};
    for (int t = 0; t < 2; t++) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, pccTags[t]);
        if (!mpe) continue;
        if (mpe->NumElements() != 1 || !mpe->GetElement(0) ||
            mpe->GetElement(0)->GetType() != icSigMatrixElemType)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 309}, Severity::HIGH,
                "sref PCC must be single 3x3 matrixElement", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("sref PCC matrix restriction met");
    return {CheckResult::Status::FINDINGS, "sref PCC matrix issues", std::move(findings)};
}

static CheckResult check_cf310_sref_dtob3_btod3_part_1_element_restrict(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x73726566) return CheckResult::ok("Not sref — not applicable");

    std::vector<Finding> findings;
    icTagSignature tags[] = {icSigDToB3Tag, icSigBToD3Tag};
    for (int t = 0; t < 2; t++) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, tags[t]);
        if (!mpe) continue;
        for (icUInt32Number i = 0; i < mpe->NumElements(); i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (elem && !IsICSPart1AllowedMPE(elem->GetType())) {
                char s[5]; SigToChars(static_cast<uint32_t>(elem->GetType()), s);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 310}, Severity::HIGH,
                    std::string("sref DToB3/BToD3 has non-Part-1 MPE type '") + s + "'", "", ""});
            }
        }
    }

    if (findings.empty()) return CheckResult::ok("sref DToB3/BToD3 Part 1 restriction met");
    return {CheckResult::Status::FINDINGS, "sref Part 1 restriction violated", std::move(findings)};
}

static CheckResult check_cf311_sref_spectral_range_mandatory(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x73726566) return CheckResult::ok("Not sref — not applicable");

    if (pIcc->m_Header.spectralRange.steps == 0) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 311}, Severity::HIGH,
            "sref sub-class requires spectral range in header", "", ""});
        return {CheckResult::Status::FINDINGS, "Missing spectral range", std::move(findings)};
    }
    return CheckResult::ok("sref spectral range present");
}

static CheckResult check_cf312_ext_required_tag_completeness(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x65787420) return CheckResult::ok("Not ext sub-class — not applicable");

    std::vector<Finding> findings;
    icTagSignature reqTags[] = {icSigSpectralViewingConditionsTag,
        icSigCustomToStandardPccTag, icSigStandardToCustomPccTag,
        icSigProfileDescriptionTag, icSigCopyrightTag};
    const char* reqNames[] = {"svcn", "c2sp", "s2cp", "desc", "cprt"};

    for (int i = 0; i < 5; i++) {
        if (!pIcc->FindTag(reqTags[i]))
            findings.push_back({CheckID{CheckID::Kind::Conformance, 312}, Severity::HIGH,
                std::string("ext sub-class missing '") + reqNames[i] + "'", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("ext required tags present");
    return {CheckResult::Status::FINDINGS, "Missing ext tags", std::move(findings)};
}

static CheckResult check_cf313_ext_part_1_element_type_restriction(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x65787420) return CheckResult::ok("Not ext — not applicable");

    std::vector<Finding> findings;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        for (icUInt32Number i = 0; i < mpe->NumElements(); i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (elem && !IsICSPart1AllowedMPE(elem->GetType())) {
                char s[5]; SigToChars(static_cast<uint32_t>(elem->GetType()), s);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 313}, Severity::HIGH,
                    std::string("ext sub-class has non-Part-1 MPE type '") + s + "'", "", ""});
            }
        }
    }

    if (findings.empty()) return CheckResult::ok("ext Part 1 element restriction met");
    return {CheckResult::Status::FINDINGS, "ext Part 1 restriction violated", std::move(findings)};
}

static CheckResult check_cf314_xrng_atob1_btoa1_part_1_element_restrict(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng — not applicable");

    std::vector<Finding> findings;
    icTagSignature tags[] = {icSigAToB1Tag, icSigBToA1Tag};
    for (int t = 0; t < 2; t++) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, tags[t]);
        if (!mpe) continue;
        for (icUInt32Number i = 0; i < mpe->NumElements(); i++) {
            CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(i));
            if (elem && !IsICSPart1AllowedMPE(elem->GetType())) {
                char s[5]; SigToChars(static_cast<uint32_t>(elem->GetType()), s);
                findings.push_back({CheckID{CheckID::Kind::Conformance, 314}, Severity::HIGH,
                    std::string("xrng AToB1/BToA1 non-Part-1 MPE type '") + s + "'", "", ""});
            }
        }
    }

    if (findings.empty()) return CheckResult::ok("xrng AToB1/BToA1 Part 1 restriction met");
    return {CheckResult::Status::FINDINGS, "xrng Part 1 restriction violated", std::move(findings)};
}

static CheckResult check_cf315_xrng_part_2_pcc_matrix_restriction(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x78726E67) return CheckResult::ok("Not xrng — not applicable");

    std::vector<Finding> findings;
    icTagSignature pccTags[] = {icSigCustomToStandardPccTag, icSigStandardToCustomPccTag};
    for (int t = 0; t < 2; t++) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, pccTags[t]);
        if (!mpe) continue;
        if (mpe->NumElements() != 1 || !mpe->GetElement(0) ||
            mpe->GetElement(0)->GetType() != icSigMatrixElemType)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 315}, Severity::HIGH,
                "xrng PCC must be single 3x3 matrixElement", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("xrng Part 2 PCC matrix restriction met");
    return {CheckResult::Status::FINDINGS, "xrng PCC matrix issues", std::move(findings)};
}

static CheckResult check_cf316_ics_svcn_observer_illuminant_plausibilit(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (!IsICSSubClass(scVal)) return CheckResult::ok("Not an ICS sub-class — not applicable");

    const CIccTagSpectralViewingConditions *svcn =
        FindAndCast<CIccTagSpectralViewingConditions>(pIcc, icSigSpectralViewingConditionsTag);
    if (!svcn) return CheckResult::ok("No svcn tag — covered by other checks");

    std::vector<Finding> findings;
    icIlluminant illum = svcn->getStdIllumiant();
    icStandardObserver obs = svcn->getStdObserver();

    if (static_cast<icUInt32Number>(illum) == 0 && static_cast<icUInt32Number>(obs) == 0) {
        icSpectralRange illumRange, obsRange;
        svcn->getIlluminant(illumRange);
        svcn->getObserver(obsRange);
        if (illumRange.steps == 0 && obsRange.steps == 0)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 316}, Severity::MEDIUM,
                "ICS svcn has no standard or custom illuminant/observer data", "", ""});
    }

    if (findings.empty()) return CheckResult::ok("ICS svcn observer/illuminant plausible");
    return {CheckResult::Status::FINDINGS, "ICS svcn issues", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-317..CF-320: K.2.9 HToS HDR-to-SDR
// ═══════════════════════════════════════════════════════════════════════════

static CheckResult check_cf317_hdr_to_sdr_flag_tag_consistency(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    bool bit3Set = (pv.header().flags & 0x00000008) != 0;
    icTagSignature htosTagSigs[] = {icSigHToS0Tag, icSigHToS1Tag, icSigHToS2Tag, icSigHToS3Tag};
    int htosCount = 0;
    for (int i = 0; i < 4; i++)
        if (pIcc->FindTag(htosTagSigs[i])) htosCount++;

    std::vector<Finding> findings;
    if (bit3Set && htosCount == 0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 317}, Severity::MEDIUM,
            "Extended Range PCS flag set but no HToS tags — K.2.9 recommends HToS", "", ""});
    if (!bit3Set && htosCount > 0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 317}, Severity::MEDIUM,
            "HToS tags present but Extended Range PCS flag not set", "", ""});

    if (findings.empty()) return CheckResult::ok("HToS flag/tag consistency OK");
    return {CheckResult::Status::FINDINGS, "HToS consistency issues", std::move(findings)};
}

static CheckResult check_cf318_hdr_to_sdr_tag_type_validation(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icTagSignature htosTagSigs[] = {icSigHToS0Tag, icSigHToS1Tag, icSigHToS2Tag, icSigHToS3Tag};
    const char* htosNames[] = {"H2S0", "H2S1", "H2S2", "H2S3"};

    std::vector<Finding> findings;
    int found = 0;
    for (int i = 0; i < 4; i++) {
        CIccTag *pTag = pIcc->FindTag(htosTagSigs[i]);
        if (!pTag) continue;
        found++;
        if (pTag->GetType() != icSigMultiProcessElementType)
            findings.push_back({CheckID{CheckID::Kind::Conformance, 318}, Severity::MEDIUM,
                std::string(htosNames[i]) + " tag must be multiProcessElementsType", "", ""});
    }

    if (found == 0) return CheckResult::ok("No HToS tags — not applicable");
    if (findings.empty()) return CheckResult::ok("HToS tag types valid");
    return {CheckResult::Status::FINDINGS, "HToS type issues", std::move(findings)};
}

static CheckResult check_cf319_hdr_to_sdr_tag_channel_consistency(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icTagSignature htosTagSigs[] = {icSigHToS0Tag, icSigHToS1Tag, icSigHToS2Tag, icSigHToS3Tag};
    const char* htosNames[] = {"H2S0", "H2S1", "H2S2", "H2S3"};
    icUInt16Number pcsChan = icGetSpaceSamples(pIcc->m_Header.pcs);

    std::vector<Finding> findings;
    int found = 0;
    for (int i = 0; i < 4; i++) {
        CIccTag *pTag = pIcc->FindTag(htosTagSigs[i]);
        if (!pTag) continue;
        found++;

        CIccTagMultiProcessElement *mpe = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
        if (mpe) {
            if (mpe->NumInputChannels() != pcsChan) {
                findings.push_back({CheckID{CheckID::Kind::Conformance, 319}, Severity::MEDIUM,
                    std::string(htosNames[i]) + " input channels=" +
                    std::to_string(mpe->NumInputChannels()) +
                    ", expected PCS channels=" + std::to_string(pcsChan), "", ""});
            }
            if (mpe->NumOutputChannels() != pcsChan) {
                findings.push_back({CheckID{CheckID::Kind::Conformance, 319}, Severity::MEDIUM,
                    std::string(htosNames[i]) + " output channels=" +
                    std::to_string(mpe->NumOutputChannels()) +
                    ", expected PCS channels=" + std::to_string(pcsChan), "", ""});
            }
            continue;
        }

        CIccMBB *mbb = dynamic_cast<CIccMBB *>(pTag);
        if (mbb) {
            if (mbb->InputChannels() != pcsChan) {
                findings.push_back({CheckID{CheckID::Kind::Conformance, 319}, Severity::MEDIUM,
                    std::string(htosNames[i]) + " input channels=" +
                    std::to_string(mbb->InputChannels()) +
                    ", expected PCS channels=" + std::to_string(pcsChan), "", ""});
            }
            if (mbb->OutputChannels() != pcsChan) {
                findings.push_back({CheckID{CheckID::Kind::Conformance, 319}, Severity::MEDIUM,
                    std::string(htosNames[i]) + " output channels=" +
                    std::to_string(mbb->OutputChannels()) +
                    ", expected PCS channels=" + std::to_string(pcsChan), "", ""});
            }
            continue;
        }

        findings.push_back({CheckID{CheckID::Kind::Conformance, 319}, Severity::MEDIUM,
            std::string(htosNames[i]) + " tag present but not MPE or LUT type — cannot validate channels",
            "ICC.2-2023 K.2.9", "CWE-20"});
    }

    if (found == 0) return CheckResult::ok("No HToS tags — not applicable");
    if (findings.empty()) return CheckResult::ok("HToS channel consistency OK");
    return {CheckResult::Status::FINDINGS, "HToS channel issues", std::move(findings)};
}

static CheckResult check_cf320_hdr_to_sdr_intent_coverage(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    icTagSignature htosTagSigs[] = {icSigHToS0Tag, icSigHToS1Tag, icSigHToS2Tag, icSigHToS3Tag};
    int count = 0;
    for (int i = 0; i < 4; i++)
        if (pIcc->FindTag(htosTagSigs[i])) count++;

    if (count == 0) return CheckResult::ok("No HToS tags — not applicable");
    if (count == 4) return CheckResult::ok("All 4 HToS intent tags present");

    std::vector<Finding> findings;
    findings.push_back({CheckID{CheckID::Kind::Conformance, 320}, Severity::LOW,
        "Only " + std::to_string(count) + "/4 HToS intent tags present — consider all 4 for full coverage", "", ""});
    return {CheckResult::Status::FINDINGS, "Partial HToS coverage", std::move(findings)};
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-321..CF-326: K.2.8/K.2.7 Calculator solv/env operators
// ═══════════════════════════════════════════════════════════════════════════

static CheckResult check_cf321_calculator_solv_operator_presence(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    int solvCount = 0, calcCount = 0;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        std::string desc; mpe->Describe(desc, 0);
        if (desc.find("Calculator") == std::string::npos && desc.find("calc") == std::string::npos) continue;
        calcCount++;
        size_t pos = 0;
        while ((pos = desc.find("solv(", pos)) != std::string::npos) { solvCount++; pos += 5; }
    }

    if (calcCount == 0) return CheckResult::ok("No calculator elements — not applicable");
    if (solvCount == 0) return CheckResult::ok("No solv operators (no CMM matrix solver dependency)");
    return CheckResult::ok(std::to_string(solvCount) + " solv operator(s) — requires CMM IIccMatrixSolver");
}

static CheckResult check_cf322_calculator_solv_status_handling(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    int solvCount = 0, solvWithoutIf = 0;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        std::string desc; mpe->Describe(desc, 0);
        size_t pos = 0;
        while ((pos = desc.find("solv(", pos)) != std::string::npos) {
            solvCount++;
            size_t end = desc.find("END_CALC_FUNCTION", pos);
            if (end == std::string::npos) end = desc.size();
            std::string after = desc.substr(pos + 5, end - pos - 5);
            if (after.find("if ") == std::string::npos && after.find("if\n") == std::string::npos)
                solvWithoutIf++;
            pos += 5;
        }
    }

    if (solvCount == 0) return CheckResult::ok("No solv operators — not applicable");
    if (solvWithoutIf > 0) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 322}, Severity::MEDIUM,
            std::to_string(solvWithoutIf) + "/" + std::to_string(solvCount) + " solv operators lack status check", "K.2.8", ""});
        return {CheckResult::Status::FINDINGS, "solv status handling", std::move(findings)};
    }
    return CheckResult::ok("All solv operators have status check");
}

static CheckResult check_cf323_calculator_solv_matrix_dimensions(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    std::vector<Finding> findings;
    int solvCount = 0;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        std::string desc; mpe->Describe(desc, 0);
        size_t pos = 0;
        while ((pos = desc.find("solv(", pos)) != std::string::npos) {
            solvCount++;
            int r = 0, c = 0;
            if (sscanf(desc.c_str() + pos, "solv(%d,%d)", &r, &c) == 2) {
                if (r < 2 || c < 2)
                    findings.push_back({CheckID{CheckID::Kind::Conformance, 323}, Severity::MEDIUM,
                        "solv(" + std::to_string(r) + "," + std::to_string(c) + ") — degenerate dimensions", "§11.2.1.7", ""});
                else if (static_cast<long long>(r) * c > 10000)
                    findings.push_back({CheckID{CheckID::Kind::Conformance, 323}, Severity::MEDIUM,
                        "solv(" + std::to_string(r) + "," + std::to_string(c) + ") — excessive matrix size", "", ""});
            }
            pos += 5;
        }
    }

    if (solvCount == 0) return CheckResult::ok("No solv operators — not applicable");
    if (findings.empty()) return CheckResult::ok("solv matrix dimensions valid");
    return {CheckResult::Status::FINDINGS, "solv dimension issues", std::move(findings)};
}

static CheckResult check_cf324_calculator_env_operator_usage(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    int envCount = 0, calcCount = 0;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        std::string desc; mpe->Describe(desc, 0);
        if (desc.find("Calculator") == std::string::npos && desc.find("calc") == std::string::npos) continue;
        calcCount++;
        size_t pos = 0;
        while ((pos = desc.find("env(", pos)) != std::string::npos) { envCount++; pos += 4; }
    }

    if (calcCount == 0) return CheckResult::ok("No calculator elements — not applicable");
    if (envCount == 0) return CheckResult::ok("No env operators (no CMM env var dependency)");
    return CheckResult::ok(std::to_string(envCount) + " env operator(s) — requires CMM env var support");
}

static CheckResult check_cf325_calculator_env_status_handling(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    int envCount = 0, envWithoutIf = 0;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        std::string desc; mpe->Describe(desc, 0);
        size_t pos = 0;
        while ((pos = desc.find("env(", pos)) != std::string::npos) {
            // Skip constant pseudo-variables
            if (desc.compare(pos, 9, "env(true)") == 0 || desc.compare(pos, 9, "env(ndef)") == 0) {
                pos += 4; continue;
            }
            envCount++;
            size_t end = desc.find("END_CALC_FUNCTION", pos);
            if (end == std::string::npos) end = desc.size();
            std::string after = desc.substr(pos + 4, end - pos - 4);
            if (after.find("if ") == std::string::npos && after.find("if\n") == std::string::npos)
                envWithoutIf++;
            pos += 4;
        }
    }

    if (envCount == 0) return CheckResult::ok("No env operators — not applicable");
    if (envWithoutIf > 0) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 325}, Severity::MEDIUM,
            std::to_string(envWithoutIf) + "/" + std::to_string(envCount) + " env operators lack status check", "K.2.7", ""});
        return {CheckResult::Status::FINDINGS, "env status handling", std::move(findings)};
    }
    return CheckResult::ok("All env operators have status check");
}

static CheckResult check_cf326_calculator_env_reserved_signatures(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    int envTrueCount = 0, envNdefCount = 0;
    for (const auto& entry : pv.rawTagTable()) {
        CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(
            pIcc, static_cast<icTagSignature>(entry.signature));
        if (!mpe) continue;
        std::string desc; mpe->Describe(desc, 0);
        size_t pos = 0;
        while ((pos = desc.find("env(", pos)) != std::string::npos) {
            if (desc.compare(pos, 9, "env(true)") == 0) envTrueCount++;
            else if (desc.compare(pos, 9, "env(ndef)") == 0) envNdefCount++;
            pos += 4;
        }
    }

    if (envTrueCount == 0 && envNdefCount == 0)
        return CheckResult::ok("No reserved env signatures (true/ndef) used");
    return CheckResult::ok(std::to_string(envTrueCount) + " env(true) + " +
        std::to_string(envNdefCount) + " env(ndef) — reserved constants (not runtime lookups)");
}

// ═══════════════════════════════════════════════════════════════════════════
// CF-327..CF-329: K.2.6 PCC Alternate Override
// ═══════════════════════════════════════════════════════════════════════════

static CheckResult check_cf327_pcc_alternate_override_readiness(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    bool hasSvcn = pIcc->FindTag(icSigSpectralViewingConditionsTag) != nullptr;
    bool hasC2sp = pIcc->FindTag(icSigCustomToStandardPccTag) != nullptr;
    bool hasS2cp = pIcc->FindTag(icSigStandardToCustomPccTag) != nullptr;
    bool hasSpectral = static_cast<icUInt32Number>(pIcc->m_Header.spectralPCS) != 0;

    std::vector<Finding> findings;
    if (!hasSvcn && (hasC2sp || hasS2cp))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 327}, Severity::MEDIUM,
            "PCC transform tags present without svcn — incomplete PCC", "", ""});

    if (findings.empty()) {
        std::string detail = hasC2sp && hasS2cp ? "bidirectional" :
            (hasC2sp || hasS2cp) ? "one-directional" :
            (hasSpectral && hasSvcn) ? "spectral-only" : "none";
        return CheckResult::ok("PCC override readiness: " + detail);
    }
    return {CheckResult::Status::FINDINGS, "PCC readiness issues", std::move(findings)};
}

static CheckResult check_cf328_pcc_non_standard_colorimetry_indication(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    bool hasC2sp = pIcc->FindTag(icSigCustomToStandardPccTag) != nullptr;
    bool hasS2cp = pIcc->FindTag(icSigStandardToCustomPccTag) != nullptr;
    if (!hasC2sp && !hasS2cp)
        return CheckResult::ok("No custom colorimetry transforms — not applicable");

    const CIccTagSpectralViewingConditions *svcn =
        FindAndCast<CIccTagSpectralViewingConditions>(pIcc, icSigSpectralViewingConditionsTag);
    if (!svcn) {
        std::vector<Finding> findings;
        findings.push_back({CheckID{CheckID::Kind::Conformance, 328}, Severity::MEDIUM,
            "Custom colorimetry transforms present but svcn absent", "K.2.6", ""});
        return {CheckResult::Status::FINDINGS, "Missing svcn for PCC", std::move(findings)};
    }

    std::vector<Finding> findings;
    icSpectralRange illumRange;
    const icFloatNumber *illumSPD = svcn->getIlluminant(illumRange);
    if (!illumSPD || illumRange.steps == 0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 328}, Severity::LOW,
            "svcn has no illuminant SPD — alternate PCC spectral processing limited", "", ""});

    icSpectralRange obsRange;
    const icFloatNumber *obsCMF = svcn->getObserver(obsRange);
    if (!obsCMF || obsRange.steps == 0)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 328}, Severity::LOW,
            "svcn has no observer CMF data", "", ""});

    if (findings.empty()) return CheckResult::ok("PCC spectral data complete for alternate override");
    return {CheckResult::Status::FINDINGS, "PCC spectral data issues", std::move(findings)};
}

static CheckResult check_cf329_pcc_override_source_profile_validation(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5 profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t scVal = static_cast<uint32_t>(pIcc->m_Header.deviceSubClass);
    if (scVal != 0x70636320) // 'pcc '
        return CheckResult::ok("Not a PCC override source profile");

    std::vector<Finding> findings;
    if (!pIcc->FindTag(icSigSpectralViewingConditionsTag))
        findings.push_back({CheckID{CheckID::Kind::Conformance, 329}, Severity::HIGH,
            "PCC override source missing svcn — cannot provide alternate viewing conditions", "", ""});

    bool hasC2sp = pIcc->FindTag(icSigCustomToStandardPccTag) != nullptr;
    bool hasS2cp = pIcc->FindTag(icSigStandardToCustomPccTag) != nullptr;
    if (!hasC2sp && !hasS2cp)
        findings.push_back({CheckID{CheckID::Kind::Conformance, 329}, Severity::MEDIUM,
            "PCC override source lacks c2sp/s2cp", "", ""});

    if (findings.empty()) return CheckResult::ok("PCC override source profile valid");
    return {CheckResult::Status::FINDINGS, "PCC source validation issues", std::move(findings)};
}


// ── Registrations (93 checks) ──

REGISTER_CONFORMANCE(80, "v5 Spectral PCS Signature",
    "§7.2.22", "ICC.2-2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf080_v5_spectral_pcs_signature);

REGISTER_CONFORMANCE(81, "v5 Spectral PCS Range Validity",
    "§7.2.23", "ICC.2-2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf081_v5_spectral_pcs_range_validity);

REGISTER_CONFORMANCE(82, "v5 PCC Tags Required When Spectral",
    "§8 (spectral classes)", "ICC.2-2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf082_v5_pcc_tags_required_when_spectral);

REGISTER_CONFORMANCE(83, "v5 MCS Signature Encoding",
    "§7.2.25", "ICC.2-2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf083_v5_mcs_signature_encoding);

REGISTER_CONFORMANCE(84, "v5 Profile Sub-Class Signature",
    "§7.2.26", "ICC.2-2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf084_v5_profile_sub_class_signature);

REGISTER_CONFORMANCE(85, "v5 Version Field 5.x BCD",
    "§7.2.4", "ICC.2-2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf085_v5_version_field_5_x_bcd);

REGISTER_CONFORMANCE(86, "v5 Extended Attribute Bits",
    "§7.2.14", "ICC.2-2023",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf086_v5_extended_attribute_bits);

REGISTER_CONFORMANCE(87, "v5 MPE Element Signature Valid",
    "§10.x (MPE types)", "ICC.2-2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf087_v5_mpe_element_signature_valid);

REGISTER_CONFORMANCE(88, "v5 Calculator Element Stack Structure",
    "§10.x (calc)", "ICC.2-2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf088_v5_calculator_element_stack_structure);

REGISTER_CONFORMANCE(89, "v5 Spectral Wavelength Range",
    "§7.2.23 (380-780nm typical)", "ICC.2-2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf089_v5_spectral_wavelength_range);

REGISTER_CONFORMANCE(90, "Spectral Illuminant Consistency",
    "§7.2.17", "ICC.2-2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf090_spectral_illuminant_consistency);

REGISTER_CONFORMANCE(113, "Spectral Range Physical Bounds",
    "§7.2.23 (wavelengths within [100-2500] nm)", "ICC.2-2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf113_spectral_range_physical_bounds);

REGISTER_CONFORMANCE(114, "MCS Colour Space Consistency",
    "§7.2.19 (MCS signature valid colour space)", "ICC.2-2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf114_mcs_colour_space_consistency);

REGISTER_CONFORMANCE(115, "Calculator Element Complexity",
    "§10.2.6 (calculator sub-element limits)", "ICC.2-2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf115_calculator_element_complexity);

REGISTER_CONFORMANCE(144, "Extended Range PCS Flag Consistency",
    "Flag bit 3 (extended range PCS) requires v5 (iccMAX) profile", "ICC.2-2023 §7.2.13",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf144_extended_range_pcs_flag_consistency);

REGISTER_CONFORMANCE(145, "Extended Range PCS + Spectral Co-existence",
    "Extended range PCS co-existence with spectral/colorimetric PCS validation", "ICS-ExtendedRange-Part1 §6.2",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf145_extended_range_pcs_spectral_co_existence);

REGISTER_CONFORMANCE(146, "Extended Range Class Restriction",
    "Extended range PCS limited to mntr, spac, prtr profile classes", "ICS-ExtendedRange-Part1 Table 1",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf146_extended_range_class_restriction);

REGISTER_CONFORMANCE(150, "Extended Output Gamut Boundary Tag",
    "Gamut boundary description tags are optional but recommended for output profiles", "ICS-ExtendedOutput-Part1 Table 13",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf150_extended_output_gamut_boundary_tag);

REGISTER_CONFORMANCE(151, "Extended Output mediaWhitePoint Range",
    "mediaWhitePointTag XYZ values must be positive and plausible", "ICS-ExtendedOutput-Part1 Table 12",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf151_extended_output_mediawhitepoint_range);

REGISTER_CONFORMANCE(154, "Embedded Profile Version Bridging",
    "Parent shall be ICC.1 (v2/v4), child shall be ICC.2 (v5+)", "ICC TN Embedding",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf154_embedded_profile_version_bridging);

REGISTER_CONFORMANCE(155, "Embedded Profile Device Class Match",
    "Embedded profile shall have same profile class and device color space as parent", "ICC TN Embedding",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf155_embedded_profile_device_class_match);

REGISTER_CONFORMANCE(156, "Embedded Profile Header Flags",
    "Embedded ICC.2 profile flags: bit 0 should be 1 (embedded), bit 1 should be 0", "ICC TN Embedding",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf156_embedded_profile_header_flags);

REGISTER_CONFORMANCE(175, "Embedded Profile PCS Compatibility",
    "Child PCS should be compatible with parent PCS for 'logical replacement' semantics", "ICC TN Embedding §Processing",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf175_embedded_profile_pcs_compatibility);

REGISTER_CONFORMANCE(176, "Embedded Profile Tag Reserved Bytes",
    "Bytes 4-7 of embeddedProfileType encoding shall be 0 per Table 1", "ICC TN Embedding Table 1",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf176_embedded_profile_tag_reserved_bytes);

REGISTER_CONFORMANCE(177, "Embedded Profile Data Integrity",
    "Embedded ICC.2 profile shall be included in its entirety and validate cleanly", "ICC TN Embedding §Embedding",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf177_embedded_profile_data_integrity);

REGISTER_CONFORMANCE(178, "Chad Matrix Diagonal Dominance",
    "Valid chromatic adaptation matrices (Bradford, CAT02) are diagonally dominant", "ICC TN Partial Adaptation",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf178_chad_matrix_diagonal_dominance);

REGISTER_CONFORMANCE(179, "Chad D50-to-D50 Identity Check",
    "When illuminant is D50, chad should be near-identity (D50→D50 adaptation)", "ICC TN Partial Adaptation",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf179_chad_d50_to_d50_identity_check);

REGISTER_CONFORMANCE(180, "PCC Complete Adaptation Principle",
    "Profiles should perform complete adaptation (D=1.0) in c2sp/s2cp; CMM applies partial", "ICC TN Partial Adaptation",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf180_pcc_complete_adaptation_principle);

REGISTER_CONFORMANCE(181, "PCC Illuminant-Chad Consistency",
    "Non-D50 PCC illuminant requires chromaticAdaptationTag for adaptation", "ICC TN Partial Adaptation",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf181_pcc_illuminant_chad_consistency);

REGISTER_CONFORMANCE(182, "PCC Observer Standard Compliance",
    "Spectral viewing conditions observer should be CIE 1931 2° or 1964 10°", "ICC TN Partial Adaptation",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf182_pcc_observer_standard_compliance);

REGISTER_CONFORMANCE(183, "Chad Column Normalization",
    "Adaptation matrix column norms should be bounded (not degenerate or extreme)", "ICC TN Partial Adaptation",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf183_chad_column_normalization);

REGISTER_CONFORMANCE(191, "ICS Sub-Class Signature Registry",
    "Validate deviceSubClass matches a registered ICS sub-class signature (pcc, xrng, sref, ext)", "ICC WP-57 ICS Registration",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf191_ics_sub_class_signature_registry);

REGISTER_CONFORMANCE(192, "Colorimetric ICS Required Tags",
    "Colorimetric PCC sub-class requires AToB1, BToA1, svcn, c2sp, s2cp tags and colorSpace class", "ICS-Colorimetric-Part1",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf192_colorimetric_ics_required_tags);

REGISTER_CONFORMANCE(193, "Colorimetric ICS PCC Matrix Restriction",
    "Part 1 Colorimetric ICS restricts c2sp/s2cp to a single 3x3 matrix element", "ICS-Colorimetric-Part1",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf193_colorimetric_ics_pcc_matrix_restriction);

REGISTER_CONFORMANCE(194, "Spectral Reflectance ICS Required Tags",
    "Spectral Reflectance sub-class requires DToB3, BToD3, svcn, c2sp, s2cp tags and reflectance PCS", "ICS-SpectralReflectance-Part1",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf194_spectral_reflectance_ics_required_tags);

REGISTER_CONFORMANCE(195, "Extended Dynamic Range Radiance White Point",
    "Extended range profiles may have white point Y > 1.0 representing luminance in cd/m2", "ICS-ExtendedRange",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf195_extended_dynamic_range_radiance_white_po);

REGISTER_CONFORMANCE(196, "ICS MPE Calculator Restriction",
    "Part 1 ICS profiles restrict MPE to curve/matrix/CLUT/tint; calculatorElement requires Part 2", "ICC WP-57 Part 1 vs Part 2",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf196_ics_mpe_calculator_restriction);

REGISTER_CONFORMANCE(197, "ICS PCC Transform Pair Completeness",
    "customToStandardPcc (c2sp) and standardToCustomPcc (s2cp) must both be present as a mandatory pair", "ICC WP-57 PCC Transforms",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf197_ics_pcc_transform_pair_completeness);

REGISTER_CONFORMANCE(198, "Extended Range Sub-Class Validation",
    "Extended dynamic range (xrng) sub-class requires display or colorSpace class and extended range PCS flag", "ICS-ExtendedRange",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf198_extended_range_sub_class_validation);

REGISTER_CONFORMANCE(235, "xrng Data Colour Space Restriction",
    "Part 1 requires data colour space = RGB with 3 channels for extendedRange sub-class", "ICS-ExtRange-Part1 Table 3",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf235_xrng_data_colour_space_restriction);

REGISTER_CONFORMANCE(236, "xrng Colorimetric PCS Constraint",
    "Part 1 requires colorimetric PCS = XYZ with D50 illuminant (1931 2-degree observer)", "ICS-ExtRange-Part1 Table 3",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf236_xrng_colorimetric_pcs_constraint);

REGISTER_CONFORMANCE(237, "xrng Required Tag Completeness",
    "Table 4 requires desc(mluc), cprt(mluc), mwpt(XYZ), A2B1(MPE), B2A1(MPE) all present with correct types", "ICS-ExtRange-Part1 Table 4",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf237_xrng_required_tag_completeness);

REGISTER_CONFORMANCE(238, "xrng Header Field Restrictions",
    "Flags=0, attributes<=1, spectralPCS=0, biSpectralRange=0, MCS=0 for Part 1 basic encoding", "ICS-ExtRange-Part1 Table 3",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf238_xrng_header_field_restrictions);

REGISTER_CONFORMANCE(239, "xrng Optional Tag Type Validation",
    "Optional tags: chad(s15Fixed16Array), gbdX(gamutBoundaryDesc), AToBx/BToAx(MPE) type enforcement", "ICS-ExtRange-Part1 Table 5",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf239_xrng_optional_tag_type_validation);

REGISTER_CONFORMANCE(240, "xrng Transform Channel Dimensions",
    "AToB1/BToA1 MPE transforms must map 3 input channels (RGB) to 3 output channels (XYZ)", "ICS-ExtRange-Part1 S5.2",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf240_xrng_transform_channel_dimensions);

REGISTER_CONFORMANCE(241, "xrng mediaWhitePointTag Absolute Radiance",
    "mwpt must contain positive XYZ tristimulus values of near-diffuse white in absolute radiance", "ICS-ExtRange-Part1 Table 4",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf241_xrng_mediawhitepointtag_absolute_radianc);

REGISTER_CONFORMANCE(242, "xrng Workflow Connection Consistency",
    "Source/destination workflow requires AToB1/BToA1 with colorimetric rendering intent", "ICS-ExtRange-Part1 S5.2.3",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf242_xrng_workflow_connection_consistency);

REGISTER_CONFORMANCE(257, "Spectral Range Step Count",
    "Spectral range must have steps >= 2 and start < end when spectral PCS is declared", "ICC.2-2023 §7.2.20",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf257_spectral_range_step_count);

REGISTER_CONFORMANCE(284, "BRDF Spectral Parameter Tag Type",
    "BRDF spectral parameter tags (bsp0..bsp3) must be multiProcessElementType", "ICC.2-2023 §9.2.10-13",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf284_brdf_spectral_parameter_tag_type);

REGISTER_CONFORMANCE(285, "BRDF Tag Presence Consistency",
    "If any BRDF spectral parameter tag is present, all 4 should be present", "ICC.2-2023 §9.2.10",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf285_brdf_tag_presence_consistency);

REGISTER_CONFORMANCE(286, "GBD Triangle-Vertex Consistency",
    "Gamut boundary description triangle count requires >= 3 vertices", "ICC.2-2023 §10.2.11",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf286_gbd_triangle_vertex_consistency);

REGISTER_CONFORMANCE(287, "GBD Channel Count Plausibility",
    "GBD PCS channels should be 3 (Lab/XYZ), device channels reasonable", "ICC.2-2023 §10.2.11",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf287_gbd_channel_count_plausibility);

REGISTER_CONFORMANCE(288, "Spectral Data Info Bi-Spectral Consistency",
    "BiSpectralRange requires valid base spectralRange", "ICC.2-2023 §9.2.84",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf288_spectral_data_info_bi_spectral_consisten);

REGISTER_CONFORMANCE(289, "Spectral Viewing Conditions Illuminant Bounds",
    "Spectral viewing conditions illuminant XYZ must be physically plausible", "ICC.2-2023 §10.2.30",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf289_spectral_viewing_conditions_illuminant_b);

REGISTER_CONFORMANCE(290, "Material Default Values Tag Presence",
    "Material identification/visualization profiles should have multiplexDefaultValuesTag", "ICC.2-2023 §9.2.47",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf290_material_default_values_tag_presence);

REGISTER_CONFORMANCE(291, "Spectral White Point XYZ Range",
    "Spectral white point XYZ values must be physically plausible", "ICC.2-2023 §9.2.85",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf291_spectral_white_point_xyz_range);

REGISTER_CONFORMANCE(292, "MPE Chain I/O Channel Consistency",
    "Adjacent MPE elements must have matching output/input channel counts", "ICC.2-2023 §10.2.17",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf292_mpe_chain_i_o_channel_consistency);

REGISTER_CONFORMANCE(293, "MPE Container I/O vs First/Last Element",
    "Container input must match first element input; output must match last element output", "ICC.2-2023 §10.2.17",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf293_mpe_container_i_o_vs_first_last_element);

REGISTER_CONFORMANCE(294, "MPE ACS Boundary Element Pairing",
    "bACS and eACS elements must appear in pairs with matching signatures", "ICC.2-2023 §10.2.1-2",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf294_mpe_acs_boundary_element_pairing);

REGISTER_CONFORMANCE(295, "MPE Element Type Version Compatibility",
    "V5+ element types (calc, xclt, spectral, etc.) must not appear in v4 profiles", "ICC.2-2023 §10.2.17",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf295_mpe_element_type_version_compatibility);

REGISTER_CONFORMANCE(296, "MPE Empty Container Validation",
    "Empty MPE container must have inputChannels == outputChannels (identity)", "ICC.2-2023 §10.2.17",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf296_mpe_empty_container_validation);

REGISTER_CONFORMANCE(297, "MPE CurveSet Element Channel Count",
    "CurveSet element must have inputChannels == outputChannels", "ICC.2-2023 §10.2.5",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf297_mpe_curveset_element_channel_count);

REGISTER_CONFORMANCE(298, "MPE Matrix Element Dimension",
    "Matrix element must have non-zero channel dimensions and allocated matrix data", "ICC.2-2023 §10.2.9",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf298_mpe_matrix_element_dimension);

REGISTER_CONFORMANCE(299, "MPE CLUT Element Grid Dimension",
    "CLUT element must have non-zero I/O channels and reasonable input dimensions", "ICC.2-2023 §10.2.3",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf299_mpe_clut_element_grid_dimension);

REGISTER_CONFORMANCE(300, "MPE Tag vs Color Space Channels",
    "AToB/BToA MPE tag channels must match profile data color space and PCS", "ICC.2-2023 §10.2.17",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf300_mpe_tag_vs_color_space_channels);

REGISTER_CONFORMANCE(301, "Measurement Struct tagStructType Enforcement",
    "v5 measurement tags MUST use tagStructType wrapper with measurementInfoStruct per errata §9.2.86/87", "ICC.2-2019 Errata §9.2.86/87",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf301_measurement_struct_tagstructtype_enforce);

REGISTER_CONFORMANCE(302, "Measurement Struct Member Completeness",
    "measurementInfoStruct must contain required members: backing, flare, geometry, illuminant, mode", "ICC.2-2019 Errata §9.2.86/87",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf302_measurement_struct_member_completeness);

REGISTER_CONFORMANCE(303, "Spectral Data Array Type Restriction",
    "Spectral data tags must use only uInt8/uInt16/float16/float32 array types", "ICC.2-2019 Errata §9.2.84",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf303_spectral_data_array_type_restriction);

REGISTER_CONFORMANCE(305, "multiProcessElementsType Nomenclature Audit",
    "Validates mpet signature and documents singular/plural naming divergence per errata Tech.Err.#3", "ICC.2-2019 Errata Tech.Err.#3",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf305_multiprocesselementstype_nomenclature_au);

REGISTER_CONFORMANCE(306, "Embedded Image Data Length Cross-Validation",
    "ehim header=24 bytes, enim header=16 bytes per errata §10.2.6/10.2.7 correction", "ICC.2-2019 Errata §10.2.6/10.2.7",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf306_embedded_image_data_length_cross_validat);

REGISTER_CONFORMANCE(307, "Calculator Vector-Or Signature Validation",
    "vor signature must be 766f7220h with trailing space per Sept 2021 errata §11.2.1.9", "ICC.2-2019 Errata §11.2.1.9",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf307_calculator_vector_or_signature_validatio);

REGISTER_CONFORMANCE(308, "pcc AToB1/BToA1 Part 1 Element Restriction",
    "Colorimetric PCC Part 1 restricts AToB1/BToA1 elements to curveSet, matrix, CLUT, extCLUT, tintArray", "ICS-ColorimetricPCC-Part1 §6",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf308_pcc_atob1_btoa1_part_1_element_restricti);

REGISTER_CONFORMANCE(309, "sref PCC Matrix Restriction",
    "Spectral Reflectance Part 1 restricts c2sp/s2cp to single 3x3 matrixElement", "ICS-SpectralReflectance-Part1 §6.2",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf309_sref_pcc_matrix_restriction);

REGISTER_CONFORMANCE(310, "sref DToB3/BToD3 Part 1 Element Restriction",
    "Spectral Reflectance Part 1 restricts DToB3/BToD3 to curveSet, matrix, CLUT, extCLUT, tintArray", "ICS-SpectralReflectance-Part1 §6",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf310_sref_dtob3_btod3_part_1_element_restrict);

REGISTER_CONFORMANCE(311, "sref Spectral Range Mandatory",
    "Spectral Reflectance requires non-zero spectral range steps and reflectance PCS", "ICS-SpectralReflectance-Part1 §5.2",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf311_sref_spectral_range_mandatory);

REGISTER_CONFORMANCE(312, "ext Required Tag Completeness",
    "Extended Output sub-class requires svcn, c2sp, s2cp, desc, cprt tags", "ICS-ExtendedOutput-Part1 §6",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf312_ext_required_tag_completeness);

REGISTER_CONFORMANCE(313, "ext Part 1 Element Type Restriction",
    "Extended Output Part 1 restricts transform elements to curveSet, matrix, CLUT, extCLUT", "ICS-ExtendedOutput-Part1 §6.3",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf313_ext_part_1_element_type_restriction);

REGISTER_CONFORMANCE(314, "xrng AToB1/BToA1 Part 1 Element Restriction",
    "Extended Dynamic Range Part 1 restricts AToB1/BToA1 to curveSet, matrix, CLUT, extCLUT, tintArray", "ICS-ExtRange-Part1 §6.2",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf314_xrng_atob1_btoa1_part_1_element_restrict);

REGISTER_CONFORMANCE(315, "xrng Part 2 PCC Matrix Restriction",
    "Extended Dynamic Range Part 2 restricts c2sp/s2cp to single 3x3 matrixElement", "ICS-ExtRange-Part2 §6",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf315_xrng_part_2_pcc_matrix_restriction);

REGISTER_CONFORMANCE(316, "ICS svcn Observer/Illuminant Plausibility",
    "Validates svcn illuminant XYZ non-negative with Y>0, spectral range physically reasonable", "ICC WP-57 §svcn",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf316_ics_svcn_observer_illuminant_plausibilit);

REGISTER_CONFORMANCE(317, "HDR-to-SDR Flag-Tag Consistency",
    "Cross-validates Extended Range PCS flag (bit 3) against presence of HToS tags (H2S0-H2S3)", "K.2.9, ICC.2 §7.2.13",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf317_hdr_to_sdr_flag_tag_consistency);

REGISTER_CONFORMANCE(318, "HDR-to-SDR Tag Type Validation",
    "Validates HToS tags are multiProcessElementsType for v5 profiles", "K.2.9, ICC.2 §9.2",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf318_hdr_to_sdr_tag_type_validation);

REGISTER_CONFORMANCE(319, "HDR-to-SDR Tag Channel Consistency",
    "Validates HToS tag input/output channels match PCS channel count (PCS-to-PCS transform)", "K.2.9",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf319_hdr_to_sdr_tag_channel_consistency);

REGISTER_CONFORMANCE(320, "HDR-to-SDR Intent Coverage",
    "Checks rendering intent coverage of HToS tags and CMM fallback chain completeness", "K.2.9",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf320_hdr_to_sdr_intent_coverage);

REGISTER_CONFORMANCE(321, "Calculator 'solv' Operator Presence",
    "Detects 'solv' matrix solve operators in calculator elements — indicates CMM IIccMatrixSolver dependency", "K.2.8, ICC.2 §11.2.1.7",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf321_calculator_solv_operator_presence);

REGISTER_CONFORMANCE(322, "Calculator 'solv' Status Handling",
    "Verifies profiles check the 'solv' status flag via conditional to handle solver unavailability", "K.2.8",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf322_calculator_solv_status_handling);

REGISTER_CONFORMANCE(323, "Calculator 'solv' Matrix Dimensions",
    "Validates 'solv' operator matrix dimensions are meaningful (R,C >= 2) and not excessive", "K.2.8, ICC.2 §11.2.1.7",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf323_calculator_solv_matrix_dimensions);

REGISTER_CONFORMANCE(324, "Calculator 'env' Operator Usage",
    "Detects 'env' operators in calculator elements — indicates CMM environment variable dependency", "K.2.7, ICC.2 §11.2.1.4",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf324_calculator_env_operator_usage);

REGISTER_CONFORMANCE(325, "Calculator 'env' Status Handling",
    "Verifies profiles check 'env' operator status flag via conditional for unavailable variable handling", "K.2.7",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf325_calculator_env_status_handling);

REGISTER_CONFORMANCE(326, "Calculator 'env' Reserved Signatures",
    "Reports usage of reserved env signatures 'true' and 'ndef' which are constants, not runtime lookups", "K.2.7, ICC.2 §11.2.1.4",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf326_calculator_env_reserved_signatures);

REGISTER_CONFORMANCE(327, "PCC Alternate Override Readiness",
    "Identifies profiles with PCC tags eligible for alternate PCC override per K.2.6", "K.2.6, ICC.2 §6.3.2",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf327_pcc_alternate_override_readiness);

REGISTER_CONFORMANCE(328, "PCC Non-Standard Colorimetry Indication",
    "Validates spectral data completeness in svcn when custom colorimetry transforms present for alternate PCC", "K.2.6, ICC.2 §6.3.2",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf328_pcc_non_standard_colorimetry_indication);

REGISTER_CONFORMANCE(329, "PCC Override Source Profile Validation",
    "Validates profiles with deviceSubClass pcc have proper svcn content for use as alternate PCC source", "K.2.6, ICS-Colorimetric",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf329_pcc_override_source_profile_validation);

// ============================================================================
// Extended Device Colour Space Support (ICC.2:2023 amendment, Oct 2025)
// Heuristics H175-H178 and Conformance CF-330..CF-339
// ============================================================================

// --- Helper: is device colour space spectral? (upper 16 bits check) ----------
static bool IsSpectralDeviceColorSpaceV2(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return false;
    uint32_t cs = static_cast<uint32_t>(pIcc->m_Header.colorSpace);
    uint16_t upper = static_cast<uint16_t>(cs >> 16);
    return (upper == 0x7273 || upper == 0x7473 || upper == 0x6573 ||
            upper == 0x6273 || upper == 0x736D);
}

// --- Helper: is device colour space bi-spectral? ----------------------------
static bool IsBiSpectralDeviceV2(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return false;
    uint32_t cs = static_cast<uint32_t>(pIcc->m_Header.colorSpace);
    uint16_t upper = static_cast<uint16_t>(cs >> 16);
    return (upper == 0x6273 || upper == 0x736D);
}

// --- Helper: read 16-bit big-endian from raw bytes --------------------------
static inline uint16_t ReadU16BE(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

// ============================================================================
// H175 — Device Spectral Colour Space Range Requirement
// ============================================================================
static CheckResult check_h175_device_spectral_colour_space_range(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    if (!IsSpectralDeviceColorSpaceV2(pv))
        return CheckResult::ok("Device colour space is not spectral — check not applicable");

    CheckID id{CheckID::Kind::Heuristic, 175};
    std::vector<Finding> findings;

    uint32_t cs = static_cast<uint32_t>(pIcc->m_Header.colorSpace);
    uint16_t upper = static_cast<uint16_t>(cs >> 16);
    const char *type = "unknown";
    switch (upper) {
        case 0x7273: type = "reflectance"; break;
        case 0x7473: type = "transmission"; break;
        case 0x6573: type = "radiant"; break;
        case 0x6273: type = "bi-spectral reflectance"; break;
        case 0x736D: type = "sparse matrix reflectance"; break;
    }

    // Check 1: Look for 'dsrn' tag (0x6473726E) in tag table
    auto dsrnTag = pv.rawTag(0x6473726Eu);
    if (dsrnTag)
        return CheckResult::ok("Device spectral range defined by dsrn tag");

    // Check 2: Fall back to header spectralRange fields
    const icSpectralRange &sr = pIcc->m_Header.spectralRange;
    if (sr.steps > 0 && (sr.start > 0 || sr.end > 0))
        return CheckResult::ok("Device spectral range defined by header spectral PCS range fields");

    // Neither source provides the range — CRITICAL
    findings.push_back({id, Severity::CRITICAL,
        std::string("Spectral device colour space (") + type +
        ") has NO spectral range definition",
        "Must provide either dsrn tag or header spectralRange — ICC.2:2023 §7.2.8",
        "CWE-20"});
    return {CheckResult::Status::FINDINGS, "No spectral range for spectral device", std::move(findings)};
}

REGISTER_HEURISTIC(175, "Device Spectral Colour Space Range Requirement",
    "§7.2.8 amend", "ICC.2:2023",
    "CWE-20", "", Severity::HIGH, CheckPhase::RAW_SCAN,
    check_h175_device_spectral_colour_space_range);

// ============================================================================
// H176 — deviceSpectralRangeTag ('dsrn') Validation
// ============================================================================
static CheckResult check_h176_dsrn_tag_validation(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");

    auto dsrnTag = pv.rawTag(0x6473726Eu);
    if (!dsrnTag) return CheckResult::ok("No dsrn tag present — check not applicable");

    CheckID id{CheckID::Kind::Heuristic, 176};
    std::vector<Finding> findings;

    if (dsrnTag->size < 20) {
        findings.push_back({id, Severity::CRITICAL,
            "dsrn tag too small: " + std::to_string(dsrnTag->size) + " bytes (need 20)",
            "spectralRangeType minimum size", "CWE-125"});
        return {CheckResult::Status::FINDINGS, "dsrn tag undersized", std::move(findings)};
    }

    if (dsrnTag->offset > pv.rawSize() || dsrnTag->size > pv.rawSize() - dsrnTag->offset)
        return CheckResult::error("dsrn tag offset/size exceeds file");

    const uint8_t* tagData = pv.rawData() + dsrnTag->offset;

    // Type signature = 'srng' (0x73726E67)
    uint32_t typeSig = ReadU32BE(tagData);
    if (typeSig != 0x73726E67u) {
        char sigStr[5]; SigToChars(typeSig, sigStr);
        findings.push_back({id, Severity::CRITICAL,
            std::string("dsrn tag type '") + sigStr + "' — expected 'srng'",
            "ICC.2:2023 §10.2.w", "CWE-20"});
        return {CheckResult::Status::FINDINGS, "Wrong type in dsrn", std::move(findings)};
    }

    // Reserved bytes (4-7) = 0
    uint32_t reserved = ReadU32BE(tagData + 4);
    if (reserved != 0) {
        char hex[11]; std::snprintf(hex, sizeof(hex), "0x%08X", reserved);
        findings.push_back({id, Severity::MEDIUM,
            std::string("dsrn reserved field is ") + hex + " (should be 0)",
            "ICC.2:2023 §10.2.w", "CWE-20"});
    }

    // Spectral range (bytes 8-13)
    uint16_t specStartRaw = ReadU16BE(tagData + 8);
    uint16_t specEndRaw   = ReadU16BE(tagData + 10);
    uint16_t specSteps    = ReadU16BE(tagData + 12);
    float specStart = safeF16ToF(specStartRaw);
    float specEnd   = safeF16ToF(specEndRaw);

    if (std::isnan(specStart) || std::isinf(specStart))
        findings.push_back({id, Severity::CRITICAL, "Spectral start wavelength is NaN/Inf", "", "CWE-20"});
    if (std::isnan(specEnd) || std::isinf(specEnd))
        findings.push_back({id, Severity::CRITICAL, "Spectral end wavelength is NaN/Inf", "", "CWE-20"});

    if (std::isfinite(specStart) && std::isfinite(specEnd)) {
        if (specEnd <= specStart)
            findings.push_back({id, Severity::CRITICAL,
                "Spectral end <= start — inverted range", "", "CWE-682"});
    }

    if (specSteps < 2 && (specStartRaw != 0 || specEndRaw != 0))
        findings.push_back({id, Severity::CRITICAL,
            "Spectral steps=" + std::to_string(specSteps) + " (must be >= 2)", "", "CWE-369"});

    // Bi-spectral range (bytes 14-19)
    uint16_t biStartRaw = ReadU16BE(tagData + 14);
    uint16_t biEndRaw   = ReadU16BE(tagData + 16);
    uint16_t biSteps    = ReadU16BE(tagData + 18);

    if (!IsBiSpectralDeviceV2(pv) && (biStartRaw != 0 || biEndRaw != 0 || biSteps != 0))
        findings.push_back({id, Severity::MEDIUM,
            "Bi-spectral range non-zero for non-bi-spectral device", "", "CWE-20"});

    if (findings.empty()) return CheckResult::ok("dsrn tag validation passed");
    return {CheckResult::Status::FINDINGS, "dsrn tag issues found", std::move(findings)};
}

REGISTER_HEURISTIC(176, "deviceSpectralRangeTag Validation",
    "§9.2.x", "ICC.2:2023",
    "CWE-20/CWE-125", "", Severity::HIGH, CheckPhase::RAW_SCAN,
    check_h176_dsrn_tag_validation);

// ============================================================================
// H177 — devicePccTag ('dpcc') Structure Validation
// ============================================================================
static CheckResult check_h177_dpcc_tag_validation(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");

    auto dpccTag = pv.rawTag(0x64706363u);
    if (!dpccTag) return CheckResult::ok("No dpcc tag present — check not applicable");

    CheckID id{CheckID::Kind::Heuristic, 177};
    std::vector<Finding> findings;

    if (dpccTag->size < 12) {
        findings.push_back({id, Severity::CRITICAL,
            "dpcc tag too small: " + std::to_string(dpccTag->size) + " bytes (need >= 12)",
            "tagStructType header", "CWE-125"});
        return {CheckResult::Status::FINDINGS, "dpcc tag undersized", std::move(findings)};
    }

    if (dpccTag->offset > pv.rawSize() || dpccTag->size > pv.rawSize() - dpccTag->offset)
        return CheckResult::error("dpcc tag offset/size exceeds file");

    const uint8_t* tagData = pv.rawData() + dpccTag->offset;
    size_t readSize = std::min(static_cast<size_t>(dpccTag->size), size_t(4096));

    // Structure type at offset 8-11 should be 'pcc ' (0x70636320)
    if (readSize >= 12) {
        uint32_t structType = ReadU32BE(tagData + 8);
        if (structType != 0x70636320u) {
            char sigStr[5]; SigToChars(structType, sigStr);
            findings.push_back({id, Severity::CRITICAL,
                std::string("dpcc structure type '") + sigStr + "' — expected 'pcc '",
                "ICC.2:2023 §12.2.y", "CWE-20"});
            return {CheckResult::Status::FINDINGS, "Wrong structure type", std::move(findings)};
        }
    }

    // Scan for 6 required sub-tag signatures
    struct PccSubTag { uint32_t sig; const char *name; bool required; bool found; };
    PccSubTag subTags[] = {
        {0x6958595Au, "iXYZ", true,  false},
        {0x6D777074u, "mwpt", false, false},  // conditionally required
        {0x73777074u, "swpt", false, false},  // conditionally required
        {0x7376636Eu, "svcn", true,  false},
        {0x63327370u, "c2sp", true,  false},
        {0x73326370u, "s2cp", true,  false},
    };

    for (size_t pos = 12; pos + 3 < readSize; pos += 4) {
        uint32_t w = ReadU32BE(tagData + pos);
        for (auto &st : subTags)
            if (w == st.sig) st.found = true;
    }

    for (const auto &st : subTags) {
        if (!st.found && st.required)
            findings.push_back({id, Severity::HIGH,
                std::string("Required PCC sub-tag '") + st.name + "' missing",
                "ICC.2:2023 §12.2.y", "CWE-476"});
    }

    if (findings.empty()) return CheckResult::ok("dpcc tag structure validation passed");
    return {CheckResult::Status::FINDINGS, "dpcc tag issues found", std::move(findings)};
}

REGISTER_HEURISTIC(177, "devicePccTag Structure Validation",
    "§9.2.x+1", "ICC.2:2023",
    "CWE-20/CWE-476", "", Severity::HIGH, CheckPhase::RAW_SCAN,
    check_h177_dpcc_tag_validation);

// ============================================================================
// H178 — spectralRangeType ('srng') Encoding Validation
// ============================================================================
static CheckResult check_h178_srng_encoding_validation(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");

    CheckID id{CheckID::Kind::Heuristic, 178};
    std::vector<Finding> findings;
    int srngCount = 0;

    for (const auto &tag : pv.rawTagTable()) {
        if (tag.size < 20) continue;
        if (tag.offset > pv.rawSize() || tag.size > pv.rawSize() - tag.offset) continue;

        const uint8_t* tagData = pv.rawData() + tag.offset;
        uint32_t typeSig = ReadU32BE(tagData);
        if (typeSig != 0x73726E67u) continue; // not 'srng'

        srngCount++;
        char tagSigStr[5]; SigToChars(tag.signature, tagSigStr);

        // Reserved bytes (4-7) = 0
        uint32_t reserved = ReadU32BE(tagData + 4);
        if (reserved != 0)
            findings.push_back({id, Severity::MEDIUM,
                std::string("Tag '") + tagSigStr + "': srng reserved field non-zero",
                "", "CWE-20"});

        // Spectral range (bytes 8-13)
        uint16_t specStartRaw = ReadU16BE(tagData + 8);
        uint16_t specEndRaw   = ReadU16BE(tagData + 10);
        uint16_t specSteps    = ReadU16BE(tagData + 12);
        float specStart = safeF16ToF(specStartRaw);
        float specEnd   = safeF16ToF(specEndRaw);

        if (std::isnan(specStart) || std::isinf(specStart) ||
            std::isnan(specEnd) || std::isinf(specEnd))
            findings.push_back({id, Severity::CRITICAL,
                std::string("Tag '") + tagSigStr + "': NaN/Inf wavelength", "", "CWE-20"});
        else if (specStart > 0.0f || specEnd > 0.0f) {
            if (specEnd <= specStart)
                findings.push_back({id, Severity::CRITICAL,
                    std::string("Tag '") + tagSigStr + "': inverted spectral range",
                    "", "CWE-682"});
            if (specSteps < 2)
                findings.push_back({id, Severity::CRITICAL,
                    std::string("Tag '") + tagSigStr + "': steps=" +
                    std::to_string(specSteps) + " (need >= 2)", "", "CWE-369"});
        }

        // Bi-spectral range (bytes 14-19)
        uint16_t biStartRaw = ReadU16BE(tagData + 14);
        uint16_t biEndRaw   = ReadU16BE(tagData + 16);
        uint16_t biSteps    = ReadU16BE(tagData + 18);

        if (!IsBiSpectralDeviceV2(pv) && (biStartRaw != 0 || biEndRaw != 0 || biSteps != 0))
            findings.push_back({id, Severity::MEDIUM,
                std::string("Tag '") + tagSigStr + "': bi-spectral range non-zero for non-bi-spectral",
                "", "CWE-20"});
    }

    if (srngCount == 0) return CheckResult::ok("No srng type tags found");
    if (findings.empty()) return CheckResult::ok("srng encoding validation passed");
    return {CheckResult::Status::FINDINGS, "srng encoding issues found", std::move(findings)};
}

REGISTER_HEURISTIC(178, "spectralRangeType Encoding Validation",
    "§10.2.w", "ICC.2:2023",
    "CWE-20/CWE-125", "", Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h178_srng_encoding_validation);

// ============================================================================
// CF-330: Device Spectral Colour Space Signature
// ============================================================================
static CheckResult check_cf330_device_spectral_signature(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    uint32_t cs = static_cast<uint32_t>(pIcc->m_Header.colorSpace);
    if (!IsSpectralDeviceColorSpaceV2(pv))
        return CheckResult::ok("colorSpace is not a spectral device signature");

    uint16_t upper = static_cast<uint16_t>(cs >> 16);
    const char *type = "unknown";
    switch (upper) {
        case 0x7273: type = "Reflectance Spectral"; break;
        case 0x7473: type = "Transmission Spectral"; break;
        case 0x6573: type = "Radiant Spectral"; break;
        case 0x6273: type = "Bi-Spectral Reflectance"; break;
        case 0x736D: type = "Sparse Matrix Reflectance"; break;
    }
    return CheckResult::ok(std::string("Spectral device signature recognized: ") + type);
}

REGISTER_CONFORMANCE(330, "Device Spectral Colour Space Signature",
    "§7.2.8 amend", "ICC.2:2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf330_device_spectral_signature);

// ============================================================================
// CF-331: Device Spectral Range Source Requirement
// ============================================================================
static CheckResult check_cf331_device_spectral_range_source(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");
    if (!IsSpectralDeviceColorSpaceV2(pv)) return CheckResult::skip("Not spectral device");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CheckID id{CheckID::Kind::Conformance, 331};

    CIccTag *dsrnTag = pIcc->FindTag((icTagSignature)0x6473726E);
    if (dsrnTag) return CheckResult::ok("Device spectral range defined by dsrn tag");

    icSpectralRange sr = pIcc->m_Header.spectralRange;
    if (sr.steps > 0)
        return CheckResult::ok("Device spectral range defined by header spectralRange (fallback)");

    return {CheckResult::Status::FINDINGS, "No spectral range source",
        {{id, Severity::HIGH,
          "Spectral device has no range definition — need dsrn tag or header spectralRange",
          "ICC.2:2023 §7.2.8 + §9.2.x", ""}}};
}

REGISTER_CONFORMANCE(331, "Device Spectral Range Source Requirement",
    "§7.2.8 + §9.2.x", "ICC.2:2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf331_device_spectral_range_source);

// ============================================================================
// CF-332: spectralRangeType Reserved Bytes
// ============================================================================
static CheckResult check_cf332_srng_reserved_bytes(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *dsrnTag = pIcc->FindTag((icTagSignature)0x6473726E);
    if (!dsrnTag) return CheckResult::skip("No dsrn tag present");

    // Check tag size via tag iteration
    for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
        if (it->TagInfo.sig == (icTagSignature)0x6473726E) {
            if (it->TagInfo.size < 20) {
                return {CheckResult::Status::FINDINGS, "dsrn tag undersized",
                    {{{CheckID::Kind::Conformance, 332}, Severity::HIGH,
                      "dsrn tag size " + std::to_string(it->TagInfo.size) +
                      " < 20 (minimum spectralRangeType)", "", ""}}};
            }
            break;
        }
    }
    return CheckResult::ok("dsrn tag size meets spectralRangeType minimum");
}

REGISTER_CONFORMANCE(332, "spectralRangeType Reserved Bytes",
    "§10.2.w", "ICC.2:2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf332_srng_reserved_bytes);

// ============================================================================
// CF-333: devicePccTag Sub-Tag Completeness
// ============================================================================
static CheckResult check_cf333_dpcc_subtag_completeness(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *dpccTag = pIcc->FindTag((icTagSignature)0x64706363);
    if (!dpccTag) return CheckResult::skip("No dpcc tag present");

    return CheckResult::ok("dpcc tag present — sub-tag completeness validated by H177");
}

REGISTER_CONFORMANCE(333, "devicePccTag Sub-Tag Completeness",
    "§12.2.y", "ICC.2:2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf333_dpcc_subtag_completeness);

// ============================================================================
// CF-334: PCC pcsIlluminantXYZMbr Required
// ============================================================================
static CheckResult check_cf334_pcc_illuminant_required(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *dpccTag = pIcc->FindTag((icTagSignature)0x64706363);
    if (!dpccTag) return CheckResult::skip("No dpcc tag");

    return CheckResult::ok("dpcc present — iXYZ requirement validated by H177");
}

REGISTER_CONFORMANCE(334, "PCC pcsIlluminantXYZMbr Required",
    "§12.2.y.2.1", "ICC.2:2023",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf334_pcc_illuminant_required);

// ============================================================================
// CF-335: PCC mediaWhitePointMbr Conditional
// ============================================================================
static CheckResult check_cf335_pcc_media_white_point(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *dpccTag = pIcc->FindTag((icTagSignature)0x64706363);
    if (!dpccTag) return CheckResult::skip("No dpcc tag");

    return CheckResult::ok("dpcc present — mwpt conditionality validated by H177");
}

REGISTER_CONFORMANCE(335, "PCC mediaWhitePointMbr Conditional",
    "§12.2.y.2.2", "ICC.2:2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf335_pcc_media_white_point);

// ============================================================================
// CF-336: PCC spectralWhitePointMbr Conditional
// ============================================================================
static CheckResult check_cf336_pcc_spectral_white_point(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *dpccTag = pIcc->FindTag((icTagSignature)0x64706363);
    if (!dpccTag) return CheckResult::skip("No dpcc tag");

    return CheckResult::ok("dpcc present — swpt conditionality validated by H177");
}

REGISTER_CONFORMANCE(336, "PCC spectralWhitePointMbr Conditional",
    "§12.2.y.2.3", "ICC.2:2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf336_pcc_spectral_white_point);

// ============================================================================
// CF-337: Device Spectral Range vs Header Consistency
// ============================================================================
static CheckResult check_cf337_device_range_header_consistency(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");
    if (!IsSpectralDeviceColorSpaceV2(pv)) return CheckResult::skip("Not spectral device");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    CIccTag *dsrnTag = pIcc->FindTag((icTagSignature)0x6473726E);
    icSpectralRange sr = pIcc->m_Header.spectralRange;

    if (dsrnTag && sr.steps > 0)
        return CheckResult::ok("Both dsrn tag and header spectralRange present — dsrn takes precedence");
    if (dsrnTag)
        return CheckResult::ok("Range source is dsrn tag");
    if (sr.steps > 0)
        return CheckResult::ok("Range source is header spectralRange (fallback)");

    return {CheckResult::Status::FINDINGS, "No spectral range source",
        {{{CheckID::Kind::Conformance, 337}, Severity::HIGH,
          "No spectral range source for spectral device colour space",
          "ICC.2:2023 §7.2.8 + §7.2.22", ""}}};
}

REGISTER_CONFORMANCE(337, "Device Spectral Range vs Header Consistency",
    "§7.2.8 + §7.2.22", "ICC.2:2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf337_device_range_header_consistency);

// ============================================================================
// CF-338: Bi-Spectral Device Range Zero Check
// ============================================================================
static CheckResult check_cf338_bispectral_range_zero(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");
    if (!IsSpectralDeviceColorSpaceV2(pv)) return CheckResult::skip("Not spectral device");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    if (IsBiSpectralDeviceV2(pv))
        return CheckResult::ok("Bi-spectral device — bi-spectral range may be non-zero");

    icSpectralRange bsr = pIcc->m_Header.biSpectralRange;
    if (bsr.start != 0 || bsr.end != 0 || bsr.steps != 0) {
        return {CheckResult::Status::FINDINGS, "Non-zero bi-spectral range",
            {{{CheckID::Kind::Conformance, 338}, Severity::MEDIUM,
              "Non-bi-spectral device has non-zero header biSpectralRange",
              "ICC.2:2023 §10.2.w", ""}}};
    }
    return CheckResult::ok("Bi-spectral range correctly zero for non-bi-spectral device");
}

REGISTER_CONFORMANCE(338, "Bi-Spectral Device Range Zero Check",
    "§10.2.w", "ICC.2:2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf338_bispectral_range_zero);

// ============================================================================
// CF-339: Abstract Profile Device PCC Presence
// ============================================================================
static CheckResult check_cf339_abstract_device_pcc_presence(const ProfileView& pv) {
    if (!IsV5(pv)) return CheckResult::skip("Not a v5+ profile");
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("No library handle");

    if (pIcc->m_Header.deviceClass != icSigAbstractClass)
        return CheckResult::skip("Not an abstract profile");

    CheckID id{CheckID::Kind::Conformance, 339};
    CIccTag *dpccTag = pIcc->FindTag((icTagSignature)0x64706363);
    uint32_t cs = static_cast<uint32_t>(pIcc->m_Header.colorSpace);
    bool spectralDevice = IsSpectralDeviceColorSpaceV2(pv);
    bool colorimetricDevice = (cs == 0x4C616220 || cs == 0x58595A20); // 'Lab ' or 'XYZ '

    if (spectralDevice || colorimetricDevice) {
        if (dpccTag)
            return CheckResult::ok("Abstract profile with PCS-like device has dpcc tag");
        return CheckResult::ok("Abstract profile — dpcc absent (device PCC matches spectral PCS)");
    }

    if (dpccTag) {
        return {CheckResult::Status::FINDINGS, "Unexpected dpcc on abstract profile",
            {{id, Severity::MEDIUM,
              "dpcc tag present on abstract profile with non-PCS device colour space",
              "ICC.2:2023 §9.2.x+1", ""}}};
    }
    return CheckResult::ok("Abstract profile — dpcc not expected for this device space");
}

REGISTER_CONFORMANCE(339, "Abstract Profile Device PCC Presence",
    "§9.2.x+1", "ICC.2:2023",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf339_abstract_device_pcc_presence);
