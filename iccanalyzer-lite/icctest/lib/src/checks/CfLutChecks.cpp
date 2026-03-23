// CfLutChecks.cpp — V2 conformance checks (LUT/curve/matrix)
// 37 checks: CF-060..CF-262
//
// Ported from V1 IccConformanceLUT.cpp + CF-231 from IccConformanceTagTypes.cpp
//
// SPDX-License-Identifier: MIT

#include <icctest/CheckRegistry.h>
#include <icctest/ProfileView.h>
#include <icctest/CheckResult.h>

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagLut.h"
#include "IccTagMPE.h"
#include "IccUtil.h"
#include "IccDefs.h"

#include <cmath>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>

using namespace icctest;

// ── LUT tag signature tables ────────────────────────────────────────────────

static const icTagSignature kAToBSigs[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag
};
static const char *kAToBNames[] = { "AToB0", "AToB1", "AToB2" };

static const icTagSignature kBToASigs[] = {
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag
};
static const char *kBToANames[] = { "BToA0", "BToA1", "BToA2" };

static constexpr int kLUTDirCount = 3;

static const icTagSignature kAllLUTSigs[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag
};
static const char *kAllLUTNames[] = {
    "AToB0", "AToB1", "AToB2", "BToA0", "BToA1", "BToA2"
};
static constexpr int kAllLUTCount = 6;
static const icTagSignature kRgbTrcSigs[] = {
    icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag
};
static const icTagSignature kRgbMatrixSigs[] = {
    icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag
};
static constexpr int kRgbFamilyCount = 3;

static constexpr double kMatrixIdentityTol = 0.002;
static constexpr double kDetEpsilon = 0.0001;
static constexpr double kS15F16Min = -32768.0;
static constexpr double kS15F16Max =  32767.99998474;
static constexpr double kOffsetReasonableMax = 10.0;
static constexpr double kOutputReasonableMin = -2.0;
static constexpr double kOutputReasonableMax =  3.0;

static bool IsAToBDirection(icTagSignature sig) {
    return sig == icSigAToB0Tag || sig == icSigAToB1Tag || sig == icSigAToB2Tag;
}

static bool get_transform_tag_channel_counts(CIccTag* tag,
                                             icUInt16Number& inputChannels,
                                             icUInt16Number& outputChannels) {
    if (auto* mbb = dynamic_cast<CIccMBB*>(tag)) {
        inputChannels = mbb->InputChannels();
        outputChannels = mbb->OutputChannels();
        return true;
    }
    if (auto* mpe = dynamic_cast<CIccTagMultiProcessElement*>(tag)) {
        inputChannels = mpe->NumInputChannels();
        outputChannels = mpe->NumOutputChannels();
        return true;
    }
    return false;
}

static int count_present_tags(CIccProfile* pIcc,
                              const icTagSignature* sigs,
                              int count) {
    int found = 0;
    for (int i = 0; i < count; ++i) {
        if (pIcc->FindTag(sigs[i])) {
            ++found;
        }
    }
    return found;
}

static bool has_any_tag(CIccProfile* pIcc,
                        const icTagSignature* sigs,
                        int count) {
    return count_present_tags(pIcc, sigs, count) > 0;
}

static bool has_any_lut_tag(CIccProfile* pIcc) {
    return has_any_tag(pIcc, kAllLUTSigs, kAllLUTCount);
}

static bool is_rgb_matrix_trc_fallback_applicable(CIccProfile* pIcc) {
    if (!pIcc || has_any_lut_tag(pIcc)) return false;
    if (pIcc->m_Header.colorSpace != icSigRgbData) return false;

    icProfileClassSignature klass = pIcc->m_Header.deviceClass;
    return klass == icSigInputClass || klass == icSigDisplayClass;
}

static bool is_gray_trc_fallback_applicable(CIccProfile* pIcc) {
    if (!pIcc || has_any_lut_tag(pIcc)) return false;
    if (pIcc->m_Header.colorSpace != icSigGrayData) return false;

    icProfileClassSignature klass = pIcc->m_Header.deviceClass;
    return klass == icSigInputClass
        || klass == icSigDisplayClass
        || klass == icSigOutputClass;
}

// ── CF-060: LUT Input Channel Count ────────────────────────────────────────

static CheckResult check_cf060_lut_input_channel_count(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 60};
    bool found = false;
    std::string okSummary = "LUT input channel counts valid";

    icUInt32Number deviceChan = icGetSpaceSamples(pIcc->m_Header.colorSpace);
    icUInt32Number pcsChan    = icGetSpaceSamples(pIcc->m_Header.pcs);

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        icUInt16Number lutIn = 0;
        icUInt16Number lutOut = 0;
        if (!get_transform_tag_channel_counts(tag, lutIn, lutOut)) continue;
        found = true;

        icUInt32Number expectedIn = IsAToBDirection(kAllLUTSigs[i]) ? deviceChan : pcsChan;
        if (expectedIn == 0) continue;

        if (lutIn != expectedIn) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kAllLUTNames[i] + "' input channels=" +
                std::to_string(lutIn) + ", expected=" + std::to_string(expectedIn),
                "ICC.1-2022-05 §10.8-10.11", ""});
        }
    }

    if (!found && is_rgb_matrix_trc_fallback_applicable(pIcc)) {
        found = true;
        okSummary = "Matrix/TRC device-side channel tags valid";

        int trcCount = count_present_tags(pIcc, kRgbTrcSigs, kRgbFamilyCount);
        if (deviceChan == 0) {
            return CheckResult::skip("Could not determine expected RGB device channel count");
        }
        if (trcCount != static_cast<int>(deviceChan)) {
            findings.push_back({cfId, Severity::HIGH,
                "Matrix/TRC RGB profile exposes " + std::to_string(trcCount) +
                " device-side TRC tag(s); expected " + std::to_string(deviceChan),
                "ICC.1-2022-05 §10.8-10.11", ""});
        }
        if (pIcc->FindTag(icSigGrayTRCTag)) {
            findings.push_back({cfId, Severity::MEDIUM,
                "RGB matrix/TRC profile unexpectedly contains grayTRCTag",
                "ICC.1-2022-05 §10.8-10.11", ""});
        }
    }

    if (!found && is_gray_trc_fallback_applicable(pIcc)) {
        found = true;
        okSummary = "Gray TRC device-side channel tags valid";

        int grayCount = pIcc->FindTag(icSigGrayTRCTag) ? 1 : 0;
        if (deviceChan == 0) {
            return CheckResult::skip("Could not determine expected Gray device channel count");
        }
        if (grayCount != static_cast<int>(deviceChan)) {
            findings.push_back({cfId, Severity::HIGH,
                "Gray profile exposes " + std::to_string(grayCount) +
                " grayTRCTag(s); expected " + std::to_string(deviceChan),
                "ICC.1-2022-05 §10.8-10.11", ""});
        }
        if (has_any_tag(pIcc, kRgbTrcSigs, kRgbFamilyCount)) {
            findings.push_back({cfId, Severity::MEDIUM,
                "Gray profile unexpectedly contains RGB TRC tags",
                "ICC.1-2022-05 §10.8-10.11", ""});
        }
    }

    if (!found && pIcc->m_Header.deviceClass == icSigNamedColorClass) {
        return CheckResult::skip(
            "NamedColor profiles do not encode transform input channel counts; not applicable");
    }

    if (!found) return CheckResult::skip("No LUT tags present");
    if (findings.empty()) return CheckResult::ok(okSummary);
    return {CheckResult::Status::FINDINGS, "Input channel count mismatch", std::move(findings)};
}

// ── CF-061: LUT Output Channel Count ───────────────────────────────────────

static CheckResult check_cf061_lut_output_channel_count(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 61};
    bool found = false;
    std::string okSummary = "LUT output channel counts valid";

    icUInt32Number deviceChan = icGetSpaceSamples(pIcc->m_Header.colorSpace);
    icUInt32Number pcsChan    = icGetSpaceSamples(pIcc->m_Header.pcs);

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        icUInt16Number lutIn = 0;
        icUInt16Number lutOut = 0;
        if (!get_transform_tag_channel_counts(tag, lutIn, lutOut)) continue;
        found = true;

        icUInt32Number expectedOut = IsAToBDirection(kAllLUTSigs[i]) ? pcsChan : deviceChan;
        if (expectedOut == 0) continue;

        if (lutOut != expectedOut) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kAllLUTNames[i] + "' output channels=" +
                std::to_string(lutOut) + ", expected=" + std::to_string(expectedOut),
                "ICC.1-2022-05 §10.8-10.11", ""});
        }
    }

    if (!found && is_rgb_matrix_trc_fallback_applicable(pIcc)) {
        found = true;
        okSummary = "Matrix/TRC PCS-side channel tags valid";

        int matrixCount = count_present_tags(pIcc, kRgbMatrixSigs, kRgbFamilyCount);
        if (pcsChan == 0) {
            return CheckResult::skip("Could not determine expected PCS channel count");
        }
        if (matrixCount != static_cast<int>(pcsChan)) {
            findings.push_back({cfId, Severity::HIGH,
                "Matrix/TRC RGB profile exposes " + std::to_string(matrixCount) +
                " PCS-side matrix column tag(s); expected " + std::to_string(pcsChan),
                "ICC.1-2022-05 §10.8-10.11", ""});
        }
    }

    if (!found && is_gray_trc_fallback_applicable(pIcc)) {
        return CheckResult::skip(
            "Gray TRC profiles do not encode PCS channel count in per-channel output tags; not applicable");
    }

    if (!found && pIcc->m_Header.deviceClass == icSigNamedColorClass) {
        return CheckResult::skip(
            "NamedColor profiles do not encode transform output channel counts; not applicable");
    }

    if (!found) return CheckResult::skip("No LUT tags present");
    if (findings.empty()) return CheckResult::ok(okSummary);
    return {CheckResult::Status::FINDINGS, "Output channel count mismatch", std::move(findings)};
}

// ── CF-062: CLUT Grid Dimensionality ───────────────────────────────────────

static CheckResult check_cf062_clut_grid_dimensionality(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 62};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        CIccCLUT *clut = mbb->GetCLUT();
        if (!clut) continue;
        found = true;

        int nDims = clut->GetInputDim();
        for (int d = 0; d < nDims; d++) {
            icUInt8Number gp = clut->GridPoint(d);
            if (gp < 2) {
                findings.push_back({cfId, Severity::HIGH,
                    std::string("Tag '") + kAllLUTNames[i] + "' grid dim " +
                    std::to_string(d) + " has " + std::to_string(gp) + " points (minimum 2)",
                    "ICC.1-2022-05 §10.8", ""});
            }
        }

        // Check for grid size overflow
        uint64_t total = 1;
        bool overflow = false;
        for (int d = 0; d < nDims; d++) {
            uint64_t gp = clut->GridPoint(d);
            if (gp > 0 && total > UINT32_MAX / gp) { overflow = true; break; }
            total *= gp;
        }
        if (overflow) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kAllLUTNames[i] + "' CLUT grid dimension product overflows uint32",
                "ICC.1-2022-05 §10.8", ""});
        }
    }

    if (!found) return CheckResult::skip("No CLUT elements found");
    if (findings.empty()) return CheckResult::ok("CLUT grid dimensions valid");
    return {CheckResult::Status::FINDINGS, "CLUT grid dimensionality issue", std::move(findings)};
}

// ── CF-063: lut8Type Fixed Table Size 256 ──────────────────────────────────

static CheckResult check_cf063_lut8type_fixed_table_size_256(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 63};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccTagLut8 *lut8 = dynamic_cast<CIccTagLut8 *>(tag);
        if (!lut8) continue;
        found = true;

        int nIn  = lut8->InputChannels();
        int nOut = lut8->OutputChannels();

        LPIccCurve *curvesB = lut8->GetCurvesB();
        if (curvesB) {
            for (int c = 0; c < nIn; c++) {
                if (!curvesB[c]) continue;
                CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesB[c]);
                if (curve && curve->GetSize() != 256) {
                    findings.push_back({cfId, Severity::HIGH,
                        std::string("Tag '") + kAllLUTNames[i] + "' input table[" +
                        std::to_string(c) + "] has " + std::to_string(curve->GetSize()) +
                        " entries (must be 256)",
                        "ICC.1-2022-05 §10.9", ""});
                }
            }
        }

        LPIccCurve *curvesA = lut8->GetCurvesA();
        if (curvesA) {
            for (int c = 0; c < nOut; c++) {
                if (!curvesA[c]) continue;
                CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesA[c]);
                if (curve && curve->GetSize() != 256) {
                    findings.push_back({cfId, Severity::HIGH,
                        std::string("Tag '") + kAllLUTNames[i] + "' output table[" +
                        std::to_string(c) + "] has " + std::to_string(curve->GetSize()) +
                        " entries (must be 256)",
                        "ICC.1-2022-05 §10.9", ""});
                }
            }
        }
    }

    if (!found) return CheckResult::skip("No lut8Type tags found");
    if (findings.empty()) return CheckResult::ok("lut8Type table sizes conformant");
    return {CheckResult::Status::FINDINGS, "lut8Type table size violation", std::move(findings)};
}

// ── CF-064: lut16Type Table Size Range 2-4096 ──────────────────────────────

static CheckResult check_cf064_lut16type_table_size_range_2_4096(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 64};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccTagLut16 *lut16 = dynamic_cast<CIccTagLut16 *>(tag);
        if (!lut16) continue;
        found = true;

        int nIn  = lut16->InputChannels();
        int nOut = lut16->OutputChannels();

        LPIccCurve *curvesB = lut16->GetCurvesB();
        if (curvesB) {
            for (int c = 0; c < nIn; c++) {
                if (!curvesB[c]) continue;
                CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesB[c]);
                if (curve) {
                    icUInt32Number sz = curve->GetSize();
                    if (sz < 2 || sz > 4096) {
                        findings.push_back({cfId, Severity::HIGH,
                            std::string("Tag '") + kAllLUTNames[i] + "' input table[" +
                            std::to_string(c) + "] has " + std::to_string(sz) +
                            " entries (must be 2-4096)",
                            "ICC.1-2022-05 §10.10", ""});
                    }
                }
            }
        }

        LPIccCurve *curvesA = lut16->GetCurvesA();
        if (curvesA) {
            for (int c = 0; c < nOut; c++) {
                if (!curvesA[c]) continue;
                CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesA[c]);
                if (curve) {
                    icUInt32Number sz = curve->GetSize();
                    if (sz < 2 || sz > 4096) {
                        findings.push_back({cfId, Severity::HIGH,
                            std::string("Tag '") + kAllLUTNames[i] + "' output table[" +
                            std::to_string(c) + "] has " + std::to_string(sz) +
                            " entries (must be 2-4096)",
                            "ICC.1-2022-05 §10.10", ""});
                    }
                }
            }
        }
    }

    if (!found) return CheckResult::skip("No lut16Type tags found");
    if (findings.empty()) return CheckResult::ok("lut16Type table sizes within range");
    return {CheckResult::Status::FINDINGS, "lut16Type table size out of range", std::move(findings)};
}

// ── CF-065: lutAToBType Processing Element Present ─────────────────────────

static CheckResult check_cf065_lutatobtype_processing_element_present(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 65};
    bool found = false;

    for (int i = 0; i < kLUTDirCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAToBSigs[i]);
        if (!tag) continue;
        if (tag->GetType() != icSigLutAtoBType) continue;
        CIccTagLutAtoB *atob = dynamic_cast<CIccTagLutAtoB *>(tag);
        if (!atob) continue;
        found = true;

        bool hasA      = (atob->GetCurvesA() != nullptr);
        bool hasB      = (atob->GetCurvesB() != nullptr);
        bool hasM      = (atob->GetCurvesM() != nullptr);
        bool hasCLUT   = (atob->GetCLUT()    != nullptr);
        bool hasMatrix = (atob->GetMatrix()  != nullptr);

        if (!hasB) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kAToBNames[i] + "' B curves missing (required)",
                "ICC.1-2022-05 §10.11", ""});
        }
        if (hasCLUT && !hasA) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kAToBNames[i] + "' CLUT present without A curves",
                "ICC.1-2022-05 §10.11", ""});
        }
        if (hasMatrix && !hasM) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kAToBNames[i] + "' Matrix present without M curves",
                "ICC.1-2022-05 §10.11", ""});
        }
    }

    if (!found) return CheckResult::skip("No lutAToBType tags found");
    if (findings.empty()) return CheckResult::ok("lutAToBType element presence valid");
    return {CheckResult::Status::FINDINGS, "lutAToBType element presence violation", std::move(findings)};
}

// ── CF-066: lutBToAType Processing Element Present ─────────────────────────

static CheckResult check_cf066_lutbtoatype_processing_element_present(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 66};
    bool found = false;

    for (int i = 0; i < kLUTDirCount; i++) {
        CIccTag *tag = pIcc->FindTag(kBToASigs[i]);
        if (!tag) continue;
        if (tag->GetType() != icSigLutBtoAType) continue;
        CIccTagLutBtoA *btoa = dynamic_cast<CIccTagLutBtoA *>(tag);
        if (!btoa) continue;
        found = true;

        bool hasA      = (btoa->GetCurvesA() != nullptr);
        bool hasB      = (btoa->GetCurvesB() != nullptr);
        bool hasM      = (btoa->GetCurvesM() != nullptr);
        bool hasCLUT   = (btoa->GetCLUT()    != nullptr);
        bool hasMatrix = (btoa->GetMatrix()  != nullptr);

        if (!hasB) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kBToANames[i] + "' B curves missing (required)",
                "ICC.1-2022-05 §10.12", ""});
        }
        if (hasCLUT && !hasA) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kBToANames[i] + "' CLUT present without A curves",
                "ICC.1-2022-05 §10.12", ""});
        }
        if (hasMatrix && !hasM) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kBToANames[i] + "' Matrix present without M curves",
                "ICC.1-2022-05 §10.12", ""});
        }
    }

    if (!found) return CheckResult::skip("No lutBToAType tags found");
    if (findings.empty()) return CheckResult::ok("lutBToAType element presence valid");
    return {CheckResult::Status::FINDINGS, "lutBToAType element presence violation", std::move(findings)};
}

// ── CF-067: lut8/16 Matrix Identity When Not PCSXYZ ────────────────────────

static CheckResult check_cf067_lut8_16_matrix_identity_when_not_pcsxyz(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    if (pIcc->m_Header.pcs == icSigXYZData)
        return CheckResult::ok("PCS is XYZ — matrix may be non-identity");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 67};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        bool isLut8  = (dynamic_cast<CIccTagLut8 *>(tag) != nullptr);
        bool isLut16 = (dynamic_cast<CIccTagLut16 *>(tag) != nullptr);
        if (!isLut8 && !isLut16) continue;

        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        const CIccMatrix *matrix = mbb->GetMatrix();
        if (!matrix) continue;
        found = true;

        const icFloatNumber *e = matrix->m_e;
        bool isIdentity = true;
        for (int r = 0; r < 3 && isIdentity; r++) {
            for (int c = 0; c < 3 && isIdentity; c++) {
                double expected = (r == c) ? 1.0 : 0.0;
                if (std::fabs(static_cast<double>(e[r * 3 + c]) - expected) > kMatrixIdentityTol)
                    isIdentity = false;
            }
        }

        if (!isIdentity) {
            char buf[256];
            snprintf(buf, sizeof(buf),
                "Tag '%s' PCS is not XYZ but matrix is not identity: "
                "[%.4f %.4f %.4f] [%.4f %.4f %.4f] [%.4f %.4f %.4f]",
                kAllLUTNames[i],
                (double)e[0], (double)e[1], (double)e[2],
                (double)e[3], (double)e[4], (double)e[5],
                (double)e[6], (double)e[7], (double)e[8]);
            findings.push_back({cfId, Severity::MEDIUM, buf,
                "ICC.1-2022-05 §10.8-10.10", ""});
        }
    }

    if (!found) return CheckResult::skip("No lut8/lut16 tags with matrix found");
    if (findings.empty()) return CheckResult::ok("lut8/16 matrix identity check passed");
    return {CheckResult::Status::FINDINGS, "lut8/16 matrix should be identity when PCS != XYZ", std::move(findings)};
}

// ── CF-068: Chromatic Adaptation Matrix Invertible ─────────────────────────

static CheckResult check_cf068_chromatic_adaptation_matrix_invertible(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    CheckID cfId{CheckID::Kind::Conformance, 68};

    CIccTag *chadTag = pIcc->FindTag(icSigChromaticAdaptationTag);
    if (!chadTag) return CheckResult::skip("No chromaticAdaptationTag present");

    CIccTagS15Fixed16 *chad = dynamic_cast<CIccTagS15Fixed16 *>(chadTag);
    if (!chad) return CheckResult::skip("Chad tag is not S15Fixed16 type");

    if (chad->GetSize() < 9) {
        return {CheckResult::Status::FINDINGS, "Chad has insufficient values", {
            {cfId, Severity::HIGH,
             "chad has " + std::to_string(chad->GetSize()) + " values (need 9 for 3x3 matrix)",
             "ICC.1-2022-05 §9.2.10", ""}}};
    }

    double m[9];
    for (int i = 0; i < 9; i++)
        m[i] = static_cast<double>((*chad)[i]) / 65536.0;

    double det = m[0] * (m[4] * m[8] - m[5] * m[7])
               - m[1] * (m[3] * m[8] - m[5] * m[6])
               + m[2] * (m[3] * m[7] - m[4] * m[6]);

    if (std::fabs(det) < kDetEpsilon) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Determinant = %.8f — matrix is singular or near-singular", det);
        return {CheckResult::Status::FINDINGS, "Chad matrix not invertible", {
            {cfId, Severity::HIGH, buf, "ICC.1-2022-05 §9.2.10", ""}}};
    }

    return CheckResult::ok("Chromatic adaptation matrix invertible");
}

// ── CF-069: Matrix Column Tag XYZ Count ────────────────────────────────────

static CheckResult check_cf069_matrix_column_tag_xyz_count(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 69};
    bool found = false;

    static const icTagSignature kColSigs[] = {
        icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag
    };
    static const char *kColNames[] = { "rXYZ (Red)", "gXYZ (Green)", "bXYZ (Blue)" };

    for (int i = 0; i < 3; i++) {
        CIccTag *tag = pIcc->FindTag(kColSigs[i]);
        if (!tag) continue;
        CIccTagXYZ *xyz = dynamic_cast<CIccTagXYZ *>(tag);
        if (!xyz) continue;
        found = true;

        if (xyz->GetSize() != 1) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kColNames[i] + "' contains " +
                std::to_string(xyz->GetSize()) + " XYZ triplets (must be exactly 1)",
                "ICC.1-2022-05 §9.2", ""});
        }
    }

    if (!found) return CheckResult::skip("No matrix column tags present");
    if (findings.empty()) return CheckResult::ok("Matrix column XYZ counts valid");
    return {CheckResult::Status::FINDINGS, "Matrix column XYZ count violation", std::move(findings)};
}

// ── CF-070: Chad s15Fixed16 Array Count 9 ──────────────────────────────────

static CheckResult check_cf070_chad_s15fixed16_array_count_9(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    CheckID cfId{CheckID::Kind::Conformance, 70};

    CIccTag *chadTag = pIcc->FindTag(icSigChromaticAdaptationTag);
    if (!chadTag) return CheckResult::skip("No chromaticAdaptationTag present");

    CIccTagS15Fixed16 *chad = dynamic_cast<CIccTagS15Fixed16 *>(chadTag);
    if (!chad) return CheckResult::skip("Chad tag is not S15Fixed16 type");

    if (chad->GetSize() != 9) {
        return {CheckResult::Status::FINDINGS, "Chad array count not 9", {
            {cfId, Severity::HIGH,
             "chad contains " + std::to_string(chad->GetSize()) +
             " s15Fixed16 values (must be exactly 9)",
             "ICC.1-2022-05 §9.2.10", ""}}};
    }

    return CheckResult::ok("Chad array count is 9");
}

// ── CF-071: Curve Count vs Channel Match ───────────────────────────────────

static CheckResult check_cf071_curve_count_vs_channel_match(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 71};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        found = true;

        int nIn  = mbb->InputChannels();
        int nOut = mbb->OutputChannels();

        // B curves
        LPIccCurve *curvesB = mbb->GetCurvesB();
        if (curvesB) {
            int expectedB = mbb->IsInputB() ? nIn : nOut;
            int countB = 0;
            for (int c = 0; c < expectedB && c < 16; c++) {
                if (curvesB[c]) countB++;
            }
            if (countB > 0 && countB != expectedB) {
                findings.push_back({cfId, Severity::HIGH,
                    std::string("Tag '") + kAllLUTNames[i] + "' B curve count " +
                    std::to_string(countB) + " != expected " + std::to_string(expectedB),
                    "ICC.1-2022-05 §10.10-10.12", ""});
            }
        }

        // A curves
        LPIccCurve *curvesA = mbb->GetCurvesA();
        if (curvesA) {
            int expectedA = mbb->IsInputB() ? nOut : nIn;
            int countA = 0;
            for (int c = 0; c < expectedA && c < 16; c++) {
                if (curvesA[c]) countA++;
            }
            if (countA > 0 && countA != expectedA) {
                findings.push_back({cfId, Severity::HIGH,
                    std::string("Tag '") + kAllLUTNames[i] + "' A curve count " +
                    std::to_string(countA) + " != expected " + std::to_string(expectedA),
                    "ICC.1-2022-05 §10.10-10.12", ""});
            }
        }

        // M curves: always 3 when present
        LPIccCurve *curvesM = mbb->GetCurvesM();
        if (curvesM) {
            int nCurvesM = mbb->IsInputMatrix() ? nIn : nOut;
            if (nCurvesM < 1) nCurvesM = 0;
            if (nCurvesM > 16) nCurvesM = 16;
            int countM = 0;
            for (int c = 0; c < nCurvesM && c < 3; c++) {
                if (curvesM[c]) countM++;
            }
            if (nCurvesM < 3) {
                findings.push_back({cfId, Severity::HIGH,
                    std::string("Tag '") + kAllLUTNames[i] + "' M curve array size " +
                    std::to_string(nCurvesM) + " < expected 3",
                    "ICC.1-2022-05 §10.10-10.12", ""});
            } else if (countM > 0 && countM != 3) {
                findings.push_back({cfId, Severity::HIGH,
                    std::string("Tag '") + kAllLUTNames[i] + "' M curve count " +
                    std::to_string(countM) + " != expected 3",
                    "ICC.1-2022-05 §10.10-10.12", ""});
            }
        }
    }

    if (!found) return CheckResult::skip("No LUT tags found");
    if (findings.empty()) return CheckResult::ok("Curve counts match channel expectations");
    return {CheckResult::Status::FINDINGS, "Curve count vs channel mismatch", std::move(findings)};
}

// ── CF-072: CLUT Output Value Range ────────────────────────────────────────

static CheckResult check_cf072_clut_output_value_range(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 72};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        CIccCLUT *clut = mbb->GetCLUT();
        if (!clut) continue;
        found = true;

        icUInt32Number nPoints = clut->NumPoints();
        int nOut = clut->GetOutputChannels();
        if (nOut < 1 || nOut > 16) continue;

        icUInt32Number limit = (nPoints < 1000) ? nPoints : 1000;
        int badCount = 0;

        for (icUInt32Number p = 0; p < limit && badCount < 5; p++) {
            icFloatNumber *data = clut->GetData(p * nOut);
            if (!data) break;
            for (int ch = 0; ch < nOut; ch++) {
                if (std::isnan(data[ch]) || std::isinf(data[ch])) {
                    if (badCount == 0) {
                        char buf[128];
                        snprintf(buf, sizeof(buf), "Tag '%s' CLUT[%u][%d] = %f (non-finite)",
                                 kAllLUTNames[i], p, ch, (double)data[ch]);
                        findings.push_back({cfId, Severity::MEDIUM, buf,
                            "ICC.1-2022-05 §10.8", ""});
                    }
                    badCount++;
                    break;
                }
            }
        }
        if (badCount > 1) {
            findings.push_back({cfId, Severity::MEDIUM,
                std::string("Tag '") + kAllLUTNames[i] + "' " +
                std::to_string(badCount - 1) + " additional non-finite CLUT values",
                "ICC.1-2022-05 §10.8", ""});
        }
    }

    if (!found) return CheckResult::skip("No CLUT elements found");
    if (findings.empty()) return CheckResult::ok("CLUT output values are finite");
    return {CheckResult::Status::FINDINGS, "CLUT contains non-finite values", std::move(findings)};
}

// ── CF-073: MBB Matrix Determinant Non-Zero ────────────────────────────────

static CheckResult check_cf073_mbb_matrix_determinant_non_zero(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 73};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        if (tag->GetType() != icSigLutAtoBType && tag->GetType() != icSigLutBtoAType)
            continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        const CIccMatrix *matrix = mbb->GetMatrix();
        if (!matrix) continue;
        found = true;

        double a = matrix->m_e[0], b = matrix->m_e[1], c = matrix->m_e[2];
        double d = matrix->m_e[3], e = matrix->m_e[4], f = matrix->m_e[5];
        double g = matrix->m_e[6], h = matrix->m_e[7], k = matrix->m_e[8];
        double det = a * (e * k - f * h) - b * (d * k - f * g) + c * (d * h - e * g);

        if (std::fabs(det) < 1e-10) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Tag '%s' matrix determinant = %.10f (near-singular)",
                     kAllLUTNames[i], det);
            findings.push_back({cfId, Severity::MEDIUM, buf,
                "ICC.1-2022-05 §10.10", ""});
        }
    }

    if (!found) return CheckResult::skip("No MBB tags with matrix found");
    if (findings.empty()) return CheckResult::ok("MBB matrix determinants are non-zero");
    return {CheckResult::Status::FINDINGS, "Singular MBB matrix detected", std::move(findings)};
}

// ── CF-074: A2B/B2A Dimension Consistency ──────────────────────────────────

static CheckResult check_cf074_a2b_b2a_dimension_consistency(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 74};
    bool found = false;

    for (int i = 0; i < kLUTDirCount; i++) {
        CIccTag *aTag = pIcc->FindTag(kAToBSigs[i]);
        CIccTag *bTag = pIcc->FindTag(kBToASigs[i]);
        if (!aTag || !bTag) continue;
        CIccMBB *aMBB = dynamic_cast<CIccMBB *>(aTag);
        CIccMBB *bMBB = dynamic_cast<CIccMBB *>(bTag);
        if (!aMBB || !bMBB) continue;
        found = true;

        if (aMBB->InputChannels() != bMBB->OutputChannels()) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Intent %d: AToB input (%u) != BToA output (%u)",
                     i, (unsigned)aMBB->InputChannels(), (unsigned)bMBB->OutputChannels());
            findings.push_back({cfId, Severity::HIGH, buf,
                "ICC.1-2022-05 §10.8", ""});
        }
        if (aMBB->OutputChannels() != bMBB->InputChannels()) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Intent %d: AToB output (%u) != BToA input (%u)",
                     i, (unsigned)aMBB->OutputChannels(), (unsigned)bMBB->InputChannels());
            findings.push_back({cfId, Severity::HIGH, buf,
                "ICC.1-2022-05 §10.8", ""});
        }
    }

    if (!found) return CheckResult::skip("No matching A2B/B2A pairs found");
    if (findings.empty()) return CheckResult::ok("A2B/B2A dimensions are consistent");
    return {CheckResult::Status::FINDINGS, "A2B/B2A dimension mismatch", std::move(findings)};
}

// ── CF-075: Tag Data Size vs Dimensions ────────────────────────────────────

static CheckResult check_cf075_tag_data_size_vs_dimensions(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 75};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        found = true;

        int nIn  = mbb->InputChannels();
        int nOut = mbb->OutputChannels();

        if (nIn < 1 || nIn > 15) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kAllLUTNames[i] + "' input channels = " +
                std::to_string(nIn) + " (expected 1-15)",
                "ICC.1-2022-05 §10.8", ""});
        }
        if (nOut < 1 || nOut > 15) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kAllLUTNames[i] + "' output channels = " +
                std::to_string(nOut) + " (expected 1-15)",
                "ICC.1-2022-05 §10.8", ""});
        }

        CIccCLUT *clut = mbb->GetCLUT();
        if (clut) {
            int nDims = clut->GetInputDim();
            uint64_t totalEntries = 1;
            bool overflow = false;
            for (int d = 0; d < nDims; d++) {
                uint64_t gp = clut->GridPoint(d);
                if (gp == 0 || (totalEntries > 0 && totalEntries > 100000000ULL / gp)) {
                    overflow = true; break;
                }
                totalEntries *= gp;
            }
            totalEntries *= static_cast<uint64_t>(clut->GetOutputChannels());

            if (overflow || totalEntries > 100000000ULL) {
                findings.push_back({cfId, Severity::MEDIUM,
                    std::string("Tag '") + kAllLUTNames[i] + "' CLUT total entries > 100M (suspicious)",
                    "ICC.1-2022-05 §10.8", ""});
            }
        }
    }

    if (!found) return CheckResult::skip("No LUT tags found");
    if (findings.empty()) return CheckResult::ok("LUT dimensions are plausible");
    return {CheckResult::Status::FINDINGS, "LUT dimension issue", std::move(findings)};
}

// ── CF-076: Curve Response Direction ───────────────────────────────────────

static CheckResult check_cf076_curve_response_direction(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 76};
    bool found = false;

    static const icFloatNumber kSamplePoints[] = { 0.0f, 0.25f, 0.5f, 0.75f, 1.0f };
    static constexpr int kNumSamples = 5;
    static constexpr icFloatNumber kDecreaseTol = 0.01f;

    for (int i = 0; i < kLUTDirCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAToBSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        LPIccCurve *curvesB = mbb->GetCurvesB();
        if (!curvesB) continue;

        int nCurves = mbb->IsInputB() ? mbb->InputChannels() : mbb->OutputChannels();
        if (nCurves < 1 || nCurves > 16) continue;
        found = true;

        for (int c = 0; c < nCurves; c++) {
            if (!curvesB[c]) continue;
            icFloatNumber prev = curvesB[c]->Apply(kSamplePoints[0]);
            for (int s = 1; s < kNumSamples; s++) {
                icFloatNumber val = curvesB[c]->Apply(kSamplePoints[s]);
                if (val < prev - kDecreaseTol) {
                    char buf[192];
                    snprintf(buf, sizeof(buf),
                        "AToB%d B-curve[%d] decreases from %.4f to %.4f at input %.2f",
                        i, c, (double)prev, (double)val, (double)kSamplePoints[s]);
                    findings.push_back({cfId, Severity::MEDIUM, buf,
                        "ICC.1-2022-05 §10.5", ""});
                    break;
                }
                prev = val;
            }
        }
    }

    if (!found) return CheckResult::skip("No AToB tags with B curves found");
    if (findings.empty()) return CheckResult::ok("B curves are non-decreasing");
    return {CheckResult::Status::FINDINGS, "B-curve not non-decreasing", std::move(findings)};
}

// ── CF-077: CLUT Grid Size Plausibility ────────────────────────────────────

static CheckResult check_cf077_clut_grid_size_plausibility(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 77};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        CIccCLUT *clut = mbb->GetCLUT();
        if (!clut) continue;
        found = true;

        int nDims = clut->GetInputDim();
        for (int d = 0; d < nDims; d++) {
            int gp = static_cast<int>(clut->GridPoint(d));
            if (gp < 2) {
                char buf[128];
                snprintf(buf, sizeof(buf), "Tag '%s' dim %d grid points = %d (< 2, cannot interpolate)",
                         kAllLUTNames[i], d, gp);
                findings.push_back({cfId, Severity::MEDIUM, buf,
                    "ICC.1-2022-05 §10.8", ""});
            }
        }

        icUInt32Number nPoints = clut->NumPoints();
        if (nPoints > 10000000U) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Tag '%s' total grid points = %u (> 10M, likely malformed)",
                     kAllLUTNames[i], nPoints);
            findings.push_back({cfId, Severity::MEDIUM, buf,
                "ICC.1-2022-05 §10.8", ""});
        }
    }

    if (!found) return CheckResult::skip("No CLUT elements found");
    if (findings.empty()) return CheckResult::ok("CLUT grid sizes are plausible");
    return {CheckResult::Status::FINDINGS, "CLUT grid size issue", std::move(findings)};
}

// ── CF-078: MBB B-Curve Presence ───────────────────────────────────────────

static CheckResult check_cf078_mbb_b_curve_presence(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 78};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        if (tag->GetType() != icSigLutAtoBType && tag->GetType() != icSigLutBtoAType)
            continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        found = true;

        if (!mbb->GetCurvesB()) {
            findings.push_back({cfId, Severity::HIGH,
                std::string("Tag '") + kAllLUTNames[i] + "' B curves missing (required for " +
                (tag->GetType() == icSigLutAtoBType ? "lutAToBType" : "lutBToAType") + ")",
                "ICC.1-2022-05 §10.10-10.12", ""});
        }
    }

    if (!found) return CheckResult::skip("No lutAToBType/lutBToAType tags found");
    if (findings.empty()) return CheckResult::ok("B curves present in all MBB tags");
    return {CheckResult::Status::FINDINGS, "Missing B curves in MBB tag", std::move(findings)};
}

// ── CF-079: LUT Bit Depth Consistency ──────────────────────────────────────

static CheckResult check_cf079_lut_bit_depth_consistency(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 79};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;

        // Check lut8Type
        CIccTagLut8 *lut8 = dynamic_cast<CIccTagLut8 *>(tag);
        if (lut8) {
            found = true;
            int nIn  = lut8->InputChannels();
            int nOut = lut8->OutputChannels();

            LPIccCurve *curvesB = lut8->GetCurvesB();
            if (curvesB) {
                for (int c = 0; c < nIn && c < 16; c++) {
                    if (!curvesB[c]) continue;
                    CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesB[c]);
                    if (curve && curve->GetSize() != 256) {
                        findings.push_back({cfId, Severity::MEDIUM,
                            std::string("Tag '") + kAllLUTNames[i] + "' lut8 input curve[" +
                            std::to_string(c) + "] has " + std::to_string(curve->GetSize()) +
                            " entries (must be 256)",
                            "ICC.1-2022-05 §10.9", ""});
                    }
                }
            }
            LPIccCurve *curvesA = lut8->GetCurvesA();
            if (curvesA) {
                for (int c = 0; c < nOut && c < 16; c++) {
                    if (!curvesA[c]) continue;
                    CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesA[c]);
                    if (curve && curve->GetSize() != 256) {
                        findings.push_back({cfId, Severity::MEDIUM,
                            std::string("Tag '") + kAllLUTNames[i] + "' lut8 output curve[" +
                            std::to_string(c) + "] has " + std::to_string(curve->GetSize()) +
                            " entries (must be 256)",
                            "ICC.1-2022-05 §10.9", ""});
                    }
                }
            }
            continue;
        }

        // Check lut16Type
        CIccTagLut16 *lut16 = dynamic_cast<CIccTagLut16 *>(tag);
        if (lut16) {
            found = true;
            int nIn  = lut16->InputChannels();
            int nOut = lut16->OutputChannels();

            LPIccCurve *curvesB = lut16->GetCurvesB();
            if (curvesB) {
                for (int c = 0; c < nIn && c < 16; c++) {
                    if (!curvesB[c]) continue;
                    CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesB[c]);
                    if (curve && curve->GetSize() < 2) {
                        findings.push_back({cfId, Severity::MEDIUM,
                            std::string("Tag '") + kAllLUTNames[i] + "' lut16 input curve[" +
                            std::to_string(c) + "] has " + std::to_string(curve->GetSize()) +
                            " entries (must be >= 2)",
                            "ICC.1-2022-05 §10.10", ""});
                    }
                }
            }
            LPIccCurve *curvesA = lut16->GetCurvesA();
            if (curvesA) {
                for (int c = 0; c < nOut && c < 16; c++) {
                    if (!curvesA[c]) continue;
                    CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(curvesA[c]);
                    if (curve && curve->GetSize() < 2) {
                        findings.push_back({cfId, Severity::MEDIUM,
                            std::string("Tag '") + kAllLUTNames[i] + "' lut16 output curve[" +
                            std::to_string(c) + "] has " + std::to_string(curve->GetSize()) +
                            " entries (must be >= 2)",
                            "ICC.1-2022-05 §10.10", ""});
                    }
                }
            }
        }
    }

    if (!found) return CheckResult::skip("No lut8/lut16 type tags found");
    if (findings.empty()) return CheckResult::ok("Legacy LUT curve sizes are consistent");
    return {CheckResult::Status::FINDINGS, "Legacy LUT curve size issue", std::move(findings)};
}

// ── CF-105: LUT Channel Symmetry ───────────────────────────────────────────

static CheckResult check_cf105_lut_channel_symmetry(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 105};
    bool found = false;

    for (int i = 0; i < kLUTDirCount; i++) {
        CIccTag *aTag = pIcc->FindTag(kAToBSigs[i]);
        CIccTag *bTag = pIcc->FindTag(kBToASigs[i]);
        if (!aTag || !bTag) continue;
        CIccMBB *aMBB = dynamic_cast<CIccMBB *>(aTag);
        CIccMBB *bMBB = dynamic_cast<CIccMBB *>(bTag);
        if (!aMBB || !bMBB) continue;
        found = true;

        if (aMBB->InputChannels() != bMBB->OutputChannels()) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Intent %d: AToB input=%u != BToA output=%u",
                     i, (unsigned)aMBB->InputChannels(), (unsigned)bMBB->OutputChannels());
            findings.push_back({cfId, Severity::HIGH, buf,
                "ICC.1-2022-05 §10.8-10.11", ""});
        }
        if (aMBB->OutputChannels() != bMBB->InputChannels()) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Intent %d: AToB output=%u != BToA input=%u",
                     i, (unsigned)aMBB->OutputChannels(), (unsigned)bMBB->InputChannels());
            findings.push_back({cfId, Severity::HIGH, buf,
                "ICC.1-2022-05 §10.8-10.11", ""});
        }
    }

    if (!found) return CheckResult::skip("No AToB/BToA tag pairs found");
    if (findings.empty()) return CheckResult::ok("LUT channel symmetry validated");
    return {CheckResult::Status::FINDINGS, "Channel symmetry violation", std::move(findings)};
}

// ── CF-106: Curve Monotonicity ─────────────────────────────────────────────

static CheckResult check_cf106_curve_monotonicity(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 106};
    bool found = false;

    static const icTagSignature trcSigs[] = {
        icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag
    };
    static const char *trcNames[] = { "rTRC", "gTRC", "bTRC", "kTRC" };

    for (int i = 0; i < 4; i++) {
        CIccTag *tag = pIcc->FindTag(trcSigs[i]);
        if (!tag) continue;
        CIccTagCurve *curve = dynamic_cast<CIccTagCurve *>(tag);
        if (!curve) continue;
        icUInt32Number n = curve->GetSize();
        if (n < 2) continue;
        found = true;

        bool monotone = true;
        for (icUInt32Number j = 1; j < n; j++) {
            if ((*curve)[j] < (*curve)[j - 1]) {
                monotone = false;
                break;
            }
        }

        if (!monotone) {
            findings.push_back({cfId, Severity::MEDIUM,
                std::string(trcNames[i]) + " TRC curve is not monotonically non-decreasing",
                "ICC.1-2022-05 §10.5", ""});
        }
    }

    if (!found) return CheckResult::skip("No tabulated TRC curves found");
    if (findings.empty()) return CheckResult::ok("TRC curves are monotonically non-decreasing");
    return {CheckResult::Status::FINDINGS, "TRC monotonicity violation", std::move(findings)};
}

// ── CF-108: CLUT Grid Point Range ──────────────────────────────────────────

static CheckResult check_cf108_clut_grid_point_range(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 108};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        CIccCLUT *clut = mbb->GetCLUT();
        if (!clut) continue;
        found = true;

        int nDims = clut->GetInputDim();
        for (int d = 0; d < nDims; d++) {
            int gp = static_cast<int>(clut->GridPoint(d));
            if (gp < 2) {
                char buf[128];
                snprintf(buf, sizeof(buf), "Tag '%s' dim %d: grid points=%u (must be 2-255)",
                         kAllLUTNames[i], d, (unsigned)gp);
                findings.push_back({cfId, Severity::HIGH, buf,
                    "ICC.1-2022-05 §10.8", ""});
            }
        }
    }

    if (!found) return CheckResult::skip("No CLUT elements found");
    if (findings.empty()) return CheckResult::ok("CLUT grid points in valid range [2,255]");
    return {CheckResult::Status::FINDINGS, "CLUT grid points out of range", std::move(findings)};
}

// ── CF-109: Matrix Column Normalization ────────────────────────────────────

static CheckResult check_cf109_matrix_column_normalization(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 109};

    static const icTagSignature matSigs[] = {
        icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag
    };
    static const char *matNames[] = { "rXYZ", "gXYZ", "bXYZ" };

    bool allPresent = true;
    for (int i = 0; i < 3; i++) {
        if (!pIcc->FindTag(matSigs[i])) { allPresent = false; break; }
    }
    if (!allPresent) return CheckResult::skip("Not all matrix column tags present");

    icFloatNumber ySum = 0.0;
    for (int i = 0; i < 3; i++) {
        CIccTag *tag = pIcc->FindTag(matSigs[i]);
        CIccTagXYZ *xyz = dynamic_cast<CIccTagXYZ *>(tag);
        if (!xyz || xyz->GetSize() < 1) continue;

        icXYZNumber val = (*xyz)[0];
        icFloatNumber x = icFtoD(val.X);
        icFloatNumber y = icFtoD(val.Y);
        icFloatNumber z = icFtoD(val.Z);

        if (y < 0.0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "%s Y value is negative (%.4f)", matNames[i], (double)y);
            findings.push_back({cfId, Severity::MEDIUM, buf,
                "ICC.1-2022-05 §9.2.7", ""});
        }
        if (x < -2.0 || x > 4.0 || y < -2.0 || y > 4.0 || z < -2.0 || z > 4.0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "%s values out of range (X=%.4f Y=%.4f Z=%.4f)",
                     matNames[i], (double)x, (double)y, (double)z);
            findings.push_back({cfId, Severity::MEDIUM, buf,
                "ICC.1-2022-05 §9.2.7", ""});
        }
        ySum += y;
    }

    if (std::fabs(ySum - 1.0) > 0.05) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Sum of matrix column Y values = %.4f (expected ~1.0 for D50)", (double)ySum);
        findings.push_back({cfId, Severity::MEDIUM, buf,
            "TN v4_matrix", ""});
    }

    if (findings.empty()) return CheckResult::ok("Matrix columns properly normalized");
    return {CheckResult::Status::FINDINGS, "Matrix column normalization issue", std::move(findings)};
}

// ── CF-110: B Curves vs CLUT Output ────────────────────────────────────────

static CheckResult check_cf110_b_curves_vs_clut_output(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 110};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        icTagTypeSignature ttype = tag->GetType();
        if (ttype != icSigLutAtoBType && ttype != icSigLutBtoAType) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        CIccCLUT *clut = mbb->GetCLUT();
        if (!clut) continue;
        found = true;

        icUInt16Number outCh = mbb->OutputChannels();
        icUInt16Number clutOut = clut->GetOutputChannels();
        if (clutOut != outCh) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Tag '%s' CLUT output=%u but tag output=%u",
                     kAllLUTNames[i], (unsigned)clutOut, (unsigned)outCh);
            findings.push_back({cfId, Severity::HIGH, buf,
                "ICC.1-2022-05 §10.8", ""});
        }
    }

    if (!found) return CheckResult::skip("No lutAToB/lutBToA with CLUT found");
    if (findings.empty()) return CheckResult::ok("B curves match CLUT output channels");
    return {CheckResult::Status::FINDINGS, "B curve / CLUT output mismatch", std::move(findings)};
}

// ── CF-116: Curve Segment Continuity ───────────────────────────────────────

static CheckResult check_cf116_curve_segment_continuity(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 116};
    bool found = false;

    static const icTagSignature trcSigs[] = {
        icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag
    };
    static const char *trcNames[] = { "rTRC", "gTRC", "bTRC", "kTRC" };

    for (int i = 0; i < 4; i++) {
        CIccTag *tag = pIcc->FindTag(trcSigs[i]);
        if (!tag) continue;
        CIccTagParametricCurve *para = dynamic_cast<CIccTagParametricCurve *>(tag);
        if (!para) continue;
        found = true;

        icUInt16Number funcType = para->GetFunctionType();
        int nParams = para->GetNumParam();

        if (funcType >= 1 && funcType <= 4 && nParams >= 4) {
            icFloatNumber g = para->Param(0);
            if (g < 0.0 || !std::isfinite(g)) {
                char buf[128];
                snprintf(buf, sizeof(buf), "%s parametric gamma=%.4f is invalid",
                         trcNames[i], (double)g);
                findings.push_back({cfId, Severity::MEDIUM, buf,
                    "ICC.1-2022-05 §10.18", ""});
            }
        }
    }

    if (!found) return CheckResult::skip("No parametricCurveType TRC tags found");
    if (findings.empty()) return CheckResult::ok("Curve segments continuous");
    return {CheckResult::Status::FINDINGS, "Curve segment continuity issue", std::move(findings)};
}

// ── CF-163: LUT Matrix Coefficient Finite ──────────────────────────────────

static CheckResult check_cf163_lut_matrix_coefficient_finite(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 163};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        const CIccMatrix *matrix = mbb->GetMatrix();
        if (!matrix) continue;
        found = true;

        int nCoeff = matrix->m_bUseConstants ? 12 : 9;
        for (int k = 0; k < nCoeff; k++) {
            double v = static_cast<double>(matrix->m_e[k]);
            if (std::isnan(v) || std::isinf(v)) {
                char buf[128];
                snprintf(buf, sizeof(buf), "Tag '%s' m_e[%d] = %f (non-finite)",
                         kAllLUTNames[i], k, v);
                findings.push_back({cfId, Severity::HIGH, buf,
                    "s15Fixed16Number encoding", ""});
            }
        }
    }

    if (!found) return CheckResult::skip("No LUT tags with matrix found");
    if (findings.empty()) return CheckResult::ok("All LUT matrix coefficients are finite");
    return {CheckResult::Status::FINDINGS, "Non-finite matrix coefficient", std::move(findings)};
}

// ── CF-164: LUT Matrix s15Fixed16 Range ────────────────────────────────────

static CheckResult check_cf164_lut_matrix_s15fixed16_range(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 164};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        const CIccMatrix *matrix = mbb->GetMatrix();
        if (!matrix) continue;
        found = true;

        int nCoeff = matrix->m_bUseConstants ? 12 : 9;
        for (int k = 0; k < nCoeff; k++) {
            double v = static_cast<double>(matrix->m_e[k]);
            if (v < kS15F16Min || v > kS15F16Max) {
                char buf[160];
                snprintf(buf, sizeof(buf),
                    "Tag '%s' m_e[%d] = %.4f outside s15Fixed16 range [%.1f, %.5f]",
                    kAllLUTNames[i], k, v, kS15F16Min, kS15F16Max);
                findings.push_back({cfId, Severity::HIGH, buf,
                    "ICC v4 Matrix Entries TN", ""});
            }
        }
    }

    if (!found) return CheckResult::skip("No LUT tags with matrix found");
    if (findings.empty()) return CheckResult::ok("All LUT matrix coefficients within s15Fixed16 range");
    return {CheckResult::Status::FINDINGS, "Matrix coefficient outside s15Fixed16 range", std::move(findings)};
}

// ── CF-165: LUT Matrix Determinant Non-Singular ────────────────────────────

static CheckResult check_cf165_lut_matrix_determinant_non_singular(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 165};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        const CIccMatrix *matrix = mbb->GetMatrix();
        if (!matrix) continue;
        found = true;

        double a = (double)matrix->m_e[0], b = (double)matrix->m_e[1], c = (double)matrix->m_e[2];
        double d = (double)matrix->m_e[3], e = (double)matrix->m_e[4], f = (double)matrix->m_e[5];
        double g = (double)matrix->m_e[6], h = (double)matrix->m_e[7], k = (double)matrix->m_e[8];
        double det = a * (e * k - f * h) - b * (d * k - f * g) + c * (d * h - e * g);

        if (std::fabs(det) < kDetEpsilon) {
            char buf[192];
            snprintf(buf, sizeof(buf),
                "Tag '%s' determinant = %.8f (singular), matrix: "
                "[%.4f %.4f %.4f] [%.4f %.4f %.4f] [%.4f %.4f %.4f]",
                kAllLUTNames[i], det, a, b, c, d, e, f, g, h, k);
            findings.push_back({cfId, Severity::HIGH, buf,
                "ICC v4 Matrix Entries TN", ""});
        }
    }

    if (!found) return CheckResult::skip("No LUT tags with matrix found");
    if (findings.empty()) return CheckResult::ok("All LUT matrices are non-singular");
    return {CheckResult::Status::FINDINGS, "Singular LUT matrix detected", std::move(findings)};
}

// ── CF-166: LUT Matrix Row Non-Zero ────────────────────────────────────────

static CheckResult check_cf166_lut_matrix_row_non_zero(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 166};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        const CIccMatrix *matrix = mbb->GetMatrix();
        if (!matrix) continue;
        found = true;

        for (int row = 0; row < 3; row++) {
            double r0 = std::fabs((double)matrix->m_e[row * 3 + 0]);
            double r1 = std::fabs((double)matrix->m_e[row * 3 + 1]);
            double r2 = std::fabs((double)matrix->m_e[row * 3 + 2]);
            if (r0 < 1e-10 && r1 < 1e-10 && r2 < 1e-10) {
                char buf[128];
                snprintf(buf, sizeof(buf),
                    "Tag '%s' row %d is all-zero [%.6f, %.6f, %.6f] -> output channel %d is constant",
                    kAllLUTNames[i], row, r0, r1, r2, row);
                findings.push_back({cfId, Severity::MEDIUM, buf,
                    "ICC v4 Matrix Entries TN", ""});
            }
        }
    }

    if (!found) return CheckResult::skip("No LUT tags with matrix found");
    if (findings.empty()) return CheckResult::ok("All LUT matrix rows have non-zero elements");
    return {CheckResult::Status::FINDINGS, "All-zero matrix row detected", std::move(findings)};
}

// ── CF-167: LUT Matrix Offset Bounds ───────────────────────────────────────

static CheckResult check_cf167_lut_matrix_offset_bounds(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 167};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        const CIccMatrix *matrix = mbb->GetMatrix();
        if (!matrix) continue;
        if (!matrix->m_bUseConstants) continue;
        found = true;

        for (int k = 9; k < 12; k++) {
            double v = static_cast<double>(matrix->m_e[k]);
            if (std::fabs(v) > kOffsetReasonableMax) {
                char buf[128];
                snprintf(buf, sizeof(buf), "Tag '%s' m_e[%d] = %.4f (|value| > %.1f)",
                         kAllLUTNames[i], k, v, kOffsetReasonableMax);
                findings.push_back({cfId, Severity::MEDIUM, buf,
                    "ICC v4 Matrix Entries TN", ""});
            }
        }
    }

    if (!found) return CheckResult::skip("No LUT tags with matrix offset constants found");
    if (findings.empty()) return CheckResult::ok("All LUT matrix offsets within reasonable bounds");
    return {CheckResult::Status::FINDINGS, "Matrix offset constant unusually large", std::move(findings)};
}

// ── CF-168: LUT Matrix Input-Output Range ──────────────────────────────────

static CheckResult check_cf168_lut_matrix_input_output_range(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 168};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB *>(tag);
        if (!mbb) continue;
        const CIccMatrix *matrix = mbb->GetMatrix();
        if (!matrix) continue;
        found = true;

        for (int axis = 0; axis < 3; axis++) {
            for (int row = 0; row < 3; row++) {
                double y = static_cast<double>(matrix->m_e[row * 3 + axis]);
                if (matrix->m_bUseConstants)
                    y += static_cast<double>(matrix->m_e[9 + row]);
                if (y < kOutputReasonableMin || y > kOutputReasonableMax) {
                    char buf[160];
                    snprintf(buf, sizeof(buf),
                        "Tag '%s' axis(%d,0,0)[%d] -> %.4f outside [%.1f, %.1f]",
                        kAllLUTNames[i], axis, row, y,
                        kOutputReasonableMin, kOutputReasonableMax);
                    findings.push_back({cfId, Severity::MEDIUM, buf,
                        "ICC v4 Matrix Entries TN", ""});
                }
            }
        }
    }

    if (!found) return CheckResult::skip("No LUT tags with matrix found");
    if (findings.empty()) return CheckResult::ok("LUT matrix outputs within expected range");
    return {CheckResult::Status::FINDINGS, "Matrix output outside expected PCS range", std::move(findings)};
}

// ── CF-231: LUT Processing Element Sequence ────────────────────────────────

static CheckResult check_cf231_lut_processing_element_sequence(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 231};

    static const icTagSignature kLutTags[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    };

    int checked = 0;
    for (auto sig : kLutTags) {
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;
        CIccMBB *pMBB = dynamic_cast<CIccMBB *>(pTag);
        if (!pMBB) continue;
        checked++;

        bool hasBCurves = pMBB->GetCurvesB() != nullptr;
        bool hasMatrix  = pMBB->GetMatrix() != nullptr;
        bool hasMCurves = pMBB->GetCurvesM() != nullptr;
        bool hasCLUT    = pMBB->GetCLUT() != nullptr;
        bool hasACurves = pMBB->GetCurvesA() != nullptr;

        char sigStr[5];
        sigStr[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));
        sigStr[1] = static_cast<char>(static_cast<unsigned char>((sig >> 16) & 0xFF));
        sigStr[2] = static_cast<char>(static_cast<unsigned char>((sig >> 8) & 0xFF));
        sigStr[3] = static_cast<char>(static_cast<unsigned char>(sig & 0xFF));
        sigStr[4] = '\0';

        if (!hasBCurves) {
            findings.push_back({cfId, Severity::MEDIUM,
                std::string("'") + sigStr + "': missing B curves (always required)",
                "ICC.1-2022-05 §10.10-10.11", ""});
        }
        if (hasMatrix != hasMCurves) {
            char buf[128];
            snprintf(buf, sizeof(buf),
                "'%s': matrix present=%d but M curves present=%d — must appear together",
                sigStr, hasMatrix, hasMCurves);
            findings.push_back({cfId, Severity::MEDIUM, buf,
                "ICC.1-2022-05 §10.10-10.11", ""});
        }
        if (hasACurves && !hasCLUT) {
            findings.push_back({cfId, Severity::MEDIUM,
                std::string("'") + sigStr + "': A curves present without CLUT",
                "ICC.1-2022-05 §10.10-10.11", ""});
        }

        icUInt16Number inCh = pMBB->InputChannels();
        icUInt16Number outCh = pMBB->OutputChannels();
        if (inCh == 0 || outCh == 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "'%s': zero channel count (in=%u, out=%u)",
                     sigStr, inCh, outCh);
            findings.push_back({cfId, Severity::MEDIUM, buf,
                "ICC.1-2022-05 §10.10-10.11", ""});
        }
    }

    if (checked == 0) return CheckResult::skip("No lutAtoB/lutBtoA type tags found");
    if (findings.empty())
        return CheckResult::ok("All " + std::to_string(checked) + " LUT processing element sequences valid");
    return {CheckResult::Status::FINDINGS, "LUT processing element sequence issue", std::move(findings)};
}

// ── CF-255: CLUT Grid Point Values ─────────────────────────────────────────

static CheckResult check_cf255_clut_grid_point_values(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 255};
    bool found = false;

    for (int i = 0; i < kAllLUTCount; i++) {
        CIccTag *pTag = pIcc->FindTag(kAllLUTSigs[i]);
        if (!pTag) continue;
        CIccMBB *pMBB = dynamic_cast<CIccMBB *>(pTag);
        if (!pMBB) continue;
        CIccCLUT *pCLUT = pMBB->GetCLUT();
        if (!pCLUT) continue;
        found = true;

        unsigned int nInput = pMBB->InputChannels();
        for (unsigned int d = 0; d < nInput && d < 16; d++) {
            icUInt8Number gp = pCLUT->GridPoint(d);
            if (gp < 2) {
                char buf[128];
                snprintf(buf, sizeof(buf),
                    "CLUT grid point[%u]=%u is below minimum of 2", d, gp);
                findings.push_back({cfId, Severity::HIGH, buf,
                    "ICC.1-2022-05 §10.12", ""});
            }
        }
    }

    if (!found) return CheckResult::skip("No CLUT elements found");
    if (findings.empty()) return CheckResult::ok("CLUT grid point values valid");
    return {CheckResult::Status::FINDINGS, "CLUT grid point below minimum", std::move(findings)};
}

// ── CF-256: LUT I/O Channels vs Profile Spaces ────────────────────────────

static CheckResult check_cf256_lut_i_o_channels_vs_profile_spaces(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 256};

    icUInt32Number nDataChannels = icGetSpaceSamples(pIcc->m_Header.colorSpace);
    icUInt32Number nPCSChannels = icGetSpaceSamples(pIcc->m_Header.pcs);
    bool found = false;

    for (int i = 0; i < kLUTDirCount; i++) {
        CIccTag *pTag = pIcc->FindTag(kAToBSigs[i]);
        if (!pTag) continue;
        CIccMBB *pMBB = dynamic_cast<CIccMBB *>(pTag);
        if (!pMBB) continue;
        found = true;

        if (pIcc->m_Header.deviceClass != icSigLinkClass) {
            if (pMBB->InputChannels() != nDataChannels) {
                char buf[128];
                snprintf(buf, sizeof(buf),
                    "AToB%d input channels (%u) != colorSpace channels (%u)",
                    i, (unsigned)pMBB->InputChannels(), nDataChannels);
                findings.push_back({cfId, Severity::HIGH, buf,
                    "ICC.1-2022-05 §10.12", ""});
            }
            if (pMBB->OutputChannels() != nPCSChannels) {
                char buf[128];
                snprintf(buf, sizeof(buf),
                    "AToB%d output channels (%u) != PCS channels (%u)",
                    i, (unsigned)pMBB->OutputChannels(), nPCSChannels);
                findings.push_back({cfId, Severity::HIGH, buf,
                    "ICC.1-2022-05 §10.12", ""});
            }
        }
    }

    if (!found) return CheckResult::skip("No AToB tags found");
    if (findings.empty()) return CheckResult::ok("LUT I/O channels match profile spaces");
    return {CheckResult::Status::FINDINGS, "LUT channel vs profile space mismatch", std::move(findings)};
}

// ── CF-261: M-Curve Count = 3 When Matrix Present ──────────────────────────

static CheckResult check_cf261_m_curve_count_3_when_matrix_present(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 261};
    bool found = false;

    // Check AToB tags
    for (int i = 0; i < kLUTDirCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAToBSigs[i]);
        if (!tag || tag->GetType() != icSigLutAtoBType) continue;
        CIccTagLutAtoB *atob = dynamic_cast<CIccTagLutAtoB *>(tag);
        if (!atob) continue;

        if (atob->GetMatrix() && atob->GetCurvesM()) {
            found = true;
            CIccCurve *const *pMCurves = atob->GetCurvesM();
            unsigned int nM = atob->OutputChannels();
            int mCount = 0;
            for (unsigned int c = 0; c < nM; c++) { if (pMCurves[c]) mCount++; }

            if (mCount != 3) {
                char buf[128];
                snprintf(buf, sizeof(buf),
                    "AToB%d: matrix present with %d M-curves (expected 3)", i, mCount);
                findings.push_back({cfId, Severity::HIGH, buf,
                    "ICC.1-2022-05 §10.11", ""});
            }
        }
    }

    // Check BToA tags
    for (int i = 0; i < kLUTDirCount; i++) {
        CIccTag *tag = pIcc->FindTag(kBToASigs[i]);
        if (!tag || tag->GetType() != icSigLutBtoAType) continue;
        CIccTagLutBtoA *btoa = dynamic_cast<CIccTagLutBtoA *>(tag);
        if (!btoa) continue;

        if (btoa->GetMatrix() && btoa->GetCurvesM()) {
            found = true;
            CIccCurve *const *pMCurves = btoa->GetCurvesM();
            unsigned int nM = btoa->InputChannels();
            int mCount = 0;
            for (unsigned int c = 0; c < nM; c++) { if (pMCurves[c]) mCount++; }

            if (mCount != 3) {
                char buf[128];
                snprintf(buf, sizeof(buf),
                    "BToA%d: matrix present with %d M-curves (expected 3)", i, mCount);
                findings.push_back({cfId, Severity::HIGH, buf,
                    "ICC.1-2022-05 §10.12", ""});
            }
        }
    }

    if (!found) return CheckResult::skip("No lutAToB/BToA tags with matrix+M-curves found");
    if (findings.empty()) return CheckResult::ok("M-curve count consistent with matrix presence");
    return {CheckResult::Status::FINDINGS, "M-curve count mismatch with matrix", std::move(findings)};
}

// ── CF-262: B-Curve Count vs Output Channels ───────────────────────────────

static CheckResult check_cf262_b_curve_count_vs_output_channels(const ProfileView& pv) {
    CIccProfile *pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::error("Library not loaded");

    std::vector<Finding> findings;
    CheckID cfId{CheckID::Kind::Conformance, 262};
    bool found = false;

    for (int i = 0; i < kLUTDirCount; i++) {
        CIccTag *tag = pIcc->FindTag(kAToBSigs[i]);
        if (!tag || tag->GetType() != icSigLutAtoBType) continue;
        CIccTagLutAtoB *atob = dynamic_cast<CIccTagLutAtoB *>(tag);
        if (!atob) continue;
        found = true;

        CIccCurve *const *pBCurves = atob->GetCurvesB();
        if (!pBCurves) continue;

        unsigned int outChan = atob->OutputChannels();
        int bCount = 0;
        for (unsigned int c = 0; c < outChan; c++) {
            if (pBCurves[c]) bCount++;
        }

        if (bCount > 0 && outChan > 0 && bCount != (int)outChan) {
            char buf[128];
            snprintf(buf, sizeof(buf), "AToB%d: %d B-curves vs %u output channels",
                     i, bCount, outChan);
            findings.push_back({cfId, Severity::HIGH, buf,
                "ICC.1-2022-05 §10.11", ""});
        }
    }

    if (!found) return CheckResult::skip("No lutAToBType tags found");
    if (findings.empty()) return CheckResult::ok("B-curve count matches output channel count");
    return {CheckResult::Status::FINDINGS, "B-curve count / output channel mismatch", std::move(findings)};
}

// ── Registrations (37 checks) ──

REGISTER_CONFORMANCE(60, "LUT Input Channel Count",
    "§10.8-10.11", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf060_lut_input_channel_count);

REGISTER_CONFORMANCE(61, "LUT Output Channel Count",
    "§10.8-10.11", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf061_lut_output_channel_count);

REGISTER_CONFORMANCE(62, "CLUT Grid Dimensionality",
    "§10.8-10.11", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf062_clut_grid_dimensionality);

REGISTER_CONFORMANCE(63, "lut8Type Fixed Table Size 256",
    "§10.9", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf063_lut8type_fixed_table_size_256);

REGISTER_CONFORMANCE(64, "lut16Type Table Size Range 2-4096",
    "§10.10", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf064_lut16type_table_size_range_2_4096);

REGISTER_CONFORMANCE(65, "lutAToBType Processing Element Present",
    "§10.11", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf065_lutatobtype_processing_element_present);

REGISTER_CONFORMANCE(66, "lutBToAType Processing Element Present",
    "§10.12", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf066_lutbtoatype_processing_element_present);

REGISTER_CONFORMANCE(67, "lut8/16 Matrix Identity When Not PCSXYZ",
    "§10.8-10.10", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf067_lut8_16_matrix_identity_when_not_pcsxyz);

REGISTER_CONFORMANCE(68, "Chromatic Adaptation Matrix Invertible",
    "§9.2.10", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf068_chromatic_adaptation_matrix_invertible);

REGISTER_CONFORMANCE(69, "Matrix Column Tag XYZ Count",
    "§9.2.7, §9.2.18, §9.2.31", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf069_matrix_column_tag_xyz_count);

REGISTER_CONFORMANCE(70, "Chad s15Fixed16 Array Count 9",
    "§9.2.10", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf070_chad_s15fixed16_array_count_9);

REGISTER_CONFORMANCE(71, "Curve Count vs Channel Match",
    "§10.8/10.9", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf071_curve_count_vs_channel_match);

REGISTER_CONFORMANCE(72, "CLUT Output Value Range",
    "§10.8/10.9", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf072_clut_output_value_range);

REGISTER_CONFORMANCE(73, "MBB Matrix Determinant Non-Zero",
    "§10.8/10.9", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf073_mbb_matrix_determinant_non_zero);

REGISTER_CONFORMANCE(74, "A2B/B2A Dimension Consistency",
    "§8", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf074_a2b_b2a_dimension_consistency);

REGISTER_CONFORMANCE(75, "Tag Data Size vs Dimensions",
    "§10.8/10.9", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf075_tag_data_size_vs_dimensions);

REGISTER_CONFORMANCE(76, "Curve Response Direction",
    "§10.8/10.9", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf076_curve_response_direction);

REGISTER_CONFORMANCE(77, "CLUT Grid Size Plausibility",
    "§10.8/10.9", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf077_clut_grid_size_plausibility);

REGISTER_CONFORMANCE(78, "MBB B-Curve Presence",
    "§10.8/10.9", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf078_mbb_b_curve_presence);

REGISTER_CONFORMANCE(79, "LUT Bit Depth Consistency",
    "§10.10/10.11", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf079_lut_bit_depth_consistency);

REGISTER_CONFORMANCE(105, "LUT Channel Symmetry",
    "§10.8-10.11 (AToB/BToA channel consistency)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf105_lut_channel_symmetry);

REGISTER_CONFORMANCE(106, "Curve Monotonicity",
    "§10.5 (TRC curves monotonically non-decreasing)", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf106_curve_monotonicity);

REGISTER_CONFORMANCE(108, "CLUT Grid Point Range",
    "§10.8-10.11 (CLUT grid points in [2,255])", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf108_clut_grid_point_range);

REGISTER_CONFORMANCE(109, "Matrix Column Normalization",
    "§9.2.35-37 (rXYZ+gXYZ+bXYZ Y sum ≈ 1.0)", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf109_matrix_column_normalization);

REGISTER_CONFORMANCE(110, "B Curves vs CLUT Output",
    "§10.8-10.11 (B curve count = CLUT output channels)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf110_b_curves_vs_clut_output);

REGISTER_CONFORMANCE(116, "Curve Segment Continuity",
    "§10.18 (parametric curve gamma positive/finite)", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf116_curve_segment_continuity);

REGISTER_CONFORMANCE(163, "LUT Matrix Coefficient Finite",
    "All 12 matrix coefficients in lutAToBType/lutBToAType/lut8/lut16 must be finite (not NaN/Inf)", "ICC v4 Matrix Entries TN",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf163_lut_matrix_coefficient_finite);

REGISTER_CONFORMANCE(164, "LUT Matrix s15Fixed16 Range",
    "Matrix coefficients must be within s15Fixed16Number representable range [-32768, +32768)", "ICC v4 Matrix Entries TN",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf164_lut_matrix_s15fixed16_range);

REGISTER_CONFORMANCE(165, "LUT Matrix Determinant Non-Singular",
    "3x3 LUT matrix determinant must be non-zero — singular matrix causes irreversible data loss", "ICC v4 Matrix Entries TN",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf165_lut_matrix_determinant_non_singular);

REGISTER_CONFORMANCE(166, "LUT Matrix Row Non-Zero",
    "Each row of the 3x3 matrix must have at least one non-zero element", "ICC v4 Matrix Entries TN",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf166_lut_matrix_row_non_zero);

REGISTER_CONFORMANCE(167, "LUT Matrix Offset Bounds",
    "Matrix offset constants e10-e12 should be within reasonable range for normalized PCS", "ICC v4 Matrix Entries TN",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf167_lut_matrix_offset_bounds);

REGISTER_CONFORMANCE(168, "LUT Matrix Input-Output Range",
    "Matrix applied to unit-cube corners should produce output within practical PCS range", "ICC v4 Matrix Entries TN",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf168_lut_matrix_input_output_range);

REGISTER_CONFORMANCE(231, "LUT Processing Element Sequence",
    "lutAtoBType/lutBtoAType: B curves required, matrix+M curves paired, A curves need CLUT", "ICC.1-2022-05 §10.10-10.11",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf231_lut_processing_element_sequence);

REGISTER_CONFORMANCE(255, "CLUT Grid Point Values",
    "CLUT grid point values must be >= 2 for each input dimension", "ICC.1-2022-05 §10.12",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf255_clut_grid_point_values);

REGISTER_CONFORMANCE(256, "LUT I/O Channels vs Profile Spaces",
    "AToB input channels must match data colour space, output must match PCS", "ICC.1-2022-05 §10.12",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf256_lut_i_o_channels_vs_profile_spaces);

REGISTER_CONFORMANCE(261, "M-Curve Count = 3 When Matrix Present",
    "lutAToBType and lutBToAType M-curve count must be exactly 3 when matrix is present", "ICC.1-2022-05 §10.11",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf261_m_curve_count_3_when_matrix_present);

REGISTER_CONFORMANCE(262, "B-Curve Count vs Output Channels",
    "lutAToBType B-curve count must match the number of output channels", "ICC.1-2022-05 §10.11",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf262_b_curve_count_vs_output_channels);
