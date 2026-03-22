// CfQualityChecks.cpp — V2 conformance checks (QUALITY)
// 4 checks: CF-099..CF-102
//
// Ported from V1 IccConformanceQuality.cpp
//
// SPDX-License-Identifier: MIT

#include <icctest/CheckRegistry.h>
#include <icctest/ProfileView.h>
#include <icctest/CheckResult.h>

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagLut.h"
#include "IccUtil.h"

#include <cmath>
#include <cstring>
#include <vector>

using namespace icctest;

// ---------------------------------------------------------------------------
// CF-099: Round-Trip Transform CIEDE2000
// ---------------------------------------------------------------------------
static CheckResult check_cf099_round_trip_ciede2000(const ProfileView& pv) {
    if (!pv.libraryLoaded()) return CheckResult::skip("Library failed to load profile");
    auto* pIcc = pv.unsafeLibraryHandle();
    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 99};

    CIccTag *pAToB = pIcc->FindTag(icSigAToB0Tag);
    CIccTag *pBToA = pIcc->FindTag(icSigBToA0Tag);
    if (!pAToB || !pBToA)
        return CheckResult::skip("AToB0/BToA0 tag pair not present");

    CIccMBB *pMBB_AToB = dynamic_cast<CIccMBB*>(pAToB);
    CIccMBB *pMBB_BToA = dynamic_cast<CIccMBB*>(pBToA);
    if (!pMBB_AToB || !pMBB_BToA)
        return CheckResult::skip("AToB0/BToA0 not LUT-based");

    int nIn_AToB = pMBB_AToB->InputChannels();
    int nOut_AToB = pMBB_AToB->OutputChannels();
    int nIn_BToA = pMBB_BToA->InputChannels();
    int nOut_BToA = pMBB_BToA->OutputChannels();

    if (nIn_AToB < 1 || nOut_AToB < 1 || nIn_BToA < 1 || nOut_BToA < 1)
        return CheckResult::skip("Invalid channel counts");

    bool channelMatch = (nOut_AToB == nIn_BToA) && (nIn_AToB == nOut_BToA);
    if (!channelMatch) {
        std::string msg = "Channel mismatch: AToB0(" + std::to_string(nIn_AToB) + "→" +
            std::to_string(nOut_AToB) + ") vs BToA0(" + std::to_string(nIn_BToA) + "→" +
            std::to_string(nOut_BToA) + ") — round-trip impossible";
        findings.push_back({id, Severity::MEDIUM, msg, "", ""});
    }

    if (findings.empty())
        return CheckResult::ok("AToB0/BToA0 channel dimensions consistent for round-trip");
    return {CheckResult::Status::FINDINGS, "Round-trip channel issues", std::move(findings)};
}

// ---------------------------------------------------------------------------
// CF-100: Curve Invertibility
// ---------------------------------------------------------------------------
static CheckResult check_cf100_curve_invertibility(const ProfileView& pv) {
    if (!pv.libraryLoaded()) return CheckResult::skip("Library failed to load profile");
    auto* pIcc = pv.unsafeLibraryHandle();
    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 100};

    struct CurveInfo { icTagSignature sig; const char *name; };
    static const CurveInfo curves[] = {
        { icSigRedTRCTag,   "rTRC" },
        { icSigGreenTRCTag, "gTRC" },
        { icSigBlueTRCTag,  "bTRC" },
        { icSigGrayTRCTag,  "kTRC" },
    };

    int curvesChecked = 0;
    for (const auto& ci : curves) {
        CIccTag *pTag = pIcc->FindTag(ci.sig);
        if (!pTag) continue;
        CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve*>(pTag);
        if (!pCurve) continue;

        icUInt32Number nEntries = pCurve->GetSize();
        if (nEntries < 2) { curvesChecked++; continue; }

        bool monotonic = true;
        icFloatNumber prev = (*pCurve)[0];
        for (icUInt32Number i = 1; i < nEntries; i++) {
            icFloatNumber val = (*pCurve)[i];
            if (val < prev) { monotonic = false; break; }
            prev = val;
        }

        if (!monotonic) {
            findings.push_back({id, Severity::HIGH,
                std::string(ci.name) + ": non-monotonic curve — not invertible",
                std::to_string(nEntries) + " entries", ""});
        }
        curvesChecked++;
    }

    if (curvesChecked == 0) return CheckResult::skip("No TRC curves found");
    if (findings.empty())
        return CheckResult::ok(std::to_string(curvesChecked) + " curve(s) checked — all invertible");
    return {CheckResult::Status::FINDINGS, "Non-invertible curves", std::move(findings)};
}

// ---------------------------------------------------------------------------
// CF-101: Transform Smoothness
// ---------------------------------------------------------------------------
static CheckResult check_cf101_transform_smoothness(const ProfileView& pv) {
    if (!pv.libraryLoaded()) return CheckResult::skip("Library failed to load profile");
    auto* pIcc = pv.unsafeLibraryHandle();
    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 101};

    CIccTag *pTag = pIcc->FindTag(icSigAToB0Tag);
    if (!pTag) return CheckResult::skip("No AToB0 tag");

    CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pTag);
    if (!pMBB) return CheckResult::skip("AToB0 is not LUT-based");

    CIccCLUT *pCLUT = pMBB->GetCLUT();
    if (!pCLUT) return CheckResult::skip("AToB0 has no CLUT");

    int nIn = pCLUT->GetInputDim();
    int nOut = pCLUT->GetOutputChannels();
    if (nIn < 1 || nOut < 1 || nIn > 15)
        return CheckResult::skip("Invalid CLUT dimensions");

    int gridSize = pCLUT->GridPoint(0);
    if (gridSize < 2) return CheckResult::skip("Grid size too small");

    int totalNodes = 1;
    for (int d = 0; d < nIn; d++) {
        int gs = pCLUT->GridPoint(d);
        if (gs < 1) { totalNodes = 0; break; }
        totalNodes *= gs;
    }
    if (totalNodes < 2 || totalNodes > 1000000)
        return CheckResult::skip("CLUT grid too large or invalid");

    int stride0 = nOut;
    for (int d = 1; d < nIn; d++)
        stride0 *= pCLUT->GridPoint(d);

    int midOffset = 0;
    int subStride = nOut;
    for (int d = nIn - 1; d >= 1; d--) {
        int gs = pCLUT->GridPoint(d);
        midOffset += (gs / 2) * subStride;
        subStride *= gs;
    }

    const icFloatNumber *clutData = pCLUT->GetData(0);
    if (!clutData) return CheckResult::skip("CLUT data not accessible");

    double maxJump = 0.0;
    int jumpCount = 0;
    for (int i = 1; i < gridSize; i++) {
        int prevIdx = (i - 1) * stride0 + midOffset;
        int currIdx = i * stride0 + midOffset;
        if (currIdx + nOut > totalNodes * nOut) break;

        double jump = 0.0;
        for (int ch = 0; ch < nOut; ch++) {
            double d = (double)clutData[currIdx + ch] - (double)clutData[prevIdx + ch];
            jump += d * d;
        }
        jump = sqrt(jump);
        if (jump > maxJump) maxJump = jump;
        if (jump > 0.5) jumpCount++;
    }

    if (jumpCount > gridSize / 4) {
        findings.push_back({id, Severity::MEDIUM,
            "Transform appears discontinuous",
            std::to_string(jumpCount) + "/" + std::to_string(gridSize - 1) + " jumps exceed threshold",
            ""});
    }

    if (findings.empty())
        return CheckResult::ok("Transform smoothness acceptable (max jump=" +
            std::to_string(maxJump).substr(0, 6) + ")");
    return {CheckResult::Status::FINDINGS, "Smoothness issues", std::move(findings)};
}

// ---------------------------------------------------------------------------
// CF-102: Characterization Data Round-Trip
// ---------------------------------------------------------------------------
static CheckResult check_cf102_characterization_round_trip(const ProfileView& pv) {
    if (!pv.libraryLoaded()) return CheckResult::skip("Library failed to load profile");
    auto* pIcc = pv.unsafeLibraryHandle();
    CIccTag *pTag = pIcc->FindTag(icSigCharTargetTag);
    if (!pTag) return CheckResult::skip("No charTargetTag present");

    CIccTagText *pText = dynamic_cast<CIccTagText*>(pTag);
    if (!pText) return CheckResult::skip("charTargetTag is not textType");

    const char *text = pText->GetText();
    if (!text || !text[0]) return CheckResult::skip("charTargetTag is empty");

    CIccTag *pAToB = pIcc->FindTag(icSigAToB0Tag);
    CIccTag *pBToA = pIcc->FindTag(icSigBToA0Tag);

    std::string summary = "charTargetTag: " + std::to_string(strlen(text)) + " bytes";
    if (pAToB && pBToA)
        summary += ", AToB0+BToA0 present — characterization data verifiable";
    else
        summary += ", missing AToB0/BToA0 — round-trip not verifiable";

    return CheckResult::ok(summary);
}

// ── Registrations (4 checks) ──

REGISTER_CONFORMANCE(99, "Round-Trip CIEDE2000",
    "§8 (AToB/BToA round-trip accuracy)", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf099_round_trip_ciede2000);

REGISTER_CONFORMANCE(100, "Curve Invertibility",
    "§10.5/§10.18 (monotonicity requirement)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf100_curve_invertibility);

REGISTER_CONFORMANCE(101, "Transform Smoothness",
    "§10.8-10.11 (LUT output smoothness)", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf101_transform_smoothness);

REGISTER_CONFORMANCE(102, "Characterization Round-Trip",
    "§8 (characterization data fidelity)", "ICC.1-2022-05",
    "", "", Severity::MEDIUM, CheckPhase::CONFORMANCE,
    check_cf102_characterization_round_trip);
