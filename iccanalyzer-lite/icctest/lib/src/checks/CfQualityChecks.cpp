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
#include "../../../../IccQualityMetrics.h"

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

    iccquality::RoundTripMetrics metrics;
    std::string reason;
    if (!iccquality::measure_round_trip(pIcc, metrics, reason))
        return CheckResult::skip(reason);

    char detail[256];
    std::snprintf(detail, sizeof(detail),
                  "model=%s samples=%d first(avg=%.4f max=%.4f) second(avg=%.4f max=%.4f)",
                  metrics.model.c_str(), metrics.samples,
                  metrics.avgFirstDe00, metrics.maxFirstDe00,
                  metrics.avgSecondDe00, metrics.maxSecondDe00);

    if (metrics.maxFirstDe00 > 5.0 || metrics.avgFirstDe00 > 2.0 ||
        metrics.maxSecondDe00 > 5.0 || metrics.avgSecondDe00 > 2.0) {
        findings.push_back({id, Severity::MEDIUM,
            "Bounded round-trip DeltaE00 exceeds expected limits",
            detail, ""});
        return {CheckResult::Status::FINDINGS, "Round-trip DeltaE00 out of bounds", std::move(findings)};
    }

    return CheckResult::ok(detail);
}

// ---------------------------------------------------------------------------
// CF-100: Curve Invertibility
// ---------------------------------------------------------------------------
static CheckResult check_cf100_curve_invertibility(const ProfileView& pv) {
    if (!pv.libraryLoaded()) return CheckResult::skip("Library failed to load profile");
    auto* pIcc = pv.unsafeLibraryHandle();
    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 100};

    const auto metrics = iccquality::measure_curve_invertibility(pIcc);
    if (metrics.curves.empty()) return CheckResult::skip("No supported curves found");

    for (const auto& curve : metrics.curves) {
        char detail[160];
        std::snprintf(detail, sizeof(detail), "avgErr=%.6f maxErr=%.6f",
                      curve.avgError, curve.maxError);
        if (!curve.monotonic) {
            findings.push_back({id, Severity::HIGH,
                curve.name + ": non-monotonic curve — not reliably invertible",
                detail, ""});
        } else if (curve.flat) {
            findings.push_back({id, Severity::HIGH,
                curve.name + ": flat curve — not invertible",
                detail, ""});
        } else if (curve.maxError > 0.01) {
            findings.push_back({id, Severity::HIGH,
                curve.name + ": bounded invertibility error exceeds threshold",
                detail, ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok(std::to_string(metrics.curves.size()) +
                               " curve(s) checked — bounded invertibility acceptable");
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

    iccquality::SmoothnessMetrics metrics;
    std::string reason;
    if (!iccquality::measure_transform_smoothness(pIcc, metrics, reason))
        return CheckResult::skip(reason);

    char detail[192];
    std::snprintf(detail, sizeof(detail),
                  "model=%s samples=%d avgStep=%.4f maxStep=%.4f maxCurvature=%.4f discontinuities=%d",
                  metrics.model.c_str(), metrics.samples,
                  metrics.avgStepDe00, metrics.maxStepDe00,
                  metrics.maxCurvatureDe00, metrics.discontinuities);

    if (metrics.maxStepDe00 > 8.0 || metrics.maxCurvatureDe00 > 4.0 ||
        metrics.discontinuities > 4) {
        findings.push_back({id, Severity::MEDIUM,
            "Transform smoothness exceeds bounded continuity expectations",
            detail, ""});
        return {CheckResult::Status::FINDINGS, "Smoothness issues", std::move(findings)};
    }

    return CheckResult::ok(detail);
}

// ---------------------------------------------------------------------------
// CF-102: Characterization Data Round-Trip
// ---------------------------------------------------------------------------
static CheckResult check_cf102_characterization_round_trip(const ProfileView& pv) {
    if (!pv.libraryLoaded()) return CheckResult::skip("Library failed to load profile");
    auto* pIcc = pv.unsafeLibraryHandle();
    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 102};

    iccquality::CharacterizationMetrics metrics;
    std::string reason;
    if (!iccquality::evaluate_characterization(pIcc, metrics, reason))
        return CheckResult::skip(reason);

    char detail[192];
    std::snprintf(detail, sizeof(detail),
                  "fields=%d rows=%d usableRows=%d avgDeltaE00=%.4f maxDeltaE00=%.4f",
                  metrics.fieldCount, metrics.rowCount, metrics.rowsUsed,
                  metrics.avgDe00, metrics.maxDe00);

    if (metrics.maxDe00 > 5.0 || metrics.avgDe00 > 2.0) {
        findings.push_back({id, Severity::MEDIUM,
            "Characterization-driven DeltaE00 exceeds bounded expectations",
            detail, ""});
        return {CheckResult::Status::FINDINGS, "Characterization fidelity issues", std::move(findings)};
    }

    return CheckResult::ok(detail);
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
