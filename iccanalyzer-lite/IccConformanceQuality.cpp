/// @file IccConformanceQuality.cpp
/// @brief Profile quality conformance checks (CF-099 through CF-102).
///
/// Validates ICC profile quality metrics:
/// - Round-trip transform accuracy (AToB→BToA)
/// - Curve invertibility
/// - Transform smoothness
/// - Characterization data fidelity
///
/// @see ICC.1-2022-05 §8 (Required transform tags per class)
/// @see ICC WP-21 Compliance (CIEDE2000 quality thresholds)

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagLut.h"
#include "IccUtil.h"
#include "IccConformanceRegistry.h"
#include "IccConformanceQuality.h"
#include "IccHeuristicResult.h"
#include "IccAnalyzerColors.h"
#include "IccQualityMetrics.h"
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstring>

static void PrintQualityCoverageLine(const char *label, const std::string &reason) {
  printf("           %s[%s]%s %s\n",
         ColorInfo(), label, ColorReset(), reason.c_str());
}

static void RecordQualityCoverage(HeuristicCollector &hc,
                                  const char *label,
                                  const std::string &reason) {
  hc.info("%s: %s", label, reason.c_str());
}

static bool IsCharacterizationNotApplicable(const std::string &reason) {
  return reason.find("No characterization data") != std::string::npos;
}

// ---------------------------------------------------------------------------
// CF-099: Round-Trip Transform CIEDE2000
//   PAWG Q28: "First/second round trip CIEDE2000"
//   Tests AToB0→BToA0 round-trip accuracy across a grid of PCS Lab values.
//   ICC.1-2022-05 §8: Profiles with AToB/BToA pairs should produce
//   accurate round-trip transforms.
// ---------------------------------------------------------------------------
int RunCF099_RoundTripDeltaE(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  printf("  %s[CF-099]%s Round-Trip Transform CIEDE2000 (%sICC.1-2022-05 §8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  iccquality::RoundTripMetrics metrics;
  std::string reason;
  if (!iccquality::measure_round_trip(pIcc, metrics, reason)) {
    PrintQualityCoverageLine("GAP", reason);
    RecordQualityCoverage(hc, "GAP", reason);
    return 0;
  }

  printf("           Model: %s, samples: %d\n",
         metrics.model.c_str(), metrics.samples);
  printf("           First round trip:  avg DeltaE00=%.4f  max DeltaE00=%.4f\n",
         metrics.avgFirstDe00, metrics.maxFirstDe00);
  printf("           Second round trip: avg DeltaE00=%.4f  max DeltaE00=%.4f\n",
         metrics.avgSecondDe00, metrics.maxSecondDe00);

  printf("           %s[OK]%s Round-trip DeltaE00 metrics recorded\n",
         ColorSuccess(), ColorReset());

  return issues;
}

// ---------------------------------------------------------------------------
// CF-100: Curve Invertibility
//   PAWG Q29: "Curve round trip differences"
//   For TRC curves (red/green/blue), test forward→inverse invertibility.
//   ICC.1-2022-05 §10.6: curveType values should be monotonically increasing.
// ---------------------------------------------------------------------------
int RunCF100_CurveInvertibility(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-100]%s Curve Invertibility Check (%sICC.1-2022-05 §10.6%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  const auto metrics = iccquality::measure_curve_invertibility(pIcc);
  if (metrics.curves.empty()) {
    const std::string reason = "No supported curves found";
    PrintQualityCoverageLine("N/A", reason);
    RecordQualityCoverage(HeuristicCollector::instance(), "N/A", reason);
    return 0;
  }

  for (const auto &curve : metrics.curves) {
    printf("           %s: avg inv err=%.6f  max err=%.6f\n",
           curve.name.c_str(), curve.avgError, curve.maxError);
    if (!curve.monotonic) {
      printf("           %s[WARN]%s %s is non-monotonic — not reliably invertible\n",
             ColorWarning(), ColorReset(), curve.name.c_str());
      issues++;
    } else if (curve.flat) {
      printf("           %s[WARN]%s %s is effectively flat — not invertible\n",
             ColorWarning(), ColorReset(), curve.name.c_str());
      issues++;
    }
  }

  if (issues == 0) {
    printf("           %s[OK]%s %zu curve(s) checked — invertibility metrics recorded\n",
           ColorSuccess(), ColorReset(), metrics.curves.size());
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-101: Transform Smoothness Metric
//   PAWG Q30: "Smoothness metric values"
//   For CLUT-based transforms, check that neighboring grid points have
//   smoothly varying output values (large jumps indicate discontinuities).
// ---------------------------------------------------------------------------
int RunCF101_TransformSmoothness(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  printf("  %s[CF-101]%s Transform Smoothness (%sICC.1-2022-05 §10.8%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  iccquality::SmoothnessMetrics metrics;
  std::string reason;
  if (!iccquality::measure_transform_smoothness(pIcc, metrics, reason)) {
    PrintQualityCoverageLine("GAP", reason);
    RecordQualityCoverage(hc, "GAP", reason);
    return 0;
  }

  printf("           Model: %s, samples: %d\n",
         metrics.model.c_str(), metrics.samples);
  printf("           Avg step DeltaE00=%.4f  max step DeltaE00=%.4f  max curvature=%.4f\n",
         metrics.avgStepDe00, metrics.maxStepDe00, metrics.maxCurvatureDe00);
  printf("           Large discontinuities (>6.0 DeltaE00): %d\n",
         metrics.discontinuities);

  printf("           %s[OK]%s Transform smoothness metrics recorded\n",
         ColorSuccess(), ColorReset());

  return issues;
}

// ---------------------------------------------------------------------------
// CF-102: Characterization Data Round-Trip CIEDE2000
//   PAWG Q31: "Characterization data round trip CIEDE2000"
//   If the profile contains a 'targ' tag (characterization target data),
//   validates that the measurement data round-trips through the profile.
// ---------------------------------------------------------------------------
int RunCF102_CharacterizationRoundTrip(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  printf("  %s[CF-102]%s Characterization Data Round-Trip (%sICC.1-2022-05 §9.2.26%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  iccquality::CharacterizationMetrics metrics;
  std::string reason;
  if (!iccquality::evaluate_characterization(pIcc, metrics, reason)) {
    const char *label = IsCharacterizationNotApplicable(reason) ? "N/A" : "GAP";
    PrintQualityCoverageLine(label, reason);
    RecordQualityCoverage(hc, label, reason);
    return 0;
  }

  printf("           charTargetTag fields=%d rows=%d usableRows=%d\n",
         metrics.fieldCount, metrics.rowCount, metrics.rowsUsed);
  printf("           Characterization fidelity: avg DeltaE00=%.4f  max DeltaE00=%.4f\n",
         metrics.avgDe00, metrics.maxDe00);

  printf("           %s[OK]%s Characterization DeltaE00 metrics recorded\n",
         ColorSuccess(), ColorReset());

  return issues;
}

// ---------------------------------------------------------------------------
// Runner: all quality conformance checks
// ---------------------------------------------------------------------------
int RunQualityConformance(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  int r;

#define CF_WRAP(id, title, call) \
  hc.begin(id, title); \
  r = call; \
  if (r > 0) hc.warn("%d non-conformance(s)", r); \
  hc.end("Conformant"); \
  issues += r;

  CF_WRAP(1099, "CF-099: Round-Trip CIEDE2000", RunCF099_RoundTripDeltaE(pIcc));
  CF_WRAP(1100, "CF-100: Curve Invertibility", RunCF100_CurveInvertibility(pIcc));
  CF_WRAP(1101, "CF-101: Transform Smoothness", RunCF101_TransformSmoothness(pIcc));
  CF_WRAP(1102, "CF-102: Characterization Round-Trip", RunCF102_CharacterizationRoundTrip(pIcc));

#undef CF_WRAP
  return issues;
}
