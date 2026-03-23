# ICCAnalyzer PAWG Quality Coverage

This note captures the current V1/V2 PAWG quality-lane coverage that is shared
through `IccQualityMetrics.h`.

## Current Coverage

- `Q1` bounded round-trip CIEDE2000 covers:
  - matrix/TRC RGB and Gray profiles
  - classic LUT round-trip pairs `A2B0/B2A0`, `A2B1/B2A1`, and `A2B2/B2A2`
  - classic LUT inputs up to 4 channels via bounded grid sampling
- `Q2` curve invertibility covers:
  - TRC curves
  - classic/MBB curve sets from `A2B0/B2A0`, `A2B1/B2A1`, `A2B2/B2A2`
  - `D2B0/B2D0`, `D2B1/B2D1`, and `D2B2/B2D2` when present
- `Q3` transform smoothness covers:
  - matrix/TRC multi-axis sampling for Gray and RGB
  - classic LUT forward transforms up to 4 input channels
  - diagonal plus per-axis bounded sweeps instead of diagonal-only sampling
- `Q4` characterization-data-driven quality evaluation covers:
  - `charTargetTag` rows with RGB, Gray, and CMYK device columns
  - classic LUT forward transforms selected from `A2B0`, `A2B1`, or `A2B2`
  - matrix/TRC forward evaluation when no classic LUT forward tag is present

## Regression Fixtures

- `tests/corpus/lut8_atob2_btoa2.icc`
  - proves alternate-intent classic LUT quality coverage
  - expected PAWG: `Q1 [WARN]`, `Q2 [OK]`, `Q3 [OK]`, `Q4 [N/A]`
- `tests/corpus/targ_quality_profile.icc`
  - proves characterization-data evaluation on the RGB/matrix path
  - expected PAWG: `Q1 [OK]`, `Q2 [OK]`, `Q3 [OK]`, `Q4 [OK]`
- `tests/corpus/targ_cmyk_quality_profile.icc`
  - proves CMYK characterization parsing plus reversible classic LUT quality
  - expected PAWG: `Q1 [OK]`, `Q2 [OK]`, `Q3 [OK]`, `Q4 [OK]`

## Verification

- V1 harness: `python3 iccanalyzer-lite/tests/run_tests.py`
- V2 PAWG verifier:
  `python3 iccanalyzer-lite/icctest/tools/verifyPawg.py`
- V2 parity verifier:
  `cmake --build iccanalyzer-lite/icctest/build --target icctest-verify-parity`

These expectations are parity-sensitive: V1 and V2 should continue to report the
same PAWG item verdicts for the fixtures above unless the canonical PAWG mapping
changes in both engines together.
