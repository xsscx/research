// IccConformanceRegistry.h — ICC Specification Conformance Check Registry
//
// Table-driven registry of conformance checks derived from:
//   ICC.1-2022-05 (v4.4), ICC.2-2023 (v5/iccMAX),
//   ICC TN-ProfileEmbedding, ICC TN-PartialAdaptation,
//   ICC.1 Adaptive Gain Curve, ICC WP-21 Compliance,
//   ICCSpecRevision dictType
//
// Each check validates a specific ICC specification requirement.
// Checks run in default conformance mode (not --legacy).
//
// SPDX-License-Identifier: MIT

#ifndef ICC_CONFORMANCE_REGISTRY_H
#define ICC_CONFORMANCE_REGISTRY_H

#include <cstdint>

// Conformance check severity
enum class CFSeverity : uint8_t {
  ERROR,    // Spec violation — profile is non-conformant
  WARNING,  // Likely issue but spec allows it (version-dependent, etc.)
  INFO      // Informational — deviation from best practice
};

// Conformance check category (maps to source file)
enum class CFCategory : uint8_t {
  HEADER,       // IccConformanceHeader.cpp
  TAG_TYPES,    // IccConformanceTagTypes.cpp
  REQUIRED,     // IccConformanceRequired.cpp
  LUT,          // IccConformanceLUT.cpp
  V5            // IccConformanceV5.cpp
};

// Registry entry for a conformance check
struct ConformanceCheck {
  const char *id;         // "CF-001" etc.
  const char *title;      // Short descriptive name
  const char *specRef;    // "ICC.1-2022-05 §7.2.8" etc.
  const char *specDoc;    // "ICC.1-2022-05" or "ICC.2-2023" etc.
  CFSeverity severity;
  CFCategory category;
};

// ── The conformance check registry ──────────────────────────────────────────
// Add new entries at the end. Do NOT reorder or remove existing entries.

static const ConformanceCheck kConformanceRegistry[] = {

  // ═══════════════════════════════════════════════════════════════════════════
  // HEADER CONFORMANCE (CF-001 to CF-019) — IccConformanceHeader.cpp
  // ═══════════════════════════════════════════════════════════════════════════

  {"CF-001", "Date/Time Month-Day Validity",
   "§7.2.8", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-002", "Date/Time Leap Year Validation",
   "§7.2.8", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-003", "Profile Flags Reserved Bits",
   "§7.2.11 Table 21", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-004", "Device Attributes Reserved Bits",
   "§7.2.14", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-005", "Rendering Intent Upper Bits Zero",
   "§7.2.15", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-006", "Profile Version BCD Encoding",
   "§7.2.4", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-007", "Primary Platform Signature",
   "§7.2.10 Table 20", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::HEADER},

  {"CF-008", "PCS Illuminant D50 Precision",
   "§7.2.16", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-009", "Chromatic Adaptation Tag Requirement",
   "§8.2, TN-PartialAdaptation", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-010", "Profile Size vs File Size",
   "§7.2.2", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-011", "Profile ID MD5 Verification",
   "§7.2.18, RFC 1321", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::HEADER},

  {"CF-012", "Profile Class Signature",
   "§7.2.5 Table 18", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-013", "Data Colour Space Signature",
   "§7.2.6 Table 19", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-014", "PCS Field for Non-DeviceLink",
   "§7.2.7", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-015", "Reserved Bytes 100-127 Zero",
   "§7.2.24", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  // ═══════════════════════════════════════════════════════════════════════════
  // TAG TYPE CONFORMANCE (CF-020 to CF-039) — IccConformanceTagTypes.cpp
  // ═══════════════════════════════════════════════════════════════════════════

  {"CF-020", "Tag Type Allowed for Signature",
   "§9.2, §10", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-021", "Tag Type Reserved Bytes Zero",
   "§10 (all types)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-022", "curveType Entry Count Mode",
   "§10.6", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-023", "parametricCurveType Function Type",
   "§10.18 Table 68", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-024", "parametricCurveType Parameter Count",
   "§10.18 Table 68", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-025", "chromaticityType Phosphor Count",
   "§10.2", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-026", "colorantTableType Colorant Count",
   "§10.4", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-027", "colorantOrderType Count Match",
   "§10.3", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-028", "namedColor2Type Coordinate Count",
   "§10.14", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-029", "dateTimeType Field Ranges",
   "§10.7, §4.2", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-030", "multiLocalizedUnicodeType Structure",
   "§10.13", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-031", "s15Fixed16ArrayType Element Count",
   "§10.18", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-032", "XYZType Triplet Count",
   "§10.23", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-033", "measurementType Standard Observer",
   "§10.12 Table 56", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-034", "measurementType Measurement Geometry",
   "§10.12 Table 57", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  // ═══════════════════════════════════════════════════════════════════════════
  // REQUIRED TAGS CONFORMANCE (CF-040 to CF-059) — IccConformanceRequired.cpp
  // ═══════════════════════════════════════════════════════════════════════════

  {"CF-040", "Common Required Tags (Non-DeviceLink)",
   "§8.2", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-041", "Input Profile Required Tags",
   "§8.3 Tables 22-24", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-042", "Display Profile Required Tags",
   "§8.4 Tables 25-27", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-043", "Output Profile Required Tags",
   "§8.5 Tables 28-29", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-044", "DeviceLink Profile Required Tags",
   "§8.6 Table 30", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-045", "ColorSpace Profile Required Tags",
   "§8.7 Table 31", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-046", "Abstract Profile Required Tags",
   "§8.8 Table 32", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-047", "NamedColor Profile Required Tags",
   "§8.9 Table 33", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-048", "Rendering Intent Transform Consistency",
   "§7.2.15, §8", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::REQUIRED},

  {"CF-049", "Matrix/TRC Profile PCS Must Be XYZ",
   "§8.3-8.4", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-050", "xCLR Colorant Table Required",
   "§8.5-8.6", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-051", "DeviceLink Prohibited Tags",
   "§8.6 Table 30", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-052", "Transform Tag Pair Consistency",
   "§8.3-8.5", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::REQUIRED},

  {"CF-053", "cicpTag Class Restriction",
   "§9.2.11", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  // ═══════════════════════════════════════════════════════════════════════════
  // LUT/CURVE CONFORMANCE (CF-060 to CF-074) — IccConformanceLUT.cpp
  // ═══════════════════════════════════════════════════════════════════════════

  {"CF-060", "LUT Input Channel Count",
   "§10.8-10.11", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-061", "LUT Output Channel Count",
   "§10.8-10.11", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-062", "CLUT Grid Dimensionality",
   "§10.8-10.11", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-063", "lut8Type Fixed Table Size 256",
   "§10.9", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-064", "lut16Type Table Size Range 2-4096",
   "§10.10", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-065", "lutAToBType Processing Element Present",
   "§10.11", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-066", "lutBToAType Processing Element Present",
   "§10.12", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-067", "lut8/16 Matrix Identity When Not PCSXYZ",
   "§10.8-10.10", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::LUT},

  {"CF-068", "Chromatic Adaptation Matrix Invertible",
   "§9.2.10", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-069", "Matrix Column Tag XYZ Count",
   "§9.2.7, §9.2.18, §9.2.31", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-070", "Chad s15Fixed16 Array Count 9",
   "§9.2.10", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  // ═══════════════════════════════════════════════════════════════════════════
  // V5/iccMAX CONFORMANCE (CF-080 to CF-094) — IccConformanceV5.cpp
  // ═══════════════════════════════════════════════════════════════════════════

  {"CF-080", "v5 Spectral PCS Signature",
   "§7.2.22", "ICC.2-2023",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-081", "v5 Spectral PCS Range Validity",
   "§7.2.23", "ICC.2-2023",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-082", "v5 PCC Tags Required When Spectral",
   "§8 (spectral classes)", "ICC.2-2023",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-083", "v5 MCS Signature Encoding",
   "§7.2.25", "ICC.2-2023",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-084", "v5 Profile Sub-Class Signature",
   "§7.2.26", "ICC.2-2023",
   CFSeverity::WARNING, CFCategory::V5},

  {"CF-085", "v5 Version Field 5.x BCD",
   "§7.2.4", "ICC.2-2023",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-086", "v5 Extended Attribute Bits",
   "§7.2.14", "ICC.2-2023",
   CFSeverity::INFO, CFCategory::V5},

  {"CF-087", "v5 MPE Element Signature Valid",
   "§10.x (MPE types)", "ICC.2-2023",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-088", "v5 Calculator Element Stack Structure",
   "§10.x (calc)", "ICC.2-2023",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-089", "v5 Spectral Wavelength Range",
   "§7.2.23 (380-780nm typical)", "ICC.2-2023",
   CFSeverity::WARNING, CFCategory::V5},
};

static constexpr int kConformanceCheckCount =
    sizeof(kConformanceRegistry) / sizeof(kConformanceRegistry[0]);

#endif // ICC_CONFORMANCE_REGISTRY_H
