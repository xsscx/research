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
  V5,           // IccConformanceV5.cpp
  SECURITY,     // IccConformanceSecurity.cpp
  QUALITY       // IccConformanceQuality.cpp
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

  {"CF-016", "Device Manufacturer Signature",
   "§7.2.12", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::HEADER},

  {"CF-017", "Device Model Signature",
   "§7.2.13", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::HEADER},

  {"CF-018", "Device Attributes Semantic Bits",
   "§7.2.14", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::HEADER},

  {"CF-019", "Creator Signature",
   "§7.2.17", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::HEADER},

  // ═══════════════════════════════════════════════════════════════════════════
  // TAG TYPE CONFORMANCE (CF-020 to CF-039) — IccConformanceTagTypes.cpp
  // ═══════════════════════════════════════════════════════════════════════════
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

  {"CF-035", "responseCurveSet16Type Structure",
   "§10.18", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-036", "profileSequenceDescType Elements",
   "§10.17", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-037", "profileSequenceIdentifierType Validation",
   "§10.18", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-038", "dateTimeType Tag Range Validation",
   "§10.7", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-039", "signatureType Technology Validation",
   "§9.2.30 Table 29", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

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

  {"CF-054", "v5 Spectral Required Tags",
   "§8", "ICC.2-2023",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-055", "D2B/B2D Tag Pair Completeness",
   "§8", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::REQUIRED},

  {"CF-056", "Embedded Profile Structure",
   "§9.2", "ICC.2-2023",
   CFSeverity::WARNING, CFCategory::REQUIRED},

  {"CF-057", "Dictionary Tag Structure v5",
   "§9.2.25", "ICC.2-2023",
   CFSeverity::WARNING, CFCategory::REQUIRED},

  {"CF-058", "Profile Sequence Identifier v5",
   "§8", "ICC.2-2023",
   CFSeverity::WARNING, CFCategory::REQUIRED},

  {"CF-059", "Colorimetric Intent Image State",
   "§9.2.12", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::REQUIRED},

  // ═══════════════════════════════════════════════════════════════════════════
  // LUT/CURVE CONFORMANCE (CF-060 to CF-079) — IccConformanceLUT.cpp
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

  {"CF-071", "Curve Count vs Channel Match",
   "§10.8/10.9", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-072", "CLUT Output Value Range",
   "§10.8/10.9", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::LUT},

  {"CF-073", "MBB Matrix Determinant Non-Zero",
   "§10.8/10.9", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::LUT},

  {"CF-074", "A2B/B2A Dimension Consistency",
   "§8", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-075", "Tag Data Size vs Dimensions",
   "§10.8/10.9", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-076", "Curve Response Direction",
   "§10.8/10.9", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::LUT},

  {"CF-077", "CLUT Grid Size Plausibility",
   "§10.8/10.9", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::LUT},

  {"CF-078", "MBB B-Curve Presence",
   "§10.8/10.9", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-079", "LUT Bit Depth Consistency",
   "§10.10/10.11", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::LUT},

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

  {"CF-090", "Spectral Illuminant Consistency",
   "§7.2.17", "ICC.2-2023",
   CFSeverity::WARNING, CFCategory::V5},

  // ═══════════════════════════════════════════════════════════════════════════
  // Security Conformance (CF-091 .. CF-094)
  // ═══════════════════════════════════════════════════════════════════════════

  {"CF-091", "Malware Signature Scan",
   "PAWG S8 — embedded executable content", "PAWG Checklist",
   CFSeverity::ERROR, CFCategory::SECURITY},

  {"CF-092", "Private Tag Presence",
   "§9 (private tag identification)", "ICC.1-2022-05",
   CFSeverity::INFO, CFCategory::SECURITY},

  {"CF-093", "Private Tag Content Scan",
   "§9 (private tag content safety)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::SECURITY},

  {"CF-094", "NOP/Shellcode Pattern Scan",
   "PAWG S13 — NOP sled and shellcode patterns", "PAWG Checklist",
   CFSeverity::ERROR, CFCategory::SECURITY},

  // ═══════════════════════════════════════════════════════════════════════════
  // Required Tag Extension (CF-095 .. CF-098)
  // ═══════════════════════════════════════════════════════════════════════════

  {"CF-095", "Non-Required Tag Identification",
   "§8.2-§8.9 (required tags per class)", "ICC.1-2022-05",
   CFSeverity::INFO, CFCategory::REQUIRED},

  {"CF-096", "Private Tag Signature Range",
   "§9 (private tag signature conventions)", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::REQUIRED},

  {"CF-097", "Private Tag Documentation",
   "§9 (vendor documentation)", "ICC.1-2022-05",
   CFSeverity::INFO, CFCategory::REQUIRED},

  {"CF-098", "Undocumented Private Tags",
   "§9 (undocumented tag identification)", "ICC.1-2022-05",
   CFSeverity::INFO, CFCategory::REQUIRED},

  // ═══════════════════════════════════════════════════════════════════════════
  // Quality Conformance (CF-099 .. CF-102)
  // ═══════════════════════════════════════════════════════════════════════════

  {"CF-099", "Round-Trip CIEDE2000",
   "§8 (AToB/BToA round-trip accuracy)", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::QUALITY},

  {"CF-100", "Curve Invertibility",
   "§10.5/§10.18 (monotonicity requirement)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::QUALITY},

  {"CF-101", "Transform Smoothness",
   "§10.8-10.11 (LUT output smoothness)", "ICC.1-2022-05",
   CFSeverity::INFO, CFCategory::QUALITY},

  {"CF-102", "Characterization Round-Trip",
   "§8 (characterization data fidelity)", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::QUALITY},

  // Deep conformance checks (CF-103 .. CF-122)

  {"CF-103", "Tag Alignment and Offset",
   "§7.3 (tag table offset/alignment)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-104", "DeviceLink PCS Match",
   "§8.4 (DeviceLink required tags)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-105", "LUT Channel Symmetry",
   "§10.8-10.11 (AToB/BToA channel consistency)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-106", "Curve Monotonicity",
   "§10.5 (TRC curves monotonically non-decreasing)", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::LUT},

  {"CF-107", "Tag Table Ordering",
   "§7.3.1 (no duplicate tag signatures)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-108", "CLUT Grid Point Range",
   "§10.8-10.11 (CLUT grid points in [2,255])", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-109", "Matrix Column Normalization",
   "§9.2.35-37 (rXYZ+gXYZ+bXYZ Y sum ≈ 1.0)", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::LUT},

  {"CF-110", "B Curves vs CLUT Output",
   "§10.8-10.11 (B curve count = CLUT output channels)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-111", "Required Tags Per Version",
   "§8 (v4+ chad requirement for non-D50 adopted white)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-112", "XYZ Triplet Normalization",
   "§10.31 (XYZ values finite, Y non-negative)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-113", "Spectral Range Physical Bounds",
   "§7.2.23 (wavelengths within [100-2500] nm)", "ICC.2-2023",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-114", "MCS Colour Space Consistency",
   "§7.2.19 (MCS signature valid colour space)", "ICC.2-2023",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-115", "Calculator Element Complexity",
   "§10.2.6 (calculator sub-element limits)", "ICC.2-2023",
   CFSeverity::WARNING, CFCategory::V5},

  {"CF-116", "Curve Segment Continuity",
   "§10.18 (parametric curve gamma positive/finite)", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::LUT},

  {"CF-117", "Rendering Intent Tags Per Class",
   "§8.3-8.5 (rig0/rig2 only for Output/Display)", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::REQUIRED},

  {"CF-118", "Private Tag Creator Signature",
   "§7.2.12 (creator signature for private tags)", "ICC.1-2022-05",
   CFSeverity::INFO, CFCategory::REQUIRED},

  {"CF-119", "Profile Sequence Identifier",
   "§9.2.33-34 (profileSequenceDescTag/Identifier)", "ICC.1-2022-05",
   CFSeverity::INFO, CFCategory::REQUIRED},

  {"CF-120", "Named Color Space Dimensions",
   "§10.14 (device coords match colour space)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-121", "Illuminant Metadata Consistency",
   "§7.2.16 (wtpt matches D50 for v4)", "ICC.1-2022-05",
   CFSeverity::ERROR, CFCategory::HEADER},

  {"CF-122", "Profile Date/Time Plausibility",
   "§7.2.8 (date year in plausible range)", "ICC.1-2022-05",
   CFSeverity::WARNING, CFCategory::HEADER},

  // ADGC (Adaptive Gain Curve) — ICC.1 Amendment April 2025
  {"CF-123", "ADGC Class Restriction",
   "ADGC §3 (RGB + Input|Display only)", "ICC.1-ADGC-2025",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-124", "ADGC Type Signature",
   "ADGC Table 1 (type 'adgc' = 0x61646763)", "ICC.1-ADGC-2025",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-125", "ADGC Function Type ID",
   "ADGC Table 1 (functionTypeID must be 1)", "ICC.1-ADGC-2025",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-126", "ADGC Reserved Bytes",
   "ADGC Table 1 (bytes 4-7 shall be 0)", "ICC.1-ADGC-2025",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-127", "ADGC Float Field Finiteness",
   "ADGC Table 1 (all float32 fields finite)", "ICC.1-ADGC-2025",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-128", "ADGC Weight Coefficient Sum",
   "ADGC §5 (kR+kG+kB+kMax+kMin+kComp ≈ 1.0)", "ICC.1-ADGC-2025",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-129", "ADGC Curve Position Bounds",
   "ADGC Table 1 (positionNumber within tag)", "ICC.1-ADGC-2025",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-130", "ADGC Image-Specific GUID Flags",
   "ADGC §6 (GUID≠0 → flags bits 0,1 set)", "ICC.1-ADGC-2025",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-131", "ADGC Headroom Range Plausibility",
   "ADGC Table 1 (headroom log2 in reasonable range)", "ICC.1-ADGC-2025",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-132", "ADGC Curve Data Monotonicity",
   "ADGC Table 2 (x values monotonically increasing)", "ICC.1-ADGC-2025",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-133", "ADGC H_baseline vs H_alternate Division-by-Zero",
   "ADGC §1.2.3 (W_target denominator H_alt-H_base must be nonzero)", "ICC.1-ADGC-2025",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-134", "ADGC Per-Channel GainMin ≤ GainMax",
   "ADGC §1.2.3 (GainMin > GainMax inverts gain range)", "ICC.1-ADGC-2025",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-135", "ADGC Curve X-Value Domain Range",
   "ADGC §1.2.2 (first x ≥ 0.0, last x ≤ 1.0 for normalized input)", "ICC.1-ADGC-2025",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-136", "ADGC Curve Adjacent-Point X-Equality",
   "ADGC §1.2.2 (x1 == x2 → div-by-zero in cubic coefficient C3)", "ICC.1-ADGC-2025",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  // ── ICC.2-2019 Cumulative Errata checks (CF-137 .. CF-143) ────────────────

  {"CF-137", "MultiplexDefaultValues Tag Type",
   "ICC.2-2019 §9.2.84 Errata: permitted types corrected to ui08/ui16/fl16/fl32", "ICC.2-2019-Errata-2021-03",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-138", "Embedded Height Image Data Length",
   "ICC.2-2019 §10.2.6 Errata: image data = tagSize - 24 (header is 24 bytes, not 12)", "ICC.2-2019-Errata-2021-03",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-139", "Embedded Normal Image Data Length",
   "ICC.2-2019 §10.2.7 Errata: image data = tagSize - 16 (header is 16 bytes, not 12)", "ICC.2-2019-Errata-2021-03",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-140", "GBD Vertex Count Field",
   "ICC.2-2019 §10.2.11 Errata: bytes 12..15 = Number of vertices (V) uInt32Number", "ICC.2-2019-Errata-2021-03",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-141", "Sparse Matrix Array Count Field",
   "ICC.2-2019 §10.2.20 Errata: bytes 12..15 = Number of sparse matrices (N)", "ICC.2-2019-Errata-2021-03",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-142", "Calculator Vector-Or Signature Alignment",
   "ICC.2-2019 §11.2.1.9 Errata: 'vor' corrected to 'vor ' (4-byte aligned)", "ICC.2-2019-Errata-2021-09",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-143", "Measurement Tag Structure Type",
   "ICC.2-2019 §9.2.86/87 Errata: permitted type = tagStructType (not structType)", "ICC.2-2019-Errata-2021-03",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  // ICS Extended Range (ICS-ExtendedRange-Part1/2/3)
  {"CF-144", "Extended Range PCS Flag Consistency",
   "Flag bit 3 (extended range PCS) requires v5 (iccMAX) profile", "ICC.2-2023 §7.2.13",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-145", "Extended Range PCS + Spectral Co-existence",
   "Extended range PCS co-existence with spectral/colorimetric PCS validation", "ICS-ExtendedRange-Part1 §6.2",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-146", "Extended Range Class Restriction",
   "Extended range PCS limited to mntr, spac, prtr profile classes", "ICS-ExtendedRange-Part1 Table 1",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-147", "Extended Range Colorimetric Intent Required",
   "AToB1Tag and BToA1Tag required for extended range display/colorSpace profiles", "ICS-ExtendedRange-Part1 Table 4",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-148", "Extended Range LUT multiProcessElementsType",
   "AToB1/BToA1 tags shall use multiProcessElementsType for extended range profiles (errata: plural)", "ICS-ExtendedRange-Part1 Table 4",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  // ICS Extended Output (ICS-ExtendedOutput-Part1)
  {"CF-149", "Extended Output Profile Class",
   "Output class with spectral PCS requires swpt, svcn, c2sp, s2cp tags", "ICS-ExtendedOutput-Part1 Table 12",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  {"CF-150", "Extended Output Gamut Boundary Tag",
   "Gamut boundary description tags are optional but recommended for output profiles", "ICS-ExtendedOutput-Part1 Table 13",
   CFSeverity::INFO, CFCategory::V5},

  {"CF-151", "Extended Output mediaWhitePoint Range",
   "mediaWhitePointTag XYZ values must be positive and plausible", "ICS-ExtendedOutput-Part1 Table 12",
   CFSeverity::WARNING, CFCategory::V5},

  {"CF-152", "Extended Output AToB/BToA/DToB Completeness",
   "Spectral output profiles require AToB1/3, BToA1/3, DToB3 tags", "ICS-ExtendedOutput-Part1 Table 12",
   CFSeverity::ERROR, CFCategory::REQUIRED},

  // ICC.2-in-ICC.1 Embedding
  {"CF-153", "Embedded Profile Tag Presence",
   "ICC5 tag with ICCp type for embedding ICC.2 profile in ICC.1 container", "ICC TN Embedding",
   CFSeverity::INFO, CFCategory::TAG_TYPES},

  {"CF-154", "Embedded Profile Version Bridging",
   "Parent shall be ICC.1 (v2/v4), child shall be ICC.2 (v5+)", "ICC TN Embedding",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-155", "Embedded Profile Device Class Match",
   "Embedded profile shall have same profile class and device color space as parent", "ICC TN Embedding",
   CFSeverity::ERROR, CFCategory::V5},

  {"CF-156", "Embedded Profile Header Flags",
   "Embedded ICC.2 profile flags: bit 0 should be 1 (embedded), bit 1 should be 0", "ICC TN Embedding",
   CFSeverity::WARNING, CFCategory::V5},

  {"CF-157", "Embedded Profile Recursive Depth",
   "Maximum nesting depth for embedded profiles (anti-bomb protection)", "Security",
   CFSeverity::ERROR, CFCategory::SECURITY},

  {"CF-158", "Embedded Profile Size Bounds",
   "Embedded profile size validation against parent profile size", "Security",
   CFSeverity::ERROR, CFCategory::SECURITY},

  // dictType Validation (ICC.2-2023 §10.2.6)
  {"CF-159", "Dictionary Name Uniqueness",
   "Name strings in dictType shall be unique within the tag", "ICC.2-2023 §10.2.6",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-160", "Dictionary Name Non-Zero",
   "Name string position size shall be > 0 for each name-value record", "ICC.2-2023 §10.2.6",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-161", "Dictionary Record Length Alignment",
   "dictType record length N shall be 16, 24, or 32", "ICC.2-2023 §10.2.6 Table 40",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-162", "Dictionary Entry Count Bounds",
   "Unreasonably large dictionary entry counts indicate potential OOM attack (CWE-400)", "ICC.2-2023 §10.2.6",
   CFSeverity::ERROR, CFCategory::SECURITY},

  // v4 Matrix Entries TN — LUT Matrix Conformance (CF-163..CF-168)
  {"CF-163", "LUT Matrix Coefficient Finite",
   "All 12 matrix coefficients in lutAToBType/lutBToAType/lut8/lut16 must be finite (not NaN/Inf)", "ICC v4 Matrix Entries TN",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-164", "LUT Matrix s15Fixed16 Range",
   "Matrix coefficients must be within s15Fixed16Number representable range [-32768, +32768)", "ICC v4 Matrix Entries TN",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-165", "LUT Matrix Determinant Non-Singular",
   "3x3 LUT matrix determinant must be non-zero — singular matrix causes irreversible data loss", "ICC v4 Matrix Entries TN",
   CFSeverity::ERROR, CFCategory::LUT},

  {"CF-166", "LUT Matrix Row Non-Zero",
   "Each row of the 3x3 matrix must have at least one non-zero element", "ICC v4 Matrix Entries TN",
   CFSeverity::WARNING, CFCategory::LUT},

  {"CF-167", "LUT Matrix Offset Bounds",
   "Matrix offset constants e10-e12 should be within reasonable range for normalized PCS", "ICC v4 Matrix Entries TN",
   CFSeverity::WARNING, CFCategory::LUT},

  {"CF-168", "LUT Matrix Input-Output Range",
   "Matrix applied to unit-cube corners should produce output within practical PCS range", "ICC v4 Matrix Entries TN",
   CFSeverity::WARNING, CFCategory::LUT},

  // Negative PCSXYZ Values TN — XYZ encoding and adaptation conformance (CF-169..CF-174)
  {"CF-169", "Negative PCSXYZ Encoding Capability",
   "XYZ tags with negative values must use s15Fixed16 or float32 encoding (u1Fixed15 cannot represent negatives)", "ICC TN Negative PCSXYZ, ICC.1:2010 §6.3.4.2",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-170", "Chromatic Adaptation Negative XYZ Consistency",
   "Negative matrix column values from chromatic adaptation should have a corresponding chad tag", "ICC TN Negative PCSXYZ, ICC.1-2022-05 §9.2.10",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-171", "White Point Non-Negative Luminance",
   "Media white point and luminance tag Y values must be non-negative (physically impossible otherwise)", "ICC TN Negative PCSXYZ, ICC.1:2010 §3.1.24",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-172", "Colorant XYZ Sum White Point Consistency",
   "Sum of rXYZ+gXYZ+bXYZ matrix columns should approximate the media white point within s15Fixed16 tolerance", "ICC TN Negative PCSXYZ, ICC.1-2022-05 §9.2.7",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  {"CF-173", "PCS XYZ Absorber Encoding",
   "White point must not be [0,0,0] — that value is reserved for the perfect absorber; luminance Y must be non-zero", "ICC TN Negative PCSXYZ, ICC.1:2010 §6.4.3",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  {"CF-174", "Lab Conversion Clipping Awareness",
   "Lab PCS profiles should use LUT model (not matrix/TRC); XYZ PCS negative values are valid per ICC TN", "ICC TN Negative PCSXYZ, ICC.1:2010 §6.4",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  // ICC.2-in-ICC.1 Embedding — additional conformance (CF-175..CF-177)
  {"CF-175", "Embedded Profile PCS Compatibility",
   "Child PCS should be compatible with parent PCS for 'logical replacement' semantics", "ICC TN Embedding §Processing",
   CFSeverity::WARNING, CFCategory::V5},

  {"CF-176", "Embedded Profile Tag Reserved Bytes",
   "Bytes 4-7 of embeddedProfileType encoding shall be 0 per Table 1", "ICC TN Embedding Table 1",
   CFSeverity::WARNING, CFCategory::V5},

  {"CF-177", "Embedded Profile Data Integrity",
   "Embedded ICC.2 profile shall be included in its entirety and validate cleanly", "ICC TN Embedding §Embedding",
   CFSeverity::ERROR, CFCategory::V5},

  // Partial Chromatic Adaptation (CF-178..CF-183)
  {"CF-178", "Chad Matrix Diagonal Dominance",
   "Valid chromatic adaptation matrices (Bradford, CAT02) are diagonally dominant", "ICC TN Partial Adaptation",
   CFSeverity::WARNING, CFCategory::V5},

  {"CF-179", "Chad D50-to-D50 Identity Check",
   "When illuminant is D50, chad should be near-identity (D50→D50 adaptation)", "ICC TN Partial Adaptation",
   CFSeverity::WARNING, CFCategory::V5},

  {"CF-180", "PCC Complete Adaptation Principle",
   "Profiles should perform complete adaptation (D=1.0) in c2sp/s2cp; CMM applies partial", "ICC TN Partial Adaptation",
   CFSeverity::WARNING, CFCategory::V5},

  {"CF-181", "PCC Illuminant-Chad Consistency",
   "Non-D50 PCC illuminant requires chromaticAdaptationTag for adaptation", "ICC TN Partial Adaptation",
   CFSeverity::WARNING, CFCategory::V5},

  {"CF-182", "PCC Observer Standard Compliance",
   "Spectral viewing conditions observer should be CIE 1931 2° or 1964 10°", "ICC TN Partial Adaptation",
   CFSeverity::WARNING, CFCategory::V5},

  {"CF-183", "Chad Column Normalization",
   "Adaptation matrix column norms should be bounded (not degenerate or extreme)", "ICC TN Partial Adaptation",
   CFSeverity::WARNING, CFCategory::V5},

  // RFC 1321 / Profile ID Conformance (CF-184..CF-187)
  {"CF-184", "Profile ID v4+ Presence",
   "v4+ profiles SHOULD have a computed Profile ID (MD5 hash per RFC 1321)", "ICC.1-2022-05 §7.2.18",
   CFSeverity::WARNING, CFCategory::HEADER},

  {"CF-185", "Profile ID Size Consistency",
   "MD5 input length (header-declared profile size) must match actual file size per RFC 1321 §3.1", "ICC.1-2022-05 §7.2.18",
   CFSeverity::WARNING, CFCategory::HEADER},

  {"CF-186", "Profile ID Entropy Analysis",
   "Profile ID (MD5 hash) should have near-uniform byte distribution per RFC 1321", "ICC.1-2022-05 §7.2.18",
   CFSeverity::WARNING, CFCategory::HEADER},

  {"CF-187", "Embedded Profile ProfileID Chain",
   "Both outer and inner profiles in embedding chain should have valid Profile IDs", "ICC TN Embedding + §7.2.18",
   CFSeverity::WARNING, CFCategory::HEADER},

  // SampleICC Profile Compliance Testing Framework (CF-188..CF-190)
  {"CF-188", "Global Per-Tag Validate() Sweep",
   "Call CIccTag::Validate() on every tag and report aggregate compliance status", "SampleICC §3 Compliance Testing",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},
  {"CF-189", "Tag Type Recognition Coverage",
   "Flag tags parsed as CIccTagUnknown — unrecognized type signatures cannot be semantically validated", "SampleICC §3 CheckTagTypes",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-190", "Profile Legibility Gate",
   "Composite readability check: non-empty tag table, all entries parse to non-NULL, file size matches header", "SampleICC §3 ReadValidate",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},

  // ICS Interoperability Conformance Specifications (CF-191..CF-198)
  {"CF-191", "ICS Sub-Class Signature Registry",
   "Validate deviceSubClass matches a registered ICS sub-class signature (pcc, xrng, sref, ext)", "ICC WP-57 ICS Registration",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-192", "Colorimetric ICS Required Tags",
   "Colorimetric PCC sub-class requires AToB1, BToA1, svcn, c2sp, s2cp tags and colorSpace class", "ICS-Colorimetric-Part1",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-193", "Colorimetric ICS PCC Matrix Restriction",
   "Part 1 Colorimetric ICS restricts c2sp/s2cp to a single 3x3 matrix element", "ICS-Colorimetric-Part1",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-194", "Spectral Reflectance ICS Required Tags",
   "Spectral Reflectance sub-class requires DToB3, BToD3, svcn, c2sp, s2cp tags and reflectance PCS", "ICS-SpectralReflectance-Part1",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-195", "Extended Dynamic Range Radiance White Point",
   "Extended range profiles may have white point Y > 1.0 representing luminance in cd/m2", "ICS-ExtendedRange",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-196", "ICS MPE Calculator Restriction",
   "Part 1 ICS profiles restrict MPE to curve/matrix/CLUT/tint; calculatorElement requires Part 2", "ICC WP-57 Part 1 vs Part 2",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-197", "ICS PCC Transform Pair Completeness",
   "customToStandardPcc (c2sp) and standardToCustomPcc (s2cp) must both be present as a mandatory pair", "ICC WP-57 PCC Transforms",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-198", "Extended Range Sub-Class Validation",
   "Extended dynamic range (xrng) sub-class requires display or colorSpace class and extended range PCS flag", "ICS-ExtendedRange",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-199", "CMM Type Signature Registration",
   "Validate CMM type signature against known registered ICC implementations or confirm printability", "ICC.1-2022-05 §7.2.3",
   CFSeverity::WARNING, CFCategory::HEADER},
  {"CF-200", "Device Manufacturer/Model Signature",
   "Validate manufacturer and model signatures for printable ASCII characters", "ICC.1-2022-05 §7.2.12-13",
   CFSeverity::WARNING, CFCategory::HEADER},
  {"CF-201", "Profile Creator Signature",
   "Validate creator signature for printable ASCII characters or zero (unspecified)", "ICC.1-2022-05 §7.2.17",
   CFSeverity::WARNING, CFCategory::HEADER},
  {"CF-202", "Tag Data Padding Zero-Fill",
   "Verify padding bytes between tag data regions are zero per spec requirement", "ICC.1-2022-05 §7.2.1c",
   CFSeverity::WARNING, CFCategory::REQUIRED},
  {"CF-203", "Profile Flags Semantic Validation",
   "Validate defined flag bits (embedded, independent, MCS) for semantic consistency", "ICC.1-2022-05 §7.2.11",
   CFSeverity::WARNING, CFCategory::HEADER},
  {"CF-204", "Device Attributes Semantic Validation",
   "Validate device attributes bits (reflective/transparency, glossy/matte, media polarity, colour/BW) and cross-check against profile class", "ICC.1-2022-05 §7.2.14 Table 22",
   CFSeverity::WARNING, CFCategory::REQUIRED},
  {"CF-205", "Tag Data Region Gap Analysis",
   "Analyze tag data region layout for coverage efficiency and detect excessive gaps", "ICC.1-2022-05 §7.3",
   CFSeverity::INFO, CFCategory::REQUIRED},

  // Spec gap coverage batch (CF-206..CF-213)
  {"CF-206", "Profile File Signature 'acsp'",
   "Validate ICC magic number 'acsp' (0x61637370) at header bytes 36-39", "ICC.1-2022-05 §7.2.9",
   CFSeverity::ERROR, CFCategory::HEADER},
  {"CF-207", "mediaWhitePointTag Value Range",
   "Validate XYZ values in mediaWhitePointTag are positive and physically plausible; v4+ non-DeviceLink must be D50", "ICC.1-2022-05 §10.27, §9.2.28",
   CFSeverity::ERROR, CFCategory::REQUIRED},
  {"CF-208", "Tag Type Version Compatibility",
   "Check that v2 profiles do not use v4+ tag types (parametricCurveType, lutAToBType, lutBToAType, multiProcessElementType)", "ICC.1-2022-05 §7.2.4, §10",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-209", "Colorspace Channel Count vs LUT Dimensions",
   "Cross-validate AToB/BToA LUT input/output channels against declared colorSpace and PCS channel counts", "ICC.1-2022-05 §7.2.6, §10.8-10.11",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},
  {"CF-210", "DeviceLink PCS Space Validation",
   "Validate DeviceLink profiles have consistent PCS space assignment and color space compatibility", "ICC.1-2022-05 §8.6",
   CFSeverity::ERROR, CFCategory::HEADER},
  {"CF-211", "AToB/BToA Tag Pair Completeness",
   "Check that AToB tags have matching BToA counterparts for bidirectional color transforms", "ICC.1-2022-05 §9.2.1-9.2.2",
   CFSeverity::WARNING, CFCategory::REQUIRED},
  {"CF-212", "textType Null Termination",
   "Validate textType tag data is non-null and non-empty per §10.24 requirements", "ICC.1-2022-05 §10.24",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-213", "viewingConditionsType Completeness",
   "Validate illuminant (positive Y), surround (non-negative Y), and illuminant type enumeration in viewingConditionsType", "ICC.1-2022-05 §10.32",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  // ICC TN "Embedding ICC Profiles" conformance (CF-214..CF-219)
  {"CF-214", "Embedded Profile Class Suitability",
   "When embedded flag (§7.2.11 bit 0) is set, validate profile class is appropriate for embedding (DeviceLink atypical)", "ICC TN Embedding §Table 1",
   CFSeverity::WARNING, CFCategory::HEADER},
  {"CF-215", "JPEG APP2 Embedding Size Limit",
   "Profile must not exceed 16,707,345 bytes (255 × 65,519) for JPEG APP2 multi-segment embedding", "ICC TN Embedding §JFIF",
   CFSeverity::WARNING, CFCategory::HEADER},
  {"CF-216", "JP2 Restricted ICC Compliance",
   "JP2 (ISO 15444-1) restricts embedded profiles to Input class, v2 only, monochrome/RGB", "ISO 15444-1 Annex I",
   CFSeverity::INFO, CFCategory::HEADER},
  {"CF-217", "JPX Any ICC Method Compliance",
   "JPX (ISO 15444-2 Annex M) allows Input/Display class only with Matrix/TRC structure (no LUT-based)", "ISO 15444-2 Annex M",
   CFSeverity::INFO, CFCategory::HEADER},
  {"CF-218", "HEIF Restricted ICC Compatibility",
   "HEIF ricc type code requires monochrome or 3-component Matrix/TRC profile; colr requires v4 or lower", "ISO/IEC 14496-12",
   CFSeverity::INFO, CFCategory::HEADER},
  {"CF-219", "Container Format Version Matrix",
   "Cross-reference profile version and class against 18 media formats supporting ICC embedding", "ICC TN Embedding §Table 1",
   CFSeverity::INFO, CFCategory::HEADER},

  // ICC TN PSD / mluc structure conformance (CF-220..CF-226)
  {"CF-220", "mluc Name Record Overlap Detection",
   "Detect partial overlaps between mluc name record string ranges (exact sharing OK, partial overlap = CWE-119)", "ICC TN PSD §mluc",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},
  {"CF-221", "profileSequenceDescTag Structure",
   "Validate profileSequenceDescTag description count, entry structure, and embedded mluc locale counts", "ICC.1-2022-05 §9.2.50",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-222", "profileSequenceIdentifierTag Validation",
   "Validate psid entry count, profile IDs (non-zero), embedded descriptions, and cross-check with pseq count", "ICC.1-2022-05 §9.2.51",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-223", "mluc Zero-Name Placeholder Encoding",
   "Zero-name mluc should encode as exactly 12 bytes per ICC TN PSD recommendation to avoid parsing ambiguity", "ICC TN PSD §placeholder",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-224", "mluc Reserved Field Zero",
   "Bytes 4-7 of every multiLocalizedUnicodeType must be zero (reserved field)", "ICC.1-2022-05 §10.13",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-225", "mluc Name Record String Alignment",
   "mluc string offsets and lengths should be even (UTF-16 = 2 bytes per code unit) per §7.1 alignment", "ICC.1-2022-05 §7.1, §10.13",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-226", "mluc Size Inference Safety",
   "Validate mluc tag size is consistent with max(offset+length) across all name records per TN PSD recommendation", "ICC TN PSD §size",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},

  // v2→v4 Features Changes conformance (CF-227..CF-234)
  {"CF-227", "v4 Text Tag Unicode Migration",
   "v4+ profiles must use multiLocalizedUnicodeType for text tags — textDescriptionType deprecated", "ICC.1-2022-05 §9",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-228", "grayTRCTag Semantic Validation",
   "Grayscale TRC must be monotonic 0=black to 1.0=white; no RGB TRC tags in Gray profiles", "v2→v4 TN",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-229", "Rendering Intent Dominance Per Class",
   "AToB dominant for Input, BToA dominant for Output/Display; Perceptual (0) intent required first", "v2→v4 TN",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-230", "CIELAB Encoding Version Consistency",
   "v4 Lab encoding: L*=100→0xFFFF (not v2 0xFF00), a*/b*=0→0x8080 (not v2 0x8000); lut16Type retains v2", "ICC.1-2022-05 §6.5.9",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-231", "LUT Processing Element Sequence",
   "lutAtoBType/lutBtoAType: B curves required, matrix+M curves paired, A curves need CLUT", "ICC.1-2022-05 §10.10-10.11",
   CFSeverity::WARNING, CFCategory::LUT},
  {"CF-232", "Date/Time UTC and Temporal Consistency",
   "All dates UTC, seconds ≤59, calibrationDateTimeTag should precede profile creation", "ICC.1-2022-05 §7.2.8",
   CFSeverity::INFO, CFCategory::HEADER},
  {"CF-233", "colorantOrderTag Index Validation",
   "Indices must form permutation of [0..count-1] — no gaps, no duplicates", "ICC.1-2022-05 §9.2.11, §10.3",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-234", "v4 Perceptual PCS Reference Medium",
   "Perceptual PCS reference medium: 287.9:1 dynamic range, L*=100 white, L*=3.1373 black", "ICC.1-2022-05 Annex D",
   CFSeverity::INFO, CFCategory::TAG_TYPES},

  // ICS Extended Range Part 1 conformance (CF-235..CF-242)
  {"CF-235", "xrng Data Colour Space Restriction",
   "Part 1 requires data colour space = RGB with 3 channels for extendedRange sub-class", "ICS-ExtRange-Part1 Table 3",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-236", "xrng Colorimetric PCS Constraint",
   "Part 1 requires colorimetric PCS = XYZ with D50 illuminant (1931 2-degree observer)", "ICS-ExtRange-Part1 Table 3",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-237", "xrng Required Tag Completeness",
   "Table 4 requires desc(mluc), cprt(mluc), mwpt(XYZ), A2B1(MPE), B2A1(MPE) all present with correct types", "ICS-ExtRange-Part1 Table 4",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-238", "xrng Header Field Restrictions",
   "Flags=0, attributes<=1, spectralPCS=0, biSpectralRange=0, MCS=0 for Part 1 basic encoding", "ICS-ExtRange-Part1 Table 3",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-239", "xrng Optional Tag Type Validation",
   "Optional tags: chad(s15Fixed16Array), gbdX(gamutBoundaryDesc), AToBx/BToAx(MPE) type enforcement", "ICS-ExtRange-Part1 Table 5",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-240", "xrng Transform Channel Dimensions",
   "AToB1/BToA1 MPE transforms must map 3 input channels (RGB) to 3 output channels (XYZ)", "ICS-ExtRange-Part1 S5.2",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-241", "xrng mediaWhitePointTag Absolute Radiance",
   "mwpt must contain positive XYZ tristimulus values of near-diffuse white in absolute radiance", "ICS-ExtRange-Part1 Table 4",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-242", "xrng Workflow Connection Consistency",
   "Source/destination workflow requires AToB1/BToA1 with colorimetric rendering intent", "ICS-ExtRange-Part1 S5.2.3",
   CFSeverity::WARNING, CFCategory::V5},

  // Conformance gap coverage (CF-243..CF-257)
  {"CF-243", "dateTimeNumber Field Range",
   "Month 1-12, day 1-31, hours 0-23, minutes 0-59, seconds 0-59", "ICC.1-2022-05 §4.2",
   CFSeverity::ERROR, CFCategory::HEADER},
  {"CF-244", "Profile Creation Date Plausibility",
   "Year must be >=1990 (ICC specification era) and <=2100", "ICC.1-2022-05 §7.2.8",
   CFSeverity::WARNING, CFCategory::HEADER},
  {"CF-245", "Profile Size Multiple of 4",
   "Profile data shall be padded to 4-byte boundary", "ICC.1-2022-05 §7.2.2",
   CFSeverity::ERROR, CFCategory::HEADER},
  {"CF-246", "Rendering Intent Range",
   "Rendering intent must be 0-3 (Perceptual/Relative/Saturation/Absolute)", "ICC.1-2022-05 §7.2.15",
   CFSeverity::ERROR, CFCategory::HEADER},
  {"CF-247", "viewingConditionsType Illuminant Type Range",
   "Illuminant type must be in ICC.1 Table 27 range 0-8", "ICC.1-2022-05 §10.30",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-248", "namedColor2Type Device Coords Limit",
   "Device coordinates count shall not exceed 15 per ICC specification", "ICC.1-2022-05 §10.14",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},
  {"CF-249", "profileDescriptionTag Non-Empty",
   "Profile description shall contain meaningful non-empty text", "ICC.1-2022-05 §9.2.41",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-250", "copyrightTag Non-Empty",
   "Copyright tag shall contain non-empty text content", "ICC.1-2022-05 §9.2.21",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-251", "chromaticityType Phosphor Type Range",
   "Phosphor/colorant type must be 0-4 per ICC.1 Table 31", "ICC.1-2022-05 §10.2",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-252", "curveType Gamma Positive/Finite",
   "When curveType count=1, gamma value must be positive and finite", "ICC.1-2022-05 §10.6",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},
  {"CF-253", "chromaticityType Channel Count",
   "Number of channels in chromaticityType must match profile data colour space", "ICC.1-2022-05 §10.2",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},
  {"CF-254", "Technology Signature Registered",
   "Technology signature must be a registered value from ICC.1 Table 25", "ICC.1-2022-05 §9.2.47",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-255", "CLUT Grid Point Values",
   "CLUT grid point values must be >= 2 for each input dimension", "ICC.1-2022-05 §10.12",
   CFSeverity::ERROR, CFCategory::LUT},
  {"CF-256", "LUT I/O Channels vs Profile Spaces",
   "AToB input channels must match data colour space, output must match PCS", "ICC.1-2022-05 §10.12",
   CFSeverity::ERROR, CFCategory::LUT},
  {"CF-257", "Spectral Range Step Count",
   "Spectral range must have steps >= 2 and start < end when spectral PCS is declared", "ICC.2-2023 §7.2.20",
   CFSeverity::ERROR, CFCategory::V5},
  // Deep conformance gap coverage (CF-258..CF-265)
  {"CF-258", "Display v4+ mediaWhitePointTag D50",
   "Display profiles v4+ must have mediaWhitePointTag equal to D50 illuminant", "ICC.1-2022-05 §8.4",
   CFSeverity::ERROR, CFCategory::REQUIRED},
  {"CF-259", "colorantOrderTag vs colorantTableTag Cross-Validation",
   "colorantOrderTag indices must reference valid colorantTableTag entries", "ICC.1-2022-05 §10.3",
   CFSeverity::ERROR, CFCategory::REQUIRED},
  {"CF-260", "Output Profile gamutTag Rendering Intent",
   "Output profiles with perceptual/saturation intents should include gamutTag", "ICC.1-2022-05 §9.2.22",
   CFSeverity::WARNING, CFCategory::REQUIRED},
  {"CF-261", "M-Curve Count = 3 When Matrix Present",
   "lutAToBType and lutBToAType M-curve count must be exactly 3 when matrix is present", "ICC.1-2022-05 §10.11",
   CFSeverity::ERROR, CFCategory::LUT},
  {"CF-262", "B-Curve Count vs Output Channels",
   "lutAToBType B-curve count must match the number of output channels", "ICC.1-2022-05 §10.11",
   CFSeverity::ERROR, CFCategory::LUT},
  {"CF-263", "Perceptual PCS White Point D50",
   "Profiles with perceptual rendering intent must have D50 PCS illuminant in header", "ICC.1-2022-05 Annex D",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-264", "parametricCurveType Function Type Range",
   "parametricCurveType functionType must be in range 0..4", "ICC.1-2022-05 §10.18",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},
  {"CF-265", "mluc Language/Country Code Validity",
   "mluc records must use ISO 639-1 language codes and ISO 3166-1 country codes", "ICC.1-2022-05 §10.15",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  // Profile class constraints (CF-266..CF-271)
  {"CF-266", "Input Profile Device Color Space",
   "Input profiles must use RGB, CMYK, Gray, or nCLR device color space", "ICC.1-2022-05 §6.1",
   CFSeverity::ERROR, CFCategory::REQUIRED},
  {"CF-267", "Display Profile Color Space",
   "Display profiles must use RGB, Gray, or nCLR device color space", "ICC.1-2022-05 §6.2",
   CFSeverity::ERROR, CFCategory::REQUIRED},
  {"CF-268", "Output Profile Color Space",
   "Output profiles must use RGB, CMYK, CMY, Gray, or nCLR device color space", "ICC.1-2022-05 §6.3",
   CFSeverity::ERROR, CFCategory::REQUIRED},
  {"CF-269", "DeviceLink Data Color Space Matching",
   "DeviceLink source and destination color spaces must be valid device spaces", "ICC.1-2022-05 §6.4",
   CFSeverity::ERROR, CFCategory::REQUIRED},
  {"CF-270", "Abstract Profile PCS",
   "Abstract profiles must use Lab or XYZ for both colorSpace and PCS", "ICC.1-2022-05 §6.6",
   CFSeverity::ERROR, CFCategory::REQUIRED},
  {"CF-271", "NamedColor Profile PCS",
   "NamedColor profiles must use Lab or XYZ PCS", "ICC.1-2022-05 §6.7",
   CFSeverity::ERROR, CFCategory::REQUIRED},
  // Primary colorant validation (CF-272..CF-274)
  {"CF-272", "Matrix/TRC RGB Required Colorant Tags",
   "RGB matrix/TRC profiles must have rXYZ, gXYZ, bXYZ, rTRC, gTRC, bTRC tags", "ICC.1-2022-05 §9.2.47",
   CFSeverity::ERROR, CFCategory::REQUIRED},
  {"CF-273", "Primary Colorant XYZ Values Positive",
   "Primary colorant XYZ values should be positive and within plausible range", "ICC.1-2022-05 §10.28",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-274", "Primary Colorant Chromaticity Sum",
   "Primary colorant chromaticity sums should not be near zero", "TN v4-matrix-entries",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  // Tag type enforcement (CF-275..CF-278)
  {"CF-275", "copyrightTag Must Be mluc for v4+",
   "v4+ profiles must use multiLocalizedUnicodeType for copyrightTag", "ICC.1-2022-05 §9.2.14",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-276", "profileDescriptionTag Must Be mluc for v4+",
   "v4+ profiles must use mluc for profileDescriptionTag", "ICC.1-2022-05 §9.2.44",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-277", "mediaWhitePointTag Must Be XYZType",
   "mediaWhitePointTag must use XYZType", "ICC.1-2022-05 §9.2.35",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},
  {"CF-278", "chromaticAdaptationTag Type",
   "chromaticAdaptationTag must use s15Fixed16ArrayType", "ICC.1-2022-05 §9.2.2",
   CFSeverity::ERROR, CFCategory::TAG_TYPES},
  // Data encoding validation (CF-279..CF-281)
  {"CF-279", "TRC Curve Values Non-Negative",
   "TRC curve entries should be non-negative", "ICC.1-2022-05 §10.5",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-280", "XYZ Element Luminance (Y) Non-Negative",
   "XYZ type luminance (Y) values should be non-negative", "ICC.1-2022-05 §10.28",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-281", "profileSequenceDescTag Structure",
   "profileSequenceDescTag must use profileSequenceDescType", "ICC.1-2022-05 §10.16",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  // DeviceLink requirements (CF-282..CF-283)
  {"CF-282", "DeviceLink AToB0Tag Required",
   "DeviceLink profiles must contain AToB0Tag", "ICC.1-2022-05 §6.4",
   CFSeverity::ERROR, CFCategory::REQUIRED},
  {"CF-283", "DeviceLink profileSequenceDescTag",
   "DeviceLink profiles should contain profileSequenceDescTag", "ICC.1-2022-05 §6.4",
   CFSeverity::WARNING, CFCategory::REQUIRED},

  // ICC.2:2019 Errata-derived v5 checks (CF-284..CF-291)
  {"CF-284", "BRDF Spectral Parameter Tag Type",
   "BRDF spectral parameter tags (bsp0..bsp3) must be multiProcessElementType", "ICC.2-2023 §9.2.10-13",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-285", "BRDF Tag Presence Consistency",
   "If any BRDF spectral parameter tag is present, all 4 should be present", "ICC.2-2023 §9.2.10",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-286", "GBD Triangle-Vertex Consistency",
   "Gamut boundary description triangle count requires >= 3 vertices", "ICC.2-2023 §10.2.11",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-287", "GBD Channel Count Plausibility",
   "GBD PCS channels should be 3 (Lab/XYZ), device channels reasonable", "ICC.2-2023 §10.2.11",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-288", "Spectral Data Info Bi-Spectral Consistency",
   "BiSpectralRange requires valid base spectralRange", "ICC.2-2023 §9.2.84",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-289", "Spectral Viewing Conditions Illuminant Bounds",
   "Spectral viewing conditions illuminant XYZ must be physically plausible", "ICC.2-2023 §10.2.30",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-290", "Material Default Values Tag Presence",
   "Material identification/visualization profiles should have multiplexDefaultValuesTag", "ICC.2-2023 §9.2.47",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-291", "Spectral White Point XYZ Range",
   "Spectral white point XYZ values must be physically plausible", "ICC.2-2023 §9.2.85",
   CFSeverity::ERROR, CFCategory::V5},

  // multiProcessElementsType Container Validation (CF-292..CF-300)
  {"CF-292", "MPE Chain I/O Channel Consistency",
   "Adjacent MPE elements must have matching output/input channel counts", "ICC.2-2023 §10.2.17",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-293", "MPE Container I/O vs First/Last Element",
   "Container input must match first element input; output must match last element output", "ICC.2-2023 §10.2.17",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-294", "MPE ACS Boundary Element Pairing",
   "bACS and eACS elements must appear in pairs with matching signatures", "ICC.2-2023 §10.2.1-2",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-295", "MPE Element Type Version Compatibility",
   "V5+ element types (calc, xclt, spectral, etc.) must not appear in v4 profiles", "ICC.2-2023 §10.2.17",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-296", "MPE Empty Container Validation",
   "Empty MPE container must have inputChannels == outputChannels (identity)", "ICC.2-2023 §10.2.17",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-297", "MPE CurveSet Element Channel Count",
   "CurveSet element must have inputChannels == outputChannels", "ICC.2-2023 §10.2.5",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-298", "MPE Matrix Element Dimension",
   "Matrix element must have non-zero channel dimensions and allocated matrix data", "ICC.2-2023 §10.2.9",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-299", "MPE CLUT Element Grid Dimension",
   "CLUT element must have non-zero I/O channels and reasonable input dimensions", "ICC.2-2023 §10.2.3",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-300", "MPE Tag vs Color Space Channels",
   "AToB/BToA MPE tag channels must match profile data color space and PCS", "ICC.2-2023 §10.2.17",
   CFSeverity::WARNING, CFCategory::V5},

  // ICC.2:2019 Errata — §9.2.86/87 + §9.2.84 + §10.2.5 + §11.2.1.9 (CF-301..CF-307)
  {"CF-301", "Measurement Struct tagStructType Enforcement",
   "v5 measurement tags MUST use tagStructType wrapper with measurementInfoStruct per errata §9.2.86/87", "ICC.2-2019 Errata §9.2.86/87",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-302", "Measurement Struct Member Completeness",
   "measurementInfoStruct must contain required members: backing, flare, geometry, illuminant, mode", "ICC.2-2019 Errata §9.2.86/87",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-303", "Spectral Data Array Type Restriction",
   "Spectral data tags must use only uInt8/uInt16/float16/float32 array types", "ICC.2-2019 Errata §9.2.84",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-304", "v5 Text Tag multiLocalizedUnicodeType",
   "v5 text tags must use multiLocalizedUnicodeType per errata Tables 40/41 correction", "ICC.2-2019 Errata §10.2.5",
   CFSeverity::WARNING, CFCategory::TAG_TYPES},
  {"CF-305", "multiProcessElementsType Nomenclature Audit",
   "Validates mpet signature and documents singular/plural naming divergence per errata Tech.Err.#3", "ICC.2-2019 Errata Tech.Err.#3",
   CFSeverity::INFO, CFCategory::V5},
  {"CF-306", "Embedded Image Data Length Cross-Validation",
   "ehim header=24 bytes, enim header=16 bytes per errata §10.2.6/10.2.7 correction", "ICC.2-2019 Errata §10.2.6/10.2.7",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-307", "Calculator Vector-Or Signature Validation",
   "vor signature must be 766f7220h with trailing space per Sept 2021 errata §11.2.1.9", "ICC.2-2019 Errata §11.2.1.9",
   CFSeverity::INFO, CFCategory::V5},

  // ICS Conformance — Part 1/2/3 element restrictions (CF-308..CF-316)
  {"CF-308", "pcc AToB1/BToA1 Part 1 Element Restriction",
   "Colorimetric PCC Part 1 restricts AToB1/BToA1 elements to curveSet, matrix, CLUT, extCLUT, tintArray", "ICS-ColorimetricPCC-Part1 §6",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-309", "sref PCC Matrix Restriction",
   "Spectral Reflectance Part 1 restricts c2sp/s2cp to single 3x3 matrixElement", "ICS-SpectralReflectance-Part1 §6.2",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-310", "sref DToB3/BToD3 Part 1 Element Restriction",
   "Spectral Reflectance Part 1 restricts DToB3/BToD3 to curveSet, matrix, CLUT, extCLUT, tintArray", "ICS-SpectralReflectance-Part1 §6",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-311", "sref Spectral Range Mandatory",
   "Spectral Reflectance requires non-zero spectral range steps and reflectance PCS", "ICS-SpectralReflectance-Part1 §5.2",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-312", "ext Required Tag Completeness",
   "Extended Output sub-class requires svcn, c2sp, s2cp, desc, cprt tags", "ICS-ExtendedOutput-Part1 §6",
   CFSeverity::ERROR, CFCategory::V5},
  {"CF-313", "ext Part 1 Element Type Restriction",
   "Extended Output Part 1 restricts transform elements to curveSet, matrix, CLUT, extCLUT", "ICS-ExtendedOutput-Part1 §6.3",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-314", "xrng AToB1/BToA1 Part 1 Element Restriction",
   "Extended Dynamic Range Part 1 restricts AToB1/BToA1 to curveSet, matrix, CLUT, extCLUT, tintArray", "ICS-ExtRange-Part1 §6.2",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-315", "xrng Part 2 PCC Matrix Restriction",
   "Extended Dynamic Range Part 2 restricts c2sp/s2cp to single 3x3 matrixElement", "ICS-ExtRange-Part2 §6",
   CFSeverity::WARNING, CFCategory::V5},
  {"CF-316", "ICS svcn Observer/Illuminant Plausibility",
   "Validates svcn illuminant XYZ non-negative with Y>0, spectral range physically reasonable", "ICC WP-57 §svcn",
   CFSeverity::WARNING, CFCategory::V5},
};

static constexpr int kConformanceCheckCount =
    sizeof(kConformanceRegistry) / sizeof(kConformanceRegistry[0]);

// ── Conformance registry statistics ─────────────────────────────────────────

struct ConformanceRegistryStats {
  int totalChecks;
  int checksWithSpecRef;
  int errorCount;
  int warningCount;
  int infoCount;
};

inline ConformanceRegistryStats ComputeConformanceRegistryStats() {
  ConformanceRegistryStats s = {};
  s.totalChecks = kConformanceCheckCount;
  for (int i = 0; i < kConformanceCheckCount; i++) {
    if (kConformanceRegistry[i].specRef && kConformanceRegistry[i].specRef[0])
      s.checksWithSpecRef++;
    switch (kConformanceRegistry[i].severity) {
      case CFSeverity::ERROR:   s.errorCount++;   break;
      case CFSeverity::WARNING: s.warningCount++; break;
      case CFSeverity::INFO:    s.infoCount++;    break;
    }
  }
  return s;
}

#endif // ICC_CONFORMANCE_REGISTRY_H
