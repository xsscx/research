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

  {"CF-148", "Extended Range LUT multiProcessElementType",
   "AToB1/BToA1 tags shall use multiProcessElementType for extended range profiles", "ICS-ExtendedRange-Part1 Table 4",
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
