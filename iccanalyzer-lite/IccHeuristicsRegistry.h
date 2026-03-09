/*
 * IccHeuristicsRegistry.h — Metadata registry for all 148 heuristics
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Data-driven registry mapping each heuristic ID to its name, spec reference,
 * primary CWE, CVE cross-references, and execution phase. Used for JSON output,
 * filtering, and programmatic enumeration of heuristics.
 *
 * CVE mappings derived from 93 iccDEV security advisories (GHSA-* / CVE-2026-*).
 * 68 advisories have CVE IDs; 25 are GHSA-only (pending CVE assignment).
 * 57 heuristics detect patterns from 87 CVEs + 19 GHSAs (binary ICC + XML + data validation).
 * 1 advisory out of scope: 1 tool-specific (iccFromCube). 0 XML out-of-scope (H142-H145).
 * Validated 2026-03-09 against closed iccDEV issues and security advisories.
 */

#ifndef ICC_HEURISTICS_REGISTRY_H
#define ICC_HEURISTICS_REGISTRY_H

#include <cstddef>

enum class HeuristicPhase {
  HEADER,
  TAG_VALIDATION,
  RAW_POST,
  DATA_VALIDATION,
  PROFILE_COMPLIANCE,
  INTEGRITY,
  IMAGE
};

// Severity classification based on CWE impact and exploitability.
// CRITICAL = memory corruption / code execution (HBO, OOB write, UAF, integer overflow → alloc)
// HIGH     = denial of service / crash (stack overflow, resource exhaustion, type confusion → crash)
// MEDIUM   = data integrity / logic errors (incorrect calculation, type flag, size mismatch)
// LOW      = spec compliance / input validation (non-exploitable validation checks)
// INFO     = informational / suspicious patterns (metadata, anomaly indicators)
enum class HeuristicSeverity {
  CRITICAL,
  HIGH,
  MEDIUM,
  LOW,
  INFO
};

struct HeuristicEntry {
  int id;
  const char *name;
  const char *specRef;       // ICC.1-2022-05 section or nullptr
  const char *primaryCWE;    // Primary CWE identifier or nullptr
  const char *cveRefs;       // Comma-separated CVE IDs or nullptr
  HeuristicPhase phase;
  HeuristicSeverity severity;
};

static const HeuristicEntry kHeuristicRegistry[] = {
  // --- HEADER VALIDATION (H1-H8, H15-H17) ---
  {  1, "Profile Size",                        "§7.2.2",  "CWE-131", nullptr, HeuristicPhase::HEADER, HeuristicSeverity::MEDIUM},
  {  2, "Magic Bytes",                         "§7.2.6",  "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  3, "Color Space Signature",               "§7.2.6",  "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  4, "PCS Color Space",                     "§7.2.7",  "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  5, "Platform Signature",                  "§7.2.10", "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  6, "Rendering Intent",                    "§7.2.15", "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  7, "Profile Class",                       "§7.2.5",  "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  8, "Illuminant XYZ",                      "§7.2.16", "CWE-682", nullptr, HeuristicPhase::HEADER, HeuristicSeverity::MEDIUM},
  { 15, "Date Validation",                     "§7.2.4",  "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  { 16, "Signature Patterns",                  "§7.2",    "CWE-506", nullptr, HeuristicPhase::HEADER, HeuristicSeverity::INFO},
  { 17, "Spectral Range",                      "§7.2.22", "CWE-843", nullptr, HeuristicPhase::HEADER, HeuristicSeverity::MEDIUM},

  // --- TAG VALIDATION (H9-H14, H18-H32) ---
  {  9, "Critical Text Tags",                  "§7.3",    "CWE-476", "CVE-2026-21496,CVE-2026-21497", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 10, "Tag Count",                           "§7.3",    "CWE-20",  "CVE-2026-21680", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::MEDIUM},
  { 11, "CLUT Entry Limit",                    "§10.10",  "CWE-190", "CVE-2026-21677,CVE-2026-22255,GHSA-6jrq-wfqg-wv7w,GHSA-w3g9-rmvh-49gh,GHSA-92v9-wq22-2rfv,GHSA-x6gg-j72w-jc9w", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 12, "MPE Chain Depth",                     "§10.26",  "CWE-674", "CVE-2026-21500,CVE-2026-21501", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 13, "Per Tag Size Check",                  "§7.3.1",  "CWE-400", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 14, "Tag Array Detection",                 "§10.33",  "CWE-416", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 18, "Technology Signature",                "§9.2.27", "CWE-20",  nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::LOW},
  { 19, "Tag Offset Overlap",                  "§7.3.1",  "CWE-122", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 20, "Tag Type Signature",                  "§10",     "CWE-843", "CVE-2026-21505,CVE-2026-24856", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 21, "Tag Struct Member Inspection",        "§10.32",  "CWE-843", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::MEDIUM},
  { 22, "Num Array Scalar Expectation",        "§10.21",  "CWE-20",  nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::LOW},
  { 23, "Num Array Value Range",               "§10.21",  "CWE-681", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::MEDIUM},
  { 24, "Tag Struct Nesting Depth",            "§10.32",  "CWE-674", "GHSA-w478-77q7-2hc2", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 25, "Tag Offset OOB",                      "§7.3.1",  "CWE-125", "CVE-2026-21487", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 26, "Named Color2String Validation",       "§10.20",  "CWE-170", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 27, "MPE Matrix Output Channel",           "§10.26",  "CWE-131", "CVE-2026-27692", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 28, "LUT Dimension Validation",            "§10.10",  "CWE-400", "CVE-2026-21490,CVE-2026-21494,GHSA-x9hr-pxxc-h38p", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 29, "Colorant Table String Validation",    "§10.4",   "CWE-170", "GHSA-4wqv-pvm8-5h27", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 30, "Gamut Boundary Desc Allocation",      "§10.12",  "CWE-400", "GHSA-rc3h-95ph-j363", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 31, "MPE Channel Count",                   "§10.26",  "CWE-131", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 32, "Tag Data Type Confusion",             "§10",     "CWE-843", "CVE-2026-21683,CVE-2026-21688,CVE-2026-21691,CVE-2026-25503", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},

  // --- RAW POST ANALYSIS (H33-H55, H57-H69) ---
  { 33, "mBA/mAB Sub-Element Offset Validation", nullptr, "CWE-122", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 34, "Integer Overflow Sub-Element Bounds",   nullptr, "CWE-190", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 35, "Suspicious Fill Pattern mBA/mAB Data",  nullptr, "CWE-506", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::INFO},
  { 36, "LUT Tag Pair Completeness",             nullptr, "CWE-20",  nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::LOW},
  { 37, "Calculator Element Complexity",          nullptr, "CWE-400", "CVE-2026-21507,CVE-2026-22047,GHSA-8c76-67wr-hrp4", HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 38, "Curve Degenerate Value Detection",       nullptr, "CWE-682", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},
  { 39, "Shared Tag Data Aliasing Detection",     nullptr, "CWE-416", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 40, "Tag Alignment Padding Validation",       nullptr, "CWE-20",  nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::LOW},
  { 41, "Version Type Consistency Check",         nullptr, "CWE-20",  nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::LOW},
  { 42, "Matrix Singularity Detection",           nullptr, "CWE-369", "GHSA-f9wv-cq46-f9wg", HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},
  { 43, "Spectral BRDF Tag Structural Validation", nullptr, "CWE-20", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::LOW},
  { 44, "Embedded Image Validation",              nullptr, "CWE-122", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 45, "Sparse Matrix Bounds Validation",        nullptr, "CWE-122", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 46, "TextDescription Unicode Length Validation", nullptr, "CWE-190", "CVE-2026-21488,CVE-2026-21491", HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 47, "NamedColor2 Size Overflow Detection",    nullptr, "CWE-190", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 48, "CLUT Grid Dimension Product Overflow",   nullptr, "CWE-190", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 49, "Float s15Fixed16 NaN Inf Detection",     nullptr, "CWE-682", "CVE-2026-21681", HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},
  { 50, "Zero-Size Profile Tag Detection",        nullptr, "CWE-835", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 51, "LUT IO Channel Count Consistency",       nullptr, "CWE-125", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 52, "Integer Underflow Tag Size Subtraction", nullptr, "CWE-191", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 53, "Embedded Profile Recursion Detection",   nullptr, "CWE-674", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 54, "Division-by-Zero Trigger Detection",     nullptr, "CWE-369", "CVE-2026-21495", HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 55, "UTF-16 Encoding Validation",             nullptr, "CWE-170", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 57, "Embedded Profile Recursion Depth",        nullptr, "CWE-674", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 59, "Spectral Wavelength Range Consistency",   nullptr, "CWE-682", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},
  { 68, "GamutBoundaryDesc Triangle Vertex Overflow", nullptr, "CWE-190", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 69, "Profile ID MD5 Consistency",              nullptr, "CWE-345", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},

  // --- DATA VALIDATION (H56, H58, H60-H67, H70-H102) ---
  { 56, "Calculator Stack Depth",               nullptr, "CWE-400", "CVE-2026-21501", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 58, "Sparse Matrix Entry Bounds",            nullptr, "CWE-126", "CVE-2026-21503", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 60, "Dictionary Tag Consistency",            nullptr, "CWE-20",  nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::LOW},
  { 61, "Viewing Conditions Validation",         nullptr, "CWE-682", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 62, "MLU String Bombs",                      nullptr, "CWE-400", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 63, "Curve LUT Channel Mismatch",            nullptr, "CWE-131", "CVE-2026-21685,CVE-2026-21686", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 64, "Named Color2Device Coord Overflow",     nullptr, "CWE-787", "CVE-2026-24406", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 65, "Chromaticity Plausibility",             nullptr, "CWE-682", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 66, "Num Array NaN Inf Scan",                nullptr, "CWE-682", "CVE-2026-21681", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 67, "Response Curve Set Bounds",             nullptr, "CWE-400", "CVE-2026-24852", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 70, "Measurement Tag Validation",            nullptr, "CWE-20",  nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::LOW},
  { 71, "Colorant Table Null Termination",       nullptr, "CWE-170", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 72, "Sparse Matrix Array Bounds",            nullptr, "CWE-843", "CVE-2026-21503,CVE-2026-21505", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 73, "Tag Array Nesting Depth",               nullptr, "CWE-674", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 74, "Tag Type Signature Consistency",        nullptr, "CWE-843", "CVE-2026-21505,CVE-2026-24856", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 75, "Tags Very Small Size",                  nullptr, "CWE-20",  nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::LOW},
  { 76, "CIccTagData Type Flag",                 nullptr, "CWE-843", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 77, "MPE Calculator Sub Element Count",      nullptr, "CWE-400", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 78, "CLUT Grid Dimension Overflow",          nullptr, "CWE-190", "CVE-2026-21677,CVE-2026-22255", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 79, "Load Tag Allocation Overflow",          nullptr, "CWE-190", "CVE-2026-21485", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 80, "Shared Tag Pointer UAF",                nullptr, "CWE-416", "CVE-2026-21486,CVE-2026-21675,GHSA-97mf-f6r7-q9q4,GHSA-fqq2-v72p-wfff", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 81, "MPE Calculator IO Consistency",         nullptr, "CWE-122", "CVE-2026-21504,CVE-2026-22047,CVE-2026-22861,CVE-2026-24405,GHSA-g9w6-5xm9-v5xj,GHSA-vg26-ggwf-6fmq", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 82, "IO Read Size Overflow",                 nullptr, "CWE-190", "CVE-2026-25582,CVE-2026-25583,GHSA-fj57-gfhq-rjqr", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 83, "Float Numeric Array Size",              nullptr, "CWE-125", "CVE-2026-25584", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 84, "LUT3D Transform Consistency",           nullptr, "CWE-125", "CVE-2026-25585,GHSA-wh5x-j6pq-pr3c,GHSA-7ww3-h4w6-x5hf", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 85, "MPE Buffer Overlap",                    nullptr, "CWE-122", "CVE-2026-25634", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 86, "Localized Unicode Bounds",              nullptr, "CWE-787", "CVE-2026-21678,CVE-2026-21679", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 87, "TRC Curve Anomaly",                     nullptr, "CWE-682", "CVE-2026-21489", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 88, "Chromatic Adaptation Matrix",           nullptr, "CWE-682", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 89, "Profile Sequence Description",          nullptr, "CWE-400", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 90, "Preview Tag Channel Consistency",       nullptr, "CWE-787", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 91, "Colorant Order Validation",             nullptr, "CWE-682", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 92, "Spectral Viewing Conditions",           nullptr, "CWE-20",  "CVE-2026-21684", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::LOW},
  { 93, "Embedded Profile Flag",                 nullptr, "CWE-20",  nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::LOW},
  { 94, "Matrix TRC Colorant Consistency",       nullptr, "CWE-682", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 95, "Sparse Matrix Array Bounds Validation", nullptr, "CWE-843", "CVE-2026-21503", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 96, "Embedded Profile Validation",           nullptr, "CWE-674", "CVE-2026-25503", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 97, "Profile Sequence Id Validation",        nullptr, "CWE-400", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 98, "Spectral MPE Element Validation",       nullptr, "CWE-787", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 99, "Embedded Image Tag Validation",         nullptr, "CWE-125", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {100, "Profile Sequence Desc Validation",      nullptr, "CWE-787", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {101, "MPE Sub Element Channel Continuity",    nullptr, "CWE-787", "CVE-2026-21492", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {102, "Tag Size Profile Size Cross Check",     nullptr, "CWE-131", "CVE-2026-21676", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},

  // --- PROFILE COMPLIANCE (H103-H120) ---
  {103, "PCC",                                   nullptr, "CWE-20",  nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::LOW},
  {104, "PRMG",                                  nullptr, "CWE-20",  nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::LOW},
  {105, "Matrix TRC",                            nullptr, "CWE-682", nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::MEDIUM},
  {106, "Env Var",                               nullptr, "CWE-131", nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::MEDIUM},
  {107, "Channel Cross Check",                   nullptr, "CWE-131", nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::MEDIUM},
  {108, "Private Tags",                          nullptr, "CWE-506", nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::INFO},
  {109, "Shellcode Patterns",                    nullptr, "CWE-506", nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::CRITICAL},
  {110, "Class Tag Validation",                  "§8",    "CWE-20",  nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::LOW},
  {111, "Reserved Bytes",                        "§7.2.19", "CWE-20", nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::LOW},
  {112, "Wtpt Validation",                       nullptr, "CWE-682", nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::MEDIUM},
  {113, "Round Trip Fidelity",                   nullptr, "CWE-682", nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::MEDIUM},
  {114, "Curve Smoothness",                      nullptr, "CWE-20",  "CVE-2026-21687", HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::LOW},
  {115, "Characterization Data",                 nullptr, "CWE-20",  nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::LOW},
  {116, "Cprt Desc Encoding",                    nullptr, "CWE-20",  nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::LOW},
  {117, "Tag Type Allowed",                      nullptr, "CWE-20",  nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::LOW},
  {118, "Calc Cost Estimate",                    nullptr, "CWE-400", nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::HIGH},
  {119, "Round Trip Delta E",                    nullptr, "CWE-682", nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::MEDIUM},
  {120, "Curve Invertibility",                   nullptr, "CWE-682", nullptr, HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::MEDIUM},

  // --- INTEGRITY (H121-H138) ---
  {121, "Char Data Round Trip",                  nullptr, "CWE-20",  nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {122, "Tag Encoding",                          nullptr, "CWE-20",  nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {123, "Non Required Tags",                     nullptr, "CWE-20",  nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {124, "Version Tags",                          nullptr, "CWE-20",  nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {125, "Transform Smoothness",                  nullptr, "CWE-20",  nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {126, "Private Tag Malware",                   nullptr, "CWE-506", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::CRITICAL},
  {127, "Private Tag Registry",                  nullptr, "CWE-20",  nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {128, "Version BCD",                           "§7.2.4", "CWE-20", "CVE-2026-24403", HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {129, "PCS Illuminant D50",                    "§7.2.16", "CWE-20", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {130, "Tag Alignment",                         "§7.3.1", "CWE-20", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {131, "Profile Id MD5",                        nullptr, "CWE-345", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::MEDIUM},
  {132, "Chad Determinant",                      nullptr, "CWE-682", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::MEDIUM},
  {133, "Flags Reserved Bits",                   "§7.2.11", "CWE-20", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {134, "Tag Type Reserved Bytes",               "§10.1", "CWE-20",  nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {135, "Duplicate Tag Signatures",              "§7.3.1", "CWE-694", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::HIGH},
  {136, "Response Curve Measurement Count",      nullptr, "CWE-400", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::HIGH},
  {137, "High Dimensional Grid Complexity",      nullptr, "CWE-400", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::HIGH},
  {138, "Calculator Branching Depth",            nullptr, "CWE-674", "CVE-2026-24407,GHSA-vgr5-3xqx-vcqx", HeuristicPhase::INTEGRITY, HeuristicSeverity::HIGH},

  // --- IMAGE ANALYSIS (H139-H141) ---
  {139, "TIFF Strip Geometry Validation",        nullptr, "CWE-122", "GHSA-wh2p-cm3r-7hm3", HeuristicPhase::IMAGE, HeuristicSeverity::CRITICAL},
  {140, "TIFF Dimension Sample Validation",      nullptr, "CWE-400", nullptr, HeuristicPhase::IMAGE, HeuristicSeverity::HIGH},
  {141, "TIFF IFD Offset Bounds Validation",     nullptr, "CWE-125", nullptr, HeuristicPhase::IMAGE, HeuristicSeverity::CRITICAL},

  // --- XML SERIALIZATION SAFETY (H142-H145) ---
  {142, "XML Serialization Safety",              "§10",   "CWE-787", "GHSA-mv6h-vpcg-pwfx,GHSA-j3mh-rjg5-8gw7,GHSA-h3ph-mwq5-3883,GHSA-pmcg-2h65-35h8,GHSA-2pjj-3c98-qp37,GHSA-xqq3-g894-w2h5,CVE-2026-25502,CVE-2026-24852,CVE-2026-24412,CVE-2026-24411,CVE-2026-24410,CVE-2026-24409,CVE-2026-24408,CVE-2026-24407,CVE-2026-24406,CVE-2026-24404,CVE-2026-22046,CVE-2026-21693,CVE-2026-21692,CVE-2026-21690,CVE-2026-21689,CVE-2026-21682,CVE-2026-21678,CVE-2026-21500", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {143, "XML Array Bounds Precheck",             "§10",   "CWE-131", "GHSA-pmcg-2h65-35h8,GHSA-xqq3-g894-w2h5,CVE-2026-21682,CVE-2026-22046", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  {144, "XML String Termination Precheck",       "§10.4", "CWE-170", "GHSA-4wqv-pvm8-5h27,GHSA-h3ph-mwq5-3883,CVE-2026-25502,CVE-2026-24852", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  {145, "XML Curve Type Consistency",            "§10.14","CWE-843", "GHSA-2pjj-3c98-qp37,GHSA-mv6h-vpcg-pwfx,CVE-2026-24411,CVE-2026-24412,CVE-2026-21693,CVE-2026-21692,CVE-2026-21690,CVE-2026-21689", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},

  // --- ADVANCED DATA VALIDATION (H146-H148) ---
  {146, "Stack Buffer Overflow GetValues",       "§10.6", "CWE-121", "GHSA-rxfr-c2c7-v5m5,GHSA-f79r-m9wh-wr6j,CVE-2026-24406,CVE-2026-24404", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {147, "Null Pointer After Tag Read",           "§7.3",  "CWE-476", "GHSA-4wqv-pvm8-5h27,GHSA-j3mh-rjg5-8gw7,CVE-2026-24852,CVE-2026-25502", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {148, "Memory Copy Bounds Overlap",            "§10.14","CWE-119", "GHSA-vgr5-3xqx-vcqx,CVE-2026-24407", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
};

static constexpr size_t kHeuristicRegistrySize = sizeof(kHeuristicRegistry) / sizeof(kHeuristicRegistry[0]);
static constexpr int kTotalHeuristics = 148;

inline const char *SeverityToString(HeuristicSeverity s) {
  switch (s) {
    case HeuristicSeverity::CRITICAL: return "CRITICAL";
    case HeuristicSeverity::HIGH:     return "HIGH";
    case HeuristicSeverity::MEDIUM:   return "MEDIUM";
    case HeuristicSeverity::LOW:      return "LOW";
    case HeuristicSeverity::INFO:     return "INFO";
  }
  return "UNKNOWN";
}

// Lookup heuristic entry by ID. Returns nullptr if not found.
inline const HeuristicEntry *LookupHeuristic(int id) {
  for (size_t i = 0; i < kHeuristicRegistrySize; i++) {
    if (kHeuristicRegistry[i].id == id)
      return &kHeuristicRegistry[i];
  }
  return nullptr;
}

#endif
