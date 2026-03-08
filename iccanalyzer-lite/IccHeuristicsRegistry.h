/*
 * IccHeuristicsRegistry.h — Metadata registry for all 141 heuristics
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Data-driven registry mapping each heuristic ID to its name, spec reference,
 * primary CWE, and execution phase. Used for JSON output, filtering, and
 * programmatic enumeration of heuristics.
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

struct HeuristicEntry {
  int id;
  const char *name;
  const char *specRef;     // ICC.1-2022-05 section or nullptr
  const char *primaryCWE;  // Primary CWE identifier or nullptr
  HeuristicPhase phase;
};

static const HeuristicEntry kHeuristicRegistry[] = {
  {  1, "Profile Size", "§7.2.2", "CWE-131", HeuristicPhase::HEADER},
  {  2, "Magic Bytes", "§7.2.6", nullptr, HeuristicPhase::HEADER},
  {  3, "Color Space Signature", "§7.2.6", "CWE-20", HeuristicPhase::HEADER},
  {  4, "PCS Color Space", "§7.2.7", "CWE-20", HeuristicPhase::HEADER},
  {  5, "Platform Signature", "§7.2.10", "CWE-20", HeuristicPhase::HEADER},
  {  6, "Rendering Intent", "§7.2.15", "CWE-20", HeuristicPhase::HEADER},
  {  7, "Profile Class", "§7.2.5", "CWE-20", HeuristicPhase::HEADER},
  {  8, "Illuminant XYZ", "§7.2.16", "CWE-682", HeuristicPhase::HEADER},
  {  9, "Critical Text Tags", "§7.3", nullptr, HeuristicPhase::TAG_VALIDATION},
  { 10, "Tag Count", "§7.3", "CWE-20", HeuristicPhase::TAG_VALIDATION},
  { 11, "CLUT Entry Limit", "§10.10", "CWE-190", HeuristicPhase::TAG_VALIDATION},
  { 12, "MPE Chain Depth", "§10.26", "CWE-674", HeuristicPhase::TAG_VALIDATION},
  { 13, "Per Tag Size Check", "§7.3.1", "CWE-400", HeuristicPhase::TAG_VALIDATION},
  { 14, "Tag Array Detection", "§10.33", "CWE-416", HeuristicPhase::TAG_VALIDATION},
  { 15, "Date Validation", "§7.2.4", "CWE-20", HeuristicPhase::HEADER},
  { 16, "Signature Patterns", "§7.2", "CWE-506", HeuristicPhase::HEADER},
  { 17, "Spectral Range", "§7.2.22", "CWE-843", HeuristicPhase::HEADER},
  { 18, "Technology Signature", "§9.2.27", "CWE-20", HeuristicPhase::TAG_VALIDATION},
  { 19, "Tag Offset Overlap", "§7.3.1", "CWE-122", HeuristicPhase::TAG_VALIDATION},
  { 20, "Tag Type Signature", "§10", "CWE-843", HeuristicPhase::TAG_VALIDATION},
  { 21, "Tag Struct Member Inspection", "§10.32", "CWE-843", HeuristicPhase::TAG_VALIDATION},
  { 22, "Num Array Scalar Expectation", "§10.21", "CWE-20", HeuristicPhase::TAG_VALIDATION},
  { 23, "Num Array Value Range", "§10.21", "CWE-681", HeuristicPhase::TAG_VALIDATION},
  { 24, "Tag Struct Nesting Depth", "§10.32", "CWE-674", HeuristicPhase::TAG_VALIDATION},
  { 25, "Tag Offset OOB", "§7.3.1", "CWE-125", HeuristicPhase::TAG_VALIDATION},
  { 26, "Named Color2String Validation", "§10.20", "CWE-170", HeuristicPhase::TAG_VALIDATION},
  { 27, "MPE Matrix Output Channel", "§10.26", "CWE-131", HeuristicPhase::TAG_VALIDATION},
  { 28, "LUT Dimension Validation", "§10.10", "CWE-400", HeuristicPhase::TAG_VALIDATION},
  { 29, "Colorant Table String Validation", "§10.4", "CWE-170", HeuristicPhase::TAG_VALIDATION},
  { 30, "Gamut Boundary Desc Allocation", "§10.12", "CWE-400", HeuristicPhase::TAG_VALIDATION},
  { 31, "MPE Channel Count", "§10.26", "CWE-131", HeuristicPhase::TAG_VALIDATION},
  { 32, "Tag Data Type Confusion", "§10", "CWE-843", HeuristicPhase::TAG_VALIDATION},
  { 33, "mBA/mAB Sub-Element Offset Validation", nullptr, "CWE-122", HeuristicPhase::RAW_POST},
  { 34, "Integer Overflow Sub-Element Bounds", nullptr, "CWE-190", HeuristicPhase::RAW_POST},
  { 35, "Suspicious Fill Pattern mBA/mAB Data", nullptr, "CWE-506", HeuristicPhase::RAW_POST},
  { 36, "LUT Tag Pair Completeness", nullptr, "CWE-20", HeuristicPhase::RAW_POST},
  { 37, "Calculator Element Complexity", nullptr, "CWE-400", HeuristicPhase::RAW_POST},
  { 38, "Curve Degenerate Value Detection", nullptr, "CWE-682", HeuristicPhase::RAW_POST},
  { 39, "Shared Tag Data Aliasing Detection", nullptr, "CWE-416", HeuristicPhase::RAW_POST},
  { 40, "Tag Alignment Padding Validation", nullptr, "CWE-20", HeuristicPhase::RAW_POST},
  { 41, "Version Type Consistency Check", nullptr, "CWE-20", HeuristicPhase::RAW_POST},
  { 42, "Matrix Singularity Detection", nullptr, "CWE-369", HeuristicPhase::RAW_POST},
  { 43, "Spectral BRDF Tag Structural Validation", nullptr, "CWE-20", HeuristicPhase::RAW_POST},
  { 44, "Embedded Image Validation", nullptr, "CWE-122", HeuristicPhase::RAW_POST},
  { 45, "Sparse Matrix Bounds Validation", nullptr, "CWE-122", HeuristicPhase::RAW_POST},
  { 46, "TextDescription Unicode Length Validation", nullptr, "CWE-190", HeuristicPhase::RAW_POST},
  { 47, "NamedColor2 Size Overflow Detection", nullptr, "CWE-190", HeuristicPhase::RAW_POST},
  { 48, "CLUT Grid Dimension Product Overflow", nullptr, "CWE-190", HeuristicPhase::RAW_POST},
  { 49, "Float s15Fixed16 NaN Inf Detection", nullptr, "CWE-369", HeuristicPhase::RAW_POST},
  { 50, "Zero-Size Profile Tag Detection", nullptr, "CWE-835", HeuristicPhase::RAW_POST},
  { 51, "LUT IO Channel Count Consistency", nullptr, "CWE-125", HeuristicPhase::RAW_POST},
  { 52, "Integer Underflow Tag Size Subtraction", nullptr, "CWE-191", HeuristicPhase::RAW_POST},
  { 53, "Embedded Profile Recursion Detection", nullptr, "CWE-674", HeuristicPhase::RAW_POST},
  { 54, "Division-by-Zero Trigger Detection", nullptr, "CWE-369", HeuristicPhase::RAW_POST},
  { 55, "UTF-16 Encoding Validation", nullptr, "CWE-170", HeuristicPhase::RAW_POST},
  { 56, "Calculator Stack Depth", nullptr, "CWE-400", HeuristicPhase::DATA_VALIDATION},
  { 57, "Embedded Profile Recursion Depth", nullptr, "CWE-674", HeuristicPhase::RAW_POST},
  { 58, "Sparse Matrix Entry Bounds", nullptr, "CWE-126", HeuristicPhase::DATA_VALIDATION},
  { 59, "Spectral Wavelength Range Consistency", nullptr, "CWE-682", HeuristicPhase::RAW_POST},
  { 60, "Dictionary Tag Consistency", nullptr, "CWE-20", HeuristicPhase::DATA_VALIDATION},
  { 61, "Viewing Conditions Validation", nullptr, "CWE-682", HeuristicPhase::DATA_VALIDATION},
  { 62, "MLU String Bombs", nullptr, "CWE-400", HeuristicPhase::DATA_VALIDATION},
  { 63, "Curve LUT Channel Mismatch", nullptr, "CWE-131", HeuristicPhase::DATA_VALIDATION},
  { 64, "Named Color2Device Coord Overflow", nullptr, "CWE-787", HeuristicPhase::DATA_VALIDATION},
  { 65, "Chromaticity Plausibility", nullptr, "CWE-682", HeuristicPhase::DATA_VALIDATION},
  { 66, "Num Array Na N Inf Scan", nullptr, "CWE-682", HeuristicPhase::DATA_VALIDATION},
  { 67, "Response Curve Set Bounds", nullptr, "CWE-400", HeuristicPhase::DATA_VALIDATION},
  { 68, "GamutBoundaryDesc Triangle Vertex Overflow", nullptr, "CWE-190", HeuristicPhase::RAW_POST},
  { 69, "Profile ID MD5 Consistency", nullptr, "CWE-345", HeuristicPhase::RAW_POST},
  { 70, "Measurement Tag Validation", nullptr, "CWE-20", HeuristicPhase::DATA_VALIDATION},
  { 71, "Colorant Table Null Termination", nullptr, "CWE-170", HeuristicPhase::DATA_VALIDATION},
  { 72, "Sparse Matrix Array Bounds", nullptr, "CWE-843", HeuristicPhase::DATA_VALIDATION},
  { 73, "Tag Array Nesting Depth", nullptr, "CWE-674", HeuristicPhase::DATA_VALIDATION},
  { 74, "Tag Type Signature Consistency", nullptr, "CWE-843", HeuristicPhase::DATA_VALIDATION},
  { 75, "Tags Very Small Size", nullptr, "CWE-20", HeuristicPhase::DATA_VALIDATION},
  { 76, "C Icc Tag Data Type Flag", nullptr, "CWE-843", HeuristicPhase::DATA_VALIDATION},
  { 77, "MPE Calculator Sub Element Count", nullptr, "CWE-400", HeuristicPhase::DATA_VALIDATION},
  { 78, "CLUT Grid Dimension Overflow", nullptr, "CWE-190", HeuristicPhase::DATA_VALIDATION},
  { 79, "Load Tag Allocation Overflow", nullptr, "CWE-190", HeuristicPhase::DATA_VALIDATION},
  { 80, "Shared Tag Pointer UAF", nullptr, "CWE-416", HeuristicPhase::DATA_VALIDATION},
  { 81, "MPE Calculator IO Consistency", nullptr, "CWE-122", HeuristicPhase::DATA_VALIDATION},
  { 82, "IO Read Size Overflow", nullptr, "CWE-190", HeuristicPhase::DATA_VALIDATION},
  { 83, "Float Numeric Array Size", nullptr, "CWE-125", HeuristicPhase::DATA_VALIDATION},
  { 84, "LUT3D Transform Consistency", nullptr, "CWE-125", HeuristicPhase::DATA_VALIDATION},
  { 85, "MPE Buffer Overlap", nullptr, "CWE-122", HeuristicPhase::DATA_VALIDATION},
  { 86, "Localized Unicode Bounds", nullptr, "CWE-787", HeuristicPhase::DATA_VALIDATION},
  { 87, "TRC Curve Anomaly", nullptr, "CWE-682", HeuristicPhase::DATA_VALIDATION},
  { 88, "Chromatic Adaptation Matrix", nullptr, "CWE-682", HeuristicPhase::DATA_VALIDATION},
  { 89, "Profile Sequence Description", nullptr, "CWE-400", HeuristicPhase::DATA_VALIDATION},
  { 90, "Preview Tag Channel Consistency", nullptr, "CWE-787", HeuristicPhase::DATA_VALIDATION},
  { 91, "Colorant Order Validation", nullptr, "CWE-682", HeuristicPhase::DATA_VALIDATION},
  { 92, "Spectral Viewing Conditions", nullptr, "CWE-20", HeuristicPhase::DATA_VALIDATION},
  { 93, "Embedded Profile Flag", nullptr, "CWE-20", HeuristicPhase::DATA_VALIDATION},
  { 94, "Matrix TRC Colorant Consistency", nullptr, "CWE-682", HeuristicPhase::DATA_VALIDATION},
  { 95, "Sparse Matrix Array Bounds Validation", nullptr, "CWE-843", HeuristicPhase::DATA_VALIDATION},
  { 96, "Embedded Profile Validation", nullptr, "CWE-674", HeuristicPhase::DATA_VALIDATION},
  { 97, "Profile Sequence Id Validation", nullptr, "CWE-400", HeuristicPhase::DATA_VALIDATION},
  { 98, "Spectral MPE Element Validation", nullptr, "CWE-787", HeuristicPhase::DATA_VALIDATION},
  { 99, "Embedded Image Tag Validation", nullptr, "CWE-125", HeuristicPhase::DATA_VALIDATION},
  {100, "Profile Sequence Desc Validation", nullptr, "CWE-787", HeuristicPhase::DATA_VALIDATION},
  {101, "MPE Sub Element Channel Continuity", nullptr, "CWE-787", HeuristicPhase::DATA_VALIDATION},
  {102, "Tag Size Profile Size Cross Check", nullptr, "CWE-131", HeuristicPhase::DATA_VALIDATION},
  {103, "PCC", nullptr, nullptr, HeuristicPhase::PROFILE_COMPLIANCE},
  {104, "PRMG", nullptr, nullptr, HeuristicPhase::PROFILE_COMPLIANCE},
  {105, "Matrix TRC", nullptr, "CWE-682", HeuristicPhase::PROFILE_COMPLIANCE},
  {106, "Env Var", nullptr, "CWE-131", HeuristicPhase::PROFILE_COMPLIANCE},
  {107, "Channel Cross Check", nullptr, "CWE-131", HeuristicPhase::PROFILE_COMPLIANCE},
  {108, "Private Tags", nullptr, "CWE-506", HeuristicPhase::PROFILE_COMPLIANCE},
  {109, "Shellcode Patterns", nullptr, "CWE-506", HeuristicPhase::PROFILE_COMPLIANCE},
  {110, "Class Tag Validation", "§8", "CWE-20", HeuristicPhase::PROFILE_COMPLIANCE},
  {111, "Reserved Bytes", "§7.2.19", "CWE-20", HeuristicPhase::PROFILE_COMPLIANCE},
  {112, "Wtpt Validation", nullptr, "CWE-682", HeuristicPhase::PROFILE_COMPLIANCE},
  {113, "Round Trip Fidelity", nullptr, "CWE-682", HeuristicPhase::PROFILE_COMPLIANCE},
  {114, "Curve Smoothness", nullptr, "CWE-20", HeuristicPhase::PROFILE_COMPLIANCE},
  {115, "Characterization Data", nullptr, nullptr, HeuristicPhase::PROFILE_COMPLIANCE},
  {116, "Cprt Desc Encoding", nullptr, "CWE-20", HeuristicPhase::PROFILE_COMPLIANCE},
  {117, "Tag Type Allowed", nullptr, "CWE-20", HeuristicPhase::PROFILE_COMPLIANCE},
  {118, "Calc Cost Estimate", nullptr, "CWE-400", HeuristicPhase::PROFILE_COMPLIANCE},
  {119, "Round Trip Delta E", nullptr, "CWE-682", HeuristicPhase::PROFILE_COMPLIANCE},
  {120, "Curve Invertibility", nullptr, "CWE-682", HeuristicPhase::PROFILE_COMPLIANCE},
  {121, "Char Data Round Trip", nullptr, nullptr, HeuristicPhase::INTEGRITY},
  {122, "Tag Encoding", nullptr, "CWE-20", HeuristicPhase::INTEGRITY},
  {123, "Non Required Tags", nullptr, "CWE-20", HeuristicPhase::INTEGRITY},
  {124, "Version Tags", nullptr, "CWE-20", HeuristicPhase::INTEGRITY},
  {125, "Transform Smoothness", nullptr, nullptr, HeuristicPhase::INTEGRITY},
  {126, "Private Tag Malware", nullptr, "CWE-506", HeuristicPhase::INTEGRITY},
  {127, "Private Tag Registry", nullptr, "CWE-20", HeuristicPhase::INTEGRITY},
  {128, "Version BCD", "§7.2.4", "CWE-20", HeuristicPhase::INTEGRITY},
  {129, "PCS Illuminant D50", "§7.2.16", "CWE-20", HeuristicPhase::INTEGRITY},
  {130, "Tag Alignment", "§7.3.1", "CWE-20", HeuristicPhase::INTEGRITY},
  {131, "Profile Id MD5", nullptr, "CWE-345", HeuristicPhase::INTEGRITY},
  {132, "Chad Determinant", nullptr, "CWE-682", HeuristicPhase::INTEGRITY},
  {133, "Flags Reserved Bits", "§7.2.11", "CWE-20", HeuristicPhase::INTEGRITY},
  {134, "Tag Type Reserved Bytes", "§10.1", "CWE-20", HeuristicPhase::INTEGRITY},
  {135, "Duplicate Tag Signatures", "§7.3.1", "CWE-694", HeuristicPhase::INTEGRITY},
  {136, "Response Curve Measurement Count", nullptr, "CWE-400", HeuristicPhase::INTEGRITY},
  {137, "High Dimensional Grid Complexity", nullptr, "CWE-400", HeuristicPhase::INTEGRITY},
  {138, "Calculator Branching Depth", nullptr, "CWE-674", HeuristicPhase::INTEGRITY},
  {139, "TIFF Strip Geometry Validation", nullptr, "CWE-122", HeuristicPhase::IMAGE},
  {140, "TIFF Dimension Sample Validation", nullptr, "CWE-400", HeuristicPhase::IMAGE},
  {141, "TIFF IFD Offset Bounds Validation", nullptr, "CWE-125", HeuristicPhase::IMAGE},
};

static constexpr size_t kHeuristicRegistrySize = sizeof(kHeuristicRegistry) / sizeof(kHeuristicRegistry[0]);
static constexpr int kTotalHeuristics = 141;

// Lookup heuristic entry by ID. Returns nullptr if not found.
inline const HeuristicEntry *LookupHeuristic(int id) {
  for (size_t i = 0; i < kHeuristicRegistrySize; i++) {
    if (kHeuristicRegistry[i].id == id)
      return &kHeuristicRegistry[i];
  }
  return nullptr;
}

#endif
