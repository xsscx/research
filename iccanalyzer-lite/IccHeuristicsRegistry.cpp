/*
 * IccHeuristicsRegistry.cpp — Compiled registry for all heuristic metadata
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Moved from header-only (static array per TU) to single compilation unit.
 * At 1000 heuristics this avoids recompiling a 2000-line array in every TU.
 */

#include "IccHeuristicsRegistry.h"
#include <set>
#include <string>

const HeuristicEntry kHeuristicRegistry[] = {
  // --- HEADER VALIDATION (H1-H8, H15-H17) ---
  {  1, "Profile Size",                        "§7.2.2",  "CWE-131", nullptr, HeuristicPhase::HEADER, HeuristicSeverity::MEDIUM},
  {  2, "Magic Bytes",                         "§7.2.6",  "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  3, "Color Space Signature",               "§7.2.6",  "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  4, "PCS Color Space",                     "§7.2.7",  "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  5, "Platform/CMM/Manufacturer/Creator",    "§7.2.10", "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  6, "Rendering Intent",                    "§7.2.15", "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  7, "Profile Class",                       "§7.2.5",  "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  {  8, "Illuminant XYZ",                      "§7.2.16", "CWE-682", nullptr, HeuristicPhase::HEADER, HeuristicSeverity::MEDIUM},
  { 15, "Date Validation",                     "§7.2.4",  "CWE-20",  nullptr, HeuristicPhase::HEADER, HeuristicSeverity::LOW},
  { 16, "Signature Patterns",                  "§7.2",    "CWE-506", nullptr, HeuristicPhase::HEADER, HeuristicSeverity::INFO},
  { 17, "Spectral Range",                      "§7.2.22", "CWE-843", nullptr, HeuristicPhase::HEADER, HeuristicSeverity::MEDIUM},

  // --- TAG VALIDATION (H9-H14, H18-H32) ---
  {  9, "Critical Text Tags",                  "§7.3",    "CWE-476", "CVE-2026-21496,CVE-2026-21497,GHSA-7gv7-cmrv-4j85,GHSA-wj8m-6w77-r4rw", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 10, "Tag Count",                           "§7.3",    "CWE-20",  "CVE-2026-21680,GHSA-mgp7-w4w3-mhx4", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::MEDIUM},
  { 11, "CLUT Entry Limit",                    "§10.10",  "CWE-190", "CVE-2026-21677,CVE-2026-22255,CVE-2026-30986,CVE-2026-31794,GHSA-6jrq-wfqg-wv7w,GHSA-92v9-wq22-2rfv,GHSA-95w5-jvqf-3994,GHSA-qv2w-mq3g-73gv,GHSA-w3g9-rmvh-49gh,GHSA-x6gg-j72w-jc9w", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 12, "MPE Chain Depth",                     "§10.26",  "CWE-674", "CVE-2026-21500,CVE-2026-21501,GHSA-4h4j-mm9w-2cp4,GHSA-x7hw-h22p-2x4w", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 13, "Per Tag Size Check",                  "§7.3.1",  "CWE-400", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 14, "Tag Array Detection",                 "§10.33",  "CWE-416", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 18, "Technology Signature",                "§9.2.27", "CWE-20",  nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::LOW},
  { 19, "Tag Offset Overlap",                  "§7.3.1",  "CWE-122", "CVE-2021-30942,CVE-2022-26730", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 20, "Tag Type Signature",                  "§10",     "CWE-843", "CVE-2026-21505,CVE-2026-24856,GHSA-j577-8285-qrf9,GHSA-w585-cv3v-c396", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 21, "Tag Struct Member Inspection",        "§10.32",  "CWE-843", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::MEDIUM},
  { 22, "Num Array Scalar Expectation",        "§10.21",  "CWE-20",  nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::LOW},
  { 23, "Num Array Value Range",               "§10.21",  "CWE-681", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::MEDIUM},
  { 24, "Tag Struct Nesting Depth",            "§10.32",  "CWE-674", "CVE-2026-30980,GHSA-w478-77q7-2hc2", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 25, "Tag Offset OOB",                      "§7.3.1",  "CWE-125", "CVE-2026-21487,GHSA-xq7x-9524-f7cp", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 26, "Named Color2String Validation",       "§10.20",  "CWE-170", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 27, "MPE Matrix Output Channel",           "§10.26",  "CWE-131", "CVE-2026-27692,GHSA-3869-prw8-gjqr", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 28, "LUT Dimension Validation",            "§10.10",  "CWE-400", "CVE-2026-21490,CVE-2026-21494,GHSA-9q9c-699q-xr2q,GHSA-hjxv-xr7w-84fc,GHSA-x9hr-pxxc-h38p", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 29, "Colorant Table String Validation",    "§10.4",   "CWE-125/CWE-170", "GHSA-4wqv-pvm8-5h27", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 30, "Gamut Boundary Desc Allocation",      "§10.12",  "CWE-400", "GHSA-rc3h-95ph-j363", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::HIGH},
  { 31, "MPE Channel Count",                   "§10.26",  "CWE-131", nullptr, HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},
  { 32, "Tag Data Type Confusion",             "§10",     "CWE-843", "CVE-2021-30942,CVE-2026-21683,CVE-2026-21688,CVE-2026-21691,CVE-2026-25503,GHSA-3r2x-j7v3-pg6f,GHSA-c9q5-x498-jv92,GHSA-f2wp-j3fr-938w,GHSA-pf84-4c7q-x764", HeuristicPhase::TAG_VALIDATION, HeuristicSeverity::CRITICAL},

  // --- RAW POST ANALYSIS (H33-H55, H57-H69) ---
  { 33, "mBA/mAB Sub-Element Offset Validation", nullptr, "CWE-122", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 34, "Integer Overflow Sub-Element Bounds",   nullptr, "CWE-190", "CVE-2026-27691,GHSA-4gfj-4cjh-53v5", HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 35, "Suspicious Fill Pattern mBA/mAB Data",  nullptr, "CWE-506", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::INFO},
  { 36, "LUT Tag Pair Completeness",             nullptr, "CWE-20",  nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::LOW},
  { 37, "Calculator Element Complexity",          nullptr, "CWE-400", "CVE-2026-21507,CVE-2026-22047,CVE-2026-30979,GHSA-22q7-8347-79m5,GHSA-8c76-67wr-hrp4,GHSA-hgp5-r8m9-8qpj", HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 38, "Curve Degenerate Value Detection",       nullptr, "CWE-682", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},
  { 39, "Shared Tag Data Aliasing Detection",     nullptr, "CWE-416", "CVE-2022-26730", HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 40, "Tag Alignment Padding Validation",       nullptr, "CWE-20",  nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::LOW},
  { 41, "Version Type Consistency Check",         nullptr, "CWE-20",  nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::LOW},
  { 42, "Matrix Singularity Detection",           nullptr, "CWE-369", "CVE-2026-30985,GHSA-f9wv-cq46-f9wg", HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},
  { 43, "Spectral BRDF Tag Structural Validation", nullptr, "CWE-20", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::LOW},
  { 44, "Embedded Image Validation",              nullptr, "CWE-122", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 45, "Sparse Matrix Bounds Validation",        nullptr, "CWE-122", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 46, "TextDescription Unicode Length Validation", nullptr, "CWE-190", "CVE-2026-21488,CVE-2026-21491,GHSA-4j2g-rvv4-86vg,GHSA-4pv4-4x2x-6j88", HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 47, "NamedColor2 Size Overflow Detection",    nullptr, "CWE-190", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 48, "CLUT Grid Dimension Product Overflow",   nullptr, "CWE-190", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 49, "Float s15Fixed16 NaN Inf Detection",     nullptr, "CWE-682", "CVE-2026-21681,GHSA-v4qq-v3c3-x62x", HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},
  { 50, "Zero-Size Profile Tag Detection",        nullptr, "CWE-835", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 51, "LUT IO Channel Count Consistency",       nullptr, "CWE-125", "CVE-2021-30942", HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 52, "Integer Underflow Tag Size Subtraction", nullptr, "CWE-191", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 53, "Embedded Profile Recursion Detection",   nullptr, "CWE-674", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 54, "Division-by-Zero Trigger Detection",     nullptr, "CWE-369", "CVE-2026-21495,GHSA-xhrm-79rg-5784", HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 55, "UTF-16 Encoding Validation",             nullptr, "CWE-170", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 57, "Embedded Profile Recursion Depth",        nullptr, "CWE-674", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  { 59, "Spectral Wavelength Range Consistency",   nullptr, "CWE-682", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},
  { 68, "GamutBoundaryDesc Triangle Vertex Overflow", nullptr, "CWE-190", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  { 69, "Profile ID MD5 Consistency",              nullptr, "CWE-345", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},

  // --- DATA VALIDATION (H56, H58, H60-H67, H70-H102) ---
  { 56, "Calculator Stack Depth",               nullptr, "CWE-400", "CVE-2026-21501,GHSA-x7hw-h22p-2x4w", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 58, "Sparse Matrix Entry Bounds",            nullptr, "CWE-126", "CVE-2026-21503,GHSA-h554-qrfh-53gx", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 60, "Dictionary Tag Consistency",            nullptr, "CWE-20",  nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::LOW},
  { 61, "Viewing Conditions Validation",         nullptr, "CWE-682", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 62, "MLU String Bombs",                      nullptr, "CWE-400", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 63, "Curve LUT Channel Mismatch",            nullptr, "CWE-131", "CVE-2026-21685,CVE-2026-21686,GHSA-792q-cqq9-mq4x,GHSA-c3xr-6687-5c8p", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 64, "Named Color2Device Coord Overflow",     nullptr, "CWE-787", "CVE-2026-24406,GHSA-h9h3-45cm-j95f", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 65, "Chromaticity Plausibility",             nullptr, "CWE-682", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 66, "Num Array NaN Inf Scan",                nullptr, "CWE-682", "CVE-2026-21681,GHSA-v4qq-v3c3-x62x", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 67, "Response Curve Set Bounds",             nullptr, "CWE-400", "CVE-2026-24852,GHSA-q8g2-mp32-3j7f", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 70, "Measurement Tag Validation",            nullptr, "CWE-20",  nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::LOW},
  { 71, "Colorant Table Null Termination",       nullptr, "CWE-170", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 72, "Sparse Matrix Array Bounds",            nullptr, "CWE-843", "CVE-2026-21503,CVE-2026-21505,GHSA-h554-qrfh-53gx,GHSA-j577-8285-qrf9", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 73, "Tag Array Nesting Depth",               nullptr, "CWE-674", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 74, "Tag Type Signature Consistency",        nullptr, "CWE-843", "CVE-2021-30942,CVE-2026-21505,CVE-2026-24856,GHSA-j577-8285-qrf9,GHSA-w585-cv3v-c396", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 75, "Tags Very Small Size",                  nullptr, "CWE-20",  nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::LOW},
  { 76, "CIccTagData Type Flag",                 nullptr, "CWE-843", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 77, "MPE Calculator Sub Element Count",      nullptr, "CWE-400", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 78, "CLUT Grid Dimension Overflow",          nullptr, "CWE-190", "CVE-2026-21677,CVE-2026-22255,GHSA-95w5-jvqf-3994,GHSA-qv2w-mq3g-73gv", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 79, "Load Tag Allocation Overflow",          nullptr, "CWE-190", "CVE-2026-21485,GHSA-chp2-4gv5-2432", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 80, "Shared Tag Pointer UAF",                nullptr, "CWE-416", "CVE-2026-21486,CVE-2026-21675,CVE-2026-30978,GHSA-97mf-f6r7-q9q4,GHSA-fqq2-v72p-wfff,GHSA-mg98-j5q2-674w,GHSA-wcwx-794g-g78f", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 81, "MPE Calculator IO Consistency",         nullptr, "CWE-122", "CVE-2026-21504,CVE-2026-22047,CVE-2026-22861,CVE-2026-24405,CVE-2026-30984,GHSA-22q7-8347-79m5,GHSA-2r5c-5w66-47vv,GHSA-g9w6-5xm9-v5xj,GHSA-rqp9-r53c-3m9h,GHSA-vg26-ggwf-6fmq,GHSA-vr49-3vf8-7j5h", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 82, "IO Read Size Overflow",                 nullptr, "CWE-190", "CVE-2026-25582,CVE-2026-25583,CVE-2026-30987,GHSA-46hq-fphp-jggf,GHSA-5ffg-r52h-fgw3,GHSA-fj57-gfhq-rjqr", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 83, "Float Numeric Array Size",              nullptr, "CWE-125", "CVE-2026-25584,GHSA-xjr3-v3vr-5794", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 84, "LUT3D Transform Consistency",           nullptr, "CWE-125", "CVE-2026-25585,CVE-2026-30982,CVE-2026-31795,GHSA-7ww3-h4w6-x5hf,GHSA-pmqx-q624-jg6w,GHSA-wh5x-j6pq-pr3c", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 85, "MPE Buffer Overlap",                    nullptr, "CWE-122", "CVE-2026-25634,GHSA-35rg-jcmp-583h", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 86, "Localized Unicode Bounds",              nullptr, "CWE-787", "CVE-2026-21678,CVE-2026-21679,GHSA-9rp2-4c6g-hppf,GHSA-h4wg-473g-p5wc", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 87, "TRC Curve Anomaly",                     nullptr, "CWE-682", "CVE-2026-21489,GHSA-ph89-6q5h-wfw5", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 88, "Chromatic Adaptation Matrix",           nullptr, "CWE-682", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 89, "Profile Sequence Description",          nullptr, "CWE-400", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 90, "Preview Tag Channel Consistency",       nullptr, "CWE-787", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 91, "Colorant Order Validation",             nullptr, "CWE-682", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 92, "Spectral Viewing Conditions",           nullptr, "CWE-20",  "CVE-2026-21684,GHSA-fg9m-j9x8-8279", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::LOW},
  { 93, "Embedded Profile Flag",                 nullptr, "CWE-20",  nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::LOW},
  { 94, "Matrix TRC Colorant Consistency",       nullptr, "CWE-682", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  { 95, "Sparse Matrix Array Bounds Validation", nullptr, "CWE-843", "CVE-2026-21503,GHSA-h554-qrfh-53gx", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 96, "Embedded Profile Validation",           nullptr, "CWE-674", "CVE-2026-25503,GHSA-pf84-4c7q-x764", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 97, "Profile Sequence Id Validation",        nullptr, "CWE-400", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  { 98, "Spectral MPE Element Validation",       nullptr, "CWE-787", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  { 99, "Embedded Image Tag Validation",         nullptr, "CWE-125", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {100, "Profile Sequence Desc Validation",      nullptr, "CWE-787", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {101, "MPE Sub Element Channel Continuity",    nullptr, "CWE-787", "CVE-2026-21492,GHSA-xpq3-v3jj-mgvx", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {102, "Tag Size Profile Size Cross Check",     nullptr, "CWE-131", "CVE-2026-21676,GHSA-j5vv-p2hv-c392", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},

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
  {114, "Curve Smoothness",                      nullptr, "CWE-20",  "CVE-2026-21687,GHSA-prmm-g479-4fv7", HeuristicPhase::PROFILE_COMPLIANCE, HeuristicSeverity::LOW},
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
  {128, "Version BCD",                           "§7.2.4", "CWE-20", "CVE-2026-24403,GHSA-ph33-qp8j-5q34", HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {129, "PCS Illuminant D50",                    "§7.2.16", "CWE-20", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {130, "Tag Alignment",                         "§7.3.1", "CWE-20", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {131, "Profile Id MD5",                        nullptr, "CWE-345", "CVE-2022-26730", HeuristicPhase::INTEGRITY, HeuristicSeverity::MEDIUM},
  {132, "Chad Determinant",                      nullptr, "CWE-682", "CVE-2022-26730", HeuristicPhase::INTEGRITY, HeuristicSeverity::MEDIUM},
  {133, "Flags Reserved Bits",                   "§7.2.11", "CWE-20", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {134, "Tag Type Reserved Bytes",               "§10.1", "CWE-20",  nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::LOW},
  {135, "Duplicate Tag Signatures",              "§7.3.1", "CWE-694", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::HIGH},
  {136, "Response Curve Measurement Count",      nullptr, "CWE-400", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::HIGH},
  {137, "High Dimensional Grid Complexity",      nullptr, "CWE-400", nullptr, HeuristicPhase::INTEGRITY, HeuristicSeverity::HIGH},
  {138, "Calculator Branching Depth",            nullptr, "CWE-674", "CVE-2026-24407,CVE-2026-31793,GHSA-m6gx-93cp-4855,GHSA-vgr5-3xqx-vcqx", HeuristicPhase::INTEGRITY, HeuristicSeverity::HIGH},

  // --- IMAGE ANALYSIS (H139-H141) ---
  {139, "TIFF Strip Geometry Validation",        nullptr, "CWE-122", "CVE-2026-31797,GHSA-wh2p-cm3r-7hm3", HeuristicPhase::IMAGE, HeuristicSeverity::CRITICAL},
  {140, "TIFF Dimension Sample Validation",      nullptr, "CWE-400", nullptr, HeuristicPhase::IMAGE, HeuristicSeverity::HIGH},
  {141, "TIFF IFD Offset Bounds Validation",     nullptr, "CWE-125", nullptr, HeuristicPhase::IMAGE, HeuristicSeverity::CRITICAL},

  // --- XML SERIALIZATION SAFETY (H142-H145) ---
  {142, "XML Serialization Safety",              "§10",   "CWE-787", "CVE-2026-21498,CVE-2026-21499,CVE-2026-21500,CVE-2026-21502,CVE-2026-21506,CVE-2026-21674,CVE-2026-21678,CVE-2026-21682,CVE-2026-21689,CVE-2026-21690,CVE-2026-21692,CVE-2026-21693,CVE-2026-22046,CVE-2026-24404,CVE-2026-24406,CVE-2026-24407,CVE-2026-24408,CVE-2026-24409,CVE-2026-24410,CVE-2026-24411,CVE-2026-24412,CVE-2026-24852,CVE-2026-25502,CVE-2026-30981,CVE-2026-30983,CVE-2026-31792,CVE-2026-31796,GHSA-2f26-vh48-38g6,GHSA-2pjj-3c98-qp37,GHSA-398q-4rpv-3v9r,GHSA-398v-jvcg-p8f3,GHSA-4h4j-mm9w-2cp4,GHSA-5rqc-w93q-589m,GHSA-67r8-q3mh-42j6,GHSA-6822-qvxq-m736,GHSA-6rf4-63j2-cfrf,GHSA-7662-mf46-wr88,GHSA-7v4q-mhr2-hj7r,GHSA-9rp2-4c6g-hppf,GHSA-c2qq-jf7w-rm27,GHSA-c3pv-2cpf-7v2p,GHSA-h3ph-mwq5-3883,GHSA-h9h3-45cm-j95f,GHSA-hqfg-45jp-hp9f,GHSA-j3mh-rjg5-8gw7,GHSA-jq9m-54gr-c56c,GHSA-m6gx-93cp-4855,GHSA-mv6h-vpcg-pwfx,GHSA-pmcg-2h65-35h8,GHSA-q8g2-mp32-3j7f,GHSA-v3q7-7hw6-6jq8,GHSA-wfm7-m548-x4vp,GHSA-x53f-7h27-9fc8,GHSA-xqq3-g894-w2h5,GHSA-xww6-v3vg-4qc7", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {143, "XML Array Bounds Precheck",             "§10",   "CWE-131", "CVE-2026-21673,CVE-2026-21682,CVE-2026-22046,CVE-2026-30981,GHSA-7v4q-mhr2-hj7r,GHSA-g66g-f82c-vgm6,GHSA-jq9m-54gr-c56c,GHSA-pmcg-2h65-35h8,GHSA-xqq3-g894-w2h5", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  {144, "XML String Termination Precheck",       "§10.4", "CWE-170", "CVE-2026-24852,CVE-2026-25502,CVE-2026-30983,GHSA-4wqv-pvm8-5h27,GHSA-c2qq-jf7w-rm27,GHSA-h3ph-mwq5-3883,GHSA-q8g2-mp32-3j7f", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::HIGH},
  {145, "XML Curve Type Consistency",            "§10.14","CWE-843", "CVE-2026-21493,CVE-2026-21689,CVE-2026-21690,CVE-2026-21692,CVE-2026-21693,CVE-2026-24411,CVE-2026-24412,CVE-2026-31796,GHSA-2f26-vh48-38g6,GHSA-2pjj-3c98-qp37,GHSA-5rqc-w93q-589m,GHSA-6rf4-63j2-cfrf,GHSA-7662-mf46-wr88,GHSA-mv6h-vpcg-pwfx,GHSA-p85g-f9q7-jmjx,GHSA-v3q7-7hw6-6jq8,GHSA-x53f-7h27-9fc8", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},

  // --- ADVANCED DATA VALIDATION (H146-H148) ---
  {146, "Stack Buffer Overflow GetValues",       "§10.6", "CWE-121", "CVE-2026-24404,CVE-2026-24406,GHSA-f79r-m9wh-wr6j,GHSA-h9h3-45cm-j95f,GHSA-hqfg-45jp-hp9f,GHSA-rxfr-c2c7-v5m5", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {147, "Null Pointer After Tag Read",           "§7.3",  "CWE-476", "CVE-2021-30942,CVE-2022-26730,CVE-2026-24852,CVE-2026-25502,CVE-2026-31792,GHSA-4wqv-pvm8-5h27,GHSA-c2qq-jf7w-rm27,GHSA-j3mh-rjg5-8gw7,GHSA-q8g2-mp32-3j7f", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},
  {148, "Memory Copy Bounds Overlap",            "§10.14","CWE-119", "CVE-2026-24407,CVE-2026-31793,GHSA-m6gx-93cp-4855,GHSA-vgr5-3xqx-vcqx", HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::CRITICAL},

  // ── TIFF Image Security (extended) ──
  {149, "TIFF IFD Chain Cycle Detection",         nullptr, "CWE-835", nullptr, HeuristicPhase::IMAGE, HeuristicSeverity::HIGH},
  {150, "TIFF Tile Geometry Validation",           nullptr, "CWE-122", nullptr, HeuristicPhase::IMAGE, HeuristicSeverity::CRITICAL},

  // --- CALCULATOR OPERATOR ENUM VALIDATION (H151) ---
  {151, "Calculator Operator Enum Validation",    "§10.26","CWE-681", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {152, "Curve Element OOM Size Validation",       "§10.26","CWE-770", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {153, "Sampled Curve NaN-to-Unsigned Cast",     "§10.26","CWE-681", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},

  // --- CODEQL-DRIVEN HEURISTICS (H154-H161) ---
  {154, "Uncontrolled Tag Allocation Size",       "§7.3",  "CWE-789", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {155, "Integer Overflow in Tag Dimensions",     "§10.6", "CWE-190", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {156, "Allocation Failure Path Profiles",       "§7.3",  "CWE-252", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  {157, "Alloc-Dealloc Mismatch Tag Patterns",    "§10.14","CWE-762", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {158, "Enum Range Violation Detection",         "§10.26","CWE-681", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  {159, "UAF Tag Ownership Chain Detection",      "§7.3",  "CWE-416", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {160, "Format String Injection in Text Tags",   "§10.24","CWE-134", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {161, "Stack Address Escape Deep Apply Chains", "§10.14","CWE-121", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},

  // ── Exploit-Gap Heuristics (H162-H169) ──
  {162, "Partial Tag Data Overlap Detection", "§7.3","CWE-119", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {163, "Executable Signature Scan In Tag Data", "§7.3","CWE-506", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  {164, "Raw LUT Channel vs ColorSpace/PCS Cross-Check", "§10.6","CWE-131", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {165, "LUT Data Sufficiency Validation", "§10.6","CWE-125", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {166, "Division-by-Zero in CAM/Array/MPE", "§10.26","CWE-369", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  {167, "Null MPE CLUT/Curve Application Guard", "§10.10","CWE-476", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {168, "Unchecked Allocation Size Overflow", "§7.3","CWE-789", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {169, "Dictionary Tag Element Bounds", "§10.22","CWE-789", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  {170, "Copy Constructor UB via Null PCS", "§7.2.7","CWE-843", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {171, "Curve Param Count vs FuncType Validation", "§10.15/§10.23","CWE-125", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::CRITICAL},
  {172, "LUT Matrix Coefficient Validation", "ICC TN v4 Matrix Entries","CWE-682", nullptr, HeuristicPhase::DATA_VALIDATION, HeuristicSeverity::MEDIUM},
  {173, "Signature Conversion Shift Overflow", "IccUtil.cpp:1088/1130/1167/1187/1228/1253","CWE-190", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},
  {174, "Half-Float Conversion Unsigned Underflow", "IccUtil.cpp:665/677, IccIO.cpp:328","CWE-190", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},
  {175, "Device Spectral Colour Space Range Requirement", "ICC.2:2023 §7.2.8 amend","CWE-20", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  {176, "deviceSpectralRangeTag Validation", "ICC.2:2023 §9.2.x","CWE-20/CWE-125", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  {177, "devicePccTag Structure Validation", "ICC.2:2023 §9.2.x+1","CWE-20/CWE-476", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::HIGH},
  {178, "spectralRangeType Encoding Validation", "ICC.2:2023 §10.2.w","CWE-20/CWE-125", nullptr, HeuristicPhase::RAW_POST, HeuristicSeverity::MEDIUM},
  {179, "AddXform Create NULL Guard Detection", "IccCmm.cpp:8292 PR#708","CWE-476", nullptr, HeuristicPhase::EXPLOIT_GAP, HeuristicSeverity::HIGH},
  {180, "XML Round-Trip Fidelity", "ICC.1-2022-05 §10","CWE-345", nullptr, HeuristicPhase::XML_SAFETY, HeuristicSeverity::HIGH},
};

const size_t kHeuristicRegistrySize = sizeof(kHeuristicRegistry) / sizeof(kHeuristicRegistry[0]);
const int kTotalHeuristics = static_cast<int>(kHeuristicRegistrySize);

const char *SeverityToString(HeuristicSeverity s) {
  switch (s) {
    case HeuristicSeverity::CRITICAL: return "CRITICAL";
    case HeuristicSeverity::HIGH:     return "HIGH";
    case HeuristicSeverity::MEDIUM:   return "MEDIUM";
    case HeuristicSeverity::LOW:      return "LOW";
    case HeuristicSeverity::INFO:     return "INFO";
  }
  return "UNKNOWN";
}

const char *PhaseToString(HeuristicPhase p) {
  switch (p) {
    case HeuristicPhase::HEADER:             return "HEADER";
    case HeuristicPhase::TAG_VALIDATION:     return "TAG_VALIDATION";
    case HeuristicPhase::RAW_POST:           return "RAW_POST";
    case HeuristicPhase::DATA_VALIDATION:    return "DATA_VALIDATION";
    case HeuristicPhase::PROFILE_COMPLIANCE: return "PROFILE_COMPLIANCE";
    case HeuristicPhase::INTEGRITY:          return "INTEGRITY";
    case HeuristicPhase::IMAGE:              return "IMAGE";
    case HeuristicPhase::CODEQL_PATTERNS:    return "CODEQL_PATTERNS";
    case HeuristicPhase::EXPLOIT_GAP:        return "EXPLOIT_GAP";
    case HeuristicPhase::XML_SAFETY:         return "XML_SAFETY";
  }
  return "UNKNOWN";
}

const HeuristicEntry *LookupHeuristic(int id) {
  for (size_t i = 0; i < kHeuristicRegistrySize; i++) {
    if (kHeuristicRegistry[i].id == id)
      return &kHeuristicRegistry[i];
  }
  return nullptr;
}

RegistryStats ComputeRegistryStats() {
  RegistryStats stats = {};
  stats.totalHeuristics = kTotalHeuristics;
  std::set<std::string> cves, ghsas;
  for (size_t i = 0; i < kHeuristicRegistrySize; i++) {
    stats.severity[static_cast<int>(kHeuristicRegistry[i].severity)]++;
    if (kHeuristicRegistry[i].cveRefs) {
      stats.heuristicsWithCVE++;
      std::string refs(kHeuristicRegistry[i].cveRefs);
      size_t start = 0;
      for (size_t pos = 0; pos <= refs.size(); pos++) {
        if (pos == refs.size() || refs[pos] == ',') {
          if (pos > start) {
            std::string ref = refs.substr(start, pos - start);
            if (ref.compare(0, 4, "CVE-") == 0)
              cves.insert(ref);
            else if (ref.compare(0, 5, "GHSA-") == 0)
              ghsas.insert(ref);
          }
          start = pos + 1;
        }
      }
    }
  }
  stats.uniqueCVEs = static_cast<int>(cves.size());
  stats.uniqueGHSAs = static_cast<int>(ghsas.size());
  return stats;
}
