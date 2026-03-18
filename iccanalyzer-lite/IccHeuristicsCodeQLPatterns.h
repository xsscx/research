/*
 * IccHeuristicsCodeQLPatterns.h — CodeQL-driven heuristics (H154-H161)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Derived from CodeQL analysis of iccDEV IccProfLib+IccXML (1,114 findings).
 * Each targets a CWE category with multiple library sites not covered by H1-H153.
 * Extracted from IccHeuristicsRawPost.cpp for maintainability.
 */

#ifndef ICC_HEURISTICS_CODEQL_PATTERNS_H
#define ICC_HEURISTICS_CODEQL_PATTERNS_H

struct RawProfileContext;  // Forward declaration

/// Run all CodeQL-driven heuristics (H154-H161).
/// @param ctx Pre-parsed raw profile context
/// @return Number of heuristic warnings detected
int RunCodeQLPatternHeuristics(RawProfileContext &ctx);

// Individual CodeQL-driven heuristic functions.
int RunHeuristic_H154_UncontrolledTagAllocationSize(RawProfileContext &ctx);
int RunHeuristic_H155_IntegerOverflowTagDimensions(RawProfileContext &ctx);
int RunHeuristic_H156_AllocationFailurePathProfiles(RawProfileContext &ctx);
int RunHeuristic_H157_AllocDeallocMismatchTagPatterns(RawProfileContext &ctx);
int RunHeuristic_H158_EnumRangeValidationExtended(RawProfileContext &ctx);
int RunHeuristic_H159_UAFTagOwnershipChains(RawProfileContext &ctx);
int RunHeuristic_H160_FormatStringInjectionTextTags(RawProfileContext &ctx);
int RunHeuristic_H161_StackAddressEscapeDeepApply(RawProfileContext &ctx);

#endif // ICC_HEURISTICS_CODEQL_PATTERNS_H
