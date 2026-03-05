/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

#ifndef _ICCHEURISTICSRAWPOST_H
#define _ICCHEURISTICSRAWPOST_H

/// Run raw-file post-library heuristics (H33-H55, H57, H59, H68-H69).
/// Each heuristic opens its own FILE* and is safe on all inputs.
/// @param filename Path to the ICC profile to analyze
/// @return Number of heuristic warnings detected
int RunRawPostLibraryHeuristics(const char *filename);

/// Run raw-file fallback heuristics (H10, H13, H25, H28, H32) when
/// the library failed to load the profile.
/// @param filename Path to the ICC profile to analyze
/// @param libraryAnalyzed true if CIccProfile loaded successfully
/// @return Number of heuristic warnings detected
int RunRawFallbackHeuristics(const char *filename, bool libraryAnalyzed);

#endif // _ICCHEURISTICSRAWPOST_H
