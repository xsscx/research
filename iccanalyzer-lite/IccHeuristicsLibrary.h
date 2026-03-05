/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

#ifndef _ICCHEURISTICSLIBRARY_H
#define _ICCHEURISTICSLIBRARY_H

class CIccProfile;

/// Run library-API heuristics (H9-H32, H56-H86) using iccDEV profile API.
/// @param pIcc Loaded ICC profile (must not be null)
/// @param filename Path to the ICC profile (for raw-file fallback reads)
/// @return Number of heuristic warnings detected
int RunLibraryAPIHeuristics(CIccProfile *pIcc, const char *filename);

#endif // _ICCHEURISTICSLIBRARY_H
