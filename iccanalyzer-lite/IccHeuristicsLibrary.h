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

/// H103: PCC (Profile Connection Conditions) validation
int RunHeuristic_H103_PCC(CIccProfile *pIcc);

/// H104: PRMG (Perceptual Reference Medium Gamut) evaluation
int RunHeuristic_H104_PRMG(CIccProfile *pIcc, const char *profilePath);

/// H105: Matrix-TRC validation (determinant, inversion, chromaticity)
int RunHeuristic_H105_MatrixTRC(CIccProfile *pIcc);

/// H106: Environment variable and spectral viewing condition tags
int RunHeuristic_H106_EnvVar(CIccProfile *pIcc);

#endif // _ICCHEURISTICSLIBRARY_H
