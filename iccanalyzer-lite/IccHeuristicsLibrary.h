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

/// H107: LUT channel count vs colorspace cross-check (CWE-121/CWE-131)
int RunHeuristic_H107_ChannelCrossCheck(CIccProfile *pIcc);

/// H108: Private/unregistered tag identification (CWE-829)
int RunHeuristic_H108_PrivateTags(CIccProfile *pIcc);

/// H109: NOP sled / shellcode pattern scan (CWE-506)
int RunHeuristic_H109_ShellcodePatterns(const char *filename);

/// H110: Profile-class required tag validation (CWE-20)
int RunHeuristic_H110_ClassTagValidation(CIccProfile *pIcc);

/// H111: Reserved byte validation (CWE-20)
int RunHeuristic_H111_ReservedBytes(const char *filename);

/// H112: Wtpt profile-class validation (CWE-20)
int RunHeuristic_H112_WtptValidation(CIccProfile *pIcc);

/// H113: Round-trip fidelity assessment (CWE-682)
int RunHeuristic_H113_RoundTripFidelity(CIccProfile *pIcc);

/// H114: TRC curve smoothness and monotonicity (CWE-682)
int RunHeuristic_H114_CurveSmoothness(CIccProfile *pIcc);

/// H115: Characterization data presence (CWE-20)
int RunHeuristic_H115_CharacterizationData(CIccProfile *pIcc);

#endif // _ICCHEURISTICSLIBRARY_H
