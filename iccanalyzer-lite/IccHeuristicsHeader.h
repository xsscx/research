/*
 * IccHeuristicsHeader.h — Header validation heuristic declarations (H1-H8, H15-H17)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

#ifndef _ICCHEURISTICSHEADER_H
#define _ICCHEURISTICSHEADER_H

#include "IccDefs.h"
#include <cstddef>

int RunHeuristic_H1_ProfileSize(const icHeader &header, size_t actualFileSize);
int RunHeuristic_H2_MagicBytes(const icHeader &header);
int RunHeuristic_H3_ColorSpaceSignature(const icHeader &header);
int RunHeuristic_H4_PCSColorSpace(const icHeader &header);
int RunHeuristic_H5_PlatformSignature(const icHeader &header);
int RunHeuristic_H6_RenderingIntent(const icHeader &header);
int RunHeuristic_H7_ProfileClass(const icHeader &header);
int RunHeuristic_H8_IlluminantXYZ(const icHeader &header);
int RunHeuristic_H15_DateValidation(const icHeader &header);
int RunHeuristic_H16_SignaturePatterns(const icHeader &header);
int RunHeuristic_H17_SpectralRange(const icHeader &header);

/// Run all header heuristics (H1-H8, H15-H17) on a parsed header.
int RunHeaderHeuristics(const icHeader &header, size_t actualFileSize);

#endif // _ICCHEURISTICSHEADER_H
