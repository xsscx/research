/*
 * IccHeuristicsLibrary.h — Collector header for library API heuristics (H9-H138)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Includes all 4 heuristic category headers and declares the dispatcher.
 */

#ifndef ICC_HEURISTICS_LIBRARY_H
#define ICC_HEURISTICS_LIBRARY_H

#include "IccHeuristicsTagValidation.h"
#include "IccHeuristicsDataValidation.h"
#include "IccHeuristicsProfileCompliance.h"
#include "IccHeuristicsIntegrity.h"
#include "IccHeuristicsXmlSafety.h"
#include "IccProfile.h"

int RunLibraryAPIHeuristics(CIccProfile *pIcc, const char *filename);

#endif
