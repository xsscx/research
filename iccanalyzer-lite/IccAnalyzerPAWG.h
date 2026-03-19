/*
 * IccAnalyzerPAWG.h — ICC Profile Assessment Working Group report output
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Generates a structured report organized per the ICC PAWG checklist:
 *   Security (13 items) -> Conformance (14 items) -> Quality (4 items)
 *
 * Reference: ICC Profile Assessment Working Group — Goals for profile assessment
 */

#ifndef ICC_ANALYZER_PAWG_H
#define ICC_ANALYZER_PAWG_H

int RunWithPAWGOutput(const char *profilePath, const char *fingerprint_db);

#endif
