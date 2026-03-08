/*
 * IccAnalyzerJson.h — JSON structured output for iccanalyzer-lite
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Provides --json mode: captures analysis output, parses [H##] markers,
 * and emits structured JSON to stdout. No heuristic function changes required.
 */

#ifndef ICC_ANALYZER_JSON_H
#define ICC_ANALYZER_JSON_H

int RunWithJsonOutput(const char *profilePath, const char *fingerprint_db);

#endif
