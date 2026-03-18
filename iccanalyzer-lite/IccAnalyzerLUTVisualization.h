/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * This software and associated documentation files (the "Software") are the
 * exclusive intellectual property of David H Hoyt LLC.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "David H Hoyt LLC" must not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID H HOYT LLC "AS IS" AND ANY EXPRESSED
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL DAVID H HOYT LLC BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Contact: https://hoyt.net
 */

#ifndef ICCANALYZERLUTVISUALIZATION_H
#define ICCANALYZERLUTVISUALIZATION_H

#include "IccAnalyzerCommon.h"
#include <string>

/// Process LUT tags: generate SVG for 1D curves and TIFF for 3D CLUTs.
/// @param profilePath Path to the ICC profile
/// @param outputBase  Base path for output files (SVG/TIFF); if nullptr, derived from profilePath
/// @return 0 on success, non-zero on error
int ProcessLutVisualization(const char *profilePath, const char *outputBase);

/// Dump v5/iccMAX summary (spectral tags, MPE counts, BRDF tags).
/// Outputs to stdout. Safe to call on any profile version (no-op if < v5).
void DumpV5Summary(CIccProfile *pIcc);

/// Dump MPE element chain for a tag to stdout.
/// @param pTag     The tag to inspect
/// @param sig      The tag signature (for display)
void DumpMPEChain(CIccTag *pTag, icTagSignature sig);

/// Dump a comprehensive tag report (type, MPE chain, Describe) to stdout.
/// @param pIcc        The profile
/// @param sig         The tag signature
/// @param verbosity   Describe verbosity (1-100)
void DumpTagDetail(CIccProfile *pIcc, icTagSignature sig, int verbosity);

/// Full DumpAll analysis: header, tag table, tag details, v5 summary.
/// @param profilePath Path to the ICC profile
/// @param verbosity   Describe verbosity (1-100)
/// @return 0 on success
int DumpAllAnalysis(const char *profilePath, int verbosity);

#endif
