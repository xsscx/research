/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

#ifndef ICCANALYZERHEURISTICTYPES_H
#define ICCANALYZERHEURISTICTYPES_H

// If heuristicCount reaches this threshold, skip library-API phase
// to avoid crashes/hangs from severely malformed profiles.
static constexpr int kCriticalHeuristicThreshold = 5;

#endif // ICCANALYZERHEURISTICTYPES_H
