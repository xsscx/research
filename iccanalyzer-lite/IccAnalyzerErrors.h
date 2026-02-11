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

#ifndef _ICCANALYZERERRORS_H
#define _ICCANALYZERERRORS_H

// Deterministic exit codes for workflow logic.
// Signals (SIGILL=132, SIGABRT=134, SIGSEGV=139) are never returned by
// the analyzer itself — their presence always indicates a real crash.
enum IccExitCode {
  ICC_EXIT_CLEAN   = 0,  // Profile analyzed, no issues detected
  ICC_EXIT_FINDING = 1,  // Findings detected (heuristic warnings, validation failures)
  ICC_EXIT_ERROR   = 2,  // I/O error (file not found, profile read failure)
  ICC_EXIT_USAGE   = 3,  // Usage error (bad arguments, unknown option)
};

extern bool g_verbose_errors;

void ErrorOutputDirRequired();
void ErrorInvalidFormat(const char *format);
void ErrorFileNotFound(const char *path);
void ErrorPatternNoMatch(const char *pattern);
void ErrorWatchDirNotFound(const char *path);
void ErrorIccProfileInvalid(const char *path, const char *reason);
void ErrorPermissionDenied(const char *path);
void ErrorDatabaseNotFound(const char *path);
void ErrorDatabaseCorrupted(const char *path);

#endif
