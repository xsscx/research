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

#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <libxml/parser.h>
#include "IccTagXmlFactory.h"
#include "IccMpeXmlFactory.h"
#include "IccProfileXml.h"
#include "IccIO.h"
#include "IccUtil.h"
#include <climits>

// Suppress libxml2 errors during fuzzing
static void suppressXmlErrors(void *ctx, const char *msg, ...) {
  // Silent
}

// Initialize factories once
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  CIccTagCreator::PushFactory(new CIccTagXmlFactory());
  CIccMpeCreator::PushFactory(new CIccMpeXmlFactory());
  xmlSetGenericErrorFunc(nullptr, suppressXmlErrors);
  return 0;
}

// FUZZER HARNESS - Minimal wrapper around tool code
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10 || size > 10 * 1024 * 1024) return 0;

  // Write fuzzer data to temp file (replaces argv[1])
  const char *tmpdir = getenv("FUZZ_TMPDIR");
  if (!tmpdir) tmpdir = "/tmp";
  char temp_input[PATH_MAX];
  snprintf(temp_input, sizeof(temp_input), "%s/fuzz_fromxml_tool_XXXXXX", tmpdir);
  int fd = mkstemp(temp_input);
  if (fd == -1) return 0;
  
  ssize_t written = write(fd, data, size);
  close(fd);
  
  if (written != static_cast<ssize_t>(size)) {
    unlink(temp_input);
    return 0;
  }

  // ═══════════════════════════════════════════════════════════════════
  // TOOL CODE STARTS HERE - EXACT COPY FROM IccFromXml.cpp lines 24-109
  // ═══════════════════════════════════════════════════════════════════

  CIccProfileXml profile;
  std::string reason;  

  std::string szRelaxNGDir;
  bool bNoId = false;

  // NOTE: Schema validation and -noid flag skipped (fuzzer doesn't use args)
  // This matches tool behavior when called without optional flags

  if (!profile.LoadXml(temp_input, szRelaxNGDir.c_str(), &reason)) {
    // Tool: printf("%s", reason.c_str());
    // Tool: printf("Unable to Parse '%s'\n", argv[1]);
    unlink(temp_input);
    return 0;  // Tool: return -1
  }

  std::string valid_report;

  if (profile.Validate(valid_report)<=icValidateWarning) {
    int i;

    for (i=0; i<16; i++) {
      if (profile.m_Header.profileID.ID8[i])
        break;
    }
    
    // Write to temp output file (replaces argv[2])
    char temp_output[PATH_MAX];
    snprintf(temp_output, sizeof(temp_output), "%s/fuzz_fromxml_tool_out_XXXXXX", tmpdir);
    int out_fd = mkstemp(temp_output);
    if (out_fd != -1) {
      close(out_fd);
      
      if (SaveIccProfile(temp_output, &profile, bNoId ? icNeverWriteID : (i<16 ? icAlwaysWriteID : icVersionBasedID))) {
        // Tool: printf("Profile parsed and saved correctly\n");
      }
      else {
        // Tool: printf("Unable to save profile as '%s'\n", argv[2]);
        // Tool: return -1;
      }
      
      unlink(temp_output);
    }
  }
  else {
    int i;

    for (i=0; i<16; i++) {
      if (profile.m_Header.profileID.ID8[i])
        break;
    }
    
    char temp_output[PATH_MAX];
    snprintf(temp_output, sizeof(temp_output), "%s/fuzz_fromxml_tool_out_XXXXXX", tmpdir);
    int out_fd = mkstemp(temp_output);
    if (out_fd != -1) {
      close(out_fd);
      
      if (SaveIccProfile(temp_output, &profile, bNoId ? icNeverWriteID : (i<16 ? icAlwaysWriteID : icVersionBasedID))) {
        // Tool: printf("Profile parsed.  Profile is invalid, but saved correctly\n");
      }
      else {
        // Tool: printf("Unable to save profile - profile is invalid!\n");
        // Tool: return -1;
      }
      // Tool: printf("%s", valid_report.c_str());
      
      unlink(temp_output);
    }
  }

  // Tool: printf("\n");
  // Tool: return 0;

  // ═══════════════════════════════════════════════════════════════════
  // TOOL CODE ENDS HERE
  // ═══════════════════════════════════════════════════════════════════

  unlink(temp_input);
  return 0;
}
