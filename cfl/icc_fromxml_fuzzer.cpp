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
#include <new>
#include <unistd.h>
#include <fcntl.h>
#include <libxml/parser.h>
#include "IccTagXmlFactory.h"
#include "IccMpeXmlFactory.h"
#include "IccProfileXml.h"
#include "IccIO.h"
#include "IccUtil.h"
#include <climits>
#include "fuzz_utils.h"

// Suppress libxml2 errors during fuzzing
static void suppressXmlErrors(void *ctx, const char *msg, ...) {
  // Silent
}

// Initialize factories once
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  auto *tagFactory = new (std::nothrow) CIccTagXmlFactory();
  auto *mpeFactory = new (std::nothrow) CIccMpeXmlFactory();
  if (!tagFactory || !mpeFactory) { delete tagFactory; delete mpeFactory; return -1; }
  CIccTagCreator::PushFactory(tagFactory);
  CIccMpeCreator::PushFactory(mpeFactory);
  xmlSetGenericErrorFunc(nullptr, suppressXmlErrors);

  // XXE protection: disable external entity loading and substitution
  xmlSubstituteEntitiesDefault(0);
  xmlLoadExtDtdDefaultValue = 0;

  return 0;
}

// FUZZER HARNESS - Minimal wrapper around tool code
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10 || size > 10 * 1024 * 1024) return 0;

  // Write fuzzer data to temp file (replaces argv[1])
  const char *tmpdir = fuzz_tmpdir();
  char temp_input[PATH_MAX];
  if (!fuzz_build_path(temp_input, sizeof(temp_input), tmpdir, "/fuzz_fromxml_tool_XXXXXX")) return 0;
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

  // Disable XXE: prevent external entity loading in untrusted XML
  xmlSubstituteEntitiesDefault(0);
  xmlLoadExtDtdDefaultValue = 0;

  if (!profile.LoadXml(temp_input, szRelaxNGDir.c_str(), &reason)) {
    unlink(temp_input);
    return 0;
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
    if (!fuzz_build_path(temp_output, sizeof(temp_output), tmpdir, "/fuzz_fromxml_tool_out_XXXXXX")) {
      unlink(temp_input);
      return 0;
    }
    int out_fd = mkstemp(temp_output);
    if (out_fd != -1) {
      close(out_fd);
      
      SaveIccProfile(temp_output, &profile, bNoId ? icNeverWriteID : (i<16 ? icAlwaysWriteID : icVersionBasedID));
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
    if (!fuzz_build_path(temp_output, sizeof(temp_output), tmpdir, "/fuzz_fromxml_tool_out_XXXXXX")) {
      unlink(temp_input);
      return 0;
    }
    int out_fd = mkstemp(temp_output);
    if (out_fd != -1) {
      close(out_fd);
      SaveIccProfile(temp_output, &profile, bNoId ? icNeverWriteID : (i<16 ? icAlwaysWriteID : icVersionBasedID));
      std::string discard;
      profile.Validate(discard);
      unlink(temp_output);
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // TOOL CODE ENDS HERE
  // ═══════════════════════════════════════════════════════════════════

  unlink(temp_input);
  return 0;
}
