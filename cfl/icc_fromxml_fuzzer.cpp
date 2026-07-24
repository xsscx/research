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
#include "IccXmlConfig.h"
#include <climits>
#include <string>
#include "fuzz_utils.h"

// Suppress libxml2 errors during fuzzing
static void suppressXmlErrors(void *ctx, const char *msg, ...) {
  // Silent
}

static xmlParserInputPtr blockExternalEntity(const char *URL,
                                             const char *ID,
                                             xmlParserCtxtPtr ctxt) {
  (void)URL;
  (void)ID;
  (void)ctxt;
  return nullptr;
}

// Initialize factories once
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  auto *tagFactory = new (std::nothrow) CIccTagXmlFactory();
  auto *mpeFactory = new (std::nothrow) CIccMpeXmlFactory();
  if (!tagFactory || !mpeFactory) { delete tagFactory; delete mpeFactory; return -1; }
  CIccTagCreator::PushFactory(tagFactory);
  CIccMpeCreator::PushFactory(mpeFactory);
  IccXmlSetAllowFileIncludes(true);
  xmlSetGenericErrorFunc(nullptr, suppressXmlErrors);
  xmlSetExternalEntityLoader(blockExternalEntity);

  return 0;
}

static icProfileIDSaveMethod ProfileIdSaveMethod(const CIccProfileXml &profile, bool bNoId) {
  if (bNoId)
    return icNeverWriteID;

  for (int i = 0; i < 16; i++) {
    if (profile.m_Header.profileID.ID8[i])
      return icAlwaysWriteID;
  }
  return icVersionBasedID;
}

static void ExerciseFromXmlToolPath(const char *inputPath,
                                    const char *outputPath,
                                    const char *relaxNgPath,
                                    bool bNoId) {
  // ===================================================================
  // TOOL CODE STARTS HERE - mirrors IccFromXml.cpp parse/validate/save
  // ===================================================================

  CIccProfileXml profile;
  std::string reason;
  std::string szRelaxNGDir = relaxNgPath ? relaxNgPath : "";

  if (!profile.LoadXml(inputPath, szRelaxNGDir.c_str(), &reason))
    return;

  std::string valid_report;
  if (profile.Validate(valid_report) <= icValidateWarning) {
    SaveIccProfile(outputPath, &profile, ProfileIdSaveMethod(profile, bNoId));
  }
  else {
    SaveIccProfile(outputPath, &profile, ProfileIdSaveMethod(profile, bNoId));
    std::string discard;
    profile.Validate(discard);
  }

  // ===================================================================
  // TOOL CODE ENDS HERE
  // ===================================================================
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

  char temp_output[PATH_MAX];
  if (!fuzz_build_path(temp_output, sizeof(temp_output), tmpdir, "/fuzz_fromxml_tool_out_XXXXXX")) {
    unlink(temp_input);
    return 0;
  }
  int out_fd = mkstemp(temp_output);
  if (out_fd == -1) {
    unlink(temp_input);
    return 0;
  }
  close(out_fd);

  char temp_rng[PATH_MAX];
  temp_rng[0] = '\0';
  bool have_rng = false;
  if (fuzz_build_path(temp_rng, sizeof(temp_rng), tmpdir, "/fuzz_fromxml_relax_XXXXXX")) {
    int rng_fd = mkstemp(temp_rng);
    if (rng_fd != -1) {
      static const char kRelaxNgSeed[] =
        "<grammar xmlns=\"http://relaxng.org/ns/structure/1.0\">"
        "<start><ref name=\"any\"/></start>"
        "<define name=\"any\"><element><anyName/><zeroOrMore><choice>"
        "<attribute><anyName/><text/></attribute><text/><ref name=\"any\"/>"
        "</choice></zeroOrMore></element></define></grammar>";
      ssize_t rng_written = write(rng_fd, kRelaxNgSeed, sizeof(kRelaxNgSeed) - 1);
      close(rng_fd);
      have_rng = rng_written == static_cast<ssize_t>(sizeof(kRelaxNgSeed) - 1);
    }
  }

  // argv shape coverage:
  //   iccFromXml input.xml output.icc
  //   iccFromXml input.xml output.icc -noid
  //   iccFromXml input.xml output.icc -v=<schema>
  ExerciseFromXmlToolPath(temp_input, temp_output, nullptr, false);
  ExerciseFromXmlToolPath(temp_input, temp_output, nullptr, true);
  if (have_rng)
    ExerciseFromXmlToolPath(temp_input, temp_output, temp_rng, false);

  if (temp_rng[0])
    unlink(temp_rng);
  unlink(temp_output);
  unlink(temp_input);
  return 0;
}
