/*
 * Copyright (c) International Color Consortium.
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
 * 3. In the absence of prior written permission, the names "ICC" and "The
 *    International Color Consortium" must not be used to imply that the
 *    ICC organization endorses or promotes products derived from this
 *    software.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNATIONAL COLOR CONSORTIUM OR
 * ITS CONTRIBUTING MEMBERS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/** @file
    File:       icc_toxml_fuzzer.cpp
    Contains:   LibFuzzer harness for IccToXml — 1:1 tool fidelity
    Version:    V3 — File-based I/O matching upstream IccToXml.cpp

    Upstream tool: IccXML/CmdLine/IccToXml/IccToXml.cpp
    AST gates match tool lines:
      Gate 0: argc check (tool line 14) — size validation
      Gate 1: CIccFileIO srcIO.Open (tool line 28)
      Gate 2: profile.Read(&srcIO) (tool line 33)
      Gate 3: profile.ToXml(xml) (tool line 40)
*/

#include "IccProfileXml.h"
#include "IccIO.h"
#include "IccTagXmlFactory.h"
#include "IccMpeXmlFactory.h"
#include "fuzz_utils.h"
#include <stdint.h>
#include <stddef.h>
#include <cstdio>
#include <cstring>
#include <new>
#include <string>
#include <unistd.h>

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  // Match tool lines 23-24: register XML factories
  auto *tagFactory = new (std::nothrow) CIccTagXmlFactory();
  auto *mpeFactory = new (std::nothrow) CIccMpeXmlFactory();
  if (!tagFactory || !mpeFactory) { delete tagFactory; delete mpeFactory; return -1; }
  CIccTagCreator::PushFactory(tagFactory);
  CIccMpeCreator::PushFactory(mpeFactory);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Gate 0: minimum viable ICC profile (128-byte header + tag count)
  if (size < 132 || size > 5 * 1024 * 1024) return 0;

  // Gate 0b: Validate tag table — reject profiles with tag sizes or offsets
  // exceeding file size (CWE-789 amplification). Upstream CIccFileIO rejects
  // these at Read() time, but the attempted allocation can exceed RSS limits.
  {
    uint32_t tagCount = (data[128] << 24) | (data[129] << 16) | (data[130] << 8) | data[131];
    if (tagCount > 100) return 0;
    for (uint32_t i = 0; i < tagCount; i++) {
      size_t base = 132 + i * 12;
      if (base + 12 > size) return 0;
      uint32_t tOff  = (data[base+4] << 24) | (data[base+5] << 16) | (data[base+6] << 8) | data[base+7];
      uint32_t tSize = (data[base+8] << 24) | (data[base+9] << 16) | (data[base+10] << 8) | data[base+11];
      if (tOff > size || tSize > size) return 0;
      if (tOff + tSize < tOff) return 0;  // overflow
    }

    // Reject profiles where header-declared size exceeds actual file
    uint32_t hdrSize = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    if (hdrSize > size) return 0;
  }

  // Write to temp file — upstream uses CIccFileIO, NOT CIccMemIO
  char tmppath[512];
  if (!fuzz_build_path(tmppath, sizeof(tmppath), fuzz_tmpdir(), "/fuzz_toxml.icc"))
    return 0;

  FILE *fp = fopen(tmppath, "wb");
  if (!fp) return 0;
  size_t written = fwrite(data, 1, size, fp);
  fclose(fp);
  if (written != size) { unlink(tmppath); return 0; }

  // Gate 1: CIccFileIO Open — matches tool line 28
  CIccFileIO srcIO;
  if (!srcIO.Open(tmppath, "r")) {
    unlink(tmppath);
    return 0;
  }

  // Gate 2: profile.Read — matches tool line 33
  CIccProfileXml profile;
  if (!profile.Read(&srcIO)) {
    srcIO.Close();
    unlink(tmppath);
    return 0;
  }
  srcIO.Close();

  // Gate 3: profile.ToXml — matches tool line 40
  // Tool reserves 40MB for xml string (line 38)
  std::string xml;
  xml.reserve(4 * 1024 * 1024);  // 4MB cap (vs tool's 40MB)
  profile.ToXml(xml);

  unlink(tmppath);
  return 0;
}
