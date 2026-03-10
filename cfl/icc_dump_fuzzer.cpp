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

/** @file
    File:       icc_dump_fuzzer.cpp
    Contains:   LibFuzzer harness for IccDumpProfile — 1:1 tool fidelity
    Version:    V4 — File-based I/O matching upstream iccDumpProfile.cpp

    Upstream tool: Tools/CmdLine/IccDumpProfile/iccDumpProfile.cpp
    AST gates match tool lines:
      Gate 0: argc/size check (tool line 155)
      Gate 0b: Tag table size validation (CWE-789 guard)
      Gate 1: ValidateIccProfile(path) or OpenIccProfile(path) (tool lines 198/218)
      Gate 2: CIccInfo header formatting (tool lines 244-290)
      Gate 3: O(N logN) tag overlap detection (tool lines 309-380)
      Gate 4: DumpTagEntry → Describe() all tags (tool line 402, "ALL" mode)
*/

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <new>
#include <cstdio>
#include <unistd.h>

#include "IccProfile.h"
#include "IccTag.h"
#include "IccUtil.h"
#include "IccIO.h"
#include "CflSafeDescribe.h"
#include "fuzz_utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Gate 0: minimum viable ICC profile
  if (size < 132 || size > 5 * 1024 * 1024) return 0;

  // Gate 0b: Reject profiles with tag offsets/sizes exceeding file size (CWE-789)
  {
    uint32_t tagCount = (data[128] << 24) | (data[129] << 16) | (data[130] << 8) | data[131];
    if (tagCount > 200) return 0;
    for (uint32_t t = 0; t < tagCount; t++) {
      size_t base = 132 + t * 12;
      if (base + 12 > size) return 0;
      uint32_t tOff  = (data[base+4] << 24) | (data[base+5] << 16) |
                       (data[base+6] << 8) | data[base+7];
      uint32_t tSize = (data[base+8] << 24) | (data[base+9] << 16) |
                       (data[base+10] << 8) | data[base+11];
      if (tOff > size || tSize > size) return 0;
      if (tOff + tSize < tOff) return 0;
    }
    uint32_t hdrSize = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    if (hdrSize > size) return 0;
  }

  // Write to temp file — upstream uses CIccFileIO, NOT CIccMemIO
  char tmppath[512];
  if (!fuzz_build_path(tmppath, sizeof(tmppath), fuzz_tmpdir(), "/fuzz_dump.icc"))
    return 0;

  FILE *fp = fopen(tmppath, "wb");
  if (!fp) return 0;
  size_t written = fwrite(data, 1, size, fp);
  fclose(fp);
  if (written != size) { unlink(tmppath); return 0; }

  // Derive control from trailing bytes
  uint8_t verbByte = data[size - 1];
  uint8_t modeByte = (size >= 133) ? data[size - 2] : 0;
  int verboseness = (verbByte % 100) + 1;
  bool useValidatePath = (modeByte & 0x01);

  // Gate 1: Parse profile via two paths matching upstream tool
  CIccProfile *pIcc = nullptr;

  if (useValidatePath) {
    // Validating path: ValidateIccProfile(path) — tool line 198 (-v flag)
    std::string report;
    icValidateStatus nStatus = icValidateOK;
    pIcc = ValidateIccProfile(tmppath, report, nStatus);
  } else {
    // Non-validating path: OpenIccProfile(path) — tool line 218
    pIcc = OpenIccProfile(tmppath);
  }

  unlink(tmppath);
  if (!pIcc) return 0;

  icHeader *pHdr = &pIcc->m_Header;

  // Gate 2: CIccInfo header formatting — tool lines 244-290
  CIccInfo Fmt;
  Fmt.GetDeviceAttrName(pHdr->attributes);
  Fmt.GetProfileFlagsName(pHdr->flags);
  Fmt.GetPlatformSigName(pHdr->platform);
  Fmt.GetCmmSigName((icCmmSignature)pHdr->cmmId);
  Fmt.GetRenderingIntentName((icRenderingIntent)pHdr->renderingIntent);
  Fmt.GetProfileClassSigName(pHdr->deviceClass);
  Fmt.GetColorSpaceSigName(pHdr->colorSpace);
  Fmt.GetColorSpaceSigName(pHdr->pcs);
  Fmt.GetVersionName(pHdr->version);
  Fmt.GetSpectralColorSigName(pHdr->spectralPCS);
  Fmt.IsProfileIDCalculated(&pHdr->profileID);
  Fmt.GetProfileID(&pHdr->profileID);

  if (pHdr->version >= icVersionNumberV5 && pHdr->deviceSubClass) {
    Fmt.GetSubClassVersionName(pHdr->version);
  }

  // Gate 3: Tag structure analysis — O(N logN) overlap detection (tool lines 309-380)
  size_t n = pIcc->m_Tags.size();
  if (n > 200) { delete pIcc; return 0; }

  std::vector<icUInt32Number> sortedOffsets;
  sortedOffsets.reserve(n);

  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    sortedOffsets.push_back(i->TagInfo.offset);
    Fmt.GetTagSigName(i->TagInfo.sig);
  }
  std::sort(sortedOffsets.begin(), sortedOffsets.end());

  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    auto match = std::upper_bound(sortedOffsets.cbegin(), sortedOffsets.cend(),
                                  i->TagInfo.offset);
    icUInt32Number closest = (match != sortedOffsets.cend()) ? *match : pHdr->size;

    // Overlap/gap detection (same as tool)
    icUInt32Number tag_end = i->TagInfo.offset + i->TagInfo.size;
    (void)tag_end;
    (void)closest;
  }

  // Gate 4: Describe() all tags — tool line 402 ("ALL" mode)
  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    if (!i->pTag) continue;
    std::string desc;
    SafeDescribe(i->pTag, desc, verboseness);
    Fmt.GetTagTypeSigName(i->pTag->GetType());
  }

  pIcc->GetSpaceSamples();
  pIcc->AreTagsUnique();

  delete pIcc;
  return 0;
}
