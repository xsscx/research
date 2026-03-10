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

/*
 * icc_dump_fuzzer.cpp V2 — IccDumpProfile-aligned fuzzer
 *
 * Tight alignment with iccDumpProfile.cpp: exercises ValidateIccProfile +
 * OpenIccProfile paths, CIccInfo formatting, O(N logN) tag overlap detection,
 * Describe() on all tags (with 256KB cap to prevent CWE-400 timeouts).
 *
 * V1 had: O(N²) overlap, unbounded Describe(), no tag count cap, no OOM guard.
 * V2 fixes all 4 timeout vectors while maintaining full tool API alignment.
 *
 * Scope: profile parsing + Describe/Validate only — NO Begin/Apply/CMM.
 * Complementary to icc_deep_dump_fuzzer which adds type-specific deep dives.
 *
 * V3: SafeDescribe() guards — validates tag state before Describe() to prevent
 *     crashes from partially-loaded internal state (CFL-004 alignment fix).
 */

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <new>

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagLut.h"
#include "IccUtil.h"
#include "IccIO.h"
#include "CflSafeDescribe.h"

// ─── Timeout/OOM guards ───
static constexpr size_t   kMaxProfileSize    = 4 * 1024 * 1024;   // 4 MB
static constexpr size_t   kMaxDescribeLen    = 256 * 1024;        // 256 KB per tag
static constexpr uint32_t kMaxTagCount       = 200;               // ICC profiles rarely exceed 50
static constexpr size_t   kMaxAllocPerTag    = 128 * 1024 * 1024; // 128 MB
static constexpr size_t   kMaxSingleAlloc    = 256 * 1024 * 1024; // 256 MB icRealloc cap

// ─── ASAN: return NULL on allocation failure ───
extern "C" const char *__asan_default_options() {
  return "allocator_may_return_null=1";
}

// ─── Per-allocation size cap via icRealloc override ───
void* icRealloc(void *ptr, size_t size) {
  if (size == 0) { free(ptr); return nullptr; }
  if (size > kMaxSingleAlloc) { free(ptr); return nullptr; }
  void *nptr = realloc(ptr, size);
  if (!nptr) free(ptr);
  return nptr;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 132 || size > kMaxProfileSize) return 0;

  // ── Pre-scan: reject profiles with OOM-inducing tag table ──
  {
    uint32_t claimedSize = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                           ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    if (claimedSize > 0 && claimedSize > size * 16 && claimedSize > kMaxAllocPerTag)
      return 0;

    uint32_t tagCount = ((uint32_t)data[128] << 24) | ((uint32_t)data[129] << 16) |
                        ((uint32_t)data[130] << 8) | (uint32_t)data[131];
    if (tagCount > kMaxTagCount) return 0;
    size_t tableEnd = 132 + (size_t)tagCount * 12;
    if (tableEnd > size) return 0;
    for (uint32_t t = 0; t < tagCount; t++) {
      size_t base = 132 + t * 12;
      uint32_t tSize = ((uint32_t)data[base+8] << 24) | ((uint32_t)data[base+9] << 16) |
                       ((uint32_t)data[base+10] << 8) | (uint32_t)data[base+11];
      uint32_t tOff  = ((uint32_t)data[base+4] << 24) | ((uint32_t)data[base+5] << 16) |
                       ((uint32_t)data[base+6] << 8) | (uint32_t)data[base+7];
      if (tSize > kMaxAllocPerTag || tOff > size) return 0;
    }
  }

  // Derive control from trailing bytes (preserve ICC header at offset 0)
  uint8_t verbByte = data[size - 1];
  uint8_t modeByte = (size >= 133) ? data[size - 2] : 0;
  int verboseness = (verbByte % 100) + 1;
  bool useOpenPath = (modeByte & 0x01);

  // ── Parse profile via two paths (matching tool's -v and default modes) ──
  CIccProfile *pIcc = nullptr;

  if (useOpenPath) {
    // Non-validating path: OpenIccProfile (iccDumpProfile.cpp line 218)
    CIccMemIO *pIO = new (std::nothrow) CIccMemIO();
    if (!pIO) return 0;
    if (!pIO->Attach(const_cast<uint8_t*>(data), (icUInt32Number)size)) {
      delete pIO;
      return 0;
    }
    pIcc = new (std::nothrow) CIccProfile();
    if (!pIcc->Read(pIO)) {
      delete pIcc;
      delete pIO;
      return 0;
    }
    delete pIO;
  } else {
    // Validating path: ValidateIccProfile (iccDumpProfile.cpp line 198)
    std::string report;
    icValidateStatus nStatus = icValidateOK;
    pIcc = ValidateIccProfile(data, size, report, nStatus);
  }

  if (!pIcc) return 0;

  icHeader *pHdr = &pIcc->m_Header;

  // ── Phase 1: CIccInfo header formatting (iccDumpProfile lines 244-290) ──
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

  // ── Phase 2: Tag structure analysis — O(N logN) overlap detection ──
  size_t n = pIcc->m_Tags.size();
  if (n > kMaxTagCount) { delete pIcc; return 0; }

  // Build sorted offset vector for binary search (iccDumpProfile lines 309-315)
  std::vector<icUInt32Number> sortedOffsets;
  sortedOffsets.reserve(n);
  std::unordered_map<icUInt32Number, int> dupSigMap;
  icUInt32Number smallest_offset = pHdr->size;

  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    sortedOffsets.push_back(i->TagInfo.offset);
    dupSigMap[(icUInt32Number)i->TagInfo.sig]++;
    if (i->TagInfo.offset < smallest_offset)
      smallest_offset = i->TagInfo.offset;
  }
  std::sort(sortedOffsets.begin(), sortedOffsets.end());

  // Tag overlap + padding validation using binary search (iccDumpProfile lines 337-380)
  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    icUInt32Number tag_end = i->TagInfo.offset + i->TagInfo.size;

    // OOB check
    if ((tag_end > i->TagInfo.offset) && (tag_end > pHdr->size)) {
      volatile bool non_compliant = true; (void)non_compliant;
    }

    // Find closest following offset via binary search — O(logN) not O(N)
    auto match = std::upper_bound(sortedOffsets.cbegin(), sortedOffsets.cend(),
                                  i->TagInfo.offset);
    icUInt32Number closest = (match != sortedOffsets.cend()) ? *match : pHdr->size;

    // Overlap detection
    if ((tag_end > i->TagInfo.offset) && (closest < tag_end) && (closest < pHdr->size)) {
      volatile bool overlap = true; (void)overlap;
    }

    // Padding gap check (4-byte alignment)
    icUInt32Number rndup = 4 * ((i->TagInfo.size + 3) / 4);
    icUInt32Number aligned_end = i->TagInfo.offset + rndup;
    if ((aligned_end > i->TagInfo.offset) && (closest > aligned_end)) {
      volatile bool gap = true; (void)gap;
    }
  }

  // First tag offset validation (iccDumpProfile lines 384-390)
  if (n > 0) {
    icUInt32Number expected_first = 128 + 4 + ((icUInt32Number)n * 12);
    if (smallest_offset > expected_first) {
      volatile bool firstTagGap = true; (void)firstTagGap;
    }
  }

  // File size multiple-of-4 check (iccDumpProfile lines 331-335)
  if ((pHdr->version >= icVersionNumberV4_2) && (pHdr->size % 4 != 0)) {
    volatile bool badSize = true; (void)badSize;
  }

  // ── Phase 3: Describe() all tags with validation guard (DumpTagCore, line 108) ──
  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    if (!i->pTag) continue;

    std::string desc;
    SafeDescribe(i->pTag, desc, verboseness);

    i->pTag->GetType();
    if (i->pTag->IsArrayType()) {
      volatile bool isArray = true; (void)isArray;
    }
    i->pTag->IsSupported();

    Fmt.GetTagSigName(i->TagInfo.sig);
    Fmt.GetTagTypeSigName(i->pTag->GetType());
  }

  // ── Phase 4: Profile-level methods ──
  pIcc->GetSpaceSamples();
  pIcc->AreTagsUnique();

  delete pIcc;
  return 0;
}
