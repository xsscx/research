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
 * icc_deep_dump_fuzzer.cpp — Enhanced ICC profile fuzzer
 *
 * Aligned with iccDumpProfile.cpp tool scope: exercises the same API
 * surface (Describe, Validate, FindTag, GetType, IsArrayType) without
 * entering tag execution paths (Begin/Apply) or CMM transforms.
 *
 * Targets:
 *  - TagArrayType (tary) heap-use-after-free in CIccTagArray::Cleanup()
 *  - CLUT size overflow in multi-dimensional LUT tags
 *  - MPE chain depth exhaustion via nested MultiProcessElements
 *  - Integer overflow in tag offset/size arithmetic
 *  - Named color lookup with adversarial inputs
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <cmath>
#include <map>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagLut.h"
#include "IccTagMPE.h"
#include "IccTagComposite.h"
#include "IccTagDict.h"
#include "IccMpeCalc.h"
#include "IccUtil.h"
#include "IccIO.h"
#include "IccSignatureUtils.h"

// Limits to prevent OOM in fuzzer (mirrors iccanalyzer-lite constants)
static constexpr size_t kMaxProfileSize = 4 * 1024 * 1024;  // 4 MB
static constexpr size_t kMaxDescribeLen = 256 * 1024;        // 256 KB
static constexpr uint32_t kMaxTagCount  = 200;
static constexpr uint64_t kMaxCLUT      = 16 * 1024 * 1024;  // 16M entries
static constexpr uint64_t kMaxTagSize   = 64 * 1024 * 1024;  // 64 MB (iccanalyzer-lite H13)
static constexpr uint32_t kMaxMPEDepth  = 1024;              // iccanalyzer-lite H12

// ─── Sanitizer integration ───
// Use __sanitizer_print_stack_trace when available (ASAN/UBSAN builds)
// to emit stack context just before exercising crash-prone paths.
#if defined(__has_feature)
  #if __has_feature(address_sanitizer) || __has_feature(undefined_behavior_sanitizer)
    extern "C" void __sanitizer_print_stack_trace(void);
    #define HAS_SANITIZER_STACK 1
  #endif
#endif
#ifndef HAS_SANITIZER_STACK
  #define HAS_SANITIZER_STACK 0
  __attribute__((unused))
  static inline void __sanitizer_print_stack_trace(void) {}
#endif

// ─── Diagnostic flag (forward decl for icRealloc) ───
static bool g_diagEnabled = false;

// ─── ASAN options: return NULL on allocation failure ───
// Library bugs call icRealloc/calloc with user-controlled sizes up to 4GB.
// With allocator_may_return_null=1, ASAN returns NULL and the library's
// own error handling kicks in (icRealloc frees old ptr and returns NULL).
extern "C" const char *__asan_default_options() {
  return "allocator_may_return_null=1";
}

// ─── Per-allocation size cap via icRealloc override ───
// The iccDEV library routes ALL tag data allocations through icRealloc()
// (IccUtil.cpp:112). By providing our own definition, the linker picks
// this over the static library's version, capping single allocations.
// This catches OOM from CIccTagXYZ::SetSize, CIccTagData::SetSize,
// CIccTagFloatNum::SetSize, CIccMpeTintArray::Read, etc.
static constexpr size_t kMaxSingleAlloc = 256 * 1024 * 1024; // 256 MB

void* icRealloc(void *ptr, size_t size) {
  if (size == 0) {
    free(ptr);
    return nullptr;
  }
  if (size > kMaxSingleAlloc) {
    if (g_diagEnabled)
      fprintf(stderr, "[DIAG] OOM-guard: icRealloc(%p, %zu) rejected (%.1fMB > %zuMB limit)\n",
              ptr, size, (double)size / (1024.0*1024.0),
              kMaxSingleAlloc / (1024*1024));
    free(ptr);  // free(NULL) is safe per C standard
    return nullptr;
  }
  void *nptr = realloc(ptr, size);
  // realloc guarantees: on failure, original ptr is NOT freed (C11 §7.22.3.5)
  if (!nptr) free(ptr);
  return nptr;
}

// ─── Diagnostic logging framework ───
// Controlled by DEEP_DUMP_DIAG=1 env var. When enabled, logs pre-crash
// state to stderr so ASAN/UBSAN reports include root-cause context.
// In production fuzzing, leave disabled for speed.
// (g_diagEnabled declared above icRealloc for forward reference)

__attribute__((constructor))
static void InitDiag() {
  const char *env = getenv("DEEP_DUMP_DIAG");
  g_diagEnabled = env && env[0] == '1';
}

// Log diagnostic only when enabled — zero overhead when off
#define DIAG(fmt, ...) do { \
  if (__builtin_expect(g_diagEnabled, 0)) \
    fprintf(stderr, "[DIAG] " fmt "\n", ##__VA_ARGS__); \
} while(0)

// Log tag context before exercising — aids crash-to-root-cause mapping
static void DiagTagContext(const char *phase, icTagSignature sig,
                           icTagTypeSignature type, uint32_t offset,
                           uint32_t size, uint32_t fileSize) {
  if (!g_diagEnabled) return;
  const size_t bs = 16;
  char sBuf[bs], tBuf[bs];
  fprintf(stderr, "[DIAG] %s: tag=%s type=%s offset=%u size=%u fileSize=%u",
          phase,
          icGetSig(sBuf, bs, sig),
          icGetSig(tBuf, bs, type),
          offset, size, fileSize);
  // Flag high-risk conditions (mirrors iccanalyzer-lite H13)
  if ((uint64_t)offset + size > fileSize)
    fprintf(stderr, " [OOB: offset+size=%llu > fileSize]",
            (unsigned long long)offset + size);
  if (size > kMaxTagSize)
    fprintf(stderr, " [EXCESSIVE: >64MB]");
  else if (size > 1024 * 1024)
    fprintf(stderr, " [LARGE: %uMB]", size / (1024*1024));
  fprintf(stderr, "\n");
}

// Log allocation-relevant values before library calls that calloc/malloc
// Mirrors iccanalyzer-lite SafeMul64/SafeAdd64 overflow detection
static void DiagAlloc(const char *context, uint64_t count, uint64_t elemSize) {
  if (!g_diagEnabled) return;
  uint64_t total = count * elemSize;
  fprintf(stderr, "[DIAG] alloc-risk %s: count=%llu elemSize=%llu total=%llu",
          context,
          (unsigned long long)count,
          (unsigned long long)elemSize,
          (unsigned long long)total);
  if (total > 256 * 1024 * 1024ULL)
    fprintf(stderr, " [EXCESSIVE: >256MB]");
  if (count > 0 && total / count != elemSize)
    fprintf(stderr, " [INTEGER OVERFLOW]");
  fprintf(stderr, "\n");
}

// Log enum load from user input — root cause for UBSAN invalid-enum-load
static void DiagEnumLoad(const char *enumName, uint32_t rawValue,
                         uint32_t expectedValue, const char *location) {
  if (!g_diagEnabled) return;
  fprintf(stderr, "[DIAG] enum-load %s: raw=0x%08x (%u) expected=0x%08x at %s",
          enumName, rawValue, rawValue, expectedValue, location);
  if (rawValue != expectedValue)
    fprintf(stderr, " [UBSAN: invalid enum value]");
  fprintf(stderr, "\n");
}

// Log dynamic_cast result — tracks type confusion and null deref risk
// Mirrors iccanalyzer-lite VulnMetadata pattern for variable tracking
static void DiagCast(const char *targetType, const void *result,
                     icTagSignature sig, icTagTypeSignature type) {
  if (!g_diagEnabled) return;
  const size_t bs = 16;
  char sBuf[bs], tBuf[bs];
  if (!result) {
    fprintf(stderr, "[DIAG] cast-fail: %s=nullptr tag=%s type=%s\n",
            targetType,
            icGetSig(sBuf, bs, sig),
            icGetSig(tBuf, bs, type));
  } else {
    fprintf(stderr, "[DIAG] cast-ok: %s=%p tag=%s type=%s\n",
            targetType, result,
            icGetSig(sBuf, bs, sig),
            icGetSig(tBuf, bs, type));
  }
}

// Log pre-crash state snapshot — frame-like context for ASAN correlation
// Mirrors iccanalyzer-lite ASANFrame struct (function, file, line, crash)
static void DiagPreCrashState(const char *function, const char *context,
                              const void *ptr, size_t size) {
  if (!g_diagEnabled) return;
  fprintf(stderr, "[DIAG] pre-crash: func=%s ctx=%s ptr=%p size=%zu\n",
          function, context, ptr, size);
  if (HAS_SANITIZER_STACK) {
    fprintf(stderr, "[DIAG] --- stack trace ---\n");
    __sanitizer_print_stack_trace();
  }
}

// ── Phase 1: Header heuristic analysis (H1–H8 from iccanalyzer-lite) ──
static void AnalyzeHeader(CIccProfile *pIcc) {
  icHeader *hdr = &pIcc->m_Header;
  const size_t bufSize = 64;
  char buf[bufSize];

  // H1: Size sanity (iccanalyzer-lite H1)
  volatile bool sizeZero = (hdr->size == 0);
  volatile bool sizeHuge = (hdr->size > (1ULL << 30));
  DIAG("H1: profileSize=%u zero=%d huge=%d", hdr->size, (int)sizeZero, (int)sizeHuge);
  (void)sizeZero; (void)sizeHuge;

  // H2: Magic bytes check (iccanalyzer-lite H2)
  volatile bool badMagic = (hdr->magic != icMagicNumber);
  DIAG("H2: magic=0x%08x expected=0x%08x valid=%d",
       hdr->magic, icMagicNumber, !badMagic);
  (void)badMagic;

  // H3: ColorSpace signature validation via IccSignatureUtils
  CIccInfo fmt;
  const char *csName = fmt.GetColorSpaceSigName(hdr->colorSpace);
  const char *pcsName = fmt.GetColorSpaceSigName(hdr->pcs);
  (void)csName; (void)pcsName;

  // DescribeColorSpaceSignature provides raw byte decomposition for crash mapping
  IccColorSpaceDescription csDesc = DescribeColorSpaceSignature((icUInt32Number)hdr->colorSpace);
  IccColorSpaceDescription pcsDesc = DescribeColorSpaceSignature((icUInt32Number)hdr->pcs);

  bool csValid = csDesc.isKnown;
  bool pcsValid = pcsDesc.isKnown;
  DIAG("H3: colorSpace=0x%08x(%s) valid=%d bytes='%s'  pcs=0x%08x(%s) valid=%d bytes='%s'",
       (uint32_t)hdr->colorSpace, csDesc.name, csValid, csDesc.bytes,
       (uint32_t)hdr->pcs, pcsDesc.name, pcsValid, pcsDesc.bytes);

  // Spectral PCS check via IccSignatureUtils
  bool isSpectral = IsSpaceSpectralPCS(hdr->pcs);
  DIAG("H3: pcs isSpectralPCS=%d", isSpectral);

  // H5: Platform signature
  fmt.GetPlatformSigName(hdr->platform);

  // Validate critical header signatures — return early on corrupt/fuzzed values
  // (ICC_SANITY_CHECK_SIGNATURE asserts on bad data, which kills the fuzzer)
  {
    icUInt32Number sigs[] = {
      (icUInt32Number)hdr->colorSpace, (icUInt32Number)hdr->pcs,
      (icUInt32Number)hdr->platform, (icUInt32Number)hdr->deviceClass
    };
    for (auto s : sigs) {
      if (s == 0) return;  // null signature
      uint8_t b0 = (s >> 24) & 0xFF;
      if (b0 == ((s >> 16) & 0xFF) && b0 == ((s >> 8) & 0xFF) && b0 == (s & 0xFF))
        return;  // repeat-byte pattern (e.g. 0x8e8e8e8e)
    }
  }

  // Rendering intent name (tool line 255) + enum bounds diagnostic
  fmt.GetRenderingIntentName((icRenderingIntent)(hdr->renderingIntent));
  DiagEnumLoad("renderingIntent", (uint32_t)hdr->renderingIntent, 3,
               "Header (valid: 0=Perceptual, 1=Relative, 2=Saturation, 3=Absolute)");

  // H6: Rendering intent bounds
  volatile bool intentOOB = ((uint32_t)hdr->renderingIntent > 3);
  (void)intentOOB;

  // H7: Profile class + signature sanity check
  fmt.GetProfileClassSigName(hdr->deviceClass);
  DiagEnumLoad("deviceClass", (uint32_t)hdr->deviceClass,
               0x6D6E7472, "Header (expected: mntr/scnr/prtr/link/spac/abst/nmcl)");

  // H8: Illuminant XYZ sanity with NaN detection
  icFloatNumber illumX = icFtoD(hdr->illuminant.X);
  icFloatNumber illumY = icFtoD(hdr->illuminant.Y);
  icFloatNumber illumZ = icFtoD(hdr->illuminant.Z);
  volatile bool illumNeg = (illumX < 0.0 || illumY < 0.0 || illumZ < 0.0);
  volatile bool illumHuge = (illumX > 5.0 || illumY > 5.0 || illumZ > 5.0);
  volatile bool illumNaN = (std::isnan(illumX) || std::isnan(illumY) || std::isnan(illumZ));
  (void)illumNeg; (void)illumHuge; (void)illumNaN;
  DIAG("H8: illuminant X=%.6f Y=%.6f Z=%.6f neg=%d huge=%d nan=%d",
       (double)illumX, (double)illumY, (double)illumZ,
       (int)illumNeg, (int)illumHuge, (int)illumNaN);

  // Version-specific checks
  fmt.GetVersionName(hdr->version);
  if (hdr->version >= icVersionNumberV5 && hdr->deviceSubClass) {
    fmt.GetSubClassVersionName(hdr->version);
  }
  fmt.GetSpectralColorSigName(hdr->spectralPCS);
  fmt.IsProfileIDCalculated(&hdr->profileID);
  fmt.GetProfileID(&hdr->profileID);
  fmt.GetDeviceAttrName(hdr->attributes);
  fmt.GetProfileFlagsName(hdr->flags);
  fmt.GetCmmSigName((icCmmSignature)hdr->cmmId);

  // icGetSig for creator and manufacturer (tool lines 249-250)
  icGetSig(buf, bufSize, hdr->creator);
  icGetSig(buf, bufSize, hdr->manufacturer);

  // Date fields (tool lines 246-248) with range sanity
  volatile int month = hdr->date.month;
  volatile int day = hdr->date.day;
  volatile int year = hdr->date.year;
  volatile int hours = hdr->date.hours;
  volatile int minutes = hdr->date.minutes;
  volatile int seconds = hdr->date.seconds;
  bool dateValid = (month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
                    hours <= 23 && minutes <= 59 && seconds <= 59);
  DIAG("Date: year=%u month=%u day=%u hours=%u minutes=%u seconds=%u valid=%d",
       (unsigned)year, (unsigned)month, (unsigned)day,
       (unsigned)hours, (unsigned)minutes, (unsigned)seconds, dateValid ? 1 : 0);
  (void)month; (void)day; (void)year;
  (void)hours; (void)minutes; (void)seconds;

  // DeviceSubClass sig formatting (tool line 258)
  if (hdr->deviceSubClass) {
    icGetSig(buf, bufSize, hdr->deviceSubClass);
  }

  // Spectral range (tool lines 270-288) with NaN check
  if (hdr->spectralRange.start || hdr->spectralRange.end || hdr->spectralRange.steps) {
    volatile float specStart = icF16toF(hdr->spectralRange.start);
    volatile float specEnd = icF16toF(hdr->spectralRange.end);
    volatile int specSteps = hdr->spectralRange.steps;
    DIAG("Spectral: start=%.2f end=%.2f steps=%d nan=%d",
         (double)specStart, (double)specEnd, (int)specSteps,
         (std::isnan(specStart) || std::isnan(specEnd)) ? 1 : 0);
    (void)specStart; (void)specEnd; (void)specSteps;
  }
  if (hdr->biSpectralRange.start || hdr->biSpectralRange.end || hdr->biSpectralRange.steps) {
    volatile float biStart = icF16toF(hdr->biSpectralRange.start);
    volatile float biEnd = icF16toF(hdr->biSpectralRange.end);
    volatile int biSteps = hdr->biSpectralRange.steps;
    DIAG("BiSpectral: start=%.2f end=%.2f steps=%d nan=%d",
         (double)biStart, (double)biEnd, (int)biSteps,
         (std::isnan(biStart) || std::isnan(biEnd)) ? 1 : 0);
    (void)biStart; (void)biEnd; (void)biSteps;
  }

  // MCS color space (tool lines 290-295) with validation
  if (hdr->mcs) {
    fmt.GetColorSpaceSigName((icColorSpaceSignature)hdr->mcs);
    bool mcsValid = IsValidColorSpaceSignature((icUInt32Number)hdr->mcs);
    DIAG("MCS: sig=0x%08x valid=%d", (uint32_t)hdr->mcs, mcsValid);
  }
}

// ── Phase 2: Tag structural analysis (overlaps, bounds, TagArrayType) ──
// Mirrors iccDumpProfile.cpp lines 306-437: sorted offsets, upper_bound,
// pad calculation, duplication via unordered_map, FindTag(entry) path.
static void AnalyzeTagStructure(CIccProfile *pIcc) {
  icHeader *hdr = &pIcc->m_Header;
  size_t tagCount = pIcc->m_Tags.size();
  const size_t bufSize = 64;
  char buf[bufSize];

  // H10: Tag count limits
  if (tagCount == 0 || tagCount > kMaxTagCount) return;

  CIccInfo fmt;

  // Build sorted offset vector (tool lines 309-315)
  std::vector<icUInt32Number> sortedOffsets;
  sortedOffsets.resize(tagCount);
  int idx = 0;
  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i, ++idx) {
    sortedOffsets[idx] = i->TagInfo.offset;
  }
  std::sort(sortedOffsets.begin(), sortedOffsets.end());

  // Tag table display pass (tool lines 320-336)
  int smallestOffset = (int)hdr->size;
  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i) {
    // icGetSig for tag sig (tool line 334)
    icGetSig(buf, bufSize, i->TagInfo.sig, false);
    fmt.GetTagSigName(i->TagInfo.sig);

    // Find closest following tag via upper_bound (tool lines 322-328)
    auto match = std::upper_bound(sortedOffsets.cbegin(), sortedOffsets.cend(),
                                  i->TagInfo.offset);
    int closest;
    if (match == sortedOffsets.cend())
      closest = (int)hdr->size;
    else
      closest = *match;
    closest = std::min(closest, (int)hdr->size);

    // Pad calculation (tool line 332)
    volatile int pad = closest - (int)i->TagInfo.offset - (int)i->TagInfo.size;
    (void)pad;

    // Track smallest offset for first tag check
    if ((int)i->TagInfo.offset < smallestOffset)
      smallestOffset = (int)i->TagInfo.offset;
  }

  // Tag duplication via unordered_map (tool lines 342-354)
  std::unordered_map<icTagSignature, int> tagLookup;
  idx = 0;
  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i, ++idx) {
    auto found = tagLookup.find(i->TagInfo.sig);
    if (found != tagLookup.end()) {
      // Duplicate detected — exercise the same path as tool
      volatile int dup1 = idx;
      volatile int dup2 = found->second;
      (void)dup1; (void)dup2;
    } else {
      tagLookup[i->TagInfo.sig] = idx;
    }
  }

  // Validation pass (tool lines 369-437)

  // File size alignment (tool lines 377-381)
  if (hdr->version >= icVersionNumberV4_2) {
    volatile bool sizeUnaligned = (hdr->size % 4 != 0);
    (void)sizeUnaligned;
  }

  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i) {
    int rndup = 4 * ((i->TagInfo.size + 3) / 4);

    // Tag offset+size > EOF (tool lines 388-394)
    volatile bool tagOOB = (i->TagInfo.offset + i->TagInfo.size > hdr->size);
    if (tagOOB) {
      DIAG("P2-OOB: tag=%s offset=%u size=%u EOF=%u overflow=%llu",
           fmt.GetTagSigName(i->TagInfo.sig),
           i->TagInfo.offset, i->TagInfo.size, hdr->size,
           (unsigned long long)i->TagInfo.offset + i->TagInfo.size);
    }
    (void)tagOOB;

    // Overlap via upper_bound (tool lines 403-417)
    auto match = std::upper_bound(sortedOffsets.cbegin(), sortedOffsets.cend(),
                                  i->TagInfo.offset);
    int closest;
    if (match == sortedOffsets.cend())
      closest = (int)hdr->size;
    else
      closest = *match;
    closest = std::min(closest, (int)hdr->size);

    volatile bool overlap = (closest < (int)i->TagInfo.offset + (int)i->TagInfo.size)
                            && (closest < (int)hdr->size);
    if (overlap) {
      DIAG("P2-OVERLAP: tag=%s offset=%u size=%u closest=%d",
           fmt.GetTagSigName(i->TagInfo.sig),
           i->TagInfo.offset, i->TagInfo.size, closest);
    }
    (void)overlap;

    // Gap detection (tool lines 420-426)
    volatile bool gap = (closest > (int)i->TagInfo.offset + rndup);
    if (gap) {
      DIAG("P2-GAP: tag=%s offset=%u rndup=%d closest=%d gap=%d",
           fmt.GetTagSigName(i->TagInfo.sig),
           i->TagInfo.offset, rndup, closest,
           closest - (int)i->TagInfo.offset - rndup);
    }
    (void)gap;
  }

  // First tag offset check (tool lines 431-437)
  {
    int expectedFirst = 128 + 4 + ((int)tagCount * 12);
    volatile bool firstTagGap = (smallestOffset > expectedFirst);
    (void)firstTagGap;
  }
}

// ── Phase 3: Deep tag exercising with type-specific paths ──
// Mirrors tool's DumpTagEntry→FindTag(entry)→DumpTagCore flow (lines 124-128, 93-114)
static void ExerciseTags(CIccProfile *pIcc, int verboseness) {
  CIccInfo fmt;
  const size_t bufSize = 64;
  char buf[bufSize];
  icHeader *hdr = &pIcc->m_Header;

  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i) {
    // Use FindTag(entry) like tool's DumpTagEntry (line 126)
    CIccTag *pTag = pIcc->FindTag(*i);
    if (!pTag) continue;

    icTagTypeSignature tagType = pTag->GetType();

    // Diagnostic: log tag context before exercising
    DiagTagContext("ExerciseTag", i->TagInfo.sig, tagType,
                   i->TagInfo.offset, i->TagInfo.size, hdr->size);

    // icGetSig calls matching tool's DumpTagCore (lines 102, 107)
    icGetSig(buf, bufSize, i->TagInfo.sig);
    icGetSig(buf, bufSize, pTag->GetType());
    const char *tagSigName = fmt.GetTagSigName(i->TagInfo.sig);
    const char *tagTypeName = fmt.GetTagTypeSigName(tagType);
    DIAG("Tag: sig=%s(%s) type=%s(%s) arrayType=%d",
         icGetSig(buf, bufSize, i->TagInfo.sig), tagSigName ? tagSigName : "?",
         icGetSig(buf, bufSize, tagType), tagTypeName ? tagTypeName : "?",
         pTag->IsArrayType());

    // IsArrayType check (tool line 104)
    pTag->IsArrayType();

    // Describe at caller-controlled verbosity (tool line 108)
    std::string desc;
    desc.reserve(kMaxDescribeLen);
    pTag->Describe(desc, verboseness);

    // Validate every tag
    std::string valReport;
    pTag->Validate(fmt.GetTagSigName(i->TagInfo.sig), valReport);

    pTag->IsSupported();
    pTag->GetType();

    // ── LUT tag deep exercise (CLUT overflow paths) ──
    CIccMBB *pLut = dynamic_cast<CIccMBB*>(pTag);
    DiagCast("CIccMBB", pLut, i->TagInfo.sig, tagType);
    if (pLut) {
      volatile int inCh = pLut->InputChannels();
      volatile int outCh = pLut->OutputChannels();
      (void)inCh; (void)outCh;

      DIAG("LUT: in=%d out=%d isInputMatrix=%d",
           (int)inCh, (int)outCh, pLut->IsInputMatrix());

      pLut->IsInputMatrix();

      // Access CLUT if present — triggers size calculations
      CIccCLUT *pCLUT = pLut->GetCLUT();
      if (pCLUT) {
        volatile int clutIn = pCLUT->GetInputDim();
        volatile int clutOut = pCLUT->GetOutputChannels();
        volatile uint32_t clutGrid = pCLUT->GridPoints();
        volatile uint32_t clutNum = pCLUT->NumPoints();

        DiagAlloc("CLUT", (uint64_t)clutNum, (uint64_t)clutOut * sizeof(icFloatNumber));

        // H11: CLUT entry limit (iccanalyzer-lite)
        if ((uint64_t)clutNum > kMaxCLUT) {
          DIAG("  CLUT: numPoints=%u > limit=%llu [H11: EXCESSIVE]",
               (uint32_t)clutNum, (unsigned long long)kMaxCLUT);
        }

        // Per-dimension grid point logging
        for (int d = 0; d < (int)clutIn && d < 16; d++) {
          volatile uint32_t dimPts = pCLUT->GridPoints();
          DIAG("  CLUT dim[%d] gridPts=%u", d, (uint32_t)dimPts);
          (void)dimPts;
        }

        (void)clutIn; (void)clutOut; (void)clutGrid; (void)clutNum;
      } else {
        DIAG("  CLUT: not present (GetCLUT()=nullptr)");
      }

      // Exercise curve access with null logging
      CIccCurve *pCurveA = pLut->GetCurvesA() ? pLut->GetCurvesA()[0] : nullptr;
      CIccCurve *pCurveB = pLut->GetCurvesB() ? pLut->GetCurvesB()[0] : nullptr;
      CIccCurve *pCurveM = pLut->GetCurvesM() ? pLut->GetCurvesM()[0] : nullptr;
      DIAG("  Curves: A=%p B=%p M=%p", (void*)pCurveA, (void*)pCurveB, (void*)pCurveM);
      if (pCurveA) { std::string s; pCurveA->Describe(s, verboseness); }
      if (pCurveB) { std::string s; pCurveB->Describe(s, verboseness); }
      if (pCurveM) { std::string s; pCurveM->Describe(s, verboseness); }
    }

    // ── MPE tag deep exercise (chain depth, element iteration) ──
    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    DiagCast("CIccTagMPE", pMPE, i->TagInfo.sig, tagType);
    if (pMPE) {
      volatile int mpeIn = pMPE->NumInputChannels();
      volatile int mpeOut = pMPE->NumOutputChannels();
      volatile uint32_t numElems = pMPE->NumElements();
      (void)mpeIn; (void)mpeOut;

      DIAG("MPE: in=%d out=%d elements=%u", (int)mpeIn, (int)mpeOut, (uint32_t)numElems);
      DiagAlloc("MPE-elements", numElems, sizeof(void*));

      // H12: MPE chain depth limit (iccanalyzer-lite)
      if (numElems > kMaxMPEDepth) {
        DIAG("  MPE: elements=%u > limit=%u [H12: EXCESSIVE CHAIN]",
             (uint32_t)numElems, kMaxMPEDepth);
      }

      // Per-element type iteration — identify Calculator, Curve, Matrix, etc.
      if (numElems > 0 && numElems <= 64) {
        for (uint32_t e = 0; e < numElems && e < 32; e++) {
          CIccMultiProcessElement *pElem = pMPE->GetElement(e);
          if (pElem) {
            icGetSig(buf, bufSize, pElem->GetType());
            DIAG("  MPE[%u]: type=%s in=%d out=%d",
                 e, buf, (int)pElem->NumInputChannels(),
                 (int)pElem->NumOutputChannels());
          } else {
            DIAG("  MPE[%u]: nullptr from GetElement()", e);
          }
        }
      }

      // Note: iccDumpProfile calls Describe()/Validate() on MPE tags
      // but never Begin() — tag execution is out of tool scope.

      (void)numElems;
    }

    // ── Named color exercising ──
    CIccTagNamedColor2 *pNamed = dynamic_cast<CIccTagNamedColor2*>(pTag);
    DiagCast("CIccTagNamedColor2", pNamed, i->TagInfo.sig, tagType);
    if (pNamed) {
      volatile uint32_t count = pNamed->GetSize();
      DIAG("NamedColor2: count=%u", (uint32_t)count);
      (void)count;
      // Enumerate color names (Describe() scope — no FindColor, which is
      // outside iccDumpProfile scope and has a known OOB in suffix handling)
      if (pNamed->GetSize() > 0 && pNamed->GetSize() < 10000) {
        for (uint32_t idx = 0; idx < pNamed->GetSize() && idx < 16; idx++) {
          std::string name;
          pNamed->GetColorName(name, idx);
          (void)name;
        }
      }
    }

    // ── TagArray exercise (CIccTagArray — OOM via SetSize, UAF in Cleanup) ──
    CIccTagArray *pArr = dynamic_cast<CIccTagArray*>(pTag);
    DiagCast("CIccTagArray", pArr, i->TagInfo.sig, tagType);
    if (pArr) {
      volatile uint32_t arrSize = pArr->GetSize();
      DIAG("TagArray: type=%s size=%u",
           icGetSig(buf, bufSize, pArr->GetTagArrayType()),
           (uint32_t)arrSize);
      DiagAlloc("TagArray", arrSize, sizeof(void*));
      (void)arrSize;

      // Exercise element access — triggers LoadTag for lazy elements
      if (arrSize > 0 && arrSize <= 1024) {
        for (uint32_t idx = 0; idx < arrSize && idx < 8; idx++) {
          CIccTag *pElem = pArr->GetIndex(idx);
          if (pElem) {
            DIAG("  TagArray[%u]: type=%s", idx,
                 icGetSig(buf, bufSize, pElem->GetType()));
            std::string elemDesc;
            elemDesc.reserve(4096);
            pElem->Describe(elemDesc, verboseness > 50 ? 50 : verboseness);
          }
        }
      }
    }

    // ── TagStruct exercise ──
    CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct*>(pTag);
    DiagCast("CIccTagStruct", pStruct, i->TagInfo.sig, tagType);
    if (pStruct) {
      DIAG("TagStruct: structType=%s",
           icGetSig(buf, bufSize, pStruct->GetTagStructType()));
      auto *pStructHandler = pStruct->GetStructHandler();
      if (pStructHandler) {
        std::string structDesc;
        structDesc.reserve(4096);
        pStruct->Describe(structDesc, verboseness > 50 ? 50 : verboseness);
      } else {
        DIAG("  TagStruct: GetStructHandler()=nullptr");
      }
    }

    // ── Dictionary tag exercise (CIccTagDict — OOM via count*reclen) ──
    CIccTagDict *pDict = dynamic_cast<CIccTagDict*>(pTag);
    DiagCast("CIccTagDict", pDict, i->TagInfo.sig, tagType);
    if (pDict) {
      // Describe exercises the full record iteration path
      DIAG("TagDict: exercising Describe");
      std::string dictDesc;
      dictDesc.reserve(8192);
      pDict->Describe(dictDesc, verboseness > 50 ? 50 : verboseness);

      // Validate exercises structural integrity checks
      std::string dictVal;
      pDict->Validate("dict", dictVal);
    }

    // ── Curve tag exercise (TRC, parametric curves) ──
    CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve*>(pTag);
    DiagCast("CIccTagCurve", pCurve, i->TagInfo.sig, tagType);
    if (pCurve) {
      volatile uint32_t curveSize = pCurve->GetSize();
      DIAG("Curve: entries=%u", (uint32_t)curveSize);
      DiagAlloc("Curve", curveSize, sizeof(icFloatNumber));
      // Exercise element access on small curves — guard size=0
      if (curveSize == 0) {
        DIAG("  Curve: size=0, skipping element access");
      } else if (curveSize <= 65536) {
        volatile icFloatNumber first = (*pCurve)[0];
        volatile icFloatNumber last = (*pCurve)[curveSize - 1];
        volatile icFloatNumber mid = (*pCurve)[curveSize / 2];
        DIAG("  Curve values: first=%.6f mid=%.6f last=%.6f nan=%d",
             (double)first, (double)mid, (double)last,
             (std::isnan(first) || std::isnan(mid) || std::isnan(last)) ? 1 : 0);
        (void)first; (void)last; (void)mid;
        // Note: pCurve->Apply() not called — iccDumpProfile uses Describe() only
      }
      (void)curveSize;
    }

    // ── XYZ tag exercise (colorants, media points) ──
    CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ*>(pTag);
    DiagCast("CIccTagXYZ", pXYZ, i->TagInfo.sig, tagType);
    if (pXYZ) {
      volatile uint32_t xyzCount = pXYZ->GetSize();
      DIAG("XYZ: entries=%u", (uint32_t)xyzCount);
      if (xyzCount > 0 && xyzCount <= 256) {
        for (uint32_t x = 0; x < xyzCount && x < 8; x++) {
          icXYZNumber *pVal = &(*pXYZ)[x];
          if (!pVal) {
            DIAG("  XYZ[%u]: nullptr", x);
            continue;
          }
          icFloatNumber fx = icFtoD(pVal->X);
          icFloatNumber fy = icFtoD(pVal->Y);
          icFloatNumber fz = icFtoD(pVal->Z);
          DIAG("  XYZ[%u]: X=%.6f Y=%.6f Z=%.6f nan=%d inf=%d",
               x, (double)fx, (double)fy, (double)fz,
               (std::isnan(fx) || std::isnan(fy) || std::isnan(fz)) ? 1 : 0,
               (std::isinf(fx) || std::isinf(fy) || std::isinf(fz)) ? 1 : 0);
        }
      }
      (void)xyzCount;
    }

    // ── Text description exercise ──
    CIccTagText *pText = dynamic_cast<CIccTagText*>(pTag);
    DiagCast("CIccTagText", pText, i->TagInfo.sig, tagType);
    if (pText) {
      const char *textStr = pText->GetText();
      if (textStr) {
        volatile size_t textLen = strlen(textStr);
        DIAG("Text: len=%zu", (size_t)textLen);
        (void)textLen;
      } else {
        DIAG("Text: GetText()=nullptr");
      }
    }

    // ── ProfileSequenceId / ProfileSequenceDesc ──
    // These use new[] with user-controlled count — exercise to trigger OOM/overflow
    if (tagType == icSigProfileSequenceDescType ||
        tagType == icSigProfileSequceIdType) {
      DIAG("ProfSeq: type=%s size=%u",
           icGetSig(buf, bufSize, tagType), i->TagInfo.size);
      // Describe already called above — this just logs the context
    }
  }
}

// ── Phase 3c: Calculator/ChannelFunc UBSAN exerciser ──
// Root cause: IccMpeCalc.cpp:3482 loads user-controlled uint32 into
// icChannelFuncSignature enum (single valid value 0x66756e63 = 'func').
// UBSAN fires on comparison when the raw value isn't a valid enum member.
// This phase deliberately exercises the code path to surface the bug.
static void ExerciseCalculatorTags(CIccProfile *pIcc) {
  const size_t bufSize = 64;
  char buf[bufSize];

  for (auto i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i) {
    CIccTag *pTag = pIcc->FindTag(*i);
    if (!pTag) continue;

    // CIccMpeCalculator contains CIccCalculatorFunc which has the UBSAN bug
    CIccTagMultiProcessElement *pMPE =
        dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMPE) continue;

    DIAG("Calculator probe: tag=%s elements=%u",
         icGetSig(buf, bufSize, i->TagInfo.sig),
         pMPE->NumElements());

    // Pre-crash state dump — this path triggers IccMpeCalc.cpp:3482 UBSAN
    DiagPreCrashState("ExerciseCalculatorTags", "UBSAN enum-load path",
                      pMPE, sizeof(*pMPE));

    // Validate exercises Read paths that trigger the enum load
    std::string valReport;
    pMPE->Validate(icGetSig(buf, bufSize, i->TagInfo.sig), valReport);
    if (!valReport.empty()) {
      DIAG("  Validate report length=%zu", valReport.size());
    }

    // Describe exercises Describe→DescribeSequence path in calculator
    std::string desc;
    desc.reserve(kMaxDescribeLen);
    pMPE->Describe(desc, 100);

    // Note: iccDumpProfile calls Describe()/Validate() on MPE tags
    // but never Begin() — tag execution is out of tool scope.
  }
}

// ── Phase 4: Cross-tag signature lookup (rendering intent coverage) ──
static void ExerciseSignatureLookups(CIccProfile *pIcc, int verboseness) {
  static const icSignature sigs[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
    icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
    icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag,
    icSigRedColorantTag, icSigGreenColorantTag, icSigBlueColorantTag,
    icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag,
    icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag,
    icSigGrayTRCTag, icSigMediaWhitePointTag, icSigMediaBlackPointTag,
    icSigLuminanceTag, icSigMeasurementTag,
    icSigNamedColor2Tag, icSigColorantTableTag, icSigColorantOrderTag,
    icSigChromaticAdaptationTag, icSigCopyrightTag,
    icSigProfileDescriptionTag, icSigViewingCondDescTag,
    icSigColorimetricIntentImageStateTag,
    icSigPerceptualRenderingIntentGamutTag,
    icSigSaturationRenderingIntentGamutTag,
    icSigTechnologyTag, icSigDeviceMfgDescTag, icSigDeviceModelDescTag,
    icSigProfileSequenceDescTag, icSigCicpTag, icSigMetaDataTag,
    icSigGamutBoundaryDescription0Tag, icSigGamutBoundaryDescription1Tag,
    icSigGamutBoundaryDescription2Tag, icSigGamutBoundaryDescription3Tag,
    icSigBrdfColorimetricParameter0Tag,
    icSigMaterialTypeArrayTag, icSigMaterialDefaultValuesTag,
    icSigSpectralViewingConditionsTag,
    icSigCustomToStandardPccTag, icSigStandardToCustomPccTag,
  };

  CIccInfo fmt;
  const size_t bufSize = 64;
  char buf[bufSize];

  for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
    CIccTag *tag = pIcc->FindTag(sigs[i]);
    if (tag) {
      icTagTypeSignature foundType = tag->GetType();
      icTagSignature tagSig = (icTagSignature)sigs[i];
      DIAG("P4: sig=%s found type=%s(%s)",
           fmt.GetTagSigName(tagSig),
           icGetSig(buf, bufSize, foundType),
           fmt.GetTagTypeSigName(foundType));

      std::string desc;
      desc.reserve(kMaxDescribeLen);
      tag->Describe(desc, verboseness);

      std::string valReport;
      tag->Validate(fmt.GetTagSigName(tagSig), valReport);
      if (!valReport.empty()) {
        DIAG("  P4 validate: sig=%s reportLen=%zu",
             fmt.GetTagSigName(tagSig), valReport.size());
      }

      // Technology tag: validate signature value against known sigs
      if (sigs[i] == icSigTechnologyTag) {
        CIccTagSignature *pTechTag = dynamic_cast<CIccTagSignature*>(tag);
        DiagCast("CIccTagSignature(tech)", pTechTag, tagSig, foundType);
        if (pTechTag) {
          icUInt32Number techVal = (icUInt32Number)pTechTag->GetValue();
          bool techValid = IsValidTechnologySignature(techVal);
          DIAG("  Technology: value=0x%08x valid=%d name=%s",
               techVal, techValid,
               fmt.GetTechnologySigName((icTechnologySignature)techVal));
        }
      }
    }
  }
}

// Note: ExerciseCMM (Phase 5) and ExerciseAttach (Phase 6) removed —
// iccDumpProfile.cpp never performs CMM transforms or Attach re-reads.
// These were outside the tool's scope and degraded fidelity alignment.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 132 || size > kMaxProfileSize) return 0;

  // Derive control bytes from trailing bytes to preserve ICC header structure
  // (consuming leading bytes shifts the profile header, breaking fidelity)
  uint8_t verbByte = data[size - 1];
  uint8_t phaseByte = data[size - 2];
  uint8_t extraByte = data[size - 3];
  uint8_t intentByte = data[size - 4];

  // ── Pre-scan tag table for OOM-inducing entries ──
  static constexpr size_t kMaxAllocPerTag = 128 * 1024 * 1024; // 128 MB

  // OOM guard 1: Reject profiles with claimed size >> actual input.
  // Library uses header profileSize to set internal expectations, then
  // tag-internal Read methods allocate based on data they parse.
  {
    uint32_t claimedSize = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                           ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    if (claimedSize > 0 && claimedSize > size * 16 && claimedSize > kMaxAllocPerTag) {
      DIAG("OOM-guard: header profileSize=%u but input=%zu (%.0fx inflation), rejected",
           claimedSize, size, (double)claimedSize / size);
      return 0;
    }
  }

  // OOM guard 2: Reject profiles with any single tag > kMaxAllocPerTag.
  // ICC tag count is at offset 128, entries start at 132.
  {
    uint32_t tagCount = ((uint32_t)data[128] << 24) | ((uint32_t)data[129] << 16) |
                        ((uint32_t)data[130] << 8) | (uint32_t)data[131];
    if (tagCount > kMaxTagCount) return 0;
    size_t tableEnd = 132 + (size_t)tagCount * 12;
    if (tableEnd > size) return 0;
    for (uint32_t t = 0; t < tagCount; t++) {
      size_t base = 132 + t * 12;
      uint32_t tagSize = ((uint32_t)data[base+8] << 24) | ((uint32_t)data[base+9] << 16) |
                         ((uint32_t)data[base+10] << 8) | (uint32_t)data[base+11];
      uint32_t tagOffset = ((uint32_t)data[base+4] << 24) | ((uint32_t)data[base+5] << 16) |
                           ((uint32_t)data[base+6] << 8) | (uint32_t)data[base+7];
      if (tagSize > kMaxAllocPerTag || tagOffset > size) {
        DIAG("OOM-guard: tag[%u] offset=%u size=%u rejected (limit=%zuMB)",
             t, tagOffset, tagSize, kMaxAllocPerTag / (1024*1024));
        return 0;
      }
    }
  }

  int verboseness = (verbByte % 100) + 1;
  bool doHighVerb = (phaseByte & 0x04);
  bool doOpenPath = (phaseByte & 0x08);  // OpenIccProfile path (tool line 218)
  (void)extraByte;
  (void)intentByte;

  DIAG("input size=%zu verb=%d phase=0x%02x open=%d highverb=%d",
       size, verboseness, phaseByte, doOpenPath, doHighVerb);

  CIccProfile *pIcc = nullptr;

  if (doOpenPath) {
    DIAG("path=OpenIccProfile (non-validating)");
    // Non-validating read path (matches tool's OpenIccProfile, line 218)
    CIccMemIO *pIO = new CIccMemIO();
    if (!pIO->Attach(const_cast<uint8_t*>(data), (icUInt32Number)size)) {
      delete pIO;
      return 0;
    }
    pIcc = new CIccProfile();
    if (!pIcc->Read(pIO)) {
      delete pIcc;
      delete pIO;
      return 0;
    }
    delete pIO;
  } else {
    DIAG("path=ValidateIccProfile (with validation)");
    // Primary parse via ValidateIccProfile (matches tool's -v path, line 198)
    std::string report;
    icValidateStatus nStatus;
    pIcc = ValidateIccProfile(data, size, report, nStatus);
    DIAG("validation status=%d reportLen=%zu", (int)nStatus, report.size());
  }

  if (!pIcc) {
    DIAG("profile parse failed, exiting");
    return 0;
  }

  DIAG("profile loaded: version=0x%08x class=0x%08x tags=%zu",
       pIcc->m_Header.version, pIcc->m_Header.deviceClass,
       pIcc->m_Tags.size());

  // Phase 1: Header heuristics
  AnalyzeHeader(pIcc);

  // Phase 2: Tag structural analysis
  AnalyzeTagStructure(pIcc);

  // Phase 3: Deep tag exercising with type-specific paths
  ExerciseTags(pIcc, verboseness);

  // Phase 3b: Higher verbosity pass on small profiles
  if (doHighVerb && size < 32768) {
    ExerciseTags(pIcc, 100);
  }

  // Phase 3c: Calculator/ChannelFunc UBSAN exerciser
  ExerciseCalculatorTags(pIcc);

  // Phase 4: Cross-tag signature lookup
  ExerciseSignatureLookups(pIcc, verboseness);

  // Note: CMM transforms (AddXform/Begin/Apply) and Attach re-read
  // are outside iccDumpProfile.cpp scope — removed for fidelity alignment.

  // Global profile methods (iccDumpProfile calls these)
  pIcc->GetSpaceSamples();
  pIcc->AreTagsUnique();

  delete pIcc;

  return 0;
}
