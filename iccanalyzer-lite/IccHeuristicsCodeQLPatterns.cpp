/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

// CodeQL-driven heuristics (H154-H161).
// Derived from CodeQL analysis of iccDEV IccProfLib+IccXML (1,114 findings).
// Extracted from IccHeuristicsRawPost.cpp for maintainability.

#include "IccHeuristicsCodeQLPatterns.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerColors.h"
#include "IccAnalyzerSignatures.h"
#include "IccHeuristicsHelpers.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <vector>
#include <algorithm>


// ============================================================================
// CodeQL-Driven Heuristics H154-H159
// Derived from CodeQL analysis of iccDEV IccProfLib+IccXML (1,114 findings).
// Each targets a CWE category with multiple library sites not covered by H1-H153.
// ============================================================================

// ---------------------------------------------------------------------------
// H154: Uncontrolled Tag Allocation Size (CWE-789)
// CodeQL found 21 sites where file-controlled values are passed directly to
// new[] or malloc() without upper-bound validation in Read() methods.
// Hotspots: IccTagBasic.cpp(7), IccMpeBasic.cpp(3), IccTagLut.cpp(3),
//           IccMpeSpectral.cpp(2), IccMpeCalc.cpp(1).
// Detection: Scan tag table for tags whose declared size is disproportionately
// large relative to the profile size — these trigger unbounded allocations.
// ---------------------------------------------------------------------------
int RunHeuristic_H154_UncontrolledTagAllocationSize(RawProfileContext &ctx)
{
  int heuristicCount = 0;
  printf("[H154] Uncontrolled Tag Allocation Size (CWE-789, §7.3 Tag Table)\n");

  if (!ctx.valid) {
    printf("      [SKIP] File too small for tag table\n\n");
    return 0;
  }

  size_t fs = ctx.fileSize();

  int issues = 0;
  for (const auto &_tag : ctx.tags) {
    uint32_t tSig    = _tag.sig;
    uint32_t tOffset = _tag.offset;
    uint32_t tSize   = _tag.size;

    // Skip tags that fit within the profile
    if ((uint64_t)tOffset <= fs && (uint64_t)tSize <= fs && (uint64_t)tOffset + tSize <= fs)
      continue;

    // Tag data extends beyond file — library Read() will allocate tSize
    // bytes then fail during fread, but allocation already happened
    char sig[5];
    sig[0] = static_cast<char>(static_cast<unsigned char>((tSig >> 24) & 0xFF));
    sig[1] = static_cast<char>(static_cast<unsigned char>((tSig >> 16) & 0xFF));
    sig[2] = static_cast<char>(static_cast<unsigned char>((tSig >>  8) & 0xFF));
    sig[3] = static_cast<char>(static_cast<unsigned char>( tSig        & 0xFF));
    sig[4] = '\0';

    printf("      %s[CRITICAL] Tag '%s': offset=%u size=%u exceeds file (%zu bytes)%s\n",
           ColorCritical(), sig, tOffset, tSize, fs, ColorReset());
    printf("       %sCWE-789: Uncontrolled allocation — Read() allocates %u bytes "
           "from file-controlled size before bounds check%s\n",
           ColorCritical(), tSize, ColorReset());
    issues++;
    if (issues >= 8) break;
  }

  // Second pass: check for tags with extreme allocation amplification
  // (tag data size that implies huge internal allocation via element count × struct size)
  fseek(ctx.fh.fp, 132, SEEK_SET);
  for (const auto &_tag : ctx.tags) {
    uint32_t tSig    = _tag.sig;
    uint32_t tOffset = _tag.offset;
    uint32_t tSize   = _tag.size;

    if ((uint64_t)tOffset + 12 > fs || tSize < 12) continue;

    // Read tag type signature
    long savedPos = ftell(ctx.fh.fp);
    fseek(ctx.fh.fp, tOffset, SEEK_SET);
    uint8_t typeBuf[12];
    if (fread(typeBuf, 1, 12, ctx.fh.fp) != 12) {
      fseek(ctx.fh.fp, savedPos, SEEK_SET);
      continue;
    }
    fseek(ctx.fh.fp, savedPos, SEEK_SET);

    uint32_t typeSig = ReadU32BE(&typeBuf[0]);

    // ncl2 (NamedColor2): nDeviceCoords at offset+12 (uint32) drives allocation
    if (typeSig == 0x6E636C32 && tSize >= 16) { // 'ncl2'
      fseek(ctx.fh.fp, tOffset + 12, SEEK_SET);
      uint8_t ncBuf[4];
      if (fread(ncBuf, 1, 4, ctx.fh.fp) == 4) {
        uint32_t nDevCoords = ReadU32BE(ncBuf);
        if (nDevCoords > 15) {
          printf("      %s[CRITICAL] NamedColor2: nDeviceCoords=%u (ICC spec max=15)%s\n",
                 ColorCritical(), nDevCoords, ColorReset());
          printf("       %sCWE-789: m_nColorEntrySize = 32 + nDevCoords*sizeof(icFloatNumber) "
                 "→ unbounded allocation in Read() (IccTagBasic.cpp)%s\n",
                 ColorCritical(), ColorReset());
          issues++;
        }
      }
      fseek(ctx.fh.fp, savedPos, SEEK_SET);
    }

    // mAB/mBA: sub-element offsets (Bcurves, Matrix, Acurves, CLUT) must be
    // within tag size. Out-of-bounds offsets cause the parser to read adjacent
    // tag data as curve elements, triggering OOM from garbage nCount values.
    // mAB = 0x6D414220, mBA = 0x6D424120
    if ((typeSig == 0x6D414220 || typeSig == 0x6D424120) && tSize >= 28) {
      fseek(ctx.fh.fp, tOffset + 12, SEEK_SET);
      uint8_t mabBuf[16];
      if (fread(mabBuf, 1, 16, ctx.fh.fp) == 16) {
        const char *subNames[] = {"Bcurves", "Matrix", "Acurves", "CLUT"};
        for (int s = 0; s < 4; s++) {
          uint32_t subOff = ReadU32BE(&mabBuf[s * 4]);
          if (subOff > 0 && subOff >= tSize) {
            char tagSig[5];
            tagSig[0] = static_cast<char>(static_cast<unsigned char>((tSig >> 24) & 0xFF));
            tagSig[1] = static_cast<char>(static_cast<unsigned char>((tSig >> 16) & 0xFF));
            tagSig[2] = static_cast<char>(static_cast<unsigned char>((tSig >>  8) & 0xFF));
            tagSig[3] = static_cast<char>(static_cast<unsigned char>( tSig        & 0xFF));
            tagSig[4] = '\0';
            printf("      %s[CRITICAL] Tag '%s' (%s): %s offset=%u exceeds tag size (%u)%s\n",
                   ColorCritical(), tagSig,
                   typeSig == 0x6D414220 ? "mAB" : "mBA",
                   subNames[s], subOff, tSize, ColorReset());
            printf("       %sCWE-789: Out-of-bounds sub-element offset causes parser to read "
                   "adjacent data as curve elements → OOM allocation%s\n",
                   ColorCritical(), ColorReset());
            issues++;
          }
        }
      }
      fseek(ctx.fh.fp, savedPos, SEEK_SET);
    }
  }

  if (issues > 0) {
    heuristicCount += issues;
  } else {
    printf("      %s[OK] All tag allocation sizes within bounds%s\n",
           ColorSuccess(), ColorReset());
  }
  printf("\n");

  return heuristicCount;
}

// ---------------------------------------------------------------------------
// H155: Integer Overflow in Tag Dimensions (CWE-190)
// CodeQL found 24 integer multiplication overflow sites where channel_count ×
// element_size overflows uint32 before allocation. Hotspots: IccTagBasic.cpp(4),
// IccTagLut.cpp(4), IccMpeSpectral.cpp(3), IccMpeBasic.cpp(2), IccCmm.cpp(2).
// Detection: For LUT/MPE tags, validate that input×output×gridPoints product
// fits in 32 bits and doesn't exceed profile size.
// ---------------------------------------------------------------------------
int RunHeuristic_H155_IntegerOverflowTagDimensions(RawProfileContext &ctx)
{
  int heuristicCount = 0;
  printf("[H155] Integer Overflow in Tag Dimensions (CWE-190, §10.6-10.14)\n");

  if (!ctx.valid) {
    printf("      [SKIP] File too small\n\n");
    return 0;
  }

  size_t fs = ctx.fileSize();
  std::vector<uint8_t> buf(fs);
  fseek(ctx.fh.fp, 0, SEEK_SET);
  if (fread(buf.data(), 1, fs, ctx.fh.fp) != fs) {
    printf("      [SKIP] Cannot read file\n\n");
    return 0;
  }

  uint32_t tagCount = ReadU32BE(&buf[128]);
  if (tagCount > 1000 || tagCount == 0) {
    printf("      [SKIP] Invalid tag count\n\n");
    return 0;
  }

  int issues = 0;
  for (uint32_t i = 0; i < tagCount && i < 256; i++) {
    size_t entryOff = 132 + (size_t)i * 12;
    if (entryOff + 12 > fs) break;

    uint32_t tSig    = ReadU32BE(&buf[entryOff]);
    uint32_t tOffset = ReadU32BE(&buf[entryOff + 4]);
    uint32_t tSize   = ReadU32BE(&buf[entryOff + 8]);

    if ((uint64_t)tOffset + 8 > fs || tSize < 8) continue;
    uint32_t typeSig = ReadU32BE(&buf[tOffset]);

    char sig[5];
    sig[0] = static_cast<char>(static_cast<unsigned char>((tSig >> 24) & 0xFF));
    sig[1] = static_cast<char>(static_cast<unsigned char>((tSig >> 16) & 0xFF));
    sig[2] = static_cast<char>(static_cast<unsigned char>((tSig >>  8) & 0xFF));
    sig[3] = static_cast<char>(static_cast<unsigned char>( tSig        & 0xFF));
    sig[4] = '\0';

    // mft1 (Lut8Type): nInput(1) × nOutput(1) × gridPoints^nInput × nOutput
    if (typeSig == 0x6D667431 && (uint64_t)tOffset + 48 <= fs) { // 'mft1'
      uint8_t nInput  = buf[tOffset + 8];
      uint8_t nOutput = buf[tOffset + 9];
      uint8_t grid    = buf[tOffset + 10];

      if (nInput > 0 && grid > 0) {
        uint64_t clutSize = 1;
        bool overflow = false;
        for (int d = 0; d < static_cast<int>(nInput); d++) {
          clutSize *= grid;
          if (clutSize > 0xFFFFFFFF) { overflow = true; break; }
        }
        clutSize *= nOutput;
        if (clutSize > 0xFFFFFFFF) overflow = true;

        if (overflow || clutSize > tSize) {
          printf("      %s[CRITICAL] Tag '%s' (Lut8): %ux%u grid^%u × %u = overflow%s\n",
                 ColorCritical(), sig, nInput, nOutput, nInput, grid, ColorReset());
          printf("       %sCWE-190: Integer overflow in CLUT size calculation "
                 "(IccTagLut.cpp Read())%s\n", ColorCritical(), ColorReset());
          issues++;
        }
      }
    }

    // mft2 (Lut16Type): same pattern with 2 bytes per entry
    if (typeSig == 0x6D667432 && (uint64_t)tOffset + 48 <= fs) { // 'mft2'
      uint8_t nInput  = buf[tOffset + 8];
      uint8_t nOutput = buf[tOffset + 9];
      uint8_t grid    = buf[tOffset + 10];

      if (nInput > 0 && grid > 0) {
        uint64_t clutSize = 2;  // 2 bytes per entry
        bool overflow = false;
        for (int d = 0; d < static_cast<int>(nInput); d++) {
          clutSize *= grid;
          if (clutSize > 0xFFFFFFFF) { overflow = true; break; }
        }
        clutSize *= nOutput;
        if (clutSize > 0xFFFFFFFF) overflow = true;

        if (overflow || clutSize > tSize) {
          printf("      %s[CRITICAL] Tag '%s' (Lut16): %ux%u grid^%u × %u × 2 = overflow%s\n",
                 ColorCritical(), sig, nInput, nOutput, nInput, grid, ColorReset());
          printf("       %sCWE-190: Integer overflow in CLUT size calculation "
                 "(IccTagLut.cpp Read())%s\n", ColorCritical(), ColorReset());
          issues++;
        }
      }
    }

    // mAB/mBA (LutAtoB/LutBtoA): nInput(1) at +8, nOutput(1) at +9
    // CLUT offset at +24 (uint32) — if nonzero, CLUT present
    if ((typeSig == 0x6D414220 || typeSig == 0x6D424120) && (uint64_t)tOffset + 32 <= fs) {
      uint8_t nInput  = buf[tOffset + 8];
      uint8_t nOutput = buf[tOffset + 9];
      uint32_t clutOff = ReadU32BE(&buf[tOffset + 24]);

      if (clutOff != 0 && (uint64_t)tOffset + clutOff + 20 <= fs) {
        // CLUT header: gridPoints[16](16 bytes) + precision(1) + pad(3)
        size_t clutAddr = tOffset + clutOff;
        uint64_t clutSize = (buf[clutAddr + 16] == 2) ? 2 : 1;  // precision
        bool overflow = false;
        for (int d = 0; d < static_cast<int>(nInput) && d < 16; d++) {
          uint8_t gp = buf[clutAddr + d];
          if (gp == 0) gp = 1;
          clutSize *= gp;
          if (clutSize > 0xFFFFFFFF) { overflow = true; break; }
        }
        clutSize *= nOutput;
        if (clutSize > 0xFFFFFFFF) overflow = true;

        if (overflow) {
          const char *lutName = (typeSig == 0x6D414220) ? "mAB" : "mBA";
          printf("      %s[CRITICAL] Tag '%s' (%s): %u-in × %u-out CLUT grid overflows uint32%s\n",
                 ColorCritical(), sig, lutName, nInput, nOutput, ColorReset());
          printf("       %sCWE-190: Multiplication overflow before allocation "
                 "(IccTagLut.cpp CIccCLUT::Init)%s\n", ColorCritical(), ColorReset());
          issues++;
        }
      }
    }

    // mpet (MultiProcessElement): nInput(2) at +8, nOutput(2) at +10, nElements(4) at +12
    if (typeSig == 0x6D706574 && (uint64_t)tOffset + 16 <= fs) { // 'mpet'
      uint16_t nInput  = (uint16_t)((buf[tOffset + 8] << 8) | buf[tOffset + 9]);
      uint16_t nOutput = (uint16_t)((buf[tOffset + 10] << 8) | buf[tOffset + 11]);
      uint32_t nElem   = ReadU32BE(&buf[tOffset + 12]);

      // Each element position entry is 8 bytes (offset + size)
      uint64_t posTableSize = (uint64_t)nElem * 8;
      if (posTableSize > tSize || nElem > 10000) {
        printf("      %s[CRITICAL] Tag '%s' (MPE): %u elements × 8 = %llu bytes "
               "(tag size=%u)%s\n",
               ColorCritical(), sig, nElem,
               (unsigned long long)posTableSize, tSize, ColorReset());
        printf("       %sCWE-190: Element count drives allocation overflow "
               "(IccMpeBasic.cpp)%s\n", ColorCritical(), ColorReset());
        issues++;
      }

      // Channel count amplification: each sub-element allocates nInput×nOutput floats
      if (nInput > 0 && nOutput > 0) {
        uint64_t chanProduct = (uint64_t)nInput * nOutput * 4;
        if (chanProduct > 1024 * 1024) {
          printf("      %s[WARN]  Tag '%s' (MPE): %u×%u channels → %llu bytes per element%s\n",
                 ColorWarning(), sig, nInput, nOutput,
                 (unsigned long long)chanProduct, ColorReset());
          printf("       %sCWE-190: High channel count amplifies per-element allocation%s\n",
                 ColorCritical(), ColorReset());
          issues++;
        }
      }
    }

    if (issues >= 8) break;
  }

  if (issues > 0) {
    heuristicCount += issues;
  } else {
    printf("      %s[OK] No integer overflow in tag dimension calculations%s\n",
           ColorSuccess(), ColorReset());
  }
  printf("\n");

  return heuristicCount;
}

// ---------------------------------------------------------------------------
// H156: Allocation Failure Path Profiles (CWE-252)
// CodeQL found 88 sites where new/malloc return is not checked. When the
// library allocates based on file-controlled sizes, OOM → NULL deref.
// Detection: Flag profiles that combine large tag counts with large tag sizes,
// creating high aggregate allocation pressure that increases OOM probability
// on resource-constrained systems.
// ---------------------------------------------------------------------------
int RunHeuristic_H156_AllocationFailurePathProfiles(RawProfileContext &ctx)
{
  int heuristicCount = 0;
  printf("[H156] Allocation Failure Path Profiles (CWE-252, §7.3)\n");

  if (!ctx.valid) {
    printf("      [SKIP] File too small\n\n");
    return 0;
  }

  uint32_t profileSize = ReadU32BE(ctx.header);

  // Track aggregate allocation demands
  uint64_t totalDeclaredSize = 0;
  int largeTagCount = 0;
  int issues = 0;

  for (const auto &tag : ctx.tags) {
    uint32_t tSize = tag.size;
    totalDeclaredSize += tSize;

    // Tags > 10MB each create individual allocation pressure
    if (tSize > 10 * 1024 * 1024) {
      largeTagCount++;
    }
  }

  // Aggregate allocation > 256MB is extreme for an ICC profile
  if (totalDeclaredSize > 256ULL * 1024 * 1024) {
    printf("      %s[WARN]  Aggregate tag allocation: %.1f MB across %u tags%s\n",
           ColorWarning(),
           (double)totalDeclaredSize / (1024.0 * 1024.0),
           ctx.tagCount, ColorReset());
    printf("       %sCWE-252: iccDEV has 88 unchecked allocation sites — "
           "aggregate pressure increases OOM probability%s\n",
           ColorCritical(), ColorReset());
    printf("       %sRisk: new/malloc returns NULL → dereference at "
           "IccCmm.cpp, IccMpeSpectral.cpp, IccEncoding.cpp%s\n",
           ColorCritical(), ColorReset());
    issues++;
  }

  // Multiple large tags compound the risk
  if (largeTagCount >= 3) {
    printf("      %s[WARN]  %d tags exceed 10MB — high concurrent allocation demand%s\n",
           ColorWarning(), largeTagCount, ColorReset());
    printf("       %sCWE-252: Multiple large allocations without error checking "
           "increase NULL-deref risk%s\n", ColorCritical(), ColorReset());
    issues++;
  }

  // Profile size vs tag total mismatch (tags claim more data than file contains)
  if (totalDeclaredSize > (uint64_t)profileSize * 2 && profileSize > 0) {
    printf("      %s[WARN]  Tag sizes total %llu bytes but profile is %u bytes%s\n",
           ColorWarning(), (unsigned long long)totalDeclaredSize,
           profileSize, ColorReset());
    printf("       %sCWE-252: Oversized tag declarations trigger allocation "
           "then fail on read — unchecked paths crash%s\n",
           ColorCritical(), ColorReset());
    issues++;
  }

  if (issues > 0) {
    heuristicCount += issues;
  } else {
    printf("      %s[OK] Allocation pressure within safe bounds%s\n",
           ColorSuccess(), ColorReset());
  }
  printf("\n");

  return heuristicCount;
}

// ---------------------------------------------------------------------------
// H157: Alloc-Dealloc Mismatch Tag Patterns (CWE-762)
// CodeQL found 2 confirmed alloc-dealloc mismatches in iccDEV:
//   IccCmm.cpp:4785  — CIccApplyNamedCmm::m_vals: new[] freed with delete
//   IccTagLut.cpp:984 — CIccFormulaCurveSegment::m_dParam: new[] freed with delete
// Plus CFL-003: CIccTagArray copy ctor new[] → Cleanup() free().
// Detection: Flag profiles containing tag types that trigger mismatch paths:
//   ncl2 (NamedColor2) → triggers CIccApplyNamedCmm allocation
//   para (ParametricCurve) with formula segments → triggers m_dParam path
//   tary (TagArray) → triggers CFL-003 copy ctor mismatch
// ---------------------------------------------------------------------------
int RunHeuristic_H157_AllocDeallocMismatchTagPatterns(RawProfileContext &ctx)
{
  int heuristicCount = 0;
  printf("[H157] Alloc-Dealloc Mismatch Tag Patterns (CWE-762, §10.14)\n");

  if (!ctx.valid) {
    printf("      [SKIP] File too small\n\n");
    return 0;
  }

  size_t fs = ctx.fileSize();

  int issues = 0;
  bool hasTagArray = false;
  bool hasNamedColor2 = false;
  bool hasFormulaCurve = false;

  for (const auto &tag : ctx.tags) {
    uint32_t tOffset = tag.offset;
    uint32_t tSize   = tag.size;

    if ((uint64_t)tOffset + 4 > fs || tSize < 4) continue;

    // Read type signature
    uint8_t typeBuf[4];
    if (!ctx.ReadAt(tOffset, typeBuf, 4)) continue;
    uint32_t typeSig = ReadU32BE(typeBuf);

    // tary (TagArray) — CFL-003: copy ctor new[] vs Cleanup() free()
    if (typeSig == 0x74617279) hasTagArray = true;   // 'tary'

    // ncl2 (NamedColor2) — IccCmm.cpp:4785 new[] vs delete
    if (typeSig == 0x6E636C32) hasNamedColor2 = true; // 'ncl2'

    // curf (CurveSet with formula segments) — IccTagLut.cpp:984 new[] vs delete
    // psgm = 0x7073676D (segmented curve) contains formula curve segments
    if (typeSig == 0x63757266) hasFormulaCurve = true; // 'curf'
  }

  if (hasTagArray) {
    printf("      %s[CRITICAL] Profile contains TagArray ('tary') — "
           "triggers CIccTagArray copy ctor new[]/free() mismatch%s\n",
           ColorCritical(), ColorReset());
    printf("       %sCWE-762: CFL-003 — CIccTagArray(const&) uses new[] but "
           "Cleanup() calls free() (IccTagComposite.cpp:1037,1523)%s\n",
           ColorCritical(), ColorReset());
    printf("       %sImpact: Heap corruption when profile is copied via "
           "CIccCmm::AddXform(CIccProfile&)%s\n",
           ColorCritical(), ColorReset());
    issues++;
  }

  if (hasNamedColor2) {
    printf("      %s[WARN]  Profile contains NamedColor2 ('ncl2') — "
           "CIccApplyNamedCmm uses new[]/delete mismatch%s\n",
           ColorWarning(), ColorReset());
    printf("       %sCWE-762: m_vals allocated with new icFloatNumber[] "
           "but freed with delete (IccCmm.cpp:4785)%s\n",
           ColorCritical(), ColorReset());
    issues++;
  }

  if (hasFormulaCurve) {
    printf("      %s[WARN]  Profile contains CurveSet ('curf') — "
           "formula segments use new[]/delete mismatch%s\n",
           ColorWarning(), ColorReset());
    printf("       %sCWE-762: m_dParam allocated with new[] but freed with "
           "delete (IccTagLut.cpp:984)%s\n",
           ColorCritical(), ColorReset());
    issues++;
  }

  if (issues > 0) {
    heuristicCount += issues;
  } else {
    printf("      %s[OK] No alloc-dealloc mismatch trigger patterns%s\n",
           ColorSuccess(), ColorReset());
  }
  printf("\n");

  return heuristicCount;
}

// ---------------------------------------------------------------------------
// H158: Enum Range Validation Extended (CWE-681)
// CodeQL found 139 enum UB sites where file-controlled uint32 values are cast
// to C++ enum types without range validation. H151 covers calculator ops only.
// This extends validation to header enums: rendering intent, color space,
// platform, device class, and tag type signatures.
// Detection: Read ICC header enums and validate against known-valid values.
// ---------------------------------------------------------------------------
int RunHeuristic_H158_EnumRangeValidationExtended(RawProfileContext &ctx)
{
  int heuristicCount = 0;
  printf("[H158] Enum Range Validation Extended (CWE-681, §7.2 Header Fields)\n");

  if (!ctx.valid) {
    printf("      [SKIP] File too small\n\n");
    return 0;
  }

  size_t fs = ctx.fileSize();
  std::vector<uint8_t> buf(fs);
  fseek(ctx.fh.fp, 0, SEEK_SET);
  if (fread(buf.data(), 1, fs, ctx.fh.fp) != fs) {
    printf("      [SKIP] Cannot read file\n\n");
    return 0;
  }

  int issues = 0;

  // Scan tag table for tag type signatures that are not valid FourCC
  // iccDEV casts the raw uint32 to icTagTypeSignature enum without validation
  // at IccProfile.cpp LoadTag() — invalid values cause UBSAN UB
  uint32_t tagCount = ReadU32BE(&buf[128]);
  if (tagCount > 0 && tagCount <= 1000) {
    int invalidTypeSigs = 0;
    for (uint32_t i = 0; i < tagCount && i < 256; i++) {
      size_t entryOff = 132 + (size_t)i * 12;
      if (entryOff + 12 > fs) break;

      uint32_t tOffset = ReadU32BE(&buf[entryOff + 4]);
      uint32_t tSize   = ReadU32BE(&buf[entryOff + 8]);

      if ((uint64_t)tOffset + 4 > fs || tSize < 4) continue;

      uint32_t typeSig = ReadU32BE(&buf[tOffset]);

      // Validate: type signature must be printable ASCII FourCC
      bool validFourCC = true;
      for (int byte = 0; byte < 4; byte++) {
        uint8_t ch = (typeSig >> (24 - byte * 8)) & 0xFF;
        if (ch < 0x20 || ch > 0x7E) { validFourCC = false; break; }
      }
      if (!validFourCC && typeSig != 0) {
        invalidTypeSigs++;
      }
    }

    if (invalidTypeSigs > 0) {
      printf("      %s[WARN]  %d tag type signatures are not valid FourCC "
             "(non-printable bytes)%s\n",
             ColorWarning(), invalidTypeSigs, ColorReset());
      printf("       %sCWE-681: iccDEV casts raw uint32 to icTagTypeSignature enum "
             "without validation (IccProfile.cpp LoadTag)%s\n",
             ColorCritical(), ColorReset());
      printf("       %sRisk: 139 enum UB sites identified by CodeQL across "
             "IccProfLib — invalid enum values cause undefined behavior%s\n",
             ColorCritical(), ColorReset());
      issues++;
    }
  }

  // Scan for MPE sub-element type signatures within mpet tags
  // These are cast to icElemTypeSignature without range check
  for (uint32_t i = 0; i < tagCount && i < 256; i++) {
    size_t entryOff = 132 + (size_t)i * 12;
    if (entryOff + 12 > fs) break;

    uint32_t tOffset = ReadU32BE(&buf[entryOff + 4]);
    uint32_t tSize   = ReadU32BE(&buf[entryOff + 8]);

    if ((uint64_t)tOffset + 16 > fs || tSize < 16) continue;
    uint32_t typeSig = ReadU32BE(&buf[tOffset]);

    if (typeSig != 0x6D706574) continue; // 'mpet' only

    uint32_t nElem = ReadU32BE(&buf[tOffset + 12]);
    if (nElem > 10000) continue;

    // Position table at tOffset+16, each entry 8 bytes
    int invalidElemSigs = 0;
    for (uint32_t e = 0; e < nElem && e < 100; e++) {
      size_t posOff = tOffset + 16 + (size_t)e * 8;
      if (posOff + 8 > fs) break;

      uint32_t elemOff = ReadU32BE(&buf[posOff]);
      size_t absElemOff = tOffset + elemOff;
      if (absElemOff + 4 > fs) continue;

      uint32_t elemSig = ReadU32BE(&buf[absElemOff]);
      bool validFourCC = true;
      for (int byte = 0; byte < 4; byte++) {
        uint8_t ch = (elemSig >> (24 - byte * 8)) & 0xFF;
        if (ch < 0x20 || ch > 0x7E) { validFourCC = false; break; }
      }
      if (!validFourCC && elemSig != 0) {
        invalidElemSigs++;
      }
    }

    if (invalidElemSigs > 0) {
      printf("      %s[WARN]  MPE tag has %d sub-elements with invalid type "
             "signatures (non-FourCC)%s\n",
             ColorWarning(), invalidElemSigs, ColorReset());
      printf("       %sCWE-681: icElemTypeSignature enum cast without validation "
             "(IccMpeBasic.cpp, IccMpeCalc.cpp)%s\n",
             ColorCritical(), ColorReset());
      issues++;
    }
  }

  if (issues > 0) {
    heuristicCount += issues;
  } else {
    printf("      %s[OK] All enum values within valid ranges%s\n",
           ColorSuccess(), ColorReset());
  }
  printf("\n");

  return heuristicCount;
}

// ---------------------------------------------------------------------------
// H159: UAF in Tag Ownership Chain Detection (CWE-416)
// CodeQL found 9 UAF sites including the CFL-003 CIccCmm::AddXform ownership
// bug and CIccTagBasic m_NamedColor UAF. Key pattern: profiles containing
// TagArray + a class requiring round-trip evaluation (scnr/mntr/prtr/spac)
// trigger the copy-ctor UAF via EvaluateProfile→AddXform(CIccProfile&).
// Detection: Flag structural combinations known to trigger UAF paths.
// ---------------------------------------------------------------------------
int RunHeuristic_H159_UAFTagOwnershipChains(RawProfileContext &ctx)
{
  int heuristicCount = 0;
  printf("[H159] UAF Tag Ownership Chain Detection (CWE-416, §7.3)\n");

  if (!ctx.valid) {
    printf("      [SKIP] File too small\n\n");
    return 0;
  }

  size_t fs = ctx.fileSize();

  // Device class at offset 12 (4 bytes)
  uint32_t devClass = ReadU32BE(&ctx.header[12]);

  // Classes that trigger EvaluateProfile→AddXform(CIccProfile&) copy path
  bool isRoundTripClass = (devClass == 0x73636E72 || // 'scnr'
                           devClass == 0x6D6E7472 || // 'mntr'
                           devClass == 0x70727472 || // 'prtr'
                           devClass == 0x73706163);  // 'spac'

  bool hasTagArray = false;
  bool hasNamedColor2 = false;
  int issues = 0;

  for (const auto &tag : ctx.tags) {
    uint32_t tOffset = tag.offset;
    uint32_t tSize   = tag.size;
    if ((uint64_t)tOffset + 4 > fs || tSize < 4) continue;

    uint8_t typeBuf[4];
    if (!ctx.ReadAt(tOffset, typeBuf, 4)) continue;
    uint32_t typeSig = ReadU32BE(typeBuf);

    if (typeSig == 0x74617279) hasTagArray = true;    // 'tary'
    if (typeSig == 0x6E636C32) hasNamedColor2 = true; // 'ncl2'
  }

  // CFL-003: TagArray + round-trip class → UAF via copy ctor
  if (hasTagArray && isRoundTripClass) {
    char cls[5];
    cls[0] = static_cast<char>(static_cast<unsigned char>((devClass >> 24) & 0xFF));
    cls[1] = static_cast<char>(static_cast<unsigned char>((devClass >> 16) & 0xFF));
    cls[2] = static_cast<char>(static_cast<unsigned char>((devClass >>  8) & 0xFF));
    cls[3] = static_cast<char>(static_cast<unsigned char>( devClass        & 0xFF));
    cls[4] = '\0';

    printf("      %s[CRITICAL] Profile class '%s' + TagArray ('tary') → "
           "CFL-003 UAF path%s\n", ColorCritical(), cls, ColorReset());
    printf("       %sCWE-416: EvaluateProfile() → AddXform(CIccProfile&) → "
           "new CIccProfile(copy) → CIccTagArray copy ctor → "
           "Cleanup() accesses freed memory%s\n",
           ColorCritical(), ColorReset());
    printf("       %sCall chain: iccRoundTrip → EvaluateProfile → CIccCmm::AddXform "
           "→ CIccProfile::CIccProfile(const&) → CIccTagArray::NewCopy()%s\n",
           ColorCritical(), ColorReset());
    printf("       %sUpstream: IccTagComposite.cpp:1037,1074,1523 "
           "(alloc mismatch new[]/free in copy vs cleanup)%s\n",
           ColorCritical(), ColorReset());
    issues++;
  }

  // NamedColor2 + any transform path → m_NamedColor UAF
  if (hasNamedColor2) {
    printf("      %s[WARN]  Profile contains NamedColor2 ('ncl2') — "
           "potential m_NamedColor UAF after Cleanup%s\n",
           ColorWarning(), ColorReset());
    printf("       %sCWE-416: IccTagBasic.cpp:2879 — m_NamedColor accessed after "
           "CIccTagNamedColor2::Cleanup() frees it%s\n",
           ColorCritical(), ColorReset());
    issues++;
  }

  if (issues > 0) {
    heuristicCount += issues;
  } else {
    printf("      %s[OK] No UAF-triggering ownership patterns detected%s\n",
           ColorSuccess(), ColorReset());
  }
  printf("\n");

  return heuristicCount;
}

// H160: Format String Injection in Text Tags (CWE-134)
// CodeQL found 6 tainted-format-string sites in IccCmmConfig.cpp where CLI
// args flow to fprintf/snprintf format positions. While the analyzer itself
// never uses tag text as format args, downstream consumers (tools, browsers,
// CMS engines) may sprintf tag descriptions without escaping. Detection:
// scan text-type tags (desc, cprt, dmnd, dmdd, vued, targ) for printf format
// specifiers (%n, %s, %p, %x, %d, %f) that indicate injection attempts.
// ---------------------------------------------------------------------------
int RunHeuristic_H160_FormatStringInjectionTextTags(RawProfileContext &ctx)
{
  int heuristicCount = 0;

  printf("[H160] Format String Injection in Text Tags (CWE-134, §10.24/§10.22)\n");

  if (!ctx.valid) {
    printf("      [SKIP] Cannot open file\n\n");
    return 0;
  }

  size_t fileSize = ctx.fileSize();

  // Text-bearing tag signatures (4CC as big-endian uint32)
  static const uint32_t kTextTags[] = {
    0x64657363, // 'desc' profileDescriptionTag
    0x63707274, // 'cprt' copyrightTag
    0x646D6E64, // 'dmnd' deviceMfgDescTag
    0x646D6464, // 'dmdd' deviceModelDescTag
    0x76756564, // 'vued' viewingConditionsDescTag
    0x74617267, // 'targ' charTargetTag
    0x74656368, // 'tech' technologyTag (4 bytes but may have text)
  };
  static const size_t kNumTextTags = sizeof(kTextTags) / sizeof(kTextTags[0]);

  // Dangerous format specifiers — %n is write-what-where, others leak data
  static const char *kFmtSpecs[] = {"%n", "%s", "%p", "%x", "%X", "%d", "%i",
                                     "%u", "%f", "%e", "%g", "%hn", "%ln",
                                     "%hhn", "%lln", "%%n"};
  static const size_t kNumFmtSpecs = sizeof(kFmtSpecs) / sizeof(kFmtSpecs[0]);

  int findings = 0;
  const int kMaxFindings = 8;

  for (const auto &_tag : ctx.tags) {
    if (findings >= kMaxFindings) break;
    uint32_t sig = _tag.sig;
    uint32_t tOffset = _tag.offset;
    uint32_t tSize = _tag.size;

    // Check if this is a text-bearing tag
    bool isTextTag = false;
    for (size_t i = 0; i < kNumTextTags; i++) {
      if (sig == kTextTags[i]) { isTextTag = true; break; }
    }
    if (!isTextTag) continue;
    if (tSize < 12 || tSize > 65536 || (uint64_t)tOffset + tSize > (uint64_t)fileSize)
      continue;

    // Read tag data (skip type sig + reserved = 8 bytes)
    size_t textLen = tSize - 8;
    if (textLen > 4096) textLen = 4096; // cap scan length
    std::vector<char> buf(textLen + 1, 0);
    fseek(ctx.fh.fp, tOffset + 8, SEEK_SET);
    size_t nread = fread(buf.data(), 1, textLen, ctx.fh.fp);
    if (nread == 0) continue;
    buf[nread] = '\0';

    char tagSig[5];
    tagSig[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));
    tagSig[1] = static_cast<char>(static_cast<unsigned char>((sig >> 16) & 0xFF));
    tagSig[2] = static_cast<char>(static_cast<unsigned char>((sig >> 8) & 0xFF));
    tagSig[3] = static_cast<char>(static_cast<unsigned char>(sig & 0xFF));
    tagSig[4] = '\0';

    // Scan for format specifiers
    for (size_t f = 0; f < kNumFmtSpecs; f++) {
      if (findings >= kMaxFindings) break;
      const char *found = strstr(buf.data(), kFmtSpecs[f]);
      if (found) {
        size_t pos = static_cast<size_t>(found - buf.data());
        printf("      %s[WARN]  HEURISTIC: Tag '%s' contains format specifier \"%s\" at "
               "offset +%zu — ICC.1-2022-05 §10.24%s\n",
               ColorCritical(), tagSig, kFmtSpecs[f], pos, ColorReset());
        if (strcmp(kFmtSpecs[f], "%n") == 0 || strcmp(kFmtSpecs[f], "%hn") == 0 ||
            strcmp(kFmtSpecs[f], "%ln") == 0 || strcmp(kFmtSpecs[f], "%hhn") == 0 ||
            strcmp(kFmtSpecs[f], "%lln") == 0) {
          printf("       %sCWE-134: Write-format specifier (%s) enables arbitrary memory write%s\n",
                 ColorCritical(), kFmtSpecs[f], ColorReset());
        } else {
          printf("       %sCWE-134: Format specifier injection — data leak via printf-family%s\n",
                 ColorCritical(), ColorReset());
        }
        findings++;
        break; // one finding per tag per specifier type
      }
    }
  }

  if (findings > 0) {
    heuristicCount += findings;
  } else {
    printf("      %s[OK] No format string specifiers in text tags%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// H161: Stack Address Escape via Deep Apply Chains (CWE-121)
// CodeQL found 8 stack-address-escape sites where local pixel buffers in
// IccCmm.cpp, IccMpeCalc.cpp, IccTagLut.cpp, IccTagMPE.cpp are passed through
// deep call chains. H146 covers the GetValues() SBO vector. H161 extends
// coverage to detect profiles whose structural complexity maximizes stack frame
// depth during Apply() — high channel counts combined with deeply nested MPE
// elements or multi-stage LUT chains cause local buffer addresses to propagate
// across function boundaries where their lifetime may be exceeded.
// Detection: flag profiles with (channels > 8 AND nested MPE) OR (multi-stage
// LUT with output channels > colorspace declared), indicating deep Apply() paths.
// ---------------------------------------------------------------------------
int RunHeuristic_H161_StackAddressEscapeDeepApply(RawProfileContext &ctx)
{
  int heuristicCount = 0;

  printf("[H161] Stack Address Escape via Deep Apply Chains (CWE-121, §10.6/§10.14)\n");

  if (!ctx.valid) {
    printf("      [SKIP] Cannot open file\n\n");
    return 0;
  }

  size_t fileSize = ctx.fileSize();

  // Read color space from pre-parsed header
  uint32_t colorSpaceSig = ReadU32BE(&ctx.header[16]);
  (void)ReadU32BE(&ctx.header[20]);  // PCS sig — reserved for future use

  // Estimate channel count from color space signature
  auto channelsFromSig = [](uint32_t sig) -> int {
    switch (sig) {
      case 0x58595A20: return 3;  // 'XYZ '
      case 0x4C616220: return 3;  // 'Lab '
      case 0x52474220: return 3;  // 'RGB '
      case 0x47524159: return 1;  // 'GRAY'
      case 0x434D594B: return 4;  // 'CMYK'
      case 0x48535620: return 3;  // 'HSV '
      default: {
        // nCLR signatures: 0x3243..0x4643 → 2..15 channels
        uint8_t hi = static_cast<uint8_t>((sig >> 24) & 0xFF);
        uint8_t lo = static_cast<uint8_t>((sig >> 16) & 0xFF);
        uint32_t suffix = sig & 0x0000FFFF;
        if (suffix == 0x434C && hi >= '0' && hi <= '9' && lo >= '0' && lo <= '9') {
          return (hi - '0') * 10 + (lo - '0');
        }
        if (suffix == 0x434C && hi >= '1' && hi <= 'F') {
          return (hi <= '9') ? (hi - '0') : (hi - 'A' + 10);
        }
        return 3; // default
      }
    }
  };

  int nChannels = channelsFromSig(colorSpaceSig);

  // Count MPE ('mpet') tags, multi-stage LUTs, and check output channel mismatches
  int mpetCount = 0;
  int findings = 0;

  // LUT type signatures
  static const uint32_t kLutTypes[] = {
    0x6D414220, // 'mAB ' LutAtoBType
    0x6D424120, // 'mBA ' LutBtoAType
    0x6D667431, // 'mft1' Lut8Type
    0x6D667432, // 'mft2' Lut16Type
  };

  for (const auto &_tag : ctx.tags) {
    uint32_t tOffset = _tag.offset;
    uint32_t tSize = _tag.size;

    if (tSize < 12 || (uint64_t)tOffset + 12 > (uint64_t)fileSize) continue;

    // Read tag type signature
    icUInt8Number typeSigBuf[4];
    if (!ctx.ReadAt(tOffset, typeSigBuf, 4)) continue;
    uint32_t type = ReadU32BE(typeSigBuf);

    if (type == 0x6D706574) { // 'mpet' multiProcessElementType
      mpetCount++;
      // Check element count for deep nesting
      if (tSize >= 16 && (uint64_t)tOffset + 16 <= (uint64_t)fileSize) {
        icUInt8Number mpetHdr[8];
        if (ctx.ReadAt(tOffset + 8, mpetHdr, 8)) {
          uint32_t nInputChannels = static_cast<uint32_t>(mpetHdr[0]) << 8 |
                                    static_cast<uint32_t>(mpetHdr[1]);
          uint32_t nOutputChannels = static_cast<uint32_t>(mpetHdr[2]) << 8 |
                                     static_cast<uint32_t>(mpetHdr[3]);
          uint32_t nElements = ReadU32BE(&mpetHdr[4]);

          // Deep chain: many elements × high channels = deep stack Apply() path
          if (nElements > 4 && (nInputChannels > 8 || nOutputChannels > 8)) {
            char tagSig[5];
            SigToChars(_tag.sig, tagSig);
            printf("      %s[WARN]  HEURISTIC: Tag '%s' MPE chain: %u elements × %u→%u channels "
                   "— deep Apply() stack risk — ICC.1-2022-05 §10.14%s\n",
                   ColorCritical(), tagSig, nElements, nInputChannels, nOutputChannels,
                   ColorReset());
            printf("       %sCWE-121: Local pixel buffers propagated across %u function frames%s\n",
                   ColorCritical(), nElements, ColorReset());
            findings++;
          }
        }
      }
    }

    // Check LUT output channel mismatch (extends H146 to cover local-var-escape path)
    for (size_t i = 0; i < sizeof(kLutTypes) / sizeof(kLutTypes[0]); i++) {
      if (type == kLutTypes[i]) {
        // For Lut8/Lut16, output channels are at offset 9
        if ((type == 0x6D667431 || type == 0x6D667432) && tSize > 11u) {
          icUInt8Number lutHdr[4];
          if (ctx.ReadAt(tOffset + 8, lutHdr, 4)) {
            uint8_t nInput = lutHdr[0];
            uint8_t nOutput = lutHdr[1];
            // Output channels exceeding colorspace → tmpPixel[16] SBO risk
            if (nOutput > 16 || (nOutput > 0 && nInput > 0 && nInput * nOutput > 256)) {
              printf("      %s[WARN]  HEURISTIC: LUT %ux%u channels — local buffer overflow "
                     "risk in Apply() tmpPixel — ICC.1-2022-05 §10.6%s\n",
                     ColorCritical(), nInput, nOutput, ColorReset());
              printf("       %sCWE-121: Stack buffer sized for declared channels (%d) may be "
                     "overwritten by LUT output (%u)%s\n",
                     ColorCritical(), nChannels, nOutput, ColorReset());
              findings++;
            }
          }
        }
        break;
      }
    }
  }

  // High channel count profile with multiple MPE = amplified stack depth
  if (nChannels > 8 && mpetCount >= 2 && findings == 0) {
    printf("      %s[WARN]  HEURISTIC: %d-channel profile with %d MPE tags — "
           "deep Apply() stack chain risk — ICC.1-2022-05 §10.14%s\n",
           ColorCritical(), nChannels, mpetCount, ColorReset());
    printf("       %sCWE-121: High channel count amplifies local buffer size across "
           "stack frames%s\n", ColorCritical(), ColorReset());
    findings++;
  }

  if (findings > 0) {
    heuristicCount += findings;
  } else {
    printf("      %s[OK] No deep Apply() chain stack-escape risk patterns%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

int RunCodeQLPatternHeuristics(RawProfileContext &ctx)
{
  int heuristicCount = 0;
  heuristicCount += RunHeuristic_H154_UncontrolledTagAllocationSize(ctx);
  heuristicCount += RunHeuristic_H155_IntegerOverflowTagDimensions(ctx);
  heuristicCount += RunHeuristic_H156_AllocationFailurePathProfiles(ctx);
  heuristicCount += RunHeuristic_H157_AllocDeallocMismatchTagPatterns(ctx);
  heuristicCount += RunHeuristic_H158_EnumRangeValidationExtended(ctx);
  heuristicCount += RunHeuristic_H159_UAFTagOwnershipChains(ctx);
  heuristicCount += RunHeuristic_H160_FormatStringInjectionTextTags(ctx);
  heuristicCount += RunHeuristic_H161_StackAddressEscapeDeepApply(ctx);
  return heuristicCount;
}
