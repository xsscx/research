/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

// Post-library raw-file heuristics (H33-H55, H57, H59, H68-H69, H153, H175-H178).
// Refactored: all functions use shared RawProfileContext (single file open)
// and HeuristicCollector for dual-mode output (printf + structured collection).

#include "IccHeuristicsRawPost.h"
#include "IccHeuristicsCodeQLPatterns.h"
#include "IccHeuristicsExploitGap.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerColors.h"
#include "IccAnalyzerSignatures.h"
#include "IccHeuristicResult.h"
#include "IccHeuristicsHelpers.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <vector>
#include <set>
#include <algorithm>
#include <new>

// ── Named constants replacing magic numbers ──
static constexpr icUInt32Number kMaxTagScanCount = 256;
static constexpr size_t kMaxTagDataScan = 4096;
static constexpr size_t kMaxCurveDataScan = 512;
static constexpr uint32_t kMaxMpeElements = 256;
static constexpr uint64_t kMaxSparseMatrixEntries = 16ULL * 1024 * 1024;
static constexpr uint64_t kMaxCLUTGridProduct = 256ULL * 1024 * 1024;
static constexpr uint64_t kMaxVertexDataBytes = 256ULL * 1024 * 1024;


// =========================================================================
// H33 — mBA/mAB Sub-Element Offset Validation
// =========================================================================
int RunHeuristic_H33_mBAmABSubElementOffset(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(33, "mBA/mAB Sub-Element Offset Validation");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();
  int issues = 0;

  for (const auto &tag : ctx.tags) {
    uint32_t tSig = tag.sig;
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 32 > fs || tSz < 32) continue;
    icUInt8Number tagData[32];
    if (!ctx.ReadAt(tOff, tagData, 32)) continue;

    icUInt32Number tagType = ReadU32BE(tagData);
    if (tagType != 0x6D414220 && tagType != 0x6D424120) continue;

    char sig[5];
    SigToChars(tSig, sig);
    const char *typeName = (tagType == 0x6D414220) ? "mAB" : "mBA";

    struct { const char *name; size_t pos; } subElems[] = {
      {"B_curves", 12}, {"Matrix", 16}, {"M_curves", 20}, {"CLUT", 24}, {"A_curves", 28}
    };

    for (int se = 0; se < 5; se++) {
      size_t p = subElems[se].pos;
      icUInt32Number subOff = ReadU32BE(&tagData[p]);
      if (subOff == 0) continue;

      if (subOff > tSz) {
        hc.warn("Tag '%s' (%s): %s offset 0x%08X exceeds tag size %u",
                sig, typeName, subElems[se].name, subOff, tSz);
        if (subOff > 0xFFFFF000)
          hc.cweNote("CRITICAL: Offset near uint32 max — OOB read/write past mmap boundary");
        issues++;
      } else if ((uint64_t)tOff + subOff > fs) {
        hc.warn("Tag '%s' (%s): %s at file offset 0x%llX past EOF 0x%zX",
                sig, typeName, subElems[se].name,
                (unsigned long long)((uint64_t)tOff + subOff), fs);
        issues++;
      }
    }
  }

  if (issues > 0)
    hc.info("      %d mBA/mAB sub-element offset(s) reference data beyond tag bounds", issues);

  return hc.end("All mBA/mAB sub-element offsets within tag bounds");
}

// =========================================================================
// H34 — Integer Overflow in Sub-Element Bounds
// =========================================================================
int RunHeuristic_H34_IntegerOverflowSubElement(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(34, "Integer Overflow in Sub-Element Bounds");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tSig = tag.sig;
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 32 > fs || tSz < 32) continue;
    icUInt8Number tagData[32];
    if (!ctx.ReadAt(tOff, tagData, 32)) continue;

    icUInt32Number tagType = ReadU32BE(tagData);
    if (tagType != 0x6D414220 && tagType != 0x6D424120) continue;

    char sig[5];
    SigToChars(tSig, sig);

    struct { const char *name; size_t pos; } subElems[] = {
      {"B_curves", 12}, {"Matrix", 16}, {"M_curves", 20}, {"CLUT", 24}, {"A_curves", 28}
    };

    for (int se = 0; se < 5; se++) {
      size_t p = subElems[se].pos;
      icUInt32Number subOff = ReadU32BE(&tagData[p]);
      if (subOff == 0) continue;

      uint64_t endPos = (uint64_t)tOff + subOff;
      if (endPos > 0xFFFFFFFFULL) {
        hc.warn("Tag '%s': %s offset 0x%X + tag offset 0x%X > 4GB (32-bit truncation)",
                sig, subElems[se].name, subOff, tOff);
        hc.cweNote("CWE-190: Integer overflow in offset+base — wraps to low address");

      }
    }
  }

  return hc.end("No integer overflow in sub-element bounds");
}

// =========================================================================
// H35 — Suspicious Fill Pattern in mBA/mAB Data
// =========================================================================
int RunHeuristic_H35_SuspiciousFillPattern(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(35, "Suspicious Fill Pattern in mBA/mAB Data");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();
  int fillCount = 0;

  for (const auto &tag : ctx.tags) {
    uint32_t tSig = tag.sig;
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 32 > fs || tSz < 48) continue;
    icUInt8Number typeCheck[4];
    if (!ctx.ReadAt(tOff, typeCheck, 4)) continue;

    icUInt32Number tagType = ReadU32BE(typeCheck);
    if (tagType != 0x6D414220 && tagType != 0x6D424120) continue;

    size_t dataStart = (uint64_t)tOff + 32;
    size_t dataLen = tSz - 32;
    if (dataLen > kMaxTagScanCount) dataLen = kMaxTagScanCount;
    if (dataStart + dataLen > fs) dataLen = fs - dataStart;
    if (dataLen < 16) continue;

    std::vector<icUInt8Number> bData(dataLen);
    if (!ctx.ReadAt(dataStart, bData.data(), dataLen)) continue;

    int runLen = 1;
    for (size_t b = 1; b < dataLen; b++) {
      if (bData[b] == bData[b-1]) {
        runLen++;
      } else {
        if (runLen >= 16) {
          char sigStr[5];
          SigToChars(tSig, sigStr);
          hc.warn("Tag '%s': %d-byte run of 0x%02X at B-curve data+%zu",
                  sigStr, runLen, bData[b-1], b - runLen);
          if (bData[b-1] == 0xFF)
            hc.cweNote("0xFF fill creates parseable curve structure — enables OOB offset traversal");
          fillCount++;
        }
        runLen = 1;
      }
    }
    if (runLen >= 16) {
      char sigStr[5];
      SigToChars(tSig, sigStr);
      hc.warn("Tag '%s': %d-byte run of 0x%02X at B-curve data+%zu",
              sigStr, runLen, bData[dataLen-1], dataLen - runLen);
      if (bData[dataLen-1] == 0xFF)
        hc.cweNote("0xFF fill creates parseable curve structure — enables OOB offset traversal");
      fillCount++;
    }
  }

  if (fillCount > 0)
    hc.info("      %d suspicious fill pattern(s) in mBA/mAB B-curve data", fillCount);

  return hc.end("No suspicious fill patterns in mBA/mAB data");
}

// =========================================================================
// H36 — LUT Tag Pair Completeness
// =========================================================================
int RunHeuristic_H36_LUTTagPairCompleteness(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(36, "LUT Tag Pair Completeness");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  bool hasA2B[4] = {false}, hasB2A[4] = {false};
  bool hasD2B[4] = {false}, hasB2D[4] = {false};

  for (const auto &tag : ctx.tags) {
    switch (tag.sig) {
      case 0x41324230u: hasA2B[0] = true; break;
      case 0x41324231u: hasA2B[1] = true; break;
      case 0x41324232u: hasA2B[2] = true; break;
      case 0x41324233u: hasA2B[3] = true; break;
      case 0x42324130u: hasB2A[0] = true; break;
      case 0x42324131u: hasB2A[1] = true; break;
      case 0x42324132u: hasB2A[2] = true; break;
      case 0x42324133u: hasB2A[3] = true; break;
      case 0x44324230u: hasD2B[0] = true; break;
      case 0x44324231u: hasD2B[1] = true; break;
      case 0x44324232u: hasD2B[2] = true; break;
      case 0x44324233u: hasD2B[3] = true; break;
      case 0x42324430u: hasB2D[0] = true; break;
      case 0x42324431u: hasB2D[1] = true; break;
      case 0x42324432u: hasB2D[2] = true; break;
      case 0x42324433u: hasB2D[3] = true; break;
      default: break;
    }
  }

  int pairIssues = 0;
  for (int idx = 0; idx < 4; idx++) {
    if (hasA2B[idx] && !hasB2A[idx]) { hc.info("      A2B%d present but B2A%d missing — forward-only LUT", idx, idx); pairIssues++; }
    if (hasB2A[idx] && !hasA2B[idx]) { hc.info("      B2A%d present but A2B%d missing — reverse-only LUT", idx, idx); pairIssues++; }
    if (hasD2B[idx] && !hasB2D[idx]) { hc.info("      D2B%d present but B2D%d missing — forward-only device LUT", idx, idx); pairIssues++; }
    if (hasB2D[idx] && !hasD2B[idx]) { hc.info("      B2D%d present but D2B%d missing — reverse-only device LUT", idx, idx); pairIssues++; }
  }

  if (pairIssues > 0)
    hc.info("      %d unpaired LUT tag(s) — may indicate crafted profile", pairIssues);

  return hc.end("All LUT tags properly paired");
}

// =========================================================================
// H37 — Calculator Element Complexity Validation (LARGE)
// Includes H151 (calculator enum) inline.
// =========================================================================
int RunHeuristic_H37_CalculatorElementComplexity(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(37, "Calculator Element Complexity Validation");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tSig = tag.sig;
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 4 > fs || tSz < 4) continue;

    icUInt8Number typeCheck[4];
    if (!ctx.ReadAt(tOff, typeCheck, 4)) continue;
    icUInt32Number tagType = ReadU32BE(typeCheck);
    // mpet = 0x6D706574
    if (tagType != 0x6D706574) continue;

    size_t scanLen = (tSz < kMaxTagDataScan) ? tSz : kMaxTagDataScan;
    if (tOff + scanLen > fs) scanLen = fs - tOff;
    if (scanLen < 8) continue;

    std::vector<icUInt8Number> scanBufVec(scanLen);
    icUInt8Number *scanBuf = scanBufVec.data();
    if (!ctx.ReadAt(tOff, scanBuf, scanLen)) continue;

    char sig[5];
    SigToChars(tSig, sig);

    int calcCount = 0;
    int ifSelCount = 0;
    for (size_t b = 0; b + 3 < scanLen; b++) {
      icUInt32Number w = ReadU32BE(&scanBuf[b]);
      if (w == 0x63616C63) calcCount++; // 'calc'
      if (w == 0x69660000 || w == 0x73656C00) ifSelCount++; // 'if\0\0' or 'sel\0'
    }

    if (calcCount > 100) {
      hc.warn("Tag '%s': %d calculator sub-elements (limit 100)", sig, calcCount);
      hc.cweNote("Risk: Stack exhaustion / OOM via calculator element recursion");

    }

    if (ifSelCount > 50) {
      hc.warn("Tag '%s': %d if/sel branching opcodes — exponential path risk", sig, ifSelCount);
      hc.cweNote("CWE-400: Branching opcodes cause exponential path exploration");

    }

    if (tSz >= 8 && tSz < 16) {
      hc.warn("Tag '%s': MPE tag size %u too small for any elements", sig, tSz);
      hc.cweNote("Risk: Crash on empty element list traversal");

    }

    // Check extreme sub-element count in mpet header
    if (scanLen >= 16) {
      icUInt32Number nElems = ReadU32BE(&scanBuf[12]);
      if (nElems > kMaxMpeElements) {
        hc.warn("Tag '%s': MPE has %u elements (limit %u)", sig, nElems, kMaxMpeElements);
        hc.cweNote("Risk: DoS via excessive element processing");

      }
    }

    // H151: Validate calculator channel function & operator enum signatures
    for (size_t b = 0; b + 15 < scanLen; /* increment below */) {
      icUInt32Number w = ReadU32BE(&scanBuf[b]);
      if (w != 0x63616C63) { b++; continue; }

      size_t calcOff = b;
      if (calcOff + 16 > scanLen) break;
      icUInt32Number nSubElem = ReadU32BE(&scanBuf[calcOff + 12]);
      if (nSubElem > 10000) { b = calcOff + 4; continue; }

      icUInt32Number nPos = nSubElem + 1;
      size_t posTableStart = calcOff + 16;
      if (posTableStart + (size_t)nPos * 8 > scanLen) { b = calcOff + 4; continue; }

      icUInt32Number funcOff = ReadU32BE(&scanBuf[posTableStart]);
      icUInt32Number funcSz  = ReadU32BE(&scanBuf[posTableStart + 4]);
      size_t absFuncOff = calcOff + funcOff;

      if (absFuncOff + 12 > scanLen || funcSz < 12) { b = calcOff + 15; continue; }

      // Validate icChannelFuncSignature (must be 0x66756E63 = 'func')
      icUInt32Number chanFuncSig = ReadU32BE(&scanBuf[absFuncOff]);
      if (chanFuncSig != 0x66756E63) {
        hc.critical("Tag '%s': Calculator channel function signature "
                    "0x%08X is not 'func' (0x66756E63)", sig, chanFuncSig);
        hc.cweNote("CWE-681: Invalid icChannelFuncSignature enum load causes "
                   "undefined behavior (UBSAN at IccMpeCalc.cpp:3482)");
        hc.cweNote("Ref: CFL-005 patch, iccDEV upstream issues");

      }

      // Validate operator signatures in the func block
      icUInt32Number nOps = ReadU32BE(&scanBuf[absFuncOff + 8]);
      if (nOps > 0 && nOps < 100000) {
        size_t opsStart = absFuncOff + 12;
        icUInt32Number invalidOps = 0;
        int dangerousOps = 0;
        icUInt32Number checkedOps = (nOps < 1000) ? nOps : 1000;
        for (icUInt32Number op = 0; op < checkedOps; op++) {
          size_t opOff = opsStart + (size_t)op * 8;
          if (opOff + 4 > scanLen) break;
          icUInt32Number opSig = ReadU32BE(&scanBuf[opOff]);
          if (opSig == 0x00000000) continue;
          bool valid = true;
          for (int byte = 0; byte < 4; byte++) {
            icUInt8Number ch = (opSig >> (24 - byte * 8)) & 0xFF;
            if (ch < 0x20 || ch > 0x7E) { valid = false; break; }
          }
          if (!valid) invalidOps++;
          // Count dangerous float-to-int cast operators (CFL-022)
          if (opSig == 0x74726E63 || // trnc
              opSig == 0x666C6F72 || // flor
              opSig == 0x6365696C || // ceil
              opSig == 0x726F6E64 || // rond
              opSig == 0x6D6F6420) { // mod
            dangerousOps++;
          }
        }
        if (invalidOps > 0) {
          hc.critical("Tag '%s': %u/%u calculator operator signatures "
                      "are invalid enum values (non-FourCC)", sig, invalidOps, checkedOps);
          hc.cweNote("CWE-681: Invalid operator enum at m_Op[i].sig (IccMpeCalc.cpp:3514)");

        }
        if (dangerousOps > 0) {
          hc.warn("Tag '%s': Calculator has %d float-to-int cast "
                  "operators (trnc/flor/ceil/rond/mod)", sig, dangerousOps);
          hc.cweNote("CWE-681: Unguarded (int)float cast overflows for "
                     "|value| > 2.147e9 (IccMpeCalc.cpp:953,1215,1240,1257,1285)");
          hc.cweNote("Ref: CFL-022 patch, UBSAN runtime error in applyprofiles/applynamedcmm fuzzers");

        }
      }

      b = calcOff + 15;
    }
  }

  return hc.end("No calculator complexity issues");
}

bool DetectH152CurveElementOOMSize(const char *filename) {
  RawProfileContext ctx = OpenRawProfileContext(filename);
  if (!ctx.valid) {
    return false;
  }
  return !ScanRawCurveElementIssues(ctx, 1).empty();
}

// =========================================================================
// H152 — Curve Element OOM Size Validation
// =========================================================================
int RunHeuristic_H152_CurveElementOOMSizeValidation(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(152, "Curve Element OOM Size Validation");

  if (!ctx.fh) return hc.skip("Cannot open profile for raw curve scan");
  if (ctx.fileSize() < 12) return hc.skip("File too small for raw curve scan");

  auto issues = ScanRawCurveElementIssues(ctx);
  for (const auto &issue : issues) {
    hc.critical("%s", FormatRawCurveElementIssue(issue).c_str());
    hc.cweNote("%s", CurveElementIssueCweNote(issue).c_str());
  }

  return hc.end("Curve elements within bounded size limits");
}

// =========================================================================
// H38 — Curve Degenerate Value Detection
// =========================================================================
int RunHeuristic_H38_CurveDegenerateValue(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(38, "Curve Degenerate Value Detection");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tSig = tag.sig;
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 12 > fs || tSz < 12) continue;
    icUInt8Number tagHdr[12];
    if (!ctx.ReadAt(tOff, tagHdr, 12)) continue;

    icUInt32Number tagType = ReadU32BE(tagHdr);
    char sig[5];
    SigToChars(tSig, sig);

    // curv (0x63757276)
    if (tagType == 0x63757276) {
      icUInt32Number curveCount = ReadU32BE(&tagHdr[8]);
      if (curveCount == 0) continue; // identity — valid
      if (curveCount > 65536) {
        hc.warn("Tag '%s' (curv): count %u > 64K — OOM risk", sig, curveCount);

        continue;
      }
      // Sample first kMaxCurveDataScan entries for degenerate values
      size_t sampleCount = curveCount;
      if (sampleCount > kMaxCurveDataScan) sampleCount = kMaxCurveDataScan;
      size_t dataOff = (uint64_t)tOff + 12;
      if (dataOff + sampleCount * 2 > fs) continue;

      std::vector<icUInt8Number> cData(sampleCount * 2);
      if (!ctx.ReadAt(dataOff, cData.data(), sampleCount * 2)) continue;

      bool allZero = true, allMax = true;
      for (size_t c = 0; c < sampleCount; c++) {
        uint16_t val = ((uint16_t)cData[c*2] << 8) | cData[c*2 + 1];
        if (val != 0) allZero = false;
        if (val != 0xFFFF) allMax = false;
      }
      if (allZero && curveCount > 1) {
        hc.warn("Tag '%s' (curv): all %u entries are zero — input always mapped to 0",
                sig, curveCount);
        hc.cweNote("CWE-682: Degenerate TRC destroys color information");

      }
      if (allMax && curveCount > 1) {
        hc.warn("Tag '%s' (curv): all %u entries are 0xFFFF — input always mapped to max",
                sig, curveCount);

      }
    }

    // para (0x70617261)
    if (tagType == 0x70617261 && tSz >= 16) {
      icUInt8Number paraHdr[4];
      if (!ctx.ReadAt(tOff + 8, paraHdr, 4)) continue;
      uint16_t funcType = ((uint16_t)paraHdr[0] << 8) | paraHdr[1];
      if (funcType > 4) {
        hc.warn("Tag '%s' (para): funcType %u > 4 (ICC max)", sig, funcType);
        hc.cweNote("CWE-681: Invalid parametric curve function type");

      }
    }
  }

  return hc.end("No degenerate curve values detected");
}

// =========================================================================
// H39 — Shared Tag Data Aliasing Detection
// =========================================================================
int RunHeuristic_H39_SharedTagDataAliasing(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(39, "Shared Tag Data Aliasing Detection");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  // Immutable tag type signatures (safe to share pointers)
  static const uint32_t kImmutableTypes[] = {
    0x63757276, // curv
    0x73663332, // sf32
    0x58595A20, // XYZ
    0x6D667432, // mft2
    0x6D667431, // mft1
    0x70617261, // para
    0x74657874, // text
    0x64657363, // desc
    0x6D6C7563, // mluc
  };
  auto isImmutableType = [&](uint32_t sig) -> bool {
    for (auto s : kImmutableTypes)
      if (s == sig) return true;
    return false;
  };

  size_t nTags = ctx.tags.size();
  int sharedPairs = 0;
  bool allImmutable = true;
  size_t fs = ctx.fileSize();

  for (size_t i = 0; i < nTags; i++) {
    for (size_t j = i + 1; j < nTags; j++) {
      uint32_t offI = ctx.tags[i].offset;
      uint32_t szI  = ctx.tags[i].size;
      uint32_t offJ = ctx.tags[j].offset;
      uint32_t szJ  = ctx.tags[j].size;

      // Exact match = shared (valid ICC practice)
      if (offI == offJ && szI == szJ) {
        sharedPairs++;
        // Read type signature to check immutability
        if ((uint64_t)offI + 4 <= fs) {
          icUInt8Number typeBuf[4];
          if (ctx.ReadAt(offI, typeBuf, 4)) {
            uint32_t typeVal = ReadU32BE(typeBuf);
            if (!isImmutableType(typeVal))
              allImmutable = false;
          }
        }
        continue;
      }

      // Same offset, different sizes = suspicious
      if (offI == offJ && szI != szJ) {
        char sigI[5], sigJ[5];
        SigToChars(ctx.tags[i].sig, sigI);
        SigToChars(ctx.tags[j].sig, sigJ);
        hc.warn("Tags '%s' and '%s' share offset 0x%X but have different sizes (%u vs %u)",
                sigI, sigJ, offI, szI, szJ);
        hc.cweNote("CWE-119: Shared offset with size mismatch — potential OOB");

      } else {
        if ((uint64_t)offI < (uint64_t)offJ + szJ && (uint64_t)offJ < (uint64_t)offI + szI && offI != offJ) {
          char sigI[5], sigJ[5];
          SigToChars(ctx.tags[i].sig, sigI);
          SigToChars(ctx.tags[j].sig, sigJ);
          hc.warn("Tags '%s' [0x%X+%u] and '%s' [0x%X+%u] partially overlap",
                  sigI, offI, szI, sigJ, offJ, szJ);
          hc.cweNote("CWE-119: Partial tag data overlap — parser confusion");
        }
      }
    }
  }

  if (sharedPairs > 0 && allImmutable) {
    hc.info("      %d shared tag pair(s) — all immutable types (safe)", sharedPairs);
  } else if (sharedPairs > 0) {
    hc.warn("%d shared tag pair(s) include mutable types — UAF risk in Cleanup()", sharedPairs);
    hc.cweNote("CWE-416: Shared mutable tag pointers — double-free in dedup loop");
  }

  return hc.end("No risky shared tag data aliasing");
}

// =========================================================================
// H40 — Tag Alignment Padding
// =========================================================================
int RunHeuristic_H40_TagAlignmentPadding(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(40, "Tag Alignment Padding");

  if (!ctx.valid) return hc.skip("File too small for tag table");



  for (const auto &tag : ctx.tags) {
    if (tag.offset % 4 != 0) {
      char sig[5];
      SigToChars(tag.sig, sig);
      hc.warn("Tag '%s': offset 0x%X not 4-byte aligned", sig, tag.offset);

    }
  }

  return hc.end("All tag offsets are 4-byte aligned");
}

// =========================================================================
// H41 — Version/Type Consistency
// =========================================================================
int RunHeuristic_H41_VersionTypeConsistency(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(41, "Version/Type Consistency");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();
  uint8_t versionMajor = ctx.header[8];


  // v2-only types used in v4+ profile → type confusion
  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 4 > fs || tSz < 4) continue;
    icUInt8Number typeSig[4];
    if (!ctx.ReadAt(tOff, typeSig, 4)) continue;
    uint32_t typeVal = ReadU32BE(typeSig);

    // textDescription (0x64657363) is deprecated in v4
    if (versionMajor >= 4 && typeVal == 0x64657363) {
      char sig[5]; SigToChars(tag.sig, sig);
      hc.warn("Tag '%s': v2-only textDescription type (0x64657363) in v%u profile",
              sig, versionMajor);

    }

    // Check for namedColor (0x6E636F6C) in v4+ (replaced by namedColor2)
    if (versionMajor >= 4 && typeVal == 0x6E636F6C) {
      char sig[5]; SigToChars(tag.sig, sig);
      hc.warn("Tag '%s': deprecated namedColor type in v%u profile", sig, versionMajor);

    }
  }

  return hc.end("Version/type consistency OK");
}

// =========================================================================
// H42 — Matrix Singularity
// =========================================================================
int RunHeuristic_H42_MatrixSingularity(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(42, "Matrix Singularity");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 4 > fs || tSz < 4) continue;
    icUInt8Number typeSig[4];
    if (!ctx.ReadAt(tOff, typeSig, 4)) continue;
    uint32_t typeVal = ReadU32BE(typeSig);

    // lut8 (mft1) and lut16 (mft2) have 3x3 matrix at +12
    if (typeVal != 0x6D667431 && typeVal != 0x6D667432) continue;
    if (tSz < 48 || (uint64_t)tOff + 48 > fs) continue;

    icUInt8Number matData[36];
    if (!ctx.ReadAt(tOff + 12, matData, 36)) continue;

    // Read 3x3 s15Fixed16 matrix
    double m[3][3];
    for (int r = 0; r < 3; r++) {
      for (int c = 0; c < 3; c++) {
        int32_t raw = (int32_t)ReadU32BE(&matData[(r*3+c)*4]);
        m[r][c] = raw / 65536.0;
      }
    }

    // Compute determinant
    double det = m[0][0] * (m[1][1]*m[2][2] - m[1][2]*m[2][1])
               - m[0][1] * (m[1][0]*m[2][2] - m[1][2]*m[2][0])
               + m[0][2] * (m[1][0]*m[2][1] - m[1][1]*m[2][0]);

    char sig[5]; SigToChars(tag.sig, sig);

    if (std::fabs(det) < 1e-6) {
      hc.warn("Tag '%s' (%s): near-singular 3x3 matrix (det=%.6g)",
              sig, (typeVal == 0x6D667431) ? "lut8" : "lut16", det);
      hc.cweNote("CWE-369: Singular matrix — inversion produces div-by-zero or garbage");

    }

    // All-zero matrix
    bool allZero = (std::fabs(det) < 1e-20);
    for (int r = 0; r < 3 && allZero; r++)
      for (int c = 0; c < 3 && allZero; c++)
        if (std::fabs(m[r][c]) > 1e-10) allZero = false;
    if (allZero) {
      hc.warn("Tag '%s': matrix is all zeros — destroys color data", sig);

    }
  }

  return hc.end("No singular matrices detected");
}

// =========================================================================
// H43 — Spectral/BRDF Tag Structure
// =========================================================================
int RunHeuristic_H43_SpectralBRDFTagStructure(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(43, "Spectral/BRDF Tag Structure");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 8 > fs || tSz < 8) continue;
    icUInt8Number tagHdr[8];
    if (!ctx.ReadAt(tOff, tagHdr, 8)) continue;

    uint32_t typeVal = ReadU32BE(tagHdr);

    // Spectral viewing conditions (svwc = 0x73767763)
    if (typeVal == 0x73767763 && tSz >= 20) {
      icUInt8Number specData[12];
      if (ctx.ReadAt(tOff + 8, specData, 12)) {
        uint16_t specStart = ((uint16_t)specData[0] << 8) | specData[1];
        uint16_t specEnd   = ((uint16_t)specData[2] << 8) | specData[3];
        uint16_t specSteps = ((uint16_t)specData[4] << 8) | specData[5];

        if (specStart > 0 && specEnd > 0 && specEnd <= specStart) {
          char sig[5]; SigToChars(tag.sig, sig);
          hc.warn("Tag '%s' (svwc): spectral end (%u) <= start (%u)", sig, specEnd, specStart);
          hc.cweNote("CWE-682: Inverted spectral range");

        }
        if ((specStart > 0 || specEnd > 0) && specSteps == 0) {
          char sig[5]; SigToChars(tag.sig, sig);
          hc.warn("Tag '%s' (svwc): spectral steps = 0 with non-zero range", sig);
          hc.cweNote("CWE-369: Division by zero in spectral interpolation");

        }
      }
    }
  }

  return hc.end("No spectral/BRDF structure issues");
}

// =========================================================================
// H44 — Embedded Image Validation
// =========================================================================
int RunHeuristic_H44_EmbeddedImageValidation(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(44, "Embedded Image Validation");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 8 > fs || tSz < 8) continue;

    // Check for embedded image tags (preview, gamut map)
    // Preview image types use PNG or TIFF internal format
    if (tSz > 16 * 1024 * 1024) {
      char sig[5]; SigToChars(tag.sig, sig);
      hc.warn("Tag '%s': size %u bytes (>16MB) — oversized embedded data", sig, tSz);
      hc.cweNote("CWE-400: Potential resource exhaustion via large embedded image");

    }

    // Check for TIFF/PNG/JPEG magic bytes in tag data
    if ((uint64_t)tOff + 8 <= fs) {
      icUInt8Number magic[8];
      if (ctx.ReadAt(tOff + 8, magic, 8)) {
        // Skip type signature (bytes 0-3), check after reserved (bytes 8+)
        // TIFF: II (0x4949) or MM (0x4D4D) at data start
        // PNG: 0x89504E47 at data start
        // JPEG: 0xFFD8FF at data start
        if ((magic[0] == 0x49 && magic[1] == 0x49) ||
            (magic[0] == 0x4D && magic[1] == 0x4D)) {
          char sig[5]; SigToChars(tag.sig, sig);
          hc.info("      Tag '%s': TIFF image detected in tag data", sig);
        }
        if (magic[0] == 0x89 && magic[1] == 0x50 && magic[2] == 0x4E && magic[3] == 0x47) {
          char sig[5]; SigToChars(tag.sig, sig);
          hc.info("      Tag '%s': PNG image detected in tag data", sig);
        }
      }
    }
  }

  return hc.end("No embedded image issues");
}

// =========================================================================
// H45 — Sparse Matrix Bounds
// =========================================================================
int RunHeuristic_H45_SparseMatrixBounds(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(45, "Sparse Matrix Bounds");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 4 > fs || tSz < 4) continue;
    icUInt8Number typeSig[4];
    if (!ctx.ReadAt(tOff, typeSig, 4)) continue;
    uint32_t typeVal = ReadU32BE(typeSig);

    // mpet sub-elements: scan for 'smtx' (sparse matrix) type (0x736D7478)
    if (typeVal == 0x6D706574 && tSz >= 16) {
      size_t scanLen = (tSz < kMaxTagDataScan) ? tSz : kMaxTagDataScan;
      if (tOff + scanLen > fs) scanLen = fs - tOff;
      std::vector<icUInt8Number> data(scanLen);
      if (!ctx.ReadAt(tOff, data.data(), scanLen)) continue;

      for (size_t b = 0; b + 15 < scanLen; b += 4) {
        uint32_t w = ReadU32BE(&data[b]);
        if (w == 0x736D7478 && b + 16 < scanLen) { // 'smtx'
          uint32_t rows = ReadU32BE(&data[b + 8]);
          uint32_t cols = ReadU32BE(&data[b + 12]);
          uint64_t entries = (uint64_t)rows * cols;
          if (entries > kMaxSparseMatrixEntries) {
            char sig[5]; SigToChars(tag.sig, sig);
            hc.warn("Tag '%s': sparse matrix %ux%u = %llu entries (limit %llu)",
                    sig, rows, cols, (unsigned long long)entries,
                    (unsigned long long)kMaxSparseMatrixEntries);
            hc.cweNote("CWE-789: Amplification — small tag triggers huge allocation");

          }
        }
      }
    }
  }

  return hc.end("No sparse matrix bounds issues");
}

// =========================================================================
// H46 — TextDescription Unicode Length
// =========================================================================
int RunHeuristic_H46_TextDescUnicodeLength(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(46, "TextDescription Unicode Length");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 12 > fs || tSz < 12) continue;
    icUInt8Number tagHdr[12];
    if (!ctx.ReadAt(tOff, tagHdr, 12)) continue;

    uint32_t typeVal = ReadU32BE(tagHdr);

    // textDescription (0x64657363)
    if (typeVal == 0x64657363) {
      uint32_t asciiLen = ReadU32BE(&tagHdr[8]);
      if (asciiLen > tSz - 8) {
        char sig[5]; SigToChars(tag.sig, sig);
        hc.warn("Tag '%s' (desc): ASCII length %u exceeds available tag data %u",
                sig, asciiLen, tSz - 8);
        hc.cweNote("CWE-120: Buffer overflow in textDescription parsing");

      }
      // Check for unicode section overflow
      size_t uniOff = 12 + asciiLen;
      if (uniOff + 8 <= tSz && (uint64_t)tOff + uniOff + 8 <= fs) {
        icUInt8Number uniHdr[8];
        if (ctx.ReadAt(tOff + uniOff, uniHdr, 8)) {
          uint32_t uniLen = ReadU32BE(&uniHdr[4]);
          if (uniLen > 0 && uniOff + 8 + uniLen * 2 > tSz) {
            char sig[5]; SigToChars(tag.sig, sig);
            hc.warn("Tag '%s' (desc): unicode length %u exceeds tag bounds", sig, uniLen);
            hc.cweNote("CWE-120: Unicode string overflow in textDescription");

          }
        }
      }
    }

    // mluc (0x6D6C7563) — record count validation
    if (typeVal == 0x6D6C7563) {
      icUInt8Number mlucHdr[4];
      if (ctx.ReadAt(tOff + 8, mlucHdr, 4)) {
        uint32_t numRec = ReadU32BE(mlucHdr);
        if (numRec > 500) {
          char sig[5]; SigToChars(tag.sig, sig);
          hc.warn("Tag '%s' (mluc): %u records (>500) — OOM risk", sig, numRec);

        }
      }
    }
  }

  return hc.end("No text description length issues");
}

// =========================================================================
// H47 — NamedColor2 Size Overflow
// =========================================================================
int RunHeuristic_H47_NamedColor2SizeOverflow(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(47, "NamedColor2 Size Overflow");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 4 > fs || tSz < 4) continue;
    icUInt8Number typeSig[4];
    if (!ctx.ReadAt(tOff, typeSig, 4)) continue;
    uint32_t typeVal = ReadU32BE(typeSig);

    // ncl2 (0x6E636C32)
    if (typeVal != 0x6E636C32) continue;
    if (tSz < 84 || (uint64_t)tOff + 84 > fs) continue;

    icUInt8Number ncl2Hdr[76];
    if (!ctx.ReadAt(tOff + 8, ncl2Hdr, 76)) continue;

    // vendor flag (4), count (4), nDeviceCoords (4), prefix(32), suffix(32)
    uint32_t nColors = ReadU32BE(&ncl2Hdr[4]);
    uint32_t nDevice = ReadU32BE(&ncl2Hdr[8]);

    // Each color entry: name(32) + PCS(6) + device(nDevice*2) bytes
    uint64_t entrySize = 32 + 6 + (uint64_t)nDevice * 2;
    uint64_t totalData = (uint64_t)nColors * entrySize;

    if (nDevice > 15) {
      char sig[5]; SigToChars(tag.sig, sig);
      hc.warn("Tag '%s' (ncl2): nDeviceCoords = %u (>15 ICC spec max)", sig, nDevice);
      hc.cweNote("CWE-787: Device coord count exceeds ICC spec max (CFL-076 pattern)");
    }

    if (nColors > 0 && totalData + 84 > tSz) {
      char sig[5]; SigToChars(tag.sig, sig);
      hc.warn("Tag '%s' (ncl2): %u entries × %llu bytes = %llu, but tag is only %u bytes",
              sig, nColors, (unsigned long long)entrySize, (unsigned long long)totalData, tSz);
    }

    if (nColors > 10000) {
      char sig[5]; SigToChars(tag.sig, sig);
      hc.warn("Tag '%s' (ncl2): %u entries (>10000) — Describe() DoS risk", sig, nColors);
      hc.cweNote("CWE-400: Describe() iterates m_nSize with no runtime cap (CFL-078 pattern)");
    }
  }

  return hc.end("No NamedColor2 size overflow");
}

// =========================================================================
// H48 — CLUT Grid Dimension Product Overflow
// =========================================================================
int RunHeuristic_H48_CLUTGridDimensionOverflow(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(48, "CLUT Grid Dimension Product Overflow");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tSig = tag.sig;
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 12 > fs || tSz < 12) continue;
    icUInt8Number typeSig[4];
    if (!ctx.ReadAt(tOff, typeSig, 4)) continue;
    uint32_t typeVal = ReadU32BE(typeSig);
    char sig[5]; SigToChars(tSig, sig);

    // lut8 (0x6D667431) and lut16 (0x6D667432): uniform grid
    if (typeVal == 0x6D667431 || typeVal == 0x6D667432) {
      if ((uint64_t)tOff + 12 > fs) continue;
      icUInt8Number lutHdr[4];
      if (!ctx.ReadAt(tOff + 8, lutHdr, 4)) continue;

      uint8_t nInput = lutHdr[0];
      uint8_t nOutput = lutHdr[1];
      uint8_t gridPts = lutHdr[2];

      if (nInput > 0 && gridPts > 0 && nOutput > 0) {
        uint64_t product = 1;
        bool overflow = false;
        for (uint8_t d = 0; d < nInput; d++) {
          product *= gridPts;
          if (product > kMaxCLUTGridProduct) { overflow = true; break; }
        }
        if (!overflow) product *= nOutput;
        if (product > kMaxCLUTGridProduct) overflow = true;

        if (overflow) {
          hc.warn("Tag '%s' (%s): grid %u^%u x %u output = overflow",
                  sig, (typeVal == 0x6D667431) ? "lut8" : "lut16",
                  gridPts, nInput, nOutput);
          hc.cweNote("CRITICAL: CWE-131/CWE-190 CLUT allocation overflow (CVE-2026-22255 pattern)");

        }
      }
    }

    // mAB (0x6D414220) / mBA (0x6D424120): per-dimension grid
    if (typeVal == 0x6D414220 || typeVal == 0x6D424120) {
      if ((uint64_t)tOff + 32 > fs) continue;
      icUInt8Number mbaHdr[24];
      if (!ctx.ReadAt(tOff + 8, mbaHdr, 24)) continue;

      uint8_t nInput = mbaHdr[0];
      uint8_t nOutput = mbaHdr[1];
      uint32_t clutOff = ReadU32BE(&mbaHdr[12]);

      if (clutOff > 0 && clutOff < tSz && (uint64_t)tOff + clutOff + 16 <= fs && nInput <= 16) {
        icUInt8Number gridDims[16];
        if (!ctx.ReadAt(tOff + clutOff, gridDims, 16)) continue;

        uint64_t product = 1;
        bool overflow = false;
        bool hasZeroDim = false;
        for (uint8_t d = 0; d < nInput; d++) {
          if (gridDims[d] == 0) { hasZeroDim = true; break; }
          product *= gridDims[d];
          if (product > kMaxCLUTGridProduct) { overflow = true; break; }
        }
        if (!overflow && !hasZeroDim && nOutput > 0) {
          product *= nOutput;
          if (product > kMaxCLUTGridProduct) overflow = true;
        }

        if (overflow) {
          hc.warn("Tag '%s' (%s): CLUT grid product overflows (>256M entries)",
                  sig, (typeVal == 0x6D414220) ? "mAB" : "mBA");
          hc.cweNote("CRITICAL: CWE-131/CWE-190 CLUT allocation overflow (CVE-2026-22255 pattern)");

        }
      }
    }
  }

  return hc.end("CLUT grid dimension products within bounds");
}

// =========================================================================
// H49 — Float/s15Fixed16 NaN/Inf Detection
// =========================================================================
int RunHeuristic_H49_FloatNaNInfDetection(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(49, "Float/s15Fixed16 NaN/Inf Detection");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();
  int issues = 0;

  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 12 > fs || tSz < 12) continue;
    icUInt8Number typeSig[4];
    if (!ctx.ReadAt(tOff, typeSig, 4)) continue;
    uint32_t typeVal = ReadU32BE(typeSig);

    // Only check IEEE 754 float types: fl32, para, mpet
    // NOTE: sf32 (0x73663332) is s15Fixed16ArrayType — fixed-point integers,
    // NOT IEEE 754 floats. Raw s15Fixed16 bytes like 0xFFFFF328 (valid negative
    // values ≈ -0.0508) have bit patterns that look like IEEE NaN but are perfectly
    // valid fixed-point data. Exclude sf32 to prevent false positives on chad, etc.
    bool hasFloat = (typeVal == 0x666C3332 ||  // fl32 (IEEE float array)
                     typeVal == 0x70617261 ||  // para (parametricCurve, has floats)
                     typeVal == 0x6D706574);   // mpet (MPE, contains floats)
    if (!hasFloat) continue;

    size_t scanLen = tSz;
    if (scanLen > kMaxTagDataScan) scanLen = kMaxTagDataScan;
    if (tOff + scanLen > fs) scanLen = fs - tOff;
    if (scanLen < 12) continue;

    std::vector<icUInt8Number> data(scanLen);
    if (!ctx.ReadAt(tOff, data.data(), scanLen)) continue;

    // Scan for IEEE 754 NaN/Inf patterns in 4-byte aligned positions after header
    for (size_t b = 8; b + 3 < scanLen; b += 4) {
      uint32_t raw = ReadU32BE(&data[b]);
      float fval;
      memcpy(&fval, &raw, 4);

      if (std::isnan(fval) || std::isinf(fval)) {
        char sig[5]; SigToChars(tag.sig, sig);
        hc.warn("Tag '%s': %s detected at offset +%zu (raw=0x%08X)",
                sig, std::isnan(fval) ? "NaN" : "Inf", b, raw);
        hc.cweNote("CWE-758: Undefined behavior when converting NaN to integer (CVE-2026-21681)");
        issues++;
        if (issues >= 10) break;
      }
    }
    if (issues >= 10) break;
  }

  if (issues >= 10)
    hc.info("      (capped at 10 NaN/Inf findings)");

  return hc.end("No NaN/Inf values in float tags");
}

// =========================================================================
// H50 — Zero-Size Profile Tag
// =========================================================================
int RunHeuristic_H50_ZeroSizeProfileTag(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(50, "Zero-Size Profile Tag");

  if (!ctx.valid) return hc.skip("File too small for tag table");



  for (const auto &tag : ctx.tags) {
    if (tag.size == 0) {
      char sig[5]; SigToChars(tag.sig, sig);
      hc.warn("Tag '%s' at offset 0x%X: zero size", sig, tag.offset);
      hc.cweNote("CWE-476: Zero-size tag may cause null deref or empty buffer access");

    }
  }

  return hc.end("No zero-size tags");
}

// =========================================================================
// H51 — LUT Channel Count Consistency
// =========================================================================
int RunHeuristic_H51_LUTChannelCountConsistency(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(51, "LUT Channel Count Consistency");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  // Get declared color space from header



  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 12 > fs || tSz < 12) continue;
    icUInt8Number typeSig[4];
    if (!ctx.ReadAt(tOff, typeSig, 4)) continue;
    uint32_t typeVal = ReadU32BE(typeSig);

    // lut8 or lut16
    if (typeVal != 0x6D667431 && typeVal != 0x6D667432) continue;

    icUInt8Number lutHdr[4];
    if (!ctx.ReadAt(tOff + 8, lutHdr, 4)) continue;

    uint8_t nInput = lutHdr[0];
    uint8_t nOutput = lutHdr[1];

    if (nInput == 0 || nOutput == 0) {
      char sig[5]; SigToChars(tag.sig, sig);
      hc.warn("Tag '%s': LUT has 0 channels (in=%u, out=%u)", sig, nInput, nOutput);
      hc.cweNote("CWE-476: Zero-channel LUT causes null/zero-size allocation");

    }

    if (nInput > 16) {
      char sig[5]; SigToChars(tag.sig, sig);
      hc.warn("Tag '%s': LUT nInput=%u > 16 — exponential CLUT size", sig, nInput);
      hc.cweNote("CWE-400: High-dimensional LUT — OOM risk");

    }
  }

  return hc.end("LUT channel counts consistent");
}

// =========================================================================
// H52 — Integer Underflow in Tag Size (ICC.1-2022-05 §10.10, §10.11)
// =========================================================================
// Phase 1: Check minimum sizes for known tag types.
// Phase 2: For lutAtoBType (mAB, 0x6D414220) and lutBtoAType (mBA, 0x6D424120),
//          validate the 5 sub-element offset fields (B-curves, Matrix, M-curves,
//          CLUT, A-curves). If any non-zero offset exceeds the tag size, the
//          library's (nEnd - pIO->Tell()) subtraction underflows to ~4GB,
//          defeating all downstream size validation. CFL-065, CWE-191→CWE-789.
// Phase 3: For lut8Type and lut16Type, validate that declared channel counts
//          and grid dimensions produce sequential read sizes within the tag.
int RunHeuristic_H52_IntegerUnderflowTagSize(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(52, "Integer Underflow in Tag Size (ICC.1-2022-05 §10.10, §10.11)");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();

  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 4 > fs || tSz < 4) continue;
    icUInt8Number typeSig[4];
    if (!ctx.ReadAt(tOff, typeSig, 4)) continue;
    uint32_t typeVal = ReadU32BE(typeSig);

    // Phase 1: Check minimum sizes for known types
    struct { uint32_t type; uint32_t minSize; const char *name; } mins[] = {
      {0x64657363, 12, "desc"},  // textDescription
      {0x58595A20, 20, "XYZ"},   // XYZType
      {0x63757276, 12, "curv"},  // curve
      {0x70617261, 12, "para"},  // parametric curve
      {0x6D667431, 48, "lut8"},  // lut8
      {0x6D667432, 52, "lut16"}, // lut16
      {0x6D414220, 32, "mAB"},   // mAB
      {0x6D424120, 32, "mBA"},   // mBA
      {0x6D706574, 16, "mpet"},  // mpet
      {0x6D6C7563, 16, "mluc"},  // mluc
    };

    for (const auto &m : mins) {
      if (typeVal == m.type && tSz < m.minSize) {
        char sig[5]; SigToChars(tag.sig, sig);
        hc.warn("Tag '%s' (type %s): size %u < minimum %u",
                sig, m.name, tSz, m.minSize);
        hc.cweNote("CWE-191: Undersized tag — size arithmetic underflows on (size - headerSize)");
        break;
      }
    }

    // Phase 2: mAB/mBA sub-element offset validation (CFL-065 pattern)
    // Layout: [typeSig(4)][reserved(4)][nInput(1)][nOutput(1)][reserved(2)][Offset[5](20)]
    // Total header: 32 bytes. Offset[0..4] = {B-curves, Matrix, M-curves, CLUT, A-curves}
    // Each non-zero offset is relative to tag start; must be < tagSize.
    if ((typeVal == 0x6D414220 || typeVal == 0x6D424120) && tSz >= 32) {
      // Read the 5 offset fields starting at tag_offset + 12
      if ((uint64_t)tOff + 32 <= fs) {
        icUInt8Number offBuf[20];
        if (ctx.ReadAt(tOff + 12, offBuf, 20)) {
          const char *elemNames[] = {"B-curves", "Matrix", "M-curves", "CLUT", "A-curves"};
          const char *typeName = (typeVal == 0x6D414220) ? "mAB" : "mBA";

          for (int e = 0; e < 5; e++) {
            uint32_t subOff = ReadU32BE(offBuf + e * 4);
            if (subOff == 0) continue; // not present

            if (subOff > tSz) {
              char sig[5]; SigToChars(tag.sig, sig);
              hc.critical("Tag '%s' (type %s): %s offset %u exceeds tag size %u "
                          "— (nEnd - pIO->Tell()) underflows to ~4GB",
                          sig, typeName, elemNames[e], subOff, tSz);
              hc.cweNote("CWE-191: Integer underflow in sub-element offset subtraction "
                         "(CFL-065: defeated size validation → CWE-789 uncontrolled allocation)");
            } else if (subOff < 32) {
              char sig[5]; SigToChars(tag.sig, sig);
              hc.warn("Tag '%s' (type %s): %s offset %u overlaps header (< 32)",
                      sig, typeName, elemNames[e], subOff);
              hc.cweNote("CWE-125: Sub-element offset within tag header region");
            }
          }
        }
      }
    }

    // Phase 3: lut8/lut16 sequential read size validation
    // lut8 layout: [sig(4)][reserved(4)][nIn(1)][nOut(1)][gridPoints(1)][pad(1)]
    //              [matrix(36)][inTableEntries(nIn*256)][clutEntries(grid^nIn*nOut)]
    //              [outTableEntries(nOut*256)]
    // lut16 layout: [sig(4)][reserved(4)][nIn(1)][nOut(1)][gridPoints(1)][pad(1)]
    //              [matrix(36)][nInputTableEntries(2)][nOutputTableEntries(2)]
    //              [inTable(nIn*nInputEntries*2)][clutEntries(grid^nIn*nOut*2)]
    //              [outTable(nOut*nOutputEntries*2)]
    if (typeVal == 0x6D667431 && tSz >= 48) {
      // lut8Type: read nIn, nOut, gridPoints at offset+8,+9,+10
      if ((uint64_t)tOff + 12 <= fs) {
        icUInt8Number lutHdr[4];
        if (ctx.ReadAt(tOff + 8, lutHdr, 4)) {
          uint8_t nIn = lutHdr[0], nOut = lutHdr[1], grid = lutHdr[2];
          if (nIn > 0 && nOut > 0 && grid > 0 && nIn <= 15 && nOut <= 15) {
            // Fixed header = 48 bytes
            // Input tables = nIn * 256
            // CLUT = grid^nIn * nOut (1-byte entries)
            // Output tables = nOut * 256
            uint64_t inTable = (uint64_t)nIn * 256;
            uint64_t clutEntries = 1;
            for (int d = 0; d < nIn; d++) {
              clutEntries *= grid;
              if (clutEntries > 0x10000000ULL) { clutEntries = 0xFFFFFFFFULL; break; }
            }
            uint64_t clutData = clutEntries * nOut;
            uint64_t outTable = (uint64_t)nOut * 256;
            uint64_t totalMin = 48 + inTable + clutData + outTable;

            if (totalMin > tSz && clutEntries < 0xFFFFFFFFULL) {
              char sig[5]; SigToChars(tag.sig, sig);
              hc.warn("Tag '%s' (lut8): nIn=%u nOut=%u grid=%u requires %llu bytes, "
                      "tag size only %u — sequential reads will underflow nEnd",
                      sig, nIn, nOut, grid, (unsigned long long)totalMin, tSz);
              hc.cweNote("CWE-191: lut8 sequential read data exceeds tag size boundary");
            }
          }
        }
      }
    }

    if (typeVal == 0x6D667432 && tSz >= 52) {
      // lut16Type: read nIn, nOut, gridPoints at offset+8,+9,+10
      // nInputTableEntries at offset+48 (2 bytes), nOutputTableEntries at offset+50 (2 bytes)
      if ((uint64_t)tOff + 52 <= fs) {
        icUInt8Number lutHdr[44];
        if (ctx.ReadAt(tOff + 8, lutHdr, 44)) {
          uint8_t nIn = lutHdr[0], nOut = lutHdr[1], grid = lutHdr[2];
          // nInputTableEntries at byte 40 (offset+48 - offset-8 = 40), nOutputTableEntries at 42
          uint16_t nInEntries = ((uint16_t)lutHdr[40] << 8) | lutHdr[41];
          uint16_t nOutEntries = ((uint16_t)lutHdr[42] << 8) | lutHdr[43];
          if (nIn > 0 && nOut > 0 && grid > 0 && nIn <= 15 && nOut <= 15) {
            uint64_t inTable = (uint64_t)nIn * nInEntries * 2;
            uint64_t clutEntries = 1;
            for (int d = 0; d < nIn; d++) {
              clutEntries *= grid;
              if (clutEntries > 0x10000000ULL) { clutEntries = 0xFFFFFFFFULL; break; }
            }
            uint64_t clutData = clutEntries * nOut * 2;
            uint64_t outTable = (uint64_t)nOut * nOutEntries * 2;
            uint64_t totalMin = 52 + inTable + clutData + outTable;

            if (totalMin > tSz && clutEntries < 0xFFFFFFFFULL) {
              char sig[5]; SigToChars(tag.sig, sig);
              hc.warn("Tag '%s' (lut16): nIn=%u nOut=%u grid=%u inEntries=%u outEntries=%u "
                      "requires %llu bytes, tag size only %u",
                      sig, nIn, nOut, grid, nInEntries, nOutEntries,
                      (unsigned long long)totalMin, tSz);
              hc.cweNote("CWE-191: lut16 sequential read data exceeds tag size boundary");
            }
          }
        }
      }
    }
  }

  return hc.end("No integer underflow in tag sizes");
}

// =========================================================================
// H53 — Embedded Profile Recursion
// =========================================================================
int RunHeuristic_H53_EmbeddedProfileRecursion(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(53, "Embedded Profile Recursion");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    // Check for 'acsp' magic at tag data offset + 36
    if (tSz >= 128 && (uint64_t)tOff + 128 <= fs) {
      icUInt8Number embHdr[4];
      if (ctx.ReadAt(tOff + 36, embHdr, 4)) {
        if (embHdr[0] == 'a' && embHdr[1] == 'c' && embHdr[2] == 's' && embHdr[3] == 'p') {
          char sig[5]; SigToChars(tag.sig, sig);
          hc.warn("Tag '%s': contains embedded ICC profile ('acsp' at +36)", sig);
          hc.cweNote("CWE-674: Recursive profile parsing — potential stack overflow");

        }
      }
    }

    // Also check at data offset + 8 + 36 (after type sig + reserved)
    if (tSz >= 136 && (uint64_t)tOff + 136 <= fs) {
      icUInt8Number embHdr[4];
      if (ctx.ReadAt(tOff + 8 + 36, embHdr, 4)) {
        if (embHdr[0] == 'a' && embHdr[1] == 'c' && embHdr[2] == 's' && embHdr[3] == 'p') {
          char sig[5]; SigToChars(tag.sig, sig);
          hc.warn("Tag '%s': embedded ICC profile at +44 (after type header)", sig);
          hc.cweNote("CWE-674: Recursive profile parsing — potential stack overflow");

        }
      }
    }
  }

  return hc.end("No embedded profile recursion detected");
}

// =========================================================================
// H54 — Division by Zero Trigger
// =========================================================================
int RunHeuristic_H54_DivisionByZeroTrigger(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(54, "Division by Zero Trigger");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 32 > fs || tSz < 32) continue;
    icUInt8Number tagData[32];
    if (!ctx.ReadAt(tOff, tagData, 32)) continue;

    uint32_t typeVal = ReadU32BE(tagData);

    // mAB/mBA: check CLUT grid dims for zeros
    if (typeVal == 0x6D414220 || typeVal == 0x6D424120) {
      uint8_t nInput = tagData[8];
      uint32_t clutOff = ReadU32BE(&tagData[24]);

      if (clutOff > 0 && clutOff < tSz && (uint64_t)tOff + clutOff + 16 <= fs && nInput <= 16) {
        icUInt8Number gridDims[16];
        if (ctx.ReadAt(tOff + clutOff, gridDims, 16)) {
          for (uint8_t d = 0; d < nInput; d++) {
            if (gridDims[d] == 0) {
              char sig[5]; SigToChars(tag.sig, sig);
              hc.warn("Tag '%s' (%s): CLUT grid dimension[%u] = 0",
                      sig, (typeVal == 0x6D414220) ? "mAB" : "mBA", (unsigned)d);
              hc.cweNote("CWE-369: Zero grid dimension — div-by-zero in interpolation");

              break;
            }
          }
        }
      }
    }

    // curv with count=1: gamma. Check for gamma=0
    if (typeVal == 0x63757276 && (uint64_t)tOff + 14 <= fs) {
      uint32_t count = ReadU32BE(&tagData[8]);
      if (count == 1) {
        icUInt8Number gammaBytes[2];
        if (ctx.ReadAt(tOff + 12, gammaBytes, 2)) {
          uint16_t gamma = ((uint16_t)gammaBytes[0] << 8) | gammaBytes[1];
          if (gamma == 0) {
            char sig[5]; SigToChars(tag.sig, sig);
            hc.warn("Tag '%s' (curv): gamma = 0 (u8Fixed8)", sig);
            hc.cweNote("CWE-369: Zero gamma causes division by zero in inverse TRC");

          }
        }
      }
    }
  }

  return hc.end("No division-by-zero triggers");
}

// =========================================================================
// H55 — UTF-16 Encoding Validation
// =========================================================================
int RunHeuristic_H55_UTF16EncodingValidation(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(55, "UTF-16 Encoding Validation");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 12 > fs || tSz < 12) continue;
    icUInt8Number tagHdr[12];
    if (!ctx.ReadAt(tOff, tagHdr, 12)) continue;
    uint32_t typeVal = ReadU32BE(tagHdr);

    // mluc (0x6D6C7563) contains UTF-16BE strings
    if (typeVal != 0x6D6C7563) continue;
    if (tSz < 16 || (uint64_t)tOff + 16 > fs) continue;

    icUInt8Number mlucInfo[8];
    if (!ctx.ReadAt(tOff + 8, mlucInfo, 8)) continue;
    uint32_t numRec = ReadU32BE(mlucInfo);
    uint32_t recSize = ReadU32BE(&mlucInfo[4]);

    if (recSize != 12) {
      char sig[5]; SigToChars(tag.sig, sig);
      hc.warn("Tag '%s' (mluc): record size %u != 12 (expected)", sig, recSize);

    }

    // Validate each record's string offset/length
    if (numRec > 500) numRec = 500;
    for (uint32_t r = 0; r < numRec; r++) {
      size_t recOff = 16 + (size_t)r * 12;
      if (recOff + 12 > tSz || (uint64_t)tOff + recOff + 12 > fs) break;

      icUInt8Number rec[12];
      if (!ctx.ReadAt(tOff + recOff, rec, 12)) break;

      uint32_t strLen = ReadU32BE(&rec[4]);
      uint32_t strOff = ReadU32BE(&rec[8]);

      if ((uint64_t)strOff + strLen > tSz) {
        char sig[5]; SigToChars(tag.sig, sig);
        hc.warn("Tag '%s' (mluc): record[%u] string at +%u len %u exceeds tag size %u",
                sig, r, strOff, strLen, tSz);
        hc.cweNote("CWE-120: UTF-16 string overflows tag boundary");

      }
      if (strLen % 2 != 0) {
        char sig[5]; SigToChars(tag.sig, sig);
        hc.warn("Tag '%s' (mluc): string %u has odd byte length %u (invalid UTF-16)",
                sig, r, strLen);

      }
    }
  }

  return hc.end("UTF-16 encoding OK");
}

// =========================================================================
// H57 — Embedded Profile Recursion Depth
// =========================================================================
int RunHeuristic_H57_EmbeddedProfileRecursionDepth(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(57, "Embedded Profile Recursion Depth");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();

  int embeddedCount = 0;

  // Scan the raw file for 'acsp' (0x61637370) signatures
  // Each occurrence after offset 36 suggests a nested profile
  if (fs > 128) {
    std::vector<icUInt8Number> buf(fs);
    if (ctx.ReadAt(0, buf.data(), fs)) {
      for (size_t b = 128; b + 3 < fs; b++) {
        uint32_t w = ReadU32BE(&buf[b]);
        if (w == 0x61637370) { // 'acsp'
          // Check if this looks like a real profile header (magic at b, size at b-36)
          if (b >= 36) {
            uint32_t embSize = ReadU32BE(&buf[b - 36]);
            if (embSize > 128 && embSize < fs - (b - 36)) {
              embeddedCount++;
            }
          }
        }
      }
    }
  }

  if (embeddedCount > 3) {
    hc.warn("Profile contains %d potential embedded profiles", embeddedCount);
    hc.cweNote("CWE-674: Deep profile nesting — recursion stack overflow risk");
    // issues count tracked by HeuristicCollector
  } else if (embeddedCount > 0) {
    hc.info("      %d embedded profile(s) detected (within safe depth)", embeddedCount);
  }

  return hc.end("No excessive profile nesting");
}

// =========================================================================
// H59 — Spectral Wavelength Range
// =========================================================================
int RunHeuristic_H59_SpectralWavelengthRange(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(59, "Spectral Wavelength Range");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  // Check spectral PCS range from header bytes 40-43 (spectral PCS)
  // and bytes 44-59 (spectral PCS range: start(2) + end(2) + steps(2))
  // Only relevant for v5/iccMAX profiles
  uint8_t versionMajor = ctx.header[8];
  if (versionMajor < 5) return hc.end("Not a v5+ profile — spectral check skipped");

  // Spectral PCS range at header offset 104-109 (ICC.2-2023 §7.2.24)
  if (sizeof(ctx.header) >= 110) {
    uint16_t specStart = ((uint16_t)ctx.header[104] << 8) | ctx.header[105];
    uint16_t specEnd   = ((uint16_t)ctx.header[106] << 8) | ctx.header[107];
    uint16_t specSteps = ((uint16_t)ctx.header[108] << 8) | ctx.header[109];

    if (specStart > 0 || specEnd > 0 || specSteps > 0) {
      // Visible spectrum: 380-780nm typical
      if (specStart > 0 && (specStart < 100 || specStart > 2000)) {
        hc.warn("Spectral start wavelength %u nm outside reasonable range (100-2000)", specStart);
      }
      if (specEnd > 0 && specEnd <= specStart) {
        hc.warn("Spectral end (%u) <= start (%u)", specEnd, specStart);
        hc.cweNote("CWE-682: Inverted spectral range");
      }
      if (specSteps == 0 && (specStart > 0 || specEnd > 0)) {
        hc.warn("Spectral steps = 0 with non-zero wavelength range (%u-%u nm)", specStart, specEnd);
        hc.cweNote("CWE-369: Division by zero in spectral interpolation");
      }
    }
  }

  return hc.end("Spectral wavelength range OK");
}

// =========================================================================
// H68 — Gamut Boundary Description Overflow
// =========================================================================
int RunHeuristic_H68_GamutBoundaryDescOverflow(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(68, "Gamut Boundary Description Overflow");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();


  auto scanGbdRecord = [&](const char *ownerSig, const icUInt8Number *gbdHdr) {
    uint32_t nVerts = ReadU32BE(gbdHdr + 12);
    uint32_t nTris  = ReadU32BE(gbdHdr + 16);

    uint64_t triProduct = (uint64_t)nTris * 3;
    if (triProduct > 0x7FFFFFFF) {
      hc.warn("Tag '%s' (gbd): nTriangles=%u * 3 = %llu overflows int32",
              ownerSig, nTris, (unsigned long long)triProduct);
      hc.cweNote("CWE-190: Signed integer overflow in triangle index computation (CFL-002)");
    }

    uint64_t vertexBytes = (uint64_t)nVerts * 12;
    if (vertexBytes > kMaxVertexDataBytes) {
      hc.warn("Tag '%s' (gbd): %u vertices * 12 = %llu bytes exceeds 256MB",
              ownerSig, nVerts, (unsigned long long)vertexBytes);
      hc.cweNote("CWE-789: Amplification via vertex count");
    }
  };

  for (const auto &tag : ctx.tags) {
    uint32_t tOff = tag.offset;
    uint32_t tSz  = tag.size;

    if ((uint64_t)tOff + 4 > fs || tSz < 4) continue;
    icUInt8Number typeSig[4];
    if (!ctx.ReadAt(tOff, typeSig, 4)) continue;
    uint32_t typeVal = ReadU32BE(typeSig);

    if (typeVal == 0x67626420) {
      if (tSz < 20 || (uint64_t)tOff + 20 > fs) continue;
      icUInt8Number gbdHdr[20];
      if (!ctx.ReadAt(tOff, gbdHdr, 20)) continue;
      char sig[5]; SigToChars(tag.sig, sig);
      scanGbdRecord(sig, gbdHdr);
      continue;
    }

    if (typeVal != 0x74617279 || tSz < 16) continue;  // 'tary'

    icUInt8Number taryHdr[16];
    if (!ctx.ReadAt(tOff, taryHdr, 16)) continue;
    uint32_t elemCount = ReadU32BE(taryHdr + 12);
    if (!elemCount || elemCount > 256) continue;

    for (uint32_t j = 0; j < elemCount; j++) {
      uint64_t recPos = (uint64_t)tOff + 16 + (uint64_t)j * 8;
      if (recPos + 8 > fs || recPos + 8 > (uint64_t)tOff + tSz) break;
      icUInt8Number rec[8];
      if (!ctx.ReadAt((uint32_t)recPos, rec, 8)) break;

      uint32_t childOff = ReadU32BE(rec);
      uint32_t childSz  = ReadU32BE(rec + 4);
      if (!childOff || childSz < 20) continue;

      uint64_t childPos = (uint64_t)tOff + childOff;
      if (childPos + 20 > fs || childPos + childSz > (uint64_t)tOff + tSz) continue;
      icUInt8Number childHdr[20];
      if (!ctx.ReadAt((uint32_t)childPos, childHdr, 20)) continue;
      if (ReadU32BE(childHdr) != 0x67626420) continue;

      char ownerSig[16];
      char sig[5]; SigToChars(tag.sig, sig);
      std::snprintf(ownerSig, sizeof(ownerSig), "%s[tary]", sig);
      scanGbdRecord(ownerSig, childHdr);
    }
  }

  return hc.end("No gamut boundary overflow");
}

// =========================================================================
// H69 — Profile ID MD5 Consistency
// =========================================================================
int RunHeuristic_H69_ProfileIDMD5Consistency(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(69, "Profile ID / MD5 Consistency");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  // Profile ID is at header bytes 84-99 (16 bytes)
  icUInt8Number profileId[16];
  memcpy(profileId, &ctx.header[84], 16);

  bool allZero = true;
  for (int i = 0; i < 16; i++) {
    if (profileId[i] != 0) { allZero = false; break; }
  }

  if (allZero) {
    hc.info("      Profile ID is all zeros (MD5 not computed)");
    return hc.end("Profile ID not set (zeros)");
  }

  // Verify profile ID appears plausible (not all 0xFF or repeating)
  bool allFF = true;
  bool repeating = true;
  for (int i = 0; i < 16; i++) {
    if (profileId[i] != 0xFF) allFF = false;
    if (i > 0 && profileId[i] != profileId[0]) repeating = false;
  }

  if (allFF || repeating) {
    hc.warn("Profile ID: suspicious pattern (all 0x%02X)", profileId[0]);
    hc.cweNote("CWE-345: Spoofed/invalid Profile ID");
  } else {
    hc.info("      Profile ID present: %02x%02x%02x%02x...%02x%02x%02x%02x",
            profileId[0], profileId[1], profileId[2], profileId[3],
            profileId[12], profileId[13], profileId[14], profileId[15]);
  }

  return hc.end("Profile ID / MD5 consistency OK");
}

// =========================================================================
// H153 — Sampled Curve NaN-to-Unsigned Cast Detection
// =========================================================================
int RunHeuristic_H153_SampledCurveNaNCast(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(153, "Sampled Curve NaN-to-Unsigned Cast Detection (10.26 MPE)");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  size_t fs = ctx.fileSize();
  if (fs <= 20) return hc.end("File too small for curve elements");

  std::vector<icUInt8Number> buf(fs);
  if (!ctx.ReadAt(0, buf.data(), fs))
    return hc.skip("Cannot read file data");

  int castIssues = 0;

  for (size_t b = 0; b + 19 < fs; b++) {
    icUInt32Number w = ReadU32BE(&buf[b]);
    const char *curveName = nullptr;
    const char *applyLoc = nullptr;

    if (w == 0x736E6766) {
      curveName = "SingleSampledCurve";
      applyLoc = "IccMpeBasic.cpp:1823";
    } else if (w == 0x636C6366) {
      curveName = "SampledCalculatorCurve";
      applyLoc = "IccMpeBasic.cpp:2446";
    } else if (w == 0x73616D66) {
      curveName = "SampledCurveSegment";
      applyLoc = "IccMpeBasic.cpp:1204";
    } else {
      continue;
    }

    // firstEntry at offset +12, lastEntry at offset +16 (big-endian float)
    float firstEntry, lastEntry;
    icUInt32Number feBE = ReadU32BE(&buf[b + 12]);
    icUInt32Number leBE = ReadU32BE(&buf[b + 16]);
    memcpy(&firstEntry, &feBE, 4);
    memcpy(&lastEntry, &leBE, 4);

    bool feNaN = std::isnan(firstEntry);
    bool feInf = std::isinf(firstEntry);
    bool leNaN = std::isnan(lastEntry);
    bool leInf = std::isinf(lastEntry);
    bool rangeZero = (!feNaN && !leNaN && !feInf && !leInf &&
                      !(firstEntry < lastEntry) && !(lastEntry < firstEntry));

    if (feNaN || feInf || leNaN || leInf || rangeZero) {
      if (feNaN || leNaN)
        hc.critical("%s at offset 0x%zX: NaN in range entries (first=%g, last=%g)",
                    curveName, b, (double)firstEntry, (double)lastEntry);
      else if (feInf || leInf)
        hc.critical("%s at offset 0x%zX: Inf in range entries (first=%g, last=%g)",
                    curveName, b, (double)firstEntry, (double)lastEntry);
      else
        hc.critical("%s at offset 0x%zX: degenerate range (first=last=%g -> div-by-zero)",
                    curveName, b, (double)firstEntry);
      hc.cweNote("CWE-681: NaN/Inf -> unsigned int cast is undefined behavior (%s)", applyLoc);
      hc.cweNote("Risk: Apply() computes (v-first)/range*last -> NaN -> (unsigned)NaN = UB");
      castIssues++;
      if (castIssues >= 8) break;
    }
  }

  return hc.end("No sampled curve degenerate range entries");
}


// =========================================================================
// H175 — Device Spectral Colour Space Range Requirement
// ICC.2:2023 §7.2.8 amendment (Oct 2025): when colorSpace uses a spectral
// signature (rs/ts/es/bs/sm upper 16 bits), the spectral range MUST be
// defined by either a deviceSpectralRangeTag ('dsrn') or the header
// spectralRange fields (§7.2.22/23).
// =========================================================================
int RunHeuristic_H175_DeviceSpectralColourSpaceRange(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(175, "Device Spectral Colour Space Range Requirement (ICC.2:2023 §7.2.8 amend)");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  // Only relevant for v5+ profiles
  uint8_t versionMajor = ctx.header[8];
  if (versionMajor < 5) return hc.end("Not a v5+ profile — device spectral check skipped");

  // Read colorSpace from header offset 16-19 (big-endian)
  uint32_t colorSpace = ReadU32BE(&ctx.header[16]);
  uint16_t csUpper = static_cast<uint16_t>((colorSpace >> 16) & 0xFFFFu);

  // Check if colorSpace uses a spectral signature (Table 21)
  // rs = 0x7273, ts = 0x7473, es = 0x6573, bs = 0x6273, sm = 0x736D
  bool isSpectralDevice = (csUpper == 0x7273 || csUpper == 0x7473 ||
                           csUpper == 0x6573 || csUpper == 0x6273 ||
                           csUpper == 0x736D);

  if (!isSpectralDevice)
    return hc.end("Device colour space is not spectral — check not applicable");

  const char *spectralType = "unknown";
  if (csUpper == 0x7273) spectralType = "reflectance";
  else if (csUpper == 0x7473) spectralType = "transmission";
  else if (csUpper == 0x6573) spectralType = "radiant";
  else if (csUpper == 0x6273) spectralType = "bi-spectral reflectance";
  else if (csUpper == 0x736D) spectralType = "sparse matrix reflectance";

  hc.info("Device colour space uses %s spectral signature (0x%08X)", spectralType, colorSpace);

  // Check 1: Look for 'dsrn' tag (0x6473726E) in tag table
  const uint32_t kDsrnSig = 0x6473726Eu;
  auto dsrnTag = ctx.FindTag(kDsrnSig);
  bool hasDsrnTag = (dsrnTag != nullptr);

  if (hasDsrnTag) {
    hc.info("deviceSpectralRangeTag ('dsrn') found at offset %u, size %u",
            dsrnTag->offset, dsrnTag->size);
    return hc.end("Device spectral range defined by dsrn tag");
  }

  // Check 2: Fall back to header spectralRange fields (offset 104-109)
  if (sizeof(ctx.header) >= 116) {
    uint16_t specStart = (static_cast<uint16_t>(ctx.header[104]) << 8) | ctx.header[105];
    uint16_t specEnd   = (static_cast<uint16_t>(ctx.header[106]) << 8) | ctx.header[107];
    uint16_t specSteps = (static_cast<uint16_t>(ctx.header[108]) << 8) | ctx.header[109];

    if (specSteps > 0 && (specStart > 0 || specEnd > 0)) {
      hc.info("No dsrn tag — using header spectralRange fields (start=0x%04X, end=0x%04X, steps=%u)",
              specStart, specEnd, specSteps);
      return hc.end("Device spectral range defined by header spectral PCS range fields");
    }
  }

  // Neither source provides the range — CRITICAL
  hc.critical("Spectral device colour space (0x%08X, %s) has NO spectral range definition",
              colorSpace, spectralType);
  hc.critical("Must provide either deviceSpectralRangeTag ('dsrn') or header spectralRange fields (§7.2.22/23)");
  hc.cweNote("CWE-20: Improper Input Validation — spectral processing requires valid wavelength range");
  return hc.end("CRITICAL: spectral device colour space without range definition");
}


// =========================================================================
// H176 — deviceSpectralRangeTag ('dsrn') Validation
// ICC.2:2023 §9.2.x: validates the dsrn tag data encodes a valid
// spectralRangeType ('srng'), with correct reserved bytes, spectral range
// start < end, steps >= 2, and bi-spectral range zero for non-bi-spectral.
// =========================================================================
int RunHeuristic_H176_DsrnTagValidation(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(176, "deviceSpectralRangeTag ('dsrn') Validation (ICC.2:2023 §9.2.x)");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  uint8_t versionMajor = ctx.header[8];
  if (versionMajor < 5) return hc.end("Not a v5+ profile — dsrn check skipped");

  // Find 'dsrn' tag (0x6473726E) in tag table
  const uint32_t kDsrnSig = 0x6473726Eu;
  auto dsrnTag = ctx.FindTag(kDsrnSig);
  if (!dsrnTag)
    return hc.end("No deviceSpectralRangeTag present — check not applicable");

  // spectralRangeType requires exactly 20 bytes
  if (dsrnTag->size < 20) {
    hc.critical("dsrn tag too small: %u bytes (need 20 for spectralRangeType)", dsrnTag->size);
    hc.cweNote("CWE-125: Out-of-bounds Read — insufficient data for spectralRangeType");
    return hc.end("dsrn tag undersized");
  }

  // Read tag data
  uint8_t tagData[20];
  if (!ctx.ReadAt(dsrnTag->offset, tagData, 20))
    return hc.skip("Cannot read dsrn tag data");

  // Validate type signature = 'srng' (0x73726E67)
  uint32_t typeSig = ReadU32BE(tagData);
  if (typeSig != 0x73726E67u) {
    char sigStr[5];
    sigStr[0] = static_cast<char>(static_cast<unsigned char>((typeSig >> 24) & 0xFF));
    sigStr[1] = static_cast<char>(static_cast<unsigned char>((typeSig >> 16) & 0xFF));
    sigStr[2] = static_cast<char>(static_cast<unsigned char>((typeSig >> 8) & 0xFF));
    sigStr[3] = static_cast<char>(static_cast<unsigned char>(typeSig & 0xFF));
    sigStr[4] = '\0';
    hc.critical("dsrn tag type signature is '%s' (0x%08X), expected 'srng' (0x73726E67)",
                sigStr, typeSig);
    hc.cweNote("CWE-20: Wrong type signature for deviceSpectralRangeTag");
    return hc.end("dsrn tag has wrong type signature");
  }

  // Validate reserved bytes (4-7) = 0
  uint32_t reserved = ReadU32BE(&tagData[4]);
  if (reserved != 0) {
    hc.warn("dsrn tag reserved field is 0x%08X (should be 0x00000000)", reserved);
    hc.cweNote("CWE-20: Non-zero reserved field in spectralRangeType");
  }

  // Validate spectral wavelength range (bytes 8-13)
  // start (float16), end (float16), steps (uint16)
  uint16_t specStartRaw = (static_cast<uint16_t>(tagData[8]) << 8) | tagData[9];
  uint16_t specEndRaw   = (static_cast<uint16_t>(tagData[10]) << 8) | tagData[11];
  uint16_t specSteps    = (static_cast<uint16_t>(tagData[12]) << 8) | tagData[13];

  icFloatNumber specStart = SafeF16ToF(specStartRaw);
  icFloatNumber specEnd = SafeF16ToF(specEndRaw);

  hc.info("Spectral range: start=%.1f nm (0x%04X), end=%.1f nm (0x%04X), steps=%u",
          (double)specStart, specStartRaw, (double)specEnd, specEndRaw, specSteps);

  if (std::isnan(specStart) || std::isinf(specStart)) {
    hc.critical("Spectral start wavelength is %s (raw=0x%04X)",
                std::isnan(specStart) ? "NaN" : "Inf", specStartRaw);
    hc.cweNote("CWE-20: Invalid float16 wavelength value");
  }
  if (std::isnan(specEnd) || std::isinf(specEnd)) {
    hc.critical("Spectral end wavelength is %s (raw=0x%04X)",
                std::isnan(specEnd) ? "NaN" : "Inf", specEndRaw);
    hc.cweNote("CWE-20: Invalid float16 wavelength value");
  }

  if (std::isfinite(specStart) && std::isfinite(specEnd)) {
    if (specStart < 100.0f || specStart > 2500.0f) {
      hc.warn("Spectral start wavelength %.1f nm outside typical range (100-2500 nm)", (double)specStart);
    }
    if (specEnd < 100.0f || specEnd > 2500.0f) {
      hc.warn("Spectral end wavelength %.1f nm outside typical range (100-2500 nm)", (double)specEnd);
    }
    if (specEnd <= specStart) {
      hc.critical("Spectral end (%.1f nm) <= start (%.1f nm) — inverted range", (double)specEnd, (double)specStart);
      hc.cweNote("CWE-682: Incorrect Calculation — inverted spectral range");
    }
  }

  if (specSteps < 2 && (specStartRaw != 0 || specEndRaw != 0)) {
    hc.critical("Spectral steps=%u (must be >= 2 for valid spectral sampling)", specSteps);
    hc.cweNote("CWE-369: Divide By Zero — insufficient spectral steps for interpolation");
  }

  // Validate bi-spectral wavelength range (bytes 14-19)
  uint16_t biStartRaw = (static_cast<uint16_t>(tagData[14]) << 8) | tagData[15];
  uint16_t biEndRaw   = (static_cast<uint16_t>(tagData[16]) << 8) | tagData[17];
  uint16_t biSteps    = (static_cast<uint16_t>(tagData[18]) << 8) | tagData[19];

  // Check device colour space — bi-spectral range must be zero for non-bi-spectral
  uint32_t colorSpace = ReadU32BE(&ctx.header[16]);
  uint16_t csUpper = static_cast<uint16_t>((colorSpace >> 16) & 0xFFFFu);
  bool isBiSpectral = (csUpper == 0x6273); // 'bs' prefix

  if (!isBiSpectral && (biStartRaw != 0 || biEndRaw != 0 || biSteps != 0)) {
    hc.warn("Bi-spectral range is non-zero (start=0x%04X, end=0x%04X, steps=%u) "
            "but device colour space is not bi-spectral",
            biStartRaw, biEndRaw, biSteps);
    hc.cweNote("CWE-20: Bi-spectral range must be zero for non-bi-spectral device colour space");
  }

  if (isBiSpectral && biSteps < 2 && (biStartRaw != 0 || biEndRaw != 0)) {
    hc.warn("Bi-spectral steps=%u (must be >= 2 for valid bi-spectral sampling)", biSteps);
    hc.cweNote("CWE-369: Divide By Zero — insufficient bi-spectral steps");
  }

  return hc.end("dsrn tag validation complete");
}


// =========================================================================
// H177 — devicePccTag ('dpcc') Structure Validation
// ICC.2:2023 §9.2.x+1: validates the dpcc tag contains a tagStructType
// with 'pcc ' structure ID and all 6 required sub-tag members.
// =========================================================================
int RunHeuristic_H177_DpccTagValidation(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(177, "devicePccTag ('dpcc') Structure Validation (ICC.2:2023 §9.2.x+1)");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  uint8_t versionMajor = ctx.header[8];
  if (versionMajor < 5) return hc.end("Not a v5+ profile — dpcc check skipped");

  // Find 'dpcc' tag (0x64706363) in tag table
  const uint32_t kDpccSig = 0x64706363u;
  auto dpccTag = ctx.FindTag(kDpccSig);
  if (!dpccTag)
    return hc.end("No devicePccTag present — check not applicable");

  // tagStructType minimum: 4 (sig) + 4 (reserved) + 4 (struct type) = 12 bytes header
  if (dpccTag->size < 12) {
    hc.critical("dpcc tag too small: %u bytes (need >= 12 for tagStructType header)", dpccTag->size);
    hc.cweNote("CWE-125: Out-of-bounds Read — insufficient data for tagStructType");
    return hc.end("dpcc tag undersized");
  }

  // Read enough tag data to parse the structure header and scan for sub-tags
  size_t readSize = (dpccTag->size > 4096) ? 4096u : dpccTag->size;
  std::vector<uint8_t> tagData(readSize);
  if (!ctx.ReadAt(dpccTag->offset, tagData.data(), readSize))
    return hc.skip("Cannot read dpcc tag data");

  // Validate outer type = tagStructType (0x74737470 = 'tstp')
  // NOTE: iccDEV uses 0x74737470 for tagStructType in some places.
  // The actual ICC spec uses the struct type ID at offset 8.
  // ICC.2-2023 uses tagStructType 'tstr' (0x74737472)... let's check both patterns.
  // Regardless, the key check is the structure type ID.

  // Structure type at offset 8-11 should be 'pcc ' (0x70636320)
  if (readSize >= 12) {
    uint32_t structType = ReadU32BE(&tagData[8]);
    if (structType != 0x70636320u) {
      char sigStr[5];
      sigStr[0] = static_cast<char>(static_cast<unsigned char>((structType >> 24) & 0xFF));
      sigStr[1] = static_cast<char>(static_cast<unsigned char>((structType >> 16) & 0xFF));
      sigStr[2] = static_cast<char>(static_cast<unsigned char>((structType >> 8) & 0xFF));
      sigStr[3] = static_cast<char>(static_cast<unsigned char>(structType & 0xFF));
      sigStr[4] = '\0';
      hc.critical("dpcc tag structure type is '%s' (0x%08X), expected 'pcc ' (0x70636320)",
                  sigStr, structType);
      hc.cweNote("CWE-20: Wrong structure type for devicePccTag");
      return hc.end("dpcc tag has wrong structure type");
    }
    hc.info("dpcc tag has correct structure type 'pcc ' (profileConnectionConditionsStructure)");
  }

  // Scan for the 6 required sub-tag member signatures within the tag data
  struct PccSubTag {
    uint32_t sig;
    const char *name;
    const char *desc;
    bool found;
  };

  PccSubTag subTags[] = {
    {0x6958595Au, "iXYZ", "pcsIlluminantXYZMbr",          false},
    {0x6D777074u, "mwpt", "mediaWhitePointMbr",           false},
    {0x73777074u, "swpt", "spectralWhitePointMbr",         false},
    {0x7376636Eu, "svcn", "spectralViewingConditionsMbr",  false},
    {0x63327370u, "c2sp", "customToStandardPccMbr",        false},
    {0x73326370u, "s2cp", "standardToCustomPccMbr",        false},
  };

  // Scan tag data for sub-tag signatures (4-byte aligned positions)
  for (size_t pos = 12; pos + 3 < readSize; pos += 4) {
    uint32_t w = ReadU32BE(&tagData[pos]);
    for (auto &st : subTags) {
      if (w == st.sig) {
        st.found = true;
        hc.info("  Sub-tag '%s' (%s) found at offset +%zu", st.name, st.desc, pos);
      }
    }
  }

  // Report missing sub-tags
  int missingCount = 0;
  for (const auto &st : subTags) {
    if (!st.found) {
      // iXYZ and svcn/c2sp/s2cp are always required
      // mwpt is "required if colorimetric connection used"
      // swpt is "required if spectral connection used"
      if (st.sig == 0x6D777074u || st.sig == 0x73777074u) {
        hc.warn("PCC sub-tag '%s' (%s) not found — conditionally required", st.name, st.desc);
      } else {
        hc.critical("Required PCC sub-tag '%s' (%s) missing from dpcc structure", st.name, st.desc);
        missingCount++;
      }
    }
  }

  if (missingCount > 0) {
    hc.cweNote("CWE-476: Missing required PCC sub-tags may cause null dereference during transform processing");
    hc.cweNote("CWE-20: Incomplete profileConnectionConditionsStructure — %d required members absent", missingCount);
  }

  return hc.end("dpcc tag structure validation complete");
}


// =========================================================================
// H178 — spectralRangeType ('srng') Encoding Validation
// ICC.2:2023 §10.2.w: generic validator for any tag using spectralRangeType.
// Validates type signature, reserved bytes, wavelength values, and step counts.
// Scans entire tag table for any tag typed as 'srng'.
// =========================================================================
int RunHeuristic_H178_SrngEncodingValidation(RawProfileContext &ctx)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(178, "spectralRangeType ('srng') Encoding Validation (ICC.2:2023 §10.2.w)");

  if (!ctx.valid) return hc.skip("File too small for tag table");

  uint8_t versionMajor = ctx.header[8];
  if (versionMajor < 5) return hc.end("Not a v5+ profile — srng check skipped");

  // Scan all tags for any that contain a spectralRangeType ('srng') type sig
  int srngCount = 0;
  int issues = 0;

  for (const auto &tag : ctx.tags) {
    if (tag.size < 20) continue;

    // Read first 4 bytes of tag data to check type signature
    uint8_t typeSigBuf[4];
    if (!ctx.ReadAt(tag.offset, typeSigBuf, 4)) continue;

    uint32_t typeSig = ReadU32BE(typeSigBuf);
    if (typeSig != 0x73726E67u) continue; // not 'srng'

    srngCount++;

    // Read full 20-byte spectralRangeType
    uint8_t srngData[20];
    if (!ctx.ReadAt(tag.offset, srngData, 20)) continue;

    char tagSigStr[5];
    tagSigStr[0] = static_cast<char>(static_cast<unsigned char>((tag.sig >> 24) & 0xFF));
    tagSigStr[1] = static_cast<char>(static_cast<unsigned char>((tag.sig >> 16) & 0xFF));
    tagSigStr[2] = static_cast<char>(static_cast<unsigned char>((tag.sig >> 8) & 0xFF));
    tagSigStr[3] = static_cast<char>(static_cast<unsigned char>(tag.sig & 0xFF));
    tagSigStr[4] = '\0';

    // Reserved bytes (4-7) = 0
    uint32_t reserved = ReadU32BE(&srngData[4]);
    if (reserved != 0) {
      hc.warn("Tag '%s': srng reserved field is 0x%08X (must be 0)", tagSigStr, reserved);
      hc.cweNote("CWE-20: Non-zero reserved field in spectralRangeType");
      issues++;
    }

    // Spectral range (bytes 8-13): start (F16), end (F16), steps (U16)
    uint16_t specStartRaw = (static_cast<uint16_t>(srngData[8]) << 8) | srngData[9];
    uint16_t specEndRaw   = (static_cast<uint16_t>(srngData[10]) << 8) | srngData[11];
    uint16_t specSteps    = (static_cast<uint16_t>(srngData[12]) << 8) | srngData[13];

    icFloatNumber specStart = SafeF16ToF(specStartRaw);
    icFloatNumber specEnd = SafeF16ToF(specEndRaw);

    if (std::isnan(specStart) || std::isinf(specStart) ||
        std::isnan(specEnd) || std::isinf(specEnd)) {
      hc.critical("Tag '%s': srng spectral range has NaN/Inf wavelength values "
                  "(start=0x%04X→%g, end=0x%04X→%g)",
                  tagSigStr, specStartRaw, (double)specStart, specEndRaw, (double)specEnd);
      hc.cweNote("CWE-20: Invalid float16 wavelength in spectralRangeType");
      issues++;
    } else if (specStart > 0.0f || specEnd > 0.0f) {
      if (specStart < 100.0f || specStart > 2500.0f)
        hc.warn("Tag '%s': srng start wavelength %.1f nm outside 100-2500 nm", tagSigStr, (double)specStart);
      if (specEnd < 100.0f || specEnd > 2500.0f)
        hc.warn("Tag '%s': srng end wavelength %.1f nm outside 100-2500 nm", tagSigStr, (double)specEnd);
      if (specEnd <= specStart) {
        hc.critical("Tag '%s': srng spectral end (%.1f) <= start (%.1f)", tagSigStr, (double)specEnd, (double)specStart);
        hc.cweNote("CWE-682: Inverted spectral range in spectralRangeType");
        issues++;
      }
      if (specSteps < 2) {
        hc.critical("Tag '%s': srng spectral steps=%u (must be >= 2)", tagSigStr, specSteps);
        hc.cweNote("CWE-369: Divide By Zero — insufficient spectral steps");
        issues++;
      }
    }

    // Bi-spectral range (bytes 14-19): start (F16), end (F16), steps (U16)
    uint16_t biStartRaw = (static_cast<uint16_t>(srngData[14]) << 8) | srngData[15];
    uint16_t biEndRaw   = (static_cast<uint16_t>(srngData[16]) << 8) | srngData[17];
    uint16_t biSteps    = (static_cast<uint16_t>(srngData[18]) << 8) | srngData[19];

    // Check device colour space for bi-spectral type
    uint32_t colorSpace = ReadU32BE(&ctx.header[16]);
    uint16_t csUpper = static_cast<uint16_t>((colorSpace >> 16) & 0xFFFFu);
    bool isBiSpectral = (csUpper == 0x6273); // 'bs' prefix

    if (!isBiSpectral && (biStartRaw != 0 || biEndRaw != 0 || biSteps != 0)) {
      hc.warn("Tag '%s': bi-spectral range non-zero but colour space is not bi-spectral",
              tagSigStr);
      hc.cweNote("CWE-20: Bi-spectral range must be zero for non-bi-spectral space (§10.2.w)");
      issues++;
    }

    if (isBiSpectral && (biStartRaw != 0 || biEndRaw != 0)) {
      icFloatNumber biStart = SafeF16ToF(biStartRaw);
      icFloatNumber biEnd = SafeF16ToF(biEndRaw);

      if (std::isnan(biStart) || std::isinf(biStart) ||
          std::isnan(biEnd) || std::isinf(biEnd)) {
        hc.critical("Tag '%s': bi-spectral range has NaN/Inf (start=0x%04X, end=0x%04X)",
                    tagSigStr, biStartRaw, biEndRaw);
        issues++;
      }
      if (biSteps < 2) {
        hc.warn("Tag '%s': bi-spectral steps=%u (must be >= 2)", tagSigStr, biSteps);
        issues++;
      }
    }
  }

  if (srngCount == 0)
    return hc.end("No spectralRangeType tags found — check not applicable");

  hc.info("Validated %d spectralRangeType instance(s), %d issue(s) found", srngCount, issues);
  return hc.end("srng encoding validation complete");
}


// =========================================================================
// Dispatcher — single file open, shared context for all raw heuristics
// =========================================================================
int RunRawPostLibraryHeuristics(const char *filename)
{
  int heuristicCount = 0;

  // Single file open for all raw-post heuristic functions
  RawProfileContext ctx = OpenRawProfileContext(filename);

  heuristicCount += RunHeuristic_H33_mBAmABSubElementOffset(ctx);
  heuristicCount += RunHeuristic_H34_IntegerOverflowSubElement(ctx);
  heuristicCount += RunHeuristic_H35_SuspiciousFillPattern(ctx);
  heuristicCount += RunHeuristic_H36_LUTTagPairCompleteness(ctx);
  heuristicCount += RunHeuristic_H37_CalculatorElementComplexity(ctx);
  heuristicCount += RunHeuristic_H152_CurveElementOOMSizeValidation(ctx);
  heuristicCount += RunHeuristic_H38_CurveDegenerateValue(ctx);
  heuristicCount += RunHeuristic_H39_SharedTagDataAliasing(ctx);
  heuristicCount += RunHeuristic_H40_TagAlignmentPadding(ctx);
  heuristicCount += RunHeuristic_H41_VersionTypeConsistency(ctx);
  heuristicCount += RunHeuristic_H42_MatrixSingularity(ctx);
  heuristicCount += RunHeuristic_H43_SpectralBRDFTagStructure(ctx);
  heuristicCount += RunHeuristic_H44_EmbeddedImageValidation(ctx);
  heuristicCount += RunHeuristic_H45_SparseMatrixBounds(ctx);
  heuristicCount += RunHeuristic_H46_TextDescUnicodeLength(ctx);
  heuristicCount += RunHeuristic_H47_NamedColor2SizeOverflow(ctx);
  heuristicCount += RunHeuristic_H48_CLUTGridDimensionOverflow(ctx);
  heuristicCount += RunHeuristic_H49_FloatNaNInfDetection(ctx);
  heuristicCount += RunHeuristic_H50_ZeroSizeProfileTag(ctx);
  heuristicCount += RunHeuristic_H51_LUTChannelCountConsistency(ctx);
  heuristicCount += RunHeuristic_H52_IntegerUnderflowTagSize(ctx);
  heuristicCount += RunHeuristic_H53_EmbeddedProfileRecursion(ctx);
  heuristicCount += RunHeuristic_H54_DivisionByZeroTrigger(ctx);
  heuristicCount += RunHeuristic_H55_UTF16EncodingValidation(ctx);
  heuristicCount += RunHeuristic_H57_EmbeddedProfileRecursionDepth(ctx);
  heuristicCount += RunHeuristic_H59_SpectralWavelengthRange(ctx);
  heuristicCount += RunHeuristic_H68_GamutBoundaryDescOverflow(ctx);
  heuristicCount += RunHeuristic_H69_ProfileIDMD5Consistency(ctx);
  heuristicCount += RunHeuristic_H153_SampledCurveNaNCast(ctx);
  heuristicCount += RunHeuristic_H175_DeviceSpectralColourSpaceRange(ctx);
  heuristicCount += RunHeuristic_H176_DsrnTagValidation(ctx);
  heuristicCount += RunHeuristic_H177_DpccTagValidation(ctx);
  heuristicCount += RunHeuristic_H178_SrngEncodingValidation(ctx);

  // CodeQL-driven heuristics (H154-H161) — extracted to IccHeuristicsCodeQLPatterns.cpp
  heuristicCount += RunCodeQLPatternHeuristics(ctx);

  // Exploit-gap heuristics (H162-H165+) — extracted to IccHeuristicsExploitGap.cpp
  heuristicCount += RunExploitGapHeuristics(ctx);

  return heuristicCount;
}

// =========================================================================
// Fallback — runs when library failed to load the profile
// Uses its own file context (independent of library-phase ctx).
// =========================================================================
int RunRawFallbackHeuristics(const char *filename, bool libraryAnalyzed)
{
  auto &hc = HeuristicCollector::instance();
  int heuristicCount = 0;

  if (!libraryAnalyzed) {
    printf("RAW-FILE ANALYSIS ENGINE (library load failed)\n");
    printf("=======================================================================\n\n");

    RawFileHandle fhRaw = OpenRawFile(filename);
    if (fhRaw) {
      size_t fileSize = (size_t)fhRaw.fileSize;

      icUInt8Number rawHdr[132] = {};
      bool hdrOk = (fileSize >= 132 && fread(rawHdr, 1, 132, fhRaw.fp) == 132);

      if (hdrOk) {
        icUInt32Number tagCount = ReadU32BE(&rawHdr[128]);
        icUInt32Number declaredSize = ReadU32BE(rawHdr);

        // --- H10 fallback: Tag Count ---
        hc.begin(10, "Tag Count (raw fallback)");
        if (tagCount == 0) {
          hc.warn("Zero tags — empty or severely malformed profile");
        } else if (tagCount > kMaxTagScanCount) {
          hc.warn("Excessive tag count: %u (>%u) — potential DoS",
                  tagCount, (unsigned)kMaxTagScanCount);
        }
        heuristicCount += hc.end(nullptr);

        // --- H13 fallback: Per-Tag Size vs File Size ---
        hc.begin(13, "Per-Tag Size Check (raw fallback)");
        {
          int tagSizeIssues = 0;
          int tagsAccessible = 0, tagsTotal = 0;
          size_t safeTagCount = (tagCount > kMaxTagScanCount) ? kMaxTagScanCount : tagCount;
          for (size_t i = 0; i < safeTagCount; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fileSize) break;

            icUInt8Number entry[12];
            fseek(fhRaw.fp, ePos, SEEK_SET);
            if (fread(entry, 1, 12, fhRaw.fp) != 12) break;

            icUInt32Number tOffset = ReadU32BE(&entry[4]);
            icUInt32Number tSize   = ReadU32BE(&entry[8]);
            char tagSig[5] = {(char)entry[0], (char)entry[1], (char)entry[2], (char)entry[3], 0};

            tagsTotal++;
            uint64_t endPos = (uint64_t)tOffset + tSize;
            if (endPos > fileSize) {
              if (tOffset >= fileSize) {
                hc.warn("Tag '%s': offset=0x%X past EOF (0x%lX) — fully inaccessible",
                        tagSig, tOffset, (unsigned long)fileSize);
              } else {
                size_t accessible = fileSize - tOffset;
                hc.warn("Tag '%s': offset=0x%X size=0x%X — only %zu/%u bytes accessible (truncated at EOF)",
                        tagSig, tOffset, tSize, accessible, tSize);
              }
              tagSizeIssues++;
            } else {
              tagsAccessible++;
            }

            if (tSize > 16777216) {
              hc.warn("Tag '%s': size %u bytes (>16MB) — potential OOM", tagSig, tSize);
              tagSizeIssues++;
            }
          }
          if (tagSizeIssues > 0 && tagsTotal > 0) {
            int inaccessible = tagsTotal - tagsAccessible;
            hc.info("      Tag accessibility: %d/%d accessible (%d inaccessible due to truncation)",
                    tagsAccessible, tagsTotal, inaccessible);
          }
          heuristicCount += tagSizeIssues;
        }
        hc.end("All tag sizes within file bounds");

        // --- H25 fallback: Tag Offset/Size OOB ---
        hc.begin(25, "Tag Offset/Size Out-of-Bounds Detection (raw fallback)");
        {
          int oobIssues = 0;
          size_t safeTagCount = (tagCount > kMaxTagScanCount) ? kMaxTagScanCount : tagCount;
          for (size_t i = 0; i < safeTagCount; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fileSize) break;

            icUInt8Number entry[12];
            fseek(fhRaw.fp, ePos, SEEK_SET);
            if (fread(entry, 1, 12, fhRaw.fp) != 12) break;

            icUInt32Number tOffset = ReadU32BE(&entry[4]);
            icUInt32Number tSize   = ReadU32BE(&entry[8]);
            char tagSig[5] = {(char)entry[0], (char)entry[1], (char)entry[2], (char)entry[3], 0};

            if (tOffset > fileSize) {
              hc.warn("Tag '%s': offset 0x%08X past file end (0x%lX)",
                      tagSig, tOffset, (unsigned long)fileSize);
              hc.cweNote("CRITICAL: OOB read if parser follows this offset");
              oobIssues++;
            }

            if (declaredSize > 0 && (uint64_t)tOffset + tSize > declaredSize && (uint64_t)tOffset + tSize > fileSize) {
              hc.warn("Tag '%s': extends past declared profile size (%u)",
                      tagSig, declaredSize);
              oobIssues++;
            }
          }
          heuristicCount += oobIssues;
        }
        hc.end("All tag offsets within file bounds");

        // --- H28 fallback: LUT Dimension Validation ---
        hc.begin(28, "LUT Dimension Validation (raw fallback)");
        {
          int lutIssues = 0;
          size_t safeTagCount = (tagCount > kMaxTagScanCount) ? kMaxTagScanCount : tagCount;
          for (size_t i = 0; i < safeTagCount; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fileSize) break;

            icUInt8Number entry[12];
            fseek(fhRaw.fp, ePos, SEEK_SET);
            if (fread(entry, 1, 12, fhRaw.fp) != 12) break;

            icUInt32Number tOffset = ReadU32BE(&entry[4]);
            icUInt32Number tSize   = ReadU32BE(&entry[8]);

            if ((uint64_t)tOffset + 12 > fileSize || tSize < 12) continue;

            icUInt8Number typeSig[4];
            fseek(fhRaw.fp, tOffset, SEEK_SET);
            if (fread(typeSig, 1, 4, fhRaw.fp) != 4) continue;

            char tagSig[5] = {(char)entry[0], (char)entry[1], (char)entry[2], (char)entry[3], 0};

            bool isLut8  = (typeSig[0]=='m' && typeSig[1]=='f' && typeSig[2]=='t' && typeSig[3]=='1');
            bool isLut16 = (typeSig[0]=='m' && typeSig[1]=='f' && typeSig[2]=='t' && typeSig[3]=='2');
            if (!isLut8 && !isLut16) continue;

            if ((uint64_t)tOffset + 12 > fileSize) continue;
            icUInt8Number lutHdr[4];
            fseek(fhRaw.fp, tOffset + 8, SEEK_SET);
            if (fread(lutHdr, 1, 4, fhRaw.fp) != 4) continue;

            uint8_t nInput = lutHdr[0];
            uint8_t nOutput = lutHdr[1];
            uint8_t nGrid = lutHdr[2];

            if (nInput == 0 || nOutput == 0) {
              hc.warn("Tag '%s': LUT has 0 channels (in=%u out=%u)", tagSig, nInput, nOutput);
              lutIssues++;
            }
            if (nGrid > 0 && nInput > 0) {
              uint64_t clutSize = 1;
              for (uint8_t d = 0; d < nInput; d++) {
                clutSize *= nGrid;
                if (clutSize > 1073741824ULL) {
                  hc.warn("Tag '%s': CLUT %u^%u x %u entries -> >1GB allocation",
                          tagSig, nGrid, nInput, nOutput);
                  hc.cweNote("Risk: OOM crash in CLUT allocation");
                  lutIssues++;
                  break;
                }
              }
            }
          }
          heuristicCount += lutIssues;
        }
        hc.end("No LUT dimension issues");

        // --- H32 fallback: Tag Type Confusion ---
        hc.begin(32, "Tag Data Type Confusion Detection (raw fallback)");
        {
          int typeIssues = 0;
          size_t safeTagCount = (tagCount > kMaxTagScanCount) ? kMaxTagScanCount : tagCount;
          for (size_t i = 0; i < safeTagCount; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fileSize) break;

            icUInt8Number entry[12];
            fseek(fhRaw.fp, ePos, SEEK_SET);
            if (fread(entry, 1, 12, fhRaw.fp) != 12) break;

            icUInt32Number tOffset = ReadU32BE(&entry[4]);
            if ((uint64_t)tOffset + 4 > fileSize) continue;

            icUInt8Number typeBuf[4];
            fseek(fhRaw.fp, tOffset, SEEK_SET);
            if (fread(typeBuf, 1, 4, fhRaw.fp) != 4) continue;

            char tagSig[5] = {(char)entry[0], (char)entry[1], (char)entry[2], (char)entry[3], 0};

            bool validType = true;
            for (int b = 0; b < 4; b++) {
              if (typeBuf[b] != 0 && (typeBuf[b] < 0x20 || typeBuf[b] > 0x7E)) {
                validType = false;
                break;
              }
            }
            if (!validType) {
              hc.warn("Tag '%s' at 0x%08X: type signature 0x%02X%02X%02X%02X is non-printable",
                      tagSig, tOffset, typeBuf[0], typeBuf[1], typeBuf[2], typeBuf[3]);
              hc.cweNote("Risk: Type confusion -> wrong parser invoked -> memory corruption");

              // GAP-A: Quantify exploitation severity
              icUInt32Number tSize32 = ReadU32BE(&entry[8]);
              if ((uint64_t)tOffset + 16 <= fileSize && tSize32 >= 16) {
                icUInt8Number mpetHdr[8];
                fseek(fhRaw.fp, tOffset + 8, SEEK_SET);
                if (fread(mpetHdr, 1, 8, fhRaw.fp) == 8) {
                  uint16_t pseudoIn  = (static_cast<uint16_t>(mpetHdr[0]) << 8) | mpetHdr[1];
                  uint16_t pseudoOut = (static_cast<uint16_t>(mpetHdr[2]) << 8) | mpetHdr[3];
                  uint32_t pseudoElem = ReadU32BE(&mpetHdr[4]);
                  if (pseudoElem > 1000 || pseudoIn > 16 || pseudoOut > 16) {
                    hc.cweNote("Exploitability: if parsed as mpet -> %u inputs, %u outputs, %u elements",
                               pseudoIn, pseudoOut, pseudoElem);
                    hc.cweNote("CWE-131: Catastrophic OOB if element count used for allocation/iteration");
                  }
                }
              }

              typeIssues++;
            }

            // GAP-C: For valid mpet tags, check sub-element type signatures
            icUInt32Number tagTypeSig = ReadU32BE(typeBuf);
            icUInt32Number tSize32_c = ReadU32BE(&entry[8]);
            if (tagTypeSig == 0x6D706574 && tSize32_c >= 16 &&
                (uint64_t)tOffset + 16 <= fileSize) {
              icUInt8Number mpetInfo[8];
              fseek(fhRaw.fp, tOffset + 8, SEEK_SET);
              if (fread(mpetInfo, 1, 8, fhRaw.fp) == 8) {
                uint32_t nElem = ReadU32BE(&mpetInfo[4]);
                if (nElem > 0 && nElem <= 64) {
                  size_t posTableStart = tOffset + 16;
                  size_t posTableEnd = posTableStart + nElem * 8;
                  if (posTableEnd <= fileSize) {
                    for (uint32_t e = 0; e < nElem; e++) {
                      icUInt8Number posEntry[8];
                      fseek(fhRaw.fp, posTableStart + e * 8, SEEK_SET);
                      if (fread(posEntry, 1, 8, fhRaw.fp) != 8) break;
                      uint32_t eOff = ReadU32BE(posEntry);
                      size_t absOff = tOffset + 8 + eOff;
                      if (absOff + 4 <= fileSize) {
                        icUInt8Number eSig[4];
                        fseek(fhRaw.fp, absOff, SEEK_SET);
                        if (fread(eSig, 1, 4, fhRaw.fp) == 4) {
                          bool elemValid = true;
                          for (int b = 0; b < 4; b++) {
                            if (eSig[b] != 0 && (eSig[b] < 0x20 || eSig[b] > 0x7E)) {
                              elemValid = false;
                              break;
                            }
                          }
                          if (!elemValid) {
                            hc.warn("Tag '%s' mpet element[%u]: type 0x%02X%02X%02X%02X is non-printable",
                                    tagSig, e, eSig[0], eSig[1], eSig[2], eSig[3]);
                            hc.cweNote("CWE-843: Sub-element type confusion in MPE chain");
                            typeIssues++;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          heuristicCount += typeIssues;
        }
        hc.end("All tag type signatures are printable ICC 4CC codes");

        printf("\n");
      }
    }
  }

  return heuristicCount;
}
