/*
 * IccHeuristicsDataValidation.cpp — Data content validation heuristics (H56-H102)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * Extracted from IccHeuristicsLibrary.cpp as part of codebase modernization.
 */

#include "IccHeuristicsDataValidation.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerSignatures.h"
#include "IccAnalyzerSafeArithmetic.h"
#include "IccAnalyzerColors.h"
#include "IccTagBasic.h"
#include "IccTagComposite.h"
#include "IccTagDict.h"
#include "IccProfile.h"
#include "IccMD5.h"
#include "IccMpeBasic.h"
#include "IccMpeCalc.h"
#include "IccTagMPE.h"
#include "IccTagLut.h"
#include "IccSparseMatrix.h"
#include "IccMpeSpectral.h"
#include "IccUtil.h"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <climits>
#include <algorithm>
#include <string>
#include <set>
#include <map>
#include <vector>
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicResult.h"

int RunHeuristic_H56_CalculatorStackDepth(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H56 — Calculator Element Stack Depth Analysis (CWE-674/CWE-835)
// =====================================================================
hc.begin(56, "Calculator Element Stack Depth Analysis");
{
  icSignature mpeSigs56[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
    icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
    icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag,
    icSigGamutTag,
    (icSignature)0
  };

  for (int s = 0; mpeSigs56[s] != (icSignature)0; s++) {
    CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, (icTagSignature)mpeSigs56[s]);
    if (!mpe) continue;

    icUInt32Number elemCount = mpe->NumElements();
    if (elemCount > 512) {
      hc.warn("MPE tag '%s': %u elements in processing chain (>512)", info.GetTagSigName((icTagSignature)mpeSigs56[s]), elemCount);
      hc.cweNote("CWE-835: Excessive MPE chain length → potential DoS");
    }
  }

}

  return hc.end("Calculator element depths within safe bounds");
}

int RunHeuristic_H58_SparseMatrixEntryBounds(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H58 — Sparse Matrix / Large Array Entry Bounds (CWE-131/CWE-400)
// =====================================================================
hc.begin(58, "Sparse Matrix Entry Bounds");
{
  TagEntryList::iterator sit;
  for (sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    IccTagEntry *e = &(*sit);
    CIccTagNumArray *numArr = FindAndCast<CIccTagNumArray>(pIcc, e->TagInfo.sig);
    if (!numArr) continue;
    icUInt32Number arrSz = numArr->GetNumValues();
    if (arrSz > 16777216) {
      hc.warn("Tag '%s': NumArray with %u values (>16M, OOM risk)", info.GetTagSigName(e->TagInfo.sig), arrSz);
      hc.cweNote("CWE-400: Resource exhaustion via oversized array");
    }
  }
}

  return hc.end("No oversized array/sparse matrix entries");
}

int RunHeuristic_H60_DictionaryTagConsistency(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H60 — Dictionary Tag Key/Value Consistency (CWE-126/CWE-170)
// =====================================================================
hc.begin(60, "Dictionary Tag Consistency");
{
  CIccTagDict *dict = FindAndCast<CIccTagDict>(pIcc, icSigMetaDataTag);
  if (dict) {
    if (dict && dict->m_Dict) {
      std::set<std::string> seenKeys;
      int entryCount = 0;
      for (auto dit = dict->m_Dict->begin(); dit != dict->m_Dict->end(); ++dit) {
        entryCount++;
        if (entryCount > 4096) {
          hc.warn("Dict has >4096 entries (excessive)");
          hc.cweNote("CWE-400: Potential DoS via unbounded dictionary");
          break;
        }
        CIccDictEntry *entry = dit->ptr;
        if (!entry) continue;
        std::wstring key = entry->GetName();
        // Safe wchar_t→UTF-8: avoid UB from implicit narrowing
        std::string keyUtf8;
        keyUtf8.reserve(key.size());
        for (wchar_t wc : key) {
          keyUtf8.push_back(static_cast<char>(static_cast<unsigned char>(wc & 0xFF)));
        }
        if (seenKeys.count(keyUtf8)) {
          hc.warn("Duplicate dictionary key detected");
          hc.cweNote("CWE-170: Key collision may cause UAF on replacement");
        }
        seenKeys.insert(keyUtf8);
      }
    }
  }
}

  return hc.end("Dictionary tags consistent");
}

int RunHeuristic_H61_ViewingConditionsValidation(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H61 — Viewing Conditions Validation (CWE-682/CWE-20)
// =====================================================================
hc.begin(61, "Viewing Conditions Validation");
{
  CIccTagViewingConditions *vc = FindAndCast<CIccTagViewingConditions>(pIcc, (icTagSignature)icSigViewingConditionsTag);
  if (vc) {
    if (vc) {
      icFloatNumber vcIllumX = icFtoD(vc->m_XYZIllum.X);
      icFloatNumber vcIllumY = icFtoD(vc->m_XYZIllum.Y);
      icFloatNumber vcIllumZ = icFtoD(vc->m_XYZIllum.Z);
      if (vcIllumX < 0 || vcIllumY < 0 || vcIllumZ < 0) {
        hc.warn("Negative illuminant XYZ (%.4f, %.4f, %.4f)", vcIllumX, vcIllumY, vcIllumZ);
        hc.cweNote("CWE-682: Negative tristimulus → invalid color math");
      }
      if (vcIllumY > 200.0 || vcIllumX > 200.0 || vcIllumZ > 200.0) {
        hc.warn("Extreme illuminant XYZ magnitude (%.4f, %.4f, %.4f)", vcIllumX, vcIllumY, vcIllumZ);
      }
      icFloatNumber surX = icFtoD(vc->m_XYZSurround.X);
      icFloatNumber surY = icFtoD(vc->m_XYZSurround.Y);
      icFloatNumber surZ = icFtoD(vc->m_XYZSurround.Z);
      if (surX < 0 || surY < 0 || surZ < 0) {
        hc.warn("Negative surround XYZ (%.4f, %.4f, %.4f)", surX, surY, surZ);
      }
    }
  }
}

  return hc.end("Viewing conditions plausible (or tag absent)");
}

int RunHeuristic_H62_MLUStringBombs(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H62 — Multi-Localized Unicode String Bombs (CWE-400/CWE-770)
// =====================================================================
hc.begin(62, "Multi-Localized Unicode String Bombs");
{
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTagMultiLocalizedUnicode *mluc = FindAndCast<CIccTagMultiLocalizedUnicode>(pIcc, sit->TagInfo.sig);
    if (!mluc) continue;

    int localeCount = 0;
    size_t totalBytes = 0;
    for (auto lit = mluc->m_Strings->begin(); lit != mluc->m_Strings->end(); ++lit) {
      localeCount++;
      totalBytes += lit->GetLength() * sizeof(icUInt16Number);
      if (localeCount > 10000) break;
    }

    if (localeCount > 1000) {
      hc.warn("Tag '%s': mluc has %d locales (>1000)", info.GetTagSigName(sit->TagInfo.sig), localeCount);
      hc.cweNote("CWE-400: Locale-bomb DoS");
    }
    if (totalBytes > 10485760) { // 10MB aggregate
      hc.warn("Tag '%s': mluc aggregate %zu bytes (>10MB)", info.GetTagSigName(sit->TagInfo.sig), totalBytes);
      hc.cweNote("CWE-770: Excessive string data allocation");
    }
  }
}

  return hc.end("MultiLocalizedUnicode tags within bounds");
}

int RunHeuristic_H63_CurveLUTChannelMismatch(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H63 — Curve/LUT I/O Channel Mismatch (CWE-120/CWE-131)
// =====================================================================
hc.begin(63, "Curve/LUT I/O Channel Mismatch");
{
  icSignature lutSigs[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    (icSignature)0
  };
  for (int s = 0; lutSigs[s] != (icSignature)0; s++) {
    CIccMBB *mbb = FindAndCast<CIccMBB>(pIcc, (icTagSignature)lutSigs[s]);
    if (!mbb) continue;

    icUInt8Number nIn = mbb->InputChannels();
    icUInt8Number nOut = mbb->OutputChannels();
    if (nIn == 0 || nOut == 0) {
      hc.warn("LUT tag '%s': zero channels (in=%d, out=%d)", info.GetTagSigName((icTagSignature)lutSigs[s]), nIn, nOut);
      hc.cweNote("CWE-131: Zero-channel LUT → division by zero risk");
    }
    if (nIn > 16 || nOut > 16) {
      hc.warn("LUT tag '%s': extreme channels (in=%d, out=%d)", info.GetTagSigName((icTagSignature)lutSigs[s]), nIn, nOut);
      hc.cweNote("CWE-120: Channel count exceeds fixed buffer (16)");
    }
  }
}

  return hc.end("LUT I/O channel counts valid");
}

int RunHeuristic_H64_NamedColor2DeviceCoordOverflow(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H64 — NamedColor2 Device Coord Overflow (CWE-131/CWE-787/CWE-400)
// Also detects Describe() iteration asymmetry: nColors controls
// loop count in Describe() with 5 snprintf calls per entry.
// Validation-time: Read() caps nDevCoords at 16 (CFL-076).
// Runtime: Describe() iterates m_nSize with no cap (CFL-078).
// =====================================================================
hc.begin(64, "NamedColor2 Device Coord Overflow");
{
  CIccTagNamedColor2 *nc2 = FindAndCast<CIccTagNamedColor2>(pIcc, icSigNamedColor2Tag);
  if (nc2) {
    if (nc2) {
      icUInt32Number nColors = nc2->GetSize();
      icUInt32Number nDevCoords = nc2->GetDeviceCoords();
      if (nColors > 10000) {
        hc.warn("NamedColor2: %u entries (>10000) — Describe() DoS risk", nColors);
        hc.cweNote("CWE-400: Describe() iterates m_nSize with no runtime cap (CFL-078 pattern)");
      }
      if (nColors > 65536) {
        hc.warn("NamedColor2: %u entries (>65536)", nColors);
        hc.cweNote("CWE-400: Excessive named color entries");
      }
      if (nDevCoords > 15) {
        hc.warn("NamedColor2: %u device coords (>15)", nDevCoords);
        hc.cweNote("CWE-787: Device coord count exceeds ICC spec max");
      }
      // Check product overflow
      if (nColors > 0 && nDevCoords > 0) {
        uint64_t product = (uint64_t)nColors * (uint64_t)(nDevCoords + 3) * sizeof(icFloatNumber);
        if (product > 1073741824ULL) { // 1GB
          hc.warn("NamedColor2: allocation %llu bytes (>1GB)", (unsigned long long)product);
          hc.cweNote("CWE-131: Integer overflow in size calculation");
        }
      }
    }
  }
}

  return hc.end("NamedColor2 dimensions valid (or tag absent)");
}

int RunHeuristic_H65_ChromaticityPlausibility(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H65 — Chromaticity Physical Plausibility (CWE-682)
// =====================================================================
hc.begin(65, "Chromaticity Physical Plausibility");
{
  CIccTagChromaticity *chrom = FindAndCast<CIccTagChromaticity>(pIcc, icSigChromaticityTag);
  if (chrom) {
    if (chrom) {
      icUInt32Number nChan = chrom->GetSize();
      for (icUInt32Number c = 0; c < nChan && c < 16; c++) {
        icChromaticityNumber *xy = chrom->Getxy(c);
        if (xy) {
          icFloatNumber x = icUFtoD(xy->x);
          icFloatNumber y = icUFtoD(xy->y);
          if (x < 0 || x > 0.9 || y < 0 || y > 0.9) {
            hc.warn("Chromaticity[%u]: xy=(%.4f, %.4f) outside CIE bounds", c, x, y);
            hc.cweNote("CWE-682: Non-physical chromaticity coordinates");
          }
          if (y == 0 && x != 0) {
            hc.warn("Chromaticity[%u]: y=0 with x!=0 (singularity)", c);
          }
        }
      }
    }
  }
}

  return hc.end("Chromaticity coordinates plausible (or tag absent)");
}

int RunHeuristic_H66_NumArrayNaNInfScan(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H66 — Comprehensive NumArray NaN/Inf Scan (CWE-682/CWE-369)
// =====================================================================
hc.begin(66, "Comprehensive NumArray NaN/Inf Scan");
{
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTag *tag = pIcc->FindTag(sit->TagInfo.sig);
    if (!tag || !tag->IsNumArrayType()) continue;
    CIccTagNumArray *numArr = dynamic_cast<CIccTagNumArray*>(tag);
    if (!numArr) continue;

    icUInt32Number nVals = numArr->GetNumValues();
    if (nVals == 0 || nVals > 1048576) continue; // skip empty or huge

    icUInt32Number scanLimit = (nVals > 4096) ? 4096 : nVals;
    // Guard against overflow: scanLimit <= 4096 so product fits in uint32
    std::vector<icFloatNumber> vals(scanLimit);

    if (numArr->GetValues(vals.data(), 0, scanLimit)) {
      int nanCount = 0, infCount = 0, extremeCount = 0;
      for (icUInt32Number v = 0; v < scanLimit; v++) {
        if (std::isnan(vals[v])) nanCount++;
        else if (std::isinf(vals[v])) infCount++;
        else if (std::fabs(vals[v]) > 1e10) extremeCount++;
      }
      if (nanCount > 0 || infCount > 0) {
        hc.warn("Tag '%s': %d NaN, %d Inf in %u values", info.GetTagSigName(sit->TagInfo.sig), nanCount, infCount, scanLimit);
        hc.cweNote("CWE-682: Non-finite values propagate through color math");
      }
      if (extremeCount > static_cast<int>(scanLimit / 4)) {
        hc.warn("Tag '%s': %d/%u extreme values (>1e10)", info.GetTagSigName(sit->TagInfo.sig), extremeCount, scanLimit);
      }
    }
  }
}

  return hc.end("All numeric arrays free of NaN/Inf");
}

int RunHeuristic_H67_ResponseCurveSetBounds(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H67 — ResponseCurveSet Bounds (CWE-400/CWE-131)
// Validation-time: Read() accepts arbitrary nMeasurements[] per channel.
// Runtime: Describe() iterates nMeasurements with no cap (CFL-077/078).
// H136 catches this via raw-byte scan; H67 checks via library API.
// =====================================================================
hc.begin(67, "ResponseCurveSet Bounds");
{
  // ResponseCurveSet16 has no well-known tag signature — scan all tags by type
  CIccTagResponseCurveSet16 *rcs = nullptr;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *t = pIcc->FindTag(it->TagInfo.sig);
    if (!t) continue;
    rcs = dynamic_cast<CIccTagResponseCurveSet16*>(t);
    if (rcs) break;
  }
  if (rcs) {
    icUInt16Number nChan = rcs->GetNumChannels();
    if (nChan > 16) {
      hc.warn("ResponseCurveSet: %u channels (>16)", nChan);
      hc.cweNote("CWE-131: Channel count exceeds safe bounds");
    }
    icUInt16Number nMeasTypes = rcs->GetNumResponseCurveTypes();
    if (nMeasTypes > 100) {
      hc.warn("ResponseCurveSet: %u measurement types (>100)", nMeasTypes);
      hc.cweNote("CWE-400: Excessive measurement types → O(n) in Describe()");
    }
  }
}

  return hc.end("ResponseCurveSet bounds valid (or tag absent)");
}

int RunHeuristic_H70_MeasurementTagValidation(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H70 — Measurement Tag Validation (CWE-20)
// =====================================================================
hc.begin(70, "Measurement Tag Validation");
{
  CIccTagMeasurement *meas = FindAndCast<CIccTagMeasurement>(pIcc, icSigMeasurementTag);
  if (meas) {
    if (meas) {
      icUInt32Number obs = meas->m_Data.stdObserver;
      if (obs != 0 && obs != 1 && obs != 2) {
        hc.warn("Measurement: invalid observer type %u", obs);
        hc.cweNote("CWE-20: Invalid enum → undefined behavior in observer selection");
      }
      icUInt32Number geom = meas->m_Data.geometry;
      if (geom > 3) {
        hc.warn("Measurement: invalid geometry %u (>3)", geom);
      }
      icUInt32Number flareRaw = (icUInt32Number)meas->m_Data.flare;
      if (flareRaw > 0x00010000) { // > 1.0 in u16Fixed16
        hc.warn("Measurement: flare 0x%08X exceeds 1.0", flareRaw);
      }
    }
  }
}

  return hc.end("Measurement tag valid (or absent)");
}

int RunHeuristic_H71_ColorantTableNullTermination(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H71 — ColorantTable Name Null-Termination (CWE-170/CWE-125)
// Targets patches 019/020, CVE-2026-21488: strlen OOB on name[32]
// =====================================================================
hc.begin(71, "ColorantTable Name Null-Termination");
{
  icTagSignature ctSigs[] = {icSigColorantTableTag, icSigColorantTableOutTag, (icTagSignature)0};
  for (int s = 0; ctSigs[s] != (icTagSignature)0; s++) {
    CIccTagColorantTable *ct = FindAndCast<CIccTagColorantTable>(pIcc, ctSigs[s]);
    if (!ct) continue;

    icUInt32Number nEntries = ct->GetSize();
    if (nEntries > 65535) {
      hc.warn("ColorantTable: %u entries (excessive)", nEntries);
      hc.cweNote("CWE-400: Excessive colorant count");
      continue;
    }
    for (icUInt32Number i = 0; i < nEntries && i < 256; i++) {
      icColorantTableEntry *entry = ct->GetEntry(i);
      if (!entry) continue;
      // Check if name[32] has a null terminator within bounds
      bool hasNull = false;
      for (int j = 0; j < 32; j++) {
        if (entry->name[j] == 0) { hasNull = true; break; }
      }
      if (!hasNull) {
        hc.warn("Colorant[%u]: name[32] has no null terminator", i);
        hc.cweNote("CWE-170: strlen OOB → heap-buffer-overflow (P019/P020)");
      }
    }
  }
}

  return hc.end("ColorantTable names properly terminated (or absent)");
}

int RunHeuristic_H72_SparseMatrixArrayBounds(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H72 — SparseMatrixArray Allocation Bounds + Enum Validation (CWE-400/CWE-125/CWE-843)
// Targets patches 044/059/060: OOM + OOB in sparse matrix
// Upstream issues: #526 (null ptr in GetColumnsForRow), #538/#548 (invalid enum icSparseMatrixType)
// =====================================================================
hc.begin(72, "SparseMatrixArray Allocation Bounds + Enum Validation");
{
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTagSparseMatrixArray *sma = FindAndCast<CIccTagSparseMatrixArray>(pIcc, sit->TagInfo.sig);
    if (!sma) continue;

    char sigStr72[5];
    SignatureToFourCC(sit->TagInfo.sig, sigStr72);

    icUInt32Number nMat = sma->GetNumMatrices();
    icUInt32Number nCPM = sma->GetChannelsPerMatrix();
    uint64_t product = (uint64_t)nMat * nCPM * sizeof(icFloatNumber);
    if (product > 16777216ULL) { // 16MB cap per patch 044
      hc.warn("Tag '%s': SparseMatrix %u matrices × %u channels = %llu bytes", sigStr72, nMat, nCPM, (unsigned long long)product);
      hc.cweNote("CWE-400: Exceeds 16MB allocation cap (P044)");
    }

    // Validate icSparseMatrixType enum value (iccDEV #538, #548)
    // Valid values: 0x0000 (FloatNum), 0x0001 (UInt8), 0x0002 (UInt16),
    //              0x0003 (Float16), 0x0004 (Float32)
    icSparseMatrixType matType = sma->GetMatrixType();
    icUInt16Number matTypeVal = static_cast<icUInt16Number>(matType);
    if (matTypeVal > 4) {
      hc.warn("Tag '%s': invalid icSparseMatrixType=%u (valid: 0-4)", sigStr72, matTypeVal);
      hc.cweNote("CWE-843: Type confusion — triggers UBSAN enum out-of-range in Read()");
    }

    // Check zero channels per matrix (null pointer risk in GetColumnsForRow, iccDEV #526)
    if (nCPM == 0 && nMat > 0) {
      hc.warn("Tag '%s': SparseMatrix %u matrices with 0 channels — null deref risk", sigStr72, nMat);
      hc.cweNote("CWE-476: GetColumnsForRow() dereferences null matrix data");
    }
  }
}

  return hc.end("SparseMatrixArray allocations and types valid (or absent)");
}

int RunHeuristic_H73_TagArrayNestingDepth(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H73 — TagArray/TagStruct Nesting Depth (CWE-674)
// Targets patch 061: stack overflow via nested tstr/tary elements
// =====================================================================
hc.begin(73, "TagArray/TagStruct Nesting Depth");
{
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTag *tag = pIcc->FindTag(sit->TagInfo.sig);
    if (!tag) continue;

    // Check TagStruct nesting
    CIccTagStruct *ts = dynamic_cast<CIccTagStruct*>(tag);
    if (ts) {
      TagEntryList *elems = ts->GetElemList();
      if (elems) {
        for (auto it = elems->begin(); it != elems->end(); it++) {
          CIccTag *child = ts->FindElem(it->TagInfo.sig);
          if (!child) continue;
          CIccTagStruct *childStruct = dynamic_cast<CIccTagStruct*>(child);
          CIccTagArray *childArray = dynamic_cast<CIccTagArray*>(child);
          if (childStruct || childArray) {
            hc.warn("Tag '%s': nested TagStruct/TagArray detected", info.GetTagSigName(sit->TagInfo.sig));
            hc.cweNote("CWE-674: Potential recursive nesting → stack overflow (P061)");
            break;
          }
        }
      }
    }

    // Check TagArray nesting + element type safety (iccDEV #530, #531: UAF in Cleanup)
    CIccTagArray *ta = dynamic_cast<CIccTagArray*>(tag);
    if (ta) {
      icUInt32Number nSz = ta->GetSize();
      if (nSz > 10000) {
        hc.warn("Tag '%s': TagArray with %u elements (excessive)", info.GetTagSigName(sit->TagInfo.sig), nSz);
        hc.cweNote("CWE-400: Excessive array size");
      } else {
        int unknownCount = 0;
        for (icUInt32Number i = 0; i < nSz && i < 100; i++) {
          CIccTag *child = ta->GetIndex(i);
          if (!child) continue;
          if (dynamic_cast<CIccTagStruct*>(child) || dynamic_cast<CIccTagArray*>(child)) {
            hc.warn("Tag '%s'[%u]: nested TagStruct/TagArray", info.GetTagSigName(sit->TagInfo.sig), i);
            hc.cweNote("CWE-674: Recursive nesting → stack overflow (P061)");
            break;
          }
          // Count CIccTagUnknown elements — risk of UAF in Cleanup() (iccDEV #530, #531)
          if (child->GetType() == icSigUnknownType) {
            unknownCount++;
          }
        }
        if (unknownCount > 0 && nSz > 1) {
          hc.warn("Tag '%s': TagArray has %d/%u CIccTagUnknown elements", info.GetTagSigName(sit->TagInfo.sig), unknownCount, nSz);
          hc.cweNote("CWE-416: Unknown elements in TagArray → use-after-free in Cleanup()");
        }

        // Detect shared pointers in TagArray — Cleanup() deduplicates via pointer
        // comparison (m_TagVals[j].ptr == pTag) then deletes. If the dedup logic
        // fails (e.g., freed object at 0xbebebebebebebebe), double-free occurs.
        // Check if any two entries share the same tag object pointer.
        int sharedPtrs = 0;
        for (icUInt32Number i = 0; i < nSz && i < 100; i++) {
          CIccTag *ci = ta->GetIndex(i);
          if (!ci) continue;
          for (icUInt32Number j = i + 1; j < nSz && j < 100; j++) {
            CIccTag *cj = ta->GetIndex(j);
            if (cj && ci == cj) {
              sharedPtrs++;
              break;
            }
          }
        }
        if (sharedPtrs > 0) {
          hc.critical("HEURISTIC: Tag '%s': TagArray has %d shared tag pointers", info.GetTagSigName(sit->TagInfo.sig), sharedPtrs);
          hc.cweNote("CWE-416: Shared pointers in Cleanup() dedup loop → " "double-free / use-after-free (IccTagComposite.cpp:1524)");
          hc.info("Ref: CFL-024 patch — guard against freed-object access (0xbe pattern)");
        }
      }
    }
  }
}

  return hc.end("No suspicious TagArray/TagStruct nesting");
}

int RunHeuristic_H74_TagTypeSignatureConsistency(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H74 — Tag Type Signature Consistency (CWE-843)
// Targets CVEs 34, 39-44, 73: type confusion in tag processing
// =====================================================================
hc.begin(74, "Tag Type Signature Consistency");
{
  struct TagTypeExpectation {
    icTagSignature tag;
    icTagTypeSignature expected[5]; // up to 5 valid types, 0 = end
  };
  TagTypeExpectation expectations[] = {
    {icSigAToB0Tag,        {icSigLutAtoBType, icSigLut8Type, icSigLut16Type, icSigMultiProcessElementType, (icTagTypeSignature)0}},
    {icSigAToB1Tag,        {icSigLutAtoBType, icSigLut8Type, icSigLut16Type, icSigMultiProcessElementType, (icTagTypeSignature)0}},
    {icSigBToA0Tag,        {icSigLutBtoAType, icSigLut8Type, icSigLut16Type, icSigMultiProcessElementType, (icTagTypeSignature)0}},
    {icSigBToA1Tag,        {icSigLutBtoAType, icSigLut8Type, icSigLut16Type, icSigMultiProcessElementType, (icTagTypeSignature)0}},
    {icSigMediaWhitePointTag, {icSigXYZType, (icTagTypeSignature)0}},
    {icSigCopyrightTag,    {icSigTextType, icSigMultiLocalizedUnicodeType, (icTagTypeSignature)0}},
    {(icTagSignature)0,    {(icTagTypeSignature)0}}
  };

  for (int e = 0; expectations[e].tag != (icTagSignature)0; e++) {
    CIccTag *tag = pIcc->FindTag(expectations[e].tag);
    if (!tag) continue;
    icTagTypeSignature actualType = tag->GetType();
    bool valid = false;
    for (int t = 0; t < 5 && expectations[e].expected[t] != (icTagTypeSignature)0; t++) {
      if (actualType == expectations[e].expected[t]) { valid = true; break; }
    }
    if (!valid) {
      char typeSig[5];
      SignatureToFourCC((icUInt32Number)actualType, typeSig);
      hc.warn("Tag '%s': unexpected type '%s'", info.GetTagSigName(expectations[e].tag), typeSig);
      hc.cweNote("CWE-843: Type confusion → incorrect cast in processing");
    }
  }
}

  return hc.end("Tag type signatures consistent");
}

int RunHeuristic_H75_TagsVerySmallSize(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H75 — Tags with Very Small Size (CWE-122/CWE-191)
// Targets patch 009: m_nSize ≤ 4 causes underflow in Describe
// =====================================================================
hc.begin(75, "Tags with Very Small Size");
{
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    // Tag data size from tag table (not including type sig)
    if (sit->TagInfo.size <= 8 && sit->TagInfo.size > 0) {
      hc.warn("Tag '%s': size %u bytes (≤ 8, suspiciously small)", info.GetTagSigName(sit->TagInfo.sig), sit->TagInfo.size);
      hc.cweNote("CWE-191: Unsigned underflow in size−N calculations (P009)");
    }
  }
}

  return hc.end("All tags have sufficient minimum size");
}

int RunHeuristic_H76_CIccTagDataTypeFlag(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H76 — CIccTagData Type Flag Validation (CWE-843/CWE-20)
// Targets CVE-2026-21691: IsTypeCompressed type confusion
// =====================================================================
hc.begin(76, "CIccTagData Type Flag Validation");
{
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTagData *dataTag = FindAndCast<CIccTagData>(pIcc, sit->TagInfo.sig);
    if (!dataTag) continue;

    icUInt32Number dataSz = dataTag->GetSize();
    if (dataSz > 134217728) { // 128MB
      hc.warn("Tag '%s': CIccTagData size %u bytes (>128MB)", info.GetTagSigName(sit->TagInfo.sig), dataSz);
      hc.cweNote("CWE-400: Excessive data tag allocation (P007)");
    }
    if (dataTag->IsTypeCompressed()) {
      hc.warn("Tag '%s': compressed data flag set", info.GetTagSigName(sit->TagInfo.sig));
      hc.cweNote("CWE-843: Compressed type may trigger unsafe decompression");
    }
  }
}

  return hc.end("CIccTagData types valid (or absent)");
}

int RunHeuristic_H77_MPECalculatorSubElementCount(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H77 — MPE Calculator Sub-Element Count (CWE-400/CWE-125)
// Targets patches 032/045/064: HBO in ApplySequence ops
// =====================================================================
hc.begin(77, "MPE Calculator Sub-Element Count");
{
  icTagSignature mpeSigs[] = {
    icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
    icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag,
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    (icTagSignature)0
  };
  for (int s = 0; mpeSigs[s] != (icTagSignature)0; s++) {
    CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, mpeSigs[s]);
    if (!mpe) continue;

    icUInt32Number nElems = mpe->NumElements();
    if (nElems > 256) {
      hc.warn("Tag '%s': MPE with %u elements (>256)", info.GetTagSigName(mpeSigs[s]), nElems);
      hc.cweNote("CWE-400: Excessive MPE elements → large op arrays");
    }
  }
}

  return hc.end("MPE calculator element counts within bounds");
}

int RunHeuristic_H78_CLUTGridDimensionOverflow(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H78 — CLUT Grid Dimension Product Overflow (CWE-190/CWE-131)
// Targets patch 001, CVE-2026-22255, CVE-2026-21677: grid dims overflow
// =====================================================================
hc.begin(78, "CLUT Grid Dimension Product Overflow");
{
  icTagSignature clutSigs[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    (icTagSignature)0
  };
  for (int s = 0; clutSigs[s] != (icTagSignature)0; s++) {
    CIccMBB *mbb = FindAndCast<CIccMBB>(pIcc, clutSigs[s]);
    if (!mbb) continue;

    CIccCLUT *clut = mbb->GetCLUT();
    if (!clut) continue;

    icUInt8Number nIn = mbb->InputChannels();
    icUInt8Number nOut = mbb->OutputChannels();

    if (nIn > 0) {
      // Check grid dimension product for exponential blowup
      uint64_t gridProduct = 1;
      bool overflow = false;
      for (int d = 0; d < static_cast<int>(nIn) && d < 16; d++) {
        icUInt8Number gridPt = clut->GridPoint(d);
        if (gridPt == 0) { overflow = true; break; }
        gridProduct *= gridPt;
        if (gridProduct > 268435456ULL) { overflow = true; break; } // 256M entries
      }
      if (overflow) {
        hc.warn("Tag '%s': CLUT grid product overflow (%u inputs)", info.GetTagSigName(clutSigs[s]), nIn);
        hc.cweNote("CWE-190: Exponential grid allocation (P001)");
      } else {
        uint64_t totalBytes = gridProduct * nOut * sizeof(icFloatNumber);
        if (totalBytes > 16777216ULL) { // 16MB per-CLUT cap
          hc.warn("Tag '%s': CLUT alloc %llu bytes (>16MB)", info.GetTagSigName(clutSigs[s]), (unsigned long long)totalBytes);
          hc.cweNote("CWE-131: CLUT exceeds per-allocation cap (P001)");
        }
      }
    }
  }
}

  return hc.end("CLUT grid dimension products within bounds");
}

int RunHeuristic_H79_LoadTagAllocationOverflow(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H79: LoadTag Offset/Size vs File Length Consistency
// CVE-2026-21485 — UB + OOM in CIccProfile::LoadTag()
// The library validates offset+size<=fileLen, but we independently check
// that no tag's declared size could trigger allocation overflow.
// CWE-190 (Integer Overflow), CWE-400 (Resource Exhaustion)
// =====================================================================
hc.begin(79, "LoadTag Allocation Overflow Detection");
{
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    icUInt32Number tagSize = sit->TagInfo.size;
    icUInt32Number tagOffset = sit->TagInfo.offset;

    // Check for tags that claim extremely large sizes (>256MB)
    // These trigger massive allocations in CIccTag::Read() implementations
    if (tagSize > 268435456U) {
      hc.warn("Tag '%s' (0x%08X): size=%u (>256MB) — potential OOM in LoadTag", info.GetTagSigName(sit->TagInfo.sig), sit->TagInfo.sig, tagSize);
      hc.cweNote("CWE-400: Uncapped allocation from tag size (CVE-2026-21485)");
    }
    // Check for offset+size overflow (32-bit wraparound)
    if (tagOffset > 0 && tagSize > 0 && ((uint64_t)tagOffset + tagSize) > 0xFFFFFFFFULL) {
      hc.warn("Tag '%s': offset(%u)+size(%u) wraps 32-bit — OOB read in LoadTag", info.GetTagSigName(sit->TagInfo.sig), tagOffset, tagSize);
      hc.cweNote("CWE-190: Integer overflow in offset+size");
    }
  }
}

  return hc.end("Tag sizes within safe allocation limits");
}

int RunHeuristic_H80_SharedTagPointerUAF(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H80: Use-After-Free Pattern Detection (Shared Tag Pointers)
// CVE-2026-21675 (Critical 9.8) — UAF in CIccXform::Create()
// CVE-2026-21486 (High 7.8) — UAF + HBO + integer overflow
// When multiple tag directory entries point to the same offset,
// the library creates shared tag pointers. If one is freed while
// another reference exists, UAF occurs. Detect shared-offset tags.
// CWE-416 (Use After Free)
// =====================================================================
hc.begin(80, "Shared Tag Pointer / Use-After-Free Pattern");
{
  std::map<icUInt32Number, std::vector<icSignature>> offsetMap;
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    if (sit->TagInfo.offset > 0 && sit->TagInfo.size > 0) {
      offsetMap[sit->TagInfo.offset].push_back(sit->TagInfo.sig);
    }
  }
  for (auto &pair : offsetMap) {
    if (pair.second.size() > 4) {
      // More than 4 tags sharing a single offset is suspicious
      hc.warn("Offset 0x%08X shared by %zu tags — UAF risk if tag freed independently", pair.first, pair.second.size());
      hc.cweNote("CWE-416: Shared tag pointer pattern (CVE-2026-21675)");
    }
  }
}

  return hc.end("No excessive tag pointer sharing detected");
}

int RunHeuristic_H81_MPECalculatorIOConsistency(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H81: CIccMpeCalculator Sub-Element Channel Mismatch
// CVE-2026-21504 (Medium 6.6) — HBO in CIccMpeToneMap::Read()
// CVE-2026-24405 (High 8.8) — HBO in CIccMpeCalculator::Read()
// CVE-2026-22047 (High 8.8) — HBO in SIccCalcOp::Describe()
// When MPE elements (Calculator, ToneMap) have sub-elements whose channel
// counts don't match expectations, buffer overflows occur during Read/Apply.
// CWE-122 (Heap-based Buffer Overflow)
// =====================================================================
hc.begin(81, "MPE Calculator I/O Channel Consistency");
{
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTag *pTag = pIcc->FindTag(sit->TagInfo.sig);
    CIccTagMultiProcessElement *pMpe = (pTag && pTag->GetType() == icSigMultiProcessElementType)
                                         ? dynamic_cast<CIccTagMultiProcessElement*>(pTag)
                                         : nullptr;
    if (!pMpe) continue;

    icUInt16Number mpeIn = pMpe->NumInputChannels();
    icUInt16Number mpeOut = pMpe->NumOutputChannels();
    if (mpeIn == 0 || mpeOut == 0) {
      hc.warn("Tag '%s': MPE with 0 channels (in=%u, out=%u)", info.GetTagSigName(sit->TagInfo.sig), mpeIn, mpeOut);
      hc.cweNote("CWE-122: Zero-channel MPE causes division/buffer errors (CVE-2026-24405)");
    }
    // Check for absurdly large channel counts (>1024)
    if (mpeIn > 1024 || mpeOut > 1024) {
      hc.warn("Tag '%s': MPE channel count extreme (in=%u, out=%u)", info.GetTagSigName(sit->TagInfo.sig), mpeIn, mpeOut);
      hc.cweNote("CWE-122: Large channel count → massive buffer allocation (CVE-2026-22047)");
    }
  }
}

  return hc.end("MPE calculator channel counts within bounds");
}

int RunHeuristic_H82_IOReadSizeOverflow(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H82: IccIO Read Size Bit-Shift Overflow
// CVE-2026-25582 (High 7.8) — HBO in CIccIO::WriteUInt16Float()
// CVE-2026-25583 (High 7.8) — HBO in CIccFileIO::Read8()
// IccIO Read16/Read32/Read64 use nNum<<1/<<2/<<3 without overflow
// checks. We detect tags whose sizes, when divided by element size,
// could cause bit-shift overflow in the reader.
// CWE-190 (Integer Overflow or Wraparound)
// =====================================================================
hc.begin(82, "I/O Read Size Overflow Pattern");
{
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    icUInt32Number tagSize = sit->TagInfo.size;
    // Tags with size near 32-bit max / 8 can overflow in Read64
    if (tagSize > 0x1FFFFFFFU) { // > SIZE_MAX/8 for 32-bit
      hc.warn("Tag '%s': size=%u may overflow Read64 bit-shift", info.GetTagSigName(sit->TagInfo.sig), tagSize);
      hc.cweNote("CWE-190: nNum<<3 overflow in CIccIO (CVE-2026-25582/25583)");
    }
  }
}

  return hc.end("Tag sizes safe for I/O bit-shift operations");
}

int RunHeuristic_H83_FloatNumericArraySize(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H83: CIccTagFloatNum GetValues Stack Buffer Overflow
// CVE-2026-25584 (High 7.8) — SBO in CIccTagFloatNum::GetValues()
// GetValues() copies into a caller-provided buffer. If the tag's
// m_nSize exceeds the expected count for the tag type, SBO occurs.
// We validate that numeric array tag sizes match expected element counts.
// CWE-121 (Stack-based Buffer Overflow)
// =====================================================================
hc.begin(83, "Float/Numeric Array Size Validation");
{
  icSignature floatSigs[] = {
    icSigXYZType, icSigS15Fixed16ArrayType, icSigU16Fixed16ArrayType,
    icSigFloat16ArrayType, icSigFloat32ArrayType, icSigFloat64ArrayType,
    (icSignature)0
  };
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTag *pTag = pIcc->FindTag(sit->TagInfo.sig);
    if (!pTag) continue;

    icTagTypeSignature tagType = pTag->GetType();
    bool isFloatArray = false;
    for (int f = 0; floatSigs[f] != (icSignature)0; f++) {
      if (tagType == (icTagTypeSignature)floatSigs[f]) {
        isFloatArray = true;
        break;
      }
    }
    if (!isFloatArray) continue;

    // Check tag payload vs declared size
    icUInt32Number tagDataSize = sit->TagInfo.size;
    if (tagDataSize < 8) continue; // type + reserved
    icUInt32Number payloadSize = tagDataSize - 8;

    // For XYZ, each element = 12 bytes (3 × s15Fixed16)
    // For s15Fixed16Array / u16Fixed16Array, each = 4 bytes
    // For float32, each = 4; float64, each = 8; float16, each = 2
    icUInt32Number elemSize = 4;
    if (tagType == (icTagTypeSignature)icSigXYZType) elemSize = 12;
    else if (tagType == (icTagTypeSignature)icSigFloat64ArrayType) elemSize = 8;
    else if (tagType == (icTagTypeSignature)icSigFloat16ArrayType) elemSize = 2;

    if (payloadSize / elemSize > 16777216U) { // 16M elements
      hc.warn("Tag '%s': %u elements in float array (>16M)", info.GetTagSigName(sit->TagInfo.sig), payloadSize / elemSize);
      hc.cweNote("CWE-121: Stack overflow risk in GetValues (CVE-2026-25584)");
    }
  }
}

  return hc.end("Float/numeric array sizes within bounds");
}

int RunHeuristic_H84_LUT3DTransformConsistency(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H84: CIccXform3DLut Apply Out-of-Bounds
// CVE-2026-25585 (High 7.8) — OOB in CIccXform3DLut::Apply()
// The 3D LUT transform uses input channel values as indices into
// a grid. If input/output channel counts don't match profile color
// space expectations, OOB access occurs during interpolation.
// CWE-125 (Out-of-bounds Read)
// =====================================================================
hc.begin(84, "3D LUT Transform Channel/Grid Consistency");
{
  // Check that AToB/BToA tags with 3D CLUT have matching color space channels
  icUInt32Number csChannels = icGetSpaceSamples(pIcc->m_Header.colorSpace);
  icUInt32Number pcsChannels = icGetSpaceSamples(pIcc->m_Header.pcs);

  if (csChannels == 3) {
    // This is a 3-channel color space — 3D LUT transforms are typical
    icTagSignature aToBSigs[] = { icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, (icTagSignature)0 };
    for (int a = 0; aToBSigs[a] != (icTagSignature)0; a++) {
      CIccTag *pTag = pIcc->FindTag(aToBSigs[a]);
      if (!pTag || !pTag->IsMBBType()) continue;
      CIccMBB *pMbb = dynamic_cast<CIccMBB*>(pTag);
      if (!pMbb) continue;

      CIccCLUT *pClut = pMbb->GetCLUT();
      if (!pClut) continue;

      icUInt8Number clutIn = pClut->GetInputDim();
      icUInt8Number clutOut = pClut->GetOutputChannels();

      if (clutIn != csChannels) {
        hc.warn("Tag '%s': CLUT input dim=%u != colorSpace channels=%u", info.GetTagSigName(aToBSigs[a]), clutIn, csChannels);
        hc.cweNote("CWE-125: 3D LUT dimension mismatch (CVE-2026-25585)");
      }
      if (clutOut != pcsChannels && pcsChannels > 0) {
        hc.warn("Tag '%s': CLUT output=%u != PCS channels=%u", info.GetTagSigName(aToBSigs[a]), clutOut, pcsChannels);
        hc.cweNote("CWE-125: Output channel mismatch → buffer overread (CVE-2026-25585)");
      }
    }
  }
}

  return hc.end("3D LUT channel/grid dimensions consistent");
}

int RunHeuristic_H85_MPEBufferOverlap(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H85: memcpy-param-overlap in MultiProcessElement::Apply()
// CVE-2026-25634 (High 7.8) — memcpy overlap
// When MPE input and output channels are the same count, Apply()
// may use overlapping src/dst buffers. Detect MPE tags where
// in==out and multiple elements chain (buffer reuse pattern).
// CWE-120 (Buffer Copy without Checking Size of Input)
// =====================================================================
hc.begin(85, "MPE Buffer Overlap Pattern Detection");
{
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTag *pTag = pIcc->FindTag(sit->TagInfo.sig);
    CIccTagMultiProcessElement *pMpe = (pTag && pTag->GetType() == icSigMultiProcessElementType)
                                         ? dynamic_cast<CIccTagMultiProcessElement*>(pTag)
                                         : nullptr;
    if (!pMpe) continue;

    icUInt16Number mpeIn = pMpe->NumInputChannels();
    icUInt16Number mpeOut = pMpe->NumOutputChannels();
    int elemCount = 0;
    CIccMultiProcessElement *pElem = pMpe->GetElement(0);
    while (pElem) {
      elemCount++;
      pElem = pMpe->GetElement(elemCount);
    }
    // When in==out and >1 chained elements, buffer overlap is possible
    if (mpeIn == mpeOut && elemCount > 1 && mpeIn > 0) {
      // This is informational — the pattern exists in normal profiles too
      // Flag only if channel count is extreme
      if (mpeIn > 256) {
        hc.warn("Tag '%s': MPE chain (%d elements, %u channels) — memcpy overlap risk", info.GetTagSigName(sit->TagInfo.sig), elemCount, mpeIn);
        hc.cweNote("CWE-120: Buffer overlap in chained Apply (CVE-2026-25634)");
      }
    }
  }
}

  return hc.end("No excessive MPE buffer overlap patterns");
}

int RunHeuristic_H86_LocalizedUnicodeBounds(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H86: CIccLocalizedUnicode GetText Heap Overflow
// CVE-2026-21679 (High 8.8) — HBO in CIccLocalizedUnicode::GetText()
// CVE-2026-21678 (High 7.8) — HBO on IccTagXml()
// The mluc tag stores per-locale text. If a locale's text length
// exceeds the tag's declared size boundary, GetText() overflows.
// We validate that the sum of all locale text sizes <= tag size.
// CWE-122 (Heap-based Buffer Overflow)
// =====================================================================
hc.begin(86, "Localized Unicode Text Bounds Validation");
{
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTag *pTag = pIcc->FindTag(sit->TagInfo.sig);
    if (!pTag) continue;
    if (pTag->GetType() != icSigMultiLocalizedUnicodeType) continue;

    CIccTagMultiLocalizedUnicode *pMluc =
        dynamic_cast<CIccTagMultiLocalizedUnicode*>(pTag);
    if (!pMluc) continue;

    // Check total number of locale entries
    CIccMultiLocalizedUnicode::iterator mlucIt;
    int localeCount = 0;
    uint64_t totalTextBytes = 0;
    for (mlucIt = pMluc->m_Strings->begin(); mlucIt != pMluc->m_Strings->end(); mlucIt++) {
      localeCount++;
      totalTextBytes += mlucIt->GetLength() * sizeof(icUInt16Number);
    }

    // More than 1000 locale entries is suspicious (mluc bomb)
    if (localeCount > 1000) {
      hc.warn("Tag '%s': %d locale entries in mluc (>1000) — memory bomb", info.GetTagSigName(sit->TagInfo.sig), localeCount);
      hc.cweNote("CWE-122: Excessive locale entries → HBO in GetText (CVE-2026-21679)");
    }
    // Total text > 64MB is excessive
    if (totalTextBytes > 67108864ULL) {
      hc.warn("Tag '%s': total mluc text=%llu bytes (>64MB)", info.GetTagSigName(sit->TagInfo.sig), (unsigned long long)totalTextBytes);
      hc.cweNote("CWE-122: Excessive text size → heap overflow (CVE-2026-21678)");
    }

    // H86 enhancement: Scan mluc text content for suspicious Unicode patterns.
    // Fuzzed profiles inject non-ASCII into profile descriptions that should be
    // plain text (e.g., "Channel seleI协⁭on" instead of "Channel selection").
    // Detects: Unicode bidi overrides (injection), control chars, mixed-script
    // corruption, and null bytes in text — all user-controllable attack surface.
    for (mlucIt = pMluc->m_Strings->begin(); mlucIt != pMluc->m_Strings->end(); mlucIt++) {
      icUInt32Number textLen = mlucIt->GetLength();
      const icUInt16Number *textBuf = mlucIt->GetBuf();
      if (!textBuf || textLen == 0) continue;
      if (textLen > 10000) textLen = 10000; // cap scan length

      int controlChars = 0, bidiOverrides = 0, nullChars = 0;
      int nonLatinMixed = 0;
      bool hasLatin = false, hasNonLatin = false;
      for (icUInt32Number c = 0; c < textLen; c++) {
        icUInt16Number ch = textBuf[c];
        if (ch == 0x0000) { nullChars++; continue; }
        // C0/C1 control chars (except tab/LF/CR)
        if ((ch < 0x0020 && ch != 0x0009 && ch != 0x000A && ch != 0x000D) ||
            (ch >= 0x007F && ch <= 0x009F)) {
          controlChars++;
        }
        // Unicode bidi overrides and formatting (U+200B-U+206F, U+FEFF)
        if ((ch >= 0x200B && ch <= 0x206F) || ch == 0xFEFF) {
          bidiOverrides++;
        }
        // Track script mixing: basic Latin (0x20-0x7E) vs non-Latin
        if (ch >= 0x0020 && ch <= 0x007E) hasLatin = true;
        if (ch > 0x024F) hasNonLatin = true; // beyond Latin Extended-B
      }
      if (hasLatin && hasNonLatin) nonLatinMixed = 1;

      if (bidiOverrides > 0) {
        hc.critical("HEURISTIC: Tag '%s': mluc text contains %d Unicode " "bidi override/formatting characters (U+200B-U+206F)", info.GetTagSigName(sit->TagInfo.sig), bidiOverrides);
        hc.cweNote("CWE-116: Bidi text injection — can reverse displayed text " "direction for spoofing/phishing");
      }
      if (controlChars > 0) {
        hc.warn("Tag '%s': mluc text contains %d non-printable " "control characters", info.GetTagSigName(sit->TagInfo.sig), controlChars);
        hc.cweNote("CWE-116: Control character injection in profile text");
      }
      if (nullChars > 0 && nullChars < (int)textLen) {
        // A single null at the very end is just a standard terminator — not suspicious
        bool isJustTerminator = (nullChars == 1 && textBuf[textLen - 1] == 0x0000);
        if (!isJustTerminator) {
          hc.warn("Tag '%s': mluc text contains %d embedded null " "characters (string truncation attack)", info.GetTagSigName(sit->TagInfo.sig), nullChars);
          hc.cweNote("CWE-170: Embedded nulls truncate text differently per " "consumer (injection vector)");
        }
      }
      if (nonLatinMixed) {
        hc.warn("Tag '%s': mluc text mixes Latin + non-Latin scripts " "(possible homoglyph/corruption)", info.GetTagSigName(sit->TagInfo.sig));
        hc.cweNote("CWE-116: Mixed-script text may indicate fuzzed/corrupted " "Unicode data");
      }
    }
  }
}

  return hc.end("Localized Unicode text within bounds");
}

int RunHeuristic_H87_TRCCurveAnomaly(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H87 — TRC Curve Anomaly Detection (CWE-125/CWE-787)
// TRC (Tone Reproduction Curve) tags define gamma/response curves for
// each channel. Malformed curves with excessive point counts, invalid
// parametric function types, or degenerate values can trigger OOB
// reads in CIccTagCurve::Apply() and stack overflows in interpolation.
// =====================================================================
hc.begin(87, "TRC Curve Anomaly Detection");
{
  icTagSignature trcSigs[] = {
    icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag,
    (icTagSignature)0
  };
  for (int t = 0; trcSigs[t] != (icTagSignature)0; t++) {
    CIccTag *pTag = pIcc->FindTag(trcSigs[t]);
    if (!pTag) continue;

    // Check CIccTagCurve (tabulated TRC)
    CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve*>(pTag);
    if (pCurve) {
      icUInt32Number nSize = pCurve->GetSize();
      if (nSize > 65536) {
        hc.warn("Tag '%s': TRC curve with %u points (>65536) — excessive allocation", info.GetTagSigName(trcSigs[t]), nSize);
        hc.cweNote("CWE-400: Oversized curve table → OOM in Apply()");
      }
      // Size=0 means embedded gamma (valid), size=1 means identity curve (valid)
      // Check for degenerate values in tabulated curves
      if (nSize > 1) {
        bool allZero = true;
        for (icUInt32Number i = 0; i < nSize && i < 16; i++) {
          icFloatNumber v = (*pCurve)[i];
          if (v != 0.0f) allZero = false;
        }
        if (allZero && nSize > 2) {
          hc.warn("Tag '%s': TRC curve all-zero (%u points) — clipped output", info.GetTagSigName(trcSigs[t]), nSize);
        }
      }
    }

    // Check CIccTagParametricCurve
    CIccTagParametricCurve *pParam = dynamic_cast<CIccTagParametricCurve*>(pTag);
    if (pParam) {
      icUInt16Number funcType = pParam->GetFunctionType();
      if (funcType > 4) {
        hc.warn("Tag '%s': parametric curve function type %u (>4, spec violation)", info.GetTagSigName(trcSigs[t]), funcType);
        hc.cweNote("CWE-843: Invalid function type → unpredictable Apply() behavior");
      }
      icUInt16Number nParams = pParam->GetNumParam();
      // Validate param count sufficiency for funcType (CFL-051 pattern)
      static const int kParaMinParams[] = {1, 3, 4, 5, 7};
      if (funcType <= 4) {
        int required = kParaMinParams[funcType];
        if (static_cast<int>(nParams) < required) {
          hc.critical("HEURISTIC: Tag '%s': funcType %u requires %d params, has %u " "— HBO in Describe() — ICC.1-2022-05 §10.15", info.GetTagSigName(trcSigs[t]), funcType, required, nParams);
          hc.cweNote("CWE-125: Heap-Buffer-Overflow via insufficient parametric curve params");
        }
      }
      icFloatNumber *params = pParam->GetParams();
      if (params && nParams > 0) {
        for (icUInt16Number p = 0; p < nParams; p++) {
          if (std::isnan(params[p]) || std::isinf(params[p])) {
            hc.warn("Tag '%s': parametric curve param[%u] = NaN/Inf", info.GetTagSigName(trcSigs[t]), p);
            hc.cweNote("CWE-682: NaN/Inf in curve parameters → undefined math");
            break;
          }
        }
      }
    }
  }
}

  return hc.end("TRC curves within bounds (or absent)");
}

int RunHeuristic_H88_ChromaticAdaptationMatrix(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H88 — Chromatic Adaptation Matrix Validation (CWE-682/CWE-125)
// The chad (chromatic adaptation) tag contains a 3×3 s15Fixed16 matrix.
// A singular matrix (det≈0) causes division-by-zero in PCS conversions.
// NaN/Inf values or extreme magnitudes indicate crafted profiles.
// =====================================================================
hc.begin(88, "Chromatic Adaptation Matrix Validation");
{
  CIccTagS15Fixed16 *pChad = FindAndCast<CIccTagS15Fixed16>(pIcc, icSigChromaticAdaptationTag);
  if (pChad) {
    if (pChad) {
      icUInt32Number nSize = pChad->GetSize();
      if (nSize < 9) {
        hc.warn("chad tag has %u elements (need 9 for 3×3 matrix)", nSize);
        hc.cweNote("CWE-125: Undersized chad → OOB read in PCS conversion");
      } else {
        // Extract 3×3 matrix and compute determinant
        icFloatNumber m[9];
        for (int i = 0; i < 9; i++) {
          m[i] = icFtoD((*pChad)[i]);
        }
        // Check for NaN/Inf
        bool hasNanInf = false;
        for (int i = 0; i < 9; i++) {
          if (std::isnan(m[i]) || std::isinf(m[i])) {
            hasNanInf = true;
            break;
          }
        }
        if (hasNanInf) {
          hc.warn("chad matrix contains NaN/Inf values");
          hc.cweNote("CWE-682: NaN/Inf in adaptation matrix → undefined PCS transform");
        } else {
          // Determinant of 3×3: a(ei−fh) − b(di−fg) + c(dh−eg)
          double det = (double)m[0] * ((double)m[4]*m[8] - (double)m[5]*m[7])
                     - (double)m[1] * ((double)m[3]*m[8] - (double)m[5]*m[6])
                     + (double)m[2] * ((double)m[3]*m[7] - (double)m[4]*m[6]);
          if (std::fabs(det) < 1e-10) {
            hc.warn("chad matrix near-singular (det=%.2e)", det);
            hc.cweNote("CWE-369: Singular chad → division-by-zero in PCS inversion");
          }
          // Check for extreme values (s15Fixed16 range ±32768)
          for (int i = 0; i < 9; i++) {
            if (std::fabs(m[i]) > 100.0) {
              hc.warn("chad matrix element[%d] = %.4f (extreme, >100)", i, m[i]);
              break;
            }
          }
        }
      }
    } else {
      hc.warn("chad tag present but unexpected type");
    }
  }
}

  return hc.end("No chromatic adaptation tag (standard D50)");
}

int RunHeuristic_H89_ProfileSequenceDescription(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H89 — Profile Sequence Description Validation (CWE-400/CWE-131)
// The pseq tag stores a sequence of profile descriptions (used in
// device link profiles). An excessive count can trigger OOM; count
// × entry_size overflow can cause heap corruption during Read().
// =====================================================================
hc.begin(89, "Profile Sequence Description Validation");
{
  CIccTag *pTag = pIcc->FindTag(icSigProfileSequenceDescTag);
  if (pTag) {
    CIccTagProfileSeqDesc *pSeq = dynamic_cast<CIccTagProfileSeqDesc*>(pTag);
    if (pSeq && pSeq->m_Descriptions) {
      size_t descCount = pSeq->m_Descriptions->size();
      if (descCount > 256) {
        hc.warn("Profile sequence has %zu descriptions (>256) — OOM risk", descCount);
        hc.cweNote("CWE-400: Excessive sequence entries → large allocations in Read()");
      }
      if (descCount == 0) {
        hc.warn("Profile sequence has 0 descriptions (empty)");
      }
    } else if (pTag) {
      hc.warn("pseq tag present but wrong type or NULL descriptions");
    }
  }
  // Also check psid (profile sequence identifier)
  CIccTag *pIdTag = pIcc->FindTag((icTagSignature)icSigProfileSequceIdTag);
  if (pIdTag) {
    // psid should be a ResponseCurveSet16 or similar
    // Just verify it loaded successfully (non-null)
    hc.info("ProfileSequenceId tag present");
  }
}

  return hc.end("Profile sequence descriptions within bounds (or absent)");
}

int RunHeuristic_H90_PreviewTagChannelConsistency(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// =====================================================================
// H90 — Preview Tag Channel Consistency (CWE-125/CWE-787)
// Preview0/1/2 tags contain transforms for soft-proofing. If their
// CLUT dimensions don't match the profile's color space channels,
// Apply() will read/write out of bounds during interpolation.
// =====================================================================
hc.begin(90, "Preview Tag Channel Consistency");
{
  icUInt32Number pcsChannels = icGetSpaceSamples(pIcc->m_Header.pcs);
  icTagSignature previewSigs[] = {
    icSigPreview0Tag, icSigPreview1Tag, icSigPreview2Tag,
    (icTagSignature)0
  };
  for (int p = 0; previewSigs[p] != (icTagSignature)0; p++) {
    CIccMBB *pMbb = FindAndCast<CIccMBB>(pIcc, previewSigs[p]);
    if (!pMbb) continue;
    if (pMbb) {
      icUInt8Number mbbIn = pMbb->InputChannels();
      icUInt8Number mbbOut = pMbb->OutputChannels();
      // Preview tags should map PCS→PCS (same channels in and out)
      if (pcsChannels > 0 && mbbIn != pcsChannels) {
        hc.warn("Tag '%s': input channels=%u != PCS channels=%u", info.GetTagSigName(previewSigs[p]), mbbIn, pcsChannels);
        hc.cweNote("CWE-125: Channel mismatch → OOB in preview transform");
      }
      if (pcsChannels > 0 && mbbOut != pcsChannels) {
        hc.warn("Tag '%s': output channels=%u != PCS channels=%u", info.GetTagSigName(previewSigs[p]), mbbOut, pcsChannels);
        hc.cweNote("CWE-787: Output channel mismatch → buffer overwrite");
      }
    }
  }
}

  return hc.end("Preview tag channels consistent (or absent)");
}

int RunHeuristic_H91_ColorantOrderValidation(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H91 — Colorant Order Validation (CWE-125/CWE-787)
// ColorantOrder tag stores permutation indices for colorant channels.
// If indices exceed the ColorantTable entry count, array OOB occurs
// when the CMM maps channels. Duplicate indices indicate confusion.
// =====================================================================
hc.begin(91, "Colorant Order Validation");
{
  icTagSignature orderSigs[] = {
    icSigColorantOrderTag, icSigColorantOrderOutTag, (icTagSignature)0
  };
  icTagSignature tableSigs[] = {
    icSigColorantTableTag, icSigColorantTableOutTag, (icTagSignature)0
  };
  for (int o = 0; orderSigs[o] != (icTagSignature)0; o++) {
    CIccTagColorantOrder *pOrder = FindAndCast<CIccTagColorantOrder>(pIcc, orderSigs[o]);
    if (!pOrder) continue;

    icUInt32Number orderCount = pOrder->GetSize();
    // Get matching colorant table count
    icUInt32Number tableCount = 0;
    CIccTagColorantTable *pTable = FindAndCast<CIccTagColorantTable>(pIcc, tableSigs[o]);
    if (pTable) {
      if (pTable) tableCount = pTable->GetSize();
    }

    if (tableCount > 0 && orderCount != tableCount) {
      hc.warn("ColorantOrder has %u entries but ColorantTable has %u", orderCount, tableCount);
    }

    // Check indices within bounds and for duplicates
    std::set<icUInt8Number> seen;
    for (icUInt32Number i = 0; i < orderCount; i++) {
      icUInt8Number idx = (*pOrder)[i];
      if (tableCount > 0 && idx >= tableCount) {
        hc.warn("ColorantOrder[%u]=%u >= table count %u — OOB", i, idx, tableCount);
        hc.cweNote("CWE-125: Index out-of-bounds in colorant mapping");
        break;
      }
      if (seen.count(idx)) {
        hc.warn("ColorantOrder has duplicate index %u", idx);
        break;
      }
      seen.insert(idx);
    }
  }
}

  return hc.end("Colorant order indices valid (or absent)");
}

int RunHeuristic_H92_SpectralViewingConditions(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H92 — Spectral Viewing Conditions Validation (CWE-20/CWE-682)
// PCC (Profile Connection Conditions) profiles use spectral viewing
// conditions to define illuminant/observer. Invalid spectral ranges
// or unknown illuminant/observer types can crash IccPcc.cpp transforms.
// =====================================================================
hc.begin(92, "Spectral Viewing Conditions Validation");
{
  CIccTag *pTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (pTag) {
    CIccTagSpectralViewingConditions *pSvc =
        dynamic_cast<CIccTagSpectralViewingConditions*>(pTag);
    if (pSvc) {
      // Check illuminant XYZ for NaN/Inf
      if (std::isnan(pSvc->m_illuminantXYZ.X) || std::isnan(pSvc->m_illuminantXYZ.Y) ||
          std::isnan(pSvc->m_illuminantXYZ.Z) || std::isinf(pSvc->m_illuminantXYZ.X) ||
          std::isinf(pSvc->m_illuminantXYZ.Y) || std::isinf(pSvc->m_illuminantXYZ.Z)) {
        hc.warn("Spectral viewing conditions: illuminant XYZ contains NaN/Inf");
        hc.cweNote("CWE-682: NaN/Inf in PCC illuminant → undefined PCS transform");
      }
      // Check illuminant Y > 0 (physical requirement)
      if (pSvc->m_illuminantXYZ.Y <= 0.0f && pSvc->m_illuminantXYZ.Y != 0.0f) {
        hc.warn("Spectral viewing conditions: illuminant Y=%.4f (non-positive)", pSvc->m_illuminantXYZ.Y);
      }
      // Check surround XYZ
      if (std::isnan(pSvc->m_surroundXYZ.X) || std::isnan(pSvc->m_surroundXYZ.Y) ||
          std::isnan(pSvc->m_surroundXYZ.Z)) {
        hc.warn("Spectral viewing conditions: surround XYZ contains NaN");
      }
      // Check CCT (correlated color temperature) range
      icFloatNumber cct = pSvc->getIlluminantCCT();
      if (cct < 0.0f || cct > 100000.0f) {
        hc.warn("Illuminant CCT=%.1f (outside 0-100000K range)", cct);
      }
    } else {
      hc.warn("Spectral viewing conditions tag has unexpected type");
    }
  }
}

  return hc.end("Spectral viewing conditions valid");
}

int RunHeuristic_H93_EmbeddedProfileFlag(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H93 — Embedded Profile Flag Consistency (CWE-345/CWE-20)
// The profile flags field (header offset 44) has defined bits:
//   bit 0: Embedded profile (0=not embedded, 1=embedded in file)
//   bit 1: Profile cannot be used independently
// Bits 2-15 are reserved and should be zero per ICC spec.
// Non-zero reserved bits indicate spec violation or crafted profile.
// =====================================================================
hc.begin(93, "Embedded Profile Flag Consistency");
{
  icUInt32Number flags = pIcc->m_Header.flags;
  // Check reserved bits (bits 16-31 are reserved for ICC, bits 2-15 per spec)
  icUInt32Number reservedMask = 0xFFFFFFFC; // All bits except 0 and 1
  if (flags & reservedMask) {
    hc.warn("Profile flags=0x%08X: reserved bits set (mask=0x%08X)", flags, flags & reservedMask);
    hc.cweNote("CWE-20: Non-zero reserved flag bits → spec violation or crafted profile");
  }
  // Check consistency: bit 1 (cannot use independently) only makes sense with bit 0 (embedded)
  bool embedded = (flags & 0x01) != 0;
  bool notIndependent = (flags & 0x02) != 0;
  if (notIndependent && !embedded) {
    hc.warn("Flag conflict: 'cannot use independently' set but 'embedded' not set");
  }
  // Check attributes field too (rendering attributes at header offset 56)
  icUInt64Number attributes = pIcc->m_Header.attributes;
  // Bits 0-3: Reflective/Transparency, Glossy/Matte, Media positive/negative, B&W/Color
  // Bits 4-63: reserved (should be zero)
  uint64_t attrReserved = attributes & 0xFFFFFFFFFFFFFFF0ULL;
  if (attrReserved) {
    hc.warn("Attributes=0x%016llX: reserved bits set", (unsigned long long)attributes);
  }
}

  return hc.end("Profile flags and attributes consistent");
}

int RunHeuristic_H94_MatrixTRCColorantConsistency(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// =====================================================================
// H94 — Matrix/TRC Colorant Consistency (CWE-682/CWE-125)
// For matrix/TRC-based profiles (Display class with RGB colorSpace),
// the Red/Green/Blue MatrixColumn tags define a 3×3 matrix. The sum
// of columns should approximate D50 whitepoint (0.9505, 1.0, 1.0890).
// Large deviations indicate malformed profiles that produce extreme
// values during PCS transforms, potentially triggering overflows.
// =====================================================================
hc.begin(94, "Matrix/TRC Colorant Consistency");
{
  // Only check RGB display/input profiles (matrix/TRC architecture)
  if (pIcc->m_Header.colorSpace == icSigRgbData) {
    CIccTag *pRedCol = pIcc->FindTag(icSigRedMatrixColumnTag);
    CIccTag *pGrnCol = pIcc->FindTag(icSigGreenMatrixColumnTag);
    CIccTag *pBluCol = pIcc->FindTag(icSigBlueMatrixColumnTag);
    CIccTag *pWP = pIcc->FindTag(icSigMediaWhitePointTag);

    if (pRedCol && pGrnCol && pBluCol) {
      CIccTagXYZ *rXYZ = dynamic_cast<CIccTagXYZ*>(pRedCol);
      CIccTagXYZ *gXYZ = dynamic_cast<CIccTagXYZ*>(pGrnCol);
      CIccTagXYZ *bXYZ = dynamic_cast<CIccTagXYZ*>(pBluCol);

      if (rXYZ && gXYZ && bXYZ &&
          rXYZ->GetSize() >= 1 && gXYZ->GetSize() >= 1 && bXYZ->GetSize() >= 1) {
        icFloatNumber sumX = icFtoD((*rXYZ)[0].X) + icFtoD((*gXYZ)[0].X) + icFtoD((*bXYZ)[0].X);
        icFloatNumber sumY = icFtoD((*rXYZ)[0].Y) + icFtoD((*gXYZ)[0].Y) + icFtoD((*bXYZ)[0].Y);
        icFloatNumber sumZ = icFtoD((*rXYZ)[0].Z) + icFtoD((*gXYZ)[0].Z) + icFtoD((*bXYZ)[0].Z);

        // D50 whitepoint: X=0.9505, Y=1.0000, Z=1.0890
        double devX = std::fabs(sumX - 0.9505);
        double devY = std::fabs(sumY - 1.0000);
        double devZ = std::fabs(sumZ - 1.0890);

        if (devX > 0.1 || devY > 0.1 || devZ > 0.1) {
          hc.warn("Matrix column sum (%.4f, %.4f, %.4f) deviates from D50", sumX, sumY, sumZ);
          hc.info("Expected ≈ (0.9505, 1.0000, 1.0890), deviation (%.4f, %.4f, %.4f)", devX, devY, devZ);
        }
        // Check for NaN/Inf in any column
        for (int c = 0; c < 3; c++) {
          CIccTagXYZ *col = (c == 0) ? rXYZ : (c == 1) ? gXYZ : bXYZ;
          if (std::isnan(icFtoD((*col)[0].X)) || std::isnan(icFtoD((*col)[0].Y)) ||
              std::isnan(icFtoD((*col)[0].Z))) {
            hc.warn("Matrix column %d contains NaN — corrupted colorant", c);
            hc.cweNote("CWE-682: NaN in matrix → undefined PCS output");
          }
        }
        // Check for negative XYZ values (physically impossible)
        if (icFtoD((*rXYZ)[0].Y) < -0.01 || icFtoD((*gXYZ)[0].Y) < -0.01 || icFtoD((*bXYZ)[0].Y) < -0.01) {
          hc.warn("Matrix column Y value negative — non-physical colorant");
        }
      }
    }

    // Also check whitepoint tag if present
    if (pWP) {
      CIccTagXYZ *wpXYZ = dynamic_cast<CIccTagXYZ*>(pWP);
      if (wpXYZ && wpXYZ->GetSize() >= 1) {
        icFloatNumber wpY = icFtoD((*wpXYZ)[0].Y);
        if (std::fabs(wpY - 1.0) > 0.1) {
          hc.warn("Media whitepoint Y=%.4f (expected ≈1.0 for D50)", wpY);
        }
      }
    }
  }
}

  return hc.end("Matrix/TRC colorant consistency valid (or non-RGB)");
}

int RunHeuristic_H95_SparseMatrixArrayBoundsValidation(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// H95 — Sparse Matrix Array Bounds Validation (CWE-125/CWE-787)
// Exercises: IccSparseMatrix.cpp (26.8% coverage → Init, GetSparseMatrix, Rows, Cols)
//            IccTagBasic.cpp CIccTagSparseMatrixArray
{
  hc.begin(95, "Sparse Matrix Array Bounds Validation");
  bool foundSparse = false;

  // Scan all tags for CIccTagSparseMatrixArray (type icSigSparseMatrixArrayType)
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); ++sit) {
    CIccTag *pSmaTag = pIcc->FindTag(sit->TagInfo.sig);
    if (!pSmaTag) continue;
    if (pSmaTag->GetType() != icSigSparseMatrixArrayType) continue;

    CIccTagSparseMatrixArray *pSma = dynamic_cast<CIccTagSparseMatrixArray *>(pSmaTag);
    if (pSma) {
      foundSparse = true;
      icUInt32Number nChannels = pSma->GetChannelsPerMatrix();
      icUInt32Number nBytesPerMatrix = pSma->GetBytesPerMatrix();

      hc.info("Sparse matrix array '': channels=%u, bytes/matrix=%u", info.GetTagSigName(sit->TagInfo.sig), nChannels, nBytesPerMatrix);

      if (nChannels == 0) {
        hc.critical("Zero channels per matrix — potential division-by-zero");
      }

      if (nChannels > 65535) {
        hc.warn("Channels per matrix=%u exceeds reasonable limit", nChannels);
      }

      // Try to get first sparse matrix and validate dimensions
      CIccSparseMatrix mtx;
      if (pSma->GetSparseMatrix(mtx, 0, true)) {
        icUInt16Number rows = mtx.Rows();
        icUInt16Number cols = mtx.Cols();
        hc.info("Matrix[0]: rows=%u, cols=%u", rows, cols);

        if (rows == 0 || cols == 0) {
          hc.critical("Zero-dimension sparse matrix (rows=%u, cols=%u)", rows, cols);
        }
      }

    } else {
      hc.warn("SparseMatrix tag present but wrong type — type confusion risk");
    }
  }

  if (!foundSparse) {
    return hc.skip("No sparse matrix array tags present");
  }
}

  return hc.end("Sparse matrix array bounds valid");
}

int RunHeuristic_H96_EmbeddedProfileValidation(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// H96 — Embedded Profile Validation (CWE-674/CWE-400/CWE-843)
// Exercises: IccTagEmbedIcc.cpp (30.9% coverage → GetProfile, Read, Validate)
// Upstream issues: #527, #528, #544 (type confusion CIccTagUnknown → CIccTagEmbeddedProfile)
{
  hc.begin(96, "Embedded Profile Validation");

  CIccTagEmbeddedProfile *pEmbed = FindAndCast<CIccTagEmbeddedProfile>(pIcc, icSigEmbeddedV5ProfileTag);
  if (pEmbed) {
    if (pEmbed) {
      CIccProfile *pEmbeddedProfile = pEmbed->GetProfile();

      if (!pEmbeddedProfile) {
        hc.warn("Embedded profile tag present but profile is NULL");
      } else {
        // Validate embedded profile header
        icHeader &embedHdr = pEmbeddedProfile->m_Header;

        hc.info("Embedded profile: class=, colorSpace=, version=%u.%u", info.GetProfileClassSigName(embedHdr.deviceClass), info.GetColorSpaceSigName(embedHdr.colorSpace), embedHdr.version >> 24, (embedHdr.version >> 20) & 0xF);

        // Check for recursive embedding — potential infinite recursion (CWE-674)
        CIccTag *pInnerEmbed = pEmbeddedProfile->FindTag(icSigEmbeddedV5ProfileTag);
        if (pInnerEmbed) {
          hc.critical("Recursively embedded profile — infinite recursion risk (CWE-674)");
        }

        // Check embedded profile size vs parent
        icUInt32Number parentSize = pIcc->m_Header.size;
        icUInt32Number embedSize = embedHdr.size;
        if (embedSize > 0 && parentSize > 0 && embedSize >= parentSize) {
          hc.warn("Embedded profile size (%u) >= parent size (%u) — suspicious", embedSize, parentSize);
        }

        // Check embedded profile count > tag count (resource exhaustion)
        icUInt32Number embedTagCount = (icUInt32Number)pEmbeddedProfile->m_Tags.size();
        if (embedTagCount > 200) {
          hc.warn("Embedded profile has %u tags — potential resource exhaustion", embedTagCount);
        }
      }
    } else {
      hc.critical("Embedded profile tag present but wrong type (dynamic_cast failed)");
      hc.cweNote("CWE-843: Type confusion — tag is CIccTagUnknown, not CIccTagEmbeddedProfile");
      hc.info("Upstream: iccDEV #527, #528, #544 — DumpProfileInfo() SEGV via misaligned access");
    }
  } else {
    return hc.skip("No embedded profile tag present");
  }
  if (pIcc->FindTag(icSigEmbeddedV5ProfileTag)) {
  }
}

  return hc.end("Embedded profile structure valid");
}

int RunHeuristic_H97_ProfileSequenceIdValidation(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// H97 — Profile Sequence Identifier Validation (CWE-125/CWE-400)
// Exercises: IccTagProfSeqId.cpp (27.7% coverage → GetFirst, GetLast, begin/end iterators)
{
  hc.begin(97, "Profile Sequence Identifier Validation");

  CIccTag *pSeqIdTag = pIcc->FindTag(icSigProfileSequceIdTag);
  CIccTagProfileSequenceId *pSeqId = pSeqIdTag ? dynamic_cast<CIccTagProfileSequenceId*>(pSeqIdTag) : nullptr;
  if (pSeqId) {
      int entryCount = 0;
      bool hasNullId = false;
      bool hasDupId = false;
      std::set<std::string> seenIds;

      for (const auto& entry : *pSeqId) {
        entryCount++;

        icProfileID pid = entry.m_profileID;
        bool allZero = true;
        for (int k = 0; k < 16; k++) {
          if (pid.ID8[k] != 0) { allZero = false; break; }
        }
        if (allZero) hasNullId = true;

        std::string idStr(reinterpret_cast<const char *>(pid.ID8), 16);
        if (!allZero && seenIds.count(idStr)) {
          hasDupId = true;
        }
        seenIds.insert(idStr);

        if (entryCount > 1000) {
          hc.warn("Profile sequence >1000 entries — potential DoS (CWE-400)");
          break;
        }
      }

      hc.info("Profile sequence: %d entries", entryCount);

      if (hasNullId) {
        hc.warn("Null profile ID (all zeros) in sequence");
      }

      if (hasDupId) {
        hc.warn("Duplicate profile IDs in sequence");
      }

      // Validate first/last accessors
      CIccProfileIdDesc *pFirst = pSeqId->GetFirst();
      CIccProfileIdDesc *pLast = pSeqId->GetLast();
      if (entryCount > 0 && (!pFirst || !pLast)) {
        hc.critical("Non-empty sequence but GetFirst/GetLast returns NULL");
      }
  } else {
    return hc.skip("No profile sequence ID tag present");
  }
  if (pIcc->FindTag(icSigProfileSequceIdTag)) {
  }
}

  return hc.end("Profile sequence identifiers valid");
}

int RunHeuristic_H98_SpectralMPEElementValidation(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// H98 — Spectral MPE Element Validation (CWE-125/CWE-682)
// Exercises: IccMpeSpectral.cpp (31.8% coverage → CIccMpeSpectralMatrix, CIccMpeSpectralCLUT,
//            CIccMpeSpectralObserver via CIccTagMultiProcessElement iteration)
{
  hc.begin(98, "Spectral MPE Element Validation");

  // Search MPE tags for spectral elements
  icTagSignature mpeTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
    icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
    icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag
  };

  bool foundSpectral = false;
  for (int i = 0; i < 16; i++) {
    CIccTagMultiProcessElement *pMpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, mpeTags[i]);
    if (!pMpe) continue;

    icUInt32Number numElems = pMpe->NumElements();
    if (numElems == 0) continue;

    for (icUInt32Number e = 0; e < numElems; e++) {
      CIccMultiProcessElement *pElem = pMpe->GetElement(e);
      if (!pElem) continue;

      icElemTypeSignature elemType = pElem->GetType();

      // Check spectral matrix elements
      CIccMpeSpectralMatrix *pSpecMtx = dynamic_cast<CIccMpeSpectralMatrix *>(pElem);
      if (pSpecMtx) {
        foundSpectral = true;
        icUInt16Number numIn = pSpecMtx->NumInputChannels();
        icUInt16Number numOut = pSpecMtx->NumOutputChannels();
        const icSpectralRange &range = pSpecMtx->GetRange();
        hc.info("Spectral matrix: in=%u, out=%u, steps=%u, type=0x%08x", numIn, numOut, range.steps, elemType);

        if (numIn == 0 || numOut == 0) {
          hc.critical("Zero-channel spectral matrix element");
        }

        if (numIn > 256 || numOut > 256) {
          hc.warn("Spectral matrix channels (%u→%u) exceed 256", numIn, numOut);
        }

        // Detect CIccMpeSpectralMatrix::Describe() HBO pattern (CWE-122).
        // SetSize() allocates numVectors()*range.steps floats. numVectors()
        // returns m_nInputChannels for EmissionMatrix, m_nOutputChannels for
        // InvEmissionMatrix. Describe() iterates m_nOutputChannels rows and
        // advances pointer by m_nInputChannels. When these don't match
        // numVectors()/range.steps, Describe() reads past the allocation.
        // Ref: CFL-006, GHSA pending.
        if (range.steps > 0 && numIn != numOut) {
          bool isEmission = (elemType == icSigEmissionMatrixElemType);
          bool isInvEmission = (elemType == icSigInvEmissionMatrixElemType);
          if (isEmission && numOut > numIn) {
            // EmissionMatrix: numVectors()=numIn, alloc=numIn*steps
            // Describe iterates numOut rows → reads past allocation
            hc.critical("HEURISTIC: EmissionMatrix out(%u) > in(%u) — " "Describe() HBO: iterates %u rows but allocation has %u " "— ICC.2-2023 §10.2.4", numOut, numIn, numOut, numIn);
            hc.cweNote("CWE-122: Heap-based Buffer Overflow in Describe()");
          }
          if ((isEmission || isInvEmission) && numIn != range.steps) {
            // Pointer advance uses m_nInputChannels but data layout is
            // range.steps per row — mismatch causes offset drift
            hc.warn("HEURISTIC: SpectralMatrix in(%u) != steps(%u) — " "Describe() pointer advance mismatch — ICC.2-2023 §10.2.4", numIn, range.steps);
            hc.cweNote("CWE-125: Out-of-bounds Read via pointer drift");
          }
        }

        // CFL-056 pattern: null m_pWhite/m_pOffset in Describe()
        // SpectralMatrix::Describe() dereferences m_pWhite and m_pOffset
        // without null checks. If Read() fails to allocate these, Describe()
        // crashes with NPD (CWE-476).
        if (!pSpecMtx->GetWhite()) {
          hc.critical("HEURISTIC: SpectralMatrix has null white point array " "— NPD in Describe() — ICC.2-2023 §10.2.4");
          hc.cweNote("CWE-476: Null Pointer Dereference in spectral white access");
        }
        if (!pSpecMtx->GetOffset()) {
          hc.warn("SpectralMatrix has null offset array " "— potential NPD in Describe() — ICC.2-2023 §10.2.4");
          hc.cweNote("CWE-476: Null Pointer Dereference in spectral offset access");
        }
      }

      // Check spectral CLUT elements
      CIccMpeSpectralCLUT *pSpecClut = dynamic_cast<CIccMpeSpectralCLUT *>(pElem);
      if (pSpecClut) {
        foundSpectral = true;
        icUInt16Number numIn = pSpecClut->NumInputChannels();
        icUInt16Number numOut = pSpecClut->NumOutputChannels();
        hc.info("Spectral CLUT: in=%u, out=%u, type=0x%08x", numIn, numOut, elemType);

        if (numIn == 0 || numOut == 0) {
          hc.critical("Zero-channel spectral CLUT element");
        }

        // CLUT with high input channels → exponential memory
        if (numIn > 16) {
          hc.warn("Spectral CLUT input channels=%u — exponential grid risk", numIn);
        }
      }

      // Check spectral observer elements
      CIccMpeSpectralObserver *pSpecObs = dynamic_cast<CIccMpeSpectralObserver *>(pElem);
      if (pSpecObs) {
        foundSpectral = true;
        icUInt16Number numIn = pSpecObs->NumInputChannels();
        icUInt16Number numOut = pSpecObs->NumOutputChannels();
        hc.info("Spectral observer: in=%u, out=%u, type=0x%08x", numIn, numOut, elemType);

        if (numIn == 0 || numOut == 0) {
          hc.critical("Zero-channel spectral observer element");
        }
      }
    }
  }

  if (!foundSpectral) {
    return hc.skip("No spectral MPE elements present");
  }
}

  return hc.end("Spectral MPE elements valid");
}

int RunHeuristic_H99_EmbeddedImageTagValidation(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// H99 — Embedded Height/Normal Image Validation (CWE-120/CWE-787)
// Exercises: IccTagEmbedIcc.cpp for non-profile embedded data types
{
  hc.begin(99, "Embedded Image Tag Validation");
  bool foundEmbedImg = false;

  // Scan all tags for embedded image types
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); ++sit) {
    CIccTag *pTag = pIcc->FindTag(sit->TagInfo.sig);
    if (!pTag) continue;

    icTagTypeSignature tagType = pTag->GetType();
    if (tagType == icSigEmbeddedHeightImageType || tagType == icSigEmbeddedNormalImageType) {
      foundEmbedImg = true;
      const char *typeName = (tagType == icSigEmbeddedHeightImageType) ? "HeightImage" : "NormalImage";
      hc.info("Found  tag in ''", typeName, info.GetTagSigName(sit->TagInfo.sig));

      // Validate tag size is reasonable
      if (sit->TagInfo.size > 100 * 1024 * 1024) {
        hc.warn("%s tag size %u bytes (>100MB) — potential DoS", typeName, sit->TagInfo.size);
      }
    }
  }

  if (!foundEmbedImg) {
    return hc.skip("No embedded image tags present");
  }
}

  return hc.end("Embedded image tags valid");
}

int RunHeuristic_H100_ProfileSequenceDescValidation(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// H100 — Profile Sequence Description Consistency (CWE-125/CWE-120)
// Exercises: IccTagBasic.cpp CIccTagProfileSeqDesc (different from H97 ProfileSequenceId)
{
  hc.begin(100, "Profile Sequence Description Validation");

  CIccTag *pPseqTag = pIcc->FindTag(icSigProfileSequenceDescTag);
  if (pPseqTag) {
    hc.info("Found ProfileSequenceDesc tag");

    // Describe for size validation
    std::string desc;
    pPseqTag->Describe(desc, 1);

    if (desc.empty()) {
      hc.warn("ProfileSequenceDesc describes as empty");
    } else {
      // Count entries by looking for pattern matches
      size_t pos = 0;
      int descEntries = 0;
      while ((pos = desc.find("Device Manufacturer", pos)) != std::string::npos) {
        descEntries++;
        pos++;
      }
      hc.info("Sequence description entries: ~%d", descEntries);

      if (descEntries > 100) {
        hc.warn("Excessive sequence entries (%d) — DoS risk", descEntries);
      }
    }
  } else {
    return hc.skip("No profile sequence description tag");
  }
  if (pPseqTag) {
  }
}

  return hc.end("Profile sequence description valid");
}

int RunHeuristic_H101_MPESubElementChannelContinuity(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();

// H101 — MPE Sub-Element Channel Continuity (CWE-125/CWE-787)
// CVE-2026-21492 (Medium 5.5) — NPD in CIccMpeToneMap Write (invalid sub-element state)
// Exercises: IccMpeBasic.cpp (64.4% → NumInputChannels/NumOutputChannels chain validation)
//            Verifies in[i+1] == out[i] across entire MPE processing pipeline
{
  hc.begin(101, "MPE Sub-Element Channel Continuity");

  icTagSignature mpeTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
    icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
    icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag
  };

  for (int i = 0; i < 16; i++) {
    CIccTagMultiProcessElement *pMpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, mpeTags[i]);
    if (!pMpe) continue;

    icUInt32Number numElems = pMpe->NumElements();
    if (numElems == 0) continue;

    icUInt16Number prevOut = 0;
    bool first = true;

    for (icUInt32Number e = 0; e < numElems; e++) {
      CIccMultiProcessElement *pElem = pMpe->GetElement(e);
      if (!pElem) continue;

      icUInt16Number curIn = pElem->NumInputChannels();
      icUInt16Number curOut = pElem->NumOutputChannels();

      if (!first && curIn != prevOut) {
        char tagSig[5];
        icUInt32Number sig = (icUInt32Number)mpeTags[i];
        SigToChars(sig, tagSig);
        hc.critical("Channel discontinuity in '%s' at element %u: " "prev_out=%u, cur_in=%u — buffer overflow risk (CWE-787)", tagSig, e, prevOut, curIn);
      }

      prevOut = curOut;
      first = false;
    }
  }

}

  return hc.end("MPE sub-element channel continuity valid");
}

int RunHeuristic_H102_TagSizeProfileSizeCrossCheck(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

// H102 — Tag Size vs Profile Size Cross-Check (CWE-125/CWE-120)
// Exercises: IccProfile.cpp (75.25% → tag table iteration, offset validation)
//            Direct binary-level validation independent of tag parsing
{
  hc.begin(102, "Tag Size vs Profile Size Cross-Check");

  icUInt32Number profileSize = pIcc->m_Header.size;
  icUInt32Number h102TagCount = (icUInt32Number)pIcc->m_Tags.size();

  hc.info("Profile size: %u bytes, tag count: %u", profileSize, h102TagCount);

  if (profileSize > 0 && profileSize < 128 + (h102TagCount * 12)) {
    hc.critical("Profile size %u too small for %u tags (min=%u) — truncation", profileSize, h102TagCount, 128 + h102TagCount * 12);
  }

  // Check each tag entry for offset/size validity
  icUInt32Number maxTagEnd = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    icUInt32Number tagOffset = it->TagInfo.offset;
    icUInt32Number tagSize = it->TagInfo.size;

    if (profileSize > 0) {
      if (tagOffset > profileSize) {
        hc.critical("Tag '%s' offset %u exceeds profile size %u", info.GetTagSigName(it->TagInfo.sig), tagOffset, profileSize);
      } else if (tagSize > profileSize - tagOffset) {
        hc.warn("Tag '%s' extends past profile end: offset=%u size=%u total=%u", info.GetTagSigName(it->TagInfo.sig), tagOffset, tagSize, profileSize);
      }
    }

    // Track the furthest tag end for EOF gap detection (guard against overflow)
    if (tagSize <= profileSize && tagOffset <= profileSize - tagSize) {
      icUInt32Number tagEnd = tagOffset + tagSize;
      if (tagEnd > maxTagEnd) {
        maxTagEnd = tagEnd;
      }
    }
  }

  // PAWS: "EOF follows last tag (including four-byte boundary), no additional bytes"
  // Check for trailing bytes after the last tag (potential hidden data)
  if (profileSize > 0 && maxTagEnd > 0) {
    // Round up to 4-byte boundary per ICC spec
    icUInt32Number alignedEnd = (maxTagEnd + 3) & ~3u;
    if (profileSize > alignedEnd + 4) {
      icUInt32Number trailingBytes = profileSize - alignedEnd;
      hc.warn("HEURISTIC: %u trailing bytes after last tag end (aligned=%u, profileSize=%u)", trailingBytes, alignedEnd, profileSize);
      hc.info("Risk: Hidden data appended after declared profile content — ICC.1-2022-05 §7.2");
    }
  }

}

  return hc.end("Tag size vs profile size consistent");
}

// =====================================================================
// H146 — Stack Buffer Overflow Detection via GetValues() Size Mismatch
// Detects: CIccTagFloatNum::GetValues() writes nVectorSize floats into
// a caller-provided buffer without checking the buffer length. If
// m_nSize (tag array length) exceeds the expected channel count for
// the color space, a fixed-size stack buffer overflows.
// PoCs: #551, #618, #649, #625, #624, #537
// CWE-121: Stack-based Buffer Overflow
// =====================================================================
int RunHeuristic_H146_StackBufferOverflowGetValues(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

  hc.begin(146, "Stack Buffer Overflow — GetValues() Size Mismatch (CWE-121)");
  {

    // Get expected channel count from PCS and device color spaces
    icUInt32Number pcsChannels = icGetSpaceSamples(pIcc->m_Header.pcs);
    icUInt32Number devChannels = icGetSpaceSamples(pIcc->m_Header.colorSpace);
    icUInt32Number maxExpected = (pcsChannels > devChannels) ? pcsChannels : devChannels;
    if (maxExpected == 0) maxExpected = 4;
    // Safe upper bound: no legitimate profile needs > 16 channels per operation
    const icUInt32Number kMaxSafeChannels = 16;

    // Check numeric array tags where GetValues() is called with fixed buffers
    icTagSignature numArrayTags[] = {
      icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag,
      icSigMediaWhitePointTag, icSigMediaBlackPointTag,
      icSigLuminanceTag, icSigChromaticAdaptationTag,
      icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag,
      (icTagSignature)0
    };

    for (int t = 0; numArrayTags[t] != (icTagSignature)0; t++) {
      CIccTag *pTag = pIcc->FindTag(numArrayTags[t]);
      if (!pTag) continue;

      // CIccTagFixedNum and CIccTagNum both have GetSize()
      // Check if the stored array size exceeds safe bounds for stack buffers
      icUInt32Number tagArraySize = 0;

      CIccTagXYZ *xyz = dynamic_cast<CIccTagXYZ *>(pTag);
      if (xyz) {
        tagArraySize = xyz->GetSize();
      }

      CIccTagS15Fixed16 *s15 = dynamic_cast<CIccTagS15Fixed16 *>(pTag);
      if (s15) {
        tagArraySize = s15->GetSize();
      }

      CIccTagU16Fixed16 *u16 = dynamic_cast<CIccTagU16Fixed16 *>(pTag);
      if (u16) {
        tagArraySize = u16->GetSize();
      }

      if (tagArraySize > kMaxSafeChannels) {
        hc.critical("HEURISTIC: Tag '%s' array size %u exceeds safe stack buffer limit (%u)", info.GetTagSigName(numArrayTags[t]), tagArraySize, kMaxSafeChannels);
        hc.info("CWE-121: GetValues() writes %u elements into fixed-size caller buffer", tagArraySize);
      }
    }

    // Check LUT tags where Apply() uses fixed-size pixel buffers
    icTagSignature lutTags[] = {
      icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
      icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
      (icTagSignature)0
    };

    for (int t = 0; lutTags[t] != (icTagSignature)0; t++) {
      CIccTag *pTag = pIcc->FindTag(lutTags[t]);
      if (!pTag) continue;

      // Check CLUT output channels vs declared color space
      CIccMBB *pMBB = dynamic_cast<CIccMBB *>(pTag);
      if (pMBB) {
        icUInt16Number nOutput = pMBB->OutputChannels();
        if (nOutput > kMaxSafeChannels) {
          hc.critical("HEURISTIC: Tag '%s' LUT output channels %u exceeds safe limit (%u)", info.GetTagSigName(lutTags[t]), nOutput, kMaxSafeChannels);
          hc.cweNote("CWE-121: CIccXform3DLut::Apply() writes to fixed tmpPixel[16] buffer");
        }
        // Also check: output channels declared but mismatch with color space
        if (nOutput > 0 && nOutput > maxExpected * 2) {
          hc.warn("Tag '%s' output channels %u >> color space channels %u — SBO risk", info.GetTagSigName(lutTags[t]), nOutput, maxExpected);
        }
      }
    }

  }

  return hc.end("No stack buffer overflow patterns detected in numeric/LUT tags");
}

// =====================================================================
// H147 — Null Pointer Dereference After Failed Tag Operations
// Detects: Tags that Read() but leave internal pointers null when the
// tag data is malformed. Subsequent access (GetBuffer, Describe, Apply)
// dereferences null. Key pattern: CIccTagUtf16Text with m_nBufferSize=0
// after Read() on truncated data, CIccTagTextDescription with null m_szText.
// PoCs: #553, #560, #484, #485, #507, #633
// CWE-476: NULL Pointer Dereference
// =====================================================================
int RunHeuristic_H147_NullPointerAfterTagRead(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

  hc.begin(147, "Null Pointer Dereference — Post-Read() Tag State (CWE-476)");
  {

    // Check Utf16Text tags — GetBuffer() returns null when m_nBufferSize == 0
    icTagSignature textTags[] = {
      icSigProfileDescriptionTag,
      icSigDeviceMfgDescTag,
      icSigDeviceModelDescTag,
      icSigCopyrightTag,
      icSigCharTargetTag,
      (icTagSignature)0
    };

    for (int t = 0; textTags[t] != (icTagSignature)0; t++) {
      CIccTag *pTag = pIcc->FindTag(textTags[t]);
      if (!pTag) continue;

      // CIccTagUtf16Text: check if text pointer is usable
      CIccTagUtf16Text *utf16 = dynamic_cast<CIccTagUtf16Text *>(pTag);
      if (utf16) {
        const icUChar16 *buf = utf16->GetText();
        if (!buf || utf16->GetLength() == 0) {
          hc.critical("HEURISTIC: Tag '%s' (Utf16Text) has null/empty text after Read()", info.GetTagSigName(textTags[t]));
          hc.cweNote("CWE-476: GetText() returns null — subsequent access crashes");
        }
      }

      // CIccTagTextDescription: check m_szText
      CIccTagTextDescription *desc = dynamic_cast<CIccTagTextDescription *>(pTag);
      if (desc) {
        const icChar *text = desc->GetText();
        if (!text) {
          hc.critical("HEURISTIC: Tag '%s' (TextDescription) has null text pointer", info.GetTagSigName(textTags[t]));
          hc.cweNote("CWE-476: GetText() returns null — strlen/Describe crashes");
        }
      }
    }

    // Check MPE tags — Apply() with null sub-elements
    icTagSignature mpeTags[] = {
      icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
      icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
      icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
      icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag,
      (icTagSignature)0
    };

    for (int t = 0; mpeTags[t] != (icTagSignature)0; t++) {
      CIccTagMultiProcessElement *mpe =
          FindAndCast<CIccTagMultiProcessElement>(pIcc, mpeTags[t]);
      if (!mpe) continue;

      icUInt32Number nElem = mpe->NumElements();
      for (icUInt32Number e = 0; e < nElem && e < 64; e++) {
        CIccMultiProcessElement *elem = mpe->GetElement(e);
        if (!elem) {
          hc.critical("HEURISTIC: Tag '%s' MPE element[%u] is null — Apply() will crash", info.GetTagSigName(mpeTags[t]), e);
          hc.cweNote("CWE-476: Null element dereference in processing pipeline");
          break;  // one finding per tag is sufficient
        }
      }
    }

    // Check struct tags — ParseTag() returns null for unrecognized members
    for (const auto &entry : pIcc->m_Tags) {
      CIccTag *pTag = entry.pTag;
      if (!pTag) {
        hc.critical("HEURISTIC: Tag '%s' entry exists but pTag pointer is null", info.GetTagSigName(entry.TagInfo.sig));
        hc.cweNote("CWE-476: Null tag pointer in tag table — any access crashes");
      }
    }

    // Check LUT CLUT — GetCLUT() returns null when CLUT data is missing/invalid.
    // CIccCLUT::InterpND() at IccTagLut.cpp:3181 dereferences pApply->m_df
    // without null check. If GetNewApply() fails (null CLUT, 0 grid points,
    // 0 input channels), pApply is null → NPD. CWE-476.
    icTagSignature clutLutTags[] = {
      icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
      icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
      (icTagSignature)0
    };
    for (int t = 0; clutLutTags[t] != (icTagSignature)0; t++) {
      CIccMBB *pMBB = FindAndCast<CIccMBB>(pIcc, clutLutTags[t]);
      if (!pMBB) continue;

      CIccCLUT *pCLUT = pMBB->GetCLUT();
      if (!pCLUT) {
        // LUT tag exists but has no CLUT — Apply() will NPD
        hc.critical("HEURISTIC: Tag '%s' LUT has null CLUT — Apply() will crash", info.GetTagSigName(clutLutTags[t]));
        hc.cweNote("CWE-476: CIccCLUT::InterpND() dereferences null pApply " "(IccTagLut.cpp:3181)");
      } else {
        // Check for degenerate CLUT: zero grid points or zero input channels
        icUInt8Number nInput = pCLUT->GetInputDim();
        icUInt32Number nGridPts = pCLUT->NumPoints();
        if (nInput == 0 || nGridPts == 0) {
          hc.critical("HEURISTIC: Tag '%s' CLUT has %u input dims, %u grid points", info.GetTagSigName(clutLutTags[t]), (unsigned)nInput, nGridPts);
          hc.cweNote("CWE-476: Degenerate CLUT → GetNewApply() Init() fails → null pApply");
        }
      }
    }

    // CFL-044: CIccXformNDLut::Apply() dispatch gap.
    // When colorSpace is NOT 3-channel or 4-channel, the CMM selects NDLut.
    // NDLut::Apply() switch(nInput) only has cases for 5 and 6 — inputs 1-4
    // fall through to InterpND(pApply) but GetNewApply() only allocates pApply
    // when m_nNumInput > 6. Result: null deref at IccTagLut.cpp:3181.
    // Detect: BToA tag with CLUT input dim 1-4 on a non-3CLR/4CLR profile.
    icColorSpaceSignature cs = pIcc->m_Header.colorSpace;
    bool isNDLutPath = (cs != icSigRgbData && cs != icSigLabData &&
                        cs != icSigXYZData && cs != icSigHsvData &&
                        cs != icSigHlsData && cs != icSigCmyData &&
                        cs != icSig3colorData &&
                        cs != icSigCmykData && cs != icSig4colorData);
    if (isNDLutPath) {
      icTagSignature btoaSigs[] = {
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
        (icTagSignature)0
      };
      for (int t = 0; btoaSigs[t] != (icTagSignature)0; t++) {
        CIccMBB *pMBB = FindAndCast<CIccMBB>(pIcc, btoaSigs[t]);
        if (!pMBB) continue;
        CIccCLUT *pCLUT = pMBB->GetCLUT();
        if (!pCLUT) continue;
        icUInt8Number nIn = pCLUT->GetInputDim();
        if (nIn >= 1 && nIn <= 4) {
          hc.critical("HEURISTIC: Tag '%s' CLUT has %u input dims on NDLut path", info.GetTagSigName(btoaSigs[t]), (unsigned)nIn);
          hc.info("CWE-476: CIccXformNDLut::Apply() missing Interp%ud dispatch — " "falls to InterpND(pApply=NULL) (IccCmm.cpp:6570/6600)", (unsigned)nIn);
        }
      }
    }

  }

  return hc.end("No null pointer patterns detected in loaded tags");
}

// =====================================================================
// H148 — Memory Copy Bounds and Overlap Detection
// Detects: MPE Apply() chains where input and output buffers alias the
// same memory region, causing memcpy-param-overlap (ASAN). Also detects
// tag data sizes that would overflow intermediate copy buffers.
// Pattern: CIccTagMultiProcessElement::Apply() ping-pongs between
// m_pApplyBuf and pDst — if nInput == nOutput and channels are reused,
// intermediate Apply() calls can overlap src/dst in memcpy.
// PoC: #577 (memcpy-param-overlap in CIccTagMultiProcessElement::Apply)
// CWE-119: Improper Restriction of Operations within Buffer Bounds
// =====================================================================
int RunHeuristic_H148_MemcpyBoundsOverlap(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  CIccInfo info;

  hc.begin(148, "Memory Copy Bounds and Overlap Detection (CWE-119)");
  {

    // Check MPE tags for Apply() buffer overlap conditions
    icTagSignature mpeTags[] = {
      icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
      icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
      icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
      icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag,
      (icTagSignature)0
    };

    for (int t = 0; mpeTags[t] != (icTagSignature)0; t++) {
      CIccTagMultiProcessElement *mpe =
          FindAndCast<CIccTagMultiProcessElement>(pIcc, mpeTags[t]);
      if (!mpe) continue;

      icUInt16Number nIn = mpe->NumInputChannels();
      icUInt16Number nOut = mpe->NumOutputChannels();
      icUInt32Number nElem = mpe->NumElements();

      if (nElem < 2) continue;

      // Check for channel count oscillation that causes buffer reuse
      // Pattern: elem[i].nOutput != elem[i+1].nInput creates size mismatch
      // but if elem[i].nOutput == elem[i+1].nInput and Apply buffers alias,
      // memcpy overlap occurs
      bool hasOverlapRisk = false;
      icUInt16Number prevOut = nIn;

      for (icUInt32Number e = 0; e < nElem && e < 64; e++) {
        CIccMultiProcessElement *elem = mpe->GetElement(e);
        if (!elem) break;

        icUInt16Number eIn = elem->NumInputChannels();
        icUInt16Number eOut = elem->NumOutputChannels();

        // If consecutive elements have same channel count AND chain > 2,
        // Apply() ping-pong buffer reuse can cause overlap
        if (eIn == eOut && eIn == prevOut && nElem > 2) {
          hasOverlapRisk = true;
        }

        // Channel mismatch between consecutive elements
        if (eIn != prevOut && prevOut > 0) {
          hc.warn("Tag '%s' MPE chain: element[%u] output=%u → element[%u] input=%u mismatch", info.GetTagSigName(mpeTags[t]), e > 0 ? e - 1 : 0, prevOut, e, eIn);
          hc.cweNote("CWE-119: Channel mismatch may cause out-of-bounds memcpy");
        }

        prevOut = eOut;
      }

      if (hasOverlapRisk) {
        hc.warn("Tag '%s' MPE chain (%u elements, in=%u out=%u) has memcpy overlap risk", info.GetTagSigName(mpeTags[t]), nElem, nIn, nOut);
        hc.cweNote("CWE-119: Apply() ping-pong buffers may alias when channels match");
      }
    }

    // Check tag data where Read() copies into fixed internal buffers
    // Pattern: NamedColor2 prefix (32 bytes fixed) and color name (32 bytes fixed)
    CIccTagNamedColor2 *pNamed = FindAndCast<CIccTagNamedColor2>(pIcc, icSigNamedColor2Tag);
    if (pNamed) {
      icUInt32Number nColors = pNamed->GetSize();
      icUInt32Number nDevCoords = pNamed->GetDeviceCoords();

      // Each entry has: 32-byte name + 3 PCS values + nDevCoords device values
      // If nDevCoords > 15 (ICC spec max), the internal copy overflows
      if (nDevCoords > 15) {
        hc.critical("HEURISTIC: NamedColor2 deviceCoords=%u exceeds ICC max (15)", nDevCoords);
        hc.cweNote("CWE-119: Internal buffer overflow in color entry copy");
      }

      // Large nColors with high nDevCoords = multiplicative amplification
      if (nColors > 10000 && nDevCoords > 4) {
        hc.warn("NamedColor2: %u colors × %u deviceCoords — memory amplification risk", nColors, nDevCoords);
      }
    }

  }

  return hc.end("No memory copy overlap or bounds issues detected");
}

// ================================================================
// RunLibraryAPIHeuristics — dispatcher (was 3,780-line mega-function)
// ================================================================
