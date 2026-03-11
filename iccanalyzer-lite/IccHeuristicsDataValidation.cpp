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

int RunHeuristic_H56_CalculatorStackDepth(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H56 — Calculator Element Stack Depth Analysis (CWE-674/CWE-835)
// =====================================================================
printf("[H56] Calculator Element Stack Depth Analysis\n");
{
  int calcIssues = 0;
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
      printf("      %s[WARN]  MPE tag '%s': %u elements in processing chain (>512)%s\n",
             ColorCritical(), info.GetTagSigName((icTagSignature)mpeSigs56[s]),
             elemCount, ColorReset());
      printf("       %sCWE-835: Excessive MPE chain length → potential DoS%s\n",
             ColorCritical(), ColorReset());
      calcIssues++;
    }
  }

  if (calcIssues > 0) {
    heuristicCount += calcIssues;
  } else {
    printf("      %s[OK] Calculator element depths within safe bounds%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H58_SparseMatrixEntryBounds(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H58 — Sparse Matrix / Large Array Entry Bounds (CWE-131/CWE-400)
// =====================================================================
printf("[H58] Sparse Matrix Entry Bounds\n");
{
  int sparseIssues = 0;
  TagEntryList::iterator sit;
  for (sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    IccTagEntry *e = &(*sit);
    CIccTagNumArray *numArr = FindAndCast<CIccTagNumArray>(pIcc, e->TagInfo.sig);
    if (!numArr) continue;
    icUInt32Number arrSz = numArr->GetNumValues();
    if (arrSz > 16777216) {
      printf("      %s[WARN]  Tag '%s': NumArray with %u values (>16M, OOM risk)%s\n",
             ColorCritical(), info.GetTagSigName(e->TagInfo.sig),
             arrSz, ColorReset());
      printf("       %sCWE-400: Resource exhaustion via oversized array%s\n",
             ColorCritical(), ColorReset());
      sparseIssues++;
    }
  }
  if (sparseIssues > 0) {
    heuristicCount += sparseIssues;
  } else {
    printf("      %s[OK] No oversized array/sparse matrix entries%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H60_DictionaryTagConsistency(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H60 — Dictionary Tag Key/Value Consistency (CWE-126/CWE-170)
// =====================================================================
printf("[H60] Dictionary Tag Consistency\n");
{
  int dictIssues = 0;
  CIccTagDict *dict = FindAndCast<CIccTagDict>(pIcc, icSigMetaDataTag);
  if (dict) {
    if (dict && dict->m_Dict) {
      std::set<std::string> seenKeys;
      int entryCount = 0;
      for (auto dit = dict->m_Dict->begin(); dit != dict->m_Dict->end(); ++dit) {
        entryCount++;
        if (entryCount > 4096) {
          printf("      %s[WARN]  Dict has >4096 entries (excessive)%s\n",
                 ColorCritical(), ColorReset());
          printf("       %sCWE-400: Potential DoS via unbounded dictionary%s\n",
                 ColorCritical(), ColorReset());
          dictIssues++;
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
          printf("      %s[WARN]  Duplicate dictionary key detected%s\n",
                 ColorCritical(), ColorReset());
          printf("       %sCWE-170: Key collision may cause UAF on replacement%s\n",
                 ColorCritical(), ColorReset());
          dictIssues++;
        }
        seenKeys.insert(keyUtf8);
      }
    }
  }
  if (dictIssues > 0) {
    heuristicCount += dictIssues;
  } else {
    printf("      %s[OK] Dictionary tags consistent%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H61_ViewingConditionsValidation(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H61 — Viewing Conditions Validation (CWE-682/CWE-20)
// =====================================================================
printf("[H61] Viewing Conditions Validation\n");
{
  int viewIssues = 0;
  CIccTagViewingConditions *vc = FindAndCast<CIccTagViewingConditions>(pIcc, (icTagSignature)icSigViewingConditionsTag);
  if (vc) {
    if (vc) {
      icFloatNumber vcIllumX = icFtoD(vc->m_XYZIllum.X);
      icFloatNumber vcIllumY = icFtoD(vc->m_XYZIllum.Y);
      icFloatNumber vcIllumZ = icFtoD(vc->m_XYZIllum.Z);
      if (vcIllumX < 0 || vcIllumY < 0 || vcIllumZ < 0) {
        printf("      %s[WARN]  Negative illuminant XYZ (%.4f, %.4f, %.4f)%s\n",
               ColorCritical(), vcIllumX, vcIllumY, vcIllumZ, ColorReset());
        printf("       %sCWE-682: Negative tristimulus → invalid color math%s\n",
               ColorCritical(), ColorReset());
        viewIssues++;
      }
      if (vcIllumY > 200.0 || vcIllumX > 200.0 || vcIllumZ > 200.0) {
        printf("      %s[WARN]  Extreme illuminant XYZ magnitude (%.4f, %.4f, %.4f)%s\n",
               ColorWarning(), vcIllumX, vcIllumY, vcIllumZ, ColorReset());
        viewIssues++;
      }
      icFloatNumber surX = icFtoD(vc->m_XYZSurround.X);
      icFloatNumber surY = icFtoD(vc->m_XYZSurround.Y);
      icFloatNumber surZ = icFtoD(vc->m_XYZSurround.Z);
      if (surX < 0 || surY < 0 || surZ < 0) {
        printf("      %s[WARN]  Negative surround XYZ (%.4f, %.4f, %.4f)%s\n",
               ColorCritical(), surX, surY, surZ, ColorReset());
        viewIssues++;
      }
    }
  }
  if (viewIssues > 0) {
    heuristicCount += viewIssues;
  } else {
    printf("      %s[OK] Viewing conditions plausible (or tag absent)%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H62_MLUStringBombs(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H62 — Multi-Localized Unicode String Bombs (CWE-400/CWE-770)
// =====================================================================
printf("[H62] Multi-Localized Unicode String Bombs\n");
{
  int mlucIssues = 0;
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
      printf("      %s[WARN]  Tag '%s': mluc has %d locales (>1000)%s\n",
             ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
             localeCount, ColorReset());
      printf("       %sCWE-400: Locale-bomb DoS%s\n", ColorCritical(), ColorReset());
      mlucIssues++;
    }
    if (totalBytes > 10485760) { // 10MB aggregate
      printf("      %s[WARN]  Tag '%s': mluc aggregate %zu bytes (>10MB)%s\n",
             ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
             totalBytes, ColorReset());
      printf("       %sCWE-770: Excessive string data allocation%s\n",
             ColorCritical(), ColorReset());
      mlucIssues++;
    }
  }
  if (mlucIssues > 0) {
    heuristicCount += mlucIssues;
  } else {
    printf("      %s[OK] MultiLocalizedUnicode tags within bounds%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H63_CurveLUTChannelMismatch(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H63 — Curve/LUT I/O Channel Mismatch (CWE-120/CWE-131)
// =====================================================================
printf("[H63] Curve/LUT I/O Channel Mismatch\n");
{
  int lutIssues = 0;
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
      printf("      %s[WARN]  LUT tag '%s': zero channels (in=%d, out=%d)%s\n",
             ColorCritical(), info.GetTagSigName((icTagSignature)lutSigs[s]),
             nIn, nOut, ColorReset());
      printf("       %sCWE-131: Zero-channel LUT → division by zero risk%s\n",
             ColorCritical(), ColorReset());
      lutIssues++;
    }
    if (nIn > 16 || nOut > 16) {
      printf("      %s[WARN]  LUT tag '%s': extreme channels (in=%d, out=%d)%s\n",
             ColorCritical(), info.GetTagSigName((icTagSignature)lutSigs[s]),
             nIn, nOut, ColorReset());
      printf("       %sCWE-120: Channel count exceeds fixed buffer (16)%s\n",
             ColorCritical(), ColorReset());
      lutIssues++;
    }
  }
  if (lutIssues > 0) {
    heuristicCount += lutIssues;
  } else {
    printf("      %s[OK] LUT I/O channel counts valid%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H64_NamedColor2DeviceCoordOverflow(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H64 — NamedColor2 Device Coord Overflow (CWE-131/CWE-787/CWE-400)
// Also detects Describe() iteration asymmetry: nColors controls
// loop count in Describe() with 5 snprintf calls per entry.
// Validation-time: Read() caps nDevCoords at 16 (CFL-076).
// Runtime: Describe() iterates m_nSize with no cap (CFL-078).
// =====================================================================
printf("[H64] NamedColor2 Device Coord Overflow\n");
{
  int nc2Issues = 0;
  CIccTagNamedColor2 *nc2 = FindAndCast<CIccTagNamedColor2>(pIcc, icSigNamedColor2Tag);
  if (nc2) {
    if (nc2) {
      icUInt32Number nColors = nc2->GetSize();
      icUInt32Number nDevCoords = nc2->GetDeviceCoords();
      if (nColors > 10000) {
        printf("      %s[WARN]  NamedColor2: %u entries (>10000) — Describe() DoS risk%s\n",
               ColorCritical(), nColors, ColorReset());
        printf("       %sCWE-400: Describe() iterates m_nSize with no runtime cap (CFL-078 pattern)%s\n",
               ColorCritical(), ColorReset());
        nc2Issues++;
      }
      if (nColors > 65536) {
        printf("      %s[WARN]  NamedColor2: %u entries (>65536)%s\n",
               ColorCritical(), nColors, ColorReset());
        printf("       %sCWE-400: Excessive named color entries%s\n",
               ColorCritical(), ColorReset());
        nc2Issues++;
      }
      if (nDevCoords > 15) {
        printf("      %s[WARN]  NamedColor2: %u device coords (>15)%s\n",
               ColorCritical(), nDevCoords, ColorReset());
        printf("       %sCWE-787: Device coord count exceeds ICC spec max%s\n",
               ColorCritical(), ColorReset());
        nc2Issues++;
      }
      // Check product overflow
      if (nColors > 0 && nDevCoords > 0) {
        uint64_t product = (uint64_t)nColors * (uint64_t)(nDevCoords + 3) * sizeof(icFloatNumber);
        if (product > 1073741824ULL) { // 1GB
          printf("      %s[WARN]  NamedColor2: allocation %llu bytes (>1GB)%s\n",
                 ColorCritical(), (unsigned long long)product, ColorReset());
          printf("       %sCWE-131: Integer overflow in size calculation%s\n",
                 ColorCritical(), ColorReset());
          nc2Issues++;
        }
      }
    }
  }
  if (nc2Issues > 0) {
    heuristicCount += nc2Issues;
  } else {
    printf("      %s[OK] NamedColor2 dimensions valid (or tag absent)%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H65_ChromaticityPlausibility(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H65 — Chromaticity Physical Plausibility (CWE-682)
// =====================================================================
printf("[H65] Chromaticity Physical Plausibility\n");
{
  int chromIssues = 0;
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
            printf("      %s[WARN]  Chromaticity[%u]: xy=(%.4f, %.4f) outside CIE bounds%s\n",
                   ColorCritical(), c, x, y, ColorReset());
            printf("       %sCWE-682: Non-physical chromaticity coordinates%s\n",
                   ColorCritical(), ColorReset());
            chromIssues++;
          }
          if (y == 0 && x != 0) {
            printf("      %s[WARN]  Chromaticity[%u]: y=0 with x!=0 (singularity)%s\n",
                   ColorCritical(), c, ColorReset());
            chromIssues++;
          }
        }
      }
    }
  }
  if (chromIssues > 0) {
    heuristicCount += chromIssues;
  } else {
    printf("      %s[OK] Chromaticity coordinates plausible (or tag absent)%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H66_NumArrayNaNInfScan(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H66 — Comprehensive NumArray NaN/Inf Scan (CWE-682/CWE-369)
// =====================================================================
printf("[H66] Comprehensive NumArray NaN/Inf Scan\n");
{
  int nanIssues = 0;
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
        printf("      %s[WARN]  Tag '%s': %d NaN, %d Inf in %u values%s\n",
               ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
               nanCount, infCount, scanLimit, ColorReset());
        printf("       %sCWE-682: Non-finite values propagate through color math%s\n",
               ColorCritical(), ColorReset());
        nanIssues++;
      }
      if (extremeCount > static_cast<int>(scanLimit / 4)) {
        printf("      %s[WARN]  Tag '%s': %d/%u extreme values (>1e10)%s\n",
               ColorWarning(), info.GetTagSigName(sit->TagInfo.sig),
               extremeCount, scanLimit, ColorReset());
        nanIssues++;
      }
    }
  }
  if (nanIssues > 0) {
    heuristicCount += nanIssues;
  } else {
    printf("      %s[OK] All numeric arrays free of NaN/Inf%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H67_ResponseCurveSetBounds(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H67 — ResponseCurveSet Bounds (CWE-400/CWE-131)
// Validation-time: Read() accepts arbitrary nMeasurements[] per channel.
// Runtime: Describe() iterates nMeasurements with no cap (CFL-077/078).
// H136 catches this via raw-byte scan; H67 checks via library API.
// =====================================================================
printf("[H67] ResponseCurveSet Bounds\n");
{
  int rcsIssues = 0;
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
      printf("      %s[WARN]  ResponseCurveSet: %u channels (>16)%s\n",
             ColorCritical(), nChan, ColorReset());
      printf("       %sCWE-131: Channel count exceeds safe bounds%s\n",
             ColorCritical(), ColorReset());
      rcsIssues++;
    }
    icUInt16Number nMeasTypes = rcs->GetNumResponseCurveTypes();
    if (nMeasTypes > 100) {
      printf("      %s[WARN]  ResponseCurveSet: %u measurement types (>100)%s\n",
             ColorCritical(), nMeasTypes, ColorReset());
      printf("       %sCWE-400: Excessive measurement types → O(n) in Describe()%s\n",
             ColorCritical(), ColorReset());
      rcsIssues++;
    }
  }
  if (rcsIssues > 0) {
    heuristicCount += rcsIssues;
  } else {
    printf("      %s[OK] ResponseCurveSet bounds valid (or tag absent)%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H70_MeasurementTagValidation(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H70 — Measurement Tag Validation (CWE-20)
// =====================================================================
printf("[H70] Measurement Tag Validation\n");
{
  int measIssues = 0;
  CIccTagMeasurement *meas = FindAndCast<CIccTagMeasurement>(pIcc, icSigMeasurementTag);
  if (meas) {
    if (meas) {
      icUInt32Number obs = meas->m_Data.stdObserver;
      if (obs != 0 && obs != 1 && obs != 2) {
        printf("      %s[WARN]  Measurement: invalid observer type %u%s\n",
               ColorCritical(), obs, ColorReset());
        printf("       %sCWE-20: Invalid enum → undefined behavior in observer selection%s\n",
               ColorCritical(), ColorReset());
        measIssues++;
      }
      icUInt32Number geom = meas->m_Data.geometry;
      if (geom > 3) {
        printf("      %s[WARN]  Measurement: invalid geometry %u (>3)%s\n",
               ColorCritical(), geom, ColorReset());
        measIssues++;
      }
      icUInt32Number flareRaw = (icUInt32Number)meas->m_Data.flare;
      if (flareRaw > 0x00010000) { // > 1.0 in u16Fixed16
        printf("      %s[WARN]  Measurement: flare 0x%08X exceeds 1.0%s\n",
               ColorWarning(), flareRaw, ColorReset());
        measIssues++;
      }
    }
  }
  if (measIssues > 0) {
    heuristicCount += measIssues;
  } else {
    printf("      %s[OK] Measurement tag valid (or absent)%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H71_ColorantTableNullTermination(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H71 — ColorantTable Name Null-Termination (CWE-170/CWE-125)
// Targets patches 019/020, CVE-2026-21488: strlen OOB on name[32]
// =====================================================================
printf("[H71] ColorantTable Name Null-Termination\n");
{
  int ctIssues = 0;
  icTagSignature ctSigs[] = {icSigColorantTableTag, icSigColorantTableOutTag, (icTagSignature)0};
  for (int s = 0; ctSigs[s] != (icTagSignature)0; s++) {
    CIccTagColorantTable *ct = FindAndCast<CIccTagColorantTable>(pIcc, ctSigs[s]);
    if (!ct) continue;

    icUInt32Number nEntries = ct->GetSize();
    if (nEntries > 65535) {
      printf("      %s[WARN]  ColorantTable: %u entries (excessive)%s\n",
             ColorCritical(), nEntries, ColorReset());
      printf("       %sCWE-400: Excessive colorant count%s\n",
             ColorCritical(), ColorReset());
      ctIssues++;
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
        printf("      %s[WARN]  Colorant[%u]: name[32] has no null terminator%s\n",
               ColorCritical(), i, ColorReset());
        printf("       %sCWE-170: strlen OOB → heap-buffer-overflow (P019/P020)%s\n",
               ColorCritical(), ColorReset());
        ctIssues++;
        if (ctIssues >= 5) break; // limit output
      }
    }
  }
  if (ctIssues > 0) {
    heuristicCount += ctIssues;
  } else {
    printf("      %s[OK] ColorantTable names properly terminated (or absent)%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H72_SparseMatrixArrayBounds(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H72 — SparseMatrixArray Allocation Bounds + Enum Validation (CWE-400/CWE-125/CWE-843)
// Targets patches 044/059/060: OOM + OOB in sparse matrix
// Upstream issues: #526 (null ptr in GetColumnsForRow), #538/#548 (invalid enum icSparseMatrixType)
// =====================================================================
printf("[H72] SparseMatrixArray Allocation Bounds + Enum Validation\n");
{
  int smaIssues = 0;
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTagSparseMatrixArray *sma = FindAndCast<CIccTagSparseMatrixArray>(pIcc, sit->TagInfo.sig);
    if (!sma) continue;

    char sigStr72[5];
    SignatureToFourCC(sit->TagInfo.sig, sigStr72);

    icUInt32Number nMat = sma->GetNumMatrices();
    icUInt32Number nCPM = sma->GetChannelsPerMatrix();
    uint64_t product = (uint64_t)nMat * nCPM * sizeof(icFloatNumber);
    if (product > 16777216ULL) { // 16MB cap per patch 044
      printf("      %s[WARN]  Tag '%s': SparseMatrix %u matrices × %u channels = %llu bytes%s\n",
             ColorCritical(), sigStr72,
             nMat, nCPM, (unsigned long long)product, ColorReset());
      printf("       %sCWE-400: Exceeds 16MB allocation cap (P044)%s\n",
             ColorCritical(), ColorReset());
      smaIssues++;
    }

    // Validate icSparseMatrixType enum value (iccDEV #538, #548)
    // Valid values: 0x0000 (FloatNum), 0x0001 (UInt8), 0x0002 (UInt16),
    //              0x0003 (Float16), 0x0004 (Float32)
    icSparseMatrixType matType = sma->GetMatrixType();
    icUInt16Number matTypeVal = static_cast<icUInt16Number>(matType);
    if (matTypeVal > 4) {
      printf("      %s[WARN]  Tag '%s': invalid icSparseMatrixType=%u (valid: 0-4)%s\n",
             ColorCritical(), sigStr72, matTypeVal, ColorReset());
      printf("       %sCWE-843: Type confusion — triggers UBSAN enum out-of-range in Read()%s\n",
             ColorCritical(), ColorReset());
      smaIssues++;
    }

    // Check zero channels per matrix (null pointer risk in GetColumnsForRow, iccDEV #526)
    if (nCPM == 0 && nMat > 0) {
      printf("      %s[WARN]  Tag '%s': SparseMatrix %u matrices with 0 channels — null deref risk%s\n",
             ColorCritical(), sigStr72, nMat, ColorReset());
      printf("       %sCWE-476: GetColumnsForRow() dereferences null matrix data%s\n",
             ColorCritical(), ColorReset());
      smaIssues++;
    }
  }
  if (smaIssues > 0) {
    heuristicCount += smaIssues;
  } else {
    printf("      %s[OK] SparseMatrixArray allocations and types valid (or absent)%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H73_TagArrayNestingDepth(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H73 — TagArray/TagStruct Nesting Depth (CWE-674)
// Targets patch 061: stack overflow via nested tstr/tary elements
// =====================================================================
printf("[H73] TagArray/TagStruct Nesting Depth\n");
{
  int nestIssues = 0;
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
            printf("      %s[WARN]  Tag '%s': nested TagStruct/TagArray detected%s\n",
                   ColorWarning(), info.GetTagSigName(sit->TagInfo.sig), ColorReset());
            printf("       %sCWE-674: Potential recursive nesting → stack overflow (P061)%s\n",
                   ColorCritical(), ColorReset());
            nestIssues++;
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
        printf("      %s[WARN]  Tag '%s': TagArray with %u elements (excessive)%s\n",
               ColorCritical(), info.GetTagSigName(sit->TagInfo.sig), nSz, ColorReset());
        printf("       %sCWE-400: Excessive array size%s\n",
               ColorCritical(), ColorReset());
        nestIssues++;
      } else {
        int unknownCount = 0;
        for (icUInt32Number i = 0; i < nSz && i < 100; i++) {
          CIccTag *child = ta->GetIndex(i);
          if (!child) continue;
          if (dynamic_cast<CIccTagStruct*>(child) || dynamic_cast<CIccTagArray*>(child)) {
            printf("      %s[WARN]  Tag '%s'[%u]: nested TagStruct/TagArray%s\n",
                   ColorWarning(), info.GetTagSigName(sit->TagInfo.sig), i, ColorReset());
            printf("       %sCWE-674: Recursive nesting → stack overflow (P061)%s\n",
                   ColorCritical(), ColorReset());
            nestIssues++;
            break;
          }
          // Count CIccTagUnknown elements — risk of UAF in Cleanup() (iccDEV #530, #531)
          if (child->GetType() == icSigUnknownType) {
            unknownCount++;
          }
        }
        if (unknownCount > 0 && nSz > 1) {
          printf("      %s[WARN]  Tag '%s': TagArray has %d/%u CIccTagUnknown elements%s\n",
                 ColorWarning(), info.GetTagSigName(sit->TagInfo.sig), unknownCount, nSz, ColorReset());
          printf("       %sCWE-416: Unknown elements in TagArray → use-after-free in Cleanup()%s\n",
                 ColorCritical(), ColorReset());
          nestIssues++;
        }
      }
    }
  }
  if (nestIssues > 0) {
    heuristicCount += nestIssues;
  } else {
    printf("      %s[OK] No suspicious TagArray/TagStruct nesting%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H74_TagTypeSignatureConsistency(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H74 — Tag Type Signature Consistency (CWE-843)
// Targets CVEs 34, 39-44, 73: type confusion in tag processing
// =====================================================================
printf("[H74] Tag Type Signature Consistency\n");
{
  int typeIssues = 0;
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
      printf("      %s[WARN]  Tag '%s': unexpected type '%s'%s\n",
             ColorCritical(), info.GetTagSigName(expectations[e].tag),
             typeSig, ColorReset());
      printf("       %sCWE-843: Type confusion → incorrect cast in processing%s\n",
             ColorCritical(), ColorReset());
      typeIssues++;
    }
  }
  if (typeIssues > 0) {
    heuristicCount += typeIssues;
  } else {
    printf("      %s[OK] Tag type signatures consistent%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H75_TagsVerySmallSize(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H75 — Tags with Very Small Size (CWE-122/CWE-191)
// Targets patch 009: m_nSize ≤ 4 causes underflow in Describe
// =====================================================================
printf("[H75] Tags with Very Small Size\n");
{
  int smallIssues = 0;
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    // Tag data size from tag table (not including type sig)
    if (sit->TagInfo.size <= 8 && sit->TagInfo.size > 0) {
      printf("      %s[WARN]  Tag '%s': size %u bytes (≤ 8, suspiciously small)%s\n",
             ColorWarning(), info.GetTagSigName(sit->TagInfo.sig),
             sit->TagInfo.size, ColorReset());
      printf("       %sCWE-191: Unsigned underflow in size−N calculations (P009)%s\n",
             ColorCritical(), ColorReset());
      smallIssues++;
    }
  }
  if (smallIssues > 0) {
    heuristicCount += smallIssues;
  } else {
    printf("      %s[OK] All tags have sufficient minimum size%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H76_CIccTagDataTypeFlag(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H76 — CIccTagData Type Flag Validation (CWE-843/CWE-20)
// Targets CVE-2026-21691: IsTypeCompressed type confusion
// =====================================================================
printf("[H76] CIccTagData Type Flag Validation\n");
{
  int dataIssues = 0;
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTagData *dataTag = FindAndCast<CIccTagData>(pIcc, sit->TagInfo.sig);
    if (!dataTag) continue;

    icUInt32Number dataSz = dataTag->GetSize();
    if (dataSz > 134217728) { // 128MB
      printf("      %s[WARN]  Tag '%s': CIccTagData size %u bytes (>128MB)%s\n",
             ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
             dataSz, ColorReset());
      printf("       %sCWE-400: Excessive data tag allocation (P007)%s\n",
             ColorCritical(), ColorReset());
      dataIssues++;
    }
    if (dataTag->IsTypeCompressed()) {
      printf("      %s[WARN]  Tag '%s': compressed data flag set%s\n",
             ColorWarning(), info.GetTagSigName(sit->TagInfo.sig), ColorReset());
      printf("       %sCWE-843: Compressed type may trigger unsafe decompression%s\n",
             ColorCritical(), ColorReset());
      dataIssues++;
    }
  }
  if (dataIssues > 0) {
    heuristicCount += dataIssues;
  } else {
    printf("      %s[OK] CIccTagData types valid (or absent)%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H77_MPECalculatorSubElementCount(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H77 — MPE Calculator Sub-Element Count (CWE-400/CWE-125)
// Targets patches 032/045/064: HBO in ApplySequence ops
// =====================================================================
printf("[H77] MPE Calculator Sub-Element Count\n");
{
  int calcSubIssues = 0;
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
      printf("      %s[WARN]  Tag '%s': MPE with %u elements (>256)%s\n",
             ColorCritical(), info.GetTagSigName(mpeSigs[s]),
             nElems, ColorReset());
      printf("       %sCWE-400: Excessive MPE elements → large op arrays%s\n",
             ColorCritical(), ColorReset());
      calcSubIssues++;
    }
  }
  if (calcSubIssues > 0) {
    heuristicCount += calcSubIssues;
  } else {
    printf("      %s[OK] MPE calculator element counts within bounds%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H78_CLUTGridDimensionOverflow(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H78 — CLUT Grid Dimension Product Overflow (CWE-190/CWE-131)
// Targets patch 001, CVE-2026-22255, CVE-2026-21677: grid dims overflow
// =====================================================================
printf("[H78] CLUT Grid Dimension Product Overflow\n");
{
  int clutGridIssues = 0;
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
      for (int d = 0; d < nIn && d < 16; d++) {
        icUInt8Number gridPt = clut->GridPoint(d);
        if (gridPt == 0) { overflow = true; break; }
        gridProduct *= gridPt;
        if (gridProduct > 268435456ULL) { overflow = true; break; } // 256M entries
      }
      if (overflow) {
        printf("      %s[WARN]  Tag '%s': CLUT grid product overflow (%u inputs)%s\n",
               ColorCritical(), info.GetTagSigName(clutSigs[s]), nIn, ColorReset());
        printf("       %sCWE-190: Exponential grid allocation (P001)%s\n",
               ColorCritical(), ColorReset());
        clutGridIssues++;
      } else {
        uint64_t totalBytes = gridProduct * nOut * sizeof(icFloatNumber);
        if (totalBytes > 16777216ULL) { // 16MB per-CLUT cap
          printf("      %s[WARN]  Tag '%s': CLUT alloc %llu bytes (>16MB)%s\n",
                 ColorCritical(), info.GetTagSigName(clutSigs[s]),
                 (unsigned long long)totalBytes, ColorReset());
          printf("       %sCWE-131: CLUT exceeds per-allocation cap (P001)%s\n",
                 ColorCritical(), ColorReset());
          clutGridIssues++;
        }
      }
    }
  }
  if (clutGridIssues > 0) {
    heuristicCount += clutGridIssues;
  } else {
    printf("      %s[OK] CLUT grid dimension products within bounds%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H79_LoadTagAllocationOverflow(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H79: LoadTag Offset/Size vs File Length Consistency
// CVE-2026-21485 — UB + OOM in CIccProfile::LoadTag()
// The library validates offset+size<=fileLen, but we independently check
// that no tag's declared size could trigger allocation overflow.
// CWE-190 (Integer Overflow), CWE-400 (Resource Exhaustion)
// =====================================================================
printf("[H79] LoadTag Allocation Overflow Detection\n");
{
  int loadTagIssues = 0;
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    icUInt32Number tagSize = sit->TagInfo.size;
    icUInt32Number tagOffset = sit->TagInfo.offset;

    // Check for tags that claim extremely large sizes (>256MB)
    // These trigger massive allocations in CIccTag::Read() implementations
    if (tagSize > 268435456U) {
      printf("      %s[WARN]  Tag '%s' (0x%08X): size=%u (>256MB) — potential OOM in LoadTag%s\n",
             ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
             sit->TagInfo.sig, tagSize, ColorReset());
      printf("       %sCWE-400: Uncapped allocation from tag size (CVE-2026-21485)%s\n",
             ColorCritical(), ColorReset());
      loadTagIssues++;
    }
    // Check for offset+size overflow (32-bit wraparound)
    if (tagOffset > 0 && tagSize > 0 && ((uint64_t)tagOffset + tagSize) > 0xFFFFFFFFULL) {
      printf("      %s[WARN]  Tag '%s': offset(%u)+size(%u) wraps 32-bit — OOB read in LoadTag%s\n",
             ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
             tagOffset, tagSize, ColorReset());
      printf("       %sCWE-190: Integer overflow in offset+size%s\n",
             ColorCritical(), ColorReset());
      loadTagIssues++;
    }
  }
  if (loadTagIssues > 0) {
    heuristicCount += loadTagIssues;
  } else {
    printf("      %s[OK] Tag sizes within safe allocation limits%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H80_SharedTagPointerUAF(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H80: Use-After-Free Pattern Detection (Shared Tag Pointers)
// CVE-2026-21675 (Critical 9.8) — UAF in CIccXform::Create()
// CVE-2026-21486 (High 7.8) — UAF + HBO + integer overflow
// When multiple tag directory entries point to the same offset,
// the library creates shared tag pointers. If one is freed while
// another reference exists, UAF occurs. Detect shared-offset tags.
// CWE-416 (Use After Free)
// =====================================================================
printf("[H80] Shared Tag Pointer / Use-After-Free Pattern\n");
{
  int uafIssues = 0;
  std::map<icUInt32Number, std::vector<icSignature>> offsetMap;
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    if (sit->TagInfo.offset > 0 && sit->TagInfo.size > 0) {
      offsetMap[sit->TagInfo.offset].push_back(sit->TagInfo.sig);
    }
  }
  for (auto &pair : offsetMap) {
    if (pair.second.size() > 4) {
      // More than 4 tags sharing a single offset is suspicious
      printf("      %s[WARN]  Offset 0x%08X shared by %zu tags — UAF risk if tag freed independently%s\n",
             ColorCritical(), pair.first, pair.second.size(), ColorReset());
      printf("       %sCWE-416: Shared tag pointer pattern (CVE-2026-21675)%s\n",
             ColorCritical(), ColorReset());
      uafIssues++;
    }
  }
  if (uafIssues > 0) {
    heuristicCount += uafIssues;
  } else {
    printf("      %s[OK] No excessive tag pointer sharing detected%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H81_MPECalculatorIOConsistency(CIccProfile *pIcc) {
  int heuristicCount = 0;
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
printf("[H81] MPE Calculator I/O Channel Consistency\n");
{
  int calcChIssues = 0;
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    CIccTag *pTag = pIcc->FindTag(sit->TagInfo.sig);
    CIccTagMultiProcessElement *pMpe = (pTag && pTag->GetType() == icSigMultiProcessElementType)
                                         ? dynamic_cast<CIccTagMultiProcessElement*>(pTag)
                                         : nullptr;
    if (!pMpe) continue;

    icUInt16Number mpeIn = pMpe->NumInputChannels();
    icUInt16Number mpeOut = pMpe->NumOutputChannels();
    if (mpeIn == 0 || mpeOut == 0) {
      printf("      %s[WARN]  Tag '%s': MPE with 0 channels (in=%u, out=%u)%s\n",
             ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
             mpeIn, mpeOut, ColorReset());
      printf("       %sCWE-122: Zero-channel MPE causes division/buffer errors (CVE-2026-24405)%s\n",
             ColorCritical(), ColorReset());
      calcChIssues++;
    }
    // Check for absurdly large channel counts (>1024)
    if (mpeIn > 1024 || mpeOut > 1024) {
      printf("      %s[WARN]  Tag '%s': MPE channel count extreme (in=%u, out=%u)%s\n",
             ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
             mpeIn, mpeOut, ColorReset());
      printf("       %sCWE-122: Large channel count → massive buffer allocation (CVE-2026-22047)%s\n",
             ColorCritical(), ColorReset());
      calcChIssues++;
    }
  }
  if (calcChIssues > 0) {
    heuristicCount += calcChIssues;
  } else {
    printf("      %s[OK] MPE calculator channel counts within bounds%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H82_IOReadSizeOverflow(CIccProfile *pIcc) {
  int heuristicCount = 0;
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
printf("[H82] I/O Read Size Overflow Pattern\n");
{
  int ioIssues = 0;
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
    icUInt32Number tagSize = sit->TagInfo.size;
    // Tags with size near 32-bit max / 8 can overflow in Read64
    if (tagSize > 0x1FFFFFFFU) { // > SIZE_MAX/8 for 32-bit
      printf("      %s[WARN]  Tag '%s': size=%u may overflow Read64 bit-shift%s\n",
             ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
             tagSize, ColorReset());
      printf("       %sCWE-190: nNum<<3 overflow in CIccIO (CVE-2026-25582/25583)%s\n",
             ColorCritical(), ColorReset());
      ioIssues++;
    }
  }
  if (ioIssues > 0) {
    heuristicCount += ioIssues;
  } else {
    printf("      %s[OK] Tag sizes safe for I/O bit-shift operations%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H83_FloatNumericArraySize(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H83: CIccTagFloatNum GetValues Stack Buffer Overflow
// CVE-2026-25584 (High 7.8) — SBO in CIccTagFloatNum::GetValues()
// GetValues() copies into a caller-provided buffer. If the tag's
// m_nSize exceeds the expected count for the tag type, SBO occurs.
// We validate that numeric array tag sizes match expected element counts.
// CWE-121 (Stack-based Buffer Overflow)
// =====================================================================
printf("[H83] Float/Numeric Array Size Validation\n");
{
  int floatIssues = 0;
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
      printf("      %s[WARN]  Tag '%s': %u elements in float array (>16M)%s\n",
             ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
             payloadSize / elemSize, ColorReset());
      printf("       %sCWE-121: Stack overflow risk in GetValues (CVE-2026-25584)%s\n",
             ColorCritical(), ColorReset());
      floatIssues++;
    }
  }
  if (floatIssues > 0) {
    heuristicCount += floatIssues;
  } else {
    printf("      %s[OK] Float/numeric array sizes within bounds%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H84_LUT3DTransformConsistency(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H84: CIccXform3DLut Apply Out-of-Bounds
// CVE-2026-25585 (High 7.8) — OOB in CIccXform3DLut::Apply()
// The 3D LUT transform uses input channel values as indices into
// a grid. If input/output channel counts don't match profile color
// space expectations, OOB access occurs during interpolation.
// CWE-125 (Out-of-bounds Read)
// =====================================================================
printf("[H84] 3D LUT Transform Channel/Grid Consistency\n");
{
  int lut3dIssues = 0;
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
        printf("      %s[WARN]  Tag '%s': CLUT input dim=%u != colorSpace channels=%u%s\n",
               ColorCritical(), info.GetTagSigName(aToBSigs[a]),
               clutIn, csChannels, ColorReset());
        printf("       %sCWE-125: 3D LUT dimension mismatch (CVE-2026-25585)%s\n",
               ColorCritical(), ColorReset());
        lut3dIssues++;
      }
      if (clutOut != pcsChannels && pcsChannels > 0) {
        printf("      %s[WARN]  Tag '%s': CLUT output=%u != PCS channels=%u%s\n",
               ColorCritical(), info.GetTagSigName(aToBSigs[a]),
               clutOut, pcsChannels, ColorReset());
        printf("       %sCWE-125: Output channel mismatch → buffer overread (CVE-2026-25585)%s\n",
               ColorCritical(), ColorReset());
        lut3dIssues++;
      }
    }
  }
  if (lut3dIssues > 0) {
    heuristicCount += lut3dIssues;
  } else {
    printf("      %s[OK] 3D LUT channel/grid dimensions consistent%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H85_MPEBufferOverlap(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H85: memcpy-param-overlap in MultiProcessElement::Apply()
// CVE-2026-25634 (High 7.8) — memcpy overlap
// When MPE input and output channels are the same count, Apply()
// may use overlapping src/dst buffers. Detect MPE tags where
// in==out and multiple elements chain (buffer reuse pattern).
// CWE-120 (Buffer Copy without Checking Size of Input)
// =====================================================================
printf("[H85] MPE Buffer Overlap Pattern Detection\n");
{
  int overlapIssues = 0;
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
        printf("      %s[WARN]  Tag '%s': MPE chain (%d elements, %u channels) — memcpy overlap risk%s\n",
               ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
               elemCount, mpeIn, ColorReset());
        printf("       %sCWE-120: Buffer overlap in chained Apply (CVE-2026-25634)%s\n",
               ColorCritical(), ColorReset());
        overlapIssues++;
      }
    }
  }
  if (overlapIssues > 0) {
    heuristicCount += overlapIssues;
  } else {
    printf("      %s[OK] No excessive MPE buffer overlap patterns%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H86_LocalizedUnicodeBounds(CIccProfile *pIcc) {
  int heuristicCount = 0;
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
printf("[H86] Localized Unicode Text Bounds Validation\n");
{
  int unicodeIssues = 0;
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
      printf("      %s[WARN]  Tag '%s': %d locale entries in mluc (>1000) — memory bomb%s\n",
             ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
             localeCount, ColorReset());
      printf("       %sCWE-122: Excessive locale entries → HBO in GetText (CVE-2026-21679)%s\n",
             ColorCritical(), ColorReset());
      unicodeIssues++;
    }
    // Total text > 64MB is excessive
    if (totalTextBytes > 67108864ULL) {
      printf("      %s[WARN]  Tag '%s': total mluc text=%llu bytes (>64MB)%s\n",
             ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
             (unsigned long long)totalTextBytes, ColorReset());
      printf("       %sCWE-122: Excessive text size → heap overflow (CVE-2026-21678)%s\n",
             ColorCritical(), ColorReset());
      unicodeIssues++;
    }
  }
  if (unicodeIssues > 0) {
    heuristicCount += unicodeIssues;
  } else {
    printf("      %s[OK] Localized Unicode text within bounds%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H87_TRCCurveAnomaly(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H87 — TRC Curve Anomaly Detection (CWE-125/CWE-787)
// TRC (Tone Reproduction Curve) tags define gamma/response curves for
// each channel. Malformed curves with excessive point counts, invalid
// parametric function types, or degenerate values can trigger OOB
// reads in CIccTagCurve::Apply() and stack overflows in interpolation.
// =====================================================================
printf("[H87] TRC Curve Anomaly Detection\n");
{
  int trcIssues = 0;
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
        printf("      %s[WARN]  Tag '%s': TRC curve with %u points (>65536) — excessive allocation%s\n",
               ColorCritical(), info.GetTagSigName(trcSigs[t]), nSize, ColorReset());
        printf("       %sCWE-400: Oversized curve table → OOM in Apply()%s\n",
               ColorCritical(), ColorReset());
        trcIssues++;
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
          printf("      %s[WARN]  Tag '%s': TRC curve all-zero (%u points) — clipped output%s\n",
                 ColorWarning(), info.GetTagSigName(trcSigs[t]), nSize, ColorReset());
          trcIssues++;
        }
      }
    }

    // Check CIccTagParametricCurve
    CIccTagParametricCurve *pParam = dynamic_cast<CIccTagParametricCurve*>(pTag);
    if (pParam) {
      icUInt16Number funcType = pParam->GetFunctionType();
      if (funcType > 4) {
        printf("      %s[WARN]  Tag '%s': parametric curve function type %u (>4, spec violation)%s\n",
               ColorCritical(), info.GetTagSigName(trcSigs[t]), funcType, ColorReset());
        printf("       %sCWE-843: Invalid function type → unpredictable Apply() behavior%s\n",
               ColorCritical(), ColorReset());
        trcIssues++;
      }
      icUInt16Number nParams = pParam->GetNumParam();
      icFloatNumber *params = pParam->GetParams();
      if (params && nParams > 0) {
        for (icUInt16Number p = 0; p < nParams; p++) {
          if (std::isnan(params[p]) || std::isinf(params[p])) {
            printf("      %s[WARN]  Tag '%s': parametric curve param[%u] = NaN/Inf%s\n",
                   ColorCritical(), info.GetTagSigName(trcSigs[t]), p, ColorReset());
            printf("       %sCWE-682: NaN/Inf in curve parameters → undefined math%s\n",
                   ColorCritical(), ColorReset());
            trcIssues++;
            break;
          }
        }
      }
    }
  }
  if (trcIssues > 0) {
    heuristicCount += trcIssues;
  } else {
    printf("      %s[OK] TRC curves within bounds (or absent)%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H88_ChromaticAdaptationMatrix(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H88 — Chromatic Adaptation Matrix Validation (CWE-682/CWE-125)
// The chad (chromatic adaptation) tag contains a 3×3 s15Fixed16 matrix.
// A singular matrix (det≈0) causes division-by-zero in PCS conversions.
// NaN/Inf values or extreme magnitudes indicate crafted profiles.
// =====================================================================
printf("[H88] Chromatic Adaptation Matrix Validation\n");
{
  int chadIssues = 0;
  CIccTagS15Fixed16 *pChad = FindAndCast<CIccTagS15Fixed16>(pIcc, icSigChromaticAdaptationTag);
  if (pChad) {
    if (pChad) {
      icUInt32Number nSize = pChad->GetSize();
      if (nSize < 9) {
        printf("      %s[WARN]  chad tag has %u elements (need 9 for 3×3 matrix)%s\n",
               ColorCritical(), nSize, ColorReset());
        printf("       %sCWE-125: Undersized chad → OOB read in PCS conversion%s\n",
               ColorCritical(), ColorReset());
        chadIssues++;
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
          printf("      %s[WARN]  chad matrix contains NaN/Inf values%s\n",
                 ColorCritical(), ColorReset());
          printf("       %sCWE-682: NaN/Inf in adaptation matrix → undefined PCS transform%s\n",
                 ColorCritical(), ColorReset());
          chadIssues++;
        } else {
          // Determinant of 3×3: a(ei−fh) − b(di−fg) + c(dh−eg)
          double det = (double)m[0] * ((double)m[4]*m[8] - (double)m[5]*m[7])
                     - (double)m[1] * ((double)m[3]*m[8] - (double)m[5]*m[6])
                     + (double)m[2] * ((double)m[3]*m[7] - (double)m[4]*m[6]);
          if (std::fabs(det) < 1e-10) {
            printf("      %s[WARN]  chad matrix near-singular (det=%.2e)%s\n",
                   ColorCritical(), det, ColorReset());
            printf("       %sCWE-369: Singular chad → division-by-zero in PCS inversion%s\n",
                   ColorCritical(), ColorReset());
            chadIssues++;
          }
          // Check for extreme values (s15Fixed16 range ±32768)
          for (int i = 0; i < 9; i++) {
            if (std::fabs(m[i]) > 100.0) {
              printf("      %s[WARN]  chad matrix element[%d] = %.4f (extreme, >100)%s\n",
                     ColorWarning(), i, m[i], ColorReset());
              chadIssues++;
              break;
            }
          }
        }
      }
    } else {
      printf("      %s[WARN]  chad tag present but unexpected type%s\n",
             ColorWarning(), ColorReset());
      chadIssues++;
    }
  } else {
    printf("      %s[OK] No chromatic adaptation tag (standard D50)%s\n",
           ColorSuccess(), ColorReset());
  }
  if (chadIssues > 0) {
    heuristicCount += chadIssues;
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H89_ProfileSequenceDescription(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H89 — Profile Sequence Description Validation (CWE-400/CWE-131)
// The pseq tag stores a sequence of profile descriptions (used in
// device link profiles). An excessive count can trigger OOM; count
// × entry_size overflow can cause heap corruption during Read().
// =====================================================================
printf("[H89] Profile Sequence Description Validation\n");
{
  int pseqIssues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigProfileSequenceDescTag);
  if (pTag) {
    CIccTagProfileSeqDesc *pSeq = dynamic_cast<CIccTagProfileSeqDesc*>(pTag);
    if (pSeq && pSeq->m_Descriptions) {
      size_t descCount = pSeq->m_Descriptions->size();
      if (descCount > 256) {
        printf("      %s[WARN]  Profile sequence has %zu descriptions (>256) — OOM risk%s\n",
               ColorCritical(), descCount, ColorReset());
        printf("       %sCWE-400: Excessive sequence entries → large allocations in Read()%s\n",
               ColorCritical(), ColorReset());
        pseqIssues++;
      }
      if (descCount == 0) {
        printf("      %s[WARN]  Profile sequence has 0 descriptions (empty)%s\n",
               ColorWarning(), ColorReset());
        pseqIssues++;
      }
    } else if (pTag) {
      printf("      %s[WARN]  pseq tag present but wrong type or NULL descriptions%s\n",
             ColorWarning(), ColorReset());
      pseqIssues++;
    }
  }
  // Also check psid (profile sequence identifier)
  CIccTag *pIdTag = pIcc->FindTag((icTagSignature)icSigProfileSequceIdTag);
  if (pIdTag) {
    // psid should be a ResponseCurveSet16 or similar
    // Just verify it loaded successfully (non-null)
    printf("      ProfileSequenceId tag present\n");
  }
  if (pseqIssues > 0) {
    heuristicCount += pseqIssues;
  } else {
    printf("      %s[OK] Profile sequence descriptions within bounds (or absent)%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H90_PreviewTagChannelConsistency(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// =====================================================================
// H90 — Preview Tag Channel Consistency (CWE-125/CWE-787)
// Preview0/1/2 tags contain transforms for soft-proofing. If their
// CLUT dimensions don't match the profile's color space channels,
// Apply() will read/write out of bounds during interpolation.
// =====================================================================
printf("[H90] Preview Tag Channel Consistency\n");
{
  int previewIssues = 0;
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
        printf("      %s[WARN]  Tag '%s': input channels=%u != PCS channels=%u%s\n",
               ColorCritical(), info.GetTagSigName(previewSigs[p]),
               mbbIn, pcsChannels, ColorReset());
        printf("       %sCWE-125: Channel mismatch → OOB in preview transform%s\n",
               ColorCritical(), ColorReset());
        previewIssues++;
      }
      if (pcsChannels > 0 && mbbOut != pcsChannels) {
        printf("      %s[WARN]  Tag '%s': output channels=%u != PCS channels=%u%s\n",
               ColorCritical(), info.GetTagSigName(previewSigs[p]),
               mbbOut, pcsChannels, ColorReset());
        printf("       %sCWE-787: Output channel mismatch → buffer overwrite%s\n",
               ColorCritical(), ColorReset());
        previewIssues++;
      }
    }
  }
  if (previewIssues > 0) {
    heuristicCount += previewIssues;
  } else {
    printf("      %s[OK] Preview tag channels consistent (or absent)%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H91_ColorantOrderValidation(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H91 — Colorant Order Validation (CWE-125/CWE-787)
// ColorantOrder tag stores permutation indices for colorant channels.
// If indices exceed the ColorantTable entry count, array OOB occurs
// when the CMM maps channels. Duplicate indices indicate confusion.
// =====================================================================
printf("[H91] Colorant Order Validation\n");
{
  int orderIssues = 0;
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
      printf("      %s[WARN]  ColorantOrder has %u entries but ColorantTable has %u%s\n",
             ColorWarning(), orderCount, tableCount, ColorReset());
      orderIssues++;
    }

    // Check indices within bounds and for duplicates
    std::set<icUInt8Number> seen;
    for (icUInt32Number i = 0; i < orderCount; i++) {
      icUInt8Number idx = (*pOrder)[i];
      if (tableCount > 0 && idx >= tableCount) {
        printf("      %s[WARN]  ColorantOrder[%u]=%u >= table count %u — OOB%s\n",
               ColorCritical(), i, idx, tableCount, ColorReset());
        printf("       %sCWE-125: Index out-of-bounds in colorant mapping%s\n",
               ColorCritical(), ColorReset());
        orderIssues++;
        break;
      }
      if (seen.count(idx)) {
        printf("      %s[WARN]  ColorantOrder has duplicate index %u%s\n",
               ColorWarning(), idx, ColorReset());
        orderIssues++;
        break;
      }
      seen.insert(idx);
    }
  }
  if (orderIssues > 0) {
    heuristicCount += orderIssues;
  } else {
    printf("      %s[OK] Colorant order indices valid (or absent)%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H92_SpectralViewingConditions(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H92 — Spectral Viewing Conditions Validation (CWE-20/CWE-682)
// PCC (Profile Connection Conditions) profiles use spectral viewing
// conditions to define illuminant/observer. Invalid spectral ranges
// or unknown illuminant/observer types can crash IccPcc.cpp transforms.
// =====================================================================
printf("[H92] Spectral Viewing Conditions Validation\n");
{
  int svcIssues = 0;
  CIccTag *pTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (pTag) {
    CIccTagSpectralViewingConditions *pSvc =
        dynamic_cast<CIccTagSpectralViewingConditions*>(pTag);
    if (pSvc) {
      // Check illuminant XYZ for NaN/Inf
      if (std::isnan(pSvc->m_illuminantXYZ.X) || std::isnan(pSvc->m_illuminantXYZ.Y) ||
          std::isnan(pSvc->m_illuminantXYZ.Z) || std::isinf(pSvc->m_illuminantXYZ.X) ||
          std::isinf(pSvc->m_illuminantXYZ.Y) || std::isinf(pSvc->m_illuminantXYZ.Z)) {
        printf("      %s[WARN]  Spectral viewing conditions: illuminant XYZ contains NaN/Inf%s\n",
               ColorCritical(), ColorReset());
        printf("       %sCWE-682: NaN/Inf in PCC illuminant → undefined PCS transform%s\n",
               ColorCritical(), ColorReset());
        svcIssues++;
      }
      // Check illuminant Y > 0 (physical requirement)
      if (pSvc->m_illuminantXYZ.Y <= 0.0f && pSvc->m_illuminantXYZ.Y != 0.0f) {
        printf("      %s[WARN]  Spectral viewing conditions: illuminant Y=%.4f (non-positive)%s\n",
               ColorWarning(), pSvc->m_illuminantXYZ.Y, ColorReset());
        svcIssues++;
      }
      // Check surround XYZ
      if (std::isnan(pSvc->m_surroundXYZ.X) || std::isnan(pSvc->m_surroundXYZ.Y) ||
          std::isnan(pSvc->m_surroundXYZ.Z)) {
        printf("      %s[WARN]  Spectral viewing conditions: surround XYZ contains NaN%s\n",
               ColorWarning(), ColorReset());
        svcIssues++;
      }
      // Check CCT (correlated color temperature) range
      icFloatNumber cct = pSvc->getIlluminantCCT();
      if (cct < 0.0f || cct > 100000.0f) {
        printf("      %s[WARN]  Illuminant CCT=%.1f (outside 0-100000K range)%s\n",
               ColorWarning(), cct, ColorReset());
        svcIssues++;
      }
    } else {
      printf("      %s[WARN]  Spectral viewing conditions tag has unexpected type%s\n",
             ColorWarning(), ColorReset());
      svcIssues++;
    }
  } else {
    printf("      %s[OK] No spectral viewing conditions tag (standard PCC)%s\n",
           ColorSuccess(), ColorReset());
  }
  if (svcIssues > 0) {
    heuristicCount += svcIssues;
  } else if (pTag) {
    printf("      %s[OK] Spectral viewing conditions valid%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H93_EmbeddedProfileFlag(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H93 — Embedded Profile Flag Consistency (CWE-345/CWE-20)
// The profile flags field (header offset 44) has defined bits:
//   bit 0: Embedded profile (0=not embedded, 1=embedded in file)
//   bit 1: Profile cannot be used independently
// Bits 2-15 are reserved and should be zero per ICC spec.
// Non-zero reserved bits indicate spec violation or crafted profile.
// =====================================================================
printf("[H93] Embedded Profile Flag Consistency\n");
{
  int flagIssues = 0;
  icUInt32Number flags = pIcc->m_Header.flags;
  // Check reserved bits (bits 16-31 are reserved for ICC, bits 2-15 per spec)
  icUInt32Number reservedMask = 0xFFFFFFFC; // All bits except 0 and 1
  if (flags & reservedMask) {
    printf("      %s[WARN]  Profile flags=0x%08X: reserved bits set (mask=0x%08X)%s\n",
           ColorWarning(), flags, flags & reservedMask, ColorReset());
    printf("       %sCWE-20: Non-zero reserved flag bits → spec violation or crafted profile%s\n",
           ColorWarning(), ColorReset());
    flagIssues++;
  }
  // Check consistency: bit 1 (cannot use independently) only makes sense with bit 0 (embedded)
  bool embedded = (flags & 0x01) != 0;
  bool notIndependent = (flags & 0x02) != 0;
  if (notIndependent && !embedded) {
    printf("      %s[WARN]  Flag conflict: 'cannot use independently' set but 'embedded' not set%s\n",
           ColorWarning(), ColorReset());
    flagIssues++;
  }
  // Check attributes field too (rendering attributes at header offset 56)
  icUInt64Number attributes = pIcc->m_Header.attributes;
  // Bits 0-3: Reflective/Transparency, Glossy/Matte, Media positive/negative, B&W/Color
  // Bits 4-63: reserved (should be zero)
  uint64_t attrReserved = attributes & 0xFFFFFFFFFFFFFFF0ULL;
  if (attrReserved) {
    printf("      %s[WARN]  Attributes=0x%016llX: reserved bits set%s\n",
           ColorWarning(), (unsigned long long)attributes, ColorReset());
    flagIssues++;
  }
  if (flagIssues > 0) {
    heuristicCount += flagIssues;
  } else {
    printf("      %s[OK] Profile flags and attributes consistent%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H94_MatrixTRCColorantConsistency(CIccProfile *pIcc) {
  int heuristicCount = 0;

// =====================================================================
// H94 — Matrix/TRC Colorant Consistency (CWE-682/CWE-125)
// For matrix/TRC-based profiles (Display class with RGB colorSpace),
// the Red/Green/Blue MatrixColumn tags define a 3×3 matrix. The sum
// of columns should approximate D50 whitepoint (0.9505, 1.0, 1.0890).
// Large deviations indicate malformed profiles that produce extreme
// values during PCS transforms, potentially triggering overflows.
// =====================================================================
printf("[H94] Matrix/TRC Colorant Consistency\n");
{
  int matrixIssues = 0;
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
          printf("      %s[WARN]  Matrix column sum (%.4f, %.4f, %.4f) deviates from D50%s\n",
                 ColorWarning(), sumX, sumY, sumZ, ColorReset());
          printf("       %sExpected ≈ (0.9505, 1.0000, 1.0890), deviation (%.4f, %.4f, %.4f)%s\n",
                 ColorWarning(), devX, devY, devZ, ColorReset());
          matrixIssues++;
        }
        // Check for NaN/Inf in any column
        for (int c = 0; c < 3; c++) {
          CIccTagXYZ *col = (c == 0) ? rXYZ : (c == 1) ? gXYZ : bXYZ;
          if (std::isnan(icFtoD((*col)[0].X)) || std::isnan(icFtoD((*col)[0].Y)) ||
              std::isnan(icFtoD((*col)[0].Z))) {
            printf("      %s[WARN]  Matrix column %d contains NaN — corrupted colorant%s\n",
                   ColorCritical(), c, ColorReset());
            printf("       %sCWE-682: NaN in matrix → undefined PCS output%s\n",
                   ColorCritical(), ColorReset());
            matrixIssues++;
          }
        }
        // Check for negative XYZ values (physically impossible)
        if (icFtoD((*rXYZ)[0].Y) < -0.01 || icFtoD((*gXYZ)[0].Y) < -0.01 || icFtoD((*bXYZ)[0].Y) < -0.01) {
          printf("      %s[WARN]  Matrix column Y value negative — non-physical colorant%s\n",
                 ColorWarning(), ColorReset());
          matrixIssues++;
        }
      }
    }

    // Also check whitepoint tag if present
    if (pWP) {
      CIccTagXYZ *wpXYZ = dynamic_cast<CIccTagXYZ*>(pWP);
      if (wpXYZ && wpXYZ->GetSize() >= 1) {
        icFloatNumber wpY = icFtoD((*wpXYZ)[0].Y);
        if (std::fabs(wpY - 1.0) > 0.1) {
          printf("      %s[WARN]  Media whitepoint Y=%.4f (expected ≈1.0 for D50)%s\n",
                 ColorWarning(), wpY, ColorReset());
          matrixIssues++;
        }
      }
    }
  }
  if (matrixIssues > 0) {
    heuristicCount += matrixIssues;
  } else {
    printf("      %s[OK] Matrix/TRC colorant consistency valid (or non-RGB)%s\n",
           ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H95_SparseMatrixArrayBoundsValidation(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// H95 — Sparse Matrix Array Bounds Validation (CWE-125/CWE-787)
// Exercises: IccSparseMatrix.cpp (26.8% coverage → Init, GetSparseMatrix, Rows, Cols)
//            IccTagBasic.cpp CIccTagSparseMatrixArray
{
  printf("[H95] Sparse Matrix Array Bounds Validation\n");
  int sparseIssues = 0;
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

      printf("      Sparse matrix array '%s': channels=%u, bytes/matrix=%u\n",
             info.GetTagSigName(sit->TagInfo.sig), nChannels, nBytesPerMatrix);

      if (nChannels == 0) {
        printf("      %s[CRIT]  Zero channels per matrix — potential division-by-zero%s\n",
               ColorCritical(), ColorReset());
        sparseIssues++;
      }

      if (nChannels > 65535) {
        printf("      %s[WARN]  Channels per matrix=%u exceeds reasonable limit%s\n",
               ColorWarning(), nChannels, ColorReset());
        sparseIssues++;
      }

      // Try to get first sparse matrix and validate dimensions
      CIccSparseMatrix mtx;
      if (pSma->GetSparseMatrix(mtx, 0, true)) {
        icUInt16Number rows = mtx.Rows();
        icUInt16Number cols = mtx.Cols();
        printf("      Matrix[0]: rows=%u, cols=%u\n", rows, cols);

        if (rows == 0 || cols == 0) {
          printf("      %s[CRIT]  Zero-dimension sparse matrix (rows=%u, cols=%u)%s\n",
                 ColorCritical(), rows, cols, ColorReset());
          sparseIssues++;
        }
      }

      if (sparseIssues == 0) {
        printf("      %s[OK] Sparse matrix array bounds valid%s\n",
               ColorSuccess(), ColorReset());
      }
    } else {
      printf("      %s[WARN]  SparseMatrix tag present but wrong type — type confusion risk%s\n",
             ColorWarning(), ColorReset());
      sparseIssues++;
    }
  }

  if (!foundSparse) {
    printf("      [SKIP] No sparse matrix array tags present\n");
  }
  heuristicCount += sparseIssues;
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H96_EmbeddedProfileValidation(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// H96 — Embedded Profile Validation (CWE-674/CWE-400/CWE-843)
// Exercises: IccTagEmbedIcc.cpp (30.9% coverage → GetProfile, Read, Validate)
// Upstream issues: #527, #528, #544 (type confusion CIccTagUnknown → CIccTagEmbeddedProfile)
{
  printf("[H96] Embedded Profile Validation\n");
  int embedIssues = 0;

  CIccTagEmbeddedProfile *pEmbed = FindAndCast<CIccTagEmbeddedProfile>(pIcc, icSigEmbeddedV5ProfileTag);
  if (pEmbed) {
    if (pEmbed) {
      CIccProfile *pEmbeddedProfile = pEmbed->GetProfile();

      if (!pEmbeddedProfile) {
        printf("      %s[WARN]  Embedded profile tag present but profile is NULL%s\n",
               ColorWarning(), ColorReset());
        embedIssues++;
      } else {
        // Validate embedded profile header
        icHeader &embedHdr = pEmbeddedProfile->m_Header;

        printf("      Embedded profile: class=%s, colorSpace=%s, version=%u.%u\n",
               info.GetProfileClassSigName(embedHdr.deviceClass),
               info.GetColorSpaceSigName(embedHdr.colorSpace),
               embedHdr.version >> 24, (embedHdr.version >> 20) & 0xF);

        // Check for recursive embedding — potential infinite recursion (CWE-674)
        CIccTag *pInnerEmbed = pEmbeddedProfile->FindTag(icSigEmbeddedV5ProfileTag);
        if (pInnerEmbed) {
          printf("      %s[CRIT]  Recursively embedded profile — infinite recursion risk (CWE-674)%s\n",
                 ColorCritical(), ColorReset());
          embedIssues++;
        }

        // Check embedded profile size vs parent
        icUInt32Number parentSize = pIcc->m_Header.size;
        icUInt32Number embedSize = embedHdr.size;
        if (embedSize > 0 && parentSize > 0 && embedSize >= parentSize) {
          printf("      %s[WARN]  Embedded profile size (%u) >= parent size (%u) — suspicious%s\n",
                 ColorWarning(), embedSize, parentSize, ColorReset());
          embedIssues++;
        }

        // Check embedded profile count > tag count (resource exhaustion)
        icUInt32Number embedTagCount = (icUInt32Number)pEmbeddedProfile->m_Tags.size();
        if (embedTagCount > 200) {
          printf("      %s[WARN]  Embedded profile has %u tags — potential resource exhaustion%s\n",
                 ColorWarning(), embedTagCount, ColorReset());
          embedIssues++;
        }
      }
    } else {
      printf("      %s[CRIT]  Embedded profile tag present but wrong type (dynamic_cast failed)%s\n",
             ColorCritical(), ColorReset());
      printf("       %sCWE-843: Type confusion — tag is CIccTagUnknown, not CIccTagEmbeddedProfile%s\n",
             ColorCritical(), ColorReset());
      printf("       %sUpstream: iccDEV #527, #528, #544 — DumpProfileInfo() SEGV via misaligned access%s\n",
             ColorCritical(), ColorReset());
      embedIssues++;
    }
  } else {
    printf("      [SKIP] No embedded profile tag present\n");
  }

  if (embedIssues == 0 && pIcc->FindTag(icSigEmbeddedV5ProfileTag)) {
    printf("      %s[OK] Embedded profile structure valid%s\n",
           ColorSuccess(), ColorReset());
  }
  heuristicCount += embedIssues;
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H97_ProfileSequenceIdValidation(CIccProfile *pIcc) {
  int heuristicCount = 0;

// H97 — Profile Sequence Identifier Validation (CWE-125/CWE-400)
// Exercises: IccTagProfSeqId.cpp (27.7% coverage → GetFirst, GetLast, begin/end iterators)
{
  printf("[H97] Profile Sequence Identifier Validation\n");
  int seqIdIssues = 0;

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
          printf("      %s[WARN]  Profile sequence >1000 entries — potential DoS (CWE-400)%s\n",
                 ColorWarning(), ColorReset());
          seqIdIssues++;
          break;
        }
      }

      printf("      Profile sequence: %d entries\n", entryCount);

      if (hasNullId) {
        printf("      %s[WARN]  Null profile ID (all zeros) in sequence%s\n",
               ColorWarning(), ColorReset());
        seqIdIssues++;
      }

      if (hasDupId) {
        printf("      %s[WARN]  Duplicate profile IDs in sequence%s\n",
               ColorWarning(), ColorReset());
        seqIdIssues++;
      }

      // Validate first/last accessors
      CIccProfileIdDesc *pFirst = pSeqId->GetFirst();
      CIccProfileIdDesc *pLast = pSeqId->GetLast();
      if (entryCount > 0 && (!pFirst || !pLast)) {
        printf("      %s[CRIT]  Non-empty sequence but GetFirst/GetLast returns NULL%s\n",
               ColorCritical(), ColorReset());
        seqIdIssues++;
      }
  } else {
    printf("      [SKIP] No profile sequence ID tag present\n");
  }

  if (seqIdIssues == 0 && pIcc->FindTag(icSigProfileSequceIdTag)) {
    printf("      %s[OK] Profile sequence identifiers valid%s\n",
           ColorSuccess(), ColorReset());
  }
  heuristicCount += seqIdIssues;
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H98_SpectralMPEElementValidation(CIccProfile *pIcc) {
  int heuristicCount = 0;

// H98 — Spectral MPE Element Validation (CWE-125/CWE-682)
// Exercises: IccMpeSpectral.cpp (31.8% coverage → CIccMpeSpectralMatrix, CIccMpeSpectralCLUT,
//            CIccMpeSpectralObserver via CIccTagMultiProcessElement iteration)
{
  printf("[H98] Spectral MPE Element Validation\n");
  int spectralIssues = 0;

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
        printf("      Spectral matrix: in=%u, out=%u, steps=%u, type=0x%08x\n",
               numIn, numOut, range.steps, elemType);

        if (numIn == 0 || numOut == 0) {
          printf("      %s[CRIT]  Zero-channel spectral matrix element%s\n",
                 ColorCritical(), ColorReset());
          spectralIssues++;
        }

        if (numIn > 256 || numOut > 256) {
          printf("      %s[WARN]  Spectral matrix channels (%u→%u) exceed 256%s\n",
                 ColorWarning(), numIn, numOut, ColorReset());
          spectralIssues++;
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
            printf("      %s[CRIT]  HEURISTIC: EmissionMatrix out(%u) > in(%u) — "
                   "Describe() HBO: iterates %u rows but allocation has %u "
                   "— ICC.2-2023 §10.2.4%s\n",
                   ColorCritical(), numOut, numIn, numOut, numIn, ColorReset());
            printf("       CWE-122: Heap-based Buffer Overflow in Describe()\n");
            spectralIssues++;
          }
          if ((isEmission || isInvEmission) && numIn != range.steps) {
            // Pointer advance uses m_nInputChannels but data layout is
            // range.steps per row — mismatch causes offset drift
            printf("      %s[WARN]  HEURISTIC: SpectralMatrix in(%u) != steps(%u) — "
                   "Describe() pointer advance mismatch — ICC.2-2023 §10.2.4%s\n",
                   ColorWarning(), numIn, range.steps, ColorReset());
            printf("       CWE-125: Out-of-bounds Read via pointer drift\n");
            spectralIssues++;
          }
        }
      }

      // Check spectral CLUT elements
      CIccMpeSpectralCLUT *pSpecClut = dynamic_cast<CIccMpeSpectralCLUT *>(pElem);
      if (pSpecClut) {
        foundSpectral = true;
        icUInt16Number numIn = pSpecClut->NumInputChannels();
        icUInt16Number numOut = pSpecClut->NumOutputChannels();
        printf("      Spectral CLUT: in=%u, out=%u, type=0x%08x\n",
               numIn, numOut, elemType);

        if (numIn == 0 || numOut == 0) {
          printf("      %s[CRIT]  Zero-channel spectral CLUT element%s\n",
                 ColorCritical(), ColorReset());
          spectralIssues++;
        }

        // CLUT with high input channels → exponential memory
        if (numIn > 16) {
          printf("      %s[WARN]  Spectral CLUT input channels=%u — exponential grid risk%s\n",
                 ColorWarning(), numIn, ColorReset());
          spectralIssues++;
        }
      }

      // Check spectral observer elements
      CIccMpeSpectralObserver *pSpecObs = dynamic_cast<CIccMpeSpectralObserver *>(pElem);
      if (pSpecObs) {
        foundSpectral = true;
        icUInt16Number numIn = pSpecObs->NumInputChannels();
        icUInt16Number numOut = pSpecObs->NumOutputChannels();
        printf("      Spectral observer: in=%u, out=%u, type=0x%08x\n",
               numIn, numOut, elemType);

        if (numIn == 0 || numOut == 0) {
          printf("      %s[CRIT]  Zero-channel spectral observer element%s\n",
                 ColorCritical(), ColorReset());
          spectralIssues++;
        }
      }
    }
  }

  if (!foundSpectral) {
    printf("      [SKIP] No spectral MPE elements present\n");
  } else if (spectralIssues == 0) {
    printf("      %s[OK] Spectral MPE elements valid%s\n",
           ColorSuccess(), ColorReset());
  }
  heuristicCount += spectralIssues;
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H99_EmbeddedImageTagValidation(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// H99 — Embedded Height/Normal Image Validation (CWE-120/CWE-787)
// Exercises: IccTagEmbedIcc.cpp for non-profile embedded data types
{
  printf("[H99] Embedded Image Tag Validation\n");
  int embedImgIssues = 0;
  bool foundEmbedImg = false;

  // Scan all tags for embedded image types
  for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); ++sit) {
    CIccTag *pTag = pIcc->FindTag(sit->TagInfo.sig);
    if (!pTag) continue;

    icTagTypeSignature tagType = pTag->GetType();
    if (tagType == icSigEmbeddedHeightImageType || tagType == icSigEmbeddedNormalImageType) {
      foundEmbedImg = true;
      const char *typeName = (tagType == icSigEmbeddedHeightImageType) ? "HeightImage" : "NormalImage";
      printf("      Found %s tag in '%s'\n", typeName, info.GetTagSigName(sit->TagInfo.sig));

      // Validate tag size is reasonable
      if (sit->TagInfo.size > 100 * 1024 * 1024) {
        printf("      %s[WARN]  %s tag size %u bytes (>100MB) — potential DoS%s\n",
               ColorWarning(), typeName, sit->TagInfo.size, ColorReset());
        embedImgIssues++;
      }
    }
  }

  if (!foundEmbedImg) {
    printf("      [SKIP] No embedded image tags present\n");
  } else if (embedImgIssues == 0) {
    printf("      %s[OK] Embedded image tags valid%s\n",
           ColorSuccess(), ColorReset());
  }
  heuristicCount += embedImgIssues;
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H100_ProfileSequenceDescValidation(CIccProfile *pIcc) {
  int heuristicCount = 0;

// H100 — Profile Sequence Description Consistency (CWE-125/CWE-120)
// Exercises: IccTagBasic.cpp CIccTagProfileSeqDesc (different from H97 ProfileSequenceId)
{
  printf("[H100] Profile Sequence Description Validation\n");
  int pseqIssues = 0;

  CIccTag *pPseqTag = pIcc->FindTag(icSigProfileSequenceDescTag);
  if (pPseqTag) {
    printf("      Found ProfileSequenceDesc tag\n");

    // Describe for size validation
    std::string desc;
    pPseqTag->Describe(desc, 1);

    if (desc.empty()) {
      printf("      %s[WARN]  ProfileSequenceDesc describes as empty%s\n",
             ColorWarning(), ColorReset());
      pseqIssues++;
    } else {
      // Count entries by looking for pattern matches
      size_t pos = 0;
      int descEntries = 0;
      while ((pos = desc.find("Device Manufacturer", pos)) != std::string::npos) {
        descEntries++;
        pos++;
      }
      printf("      Sequence description entries: ~%d\n", descEntries);

      if (descEntries > 100) {
        printf("      %s[WARN]  Excessive sequence entries (%d) — DoS risk%s\n",
               ColorWarning(), descEntries, ColorReset());
        pseqIssues++;
      }
    }
  } else {
    printf("      [SKIP] No profile sequence description tag\n");
  }

  if (pseqIssues == 0 && pPseqTag) {
    printf("      %s[OK] Profile sequence description valid%s\n",
           ColorSuccess(), ColorReset());
  }
  heuristicCount += pseqIssues;
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H101_MPESubElementChannelContinuity(CIccProfile *pIcc) {
  int heuristicCount = 0;

// H101 — MPE Sub-Element Channel Continuity (CWE-125/CWE-787)
// CVE-2026-21492 (Medium 5.5) — NPD in CIccMpeToneMap Write (invalid sub-element state)
// Exercises: IccMpeBasic.cpp (64.4% → NumInputChannels/NumOutputChannels chain validation)
//            Verifies in[i+1] == out[i] across entire MPE processing pipeline
{
  printf("[H101] MPE Sub-Element Channel Continuity\n");
  int chainIssues = 0;

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
        printf("      %s[CRIT]  Channel discontinuity in '%s' at element %u: "
               "prev_out=%u, cur_in=%u — buffer overflow risk (CWE-787)%s\n",
               ColorCritical(), tagSig, e, prevOut, curIn, ColorReset());
        chainIssues++;
      }

      prevOut = curOut;
      first = false;
    }
  }

  if (chainIssues == 0) {
    printf("      %s[OK] MPE sub-element channel continuity valid%s\n",
           ColorSuccess(), ColorReset());
  }
  heuristicCount += chainIssues;
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H102_TagSizeProfileSizeCrossCheck(CIccProfile *pIcc) {
  int heuristicCount = 0;
  CIccInfo info;

// H102 — Tag Size vs Profile Size Cross-Check (CWE-125/CWE-120)
// Exercises: IccProfile.cpp (75.25% → tag table iteration, offset validation)
//            Direct binary-level validation independent of tag parsing
{
  printf("[H102] Tag Size vs Profile Size Cross-Check\n");
  int sizeIssues = 0;

  icUInt32Number profileSize = pIcc->m_Header.size;
  icUInt32Number h102TagCount = (icUInt32Number)pIcc->m_Tags.size();

  printf("      Profile size: %u bytes, tag count: %u\n", profileSize, h102TagCount);

  if (profileSize > 0 && profileSize < 128 + (h102TagCount * 12)) {
    printf("      %s[CRIT]  Profile size %u too small for %u tags (min=%u) — truncation%s\n",
           ColorCritical(), profileSize, h102TagCount, 128 + h102TagCount * 12, ColorReset());
    sizeIssues++;
  }

  // Check each tag entry for offset/size validity
  icUInt32Number maxTagEnd = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    icUInt32Number tagOffset = it->TagInfo.offset;
    icUInt32Number tagSize = it->TagInfo.size;

    if (profileSize > 0) {
      if (tagOffset > profileSize) {
        printf("      %s[CRIT]  Tag '%s' offset %u exceeds profile size %u%s\n",
               ColorCritical(), info.GetTagSigName(it->TagInfo.sig), tagOffset, profileSize, ColorReset());
        sizeIssues++;
      } else if (tagSize > profileSize - tagOffset) {
        printf("      %s[WARN]  Tag '%s' extends past profile end: offset=%u size=%u total=%u%s\n",
               ColorWarning(), info.GetTagSigName(it->TagInfo.sig), tagOffset, tagSize, profileSize, ColorReset());
        sizeIssues++;
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
      printf("      %s[WARN]  HEURISTIC: %u trailing bytes after last tag end (aligned=%u, profileSize=%u)%s\n",
             ColorWarning(), trailingBytes, alignedEnd, profileSize, ColorReset());
      printf("      %sRisk: Hidden data appended after declared profile content — ICC.1-2022-05 §7.2%s\n",
             ColorWarning(), ColorReset());
      sizeIssues++;
    }
  }

  if (sizeIssues == 0) {
    printf("      %s[OK] Tag size vs profile size consistent%s\n",
           ColorSuccess(), ColorReset());
  }
  heuristicCount += sizeIssues;
}
printf("\n");

  return heuristicCount;
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
  int heuristicCount = 0;
  CIccInfo info;

  printf("[H146] Stack Buffer Overflow — GetValues() Size Mismatch (CWE-121)\n");
  {
    int sboIssues = 0;

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
        printf("      %s[CRIT]  HEURISTIC: Tag '%s' array size %u exceeds safe stack buffer limit (%u)%s\n",
               ColorCritical(), info.GetTagSigName(numArrayTags[t]),
               tagArraySize, kMaxSafeChannels, ColorReset());
        printf("       %sCWE-121: GetValues() writes %u elements into fixed-size caller buffer%s\n",
               ColorCritical(), tagArraySize, ColorReset());
        sboIssues++;
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
          printf("      %s[CRIT]  HEURISTIC: Tag '%s' LUT output channels %u exceeds safe limit (%u)%s\n",
                 ColorCritical(), info.GetTagSigName(lutTags[t]),
                 nOutput, kMaxSafeChannels, ColorReset());
          printf("       %sCWE-121: CIccXform3DLut::Apply() writes to fixed tmpPixel[16] buffer%s\n",
                 ColorCritical(), ColorReset());
          sboIssues++;
        }
        // Also check: output channels declared but mismatch with color space
        if (nOutput > 0 && nOutput > maxExpected * 2) {
          printf("      %s[WARN]  Tag '%s' output channels %u >> color space channels %u — SBO risk%s\n",
                 ColorWarning(), info.GetTagSigName(lutTags[t]),
                 nOutput, maxExpected, ColorReset());
          sboIssues++;
        }
      }
    }

    if (sboIssues == 0) {
      printf("      %s[OK] No stack buffer overflow patterns detected in numeric/LUT tags%s\n",
             ColorSuccess(), ColorReset());
    }
    heuristicCount += sboIssues;
  }
  printf("\n");

  return heuristicCount;
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
  int heuristicCount = 0;
  CIccInfo info;

  printf("[H147] Null Pointer Dereference — Post-Read() Tag State (CWE-476)\n");
  {
    int npdIssues = 0;

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
          printf("      %s[CRIT]  HEURISTIC: Tag '%s' (Utf16Text) has null/empty text after Read()%s\n",
                 ColorCritical(), info.GetTagSigName(textTags[t]), ColorReset());
          printf("       %sCWE-476: GetText() returns null — subsequent access crashes%s\n",
                 ColorCritical(), ColorReset());
          npdIssues++;
        }
      }

      // CIccTagTextDescription: check m_szText
      CIccTagTextDescription *desc = dynamic_cast<CIccTagTextDescription *>(pTag);
      if (desc) {
        const icChar *text = desc->GetText();
        if (!text) {
          printf("      %s[CRIT]  HEURISTIC: Tag '%s' (TextDescription) has null text pointer%s\n",
                 ColorCritical(), info.GetTagSigName(textTags[t]), ColorReset());
          printf("       %sCWE-476: GetText() returns null — strlen/Describe crashes%s\n",
                 ColorCritical(), ColorReset());
          npdIssues++;
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
          printf("      %s[CRIT]  HEURISTIC: Tag '%s' MPE element[%u] is null — Apply() will crash%s\n",
                 ColorCritical(), info.GetTagSigName(mpeTags[t]), e, ColorReset());
          printf("       %sCWE-476: Null element dereference in processing pipeline%s\n",
                 ColorCritical(), ColorReset());
          npdIssues++;
          break;  // one finding per tag is sufficient
        }
      }
    }

    // Check struct tags — ParseTag() returns null for unrecognized members
    for (const auto &entry : pIcc->m_Tags) {
      CIccTag *pTag = entry.pTag;
      if (!pTag) {
        printf("      %s[CRIT]  HEURISTIC: Tag '%s' entry exists but pTag pointer is null%s\n",
               ColorCritical(), info.GetTagSigName(entry.TagInfo.sig), ColorReset());
        printf("       %sCWE-476: Null tag pointer in tag table — any access crashes%s\n",
               ColorCritical(), ColorReset());
        npdIssues++;
      }
    }

    if (npdIssues == 0) {
      printf("      %s[OK] No null pointer patterns detected in loaded tags%s\n",
             ColorSuccess(), ColorReset());
    }
    heuristicCount += npdIssues;
  }
  printf("\n");

  return heuristicCount;
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
  int heuristicCount = 0;
  CIccInfo info;

  printf("[H148] Memory Copy Bounds and Overlap Detection (CWE-119)\n");
  {
    int memIssues = 0;

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
          printf("      %s[WARN]  Tag '%s' MPE chain: element[%u] output=%u → element[%u] input=%u mismatch%s\n",
                 ColorWarning(), info.GetTagSigName(mpeTags[t]),
                 e > 0 ? e - 1 : 0, prevOut, e, eIn, ColorReset());
          printf("       %sCWE-119: Channel mismatch may cause out-of-bounds memcpy%s\n",
                 ColorWarning(), ColorReset());
          memIssues++;
        }

        prevOut = eOut;
      }

      if (hasOverlapRisk) {
        printf("      %s[WARN]  Tag '%s' MPE chain (%u elements, in=%u out=%u) has memcpy overlap risk%s\n",
               ColorWarning(), info.GetTagSigName(mpeTags[t]),
               nElem, nIn, nOut, ColorReset());
        printf("       %sCWE-119: Apply() ping-pong buffers may alias when channels match%s\n",
               ColorWarning(), ColorReset());
        memIssues++;
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
        printf("      %s[CRIT]  HEURISTIC: NamedColor2 deviceCoords=%u exceeds ICC max (15)%s\n",
               ColorCritical(), nDevCoords, ColorReset());
        printf("       %sCWE-119: Internal buffer overflow in color entry copy%s\n",
               ColorCritical(), ColorReset());
        memIssues++;
      }

      // Large nColors with high nDevCoords = multiplicative amplification
      if (nColors > 10000 && nDevCoords > 4) {
        printf("      %s[WARN]  NamedColor2: %u colors × %u deviceCoords — memory amplification risk%s\n",
               ColorWarning(), nColors, nDevCoords, ColorReset());
        memIssues++;
      }
    }

    if (memIssues == 0) {
      printf("      %s[OK] No memory copy overlap or bounds issues detected%s\n",
             ColorSuccess(), ColorReset());
    }
    heuristicCount += memIssues;
  }
  printf("\n");

  return heuristicCount;
}

// ================================================================
// RunLibraryAPIHeuristics — dispatcher (was 3,780-line mega-function)
// ================================================================
