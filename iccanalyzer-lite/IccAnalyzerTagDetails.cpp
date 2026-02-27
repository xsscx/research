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

#include "IccAnalyzerTagDetails.h"
#include "IccAnalyzerColors.h"
#include "IccAnalyzerSafeArithmetic.h"
#include "IccTagBasic.h"
#include "IccTagComposite.h"
#include "IccProfile.h"
#include <cmath>

//==============================================================================
// Helper: format a tag signature as FourCC
//==============================================================================
static void SigToStr(icUInt32Number sig, char *buf)
{
  unsigned char uc[4];
  uc[0] = (sig >> 24) & 0xff;
  uc[1] = (sig >> 16) & 0xff;
  uc[2] = (sig >> 8) & 0xff;
  uc[3] = sig & 0xff;
  for (int i = 0; i < 4; i++)
    buf[i] = (uc[i] >= 32 && uc[i] <= 126) ? (char)uc[i] : '.';
  buf[4] = '\0';
}

//==============================================================================
// 5A: LUT Tag Analysis — geometry, CLUT, matrix, curves
//==============================================================================
static int AnalyzeLutTags(CIccProfile *pIcc)
{
  int issues = 0;

  static const icTagSignature lutSigs[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    icSigDToB0Tag, icSigDToB1Tag,
    icSigBToD0Tag, icSigBToD1Tag,
  };
  static const char *lutNames[] = {
    "A2B0", "A2B1", "A2B2",
    "B2A0", "B2A1", "B2A2",
    "D2B0", "D2B1",
    "B2D0", "B2D1",
  };

  int found = 0;
  for (size_t i = 0; i < sizeof(lutSigs)/sizeof(lutSigs[0]); i++) {
    CIccTag *pTag = pIcc->FindTag(lutSigs[i]);
    if (!pTag) continue;

    CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pTag);
    if (!pMBB) {
      // Could be an MPE tag (DToB/BToD) — handled in MPE section
      continue;
    }

    found++;
    icUInt8Number nIn = pMBB->InputChannels();
    icUInt8Number nOut = pMBB->OutputChannels();

    printf("  [%s] %sLUT Tag '%s'%s\n", lutNames[i], ColorInfo(), lutNames[i], ColorReset());
    printf("      Input channels:  %u\n", nIn);
    printf("      Output channels: %u\n", nOut);
    printf("      Matrix side:     %s\n", pMBB->IsInputMatrix() ? "input (B-side)" : "output (A-side)");

    // Curves
    printf("      CurvesB:         %s\n", pMBB->GetCurvesB() ? "present" : "none");
    printf("      CurvesM:         %s\n", pMBB->GetCurvesM() ? "present" : "none");
    printf("      CurvesA:         %s\n", pMBB->GetCurvesA() ? "present" : "none");

    // CLUT geometry
    CIccCLUT *pCLUT = pMBB->GetCLUT();
    if (pCLUT) {
      icFloatNumber *pData = pCLUT->GetData(0);
      printf("      CLUT:            %s\n", pData ? "present" : "present (no data!)");
      if (!pData) {
        printf("        %s[WARN] CLUT has no data pointer — possible corruption%s\n",
               ColorWarning(), ColorReset());
        issues++;
      }
      printf("        Grid points:   ");
      uint64_t totalEntries = 1;
      bool overflow = false;
      for (int ch = 0; ch < nIn && ch < 16; ch++) {
        icUInt8Number gp = pCLUT->GridPoint(ch);
        if (ch > 0) printf(" x ");
        printf("%u", gp);
        if (!SafeMul64(&totalEntries, totalEntries, gp)) overflow = true;
      }
      printf("\n");

      if (!overflow)
        SafeMul64(&totalEntries, totalEntries, pCLUT->GetOutputChannels());

      if (overflow) {
        printf("        %s[WARN] CLUT entry count overflows 64-bit%s\n",
               ColorCritical(), ColorReset());
        issues++;
      } else {
        printf("        Total entries: %llu\n", (unsigned long long)totalEntries);
        if (totalEntries > 16777216ULL) {
          printf("        %s[WARN] Exceeds 16M entry limit — resource exhaustion risk%s\n",
                 ColorWarning(), ColorReset());
          issues++;
        }
      }
    } else {
      printf("      CLUT:            none\n");
    }
    printf("\n");
  }

  if (found == 0) {
    printf("  %sNo legacy LUT tags (A2B/B2A/D2B/B2D) found%s\n", ColorInfo(), ColorReset());
    printf("\n");
  }

  return issues;
}

//==============================================================================
// 5B: MPE Tag Analysis — element chain walk, calculator detection
//==============================================================================
static int AnalyzeMpeTags(CIccProfile *pIcc)
{
  int issues = 0;

  // MPE tags can appear under A2B/B2A/D2B/B2D signatures
  static const icTagSignature mpeSigs[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    icSigDToB0Tag, icSigDToB1Tag,
    icSigBToD0Tag, icSigBToD1Tag,
  };
  static const char *mpeNames[] = {
    "A2B0", "A2B1", "A2B2",
    "B2A0", "B2A1", "B2A2",
    "D2B0", "D2B1",
    "B2D0", "B2D1",
  };

  int found = 0;
  for (size_t i = 0; i < sizeof(mpeSigs)/sizeof(mpeSigs[0]); i++) {
    CIccTag *pTag = pIcc->FindTag(mpeSigs[i]);
    if (!pTag) continue;

    CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMPE) continue;

    found++;
    icUInt32Number nElem = pMPE->NumElements();
    printf("  [%s] %sMPE Tag '%s'%s\n", mpeNames[i], ColorInfo(), mpeNames[i], ColorReset());
    printf("      Input channels:  %u\n", pMPE->NumInputChannels());
    printf("      Output channels: %u\n", pMPE->NumOutputChannels());
    printf("      Elements:        %u\n", nElem);

    if (nElem > 256) {
      printf("      %s[WARN] Excessive element count (>256) — DoS risk%s\n",
             ColorWarning(), ColorReset());
      issues++;
    }

    bool hasCalc = false;
    for (icUInt32Number e = 0; e < nElem && e < 256; e++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement(e);
      if (!pElem) continue;

      icElemTypeSignature elemType = pElem->GetType();
      char typeStr[5];
      SigToStr((icUInt32Number)elemType, typeStr);
      printf("        [%u] type='%s' in=%u out=%u\n",
             e, typeStr, pElem->NumInputChannels(), pElem->NumOutputChannels());

      if (elemType == icSigCalculatorElemType) {
        hasCalc = true;
      }
    }

    if (hasCalc) {
      printf("      %s[INFO] Calculator element detected — #1 source of UBSAN findings%s\n",
             ColorWarning(), ColorReset());
    }
    printf("\n");
  }

  if (found == 0) {
    printf("  %sNo MPE tags found%s\n", ColorInfo(), ColorReset());
    printf("\n");
  }

  return issues;
}

//==============================================================================
// 5C: TRC / Curve Analysis — size, NaN, degenerate
//==============================================================================
static int AnalyzeCurveTags(CIccProfile *pIcc)
{
  int issues = 0;

  static const icTagSignature curveSigs[] = {
    icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag,
  };
  static const char *curveNames[] = {
    "rTRC", "gTRC", "bTRC", "kTRC",
  };

  int found = 0;
  for (size_t i = 0; i < sizeof(curveSigs)/sizeof(curveSigs[0]); i++) {
    CIccTag *pTag = pIcc->FindTag(curveSigs[i]);
    if (!pTag) continue;

    CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve*>(pTag);
    if (pCurve) {
      found++;
      icUInt32Number sz = pCurve->GetSize();
      printf("  [%s] Tabulated curve, %u entries\n", curveNames[i], sz);

      if (sz == 0) {
        printf("      %s[WARN] Empty curve — identity assumed%s\n", ColorWarning(), ColorReset());
      } else if (sz == 1) {
        icFloatNumber gamma = (*pCurve)[0];
        printf("      Gamma: %.4f\n", gamma);
        if (std::isnan(gamma) || std::isinf(gamma)) {
          printf("      %s[WARN] NaN/Inf gamma value%s\n", ColorCritical(), ColorReset());
          issues++;
        }
      } else {
        icFloatNumber first = (*pCurve)[0];
        icFloatNumber mid = (*pCurve)[sz / 2];
        icFloatNumber last = (*pCurve)[sz - 1];
        printf("      Values: [0]=%.6f  [%u]=%.6f  [%u]=%.6f\n",
               first, sz/2, mid, sz-1, last);

        if (std::isnan(first) || std::isnan(mid) || std::isnan(last)) {
          printf("      %s[WARN] NaN detected in curve data%s\n", ColorCritical(), ColorReset());
          issues++;
        }
        // Check for degenerate flat curve (all sampled values effectively equal)
        const icFloatNumber kEpsilon = 1e-7f;
        if (std::fabs(first - last) < kEpsilon && std::fabs(first - mid) < kEpsilon) {
          printf("      %s[WARN] Flat/degenerate curve (all values equal)%s\n",
                 ColorWarning(), ColorReset());
          issues++;
        }
      }
      continue;
    }

    CIccTagParametricCurve *pPara = dynamic_cast<CIccTagParametricCurve*>(pTag);
    if (pPara) {
      found++;
      printf("  [%s] Parametric curve, function type %u\n",
             curveNames[i], pPara->GetFunctionType());
      icUInt16Number nParams = pPara->GetNumParam();
      printf("      Parameters (%u):", nParams);
      const icFloatNumber *params = pPara->GetParams();
      for (int p = 0; p < nParams && p < 8; p++) {
        printf(" %.4f", params[p]);
        if (std::isnan(params[p]) || std::isinf(params[p])) {
          issues++;
        }
      }
      printf("\n");
    }
  }

  if (found == 0) {
    printf("  %sNo TRC curve tags found%s\n", ColorInfo(), ColorReset());
  }
  printf("\n");
  return issues;
}

//==============================================================================
// 5D: NamedColor2 Validation
//==============================================================================
static int AnalyzeNamedColors(CIccProfile *pIcc)
{
  int issues = 0;

  CIccTag *pTag = pIcc->FindTag(icSigNamedColor2Tag);
  if (!pTag) {
    printf("  %sNo NamedColor2 tag%s\n", ColorInfo(), ColorReset());
    printf("\n");
    return 0;
  }

  CIccTagNamedColor2 *pNC = dynamic_cast<CIccTagNamedColor2*>(pTag);
  if (!pNC) {
    printf("  %s[WARN] NamedColor2 tag has unexpected type%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 1;
  }

  icUInt32Number count = pNC->GetSize();
  icUInt32Number devCoords = pNC->GetDeviceCoords();

  printf("  NamedColor2: %u colors, %u device coordinates\n", count, devCoords);

  if (count > 1000000) {
    printf("  %s[WARN] Excessive named color count (%u) — resource exhaustion risk%s\n",
           ColorCritical(), count, ColorReset());
    issues++;
  }
  if (devCoords > 16) {
    printf("  %s[WARN] Unusual device coordinate count (%u > 16)%s\n",
           ColorWarning(), devCoords, ColorReset());
    issues++;
  }
  printf("\n");
  return issues;
}

//==============================================================================
// 5E: XYZ Tag Value Validation
//==============================================================================
static int AnalyzeXYZTags(CIccProfile *pIcc)
{
  int issues = 0;

  static const icTagSignature xyzSigs[] = {
    icSigRedColorantTag, icSigGreenColorantTag, icSigBlueColorantTag,
    icSigMediaWhitePointTag,
  };
  static const char *xyzNames[] = {
    "rXYZ", "gXYZ", "bXYZ", "wtpt",
  };

  int found = 0;
  for (size_t i = 0; i < sizeof(xyzSigs)/sizeof(xyzSigs[0]); i++) {
    CIccTag *pTag = pIcc->FindTag(xyzSigs[i]);
    if (!pTag) continue;

    CIccTagXYZ *pXYZ = dynamic_cast<CIccTagXYZ*>(pTag);
    if (!pXYZ) continue;

    found++;
    icUInt32Number count = pXYZ->GetSize();
    if (count == 0) continue;

    icFloatNumber X = icFtoD((*pXYZ)[0].X);
    icFloatNumber Y = icFtoD((*pXYZ)[0].Y);
    icFloatNumber Z = icFtoD((*pXYZ)[0].Z);

    printf("  [%s] X=%.4f Y=%.4f Z=%.4f\n", xyzNames[i], X, Y, Z);

    if (std::isnan(X) || std::isnan(Y) || std::isnan(Z) ||
        std::isinf(X) || std::isinf(Y) || std::isinf(Z)) {
      printf("      %s[WARN] NaN/Inf in XYZ values%s\n", ColorCritical(), ColorReset());
      issues++;
    }
  }

  if (found == 0) {
    printf("  %sNo XYZ colorant/white-point tags%s\n", ColorInfo(), ColorReset());
  }
  printf("\n");
  return issues;
}

//==============================================================================
// 5F: Spectral Data (ICC v5) Reporting
//==============================================================================
static int AnalyzeSpectralTags(CIccProfile *pIcc)
{
  int issues = 0;
  int found = 0;

  // Spectral Data Info
  CIccTag *pTag = pIcc->FindTag(icSigSpectralDataInfoTag);
  if (pTag) {
    CIccTagSpectralDataInfo *pSDI = dynamic_cast<CIccTagSpectralDataInfo*>(pTag);
    if (pSDI) {
      found++;
      printf("  SpectralDataInfo:\n");
      printf("      Spectral range:  %.1f - %.1f nm, %u steps\n",
             icF16toF(pSDI->m_spectralRange.start),
             icF16toF(pSDI->m_spectralRange.end),
             pSDI->m_spectralRange.steps);
      if (pSDI->m_biSpectralRange.steps > 0) {
        printf("      BiSpectral range: %.1f - %.1f nm, %u steps\n",
               icF16toF(pSDI->m_biSpectralRange.start),
               icF16toF(pSDI->m_biSpectralRange.end),
               pSDI->m_biSpectralRange.steps);
      }
    }
  }

  // Spectral Viewing Conditions
  pTag = pIcc->FindTag(icSigSpectralViewingConditionsTag);
  if (pTag) {
    CIccTagSpectralViewingConditions *pSVC =
        dynamic_cast<CIccTagSpectralViewingConditions*>(pTag);
    if (pSVC) {
      found++;
      CIccInfo info;
      printf("  SpectralViewingConditions:\n");
      printf("      Observer:    %s\n", info.GetStandardObserverName(pSVC->getStdObserver()));
      printf("      Illuminant:  %s (CCT=%.0f K)\n",
             info.GetIlluminantName(pSVC->getStdIllumiant()),
             pSVC->getIlluminantCCT());
      printf("      Illuminant XYZ: (%.4f, %.4f, %.4f)\n",
             pSVC->m_illuminantXYZ.X, pSVC->m_illuminantXYZ.Y, pSVC->m_illuminantXYZ.Z);
    }
  }

  if (found == 0) {
    printf("  %sNo ICC v5 spectral tags%s\n", ColorInfo(), ColorReset());
  }
  printf("\n");
  return issues;
}

//==============================================================================
// 5G: Profile ID (MD5) Verification
//==============================================================================
static int AnalyzeProfileID(CIccProfile *pIcc, const char *filename)
{
  int issues = 0;

  // Check if header has a non-zero profileID
  const icProfileID &headerID = pIcc->m_Header.profileID;
  bool hasID = false;
  for (int i = 0; i < 16; i++) {
    if (headerID.ID8[i] != 0) { hasID = true; break; }
  }

  if (!hasID) {
    printf("  Profile ID: not set (all zeros)\n");
    printf("      %sINFO: Profile integrity cannot be verified without ID%s\n",
           ColorInfo(), ColorReset());
    printf("\n");
    return 0;
  }

  // Compute actual MD5
  icProfileID computedID;
  memset(&computedID, 0, sizeof(computedID));
  if (!CalcProfileID(filename, &computedID)) {
    printf("  Profile ID: present but could not recompute\n");
    printf("\n");
    return 0;
  }

  // Compare
  bool match = (memcmp(headerID.ID8, computedID.ID8, 16) == 0);

  printf("  Profile ID (header):   ");
  for (int i = 0; i < 16; i++) printf("%02x", headerID.ID8[i]);
  printf("\n");
  printf("  Profile ID (computed): ");
  for (int i = 0; i < 16; i++) printf("%02x", computedID.ID8[i]);
  printf("\n");

  if (match) {
    printf("  %s[OK] Profile ID matches — integrity verified%s\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("  %s[WARN] Profile ID MISMATCH — possible tampering or corruption%s\n",
           ColorCritical(), ColorReset());
    issues++;
  }
  printf("\n");
  return issues;
}

//==============================================================================
// 5H: Per-Tag Size Analysis (actual sizes from tag table)
//==============================================================================
static int AnalyzeTagSizes(CIccProfile *pIcc)
{
  int issues = 0;
  const uint64_t TAG_SIZE_WARN = 10ULL * 1024 * 1024;  // 10 MB

  printf("  Tag sizes (flagging >10MB):\n");
  bool anyLarge = false;

  TagEntryList::iterator it;
  for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    IccTagEntry *e = &(*it);
    if (e->TagInfo.size > TAG_SIZE_WARN) {
      char sigStr[5];
      SigToStr((icUInt32Number)e->TagInfo.sig, sigStr);
      printf("      %s[WARN] '%s' size=%u bytes (%.1f MB)%s\n",
             ColorWarning(), sigStr, e->TagInfo.size,
             e->TagInfo.size / (1024.0 * 1024.0), ColorReset());
      anyLarge = true;
      issues++;
    }
  }

  if (!anyLarge) {
    printf("      %s[OK] All tags within 10MB limit%s\n", ColorSuccess(), ColorReset());
  }
  printf("\n");
  return issues;
}

//==============================================================================
// Phase 5 Entry Point
//==============================================================================
int TagDetailAnalyze(CIccProfile *pIcc, const char *filename)
{
  if (!pIcc) return -1;

  int totalIssues = 0;

  printf("--- 5A: LUT Tag Geometry ---\n\n");
  totalIssues += AnalyzeLutTags(pIcc);

  printf("--- 5B: MPE Element Chains ---\n\n");
  totalIssues += AnalyzeMpeTags(pIcc);

  printf("--- 5C: TRC Curve Analysis ---\n\n");
  totalIssues += AnalyzeCurveTags(pIcc);

  printf("--- 5D: NamedColor2 Validation ---\n\n");
  totalIssues += AnalyzeNamedColors(pIcc);

  printf("--- 5E: XYZ Tag Values ---\n\n");
  totalIssues += AnalyzeXYZTags(pIcc);

  printf("--- 5F: ICC v5 Spectral Data ---\n\n");
  totalIssues += AnalyzeSpectralTags(pIcc);

  printf("--- 5G: Profile ID Verification ---\n\n");
  totalIssues += AnalyzeProfileID(pIcc, filename);

  printf("--- 5H: Per-Tag Size Analysis ---\n\n");
  totalIssues += AnalyzeTagSizes(pIcc);

  return totalIssues;
}
