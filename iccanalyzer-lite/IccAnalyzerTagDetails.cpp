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
#include "IccAnalyzerCommon.h"
#include "IccAnalyzerColors.h"
#include "IccAnalyzerSafeArithmetic.h"
#include "IccTagBasic.h"
#include "IccTagComposite.h"
#include "IccProfile.h"
#include "IccMpeBasic.h"
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

// Identify late-binding spectral elements that require PCC at runtime
static bool IsLateBindingSpectral(icElemTypeSignature sig)
{
  switch (sig) {
    case icSigEmissionMatrixElemType:
    case icSigInvEmissionMatrixElemType:
    case icSigEmissionObserverElemType:
    case icSigReflectanceObserverElemType:
      return true;
    default:
      return false;
  }
}

static int AnalyzeMpeTags(CIccProfile *pIcc)
{
  int issues = 0;
  CIccInfo info;

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

    // Element chain visualization (inspired by IccDumpAll)
    printf("\n      === MPE Element Chain: %u elements, %u→%u channels ===\n",
           nElem, pMPE->NumInputChannels(), pMPE->NumOutputChannels());

    bool hasCalc = false;
    int lateBindCount = 0;
    for (icUInt32Number e = 0; e < nElem && e < 256; e++) {
      CIccMultiProcessElement *pElem = pMPE->GetElement(e);
      if (!pElem) continue;

      icElemTypeSignature elemType = pElem->GetType();
      char typeStr[5];
      SigToStr(static_cast<icUInt32Number>(elemType), typeStr);

      const char *typeName = info.GetElementTypeSigName(elemType);
      bool lateBind = IsLateBindingSpectral(elemType);
      if (lateBind) lateBindCount++;

      printf("      [%u] %s ('%s') %u→%u%s\n",
             e + 1, typeName, typeStr,
             pElem->NumInputChannels(), pElem->NumOutputChannels(),
             lateBind ? " [LATE-BINDING SPECTRAL]" : "");

      if (elemType == icSigCalculatorElemType) {
        hasCalc = true;
      }
    }
    printf("      ===\n");

    if (hasCalc) {
      printf("      %s[INFO] Calculator element detected — #1 source of UBSAN findings%s\n",
             ColorWarning(), ColorReset());
    }
    if (lateBindCount > 0) {
      printf("      %s[INFO] %d late-binding spectral element(s) — require PCC (svcn tag) for rendering%s\n",
             ColorInfo(), lateBindCount, ColorReset());
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
      CIccInfo svcInfo;
      printf("  SpectralViewingConditions:\n");
      printf("      Observer:    %s\n", svcInfo.GetStandardObserverName(pSVC->getStdObserver()));
      printf("      Illuminant:  %s (CCT=%.0f K)\n",
             svcInfo.GetIlluminantName(pSVC->getStdIllumiant()),
             pSVC->getIlluminantCCT());
      printf("      Illuminant XYZ: (%.4f, %.4f, %.4f)\n",
             pSVC->m_illuminantXYZ.X, pSVC->m_illuminantXYZ.Y, pSVC->m_illuminantXYZ.Z);
    }
  }

  // Spectral White Point
  pTag = pIcc->FindTag(icSigSpectralWhitePointTag);
  if (pTag) {
    found++;
    printf("  SpectralWhitePoint:  PRESENT\n");
  }

  // Custom-to-Standard / Standard-to-Custom PCC
  CIccTag *c2sp = pIcc->FindTag(icSigCustomToStandardPccTag);
  CIccTag *s2cp = pIcc->FindTag(icSigStandardToCustomPccTag);
  if (c2sp || s2cp) {
    found++;
    printf("  PCC Transform Tags:  c2sp=%s  s2cp=%s\n",
           c2sp ? "PRESENT" : "---", s2cp ? "PRESENT" : "---");
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
      SigToStr(static_cast<icUInt32Number>(e->TagInfo.sig), sigStr);
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
// 5I: V5/iccMAX Summary — BRDF, Gamut Boundary, MPE stats, Late-Binding
//==============================================================================
static int AnalyzeV5Summary(CIccProfile *pIcc)
{
  icHeader *pHdr = &pIcc->m_Header;
  if (pHdr->version < icVersionNumberV5) {
    printf("  %s(Profile is v2/v4 — v5/iccMAX summary not applicable)%s\n",
           ColorInfo(), ColorReset());
    printf("\n");
    return 0;
  }

  int issues = 0;
  CIccInfo fmtInfo;

  printf("  %s--- V5/iccMAX Profile Summary ---%s\n\n", ColorHeader(), ColorReset());

  // BRDF tags (4 sets × 4 intents = 16 possible)
  static const icTagSignature brdfTags[] = {
    icSigBRDFAToB0Tag, icSigBRDFAToB1Tag, icSigBRDFAToB2Tag, icSigBRDFAToB3Tag,
    icSigBRDFDToB0Tag, icSigBRDFDToB1Tag, icSigBRDFDToB2Tag, icSigBRDFDToB3Tag,
    icSigBRDFMToB0Tag, icSigBRDFMToB1Tag, icSigBRDFMToB2Tag, icSigBRDFMToB3Tag,
    icSigBRDFMToS0Tag, icSigBRDFMToS1Tag, icSigBRDFMToS2Tag, icSigBRDFMToS3Tag,
  };
  int brdfCount = 0;
  for (int i = 0; i < 16; i++) {
    if (pIcc->FindTag(brdfTags[i]))
      brdfCount++;
  }
  printf("  BRDF Tags:              %d of 16 present\n", brdfCount);

  // Gamut Boundary Descriptions
  CIccTag *gbd0 = pIcc->FindTag(icSigGamutBoundaryDescription0Tag);
  CIccTag *gbd1 = pIcc->FindTag(icSigGamutBoundaryDescription1Tag);
  printf("  Gamut Boundary Desc:    gbd0=%s  gbd1=%s\n",
         gbd0 ? "PRESENT" : "---", gbd1 ? "PRESENT" : "---");

  // MCS
  if (pHdr->mcs) {
    printf("  MCS Color Space:        %s\n",
           fmtInfo.GetColorSpaceSigName(static_cast<icColorSpaceSignature>(pHdr->mcs)));
  }

  // Count MPE tags and late-binding elements
  int mpeTagCount = 0;
  int totalElements = 0;
  int lateBindCount = 0;
  int calcCount = 0;

  TagEntryList::iterator it;
  for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    CIccTag *pTag = pIcc->FindTag((*it).TagInfo.sig);
    if (pTag && pTag->GetType() == icSigMultiProcessElementType) {
      CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
      if (!pMpe) continue;
      mpeTagCount++;
      for (icUInt32Number j = 0; j < pMpe->NumElements() && j < 256; j++) {
        CIccMultiProcessElement *pElem = pMpe->GetElement(j);
        if (!pElem) continue;
        totalElements++;
        if (IsLateBindingSpectral(pElem->GetType()))
          lateBindCount++;
        if (pElem->GetType() == icSigCalculatorElemType)
          calcCount++;
      }
    }
  }

  printf("\n  MPE Tags:               %d (multiProcessElementType)\n", mpeTagCount);
  printf("  Total MPE Elements:     %d\n", totalElements);
  printf("  Calculator Elements:    %d\n", calcCount);
  printf("  Late-Binding Elements:  %d (spectral observer/emission)\n", lateBindCount);

  if (lateBindCount > 0) {
    printf("    %sNOTE: Late-binding elements require PCC (svcn tag) for proper rendering%s\n",
           ColorInfo(), ColorReset());
  }
  if (calcCount > 0) {
    printf("    %sNOTE: Calculator elements are primary source of CWE-674/CWE-400 findings%s\n",
           ColorWarning(), ColorReset());
  }

  printf("\n");
  return issues;
}

//==============================================================================
// 5J: Profile Version Classification & Capabilities
//==============================================================================
static int AnalyzeVersionCapabilities(CIccProfile *pIcc)
{
  icHeader *pHdr = &pIcc->m_Header;
  CIccInfo info;

  int major = (pHdr->version >> 24) & 0xff;
  int minor = (pHdr->version >> 20) & 0x0f;
  int bugfix = (pHdr->version >> 16) & 0x0f;

  printf("  Version Classification:\n");
  printf("    ICC Version:       %d.%d.%d\n", major, minor, bugfix);

  if (pHdr->version >= icVersionNumberV5) {
    printf("    Specification:     ICC.2 (iccMAX)\n");
    printf("    Features:          MPE, Spectral PCS, Calculator, BRDF, MCS, Named Colors\n");
  } else if (pHdr->version >= icVersionNumberV4) {
    printf("    Specification:     ICC.1-2022-05 (v4)\n");
    printf("    Features:          chromaticAdaptationTag, lut16/lutAToB, profileID\n");
  } else if (pHdr->version >= icVersionNumberV2_1) {
    printf("    Specification:     ICC.1 (v2.1+)\n");
    printf("    Features:          lut8/lut16 only, no profileID\n");
  } else {
    printf("    Specification:     ICC.1 (v2.x legacy)\n");
    printf("    Features:          lut8/lut16 only, limited tag types\n");
  }

  printf("    Device Class:      %s\n", info.GetProfileClassSigName(pHdr->deviceClass));
  printf("    Color Space:       %s (%u channels)\n",
         info.GetColorSpaceSigName(pHdr->colorSpace),
         icGetSpaceSamples(pHdr->colorSpace));

  // Connection space classification
  if (pHdr->deviceClass == icSigLinkClass) {
    printf("    Connection:        Device-to-Device (DeviceLink)\n");
  } else {
    printf("    Connection Space:  %s\n", info.GetColorSpaceSigName(pHdr->pcs));
  }

  // Transform capability summary
  printf("\n  Transform Capabilities:\n");

  bool hasA2B = pIcc->FindTag(icSigAToB0Tag) != nullptr;
  bool hasB2A = pIcc->FindTag(icSigBToA0Tag) != nullptr;
  bool hasD2B = pIcc->FindTag(icSigDToB0Tag) != nullptr;
  bool hasB2D = pIcc->FindTag(icSigBToD0Tag) != nullptr;
  bool hasTRC = pIcc->FindTag(icSigRedTRCTag) != nullptr ||
                pIcc->FindTag(icSigGrayTRCTag) != nullptr;
  bool hasGamut = pIcc->FindTag(icSigGamutTag) != nullptr;
  bool hasChad = pIcc->FindTag(icSigChromaticAdaptationTag) != nullptr;
  bool hasPreview = pIcc->FindTag(icSigPreview0Tag) != nullptr;

  printf("    AToB (device→PCS):   %s%s%s\n",
         hasA2B ? ColorSuccess() : ColorInfo(),
         hasA2B ? "YES" : "no", ColorReset());
  printf("    BToA (PCS→device):   %s%s%s\n",
         hasB2A ? ColorSuccess() : ColorInfo(),
         hasB2A ? "YES" : "no", ColorReset());
  if (pHdr->version >= icVersionNumberV4) {
    printf("    DToB (device→PCS):   %s%s%s\n",
           hasD2B ? ColorSuccess() : ColorInfo(),
           hasD2B ? "YES" : "no", ColorReset());
    printf("    BToD (PCS→device):   %s%s%s\n",
           hasB2D ? ColorSuccess() : ColorInfo(),
           hasB2D ? "YES" : "no", ColorReset());
  }
  printf("    TRC (matrix/gamma):  %s%s%s\n",
         hasTRC ? ColorSuccess() : ColorInfo(),
         hasTRC ? "YES" : "no", ColorReset());
  printf("    Gamut check:         %s%s%s\n",
         hasGamut ? ColorSuccess() : ColorInfo(),
         hasGamut ? "YES" : "no", ColorReset());
  printf("    Chromatic adapt:     %s%s%s\n",
         hasChad ? ColorSuccess() : ColorInfo(),
         hasChad ? "YES" : "no", ColorReset());
  printf("    Preview:             %s%s%s\n",
         hasPreview ? ColorSuccess() : ColorInfo(),
         hasPreview ? "YES" : "no", ColorReset());

  printf("\n");
  return 0;
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

  printf("--- 5I: V5/iccMAX Summary ---\n\n");
  totalIssues += AnalyzeV5Summary(pIcc);

  printf("--- 5J: Version Classification & Capabilities ---\n\n");
  totalIssues += AnalyzeVersionCapabilities(pIcc);

  return totalIssues;
}
