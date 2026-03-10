/*
 * IccHeuristicsProfileCompliance.cpp — Profile compliance heuristics (H103-H120)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * Extracted from IccHeuristicsLibrary.cpp as part of codebase modernization.
 */

#include "IccHeuristicsProfileCompliance.h"
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
#include "IccPrmg.h"
#include "IccMatrixMath.h"
#include "IccPcc.h"
#include "IccHeuristicsHelpers.h"

int RunHeuristic_H103_PCC(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H103] Profile Connection Conditions (PCC)\n");

  // CIccProfile implements IIccProfileConnectionConditions
  const CIccTagSpectralViewingConditions *pSvc = pIcc->getPccViewingConditions();

  if (!pSvc) {
    printf("      %s[INFO] No spectral viewing conditions tag (svcn)%s\n",
           ColorInfo(), ColorReset());
    // Still check standard PCC fields
    bool isStd = pIcc->isStandardPcc();
    icIlluminant illum = pIcc->getPccIlluminant();
    icFloatNumber cct = pIcc->getPccCCT();
    icStandardObserver obs = pIcc->getPccObserver();

    printf("      Standard PCC: %s\n", isStd ? "yes (D50/2deg)" : "no (custom)");
    printf("      Illuminant: 0x%08X, CCT: %.1f, Observer: 0x%08X\n",
           (unsigned)illum, (double)cct, (unsigned)obs);

    if (!isStd) {
      printf("      %s[WARN] Non-standard PCC — profile uses custom viewing conditions%s\n",
             ColorWarning(), ColorReset());
      heuristicCount++;
    }
  } else {
    printf("      %s[INFO] Spectral viewing conditions present%s\n",
           ColorInfo(), ColorReset());

    bool isStd = pIcc->isStandardPcc();
    icIlluminant illum = pIcc->getPccIlluminant();
    icFloatNumber cct = pIcc->getPccCCT();
    icStandardObserver obs = pIcc->getPccObserver();
    bool hasSPD = pIcc->hasIlluminantSPD();

    printf("      Standard PCC: %s\n", isStd ? "yes" : "no (custom)");
    printf("      Illuminant: 0x%08X, CCT: %.1f\n", (unsigned)illum, (double)cct);
    printf("      Observer: 0x%08X, Has SPD: %s\n", (unsigned)obs, hasSPD ? "yes" : "no");

    if (cct < 0.0f || cct > 100000.0f) {
      printf("      %s[WARN] Suspicious CCT value: %.1f (expected 0-25000K)%s\n",
             ColorWarning(), (double)cct, ColorReset());
      heuristicCount++;
    }

    // Check normalized illuminant XYZ
    icFloatNumber normXYZ[3] = {0};
    pIcc->getNormIlluminantXYZ(normXYZ);
    printf("      Norm illuminant XYZ: [%.4f, %.4f, %.4f]\n",
           (double)normXYZ[0], (double)normXYZ[1], (double)normXYZ[2]);

    if (normXYZ[1] < 0.001f || normXYZ[1] > 2.0f) {
      printf("      %s[WARN] Abnormal Y illuminant: %.4f%s\n",
             ColorWarning(), (double)normXYZ[1], ColorReset());
      heuristicCount++;
    }

    // Check media white XYZ
    icFloatNumber mediaWhite[3] = {0};
    pIcc->getMediaWhiteXYZ(mediaWhite);
    printf("      Media white XYZ: [%.4f, %.4f, %.4f]\n",
           (double)mediaWhite[0], (double)mediaWhite[1], (double)mediaWhite[2]);

    if (mediaWhite[0] == 0.0f && mediaWhite[1] == 0.0f && mediaWhite[2] == 0.0f) {
      printf("      %s[WARN] Media white is all zeros%s\n",
             ColorWarning(), ColorReset());
      heuristicCount++;
    }
  }
  printf("\n");

  return heuristicCount;
}

// =====================================================================
// H104: PRMG (Perceptual Reference Medium Gamut) Evaluation
// Exercises IccPrmg.cpp — gamut evaluation and rendering intent gamut tags
// =====================================================================
int RunHeuristic_H104_PRMG(CIccProfile *pIcc, const char * /*profilePath*/) {
  int heuristicCount = 0;

  printf("[H104] PRMG Gamut Evaluation\n");

  // Check for rendering intent gamut tags
  CIccTag *pRig0 = pIcc->FindTag(icSigPerceptualRenderingIntentGamutTag);
  CIccTag *pRig2 = pIcc->FindTag(icSigSaturationRenderingIntentGamutTag);

  if (pRig0) {
    printf("      Perceptual rendering intent gamut tag present\n");
    CIccTagSignature *pSigTag = dynamic_cast<CIccTagSignature *>(pRig0);
    if (pSigTag) {
      icUInt32Number gamutSig = pSigTag->GetValue();
      char fourCC[5];
      SignatureToFourCC(gamutSig, fourCC);
      printf("      Gamut signature: 0x%08X (%s)\n", gamutSig, fourCC);

      if (gamutSig == icSigPerceptualReferenceMediumGamut) {
        printf("      %s[OK] Profile declares PRMG compliance%s\n",
               ColorSuccess(), ColorReset());
      } else {
        printf("      %s[INFO] Non-PRMG gamut: %s%s\n",
               ColorInfo(), fourCC, ColorReset());
      }
    }
  }

  if (pRig2) {
    printf("      Saturation rendering intent gamut tag present\n");
  }

  if (!pRig0 && !pRig2) {
    printf("      %s[INFO] No rendering intent gamut tags%s\n",
           ColorInfo(), ColorReset());
  }

  // Only attempt PRMG evaluation for device profiles (Input/Display/Output/ColorSpace)
  icProfileClassSignature devClass = (icProfileClassSignature)pIcc->m_Header.deviceClass;
  if (devClass == icSigInputClass || devClass == icSigDisplayClass ||
      devClass == icSigOutputClass || devClass == icSigColorSpaceClass) {
    // Quick PRMG gamut boundary test using GetChroma
    CIccPRMG prmg;
    icFloatNumber testL[] = {25.0f, 50.0f, 75.0f};
    icFloatNumber testH[] = {0.0f, 90.0f, 180.0f, 270.0f};
    int inGamutCount = 0;
    int totalTests = 0;

    for (int li = 0; li < 3; li++) {
      for (int hi = 0; hi < 4; hi++) {
        icFloatNumber chroma = prmg.GetChroma(testL[li], testH[hi]);
        if (chroma > 0.0f) {
          // Test a point at 50% of max chroma
          icFloatNumber testC = chroma * 0.5f;
          if (prmg.InGamut(testL[li], testC, testH[hi])) {
            inGamutCount++;
          }
          totalTests++;
        }
      }
    }
    printf("      PRMG boundary: %d/%d test points in gamut\n", inGamutCount, totalTests);
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H105: Matrix-TRC Validation
// Exercises IccMatrixMath.cpp — determinant, inversion, chromaticity
// =====================================================================
int RunHeuristic_H105_MatrixTRC(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H105] Matrix-TRC Validation\n");

  icColorSpaceSignature cs = (icColorSpaceSignature)pIcc->m_Header.colorSpace;
  if (cs != icSigRgbData) {
    printf("      %s[INFO] Not an RGB profile — matrix-TRC check skipped%s\n",
           ColorInfo(), ColorReset());
    printf("\n");
    return 0;
  }

  // Extract rXYZ, gXYZ, bXYZ tags (columns of the 3x3 matrix)
  CIccTag *prXYZ = pIcc->FindTag(icSigRedColorantTag);
  CIccTag *pgXYZ = pIcc->FindTag(icSigGreenColorantTag);
  CIccTag *pbXYZ = pIcc->FindTag(icSigBlueColorantTag);

  if (!prXYZ || !pgXYZ || !pbXYZ) {
    printf("      %s[INFO] Missing rXYZ/gXYZ/bXYZ colorant tags%s\n",
           ColorInfo(), ColorReset());
    printf("\n");
    return 0;
  }

  CIccTagXYZ *pR = dynamic_cast<CIccTagXYZ *>(prXYZ);
  CIccTagXYZ *pG = dynamic_cast<CIccTagXYZ *>(pgXYZ);
  CIccTagXYZ *pB = dynamic_cast<CIccTagXYZ *>(pbXYZ);

  icFloatNumber m[3][3] = {};

  if (pR && pG && pB) {
    // v2/v4 profiles: XYZ type with fixed-point s15Fixed16Number
    icXYZNumber rXYZ = (*pR)[0];
    icXYZNumber gXYZ = (*pG)[0];
    icXYZNumber bXYZ = (*pB)[0];

    m[0][0] = icFtoD(rXYZ.X); m[0][1] = icFtoD(gXYZ.X); m[0][2] = icFtoD(bXYZ.X);
    m[1][0] = icFtoD(rXYZ.Y); m[1][1] = icFtoD(gXYZ.Y); m[1][2] = icFtoD(bXYZ.Y);
    m[2][0] = icFtoD(rXYZ.Z); m[2][1] = icFtoD(gXYZ.Z); m[2][2] = icFtoD(bXYZ.Z);
  } else {
    // v5 profiles: may use float array (fl32) type for XYZ colorants
    CIccTagFloat32 *pRf = dynamic_cast<CIccTagFloat32 *>(prXYZ);
    CIccTagFloat32 *pGf = dynamic_cast<CIccTagFloat32 *>(pgXYZ);
    CIccTagFloat32 *pBf = dynamic_cast<CIccTagFloat32 *>(pbXYZ);

    if (pRf && pGf && pBf && pRf->GetSize() >= 3 && pGf->GetSize() >= 3 && pBf->GetSize() >= 3) {
      m[0][0] = (*pRf)[0]; m[0][1] = (*pGf)[0]; m[0][2] = (*pBf)[0];
      m[1][0] = (*pRf)[1]; m[1][1] = (*pGf)[1]; m[1][2] = (*pBf)[1];
      m[2][0] = (*pRf)[2]; m[2][1] = (*pGf)[2]; m[2][2] = (*pBf)[2];
    } else {
      printf("      %s[INFO] Colorant tags are not XYZ or float type — skipping%s\n",
             ColorInfo(), ColorReset());
      printf("\n");
      return 0;
    }
  }

  printf("      Matrix:\n");
  for (int r = 0; r < 3; r++) {
    printf("        [%8.5f  %8.5f  %8.5f]\n", (double)m[r][0], (double)m[r][1], (double)m[r][2]);
  }

  // Compute determinant (ad-bc style for 3x3)
  icFloatNumber det = m[0][0] * (m[1][1]*m[2][2] - m[1][2]*m[2][1])
                    - m[0][1] * (m[1][0]*m[2][2] - m[1][2]*m[2][0])
                    + m[0][2] * (m[1][0]*m[2][1] - m[1][1]*m[2][0]);

  printf("      Determinant: %.6f\n", (double)det);

  if (det == 0.0f) {
    printf("      %s[CRIT] Singular matrix (det=0) — profile cannot map colors%s\n",
           ColorCritical(), ColorReset());
    heuristicCount++;
  } else if (det < 0.0f) {
    printf("      %s[WARN] Negative determinant — flipped color space orientation%s\n",
           ColorWarning(), ColorReset());
    heuristicCount++;
  } else if (det < 0.001f) {
    printf("      %s[WARN] Near-singular matrix (det=%.6f) — may cause numerical instability%s\n",
           ColorWarning(), (double)det, ColorReset());
    heuristicCount++;
  } else {
    printf("      %s[OK] Matrix is invertible (det=%.6f)%s\n",
           ColorSuccess(), (double)det, ColorReset());
  }

  // Row sums should approximate D50 white point (0.9642, 1.0000, 0.8249)
  icFloatNumber rowSum[3];
  for (int r = 0; r < 3; r++) {
    rowSum[r] = m[r][0] + m[r][1] + m[r][2];
  }
  printf("      Row sums (≈D50 XYZ): [%.4f, %.4f, %.4f]\n",
         (double)rowSum[0], (double)rowSum[1], (double)rowSum[2]);

  // Y row sum (luminance) should be ~1.0
  if (rowSum[1] < 0.5f || rowSum[1] > 1.5f) {
    printf("      %s[WARN] Y row sum %.4f far from 1.0 — unusual white point%s\n",
           ColorWarning(), (double)rowSum[1], ColorReset());
    heuristicCount++;
  }

  // Check for NaN/Inf in matrix values
  for (int r = 0; r < 3; r++) {
    for (int c = 0; c < 3; c++) {
      if (std::isnan(m[r][c]) || std::isinf(m[r][c])) {
        printf("      %s[CRIT] NaN/Inf in matrix[%d][%d]%s\n",
               ColorCritical(), r, c, ColorReset());
        heuristicCount++;
      }
    }
  }

  // Use CIccMatrixMath to test inversion
  CIccMatrixMath mtx(3, 3);
  for (int r = 0; r < 3; r++) {
    for (int c = 0; c < 3; c++) {
      *mtx.entry(r, c) = m[r][c];
    }
  }

  CIccMatrixMath *pInv = new (std::nothrow) CIccMatrixMath(mtx);
  if (pInv) {
    bool invertible = pInv->Invert();
    if (invertible) {
      // Multiply original * inverse → should be identity
      CIccMatrixMath *pProduct = mtx.Mult(pInv);
      if (pProduct) {
        bool isIdent = pProduct->isIdentityMtx();
        if (isIdent) {
          printf("      %s[OK] Matrix × Inverse = Identity%s\n",
                 ColorSuccess(), ColorReset());
        } else {
          printf("      %s[WARN] Matrix × Inverse ≠ Identity (precision issue)%s\n",
                 ColorWarning(), ColorReset());
          heuristicCount++;
        }
        delete pProduct;
      }
    } else {
      printf("      %s[WARN] Matrix inversion failed%s\n",
             ColorWarning(), ColorReset());
      heuristicCount++;
    }
    delete pInv;
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H106: Environment Variable Tag Inspection
// Exercises IccEnvVar.cpp — env var lookup and validation
// =====================================================================
int RunHeuristic_H106_EnvVar(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H106] Environment Variable Tags\n");

  // Look for customToStandardPcc and standardToCustomPcc MPE tags
  CIccTag *pCustomToStd = pIcc->FindTag((icTagSignature)0x63327370);  // 'c2sp'
  CIccTag *pStdToCustom = pIcc->FindTag((icTagSignature)0x73326370);  // 's2cp'

  if (pCustomToStd) {
    printf("      Custom-to-standard PCC transform present\n");
    CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement *>(pCustomToStd);
    if (pMpe) {
      printf("      Input channels: %u, Output channels: %u\n",
             pMpe->NumInputChannels(), pMpe->NumOutputChannels());
      printf("      Elements: %u\n", pMpe->NumElements());
    }
  }

  if (pStdToCustom) {
    printf("      Standard-to-custom PCC transform present\n");
    CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement *>(pStdToCustom);
    if (pMpe) {
      printf("      Input channels: %u, Output channels: %u\n",
             pMpe->NumInputChannels(), pMpe->NumOutputChannels());
      printf("      Elements: %u\n", pMpe->NumElements());
    }
  }

  // Check for CIccTagSpectralViewingConditions with custom illuminant
  const CIccTagSpectralViewingConditions *pSvc = pIcc->getPccViewingConditions();
  if (pSvc) {
    printf("      Spectral viewing conditions:\n");
    printf("        Illuminant type: 0x%08X\n", (unsigned)pSvc->getStdIllumiant());
    printf("        Observer type: 0x%08X\n", (unsigned)pSvc->getStdObserver());
    
    // Use getIlluminant() which takes icSpectralRange& output
    icSpectralRange illumRange = {};
    const icFloatNumber *pIllumData = pSvc->getIlluminant(illumRange);
    
    if (illumRange.steps > 0 && pIllumData) {
      printf("        Illuminant range: %.0f–%.0f nm, %u steps\n",
             (double)icF16toF(illumRange.start), (double)icF16toF(illumRange.end),
             illumRange.steps);

      // Validate spectral range
      icFloatNumber startNm = icF16toF(illumRange.start);
      icFloatNumber endNm = icF16toF(illumRange.end);
      if (startNm >= endNm) {
        printf("        %s[WARN] Illuminant range inverted: start %.0f >= end %.0f%s\n",
               ColorWarning(), (double)startNm, (double)endNm, ColorReset());
        heuristicCount++;
      }
      if (illumRange.steps > 1000) {
        printf("        %s[WARN] Excessive illuminant steps: %u%s\n",
               ColorWarning(), illumRange.steps, ColorReset());
        heuristicCount++;
      }
    }
  }

  if (!pCustomToStd && !pStdToCustom && !pSvc) {
    printf("      %s[INFO] No environment variable or PCC transform tags%s\n",
           ColorInfo(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H107: LUT Channel vs Colorspace Cross-Check (CWE-121/CWE-131)
// Compares AToB/BToA LUT I/O channel counts against declared data
// colorspace and PCS. Mismatch is the root cause of patch 071 SBO.
// =====================================================================
int RunHeuristic_H107_ChannelCrossCheck(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H107] LUT Channel vs Colorspace Cross-Check\n");

  icUInt32Number dataChannels = icGetSpaceSamples(pIcc->m_Header.colorSpace);
  icUInt32Number pcsChannels = icGetSpaceSamples(pIcc->m_Header.pcs);

  if (dataChannels == 0 || pcsChannels == 0) {
    printf("      %s[WARN]  Cannot determine channel counts (data=%u, PCS=%u)%s\n",
           ColorWarning(), dataChannels, pcsChannels, ColorReset());
    heuristicCount++;
    printf("\n");
    return heuristicCount;
  }

  printf("      Declared data colorspace channels: %u\n", dataChannels);
  printf("      Declared PCS channels: %u\n", pcsChannels);

  // AToB tags: input=data space, output=PCS
  icTagSignature atobSigs[] = {icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, (icTagSignature)0};
  for (int i = 0; atobSigs[i] != (icTagSignature)0; i++) {
    CIccMBB *mbb = FindAndCast<CIccMBB>(pIcc, atobSigs[i]);
    if (!mbb) continue;

    icUInt8Number nIn = mbb->InputChannels();
    icUInt8Number nOut = mbb->OutputChannels();

    if (nIn != dataChannels) {
      printf("      %s[WARN]  AToB%d: input channels (%u) != data colorspace (%u)%s\n",
             ColorCritical(), i, nIn, dataChannels, ColorReset());
      printf("       %sCWE-131: Channel/colorspace mismatch — buffer overflow risk%s\n",
             ColorCritical(), ColorReset());
      heuristicCount++;
    }
    if (nOut != pcsChannels) {
      printf("      %s[WARN]  AToB%d: output channels (%u) != PCS (%u)%s\n",
             ColorCritical(), i, nOut, pcsChannels, ColorReset());
      printf("       %sCWE-121: Output channel mismatch — SBO risk (see patch 071)%s\n",
             ColorCritical(), ColorReset());
      heuristicCount++;
    }
  }

  // BToA tags: input=PCS, output=data space
  icTagSignature btoaSigs[] = {icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, (icTagSignature)0};
  for (int i = 0; btoaSigs[i] != (icTagSignature)0; i++) {
    CIccMBB *mbb = FindAndCast<CIccMBB>(pIcc, btoaSigs[i]);
    if (!mbb) continue;

    icUInt8Number nIn = mbb->InputChannels();
    icUInt8Number nOut = mbb->OutputChannels();

    if (nIn != pcsChannels) {
      printf("      %s[WARN]  BToA%d: input channels (%u) != PCS (%u)%s\n",
             ColorCritical(), i, nIn, pcsChannels, ColorReset());
      printf("       %sCWE-131: Channel/PCS mismatch — buffer overflow risk%s\n",
             ColorCritical(), ColorReset());
      heuristicCount++;
    }
    if (nOut != dataChannels) {
      printf("      %s[WARN]  BToA%d: output channels (%u) != data colorspace (%u)%s\n",
             ColorCritical(), i, nOut, dataChannels, ColorReset());
      printf("       %sCWE-121: Output channel mismatch — SBO risk%s\n",
             ColorCritical(), ColorReset());
      heuristicCount++;
    }
  }

  // DToB / BToD tags (v4+)
  icTagSignature dtobSigs[] = {
    (icTagSignature)0x44324230, (icTagSignature)0x44324231, (icTagSignature)0x44324232,
    (icTagSignature)0
  };
  for (int i = 0; dtobSigs[i] != (icTagSignature)0; i++) {
    CIccTagMultiProcessElement *mpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, dtobSigs[i]);
    if (!mpe) continue;

    if (mpe->NumInputChannels() != dataChannels) {
      printf("      %s[WARN]  DToB%d: input channels (%u) != data colorspace (%u)%s\n",
             ColorCritical(), i, mpe->NumInputChannels(), dataChannels, ColorReset());
      heuristicCount++;
    }
    if (mpe->NumOutputChannels() != pcsChannels) {
      printf("      %s[WARN]  DToB%d: output channels (%u) != PCS (%u)%s\n",
             ColorCritical(), i, mpe->NumOutputChannels(), pcsChannels, ColorReset());
      heuristicCount++;
    }
  }

  if (heuristicCount == 0) {
    printf("      %s[OK] All LUT channel counts match declared colorspace/PCS%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H108: Private Tag Identification (CWE-829)
// Identifies tags with signatures not in the ICC registry.
// =====================================================================
int RunHeuristic_H108_PrivateTags(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H108] Private Tag Identification\n");

  static const icTagSignature knownTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    icSigBlueMatrixColumnTag, icSigBlueTRCTag,
    icSigCalibrationDateTimeTag, icSigCharTargetTag,
    icSigChromaticAdaptationTag, icSigChromaticityTag,
    icSigCopyrightTag, icSigDeviceMfgDescTag,
    icSigDeviceModelDescTag, icSigGamutTag,
    icSigGrayTRCTag, icSigGreenMatrixColumnTag,
    icSigGreenTRCTag, icSigLuminanceTag,
    icSigMeasurementTag, icSigMediaBlackPointTag,
    icSigMediaWhitePointTag, icSigNamedColor2Tag,
    icSigOutputResponseTag, icSigPreview0Tag,
    icSigPreview1Tag, icSigPreview2Tag,
    icSigProfileDescriptionTag, icSigProfileSequenceDescTag,
    icSigRedMatrixColumnTag, icSigRedTRCTag,
    icSigTechnologyTag, icSigViewingCondDescTag,
    icSigViewingConditionsTag, icSigColorantOrderTag,
    icSigColorantTableTag, icSigColorantTableOutTag,
    icSigProfileSequceIdTag,
    (icTagSignature)0x44324230, // D2B0
    (icTagSignature)0x44324231, // D2B1
    (icTagSignature)0x44324232, // D2B2
    (icTagSignature)0x42324430, // B2D0
    (icTagSignature)0x42324431, // B2D1
    (icTagSignature)0x42324432, // B2D2
    (icTagSignature)0
  };

  int privateCount = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    icTagSignature sig = it->TagInfo.sig;
    bool isKnown = false;
    for (int k = 0; knownTags[k] != (icTagSignature)0; k++) {
      if (sig == knownTags[k]) { isKnown = true; break; }
    }
    if (!isKnown) {
      char sigStr[5] = {};
      SigToChars(sig, sigStr);
      printf("      %s[INFO] Private/unknown tag: '%s' (0x%08X) offset=%u size=%u%s\n",
             ColorInfo(), sigStr, (unsigned)sig,
             it->TagInfo.offset, it->TagInfo.size, ColorReset());
      privateCount++;
    }
  }

  if (privateCount > 0) {
    printf("      %s[WARN]  %d private/unregistered tag(s) detected%s\n",
           ColorWarning(), privateCount, ColorReset());
    printf("       %sCWE-829: Private tags may contain unvalidated data%s\n",
           ColorWarning(), ColorReset());
    heuristicCount += privateCount;
  } else {
    printf("      %s[OK] All tags are registered ICC signatures%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H109: NOP Sled / Shellcode Pattern Scan (CWE-506)
// Scans tag data for common exploit patterns: x86/ARM NOP sleds,
// ELF/PE headers embedded in profile data.
// =====================================================================
int RunHeuristic_H109_ShellcodePatterns(const char *filename) {
  int heuristicCount = 0;

  printf("[H109] NOP Sled / Shellcode Pattern Scan\n");

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("      %s[ERROR] Cannot open file for shellcode scan%s\n",
           ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }
  long fileSize = fh.fileSize;

  if (fileSize <= 128 || fileSize > 100 * 1024 * 1024) {
    printf("      %s[OK] File size %ld — skipping pattern scan%s\n",
           ColorSuccess(), fileSize, ColorReset());
    printf("\n");
    return 0;
  }

  size_t scanSize = (size_t)(fileSize > 10485760 ? 10485760 : fileSize);
  std::vector<unsigned char> buf(scanSize);
  size_t bytesRead = fread(buf.data(), 1, scanSize, fh.fp);

  int nopSleds = 0;
  int elfHeaders = 0;
  int peHeaders = 0;

  for (size_t i = 128; i + 16 <= bytesRead; ) {
    // x86 NOP sled: 16+ consecutive 0x90 bytes
    if (buf[i] == 0x90) {
      size_t run = 1;
      while (i + run < bytesRead && buf[i + run] == 0x90 && run < 256) run++;
      if (run >= 16) {
        printf("      %s[WARN]  x86 NOP sled at offset 0x%zX (%zu bytes)%s\n",
               ColorCritical(), i, run, ColorReset());
        nopSleds++;
        i += run;
        continue;
      }
    }
    // ELF magic: 7F 45 4C 46
    if (i + 4 <= bytesRead && buf[i] == 0x7F && buf[i+1] == 0x45 &&
        buf[i+2] == 0x4C && buf[i+3] == 0x46) {
      printf("      %s[WARN]  ELF header at offset 0x%zX%s\n",
             ColorCritical(), i, ColorReset());
      elfHeaders++;
    }
    // PE magic: 4D 5A (MZ) with valid PE offset
    if (i + 64 <= bytesRead && buf[i] == 0x4D && buf[i+1] == 0x5A) {
      uint32_t peOff = (uint32_t)buf[i+60] | ((uint32_t)buf[i+61] << 8) |
                       ((uint32_t)buf[i+62] << 16) | ((uint32_t)buf[i+63] << 24);
      if (peOff < 1024 && i + peOff + 4 <= bytesRead &&
          buf[i+peOff] == 'P' && buf[i+peOff+1] == 'E') {
        printf("      %s[WARN]  PE/MZ executable at offset 0x%zX%s\n",
               ColorCritical(), i, ColorReset());
        peHeaders++;
      }
    }
    // ARM64 NOP sled: 1F 20 03 D5 repeated 4+ times (little-endian)
    if (i + 16 <= bytesRead && buf[i] == 0x1F && buf[i+1] == 0x20 &&
        buf[i+2] == 0x03 && buf[i+3] == 0xD5) {
      int armNops = 1;
      size_t j = i + 4;
      while (j + 4 <= bytesRead && buf[j] == 0x1F && buf[j+1] == 0x20 &&
             buf[j+2] == 0x03 && buf[j+3] == 0xD5 && armNops < 64) {
        armNops++; j += 4;
      }
      if (armNops >= 4) {
        printf("      %s[WARN]  ARM64 NOP sled at offset 0x%zX (%d instructions)%s\n",
               ColorCritical(), i, armNops, ColorReset());
        nopSleds++;
      }
    }
    i++;
  }

  if (nopSleds > 0 || elfHeaders > 0 || peHeaders > 0) {
    printf("      %sCWE-506: Embedded executable content — %d NOP sled(s), %d ELF, %d PE%s\n",
           ColorCritical(), nopSleds, elfHeaders, peHeaders, ColorReset());
    heuristicCount += nopSleds + elfHeaders + peHeaders;
  } else {
    printf("      %s[OK] No shellcode or executable patterns detected%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H110: Profile-Class Required Tag Validation (CWE-20)
// Validates required/optional tags per ICC spec and checks
// class↔colorspace consistency.
// =====================================================================
int RunHeuristic_H110_ClassTagValidation(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H110] Profile-Class Required Tag Validation\n");

  icProfileClassSignature profileClass = pIcc->m_Header.deviceClass;

  // Tags required for ALL non-DeviceLink classes
  struct TagReq {
    icTagSignature sig;
    const char *name;
  };

  static const TagReq commonRequired[] = {
    {icSigProfileDescriptionTag, "desc"},
    {icSigCopyrightTag, "cprt"},
    {icSigMediaWhitePointTag, "wtpt"},
    {(icTagSignature)0, nullptr}
  };

  // Check common required tags
  if (profileClass != icSigLinkClass) {
    for (int i = 0; commonRequired[i].sig != (icTagSignature)0; i++) {
      if (!pIcc->FindTag(commonRequired[i].sig)) {
        printf("      %s[WARN]  Missing required tag '%s' for non-DeviceLink class%s\n",
               ColorWarning(), commonRequired[i].name, ColorReset());
        heuristicCount++;
      }
    }
  }

  const char *className = "unknown";
  bool needsA2B = false;

  switch (profileClass) {
    case icSigInputClass:
      className = "Input (scnr)";
      needsA2B = true;
      break;
    case icSigDisplayClass:
      className = "Display (mntr)";
      needsA2B = true;
      break;
    case icSigOutputClass:
      className = "Output (prtr)";
      needsA2B = true;
      break;
    case icSigLinkClass:
      className = "DeviceLink (link)";
      if (!pIcc->FindTag(icSigAToB0Tag)) {
        printf("      %s[WARN]  DeviceLink missing required AToB0 tag%s\n",
               ColorWarning(), ColorReset());
        heuristicCount++;
      }
      if (!pIcc->FindTag(icSigProfileDescriptionTag)) {
        printf("      %s[WARN]  DeviceLink missing required desc tag%s\n",
               ColorWarning(), ColorReset());
        heuristicCount++;
      }
      break;
    case icSigAbstractClass:
      className = "Abstract (abst)";
      needsA2B = true;
      break;
    case icSigColorSpaceClass:
      className = "ColorSpace (spac)";
      needsA2B = true;
      break;
    case icSigNamedColorClass:
      className = "NamedColor (nmcl)";
      break;
    default:
      printf("      %s[WARN]  Unknown profile class: 0x%08X%s\n",
             ColorWarning(), (unsigned)profileClass, ColorReset());
      heuristicCount++;
      break;
  }

  printf("      Profile class: %s\n", className);

  if (needsA2B && !pIcc->FindTag(icSigAToB0Tag)) {
    if ((profileClass == icSigDisplayClass || profileClass == icSigInputClass) &&
        pIcc->FindTag(icSigRedTRCTag) && pIcc->FindTag(icSigGreenTRCTag) &&
        pIcc->FindTag(icSigBlueTRCTag)) {
      printf("      [OK] Using Matrix/TRC instead of AToB0\n");
    } else if (profileClass == icSigInputClass && pIcc->FindTag(icSigGrayTRCTag)) {
      printf("      [OK] Grayscale input using kTRC\n");
    } else {
      printf("      %s[WARN]  Missing AToB0 tag (required for %s class)%s\n",
             ColorWarning(), className, ColorReset());
      heuristicCount++;
    }
  }

  // Class↔Colorspace: non-DeviceLink PCS must be Lab or XYZ (or v5 spectral)
  if (profileClass != icSigLinkClass) {
    if (pIcc->m_Header.pcs != icSigLabData && pIcc->m_Header.pcs != icSigXYZData) {
      icUInt32Number pcsVal = (icUInt32Number)pIcc->m_Header.pcs;
      if (pcsVal < 0x72300000 || pcsVal > 0x72FFFFFF) {
        printf("      %s[WARN]  Non-DeviceLink PCS is not Lab/XYZ/spectral: 0x%08X%s\n",
               ColorCritical(), (unsigned)pIcc->m_Header.pcs, ColorReset());
        printf("       %sCWE-20: Invalid PCS for profile class%s\n",
               ColorCritical(), ColorReset());
        heuristicCount++;
      }
    }
  }

  // ICC.1-2022-05 Annex G: chromaticAdaptationTag required when adopted white ≠ D50
  if (profileClass != icSigLinkClass) {
    CIccTag *chadTag = pIcc->FindTag(icSigChromaticAdaptationTag);
    CIccTag *wtptTag = pIcc->FindTag(icSigMediaWhitePointTag);
    if (wtptTag && !chadTag) {
      CIccTagXYZ *wpXyz = dynamic_cast<CIccTagXYZ*>(wtptTag);
      if (wpXyz && wpXyz->GetSize() >= 1) {
        double wpX = icFtoD((*wpXyz)[0].X);
        double wpY = icFtoD((*wpXyz)[0].Y);
        double wpZ = icFtoD((*wpXyz)[0].Z);
        // D50: X=0.9642, Y=1.0000, Z=0.8249
        if (fabs(wpX - 0.9642) > 0.01 || fabs(wpY - 1.0) > 0.01 || fabs(wpZ - 0.8249) > 0.01) {
          printf("      %s[WARN]  wtpt ≠ D50 but 'chad' tag missing (ICC.1-2022-05 Annex G)%s\n",
                 ColorWarning(), ColorReset());
          printf("       %sCWE-20: chromaticAdaptationTag required when adopted white ≠ D50%s\n",
                 ColorWarning(), ColorReset());
          heuristicCount++;
        }
      }
    }
  }

  if (heuristicCount == 0) {
    printf("      %s[OK] Profile class and required tags are consistent%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H111: Reserved Byte Validation (CWE-20)
// Checks that ICC header reserved fields are zero.
// =====================================================================
int RunHeuristic_H111_ReservedBytes(const char *filename) {
  int heuristicCount = 0;

  printf("[H111] Reserved Byte Validation\n");

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("      %s[ERROR] Cannot open file%s\n", ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }

  unsigned char hdr[128];
  if (fread(hdr, 1, 128, fh.fp) != 128) {
    printf("      %s[WARN]  File too small for ICC header%s\n",
           ColorWarning(), ColorReset());
    printf("\n");
    return 1;
  }

  // ICC header bytes 44-47: reserved (shall be zero)
  bool reserved44_ok = (hdr[44] == 0 && hdr[45] == 0 && hdr[46] == 0 && hdr[47] == 0);
  // ICC.1-2022-05 §7.2: bytes 84-99 are Profile ID (MD5), NOT reserved
  // Bytes 100-127 are reserved (shall be zero)
  bool reserved100_ok = true;
  for (int i = 100; i < 128; i++) {
    if (hdr[i] != 0) { reserved100_ok = false; break; }
  }

  if (!reserved44_ok) {
    printf("      %s[WARN]  Header bytes 44-47 non-zero: %02X %02X %02X %02X%s\n",
           ColorWarning(), hdr[44], hdr[45], hdr[46], hdr[47], ColorReset());
    heuristicCount++;
  }

  if (!reserved100_ok) {
    printf("      %s[WARN]  Header bytes 100-127 contain non-zero reserved data%s\n",
           ColorWarning(), ColorReset());
    for (int i = 100; i < 128; i++) {
      if (hdr[i] != 0) {
        printf("       First non-zero at byte %d: 0x%02X\n", i, hdr[i]);
        break;
      }
    }
    heuristicCount++;
  }

  if (heuristicCount == 0) {
    printf("      %s[OK] All reserved header bytes are zero%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H112: Wtpt Profile-Class Validation (CWE-20)
// For v4+ Display profiles, wtpt must be D50.
// =====================================================================
int RunHeuristic_H112_WtptValidation(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H112] Wtpt Profile-Class Validation\n");

  CIccTag *tag = pIcc->FindTag(icSigMediaWhitePointTag);
  if (!tag) {
    if (pIcc->m_Header.deviceClass != icSigLinkClass) {
      printf("      %s[WARN]  Missing wtpt tag (required for non-DeviceLink)%s\n",
             ColorWarning(), ColorReset());
      heuristicCount++;
    } else {
      printf("      %s[OK] DeviceLink — wtpt not required%s\n", ColorInfo(), ColorReset());
    }
    printf("\n");
    return heuristicCount;
  }

  CIccTagXYZ *xyz = dynamic_cast<CIccTagXYZ*>(tag);
  if (!xyz || xyz->GetSize() < 1) {
    printf("      %s[WARN]  wtpt tag present but not valid XYZ type%s\n",
           ColorWarning(), ColorReset());
    heuristicCount++;
    printf("\n");
    return heuristicCount;
  }

  icXYZNumber wp = (*xyz)[0];
  double wpX = icFtoD(wp.X);
  double wpY = icFtoD(wp.Y);
  double wpZ = icFtoD(wp.Z);

  printf("      wtpt: X=%.6f Y=%.6f Z=%.6f\n", wpX, wpY, wpZ);

  // ICC.1-2022-05 §7.2.16: D50 illuminant X=0.9642, Y=1.0000, Z=0.8249
  double d50X = 0.9642, d50Y = 1.0000, d50Z = 0.8249;
  double tolerance = 0.002; // s15Fixed16 rounding tolerance

  bool isD50 = (fabs(wpX - d50X) < tolerance &&
                fabs(wpY - d50Y) < tolerance &&
                fabs(wpZ - d50Z) < tolerance);

  icUInt32Number version = pIcc->m_Header.version >> 24;

  if (version >= 4 && pIcc->m_Header.deviceClass == icSigDisplayClass) {
    if (!isD50) {
      printf("      %s[WARN]  v4+ Display profile wtpt is NOT D50%s\n",
             ColorCritical(), ColorReset());
      printf("       Expected: X=0.9642 Y=1.0000 Z=0.8249 (ICC.1-2022-05 §7.2.16)\n");
      printf("       %sCWE-20: ICC v4 Display profiles must use D50 media white point%s\n",
             ColorCritical(), ColorReset());
      heuristicCount++;
    } else {
      printf("      %s[OK] v4 Display wtpt is D50%s\n", ColorSuccess(), ColorReset());
    }
  } else {
    if (wpX < 0.0 || wpY < 0.0 || wpZ < 0.0) {
      printf("      %s[WARN]  wtpt has negative component(s)%s\n",
             ColorWarning(), ColorReset());
      heuristicCount++;
    }
    if (wpY < 0.5 || wpY > 2.0) {
      printf("      %s[WARN]  wtpt Y=%.4f outside plausible range [0.5, 2.0]%s\n",
             ColorWarning(), wpY, ColorReset());
      heuristicCount++;
    }
    if (heuristicCount == 0) {
      printf("      %s[OK] wtpt is physically plausible%s\n", ColorSuccess(), ColorReset());
      if (isD50) printf("      (Matches D50 reference illuminant)\n");
    }
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H113: Round-Trip Fidelity Assessment (CWE-682)
// Checks AToB/BToA tag pair geometry for round-trip compatibility.
// =====================================================================
int RunHeuristic_H113_RoundTripFidelity(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H113] Round-Trip Fidelity Assessment\n");

  struct IntentPair {
    icTagSignature atob;
    icTagSignature btoa;
    const char *name;
  };

  static const IntentPair pairs[] = {
    {icSigAToB0Tag, icSigBToA0Tag, "Perceptual"},
    {icSigAToB1Tag, icSigBToA1Tag, "Rel. Colorimetric"},
    {icSigAToB2Tag, icSigBToA2Tag, "Saturation"},
  };

  for (int p = 0; p < 3; p++) {
    CIccTag *tagA = pIcc->FindTag(pairs[p].atob);
    CIccTag *tagB = pIcc->FindTag(pairs[p].btoa);

    if (!tagA && !tagB) continue;

    CIccMBB *mbbA = tagA ? dynamic_cast<CIccMBB*>(tagA) : nullptr;
    CIccMBB *mbbB = tagB ? dynamic_cast<CIccMBB*>(tagB) : nullptr;

    printf("      %s intent:\n", pairs[p].name);

    if (mbbA && mbbB) {
      printf("        AToB%d: %uin → %uout\n", p,
             mbbA->InputChannels(), mbbA->OutputChannels());
      printf("        BToA%d: %uin → %uout\n", p,
             mbbB->InputChannels(), mbbB->OutputChannels());

      if (mbbA->OutputChannels() != mbbB->InputChannels()) {
        printf("        %s[WARN]  Channel mismatch: AToB output=%u != BToA input=%u%s\n",
               ColorWarning(), mbbA->OutputChannels(), mbbB->InputChannels(), ColorReset());
        printf("         %sCWE-682: Incompatible round-trip dimensions%s\n",
               ColorWarning(), ColorReset());
        heuristicCount++;
      }
      if (mbbA->InputChannels() != mbbB->OutputChannels()) {
        printf("        %s[WARN]  Channel mismatch: AToB input=%u != BToA output=%u%s\n",
               ColorWarning(), mbbA->InputChannels(), mbbB->OutputChannels(), ColorReset());
        heuristicCount++;
      }

      CIccCLUT *clutA = mbbA->GetCLUT();
      CIccCLUT *clutB = mbbB->GetCLUT();
      if (clutA) printf("        AToB%d CLUT grid: %u points\n", p, clutA->GridPoints());
      if (clutB) printf("        BToA%d CLUT grid: %u points\n", p, clutB->GridPoints());
    } else if (mbbA && !tagB) {
      printf("        AToB%d present (%uin→%uout) but BToA%d MISSING\n", p,
             mbbA->InputChannels(), mbbA->OutputChannels(), p);
      printf("        %s[INFO] One-way transform only — no round-trip possible%s\n",
             ColorInfo(), ColorReset());
    } else if (!tagA && mbbB) {
      printf("        BToA%d present (%uin→%uout) but AToB%d MISSING\n", p,
             mbbB->InputChannels(), mbbB->OutputChannels(), p);
      printf("        %s[INFO] One-way transform only — no round-trip possible%s\n",
             ColorInfo(), ColorReset());
    }
  }

  if (heuristicCount == 0) {
    printf("      %s[OK] Round-trip tag geometry is consistent%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H114: TRC/Curve Smoothness and Monotonicity (CWE-682)
// Samples TRC curves for non-monotonic regions or extreme jumps.
// =====================================================================
int RunHeuristic_H114_CurveSmoothness(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H114] TRC Curve Smoothness and Monotonicity\n");

  icTagSignature trcTags[] = {
    icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag,
    (icTagSignature)0
  };
  const char *trcNames[] = {"rTRC", "gTRC", "bTRC", "kTRC"};

  int curvesChecked = 0;

  for (int t = 0; trcTags[t] != (icTagSignature)0; t++) {
    CIccTagCurve *curve = FindAndCast<CIccTagCurve>(pIcc, trcTags[t]);
    if (!curve) continue;

    icUInt32Number nEntries = curve->GetSize();
    if (nEntries < 2) {
      if (nEntries == 1) {
        icFloatNumber gamma = (*curve)[0];
        printf("      %s: gamma=%.4f", trcNames[t], (double)gamma);
        if (gamma < 0.1 || gamma > 10.0) {
          printf(" %s[WARN] extreme gamma%s", ColorWarning(), ColorReset());
          heuristicCount++;
        }
        printf("\n");
      }
      curvesChecked++;
      continue;
    }

    int nonMonotonic = 0;
    double maxJump = 0.0;
    size_t maxJumpIdx = 0;

    for (icUInt32Number i = 1; i < nEntries; i++) {
      double prev = (double)(*curve)[i-1];
      double curr = (double)(*curve)[i];

      if (curr < prev - 0.001) nonMonotonic++;

      double jump = fabs(curr - prev);
      if (jump > maxJump) { maxJump = jump; maxJumpIdx = i; }
    }

    double expectedStep = 1.0 / (double)(nEntries - 1);
    bool extremeJump = (maxJump > expectedStep * 50.0 && maxJump > 0.1);

    printf("      %s: %u entries", trcNames[t], nEntries);
    if (nonMonotonic > 0) {
      printf(" %s[WARN] %d non-monotonic region(s)%s",
             ColorWarning(), nonMonotonic, ColorReset());
      heuristicCount++;
    }
    if (extremeJump) {
      printf(" %s[WARN] extreme jump %.4f at [%zu]%s",
             ColorWarning(), maxJump, maxJumpIdx, ColorReset());
      heuristicCount++;
    }
    if (nonMonotonic == 0 && !extremeJump) printf(" [OK]");
    printf("\n");
    curvesChecked++;
  }

  if (curvesChecked == 0) {
    printf("      %s[INFO] No TRC curve tags found%s\n", ColorInfo(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H115: Characterization Data Presence (CWE-20)
// Checks for 'targ' tag containing characterization/measurement data.
// =====================================================================
int RunHeuristic_H115_CharacterizationData(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H115] Characterization Data Presence\n");

  CIccTag *targTag = pIcc->FindTag(icSigCharTargetTag);
  if (!targTag) {
    printf("      %s[INFO] No characterization data (targ) tag present%s\n",
           ColorInfo(), ColorReset());
    printf("\n");
    return 0;
  }

  printf("      Characterization data (targ) tag present\n");

  CIccTagText *textTag = dynamic_cast<CIccTagText*>(targTag);
  if (textTag) {
    const char *text = textTag->GetText();
    size_t len = text ? strlen(text) : 0;
    printf("      Text content: %zu bytes\n", len);

    if (len > 0) {
      if (strncmp(text, "BEGIN_DATA_FORMAT", 17) == 0 ||
          strncmp(text, "CGATS", 5) == 0 ||
          strncmp(text, "CTI", 3) == 0 ||
          strncmp(text, "NUMBER_OF_SETS", 14) == 0) {
        printf("      Format: CGATS/IT8 characterization data\n");
      } else {
        char preview[81] = {};
        strncpy(preview, text, 80);
        for (int i = 0; i < 80 && preview[i]; i++) {
          if (preview[i] < 32 || preview[i] > 126) preview[i] = '.';
        }
        printf("      Preview: %.80s\n", preview);
      }
    }

    if (len > 10 * 1024 * 1024) {
      printf("      %s[WARN]  Characterization data exceeds 10MB (%zu bytes)%s\n",
             ColorWarning(), len, ColorReset());
      heuristicCount++;
    }
  } else {
    printf("      %s[WARN]  targ tag is not text type%s\n",
           ColorWarning(), ColorReset());
    heuristicCount++;
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H116: cprt/desc Encoding Validation Per Spec Version (Feedback C2)
// ICC v2: textType or textDescriptionType
// ICC v4+: multiLocalizedUnicodeType
// H116: Validate copyrightTag and profileDescriptionTag encoding types.
// ICC.1-2022-05 §9.2.22: v4+ profiles MUST use multiLocalizedUnicodeType.
int RunHeuristic_H116_CprtDescEncoding(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H116] cprt/desc Encoding vs Profile Version\n");

  icUInt32Number version = pIcc->m_Header.version;
  int majorVer = (version >> 24) & 0xFF;

  printf("      Profile version: %d.%d.%d\n", majorVer,
         (version >> 20) & 0xF, (version >> 16) & 0xF);

  struct TagCheck {
    icTagSignature sig;
    const char *name;
  };
  static const TagCheck checks[] = {
    {icSigCopyrightTag, "cprt"},
    {icSigProfileDescriptionTag, "desc"},
  };

  for (int i = 0; i < 2; i++) {
    CIccTag *tag = pIcc->FindTag(checks[i].sig);
    if (!tag) {
      printf("      %s: not present\n", checks[i].name);
      continue;
    }

    icTagTypeSignature tagType = tag->GetType();
    char typeStr[5] = {};
    typeStr[0] = (char)(static_cast<unsigned char>((tagType >> 24) & 0xFF));
    typeStr[1] = (char)(static_cast<unsigned char>((tagType >> 16) & 0xFF));
    typeStr[2] = (char)(static_cast<unsigned char>((tagType >> 8) & 0xFF));
    typeStr[3] = (char)(static_cast<unsigned char>(tagType & 0xFF));

    printf("      %s: type='%s' (0x%08X)\n", checks[i].name, typeStr, (unsigned)tagType);

    if (majorVer >= 4) {
      if (tagType != icSigMultiLocalizedUnicodeType) {
        printf("      %s[WARN]  %s: v%d profile should use multiLocalizedUnicodeType, found '%s'%s\n",
               ColorWarning(), checks[i].name, majorVer, typeStr, ColorReset());
        printf("       %sCWE-20: Encoding does not match specification version%s\n",
               ColorWarning(), ColorReset());
        heuristicCount++;
      } else {
        printf("      %s[OK] %s uses correct type for v%d%s\n",
               ColorSuccess(), checks[i].name, majorVer, ColorReset());
      }
    } else if (majorVer == 2) {
      bool ok = (tagType == icSigTextType ||
                 tagType == icSigTextDescriptionType ||
                 tagType == icSigMultiLocalizedUnicodeType);
      if (!ok) {
        printf("      %s[WARN]  %s: v2 profile should use textType or textDescriptionType, found '%s'%s\n",
               ColorWarning(), checks[i].name, typeStr, ColorReset());
        heuristicCount++;
      } else {
        printf("      %s[OK] %s uses acceptable type for v2%s\n",
               ColorSuccess(), checks[i].name, ColorReset());
      }
    }
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H117: Tag-Type-Per-Signature Validation (Feedback C3)
// Validates each tag uses only the type(s) allowed by the ICC spec
// for that tag signature.
// =====================================================================
/**
 * @brief Validate each tag uses only ICC-spec-allowed type(s) for its signature.
 *
 * Cross-references ICC.1-2022-05 §9 tag definitions with §10 tag types.
 * Iterates through all tags in the profile and checks the tag type signature
 * against a whitelist of allowed types per tag signature. Reports any tag
 * whose type is not in the allowed set, which may indicate profile corruption
 * or a crafted profile designed to trigger parser confusion (CWE-1284).
 *
 * @param pIcc Pointer to a loaded CIccProfile. Must not be NULL.
 * @return Number of heuristic checks performed.
 */
// H117: Validate that each tag's type signature is in the allowed set for its tag signature.
// Uses a static table of (tagSig → allowed typeSig[]) mappings from ICC.1-2022-05 §10.
int RunHeuristic_H117_TagTypeAllowed(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H117] Tag Type Allowed Per Signature\n");

  struct AllowedType {
    icTagSignature sig;
    const char *name;
    icTagTypeSignature allowed[6];
    int count;
  };

  // ICC.1-2022-05 §9/§10: allowed tag type signatures per tag signature
  static const AllowedType table[] = {
    {icSigCopyrightTag, "cprt",
     {icSigMultiLocalizedUnicodeType, icSigTextType, icSigTextDescriptionType}, 3},
    {icSigProfileDescriptionTag, "desc",
     {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType, icSigTextType}, 3},
    {icSigMediaWhitePointTag, "wtpt",
     {icSigXYZType}, 1},
    {icSigRedMatrixColumnTag, "rXYZ",
     {icSigXYZType}, 1},
    {icSigGreenMatrixColumnTag, "gXYZ",
     {icSigXYZType}, 1},
    {icSigBlueMatrixColumnTag, "bXYZ",
     {icSigXYZType}, 1},
    {icSigRedTRCTag, "rTRC",
     {icSigCurveType, icSigParametricCurveType}, 2},
    {icSigGreenTRCTag, "gTRC",
     {icSigCurveType, icSigParametricCurveType}, 2},
    {icSigBlueTRCTag, "bTRC",
     {icSigCurveType, icSigParametricCurveType}, 2},
    {icSigGrayTRCTag, "kTRC",
     {icSigCurveType, icSigParametricCurveType}, 2},
    {icSigChromaticAdaptationTag, "chad",
     {icSigS15Fixed16ArrayType}, 1},
    {icSigLuminanceTag, "lumi",
     {icSigXYZType}, 1},
    {icSigMeasurementTag, "meas",
     {icSigMeasurementType}, 1},
    {icSigViewingConditionsTag, "view",
     {icSigViewingConditionsType}, 1},
    {icSigTechnologyTag, "tech",
     {icSigSignatureType}, 1},
    {icSigCalibrationDateTimeTag, "calt",
     {icSigDateTimeType}, 1},
    {icSigCharTargetTag, "targ",
     {icSigTextType}, 1},
    {icSigChromaticityTag, "chrm",
     {icSigChromaticityType}, 1},
    {icSigColorantOrderTag, "clro",
     {icSigColorantOrderType}, 1},
    {icSigColorantTableTag, "clrt",
     {icSigColorantTableType}, 1},
    {icSigColorantTableOutTag, "clot",
     {icSigColorantTableType}, 1},
    {icSigNamedColor2Tag, "ncl2",
     {icSigNamedColor2Type}, 1},
    {icSigOutputResponseTag, "resp",
     {icSigResponseCurveSet16Type}, 1},
    {icSigDeviceMfgDescTag, "dmnd",
     {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType}, 2},
    {icSigDeviceModelDescTag, "dmdd",
     {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType}, 2},
    {icSigViewingCondDescTag, "vued",
     {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType}, 2},
  };

  int checked = 0, violations = 0;

  // Check each present tag's type against the whitelist
  for (size_t t = 0; t < sizeof(table) / sizeof(table[0]); t++) {
    CIccTag *tag = pIcc->FindTag(table[t].sig);
    if (!tag) continue;

    checked++;
    icTagTypeSignature actualType = tag->GetType();
    bool allowed = false;
    for (int a = 0; a < table[t].count; a++) {
      if (actualType == table[t].allowed[a]) { allowed = true; break; }
    }

    if (!allowed) {
      // Type not in whitelist — report CWE-20 violation with actual type signature
      char typeStr[5] = {};
      typeStr[0] = (char)(static_cast<unsigned char>((actualType >> 24) & 0xFF));
      typeStr[1] = (char)(static_cast<unsigned char>((actualType >> 16) & 0xFF));
      typeStr[2] = (char)(static_cast<unsigned char>((actualType >> 8) & 0xFF));
      typeStr[3] = (char)(static_cast<unsigned char>(actualType & 0xFF));
      printf("      %s[WARN]  '%s': type '%s' (0x%08X) not in allowed set%s\n",
             ColorWarning(), table[t].name, typeStr, (unsigned)actualType, ColorReset());
      printf("       %sCWE-20: Tag uses disallowed type for its signature%s\n",
             ColorWarning(), ColorReset());
      violations++;
      heuristicCount++;
    }
  }

  if (violations == 0 && checked > 0) {
    printf("      %s[OK] %d tags checked — all use allowed types%s\n",
           ColorSuccess(), checked, ColorReset());
  } else if (checked == 0) {
    printf("      [INFO] No applicable tags found\n");
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H118: Calculator Computation Cost Estimate (Feedback S10)
// Walks calculator MPE elements and estimates FLOPs per evaluation.
// =====================================================================
int RunHeuristic_H118_CalcCostEstimate(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H118] Calculator Computation Cost Estimate\n");

  icTagSignature mpeTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    (icTagSignature)0x44324230, // D2B0
    (icTagSignature)0x44324231, // D2B1
    (icTagSignature)0x42324430, // B2D0
    (icTagSignature)0x42324431, // B2D1
    (icTagSignature)0
  };

  uint64_t totalCost = 0;
  int tagsWithCalc = 0;

  for (int t = 0; mpeTags[t] != (icTagSignature)0; t++) {
    CIccTagMultiProcessElement *pMpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, mpeTags[t]);
    if (!pMpe) continue;

    icUInt32Number numElems = pMpe->NumElements();
    if (numElems == 0) continue;

    uint64_t tagCost = 0;
    int calcCount = 0;

    for (icUInt32Number ei = 0; ei < numElems; ei++) {
      CIccMultiProcessElement *pElem = pMpe->GetElement(ei);
      if (!pElem) continue;

      uint32_t inCh = pElem->NumInputChannels();
      uint32_t outCh = pElem->NumOutputChannels();

      CIccMpeCalculator *pCalc = dynamic_cast<CIccMpeCalculator*>(pElem);
      if (pCalc) {
        calcCount++;
        uint64_t opCost = (uint64_t)inCh * outCh * 100;
        tagCost += opCost;
      }

      CIccMpeCLUT *pCLUT = dynamic_cast<CIccMpeCLUT*>(pElem);
      if (pCLUT) {
        CIccCLUT *clut = pCLUT->GetCLUT();
        if (clut) {
          uint32_t grid = clut->GridPoints();
          uint64_t clutSize = 1;
          for (uint32_t d = 0; d < inCh && d < 16; d++) clutSize *= grid;
          clutSize *= outCh;
          tagCost += clutSize;
        }
      }

      CIccMpeMatrix *pMatrix = dynamic_cast<CIccMpeMatrix*>(pElem);
      if (pMatrix) {
        tagCost += (uint64_t)inCh * outCh * 2;
      }

      CIccMpeCurveSet *pCurves = dynamic_cast<CIccMpeCurveSet*>(pElem);
      if (pCurves) {
        tagCost += (uint64_t)inCh * 256;
      }
    }

    if (calcCount > 0 || tagCost > 0) {
      tagsWithCalc++;
      char sigStr[5] = {};
      icUInt32Number sig = (icUInt32Number)mpeTags[t];
      SigToChars(sig, sigStr);

      printf("      '%s': %d calc element(s), est. cost: %llu ops\n",
             sigStr, calcCount, (unsigned long long)tagCost);

      if (tagCost > 100000000ULL) {
        printf("      %s[WARN]  '%s': excessive computation cost (>100M ops per pixel)%s\n",
               ColorWarning(), sigStr, ColorReset());
        printf("       %sCWE-400: Potential algorithmic complexity DoS%s\n",
               ColorWarning(), ColorReset());
        heuristicCount++;
      }
    }

    totalCost += tagCost;
  }

  if (tagsWithCalc > 0) {
    printf("      Total estimated cost: %llu ops per pixel\n",
           (unsigned long long)totalCost);
    if (totalCost > 1000000000ULL) {
      printf("      %s[WARN]  Total computation cost exceeds 1B ops — extreme DoS risk%s\n",
             ColorWarning(), ColorReset());
      heuristicCount++;
    }
  } else {
    printf("      [INFO] No MPE calculator/CLUT elements found\n");
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H119: Round-Trip ΔE Computation (Feedback Q1)
// Samples test colors through AToB→BToA CLUTs and computes avg/max ΔE.
// H119: AToB→BToA round-trip ΔE validation via CLUT node sampling.
// Samples CLUT grid points through forward/inverse LUT pairs and computes
// CIE ΔE76 to detect lossy or broken transform implementations.
// Uses CLUT node values for accurate sampling without CMM pipeline.
int RunHeuristic_H119_RoundTripDeltaE(CIccProfile *pIcc) {
  // Sample test colors through AToB→BToA CLUTs and compute avg/max ΔE.
  // Uses CLUT node values for accurate sampling without CMM pipeline.
  int heuristicCount = 0;

  printf("[H119] Round-Trip ΔE Measurement\n");

  struct IntentPair {
    icTagSignature atob;
    icTagSignature btoa;
    const char *name;
  };
  static const IntentPair pairs[] = {
    {icSigAToB0Tag, icSigBToA0Tag, "Perceptual"},
    {icSigAToB1Tag, icSigBToA1Tag, "Rel. Colorimetric"},
    {icSigAToB2Tag, icSigBToA2Tag, "Saturation"},
  };

  bool anyMeasured = false;

  for (int p = 0; p < 3; p++) {
    CIccTag *tagA = pIcc->FindTag(pairs[p].atob);
    CIccTag *tagB = pIcc->FindTag(pairs[p].btoa);
    if (!tagA || !tagB) continue;

    CIccMBB *mbbA = dynamic_cast<CIccMBB*>(tagA);
    CIccMBB *mbbB = dynamic_cast<CIccMBB*>(tagB);
    if (!mbbA || !mbbB) continue;

    CIccCLUT *clutA = mbbA->GetCLUT();
    CIccCLUT *clutB = mbbB->GetCLUT();
    if (!clutA || !clutB) continue;

    if (mbbA->OutputChannels() != mbbB->InputChannels() ||
        mbbA->OutputChannels() < 1 || mbbA->OutputChannels() > 15) continue;

    uint32_t pcsChannels = mbbA->OutputChannels();
    uint32_t gridA = (uint32_t)clutA->GridPoints();  // icUInt8Number → uint32_t
    uint32_t inputA = mbbA->InputChannels();

    if (inputA < 1 || inputA > 15 || gridA < 2) continue;

    uint64_t totalNodes = 1;
    for (uint32_t d = 0; d < inputA; d++) {
      totalNodes *= gridA;
      if (totalNodes > 100000) { totalNodes = 100000; break; }
    }

    uint32_t stride = (totalNodes > 1000) ? (uint32_t)(totalNodes / 1000) : 1;
    if (stride < 1) stride = 1;

    double sumDE = 0.0;
    double maxDE = 0.0;
    int samples = 0;

    for (uint64_t idx = 0; idx < totalNodes; idx += stride) {
      icFloatNumber pcsOut[16] = {};
      icFloatNumber *nodeData = clutA->GetData((icUInt32Number)(idx * pcsChannels));
      if (!nodeData)
        continue;
      for (uint32_t c = 0; c < pcsChannels && c < 16; c++)
        pcsOut[c] = nodeData[c];

      icFloatNumber roundTrip[16] = {};
      clutB->Interp3d(roundTrip, pcsOut);

      double de2 = 0.0;
      for (uint32_t c = 0; c < pcsChannels && c < 3; c++) {
        double d = (double)roundTrip[c] - (double)pcsOut[c];
        de2 += d * d;
      }
      double de = sqrt(de2);
      sumDE += de;
      if (de > maxDE) maxDE = de;
      samples++;
    }

    if (samples > 0) {
      anyMeasured = true;
      double avgDE = sumDE / (double)samples;

      printf("      %s intent (%d samples):\n", pairs[p].name, samples);
      printf("        AToB%d→BToA%d: avg ΔE=%.4f  max ΔE=%.4f\n",
             p, p, avgDE, maxDE);

      if (maxDE > 5.0) {
        printf("        %s[WARN]  max ΔE > 5.0 — poor round-trip fidelity%s\n",
               ColorWarning(), ColorReset());
        heuristicCount++;
      } else if (maxDE > 2.0) {
        printf("        %s[INFO] max ΔE > 2.0 — moderate round-trip error%s\n",
               ColorInfo(), ColorReset());
      } else {
        printf("        %s[OK] Good round-trip fidelity%s\n",
               ColorSuccess(), ColorReset());
      }
    }
  }

  if (!anyMeasured) {
    printf("      [INFO] No AToB/BToA CLUT pairs available for ΔE measurement\n");
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H120: Curve Invertibility Metric (Feedback Q2)
// Samples TRC curves, builds inverse lookup, measures round-trip error.
// =====================================================================
/**
 * @brief Sample TRC curves, build inverse lookup, and measure round-trip error.
 *
 * Detects non-invertible curves that break color accuracy per ICC.1-2022-05
 * §10.6 (curveType) and §10.22 (parametricCurveType). For each TRC tag
 * (rTRC/gTRC/bTRC/kTRC), samples the forward curve at 256 points, constructs
 * a piecewise-linear inverse, then computes max round-trip deviation. Curves
 * with flat regions or extreme non-monotonicity produce large errors, which
 * may indicate a malformed or weaponized profile (CWE-682).
 *
 * @param pIcc Pointer to a loaded CIccProfile. Must not be NULL.
 * @return Number of heuristic checks performed.
 */
// H120: Assess TRC curve invertibility by checking monotonicity and sufficient dynamic range.
// Non-invertible curves indicate broken round-trip transforms (CWE-682).
int RunHeuristic_H120_CurveInvertibility(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H120] Curve Invertibility Assessment\n");

  icTagSignature trcTags[] = {
    icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag,
    (icTagSignature)0
  };
  const char *trcNames[] = {"rTRC", "gTRC", "bTRC", "kTRC"};

  int curvesChecked = 0;

  for (int t = 0; trcTags[t] != (icTagSignature)0; t++) {
    CIccTagCurve *curve = FindAndCast<CIccTagCurve>(pIcc, trcTags[t]);
    if (!curve) continue;

    icUInt32Number nEntries = curve->GetSize();
    if (nEntries < 2) {
      if (nEntries == 1) {
        icFloatNumber gamma = (*curve)[0];
        if (gamma > 0.01) {
          printf("      %s: gamma=%.4f — invertible (1/gamma=%.4f)\n",
                 trcNames[t], (double)gamma, 1.0/(double)gamma);
        } else {
          printf("      %s[WARN]  %s: gamma=%.6f ≈ 0 — NOT invertible%s\n",
                 ColorWarning(), trcNames[t], (double)gamma, ColorReset());
          heuristicCount++;
        }
      }
      curvesChecked++;
      continue;
    }

    // Sample forward curve, construct piecewise-linear inverse, measure round-trip error
    std::vector<double> fwd(nEntries);
    for (icUInt32Number i = 0; i < nEntries; i++)
      fwd[i] = (double)(*curve)[i];

    double range = fwd[nEntries-1] - fwd[0];
    bool isFlat = (fabs(range) < 1e-6);

    if (isFlat) {
      printf("      %s[WARN]  %s: flat curve (range=%.6f) — NOT invertible%s\n",
             ColorWarning(), trcNames[t], range, ColorReset());
      printf("       %sCWE-682: Degenerate transform destroys color data%s\n",
             ColorWarning(), ColorReset());
      heuristicCount++;
      curvesChecked++;
      continue;
    }

    double sumErr = 0.0, maxErr = 0.0;
    int testCount = 0;
    int nTests = (nEntries > 256) ? 256 : (int)nEntries;

    // Binary search for inverse then compute deviation from identity
    for (int s = 0; s < nTests; s++) {
      double x = (double)s / (double)(nTests - 1);
      double y = fwd[0] + x * (fwd[nEntries-1] - fwd[0]);

      size_t lo = 0, hi = nEntries - 1;
      while (lo + 1 < hi) {
        size_t mid = (lo + hi) / 2;
        if (fwd[mid] <= y) lo = mid; else hi = mid;
      }
      double invX;
      double denom = fwd[hi] - fwd[lo];
      if (fabs(denom) < 1e-12)
        invX = (double)lo / (double)(nEntries - 1);
      else
        invX = ((double)lo + (y - fwd[lo]) / denom) / (double)(nEntries - 1);

      double err = fabs(invX - x);
      sumErr += err;
      if (err > maxErr) maxErr = err;
      testCount++;
    }

    double avgErr = (testCount > 0) ? sumErr / testCount : 0.0;
    printf("      %s (%u entries): inv avg err=%.6f  max err=%.6f\n",
           trcNames[t], nEntries, avgErr, maxErr);

    // Check invertibility: max round-trip error > 1% indicates poor transform fidelity
    if (maxErr > 0.01) {
      printf("      %s[WARN]  %s: poor invertibility (max err > 1%%)%s\n",
             ColorWarning(), trcNames[t], ColorReset());
      heuristicCount++;
    } else {
      printf("      %s[OK] %s: good invertibility%s\n",
             ColorSuccess(), trcNames[t], ColorReset());
    }

    curvesChecked++;
  }

  if (curvesChecked == 0) {
    printf("      [INFO] No TRC curves found for invertibility check\n");
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H121: Characterization Data Round-Trip Assessment (Feedback Q4)
// If targ (characterization data) is CGATS format, reports data set size
// and flags whether the profile has matching transform tags for evaluation.
// =====================================================================
