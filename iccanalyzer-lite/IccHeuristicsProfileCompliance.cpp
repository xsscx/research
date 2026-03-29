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
#include <cstdint>
#include "IccPrmg.h"
#include "IccMatrixMath.h"
#include "IccPcc.h"
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicResult.h"

namespace {

static bool IsFixedNearTenThousand(icS15Fixed16Number value, int targetTimes10000) {
  const int64_t scaled = static_cast<int64_t>(value) * 10000ll;
  const int64_t target = static_cast<int64_t>(targetTimes10000) * 65536ll;
  int64_t diff = scaled - target;
  if (diff < 0) {
    diff = -diff;
  }

  return diff <= 32768ll;
}

static bool IsHeaderIlluminantNearD50(const icXYZNumber &xyz) {
  return IsFixedNearTenThousand(xyz.X, 9642) &&
         IsFixedNearTenThousand(xyz.Y, 10000) &&
         IsFixedNearTenThousand(xyz.Z, 8249);
}

static void GetSafePccSummary(CIccProfile *pIcc,
                              const CIccTagSpectralViewingConditions *pSvc,
                              bool &isStd,
                              icIlluminant &illum,
                              icFloatNumber &cct,
                              icStandardObserver &obs) {
  isStd = false;
  illum = icIlluminantUnknown;
  cct = 0.0f;
  obs = icStdObsUnknown;

  if (!pIcc) {
    return;
  }

  if (pIcc->m_Header.version < icVersionNumberV5) {
    isStd = true;
    illum = icIlluminantD50;
    cct = 5000.0f;
    obs = icStdObs1931TwoDegrees;
    return;
  }

  if (!pSvc) {
    const bool isD50 = IsHeaderIlluminantNearD50(pIcc->m_Header.illuminant);
    if (isD50) {
      isStd = true;
      illum = icIlluminantD50;
      cct = 5000.0f;
      obs = icStdObs1931TwoDegrees;
    }
    return;
  }

  illum = pSvc->getStdIllumiant();
  cct = pSvc->getIlluminantCCT();
  obs = pSvc->getStdObserver();
  isStd = (illum == icIlluminantD50 && obs == icStdObs1931TwoDegrees);
}

}  // namespace

int RunHeuristic_H103_PCC(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(103, "Profile Connection Conditions (PCC)");

  // CIccProfile implements IIccProfileConnectionConditions
  const CIccTagSpectralViewingConditions *pSvc = pIcc->getPccViewingConditions();
  bool isStd = false;
  icIlluminant illum = icIlluminantUnknown;
  icFloatNumber cct = 0.0f;
  icStandardObserver obs = icStdObsUnknown;
  GetSafePccSummary(pIcc, pSvc, isStd, illum, cct, obs);

  if (!pSvc) {
    hc.info("      No spectral viewing conditions tag (svcn)");

    hc.info("      Standard PCC: %s", isStd ? "yes (D50/2deg)" : "no (custom)");
    hc.info("      Illuminant: 0x%08X, CCT: %.1f, Observer: 0x%08X",
           (unsigned)illum, (double)cct, (unsigned)obs);

    if (!isStd) {
      hc.warn("HEURISTIC: Non-standard PCC — profile uses custom viewing conditions");
    }
  } else {
    hc.info("      Spectral viewing conditions present");
    bool hasSPD = pIcc->hasIlluminantSPD();

    hc.info("      Standard PCC: %s", isStd ? "yes" : "no (custom)");
    hc.info("      Illuminant: 0x%08X, CCT: %.1f", (unsigned)illum, (double)cct);
    hc.info("      Observer: 0x%08X, Has SPD: %s", (unsigned)obs, hasSPD ? "yes" : "no");

    if (cct < 0.0f || cct > 100000.0f) {
      hc.warn("HEURISTIC: Suspicious CCT value: %.1f (expected 0-25000K)", (double)cct);
    }

    // Check normalized illuminant XYZ
    icFloatNumber normXYZ[3] = {0};
    pIcc->getNormIlluminantXYZ(normXYZ);
    hc.info("      Norm illuminant XYZ: [%.4f, %.4f, %.4f]",
           (double)normXYZ[0], (double)normXYZ[1], (double)normXYZ[2]);

    if (normXYZ[1] < 0.001f || normXYZ[1] > 2.0f) {
      hc.warn("HEURISTIC: Abnormal Y illuminant: %.4f", (double)normXYZ[1]);
    }

    // Check media white XYZ
    icFloatNumber mediaWhite[3] = {0};
    pIcc->getMediaWhiteXYZ(mediaWhite);
    hc.info("      Media white XYZ: [%.4f, %.4f, %.4f]",
           (double)mediaWhite[0], (double)mediaWhite[1], (double)mediaWhite[2]);

    if (mediaWhite[0] == 0.0f && mediaWhite[1] == 0.0f && mediaWhite[2] == 0.0f) {
      hc.warn("HEURISTIC: Media white is all zeros");
    }
  }

  return hc.end("PCC fields within expected parameters");
}

// =====================================================================
// H104: PRMG (Perceptual Reference Medium Gamut) Evaluation
// Exercises IccPrmg.cpp — gamut evaluation and rendering intent gamut tags
// =====================================================================
int RunHeuristic_H104_PRMG(CIccProfile *pIcc, const char * /*profilePath*/) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(104, "PRMG Gamut Evaluation");

  // Check for rendering intent gamut tags
  CIccTag *pRig0 = pIcc->FindTag(icSigPerceptualRenderingIntentGamutTag);
  CIccTag *pRig2 = pIcc->FindTag(icSigSaturationRenderingIntentGamutTag);

  if (pRig0) {
    hc.info("      Perceptual rendering intent gamut tag present");
    CIccTagSignature *pSigTag = dynamic_cast<CIccTagSignature *>(pRig0);
    if (pSigTag) {
      icUInt32Number gamutSig = pSigTag->GetValue();
      char fourCC[5];
      SignatureToFourCC(gamutSig, fourCC);
      hc.info("      Gamut signature: 0x%08X (%s)", gamutSig, fourCC);

      if (gamutSig == icSigPerceptualReferenceMediumGamut) {
        hc.info("      Profile declares PRMG compliance");
      } else {
        hc.info("      Non-PRMG gamut: %s", fourCC);
      }
    }
  }

  if (pRig2) {
    hc.info("      Saturation rendering intent gamut tag present");
  }

  if (!pRig0 && !pRig2) {
    hc.info("      No rendering intent gamut tags");
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
    hc.info("      PRMG boundary: %d/%d test points in gamut", inGamutCount, totalTests);
  }

  return hc.end("PRMG gamut evaluation complete");
}

// =====================================================================
// H105: Matrix-TRC Validation
// Exercises IccMatrixMath.cpp — determinant, inversion, chromaticity
// =====================================================================
int RunHeuristic_H105_MatrixTRC(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(105, "Matrix-TRC Validation");

  icColorSpaceSignature cs = (icColorSpaceSignature)pIcc->m_Header.colorSpace;
  if (cs != icSigRgbData) {
    return hc.skip("Not an RGB profile — matrix-TRC check skipped");
  }

  // Extract rXYZ, gXYZ, bXYZ tags (columns of the 3x3 matrix)
  CIccTag *prXYZ = pIcc->FindTag(icSigRedColorantTag);
  CIccTag *pgXYZ = pIcc->FindTag(icSigGreenColorantTag);
  CIccTag *pbXYZ = pIcc->FindTag(icSigBlueColorantTag);

  if (!prXYZ || !pgXYZ || !pbXYZ) {
    return hc.skip("Missing rXYZ/gXYZ/bXYZ colorant tags");
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
      return hc.skip("Colorant tags are not XYZ or float type");
    }
  }

  hc.info("      Matrix:");
  for (int r = 0; r < 3; r++) {
    hc.info("        [%8.5f  %8.5f  %8.5f]", (double)m[r][0], (double)m[r][1], (double)m[r][2]);
  }

  // Compute determinant (ad-bc style for 3x3)
  icFloatNumber det = m[0][0] * (m[1][1]*m[2][2] - m[1][2]*m[2][1])
                    - m[0][1] * (m[1][0]*m[2][2] - m[1][2]*m[2][0])
                    + m[0][2] * (m[1][0]*m[2][1] - m[1][1]*m[2][0]);

  hc.info("      Determinant: %.6f", (double)det);

  if (det == 0.0f) {
    hc.warn("HEURISTIC: Singular matrix (det=0) — profile cannot map colors");
  } else if (det < 0.0f) {
    hc.warn("HEURISTIC: Negative determinant — flipped color space orientation");
  } else if (det < 0.001f) {
    hc.warn("HEURISTIC: Near-singular matrix (det=%.6f) — may cause numerical instability", (double)det);
  } else {
    hc.info("      Matrix is invertible (det=%.6f)", (double)det);
  }

  // Row sums should approximate D50 white point (0.9642, 1.0000, 0.8249)
  icFloatNumber rowSum[3];
  for (int r = 0; r < 3; r++) {
    rowSum[r] = m[r][0] + m[r][1] + m[r][2];
  }
  hc.info("      Row sums (≈D50 XYZ): [%.4f, %.4f, %.4f]",
         (double)rowSum[0], (double)rowSum[1], (double)rowSum[2]);

  // Y row sum (luminance) should be ~1.0
  if (rowSum[1] < 0.5f || rowSum[1] > 1.5f) {
    hc.warn("HEURISTIC: Y row sum %.4f far from 1.0 — unusual white point", (double)rowSum[1]);
  }

  // Check for NaN/Inf in matrix values
  for (int r = 0; r < 3; r++) {
    for (int c = 0; c < 3; c++) {
      if (std::isnan(m[r][c]) || std::isinf(m[r][c])) {
        hc.warn("HEURISTIC: NaN/Inf in matrix[%d][%d]", r, c);
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
        if (!isIdent) {
          hc.warn("HEURISTIC: Matrix × Inverse ≠ Identity (precision issue)");
        }
        delete pProduct;
      }
    } else {
      hc.warn("HEURISTIC: Matrix inversion failed");
    }
    delete pInv;
  }

  return hc.end("Matrix-TRC validation passed");
}

// =====================================================================
// H106: Environment Variable Tag Inspection
// Exercises IccEnvVar.cpp — env var lookup and validation
// =====================================================================
int RunHeuristic_H106_EnvVar(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(106, "Environment Variable Tags");

  // Look for customToStandardPcc and standardToCustomPcc MPE tags
  CIccTag *pCustomToStd = pIcc->FindTag((icTagSignature)0x63327370);  // 'c2sp'
  CIccTag *pStdToCustom = pIcc->FindTag((icTagSignature)0x73326370);  // 's2cp'

  if (pCustomToStd) {
    hc.info("      Custom-to-standard PCC transform present");
    CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement *>(pCustomToStd);
    if (pMpe) {
      hc.info("      Input channels: %u, Output channels: %u",
             pMpe->NumInputChannels(), pMpe->NumOutputChannels());
      hc.info("      Elements: %u", pMpe->NumElements());
    }
  }

  if (pStdToCustom) {
    hc.info("      Standard-to-custom PCC transform present");
    CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement *>(pStdToCustom);
    if (pMpe) {
      hc.info("      Input channels: %u, Output channels: %u",
             pMpe->NumInputChannels(), pMpe->NumOutputChannels());
      hc.info("      Elements: %u", pMpe->NumElements());
    }
  }

  // Check for CIccTagSpectralViewingConditions with custom illuminant
  const CIccTagSpectralViewingConditions *pSvc = pIcc->getPccViewingConditions();
  if (pSvc) {
    hc.info("      Spectral viewing conditions:");
    hc.info("        Illuminant type: 0x%08X", (unsigned)pSvc->getStdIllumiant());
    hc.info("        Observer type: 0x%08X", (unsigned)pSvc->getStdObserver());

    // Use getIlluminant() which takes icSpectralRange& output
    icSpectralRange illumRange = {};
    const icFloatNumber *pIllumData = pSvc->getIlluminant(illumRange);

    if (illumRange.steps > 0 && pIllumData) {
      hc.info("        Illuminant range: %.0f–%.0f nm, %u steps",
             (double)SafeF16ToF(illumRange.start), (double)SafeF16ToF(illumRange.end),
             illumRange.steps);

      // Validate spectral range
      icFloatNumber startNm = SafeF16ToF(illumRange.start);
      icFloatNumber endNm = SafeF16ToF(illumRange.end);
      if (startNm >= endNm) {
        hc.warn("HEURISTIC: Illuminant range inverted: start %.0f >= end %.0f",
               (double)startNm, (double)endNm);
      }
      if (illumRange.steps > 1000) {
        hc.warn("HEURISTIC: Excessive illuminant steps: %u", illumRange.steps);
      }
    }
  }

  if (!pCustomToStd && !pStdToCustom && !pSvc) {
    hc.info("      No environment variable or PCC transform tags");
  }

  return hc.end("Environment variable tags validated");
}

// =====================================================================
// H107: LUT Channel vs Colorspace Cross-Check (CWE-121/CWE-131)
// Compares AToB/BToA LUT I/O channel counts against declared data
// colorspace and PCS. Mismatch is the root cause of patch 071 SBO.
// =====================================================================
int RunHeuristic_H107_ChannelCrossCheck(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(107, "LUT Channel vs Colorspace Cross-Check");

  icUInt32Number dataChannels = icGetSpaceSamples(pIcc->m_Header.colorSpace);
  icUInt32Number pcsChannels = icGetSpaceSamples(pIcc->m_Header.pcs);

  if (dataChannels == 0 || pcsChannels == 0) {
    hc.warn("HEURISTIC: Cannot determine channel counts (data=%u, PCS=%u)",
           dataChannels, pcsChannels);
    return hc.end("LUT channel cross-check complete");
  }

  hc.info("      Declared data colorspace channels: %u", dataChannels);
  hc.info("      Declared PCS channels: %u", pcsChannels);

  // AToB tags: input=data space, output=PCS
  icTagSignature atobSigs[] = {icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, (icTagSignature)0};
  for (int i = 0; atobSigs[i] != (icTagSignature)0; i++) {
    CIccMBB *mbb = FindAndCast<CIccMBB>(pIcc, atobSigs[i]);
    if (!mbb) continue;

    icUInt8Number nIn = mbb->InputChannels();
    icUInt8Number nOut = mbb->OutputChannels();

    if (nIn != dataChannels) {
      hc.warn("HEURISTIC: AToB%d: input channels (%u) != data colorspace (%u)",
             i, nIn, dataChannels);
      hc.cweNote("CWE-131: Channel/colorspace mismatch — buffer overflow risk");
    }
    if (nOut != pcsChannels) {
      hc.warn("HEURISTIC: AToB%d: output channels (%u) != PCS (%u)",
             i, nOut, pcsChannels);
      hc.cweNote("CWE-121: Output channel mismatch — SBO risk (see patch 071)");
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
      hc.warn("HEURISTIC: BToA%d: input channels (%u) != PCS (%u)",
             i, nIn, pcsChannels);
      hc.cweNote("CWE-131: Channel/PCS mismatch — buffer overflow risk");
    }
    if (nOut != dataChannels) {
      hc.warn("HEURISTIC: BToA%d: output channels (%u) != data colorspace (%u)",
             i, nOut, dataChannels);
      hc.cweNote("CWE-121: Output channel mismatch — SBO risk");
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
      hc.warn("HEURISTIC: DToB%d: input channels (%u) != data colorspace (%u)",
             i, mpe->NumInputChannels(), dataChannels);
    }
    if (mpe->NumOutputChannels() != pcsChannels) {
      hc.warn("HEURISTIC: DToB%d: output channels (%u) != PCS (%u)",
             i, mpe->NumOutputChannels(), pcsChannels);
    }
  }

  return hc.end("All LUT channel counts match declared colorspace/PCS");
}

// =====================================================================
// H108: Private Tag Identification (CWE-829)
// Identifies tags with signatures not in the ICC registry.
// =====================================================================
int RunHeuristic_H108_PrivateTags(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(108, "Private Tag Identification");

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
    icSigPerceptualRenderingIntentGamutTag,   // 'rig0' — ICC.1-2022-05 §9.2.37
    icSigSaturationRenderingIntentGamutTag,   // 'rig2' — ICC.1-2022-05 §9.2.38
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
      hc.info("      Private/unknown tag: '%s' (0x%08X) offset=%u size=%u",
             sigStr, (unsigned)sig,
             it->TagInfo.offset, it->TagInfo.size);
      privateCount++;
    }
  }

  if (privateCount > 0) {
    hc.warn("HEURISTIC: %d private/unregistered tag(s) detected", privateCount);
    hc.cweNote("CWE-829: Private tags may contain unvalidated data");
  }

  return hc.end("All tags are registered ICC signatures");
}

// =====================================================================
// H109: NOP Sled / Shellcode Pattern Scan (CWE-506)
// Scans tag data for common exploit patterns: x86/ARM NOP sleds,
// ELF/PE headers embedded in profile data.
// =====================================================================
int RunHeuristic_H109_ShellcodePatterns(const char *filename) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(109, "NOP Sled / Shellcode Pattern Scan");

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    hc.warn("HEURISTIC: Cannot open file for shellcode scan");
    return hc.end("Shellcode scan complete");
  }
  long fileSize = fh.fileSize;

  if (fileSize <= 128 || fileSize > 100 * 1024 * 1024) {
    return hc.skip("File size not suitable for pattern scan");
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
        hc.warn("HEURISTIC: x86 NOP sled at offset 0x%zX (%zu bytes)", i, run);
        nopSleds++;
        i += run;
        continue;
      }
    }
    // ELF magic: 7F 45 4C 46
    if (i + 4 <= bytesRead && buf[i] == 0x7F && buf[i+1] == 0x45 &&
        buf[i+2] == 0x4C && buf[i+3] == 0x46) {
      hc.warn("HEURISTIC: ELF header at offset 0x%zX", i);
      elfHeaders++;
    }
    // PE magic: 4D 5A (MZ) with valid PE offset
    if (i + 64 <= bytesRead && buf[i] == 0x4D && buf[i+1] == 0x5A) {
      uint32_t peOff = (uint32_t)buf[i+60] | ((uint32_t)buf[i+61] << 8) |
                       ((uint32_t)buf[i+62] << 16) | ((uint32_t)buf[i+63] << 24);
      if (peOff < 1024 && i + peOff + 4 <= bytesRead &&
          buf[i+peOff] == 'P' && buf[i+peOff+1] == 'E') {
        hc.warn("HEURISTIC: PE/MZ executable at offset 0x%zX", i);
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
        hc.warn("HEURISTIC: ARM64 NOP sled at offset 0x%zX (%d instructions)", i, armNops);
        nopSleds++;
      }
    }
    i++;
  }

  if (nopSleds > 0 || elfHeaders > 0 || peHeaders > 0) {
    hc.cweNote("CWE-506: Embedded executable content — %d NOP sled(s), %d ELF, %d PE",
           nopSleds, elfHeaders, peHeaders);
  }

  return hc.end("No shellcode or executable patterns detected");
}

// =====================================================================
// H110: Profile-Class Required Tag Validation (CWE-20)
// Validates required/optional tags per ICC spec and checks
// class↔colorspace consistency.
// =====================================================================
int RunHeuristic_H110_ClassTagValidation(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(110, "Profile-Class Required Tag Validation");

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
        hc.warn("HEURISTIC: Missing required tag '%s' for non-DeviceLink class",
               commonRequired[i].name);
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
        hc.warn("HEURISTIC: DeviceLink missing required AToB0 tag");
      }
      if (!pIcc->FindTag(icSigProfileDescriptionTag)) {
        hc.warn("HEURISTIC: DeviceLink missing required desc tag");
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
      hc.warn("HEURISTIC: Unknown profile class: 0x%08X", (unsigned)profileClass);
      break;
  }

  hc.info("      Profile class: %s", className);

  if (needsA2B && !pIcc->FindTag(icSigAToB0Tag)) {
    if ((profileClass == icSigDisplayClass || profileClass == icSigInputClass) &&
        pIcc->FindTag(icSigRedTRCTag) && pIcc->FindTag(icSigGreenTRCTag) &&
        pIcc->FindTag(icSigBlueTRCTag)) {
      hc.info("      Using Matrix/TRC instead of AToB0");
    } else if (profileClass == icSigInputClass && pIcc->FindTag(icSigGrayTRCTag)) {
      hc.info("      Grayscale input using kTRC");
    } else {
      hc.warn("HEURISTIC: Missing AToB0 tag (required for %s class)", className);
    }
  }

  // Class↔Colorspace: non-DeviceLink PCS must be Lab or XYZ (or v5 spectral)
  if (profileClass != icSigLinkClass) {
    if (pIcc->m_Header.pcs != icSigLabData && pIcc->m_Header.pcs != icSigXYZData) {
      icUInt32Number pcsVal = (icUInt32Number)pIcc->m_Header.pcs;
      if (pcsVal < 0x72300000 || pcsVal > 0x72FFFFFF) {
        hc.warn("HEURISTIC: Non-DeviceLink PCS is not Lab/XYZ/spectral: 0x%08X",
               (unsigned)pIcc->m_Header.pcs);
        hc.cweNote("CWE-20: Invalid PCS for profile class");
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
          hc.warn("HEURISTIC: wtpt ≠ D50 but 'chad' tag missing (ICC.1-2022-05 Annex G)");
          hc.cweNote("CWE-20: chromaticAdaptationTag required when adopted white ≠ D50");
        }
      }
    }
  }

  return hc.end("Profile class and required tags are consistent");
}

// =====================================================================
// H111: Reserved Byte Validation (CWE-20)
// Checks that ICC header reserved fields are zero.
// =====================================================================
int RunHeuristic_H111_ReservedBytes(const char *filename) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(111, "Reserved Byte Validation");

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    hc.warn("HEURISTIC: Cannot open file");
    return hc.end("Reserved byte validation complete");
  }

  unsigned char hdr[128];
  if (fread(hdr, 1, 128, fh.fp) != 128) {
    hc.warn("HEURISTIC: File too small for ICC header");
    return hc.end("Reserved byte validation complete");
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
    hc.warn("HEURISTIC: Header bytes 44-47 non-zero: %02X %02X %02X %02X",
           hdr[44], hdr[45], hdr[46], hdr[47]);
  }

  if (!reserved100_ok) {
    hc.warn("HEURISTIC: Header bytes 100-127 contain non-zero reserved data");
    for (int i = 100; i < 128; i++) {
      if (hdr[i] != 0) {
        hc.info("       First non-zero at byte %d: 0x%02X", i, hdr[i]);
        break;
      }
    }
  }

  return hc.end("All reserved header bytes are zero");
}

// =====================================================================
// H112: Wtpt Profile-Class Validation (CWE-20)
// For v4+ Display profiles, wtpt must be D50.
// =====================================================================
int RunHeuristic_H112_WtptValidation(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(112, "Wtpt Profile-Class Validation");

  CIccTag *tag = pIcc->FindTag(icSigMediaWhitePointTag);
  if (!tag) {
    if (pIcc->m_Header.deviceClass != icSigLinkClass) {
      hc.warn("HEURISTIC: Missing wtpt tag (required for non-DeviceLink)");
    } else {
      hc.info("      DeviceLink — wtpt not required");
    }
    return hc.end("Wtpt validation complete");
  }

  CIccTagXYZ *xyz = dynamic_cast<CIccTagXYZ*>(tag);
  if (!xyz || xyz->GetSize() < 1) {
    hc.warn("HEURISTIC: wtpt tag present but not valid XYZ type");
    return hc.end("Wtpt validation complete");
  }

  icXYZNumber wp = (*xyz)[0];
  double wpX = icFtoD(wp.X);
  double wpY = icFtoD(wp.Y);
  double wpZ = icFtoD(wp.Z);

  hc.info("      wtpt: X=%.6f Y=%.6f Z=%.6f", wpX, wpY, wpZ);

  // ICC.1-2022-05 §7.2.16: D50 illuminant X=0.9642, Y=1.0000, Z=0.8249
  double d50X = 0.9642, d50Y = 1.0000, d50Z = 0.8249;
  double tolerance = 0.002; // s15Fixed16 rounding tolerance

  bool isD50 = (fabs(wpX - d50X) < tolerance &&
                fabs(wpY - d50Y) < tolerance &&
                fabs(wpZ - d50Z) < tolerance);

  icUInt32Number version = pIcc->m_Header.version >> 24;

  if (version >= 4 && pIcc->m_Header.deviceClass == icSigDisplayClass) {
    if (!isD50) {
      hc.warn("HEURISTIC: v4+ Display profile wtpt is NOT D50");
      hc.info("       Expected: X=0.9642 Y=1.0000 Z=0.8249 (ICC.1-2022-05 §7.2.16)");
      hc.cweNote("CWE-20: ICC v4 Display profiles must use D50 media white point");
    } else {
      hc.info("      v4 Display wtpt is D50");
    }
  } else {
    if (wpX < 0.0 || wpY < 0.0 || wpZ < 0.0) {
      hc.warn("HEURISTIC: wtpt has negative component(s)");
    }
    if (wpY < 0.5 || wpY > 2.0) {
      hc.warn("HEURISTIC: wtpt Y=%.4f outside plausible range [0.5, 2.0]", wpY);
    }
    if (isD50) hc.info("      (Matches D50 reference illuminant)");
  }

  return hc.end("wtpt is physically plausible");
}

// =====================================================================
// H113: Round-Trip Fidelity Assessment (CWE-682)
// Checks AToB/BToA tag pair geometry for round-trip compatibility.
// =====================================================================
int RunHeuristic_H113_RoundTripFidelity(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(113, "Round-Trip Fidelity Assessment");

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

    hc.info("      %s intent:", pairs[p].name);

    if (mbbA && mbbB) {
      hc.info("        AToB%d: %uin → %uout", p,
             mbbA->InputChannels(), mbbA->OutputChannels());
      hc.info("        BToA%d: %uin → %uout", p,
             mbbB->InputChannels(), mbbB->OutputChannels());

      if (mbbA->OutputChannels() != mbbB->InputChannels()) {
        hc.warn("HEURISTIC: Channel mismatch: AToB output=%u != BToA input=%u",
               mbbA->OutputChannels(), mbbB->InputChannels());
        hc.cweNote("CWE-682: Incompatible round-trip dimensions");
      }
      if (mbbA->InputChannels() != mbbB->OutputChannels()) {
        hc.warn("HEURISTIC: Channel mismatch: AToB input=%u != BToA output=%u",
               mbbA->InputChannels(), mbbB->OutputChannels());
      }

      CIccCLUT *clutA = mbbA->GetCLUT();
      CIccCLUT *clutB = mbbB->GetCLUT();
      if (clutA) hc.info("        AToB%d CLUT grid: %u points", p, clutA->GridPoints());
      if (clutB) hc.info("        BToA%d CLUT grid: %u points", p, clutB->GridPoints());
    } else if (mbbA && !tagB) {
      hc.info("        AToB%d present (%uin→%uout) but BToA%d MISSING", p,
             mbbA->InputChannels(), mbbA->OutputChannels(), p);
      hc.info("        One-way transform only — no round-trip possible");
    } else if (!tagA && mbbB) {
      hc.info("        BToA%d present (%uin→%uout) but AToB%d MISSING", p,
             mbbB->InputChannels(), mbbB->OutputChannels(), p);
      hc.info("        One-way transform only — no round-trip possible");
    }
  }

  return hc.end("Round-trip tag geometry is consistent");
}

// =====================================================================
// H114: TRC/Curve Smoothness and Monotonicity (CWE-682)
// Samples TRC curves for non-monotonic regions or extreme jumps.
// =====================================================================
int RunHeuristic_H114_CurveSmoothness(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(114, "TRC Curve Smoothness and Monotonicity");

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
        hc.info("      %s: gamma=%.4f", trcNames[t], (double)gamma);
        if (gamma < 0.1 || gamma > 10.0) {
          hc.warn("HEURISTIC: %s: extreme gamma value %.4f", trcNames[t], (double)gamma);
        }
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

    hc.info("      %s: %u entries", trcNames[t], nEntries);
    if (nonMonotonic > 0) {
      hc.warn("HEURISTIC: %s: %d non-monotonic region(s)", trcNames[t], nonMonotonic);
    }
    if (extremeJump) {
      hc.warn("HEURISTIC: %s: extreme jump %.4f at [%zu]", trcNames[t], maxJump, maxJumpIdx);
    }
    curvesChecked++;
  }

  if (curvesChecked == 0) {
    hc.info("      No TRC curve tags found");
  }

  return hc.end("TRC curves are smooth and monotonic");
}

// =====================================================================
// H115: Characterization Data Presence (CWE-20)
// Checks for 'targ' tag containing characterization/measurement data.
// =====================================================================
int RunHeuristic_H115_CharacterizationData(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(115, "Characterization Data Presence");

  CIccTag *targTag = pIcc->FindTag(icSigCharTargetTag);
  if (!targTag) {
    return hc.skip("No characterization data (targ) tag present");
  }

  hc.info("      Characterization data (targ) tag present");

  CIccTagText *textTag = dynamic_cast<CIccTagText*>(targTag);
  if (textTag) {
    const char *text = textTag->GetText();
    size_t len = text ? strlen(text) : 0;
    hc.info("      Text content: %zu bytes", len);

    if (len > 0) {
      if (strncmp(text, "BEGIN_DATA_FORMAT", 17) == 0 ||
          strncmp(text, "CGATS", 5) == 0 ||
          strncmp(text, "CTI", 3) == 0 ||
          strncmp(text, "NUMBER_OF_SETS", 14) == 0) {
        hc.info("      Format: CGATS/IT8 characterization data");
      } else {
        char preview[81] = {};
        strncpy(preview, text, 80);
        for (int i = 0; i < 80 && preview[i]; i++) {
          if (preview[i] < 32 || preview[i] > 126) preview[i] = '.';
        }
        hc.info("      Preview: %.80s", preview);
      }
    }

    if (len > 10 * 1024 * 1024) {
      hc.warn("HEURISTIC: Characterization data exceeds 10MB (%zu bytes)", len);
    }
  } else {
    hc.warn("HEURISTIC: targ tag is not text type");
  }

  return hc.end("Characterization data present and valid");
}

// =====================================================================
// H116: cprt/desc Encoding Validation Per Spec Version (Feedback C2)
// ICC v2: textType or textDescriptionType
// ICC v4+: multiLocalizedUnicodeType
// H116: Validate copyrightTag and profileDescriptionTag encoding types.
// ICC.1-2022-05 §9.2.22: v4+ profiles MUST use multiLocalizedUnicodeType.
int RunHeuristic_H116_CprtDescEncoding(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(116, "cprt/desc Encoding vs Profile Version");

  icUInt32Number version = pIcc->m_Header.version;
  int majorVer = (version >> 24) & 0xFF;

  hc.info("      Profile version: %d.%d.%d", majorVer,
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
      hc.info("      %s: not present", checks[i].name);
      continue;
    }

    icTagTypeSignature tagType = tag->GetType();
    char typeStr[5] = {};
    typeStr[0] = (char)(static_cast<unsigned char>((tagType >> 24) & 0xFF));
    typeStr[1] = (char)(static_cast<unsigned char>((tagType >> 16) & 0xFF));
    typeStr[2] = (char)(static_cast<unsigned char>((tagType >> 8) & 0xFF));
    typeStr[3] = (char)(static_cast<unsigned char>(tagType & 0xFF));

    hc.info("      %s: type='%s' (0x%08X)", checks[i].name, typeStr, (unsigned)tagType);

    if (majorVer >= 4) {
      if (tagType != icSigMultiLocalizedUnicodeType) {
        hc.warn("HEURISTIC: %s: v%d profile should use multiLocalizedUnicodeType, found '%s'",
               checks[i].name, majorVer, typeStr);
        hc.cweNote("CWE-20: Encoding does not match specification version");
      }
    } else if (majorVer == 2) {
      bool ok = (tagType == icSigTextType ||
                 tagType == icSigTextDescriptionType ||
                 tagType == icSigMultiLocalizedUnicodeType);
      if (!ok) {
        hc.warn("HEURISTIC: %s: v2 profile should use textType or textDescriptionType, found '%s'",
               checks[i].name, typeStr);
      }
    }
  }

  return hc.end("cprt/desc encoding matches profile version");
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
  auto &hc = HeuristicCollector::instance();
  hc.begin(117, "Tag Type Allowed Per Signature");

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

  int checked = 0;

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
      hc.warn("HEURISTIC: '%s': type '%s' (0x%08X) not in allowed set",
             table[t].name, typeStr, (unsigned)actualType);
      hc.cweNote("CWE-20: Tag uses disallowed type for its signature");
    }
  }

  if (checked == 0) {
    hc.info("      No applicable tags found");
  }

  char endMsg[128];
  snprintf(endMsg, sizeof(endMsg), "%d tags checked — all use allowed types", checked);
  return hc.end(endMsg);
}

// =====================================================================
// H118: Calculator Computation Cost Estimate (Feedback S10)
// Walks calculator MPE elements and estimates FLOPs per evaluation.
// =====================================================================
int RunHeuristic_H118_CalcCostEstimate(CIccProfile *pIcc) {
  auto &hc = HeuristicCollector::instance();
  hc.begin(118, "Calculator Computation Cost Estimate");

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

      hc.info("      '%s': %d calc element(s), est. cost: %llu ops",
             sigStr, calcCount, (unsigned long long)tagCost);

      if (tagCost > 100000000ULL) {
        hc.warn("HEURISTIC: '%s': excessive computation cost (>100M ops per pixel)", sigStr);
        hc.cweNote("CWE-400: Potential algorithmic complexity DoS");
      }
    }

    totalCost += tagCost;
  }

  if (tagsWithCalc > 0) {
    hc.info("      Total estimated cost: %llu ops per pixel",
           (unsigned long long)totalCost);
    if (totalCost > 1000000000ULL) {
      hc.warn("HEURISTIC: Total computation cost exceeds 1B ops — extreme DoS risk");
    }
  } else {
    hc.info("      No MPE calculator/CLUT elements found");
  }

  return hc.end("Computation cost within acceptable limits");
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
  auto &hc = HeuristicCollector::instance();
  hc.begin(119, "Round-Trip ΔE Measurement");

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

    // Initialize CLUT interpolation structures (m_MaxGridPoint, m_nNodes, m_nOffset)
    // Required before any Interp*d() call — Read() loads data but not interp metadata
    clutB->Begin();

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
      icUInt8Number clutBInput = mbbB->InputChannels();
      if (clutBInput == 3)
        clutB->Interp3d(roundTrip, pcsOut);
      else if (clutBInput == 4)
        clutB->Interp4d(roundTrip, pcsOut);
      else if (clutBInput == 1)
        clutB->Interp1d(roundTrip, pcsOut);
      else
        continue;

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

      hc.info("      %s intent (%d samples):", pairs[p].name, samples);
      hc.info("        AToB%d→BToA%d: avg ΔE=%.4f  max ΔE=%.4f",
             p, p, avgDE, maxDE);

      if (maxDE > 5.0) {
        hc.warn("HEURISTIC: max ΔE > 5.0 — poor round-trip fidelity");
      } else if (maxDE > 2.0) {
        hc.info("        max ΔE > 2.0 — moderate round-trip error");
      }
    }
  }

  if (!anyMeasured) {
    hc.info("      No AToB/BToA CLUT pairs available for ΔE measurement");
  }

  return hc.end("Round-trip ΔE within acceptable range");
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
  auto &hc = HeuristicCollector::instance();
  hc.begin(120, "Curve Invertibility Assessment");

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
          hc.info("      %s: gamma=%.4f — invertible (1/gamma=%.4f)",
                 trcNames[t], (double)gamma, 1.0/(double)gamma);
        } else {
          hc.warn("HEURISTIC: %s: gamma=%.6f ≈ 0 — NOT invertible", trcNames[t], (double)gamma);
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
      hc.warn("HEURISTIC: %s: flat curve (range=%.6f) — NOT invertible", trcNames[t], range);
      hc.cweNote("CWE-682: Degenerate transform destroys color data");
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
    hc.info("      %s (%u entries): inv avg err=%.6f  max err=%.6f",
           trcNames[t], nEntries, avgErr, maxErr);

    // Check invertibility: max round-trip error > 1% indicates poor transform fidelity
    if (maxErr > 0.01) {
      hc.warn("HEURISTIC: %s: poor invertibility (max err > 1%%)", trcNames[t]);
    }

    curvesChecked++;
  }

  if (curvesChecked == 0) {
    hc.info("      No TRC curves found for invertibility check");
  }

  return hc.end("TRC curves are invertible");
}

// =====================================================================
// H121: Characterization Data Round-Trip Assessment (Feedback Q4)
// If targ (characterization data) is CGATS format, reports data set size
// and flags whether the profile has matching transform tags for evaluation.
// =====================================================================

// ============================================================================
// Sub-Dispatcher: RunComplianceHeuristics (H103-H120)
// Replaces 18 inline calls in IccAnalyzerSecurity.cpp with a single call.
// ============================================================================
int RunComplianceHeuristics(CIccProfile *pIcc, const char *filename)
{
  int heuristicCount = 0;
  heuristicCount += RunHeuristic_H103_PCC(pIcc);
  heuristicCount += RunHeuristic_H104_PRMG(pIcc, filename);
  heuristicCount += RunHeuristic_H105_MatrixTRC(pIcc);
  heuristicCount += RunHeuristic_H106_EnvVar(pIcc);
  heuristicCount += RunHeuristic_H107_ChannelCrossCheck(pIcc);
  heuristicCount += RunHeuristic_H108_PrivateTags(pIcc);
  heuristicCount += RunHeuristic_H109_ShellcodePatterns(filename);
  heuristicCount += RunHeuristic_H110_ClassTagValidation(pIcc);
  heuristicCount += RunHeuristic_H111_ReservedBytes(filename);
  heuristicCount += RunHeuristic_H112_WtptValidation(pIcc);
  heuristicCount += RunHeuristic_H113_RoundTripFidelity(pIcc);
  heuristicCount += RunHeuristic_H114_CurveSmoothness(pIcc);
  heuristicCount += RunHeuristic_H115_CharacterizationData(pIcc);
  heuristicCount += RunHeuristic_H116_CprtDescEncoding(pIcc);
  heuristicCount += RunHeuristic_H117_TagTypeAllowed(pIcc);
  heuristicCount += RunHeuristic_H118_CalcCostEstimate(pIcc);
  heuristicCount += RunHeuristic_H119_RoundTripDeltaE(pIcc);
  heuristicCount += RunHeuristic_H120_CurveInvertibility(pIcc);
  return heuristicCount;
}
