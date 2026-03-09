/*
 * IccHeuristicsIntegrity.cpp — Profile integrity heuristics (H121-H138)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * Extracted from IccHeuristicsLibrary.cpp as part of codebase modernization.
 */

#include "IccHeuristicsIntegrity.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerSignatures.h"
#include "IccAnalyzerSafeArithmetic.h"
#include "IccHeuristicsHelpers.h"
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

int RunHeuristic_H121_CharDataRoundTrip(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H121] Characterization Data Round-Trip Capability\n");

  CIccTag *targTag = pIcc->FindTag(icSigCharTargetTag);
  if (!targTag) {
    printf("      [INFO] No characterization data (targ) tag — cannot assess\n\n");
    return 0;
  }

  CIccTagText *textTag = dynamic_cast<CIccTagText*>(targTag);
  if (!textTag || !textTag->GetText()) {
    printf("      %s[WARN]  targ tag present but not readable as text%s\n",
           ColorWarning(), ColorReset());
    printf("\n");
    return 1;
  }

  const char *text = textTag->GetText();
  size_t len = strlen(text);

  int dataSetCount = 0;
  int fieldCount = 0;
  bool hasCGATS = false;
  bool hasBeginData = false;

  if (strncmp(text, "BEGIN_DATA_FORMAT", 17) == 0 ||
      strncmp(text, "CGATS", 5) == 0 ||
      strncmp(text, "CTI", 3) == 0 ||
      strncmp(text, "NUMBER_OF_SETS", 14) == 0) {
    hasCGATS = true;
  }

  const char *p = text;
  while ((p = strstr(p, "NUMBER_OF_SETS")) != NULL) {
    p += 14;
    while (*p == ' ' || *p == '\t') p++;
    dataSetCount = atoi(p);
  }
  p = text;
  while ((p = strstr(p, "NUMBER_OF_FIELDS")) != NULL) {
    p += 16;
    while (*p == ' ' || *p == '\t') p++;
    fieldCount = atoi(p);
  }
  if (strstr(text, "BEGIN_DATA")) hasBeginData = true;

  printf("      Characterization data: %zu bytes\n", len);
  if (hasCGATS) {
    printf("      Format: CGATS/IT8\n");
    if (dataSetCount > 0) printf("      Data sets: %d\n", dataSetCount);
    if (fieldCount > 0)   printf("      Fields: %d\n", fieldCount);
    if (hasBeginData)      printf("      Data section: present\n");
  }

  bool hasAToB = (pIcc->FindTag(icSigAToB0Tag) != NULL ||
                  pIcc->FindTag(icSigAToB1Tag) != NULL);
  bool hasBToA = (pIcc->FindTag(icSigBToA0Tag) != NULL ||
                  pIcc->FindTag(icSigBToA1Tag) != NULL);

  if (hasCGATS && hasBeginData && dataSetCount > 0 && hasAToB && hasBToA) {
    printf("      %s[OK] Profile has both characterization data and round-trip transforms%s\n",
           ColorSuccess(), ColorReset());
    printf("      [INFO] Full ΔE evaluation requires external tool (iccRoundTrip)\n");
  } else if (hasCGATS && hasBeginData && dataSetCount > 0) {
    printf("      [INFO] Characterization data present but missing AToB/BToA for round-trip\n");
  } else {
    printf("      [INFO] Characterization data format not recognized as evaluable CGATS\n");
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H122: Deep Tag Type Encoding Validation (Feedback C1)
// Validates specific tag data ranges and structural correctness
// beyond what the iccDEV library checks.
// =====================================================================
int RunHeuristic_H122_TagEncoding(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H122] Tag Type Encoding Validation\n");

  int checked = 0;

  // XYZ tags: values should be in reasonable range
  icTagSignature xyzTags[] = {
    icSigMediaWhitePointTag, icSigLuminanceTag,
    icSigRedMatrixColumnTag, icSigGreenMatrixColumnTag, icSigBlueMatrixColumnTag,
    (icTagSignature)0
  };
  const char *xyzNames[] = {"wtpt", "lumi", "rXYZ", "gXYZ", "bXYZ"};

  for (int t = 0; xyzTags[t] != (icTagSignature)0; t++) {
    CIccTagXYZ *xyzTag = FindAndCast<CIccTagXYZ>(pIcc, xyzTags[t]);
    if (!xyzTag || xyzTag->GetSize() < 1) continue;

    checked++;
    icXYZNumber *xyz = &(*xyzTag)[0];
    double X = icFtoD(xyz->X);
    double Y = icFtoD(xyz->Y);
    double Z = icFtoD(xyz->Z);

    if (X < -5.0 || X > 10.0 || Y < -5.0 || Y > 10.0 || Z < -5.0 || Z > 10.0) {
      printf("      %s[WARN]  '%s': XYZ(%.4f, %.4f, %.4f) out of expected range [-5,10]%s\n",
             ColorWarning(), xyzNames[t], X, Y, Z, ColorReset());
      printf("       %sCWE-20: Value out of specification range%s\n",
             ColorWarning(), ColorReset());
      heuristicCount++;
    }
  }

  // Measurement tag: observer and geometry validation
  CIccTag *measTag = pIcc->FindTag(icSigMeasurementTag);
  if (measTag) {
    checked++;
    CIccTagMeasurement *meas = dynamic_cast<CIccTagMeasurement*>(measTag);
    if (meas) {
      icMeasurement &m = meas->m_Data;
      if (m.stdObserver != icStdObs1931TwoDegrees &&
          m.stdObserver != icStdObs1964TenDegrees &&
          m.stdObserver != icStdObsCustom) {
        printf("      %s[WARN]  meas: unknown standard observer value %u%s\n",
               ColorWarning(), (unsigned)m.stdObserver, ColorReset());
        heuristicCount++;
      }
      if (m.geometry != icGeometryUnknown &&
          m.geometry != icGeometry045or450 &&
          m.geometry != icGeometry0dord0) {
        printf("      %s[WARN]  meas: unknown geometry value %u%s\n",
               ColorWarning(), (unsigned)m.geometry, ColorReset());
        heuristicCount++;
      }
    }
  }

  // Chromaticity tag: values should be in [0, 1]
  CIccTag *chrmTag = pIcc->FindTag(icSigChromaticityTag);
  if (chrmTag) {
    checked++;
    CIccTagChromaticity *chrm = dynamic_cast<CIccTagChromaticity*>(chrmTag);
    if (chrm) {
      icUInt32Number nChan = chrm->GetSize();
      for (icUInt32Number c = 0; c < nChan && c < 15; c++) {
        icChromaticityNumber cn = (*chrm)[c];
        double x = icUFtoD(cn.x);
        double y = icUFtoD(cn.y);
        if (x < 0.0 || x > 1.0 || y < 0.0 || y > 1.0) {
          printf("      %s[WARN]  chrm ch%u: (%.4f, %.4f) outside [0,1]%s\n",
                 ColorWarning(), (unsigned)c, x, y, ColorReset());
          heuristicCount++;
        }
      }
    }
  }

  if (heuristicCount == 0 && checked > 0) {
    printf("      %s[OK] %d tag types validated — encoding correct%s\n",
           ColorSuccess(), checked, ColorReset());
  } else if (checked == 0) {
    printf("      [INFO] No applicable tags for deep encoding validation\n");
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H123: Non-Required Tag Classification (Feedback C5)
// Cross-references present tags against the required+optional set for
// the profile class. Tags not in either set are flagged.
// =====================================================================
int RunHeuristic_H123_NonRequiredTags(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H123] Non-Required Tag Classification\n");

  icProfileClassSignature cls = pIcc->m_Header.deviceClass;

  // Common required tags (all classes)
  std::set<icTagSignature> allowed;
  allowed.insert(icSigProfileDescriptionTag);
  allowed.insert(icSigCopyrightTag);
  allowed.insert(icSigMediaWhitePointTag);
  allowed.insert(icSigChromaticAdaptationTag);

  // Common optional tags (all classes)
  allowed.insert(icSigCalibrationDateTimeTag);
  allowed.insert(icSigCharTargetTag);
  allowed.insert(icSigChromaticityTag);
  allowed.insert(icSigDeviceMfgDescTag);
  allowed.insert(icSigDeviceModelDescTag);
  allowed.insert(icSigMeasurementTag);
  allowed.insert(icSigTechnologyTag);
  allowed.insert(icSigViewingCondDescTag);
  allowed.insert(icSigViewingConditionsTag);
  allowed.insert(icSigProfileSequenceDescTag);
  allowed.insert(icSigProfileSequceIdTag);
  allowed.insert(icSigColorantOrderTag);
  allowed.insert(icSigColorantTableTag);
  allowed.insert(icSigColorantTableOutTag);
  allowed.insert(icSigNamedColor2Tag);
  allowed.insert(icSigOutputResponseTag);
  allowed.insert(icSigGamutTag);
  allowed.insert(icSigPreview0Tag);
  allowed.insert(icSigPreview1Tag);
  allowed.insert(icSigPreview2Tag);

  // Class-specific tags
  switch (cls) {
    case icSigInputClass:
    case icSigDisplayClass:
    case icSigOutputClass:
    case icSigColorSpaceClass:
      allowed.insert(icSigAToB0Tag); allowed.insert(icSigAToB1Tag); allowed.insert(icSigAToB2Tag);
      allowed.insert(icSigBToA0Tag); allowed.insert(icSigBToA1Tag); allowed.insert(icSigBToA2Tag);
      allowed.insert(icSigRedMatrixColumnTag); allowed.insert(icSigGreenMatrixColumnTag);
      allowed.insert(icSigBlueMatrixColumnTag);
      allowed.insert(icSigRedTRCTag); allowed.insert(icSigGreenTRCTag); allowed.insert(icSigBlueTRCTag);
      allowed.insert(icSigGrayTRCTag);
      allowed.insert(icSigLuminanceTag);
      allowed.insert(icSigMediaBlackPointTag);
      // D2B/B2D v5 tags
      allowed.insert((icTagSignature)0x44324230);
      allowed.insert((icTagSignature)0x44324231);
      allowed.insert((icTagSignature)0x44324232);
      allowed.insert((icTagSignature)0x42324430);
      allowed.insert((icTagSignature)0x42324431);
      allowed.insert((icTagSignature)0x42324432);
      break;
    case icSigLinkClass:
      allowed.insert(icSigAToB0Tag);
      allowed.insert(icSigProfileSequenceDescTag);
      break;
    case icSigAbstractClass:
      allowed.insert(icSigAToB0Tag);
      allowed.insert((icTagSignature)0x44324230);
      allowed.insert((icTagSignature)0x42324430);
      break;
    case icSigNamedColorClass:
      allowed.insert(icSigNamedColor2Tag);
      break;
    default:
      break;
  }

  int unclassified = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    icTagSignature sig = it->TagInfo.sig;
    if (allowed.find(sig) == allowed.end()) {
      char sigStr[5] = {};
      SigToChars(sig, sigStr);

      bool isUpper = true;
      for (int c = 0; c < 4; c++) {
        if (sigStr[c] < 0x20 || sigStr[c] > 0x7E) { isUpper = false; break; }
      }
      if (!isUpper) continue;

      printf("      %s[INFO] '%s' (0x%08X): not required/optional for class '%c%c%c%c'%s\n",
             ColorInfo(), sigStr, (unsigned)sig,
             static_cast<char>(static_cast<unsigned char>((cls >> 24) & 0xFF)),
             static_cast<char>(static_cast<unsigned char>((cls >> 16) & 0xFF)),
             static_cast<char>(static_cast<unsigned char>((cls >> 8) & 0xFF)),
             static_cast<char>(static_cast<unsigned char>(cls & 0xFF)), ColorReset());
      unclassified++;
    }
  }

  if (unclassified > 0) {
    printf("      %s[WARN]  %d tag(s) not in required/optional set for this profile class%s\n",
           ColorWarning(), unclassified, ColorReset());
    printf("       %sCWE-20: Non-standard tags should be registered as private%s\n",
           ColorWarning(), ColorReset());
    heuristicCount += unclassified;
  } else {
    printf("      %s[OK] All tags are required or optional for this profile class%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H124: Version-Tag Correspondence (Feedback C11)
// Validates that tags present are appropriate for the declared ICC version.
// =====================================================================
int RunHeuristic_H124_VersionTags(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H124] Version-Tag Correspondence\n");

  icUInt32Number version = pIcc->m_Header.version;
  int majorVer = (version >> 24) & 0xFF;

  // Tags introduced in v4 (not valid in v2)
  static const icTagSignature v4OnlyTags[] = {
    icSigChromaticAdaptationTag,
    icSigColorantOrderTag,
    icSigColorantTableTag,
    icSigColorantTableOutTag,
    icSigProfileSequceIdTag,
    (icTagSignature)0
  };

  // Tags deprecated in v4
  static const icTagSignature v2OnlyTags[] = {
    icSigMediaBlackPointTag,
    (icTagSignature)0
  };

  // v5 tags (D2B/B2D)
  static const icTagSignature v5Tags[] = {
    (icTagSignature)0x44324230, // D2B0
    (icTagSignature)0x44324231,
    (icTagSignature)0x44324232,
    (icTagSignature)0x42324430, // B2D0
    (icTagSignature)0x42324431,
    (icTagSignature)0x42324432,
    (icTagSignature)0
  };

  int violations = 0;

  if (majorVer <= 2) {
    for (int t = 0; v4OnlyTags[t] != (icTagSignature)0; t++) {
      if (pIcc->FindTag(v4OnlyTags[t])) {
        icUInt32Number sig = (icUInt32Number)v4OnlyTags[t];
        printf("      %s[WARN]  v%d profile contains v4+ tag (0x%08X)%s\n",
               ColorWarning(), majorVer, sig, ColorReset());
        violations++;
      }
    }
    for (int t = 0; v5Tags[t] != (icTagSignature)0; t++) {
      if (pIcc->FindTag(v5Tags[t])) {
        icUInt32Number sig = (icUInt32Number)v5Tags[t];
        printf("      %s[WARN]  v%d profile contains v5 tag (0x%08X)%s\n",
               ColorWarning(), majorVer, sig, ColorReset());
        violations++;
      }
    }
  } else if (majorVer == 4) {
    for (int t = 0; v5Tags[t] != (icTagSignature)0; t++) {
      if (pIcc->FindTag(v5Tags[t])) {
        icUInt32Number sig = (icUInt32Number)v5Tags[t];
        printf("      %s[WARN]  v4 profile contains v5 tag (0x%08X)%s\n",
               ColorWarning(), sig, ColorReset());
        violations++;
      }
    }
  }

  if (majorVer >= 4) {
    for (int t = 0; v2OnlyTags[t] != (icTagSignature)0; t++) {
      if (pIcc->FindTag(v2OnlyTags[t])) {
        icUInt32Number sig = (icUInt32Number)v2OnlyTags[t];
        printf("      %s[INFO] v%d profile contains deprecated v2 tag (0x%08X)%s\n",
               ColorInfo(), majorVer, sig, ColorReset());
      }
    }
  }

  if (violations > 0) {
    printf("      %s[WARN]  %d version-tag mismatch(es)%s\n",
           ColorWarning(), violations, ColorReset());
    printf("       %sCWE-20: Tags do not correspond to declared profile version%s\n",
           ColorWarning(), ColorReset());
    heuristicCount += violations;
  } else {
    printf("      %s[OK] Tags correspond to profile version %d%s\n",
           ColorSuccess(), majorVer, ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H125: Overall Transform Smoothness (Feedback Q3)
// Samples the primary LUT at grid points and measures smoothness of
// color transitions between adjacent grid nodes.
// =====================================================================
int RunHeuristic_H125_TransformSmoothness(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H125] Overall Transform Smoothness\n");

  icTagSignature lutTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigBToA0Tag,
    (icTagSignature)0
  };
  const char *lutNames[] = {"AToB0", "AToB1", "BToA0"};

  bool anyMeasured = false;

  for (int t = 0; lutTags[t] != (icTagSignature)0; t++) {
    CIccMBB *mbb = FindAndCast<CIccMBB>(pIcc, lutTags[t]);
    if (!mbb) continue;

    CIccCLUT *clut = mbb->GetCLUT();
    if (!clut) continue;

    uint32_t grid = clut->GridPoints();
    uint32_t inCh = mbb->InputChannels();
    uint32_t outCh = mbb->OutputChannels();

    if (inCh < 1 || inCh > 15 || outCh < 1 || outCh > 15 || grid < 3) continue;

    uint64_t totalNodes = 1;
    for (uint32_t d = 0; d < inCh; d++) {
      totalNodes *= grid;
      if (totalNodes > 50000) break;
    }
    if (totalNodes > 50000 || totalNodes < 4) continue;

    double maxJump = 0.0;
    double sumJump = 0.0;
    int pairs = 0;

    for (uint64_t idx = 1; idx < totalNodes; idx++) {
      icFloatNumber curr[16] = {};
      icFloatNumber prev[16] = {};
      icFloatNumber *currData = clut->GetData((icUInt32Number)(idx * outCh));
      icFloatNumber *prevData = clut->GetData((icUInt32Number)((idx - 1) * outCh));
      if (!currData || !prevData) continue;
      for (uint32_t c = 0; c < outCh; c++) {
        curr[c] = currData[c];
        prev[c] = prevData[c];
      }

      double dist2 = 0.0;
      for (uint32_t c = 0; c < outCh && c < 3; c++) {
        double d = (double)curr[c] - (double)prev[c];
        dist2 += d * d;
      }
      double dist = sqrt(dist2);
      sumJump += dist;
      if (dist > maxJump) maxJump = dist;
      pairs++;
    }

    if (pairs > 0) {
      anyMeasured = true;
      double avgJump = sumJump / (double)pairs;
      printf("      %s (grid=%u, %uin/%uout): avg step=%.6f  max step=%.6f\n",
             lutNames[t], grid, inCh, outCh, avgJump, maxJump);

      if (maxJump > 0.5) {
        printf("      %s[WARN]  %s: large discontinuity (max step > 0.5) — poor smoothness%s\n",
               ColorWarning(), lutNames[t], ColorReset());
        heuristicCount++;
      } else if (maxJump > 0.1) {
        printf("      %s[INFO] %s: moderate discontinuity (max step > 0.1)%s\n",
               ColorInfo(), lutNames[t], ColorReset());
      } else {
        printf("      %s[OK] %s: smooth transitions%s\n",
               ColorSuccess(), lutNames[t], ColorReset());
      }
    }
  }

  if (!anyMeasured) {
    printf("      [INFO] No suitable LUT tags for smoothness measurement\n");
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H126: Private Tag Malware Content Scan (Feedback S12)
// Scans data within private/unregistered tags for PE, ELF, script,
// and other executable content signatures.
// =====================================================================
int RunHeuristic_H126_PrivateTagMalware(CIccProfile *pIcc, const char *filename) {
  // Scan data within private/unregistered tags for PE, ELF, script,
  // and other executable content signatures that indicate embedded malware.
  int heuristicCount = 0;

  printf("[H126] Private Tag Malware Content Scan\n");

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
    (icTagSignature)0x44324230, (icTagSignature)0x44324231,
    (icTagSignature)0x44324232,
    (icTagSignature)0x42324430, (icTagSignature)0x42324431,
    (icTagSignature)0x42324432,
    (icTagSignature)0
  };

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("      [INFO] Cannot open file for private tag scan\n\n");
    return 0;
  }

  // Malware signatures to look for in private tag data
  static const struct {
    const unsigned char sig[8];
    int len;
    const char *name;
  } malwareSigs[] = {
    {{0x4D, 0x5A, 0x90, 0x00}, 4, "PE/MZ executable header"},
    {{0x7F, 0x45, 0x4C, 0x46}, 4, "ELF executable header"},
    {{0xCA, 0xFE, 0xBA, 0xBE}, 4, "Mach-O/Java class header"},
    {{0xFE, 0xED, 0xFA, 0xCE}, 4, "Mach-O 32-bit header"},
    {{0xFE, 0xED, 0xFA, 0xCF}, 4, "Mach-O 64-bit header"},
    {{0xCF, 0xFA, 0xED, 0xFE}, 4, "Mach-O 64-bit (reversed)"},
    {{0x50, 0x4B, 0x03, 0x04}, 4, "ZIP/JAR archive"},
    {{0x23, 0x21, 0x2F}, 3, "Script shebang (#!/)"},
    {{0x3C, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74}, 7, "HTML <script tag"},
    {{0}, 0, NULL}
  };

  int privateScanned = 0;
  int findings = 0;

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    icTagSignature sig = it->TagInfo.sig;
    bool isKnown = false;
    for (int k = 0; knownTags[k] != (icTagSignature)0; k++) {
      if (sig == knownTags[k]) { isKnown = true; break; }
    }
    if (isKnown) continue;

    uint32_t offset = it->TagInfo.offset;
    uint32_t size = it->TagInfo.size;
    if (size < 4 || size > 10 * 1024 * 1024 || offset < 128) continue;

    std::vector<unsigned char> buf(size < 65536 ? size : 65536);
    if (fseek(fh.fp, offset, SEEK_SET) != 0) continue;
    size_t bytesRead = fread(buf.data(), 1, buf.size(), fh.fp);
    if (bytesRead < 4) continue;

    privateScanned++;

    for (int s = 0; malwareSigs[s].name != NULL; s++) {
      int sigLen = malwareSigs[s].len;
      for (size_t pos = 0; pos + sigLen <= bytesRead; pos++) {
        bool match = true;
        for (int b = 0; b < sigLen; b++) {
          if (buf[pos + b] != malwareSigs[s].sig[b]) { match = false; break; }
        }
        if (match) {
          char sigStr[5] = {};
          SigToChars(sig, sigStr);
          printf("      %s[CRITICAL] Private tag '%s': %s at offset +%zu%s\n",
                 ColorCritical(), sigStr, malwareSigs[s].name, pos, ColorReset());
          printf("       %sCWE-506: Embedded malicious code in private tag data%s\n",
                 ColorCritical(), ColorReset());
          findings++;
          heuristicCount++;
          break;
        }
      }
    }
  }

  if (findings == 0 && privateScanned > 0) {
    printf("      %s[OK] %d private tag(s) scanned — no malware signatures found%s\n",
           ColorSuccess(), privateScanned, ColorReset());
  } else if (privateScanned == 0) {
    printf("      [INFO] No private tags to scan\n");
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H127: Private Tag Registry Lookup (Feedback C7)
// Offline table of known registered private tag signatures from the
// ICC Private Tag Registry.
// =====================================================================
int RunHeuristic_H127_PrivateTagRegistry(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H127] Private Tag Registry Check\n");

  // Known registered private tags from ICC Private Tag Registry
  // Format: 4-byte signature → registrant name
  static const struct {
    icUInt32Number sig;
    const char *registrant;
  } registry[] = {
    {0x70736564, "Adobe ('psed')"},          // Photoshop editing data
    {0x70736571, "Adobe ('pseq')"},          // Photoshop sequence
    {0x64657363, "Various ('desc')"},        // Description (standard but often private-used)
    {0x76756564, "Various ('vued')"},        // Viewing conditions desc
    {0x4D535446, "Microsoft ('MSTF')"},      // Microsoft tag
    {0x41504C45, "Apple ('APLE')"},          // Apple private
    {0x61617074, "Apple ('aapt')"},          // Apple AAP
    {0x6170706C, "Apple ('appl')"},          // Apple
    {0x43474154, "CGATS ('CGAT')"},          // CGATS data
    {0x44657669, "Device-specific ('Devi')"},
    {0, NULL}
  };

  int privateCount = 0;
  int registered = 0;
  int unregistered = 0;

  static const icTagSignature knownStd[] = {
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
    (icTagSignature)0x44324230, (icTagSignature)0x44324231,
    (icTagSignature)0x44324232,
    (icTagSignature)0x42324430, (icTagSignature)0x42324431,
    (icTagSignature)0x42324432,
    (icTagSignature)0
  };

  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    icTagSignature sig = it->TagInfo.sig;
    bool isStd = false;
    for (int k = 0; knownStd[k] != (icTagSignature)0; k++) {
      if (sig == knownStd[k]) { isStd = true; break; }
    }
    if (isStd) continue;

    privateCount++;
    icUInt32Number sigVal = (icUInt32Number)sig;
    bool found = false;
    for (int r = 0; registry[r].registrant != NULL; r++) {
      if (sigVal == registry[r].sig) {
        char sigStr[5] = {};
        sigStr[0] = (char)(static_cast<unsigned char>((sigVal >> 24) & 0xFF));
        sigStr[1] = (char)(static_cast<unsigned char>((sigVal >> 16) & 0xFF));
        sigStr[2] = (char)(static_cast<unsigned char>((sigVal >> 8) & 0xFF));
        sigStr[3] = (char)(static_cast<unsigned char>(sigVal & 0xFF));
        printf("      '%s': registered by %s\n", sigStr, registry[r].registrant);
        found = true;
        registered++;
        break;
      }
    }
    if (!found) {
      char sigStr[5] = {};
      sigStr[0] = (char)(static_cast<unsigned char>((sigVal >> 24) & 0xFF));
      sigStr[1] = (char)(static_cast<unsigned char>((sigVal >> 16) & 0xFF));
      sigStr[2] = (char)(static_cast<unsigned char>((sigVal >> 8) & 0xFF));
      sigStr[3] = (char)(static_cast<unsigned char>(sigVal & 0xFF));
      printf("      %s[WARN]  '%s' (0x%08X): not found in private tag registry%s\n",
             ColorWarning(), sigStr, sigVal, ColorReset());
      printf("       %sCWE-20: Undocumented private tag%s\n",
             ColorWarning(), ColorReset());
      unregistered++;
      heuristicCount++;
    }
  }

  if (privateCount == 0) {
    printf("      %s[OK] No private tags present%s\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("      Summary: %d private tag(s) — %d registered, %d undocumented\n",
           privateCount, registered, unregistered);
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H128: Version BCD Encoding Validation (ICC.1-2022-05 §7.2.4)
// Byte 8 = major version, byte 9 = minor.bugfix (BCD nibbles),
// bytes 10-11 must be 0x0000.
// =====================================================================
int RunHeuristic_H128_VersionBCD(const char *filename) {
  int heuristicCount = 0;

  printf("[H128] Version BCD Encoding Validation\n");

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("      %s[ERROR] Cannot open file%s\n", ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }

  unsigned char hdr[12];
  if (fread(hdr, 1, 12, fh.fp) != 12) {
    printf("      %s[WARN]  File too small for version field%s\n",
           ColorWarning(), ColorReset());
    printf("\n");
    return 1;
  }

  unsigned char major = hdr[8];
  unsigned char minorBugfix = hdr[9];
  unsigned char reserved10 = hdr[10];
  unsigned char reserved11 = hdr[11];

  int minorNibble = (minorBugfix >> 4) & 0x0F;
  int bugfixNibble = minorBugfix & 0x0F;

  printf("      Version bytes: %02X %02X %02X %02X → v%d.%d.%d\n",
         major, minorBugfix, reserved10, reserved11,
         major, minorNibble, bugfixNibble);

  // Major version: valid values are 2, 4, 5
  if (major != 2 && major != 4 && major != 5) {
    printf("      %s[WARN]  Major version %d not in {2, 4, 5}%s\n",
           ColorWarning(), major, ColorReset());
    heuristicCount++;
  }

  // BCD nibble validation: each nibble must be 0-9
  if (minorNibble > 9 || bugfixNibble > 9) {
    printf("      %s[WARN]  Non-BCD nibble in version byte 9: 0x%02X (minor=%d, bugfix=%d)%s\n",
           ColorWarning(), minorBugfix, minorNibble, bugfixNibble, ColorReset());
    printf("       %sCWE-20: Version field BCD encoding violation%s\n",
           ColorWarning(), ColorReset());
    heuristicCount++;
  }

  // Bytes 10-11 must be zero
  if (reserved10 != 0 || reserved11 != 0) {
    printf("      %s[WARN]  Version reserved bytes 10-11 non-zero: 0x%02X 0x%02X%s\n",
           ColorWarning(), reserved10, reserved11, ColorReset());
    printf("       %sCWE-20: Reserved version bytes must be 0 (ICC.1-2022-05 §7.2.4)%s\n",
           ColorWarning(), ColorReset());
    heuristicCount++;
  }

  if (heuristicCount == 0) {
    printf("      %s[OK] Version BCD encoding is valid%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H129: PCS Illuminant Exact D50 Validation (ICC.1-2022-05 §7.2.16)
// Raw bytes 68-79: D50 as s15Fixed16Number
// Expected: X=0x0000F6D6, Y=0x00010000, Z=0x0000D32D
// =====================================================================
int RunHeuristic_H129_PCSIlluminantD50(const char *filename) {
  int heuristicCount = 0;

  printf("[H129] PCS Illuminant Exact D50 Check\n");

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("      %s[ERROR] Cannot open file%s\n", ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }

  unsigned char hdr[80];
  if (fread(hdr, 1, 80, fh.fp) != 80) {
    printf("      %s[WARN]  File too small for illuminant field%s\n",
           ColorWarning(), ColorReset());
    printf("\n");
    return 1;
  }

  // Read s15Fixed16Number values from bytes 68-79
  int32_t rawX = (int32_t)((uint32_t)hdr[68] << 24 | (uint32_t)hdr[69] << 16 |
                            (uint32_t)hdr[70] << 8  | (uint32_t)hdr[71]);
  int32_t rawY = (int32_t)((uint32_t)hdr[72] << 24 | (uint32_t)hdr[73] << 16 |
                            (uint32_t)hdr[74] << 8  | (uint32_t)hdr[75]);
  int32_t rawZ = (int32_t)((uint32_t)hdr[76] << 24 | (uint32_t)hdr[77] << 16 |
                            (uint32_t)hdr[78] << 8  | (uint32_t)hdr[79]);

  // D50 exact values: X=0x0000F6D6 (0.9642), Y=0x00010000 (1.0000), Z=0x0000D32D (0.8249)
  const int32_t d50X = 0x0000F6D6;
  const int32_t d50Y = 0x00010000;
  const int32_t d50Z = 0x0000D32D;

  double fX = (double)rawX / 65536.0;
  double fY = (double)rawY / 65536.0;
  double fZ = (double)rawZ / 65536.0;

  printf("      Raw bytes: X=0x%08X Y=0x%08X Z=0x%08X\n",
         (unsigned)rawX, (unsigned)rawY, (unsigned)rawZ);
  printf("      Float:     X=%.6f   Y=%.6f   Z=%.6f\n", fX, fY, fZ);
  printf("      D50 spec:  X=0x0000F6D6 Y=0x00010000 Z=0x0000D32D\n");

  // Allow ±1 LSB tolerance for s15Fixed16 rounding
  // Note: ICC.2 (v5) spectral profiles may use non-D50 PCS illuminant
  unsigned char major = hdr[8];
  if (abs(rawX - d50X) > 1 || abs(rawY - d50Y) > 1 || abs(rawZ - d50Z) > 1) {
    if (major >= 5) {
      printf("      %s[INFO] PCS illuminant is not D50 (valid for ICC.2/v5 spectral profiles)%s\n",
             ColorInfo(), ColorReset());
    } else {
      printf("      %s[WARN]  PCS illuminant does not match D50 (>1 LSB deviation)%s\n",
             ColorWarning(), ColorReset());
      printf("       %sCWE-20: ICC.1-2022-05 §7.2.16 requires exact D50 for v2/v4%s\n",
             ColorWarning(), ColorReset());
      heuristicCount++;
    }
    heuristicCount++;
  } else {
    printf("      %s[OK] PCS illuminant is exact D50%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H130: Tag Data 4-Byte Alignment Check (ICC.1-2022-05 §7.3.1)
// All tag data elements must start at 4-byte aligned offsets.
// =====================================================================
int RunHeuristic_H130_TagAlignment(const char *filename) {
  int heuristicCount = 0;

  printf("[H130] Tag Data 4-Byte Alignment\n");

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("      %s[ERROR] Cannot open file%s\n", ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }

  if (fh.fileSize < 132) {
    printf("      %s[WARN]  File too small for tag table%s\n",
           ColorWarning(), ColorReset());
    printf("\n");
    return 1;
  }
  size_t fsz = (size_t)fh.fileSize;

  unsigned char tcBuf[4];
  fseek(fh.fp, 128, SEEK_SET);
  if (fread(tcBuf, 1, 4, fh.fp) != 4) { printf("\n"); return 1; }

  uint32_t tagCount = ((uint32_t)tcBuf[0] << 24) | ((uint32_t)tcBuf[1] << 16) |
                      ((uint32_t)tcBuf[2] << 8)  | tcBuf[3];

  if (tagCount > 1000) {
    printf("      %s[WARN]  Tag count %u too large — skipping%s\n",
           ColorWarning(), tagCount, ColorReset());
    printf("\n");
    return 1;
  }

  int misaligned = 0;
  int checked = 0;

  for (uint32_t i = 0; i < tagCount && i < 256; i++) {
    size_t ePos = 132 + i * 12;
    if (ePos + 12 > fsz) break;

    unsigned char entry[12];
    fseek(fh.fp, (long)ePos, SEEK_SET);
    if (fread(entry, 1, 12, fh.fp) != 12) break;

    uint32_t offset = ((uint32_t)entry[4] << 24) | ((uint32_t)entry[5] << 16) |
                      ((uint32_t)entry[6] << 8)  | entry[7];

    checked++;
    if (offset != 0 && (offset % 4) != 0) {
      char sigStr[5] = {};
      sigStr[0] = (char)entry[0]; sigStr[1] = (char)entry[1];
      sigStr[2] = (char)entry[2]; sigStr[3] = (char)entry[3];
      printf("      %s[WARN]  Tag '%s': offset %u not 4-byte aligned (mod 4 = %u)%s\n",
             ColorWarning(), sigStr, offset, offset % 4, ColorReset());
      misaligned++;
    }
  }

  if (misaligned > 0) {
    printf("      %s[WARN]  %d of %d tag(s) misaligned (ICC.1-2022-05 §7.3.1)%s\n",
           ColorWarning(), misaligned, checked, ColorReset());
    printf("       %sCWE-20: Tag data must be 4-byte aligned%s\n",
           ColorWarning(), ColorReset());
    heuristicCount += misaligned;
  } else if (checked > 0) {
    printf("      %s[OK] All %d tags are 4-byte aligned%s\n",
           ColorSuccess(), checked, ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H131: Profile ID (MD5) Validation (ICC.1-2022-05 §7.2.18)
// Computes MD5 of profile with bytes 44-47 (flags), 64-67 (intent),
// and 84-99 (profile ID) zeroed. Compares against stored Profile ID.
// =====================================================================
int RunHeuristic_H131_ProfileIdMD5(const char *filename) {
  int heuristicCount = 0;

  printf("[H131] Profile ID (MD5) Validation\n");

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("      %s[ERROR] Cannot open file%s\n", ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }

  if (fh.fileSize < 128) {
    printf("      %s[WARN]  File too small for header%s\n",
           ColorWarning(), ColorReset());
    printf("\n");
    return 1;
  }

  // Read stored Profile ID from bytes 84-99
  unsigned char storedId[16];
  fseek(fh.fp, 84, SEEK_SET);
  if (fread(storedId, 1, 16, fh.fp) != 16) { printf("\n"); return 1; }

  bool idIsZero = true;
  for (int i = 0; i < 16; i++) {
    if (storedId[i] != 0) { idIsZero = false; break; }
  }

  printf("      Profile ID: ");
  for (int i = 0; i < 16; i++) printf("%02X", storedId[i]);
  printf("\n");

  if (idIsZero) {
    printf("      %s[INFO] Profile ID is all zeros (not computed)%s\n",
           ColorInfo(), ColorReset());
    printf("       ICC.1-2022-05 §7.2.18: ID may be zero if not computed\n");
    printf("\n");
    return 0;
  }

  // Use iccDEV library's CalcProfileID — handles zeroing fields per §7.2.18
  icProfileID computedId;
  memset(&computedId, 0, sizeof(computedId));
  if (!CalcProfileID(filename, &computedId)) {
    printf("      %s[WARN]  Failed to compute Profile ID (file read error)%s\n",
           ColorWarning(), ColorReset());
    printf("\n");
    return 1;
  }

  printf("      Computed:   ");
  for (int i = 0; i < 16; i++) printf("%02X", computedId.ID8[i]);
  printf("\n");

  bool match = (memcmp(storedId, computedId.ID8, 16) == 0);
  if (!match) {
    printf("      %s[WARN]  Profile ID MD5 MISMATCH — profile may be modified/corrupted%s\n",
           ColorCritical(), ColorReset());
    printf("       %sCWE-354: Profile ID does not match computed hash%s\n",
           ColorCritical(), ColorReset());
    heuristicCount++;
  } else {
    printf("      %s[OK] Profile ID matches computed MD5%s\n",
           ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H132: chromaticAdaptation Matrix Determinant Check
// The chad tag contains a 3x3 adaptation matrix. It must be invertible
// (non-zero determinant) and have values in a plausible range.
// =====================================================================
int RunHeuristic_H132_ChadDeterminant(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H132] chromaticAdaptation Matrix Validation\n");

  CIccTag *tag = pIcc->FindTag(icSigChromaticAdaptationTag);
  if (!tag) {
    printf("      %s[INFO] No chromaticAdaptation (chad) tag present%s\n",
           ColorInfo(), ColorReset());
    printf("\n");
    return 0;
  }

  CIccTagS15Fixed16 *s15Tag = dynamic_cast<CIccTagS15Fixed16*>(tag);
  if (!s15Tag || s15Tag->GetSize() < 9) {
    printf("      %s[WARN]  chad tag present but not valid S15Fixed16 3x3 matrix%s\n",
           ColorWarning(), ColorReset());
    heuristicCount++;
    printf("\n");
    return heuristicCount;
  }

  // Read 3x3 matrix
  double m[3][3];
  for (int r = 0; r < 3; r++)
    for (int c = 0; c < 3; c++)
      m[r][c] = (double)(*s15Tag)[r * 3 + c];

  printf("      chad matrix:\n");
  printf("        [%.6f  %.6f  %.6f]\n", m[0][0], m[0][1], m[0][2]);
  printf("        [%.6f  %.6f  %.6f]\n", m[1][0], m[1][1], m[1][2]);
  printf("        [%.6f  %.6f  %.6f]\n", m[2][0], m[2][1], m[2][2]);

  // Compute determinant
  double det = m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
             - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
             + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]);

  printf("      Determinant: %.6f\n", det);

  if (fabs(det) < 1e-6) {
    printf("      %s[WARN]  chad matrix is singular or near-singular (det ≈ 0)%s\n",
           ColorCritical(), ColorReset());
    printf("       %sCWE-369: Division-by-zero in chromatic adaptation inverse%s\n",
           ColorCritical(), ColorReset());
    heuristicCount++;
  } else if (det < 0.0) {
    printf("      %s[WARN]  chad matrix has negative determinant (reflection transform)%s\n",
           ColorWarning(), ColorReset());
    heuristicCount++;
  } else {
    printf("      %s[OK] chad matrix is invertible (det > 0)%s\n",
           ColorSuccess(), ColorReset());
  }

  // Check for extreme values (each element should be in [-5, 5] for normal adaptation)
  bool extreme = false;
  for (int r = 0; r < 3; r++)
    for (int c = 0; c < 3; c++)
      if (fabs(m[r][c]) > 5.0) extreme = true;

  if (extreme) {
    printf("      %s[WARN]  chad matrix contains extreme values (|element| > 5.0)%s\n",
           ColorWarning(), ColorReset());
    printf("       %sCWE-682: May cause float overflow in adaptation transforms%s\n",
           ColorWarning(), ColorReset());
    heuristicCount++;
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H133: Profile flags reserved bits (ICC.1-2022-05 §7.2.11)
// Bits 0-1: embedded flag + independent flag. Bits 2-31 must be zero.
// =====================================================================
int RunHeuristic_H133_FlagsReservedBits(const char *filename) {
  int heuristicCount = 0;
  printf("[H133] Profile Flags Reserved Bits (ICC.1-2022-05 §7.2.11)\n");

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("      %s[SKIP] Cannot open file%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }

  // Profile flags at offset 44 (4 bytes big-endian)
  icUInt8Number flagBytes[4] = {};
  if (fseek(fh.fp, 44, SEEK_SET) != 0 || fread(flagBytes, 1, 4, fh.fp) != 4) {
    printf("      %s[SKIP] Cannot read flags at offset 44%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }

  icUInt32Number flags = (static_cast<icUInt32Number>(flagBytes[0]) << 24) |
                         (static_cast<icUInt32Number>(flagBytes[1]) << 16) |
                         (static_cast<icUInt32Number>(flagBytes[2]) << 8)  |
                         flagBytes[3];

  bool embeddedFlag    = (flags >> 0) & 1;
  bool independentFlag = (flags >> 1) & 1;
  icUInt32Number reservedBits = flags & 0xFFFFFFFC; // bits 2-31

  printf("      Flags: 0x%08X (embedded=%d, independent=%d)\n",
         flags, embeddedFlag, independentFlag);

  if (reservedBits != 0) {
    printf("      %s[WARN]  HEURISTIC: Reserved flag bits non-zero (0x%08X) — ICC.1-2022-05 §7.2.11%s\n",
           ColorCritical(), reservedBits, ColorReset());
    printf("       %sCWE-20: Bits 2-31 must be zero per spec%s\n",
           ColorWarning(), ColorReset());
    heuristicCount++;
  } else {
    printf("      %s[OK] Reserved flag bits are zero%s\n", ColorSuccess(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H134: Tag type reserved bytes (ICC.1-2022-05 §10.1)
// Bytes 4-7 of every tag type element shall be zero.
// =====================================================================
int RunHeuristic_H134_TagTypeReservedBytes(CIccProfile *pIcc, const char *filename) {
  int heuristicCount = 0;
  printf("[H134] Tag Type Reserved Bytes (ICC.1-2022-05 §10.1)\n");

  if (!pIcc || !filename) {
    printf("      %s[SKIP] No profile or filename%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("      %s[SKIP] Cannot open file%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }

  // Read tag count from offset 128
  icUInt8Number tcBytes[4] = {};
  if (fseek(fh.fp, 128, SEEK_SET) != 0 || fread(tcBytes, 1, 4, fh.fp) != 4) {
    printf("      %s[SKIP] Cannot read tag count%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }
  icUInt32Number tagCount = (static_cast<icUInt32Number>(tcBytes[0]) << 24) |
                            (static_cast<icUInt32Number>(tcBytes[1]) << 16) |
                            (static_cast<icUInt32Number>(tcBytes[2]) << 8)  |
                            tcBytes[3];

  if (tagCount > 200) {
    printf("      %s[SKIP] Tag count %u too high for safe iteration%s\n",
           ColorWarning(), tagCount, ColorReset());
    printf("\n");
    return 0;
  }

  // Get file size for bounds checking
  long fileSize = fh.fileSize;

  int violations = 0;
  int checked = 0;

  // Read each tag entry (12 bytes each starting at offset 132)
  for (icUInt32Number t = 0; t < tagCount; t++) {
    icUInt8Number tagEntry[12] = {};
    if (fseek(fh.fp, 132 + t * 12, SEEK_SET) != 0 || fread(tagEntry, 1, 12, fh.fp) != 12)
      continue;

    icUInt32Number offset = (static_cast<icUInt32Number>(tagEntry[4]) << 24) |
                            (static_cast<icUInt32Number>(tagEntry[5]) << 16) |
                            (static_cast<icUInt32Number>(tagEntry[6]) << 8)  |
                            tagEntry[7];
    icUInt32Number size   = (static_cast<icUInt32Number>(tagEntry[8]) << 24) |
                            (static_cast<icUInt32Number>(tagEntry[9]) << 16) |
                            (static_cast<icUInt32Number>(tagEntry[10]) << 8) |
                            tagEntry[11];

    if (size < 8 || offset + 8 > (icUInt32Number)fileSize)
      continue;

    // Read bytes 4-7 of the tag data (reserved per §10.1)
    icUInt8Number reserved[4] = {};
    if (fseek(fh.fp, offset + 4, SEEK_SET) != 0 || fread(reserved, 1, 4, fh.fp) != 4)
      continue;

    checked++;
    if (reserved[0] != 0 || reserved[1] != 0 || reserved[2] != 0 || reserved[3] != 0) {
      char sigCC[5] = {};
      sigCC[0] = tagEntry[0]; sigCC[1] = tagEntry[1];
      sigCC[2] = tagEntry[2]; sigCC[3] = tagEntry[3]; sigCC[4] = '\0';
      printf("      %s[WARN]  Tag '%s' (offset %u): reserved bytes 4-7 = %02X %02X %02X %02X (should be 00)%s\n",
             ColorWarning(), sigCC, offset, reserved[0], reserved[1], reserved[2], reserved[3], ColorReset());
      violations++;
    }
  }

  if (violations > 0) {
    printf("      %s%d of %d tags have non-zero reserved bytes — ICC.1-2022-05 §10.1%s\n",
           ColorCritical(), violations, checked, ColorReset());
    printf("       %sCWE-20: May indicate crafted/malformed tag data%s\n",
           ColorWarning(), ColorReset());
    heuristicCount++;
  } else if (checked > 0) {
    printf("      %s[OK] All %d tag types have zeroed reserved bytes%s\n",
           ColorSuccess(), checked, ColorReset());
  } else {
    printf("      %s[SKIP] No tags to check%s\n", ColorWarning(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H135: Duplicate tag signatures (ICC.1-2022-05 §7.3.1)
// Each tag signature shall appear at most once in the tag table.
// =====================================================================
int RunHeuristic_H135_DuplicateTagSignatures(const char *filename) {
  int heuristicCount = 0;
  printf("[H135] Duplicate Tag Signatures (ICC.1-2022-05 §7.3.1)\n");

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("      %s[SKIP] Cannot open file%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }

  // Read tag count from offset 128
  icUInt8Number tcBytes[4] = {};
  if (fseek(fh.fp, 128, SEEK_SET) != 0 || fread(tcBytes, 1, 4, fh.fp) != 4) {
    printf("      %s[SKIP] Cannot read tag count%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }
  icUInt32Number tagCount = (static_cast<icUInt32Number>(tcBytes[0]) << 24) |
                            (static_cast<icUInt32Number>(tcBytes[1]) << 16) |
                            (static_cast<icUInt32Number>(tcBytes[2]) << 8)  |
                            tcBytes[3];

  if (tagCount > 200) {
    printf("      %s[SKIP] Tag count %u too high for safe iteration%s\n",
           ColorWarning(), tagCount, ColorReset());
    printf("\n");
    return 0;
  }

  // Collect all tag signatures
  std::vector<icUInt32Number> signatures;
  signatures.reserve(tagCount);

  for (icUInt32Number t = 0; t < tagCount; t++) {
    icUInt8Number tagEntry[12] = {};
    if (fseek(fh.fp, 132 + t * 12, SEEK_SET) != 0 || fread(tagEntry, 1, 12, fh.fp) != 12)
      continue;

    icUInt32Number sig = (static_cast<icUInt32Number>(tagEntry[0]) << 24) |
                         (static_cast<icUInt32Number>(tagEntry[1]) << 16) |
                         (static_cast<icUInt32Number>(tagEntry[2]) << 8)  |
                         tagEntry[3];
    signatures.push_back(sig);
  }

  // Check for duplicates using sorted comparison
  int duplicates = 0;
  std::vector<icUInt32Number> sorted = signatures;
  std::sort(sorted.begin(), sorted.end());
  for (size_t i = 1; i < sorted.size(); i++) {
    if (sorted[i] == sorted[i - 1]) {
      char sigCC[5] = {};
      SigToChars(sorted[i], sigCC);
      printf("      %s[WARN]  Duplicate tag signature: '%s' (0x%08X)%s\n",
             ColorWarning(), sigCC, sorted[i], ColorReset());
      duplicates++;
    }
  }

  if (duplicates > 0) {
    printf("      %s%d duplicate tag signature(s) — ICC.1-2022-05 §7.3.1%s\n",
           ColorCritical(), duplicates, ColorReset());
    printf("       %sCWE-694: Use of multiple resources with same identifier%s\n",
           ColorWarning(), ColorReset());
    heuristicCount++;
  } else if (signatures.size() > 0) {
    printf("      %s[OK] All %zu tag signatures are unique%s\n",
           ColorSuccess(), signatures.size(), ColorReset());
  } else {
    printf("      %s[SKIP] No tags to check%s\n", ColorWarning(), ColorReset());
  }

  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H136: ResponseCurveStruct per-channel measurement count (CWE-400)
// CIccResponseCurveStruct::Read() accepts per-channel nMeasurements from
// file as uint32 with no validation. Large counts cause O(nMeasurements)
// iteration in Read() and Describe(). ICC spec has no explicit limit but
// practical profiles use <1000 measurements per channel.
// =====================================================================
int RunHeuristic_H136_ResponseCurveMeasurementCount(const char *filename) {
  int heuristicCount = 0;

  printf("[H136] ResponseCurve Per-Channel Measurement Count (CWE-400)\n");

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("      [SKIP] Cannot open file\n\n");
    return 0;
  }

  long fileSize = fh.fileSize;
  if (fileSize < 132) {
    printf("      [SKIP] File too small\n\n");
    return 0;
  }

  // Read tag count
  fseek(fh.fp, 128, SEEK_SET);
  uint8_t tagCountBuf[4];
  if (fread(tagCountBuf, 1, 4, fh.fp) != 4) {
    printf("      [SKIP] Cannot read tag count\n\n");
    return 0;
  }
  uint32_t tagCount = ((uint32_t)tagCountBuf[0] << 24) |
                      ((uint32_t)tagCountBuf[1] << 16) |
                      ((uint32_t)tagCountBuf[2] << 8)  |
                       (uint32_t)tagCountBuf[3];

  if (tagCount > 1000) {
    printf("      [SKIP] Excessive tag count (%u)\n\n", tagCount);
    return 0;
  }

  // Scan tag table for responseCurveSet16Type (rcs2 = 0x72637332)
  for (uint32_t i = 0; i < tagCount && i < 200; i++) {
    uint8_t tagEntry[12];
    fseek(fh.fp, 132 + i * 12, SEEK_SET);
    if (fread(tagEntry, 1, 12, fh.fp) != 12) break;

    uint32_t tagOffset = ((uint32_t)tagEntry[4] << 24) |
                         ((uint32_t)tagEntry[5] << 16) |
                         ((uint32_t)tagEntry[6] << 8)  |
                          (uint32_t)tagEntry[7];
    uint32_t tagSize = ((uint32_t)tagEntry[8] << 24) |
                       ((uint32_t)tagEntry[9] << 16) |
                       ((uint32_t)tagEntry[10] << 8) |
                        (uint32_t)tagEntry[11];

    if (tagOffset > UINT32_MAX - 4 || tagOffset + 4 > (uint32_t)fileSize || tagSize < 28) continue;

    // Read tag type signature at tagOffset
    uint8_t typeSig[4];
    fseek(fh.fp, tagOffset, SEEK_SET);
    if (fread(typeSig, 1, 4, fh.fp) != 4) continue;

    // responseCurveSet16Type: 'rcs2' = 0x72637332
    if (typeSig[0] == 0x72 && typeSig[1] == 0x63 &&
        typeSig[2] == 0x73 && typeSig[3] == 0x32) {
      // Read channel count at offset+8 (uint16 BE)
      fseek(fh.fp, tagOffset + 8, SEEK_SET);
      uint8_t chanBuf[2];
      if (fread(chanBuf, 1, 2, fh.fp) != 2) break;
      uint16_t nChannels = ((uint16_t)chanBuf[0] << 8) | chanBuf[1];

      if (nChannels > 16) {
        printf("      %s[WARN]  ResponseCurveSet: %u channels (>16 ICC spec max)%s\n",
               ColorCritical(), nChannels, ColorReset());
        printf("       %sCWE-400: Excessive channel count drives O(nChan) allocation%s\n",
               ColorCritical(), ColorReset());
        heuristicCount++;
      }

      // Read measurement type count at offset+10 (uint16 BE)
      uint8_t nCurvesBuf[2];
      if (fread(nCurvesBuf, 1, 2, fh.fp) != 2) break;
      uint16_t nCurves = ((uint16_t)nCurvesBuf[0] << 8) | nCurvesBuf[1];

      uint16_t nChan = nChannels > 16 ? 16 : nChannels;
      if (nChan == 0) break;

      // Walk curve offsets and check per-channel nMeasurements
      for (uint16_t c = 0; c < nCurves && c < 16; c++) {
        uint8_t offBuf[4];
        fseek(fh.fp, tagOffset + 12 + c * 4, SEEK_SET);
        if (fread(offBuf, 1, 4, fh.fp) != 4) break;
        uint32_t curveOff = ((uint32_t)offBuf[0] << 24) |
                            ((uint32_t)offBuf[1] << 16) |
                            ((uint32_t)offBuf[2] << 8)  |
                             (uint32_t)offBuf[3];

        uint32_t absOff = tagOffset + curveOff;
        if (absOff + 4 + (uint32_t)nChan * 4 > (uint32_t)fileSize) continue;

        // Skip measurement unit sig (4 bytes), read nMeasurements array
        fseek(fh.fp, absOff + 4, SEEK_SET);
        for (uint16_t ch = 0; ch < nChan; ch++) {
          uint8_t mBuf[4];
          if (fread(mBuf, 1, 4, fh.fp) != 4) break;
          uint32_t nMeas = ((uint32_t)mBuf[0] << 24) |
                           ((uint32_t)mBuf[1] << 16) |
                           ((uint32_t)mBuf[2] << 8)  |
                            (uint32_t)mBuf[3];

          if (nMeas > 100000) {
            printf("      %s[WARN]  ResponseCurve[%u] channel %u: %u measurements (>100K)%s\n",
                   ColorCritical(), c, ch, nMeas, ColorReset());
            printf("       %sCWE-400: Unbounded measurement count → O(n) iteration in Read/Describe%s\n",
                   ColorCritical(), ColorReset());
            heuristicCount++;
          }
        }
      }
    }
  }

  if (heuristicCount == 0) {
    printf("      %s[OK] ResponseCurve measurement counts within bounds (or tag absent)%s\n",
           ColorSuccess(), ColorReset());
  }
  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H137: High-Dimensional Color Space Grid Complexity (CWE-400)
// EvaluateProfile() iterates nGran^ndim grid points. For profiles with
// ndim >= 6 and default nGran=33, this creates 33^6 = 1.29B iterations.
// Flag profiles where ndim-driven computation exceeds safe bounds.
// =====================================================================
int RunHeuristic_H137_HighDimensionalGridComplexity(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H137] High-Dimensional Color Space Grid Complexity (CWE-400)\n");

  if (!pIcc) {
    printf("      [SKIP] No profile loaded\n\n");
    return 0;
  }

  icColorSpaceSignature csInput = pIcc->m_Header.colorSpace;
  icUInt32Number ndim = icGetSpaceSamples(csInput);

  if (ndim >= 6) {
    printf("      %s[WARN]  Input color space has %u channels%s\n",
           ColorWarning(), ndim, ColorReset());
    printf("       Round-trip evaluation grid: 33^%u = ", ndim);
    uint64_t gridSize = 1;
    bool overflow = false;
    for (uint32_t d = 0; d < ndim; d++) {
      gridSize *= 33;
      if (gridSize > 10000000000ULL) { overflow = true; break; }
    }
    if (overflow) {
      printf(">10B iterations\n");
    } else {
      printf("%llu iterations\n", (unsigned long long)gridSize);
    }
    printf("       %sCWE-400: O(nGran^ndim) complexity in EvaluateProfile — DoS risk%s\n",
           ColorCritical(), ColorReset());
    heuristicCount++;
  }

  // Also check CLUT tags for high-dimensional grids
  icTagSignature clutTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    (icTagSignature)0
  };

  for (int t = 0; clutTags[t] != (icTagSignature)0; t++) {
    CIccTag *pTag = pIcc->FindTag(clutTags[t]);
    if (!pTag) continue;

    CIccTagLutAtoB *mbbA = dynamic_cast<CIccTagLutAtoB*>(pTag);
    CIccTagLutBtoA *mbbB = dynamic_cast<CIccTagLutBtoA*>(pTag);
    uint32_t nIn = 0;
    CIccCLUT *clut = NULL;

    if (mbbA) {
      nIn = mbbA->InputChannels();
      clut = mbbA->GetCLUT();
    } else if (mbbB) {
      nIn = mbbB->InputChannels();
      clut = mbbB->GetCLUT();
    }

    if (nIn >= 6 && clut) {
      uint64_t total = 1;
      for (uint32_t d = 0; d < nIn && d < 16; d++) {
        total *= clut->GridPoint(d);
        if (total > 100000000ULL) break;
      }
      if (total > 1000000ULL) {
        char sigStr[5] = {};
        uint32_t sig = (uint32_t)clutTags[t];
        SigToChars(sig, sigStr);
        printf("      %s[WARN]  '%s': %u-dim CLUT grid product = %llu (>1M)%s\n",
               ColorCritical(), sigStr, nIn, (unsigned long long)total, ColorReset());
        printf("       %sCWE-400: Exponential grid iteration in Apply()%s\n",
               ColorCritical(), ColorReset());
        heuristicCount++;
      }
    }
  }

  if (heuristicCount == 0) {
    printf("      %s[OK] Color space dimensionality within safe bounds%s\n",
           ColorSuccess(), ColorReset());
  }
  printf("\n");
  return heuristicCount;
}

// =====================================================================
// H138: Calculator Element Branching Depth (CWE-400/CWE-674)
// ApplySequence() processes if/else/select/case ops recursively at
// runtime with NO depth counter. CheckUnderflowOverflow has depth=16
// for validation, but execution is unbounded. Flag profiles with
// deep calculator branching that could cause stack overflow or DoS.
// =====================================================================
int RunHeuristic_H138_CalculatorBranchingDepth(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H138] Calculator Element Branching Depth (CWE-400/CWE-674)\n");

  if (!pIcc) {
    printf("      [SKIP] No profile loaded\n\n");
    return 0;
  }

  icTagSignature mpeTags[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    (icTagSignature)0x44324230, // D2B0
    (icTagSignature)0x44324231, // D2B1
    (icTagSignature)0x42324430, // B2D0
    (icTagSignature)0x42324431, // B2D1
    (icTagSignature)0
  };

  int calcFound = 0;

  for (int t = 0; mpeTags[t] != (icTagSignature)0; t++) {
    CIccTagMultiProcessElement *pMpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, mpeTags[t]);
    if (!pMpe) continue;

    icUInt32Number numElems = pMpe->NumElements();
    for (icUInt32Number ei = 0; ei < numElems && ei < 100; ei++) {
      CIccMultiProcessElement *pElem = pMpe->GetElement(ei);
      if (!pElem) continue;

      CIccMpeCalculator *pCalc = dynamic_cast<CIccMpeCalculator*>(pElem);
      if (!pCalc) continue;
      calcFound++;

      // Count sub-elements via public GetElem API
      icUInt32Number nSub = 0;
      for (icUInt16Number si = 0; si < 256; si++) {
        if (!pCalc->GetElem(icSigApplyElemOp, si)) break;
        nSub++;
      }
      if (nSub > 16) {
        char sigStr[5] = {};
        uint32_t sig = (uint32_t)mpeTags[t];
        SigToChars(sig, sigStr);
        printf("       Note: ApplySequence() has NO runtime depth limit (validation-only guard)\n");
        heuristicCount++;
      }

      // Check for nested calculator sub-elements (re-entrant Apply)
      for (icUInt32Number si = 0; si < nSub && si < 64; si++) {
        CIccMultiProcessElement *pSubElem = pCalc->GetElem(icSigApplyElemOp, (icUInt16Number)si);
        if (!pSubElem) continue;
        CIccMpeCalculator *pSubCalc = dynamic_cast<CIccMpeCalculator*>(pSubElem);
        if (pSubCalc) {
          char sigStr[5] = {};
          uint32_t sig = (uint32_t)mpeTags[t];
          SigToChars(sig, sigStr);
          printf("      %s[WARN]  '%s' calc[%u] sub[%u]: nested calculator element%s\n",
                 ColorCritical(), sigStr, ei, si, ColorReset());
          printf("       %sCWE-674: Nested calculators cause re-entrant ApplySequence (no depth limit)%s\n",
                 ColorCritical(), ColorReset());
          heuristicCount++;
        }
      }
    }
  }

  if (heuristicCount == 0) {
    if (calcFound > 0) {
      printf("      %s[OK] Calculator branching depth within safe bounds (%d calc element(s))%s\n",
             ColorSuccess(), calcFound, ColorReset());
    } else {
      printf("      [INFO] No calculator elements found\n");
    }
  }
  printf("\n");
  return heuristicCount;
}
