/// @file IccConformanceSecurity.cpp
/// @brief Security-oriented conformance checks (CF-091 through CF-094).
///
/// Wraps existing security heuristics H108/H109/H126/H127 as conformance checks
/// for the PAWG security checklist items S8, S11, S12, S13.
///
/// ICC.1-2022-05 §8: Only registered ICC tag signatures are expected in
/// conformant profiles. Private tags (signatures not in the ICC registry)
/// may contain unvalidated data and are a security consideration.
///
/// @see ICC.1-2022-05 §9 (tag signature registry)

#include "IccProfile.h"
#include "IccTag.h"
#include "IccUtil.h"
#include "IccConformanceRegistry.h"
#include "IccConformanceSecurity.h"
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicResult.h"
#include "IccAnalyzerColors.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>

// ---------------------------------------------------------------------------
// CF-091: Malware Signature Scan
//   PAWG S8: "Confirm absence of malware embedded in color profile"
//   Scans all tag data for PE/ELF/MachO/script signatures.
//   ICC.1-2022-05 does not define binary executable content in tag data.
// ---------------------------------------------------------------------------
int RunCF091_MalwareSignatureScan(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  printf("  %s[CF-091]%s Malware Signature Scan (%sICC.1-2022-05 §9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename || !filename[0]) {
    printf("           %s[SKIP]%s No filename provided for malware scan\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("           %s[SKIP]%s Cannot open file for malware scan\n",
           ColorWarning(), ColorReset());
    return 0;
  }
  long fileSize = fh.fileSize;

  if (fileSize <= 128 || fileSize > 100 * 1024 * 1024) {
    printf("           %s[OK]%s File size not suitable for malware scan — skipped\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  size_t scanSize = (size_t)(fileSize > 10485760 ? 10485760 : fileSize);
  std::vector<unsigned char> buf(scanSize);
  size_t bytesRead = fread(buf.data(), 1, scanSize, fh.fp);

  // Scan for executable signatures in tag data (after 128-byte header)
  static const struct { const unsigned char *sig; size_t len; const char *desc; } sigs[] = {
    { (const unsigned char *)"\x7F" "ELF", 4, "ELF executable header" },
    { (const unsigned char *)"MZ",         2, "PE/MZ executable header" },
    { (const unsigned char *)"\xCF\xFA\xED\xFE", 4, "Mach-O 64-bit header" },
    { (const unsigned char *)"\xCE\xFA\xED\xFE", 4, "Mach-O 32-bit header" },
    { (const unsigned char *)"#!/",        3, "Script shebang (#!)" },
  };

  for (size_t i = 128; i + 4 <= bytesRead; i++) {
    for (size_t s = 0; s < sizeof(sigs)/sizeof(sigs[0]); s++) {
      if (i + sigs[s].len <= bytesRead &&
          memcmp(&buf[i], sigs[s].sig, sigs[s].len) == 0) {
        // PE/MZ needs additional validation (e_lfanew → PE signature)
        if (sigs[s].len == 2 && sigs[s].sig[0] == 'M') {
          if (i + 64 > bytesRead) continue;
          uint32_t peOff = (uint32_t)buf[i+60] | ((uint32_t)buf[i+61] << 8) |
                           ((uint32_t)buf[i+62] << 16) | ((uint32_t)buf[i+63] << 24);
          if (peOff >= 1024 || i + peOff + 4 > bytesRead ||
              buf[i+peOff] != 'P' || buf[i+peOff+1] != 'E')
            continue;
        }
        printf("           %s[FAIL]%s %s detected at offset 0x%zX\n",
               ColorError(), ColorReset(), sigs[s].desc, i);
        printf("                  CWE-506: Embedded Malicious Code\n");
        issues++;
        break;
      }
    }
    if (issues >= 5) break; // cap findings
  }

  if (issues == 0)
    printf("           %s[OK]%s No malware signatures detected in tag data\n",
           ColorSuccess(), ColorReset());

  return issues;
}

// ---------------------------------------------------------------------------
// CF-092: Private Tag Presence
//   PAWG S11: "Identify any additional or private tags"
//   ICC.1-2022-05 §9: All tag signatures in the profile should be from
//   the ICC tag registry. Private tags use signatures ≥ 0x80000000 or
//   unregistered 4-byte codes.
// ---------------------------------------------------------------------------
int RunCF092_PrivateTagPresence(CIccProfile *pIcc) {
  int issues = 0;
  printf("  %s[CF-092]%s Private/Unregistered Tag Identification (%sICC.1-2022-05 §9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

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
    icSigPerceptualRenderingIntentGamutTag,
    icSigSaturationRenderingIntentGamutTag,
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
      printf("           Private/unregistered: '%s' (0x%08X) offset=%u size=%u\n",
             sigStr, (unsigned)sig,
             it->TagInfo.offset, it->TagInfo.size);
      privateCount++;
    }
  }

  if (privateCount > 0) {
    printf("           %s[INFO]%s %d private/unregistered tag(s) detected\n",
           ColorInfo(), ColorReset(), privateCount);
    issues = privateCount;
  } else {
    printf("           %s[OK]%s All tags are registered ICC signatures\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-093: Private Tag Content Scan
//   PAWG S12: "Confirm absence of malware specifically within private tags"
//   More targeted than CF-091: only scans data regions of private tags.
// ---------------------------------------------------------------------------
int RunCF093_PrivateTagContentScan(CIccProfile *pIcc, const char *filename) {
  int issues = 0;
  printf("  %s[CF-093]%s Private Tag Content Security Scan (%sICC.1-2022-05 §9%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename || !filename[0]) {
    printf("           %s[SKIP]%s No filename for private tag content scan\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("           %s[SKIP]%s Cannot open file for content scan\n",
           ColorWarning(), ColorReset());
    return 0;
  }
  long fileSize = fh.fileSize;

  if (fileSize <= 132 || fileSize > 100 * 1024 * 1024) {
    printf("           %s[OK]%s File not suitable for private tag scan\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  std::vector<unsigned char> buf((size_t)fileSize);
  size_t bytesRead = fread(buf.data(), 1, (size_t)fileSize, fh.fp);

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
    icSigPerceptualRenderingIntentGamutTag,
    icSigSaturationRenderingIntentGamutTag,
    (icTagSignature)0
  };

  int privateScanned = 0;
  for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    icTagSignature sig = it->TagInfo.sig;
    bool isKnown = false;
    for (int k = 0; knownTags[k] != (icTagSignature)0; k++) {
      if (sig == knownTags[k]) { isKnown = true; break; }
    }
    if (isKnown) continue;

    uint32_t off = it->TagInfo.offset;
    uint32_t sz = it->TagInfo.size;
    if (off >= bytesRead || off + sz > bytesRead || sz < 4) continue;

    privateScanned++;
    const unsigned char *data = &buf[off];

    // Scan private tag for executable magic
    // sz >= 4 guaranteed by guard at line 242
    if (data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
      char sigStr[5] = {};
      SigToChars(sig, sigStr);
      printf("           %s[FAIL]%s ELF executable in private tag '%s'\n",
             ColorError(), ColorReset(), sigStr);
      issues++;
    }
    // sz >= 4 guaranteed by guard above
    if (data[0] == '#' && data[1] == '!' && data[2] == '/') {
      char sigStr[5] = {};
      SigToChars(sig, sigStr);
      printf("           %s[FAIL]%s Script shebang in private tag '%s'\n",
             ColorError(), ColorReset(), sigStr);
      issues++;
    }
    if (sz >= 64 && data[0] == 'M' && data[1] == 'Z') {
      uint32_t peOff = (uint32_t)data[60] | ((uint32_t)data[61] << 8) |
                       ((uint32_t)data[62] << 16) | ((uint32_t)data[63] << 24);
      if (peOff < sz - 4 && data[peOff] == 'P' && data[peOff+1] == 'E') {
        char sigStr[5] = {};
        SigToChars(sig, sigStr);
        printf("           %s[FAIL]%s PE executable in private tag '%s'\n",
               ColorError(), ColorReset(), sigStr);
        issues++;
      }
    }
  }

  if (issues > 0) {
    printf("                  CWE-506: Embedded Malicious Code in private tags\n");
  } else if (privateScanned == 0) {
    printf("           %s[OK]%s No private tags to scan\n",
           ColorSuccess(), ColorReset());
  } else {
    printf("           %s[OK]%s %d private tag(s) scanned — no malware signatures\n",
           ColorSuccess(), ColorReset(), privateScanned);
  }

  return issues;
}

// ---------------------------------------------------------------------------
// CF-094: NOP/Shellcode Pattern Scan
//   PAWG S13: "Confirm absence of NOP instructions or other suspicious patterns"
//   Scans full profile for NOP sleds (x86: 0x90×16+, ARM64: 0x1F2003D5×4+).
// ---------------------------------------------------------------------------
int RunCF094_ShellcodePatternScan(const char *filename) {
  int issues = 0;
  printf("  %s[CF-094]%s NOP/Shellcode Pattern Scan (%sCWE-506%s)\n",
         ColorHeader(), ColorReset(), ColorInfo(), ColorReset());

  if (!filename || !filename[0]) {
    printf("           %s[SKIP]%s No filename for shellcode scan\n",
           ColorWarning(), ColorReset());
    return 0;
  }

  RawFileHandle fh = OpenRawFile(filename);
  if (!fh) {
    printf("           %s[SKIP]%s Cannot open file for shellcode scan\n",
           ColorWarning(), ColorReset());
    return 0;
  }
  long fileSize = fh.fileSize;

  if (fileSize <= 128 || fileSize > 100 * 1024 * 1024) {
    printf("           %s[OK]%s File size not suitable for pattern scan\n",
           ColorSuccess(), ColorReset());
    return 0;
  }

  size_t scanSize = (size_t)(fileSize > 10485760 ? 10485760 : fileSize);
  std::vector<unsigned char> buf(scanSize);
  size_t bytesRead = fread(buf.data(), 1, scanSize, fh.fp);

  int nopSleds = 0;

  for (size_t i = 128; i + 16 <= bytesRead; ) {
    // x86 NOP sled: 16+ consecutive 0x90
    if (buf[i] == 0x90) {
      size_t run = 1;
      while (i + run < bytesRead && buf[i + run] == 0x90 && run < 256) run++;
      if (run >= 16) {
        printf("           %s[FAIL]%s x86 NOP sled at offset 0x%zX (%zu bytes)\n",
               ColorError(), ColorReset(), i, run);
        nopSleds++;
        i += run;
        continue;
      }
    }
    // ARM64 NOP sled: 0x1F2003D5 repeated 4+ times
    if (i + 16 <= bytesRead &&
        buf[i] == 0x1F && buf[i+1] == 0x20 && buf[i+2] == 0x03 && buf[i+3] == 0xD5) {
      int armNops = 1;
      size_t j = i + 4;
      while (j + 4 <= bytesRead && buf[j] == 0x1F && buf[j+1] == 0x20 &&
             buf[j+2] == 0x03 && buf[j+3] == 0xD5 && armNops < 64) {
        armNops++; j += 4;
      }
      if (armNops >= 4) {
        printf("           %s[FAIL]%s ARM64 NOP sled at offset 0x%zX (%d instructions)\n",
               ColorError(), ColorReset(), i, armNops);
        nopSleds++;
        i = j;
        continue;
      }
    }
    i++;
  }

  if (nopSleds > 0) {
    printf("                  CWE-506: Suspicious NOP sled patterns detected\n");
    issues = nopSleds;
  } else {
    printf("           %s[OK]%s No NOP sled or shellcode patterns detected\n",
           ColorSuccess(), ColorReset());
  }

  return issues;
}

// ---------------------------------------------------------------------------
// Runner: all security conformance checks
// ---------------------------------------------------------------------------
int RunSecurityConformance(CIccProfile *pIcc, const char *filename) {
  auto &hc = HeuristicCollector::instance();
  int issues = 0;
  int r;

#define CF_WRAP(id, title, call) \
  hc.begin(id, title); \
  r = call; \
  if (r < 0) { \
    hc.skip(nullptr); \
  } else { \
    if (r > 0) hc.warn("%d non-conformance(s)", r); \
    hc.end("Conformant"); \
    issues += r; \
  }

  CF_WRAP(1091, "CF-091: Malware Signature Scan", RunCF091_MalwareSignatureScan(pIcc, filename));
  CF_WRAP(1092, "CF-092: Private Tag Identification", RunCF092_PrivateTagPresence(pIcc));
  CF_WRAP(1093, "CF-093: Private Tag Content Scan", RunCF093_PrivateTagContentScan(pIcc, filename));
  CF_WRAP(1094, "CF-094: NOP/Shellcode Pattern Scan", RunCF094_ShellcodePatternScan(filename));

#undef CF_WRAP
  return issues;
}
