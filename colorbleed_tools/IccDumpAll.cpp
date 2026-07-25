/*!
 *  @file IccDumpAll.cpp
 *  @brief Enhanced ICC Profile Dump -- Full v5/iccMAX MPE Element Detail
 *  @author David Hoyt
 *  @date 13 MAR 2026
 *  @version 2.0.1
 *
 *  Based on iccDumpProfile from iccDEV by Max Derhak / Peter Wyatt.
 *  Core behavior is function-identical to upstream iccDumpProfile.
 *  Layered enhancements for security research and debugging:
 *
 *  Enhancements over iccDumpProfile:
 *    - MPE element type signatures shown per PROCESS_ELEMENT
 *    - v5 profile summary section (spectral, BRDF, MCS tags)
 *    - Element chain I/O channel flow visualization
 *    - Late-binding spectral element identification
 *    - --diag mode: file stat, sanitizer config, tag load tracking
 *    - --read mode: ReadIccProfile (eager) vs OpenIccProfile (lazy)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Copyright (c) 2003-2012 The International Color Consortium (original)
 *  Copyright (c) 2026 David H Hoyt LLC (enhancements)
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <sys/stat.h>
#include "IccProfile.h"
#include "IccTag.h"
#include "IccUtil.h"
#include "IccProfLibVer.h"
#include "IccTagMPE.h"
#include "ColorBleedKnownIssues.h"

// Diagnostic mode global -- set by --diag flag
static bool g_bDiagMode = false;

// Diagnostic logging macros
#define DIAG(...) do { if (g_bDiagMode) { fprintf(stderr, "[DIAG] "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } } while(0)

static const char* GetLateBindingNote(icElemTypeSignature sig)
{
  switch (sig) {
    case icSigEmissionMatrixElemType:
    case icSigInvEmissionMatrixElemType:
    case icSigEmissionObserverElemType:
    case icSigReflectanceObserverElemType:
      return " [LATE-BINDING SPECTRAL]";
    default:
      return "";
  }
}

static icUInt32Number CountMpeElements(CIccTagMultiProcessElement *pMpe)
{
  static const icUInt32Number kMaxMpeElements = 65536;
  icUInt32Number nElements = 0;
  while (pMpe && nElements < kMaxMpeElements && pMpe->GetElement((int)nElements)) {
    nElements++;
  }
  if (pMpe && nElements == kMaxMpeElements) {
    DIAG("MPE element count reached safety cap (%u)", kMaxMpeElements);
  }
  return nElements;
}

// Report active sanitizer configuration
static void ReportSanitizerConfig()
{
  bool asanActive = false;
  bool ubsanActive = false;

#if defined(__SANITIZE_ADDRESS__)
  asanActive = true;
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
  asanActive = true;
#endif
#endif

#if defined(__SANITIZE_UNDEFINED__)
  ubsanActive = true;
#elif defined(__has_feature)
#if __has_feature(undefined_behavior_sanitizer)
  ubsanActive = true;
#endif
#endif

  fprintf(stderr, "[DIAG] === Sanitizer Configuration ===\n");
  fprintf(stderr, "[DIAG] ASAN: %s\n", asanActive ? "ACTIVE" : "not active");
  fprintf(stderr, "[DIAG] UBSAN: %s\n", ubsanActive ? "ACTIVE" : "not active");
  if (asanActive && getenv("ASAN_OPTIONS"))
    fprintf(stderr, "[DIAG] ASAN_OPTIONS: set (value redacted)\n");
  if (ubsanActive && getenv("UBSAN_OPTIONS"))
    fprintf(stderr, "[DIAG] UBSAN_OPTIONS: set (value redacted)\n");
  fprintf(stderr, "[DIAG] ===\n");
}

// Report file stat vs header size
static void ReportFileStat(const char *filename)
{
  struct stat st;
  if (stat(filename, &st) == 0) {
    fprintf(stderr, "[DIAG] File stat: %lld bytes on disk\n", (long long)st.st_size);
  } else {
    fprintf(stderr, "[DIAG] File stat: FAILED (errno=%d)\n", errno);
  }
}

// Enhanced tag dump: adds MPE element type detail for v5 profiles
// Core behavior identical to upstream DumpTagCore()
void DumpTagCore(CIccTag *pTag, icTagSignature sig, int nVerboseness)
{
  const size_t bufSize = 64;
  char buf[bufSize];
  CIccInfo Fmt;

  std::string contents;

  if (pTag) {
    printf("\nContents of %s tag (%s)\n", Fmt.GetTagSigName(sig), icGetSig(buf, bufSize, sig));
    printf("Type: ");
    if (pTag->IsArrayType()) {
      printf("Array of ");
    }
    printf("%s (%s)\n", Fmt.GetTagTypeSigName(pTag->GetType()), icGetSig(buf, bufSize, pTag->GetType()));

    DIAG("Tag '%s' type=0x%08X loaded successfully", icGetSig(buf, bufSize, sig), pTag->GetType());

    // Enhanced: for multiProcessElementType tags, show element chain summary
    if (pTag->GetType() == icSigMultiProcessElementType) {
      CIccTagMultiProcessElement *pMpe = static_cast<CIccTagMultiProcessElement*>(pTag);
      icUInt32Number nElements = CountMpeElements(pMpe);
      printf("\n  === MPE Element Chain: %u elements, %u->%u channels ===\n",
             nElements, pMpe->NumInputChannels(), pMpe->NumOutputChannels());

      for (icUInt32Number j = 0; j < nElements; j++) {
        CIccMultiProcessElement *pElem = pMpe->GetElement(j);
        if (pElem) {
          icElemTypeSignature elemSig = pElem->GetType();
          printf("  [%u] %s (%s) %u->%u%s\n",
                 j + 1,
                 Fmt.GetElementTypeSigName(elemSig),
                 icGetSig(buf, bufSize, elemSig),
                 pElem->NumInputChannels(),
                 pElem->NumOutputChannels(),
                 GetLateBindingNote(elemSig));
        }
      }
      printf("  ===\n");
    }

    pTag->Describe(contents, nVerboseness);
    fwrite(contents.c_str(), contents.length(), 1, stdout);
  }
  else {
    printf("Tag (%s) not found in profile\n", icGetSig(buf, bufSize, sig));
    DIAG("Tag '%s' -- FindTag returned NULL (LoadTag failure or tag not present)", icGetSig(buf, bufSize, sig));
  }
}

// This does a search of all tags, slow
void DumpTagSig(CIccProfile *pIcc, icTagSignature sig, int nVerboseness)
{
  CIccTag *pTag = pIcc->FindTag(sig);
  DumpTagCore(pTag, sig, nVerboseness);
}

// This directly accesses the tag data, does not need to search
void DumpTagEntry(CIccProfile *pIcc, IccTagEntry &entry, int nVerboseness)
{
  CIccTag *pTag = pIcc->FindTag(entry);
  DumpTagCore(pTag, entry.TagInfo.sig, nVerboseness);
}

// v5 profile summary: spectral, BRDF, MCS tags
void DumpV5Summary(CIccProfile *pIcc)
{
  icHeader *pHdr = &pIcc->m_Header;
  if (pHdr->version < icVersionNumberV5)
    return;

  CIccInfo Fmt;

  printf("\nVersion 5 / iccMAX Profile Summary\n");
  printf("----------------------------------\n");

  // Spectral tags
  static const icTagSignature spectralTags[] = {
    icSigSpectralViewingConditionsTag,
    icSigSpectralDataInfoTag,
    icSigSpectralWhitePointTag,
    icSigCustomToStandardPccTag,
    icSigStandardToCustomPccTag,
  };
  static const char *spectralNames[] = {
    "Spectral Viewing Conditions (svcn)",
    "Spectral Data Info (sdin)",
    "Spectral White Point (swpt)",
    "Custom-to-Standard PCC (c2sp)",
    "Standard-to-Custom PCC (s2cp)",
  };

  printf("\n  Spectral Tags:\n");
  for (int i = 0; i < 5; i++) {
    CIccTag *pTag = pIcc->FindTag(spectralTags[i]);
    printf("    %-38s %s\n", spectralNames[i], pTag ? "PRESENT" : "---");
  }

  // BRDF tags
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
  printf("\n  BRDF Tags:                  %d of 16 present\n", brdfCount);

  // Gamut boundary
  CIccTag *gbd0 = pIcc->FindTag(icSigGamutBoundaryDescription0Tag);
  CIccTag *gbd1 = pIcc->FindTag(icSigGamutBoundaryDescription1Tag);
  printf("  Gamut Boundary Desc:        gbd0=%s gbd1=%s\n",
         gbd0 ? "PRESENT" : "---", gbd1 ? "PRESENT" : "---");

  // MCS
  if (pHdr->mcs) {
    printf("  MCS Color Space:            %s\n", Fmt.GetColorSpaceSigName((icColorSpaceSignature)pHdr->mcs));
  }

  // Count MPE tags
  int mpeCount = 0;
  int lateBindCount = 0;
  TagEntryList::iterator it;
  for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
    CIccTag *pTag = pIcc->FindTag(*it);
    if (pTag && pTag->GetType() == icSigMultiProcessElementType) {
      CIccTagMultiProcessElement *pMpe = static_cast<CIccTagMultiProcessElement*>(pTag);
      mpeCount++;
      icUInt32Number nElements = CountMpeElements(pMpe);
      for (icUInt32Number j = 0; j < nElements; j++) {
        CIccMultiProcessElement *pElem = pMpe->GetElement(j);
        if (pElem) {
          icElemTypeSignature eSig = pElem->GetType();
          if (eSig == icSigEmissionMatrixElemType ||
              eSig == icSigInvEmissionMatrixElemType ||
              eSig == icSigEmissionObserverElemType ||
              eSig == icSigReflectanceObserverElemType) {
            lateBindCount++;
          }
        }
      }
    }
  }
  printf("\n  MPE Tags:                   %d (multiProcessElementType)\n", mpeCount);
  printf("  Late-Binding Elements:      %d (spectral observer/emission)\n", lateBindCount);
  if (lateBindCount > 0) {
    printf("    NOTE: Late-binding elements require Profile Connection Conditions (PCC)\n");
    printf("          with spectralViewingConditionsTag (svcn) for proper rendering.\n");
  }

  printf("\n");
}

void printUsage(void)
{
  printf("Usage: iccDumpAll {--diag} {--read} {-v} {int} profile {tagId/\"ALL\"}\n");
  printf("\nEnhanced ICC profile dump with full v5/iccMAX MPE element detail.\n");
  printf("  -v           Perform profile validation.\n"
         "  --diag       Enable diagnostic output to stderr (sanitizer config, file stat,\n"
         "               tag load tracking, API selection, header vs stat size comparison).\n"
         "  --read       Use ReadIccProfile (eager load all tags) instead of OpenIccProfile\n"
         "               (lazy load). Useful for A/B testing tag loading behavior.\n"
         "  int          Verboseness of output (1-100, default=100).\n\n");
  printf("iccDumpAll v2.0.1 built with IccProfLib version " ICCPROFLIBVER "\n\n");
}

static bool TryParseVerbosity(const char *arg, int &verbosity)
{
  char *endptr = nullptr;
  errno = 0;
  long parsed = strtol(arg, &endptr, 10);

  if (errno == ERANGE || endptr == arg || !endptr || *endptr != '\0')
    return false;

  if (parsed <= 0)
    verbosity = 1;
  else if (parsed > 100)
    verbosity = 100;
  else
    verbosity = (int)parsed;

  return true;
}


int main(int argc, char* argv[])
{
  int nArg = 1;
  int verbosity = 100; // default is maximum verbosity (old behaviour)
  bool bUseRead = false; // --read: use ReadIccProfile instead of OpenIccProfile

  if (argc <= 1) {
    printUsage();
    return 64; // EX_USAGE for missing arguments
  }

  // Early help handling so it works regardless of flag order
  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
      printUsage();
      return 0;
    }
  }

  // Parse leading flags: --diag, --read (before -v and profile path)
  while (nArg < argc) {
    if (!strcmp(argv[nArg], "--diag")) {
      g_bDiagMode = true;
      nArg++;
    } else if (!strcmp(argv[nArg], "--read")) {
      bUseRead = true;
      nArg++;
    } else {
      break;
    }
  }

  if (nArg >= argc) {
    printUsage();
    return 64; // EX_USAGE
  }

  if (g_bDiagMode)
    ReportSanitizerConfig();

  CIccProfile *pIcc;
  std::string sReport;
  icValidateStatus nStatus = icValidateOK;
  bool bDumpValidation = false;

  if (!strncmp(argv[nArg], "-V", 2) || !strncmp(argv[nArg], "-v", 2)) {
    nArg++;
    if (argc <= nArg) {
      printUsage();
      return 64; // EX_USAGE
    }

    // Support case where ICC filename starts with an integer: e.g. "123.icc"
    if (TryParseVerbosity(argv[nArg], verbosity)) {
      nArg++;
      if (argc <= nArg) {
        printUsage();
        return 64; // EX_USAGE
      }
    }

    ColorBleedReportKnownIssues(argv[nArg], stderr, false);
    DIAG("API: ValidateIccProfile('%s')", argv[nArg]);
    pIcc = ValidateIccProfile(argv[nArg], sReport, nStatus);
    bDumpValidation = true;
  }
  else {
    // Support case where ICC filename starts with an integer: e.g. "123.icc"
    if (TryParseVerbosity(argv[nArg], verbosity)) {
      nArg++;
      if (argc <= nArg) {
        printUsage();
        return 64; // EX_USAGE
      }
    }

    ColorBleedReportKnownIssues(argv[nArg], stderr, false);
    if (bUseRead) {
      DIAG("API: ReadIccProfile('%s') -- eager load all tags", argv[nArg]);
      pIcc = ReadIccProfile(argv[nArg]);
    } else {
      DIAG("API: OpenIccProfile('%s') -- lazy load (tags loaded on FindTag)", argv[nArg]);
      pIcc = OpenIccProfile(argv[nArg]);
    }
  }

  if (g_bDiagMode)
    ReportFileStat(argv[nArg]);

  CIccInfo Fmt;
  icHeader* pHdr = NULL;

  // Precondition: nArg is argument of ICC profile filename
  printf("iccDumpAll v2.0.1 built with IccProfLib version " ICCPROFLIBVER "\n\n");
  if (!pIcc) {
    printf("Unable to parse '%s' as ICC profile!\n", argv[nArg]);
    nStatus = icValidateCriticalError;
  }
  else {
    pHdr = &pIcc->m_Header;
    const size_t bufSize = 64;
    char buf[bufSize];

    printf("Profile:            '%s'\n", argv[nArg]);
    if(Fmt.IsProfileIDCalculated(&pHdr->profileID))
      printf("Profile ID:         %s\n", Fmt.GetProfileID(&pHdr->profileID));
    else
      printf("Profile ID:         Profile ID not calculated.\n");
    printf("Size:               %u (0x%x) bytes\n", pHdr->size, pHdr->size);

    // Diagnostic: compare header size vs file stat size
    if (g_bDiagMode) {
      struct stat st;
      if (stat(argv[nArg], &st) == 0) {
        if ((icUInt32Number)st.st_size != pHdr->size) {
          fprintf(stderr, "[DIAG] *** SIZE MISMATCH: header says %u, file stat says %lld ***\n",
                  pHdr->size, (long long)st.st_size);
          if ((icUInt32Number)st.st_size < pHdr->size)
            fprintf(stderr, "[DIAG] File is TRUNCATED (%lld bytes short)\n",
                    (long long)pHdr->size - (long long)st.st_size);
          else
            fprintf(stderr, "[DIAG] File has %lld bytes BEYOND header-declared size\n",
                    (long long)st.st_size - (long long)pHdr->size);
        } else {
          fprintf(stderr, "[DIAG] Header size matches file stat: %u bytes\n", pHdr->size);
        }
      }
      fprintf(stderr, "[DIAG] Load mode: %s | Validation: %s | Verbosity: %d\n",
              bUseRead ? "ReadIccProfile (eager)" : "OpenIccProfile (lazy)",
              bDumpValidation ? "ON" : "OFF", verbosity);
    }

    printf("\nHeader\n");
    printf(  "------\n");
    printf("Attributes:         %s\n", Fmt.GetDeviceAttrName(pHdr->attributes));
    printf("Cmm:                %s\n", Fmt.GetCmmSigName((icCmmSignature)(pHdr->cmmId)));
    printf("Creation Date:      %d/%d/%d (M/D/Y)  %02u:%02u:%02u\n",
                               pHdr->date.month, pHdr->date.day, pHdr->date.year,
                               pHdr->date.hours, pHdr->date.minutes, pHdr->date.seconds);
    printf("Creator:            %s\n", icGetSig(buf, bufSize, pHdr->creator));
    printf("Device Manufacturer:%s\n", icGetSig(buf, bufSize, pHdr->manufacturer));
    printf("Data Color Space:   %s\n", Fmt.GetColorSpaceSigName(pHdr->colorSpace));
    printf("Flags:              %s\n", Fmt.GetProfileFlagsName(pHdr->flags));
    printf("PCS Color Space:    %s\n", Fmt.GetColorSpaceSigName(pHdr->pcs));
    printf("Platform:           %s\n", Fmt.GetPlatformSigName(pHdr->platform));
    printf("Rendering Intent:   %s\n", Fmt.GetRenderingIntentName((icRenderingIntent)(pHdr->renderingIntent)));
    printf("Profile Class:      %s\n", Fmt.GetProfileClassSigName(pHdr->deviceClass));
    if (pHdr->deviceSubClass)
      printf("Profile SubClass:   %s\n", icGetSig(buf, bufSize, pHdr->deviceSubClass));
    else
      printf("Profile SubClass:   Not Defined\n");
    printf("Version:            %s\n", Fmt.GetVersionName(pHdr->version));
    if (pHdr->version >= icVersionNumberV5 && pHdr->deviceSubClass) {
      printf("SubClass Version:   %s\n", Fmt.GetSubClassVersionName(pHdr->version));
    }
    printf("Illuminant:         X=%.4lf, Y=%.4lf, Z=%.4lf\n",
                                icFtoD(pHdr->illuminant.X),
                                icFtoD(pHdr->illuminant.Y),
                                icFtoD(pHdr->illuminant.Z));
    printf("Spectral PCS:       %s\n", Fmt.GetSpectralColorSigName(pHdr->spectralPCS));
    if (pHdr->spectralRange.start || pHdr->spectralRange.end || pHdr->spectralRange.steps) {
      printf("Spectral PCS Range: start=%.1fnm, end=%.1fnm, steps=%d\n",
             icF16toF(pHdr->spectralRange.start),
             icF16toF(pHdr->spectralRange.end),
             pHdr->spectralRange.steps);
    }
    else {
      printf("Spectral PCS Range: Not Defined\n");
    }

    if (pHdr->biSpectralRange.start || pHdr->biSpectralRange.end || pHdr->biSpectralRange.steps) {
      printf("BiSpectral Range:     start=%.1fnm, end=%.1fnm, steps=%d\n",
        icF16toF(pHdr->biSpectralRange.start),
        icF16toF(pHdr->biSpectralRange.end),
        pHdr->biSpectralRange.steps);
    }
    else {
      printf("BiSpectral Range:   Not Defined\n");
    }

    if (pHdr->mcs) {
      printf("MCS Color Space:    %s\n", Fmt.GetColorSpaceSigName((icColorSpaceSignature)pHdr->mcs));
    }
    else {
      printf("MCS Color Space:    Not Defined\n");
    }

    printf("\nProfile Tags (%d)\n", (int)pIcc->m_Tags.size());
    printf(  "------------\n");

    printf("%28s    ID    %8s\t%8s\t%8s\n", "Tag",  "Offset", "Size", "Pad");
    printf("%28s  ------  %8s\t%8s\t%8s\n", "----", "------", "----", "---");

    int n, closest, pad;
    TagEntryList::iterator i, j;

    typedef std::vector<icUInt32Number> offsetVector;
    offsetVector sortedTagOffsets;
    sortedTagOffsets.resize(pIcc->m_Tags.size());
    for (n = 0, i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i, n++) {
      sortedTagOffsets[n] = i->TagInfo.offset;
    }
    std::sort(sortedTagOffsets.begin(), sortedTagOffsets.end());

    for (n = 0, i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i, n++) {
      offsetVector::const_iterator match = std::upper_bound(sortedTagOffsets.cbegin(), sortedTagOffsets.cend(), i->TagInfo.offset);
      if (match == sortedTagOffsets.cend())
        closest = (int)pHdr->size;
      else
        closest = *match;
      closest = std::min(closest, (int)pHdr->size);

      pad = closest - i->TagInfo.offset - i->TagInfo.size;

      printf("%28s  %s  %8d\t%8d\t%8d\n", Fmt.GetTagSigName(i->TagInfo.sig),
          icGetSig(buf, bufSize, i->TagInfo.sig, false), i->TagInfo.offset, i->TagInfo.size, pad);
    }

    printf("\n");

    // Report duplicated tag signatures
    typedef std::unordered_map<icTagSignature, int> tag_lookup_map;
    tag_lookup_map tag_lookup;
    for (n = 0, i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i, n++) {
      tag_lookup_map::const_iterator found = tag_lookup.find(i->TagInfo.sig);
      if (found != tag_lookup.end()) {
        printf("%28s is duplicated at positions %d and %d!\n", Fmt.GetTagSigName(i->TagInfo.sig), n, found->second);
        nStatus = icMaxStatus(nStatus, icValidateWarning);
      } else {
        tag_lookup[i->TagInfo.sig] = n;
      }
    }

    // Enhanced: v5 summary section
    DumpV5Summary(pIcc);

    // Check additional details if doing detailed validation:
    // - First tag data offset is immediately after the Tag Table
    // - Tag data offsets are all 4-byte aligned
    // - Tag data should be tightly abutted with adjacent tags (or the end of the Tag Table)
    //   (note that tag data can be reused by multiple tags and tags do NOT have to be in order)
    // - Last tag also has to be padded and thus file size is always a multiple of 4. See clause
    //   7.2.1, bullet (c) of ICC.1:2010 and ICC.2:2019 specs.
    // - Tag offset + Tag Size should never go beyond EOF
    // - Multiple tags can reuse data and this is NOT reported as it is perfectly valid and
    //   occurs in real-world ICC profiles
    // - Tags with overlapping tag data are considered highly suspect (but officially valid)
    // - 1-3 padding bytes after each tag's data need to be all zero *** NOT DONE - TODO ***
    if (bDumpValidation) {
      const size_t strSize = 256;
      char str[strSize];
      int rndup, smallest_offset = pHdr->size;

      // File size is required to be a multiple of 4 bytes according to clause 7.2.1 bullet (c):
      // "all tagged element data, including the last, shall be padded by no more than three
      //  following pad bytes to reach a 4 - byte boundary"
      if ((pHdr->version >= icVersionNumberV4_2) && (pHdr->size % 4 != 0)) {
        sReport += icMsgValidateNonCompliant;
        sReport += "File size is not a multiple of 4 bytes (last tag needs padding?).\n";
        nStatus = icMaxStatus(nStatus, icValidateNonCompliant);
      }

      for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i) {
        rndup = 4 * ((i->TagInfo.size + 3) / 4); // Round up to a 4-byte aligned size as per ICC spec

        // Is the Tag offset + Tag Size beyond EOF?
        if (i->TagInfo.offset + i->TagInfo.size > pHdr->size) {
          sReport += icMsgValidateNonCompliant;
          snprintf(str, strSize, "Tag %s (offset %d, size %d) ends beyond EOF.\n",
                  Fmt.GetTagSigName(i->TagInfo.sig), i->TagInfo.offset, i->TagInfo.size);
          sReport += str;
          nStatus = icMaxStatus(nStatus, icValidateNonCompliant);
        }

        // Is it the first tag data in the file?
        if ((int)i->TagInfo.offset < smallest_offset) {
          smallest_offset = (int)i->TagInfo.offset;
        }

        // Find closest tag after this tag, by checking offsets of other tags
        // use upper_bound to allow for duplicate tags (pointing to the same offset)
        offsetVector::const_iterator match = std::upper_bound(sortedTagOffsets.cbegin(), sortedTagOffsets.cend(), i->TagInfo.offset);
        if (match == sortedTagOffsets.cend())
          closest = (int)pHdr->size;
        else
          closest = *match;
        closest = std::min(closest, (int)pHdr->size);

        // Check if closest tag after this tag is less than offset+size - in which case it overlaps!
        if ((closest < (int)i->TagInfo.offset + (int)i->TagInfo.size) && (closest < (int)pHdr->size)) {
          sReport += icMsgValidateWarning;
          snprintf(str, strSize, "Tag %s (offset %d, size %d) overlaps with following tag data starting at offset %d.\n",
              Fmt.GetTagSigName(i->TagInfo.sig), i->TagInfo.offset, i->TagInfo.size, closest);
          sReport += str;
          nStatus = icMaxStatus(nStatus, icValidateWarning);
        }

        // Check for gaps between tag data (accounting for 4-byte alignment)
        if (closest > (int)i->TagInfo.offset + rndup) {
          sReport += icMsgValidateWarning;
          snprintf(str, strSize, "Tag %s (size %d) is followed by %d unnecessary additional bytes (from offset %d).\n",
              Fmt.GetTagSigName(i->TagInfo.sig), i->TagInfo.size, closest - (i->TagInfo.offset + rndup), (i->TagInfo.offset + rndup));
          sReport += str;
          nStatus = icMaxStatus(nStatus, icValidateWarning);
        }
      }

      // Clause 7.2.1, bullet (b): "the first set of tagged element data shall immediately follow the tag table"
      // 1st tag offset should be = Header (128) + Tag Count (4) + Tag Table (n*12)
      if ((n > 0) && (smallest_offset > 128 + 4 + (n * 12))) {
        sReport += icMsgValidateNonCompliant;
        snprintf(str, strSize, "First tag data is at offset %d rather than immediately after tag table (offset %d).\n",
            smallest_offset, 128 + 4 + (n * 12));
        sReport += str;
        nStatus = icMaxStatus(nStatus, icValidateNonCompliant);
      }
    }

    if (argc > nArg + 1) {
      if (!stricmp(argv[nArg + 1], "ALL")) {
        int tagIdx = 0;
        int tagLoadFail = 0;
        for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i, tagIdx++) {
          DIAG("Loading tag %d/%d: %s (offset=%u, size=%u)",
               tagIdx + 1, (int)pIcc->m_Tags.size(),
               Fmt.GetTagSigName(i->TagInfo.sig),
               i->TagInfo.offset, i->TagInfo.size);
          CIccTag *pCheck = pIcc->FindTag(*i);
          if (!pCheck) {
            tagLoadFail++;
            DIAG("*** Tag %s: FindTag/LoadTag FAILED ***", Fmt.GetTagSigName(i->TagInfo.sig));
          }
          DumpTagEntry(pIcc, *i, verbosity);
        }
        if (g_bDiagMode && tagLoadFail > 0) {
          fprintf(stderr, "[DIAG] === %d of %d tags failed to load ===\n",
                  tagLoadFail, (int)pIcc->m_Tags.size());
        }
      }
      else {
        DumpTagSig(pIcc, (icTagSignature)icGetSigVal(argv[nArg + 1]), verbosity);
      }
    }
  }

  int nValid = 0;

  if (bDumpValidation) {
    printf("\nValidation Report\n");
    printf(  "-----------------\n");
    switch (nStatus) {
    case icValidateOK:
      printf("Profile is valid");
      if (pHdr)
        printf(" for version %s", Fmt.GetVersionName(pHdr->version));
      break;
    case icValidateWarning:
      printf("Profile has warning(s)");
      if (pHdr)
        printf(" for version %s", Fmt.GetVersionName(pHdr->version));
      break;
    case icValidateNonCompliant:
      printf("Profile violates ICC specification");
      if (pHdr)
        printf(" for version %s", Fmt.GetVersionName(pHdr->version));
      break;
    case icValidateCriticalError:
      printf("Profile has Critical Error(s) that violate ICC specification");
      if (pHdr)
        printf(" for version %s", Fmt.GetVersionName(pHdr->version));
      nValid = -1;
      break;
    default:
      printf("Profile has unknown status!");
      nValid = -2;
      break;
    }
  }
  printf("\n\n");

  sReport += "\n";
  fwrite(sReport.c_str(), sReport.length(), 1, stdout);

  delete pIcc;

  return nValid;
}
