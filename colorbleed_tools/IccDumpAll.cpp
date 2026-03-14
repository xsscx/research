/*!
 *  @file IccDumpAll.cpp
 *  @brief Enhanced ICC Profile Dump — Full v5/iccMAX MPE Element Detail
 *  @author David Hoyt
 *  @date 13 MAR 2026
 *  @version 1.0.0
 *
 *  Based on iccDumpProfile from iccDEV by Max Derhak / Peter Wyatt.
 *  Enhanced to show multiProcessElementsType element type signatures
 *  and v5-specific profile information that the upstream tool omits.
 *
 *  Enhancements over iccDumpProfile:
 *    - MPE element type signatures shown per PROCESS_ELEMENT
 *    - v5 profile summary section (spectral, BRDF, MCS tags)
 *    - Element chain I/O channel flow visualization
 *    - Late-binding spectral element identification
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
#include <vector>
#include <unordered_map>
#include <algorithm>
#include "IccProfile.h"
#include "IccTag.h"
#include "IccUtil.h"
#include "IccProfLibVer.h"
#include "IccTagMPE.h"

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

// Enhanced tag dump: adds MPE element type detail for v5 profiles
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

    // Enhanced: for multiProcessElementType tags, show element chain summary
    if (pTag->GetType() == icSigMultiProcessElementType) {
      CIccTagMultiProcessElement *pMpe = static_cast<CIccTagMultiProcessElement*>(pTag);
      icUInt32Number nElements = pMpe->NumElements();
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
  }
}

void DumpTagSig(CIccProfile *pIcc, icTagSignature sig, int nVerboseness)
{
  CIccTag *pTag = pIcc->FindTag(sig);
  DumpTagCore(pTag, sig, nVerboseness);
}

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
      for (icUInt32Number j = 0; j < pMpe->NumElements(); j++) {
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
  printf("Usage: iccDumpAll {-v} {int} profile {tagId/\"ALL\"}\n");
  printf("\nEnhanced ICC profile dump with full v5/iccMAX MPE element detail.\n");
  printf("The -v option causes profile validation to be performed.\n"
         "The optional integer parameter specifies verboseness of output (1-100, default=100).\n");
  printf("iccDumpAll built with IccProfLib version " ICCPROFLIBVER "\n\n");
}


int main(int argc, char* argv[])
{
  int nArg = 1;
  int verbosity = 100;

  if (argc <= 1) {
    printUsage();
    return 0;
  }

  CIccProfile *pIcc;
  std::string sReport;
  icValidateStatus nStatus = icValidateOK;
  bool bDumpValidation = false;

  if (!strncmp(argv[1], "-V", 2) || !strncmp(argv[1], "-v", 2)) {
    nArg++;
    if (argc <= nArg) {
      printUsage();
      return -1;
    }

    char *endptr = nullptr;
    verbosity = (int)strtol(argv[nArg], &endptr, 10);
    if ((verbosity != 0L) && (errno != ERANGE) && ((endptr == nullptr) || (*endptr == '\0'))) {
      if (verbosity < 0)
        verbosity = 1;
      else if (verbosity > 100)
        verbosity = 100;
      nArg++;
      if (argc <= nArg) {
        printUsage();
        return -1;
      }
    }
    else if (argv[nArg] == endptr) {
      verbosity = 100;
    }

    pIcc = ValidateIccProfile(argv[nArg], sReport, nStatus);
    bDumpValidation = true;
  }
  else {
    char* endptr = nullptr;
    verbosity = (int)strtol(argv[nArg], &endptr, 10);
    if ((verbosity != 0L) && (errno != ERANGE) && ((endptr == nullptr) || (*endptr == '\0'))) {
      if (verbosity < 0)
        verbosity = 1;
      else if (verbosity > 100)
        verbosity = 100;
      nArg++;
      if (argc <= nArg) {
        printUsage();
        return -1;
      }
    }

    pIcc = OpenIccProfile(argv[nArg]);
  }

  CIccInfo Fmt;
  icHeader* pHdr = NULL;

  printf("iccDumpAll built with IccProfLib version " ICCPROFLIBVER "\n\n");
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
    printf("Size:               %d (0x%x) bytes\n", pHdr->size, pHdr->size);

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

    // Validation checks
    if (bDumpValidation) {
      const size_t strSize = 256;
      char str[strSize];
      int rndup, smallest_offset = pHdr->size;

      if ((pHdr->version >= icVersionNumberV4_2) && (pHdr->size % 4 != 0)) {
        sReport += icMsgValidateNonCompliant;
        sReport += "File size is not a multiple of 4 bytes (last tag needs padding?).\n";
        nStatus = icMaxStatus(nStatus, icValidateNonCompliant);
      }

      for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i) {
        rndup = 4 * ((i->TagInfo.size + 3) / 4);

        if (i->TagInfo.offset + i->TagInfo.size > pHdr->size) {
          sReport += icMsgValidateNonCompliant;
          snprintf(str, strSize, "Tag %s (offset %d, size %d) ends beyond EOF.\n",
                  Fmt.GetTagSigName(i->TagInfo.sig), i->TagInfo.offset, i->TagInfo.size);
          sReport += str;
          nStatus = icMaxStatus(nStatus, icValidateNonCompliant);
        }

        if ((int)i->TagInfo.offset < smallest_offset) {
          smallest_offset = (int)i->TagInfo.offset;
        }

        offsetVector::const_iterator match = std::upper_bound(sortedTagOffsets.cbegin(), sortedTagOffsets.cend(), i->TagInfo.offset);
        if (match == sortedTagOffsets.cend())
          closest = (int)pHdr->size;
        else
          closest = *match;
        closest = std::min(closest, (int)pHdr->size);

        if ((closest < (int)i->TagInfo.offset + (int)i->TagInfo.size) && (closest < (int)pHdr->size)) {
          sReport += icMsgValidateWarning;
          snprintf(str, strSize, "Tag %s (offset %d, size %d) overlaps with following tag data starting at offset %d.\n",
              Fmt.GetTagSigName(i->TagInfo.sig), i->TagInfo.offset, i->TagInfo.size, closest);
          sReport += str;
          nStatus = icMaxStatus(nStatus, icValidateWarning);
        }

        if (closest > (int)i->TagInfo.offset + rndup) {
          sReport += icMsgValidateWarning;
          snprintf(str, strSize, "Tag %s (size %d) is followed by %d unnecessary additional bytes (from offset %d).\n",
              Fmt.GetTagSigName(i->TagInfo.sig), i->TagInfo.size, closest - (i->TagInfo.offset + rndup), (i->TagInfo.offset + rndup));
          sReport += str;
          nStatus = icMaxStatus(nStatus, icValidateWarning);
        }
      }

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
        for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i) {
          DumpTagEntry(pIcc, *i, verbosity);
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
