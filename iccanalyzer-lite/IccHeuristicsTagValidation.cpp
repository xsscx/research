/*
 * IccHeuristicsTagValidation.cpp — Tag structure validation heuristics (H9-H32)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * Extracted from IccHeuristicsLibrary.cpp as part of codebase modernization.
 */

#include "IccHeuristicsTagValidation.h"
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
#include <vector>
#include <algorithm>
#include <string>

int RunHeuristic_H9_CriticalTextTags(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 9. Text Tag Presence
icTagSignature textTags[] = {
  icSigProfileDescriptionTag,
  icSigCopyrightTag,
  icSigDeviceMfgDescTag,
  icSigDeviceModelDescTag
};

const char *textTagNames[] = {
  "Description",
  "Copyright",
  "Manufacturer",
  "Device Model"
};

printf("[H9] Critical Text Tags:\n");
int missingCount = 0;
for (size_t i = 0; i < sizeof(textTags)/sizeof(textTags[0]); i++) {
  CIccTag *pTag = pIcc->FindTag(textTags[i]);
  if (pTag) {
    printf("     %s: Present [OK]\n", textTagNames[i]);
  } else {
    printf("     %s: Missing\n", textTagNames[i]);
    missingCount++;
  }
}
if (missingCount > 2) {
  printf("      %s[WARN]  HEURISTIC: Multiple required text tags missing%s\n", ColorWarning(), ColorReset());
  printf("       %sRisk: Incomplete/malformed profile%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H10_TagCount(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 10. Tag Count Validation
int tagCount = pIcc->m_Tags.size();

printf("[H10] Tag Count: %d\n", tagCount);
if (tagCount == 0) {
  printf("      %s[WARN]  HEURISTIC: Zero tags (invalid profile)%s\n", ColorCritical(), ColorReset());
  printf("       %sRisk: Parser confusion, empty profile attack%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
} else if (tagCount > 200) {
  printf("      %s[WARN]  HEURISTIC: Excessive tag count (>200)%s\n", ColorWarning(), ColorReset());
  printf("       %sRisk: Resource exhaustion%s\n", ColorWarning(), ColorReset());
  heuristicCount++;
} else {
  printf("      %s[OK] Tag count within normal range%s\n", ColorSuccess(), ColorReset());
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H11_CLUTEntryLimit(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 11. CLUT Size Limit Check (Resource Exhaustion) — walk actual LUT tags
// CVE refs: CVE-2026-21490, CVE-2026-21494 (LUT8/LUT16 OOM via extreme CLUT dimensions)
printf("[H11] CLUT Entry Limit Check\n");
printf("      Max safe CLUT entries per tag: %llu (16M)\n",
       (unsigned long long)ICCANALYZER_MAX_CLUT_ENTRIES);

{
  static const icTagSignature clutSigs[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
  };
  int clutCount = 0;
  for (size_t li = 0; li < sizeof(clutSigs)/sizeof(clutSigs[0]); li++) {
    CIccMBB *pMBB = FindAndCast<CIccMBB>(pIcc, clutSigs[li]);
    if (!pMBB) continue;
    CIccCLUT *pCLUT = pMBB->GetCLUT();
    if (!pCLUT) continue;
    clutCount++;
    icUInt8Number nIn = pMBB->InputChannels();
    uint64_t entries = 1;
    bool overflow = false;
    for (int ch = 0; ch < nIn && ch < 16; ch++) {
      if (!SafeMul64(&entries, entries, pCLUT->GridPoint(ch))) { overflow = true; break; }
    }
    if (!overflow) SafeMul64(&entries, entries, pCLUT->GetOutputChannels());
    if (overflow || entries > ICCANALYZER_MAX_CLUT_ENTRIES) {
      char sig4[5];
      SignatureToFourCC(static_cast<icUInt32Number>(clutSigs[li]), sig4);
      printf("      %s[WARN] CLUT in '%s': %llu entries (limit %llu)%s\n",
             ColorWarning(), sig4, (unsigned long long)entries,
             (unsigned long long)ICCANALYZER_MAX_CLUT_ENTRIES, ColorReset());
      heuristicCount++;
    }
  }
  if (clutCount == 0) {
    printf("      %s[OK] No CLUT tags to check%s\n", ColorSuccess(), ColorReset());
  } else {
    printf("      Inspected %d CLUT tag(s)\n", clutCount);
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H12_MPEChainDepth(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 12. MPE Element Chain Depth — walk actual MPE tags
printf("[H12] MPE Chain Depth Check\n");
printf("      Max MPE elements per chain: %u\n", ICCANALYZER_MAX_MPE_ELEMENTS);

{
  static const icTagSignature mpeSigs[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
    icSigDToB0Tag, icSigDToB1Tag,
    icSigBToD0Tag, icSigBToD1Tag,
  };
  int mpeCount = 0;
  for (size_t mi = 0; mi < sizeof(mpeSigs)/sizeof(mpeSigs[0]); mi++) {
    CIccTagMultiProcessElement *pMPE = FindAndCast<CIccTagMultiProcessElement>(pIcc, mpeSigs[mi]);
    if (!pMPE) continue;
    mpeCount++;
    icUInt32Number nElem = pMPE->NumElements();
    if (nElem > ICCANALYZER_MAX_MPE_ELEMENTS) {
      char sig4[5];
      SignatureToFourCC(static_cast<icUInt32Number>(mpeSigs[mi]), sig4);
      printf("      %s[WARN] MPE '%s' has %u elements (limit %u)%s\n",
             ColorWarning(), sig4, nElem, ICCANALYZER_MAX_MPE_ELEMENTS, ColorReset());
      heuristicCount++;
    }
  }
  if (mpeCount == 0) {
    printf("      %s[OK] No MPE tags to check%s\n", ColorSuccess(), ColorReset());
  } else {
    printf("      Inspected %d MPE tag(s)\n", mpeCount);
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H13_PerTagSizeCheck(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 13. Per-Tag Size Check — inspect actual tag sizes
printf("[H13] Per-Tag Size Check\n");
printf("      Max tag size: %llu MB (%llu bytes)\n",
       (unsigned long long)(ICCANALYZER_MAX_TAG_SIZE >> 20),
       (unsigned long long)ICCANALYZER_MAX_TAG_SIZE);

{
  int oversizedCount = 0;
  TagEntryList::iterator tit;
  for (tit = pIcc->m_Tags.begin(); tit != pIcc->m_Tags.end(); tit++) {
    IccTagEntry *e = &(*tit);
    if (e->TagInfo.size > ICCANALYZER_MAX_TAG_SIZE) {
      char sig4[5];
      SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), sig4);
      printf("      %s[WARN] Tag '%s' size=%u bytes (%.1f MB) exceeds limit%s\n",
             ColorWarning(), sig4, e->TagInfo.size,
             e->TagInfo.size / (1024.0 * 1024.0), ColorReset());
      oversizedCount++;
    }
  }
  if (oversizedCount > 0) {
    printf("      %s[WARN] %d tag(s) exceed size limit%s\n",
           ColorCritical(), oversizedCount, ColorReset());
    heuristicCount++;
  } else {
    printf("      %s[OK] All %d tags within size limits%s\n",
           ColorSuccess(), (int)pIcc->m_Tags.size(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H14_TagArrayDetection(CIccProfile *pIcc, const char *filename) {
  int heuristicCount = 0;

// 14. TagArrayType Detection (CRITICAL - Heap-Use-After-Free)
// CVE refs: CVE-2026-21677 (UAF in CIccTagArray::Cleanup)
// Based on fuzzer findings 2026-01-30: TagArray can appear under ANY signature
printf("[H14] TagArrayType Detection (UAF Risk)\n");
printf("      Checking for TagArrayType (0x74617279 = 'tary')\n");
printf("      Note: Tag signature ≠ tag type - must check tag DATA\n");

// Re-read file for raw tag type validation
RawFileHandle fh = OpenRawFile(filename);
if (fh) {
  size_t fileSize = (size_t)fh.fileSize;
  
  if (fileSize >= 132) {
    icUInt8Number rawHdr[132];
    if (fread(rawHdr, 1, 132, fh.fp) == 132) {
      icUInt32Number tagTableCount = (static_cast<icUInt32Number>(rawHdr[128])<<24) | (static_cast<icUInt32Number>(rawHdr[129])<<16) | 
                                      (static_cast<icUInt32Number>(rawHdr[130])<<8) | rawHdr[131];
      
      bool foundTagArray = false;
      icUInt32Number tagArrayCount = 0;
      
      // Read each tag entry and check its TYPE (not just signature)
      for (icUInt32Number i = 0; i < tagTableCount && i < 256; i++) {
        size_t entryPos = 132 + i*12;
        if (entryPos + 12 > fileSize) break;
        
        icUInt8Number entry[12];
        fseek(fh.fp, entryPos, SEEK_SET);
        if (fread(entry, 1, 12, fh.fp) != 12) break;
        
        icUInt32Number tagSig = (static_cast<icUInt32Number>(entry[0])<<24) | (static_cast<icUInt32Number>(entry[1])<<16) | (static_cast<icUInt32Number>(entry[2])<<8) | entry[3];
        icUInt32Number tagOffset = (static_cast<icUInt32Number>(entry[4])<<24) | (static_cast<icUInt32Number>(entry[5])<<16) | (static_cast<icUInt32Number>(entry[6])<<8) | entry[7];
        icUInt32Number tagSize = (static_cast<icUInt32Number>(entry[8])<<24) | (static_cast<icUInt32Number>(entry[9])<<16) | (static_cast<icUInt32Number>(entry[10])<<8) | entry[11];
        
        // Validate tag is within file bounds (overflow-safe check)
        if (tagOffset >= 128 && tagSize >= 4 && tagSize <= fileSize && tagOffset <= fileSize - tagSize) {
          icUInt8Number tagData[4];
          fseek(fh.fp, tagOffset, SEEK_SET);
          if (fread(tagData, 1, 4, fh.fp) == 4) {
            icUInt32Number tagType = (static_cast<icUInt32Number>(tagData[0])<<24) | (static_cast<icUInt32Number>(tagData[1])<<16) | 
                                     (static_cast<icUInt32Number>(tagData[2])<<8) | tagData[3];
            
            // Check for TagArrayType (0x74617279 = 'tary')
            if (tagType == 0x74617279) {
              foundTagArray = true;
              tagArrayCount++;
              
              char sigStr[5], typeStr[5];
              sigStr[0] = static_cast<char>((tagSig>>24)&0xff); sigStr[1] = static_cast<char>((tagSig>>16)&0xff);
              sigStr[2] = static_cast<char>((tagSig>>8)&0xff); sigStr[3] = static_cast<char>(tagSig&0xff); sigStr[4] = '\0';
              typeStr[0] = static_cast<char>((tagType>>24)&0xff); typeStr[1] = static_cast<char>((tagType>>16)&0xff);
              typeStr[2] = static_cast<char>((tagType>>8)&0xff); typeStr[3] = static_cast<char>(tagType&0xff); typeStr[4] = '\0';
              
              printf("      [WARN]  CRITICAL: TagArrayType found!\n");
              printf("       Tag %u: signature='%s' (0x%08X), type='%s' (0x%08X)\n",
                     i, sigStr, tagSig, typeStr, tagType);
            }
          }
        }
      }
      
      if (foundTagArray) {
        printf("      %s[WARN]  HEURISTIC: %u TagArrayType tag(s) detected%s\n", ColorCritical(), tagArrayCount, ColorReset());
        printf("       %sRisk: CRITICAL - Heap-use-after-free in CIccTagArray::Cleanup()%s\n", ColorCritical(), ColorReset());
        printf("       %sLocation: IccProfLib/IccTagComposite.cpp:1514%s\n", ColorInfo(), ColorReset());
        printf("       %sImpact: Code execution, memory corruption%s\n", ColorCritical(), ColorReset());
        printf("       %sRecommendation: REJECT profile, potential exploit attempt%s\n", ColorCritical(), ColorReset());
        heuristicCount++;
      } else {
        printf("      %s[OK] No TagArrayType tags detected%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
} else {
  printf("      %s[WARN]  Cannot re-open file for tag type validation%s\n", ColorWarning(), ColorReset());
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H18_TechnologySignature(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 18. Technology Signature Validation
printf("[H18] Technology Signature Validation\n");
{
  CIccTagSignature *pSigTag = FindAndCast<CIccTagSignature>(pIcc, icSigTechnologyTag);
  if (pSigTag) {
    if (pSigTag) {
      icTechnologySignature techSig = static_cast<icTechnologySignature>(pSigTag->GetValue());
      if (IsValidTechnologySignature(techSig)) {
        CIccInfo techInfo;
        printf("      %s[OK] Valid technology: %s%s\n", ColorSuccess(),
               techInfo.GetTechnologySigName(techSig), ColorReset());
      } else {
        printf("      %s[WARN]  HEURISTIC: Unknown technology signature: 0x%08X%s\n",
               ColorWarning(), static_cast<unsigned>(techSig), ColorReset());
        printf("       %sRisk: Non-standard technology, possible parser issue%s\n",
               ColorWarning(), ColorReset());
        heuristicCount++;
      }
    } else {
      printf("      %s[WARN]  Technology tag has unexpected type%s\n", ColorWarning(), ColorReset());
      heuristicCount++;
    }
  } else {
    printf("      %sINFO: No technology tag present%s\n", ColorInfo(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H19_TagOffsetOverlap(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 19. Tag Overlap Detection
printf("[H19] Tag Offset/Size Overlap Detection\n");
{
  struct TagRange { icUInt32Number sig; icUInt32Number offset; icUInt32Number size; };
  std::vector<TagRange> ranges;
  TagEntryList::iterator it;
  for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    IccTagEntry *e = &(*it);
    ranges.push_back({static_cast<icUInt32Number>(e->TagInfo.sig), e->TagInfo.offset, e->TagInfo.size});
  }
  int overlapCount = 0;
  for (size_t a = 0; a < ranges.size(); a++) {
    for (size_t b = a+1; b < ranges.size(); b++) {
      if (ranges[a].offset == ranges[b].offset && ranges[a].size == ranges[b].size)
        continue; // Shared tag data (allowed by spec)
      uint64_t aEnd = (uint64_t)ranges[a].offset + ranges[a].size;
      uint64_t bEnd = (uint64_t)ranges[b].offset + ranges[b].size;
      if (ranges[a].offset < bEnd && ranges[b].offset < aEnd &&
          ranges[a].offset != ranges[b].offset) {
        char s1[5], s2[5];
        SignatureToFourCC(ranges[a].sig, s1);
        SignatureToFourCC(ranges[b].sig, s2);
        printf("      %s[WARN]  Tags '%s' and '%s' overlap: [%u+%u] vs [%u+%u]%s\n",
               ColorCritical(), s1, s2,
               ranges[a].offset, ranges[a].size,
               ranges[b].offset, ranges[b].size, ColorReset());
        overlapCount++;
      }
    }
  }
  if (overlapCount > 0) {
    printf("      %sRisk: %d tag overlap(s) — possible data corruption or exploitation%s\n",
           ColorCritical(), overlapCount, ColorReset());
    heuristicCount++;
  } else {
    printf("      %s[OK] No tag overlaps detected%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H20_TagTypeSignature(CIccProfile *pIcc, const char *filename) {
  int heuristicCount = 0;

// 20. Tag Type Signature Validation
printf("[H20] Tag Type Signature Validation\n");
{
  int invalidTypeCount = 0;
  RawFileHandle fh20 = OpenRawFile(filename);
  if (fh20) {
    TagEntryList::iterator it;
    for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
      IccTagEntry *e = &(*it);
      icUInt32Number tagOffset = e->TagInfo.offset;
      icUInt32Number tagSize = e->TagInfo.size;
      if (tagSize < 8) continue; // Too small for type+reserved

      icUInt8Number typeBuf[4] = {0};
      if (fseek(fh20.fp, tagOffset, SEEK_SET) == 0 &&
          fread(typeBuf, 1, 4, fh20.fp) == 4) {
        bool allPrintable = true;
        bool allZero = true;
        for (int b = 0; b < 4; b++) {
          if (typeBuf[b] != 0) allZero = false;
          if (typeBuf[b] < 0x20 || typeBuf[b] > 0x7E) allPrintable = false;
        }

        char sigFCC[5];
        SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), sigFCC);

        if (allZero) {
          printf("      %s[WARN]  Tag '%s' has null type signature (0x00000000)%s\n",
                 ColorWarning(), sigFCC, ColorReset());
          printf("       %sRisk: Corrupted tag data — parser may misinterpret%s\n",
                 ColorWarning(), ColorReset());
          invalidTypeCount++;
        } else if (!allPrintable) {
          printf("      %s[WARN]  Tag '%s' has non-ASCII type: 0x%02X%02X%02X%02X%s\n",
                 ColorWarning(), sigFCC,
                 typeBuf[0], typeBuf[1], typeBuf[2], typeBuf[3], ColorReset());
          printf("       %sRisk: Malformed type bytes — possible type confusion%s\n",
                 ColorWarning(), ColorReset());
          invalidTypeCount++;
        }
      }
    }
  }
  if (invalidTypeCount > 0) {
    heuristicCount += invalidTypeCount;
  } else {
    printf("      %s[OK] All tag type signatures are valid ASCII%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

// H21: Inspect tagStruct members for invalid types, null sub-elements, and malformed nesting.
// Iterates all tags, downcasts to CIccTagStruct, validates each member entry signature/type.
int RunHeuristic_H21_TagStructMemberInspection(CIccProfile *pIcc) {
  int heuristicCount = 0;

// H21: Inspect tagStruct members for invalid types, null sub-elements, malformed nesting
printf("[H21] tagStruct Member Inspection\n");
{
  int structIssues = 0;
  bool foundStruct = false;
  TagEntryList::iterator it;
  // Iterate all tags looking for CIccTagStruct instances
  for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    IccTagEntry *e = &(*it);
    CIccTagStruct *pStruct = FindAndCast<CIccTagStruct>(pIcc, e->TagInfo.sig);
    if (!pStruct) continue;
    foundStruct = true;

    char sigFCC[5];
    SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), sigFCC);
    icStructSignature structType = pStruct->GetTagStructType();
    char structFCC[5];
    SignatureToFourCC(static_cast<icUInt32Number>(structType), structFCC);

    TagEntryList *pElems = pStruct->GetElemList();
    int memberCount = 0;
    if (pElems) {
      memberCount = (int)pElems->size();
    }

    printf("      Tag '%s' is tagStruct (type='%s', %d members)\n",
           sigFCC, structFCC, memberCount);

    if (memberCount > 100) {
      printf("      %s[WARN]  Excessive member count: %d (limit 100)%s\n",
             ColorCritical(), memberCount, ColorReset());
      printf("       %sRisk: Resource exhaustion via struct expansion%s\n",
             ColorCritical(), ColorReset());
      structIssues++;
    }

    if (pElems) {
      TagEntryList::iterator eit;
      // Validate each struct member: type signature, readability, printable bytes
      for (eit = pElems->begin(); eit != pElems->end(); eit++) {
        IccTagEntry *me = &(*eit);
        char mFCC[5];
        SignatureToFourCC(static_cast<icUInt32Number>(me->TagInfo.sig), mFCC);

        CIccTag *mTag = pStruct->FindElem(me->TagInfo.sig);
        if (mTag) {
          icTagTypeSignature mType = mTag->GetType();
          char mtFCC[5];
          SignatureToFourCC(static_cast<icUInt32Number>(mType), mtFCC);
          printf("        Member '%s': type='%s' size=%u",
                 mFCC, mtFCC, me->TagInfo.size);

          if (mTag->IsNumArrayType()) {
            CIccTagNumArray *pNum = dynamic_cast<CIccTagNumArray*>(mTag);
            if (pNum) {
              printf(" values=%u", pNum->GetNumValues());
            }
          }
          printf("\n");

          // Check member type signature for non-printable bytes
          icUInt32Number mTypeVal = static_cast<icUInt32Number>(mType);
          icUInt8Number tb[4];
          tb[0] = (mTypeVal >> 24) & 0xFF;
          tb[1] = (mTypeVal >> 16) & 0xFF;
          tb[2] = (mTypeVal >> 8) & 0xFF;
          tb[3] = mTypeVal & 0xFF;
          bool mAllPrint = true;
          bool mAllZero = (mTypeVal == 0);
          for (int b = 0; b < 4; b++) {
            if (tb[b] < 0x20 || tb[b] > 0x7E) mAllPrint = false;
          }
          if (mAllZero) {
            printf("        %s[WARN]  Member '%s' has null type (0x00000000)%s\n",
                   ColorWarning(), mFCC, ColorReset());
            structIssues++;
          } else if (!mAllPrint) {
            printf("        %s[WARN]  Member '%s' has non-ASCII type: 0x%08X%s\n",
                   ColorWarning(), mFCC, mTypeVal, ColorReset());
            structIssues++;
          }
        } else {
          printf("        Member '%s': size=%u %s[UNREADABLE]%s\n",
                 mFCC, me->TagInfo.size, ColorWarning(), ColorReset());
          structIssues++;
        }
      }
    }
  }
  if (!foundStruct) {
    printf("      %s[OK] No tagStruct tags present%s\n", ColorSuccess(), ColorReset());
  } else if (structIssues > 0) {
    heuristicCount += structIssues;
  } else {
    printf("      %s[OK] tagStruct members appear well-formed%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H22_NumArrayScalarExpectation(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 22. NumArray Scalar Expectation Validation (cept-specific)
printf("[H22] NumArray Scalar Expectation (cept struct)\n");
{
  int scalarIssues = 0;
  CIccTagStruct *pCept = FindAndCast<CIccTagStruct>(pIcc, icSigColorEncodingParamsTag);

  if (!pCept) {
    printf("      %s[OK] No cept (ColorEncodingParams) tag — check not applicable%s\n",
           ColorSuccess(), ColorReset());
  } else {
    // Members consumed as scalars by GetElemNumberValue() in IccEncoding.cpp
    struct ScalarMember {
      icSignature sig;
      const char *name;
    };
    const ScalarMember scalarMembers[] = {
      { icSigCeptWhitePointLuminanceMbr,           "wlum (WhitePointLuminance)" },
      { icSigCeptAmbientWhitePointLuminanceMbr,    "awlm (AmbientWPLuminance)" },
      { icSigCeptViewingSurroundMbr,               "srnd (ViewingSurround)" },
      { icSigCeptMediumWhitePointLuminanceMbr,     "mwpl (MediumWPLuminance)" },
    };

    for (size_t s = 0; s < sizeof(scalarMembers)/sizeof(scalarMembers[0]); s++) {
      CIccTag *mTag = pCept->FindElem(scalarMembers[s].sig);
      if (!mTag) continue;
      if (!mTag->IsNumArrayType()) continue;

      CIccTagNumArray *pNum = dynamic_cast<CIccTagNumArray*>(mTag);
      if (!pNum) continue;

      icUInt32Number numVals = pNum->GetNumValues();
      if (numVals > 1) {
        printf("      %s[WARN]  %s has %u values (expected 1 scalar)%s\n",
               ColorCritical(), scalarMembers[s].name, numVals, ColorReset());
        printf("       %sRisk: Stack buffer overflow in GetElemNumberValue → GetValues%s\n",
               ColorCritical(), ColorReset());
        printf("       %s(SCARINESS: 51 — 4-byte-write-stack-buffer-overflow, CFL patch 027)%s\n",
               ColorCritical(), ColorReset());
        scalarIssues++;
      } else {
        printf("      [OK] %s: %u value (scalar)\n", scalarMembers[s].name, numVals);
      }
    }
  }
  if (scalarIssues > 0) {
    heuristicCount += scalarIssues;
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H23_NumArrayValueRange(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 23. NumArray Value Range Validation
printf("[H23] NumArray Value Range Validation\n");
{
  int rangeIssues = 0;
  TagEntryList::iterator it;
  for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    IccTagEntry *e = &(*it);
    CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
    if (!pTag || !pTag->IsNumArrayType()) continue;

    CIccTagNumArray *pNum = dynamic_cast<CIccTagNumArray*>(pTag);
    if (!pNum) continue;

    icUInt32Number numVals = pNum->GetNumValues();
    if (numVals == 0 || numVals > 1048576) {
      char sigFCC[5];
      SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), sigFCC);
      if (numVals == 0) {
        printf("      %s[WARN]  Tag '%s': empty NumArray (0 values)%s\n",
               ColorWarning(), sigFCC, ColorReset());
      } else {
        printf("      %s[WARN]  Tag '%s': excessive NumArray (%u values)%s\n",
               ColorCritical(), sigFCC, numVals, ColorReset());
      }
      rangeIssues++;
      continue;
    }

    // Allocate full numVals buffer — unpatched GetValues loops over m_nSize
    icUInt32Number sampleSize = (numVals < 64) ? numVals : 64;
    std::vector<icFloatNumber> vals(numVals);

    if (pNum->GetValues(vals.data(), 0, numVals)) {
      int nanCount = 0, infCount = 0;
      for (icUInt32Number v = 0; v < sampleSize; v++) {
        if (std::isnan(vals[v])) nanCount++;
        if (std::isinf(vals[v])) infCount++;
      }
      if (nanCount > 0 || infCount > 0) {
        char sigFCC[5];
        SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), sigFCC);
        if (nanCount > 0) {
          printf("      %s[WARN]  Tag '%s': %d NaN value(s) in NumArray%s\n",
                 ColorCritical(), sigFCC, nanCount, ColorReset());
        }
        if (infCount > 0) {
          printf("      %s[WARN]  Tag '%s': %d Inf value(s) in NumArray%s\n",
                 ColorCritical(), sigFCC, infCount, ColorReset());
        }
        printf("       %sRisk: Floating-point exceptions, division-by-zero%s\n",
               ColorWarning(), ColorReset());
        printf("       %sCWE-681: NaN/Inf propagation → UB in IccIO Write (iccDEV #536)%s\n",
               ColorCritical(), ColorReset());
        rangeIssues++;
      }
    }
  }

  // Also check NumArrays inside tagStruct members
  for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    IccTagEntry *e = &(*it);
    CIccTagStruct *pStruct = FindAndCast<CIccTagStruct>(pIcc, e->TagInfo.sig);
    if (!pStruct) continue;

    TagEntryList *pElems = pStruct->GetElemList();
    if (!pElems) continue;

    char parentFCC[5];
    SignatureToFourCC(static_cast<icUInt32Number>(e->TagInfo.sig), parentFCC);

    TagEntryList::iterator eit;
    for (eit = pElems->begin(); eit != pElems->end(); eit++) {
      IccTagEntry *me = &(*eit);
      CIccTag *mTag = pStruct->FindElem(me->TagInfo.sig);
      if (!mTag || !mTag->IsNumArrayType()) continue;

      CIccTagNumArray *pNum = dynamic_cast<CIccTagNumArray*>(mTag);
      if (!pNum) continue;

      icUInt32Number numVals = pNum->GetNumValues();
      if (numVals == 0 || numVals > 1048576) continue; // Already flagged or skip

      icUInt32Number sampleSize = (numVals < 64) ? numVals : 64;
      std::vector<icFloatNumber> vals(numVals);

      if (pNum->GetValues(vals.data(), 0, numVals)) {
        int nanCount = 0, infCount = 0;
        for (icUInt32Number v = 0; v < sampleSize; v++) {
          if (std::isnan(vals[v])) nanCount++;
          if (std::isinf(vals[v])) infCount++;
        }
        if (nanCount > 0 || infCount > 0) {
          char mFCC[5];
          SignatureToFourCC(static_cast<icUInt32Number>(me->TagInfo.sig), mFCC);
          printf("      %s[WARN]  Struct '%s' member '%s': ", ColorCritical(), parentFCC, mFCC);
          if (nanCount > 0) printf("%d NaN ", nanCount);
          if (infCount > 0) printf("%d Inf ", infCount);
          printf("value(s)%s\n", ColorReset());
          rangeIssues++;
        }
      }
    }
  }

  if (rangeIssues > 0) {
    heuristicCount += rangeIssues;
  } else {
    printf("      %s[OK] All NumArray values within normal ranges%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H24_TagStructNestingDepth(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 24. tagStruct/tagArray Nesting Depth Check
printf("[H24] tagStruct/tagArray Nesting Depth\n");
{
  int nestIssues = 0;
  const int MAX_SAFE_DEPTH = 4;

  // Lambda-like depth walk using iterative approach with stack
  struct DepthEntry { CIccTag *tag; int depth; };
  std::vector<DepthEntry> stack;

  TagEntryList::iterator it;
  for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
    IccTagEntry *e = &(*it);
    CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
    if (!pTag) continue;
    stack.push_back({pTag, 0});
  }

  int maxDepth = 0;
  while (!stack.empty()) {
    DepthEntry cur = stack.back();
    stack.pop_back();

    if (cur.depth > maxDepth) maxDepth = cur.depth;

    if (cur.depth > MAX_SAFE_DEPTH) {
      printf("      %s[WARN]  Nesting depth %d exceeds safe limit (%d)%s\n",
             ColorCritical(), cur.depth, MAX_SAFE_DEPTH, ColorReset());
      printf("       %sRisk: Stack overflow via recursive Read/Describe (CFL patch 061)%s\n",
             ColorCritical(), ColorReset());
      nestIssues++;
      continue; // Don't descend further
    }

    CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct*>(cur.tag);
    if (pStruct) {
      TagEntryList *pElems = pStruct->GetElemList();
      if (pElems) {
        TagEntryList::iterator eit;
        for (eit = pElems->begin(); eit != pElems->end(); eit++) {
          CIccTag *mTag = pStruct->FindElem((*eit).TagInfo.sig);
          if (mTag) {
            stack.push_back({mTag, cur.depth + 1});
          }
        }
      }
    }

    CIccTagArray *pArr = dynamic_cast<CIccTagArray*>(cur.tag);
    if (pArr) {
      icUInt32Number arrSize = pArr->GetSize();
      // Limit iteration to prevent runaway
      icUInt32Number checkLimit = (arrSize < 64) ? arrSize : 64;
      for (icUInt32Number idx = 0; idx < checkLimit; idx++) {
        CIccTag *aTag = pArr->GetIndex(idx);
        if (aTag) {
          stack.push_back({aTag, cur.depth + 1});
        }
      }
    }
  }

  if (nestIssues > 0) {
    heuristicCount += nestIssues;
  } else {
    printf("      %s[OK] Max nesting depth: %d (safe limit: %d)%s\n",
           ColorSuccess(), maxDepth, MAX_SAFE_DEPTH, ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H25_TagOffsetOOB(CIccProfile *pIcc, const char *filename) {
  int heuristicCount = 0;

// 25. Tag Offset/Size OOB Detection (raw file bytes)
// CVE refs: CVE-2026-25583 (HBO in CIccFileIO::Read8), CVE-2026-24852 (tag offset overflow)
printf("[H25] Tag Offset/Size Out-of-Bounds Detection\n");
{
  RawFileHandle fh25 = OpenRawFile(filename);
  if (fh25) {
    size_t realSize = (size_t)fh25.fileSize;
    
    int oobCount = 0;
    if (realSize >= 132) {
      icUInt8Number hdr25[132];
      if (fread(hdr25, 1, 132, fh25.fp) == 132) {
        icUInt32Number hdrProfileSize = (static_cast<icUInt32Number>(hdr25[0])<<24) | (static_cast<icUInt32Number>(hdr25[1])<<16) |
                                        (static_cast<icUInt32Number>(hdr25[2])<<8) | hdr25[3];
        icUInt32Number tc = (static_cast<icUInt32Number>(hdr25[128])<<24) | (static_cast<icUInt32Number>(hdr25[129])<<16) |
                            (static_cast<icUInt32Number>(hdr25[130])<<8) | hdr25[131];
        size_t bound = (realSize < hdrProfileSize) ? realSize : hdrProfileSize;
        
        for (icUInt32Number i = 0; i < tc && i < 256; i++) {
          size_t ePos = 132 + i * 12;
          if (ePos + 12 > realSize) break;
          
          icUInt8Number e25[12];
          fseek(fh25.fp, ePos, SEEK_SET);
          if (fread(e25, 1, 12, fh25.fp) != 12) break;
          
          icUInt32Number tSig = (static_cast<icUInt32Number>(e25[0])<<24) | (static_cast<icUInt32Number>(e25[1])<<16) |
                                (static_cast<icUInt32Number>(e25[2])<<8) | e25[3];
          icUInt32Number tOff = (static_cast<icUInt32Number>(e25[4])<<24) | (static_cast<icUInt32Number>(e25[5])<<16) |
                                (static_cast<icUInt32Number>(e25[6])<<8) | e25[7];
          icUInt32Number tSz  = (static_cast<icUInt32Number>(e25[8])<<24) | (static_cast<icUInt32Number>(e25[9])<<16) |
                                (static_cast<icUInt32Number>(e25[10])<<8) | e25[11];
          
          uint64_t tagEnd = (uint64_t)tOff + tSz;
          char sig25[5];
          sig25[0] = static_cast<char>((tSig>>24)&0xff); sig25[1] = static_cast<char>((tSig>>16)&0xff);
          sig25[2] = static_cast<char>((tSig>>8)&0xff);  sig25[3] = static_cast<char>(tSig&0xff); sig25[4] = '\0';
          
          if (tOff >= bound) {
            printf("      %s[WARN]  Tag '%s' offset 0x%X beyond file/profile bounds (%zu bytes)%s\n",
                   ColorCritical(), sig25, tOff, bound, ColorReset());
            oobCount++;
          } else if (tagEnd > bound) {
            printf("      %s[WARN]  Tag '%s' [offset=0x%X, size=%u] extends %llu bytes past bounds (%zu)%s\n",
                   ColorCritical(), sig25, tOff, tSz,
                   (unsigned long long)(tagEnd - bound), bound, ColorReset());
            oobCount++;
          }
        }
      }
    }

    
    if (oobCount > 0) {
      printf("      %s%d tag(s) reference data beyond file/profile bounds%s\n",
             ColorCritical(), oobCount, ColorReset());
      printf("      %sRisk: Heap-buffer-overflow when loading OOB tags%s\n",
             ColorCritical(), ColorReset());
      heuristicCount++;
    } else {
      printf("      %s[OK] All tag offsets/sizes within bounds%s\n", ColorSuccess(), ColorReset());
    }
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H26_NamedColor2StringValidation(CIccProfile *pIcc, const char *filename) {
  int heuristicCount = 0;

// 26. NamedColor2 String Validation (raw scan — checks tag TYPE, not signature)
// CVE refs: CVE-2026-21488 (non-null-terminated strings), CVE-2026-24852 (text overflow)
printf("[H26] NamedColor2 String Validation\n");
{
  RawFileHandle fh26 = OpenRawFile(filename);
  if (fh26) {
      size_t fs26 = (size_t)fh26.fileSize;
      
      int nc2Issues = 0;
      if (fs26 >= 132) {
        icUInt8Number hdr26[132];
        if (fread(hdr26, 1, 132, fh26.fp) == 132) {
          icUInt32Number tc26 = (static_cast<icUInt32Number>(hdr26[128])<<24) | (static_cast<icUInt32Number>(hdr26[129])<<16) |
                                (static_cast<icUInt32Number>(hdr26[130])<<8) | hdr26[131];
          
          for (icUInt32Number i = 0; i < tc26 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs26) break;
            
            icUInt8Number e26[12];
            fseek(fh26.fp, ePos, SEEK_SET);
            if (fread(e26, 1, 12, fh26.fp) != 12) break;
            
            icUInt32Number tOff26 = (static_cast<icUInt32Number>(e26[4])<<24) | (static_cast<icUInt32Number>(e26[5])<<16) |
                                    (static_cast<icUInt32Number>(e26[6])<<8) | e26[7];
            icUInt32Number tSz26  = (static_cast<icUInt32Number>(e26[8])<<24) | (static_cast<icUInt32Number>(e26[9])<<16) |
                                    (static_cast<icUInt32Number>(e26[10])<<8) | e26[11];
            
            // Read first 4 bytes of tag data to check type
            if (tOff26 > fs26 || tOff26 + 4 > fs26 || tSz26 < 84) continue;
            icUInt8Number typeCheck[4];
            fseek(fh26.fp, tOff26, SEEK_SET);
            if (fread(typeCheck, 1, 4, fh26.fp) != 4) continue;
            icUInt32Number tagType26 = (static_cast<icUInt32Number>(typeCheck[0])<<24) | (static_cast<icUInt32Number>(typeCheck[1])<<16) |
                                       (static_cast<icUInt32Number>(typeCheck[2])<<8) | typeCheck[3];
            if (tagType26 != 0x6E636C32) continue;  // Not 'ncl2' type
            if (tOff26 > fs26 || tOff26 + 84 > fs26) continue;
            
            // NamedColor2: type(4)+reserved(4)+vendorFlags(4)+count(4)+nDevCoords(4)+prefix(32)+suffix(32)
            icUInt8Number prefix[32], suffix[32];
            fseek(fh26.fp, tOff26 + 20, SEEK_SET);
            if (fread(prefix, 1, 32, fh26.fp) != 32) continue;
            if (fread(suffix, 1, 32, fh26.fp) != 32) continue;
            
            // Count XML-expandable chars: ' " & < > expand to 4-6 chars in icFixXml
            auto countXmlExpand = [](const icUInt8Number *buf, int len) -> int {
              int ct = 0;
              for (int j = 0; j < len && buf[j] != 0; j++) {
                if (buf[j] == '\'' || buf[j] == '"' || buf[j] == '&' ||
                    buf[j] == '<'  || buf[j] == '>')
                  ct++;
              }
              return ct;
            };
            
            int prefixLen = 0, suffixLen = 0;
            for (int j = 0; j < 32 && prefix[j]; j++) prefixLen++;
            for (int j = 0; j < 32 && suffix[j]; j++) suffixLen++;
            
            int prefixExpand = countXmlExpand(prefix, 32);
            int suffixExpand = countXmlExpand(suffix, 32);
            
            // icFixXml destination is char[256]. Expandable chars grow up to 6x (&apos; etc.)
            int prefixExpanded = prefixLen + prefixExpand * 5;
            int suffixExpanded = suffixLen + suffixExpand * 5;
            
            if (prefixExpanded > 255) {
              printf("      %s[HIGH] Prefix (%d bytes, %d XML-expandable) overflows icFixXml buffer (expanded: %d > 255)%s\n",
                     ColorCritical(), prefixLen, prefixExpand, prefixExpanded, ColorReset());
              printf("       %sRisk: Stack-buffer-overflow in icFixXml() (SCARINESS:55 class)%s\n",
                     ColorCritical(), ColorReset());
              nc2Issues++;
            } else if (prefixExpand > 0 && prefixLen > 20) {
              printf("      %s[WARN]  Prefix has %d XML-expandable chars in %d-byte string (expanded: %d)%s\n",
                     ColorWarning(), prefixExpand, prefixLen, prefixExpanded, ColorReset());
              nc2Issues++;
            }
            
            if (suffixExpanded > 255) {
              printf("      %s[HIGH] Suffix (%d bytes, %d XML-expandable) overflows icFixXml buffer (expanded: %d > 255)%s\n",
                     ColorCritical(), suffixLen, suffixExpand, suffixExpanded, ColorReset());
              printf("       %sRisk: Stack-buffer-overflow in icFixXml() (SCARINESS:55 class)%s\n",
                     ColorCritical(), ColorReset());
              nc2Issues++;
            } else if (suffixExpand > 0 && suffixLen > 20) {
              printf("      %s[WARN]  Suffix has %d XML-expandable chars in %d-byte string (expanded: %d)%s\n",
                     ColorWarning(), suffixExpand, suffixLen, suffixExpanded, ColorReset());
              nc2Issues++;
            }
            
            // Check for non-null-terminated strings
            bool prefixUnterminated = true, suffixUnterminated = true;
            for (int j = 0; j < 32; j++) { if (prefix[j] == 0) { prefixUnterminated = false; break; } }
            for (int j = 0; j < 32; j++) { if (suffix[j] == 0) { suffixUnterminated = false; break; } }
            
            if (prefixUnterminated) {
              printf("      %s[WARN]  Prefix not null-terminated (all 32 bytes non-zero)%s\n",
                     ColorCritical(), ColorReset());
              printf("       %sRisk: strlen overflow, icFixXml reads past buffer boundary%s\n",
                     ColorCritical(), ColorReset());
              nc2Issues++;
            }
            if (suffixUnterminated) {
              printf("      %s[WARN]  Suffix not null-terminated (all 32 bytes non-zero)%s\n",
                     ColorCritical(), ColorReset());
              printf("       %sRisk: strlen overflow, icFixXml reads past buffer boundary%s\n",
                     ColorCritical(), ColorReset());
              nc2Issues++;
            }
          }
        }
      }

      
      if (nc2Issues > 0) {
        heuristicCount += nc2Issues;
      } else {
        printf("      %s[OK] No NamedColor2 tags with risky strings%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H27_MPEMatrixOutputChannel(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 27. MPE Matrix Output Channel Validation
// CVE refs: CVE-2026-25634 (memcpy-param-overlap), CVE-2026-22047 (CalcOp element bounds)
printf("[H27] MPE Matrix Output Channel Validation\n");
{
  int matrixIssues = 0;
  icUInt32Number mpeSigs[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
    icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
    icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag
  };
  for (auto sig : mpeSigs) {
    CIccTagMultiProcessElement *pMpe = FindAndCast<CIccTagMultiProcessElement>(pIcc, (icTagSignature)sig);
    if (!pMpe) continue;
    
    icUInt32Number numElements = pMpe->NumElements();
    
    int elemIdx = 0;
    for (icUInt32Number ei = 0; ei < numElements && elemIdx < 64; ei++, elemIdx++) {
      CIccMultiProcessElement *pElem = pMpe->GetElement(ei);
      if (!pElem) continue;
      
      // Check for matrix elements with 0 output channels
      CIccMpeMatrix *pMatrix = dynamic_cast<CIccMpeMatrix*>(pElem);
      if (pMatrix) {
        icUInt16Number numOut = pMatrix->NumOutputChannels();
        icUInt16Number numIn = pMatrix->NumInputChannels();
        
        char sigStr27[5];
        SignatureToFourCC(sig, sigStr27);
        
        if (numOut == 0 || numIn == 0) {
          printf("      %s[WARN]  Tag '%s' elem %d: Matrix %ux%u — zero dimension%s\n",
                 ColorCritical(), sigStr27, elemIdx, numIn, numOut, ColorReset());
          printf("       %sRisk: Division by zero or null-pointer in matrix operations%s\n",
                 ColorCritical(), ColorReset());
          matrixIssues++;
        } else if (numOut < 3) {
          printf("      %s[WARN]  Tag '%s' elem %d: Matrix has %u output channels (XYZ needs 3)%s\n",
                 ColorWarning(), sigStr27, elemIdx, numOut, ColorReset());
          printf("       %sRisk: HBO in pushXYZConvert accessing pOffset[0..2] on %u-channel matrix%s\n",
                 ColorCritical(), numOut, ColorReset());
          matrixIssues++;
        }
      }
      
      // Check calculator elements for sub-element count
      CIccMpeCalculator *pCalc = dynamic_cast<CIccMpeCalculator*>(pElem);
      if (pCalc) {
        icUInt16Number calcOut = pCalc->NumOutputChannels();
        icUInt16Number calcIn = pCalc->NumInputChannels();
        
        char sigStr27c[5];
        SignatureToFourCC(sig, sigStr27c);
        
        if (calcOut == 0 || calcIn == 0) {
          printf("      %s[WARN]  Tag '%s' elem %d: Calculator %ux%u — zero dimension%s\n",
                 ColorCritical(), sigStr27c, elemIdx, calcIn, calcOut, ColorReset());
          matrixIssues++;
        }
      }
    }
  }
  
  if (matrixIssues > 0) {
    heuristicCount += matrixIssues;
  } else {
    printf("      %s[OK] All MPE matrix/calculator dimensions valid%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H28_LUTDimensionValidation(CIccProfile *pIcc, const char *filename) {
  int heuristicCount = 0;

// 28. LUT Dimension Validation (raw file bytes)
// CVE refs: CVE-2026-21490, CVE-2026-21494, GHSA-x9hr-pxxc-h38p (OOM via extreme nInput^nGrid)
// LUT8 type='mft1', LUT16 type='mft2': nInput/nOutput/nGrid parsed from raw bytes
printf("[H28] LUT Dimension Validation (OOM Risk)\n");
{
  RawFileHandle fh28 = OpenRawFile(filename);
  if (fh28) {
    size_t fs28 = (size_t)fh28.fileSize;

    int lutIssues = 0;
    if (fs28 >= 132) {
      icUInt8Number hdr28[132];
      if (fread(hdr28, 1, 132, fh28.fp) == 132) {
        icUInt32Number tc28 = (static_cast<icUInt32Number>(hdr28[128])<<24) | (static_cast<icUInt32Number>(hdr28[129])<<16) |
                              (static_cast<icUInt32Number>(hdr28[130])<<8) | hdr28[131];

        for (icUInt32Number i = 0; i < tc28 && i < 256; i++) {
          size_t ePos = 132 + i * 12;
          if (ePos + 12 > fs28) break;

          icUInt8Number e28[12];
          fseek(fh28.fp, ePos, SEEK_SET);
          if (fread(e28, 1, 12, fh28.fp) != 12) break;

          icUInt32Number tOff28 = (static_cast<icUInt32Number>(e28[4])<<24) | (static_cast<icUInt32Number>(e28[5])<<16) |
                                  (static_cast<icUInt32Number>(e28[6])<<8) | e28[7];
          icUInt32Number tSz28  = (static_cast<icUInt32Number>(e28[8])<<24) | (static_cast<icUInt32Number>(e28[9])<<16) |
                                  (static_cast<icUInt32Number>(e28[10])<<8) | e28[11];

          // Need at least type(4) + reserved(4) + nInput(1) + nOutput(1) + nGrid(1) = 11 bytes
          if (tOff28 > fs28 || tOff28 + 11 > fs28 || tSz28 < 11) continue;
          icUInt8Number lutHdr[11];
          fseek(fh28.fp, tOff28, SEEK_SET);
          if (fread(lutHdr, 1, 11, fh28.fp) != 11) continue;

          icUInt32Number lutType = (static_cast<icUInt32Number>(lutHdr[0])<<24) | (static_cast<icUInt32Number>(lutHdr[1])<<16) |
                                   (static_cast<icUInt32Number>(lutHdr[2])<<8) | lutHdr[3];

          // Check for LUT8 (0x6D667431='mft1') or LUT16 (0x6D667432='mft2')
          if (lutType != 0x6D667431 && lutType != 0x6D667432) continue;

          icUInt8Number nInput28  = lutHdr[8];
          icUInt8Number nOutput28 = lutHdr[9];
          icUInt8Number nGrid28   = lutHdr[10];

          char sig28[5];
          sig28[0] = (e28[0]); sig28[1] = (e28[1]);
          sig28[2] = (e28[2]); sig28[3] = (e28[3]); sig28[4] = '\0';

          // Spec max: nInput ≤ 16, nOutput ≤ 16
          if (nInput28 > 16 || nOutput28 > 16) {
            printf("      %s[WARN]  Tag '%s' (%s): nInput=%u nOutput=%u exceeds spec max (16)%s\n",
                   ColorCritical(), sig28, (lutType == 0x6D667431) ? "LUT8" : "LUT16",
                   nInput28, nOutput28, ColorReset());
            printf("       %sRisk: Buffer overflow in grid point arrays (max 16 channels)%s\n",
                   ColorCritical(), ColorReset());
            lutIssues++;
            continue;
          }

          // Compute CLUT point count: nGrid^nInput * nOutput
          uint64_t points = 1;
          bool overflow28 = false;
          for (int ch = 0; ch < nInput28; ch++) {
            uint64_t prev = points;
            points *= nGrid28;
            if (nGrid28 > 0 && points / nGrid28 != prev) { overflow28 = true; break; }
          }
          if (!overflow28) {
            uint64_t prev = points;
            points *= nOutput28;
            if (nOutput28 > 0 && points / nOutput28 != prev) overflow28 = true;
          }

          // 16M entries × 4 bytes = 64MB — generous limit
          const uint64_t MAX_LUT_POINTS = 16ULL * 1024 * 1024;
          if (overflow28 || points > MAX_LUT_POINTS) {
            printf("      %s[WARN]  Tag '%s' (%s): nInput=%u nOutput=%u nGrid=%u → %s CLUT points%s\n",
                   ColorCritical(), sig28, (lutType == 0x6D667431) ? "LUT8" : "LUT16",
                   nInput28, nOutput28, nGrid28,
                   overflow28 ? "OVERFLOW" : std::to_string(points).c_str(),
                   ColorReset());
            printf("       %sRisk: OOM — allocation of %s bytes in CIccCLUT::Init()%s\n",
                   ColorCritical(),
                   overflow28 ? ">2^64" : std::to_string(points * 4).c_str(),
                   ColorReset());
            lutIssues++;
          } else if (nInput28 > 0 && nGrid28 > 0) {
            printf("      [OK] Tag '%s' (%s): %ux%ux%u → %llu points\n",
                   sig28, (lutType == 0x6D667431) ? "LUT8" : "LUT16",
                   nInput28, nOutput28, nGrid28, (unsigned long long)points);
          }
        }
      }
    }


    if (lutIssues > 0) {
      heuristicCount += lutIssues;
    } else {
      printf("      %s[OK] All LUT dimensions within safe limits%s\n", ColorSuccess(), ColorReset());
    }
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H29_ColorantTableStringValidation(CIccProfile *pIcc, const char *filename) {
  int heuristicCount = 0;

// 29. ColorantTable String Validation (raw file bytes)
// CVE refs: GHSA-4wqv-pvm8-5h27 (OOB read via unterminated colorant name[32])
// CVE-2026-27692 (HBO in TextDescription from unterminated strings)
printf("[H29] ColorantTable String Validation\n");
{
  RawFileHandle fh29 = OpenRawFile(filename);
  if (fh29) {
    size_t fs29 = (size_t)fh29.fileSize;

    int clrtIssues = 0;
    if (fs29 >= 132) {
      icUInt8Number hdr29[132];
      if (fread(hdr29, 1, 132, fh29.fp) == 132) {
        icUInt32Number tc29 = (static_cast<icUInt32Number>(hdr29[128])<<24) | (static_cast<icUInt32Number>(hdr29[129])<<16) |
                              (static_cast<icUInt32Number>(hdr29[130])<<8) | hdr29[131];

        for (icUInt32Number i = 0; i < tc29 && i < 256; i++) {
          size_t ePos = 132 + i * 12;
          if (ePos + 12 > fs29) break;

          icUInt8Number e29[12];
          fseek(fh29.fp, ePos, SEEK_SET);
          if (fread(e29, 1, 12, fh29.fp) != 12) break;

          icUInt32Number tOff29 = (static_cast<icUInt32Number>(e29[4])<<24) | (static_cast<icUInt32Number>(e29[5])<<16) |
                                  (static_cast<icUInt32Number>(e29[6])<<8) | e29[7];
          icUInt32Number tSz29  = (static_cast<icUInt32Number>(e29[8])<<24) | (static_cast<icUInt32Number>(e29[9])<<16) |
                                  (static_cast<icUInt32Number>(e29[10])<<8) | e29[11];

          // Read type signature
          if (tOff29 > fs29 || tOff29 + 12 > fs29 || tSz29 < 12) continue;
          icUInt8Number typeCheck29[12];
          fseek(fh29.fp, tOff29, SEEK_SET);
          if (fread(typeCheck29, 1, 12, fh29.fp) != 12) continue;

          icUInt32Number tagType29 = (static_cast<icUInt32Number>(typeCheck29[0])<<24) | (static_cast<icUInt32Number>(typeCheck29[1])<<16) |
                                      (static_cast<icUInt32Number>(typeCheck29[2])<<8) | typeCheck29[3];

          // 'clrt' = 0x636C7274
          if (tagType29 != 0x636C7274) continue;

          // ColorantTable layout: type(4)+reserved(4)+count(4) then count × entry(38)
          // Each entry: name[32] + data[6]
          icUInt32Number colorantCount = (static_cast<icUInt32Number>(typeCheck29[8])<<24) | (static_cast<icUInt32Number>(typeCheck29[9])<<16) |
                                          (static_cast<icUInt32Number>(typeCheck29[10])<<8) | typeCheck29[11];

          if (colorantCount > 256) {
            printf("      %s[WARN]  ColorantTable: count=%u (>256) — excessive allocation risk%s\n",
                   ColorCritical(), colorantCount, ColorReset());
            clrtIssues++;
            continue;
          }

          // Check each colorant name for null termination
          for (icUInt32Number ci = 0; ci < colorantCount && ci < 256; ci++) {
            size_t namePos = tOff29 + 12 + ci * 38;
            if (namePos + 32 > fs29) break;

            icUInt8Number name29[32];
            fseek(fh29.fp, namePos, SEEK_SET);
            if (fread(name29, 1, 32, fh29.fp) != 32) break;

            bool hasNull = false;
            for (int j = 0; j < 32; j++) {
              if (name29[j] == 0) { hasNull = true; break; }
            }
            if (!hasNull) {
              printf("      %s[WARN]  Colorant[%u] name not null-terminated (all 32 bytes non-zero)%s\n",
                     ColorCritical(), ci, ColorReset());
              printf("       %sRisk: strlen overflow in ToXml → heap-buffer-overflow read%s\n",
                     ColorCritical(), ColorReset());
              clrtIssues++;
            }
          }
        }
      }
    }


    if (clrtIssues > 0) {
      heuristicCount += clrtIssues;
    } else {
      printf("      %s[OK] No ColorantTable string issues detected%s\n", ColorSuccess(), ColorReset());
    }
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H30_GamutBoundaryDescAllocation(CIccProfile *pIcc, const char *filename) {
  int heuristicCount = 0;

// 30. GamutBoundaryDesc Allocation Validation (raw file bytes)
// CVE refs: GHSA-rc3h-95ph-j363 (OOM via unvalidated triangle count in 'gbd ' tags)
printf("[H30] GamutBoundaryDesc Allocation Validation\n");
{
  RawFileHandle fh30 = OpenRawFile(filename);
  if (fh30) {
    size_t fs30 = (size_t)fh30.fileSize;

    int gbdIssues = 0;
    if (fs30 >= 132) {
      icUInt8Number hdr30[132];
      if (fread(hdr30, 1, 132, fh30.fp) == 132) {
        icUInt32Number tc30 = (static_cast<icUInt32Number>(hdr30[128])<<24) | (static_cast<icUInt32Number>(hdr30[129])<<16) |
                              (static_cast<icUInt32Number>(hdr30[130])<<8) | hdr30[131];

        for (icUInt32Number i = 0; i < tc30 && i < 256; i++) {
          size_t ePos = 132 + i * 12;
          if (ePos + 12 > fs30) break;

          icUInt8Number e30[12];
          fseek(fh30.fp, ePos, SEEK_SET);
          if (fread(e30, 1, 12, fh30.fp) != 12) break;

          icUInt32Number tOff30 = (static_cast<icUInt32Number>(e30[4])<<24) | (static_cast<icUInt32Number>(e30[5])<<16) |
                                  (static_cast<icUInt32Number>(e30[6])<<8) | e30[7];
          icUInt32Number tSz30  = (static_cast<icUInt32Number>(e30[8])<<24) | (static_cast<icUInt32Number>(e30[9])<<16) |
                                  (static_cast<icUInt32Number>(e30[10])<<8) | e30[11];

          // 'gbd ' type header: type(4)+reserved(4)+reserved(4)+nVertices(4)+nTriangles(4)+nPCSCh(2)+nDevCh(2) = 24 bytes
          if (tOff30 > fs30 || tOff30 + 24 > fs30 || tSz30 < 24) continue;
          icUInt8Number gbdHdr[24];
          fseek(fh30.fp, tOff30, SEEK_SET);
          if (fread(gbdHdr, 1, 24, fh30.fp) != 24) continue;

          icUInt32Number gbdType = (static_cast<icUInt32Number>(gbdHdr[0])<<24) | (static_cast<icUInt32Number>(gbdHdr[1])<<16) |
                                   (static_cast<icUInt32Number>(gbdHdr[2])<<8) | gbdHdr[3];

          // 'gbd ' = 0x67626420
          if (gbdType != 0x67626420) continue;

          icUInt32Number nVerts = (static_cast<icUInt32Number>(gbdHdr[12])<<24) | (static_cast<icUInt32Number>(gbdHdr[13])<<16) |
                                  (static_cast<icUInt32Number>(gbdHdr[14])<<8) | gbdHdr[15];
          icUInt32Number nTris  = (static_cast<icUInt32Number>(gbdHdr[16])<<24) | (static_cast<icUInt32Number>(gbdHdr[17])<<16) |
                                  (static_cast<icUInt32Number>(gbdHdr[18])<<8) | gbdHdr[19];
          icUInt16Number nPCSCh = (static_cast<icUInt16Number>(gbdHdr[20])<<8) | gbdHdr[21];
          icUInt16Number nDevCh = (static_cast<icUInt16Number>(gbdHdr[22])<<8) | gbdHdr[23];

          // Triangle allocation: nTriangles × 12 bytes
          uint64_t triAlloc = (uint64_t)nTris * 12;
          // Vertex arrays: nVertices × (3*4 + nPCSCh*4 + nDevCh*4)
          uint64_t vertAlloc = (uint64_t)nVerts * (12 + (uint64_t)nPCSCh * 4 + (uint64_t)nDevCh * 4);
          uint64_t totalAlloc = triAlloc + vertAlloc + 24;

          char sig30[5];
          sig30[0] = static_cast<char>(e30[0]); sig30[1] = static_cast<char>(e30[1]); sig30[2] = static_cast<char>(e30[2]); sig30[3] = static_cast<char>(e30[3]); sig30[4] = '\0';

          // Check: allocation exceeds tag size (OOM risk)
          if (totalAlloc > (uint64_t)tSz30 * 4) {
            printf("      %s[WARN]  Tag '%s' (gbd): %u vertices, %u triangles, PCS=%u Dev=%u%s\n",
                   ColorCritical(), sig30, nVerts, nTris, nPCSCh, nDevCh, ColorReset());
            printf("       %sAllocation: %llu bytes vs tag size %u bytes%s\n",
                   ColorCritical(), (unsigned long long)totalAlloc, tSz30, ColorReset());
            printf("       %sRisk: OOM in CIccTagGamutBoundaryDesc::Read()%s\n",
                   ColorCritical(), ColorReset());
            gbdIssues++;
          }

          // Check: negative channel counts (icUInt16Number interpreted as signed)
          if (nPCSCh > 3 || nDevCh > 15) {
            printf("      %s[WARN]  Tag '%s' (gbd): PCS channels=%u, Device channels=%u — out of range%s\n",
                   ColorWarning(), sig30, nPCSCh, nDevCh, ColorReset());
            printf("       %sRisk: Signed/unsigned confusion in allocation size%s\n",
                   ColorCritical(), ColorReset());
            gbdIssues++;
          }
        }
      }
    }


    if (gbdIssues > 0) {
      heuristicCount += gbdIssues;
    } else {
      printf("      %s[OK] No GamutBoundaryDesc allocation issues%s\n", ColorSuccess(), ColorReset());
    }
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H31_MPEChannelCount(CIccProfile *pIcc) {
  int heuristicCount = 0;

// 31. MPE Channel Count Validation
// CVE refs: CVE-2026-25634 (memcpy-param-overlap from large m_nInputChannels)
// CVE-2026-25584 (SBO in CIccTagFloatNum::GetValues)
// CVE-2026-25585 (OOB in CIccXform3DLut::Apply)
printf("[H31] MPE Channel Count Validation\n");
{
  int channelIssues = 0;
  icUInt32Number mpeSigs31[] = {
    icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
    icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
    icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
    icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag
  };
  for (auto sig31 : mpeSigs31) {
    CIccTagMultiProcessElement *pMpe31 = FindAndCast<CIccTagMultiProcessElement>(pIcc, (icTagSignature)sig31);
    if (!pMpe31) continue;

    icUInt16Number mpeIn  = pMpe31->NumInputChannels();
    icUInt16Number mpeOut = pMpe31->NumOutputChannels();

    char sigStr31[5];
    SignatureToFourCC(sig31, sigStr31);

    // MPE with extreme channel counts → memcpy overlap on stack buffers
    if (mpeIn > 32 || mpeOut > 32) {
      printf("      %s[WARN]  Tag '%s': MPE channels in=%u out=%u (>32)%s\n",
             ColorCritical(), sigStr31, mpeIn, mpeOut, ColorReset());
      printf("       %sRisk: memcpy-param-overlap in Apply(), stack buffer overflow%s\n",
             ColorCritical(), ColorReset());
      channelIssues++;
    }

    // Check individual elements for channel mismatches
    icUInt32Number nElems31 = pMpe31->NumElements();
    for (icUInt32Number ei = 0; ei < nElems31 && ei < 64; ei++) {
      CIccMultiProcessElement *pElem31 = pMpe31->GetElement(ei);
      if (!pElem31) continue;

      icUInt16Number elemIn  = pElem31->NumInputChannels();
      icUInt16Number elemOut = pElem31->NumOutputChannels();

      if (elemIn > 64 || elemOut > 64) {
        printf("      %s[WARN]  Tag '%s' elem %u: channels in=%u out=%u (extreme)%s\n",
               ColorCritical(), sigStr31, ei, elemIn, elemOut, ColorReset());
        printf("       %sRisk: Stack buffer overflow in element Apply()%s\n",
               ColorCritical(), ColorReset());
        channelIssues++;
      }
    }
  }

  if (channelIssues > 0) {
    heuristicCount += channelIssues;
  } else {
    printf("      %s[OK] All MPE channel counts within safe limits%s\n", ColorSuccess(), ColorReset());
  }
}
printf("\n");

  return heuristicCount;
}

int RunHeuristic_H32_TagDataTypeConfusion(CIccProfile *pIcc, const char *filename) {
  int heuristicCount = 0;

// 32. Tag Data Type Confusion Detection (raw file bytes)
// CVE refs: GHSA-2pjj-3c98-qp37 (type confusion in ToXmlCurve)
// GHSA-xqq3-g894-w2h5 (HBO in IccTagXml from type confusion)
// Checks that tag type signatures are valid printable ICC 4CC codes
printf("[H32] Tag Data Type Confusion Detection\n");
{
  RawFileHandle fh32 = OpenRawFile(filename);
  if (fh32) {
    size_t fs32 = (size_t)fh32.fileSize;

    int typeConfusionCount = 0;
    if (fs32 >= 132) {
      icUInt8Number hdr32[132];
      if (fread(hdr32, 1, 132, fh32.fp) == 132) {
        icUInt32Number tc32 = (static_cast<icUInt32Number>(hdr32[128])<<24) | (static_cast<icUInt32Number>(hdr32[129])<<16) |
                              (static_cast<icUInt32Number>(hdr32[130])<<8) | hdr32[131];

        // Known valid ICC tag type signatures
        static const icUInt32Number knownTypes[] = {
          0x63757276, // 'curv' - curveType
          0x70617261, // 'para' - parametricCurveType
          0x6D667431, // 'mft1' - lut8Type
          0x6D667432, // 'mft2' - lut16Type
          0x6D414220, // 'mAB ' - lutAtoBType
          0x6D424120, // 'mBA ' - lutBtoAType
          0x6D706574, // 'mpet' - multiProcessElementsType
          0x58595A20, // 'XYZ ' - XYZType
          0x74657874, // 'text' - textType
          0x64657363, // 'desc' - textDescriptionType
          0x6D6C7563, // 'mluc' - multiLocalizedUnicodeType
          0x73663332, // 'sf32' - s15Fixed16ArrayType
          0x75663332, // 'uf32' - u16Fixed16ArrayType
          0x73696720, // 'sig ' - signatureType
          0x64617461, // 'data' - dataType
          0x6474696D, // 'dtim' - dateTimeType
          0x76696577, // 'view' - viewingConditionsType
          0x6D656173, // 'meas' - measurementType
          0x6E636C32, // 'ncl2' - namedColor2Type
          0x636C7274, // 'clrt' - colorantTableType
          0x636C726F, // 'clro' - colorantOrderType
          0x63727064, // 'crpd' - crdInfoType
          0x75693038, // 'ui08' - uInt8ArrayType
          0x75693136, // 'ui16' - uInt16ArrayType
          0x75693332, // 'ui32' - uInt32ArrayType
          0x75693634, // 'ui64' - uInt64ArrayType
          0x666C3136, // 'fl16' - float16ArrayType
          0x666C3332, // 'fl32' - float32ArrayType
          0x666C3634, // 'fl64' - float64ArrayType
          0x67626420, // 'gbd ' - gamutBoundaryDescType
          0x63696370, // 'cicp' - cicpType
          0x73706563, // 'spec' - spectralDataInfoType
          0x736D6174, // 'smat' - sparseMatrixArrayType
          0x74617279, // 'tary' - tagArrayType
          0x74737472, // 'tstr' - tagStructType
          0x7A757466, // 'zutf' - zipUtf8Type
          0x7A786D6C, // 'zxml' - zipXmlType
          0x75746638, // 'utf8' - utf8Type
          0x64696374, // 'dict' - dictType
          0x656D6274, // 'embt' - embeddedHeightImageType / embeddedNormalImageType
          0x636F6C52, // 'colR' - colorEncodingParamsStructType
          0x636F6C53, // 'colS' - colorSpaceTypeTagType
          0x7376636E, // 'svcn' - spectralViewingConditionsType
          0x7364696E, // 'sdin' - spectralDataInfoType
          0x736D7769, // 'smwi' - spectralMediaWhiteType
        };
        const int numKnownTypes = sizeof(knownTypes) / sizeof(knownTypes[0]);

        for (icUInt32Number i = 0; i < tc32 && i < 256; i++) {
          size_t ePos = 132 + i * 12;
          if (ePos + 12 > fs32) break;

          icUInt8Number e32[12];
          fseek(fh32.fp, ePos, SEEK_SET);
          if (fread(e32, 1, 12, fh32.fp) != 12) break;

          icUInt32Number tSig32 = (static_cast<icUInt32Number>(e32[0])<<24) | (static_cast<icUInt32Number>(e32[1])<<16) |
                                  (static_cast<icUInt32Number>(e32[2])<<8) | e32[3];
          icUInt32Number tOff32 = (static_cast<icUInt32Number>(e32[4])<<24) | (static_cast<icUInt32Number>(e32[5])<<16) |
                                  (static_cast<icUInt32Number>(e32[6])<<8) | e32[7];
          icUInt32Number tSz32  = (static_cast<icUInt32Number>(e32[8])<<24) | (static_cast<icUInt32Number>(e32[9])<<16) |
                                  (static_cast<icUInt32Number>(e32[10])<<8) | e32[11];

          if (tOff32 > fs32 || tOff32 + 4 > fs32 || tSz32 < 4) continue;
          icUInt8Number typeData32[4];
          fseek(fh32.fp, tOff32, SEEK_SET);
          if (fread(typeData32, 1, 4, fh32.fp) != 4) continue;

          icUInt32Number dataType32 = (static_cast<icUInt32Number>(typeData32[0])<<24) | (static_cast<icUInt32Number>(typeData32[1])<<16) |
                                       (static_cast<icUInt32Number>(typeData32[2])<<8) | typeData32[3];

          // Already caught by H20 (non-printable type bytes)
          // Here we check if the type is a known ICC type signature
          bool isKnown = false;
          for (int k = 0; k < numKnownTypes; k++) {
            if (dataType32 == knownTypes[k]) { isKnown = true; break; }
          }

          if (!isKnown) {
            // Check if all 4 bytes are printable ASCII (might be a valid extension type)
            bool allPrintable = true;
            for (int b = 0; b < 4; b++) {
              if (typeData32[b] < 0x20 || typeData32[b] > 0x7E) { allPrintable = false; break; }
            }

            if (!allPrintable) {
              // Already caught by H20, skip to avoid duplicate
              continue;
            }

            char sigStr32[5], typeStr32[5];
            sigStr32[0] = static_cast<char>((tSig32>>24)&0xff); sigStr32[1] = static_cast<char>((tSig32>>16)&0xff);
            sigStr32[2] = static_cast<char>((tSig32>>8)&0xff); sigStr32[3] = static_cast<char>(tSig32&0xff); sigStr32[4] = '\0';
            typeStr32[0] = static_cast<char>((dataType32>>24)&0xff); typeStr32[1] = static_cast<char>((dataType32>>16)&0xff);
            typeStr32[2] = static_cast<char>((dataType32>>8)&0xff); typeStr32[3] = static_cast<char>(dataType32&0xff); typeStr32[4] = '\0';

            printf("      %s[WARN]  Tag '%s': unknown type signature '%s' (0x%08X)%s\n",
                   ColorWarning(), sigStr32, typeStr32, dataType32, ColorReset());
            printf("       %sRisk: Type confusion → wrong parser invoked → memory corruption%s\n",
                   ColorCritical(), ColorReset());
            typeConfusionCount++;
          }
        }
      }
    }


    if (typeConfusionCount > 0) {
      heuristicCount += typeConfusionCount;
    } else {
      printf("      %s[OK] All tag type signatures are known ICC types%s\n", ColorSuccess(), ColorReset());
    }
  }
}
printf("\n");

  return heuristicCount;
}

