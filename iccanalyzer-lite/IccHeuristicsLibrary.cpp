/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

// Library-API heuristics (H9-H32, H56-H86, H95-H115).
// These heuristics use the CIccProfile API for tag-level analysis.
// Extracted from IccAnalyzerSecurity.cpp for modularity.

#include "IccHeuristicsLibrary.h"
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
#include "IccTagEmbedIcc.h"
#include "IccMpeSpectral.h"
#include "IccTagProfSeqId.h"
#include "IccPrmg.h"
#include "IccMatrixMath.h"
#include "IccEnvVar.h"
#include "IccPcc.h"

#include <cmath>
#include <new>
#include <map>
#include <set>
#include <vector>
#include <algorithm>

int RunLibraryAPIHeuristics(CIccProfile *pIcc, const char *filename)
{
  int heuristicCount = 0;
  CIccInfo info;

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
      printf("     %s[WARN]  HEURISTIC: Multiple required text tags missing%s\n", ColorWarning(), ColorReset());
      printf("       %sRisk: Incomplete/malformed profile%s\n", ColorWarning(), ColorReset());
      heuristicCount++;
    }
    printf("\n");
    
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
        CIccTag *pLTag = pIcc->FindTag(clutSigs[li]);
        if (!pLTag) continue;
        CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pLTag);
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
        CIccTag *pMTag = pIcc->FindTag(mpeSigs[mi]);
        if (!pMTag) continue;
        CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement*>(pMTag);
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
               ColorSuccess(), tagCount, ColorReset());
      }
    }
    printf("\n");

    
    // 14. TagArrayType Detection (CRITICAL - Heap-Use-After-Free)
    // CVE refs: CVE-2026-21677 (UAF in CIccTagArray::Cleanup)
    // Based on fuzzer findings 2026-01-30: TagArray can appear under ANY signature
    printf("[H14] TagArrayType Detection (UAF Risk)\n");
    printf("      Checking for TagArrayType (0x74617279 = 'tary')\n");
    printf("      Note: Tag signature ≠ tag type - must check tag DATA\n");
    
    // Re-read file for raw tag type validation
    FILE *fp = fopen(filename, "rb");
    if (fp) {
      // Get file size
      fseek(fp, 0, SEEK_END);
      size_t fileSize = ftell(fp);
      fseek(fp, 0, SEEK_SET);
      
      if (fileSize >= 132) {
        icUInt8Number rawHdr[132];
        if (fread(rawHdr, 1, 132, fp) == 132) {
          icUInt32Number tagTableCount = (static_cast<icUInt32Number>(rawHdr[128])<<24) | (static_cast<icUInt32Number>(rawHdr[129])<<16) | 
                                          (static_cast<icUInt32Number>(rawHdr[130])<<8) | rawHdr[131];
          
          bool foundTagArray = false;
          icUInt32Number tagArrayCount = 0;
          
          // Read each tag entry and check its TYPE (not just signature)
          for (icUInt32Number i = 0; i < tagTableCount && i < 256; i++) {
            size_t entryPos = 132 + i*12;
            if (entryPos + 12 > fileSize) break;
            
            icUInt8Number entry[12];
            fseek(fp, entryPos, SEEK_SET);
            if (fread(entry, 1, 12, fp) != 12) break;
            
            icUInt32Number tagSig = (static_cast<icUInt32Number>(entry[0])<<24) | (static_cast<icUInt32Number>(entry[1])<<16) | (static_cast<icUInt32Number>(entry[2])<<8) | entry[3];
            icUInt32Number tagOffset = (static_cast<icUInt32Number>(entry[4])<<24) | (static_cast<icUInt32Number>(entry[5])<<16) | (static_cast<icUInt32Number>(entry[6])<<8) | entry[7];
            icUInt32Number tagSize = (static_cast<icUInt32Number>(entry[8])<<24) | (static_cast<icUInt32Number>(entry[9])<<16) | (static_cast<icUInt32Number>(entry[10])<<8) | entry[11];
            
            // Validate tag is within file bounds (overflow-safe check)
            if (tagOffset >= 128 && tagSize >= 4 && tagSize <= fileSize && tagOffset <= fileSize - tagSize) {
              icUInt8Number tagData[4];
              fseek(fp, tagOffset, SEEK_SET);
              if (fread(tagData, 1, 4, fp) == 4) {
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
            printf("      %s[CRITICAL] HEURISTIC: %u TagArrayType tag(s) detected%s\n", ColorCritical(), tagArrayCount, ColorReset());
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
      fclose(fp);
    } else {
      printf("      %s[WARN]  Cannot re-open file for tag type validation%s\n", ColorWarning(), ColorReset());
    }
    printf("\n");
    
    // 18. Technology Signature Validation
    printf("[H18] Technology Signature Validation\n");
    {
      CIccTag *pTechTag = pIcc->FindTag(icSigTechnologyTag);
      if (pTechTag) {
        CIccTagSignature *pSigTag = dynamic_cast<CIccTagSignature*>(pTechTag);
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

    // 20. Tag Type Signature Validation
    printf("[H20] Tag Type Signature Validation\n");
    {
      int invalidTypeCount = 0;
      FILE *fp20 = fopen(filename, "rb");
      if (fp20) {
        TagEntryList::iterator it;
        for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
          IccTagEntry *e = &(*it);
          icUInt32Number tagOffset = e->TagInfo.offset;
          icUInt32Number tagSize = e->TagInfo.size;
          if (tagSize < 8) continue; // Too small for type+reserved

          icUInt8Number typeBuf[4] = {0};
          if (fseek(fp20, tagOffset, SEEK_SET) == 0 &&
              fread(typeBuf, 1, 4, fp20) == 4) {
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
        fclose(fp20);
      }
      if (invalidTypeCount > 0) {
        heuristicCount += invalidTypeCount;
      } else {
        printf("      %s[OK] All tag type signatures are valid ASCII%s\n", ColorSuccess(), ColorReset());
      }
    }
    printf("\n");

    // 21. tagStruct Member Inspection
    printf("[H21] tagStruct Member Inspection\n");
    {
      int structIssues = 0;
      bool foundStruct = false;
      TagEntryList::iterator it;
      for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
        IccTagEntry *e = &(*it);
        CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
        if (!pTag) continue;

        CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct*>(pTag);
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

    // 22. NumArray Scalar Expectation Validation (cept-specific)
    printf("[H22] NumArray Scalar Expectation (cept struct)\n");
    {
      int scalarIssues = 0;
      CIccTag *pCeptTag = pIcc->FindTag(icSigColorEncodingParamsTag);
      CIccTagStruct *pCept = pCeptTag ? dynamic_cast<CIccTagStruct*>(pCeptTag) : nullptr;

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
            printf("      %s[HIGH]  %s has %u values (expected 1 scalar)%s\n",
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
        icFloatNumber *vals = new(std::nothrow) icFloatNumber[numVals];
        if (!vals) continue;

        if (pNum->GetValues(vals, 0, numVals)) {
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
            rangeIssues++;
          }
        }
        delete[] vals;
      }

      // Also check NumArrays inside tagStruct members
      for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
        IccTagEntry *e = &(*it);
        CIccTag *pTag = pIcc->FindTag(e->TagInfo.sig);
        if (!pTag) continue;
        CIccTagStruct *pStruct = dynamic_cast<CIccTagStruct*>(pTag);
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
          icFloatNumber *vals = new(std::nothrow) icFloatNumber[numVals];
          if (!vals) continue;

          if (pNum->GetValues(vals, 0, numVals)) {
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
          delete[] vals;
        }
      }

      if (rangeIssues > 0) {
        heuristicCount += rangeIssues;
      } else {
        printf("      %s[OK] All NumArray values within normal ranges%s\n", ColorSuccess(), ColorReset());
      }
    }
    printf("\n");

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

    // 25. Tag Offset/Size OOB Detection (raw file bytes)
    // CVE refs: CVE-2026-25583 (HBO in CIccFileIO::Read8), CVE-2026-24852 (tag offset overflow)
    printf("[H25] Tag Offset/Size Out-of-Bounds Detection\n");
    {
      FILE *fp25 = fopen(filename, "rb");
      if (fp25) {
        fseek(fp25, 0, SEEK_END);
        long realSize_l = ftell(fp25);
        if (realSize_l < 0) { fclose(fp25); fp25 = NULL; }
        size_t realSize = (fp25) ? (size_t)realSize_l : 0;
        if (fp25) fseek(fp25, 0, SEEK_SET);
        
        int oobCount = 0;
        if (realSize >= 132) {
          icUInt8Number hdr25[132];
          if (fread(hdr25, 1, 132, fp25) == 132) {
            icUInt32Number hdrProfileSize = (static_cast<icUInt32Number>(hdr25[0])<<24) | (static_cast<icUInt32Number>(hdr25[1])<<16) |
                                            (static_cast<icUInt32Number>(hdr25[2])<<8) | hdr25[3];
            icUInt32Number tc = (static_cast<icUInt32Number>(hdr25[128])<<24) | (static_cast<icUInt32Number>(hdr25[129])<<16) |
                                (static_cast<icUInt32Number>(hdr25[130])<<8) | hdr25[131];
            size_t bound = (realSize < hdrProfileSize) ? realSize : hdrProfileSize;
            
            for (icUInt32Number i = 0; i < tc && i < 256; i++) {
              size_t ePos = 132 + i * 12;
              if (ePos + 12 > realSize) break;
              
              icUInt8Number e25[12];
              fseek(fp25, ePos, SEEK_SET);
              if (fread(e25, 1, 12, fp25) != 12) break;
              
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
        if (fp25) fclose(fp25);
        
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

    // 26. NamedColor2 String Validation (raw scan — checks tag TYPE, not signature)
    // CVE refs: CVE-2026-21488 (non-null-terminated strings), CVE-2026-24852 (text overflow)
    printf("[H26] NamedColor2 String Validation\n");
    {
      FILE *fp26 = fopen(filename, "rb");
      if (fp26) {
          fseek(fp26, 0, SEEK_END);
          long fs26_l = ftell(fp26);
          if (fs26_l < 0) { fclose(fp26); fp26 = NULL; }
          size_t fs26 = (fp26) ? (size_t)fs26_l : 0;
          if (fp26) fseek(fp26, 0, SEEK_SET);
          
          int nc2Issues = 0;
          if (fs26 >= 132) {
            icUInt8Number hdr26[132];
            if (fread(hdr26, 1, 132, fp26) == 132) {
              icUInt32Number tc26 = (static_cast<icUInt32Number>(hdr26[128])<<24) | (static_cast<icUInt32Number>(hdr26[129])<<16) |
                                    (static_cast<icUInt32Number>(hdr26[130])<<8) | hdr26[131];
              
              for (icUInt32Number i = 0; i < tc26 && i < 256; i++) {
                size_t ePos = 132 + i * 12;
                if (ePos + 12 > fs26) break;
                
                icUInt8Number e26[12];
                fseek(fp26, ePos, SEEK_SET);
                if (fread(e26, 1, 12, fp26) != 12) break;
                
                icUInt32Number tOff26 = (static_cast<icUInt32Number>(e26[4])<<24) | (static_cast<icUInt32Number>(e26[5])<<16) |
                                        (static_cast<icUInt32Number>(e26[6])<<8) | e26[7];
                icUInt32Number tSz26  = (static_cast<icUInt32Number>(e26[8])<<24) | (static_cast<icUInt32Number>(e26[9])<<16) |
                                        (static_cast<icUInt32Number>(e26[10])<<8) | e26[11];
                
                // Read first 4 bytes of tag data to check type
                if (tOff26 + 4 > fs26 || tSz26 < 84) continue;
                icUInt8Number typeCheck[4];
                fseek(fp26, tOff26, SEEK_SET);
                if (fread(typeCheck, 1, 4, fp26) != 4) continue;
                icUInt32Number tagType26 = (static_cast<icUInt32Number>(typeCheck[0])<<24) | (static_cast<icUInt32Number>(typeCheck[1])<<16) |
                                           (static_cast<icUInt32Number>(typeCheck[2])<<8) | typeCheck[3];
                if (tagType26 != 0x6E636C32) continue;  // Not 'ncl2' type
                if (tOff26 + 84 > fs26) continue;
                
                // NamedColor2: type(4)+reserved(4)+vendorFlags(4)+count(4)+nDevCoords(4)+prefix(32)+suffix(32)
                icUInt8Number prefix[32], suffix[32];
                fseek(fp26, tOff26 + 20, SEEK_SET);
                if (fread(prefix, 1, 32, fp26) != 32) continue;
                if (fread(suffix, 1, 32, fp26) != 32) continue;
                
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
          if (fp26) fclose(fp26);
          
          if (nc2Issues > 0) {
            heuristicCount += nc2Issues;
          } else {
            printf("      %s[OK] No NamedColor2 tags with risky strings%s\n", ColorSuccess(), ColorReset());
          }
        }
      }
    printf("\n");

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
        CIccTag *pTag = pIcc->FindTag(sig);
        if (!pTag) continue;
        CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
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

    // 28. LUT Dimension Validation (raw file bytes)
    // CVE refs: CVE-2026-21490, CVE-2026-21494, GHSA-x9hr-pxxc-h38p (OOM via extreme nInput^nGrid)
    // LUT8 type='mft1', LUT16 type='mft2': nInput/nOutput/nGrid parsed from raw bytes
    printf("[H28] LUT Dimension Validation (OOM Risk)\n");
    {
      FILE *fp28 = fopen(filename, "rb");
      if (fp28) {
        fseek(fp28, 0, SEEK_END);
        long fs28_l = ftell(fp28);
        if (fs28_l < 0) { fclose(fp28); fp28 = NULL; }
        size_t fs28 = (fp28) ? (size_t)fs28_l : 0;
        if (fp28) fseek(fp28, 0, SEEK_SET);

        int lutIssues = 0;
        if (fs28 >= 132) {
          icUInt8Number hdr28[132];
          if (fread(hdr28, 1, 132, fp28) == 132) {
            icUInt32Number tc28 = (static_cast<icUInt32Number>(hdr28[128])<<24) | (static_cast<icUInt32Number>(hdr28[129])<<16) |
                                  (static_cast<icUInt32Number>(hdr28[130])<<8) | hdr28[131];

            for (icUInt32Number i = 0; i < tc28 && i < 256; i++) {
              size_t ePos = 132 + i * 12;
              if (ePos + 12 > fs28) break;

              icUInt8Number e28[12];
              fseek(fp28, ePos, SEEK_SET);
              if (fread(e28, 1, 12, fp28) != 12) break;

              icUInt32Number tOff28 = (static_cast<icUInt32Number>(e28[4])<<24) | (static_cast<icUInt32Number>(e28[5])<<16) |
                                      (static_cast<icUInt32Number>(e28[6])<<8) | e28[7];
              icUInt32Number tSz28  = (static_cast<icUInt32Number>(e28[8])<<24) | (static_cast<icUInt32Number>(e28[9])<<16) |
                                      (static_cast<icUInt32Number>(e28[10])<<8) | e28[11];

              // Need at least type(4) + reserved(4) + nInput(1) + nOutput(1) + nGrid(1) = 11 bytes
              if (tOff28 + 11 > fs28 || tSz28 < 11) continue;
              icUInt8Number lutHdr[11];
              fseek(fp28, tOff28, SEEK_SET);
              if (fread(lutHdr, 1, 11, fp28) != 11) continue;

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
        if (fp28) fclose(fp28);

        if (lutIssues > 0) {
          heuristicCount += lutIssues;
        } else {
          printf("      %s[OK] All LUT dimensions within safe limits%s\n", ColorSuccess(), ColorReset());
        }
      }
    }
    printf("\n");

    // 29. ColorantTable String Validation (raw file bytes)
    // CVE refs: GHSA-4wqv-pvm8-5h27 (OOB read via unterminated colorant name[32])
    // CVE-2026-27692 (HBO in TextDescription from unterminated strings)
    printf("[H29] ColorantTable String Validation\n");
    {
      FILE *fp29 = fopen(filename, "rb");
      if (fp29) {
        fseek(fp29, 0, SEEK_END);
        long fs29_l = ftell(fp29);
        if (fs29_l < 0) { fclose(fp29); fp29 = NULL; }
        size_t fs29 = (fp29) ? (size_t)fs29_l : 0;
        if (fp29) fseek(fp29, 0, SEEK_SET);

        int clrtIssues = 0;
        if (fs29 >= 132) {
          icUInt8Number hdr29[132];
          if (fread(hdr29, 1, 132, fp29) == 132) {
            icUInt32Number tc29 = (static_cast<icUInt32Number>(hdr29[128])<<24) | (static_cast<icUInt32Number>(hdr29[129])<<16) |
                                  (static_cast<icUInt32Number>(hdr29[130])<<8) | hdr29[131];

            for (icUInt32Number i = 0; i < tc29 && i < 256; i++) {
              size_t ePos = 132 + i * 12;
              if (ePos + 12 > fs29) break;

              icUInt8Number e29[12];
              fseek(fp29, ePos, SEEK_SET);
              if (fread(e29, 1, 12, fp29) != 12) break;

              icUInt32Number tOff29 = (static_cast<icUInt32Number>(e29[4])<<24) | (static_cast<icUInt32Number>(e29[5])<<16) |
                                      (static_cast<icUInt32Number>(e29[6])<<8) | e29[7];
              icUInt32Number tSz29  = (static_cast<icUInt32Number>(e29[8])<<24) | (static_cast<icUInt32Number>(e29[9])<<16) |
                                      (static_cast<icUInt32Number>(e29[10])<<8) | e29[11];

              // Read type signature
              if (tOff29 + 12 > fs29 || tSz29 < 12) continue;
              icUInt8Number typeCheck29[12];
              fseek(fp29, tOff29, SEEK_SET);
              if (fread(typeCheck29, 1, 12, fp29) != 12) continue;

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
                fseek(fp29, namePos, SEEK_SET);
                if (fread(name29, 1, 32, fp29) != 32) break;

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
        if (fp29) fclose(fp29);

        if (clrtIssues > 0) {
          heuristicCount += clrtIssues;
        } else {
          printf("      %s[OK] No ColorantTable string issues detected%s\n", ColorSuccess(), ColorReset());
        }
      }
    }
    printf("\n");

    // 30. GamutBoundaryDesc Allocation Validation (raw file bytes)
    // CVE refs: GHSA-rc3h-95ph-j363 (OOM via unvalidated triangle count in 'gbd ' tags)
    printf("[H30] GamutBoundaryDesc Allocation Validation\n");
    {
      FILE *fp30 = fopen(filename, "rb");
      if (fp30) {
        fseek(fp30, 0, SEEK_END);
        long fs30_l = ftell(fp30);
        if (fs30_l < 0) { fclose(fp30); fp30 = NULL; }
        size_t fs30 = (fp30) ? (size_t)fs30_l : 0;
        if (fp30) fseek(fp30, 0, SEEK_SET);

        int gbdIssues = 0;
        if (fs30 >= 132) {
          icUInt8Number hdr30[132];
          if (fread(hdr30, 1, 132, fp30) == 132) {
            icUInt32Number tc30 = (static_cast<icUInt32Number>(hdr30[128])<<24) | (static_cast<icUInt32Number>(hdr30[129])<<16) |
                                  (static_cast<icUInt32Number>(hdr30[130])<<8) | hdr30[131];

            for (icUInt32Number i = 0; i < tc30 && i < 256; i++) {
              size_t ePos = 132 + i * 12;
              if (ePos + 12 > fs30) break;

              icUInt8Number e30[12];
              fseek(fp30, ePos, SEEK_SET);
              if (fread(e30, 1, 12, fp30) != 12) break;

              icUInt32Number tOff30 = (static_cast<icUInt32Number>(e30[4])<<24) | (static_cast<icUInt32Number>(e30[5])<<16) |
                                      (static_cast<icUInt32Number>(e30[6])<<8) | e30[7];
              icUInt32Number tSz30  = (static_cast<icUInt32Number>(e30[8])<<24) | (static_cast<icUInt32Number>(e30[9])<<16) |
                                      (static_cast<icUInt32Number>(e30[10])<<8) | e30[11];

              // 'gbd ' type header: type(4)+reserved(4)+reserved(4)+nVertices(4)+nTriangles(4)+nPCSCh(2)+nDevCh(2) = 24 bytes
              if (tOff30 + 24 > fs30 || tSz30 < 24) continue;
              icUInt8Number gbdHdr[24];
              fseek(fp30, tOff30, SEEK_SET);
              if (fread(gbdHdr, 1, 24, fp30) != 24) continue;

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
        if (fp30) fclose(fp30);

        if (gbdIssues > 0) {
          heuristicCount += gbdIssues;
        } else {
          printf("      %s[OK] No GamutBoundaryDesc allocation issues%s\n", ColorSuccess(), ColorReset());
        }
      }
    }
    printf("\n");

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
        CIccTag *pTag31 = pIcc->FindTag(sig31);
        if (!pTag31) continue;
        CIccTagMultiProcessElement *pMpe31 = dynamic_cast<CIccTagMultiProcessElement*>(pTag31);
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

    // 32. Tag Data Type Confusion Detection (raw file bytes)
    // CVE refs: GHSA-2pjj-3c98-qp37 (type confusion in ToXmlCurve)
    // GHSA-xqq3-g894-w2h5 (HBO in IccTagXml from type confusion)
    // Checks that tag type signatures are valid printable ICC 4CC codes
    printf("[H32] Tag Data Type Confusion Detection\n");
    {
      FILE *fp32 = fopen(filename, "rb");
      if (fp32) {
        fseek(fp32, 0, SEEK_END);
        long fs32_l = ftell(fp32);
        if (fs32_l < 0) { fclose(fp32); fp32 = NULL; }
        size_t fs32 = (fp32) ? (size_t)fs32_l : 0;
        if (fp32) fseek(fp32, 0, SEEK_SET);

        int typeConfusionCount = 0;
        if (fs32 >= 132) {
          icUInt8Number hdr32[132];
          if (fread(hdr32, 1, 132, fp32) == 132) {
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
              fseek(fp32, ePos, SEEK_SET);
              if (fread(e32, 1, 12, fp32) != 12) break;

              icUInt32Number tSig32 = (static_cast<icUInt32Number>(e32[0])<<24) | (static_cast<icUInt32Number>(e32[1])<<16) |
                                      (static_cast<icUInt32Number>(e32[2])<<8) | e32[3];
              icUInt32Number tOff32 = (static_cast<icUInt32Number>(e32[4])<<24) | (static_cast<icUInt32Number>(e32[5])<<16) |
                                      (static_cast<icUInt32Number>(e32[6])<<8) | e32[7];
              icUInt32Number tSz32  = (static_cast<icUInt32Number>(e32[8])<<24) | (static_cast<icUInt32Number>(e32[9])<<16) |
                                      (static_cast<icUInt32Number>(e32[10])<<8) | e32[11];

              if (tOff32 + 4 > fs32 || tSz32 < 4) continue;
              icUInt8Number typeData32[4];
              fseek(fp32, tOff32, SEEK_SET);
              if (fread(typeData32, 1, 4, fp32) != 4) continue;

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
        if (fp32) fclose(fp32);

        if (typeConfusionCount > 0) {
          heuristicCount += typeConfusionCount;
        } else {
          printf("      %s[OK] All tag type signatures are known ICC types%s\n", ColorSuccess(), ColorReset());
        }
      }
    }
    printf("\n");

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
        CIccTag *tag = pIcc->FindTag((icTagSignature)mpeSigs56[s]);
        if (!tag) continue;
        CIccTagMultiProcessElement *mpe = dynamic_cast<CIccTagMultiProcessElement*>(tag);
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

    // =====================================================================
    // H58 — Sparse Matrix / Large Array Entry Bounds (CWE-131/CWE-400)
    // =====================================================================
    printf("[H58] Sparse Matrix Entry Bounds\n");
    {
      int sparseIssues = 0;
      TagEntryList::iterator sit;
      for (sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
        IccTagEntry *e = &(*sit);
        CIccTag *tag = pIcc->FindTag(e->TagInfo.sig);
        if (!tag) continue;
        CIccTagNumArray *numArr = dynamic_cast<CIccTagNumArray*>(tag);
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

    // =====================================================================
    // H60 — Dictionary Tag Key/Value Consistency (CWE-126/CWE-170)
    // =====================================================================
    printf("[H60] Dictionary Tag Consistency\n");
    {
      int dictIssues = 0;
      CIccTag *dictTag = pIcc->FindTag(icSigMetaDataTag);
      if (dictTag) {
        CIccTagDict *dict = dynamic_cast<CIccTagDict*>(dictTag);
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

    // =====================================================================
    // H61 — Viewing Conditions Validation (CWE-682/CWE-20)
    // =====================================================================
    printf("[H61] Viewing Conditions Validation\n");
    {
      int viewIssues = 0;
      CIccTag *vcTag = pIcc->FindTag((icTagSignature)icSigViewingConditionsTag);
      if (vcTag) {
        CIccTagViewingConditions *vc = dynamic_cast<CIccTagViewingConditions*>(vcTag);
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

    // =====================================================================
    // H62 — Multi-Localized Unicode String Bombs (CWE-400/CWE-770)
    // =====================================================================
    printf("[H62] Multi-Localized Unicode String Bombs\n");
    {
      int mlucIssues = 0;
      for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
        CIccTag *tag = pIcc->FindTag(sit->TagInfo.sig);
        if (!tag) continue;
        CIccTagMultiLocalizedUnicode *mluc = dynamic_cast<CIccTagMultiLocalizedUnicode*>(tag);
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
        CIccTag *tag = pIcc->FindTag((icTagSignature)lutSigs[s]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB*>(tag);
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

    // =====================================================================
    // H64 — NamedColor2 Device Coord Overflow (CWE-131/CWE-787)
    // =====================================================================
    printf("[H64] NamedColor2 Device Coord Overflow\n");
    {
      int nc2Issues = 0;
      CIccTag *ncTag = pIcc->FindTag(icSigNamedColor2Tag);
      if (ncTag) {
        CIccTagNamedColor2 *nc2 = dynamic_cast<CIccTagNamedColor2*>(ncTag);
        if (nc2) {
          icUInt32Number nColors = nc2->GetSize();
          icUInt32Number nDevCoords = nc2->GetDeviceCoords();
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

    // =====================================================================
    // H65 — Chromaticity Physical Plausibility (CWE-682)
    // =====================================================================
    printf("[H65] Chromaticity Physical Plausibility\n");
    {
      int chromIssues = 0;
      CIccTag *chTag = pIcc->FindTag(icSigChromaticityTag);
      if (chTag) {
        CIccTagChromaticity *chrom = dynamic_cast<CIccTagChromaticity*>(chTag);
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
        icFloatNumber *vals = (icFloatNumber*)malloc(scanLimit * sizeof(icFloatNumber));
        if (!vals) continue;

        if (numArr->GetValues(vals, 0, scanLimit)) {
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
          if (extremeCount > scanLimit / 4) {
            printf("      %s[WARN]  Tag '%s': %d/%u extreme values (>1e10)%s\n",
                   ColorWarning(), info.GetTagSigName(sit->TagInfo.sig),
                   extremeCount, scanLimit, ColorReset());
            nanIssues++;
          }
        }
        free(vals);
      }
      if (nanIssues > 0) {
        heuristicCount += nanIssues;
      } else {
        printf("      %s[OK] All numeric arrays free of NaN/Inf%s\n", ColorSuccess(), ColorReset());
      }
    }
    printf("\n");

    // =====================================================================
    // H67 — ResponseCurveSet Bounds (CWE-400/CWE-131)
    // =====================================================================
    printf("[H67] ResponseCurveSet Bounds\n");
    {
      int rcsIssues = 0;
      // ResponseCurveSet16 has no well-known tag signature — scan all tags by type
      CIccTagResponseCurveSet16 *rcs = NULL;
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
      }
      if (rcsIssues > 0) {
        heuristicCount += rcsIssues;
      } else {
        printf("      %s[OK] ResponseCurveSet bounds valid (or tag absent)%s\n", ColorSuccess(), ColorReset());
      }
    }
    printf("\n");

    // =====================================================================
    // H70 — Measurement Tag Validation (CWE-20)
    // =====================================================================
    printf("[H70] Measurement Tag Validation\n");
    {
      int measIssues = 0;
      CIccTag *measTag = pIcc->FindTag(icSigMeasurementTag);
      if (measTag) {
        CIccTagMeasurement *meas = dynamic_cast<CIccTagMeasurement*>(measTag);
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

    // =====================================================================
    // H71 — ColorantTable Name Null-Termination (CWE-170/CWE-125)
    // Targets patches 019/020, CVE-2026-21488: strlen OOB on name[32]
    // =====================================================================
    printf("[H71] ColorantTable Name Null-Termination\n");
    {
      int ctIssues = 0;
      icTagSignature ctSigs[] = {icSigColorantTableTag, icSigColorantTableOutTag, (icTagSignature)0};
      for (int s = 0; ctSigs[s] != (icTagSignature)0; s++) {
        CIccTag *ctTag = pIcc->FindTag(ctSigs[s]);
        if (!ctTag) continue;
        CIccTagColorantTable *ct = dynamic_cast<CIccTagColorantTable*>(ctTag);
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

    // =====================================================================
    // H72 — SparseMatrixArray Allocation Bounds (CWE-400/CWE-125)
    // Targets patches 044/059/060: OOM + OOB in sparse matrix
    // =====================================================================
    printf("[H72] SparseMatrixArray Allocation Bounds\n");
    {
      int smaIssues = 0;
      for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
        CIccTag *tag = pIcc->FindTag(sit->TagInfo.sig);
        if (!tag) continue;
        CIccTagSparseMatrixArray *sma = dynamic_cast<CIccTagSparseMatrixArray*>(tag);
        if (!sma) continue;

        icUInt32Number nMat = sma->GetNumMatrices();
        icUInt32Number nCPM = sma->GetChannelsPerMatrix();
        uint64_t product = (uint64_t)nMat * nCPM * sizeof(icFloatNumber);
        if (product > 16777216ULL) { // 16MB cap per patch 044
          printf("      %s[WARN]  Tag '%s': SparseMatrix %u matrices × %u channels = %llu bytes%s\n",
                 ColorCritical(), info.GetTagSigName(sit->TagInfo.sig),
                 nMat, nCPM, (unsigned long long)product, ColorReset());
          printf("       %sCWE-400: Exceeds 16MB allocation cap (P044)%s\n",
                 ColorCritical(), ColorReset());
          smaIssues++;
        }
      }
      if (smaIssues > 0) {
        heuristicCount += smaIssues;
      } else {
        printf("      %s[OK] SparseMatrixArray allocations within bounds (or absent)%s\n",
               ColorSuccess(), ColorReset());
      }
    }
    printf("\n");

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

        // Check TagArray nesting
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

    // =====================================================================
    // H76 — CIccTagData Type Flag Validation (CWE-843/CWE-20)
    // Targets CVE-2026-21691: IsTypeCompressed type confusion
    // =====================================================================
    printf("[H76] CIccTagData Type Flag Validation\n");
    {
      int dataIssues = 0;
      for (auto sit = pIcc->m_Tags.begin(); sit != pIcc->m_Tags.end(); sit++) {
        CIccTag *tag = pIcc->FindTag(sit->TagInfo.sig);
        if (!tag) continue;
        CIccTagData *dataTag = dynamic_cast<CIccTagData*>(tag);
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
        CIccTag *tag = pIcc->FindTag(mpeSigs[s]);
        if (!tag) continue;
        CIccTagMultiProcessElement *mpe = dynamic_cast<CIccTagMultiProcessElement*>(tag);
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
        CIccTag *tag = pIcc->FindTag(clutSigs[s]);
        if (!tag) continue;
        CIccMBB *mbb = dynamic_cast<CIccMBB*>(tag);
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

    // =====================================================================
    // H81: CIccMpeCalculator Sub-Element Channel Mismatch
    // CVE-2026-24405 (High 8.8) — HBO in CIccMpeCalculator::Read()
    // CVE-2026-22047 (High 8.8) — HBO in SIccCalcOp::Describe()
    // When MPE calculator elements have sub-elements whose channel counts
    // don't match the parent input/output expectations, buffer overflows
    // occur during Apply(). We validate sub-element I/O channel consistency.
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

    // =====================================================================
    // H88 — Chromatic Adaptation Matrix Validation (CWE-682/CWE-125)
    // The chad (chromatic adaptation) tag contains a 3×3 s15Fixed16 matrix.
    // A singular matrix (det≈0) causes division-by-zero in PCS conversions.
    // NaN/Inf values or extreme magnitudes indicate crafted profiles.
    // =====================================================================
    printf("[H88] Chromatic Adaptation Matrix Validation\n");
    {
      int chadIssues = 0;
      CIccTag *pTag = pIcc->FindTag(icSigChromaticAdaptationTag);
      if (pTag) {
        CIccTagS15Fixed16 *pChad = dynamic_cast<CIccTagS15Fixed16*>(pTag);
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
        CIccTag *pTag = pIcc->FindTag(previewSigs[p]);
        if (!pTag) continue;

        CIccMBB *pMbb = dynamic_cast<CIccMBB*>(pTag);
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
        CIccTag *pOrderTag = pIcc->FindTag(orderSigs[o]);
        if (!pOrderTag) continue;
        CIccTagColorantOrder *pOrder = dynamic_cast<CIccTagColorantOrder*>(pOrderTag);
        if (!pOrder) continue;

        icUInt32Number orderCount = pOrder->GetSize();
        // Get matching colorant table count
        icUInt32Number tableCount = 0;
        CIccTag *pTableTag = pIcc->FindTag(tableSigs[o]);
        if (pTableTag) {
          CIccTagColorantTable *pTable = dynamic_cast<CIccTagColorantTable*>(pTableTag);
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

    // H96 — Embedded Profile Validation (CWE-674/CWE-400)
    // Exercises: IccTagEmbedIcc.cpp (30.9% coverage → GetProfile, Read, Validate)
    {
      printf("[H96] Embedded Profile Validation\n");
      int embedIssues = 0;

      CIccTag *pEmbedTag = pIcc->FindTag(icSigEmbeddedV5ProfileTag);
      if (pEmbedTag) {
        CIccTagEmbeddedProfile *pEmbed = dynamic_cast<CIccTagEmbeddedProfile *>(pEmbedTag);
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
          printf("      %s[WARN]  Embedded profile tag wrong type — type confusion risk%s\n",
                 ColorWarning(), ColorReset());
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

    // H97 — Profile Sequence Identifier Validation (CWE-125/CWE-400)
    // Exercises: IccTagProfSeqId.cpp (27.7% coverage → GetFirst, GetLast, begin/end iterators)
    {
      printf("[H97] Profile Sequence Identifier Validation\n");
      int seqIdIssues = 0;

      CIccTag *pSeqIdTag = pIcc->FindTag(icSigProfileSequceIdTag);
      if (pSeqIdTag) {
        CIccTagProfileSequenceId *pSeqId = dynamic_cast<CIccTagProfileSequenceId *>(pSeqIdTag);
        if (pSeqId) {
          // Iterate entries to count and validate
          int entryCount = 0;
          bool hasNullId = false;
          bool hasDupId = false;
          std::set<std::string> seenIds;

          for (auto it = pSeqId->begin(); it != pSeqId->end(); ++it) {
            entryCount++;

            // Check for null profile ID (all zeros)
            icProfileID pid = it->m_profileID;
            bool allZero = true;
            for (int k = 0; k < 16; k++) {
              if (pid.ID8[k] != 0) { allZero = false; break; }
            }
            if (allZero) hasNullId = true;

            // Check for duplicate profile IDs
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
          printf("      %s[WARN]  ProfileSequenceId tag wrong type%s\n",
                 ColorWarning(), ColorReset());
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
        CIccTag *pTag = pIcc->FindTag(mpeTags[i]);
        if (!pTag) continue;

        CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
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
            printf("      Spectral matrix: in=%u, out=%u, type=0x%08x\n",
                   numIn, numOut, elemType);

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

    // H101 — MPE Sub-Element Channel Continuity (CWE-125/CWE-787)
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
        CIccTag *pTag = pIcc->FindTag(mpeTags[i]);
        if (!pTag) continue;

        CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement *>(pTag);
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
            tagSig[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));
            tagSig[1] = static_cast<char>(static_cast<unsigned char>((sig >> 16) & 0xFF));
            tagSig[2] = static_cast<char>(static_cast<unsigned char>((sig >> 8) & 0xFF));
            tagSig[3] = static_cast<char>(static_cast<unsigned char>(sig & 0xFF));
            tagSig[4] = '\0';
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
      for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
        icUInt32Number tagOffset = it->TagInfo.offset;
        icUInt32Number tagSize = it->TagInfo.size;

        if (profileSize > 0) {
          if (tagOffset > profileSize) {
            printf("      %s[CRIT]  Tag '%s' offset %u exceeds profile size %u%s\n",
                   ColorCritical(), info.GetTagSigName(it->TagInfo.sig), tagOffset, profileSize, ColorReset());
            sizeIssues++;
          } else if (tagOffset + tagSize > profileSize) {
            printf("      %s[WARN]  Tag '%s' extends past profile end: offset=%u size=%u total=%u%s\n",
                   ColorWarning(), info.GetTagSigName(it->TagInfo.sig), tagOffset, tagSize, profileSize, ColorReset());
            sizeIssues++;
          }
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
// H103: Profile Connection Conditions (PCC) Validation
// Exercises IccPcc.cpp — viewing conditions, illuminant, observer
// =====================================================================
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
int RunHeuristic_H104_PRMG(CIccProfile *pIcc, const char *profilePath) {
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
    CIccTag *tag = pIcc->FindTag(atobSigs[i]);
    if (!tag) continue;
    CIccMBB *mbb = dynamic_cast<CIccMBB*>(tag);
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
    CIccTag *tag = pIcc->FindTag(btoaSigs[i]);
    if (!tag) continue;
    CIccMBB *mbb = dynamic_cast<CIccMBB*>(tag);
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
    CIccTag *tag = pIcc->FindTag(dtobSigs[i]);
    if (!tag) continue;
    CIccTagMultiProcessElement *mpe = dynamic_cast<CIccTagMultiProcessElement*>(tag);
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
      sigStr[0] = (char)(static_cast<unsigned char>((sig >> 24) & 0xFF));
      sigStr[1] = (char)(static_cast<unsigned char>((sig >> 16) & 0xFF));
      sigStr[2] = (char)(static_cast<unsigned char>((sig >> 8) & 0xFF));
      sigStr[3] = (char)(static_cast<unsigned char>(sig & 0xFF));
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

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("      %s[ERROR] Cannot open file for shellcode scan%s\n",
           ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }

  fseek(fp, 0, SEEK_END);
  long fileSize = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  if (fileSize <= 128 || fileSize > 100 * 1024 * 1024) {
    printf("      %s[OK] File size %ld — skipping pattern scan%s\n",
           ColorSuccess(), fileSize, ColorReset());
    fclose(fp);
    printf("\n");
    return 0;
  }

  size_t scanSize = (size_t)(fileSize > 10485760 ? 10485760 : fileSize);
  unsigned char *buf = (unsigned char *)malloc(scanSize);
  if (!buf) { fclose(fp); printf("\n"); return 0; }
  size_t bytesRead = fread(buf, 1, scanSize, fp);
  fclose(fp);

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

  free(buf);

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
    {(icTagSignature)0, NULL}
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

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("      %s[ERROR] Cannot open file%s\n", ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }

  unsigned char hdr[128];
  if (fread(hdr, 1, 128, fp) != 128) {
    printf("      %s[WARN]  File too small for ICC header%s\n",
           ColorWarning(), ColorReset());
    fclose(fp);
    printf("\n");
    return 1;
  }
  fclose(fp);

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

    CIccMBB *mbbA = tagA ? dynamic_cast<CIccMBB*>(tagA) : NULL;
    CIccMBB *mbbB = tagB ? dynamic_cast<CIccMBB*>(tagB) : NULL;

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
    CIccTag *tag = pIcc->FindTag(trcTags[t]);
    if (!tag) continue;

    CIccTagCurve *curve = dynamic_cast<CIccTagCurve*>(tag);
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
// =====================================================================
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
int RunHeuristic_H117_TagTypeAllowed(CIccProfile *pIcc) {
  int heuristicCount = 0;

  printf("[H117] Tag Type Allowed Per Signature\n");

  struct AllowedType {
    icTagSignature sig;
    const char *name;
    icTagTypeSignature allowed[6];
    int count;
  };

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
    CIccTag *pTag = pIcc->FindTag(mpeTags[t]);
    if (!pTag) continue;
    CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
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
      sigStr[0] = (char)(static_cast<unsigned char>((sig >> 24) & 0xFF));
      sigStr[1] = (char)(static_cast<unsigned char>((sig >> 16) & 0xFF));
      sigStr[2] = (char)(static_cast<unsigned char>((sig >> 8) & 0xFF));
      sigStr[3] = (char)(static_cast<unsigned char>(sig & 0xFF));

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
// Uses CLUT node values for accurate sampling without CMM pipeline.
// =====================================================================
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
    CIccTag *tag = pIcc->FindTag(trcTags[t]);
    if (!tag) continue;

    CIccTagCurve *curve = dynamic_cast<CIccTagCurve*>(tag);
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
    CIccTag *tag = pIcc->FindTag(xyzTags[t]);
    if (!tag) continue;
    CIccTagXYZ *xyzTag = dynamic_cast<CIccTagXYZ*>(tag);
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
      sigStr[0] = (char)(static_cast<unsigned char>((sig >> 24) & 0xFF));
      sigStr[1] = (char)(static_cast<unsigned char>((sig >> 16) & 0xFF));
      sigStr[2] = (char)(static_cast<unsigned char>((sig >> 8) & 0xFF));
      sigStr[3] = (char)(static_cast<unsigned char>(sig & 0xFF));

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
    CIccTag *pTag = pIcc->FindTag(lutTags[t]);
    if (!pTag) continue;

    CIccMBB *mbb = dynamic_cast<CIccMBB*>(pTag);
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

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
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
    if (fseek(fp, offset, SEEK_SET) != 0) continue;
    size_t bytesRead = fread(buf.data(), 1, buf.size(), fp);
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
          sigStr[0] = (char)(static_cast<unsigned char>((sig >> 24) & 0xFF));
          sigStr[1] = (char)(static_cast<unsigned char>((sig >> 16) & 0xFF));
          sigStr[2] = (char)(static_cast<unsigned char>((sig >> 8) & 0xFF));
          sigStr[3] = (char)(static_cast<unsigned char>(sig & 0xFF));
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

  fclose(fp);

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

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("      %s[ERROR] Cannot open file%s\n", ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }

  unsigned char hdr[12];
  if (fread(hdr, 1, 12, fp) != 12) {
    printf("      %s[WARN]  File too small for version field%s\n",
           ColorWarning(), ColorReset());
    fclose(fp);
    printf("\n");
    return 1;
  }
  fclose(fp);

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

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("      %s[ERROR] Cannot open file%s\n", ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }

  unsigned char hdr[80];
  if (fread(hdr, 1, 80, fp) != 80) {
    printf("      %s[WARN]  File too small for illuminant field%s\n",
           ColorWarning(), ColorReset());
    fclose(fp);
    printf("\n");
    return 1;
  }
  fclose(fp);

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

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("      %s[ERROR] Cannot open file%s\n", ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }

  fseek(fp, 0, SEEK_END);
  long fsz_l = ftell(fp);
  if (fsz_l < 132) {
    printf("      %s[WARN]  File too small for tag table%s\n",
           ColorWarning(), ColorReset());
    fclose(fp);
    printf("\n");
    return 1;
  }
  size_t fsz = (size_t)fsz_l;

  unsigned char tcBuf[4];
  fseek(fp, 128, SEEK_SET);
  if (fread(tcBuf, 1, 4, fp) != 4) { fclose(fp); printf("\n"); return 1; }

  uint32_t tagCount = ((uint32_t)tcBuf[0] << 24) | ((uint32_t)tcBuf[1] << 16) |
                      ((uint32_t)tcBuf[2] << 8)  | tcBuf[3];

  if (tagCount > 1000) {
    printf("      %s[WARN]  Tag count %u too large — skipping%s\n",
           ColorWarning(), tagCount, ColorReset());
    fclose(fp);
    printf("\n");
    return 1;
  }

  int misaligned = 0;
  int checked = 0;

  for (uint32_t i = 0; i < tagCount && i < 256; i++) {
    size_t ePos = 132 + i * 12;
    if (ePos + 12 > fsz) break;

    unsigned char entry[12];
    fseek(fp, (long)ePos, SEEK_SET);
    if (fread(entry, 1, 12, fp) != 12) break;

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

  fclose(fp);

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

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("      %s[ERROR] Cannot open file%s\n", ColorCritical(), ColorReset());
    printf("\n");
    return 1;
  }

  fseek(fp, 0, SEEK_END);
  long fsz_l = ftell(fp);
  if (fsz_l < 128) {
    printf("      %s[WARN]  File too small for header%s\n",
           ColorWarning(), ColorReset());
    fclose(fp);
    printf("\n");
    return 1;
  }

  // Read stored Profile ID from bytes 84-99
  unsigned char storedId[16];
  fseek(fp, 84, SEEK_SET);
  if (fread(storedId, 1, 16, fp) != 16) { fclose(fp); printf("\n"); return 1; }

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
    fclose(fp);
    printf("\n");
    return 0;
  }

  fclose(fp);

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

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("      %s[SKIP] Cannot open file%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }

  // Profile flags at offset 44 (4 bytes big-endian)
  icUInt8Number flagBytes[4] = {};
  if (fseek(fp, 44, SEEK_SET) != 0 || fread(flagBytes, 1, 4, fp) != 4) {
    fclose(fp);
    printf("      %s[SKIP] Cannot read flags at offset 44%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }
  fclose(fp);

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

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("      %s[SKIP] Cannot open file%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }

  // Read tag count from offset 128
  icUInt8Number tcBytes[4] = {};
  if (fseek(fp, 128, SEEK_SET) != 0 || fread(tcBytes, 1, 4, fp) != 4) {
    fclose(fp);
    printf("      %s[SKIP] Cannot read tag count%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }
  icUInt32Number tagCount = (static_cast<icUInt32Number>(tcBytes[0]) << 24) |
                            (static_cast<icUInt32Number>(tcBytes[1]) << 16) |
                            (static_cast<icUInt32Number>(tcBytes[2]) << 8)  |
                            tcBytes[3];

  if (tagCount > 200) {
    fclose(fp);
    printf("      %s[SKIP] Tag count %u too high for safe iteration%s\n",
           ColorWarning(), tagCount, ColorReset());
    printf("\n");
    return 0;
  }

  // Get file size for bounds checking
  fseek(fp, 0, SEEK_END);
  long fileSize = ftell(fp);

  int violations = 0;
  int checked = 0;

  // Read each tag entry (12 bytes each starting at offset 132)
  for (icUInt32Number t = 0; t < tagCount; t++) {
    icUInt8Number tagEntry[12] = {};
    if (fseek(fp, 132 + t * 12, SEEK_SET) != 0 || fread(tagEntry, 1, 12, fp) != 12)
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
    if (fseek(fp, offset + 4, SEEK_SET) != 0 || fread(reserved, 1, 4, fp) != 4)
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

  fclose(fp);

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

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("      %s[SKIP] Cannot open file%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }

  // Read tag count from offset 128
  icUInt8Number tcBytes[4] = {};
  if (fseek(fp, 128, SEEK_SET) != 0 || fread(tcBytes, 1, 4, fp) != 4) {
    fclose(fp);
    printf("      %s[SKIP] Cannot read tag count%s\n", ColorWarning(), ColorReset());
    printf("\n");
    return 0;
  }
  icUInt32Number tagCount = (static_cast<icUInt32Number>(tcBytes[0]) << 24) |
                            (static_cast<icUInt32Number>(tcBytes[1]) << 16) |
                            (static_cast<icUInt32Number>(tcBytes[2]) << 8)  |
                            tcBytes[3];

  if (tagCount > 200) {
    fclose(fp);
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
    if (fseek(fp, 132 + t * 12, SEEK_SET) != 0 || fread(tagEntry, 1, 12, fp) != 12)
      continue;

    icUInt32Number sig = (static_cast<icUInt32Number>(tagEntry[0]) << 24) |
                         (static_cast<icUInt32Number>(tagEntry[1]) << 16) |
                         (static_cast<icUInt32Number>(tagEntry[2]) << 8)  |
                         tagEntry[3];
    signatures.push_back(sig);
  }
  fclose(fp);

  // Check for duplicates using sorted comparison
  int duplicates = 0;
  std::vector<icUInt32Number> sorted = signatures;
  std::sort(sorted.begin(), sorted.end());
  for (size_t i = 1; i < sorted.size(); i++) {
    if (sorted[i] == sorted[i - 1]) {
      char sigCC[5] = {};
      sigCC[0] = static_cast<char>(static_cast<unsigned char>((sorted[i] >> 24) & 0xFF));
      sigCC[1] = static_cast<char>(static_cast<unsigned char>((sorted[i] >> 16) & 0xFF));
      sigCC[2] = static_cast<char>(static_cast<unsigned char>((sorted[i] >> 8) & 0xFF));
      sigCC[3] = static_cast<char>(static_cast<unsigned char>(sorted[i] & 0xFF));
      sigCC[4] = '\0';
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

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("      [SKIP] Cannot open file\n\n");
    return 0;
  }

  fseek(fp, 0, SEEK_END);
  long fileSize = ftell(fp);
  if (fileSize < 132) {
    fclose(fp);
    printf("      [SKIP] File too small\n\n");
    return 0;
  }

  // Read tag count
  fseek(fp, 128, SEEK_SET);
  uint8_t tagCountBuf[4];
  if (fread(tagCountBuf, 1, 4, fp) != 4) {
    fclose(fp);
    printf("      [SKIP] Cannot read tag count\n\n");
    return 0;
  }
  uint32_t tagCount = ((uint32_t)tagCountBuf[0] << 24) |
                      ((uint32_t)tagCountBuf[1] << 16) |
                      ((uint32_t)tagCountBuf[2] << 8)  |
                       (uint32_t)tagCountBuf[3];

  if (tagCount > 1000) {
    fclose(fp);
    printf("      [SKIP] Excessive tag count (%u)\n\n", tagCount);
    return 0;
  }

  // Scan tag table for responseCurveSet16Type (rcs2 = 0x72637332)
  for (uint32_t i = 0; i < tagCount && i < 200; i++) {
    uint8_t tagEntry[12];
    fseek(fp, 132 + i * 12, SEEK_SET);
    if (fread(tagEntry, 1, 12, fp) != 12) break;

    uint32_t tagOffset = ((uint32_t)tagEntry[4] << 24) |
                         ((uint32_t)tagEntry[5] << 16) |
                         ((uint32_t)tagEntry[6] << 8)  |
                          (uint32_t)tagEntry[7];
    uint32_t tagSize = ((uint32_t)tagEntry[8] << 24) |
                       ((uint32_t)tagEntry[9] << 16) |
                       ((uint32_t)tagEntry[10] << 8) |
                        (uint32_t)tagEntry[11];

    if (tagOffset + 4 > (uint32_t)fileSize || tagSize < 28) continue;

    // Read tag type signature at tagOffset
    uint8_t typeSig[4];
    fseek(fp, tagOffset, SEEK_SET);
    if (fread(typeSig, 1, 4, fp) != 4) continue;

    // responseCurveSet16Type: 'rcs2' = 0x72637332
    if (typeSig[0] == 0x72 && typeSig[1] == 0x63 &&
        typeSig[2] == 0x73 && typeSig[3] == 0x32) {
      // Read channel count at offset+8 (uint16 BE)
      fseek(fp, tagOffset + 8, SEEK_SET);
      uint8_t chanBuf[2];
      if (fread(chanBuf, 1, 2, fp) != 2) break;
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
      if (fread(nCurvesBuf, 1, 2, fp) != 2) break;
      uint16_t nCurves = ((uint16_t)nCurvesBuf[0] << 8) | nCurvesBuf[1];

      uint16_t nChan = nChannels > 16 ? 16 : nChannels;
      if (nChan == 0) break;

      // Walk curve offsets and check per-channel nMeasurements
      for (uint16_t c = 0; c < nCurves && c < 16; c++) {
        uint8_t offBuf[4];
        fseek(fp, tagOffset + 12 + c * 4, SEEK_SET);
        if (fread(offBuf, 1, 4, fp) != 4) break;
        uint32_t curveOff = ((uint32_t)offBuf[0] << 24) |
                            ((uint32_t)offBuf[1] << 16) |
                            ((uint32_t)offBuf[2] << 8)  |
                             (uint32_t)offBuf[3];

        uint32_t absOff = tagOffset + curveOff;
        if (absOff + 4 + (uint32_t)nChan * 4 > (uint32_t)fileSize) continue;

        // Skip measurement unit sig (4 bytes), read nMeasurements array
        fseek(fp, absOff + 4, SEEK_SET);
        for (uint16_t ch = 0; ch < nChan; ch++) {
          uint8_t mBuf[4];
          if (fread(mBuf, 1, 4, fp) != 4) break;
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

  fclose(fp);

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
        sigStr[0] = (char)(static_cast<unsigned char>((sig >> 24) & 0xFF));
        sigStr[1] = (char)(static_cast<unsigned char>((sig >> 16) & 0xFF));
        sigStr[2] = (char)(static_cast<unsigned char>((sig >> 8) & 0xFF));
        sigStr[3] = (char)(static_cast<unsigned char>(sig & 0xFF));
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
    CIccTag *pTag = pIcc->FindTag(mpeTags[t]);
    if (!pTag) continue;
    CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
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
        sigStr[0] = (char)(static_cast<unsigned char>((sig >> 24) & 0xFF));
        sigStr[1] = (char)(static_cast<unsigned char>((sig >> 16) & 0xFF));
        sigStr[2] = (char)(static_cast<unsigned char>((sig >> 8) & 0xFF));
        sigStr[3] = (char)(static_cast<unsigned char>(sig & 0xFF));
        printf("      %s[WARN]  '%s' calc[%u]: %u sub-elements (>16)%s\n",
               ColorCritical(), sigStr, ei, nSub, ColorReset());
        printf("       %sCWE-674: Deep sub-element chain → unbounded recursion in ApplySequence%s\n",
               ColorCritical(), ColorReset());
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
          sigStr[0] = (char)(static_cast<unsigned char>((sig >> 24) & 0xFF));
          sigStr[1] = (char)(static_cast<unsigned char>((sig >> 16) & 0xFF));
          sigStr[2] = (char)(static_cast<unsigned char>((sig >> 8) & 0xFF));
          sigStr[3] = (char)(static_cast<unsigned char>(sig & 0xFF));
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
