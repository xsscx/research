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

#include "IccAnalyzerCommon.h"
#include "IccAnalyzerInspect.h"
#include "IccAnalyzerSignatures.h"
#include <new>

void PrintHexDump(const icUInt8Number *data, icUInt32Number size, icUInt32Number offset)
{
  for (icUInt32Number i = 0; i < size; i += 16) {
    printf("0x%04X: ", offset + i);
    
    for (icUInt32Number j = 0; j < 16; j++) {
      if (i + j < size) {
        printf("%02X ", data[i + j]);
      } else {
        printf("   ");
      }
      if (j == 7) printf(" ");
    }
    
    printf(" |");
    for (icUInt32Number j = 0; j < 16 && i + j < size; j++) {
      icUInt8Number c = data[i + j];
      // Always use '.' for non-printable chars (including null bytes)
      // This prevents null bytes in output and matches hexdump/xxd behavior
      if (c >= 32 && c <= 126) {
        printf("%c", c);
      } else {
        printf(".");
      }
    }
    printf("|\n");
  }
}

//==============================================================================
// Profile Inspection Functions
//==============================================================================

void DumpProfileHeader(CIccProfile *pIcc, CIccIO *pIO)
{
  printf("\n=== ICC Profile Header (0x0000-0x007F) ===\n");
  
  pIO->Seek(0, icSeekSet);
  icUInt8Number header[128];
  if (pIO->Read8(header, 128) != 128) {
    printf("Error reading header\n");
    return;
  }
  
  PrintHexDump(header, 128, 0);
  
  printf("\nHeader Fields:\n");
  printf("  Size:            0x%08X (%u bytes)\n", pIcc->m_Header.size, pIcc->m_Header.size);
  printf("  CMM:             %c%c%c%c\n", 
         pIcc->m_Header.cmmId>>24, (pIcc->m_Header.cmmId>>16)&0xff,
         (pIcc->m_Header.cmmId>>8)&0xff, pIcc->m_Header.cmmId&0xff);
  printf("  Version:         0x%08X\n", pIcc->m_Header.version);
  
  CIccInfo info;
  printf("  Device Class:    %s\n", info.GetProfileClassSigName(pIcc->m_Header.deviceClass));
  printf("  Color Space:     %s\n", info.GetColorSpaceSigName(pIcc->m_Header.colorSpace));
  printf("  PCS:             %s\n", info.GetColorSpaceSigName(pIcc->m_Header.pcs));
}

void DumpTagTable(CIccProfile *pIcc, CIccIO *pIO)
{
  printf("\n=== Tag Table ===\n");
  printf("Tag Count: %u\n\n", (unsigned int)pIcc->m_Tags.size());
  
  icUInt32Number tagTableOffset = 128;
  pIO->Seek(tagTableOffset, icSeekSet);
  
  icUInt32Number tagCount = 0;
  pIO->Read32(&tagCount);
  
  if (tagCount > UINT32_MAX / 12 || tagCount > 10000) {
    printf("Error: Tag count too large (%u)\n", tagCount);
    return;
  }
  
  icUInt32Number tableSize = tagCount * 12 + 4;
  icUInt8Number *tagTableData = new (std::nothrow) icUInt8Number[tableSize];
  if (!tagTableData) {
    printf("Error: Allocation failed for tag table (%u bytes)\n", tableSize);
    return;
  }
  pIO->Seek(tagTableOffset, icSeekSet);
  pIO->Read8(tagTableData, tableSize);
  
  printf("Tag Table Raw Data (0x%04X-0x%04X):\n", tagTableOffset, tagTableOffset + tableSize);
  PrintHexDump(tagTableData, tableSize, tagTableOffset);
  
  printf("\nTag Entries:\n");
  printf("%-4s %-12s %-12s %-10s %s\n", "Idx", "Signature", "FourCC", "Offset", "Size");
  printf("%-4s %-12s %-12s %-10s %s\n", "---", "------------", "------------", "----------", "----");
  
  int idx = 0;
  CIccInfo info;
  TagEntryList::iterator i;
  for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++, idx++) {
    IccTagEntry *entry = &(*i);
    char fourcc[5];
    SignatureToFourCC(entry->TagInfo.sig, fourcc);
    
    printf("%-4d %-12s '%-10s'  0x%08X  %u",
           idx,
           info.GetTagSigName(entry->TagInfo.sig),
           fourcc,
           entry->TagInfo.offset,
           entry->TagInfo.size);
    
    // Warn if signature contains non-printable characters
    if (HasNonPrintableSignature(entry->TagInfo.sig)) {
      printf(" [WARN] non-printable");
    }
    
    printf("\n");
  }
  
  delete[] tagTableData;
}

void DumpTagData(CIccProfile *pIcc, CIccIO *pIO, icTagSignature sig)
{
  CIccTag *pTag = pIcc->FindTag(sig);
  if (!pTag) {
    printf("Tag not found\n");
    return;
  }
  
  TagEntryList::iterator i;
  for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    if ((*i).TagInfo.sig == sig) {
      IccTagEntry *entry = &(*i);
      CIccInfo info;
      
      printf("\n=== Tag Data: '%s' (0x%08X-0x%08X) ===\n",
             info.GetTagSigName(sig),
             entry->TagInfo.offset,
             entry->TagInfo.offset + entry->TagInfo.size);
      
      pIO->Seek(entry->TagInfo.offset, icSeekSet);
      icUInt8Number *tagData = new icUInt8Number[entry->TagInfo.size];
      if (pIO->Read8(tagData, entry->TagInfo.size) == entry->TagInfo.size) {
        printf("Type: %s\n", info.GetTagTypeSigName(pTag->GetType()));
        PrintHexDump(tagData, entry->TagInfo.size, entry->TagInfo.offset);
      } else {
        printf("Error reading tag data\n");
      }
      delete[] tagData;
      break;
    }
  }
}
