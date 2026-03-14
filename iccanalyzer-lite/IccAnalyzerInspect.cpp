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
#include "IccAnalyzerSafeArithmetic.h"
#include "IccAnalyzerSignatures.h"
#include "IccAnalyzerColors.h"
#include <new>
#include <ctime>

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

// Format a 4-byte ICC signature as printable string
static void FormatSig4(icUInt32Number sig, char *out)
{
  for (int i = 3; i >= 0; i--) {
    unsigned char c = (sig >> (i * 8)) & 0xff;
    out[3 - i] = (c >= 32 && c <= 126) ? static_cast<char>(c) : '.';
  }
  out[4] = '\0';
}

// Decode ICC date/time from header
static void FormatIccDateTime(const icDateTimeNumber &dt, char *buf, size_t bufSize)
{
  snprintf(buf, bufSize, "%04u-%02u-%02u %02u:%02u:%02u",
           dt.year, dt.month, dt.day, dt.hours, dt.minutes, dt.seconds);
}

// Decode ICC version as human-readable string
static void FormatIccVersion(icUInt32Number ver, char *buf, size_t bufSize)
{
  int major = (ver >> 24) & 0xff;
  int minor = (ver >> 20) & 0x0f;
  int bugfix = (ver >> 16) & 0x0f;
  snprintf(buf, bufSize, "%d.%d.%d.0", major, minor, bugfix);
}

void DumpProfileHeader(CIccProfile *pIcc, CIccIO *pIO)
{
  printf("\n%s=== ICC Profile Header (0x0000-0x007F) ===%s\n", ColorInfo(), ColorReset());

  pIO->Seek(0, icSeekSet);
  icUInt8Number header[128];
  if (pIO->Read8(header, 128) != 128) {
    printf("Error reading header\n");
    return;
  }

  PrintHexDump(header, 128, 0);

  icHeader *pHdr = &pIcc->m_Header;
  CIccInfo info;
  char sigBuf[5];
  char verBuf[32];
  char dateBuf[32];

  FormatIccVersion(pHdr->version, verBuf, sizeof(verBuf));

  printf("\n%sHeader Fields:%s\n", ColorInfo(), ColorReset());
  printf("  Size:              0x%08X (%u bytes)\n", pHdr->size, pHdr->size);

  FormatSig4(pHdr->cmmId, sigBuf);
  printf("  CMM Type:          '%s' (0x%08X)\n", sigBuf, pHdr->cmmId);

  printf("  Version:           %s (0x%08X)\n", verBuf, pHdr->version);
  printf("  Device Class:      %s\n", info.GetProfileClassSigName(pHdr->deviceClass));
  printf("  Color Space:       %s (%u channels)\n",
         info.GetColorSpaceSigName(pHdr->colorSpace),
         icGetSpaceSamples(pHdr->colorSpace));
  printf("  PCS:               %s\n", info.GetColorSpaceSigName(pHdr->pcs));

  FormatIccDateTime(pHdr->date, dateBuf, sizeof(dateBuf));
  printf("  Date/Time:         %s\n", dateBuf);

  printf("  Magic:             0x%08X %s\n", pHdr->magic,
         pHdr->magic == icMagicNumber ? "[OK]" : "[INVALID]");
  printf("  Platform:          %s\n", info.GetPlatformSigName(pHdr->platform));
  printf("  Profile Flags:     0x%08X", pHdr->flags);
  if (pHdr->flags & icEmbeddedProfileTrue)
    printf(" [Embedded]");
  if (pHdr->flags & icUseWithEmbeddedDataOnly)
    printf(" [EmbeddedOnly]");
  printf("\n");

  FormatSig4(pHdr->manufacturer, sigBuf);
  printf("  Manufacturer:      '%s' (0x%08X)\n", sigBuf, pHdr->manufacturer);
  FormatSig4(pHdr->model, sigBuf);
  printf("  Model:             '%s' (0x%08X)\n", sigBuf, pHdr->model);

  printf("  Device Attribs:    0x%016llX",
         (unsigned long long)pHdr->attributes);
  if (pHdr->attributes & icTransparency)
    printf(" [Transparency]");
  if (pHdr->attributes & icMatte)
    printf(" [Matte]");
  printf("\n");

  printf("  Rendering Intent:  %s (%u)\n",
         info.GetRenderingIntentName((icRenderingIntent)(pHdr->renderingIntent)),
         pHdr->renderingIntent);
  printf("  PCS Illuminant:    X=%.4f Y=%.4f Z=%.4f\n",
         icFtoD(pHdr->illuminant.X),
         icFtoD(pHdr->illuminant.Y),
         icFtoD(pHdr->illuminant.Z));

  FormatSig4(pHdr->creator, sigBuf);
  printf("  Creator:           '%s' (0x%08X)\n", sigBuf, pHdr->creator);

  // Profile ID (MD5)
  bool hasID = false;
  for (int i = 0; i < 16; i++) {
    if (pHdr->profileID.ID8[i] != 0) { hasID = true; break; }
  }
  printf("  Profile ID:        ");
  if (hasID) {
    for (int i = 0; i < 16; i++) printf("%02x", pHdr->profileID.ID8[i]);
    printf("\n");
  } else {
    printf("(not set)\n");
  }

  // V5/iccMAX extended header fields
  if (pHdr->version >= icVersionNumberV5) {
    printf("\n%s  --- ICC v5/iccMAX Extended Header ---%s\n", ColorInfo(), ColorReset());

    if (pHdr->deviceSubClass) {
      FormatSig4(pHdr->deviceSubClass, sigBuf);
      printf("  Device SubClass:   '%s' (0x%08X)\n", sigBuf, pHdr->deviceSubClass);
      printf("  SubClass Version:  %s\n", info.GetSubClassVersionName(pHdr->version));
    }

    printf("  Spectral PCS:      %s\n",
           info.GetSpectralColorSigName(pHdr->spectralPCS));

    if (pHdr->spectralRange.start || pHdr->spectralRange.end || pHdr->spectralRange.steps) {
      printf("  Spectral Range:    %.1f - %.1f nm, %u steps\n",
             icF16toF(pHdr->spectralRange.start),
             icF16toF(pHdr->spectralRange.end),
             pHdr->spectralRange.steps);
    } else {
      printf("  Spectral Range:    Not Defined\n");
    }

    if (pHdr->biSpectralRange.start || pHdr->biSpectralRange.end || pHdr->biSpectralRange.steps) {
      printf("  BiSpectral Range:  %.1f - %.1f nm, %u steps\n",
             icF16toF(pHdr->biSpectralRange.start),
             icF16toF(pHdr->biSpectralRange.end),
             pHdr->biSpectralRange.steps);
    } else {
      printf("  BiSpectral Range:  Not Defined\n");
    }

    if (pHdr->mcs) {
      printf("  MCS Color Space:   %s\n",
             info.GetColorSpaceSigName(static_cast<icColorSpaceSignature>(pHdr->mcs)));
    } else {
      printf("  MCS Color Space:   Not Defined\n");
    }
  }
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
      
      if (entry->TagInfo.size > ICCANALYZER_MAX_TAG_SIZE) {
        printf("Tag size too large (%u > %llu)\n",
               entry->TagInfo.size, (unsigned long long)ICCANALYZER_MAX_TAG_SIZE);
        break;
      }
      pIO->Seek(entry->TagInfo.offset, icSeekSet);
      icUInt8Number *tagData = new (std::nothrow) icUInt8Number[entry->TagInfo.size];
      if (!tagData) {
        printf("Error: Allocation failed for tag data (%u bytes)\n", entry->TagInfo.size);
        break;
      }
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
